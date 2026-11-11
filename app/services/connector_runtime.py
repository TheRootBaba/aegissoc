import json
import logging
import os
from datetime import datetime, timedelta, timezone
from time import perf_counter
from urllib.parse import urlsplit
import httpx
from sqlalchemy import select, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.models import ConnectorConfig, ConnectorRuntimeState, ConnectorExecution, ThreatIndicator
from app.services.integrations import get_adapter
from app.services.source_inventory import record_ingestion
from app.services.audit_chain import append_audit_entry
from app.api.routes.events import _normalize_source_event, _persist_event, _record_connector_observation
from app.api.routes.threat_intel import _normalize

logger = logging.getLogger("aegissoc.connector_runtime")
LEASE_SECONDS = 180
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_BATCH_RECORDS = 1000

def _credential(connector: ConnectorConfig) -> str | None:
    from app.services.secrets import resolve_secret_reference
    return resolve_secret_reference(connector.credential_ref)

def _read_response(url: str, headers: dict, *, method: str = 'GET', json_body: dict | None = None) -> dict | list:
    with httpx.Client(timeout=httpx.Timeout(15.0, connect=5.0), follow_redirects=False, verify=True) as client:
        with client.stream(method, url, headers=headers, json=json_body) as response:
            response.raise_for_status()
            if response.headers.get("content-length") and int(response.headers["content-length"]) > MAX_RESPONSE_BYTES:
                raise ValueError("Connector response exceeds the 5 MiB limit")
            chunks, size = [], 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise ValueError("Connector response exceeds the 5 MiB limit")
                chunks.append(chunk)
    try:
        value = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Connector response must be valid JSON") from exc
    if not isinstance(value, (dict, list)):
        raise ValueError("Connector response must be a JSON object or array")
    return value

def _path_value(document, path: str):
    value = document
    for part in path.split(".") if path else []:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value

def _records(document, config: dict, connector_type: str = "http_poll") -> list:
    default_path = {"misp": "response.Attribute", "opencti": "data.indicators.edges", "wazuh_manager": "data.affected_items", "wazuh_indexer": "hits.hits"}.get(connector_type, "items")
    value = _path_value(document, config.get("records_path", default_path))
    if value is None and isinstance(document, list):
        value = document
    if value is None and isinstance(document, dict) and "value" in document:
        value = document["value"]
    if not isinstance(value, list):
        raise ValueError("Connector response does not contain a record array at records_path")
    if len(value) > MAX_BATCH_RECORDS:
        raise ValueError("Connector response exceeds the 1000-record batch limit")
    if not all(isinstance(item, dict) for item in value):
        raise ValueError("Every connector record must be a JSON object")
    return value

def _poll_url(connector: ConnectorConfig) -> tuple[str, dict]:
    config = dict(connector.config or {})
    adapter = get_adapter(connector.connector_type)
    check = adapter.validate_config({**config, **({"credential_ref": connector.credential_ref} if connector.credential_ref else {})})
    if not check.valid:
        raise ValueError(check.message)
    url = config["endpoint"]
    parsed = urlsplit(url)
    if parsed.hostname.lower() not in [str(host).lower() for host in config["allowed_hosts"]]:
        raise ValueError("Connector endpoint host is not allowlisted")
    headers = {"Accept": "application/json"}
    secret = _credential(connector)
    if connector.connector_type == "wazuh_manager":
        import base64
        auth_url = config.get("auth_endpoint") or (
            f"{parsed.scheme}://{parsed.netloc}/security/user/authenticate"
        )
        auth_parsed = urlsplit(auth_url)
        if auth_parsed.scheme != "https" or auth_parsed.hostname.lower() not in [
            str(host).lower() for host in config["allowed_hosts"]
        ]:
            raise ValueError("Wazuh Manager authentication endpoint must use HTTPS and an allowlisted host")
        if not secret or ":" not in secret:
            raise ValueError("Wazuh Manager credential must reference username:password")
        basic = base64.b64encode(secret.encode()).decode("ascii")
        auth_document = _read_response(auth_url, {"Authorization": "Basic " + basic, "Accept": "application/json"}, method="POST")
        token = ((auth_document.get("data") or {}).get("token")) if isinstance(auth_document, dict) else None
        if not isinstance(token, str) or not token:
            raise ValueError("Wazuh Manager did not return an API access token")
        headers["Authorization"] = "Bearer " + token
    elif secret:
        header = config.get("auth_header", "X-MISP-Auth" if connector.connector_type == "misp" else "Authorization")
        if header.lower() not in {"authorization", "x-api-key", "x-misp-auth", "x-apikeys"}:
            raise ValueError("auth_header must be a supported authentication header")
        if header.lower() == "authorization" and config.get("auth_scheme") == "basic":
            import base64
            if ":" not in secret:
                raise ValueError("Basic Auth secret must contain username:password")
            headers[header] = "Basic " + base64.b64encode(secret.encode()).decode("ascii")
        else:
            headers[header] = ("Bearer " + secret) if header.lower() == "authorization" else secret
    return url, headers

def _ingest_event_records(db: Session, connector: ConnectorConfig, records: list) -> tuple[int, int, int]:
    accepted = duplicates = rejected = 0
    for item in records:
        try:
            item = get_adapter(connector.connector_type).normalize_payload(item)
            normalized = _normalize_source_event(db, connector.connector_key, item)
            outcome, _ = _persist_event(db, normalized)
            accepted += int(outcome == "accepted")
            duplicates += int(outcome == "duplicate")
            _record_connector_observation(db, connector.connector_key)
        except Exception:
            rejected += 1
    record_ingestion(db, connector.connector_key, accepted=accepted, duplicates=duplicates, rejected=rejected)
    return accepted, duplicates, rejected

def _ingest_indicators(db: Session, connector: ConnectorConfig, records: list) -> tuple[int, int, int]:
    accepted = duplicates = rejected = 0
    for item in records:
        try:
            item = get_adapter(connector.connector_type).normalize_indicator(item)
            kind = str(item.get("type", item.get("indicator_type", ""))).lower()
            value = _normalize(kind, str(item.get("value", "")))
            existing = db.scalar(select(ThreatIndicator).where(
                ThreatIndicator.indicator_type == kind, ThreatIndicator.value == value
            ))
            expiry = item.get("expires_at")
            if isinstance(expiry, str):
                expiry = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if existing:
                existing.confidence = max(existing.confidence, min(100, max(0, int(item.get("confidence", 50)))))
                existing.expires_at = expiry
                existing.tags = list(dict.fromkeys((existing.tags or []) + ["feed:" + connector.connector_key]))
                existing.updated_at = datetime.now(timezone.utc)
                duplicates += 1
            else:
                db.add(ThreatIndicator(
                    indicator_type=kind, value=value,
                    confidence=min(100, max(0, int(item.get("confidence", 50)))),
                    severity=(item.get("severity", "medium") if item.get("severity", "medium") in {"low", "medium", "high", "critical"} else "medium"), status="active",
                    source=str(item.get("source") or connector.display_name)[:120],
                    description=str(item.get("description") or "")[:500],
                    tags=[str(tag)[:64] for tag in (item.get("tags", []) if isinstance(item.get("tags", []), list) else [])[:20]],
                    expires_at=expiry, created_by="connector-runtime",
                ))
                accepted += 1
        except Exception:
            rejected += 1
    append_audit_entry(db, actor="connector-runtime", action="threat_feed.synchronized",
        resource_type="connector", resource_id=connector.connector_key,
        details={"accepted": accepted, "updated": duplicates, "rejected": rejected})
    return accepted, duplicates, rejected

def ensure_connector_states(db: Session, now: datetime | None = None) -> int:
    run_at = now or datetime.now(timezone.utc)
    connectors = db.scalars(select(ConnectorConfig).where(
        ConnectorConfig.enabled.is_(True), ConnectorConfig.connector_type.in_(("http_poll", "threat_feed", "wazuh_manager", "wazuh_indexer", "misp", "opencti"))
    )).all()
    created = 0
    for connector in connectors:
        state = db.get(ConnectorRuntimeState, connector.id)
        if state is None:
            try:
                with db.begin_nested():
                    db.add(ConnectorRuntimeState(connector_id=connector.id, next_run_at=run_at, cursor={}))
                    db.flush()
                created += 1
            except IntegrityError:
                continue
    if created:
        db.commit()
    return created

def run_due_connectors_once(db: Session, *, now: datetime | None = None, batch_size: int = 5) -> int:
    run_at = now or datetime.now(timezone.utc)
    ensure_connector_states(db, run_at)
    statement = select(ConnectorRuntimeState).join(
        ConnectorConfig, ConnectorConfig.id == ConnectorRuntimeState.connector_id
    ).where(
        ConnectorConfig.enabled.is_(True),
        ConnectorConfig.connector_type.in_(("http_poll", "threat_feed", "wazuh_manager", "wazuh_indexer", "misp", "opencti")),
        ConnectorRuntimeState.next_run_at <= run_at,
        or_(ConnectorRuntimeState.locked_until.is_(None), ConnectorRuntimeState.locked_until <= run_at),
    ).order_by(ConnectorRuntimeState.next_run_at.asc()).limit(batch_size)
    if db.get_bind().dialect.name == "postgresql":
        statement = statement.with_for_update(skip_locked=True)
    claimed = list(db.scalars(statement).all())
    ids = [state.connector_id for state in claimed]
    for state in claimed:
        state.locked_until = run_at + timedelta(seconds=LEASE_SECONDS)
    if claimed:
        db.commit()
    completed = 0
    for connector_id in ids:
        started = datetime.now(timezone.utc)
        timer = perf_counter()
        connector = db.get(ConnectorConfig, connector_id)
        state = db.get(ConnectorRuntimeState, connector_id)
        if connector is None or state is None:
            continue
        if not connector.enabled:
            state.locked_until = None
            db.commit()
            continue
        stale_runs = db.scalars(select(ConnectorExecution).where(
            ConnectorExecution.connector_id == connector_id,
            ConnectorExecution.status == "running",
        )).all()
        for stale in stale_runs:
            stale.status = "failed"
            stale.completed_at = started
            stale.error_type = "WorkerLeaseExpired"
        execution = ConnectorExecution(connector_id=connector_id, status="running", started_at=started)
        db.add(execution)
        db.commit()
        try:
            url, headers = _poll_url(connector)
            config = dict(connector.config or {})
            if connector.connector_type == "opencti":
                query = (
                    "query AegisIndicators($after: String) { "
                    "indicators(first: 100, after: $after) { "
                    "edges { node { id pattern name description confidence valid_until labels { value } } } "
                    "pageInfo { hasNextPage endCursor } } }"
                )
                document = _read_response(
                    url, headers, method="POST",
                    json_body={"query": query, "variables": {"after": (state.cursor or {}).get("after")}},
                )
            elif connector.connector_type == "wazuh_indexer":
                page_size = int(config.get("page_size", 500))
                if not 1 <= page_size <= MAX_BATCH_RECORDS:
                    raise ValueError("Wazuh Indexer page_size must be between 1 and 1000")
                body = {
                    "size": page_size,
                    "sort": [{"@timestamp": "asc"}, {"id": "asc"}],
                    "query": {"range": {"@timestamp": {"gte": config.get("lookback", "now-7d")}}},
                }
                if (state.cursor or {}).get("search_after"):
                    body["search_after"] = state.cursor["search_after"]
                document = _read_response(url, headers, method="POST", json_body=body)
            elif connector.connector_type == "misp":
                page_size = int(config.get("page_size", 1000))
                if not 1 <= page_size <= MAX_BATCH_RECORDS:
                    raise ValueError("MISP page_size must be between 1 and 1000")
                document = _read_response(
                    url, headers, method="POST",
                    json_body={"returnFormat": "json", "page": int((state.cursor or {}).get("page", 1)), "limit": page_size},
                )
            else:
                document = _read_response(url, headers)
            records = _records(document, config, connector.connector_type)
            if connector.connector_type in {"threat_feed", "misp", "opencti"}:
                accepted, duplicates, rejected = _ingest_indicators(db, connector, records)
            else:
                accepted, duplicates, rejected = _ingest_event_records(db, connector, records)
            finished = datetime.now(timezone.utc)
            interval = int((connector.config or {}).get("interval_seconds", 60))
            state.last_run_at = finished
            state.next_run_at = finished + timedelta(seconds=interval)
            if connector.connector_type == "opencti":
                page_info = (((document.get("data") or {}).get("indicators") or {}).get("pageInfo") or {})
                state.cursor = {"after": page_info.get("endCursor")} if page_info.get("hasNextPage") else {}
            elif connector.connector_type == "wazuh_indexer":
                if records and isinstance(records[-1], dict) and isinstance(records[-1].get("sort"), list):
                    state.cursor = {"search_after": records[-1]["sort"]}
            elif connector.connector_type == "misp":
                page = int((state.cursor or {}).get("page", 1))
                page_size = int(config.get("page_size", 1000))
                state.cursor = {"page": page + 1} if len(records) == page_size else {"page": 1}
            state.consecutive_failures = 0
            state.locked_until = None
            connector.health_status = "observed" if accepted + duplicates else ("degraded" if rejected else "observed")
            connector.last_checked_at = finished
            connector.last_success_at = finished
            connector.last_error_type = None
            execution.status = "success" if rejected == 0 else "partial"
            execution.completed_at = finished
            execution.duration_ms = int((perf_counter() - timer) * 1000)
            execution.records_seen = len(records)
            execution.accepted, execution.duplicates, execution.rejected = accepted, duplicates, rejected
            db.commit()
            completed += 1
        except Exception as exc:
            db.rollback()
            state = db.get(ConnectorRuntimeState, connector_id)
            connector = db.get(ConnectorConfig, connector_id)
            execution = db.get(ConnectorExecution, execution.id)
            finished = datetime.now(timezone.utc)
            failures = (state.consecutive_failures if state else 0) + 1
            delay = min(60 * (2 ** min(failures - 1, 10)), 3600)
            if state:
                state.consecutive_failures = failures
                state.last_run_at = finished
                state.next_run_at = finished + timedelta(seconds=delay)
                state.locked_until = None
            if connector:
                connector.health_status = "degraded"
                connector.last_checked_at = finished
                connector.last_error_type = type(exc).__name__
            if execution:
                execution.status = "failed"
                execution.completed_at = finished
                execution.duration_ms = int((perf_counter() - timer) * 1000)
                execution.error_type = type(exc).__name__
            db.commit()
            logger.warning("connector_poll_failed connector_id=%s error_type=%s", connector_id, type(exc).__name__)
    return completed

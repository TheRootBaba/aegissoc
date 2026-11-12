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
from app.models import (ConnectorConfig, ConnectorRuntimeState, ConnectorExecution, ThreatIndicator, ManagedAsset, VulnerabilityFinding, ScannerImportRun)
from app.services.integrations import get_adapter
from app.services.source_inventory import record_ingestion
from app.services.audit_chain import append_audit_entry
from app.api.routes.events import _normalize_source_event, _persist_event, _record_connector_observation
from app.api.routes.threat_intel import _normalize

logger = logging.getLogger("aegissoc.connector_runtime")
LEASE_SECONDS = 180
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_BATCH_RECORDS = 1000
SCANNER_TYPES = ("nessus", "tenable", "qualys")

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
        if (
            auth_parsed.scheme != "https"
            or not auth_parsed.hostname
            or auth_parsed.username
            or auth_parsed.password
            or auth_parsed.fragment
            or auth_parsed.hostname.lower() not in [str(host).lower() for host in config["allowed_hosts"]]
        ):
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
    event_timestamps = []
    for item in records:
        try:
            item = get_adapter(connector.connector_type).normalize_payload(item)
            normalized = _normalize_source_event(db, connector.connector_key, item)
            outcome, _ = _persist_event(db, normalized)
            accepted += int(outcome == "accepted")
            duplicates += int(outcome == "duplicate")
            if normalized.timestamp is not None:
                event_timestamps.append(normalized.timestamp)
            _record_connector_observation(db, connector.connector_key)
        except Exception:
            rejected += 1
    source_type = "wazuh" if connector.connector_type in {"wazuh", "wazuh_manager", "wazuh_indexer"} else None
    record_ingestion(
        db, connector.connector_key, accepted=accepted, duplicates=duplicates,
        rejected=rejected, event_timestamp=max(event_timestamps, default=None),
        source_type=source_type, display_name=connector.display_name,
    )
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


def _scanner_export_step(db: Session, connector: ConnectorConfig, state: ConnectorRuntimeState) -> tuple[int, int, int, bool]:
    """Advance one authenticated vendor export job; cursor changes commit with each state transition."""
    from app.services.scanner_export_jobs import scanner_headers, validate_provider_url, request_export_json, retry_after_seconds, parse_job_state
    from app.services.scanner_adapters import normalize_scanner_export
    from app.schemas.runtime import ScannerImportRequest

    provider = connector.connector_type
    config = dict(connector.config or {})
    allowed = config.get("allowed_hosts", [])
    base = str(config.get("endpoint", "")).rstrip("/")
    validate_provider_url(base, allowed)
    headers = scanner_headers(provider, connector.credential_ref)
    cursor = dict(state.cursor or {})
    scan_id = str(config.get("scan_id", "")).strip()
    if not scan_id:
        raise ValueError("Scanner connector config requires scan_id")
    interval = int(config.get("interval_seconds", 300))
    if not 60 <= interval <= 86400:
        raise ValueError("Scanner interval_seconds must be between 60 and 86400")

    def api_path(key: str, default: str = "") -> str:
        path = str(config.get(key, default)).format(scan_id=scan_id, job_id=cursor.get("job_id", ""), file_id=cursor.get("job_id", ""))
        if not path.startswith("/") or path.startswith("//") or "://" in path:
            raise ValueError(key + " must be a relative absolute-path API route")
        return base + path

    if not cursor.get("job_id"):
        start_path = api_path("start_path")
        payload = dict(config.get("start_payload") or {})
        document = request_export_json(start_path, headers, method=str(config.get("start_method", "POST")).upper(), payload=payload)
        job_id = document.get("file") or document.get("file_id") or document.get("job_id") or document.get("id")
        if not job_id:
            _, job_id = parse_job_state(provider, document)
        if not job_id:
            raise ValueError("Scanner export start response did not include a job identifier")
        state.cursor = {"job_id": str(job_id), "scan_id": scan_id, "stage": "polling"}
        state.next_run_at = datetime.now(timezone.utc) + timedelta(seconds=max(interval, retry_after_seconds({})))
        db.commit()
        return 0, 0, 0, False

    if cursor.get("stage") != "download":
        status_path = api_path("status_path")
        status_doc = request_export_json(status_path, headers)
        job_status, returned_id = parse_job_state(provider, status_doc)
        if returned_id and str(returned_id) != str(cursor["job_id"]):
            raise ValueError("Scanner status response refers to a different export job")
        if job_status == "pending":
            state.next_run_at = datetime.now(timezone.utc) + timedelta(seconds=interval)
            db.commit()
            return 0, 0, 0, False
        state.cursor = {**cursor, "stage": "download"}
        db.commit()
        cursor = dict(state.cursor)

    export_path = api_path("download_path")
    export_doc = request_export_json(export_path, headers)
    normalized = ScannerImportRequest.model_validate(normalize_scanner_export(provider, export_doc))
    total = sum(len(asset.findings) for asset in normalized.assets)
    if total > 5000:
        raise ValueError("A scanner import is limited to 5,000 findings")
    previous = db.scalar(select(ScannerImportRun).where(
        ScannerImportRun.workspace_id == connector.workspace_id,
        ScannerImportRun.scanner_name == normalized.scanner_name,
        ScannerImportRun.scan_id == normalized.scan_id,
    ))
    if previous is not None:
        state.cursor = {}
        return 0, 0, total, True
    assets_matched = created = updated = rejected = 0
    for scanned in normalized.assets:
        asset = db.scalar(select(ManagedAsset).where(
            ManagedAsset.workspace_id == connector.workspace_id,
            ManagedAsset.asset_key == scanned.asset_key.strip().lower(),
        ))
        if asset is None:
            rejected += len(scanned.findings)
            continue
        assets_matched += 1
        for item in scanned.findings:
            finding = db.scalar(select(VulnerabilityFinding).where(
                VulnerabilityFinding.workspace_id == connector.workspace_id,
                VulnerabilityFinding.asset_id == asset.id,
                VulnerabilityFinding.vulnerability_id == item.vulnerability_id,
            ))
            if finding is None:
                db.add(VulnerabilityFinding(
                    workspace_id=connector.workspace_id, asset_id=asset.id,
                    vulnerability_id=item.vulnerability_id, title=item.title,
                    severity=item.severity, source=provider,
                    description=item.description, due_at=item.due_at,
                ))
                created += 1
            else:
                finding.title = item.title
                finding.severity = item.severity
                finding.source = provider
                finding.description = item.description
                finding.due_at = item.due_at
                if finding.status in {"remediated", "false_positive"}:
                    finding.status = "open"
                finding.updated_at = datetime.now(timezone.utc)
                updated += 1
    result = {
        "scan_id": normalized.scan_id, "assets_seen": len(normalized.assets),
        "assets_matched": assets_matched, "findings_seen": total,
        "findings_created": created, "findings_updated": updated,
        "findings_rejected": rejected,
    }
    db.add(ScannerImportRun(
        workspace_id=connector.workspace_id, scanner_name=provider,
        scan_id=normalized.scan_id, result=result, created_by="connector-runtime",
    ))
    state.cursor = {}
    append_audit_entry(db, actor="connector-runtime", action="vulnerability.scan_imported",
        resource_type="scanner_import", resource_id=provider + ":" + normalized.scan_id,
        details={key: value for key, value in result.items() if key != "scan_id"})
    return created, updated, rejected, True

def ensure_connector_states(db: Session, now: datetime | None = None) -> int:
    run_at = now or datetime.now(timezone.utc)
    connectors = db.scalars(select(ConnectorConfig).where(
        ConnectorConfig.enabled.is_(True), ConnectorConfig.connector_type.in_(("http_poll", "threat_feed", "wazuh_manager", "wazuh_indexer", "misp", "opencti", *SCANNER_TYPES))
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
            if connector.connector_type in SCANNER_TYPES:
                accepted, duplicates, rejected, finished_job = _scanner_export_step(db, connector, state)
                finished = datetime.now(timezone.utc)
                if finished_job:
                    state.last_run_at = finished
                    state.next_run_at = finished + timedelta(seconds=int((connector.config or {}).get("interval_seconds", 300)))
                    state.consecutive_failures = 0
                    state.locked_until = None
                    connector.health_status = "observed"
                    connector.last_checked_at = finished
                    connector.last_success_at = finished
                    connector.last_error_type = None
                    execution.status = "success" if rejected == 0 else "partial"
                    execution.completed_at = finished
                    execution.duration_ms = int((perf_counter() - timer) * 1000)
                    execution.records_seen = accepted + duplicates + rejected
                    execution.accepted, execution.duplicates, execution.rejected = accepted, duplicates, rejected
                    db.commit()
                    completed += 1
                else:
                    state.last_run_at = finished
                    state.locked_until = None
                    execution.status = "pending"
                    execution.completed_at = finished
                    execution.duration_ms = int((perf_counter() - timer) * 1000)
                    db.commit()
                continue
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
            from app.services.scanner_export_jobs import ScannerRateLimited
            delay = exc.retry_after if isinstance(exc, ScannerRateLimited) else min(60 * (2 ** min(failures - 1, 10)), 3600)
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

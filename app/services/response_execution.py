"""Leased, retryable response-action delivery with stable receiver idempotency."""

import hashlib
import hmac
import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import ConnectorConfig, ResponseActionRequest
from app.services.audit_chain import append_audit_entry
from app.services.integrations import get_adapter
from app.services.secrets import resolve_secret_reference

logger = logging.getLogger("aegissoc.response_execution")
LEASE_SECONDS = 120
MAX_ATTEMPTS = 5
MAX_RETRY_SECONDS = 1800


def _delivery(request: ResponseActionRequest, connector: ConnectorConfig) -> tuple[str, dict, bytes]:
    config = dict(connector.config or {})
    validation = get_adapter("response_webhook").validate_config(config)
    if not validation.valid:
        raise ValueError(validation.message)
    endpoint = config["endpoint"]
    parsed = urlsplit(endpoint)
    if parsed.hostname.lower() not in [str(host).lower() for host in config["allowed_hosts"]]:
        raise ValueError("Response endpoint host is not allowlisted")
    if request.action_type == "block_ip":
        ipaddress.ip_address(request.target)
    body = {
        "id": str(request.id),
        "idempotency_key": request.idempotency_key,
        "action_type": request.action_type,
        "target": request.target,
        "parameters": request.parameters,
        "case_id": str(request.case_id) if request.case_id else None,
        "requested_by": request.requested_by,
        "approved_by": request.approved_by,
    }
    encoded = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    headers = {"Content-Type": "application/json", "Idempotency-Key": request.idempotency_key}
    secret = resolve_secret_reference(connector.credential_ref)
    if secret:
        headers["X-Aegis-Signature"] = "sha256=" + hmac.new(secret.encode(), encoded, hashlib.sha256).hexdigest()
    return endpoint, headers, encoded


def _retry_delay(attempt: int) -> int:
    return min(30 * (2 ** max(0, attempt - 1)), MAX_RETRY_SECONDS)


def run_due_response_actions_once(db: Session, *, now: datetime | None = None, batch_size: int = 10) -> int:
    run_at = now or datetime.now(timezone.utc)
    eligible = or_(
        (
            (ResponseActionRequest.status == "approved")
            & ResponseActionRequest.execution_status.in_(("queued", "retry_scheduled"))
            & (ResponseActionRequest.next_attempt_at <= run_at)
        ),
        (
            (ResponseActionRequest.status == "executing")
            & (
                ResponseActionRequest.locked_until.is_(None)
                | (ResponseActionRequest.locked_until <= run_at)
            )
        ),
    )
    statement = (
        select(ResponseActionRequest)
        .where(eligible)
        .order_by(ResponseActionRequest.next_attempt_at.asc().nullsfirst(),
                  ResponseActionRequest.created_at.asc(), ResponseActionRequest.id.asc())
        .limit(batch_size)
    )
    if db.get_bind().dialect.name == "postgresql":
        statement = statement.with_for_update(skip_locked=True)
    claimed = list(db.scalars(statement).all())
    ids = [item.id for item in claimed]
    for item in claimed:
        item.status = "executing"
        item.execution_status = "submitting"
        item.execution_attempts += 1
        item.locked_until = run_at + timedelta(seconds=LEASE_SECONDS)
    if claimed:
        db.commit()

    completed = 0
    for request_id in ids:
        request = db.get(ResponseActionRequest, request_id)
        if request is None:
            continue
        started = datetime.now(timezone.utc)
        connector = db.scalar(select(ConnectorConfig).where(
            ConnectorConfig.connector_key == request.connector_key,
            ConnectorConfig.connector_type == "response_webhook",
            ConnectorConfig.enabled.is_(True),
        ))
        if connector is None:
            error_type = "ResponseConnectorUnavailable"
            response_code = None
            external_reference = None
            retryable = False
        else:
            try:
                endpoint, headers, encoded = _delivery(request, connector)
                with httpx.Client(
                    timeout=httpx.Timeout(10.0, connect=5.0),
                    follow_redirects=False,
                    verify=True,
                ) as client:
                    with client.stream("POST", endpoint, content=encoded, headers=headers) as response:
                        response_code = response.status_code
                        external_reference = response.headers.get("X-Aegis-Action-Reference")
                error_type = None if 200 <= response_code < 300 else "HTTPStatusError"
                retryable = response_code in {408, 425, 429} or response_code >= 500
            except (ValueError, OSError) as exc:
                response_code = None
                external_reference = None
                error_type = type(exc).__name__
                retryable = False
            except httpx.HTTPError as exc:
                response_code = None
                external_reference = None
                error_type = type(exc).__name__
                retryable = True

        finished = datetime.now(timezone.utc)
        request.response_code = response_code
        request.external_reference = external_reference[:160] if external_reference else None
        request.last_error_type = error_type
        request.locked_until = None
        if error_type is None and response_code is not None and 200 <= response_code < 300:
            request.status = "succeeded"
            request.execution_status = "delivered"
            request.result_summary = "Webhook accepted the action request."
            request.executed_at = finished
            request.next_attempt_at = None
        elif retryable and request.execution_attempts < MAX_ATTEMPTS:
            request.status = "approved"
            request.execution_status = "retry_scheduled"
            request.next_attempt_at = finished + timedelta(seconds=_retry_delay(request.execution_attempts))
            request.result_summary = "Delivery outcome was not successful; a bounded retry has been scheduled with the same idempotency key."
            request.executed_at = None
        else:
            request.status = "failed"
            request.execution_status = "delivery_failed" if error_type else "receiver_rejected"
            request.result_summary = (
                "Webhook delivery failed (" + error_type + ")."
                if error_type else "Webhook returned a non-success HTTP status."
            )
            request.executed_at = finished
            request.next_attempt_at = None
        append_audit_entry(
            db,
            actor="response-worker",
            action="response_action.attempt_finished",
            resource_type="response_action",
            resource_id=str(request.id),
            details={
                "attempt": request.execution_attempts,
                "status": request.status,
                "execution_status": request.execution_status,
                "response_code": response_code,
                "error_type": error_type,
                "retry_at": request.next_attempt_at.isoformat() if request.next_attempt_at else None,
            },
        )
        db.commit()
        completed += 1
    return completed

"""Receiver-aware compensation contract for reversible response operations.

A compensation is never inferred from an action name. The receiver must explicitly
advertise support and the original request must carry an external reference.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from urllib.parse import urlsplit

import httpx

from app.services.secrets import resolve_secret_reference


def build_compensation(connector, request, *, reason: str) -> tuple[str, dict, bytes]:
    config = dict(connector.config or {})
    capabilities = config.get("capabilities") if isinstance(config.get("capabilities"), dict) else {}
    if capabilities.get("compensation") is not True:
        raise ValueError("Receiver has not declared compensation support")
    endpoint = config.get("compensation_endpoint")
    allowed = {str(host).lower() for host in config.get("allowed_hosts", [])}
    parsed = urlsplit(endpoint or "")
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or parsed.hostname.lower() not in allowed):
        raise ValueError("Compensation endpoint must use HTTPS and an allowlisted host")
    reference = getattr(request, "external_reference", None)
    if not reference:
        raise ValueError("A receiver reference is required before compensation")
    operation_id = str(getattr(request, "idempotency_key", "") or "")
    if not operation_id:
        raise ValueError("Original operation idempotency key is required")
    body = {
        "operation": "compensate",
        "original_idempotency_key": operation_id,
        "original_reference": str(reference),
        "action_type": request.action_type,
        "target": request.target,
        "reason": reason[:500],
    }
    encoded = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    headers = {"Content-Type": "application/json",
               "Idempotency-Key": hashlib.sha256((operation_id + ":compensate").encode()).hexdigest()}
    secret = resolve_secret_reference(connector.credential_ref)
    if secret:
        headers["X-Aegis-Signature"] = "sha256=" + hmac.new(secret.encode(), encoded, hashlib.sha256).hexdigest()
    return endpoint, headers, encoded


def post_compensation(connector, request, *, reason: str) -> dict:
    endpoint, headers, encoded = build_compensation(connector, request, reason=reason)
    with httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=False, verify=True) as client:
        response = client.post(endpoint, headers=headers, content=encoded)
        response.raise_for_status()
        if len(response.content) > 65536:
            raise ValueError("Compensation response exceeds 64 KiB")
        document = response.json()
    if not isinstance(document, dict) or document.get("original_idempotency_key") != request.idempotency_key:
        raise ValueError("Compensation response does not identify the original operation")
    state = str(document.get("status", "")).lower()
    if state not in {"compensated", "pending", "rejected"}:
        raise ValueError("Receiver returned an unsupported compensation status")
    return {"status": state, "reference": str(document.get("reference") or "")[:160] or None}


def reconcile_compensation(connector, request) -> dict:
    """Poll a receiver-owned compensation status endpoint without resubmitting the operation."""
    config = dict(connector.config or {})
    endpoint = config.get("compensation_status_endpoint")
    allowed = {str(host).lower() for host in config.get("allowed_hosts", [])}
    parsed = urlsplit(endpoint or "")
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or parsed.hostname.lower() not in allowed):
        raise ValueError("Compensation status endpoint must use HTTPS and an allowlisted host")
    headers = {"Accept": "application/json", "Idempotency-Key":
               hashlib.sha256((request.idempotency_key + ":compensate").encode()).hexdigest()}
    secret = resolve_secret_reference(connector.credential_ref)
    if secret:
        signature = hmac.new(secret.encode(), request.idempotency_key.encode(), hashlib.sha256).hexdigest()
        headers["X-Aegis-Signature"] = "sha256=" + signature
    with httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=False, verify=True) as client:
        with client.stream("GET", endpoint, params={"original_idempotency_key": request.idempotency_key},
                           headers=headers) as response:
            response.raise_for_status()
            chunks, size = [], 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > 65536:
                    raise ValueError("Compensation status response exceeds 64 KiB")
                chunks.append(chunk)
    document = json.loads(b"".join(chunks))
    if not isinstance(document, dict) or document.get("original_idempotency_key") != request.idempotency_key:
        raise ValueError("Compensation status does not identify the original action")
    state = str(document.get("status", "")).lower()
    if state not in {"compensated", "pending", "rejected"}:
        raise ValueError("Receiver returned an unsupported compensation status")
    return {"status": state, "reference": str(document.get("reference") or "")[:160] or None}

"""Authenticated scanner export-job primitives.

Provider API credentials are resolved from credential_ref at runtime. Job identifiers and
polling cursors are persisted by the connector worker in ConnectorRuntimeState.cursor.
The configured URLs are constrained to the connector's HTTPS allowlist.
"""
from __future__ import annotations

import base64
from urllib.parse import urlsplit

import httpx

from app.services.secrets import resolve_secret_reference

MAX_EXPORT_BYTES = 5 * 1024 * 1024


def scanner_headers(provider: str, credential_ref: str | None) -> dict[str, str]:
    secret = resolve_secret_reference(credential_ref)
    if not secret:
        raise ValueError("Scanner connector has no resolvable credential_ref")
    provider = provider.lower()
    if provider == "nessus":
        # Nessus API keys are stored as "access_key:secret_key".
        if ":" not in secret:
            raise ValueError("Nessus credential must contain access_key:secret_key")
        access, private = secret.split(":", 1)
        if not access or not private:
            raise ValueError("Nessus API keys cannot be blank")
        return {"X-ApiKeys": f"accessKey={access}; secretKey={private}", "Accept": "application/json"}
    if provider == "tenable":
        # Tenable.io API keys use the same two-part format.
        if ":" not in secret:
            raise ValueError("Tenable credential must contain access_key:secret_key")
        access, private = secret.split(":", 1)
        if not access or not private:
            raise ValueError("Tenable API keys cannot be blank")
        return {"X-ApiKeys": f"accessKey={access}; secretKey={private}", "Accept": "application/json"}
    if provider == "qualys":
        if ":" not in secret:
            raise ValueError("Qualys credential must contain username:password")
        return {"Authorization": "Basic " + base64.b64encode(secret.encode()).decode("ascii"),
                "Accept": "application/json"}
    raise ValueError("Unsupported vulnerability scanner provider")


def validate_provider_url(url: str, allowed_hosts: list[str]) -> None:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or parsed.hostname.lower() not in {str(h).lower() for h in allowed_hosts}):
        raise ValueError("Scanner API URL must use HTTPS and an explicitly allowlisted host")


def request_export_json(url: str, headers: dict[str, str], *, method: str = "GET",
                        payload: dict | None = None) -> dict:
    """Perform one bounded, non-redirecting JSON API request."""
    with httpx.Client(timeout=httpx.Timeout(20.0, connect=5.0), follow_redirects=False, verify=True) as client:
        response = client.request(method, url, headers=headers, json=payload)
        response.raise_for_status()
        if len(response.content) > MAX_EXPORT_BYTES:
            raise ValueError("Scanner export API response exceeds 5 MiB")
        document = response.json()
    if not isinstance(document, dict):
        raise ValueError("Scanner export API must return a JSON object")
    return document


def retry_after_seconds(headers: dict, *, default: int = 60, maximum: int = 3600) -> int:
    """Honor numeric Retry-After values while keeping retry scheduling bounded."""
    try:
        value = int(headers.get("Retry-After", default))
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, maximum))


def scanner_job_request(provider: str, config: dict, cursor: dict, credential_ref: str | None):
    """Build the next provider request from durable cursor state.

    Config contract:
      endpoint: provider API base or export endpoint
      allowed_hosts: explicit HTTPS host allowlist
      start_path/status_path: relative, provider-specific paths
      scan_id: Nessus/Tenable scan identifier where required
      start_payload: optional provider export parameters
    """
    provider = provider.lower()
    headers = scanner_headers(provider, credential_ref)
    base = str(config.get("endpoint", "")).rstrip("/")
    validate_provider_url(base, config.get("allowed_hosts", []))
    job_id = cursor.get("job_id")
    if job_id:
        path = str(config.get("status_path", "")).format(job_id=job_id, scan_id=config.get("scan_id", ""))
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("status_path must be an absolute API path")
        return base + path, headers, "GET", None, "polling"
    path = str(config.get("start_path", ""))
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("start_path must be an absolute API path")
    return base + path, headers, str(config.get("start_method", "POST")).upper(), dict(config.get("start_payload") or {}), "starting"


def parse_job_state(provider: str, document: dict) -> tuple[str, str | None]:
    """Normalize common provider job response states without assuming completion."""
    provider = provider.lower()
    if provider == "nessus":
        status = str(document.get("status", "")).lower()
        job_id = document.get("file")
    elif provider == "tenable":
        status = str(document.get("status", "")).lower()
        job_id = document.get("file")
    else:
        status = str(document.get("status", document.get("state", ""))).lower()
        job_id = document.get("id") or document.get("report_id")
    if status in {"completed", "complete", "finished", "ready"}:
        return "completed", str(job_id) if job_id is not None else None
    if status in {"queued", "pending", "running", "processing", "in_progress"}:
        return "pending", str(job_id) if job_id is not None else None
    if status in {"failed", "error", "cancelled", "canceled"}:
        raise RuntimeError("Scanner export job failed")
    raise ValueError("Scanner export response contains an unsupported job status")

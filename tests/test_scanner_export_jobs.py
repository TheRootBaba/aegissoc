from app.services.scanner_export_jobs import (
    parse_job_state, retry_after_seconds, scanner_headers, scanner_job_request,
    validate_provider_url,
)


def test_scanner_provider_auth_formats(monkeypatch):
    monkeypatch.setattr("app.services.scanner_export_jobs.resolve_secret_reference",
                        lambda ref: "access:private")
    assert scanner_headers("nessus", "secret://nessus")["X-ApiKeys"] == "accessKey=access; secretKey=private"
    assert scanner_headers("tenable", "secret://tenable")["X-ApiKeys"] == "accessKey=access; secretKey=private"


def test_qualys_basic_auth_and_invalid_credentials(monkeypatch):
    import base64
    monkeypatch.setattr("app.services.scanner_export_jobs.resolve_secret_reference",
                        lambda ref: "scanner-user:scanner-pass")
    header = scanner_headers("qualys", "secret://qualys")["Authorization"]
    assert header == "Basic " + base64.b64encode(b"scanner-user:scanner-pass").decode()
    monkeypatch.setattr("app.services.scanner_export_jobs.resolve_secret_reference", lambda ref: "bad")
    import pytest
    with pytest.raises(ValueError):
        scanner_headers("qualys", "secret://qualys")


def test_scanner_job_cursor_and_host_validation(monkeypatch):
    monkeypatch.setattr('app.services.scanner_export_jobs.resolve_secret_reference', lambda ref: 'access:private')
    config = {"endpoint": "https://cloud.example", "allowed_hosts": ["cloud.example"],
              "start_path": "/scans/42/export", "status_path": "/exports/{job_id}",
              "scan_id": "42", "start_payload": {"format": "nessus"}}
    url, headers, method, body, state = scanner_job_request(
        "nessus", config, {}, "env://SCANNER_API_KEYS")
    assert url == "https://cloud.example/scans/42/export"
    assert method == "POST" and body == {"format": "nessus"} and state == "starting"
    url, _, method, body, state = scanner_job_request(
        "nessus", config, {"job_id": "job-7"}, "secret://scanner")
    assert url == "https://cloud.example/exports/job-7"
    assert method == "GET" and body is None and state == "polling"
    import pytest
    with pytest.raises(ValueError):
        validate_provider_url("https://evil.example/export", ["cloud.example"])


def test_scanner_job_state_and_provider_throttling():
    assert parse_job_state("nessus", {"status": "running", "file": 7}) == ("pending", "7")
    assert parse_job_state("tenable", {"status": "completed", "file": 8}) == ("completed", "8")
    assert retry_after_seconds({"Retry-After": "9000"}) == 3600
    assert retry_after_seconds({"Retry-After": "invalid"}, default=30) == 30

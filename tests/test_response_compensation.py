from types import SimpleNamespace

import pytest

from app.services.response_compensation import build_compensation


def _objects():
    connector = SimpleNamespace(
        config={"capabilities": {"compensation": True},
                "compensation_endpoint": "https://receiver.example/compensate",
                "allowed_hosts": ["receiver.example"]},
        credential_ref=None,
    )
    request = SimpleNamespace(
        external_reference="remote-123", idempotency_key="stable-op-123",
        action_type="block_ip", target="203.0.113.8",
    )
    return connector, request


def test_compensation_requires_explicit_receiver_capability():
    connector, request = _objects()
    connector.config["capabilities"]["compensation"] = False
    with pytest.raises(ValueError, match="declared compensation"):
        build_compensation(connector, request, reason="rollback")


def test_compensation_requires_receiver_reference_and_allowlisted_tls():
    connector, request = _objects()
    request.external_reference = None
    with pytest.raises(ValueError, match="reference"):
        build_compensation(connector, request, reason="rollback")
    request.external_reference = "remote-123"
    connector.config["compensation_endpoint"] = "https://attacker.example/compensate"
    with pytest.raises(ValueError, match="allowlisted"):
        build_compensation(connector, request, reason="rollback")


def test_compensation_is_bound_to_original_operation_and_idempotent():
    connector, request = _objects()
    endpoint, headers, encoded = build_compensation(connector, request, reason="operator requested rollback")
    assert endpoint == "https://receiver.example/compensate"
    assert headers["Idempotency-Key"]
    assert b"stable-op-123" in encoded
    assert b"remote-123" in encoded

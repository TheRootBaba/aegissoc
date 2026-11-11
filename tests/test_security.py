from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from app.core.security import check_login_rate_limit, clear_login_rate_limit, create_access_token, decode_access_token, hash_password, require_roles, verify_password

def test_password_hash_is_salted_and_verifiable():
    first = hash_password("correct-horse-battery-staple")
    second = hash_password("correct-horse-battery-staple")
    assert first != second
    assert verify_password("correct-horse-battery-staple", first)
    assert not verify_password("wrong-password", first)

def test_access_token_contains_signed_user_claims():
    user = SimpleNamespace(id="b8a1f5a6-8e4b-4b43-94d2-3db1a5ec2c41", username="soc-admin", role="admin")
    claims = decode_access_token(create_access_token(user))
    assert claims["username"] == "soc-admin"
    assert claims["role"] == "admin"
    assert claims["sub"] == user.id

def test_access_token_rejects_tampering():
    user = SimpleNamespace(id="b8a1f5a6-8e4b-4b43-94d2-3db1a5ec2c41", username="soc-admin", role="admin")
    token = create_access_token(user)
    header, payload, signature = token.split(".")
    with pytest.raises(HTTPException) as error:
        decode_access_token(f"{header}.{payload}.{signature[:-2]}xx")
    assert error.value.status_code == 401

def test_login_throttle_blocks_attempt_after_limit():
    key = "security-test-client"
    clear_login_rate_limit(key)
    for _ in range(5):
        check_login_rate_limit(key)
    with pytest.raises(HTTPException) as error:
        check_login_rate_limit(key)
    assert error.value.status_code == 429
    clear_login_rate_limit(key)

def test_role_dependency_rejects_read_only_for_analyst_action():
    dependency = require_roles("admin", "analyst")
    with pytest.raises(HTTPException) as error:
        dependency(SimpleNamespace(username="viewer", role="read_only"))
    assert error.value.status_code == 403

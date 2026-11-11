"""Password hashing, signed access tokens, and authentication dependencies."""
import base64, hashlib, hmac, json, secrets, time
from uuid import UUID
from collections import defaultdict, deque
from threading import Lock
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from app.core.config import settings
from app.db.session import get_db
from app.models import User

bearer_scheme = HTTPBearer(auto_error=False)
_HASH_ITERATIONS = 310_000
_LOGIN_LIMIT = 5
_LOGIN_WINDOW_SECONDS = 60
_login_attempts: dict[str, deque[float]] = defaultdict(deque)
_login_lock = Lock()

def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 with a unique 128-bit salt."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _HASH_ITERATIONS)
    return f"pbkdf2_sha256${_HASH_ITERATIONS}${_b64encode(salt)}${_b64encode(digest)}"

def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), _b64decode(salt), int(iterations))
        return hmac.compare_digest(actual, _b64decode(expected))
    except (ValueError, TypeError):
        return False

def create_access_token(user: User) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": str(user.id), "username": user.username, "role": user.role,
               "iat": now, "exp": now + settings.access_token_minutes * 60}
    signing_input = f"{_b64encode(json.dumps(header, separators=(',', ':')).encode())}.{_b64encode(json.dumps(payload, separators=(',', ':')).encode())}"
    signature = hmac.new(settings.auth_secret_key.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64encode(signature)}"

def decode_access_token(token: str) -> dict:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        header = json.loads(_b64decode(encoded_header))
        if header != {"alg": "HS256", "typ": "JWT"}:
            raise ValueError("Unsupported token header")
        signing_input = f"{encoded_header}.{encoded_payload}"
        expected = hmac.new(settings.auth_secret_key.encode(), signing_input.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64decode(encoded_signature)):
            raise ValueError("Invalid signature")
        payload = json.loads(_b64decode(encoded_payload))
        if not isinstance(payload.get("exp"), int) or payload["exp"] <= int(time.time()):
            raise ValueError("Expired token")
        if not payload.get("sub") or not payload.get("username"):
            raise ValueError("Missing subject")
        return payload
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired access token",
                            headers={"WWW-Authenticate": "Bearer"}) from exc

def check_login_rate_limit(client_key: str) -> None:
    """Apply a per-process throttle; production deployments also need an edge limiter."""
    now = time.monotonic()
    with _login_lock:
        attempts = _login_attempts[client_key]
        while attempts and now - attempts[0] >= _LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= _LOGIN_LIMIT:
            raise HTTPException(status_code=429, detail="Too many login attempts; retry shortly")
        attempts.append(now)
        if len(_login_attempts) > 10_000:
            expired = [key for key, values in _login_attempts.items()
                       if not values or now - values[-1] >= _LOGIN_WINDOW_SECONDS]
            for key in expired:
                _login_attempts.pop(key, None)

def clear_login_rate_limit(client_key: str) -> None:
    with _login_lock:
        _login_attempts.pop(client_key, None)

def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
                     db: Session = Depends(get_db)) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer access token required",
                            headers={"WWW-Authenticate": "Bearer"})
    claims = decode_access_token(credentials.credentials)
    user = db.get(User, UUID(claims["sub"]))
    if user is None or not user.is_active or user.username != claims["username"]:
        raise HTTPException(status_code=401, detail="User is inactive or no longer exists")
    return user

def require_roles(*roles: str):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role for this operation")
        return user
    return dependency

def client_rate_limit_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"

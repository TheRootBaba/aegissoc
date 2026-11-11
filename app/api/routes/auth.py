from uuid import UUID
import secrets
import json
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.security import check_login_rate_limit, clear_login_rate_limit, client_rate_limit_key, create_access_token, get_current_user, hash_password, require_roles, verify_password
from app.db.session import get_db
from app.models import User, WorkspaceMembership, ExternalIdentity
from app.schemas.auth import CurrentUserRead, LoginRequest, TokenResponse, UserCreate, UserRead, OIDCIdentityCreate
from app.services.audit_chain import append_audit_entry
from app.services.secrets import resolve_secret_reference

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])

@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate a local account and issue a short-lived bearer token."""
    key = client_rate_limit_key(request)
    check_login_rate_limit(key)
    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    clear_login_rate_limit(key)
    return TokenResponse(access_token=create_access_token(user), expires_in=settings.access_token_minutes * 60)


oauth = OAuth()
if settings.oidc_enabled:
    oidc_client_secret = settings.oidc_client_secret
    if oidc_client_secret and oidc_client_secret.startswith(("env://", "file://")):
        oidc_client_secret = resolve_secret_reference(oidc_client_secret)
    oauth.register(
        name="aegis_oidc",
        client_id=settings.oidc_client_id,
        client_secret=oidc_client_secret,
        server_metadata_url=settings.oidc_issuer_url.rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={"scope": settings.oidc_scopes},
    )


@router.get("/oidc/login")
async def oidc_login(request: Request):
    if not settings.oidc_enabled:
        raise HTTPException(status_code=404, detail="OpenID Connect is not enabled")
    nonce = secrets.token_urlsafe(32)
    request.session["aegis_oidc_nonce"] = nonce
    client = oauth.create_client("aegis_oidc")
    return await client.authorize_redirect(request, settings.oidc_redirect_url, nonce=nonce)


@router.get("/oidc/callback", response_class=HTMLResponse)
async def oidc_callback(request: Request, db: Session = Depends(get_db)):
    if not settings.oidc_enabled:
        raise HTTPException(status_code=404, detail="OpenID Connect is not enabled")
    nonce = request.session.pop("aegis_oidc_nonce", None)
    if not nonce:
        raise HTTPException(status_code=401, detail="OIDC login state is missing or expired")
    client = oauth.create_client("aegis_oidc")
    try:
        token = await client.authorize_access_token(request)
        claims = token.get("userinfo")
        # The UserInfo endpoint is not required to return an issuer claim.
        # Validate issuer and nonce against the signed ID token instead.
        if not isinstance(claims, dict) or not claims.get("iss"):
            claims = await client.parse_id_token(request, token, nonce=nonce)
        elif claims.get("sub") != token.get("userinfo", {}).get("sub"):
            raise ValueError("OIDC subject mismatch")
    except Exception as exc:
        raise HTTPException(status_code=401, detail="OpenID Connect authentication failed") from exc
    expected_issuer = settings.oidc_issuer_url.rstrip("/")
    actual_issuer = str(claims.get("iss") or "").rstrip("/")
    subject = str(claims.get("sub") or "")
    if actual_issuer != expected_issuer or not subject or len(subject) > 255:
        raise HTTPException(status_code=401, detail="OIDC issuer or subject validation failed")
    identity = db.scalar(select(ExternalIdentity).where(
        ExternalIdentity.issuer == expected_issuer,
        ExternalIdentity.subject == subject,
    ))
    if identity is None:
        raise HTTPException(status_code=403, detail="This OIDC identity has not been provisioned by an administrator")
    user = db.get(User, identity.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=403, detail="The mapped AegisSOC account is inactive")
    token_value = create_access_token(user)
    safe_token = json.dumps(token_value)
    return HTMLResponse(
        "<!doctype html><html><head><meta charset='utf-8'></head><body>"
        "<p>Authentication complete. Redirecting to AegisSOC…</p>"
        "<script>sessionStorage.setItem('aegis_token'," + safe_token + ");"
        "window.location.replace('/dashboard');</script></body></html>",
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@router.get("/methods")
def authentication_methods():
    return {"local_password": True, "oidc_enabled": settings.oidc_enabled}


@router.post("/oidc/identities", status_code=status.HTTP_201_CREATED)
def provision_oidc_identity(
    payload: OIDCIdentityCreate,
    _admin: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    if not settings.oidc_enabled:
        raise HTTPException(status_code=404, detail="OpenID Connect is not enabled")
    workspace_id = db.info.get("workspace_id")
    user = db.scalar(
        select(User)
        .join(WorkspaceMembership, WorkspaceMembership.user_id == User.id)
        .where(
            User.username == payload.username,
            WorkspaceMembership.workspace_id == workspace_id,
            WorkspaceMembership.is_active.is_(True),
        )
    )
    if user is None:
        raise HTTPException(status_code=404, detail="User is not an active member of this workspace")
    issuer = settings.oidc_issuer_url.rstrip("/")
    existing = db.scalar(select(ExternalIdentity).where(
        ExternalIdentity.issuer == issuer,
        ExternalIdentity.subject == payload.subject,
    ))
    if existing is not None:
        if existing.user_id == user.id:
            return {"status": "already_linked", "username": user.username}
        raise HTTPException(status_code=409, detail="OIDC subject is already linked to another account")
    identity = ExternalIdentity(issuer=issuer, subject=payload.subject, user_id=user.id)
    db.add(identity)
    append_audit_entry(
        db, actor=_admin.username, action="auth.oidc_identity_provisioned",
        resource_type="external_identity", resource_id=payload.subject,
        details={"username": user.username, "issuer": issuer},
    )
    db.commit()
    return {"status": "linked", "username": user.username}

@router.get("/me", response_model=CurrentUserRead)
def who_am_i(user: User = Depends(get_current_user)):
    return user

@router.get("/users", response_model=list[UserRead])
def list_users(_admin: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    workspace_id = db.info.get("workspace_id")
    if workspace_id is None:
        raise HTTPException(status_code=400, detail="An active workspace is required")
    rows = db.execute(
        select(User, WorkspaceMembership.role)
        .join(WorkspaceMembership, WorkspaceMembership.user_id == User.id)
        .where(WorkspaceMembership.workspace_id == workspace_id, WorkspaceMembership.is_active.is_(True))
        .order_by(User.username.asc())
    ).all()
    return [{
        "id": user.id, "username": user.username, "role": membership_role,
        "is_active": user.is_active, "created_at": user.created_at,
    } for user, membership_role in rows]

@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, _admin: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    """Only administrators can provision users or grant roles."""
    if db.scalar(select(User).where(User.username == payload.username)) is not None:
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(username=payload.username, password_hash=hash_password(payload.password),
                role=payload.role, is_active=True)
    db.add(user)
    db.flush()
    workspace_id = db.info.get('workspace_id')
    if workspace_id:
        db.add(WorkspaceMembership(workspace_id=UUID(str(workspace_id)), user_id=user.id, role=user.role, is_active=True))
    try:
        append_audit_entry(db, actor=_admin.username, action="user.created", resource_type="user", resource_id=user.username, details={"role": user.role})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username already exists") from exc
    db.refresh(user)
    return user

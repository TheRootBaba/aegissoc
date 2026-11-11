from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.security import check_login_rate_limit, clear_login_rate_limit, client_rate_limit_key, create_access_token, get_current_user, hash_password, require_roles, verify_password
from app.db.session import get_db
from app.models import User
from app.schemas.auth import CurrentUserRead, LoginRequest, TokenResponse, UserCreate, UserRead

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

@router.get("/me", response_model=CurrentUserRead)
def who_am_i(user: User = Depends(get_current_user)):
    return user

@router.get("/users", response_model=list[UserRead])
def list_users(_admin: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    return list(db.scalars(select(User).order_by(User.username.asc())).all())

@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, _admin: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    """Only administrators can provision users or grant roles."""
    if db.scalar(select(User).where(User.username == payload.username)) is not None:
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(username=payload.username, password_hash=hash_password(payload.password),
                role=payload.role, is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

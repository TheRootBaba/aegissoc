from datetime import datetime
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field
Role = Literal["admin", "analyst", "read_only"]
class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=256)
class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{3,64}$")
    password: str = Field(min_length=12, max_length=256)
    role: Role = "analyst"
class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    username: str
    role: Role
    is_active: bool
    created_at: datetime
class CurrentUserRead(UserRead):
    workspace_role: Role | None = None


class OIDCIdentityCreate(BaseModel):
    subject: str = Field(min_length=1, max_length=255)
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{3,64}$")

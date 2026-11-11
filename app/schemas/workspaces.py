from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

WorkspaceRole = Literal["admin", "analyst", "read_only"]


class WorkspaceCreate(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$", min_length=3, max_length=80)
    name: str = Field(min_length=2, max_length=160)


class WorkspaceMemberCreate(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{3,64}$")
    role: WorkspaceRole = "analyst"


class WorkspaceMemberRead(BaseModel):
    id: UUID
    user_id: UUID
    username: str
    role: WorkspaceRole
    is_active: bool
    created_at: datetime

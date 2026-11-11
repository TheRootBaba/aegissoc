from datetime import datetime
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

class AssetCreate(BaseModel):
    asset_key: str = Field(min_length=2, max_length=160)
    hostname: str = Field(min_length=1, max_length=255)
    asset_type: str = Field(default="server", min_length=2, max_length=32)
    environment: str = Field(default="unknown", max_length=32)
    owner: str | None = Field(default=None, max_length=120)
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    tags: list[str] = Field(default_factory=list, max_length=30)
    notes: str = Field(default="", max_length=4000)

class AssetUpdate(BaseModel):
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    asset_type: str | None = Field(default=None, min_length=2, max_length=32)
    environment: str | None = Field(default=None, max_length=32)
    owner: str | None = Field(default=None, max_length=120)
    criticality: Literal["low", "medium", "high", "critical"] | None = None
    status: Literal["active", "maintenance", "retired"] | None = None
    tags: list[str] | None = Field(default=None, max_length=30)
    notes: str | None = Field(default=None, max_length=4000)

class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    asset_key: str
    hostname: str
    asset_type: str
    environment: str
    owner: str | None
    criticality: str
    status: str
    tags: list[str]
    notes: str
    created_by: str
    created_at: datetime
    updated_at: datetime

class FindingCreate(BaseModel):
    vulnerability_id: str = Field(min_length=3, max_length=64)
    title: str = Field(min_length=3, max_length=200)
    severity: Literal["low", "medium", "high", "critical"]
    source: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=4000)
    due_at: datetime | None = None

class FindingUpdate(BaseModel):
    status: Literal["open", "in_progress", "accepted_risk", "remediated", "false_positive"] | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    due_at: datetime | None = None
    description: str | None = Field(default=None, max_length=4000)

class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    asset_id: UUID
    vulnerability_id: str
    title: str
    severity: str
    status: str
    source: str
    description: str
    discovered_at: datetime
    due_at: datetime | None
    updated_at: datetime

class PlaybookStep(BaseModel):
    title: str = Field(min_length=3, max_length=160)
    required: bool = True

class PlaybookRunCreate(BaseModel):
    case_id: UUID | None = None
    title: str = Field(min_length=3, max_length=160)
    steps: list[PlaybookStep] = Field(min_length=1, max_length=30)

class PlaybookStepUpdate(BaseModel):
    completed: bool

class PlaybookRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    case_id: UUID | None
    title: str
    status: str
    steps: list[dict]
    created_by: str
    created_at: datetime
    updated_at: datetime

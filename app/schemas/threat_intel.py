from datetime import datetime
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator

IndicatorType = Literal["ip", "domain", "hash"]
class IndicatorCreate(BaseModel):
    indicator_type: IndicatorType
    value: str = Field(min_length=3, max_length=255)
    confidence: int = Field(default=50, ge=0, le=100)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    source: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=500)
    tags: list[str] = Field(default_factory=list, max_length=20)
    expires_at: datetime | None = None
    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str) -> str:
        return value.strip().lower()

class IndicatorUpdate(BaseModel):
    confidence: int | None = Field(default=None, ge=0, le=100)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    status: Literal["active", "revoked"] | None = None
    source: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    expires_at: datetime | None = None

class IndicatorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    indicator_type: IndicatorType
    value: str
    confidence: int
    severity: str
    status: str
    source: str
    description: str
    tags: list[str]
    expires_at: datetime | None
    created_by: str
    created_at: datetime
    updated_at: datetime

class IndicatorMatch(BaseModel):
    indicator: IndicatorRead
    event_id: UUID
    event_source: str
    event_type: str
    event_timestamp: datetime

class CorrelatedEntity(BaseModel):
    entity_type: Literal["ip", "host", "user"]
    value: str
    event_count: int
    alert_count: int
    source_count: int
    sources: list[str]
    first_seen: datetime
    last_seen: datetime
    event_ids: list[UUID]
    alert_ids: list[UUID]

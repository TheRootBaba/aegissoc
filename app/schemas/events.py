import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


Severity = Literal["low", "medium", "high", "critical", "info"]


class SecurityEventCreate(BaseModel):
    source: str = Field(min_length=1, max_length=80)
    event_type: str = Field(min_length=1, max_length=120)
    severity: Severity
    timestamp: datetime
    hostname: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=45)
    username: str | None = Field(default=None, max_length=255)
    external_id: str | None = Field(default=None, min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=10000)
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def ensure_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)


class SecurityEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str
    event_type: str
    severity: Severity
    timestamp: datetime
    hostname: str | None
    source_ip: str | None
    username: str | None
    external_id: str | None
    message: str
    raw: dict[str, Any]
    created_at: datetime



class BulkEventIngest(BaseModel):
    """A bounded envelope for partial-success source batch ingestion."""

    events: list[dict[str, Any]] = Field(min_length=1, max_length=500)


class BulkEventResult(BaseModel):
    index: int
    status: Literal["accepted", "duplicate", "rejected"]
    event_id: uuid.UUID | None = None
    error: str | None = None


class BulkEventIngestResponse(BaseModel):
    received: int
    accepted: int
    duplicates: int
    rejected: int
    results: list[BulkEventResult]

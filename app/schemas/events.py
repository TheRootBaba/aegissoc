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


class EventQueryFilter(BaseModel):
    field: Literal[
        "source", "event_type", "severity", "hostname", "source_ip",
        "username", "external_id", "message",
    ]
    operator: Literal[
        "eq", "neq", "contains", "starts_with", "in", "exists",
    ] = "eq"
    value: str | list[str] | bool | None = None

    @field_validator("value")
    @classmethod
    def validate_value(cls, value):
        if isinstance(value, str) and len(value) > 500:
            raise ValueError("filter value must be at most 500 characters")
        if isinstance(value, list):
            if not 1 <= len(value) <= 50 or any(not isinstance(item, str) or len(item) > 255 for item in value):
                raise ValueError("in filters require 1–50 strings of at most 255 characters")
        return value


class InvestigationQuery(BaseModel):
    search: str | None = Field(default=None, max_length=500)
    filters: list[EventQueryFilter] = Field(default_factory=list, max_length=20)
    start_time: datetime | None = None
    end_time: datetime | None = None
    group_by: Literal["source", "event_type", "severity", "hostname", "source_ip", "username"] | None = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)

    @field_validator("start_time", "end_time")
    @classmethod
    def require_timezone(cls, value):
        if value is not None:
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("time boundaries must include a timezone offset")
            return value.astimezone(timezone.utc)
        return value


class InvestigationQueryResult(BaseModel):
    total: int
    limit: int
    offset: int
    events: list[SecurityEventRead]
    aggregations: list[dict[str, Any]] = Field(default_factory=list)


class SavedEventQueryCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    query: InvestigationQuery
    is_shared: bool = False


class SavedEventQueryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    query: dict[str, Any]
    is_shared: bool
    created_by: str
    created_at: datetime
    updated_at: datetime

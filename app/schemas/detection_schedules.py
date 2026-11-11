from datetime import datetime, timezone
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class DetectionScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    interval_seconds: int = Field(default=300, ge=60, le=604800)
    window_minutes: int = Field(default=10, ge=1, le=1440)
    threshold: int = Field(default=5, ge=2, le=100)
    enabled: bool = True


class DetectionScheduleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    interval_seconds: int | None = Field(default=None, ge=60, le=604800)
    window_minutes: int | None = Field(default=None, ge=1, le=1440)
    threshold: int | None = Field(default=None, ge=2, le=100)
    enabled: bool | None = None

    @model_validator(mode="after")
    def reject_null_updates(self):
        if not self.model_fields_set:
            raise ValueError("At least one schedule field must be updated")
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("Schedule update fields cannot be null")
        return self


class DetectionScheduleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    interval_seconds: int
    window_minutes: int
    threshold: int
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    last_status: str | None
    last_error: str | None
    consecutive_failures: int
    created_by: str
    created_at: datetime
    updated_at: datetime

    @field_validator("next_run_at", "last_run_at", "created_at", "updated_at", mode="before")
    @classmethod
    def normalize_utc(cls, value):
        if value is None:
            return value
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class DetectionExecutionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    schedule_id: UUID
    status: str
    started_at: datetime
    completed_at: datetime
    duration_ms: int
    events_evaluated: int
    alerts_created: int
    alerts_updated: int
    rules_evaluated: list[str]
    error: str | None

    @field_validator("started_at", "completed_at", mode="before")
    @classmethod
    def normalize_utc(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

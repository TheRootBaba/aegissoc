import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


AlertStatus = Literal["open", "acknowledged", "in_progress", "resolved", "false_positive"]


class AlertUpdate(BaseModel):
    actor: str = Field(min_length=1, max_length=120)
    status: AlertStatus | None = None
    assigned_to: str | None = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def require_change(self):
        if "status" not in self.model_fields_set and "assigned_to" not in self.model_fields_set:
            raise ValueError("At least one of status or assigned_to must be supplied")
        return self


class AlertNoteCreate(BaseModel):
    author: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1, max_length=10000)


class AlertNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_id: uuid.UUID
    author: str
    body: str
    created_at: datetime


class AlertAuditRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_id: uuid.UUID
    actor: str
    action: str
    details: dict
    created_at: datetime


class AlertDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: str
    fingerprint: str
    title: str
    description: str
    severity: Literal["low", "medium", "high", "critical", "info"]
    status: AlertStatus
    source_ip: str | None
    hostname: str | None
    username: str | None
    event_count: int
    first_seen: datetime
    last_seen: datetime
    evidence_event_ids: list[str]
    assigned_to: str | None
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime

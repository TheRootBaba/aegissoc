import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DetectionRunRequest(BaseModel):
    window_minutes: int = Field(default=10, ge=1, le=1440)
    threshold: int = Field(default=5, ge=2, le=100)


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: str
    fingerprint: str
    title: str
    description: str
    severity: Literal["low", "medium", "high", "critical", "info"]
    status: str
    source_ip: str | None
    hostname: str | None
    username: str | None
    event_count: int
    first_seen: datetime
    last_seen: datetime
    evidence_event_ids: list[str]
    created_at: datetime


class DetectionRunResponse(BaseModel):
    rule_id: str
    rules_evaluated: list[str]
    window_minutes: int
    threshold: int
    events_evaluated: int
    alerts_created: int
    alerts_updated: int
    alerts: list[AlertRead]

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


SourceType = Literal["generic", "wazuh", "syslog", "endpoint", "cloud", "network"]


class SourceCreate(BaseModel):
    source_name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
    display_name: str = Field(min_length=1, max_length=120)
    source_type: SourceType = "generic"
    description: str | None = Field(default=None, max_length=1000)


class SourceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_name: str
    display_name: str
    source_type: str
    description: str | None
    health_status: str
    last_attempt_at: datetime | None
    last_successful_event_at: datetime | None
    accepted_events: int
    duplicate_events: int
    rejected_events: int
    created_at: datetime
    updated_at: datetime

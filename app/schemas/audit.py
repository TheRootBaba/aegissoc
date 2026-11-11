from datetime import datetime, timezone
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator


class SecurityAuditEntryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    sequence: int
    occurred_at: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str | None
    details: dict
    previous_hash: str
    entry_hash: str

    @field_validator("occurred_at", mode="before")
    @classmethod
    def normalize_utc(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class AuditChainVerification(BaseModel):
    valid: bool
    checked_entries: int
    head_sequence: int
    head_hash: str
    first_invalid_sequence: int | None = None
    message: str

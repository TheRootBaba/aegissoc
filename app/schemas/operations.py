from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RetentionPolicyUpdate(BaseModel):
    retention_days: int = Field(ge=1, le=3650)
    enabled: bool
    preserve_active_evidence: bool = True


class RetentionPolicyRead(BaseModel):
    id: UUID
    data_kind: str
    retention_days: int
    enabled: bool
    preserve_active_evidence: bool
    updated_by: str
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OperationalJobRunRead(BaseModel):
    id: UUID
    job_name: str
    status: str
    started_at: datetime
    completed_at: datetime
    records_affected: int
    error_type: str | None
    details: dict

    model_config = ConfigDict(from_attributes=True)

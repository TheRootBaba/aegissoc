from datetime import datetime
from uuid import UUID
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class ResponseActionCreate(BaseModel):
    case_id: UUID | None = None
    connector_key: str = Field(min_length=2, max_length=80)
    action_type: Literal["notify", "block_ip", "disable_user", "isolate_host"]
    target: str = Field(min_length=1, max_length=255)
    parameters: dict = Field(default_factory=dict)

class ResponseActionDecision(BaseModel):
    note: str = Field(min_length=3, max_length=500)

class ResponseActionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    case_id: UUID | None
    connector_key: str
    action_type: str
    target: str
    parameters: dict
    status: str
    requested_by: str
    approved_by: str | None
    decided_by: str | None
    decision_note: str | None
    execution_status: str | None
    response_code: int | None
    result_summary: str | None
    execution_attempts: int
    next_attempt_at: datetime | None
    last_error_type: str | None
    external_reference: str | None
    idempotency_key: str
    created_at: datetime
    decided_at: datetime | None
    executed_at: datetime | None

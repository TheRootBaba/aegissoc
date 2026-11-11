from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

class SigmaImportRequest(BaseModel):
    sigma_yaml: str = Field(min_length=30, max_length=50000)
    enabled: bool = False

class SigmaRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    rule_id: str
    title: str
    description: str
    level: str
    status: str
    enabled: bool
    detection: dict
    condition: str
    logsource: dict
    tags: list
    correlation: dict | None
    created_by: str
    created_at: datetime
    updated_at: datetime

class SigmaTestRequest(BaseModel):
    event: dict

class SigmaTestRead(BaseModel):
    rule_id: str
    matched: bool
    reason: str

class SigmaRunRequest(BaseModel):
    lookback_minutes: int = Field(default=15, ge=1, le=1440)
    limit: int = Field(default=1000, ge=1, le=10000)

class SigmaRunRead(BaseModel):
    rules_evaluated: int
    events_evaluated: int
    matches: int
    alerts_created: int
    alerts_updated: int

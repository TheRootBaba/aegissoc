from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

RuleSeverity = Literal["info", "low", "medium", "high", "critical"]


class DetectionRuleUpdate(BaseModel):
    enabled: bool | None = None
    severity_override: RuleSeverity | None = None
    threshold_override: int | None = Field(default=None, ge=2, le=100)

    @model_validator(mode="after")
    def require_change(self):
        if not self.model_fields_set:
            raise ValueError("At least one rule setting must be supplied")
        return self


class DetectionRuleRead(BaseModel):
    rule_id: str
    title: str
    description: str
    attack_tactic: str
    attack_technique_id: str
    attack_technique_name: str
    enabled: bool
    severity_override: str | None
    threshold_override: int | None
    updated_by: str
    updated_at: datetime

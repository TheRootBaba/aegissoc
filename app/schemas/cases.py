import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CaseStatus = Literal["open", "investigating", "contained", "eradicated", "recovered", "closed"]
CasePriority = Literal["p1", "p2", "p3", "p4"]
CaseSeverity = Literal["low", "medium", "high", "critical"]


class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=12000)
    priority: CasePriority = "p2"
    severity: CaseSeverity = "medium"
    assignee: str | None = Field(default=None, max_length=120)
    tags: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("title")
    @classmethod
    def normalize_title(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Case title must not be blank")
        return value

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(tag.strip().lower() for tag in values if tag.strip()))
        if any(len(tag) > 32 for tag in normalized):
            raise ValueError("Case tags must be 32 characters or fewer")
        return normalized

    @field_validator("assignee")
    @classmethod
    def normalize_assignee(cls, value: str | None) -> str | None:
        return value.strip() or None if value else None


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=12000)
    status: CaseStatus | None = None
    priority: CasePriority | None = None
    severity: CaseSeverity | None = None
    assignee: str | None = Field(default=None, max_length=120)
    tags: list[str] | None = Field(default=None, max_length=20)

    @model_validator(mode="after")
    def require_change(self):
        if not self.model_fields_set:
            raise ValueError("At least one case field must be supplied")
        return self


class CaseNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=10000)

    @field_validator("body")
    @classmethod
    def normalize_body(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Note body must not be blank")
        return value


class CaseRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    case_number: str
    title: str
    description: str
    status: CaseStatus
    priority: CasePriority
    severity: CaseSeverity
    assignee: str | None
    tags: list[str]
    created_by: str
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


class CaseNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    case_id: uuid.UUID
    author: str
    body: str
    created_at: datetime


class CaseAlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    rule_id: str
    title: str
    severity: str
    status: str
    created_at: datetime


class CaseActivityRead(BaseModel):
    actor: str
    action: str
    occurred_at: datetime
    details: dict


class CaseDetail(CaseRead):
    alerts: list[CaseAlertRead]
    notes: list[CaseNoteRead]
    timeline: list[CaseActivityRead]

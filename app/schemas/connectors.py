from datetime import datetime
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

ConnectorType = Literal["wazuh", "syslog", "http_event", "generic", "http_poll", "threat_feed", "wazuh_manager", "misp", "opencti", "response_webhook"]

class ConnectorCreate(BaseModel):
    connector_key: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    connector_type: ConnectorType
    display_name: str = Field(min_length=2, max_length=120)
    config: dict = Field(default_factory=dict)
    credential_ref: str | None = Field(default=None, max_length=255)
    enabled: bool = True

class ConnectorUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=2, max_length=120)
    config: dict | None = None
    credential_ref: str | None = Field(default=None, max_length=255)
    enabled: bool | None = None

class ConnectorRead(BaseModel):
    id: UUID
    connector_key: str
    connector_type: str
    display_name: str
    config: dict
    credential_ref: str | None
    enabled: bool
    health_status: str
    last_checked_at: datetime | None
    last_success_at: datetime | None
    last_error_type: str | None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class ConnectorCheckRead(BaseModel):
    connector_key: str
    health_status: str
    checked_at: datetime
    configuration_valid: bool
    message: str

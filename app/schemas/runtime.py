from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

class ConnectorExecutionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    connector_id: UUID
    status: str
    started_at: datetime
    completed_at: datetime | None
    duration_ms: int
    records_seen: int
    accepted: int
    duplicates: int
    rejected: int
    error_type: str | None

class ScannerFindingInput(BaseModel):
    vulnerability_id: str = Field(min_length=3, max_length=64)
    title: str = Field(min_length=3, max_length=200)
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    description: str = Field(default="", max_length=4000)
    due_at: datetime | None = None

class ScannerAssetInput(BaseModel):
    asset_key: str = Field(min_length=2, max_length=160)
    hostname: str = Field(min_length=1, max_length=255)
    findings: list[ScannerFindingInput] = Field(default_factory=list, max_length=100)

class ScannerImportRequest(BaseModel):
    scanner_name: str = Field(min_length=2, max_length=120)
    scan_id: str = Field(min_length=2, max_length=160)
    assets: list[ScannerAssetInput] = Field(min_length=1, max_length=500)

class ScannerImportRead(BaseModel):
    scan_id: str
    assets_seen: int
    assets_matched: int
    findings_seen: int
    findings_created: int
    findings_updated: int
    findings_rejected: int

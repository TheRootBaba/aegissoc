from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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

    @field_validator("vulnerability_id", "title")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 3:
            raise ValueError("Value must contain at least three non-whitespace characters")
        return value.upper() if cls.__name__ == "ScannerFindingInput" and value.upper().startswith("CVE-") else value

class ScannerAssetInput(BaseModel):
    asset_key: str = Field(min_length=2, max_length=160)
    hostname: str = Field(min_length=1, max_length=255)
    findings: list[ScannerFindingInput] = Field(default_factory=list, max_length=100)

    @field_validator("asset_key", "hostname")
    @classmethod
    def strip_asset_identity(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Asset identity cannot be blank")
        return value

class ScannerImportRequest(BaseModel):
    scanner_name: str = Field(min_length=2, max_length=120)
    scan_id: str = Field(min_length=2, max_length=160)
    assets: list[ScannerAssetInput] = Field(min_length=1, max_length=500)

    @field_validator("scanner_name", "scan_id")
    @classmethod
    def strip_identifiers(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Identifier cannot be blank")
        return value

    @model_validator(mode="after")
    def bound_total_findings(self):
        if sum(len(asset.findings) for asset in self.assets) > 5000:
            raise ValueError("A scanner import is limited to 5,000 findings")
        return self

class ScannerImportRead(BaseModel):
    scan_id: str
    assets_seen: int
    assets_matched: int
    findings_seen: int
    findings_created: int
    findings_updated: int
    findings_rejected: int

from datetime import datetime, timezone
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.security import get_current_user, require_roles
from app.db.session import get_db
from app.models import IncidentCase, ManagedAsset, ResponsePlaybookRun, User, VulnerabilityFinding, ScannerImportRun
from app.schemas.asset_risk import (
    AssetCreate, AssetRead, AssetUpdate, FindingCreate, FindingRead, FindingUpdate,
    PlaybookRunCreate, PlaybookRunRead, PlaybookStepUpdate,
)
from app.services.audit_chain import append_audit_entry
from app.schemas.runtime import ScannerImportRequest, ScannerImportRead

router = APIRouter(
    prefix="/api/v1/asset-risk",
    tags=["asset-risk-and-response-playbooks"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))],
)

def _audit(db: Session, user: User, action: str, kind: str, identifier: str, details: dict) -> None:
    append_audit_entry(db, actor=user.username, action=action, resource_type=kind,
                       resource_id=identifier, details=details)

@router.get("/assets", response_model=list[AssetRead])
def list_assets(
    search: str | None = Query(default=None, min_length=1, max_length=160),
    status_filter: str | None = Query(default=None, alias="status", pattern="^(active|maintenance|retired)$"),
    criticality: str | None = Query(default=None, pattern="^(low|medium|high|critical)$"),
    limit: int = Query(default=100, ge=1, le=200),
    db: Session = Depends(get_db),
):
    statement = select(ManagedAsset)
    if search:
        term = "%" + search.strip() + "%"
        statement = statement.where(ManagedAsset.asset_key.ilike(term) | ManagedAsset.hostname.ilike(term))
    if status_filter:
        statement = statement.where(ManagedAsset.status == status_filter)
    if criticality:
        statement = statement.where(ManagedAsset.criticality == criticality)
    return list(db.scalars(statement.order_by(ManagedAsset.updated_at.desc()).limit(limit)).all())

@router.post("/assets", response_model=AssetRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def create_asset(payload: AssetCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    key = payload.asset_key.strip().lower()
    if db.scalar(select(ManagedAsset).where(ManagedAsset.asset_key == key)):
        raise HTTPException(409, "Asset key already exists")
    asset = ManagedAsset(
        asset_key=key, hostname=payload.hostname.strip(), asset_type=payload.asset_type.strip().lower(),
        environment=payload.environment.strip().lower(), owner=payload.owner.strip() if payload.owner else None,
        criticality=payload.criticality, tags=list(dict.fromkeys(x.strip().lower() for x in payload.tags if x.strip())),
        notes=payload.notes.strip(), created_by=user.username,
    )
    db.add(asset)
    db.flush()
    _audit(db, user, "asset.created", "managed_asset", str(asset.id),
           {"asset_key": asset.asset_key, "criticality": asset.criticality})
    db.commit()
    db.refresh(asset)
    return asset

@router.patch("/assets/{asset_id}", response_model=AssetRead,
              dependencies=[Depends(require_roles("admin", "analyst"))])
def update_asset(asset_id: UUID, payload: AssetUpdate, db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    asset = db.get(ManagedAsset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    changes = {}
    for field in payload.model_fields_set:
        value = getattr(payload, field)
        if value is None:
            continue
        if field in {"hostname", "asset_type", "environment", "owner", "notes"}:
            value = value.strip() if value else None
        if field == "tags":
            value = list(dict.fromkeys(x.strip().lower() for x in value if x.strip()))
        previous = getattr(asset, field)
        if previous != value:
            changes[field] = {"from": previous, "to": value}
            setattr(asset, field, value)
    if changes:
        asset.updated_at = datetime.now(timezone.utc)
        _audit(db, user, "asset.updated", "managed_asset", str(asset.id), changes)
        db.commit()
        db.refresh(asset)
    return asset

@router.get("/assets/{asset_id}/findings", response_model=list[FindingRead])
def list_findings(asset_id: UUID, db: Session = Depends(get_db)):
    if db.get(ManagedAsset, asset_id) is None:
        raise HTTPException(404, "Asset not found")
    return list(db.scalars(select(VulnerabilityFinding).where(
        VulnerabilityFinding.asset_id == asset_id
    ).order_by(VulnerabilityFinding.discovered_at.desc()).limit(200)).all())

@router.post("/assets/{asset_id}/findings", response_model=FindingRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def create_finding(asset_id: UUID, payload: FindingCreate, db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    asset = db.get(ManagedAsset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    vuln_id = payload.vulnerability_id.strip().upper()
    if db.scalar(select(VulnerabilityFinding).where(
        VulnerabilityFinding.asset_id == asset_id, VulnerabilityFinding.vulnerability_id == vuln_id
    )):
        raise HTTPException(409, "This vulnerability is already recorded for the asset")
    finding = VulnerabilityFinding(
        asset_id=asset_id, vulnerability_id=vuln_id, title=payload.title.strip(),
        severity=payload.severity, source=payload.source.strip(),
        description=payload.description.strip(), due_at=payload.due_at,
    )
    db.add(finding)
    db.flush()
    _audit(db, user, "vulnerability.created", "vulnerability_finding", str(finding.id),
           {"asset_id": str(asset_id), "vulnerability_id": vuln_id, "severity": finding.severity})
    db.commit()
    db.refresh(finding)
    return finding

@router.patch("/findings/{finding_id}", response_model=FindingRead,
              dependencies=[Depends(require_roles("admin", "analyst"))])
def update_finding(finding_id: UUID, payload: FindingUpdate, db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    finding = db.get(VulnerabilityFinding, finding_id)
    if finding is None:
        raise HTTPException(404, "Vulnerability finding not found")
    changes = {}
    for field in payload.model_fields_set:
        value = getattr(payload, field)
        previous = getattr(finding, field)
        if previous != value:
            changes[field] = {"from": previous.isoformat() if hasattr(previous, "isoformat") else previous,
                              "to": value.isoformat() if hasattr(value, "isoformat") else value}
            setattr(finding, field, value)
    if changes:
        finding.updated_at = datetime.now(timezone.utc)
        _audit(db, user, "vulnerability.updated", "vulnerability_finding", str(finding.id), changes)
        db.commit()
        db.refresh(finding)
    return finding

@router.get("/playbooks", response_model=list[PlaybookRunRead])
def list_playbook_runs(
    status_filter: str | None = Query(default=None, alias="status", pattern="^(in_progress|completed)$"),
    case_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=200),
    db: Session = Depends(get_db),
):
    statement = select(ResponsePlaybookRun)
    if status_filter:
        statement = statement.where(ResponsePlaybookRun.status == status_filter)
    if case_id:
        statement = statement.where(ResponsePlaybookRun.case_id == case_id)
    return list(db.scalars(statement.order_by(ResponsePlaybookRun.updated_at.desc()).limit(limit)).all())

@router.post("/playbooks", response_model=PlaybookRunRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def create_playbook_run(payload: PlaybookRunCreate, db: Session = Depends(get_db),
                        user: User = Depends(get_current_user)):
    if payload.case_id and db.get(IncidentCase, payload.case_id) is None:
        raise HTTPException(404, "Incident case not found")
    steps = [{"title": step.title.strip(), "required": step.required, "completed": False,
              "completed_by": None, "completed_at": None} for step in payload.steps]
    run = ResponsePlaybookRun(case_id=payload.case_id, title=payload.title.strip(),
                              steps=steps, created_by=user.username)
    db.add(run)
    db.flush()
    _audit(db, user, "playbook.started", "response_playbook_run", str(run.id),
           {"case_id": str(payload.case_id) if payload.case_id else None, "step_count": len(steps)})
    db.commit()
    db.refresh(run)
    return run

@router.patch("/playbooks/{run_id}/steps/{step_index}", response_model=PlaybookRunRead,
              dependencies=[Depends(require_roles("admin", "analyst"))])
def update_playbook_step(run_id: UUID, step_index: int, payload: PlaybookStepUpdate,
                         db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    run = db.get(ResponsePlaybookRun, run_id)
    if run is None:
        raise HTTPException(404, "Playbook run not found")
    if step_index < 0 or step_index >= len(run.steps):
        raise HTTPException(404, "Playbook step not found")
    steps = [dict(step) for step in run.steps]
    step = steps[step_index]
    step["completed"] = payload.completed
    step["completed_by"] = user.username if payload.completed else None
    step["completed_at"] = datetime.now(timezone.utc).isoformat() if payload.completed else None
    run.steps = steps
    run.status = "completed" if all((not item.get("required", True)) or item["completed"] for item in steps) else "in_progress"
    run.updated_at = datetime.now(timezone.utc)
    _audit(db, user, "playbook.step_updated", "response_playbook_run", str(run.id),
           {"step_index": step_index, "completed": payload.completed, "status": run.status})
    db.commit()
    db.refresh(run)
    return run


@router.post("/scanner-imports", response_model=ScannerImportRead,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def import_scanner_results(payload: ScannerImportRequest, db: Session = Depends(get_db),
                           user: User = Depends(get_current_user)):
    total_findings = sum(len(asset.findings) for asset in payload.assets)
    if total_findings > 5000:
        raise HTTPException(422, "A scanner import is limited to 5,000 findings")
    previous = db.scalar(select(ScannerImportRun).where(
        ScannerImportRun.scanner_name == payload.scanner_name.strip(),
        ScannerImportRun.scan_id == payload.scan_id.strip(),
    ))
    if previous is not None:
        return previous.result

    assets_seen = len(payload.assets)
    assets_matched = findings_seen = findings_created = findings_updated = findings_rejected = 0
    for scanned_asset in payload.assets:
        asset = db.scalar(select(ManagedAsset).where(
            ManagedAsset.asset_key == scanned_asset.asset_key.strip().lower()
        ))
        if asset is None:
            findings_rejected += len(scanned_asset.findings)
            continue
        assets_matched += 1
        for item in scanned_asset.findings:
            findings_seen += 1
            vuln_id = item.vulnerability_id.strip().upper()
            finding = db.scalar(select(VulnerabilityFinding).where(
                VulnerabilityFinding.asset_id == asset.id,
                VulnerabilityFinding.vulnerability_id == vuln_id,
            ))
            if finding is None:
                db.add(VulnerabilityFinding(
                    asset_id=asset.id, vulnerability_id=vuln_id, title=item.title.strip(),
                    severity=item.severity, source=payload.scanner_name.strip(),
                    description=item.description.strip(), due_at=item.due_at,
                ))
                findings_created += 1
            else:
                finding.title = item.title.strip()
                finding.severity = item.severity
                finding.source = payload.scanner_name.strip()
                finding.description = item.description.strip()
                finding.due_at = item.due_at
                if finding.status in {"remediated", "false_positive"}:
                    finding.status = "open"
                finding.updated_at = datetime.now(timezone.utc)
                findings_updated += 1

    result = {
        "scan_id": payload.scan_id, "assets_seen": assets_seen, "assets_matched": assets_matched,
        "findings_seen": findings_seen, "findings_created": findings_created,
        "findings_updated": findings_updated, "findings_rejected": findings_rejected,
    }
    db.add(ScannerImportRun(
        scanner_name=payload.scanner_name.strip(), scan_id=payload.scan_id.strip(),
        result=result, created_by=user.username,
    ))
    db.flush()
    append_audit_entry(db, actor=user.username, action="vulnerability.scan_imported",
        resource_type="scanner_import", resource_id=payload.scanner_name.strip() + ":" + payload.scan_id.strip(),
        details={key: value for key, value in result.items() if key != "scan_id"})
    db.commit()
    return result

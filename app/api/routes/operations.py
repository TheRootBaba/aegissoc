from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import get_current_user, require_roles
from app.db.session import get_db
from app.models import (
    ConnectorConfig, DetectionAlert, DetectionExecution, DetectionSchedule, OperationalJobRun,
    RetentionPolicy, SecurityEvent, SourceRegistry, User,
)
from app.schemas.operations import OperationalJobRunRead, RetentionPolicyRead, RetentionPolicyUpdate
from app.services.audit_chain import append_audit_entry
from app.services.retention import run_retention_cleanup

router = APIRouter(
    prefix="/api/v1/operations",
    tags=["operations and retention"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))],
)


@router.get("/health")
def operations_health(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    recent_cutoff = now - timedelta(minutes=15)
    source_rows = db.execute(
        select(SourceRegistry.health_status, func.count()).group_by(SourceRegistry.health_status)
    ).all()
    failing_schedules = db.scalar(
        select(func.count()).select_from(DetectionSchedule).where(
            DetectionSchedule.enabled.is_(True),
            DetectionSchedule.consecutive_failures > 0,
        )
    ) or 0
    latest_retention = db.scalar(
        select(OperationalJobRun).where(
            OperationalJobRun.job_name == "retention_cleanup"
        ).order_by(OperationalJobRun.completed_at.desc()).limit(1)
    )
    recent_events = db.scalar(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.created_at >= recent_cutoff)
    ) or 0
    connector_rows = db.execute(
        select(ConnectorConfig.health_status, func.count()).group_by(ConnectorConfig.health_status)
    ).all()
    return {
        "status": "degraded" if failing_schedules or any(state in ("failing", "misconfigured") for state, _ in source_rows + connector_rows) else "operational",
        "checked_at": now,
        "sources": {state: count for state, count in source_rows},
        "connectors": {state: count for state, count in connector_rows},
        "enabled_schedules_with_failures": failing_schedules,
        "events_last_15_minutes": recent_events,
        "retention": {
            "last_run_at": latest_retention.completed_at if latest_retention else None,
            "last_status": latest_retention.status if latest_retention else "never_run",
            "records_affected": latest_retention.records_affected if latest_retention else 0,
        },
    }


@router.get("/metrics")
def operations_metrics(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    since_hour = now - timedelta(hours=1)
    since_day = now - timedelta(hours=24)
    return {
        "collected_at": now,
        "events": {
            "total": db.scalar(select(func.count()).select_from(SecurityEvent)) or 0,
            "last_hour": db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.created_at >= since_hour)) or 0,
            "last_24_hours": db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.created_at >= since_day)) or 0,
        },
        "alerts": {
            "open": db.scalar(select(func.count()).select_from(DetectionAlert).where(DetectionAlert.status == "open")) or 0,
        },
        "detection_executions": {
            "last_24_hours": db.scalar(select(func.count()).select_from(DetectionExecution).where(DetectionExecution.started_at >= since_day)) or 0,
            "failed_last_24_hours": db.scalar(select(func.count()).select_from(DetectionExecution).where(DetectionExecution.started_at >= since_day, DetectionExecution.status == "failed")) or 0,
        },
        "ingestion": {
            "accepted_total": db.scalar(select(func.coalesce(func.sum(SourceRegistry.accepted_events), 0))) or 0,
            "duplicate_total": db.scalar(select(func.coalesce(func.sum(SourceRegistry.duplicate_events), 0))) or 0,
            "rejected_total": db.scalar(select(func.coalesce(func.sum(SourceRegistry.rejected_events), 0))) or 0,
        },
    }


@router.get("/retention", response_model=list[RetentionPolicyRead])
def list_retention_policies(db: Session = Depends(get_db)):
    return list(db.scalars(select(RetentionPolicy).order_by(RetentionPolicy.data_kind.asc())).all())


@router.put("/retention/{data_kind}", response_model=RetentionPolicyRead)
def update_retention_policy(
    data_kind: str,
    payload: RetentionPolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    policy = db.scalar(select(RetentionPolicy).where(RetentionPolicy.data_kind == data_kind))
    if policy is None:
        raise HTTPException(status_code=404, detail="Retention policy not found")
    before = {
        "retention_days": policy.retention_days,
        "enabled": policy.enabled,
        "preserve_active_evidence": policy.preserve_active_evidence,
    }
    for key, value in payload.model_dump().items():
        setattr(policy, key, value)
    policy.updated_by = current_user.username
    append_audit_entry(
        db, actor=current_user.username, action="retention.policy_updated",
        resource_type="retention_policy", resource_id=data_kind,
        details={"before": before, "after": payload.model_dump()},
    )
    db.commit()
    db.refresh(policy)
    return policy


@router.post("/retention/run")
def run_retention(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    try:
        result = run_retention_cleanup(db)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Retention cleanup failed ({type(exc).__name__})") from exc
    append_audit_entry(
        db, actor=current_user.username, action="retention.cleanup_requested",
        resource_type="retention_job", resource_id=None,
        details={"status": result["status"], "records_affected": result["records_affected"]},
    )
    db.commit()
    return result


@router.get("/jobs", response_model=list[OperationalJobRunRead])
def list_operational_jobs(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    return list(db.scalars(
        select(OperationalJobRun).order_by(OperationalJobRun.completed_at.desc()).limit(limit)
    ).all())

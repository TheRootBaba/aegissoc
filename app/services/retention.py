"""Bounded retention cleanup that protects evidence for active investigations."""

from datetime import datetime, timedelta, timezone
from time import perf_counter
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    DetectionAlert, DetectionExecution, OperationalJobRun, RetentionPolicy,
    SecurityEvent,
)

ACTIVE_ALERT_STATES = ("open", "acknowledged", "in_progress")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def run_retention_cleanup(
    db: Session, *, now: datetime | None = None, batch_size: int = 1000,
) -> dict:
    """Delete only expired rows, in bounded batches, while retaining live evidence.

    Event IDs referenced by non-terminal alerts are excluded from deletion.
    The newest execution for every schedule is retained regardless of age so
    the schedule workspace never loses its last known outcome.
    """
    started = _utc(now or datetime.now(timezone.utc))
    timer = perf_counter()
    affected = {"events": 0, "executions": 0, "jobs": 0}
    try:
        policies = {
            policy.data_kind: policy
            for policy in db.scalars(select(RetentionPolicy)).all()
        }

        event_policy = policies.get("events")
        if event_policy and event_policy.enabled:
            protected_ids: set[str] = set()
            if event_policy.preserve_active_evidence:
                active_alerts = db.scalars(
                    select(DetectionAlert.evidence_event_ids).where(
                        DetectionAlert.status.in_(ACTIVE_ALERT_STATES)
                    )
                ).all()
                for evidence_ids in active_alerts:
                    protected_ids.update(str(item) for item in (evidence_ids or []))

            cutoff = started - timedelta(days=event_policy.retention_days)
            protected_uuid_ids = set()
            for value in protected_ids:
                try:
                    protected_uuid_ids.add(UUID(value))
                except (ValueError, TypeError):
                    continue
            event_statement = select(SecurityEvent.id).where(SecurityEvent.timestamp < cutoff)
            if protected_uuid_ids:
                event_statement = event_statement.where(SecurityEvent.id.not_in(protected_uuid_ids))
            expired_ids = list(db.scalars(
                event_statement.order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc()).limit(batch_size)
            ).all())
            if expired_ids:
                affected["events"] = db.query(SecurityEvent).filter(
                    SecurityEvent.id.in_(expired_ids)
                ).delete(synchronize_session=False)

        execution_policy = policies.get("executions")
        if execution_policy and execution_policy.enabled:
            cutoff = started - timedelta(days=execution_policy.retention_days)
            # Preserve the most recent run by timestamp, not by UUID ordering.
            latest_rows = db.execute(
                select(DetectionExecution.schedule_id, func.max(DetectionExecution.completed_at))
                .group_by(DetectionExecution.schedule_id)
            ).all()
            latest_pairs = {(schedule_id, completed_at) for schedule_id, completed_at in latest_rows}
            candidates = db.scalars(
                select(DetectionExecution)
                .where(DetectionExecution.completed_at < cutoff)
                .order_by(DetectionExecution.completed_at.asc())
                .limit(batch_size)
            ).all()
            stale_ids = [
                run.id for run in candidates
                if (run.schedule_id, run.completed_at) not in latest_pairs
            ]
            if stale_ids:
                affected["executions"] = db.query(DetectionExecution).filter(
                    DetectionExecution.id.in_(stale_ids)
                ).delete(synchronize_session=False)

        jobs_policy = policies.get("jobs")
        if jobs_policy and jobs_policy.enabled:
            cutoff = started - timedelta(days=jobs_policy.retention_days)
            expired_job_ids = list(db.scalars(
                select(OperationalJobRun.id)
                .where(OperationalJobRun.completed_at < cutoff)
                .order_by(OperationalJobRun.completed_at.asc())
                .limit(batch_size)
            ).all())
            if expired_job_ids:
                affected["jobs"] = db.query(OperationalJobRun).filter(
                    OperationalJobRun.id.in_(expired_job_ids)
                ).delete(synchronize_session=False)

        completed = datetime.now(timezone.utc)
        total = sum(affected.values())
        db.add(OperationalJobRun(
            job_name="retention_cleanup", status="success",
            started_at=started, completed_at=completed,
            records_affected=total, error_type=None, details=affected,
        ))
        db.commit()
        return {
            "status": "success", "records_affected": total,
            "by_dataset": affected,
            "duration_ms": max(0, int((perf_counter() - timer) * 1000)),
        }
    except Exception as exc:
        db.rollback()
        completed = datetime.now(timezone.utc)
        db.add(OperationalJobRun(
            job_name="retention_cleanup", status="failed",
            started_at=started, completed_at=completed,
            records_affected=sum(affected.values()),
            error_type=type(exc).__name__,
            details={"partial_counts": affected},
        ))
        db.commit()
        raise

"""Lease-based scheduler for durable recurring detection runs."""

import logging
from datetime import datetime, timedelta, timezone
from time import perf_counter

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import DetectionExecution, DetectionSchedule
from app.services.detection_engine import run_ssh_brute_force_detection
from app.services.audit_chain import append_audit_entry

logger = logging.getLogger("aegissoc.scheduler")
LEASE_MINUTES = 15
MAX_RETRY_DELAY_SECONDS = 300


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def run_due_schedules_once(
    db: Session, *, now: datetime | None = None, batch_size: int = 10,
) -> int:
    """Claim and execute a bounded batch of due schedules.

    PostgreSQL row locks with SKIP LOCKED prevent multiple worker replicas from
    claiming the same schedule. The persisted lease lets another worker recover
    a schedule if its original worker dies before recording completion.
    """
    run_at = _utc(now or datetime.now(timezone.utc))
    statement = (
        select(DetectionSchedule)
        .where(
            DetectionSchedule.enabled.is_(True),
            DetectionSchedule.next_run_at <= run_at,
            or_(DetectionSchedule.locked_until.is_(None), DetectionSchedule.locked_until <= run_at),
        )
        .order_by(DetectionSchedule.next_run_at.asc(), DetectionSchedule.id.asc())
        .limit(batch_size)
    )
    if db.get_bind().dialect.name == "postgresql":
        statement = statement.with_for_update(skip_locked=True)

    claimed = list(db.scalars(statement).all())
    schedule_ids = [schedule.id for schedule in claimed]
    for schedule in claimed:
        schedule.locked_until = run_at + timedelta(minutes=LEASE_MINUTES)
    if claimed:
        db.commit()

    completed_count = 0
    for schedule_id in schedule_ids:
        schedule = db.get(DetectionSchedule, schedule_id)
        if schedule is None or not schedule.enabled:
            if schedule is not None:
                schedule.locked_until = None
                db.commit()
            continue

        started_at = datetime.now(timezone.utc)
        timer = perf_counter()
        try:
            result = run_ssh_brute_force_detection(
                db, window_minutes=schedule.window_minutes,
                threshold=schedule.threshold, now=run_at, commit=False,
            )
            completed_at = datetime.now(timezone.utc)
            schedule = db.get(DetectionSchedule, schedule_id)
            if schedule is None:
                continue
            schedule.last_run_at = started_at
            schedule.next_run_at = completed_at + timedelta(seconds=schedule.interval_seconds)
            schedule.last_status = "success"
            schedule.last_error = None
            schedule.consecutive_failures = 0
            schedule.locked_until = None
            db.add(DetectionExecution(
                schedule_id=schedule_id, status="success",
                started_at=started_at, completed_at=completed_at,
                duration_ms=max(0, int((perf_counter() - timer) * 1000)),
                events_evaluated=result["events_evaluated"],
                alerts_created=result["alerts_created"],
                alerts_updated=result["alerts_updated"],
                rules_evaluated=result["rules_evaluated"],
                error=None,
            ))
            append_audit_entry(db, actor="scheduler", action="detection.schedule_executed", resource_type="detection_schedule", resource_id=str(schedule_id), details={
                "status": "success", "schedule_owner": schedule.created_by,
                "events_evaluated": result["events_evaluated"], "alerts_created": result["alerts_created"],
                "alerts_updated": result["alerts_updated"], "rules_evaluated": result["rules_evaluated"],
            })
            db.commit()
            completed_count += 1
        except Exception as exc:  # keep one bad schedule from stopping the worker
            db.rollback()
            schedule = db.get(DetectionSchedule, schedule_id)
            if schedule is None:
                continue
            completed_at = datetime.now(timezone.utc)
            schedule.consecutive_failures += 1
            retry_delay = min(
                60 * (2 ** min(schedule.consecutive_failures - 1, 8)),
                MAX_RETRY_DELAY_SECONDS,
                schedule.interval_seconds,
            )
            schedule.next_run_at = completed_at + timedelta(seconds=retry_delay)
            schedule.last_run_at = started_at
            schedule.last_status = "failed"
            # Store the exception class, not raw exception text that may contain
            # query values, connection details, or other sensitive information.
            schedule.last_error = f"Detection execution failed ({type(exc).__name__})"
            schedule.locked_until = None
            db.add(DetectionExecution(
                schedule_id=schedule_id, status="failed",
                started_at=started_at, completed_at=completed_at,
                duration_ms=max(0, int((perf_counter() - timer) * 1000)),
                events_evaluated=0, alerts_created=0, alerts_updated=0,
                rules_evaluated=[], error=schedule.last_error,
            ))
            append_audit_entry(db, actor="scheduler", action="detection.schedule_failed", resource_type="detection_schedule", resource_id=str(schedule_id), details={
                "schedule_owner": schedule.created_by, "error_type": type(exc).__name__,
                "consecutive_failures": schedule.consecutive_failures,
            })
            db.commit()
            logger.error("scheduled_detection_failed schedule_id=%s error_type=%s", schedule_id, type(exc).__name__)
    return completed_count

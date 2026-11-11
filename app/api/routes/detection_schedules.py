from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import get_current_user, require_roles
from app.db.session import get_db
from app.models import DetectionExecution, DetectionSchedule, User
from app.schemas.detection_schedules import (
    DetectionExecutionRead, DetectionScheduleCreate, DetectionScheduleRead,
    DetectionScheduleUpdate,
)

router = APIRouter(
    prefix="/api/v1/detection-schedules",
    tags=["detection schedules"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))],
)


def _get_schedule(db: Session, schedule_id: UUID) -> DetectionSchedule:
    schedule = db.get(DetectionSchedule, schedule_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="Detection schedule not found")
    return schedule


@router.get("", response_model=list[DetectionScheduleRead])
def list_schedules(db: Session = Depends(get_db)):
    return list(db.scalars(
        select(DetectionSchedule).order_by(DetectionSchedule.next_run_at.asc())
    ).all())


@router.post("", response_model=DetectionScheduleRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin"))])
def create_schedule(payload: DetectionScheduleCreate, db: Session = Depends(get_db),
                    current_user: User = Depends(get_current_user)):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Schedule name cannot be blank")
    now = datetime.now(timezone.utc)
    schedule = DetectionSchedule(
        name=name, interval_seconds=payload.interval_seconds,
        window_minutes=payload.window_minutes, threshold=payload.threshold,
        enabled=payload.enabled,
        next_run_at=now + timedelta(seconds=payload.interval_seconds),
        created_by=current_user.username,
    )
    db.add(schedule)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="You already have a schedule with this name") from exc
    db.refresh(schedule)
    return schedule


@router.patch("/{schedule_id}", response_model=DetectionScheduleRead,
              dependencies=[Depends(require_roles("admin"))])
def update_schedule(schedule_id: UUID, payload: DetectionScheduleUpdate,
                    db: Session = Depends(get_db)):
    schedule = _get_schedule(db, schedule_id)
    changes = payload.model_dump(exclude_unset=True)
    if "name" in changes:
        changes["name"] = changes["name"].strip()
        if not changes["name"]:
            raise HTTPException(status_code=422, detail="Schedule name cannot be blank")
    for field, value in changes.items():
        setattr(schedule, field, value)
    if "interval_seconds" in changes or ("enabled" in changes and changes["enabled"]):
        schedule.next_run_at = datetime.now(timezone.utc) + timedelta(seconds=schedule.interval_seconds)
    if changes.get("enabled") is False:
        schedule.locked_until = None
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="You already have a schedule with this name") from exc
    db.refresh(schedule)
    return schedule


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require_roles("admin"))])
def delete_schedule(schedule_id: UUID, db: Session = Depends(get_db)):
    schedule = _get_schedule(db, schedule_id)
    db.delete(schedule)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{schedule_id}/executions", response_model=list[DetectionExecutionRead])
def list_schedule_executions(
    schedule_id: UUID,
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    _get_schedule(db, schedule_id)
    return list(db.scalars(
        select(DetectionExecution)
        .where(DetectionExecution.schedule_id == schedule_id)
        .order_by(DetectionExecution.started_at.desc(), DetectionExecution.id.desc())
        .limit(limit)
    ).all())

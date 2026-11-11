from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.db.session import get_db
from app.models import DetectionAlert
from app.schemas.detections import AlertRead, DetectionRunRequest, DetectionRunResponse
from app.services.detection_engine import run_ssh_brute_force_detection

router = APIRouter(tags=["detections", "alerts"],
                   dependencies=[Depends(require_roles("admin", "analyst", "read_only"))])


@router.post("/api/v1/detections/run", response_model=DetectionRunResponse,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def run_detections(request: DetectionRunRequest, db: Session = Depends(get_db)):
    return run_ssh_brute_force_detection(db, window_minutes=request.window_minutes, threshold=request.threshold)


@router.get("/api/v1/alerts/stats")
def alert_stats(db: Session = Depends(get_db)):
    total = db.scalar(select(func.count()).select_from(DetectionAlert)) or 0
    status_rows = db.execute(select(DetectionAlert.status, func.count()).group_by(DetectionAlert.status)).all()
    severity_rows = db.execute(select(DetectionAlert.severity, func.count()).group_by(DetectionAlert.severity)).all()
    return {"total_alerts": total, "by_status": {key: count for key, count in status_rows},
            "by_severity": {key: count for key, count in severity_rows}}


@router.get("/api/v1/alerts", response_model=list[AlertRead])
def list_alerts(
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical|info)$"),
    status_filter: str | None = Query(default=None, alias="status", pattern="^(open|acknowledged|in_progress|resolved|false_positive)$"),
    rule_id: str | None = Query(default=None, min_length=1, max_length=64),
    attack_technique_id: str | None = Query(default=None, min_length=1, max_length=32),
    assigned_to: str | None = Query(default=None, min_length=1, max_length=120),
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    statement = select(DetectionAlert)
    for column, value in ((DetectionAlert.severity, severity), (DetectionAlert.status, status_filter),
                          (DetectionAlert.rule_id, rule_id), (DetectionAlert.attack_technique_id, attack_technique_id),
                          (DetectionAlert.assigned_to, assigned_to)):
        if value is not None:
            statement = statement.where(column == value)
    statement = statement.order_by(DetectionAlert.created_at.desc(), DetectionAlert.id.desc()).offset(offset).limit(limit)
    return list(db.scalars(statement).all())

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import DetectionAlert
from app.schemas.detections import AlertRead, DetectionRunRequest, DetectionRunResponse
from app.services.detection_engine import run_ssh_brute_force_detection

router = APIRouter(tags=["detections", "alerts"])


@router.post("/api/v1/detections/run", response_model=DetectionRunResponse)
def run_detections(
    request: DetectionRunRequest,
    db: Session = Depends(get_db),
):
    """Run enabled deterministic detection rules on stored events."""
    return run_ssh_brute_force_detection(
        db,
        window_minutes=request.window_minutes,
        threshold=request.threshold,
    )


@router.get("/api/v1/alerts", response_model=list[AlertRead])
def list_alerts(
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical|info)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """List generated alerts newest first with optional severity filtering."""
    statement = select(DetectionAlert)
    if severity is not None:
        statement = statement.where(DetectionAlert.severity == severity)
    statement = statement.order_by(
        DetectionAlert.created_at.desc(),
        DetectionAlert.id.desc(),
    ).offset(offset).limit(limit)
    return list(db.scalars(statement).all())

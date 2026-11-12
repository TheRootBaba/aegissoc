from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.db.session import get_db
from app.models import ConnectorConfig, ConnectorExecution, ConnectorRuntimeState, User
from app.schemas.connectors import ConnectorCheckRead, ConnectorCreate, ConnectorRead, ConnectorUpdate
from app.services.audit_chain import append_audit_entry
from app.services.integrations import get_adapter
from app.schemas.runtime import ConnectorExecutionRead

router = APIRouter(
    prefix="/api/v1/connectors",
    tags=["integration connectors"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))],
)


def _check(connector: ConnectorConfig):
    adapter = get_adapter(connector.connector_type)
    config = dict(connector.config or {})
    if connector.credential_ref:
        config["credential_ref"] = connector.credential_ref
    return adapter.validate_config(config)


@router.get("", response_model=list[ConnectorRead])
def list_connectors(db: Session = Depends(get_db)):
    connectors = list(db.scalars(
        select(ConnectorConfig).order_by(ConnectorConfig.connector_key.asc())
    ).all())
    if not connectors:
        return []

    connector_ids = [connector.id for connector in connectors]
    latest_rows = select(
        ConnectorExecution.connector_id.label("connector_id"),
        ConnectorExecution.status.label("status"),
        ConnectorExecution.completed_at.label("completed_at"),
        ConnectorExecution.started_at.label("started_at"),
        func.row_number().over(
            partition_by=ConnectorExecution.connector_id,
            order_by=(
                ConnectorExecution.completed_at.desc().nulls_last(),
                ConnectorExecution.started_at.desc(),
            ),
        ).label("position"),
    ).where(ConnectorExecution.connector_id.in_(connector_ids)).subquery()
    latest = {
        row.connector_id: row
        for row in db.execute(select(latest_rows).where(latest_rows.c.position == 1))
    }

    success_rows = select(
        ConnectorExecution.connector_id.label("connector_id"),
        ConnectorExecution.completed_at.label("completed_at"),
        func.row_number().over(
            partition_by=ConnectorExecution.connector_id,
            order_by=ConnectorExecution.completed_at.desc(),
        ).label("position"),
    ).where(
        ConnectorExecution.connector_id.in_(connector_ids),
        ConnectorExecution.status.in_({"success", "partial"}),
        ConnectorExecution.completed_at.is_not(None),
    ).subquery()
    latest_success = {
        row.connector_id: row
        for row in db.execute(select(success_rows).where(success_rows.c.position == 1))
    }

    result = []
    for connector in connectors:
        data = ConnectorRead.model_validate(connector).model_dump()
        latest_execution = latest.get(connector.id)
        successful_execution = latest_success.get(connector.id)
        if data["last_success_at"] is None and successful_execution is not None:
            data["last_success_at"] = successful_execution.completed_at
        if data["last_checked_at"] is None and latest_execution is not None:
            data["last_checked_at"] = latest_execution.completed_at or latest_execution.started_at
        if connector.enabled and connector.health_status == "unverified" and latest_execution is not None:
            if latest_execution.status == "success":
                data["health_status"] = "observed"
            elif latest_execution.status in {"partial", "failed"}:
                data["health_status"] = "degraded"
        result.append(data)
    return result


@router.post("", response_model=ConnectorRead, status_code=status.HTTP_201_CREATED)
def create_connector(
    payload: ConnectorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    adapter = get_adapter(payload.connector_type)
    config = dict(payload.config)
    if payload.credential_ref:
        config["credential_ref"] = payload.credential_ref
    validation = adapter.validate_config(config)
    if not validation.valid:
        raise HTTPException(status_code=422, detail=validation.message)
    connector = ConnectorConfig(
        connector_key=payload.connector_key,
        connector_type=payload.connector_type,
        display_name=payload.display_name.strip(),
        config=payload.config,
        credential_ref=payload.credential_ref,
        enabled=payload.enabled,
        health_status="unverified" if payload.enabled else "disabled",
    )
    db.add(connector)
    try:
        db.flush()
        append_audit_entry(
            db, actor=current_user.username, action="connector.created",
            resource_type="connector", resource_id=connector.connector_key,
            details={"connector_type": connector.connector_type, "enabled": connector.enabled},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Connector key already exists") from exc
    db.refresh(connector)
    return connector


@router.patch("/{connector_id}", response_model=ConnectorRead)
def update_connector(
    connector_id: UUID,
    payload: ConnectorUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    connector = db.get(ConnectorConfig, connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    changes = payload.model_dump(exclude_unset=True)
    next_config = changes.get("config", connector.config)
    next_credential = changes.get("credential_ref", connector.credential_ref)
    if "config" in changes and next_config is None:
        raise HTTPException(status_code=422, detail="Connector config must be a JSON object")
    if "display_name" in changes:
        changes["display_name"] = changes["display_name"].strip()
        if not changes["display_name"]:
            raise HTTPException(status_code=422, detail="Connector display name cannot be blank")
    if next_config is not None:
        candidate = dict(next_config)
        if next_credential:
            candidate["credential_ref"] = next_credential
        validation = get_adapter(connector.connector_type).validate_config(candidate)
        if not validation.valid:
            raise HTTPException(status_code=422, detail=validation.message)
    for key, value in changes.items():
        setattr(connector, key, value)
    if "enabled" in changes:
        connector.health_status = "unverified" if changes["enabled"] else "disabled"
    append_audit_entry(
        db, actor=current_user.username, action="connector.updated",
        resource_type="connector", resource_id=connector.connector_key,
        details={"changed_fields": sorted(changes)},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Connector update conflicts with an existing record") from exc
    db.refresh(connector)
    return connector


@router.post("/{connector_id}/check", response_model=ConnectorCheckRead)
def check_connector(
    connector_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    connector = db.get(ConnectorConfig, connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    checked_at = datetime.now(timezone.utc)
    validation = _check(connector)
    connector.last_checked_at = checked_at
    if not connector.enabled:
        connector.health_status = "disabled"
        message = "Connector is disabled; no endpoint or credential was contacted."
    elif validation.valid:
        connector.health_status = "unverified"
        connector.last_error_type = None
        message = validation.message + " This check validates configuration only; it does not claim endpoint connectivity."
    else:
        connector.health_status = "misconfigured"
        connector.last_error_type = "ConfigurationValidationError"
        message = validation.message
    append_audit_entry(
        db, actor=current_user.username, action="connector.checked",
        resource_type="connector", resource_id=connector.connector_key,
        details={"health_status": connector.health_status},
    )
    db.commit()
    return {
        "connector_key": connector.connector_key,
        "health_status": connector.health_status,
        "checked_at": checked_at,
        "configuration_valid": validation.valid,
        "message": message,
    }


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connector(
    connector_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    connector = db.get(ConnectorConfig, connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    append_audit_entry(
        db, actor=current_user.username, action="connector.deleted",
        resource_type="connector", resource_id=connector.connector_key,
        details={"connector_type": connector.connector_type},
    )
    db.delete(connector)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{connector_id}/executions", response_model=list[ConnectorExecutionRead])
def connector_executions(connector_id: UUID, limit: int = 50, db: Session = Depends(get_db)):
    if limit < 1 or limit > 200:
        raise HTTPException(422, "limit must be between 1 and 200")
    if db.get(ConnectorConfig, connector_id) is None:
        raise HTTPException(404, "Connector not found")
    return list(db.scalars(select(ConnectorExecution).where(
        ConnectorExecution.connector_id == connector_id
    ).order_by(ConnectorExecution.started_at.desc()).limit(limit)).all())

@router.get("/runtime-health")
def connector_runtime_health(db: Session = Depends(get_db)):
    from sqlalchemy import func
    rows = db.execute(select(ConnectorExecution.status, func.count()).group_by(ConnectorExecution.status)).all()
    states = db.scalars(select(ConnectorRuntimeState)).all()
    return {
        "executions_by_status": {name: count for name, count in rows},
        "scheduled_connectors": len(states),
        "leased_connectors": sum(1 for item in states if item.locked_until is not None and item.locked_until > datetime.now(timezone.utc)),
        "connectors_with_failures": sum(1 for item in states if item.consecutive_failures > 0),
    }

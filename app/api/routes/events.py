import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.core.security import get_current_user, require_roles
from app.db.session import get_db
from app.models import ConnectorConfig, SavedEventQuery, SecurityEvent
from app.services.source_inventory import record_ingestion
from app.services.audit_chain import append_audit_entry
from app.schemas.events import (
    BulkEventIngest,
    BulkEventIngestResponse,
    SecurityEventCreate,
    SecurityEventRead,
    InvestigationQuery,
    InvestigationQueryResult,
    SavedEventQueryCreate,
)
from app.services.event_normalizer import normalize_event
from app.services.wazuh_adapter import normalize_wazuh_alert
from app.services.integrations import get_adapter

router = APIRouter(
    prefix="/api/v1/events", tags=["events"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))],
)




def _persist_event(db: Session, payload: SecurityEventCreate) -> tuple[str, uuid.UUID]:
    """Insert once per (source, external_id), safely under concurrent retries.

    PostgreSQL is the production database and SQLite backs the isolated test
    suite. Both support ON CONFLICT DO NOTHING, so a replay racing another
    request cannot turn an otherwise successful ingest into a 500 response.
    """
    values = payload.model_dump()
    dialect = db.get_bind().dialect.name

    if dialect == "postgresql":
        statement = pg_insert(SecurityEvent).values(**values)
    elif dialect == "sqlite":
        statement = sqlite_insert(SecurityEvent).values(**values)
    else:
        if payload.external_id:
            existing_id = db.scalar(
                select(SecurityEvent.id).where(
                    SecurityEvent.source == payload.source,
                    SecurityEvent.external_id == payload.external_id,
                )
            )
            if existing_id is not None:
                return "duplicate", existing_id
        event = SecurityEvent(**values)
        db.add(event)
        db.flush()
        return "accepted", event.id

    event_id = db.scalar(
        statement.on_conflict_do_nothing(
            index_elements=[SecurityEvent.source, SecurityEvent.external_id]
        ).returning(SecurityEvent.id)
    )
    if event_id is not None:
        return "accepted", event_id

    existing_id = db.scalar(
        select(SecurityEvent.id).where(
            SecurityEvent.source == payload.source,
            SecurityEvent.external_id == payload.external_id,
        )
    )
    if existing_id is None:
        raise RuntimeError("Event insert conflicted but the existing event was not found")
    return "duplicate", existing_id


def _validation_summary(exc: ValidationError) -> str:
    """Describe invalid fields without echoing attacker-controlled input values."""
    details = exc.errors(include_input=False, include_url=False)
    return "; ".join(
        f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
        for item in details
    )


def _normalize_source_event(db: Session, source: str, payload: dict[str, Any]) -> SecurityEventCreate:
    """Resolve a configured connector adapter while retaining legacy source ingest."""
    connector = db.scalar(
        select(ConnectorConfig).where(ConnectorConfig.connector_key == source)
    )
    if connector is None:
        return normalize_wazuh_alert(payload) if source.lower() == "wazuh" else normalize_event(payload, source=source)
    if not connector.enabled:
        raise ValueError("The configured connector is disabled")
    adapter = get_adapter(connector.connector_type)
    adapter_config = dict(connector.config or {})
    if connector.credential_ref:
        adapter_config["credential_ref"] = connector.credential_ref
    validation = adapter.validate_config(adapter_config)
    if not validation.valid:
        raise ValueError(validation.message)
    normalized_payload = adapter.normalize_payload(payload)
    normalized = (
        normalize_wazuh_alert(normalized_payload)
        if connector.connector_type == "wazuh"
        else normalize_event(normalized_payload, source=source)
    )
    normalized.source = source
    return normalized


def _record_connector_observation(db: Session, source: str) -> None:
    connector = db.scalar(
        select(ConnectorConfig).where(ConnectorConfig.connector_key == source)
    )
    if connector is not None:
        from datetime import timezone
        connector.health_status = "observed"
        connector.last_success_at = datetime.now(timezone.utc)
        connector.last_error_type = None


def _require_aware(value: datetime | None, parameter: str) -> datetime | None:
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{parameter} must include a timezone offset")
    return value


@router.post("", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def ingest_event(payload: SecurityEventCreate, response: Response, db: Session = Depends(get_db)):
    outcome, event_id = _persist_event(db, payload)
    record_ingestion(db, payload.source, accepted=int(outcome == "accepted"), duplicates=int(outcome == "duplicate"), rejected=0, event_timestamp=payload.timestamp)
    _record_connector_observation(db, payload.source)
    db.commit()
    if outcome == "duplicate":
        response.status_code = status.HTTP_200_OK
    return db.get(SecurityEvent, event_id)


@router.post("/ingest/{source}", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_roles("admin", "analyst"))])
def ingest_normalized_event(payload: dict[str, Any], response: Response,
                            source: str = Path(min_length=1, max_length=80), db: Session = Depends(get_db)):
    try:
        normalized = _normalize_source_event(db, source, payload)
    except ValidationError as exc:
        record_ingestion(db, source, accepted=0, duplicates=0, rejected=1)
        db.commit()
        raise RequestValidationError(exc.errors()) from exc
    except (ValueError, TypeError) as exc:
        record_ingestion(db, source, accepted=0, duplicates=0, rejected=1)
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    outcome, event_id = _persist_event(db, normalized)
    record_ingestion(db, source, accepted=int(outcome == "accepted"), duplicates=int(outcome == "duplicate"), rejected=0, event_timestamp=normalized.timestamp)
    _record_connector_observation(db, source)
    db.commit()
    if outcome == "duplicate":
        response.status_code = status.HTTP_200_OK
    return db.get(SecurityEvent, event_id)


@router.post(
    "/ingest/{source}/bulk",
    response_model=BulkEventIngestResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_roles("admin", "analyst"))],
)
def ingest_event_batch(
    batch: BulkEventIngest,
    source: str = Path(min_length=1, max_length=80),
    db: Session = Depends(get_db),
):
    """Normalize and ingest up to 500 source events with per-record outcomes.

    Valid records are committed together. Invalid records are reported by
    index without discarding valid siblings; duplicate source IDs resolve to
    the original event ID and do not create extra rows.
    """
    results = []
    accepted_timestamps = []
    accepted = duplicates = rejected = 0

    for index, raw_event in enumerate(batch.events):
        try:
            normalized = _normalize_source_event(db, source, raw_event)
            outcome, event_id = _persist_event(db, normalized)
            results.append({"index": index, "status": outcome, "event_id": event_id})
            if outcome == "accepted":
                accepted_timestamps.append(normalized.timestamp)
                accepted += 1
            else:
                duplicates += 1
        except (ValidationError, ValueError, TypeError) as exc:
            rejected += 1
            error = _validation_summary(exc) if isinstance(exc, ValidationError) else str(exc)
            results.append({"index": index, "status": "rejected", "error": error})

    record_ingestion(db, source, accepted=accepted, duplicates=duplicates, rejected=rejected, event_timestamp=max(accepted_timestamps, default=None))
    if accepted or duplicates:
        _record_connector_observation(db, source)
    db.commit()
    return {
        "received": len(batch.events),
        "accepted": accepted,
        "duplicates": duplicates,
        "rejected": rejected,
        "results": results,
    }


@router.get("", response_model=list[SecurityEventRead])
def list_events(
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical|info)$"),
    source: str | None = Query(default=None, min_length=1, max_length=80),
    event_type: str | None = Query(default=None, min_length=1, max_length=120),
    hostname: str | None = Query(default=None, min_length=1, max_length=255),
    source_ip: str | None = Query(default=None, min_length=1, max_length=45),
    external_id: str | None = Query(default=None, min_length=1, max_length=128),
    start_time: datetime | None = Query(default=None, description="Inclusive event-time lower bound; must include a timezone"),
    end_time: datetime | None = Query(default=None, description="Inclusive event-time upper bound; must include a timezone"),
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    start_time = _require_aware(start_time, "start_time")
    end_time = _require_aware(end_time, "end_time")
    if start_time and end_time and start_time > end_time:
        raise HTTPException(status_code=422, detail="start_time must be earlier than or equal to end_time")
    statement = select(SecurityEvent)
    for column, value in ((SecurityEvent.severity, severity), (SecurityEvent.source, source),
                          (SecurityEvent.event_type, event_type), (SecurityEvent.hostname, hostname),
                          (SecurityEvent.source_ip, source_ip), (SecurityEvent.external_id, external_id)):
        if value is not None:
            statement = statement.where(column == value)
    if start_time is not None:
        statement = statement.where(SecurityEvent.timestamp >= start_time)
    if end_time is not None:
        statement = statement.where(SecurityEvent.timestamp <= end_time)
    statement = statement.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).offset(offset).limit(limit)
    return list(db.scalars(statement).all())


@router.get("/stats")
def event_stats(db: Session = Depends(get_db)):
    total = db.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    severity_rows = db.execute(select(SecurityEvent.severity, func.count()).group_by(SecurityEvent.severity)).all()
    source_rows = db.execute(select(SecurityEvent.source, func.count()).group_by(SecurityEvent.source)).all()
    return {"total_events": total, "by_severity": {key: count for key, count in severity_rows},
            "by_source": {key: count for key, count in source_rows}}



FIELD_COLUMNS = {
    "source": SecurityEvent.source,
    "event_type": SecurityEvent.event_type,
    "severity": SecurityEvent.severity,
    "hostname": SecurityEvent.hostname,
    "source_ip": SecurityEvent.source_ip,
    "username": SecurityEvent.username,
    "external_id": SecurityEvent.external_id,
    "message": SecurityEvent.message,
}
GROUP_COLUMNS = {key: FIELD_COLUMNS[key] for key in (
    "source", "event_type", "severity", "hostname", "source_ip", "username"
)}


def _build_investigation_statement(query: InvestigationQuery):
    """Compile validated filter objects into parameterized SQL predicates."""
    from sqlalchemy import or_

    statement = select(SecurityEvent)
    if query.search:
        needle = f"%{query.search.strip().lower()}%"
        statement = statement.where(or_(*[
            func.lower(column).like(needle)
            for column in (
                SecurityEvent.message, SecurityEvent.event_type, SecurityEvent.source,
                SecurityEvent.hostname, SecurityEvent.source_ip, SecurityEvent.username,
                SecurityEvent.external_id,
            )
        ]))
    for item in query.filters:
        column, value = FIELD_COLUMNS[item.field], item.value
        if item.operator == "exists":
            statement = statement.where(column.is_not(None) if value is not False else column.is_(None))
        elif item.operator == "in":
            if not isinstance(value, list):
                raise HTTPException(status_code=422, detail="The in operator requires a list of values")
            statement = statement.where(column.in_(value))
        elif not isinstance(value, str):
            raise HTTPException(status_code=422, detail="This filter operator requires a string value")
        elif item.operator == "eq":
            statement = statement.where(column == value)
        elif item.operator == "neq":
            statement = statement.where(column != value)
        elif item.operator == "contains":
            statement = statement.where(func.lower(column).like(f"%{value.lower()}%"))
        elif item.operator == "starts_with":
            statement = statement.where(func.lower(column).like(f"{value.lower()}%"))
    if query.start_time is not None:
        statement = statement.where(SecurityEvent.timestamp >= query.start_time)
    if query.end_time is not None:
        statement = statement.where(SecurityEvent.timestamp <= query.end_time)
    return statement


@router.get("/fields")
def discover_event_fields(db: Session = Depends(get_db)):
    """Describe supported search fields and return bounded facet samples."""
    fields = []
    for name, column in FIELD_COLUMNS.items():
        if name == "message":
            fields.append({"name": name, "type": "text", "distinct_values": None})
            continue
        values = db.execute(
            select(column, func.count().label("count"))
            .where(column.is_not(None))
            .group_by(column)
            .order_by(func.count().desc(), column.asc())
            .limit(20)
        ).all()
        fields.append({
            "name": name,
            "type": "severity" if name == "severity" else "keyword",
            "distinct_values": [{"value": value, "count": count} for value, count in values],
        })
    return {"fields": fields, "operators": ["eq", "neq", "contains", "starts_with", "in", "exists"]}


@router.post("/query", response_model=InvestigationQueryResult)
def run_investigation_query(query: InvestigationQuery, db: Session = Depends(get_db)):
    """Run a bounded multi-condition search with optional group-by aggregation."""
    if query.start_time and query.end_time and query.start_time > query.end_time:
        raise HTTPException(status_code=422, detail="start_time must be earlier than or equal to end_time")
    statement = _build_investigation_statement(query)
    total = db.scalar(select(func.count()).select_from(statement.order_by(None).subquery())) or 0
    events = list(db.scalars(
        statement.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .offset(query.offset).limit(query.limit)
    ).all())
    aggregations = []
    if query.group_by:
        column = GROUP_COLUMNS[query.group_by]
        aggregate_statement = select(column.label("value"), func.count().label("count")).select_from(SecurityEvent)
        if statement.whereclause is not None:
            aggregate_statement = aggregate_statement.where(statement.whereclause)
        grouped = db.execute(
            aggregate_statement.group_by(column).order_by(func.count().desc(), column.asc()).limit(25)
        ).all()
        aggregations = [{"value": value, "count": count} for value, count in grouped]
    return {"total": total, "limit": query.limit, "offset": query.offset,
            "events": events, "aggregations": aggregations}


@router.get("/saved-queries")
def list_saved_queries(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    statement = select(SavedEventQuery).where(
        (SavedEventQuery.created_by == current_user.username) | (SavedEventQuery.is_shared.is_(True))
    ).order_by(SavedEventQuery.updated_at.desc())
    return [{
        "id": item.id, "name": item.name, "description": item.description,
        "query": item.query, "is_shared": item.is_shared,
        "created_by": item.created_by, "created_at": item.created_at, "updated_at": item.updated_at,
    } for item in db.scalars(statement).all()]


@router.post("/saved-queries", status_code=201)
def create_saved_query(payload: SavedEventQueryCreate, db: Session = Depends(get_db),
                       current_user=Depends(require_roles("admin", "analyst"))):
    from sqlalchemy.exc import IntegrityError

    item = SavedEventQuery(
        name=payload.name.strip(), description=payload.description,
        query=payload.query.model_dump(mode="json"), is_shared=payload.is_shared,
        created_by=current_user.username,
    )
    if not item.name:
        raise HTTPException(status_code=422, detail="Saved query name cannot be blank")
    db.add(item)
    try:
        db.flush()
        append_audit_entry(db, actor=current_user.username, action="investigation.saved", resource_type="saved_query", resource_id=str(item.id), details={"name": item.name, "is_shared": item.is_shared})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="You already have a saved query with this name") from exc
    db.refresh(item)
    return {
        "id": item.id, "name": item.name, "description": item.description,
        "query": item.query, "is_shared": item.is_shared,
        "created_by": item.created_by, "created_at": item.created_at, "updated_at": item.updated_at,
    }


@router.delete("/saved-queries/{query_id}", status_code=204)
def delete_saved_query(query_id: uuid.UUID, db: Session = Depends(get_db),
                       current_user=Depends(get_current_user)):
    item = db.get(SavedEventQuery, query_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Saved query not found")
    if item.created_by != current_user.username and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only the owner or an administrator can delete this query")
    append_audit_entry(db, actor=current_user.username, action="investigation.deleted", resource_type="saved_query", resource_id=str(item.id), details={"name": item.name})
    db.delete(item)
    db.commit()
    return Response(status_code=204)


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_event(event_id: uuid.UUID, db: Session = Depends(get_db)):
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event

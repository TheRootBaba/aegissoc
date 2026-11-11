import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timezone
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.security import get_current_user, require_roles
from app.db.session import get_db
from app.models import DetectionAlert, SecurityEvent, ThreatIndicator, User
from app.schemas.threat_intel import IndicatorCreate, IndicatorMatch, IndicatorRead, IndicatorUpdate, CorrelatedEntity
from app.services.audit_chain import append_audit_entry

router = APIRouter(prefix="/api/v1/threat-intel", tags=["threat-intelligence"],
    dependencies=[Depends(require_roles("admin", "analyst", "read_only"))])
HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)

def _normalize(kind: str, value: str) -> str:
    value = value.strip().lower()
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise HTTPException(422, "Invalid IP indicator") from exc
    if kind == "domain" and DOMAIN_RE.fullmatch(value) and len(value) <= 253:
        return value.rstrip(".")
    if kind == "hash" and re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value):
        return value
    raise HTTPException(422, "Indicator does not match its declared type")

def _is_active(item: ThreatIndicator, now: datetime) -> bool:
    expiry = item.expires_at
    if expiry is not None:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= now:
            return False
    return item.status == "active"

def _matches(item: ThreatIndicator, event: SecurityEvent) -> bool:
    if item.indicator_type == "ip" and event.source_ip == item.value:
        return True
    haystack = " ".join((event.message or "", str(event.raw or ""))).lower()
    if item.indicator_type == "hash":
        return item.value in HASH_RE.findall(haystack)
    if item.indicator_type == "domain":
        return item.value in DOMAIN_RE.findall(haystack)
    return bool(re.search(r"(?<![0-9a-f:.])" + re.escape(item.value) + r"(?![0-9a-f:.])", haystack))

@router.get("/indicators", response_model=list[IndicatorRead])
def list_indicators(indicator_type: str | None = Query(default=None, alias="type", pattern="^(ip|domain|hash)$"),
    status_filter: str | None = Query(default=None, alias="status", pattern="^(active|revoked)$"),
    search: str | None = Query(default=None, min_length=1, max_length=255),
    limit: int = Query(default=100, ge=1, le=200), db: Session = Depends(get_db)):
    statement = select(ThreatIndicator)
    if indicator_type: statement = statement.where(ThreatIndicator.indicator_type == indicator_type)
    if status_filter: statement = statement.where(ThreatIndicator.status == status_filter)
    if search: statement = statement.where(ThreatIndicator.value.ilike("%" + search.strip() + "%"))
    return list(db.scalars(statement.order_by(ThreatIndicator.updated_at.desc()).limit(limit)).all())

@router.post("/indicators", response_model=IndicatorRead, status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles("admin", "analyst"))])
def create_indicator(payload: IndicatorCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    value = _normalize(payload.indicator_type, payload.value)
    existing = db.scalar(select(ThreatIndicator).where(ThreatIndicator.indicator_type == payload.indicator_type, ThreatIndicator.value == value))
    if existing: raise HTTPException(409, "Indicator already exists; update the existing record")
    item = ThreatIndicator(indicator_type=payload.indicator_type, value=value, confidence=payload.confidence,
        severity=payload.severity, source=payload.source.strip(), description=payload.description.strip(),
        tags=list(dict.fromkeys(x.strip().lower() for x in payload.tags if x.strip())),
        expires_at=payload.expires_at, created_by=user.username)
    db.add(item); db.flush()
    append_audit_entry(db, actor=user.username, action="threat_indicator.created", resource_type="threat_indicator",
        resource_id=str(item.id), details={"type": item.indicator_type, "value": item.value, "source": item.source})
    db.commit(); db.refresh(item)
    return item

@router.patch("/indicators/{indicator_id}", response_model=IndicatorRead,
    dependencies=[Depends(require_roles("admin", "analyst"))])
def update_indicator(indicator_id: UUID, payload: IndicatorUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    item = db.get(ThreatIndicator, indicator_id)
    if item is None: raise HTTPException(404, "Threat indicator not found")
    changes = {}
    for field in payload.model_fields_set:
        value = getattr(payload, field)
        if field == "source" and value is not None: value = value.strip()
        if field == "description" and value is not None: value = value.strip()
        previous = getattr(item, field)
        if previous != value: changes[field] = {"from": previous, "to": value}; setattr(item, field, value)
    if changes:
        item.updated_at = datetime.now(timezone.utc)
        append_audit_entry(db, actor=user.username, action="threat_indicator.updated", resource_type="threat_indicator",
            resource_id=str(item.id), details=changes)
        db.commit(); db.refresh(item)
    return item

@router.get("/lookup", response_model=list[IndicatorRead])
def lookup_indicator(value: str = Query(min_length=3, max_length=255), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    rows = db.scalars(select(ThreatIndicator).where(ThreatIndicator.value == value.strip().lower())).all()
    return [item for item in rows if _is_active(item, now)]

@router.get("/matches", response_model=list[IndicatorMatch])
def find_indicator_matches(limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    indicators = [x for x in db.scalars(select(ThreatIndicator).where(ThreatIndicator.status == "active")).all() if _is_active(x, now)]
    if not indicators: return []
    events = db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(5000)).all()
    matches = []
    for event in events:
        for item in indicators:
            if _matches(item, event):
                matches.append(IndicatorMatch(indicator=IndicatorRead.model_validate(item), event_id=event.id,
                    event_source=event.source, event_type=event.event_type, event_timestamp=event.timestamp))
                if len(matches) >= limit: return matches
    return matches

@router.get("/entities", response_model=list[CorrelatedEntity])
def correlated_entities(entity_type: str | None = Query(default=None, alias="type", pattern="^(ip|host|user)$"),
    search: str | None = Query(default=None, min_length=1, max_length=255),
    min_events: int = Query(default=2, ge=1, le=10000), limit: int = Query(default=100, ge=1, le=200),
    db: Session = Depends(get_db)):
    """Create a bounded evidence pivot across IP, host and user identities."""
    now = datetime.now(timezone.utc)
    cutoff = now.timestamp() - 30 * 86400
    events = db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(10000)).all()
    groups = defaultdict(list)
    for event in events:
        stamp = event.timestamp if event.timestamp.tzinfo else event.timestamp.replace(tzinfo=timezone.utc)
        if stamp.timestamp() < cutoff: continue
        for kind, value in (("ip", event.source_ip), ("host", event.hostname), ("user", event.username)):
            if value and (not entity_type or kind == entity_type) and (not search or search.lower() in value.lower()):
                groups[(kind, value)].append(event)
    alerts = db.scalars(select(DetectionAlert).order_by(DetectionAlert.last_seen.desc()).limit(5000)).all()
    result = []
    for (kind, value), records in groups.items():
        linked = [a for a in alerts if (kind == "ip" and a.source_ip == value) or (kind == "host" and a.hostname == value) or (kind == "user" and a.username == value)]
        if len(records) < min_events and not linked: continue
        result.append(CorrelatedEntity(entity_type=kind, value=value, event_count=len(records), alert_count=len(linked),
            source_count=len({e.source for e in records}), sources=sorted({e.source for e in records}),
            first_seen=min(e.timestamp for e in records), last_seen=max(e.timestamp for e in records),
            event_ids=[e.id for e in records[:100]], alert_ids=[a.id for a in linked[:50]]))
    result.sort(key=lambda x: (x.alert_count, x.event_count, x.last_seen), reverse=True)
    return result[:limit]

"""Deterministic, evidence-backed detection rules for normalized events."""

import hashlib
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import DetectionAlert, SecurityEvent


SSH_BRUTE_FORCE_RULE_ID = "AUTH-SSH-001"
SSH_FAILURE_TYPES = {
    "authentication.failure",
    "ssh.authentication.failure",
    "sshd.authentication.failure",
}


def _as_utc(value: datetime) -> datetime:
    """SQLite may return naive datetimes for timezone-aware columns."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def run_ssh_brute_force_detection(
    db: Session,
    *,
    window_minutes: int = 10,
    threshold: int = 5,
    now: datetime | None = None,
) -> dict:
    """Create or refresh one alert per source IP and target host."""
    if not 1 <= window_minutes <= 1440:
        raise ValueError("window_minutes must be between 1 and 1440")
    if not 2 <= threshold <= 100:
        raise ValueError("threshold must be between 2 and 100")

    run_at = _as_utc(now or datetime.now(timezone.utc))
    window_start = run_at - timedelta(minutes=window_minutes)
    statement = (
        select(SecurityEvent)
        .where(
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.timestamp <= run_at,
            SecurityEvent.event_type.in_(SSH_FAILURE_TYPES),
            SecurityEvent.source_ip.is_not(None),
        )
        .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc())
    )
    candidates = list(db.scalars(statement).all())
    groups: dict[tuple[str, str | None], list[SecurityEvent]] = defaultdict(list)

    for event in candidates:
        message = (event.message or "").lower()
        event_type = event.event_type.lower()
        if "ssh" in message or "ssh" in event_type or "sshd" in event_type:
            groups[(event.source_ip, event.hostname)].append(event)

    created = 0
    updated = 0
    matched_alerts: list[DetectionAlert] = []

    for (source_ip, hostname), events in groups.items():
        if len(events) < threshold:
            continue

        fingerprint_input = f"{SSH_BRUTE_FORCE_RULE_ID}:{source_ip}:{hostname or ''}"
        fingerprint = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()
        evidence_ids = [str(event.id) for event in events]
        usernames = sorted({event.username for event in events if event.username})
        alert = db.scalar(
            select(DetectionAlert).where(DetectionAlert.fingerprint == fingerprint)
        )

        if alert is None:
            alert = DetectionAlert(
                rule_id=SSH_BRUTE_FORCE_RULE_ID,
                fingerprint=fingerprint,
                title="SSH brute-force activity detected",
                description=(
                    f"{len(events)} SSH authentication failures from {source_ip} "
                    f"targeting {hostname or 'an unspecified host'} within "
                    f"{window_minutes} minutes."
                ),
                severity="high" if len(events) >= threshold * 2 else "medium",
                status="open",
                source_ip=source_ip,
                hostname=hostname,
                username=", ".join(usernames)[:255] or None,
                event_count=len(events),
                first_seen=_as_utc(events[0].timestamp),
                last_seen=_as_utc(events[-1].timestamp),
                evidence_event_ids=evidence_ids,
            )
            db.add(alert)
            created += 1
        else:
            alert.event_count = len(events)
            alert.last_seen = _as_utc(events[-1].timestamp)
            alert.evidence_event_ids = evidence_ids
            alert.username = ", ".join(usernames)[:255] or None
            alert.description = (
                f"{len(events)} SSH authentication failures from {source_ip} "
                f"targeting {hostname or 'an unspecified host'} within "
                f"{window_minutes} minutes."
            )
            updated += 1
        matched_alerts.append(alert)

    db.commit()
    for alert in matched_alerts:
        db.refresh(alert)

    return {
        "rule_id": SSH_BRUTE_FORCE_RULE_ID,
        "window_minutes": window_minutes,
        "threshold": threshold,
        "events_evaluated": len(candidates),
        "alerts_created": created,
        "alerts_updated": updated,
        "alerts": matched_alerts,
    }

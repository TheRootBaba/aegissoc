"""Deterministic, evidence-backed detections over normalized security events."""

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import DetectionAlert, SecurityEvent


SSH_BRUTE_FORCE_RULE_ID = "AUTH-SSH-001"
SSH_PASSWORD_SPRAY_RULE_ID = "AUTH-SSH-002"
AUTH_SUCCESS_AFTER_FAILURES_RULE_ID = "AUTH-CHAIN-001"
PRIVILEGE_ESCALATION_RULE_ID = "PRIV-ESC-001"
SUSPICIOUS_PROCESS_RULE_ID = "PROC-SUSP-001"

ATTACK_MAPPINGS = {
    SSH_BRUTE_FORCE_RULE_ID: {
        "attack_tactic": "Credential Access", "attack_technique_id": "T1110",
        "attack_technique_name": "Brute Force",
    },
    SSH_PASSWORD_SPRAY_RULE_ID: {
        "attack_tactic": "Credential Access", "attack_technique_id": "T1110.003",
        "attack_technique_name": "Password Spraying",
    },
    AUTH_SUCCESS_AFTER_FAILURES_RULE_ID: {
        "attack_tactic": "Credential Access", "attack_technique_id": "T1110.001",
        "attack_technique_name": "Password Guessing",
    },
    PRIVILEGE_ESCALATION_RULE_ID: {
        "attack_tactic": "Privilege Escalation", "attack_technique_id": "T1548",
        "attack_technique_name": "Abuse Elevation Control Mechanism",
    },
    SUSPICIOUS_PROCESS_RULE_ID: {
        "attack_tactic": "Execution", "attack_technique_id": "T1059",
        "attack_technique_name": "Command and Scripting Interpreter",
    },
}

SSH_FAILURE_TYPES = {
    "authentication.failure", "ssh.authentication.failure", "sshd.authentication.failure",
}
AUTH_FAILURE_TYPES = SSH_FAILURE_TYPES | {"windows.logon.failure", "rdp.authentication.failure"}
AUTH_SUCCESS_TYPES = {
    "authentication.success", "ssh.authentication.success", "sshd.authentication.success",
    "windows.logon.success", "rdp.authentication.success",
}
PRIVILEGE_EVENT_TYPES = {
    "privilege.escalation", "account.privilege.escalation",
    "process.privilege.escalation", "sudo.privileged_command",
}
PROCESS_EVENT_TYPES = {"process.started", "process.execution", "process.created"}
PROCESS_INDICATORS = (
    ("powershell_encoded", ("-encodedcommand", " -enc ", " -e ", "frombase64string")),
    ("certutil_download", ("certutil -urlcache", "certutil.exe -urlcache")),
    ("bitsadmin_transfer", ("bitsadmin /transfer", "bitsadmin.exe /transfer")),
    ("mshta_execution", ("mshta ", "mshta.exe")),
    ("rundll32_execution", ("rundll32 ", "rundll32.exe")),
    ("regsvr32_execution", ("regsvr32 ", "regsvr32.exe")),
    ("script_host_execution", ("wscript ", "cscript ", "wscript.exe", "cscript.exe")),
)


def _as_utc(value: datetime) -> datetime:
    """SQLite may return naive datetimes for timezone-aware columns."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _upsert_alert(
    db, *, rule_id, title, source_ip, hostname, events, usernames,
    window_minutes, severity, description=None, fingerprint_scope=None,
):
    """Persist one evidence-backed rule match and refresh it on later runs."""
    fingerprint_input = f"{rule_id}:{source_ip}:{hostname or ''}"
    if fingerprint_scope:
        fingerprint_input += f":{fingerprint_scope}"
    fingerprint = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()
    description = description or (
        f"{len(events)} SSH authentication failures from {source_ip} "
        f"targeting {hostname or 'an unspecified host'} within {window_minutes} minutes."
    )
    ordered_events = sorted(events, key=lambda event: (_as_utc(event.timestamp), str(event.id)))
    evidence_ids = [str(event.id) for event in ordered_events]
    alert = db.scalar(select(DetectionAlert).where(DetectionAlert.fingerprint == fingerprint))
    created = alert is None

    if created:
        alert = DetectionAlert(
            rule_id=rule_id, fingerprint=fingerprint, title=title, description=description,
            **ATTACK_MAPPINGS[rule_id], severity=severity, status="open",
            source_ip=source_ip, hostname=hostname,
            username=", ".join(sorted({name for name in usernames if name}))[:255] or None,
            event_count=len(ordered_events),
            first_seen=_as_utc(ordered_events[0].timestamp),
            last_seen=_as_utc(ordered_events[-1].timestamp),
            evidence_event_ids=evidence_ids,
        )
        db.add(alert)
    else:
        alert.event_count = len(ordered_events)
        alert.last_seen = _as_utc(ordered_events[-1].timestamp)
        alert.evidence_event_ids = evidence_ids
        alert.username = ", ".join(sorted({name for name in usernames if name}))[:255] or None
        alert.description = description
        for field, value in ATTACK_MAPPINGS[rule_id].items():
            setattr(alert, field, value)
        if severity == "high":
            alert.severity = "high"
    return alert, created


def _record_match(db, matches, *, rule_id, title, source_ip, hostname, events,
                  usernames, window_minutes, severity, description, fingerprint_scope=None):
    alert, created = _upsert_alert(
        db, rule_id=rule_id, title=title, source_ip=source_ip, hostname=hostname,
        events=events, usernames=usernames, window_minutes=window_minutes,
        severity=severity, description=description, fingerprint_scope=fingerprint_scope,
    )
    matches.append((alert, created))


def _process_command(event: SecurityEvent) -> str:
    raw = event.raw if isinstance(event.raw, dict) else {}
    return (event.message or "") + " " + json.dumps(raw, sort_keys=True, default=str)


def run_ssh_brute_force_detection(
    db: Session, *, window_minutes: int = 10, threshold: int = 5,
    now: datetime | None = None,
    commit: bool = True,
) -> dict:
    """Run the SSH, authentication-sequence, privilege, and process rules."""
    if not 1 <= window_minutes <= 1440:
        raise ValueError("window_minutes must be between 1 and 1440")
    if not 2 <= threshold <= 100:
        raise ValueError("threshold must be between 2 and 100")

    run_at = _as_utc(now or datetime.now(timezone.utc))
    window_start = run_at - timedelta(minutes=window_minutes)
    relevant_types = (
        SSH_FAILURE_TYPES | AUTH_SUCCESS_TYPES | PRIVILEGE_EVENT_TYPES | PROCESS_EVENT_TYPES
    )
    candidates = list(db.scalars(
        select(SecurityEvent).where(
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.timestamp <= run_at,
            SecurityEvent.event_type.in_(relevant_types),
        ).order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc())
    ).all())

    matches = []
    ssh_groups: dict[tuple[str, str | None], list[SecurityEvent]] = defaultdict(list)
    auth_groups: dict[tuple[str, str | None, str], list[SecurityEvent]] = defaultdict(list)
    privilege_groups: dict[tuple[str | None, str | None, str | None], list[SecurityEvent]] = defaultdict(list)
    process_groups: dict[tuple[str | None, str | None, str | None, str], list[SecurityEvent]] = defaultdict(list)

    for event in candidates:
        event_type = event.event_type.lower()
        message = (event.message or "").lower()
        if event_type in SSH_FAILURE_TYPES and event.source_ip and (
            "ssh" in message or "ssh" in event_type or "sshd" in event_type
        ):
            ssh_groups[(event.source_ip, event.hostname)].append(event)
        if event.source_ip and event.username and event_type in AUTH_FAILURE_TYPES | AUTH_SUCCESS_TYPES:
            auth_groups[(event.source_ip, event.hostname, event.username)].append(event)
        if event_type in PRIVILEGE_EVENT_TYPES:
            privilege_groups[(event.source_ip, event.hostname, event.username)].append(event)
        if event_type in PROCESS_EVENT_TYPES:
            command = _process_command(event).lower()
            for indicator, patterns in PROCESS_INDICATORS:
                if any(pattern in command for pattern in patterns):
                    process_groups[(event.source_ip, event.hostname, event.username, indicator)].append(event)
                    break

    for (source_ip, hostname), events in ssh_groups.items():
        usernames = [event.username for event in events if event.username]
        if len(events) >= threshold:
            _record_match(
                db, matches, rule_id=SSH_BRUTE_FORCE_RULE_ID,
                title="SSH brute-force activity detected", source_ip=source_ip,
                hostname=hostname, events=events, usernames=usernames,
                window_minutes=window_minutes,
                severity="high" if len(events) >= threshold * 2 else "medium",
                description=f"{len(events)} SSH authentication failures from {source_ip} targeting {hostname or 'an unspecified host'} within {window_minutes} minutes.",
            )
        if len(set(usernames)) >= threshold:
            _record_match(
                db, matches, rule_id=SSH_PASSWORD_SPRAY_RULE_ID,
                title="SSH password-spray activity detected", source_ip=source_ip,
                hostname=hostname, events=events, usernames=usernames,
                window_minutes=window_minutes, severity="high",
                description=f"{len(set(usernames))} distinct accounts received SSH authentication failures from {source_ip}.",
            )

    for (source_ip, hostname, username), events in auth_groups.items():
        failures = [event for event in events if event.event_type.lower() in AUTH_FAILURE_TYPES]
        successes = [event for event in events if event.event_type.lower() in AUTH_SUCCESS_TYPES]
        if len(failures) < threshold or not successes:
            continue
        qualifying_successes = [
            success for success in successes
            if any(_as_utc(failure.timestamp) < _as_utc(success.timestamp) for failure in failures)
        ]
        if not qualifying_successes:
            continue
        first_success = min(qualifying_successes, key=lambda event: _as_utc(event.timestamp))
        prior_failures = [
            failure for failure in failures
            if _as_utc(failure.timestamp) < _as_utc(first_success.timestamp)
        ]
        evidence = prior_failures + [first_success]
        _record_match(
            db, matches, rule_id=AUTH_SUCCESS_AFTER_FAILURES_RULE_ID,
            title="Successful login after repeated authentication failures",
            source_ip=source_ip, hostname=hostname, events=evidence,
            usernames=[username], window_minutes=window_minutes, severity="high",
            fingerprint_scope=username,
            description=f"{len(prior_failures)} authentication failures were followed by a successful login for {username} from {source_ip}.",
        )

    for (source_ip, hostname, username), events in privilege_groups.items():
        _record_match(
            db, matches, rule_id=PRIVILEGE_ESCALATION_RULE_ID,
            title="Privilege escalation activity detected", source_ip=source_ip,
            hostname=hostname, events=events, usernames=[username] if username else [],
            window_minutes=window_minutes, severity="high",
            fingerprint_scope=username or "unknown",
            description=f"{len(events)} privilege escalation signal(s) observed on {hostname or 'an unspecified host'}.",
        )

    for (source_ip, hostname, username, indicator), events in process_groups.items():
        _record_match(
            db, matches, rule_id=SUSPICIOUS_PROCESS_RULE_ID,
            title="Suspicious process execution detected", source_ip=source_ip,
            hostname=hostname, events=events, usernames=[username] if username else [],
            window_minutes=window_minutes, severity="high",
            fingerprint_scope=f"{username or 'unknown'}:{indicator}",
            description=f"Process telemetry matched suspicious execution pattern '{indicator}' on {hostname or 'an unspecified host'}.",
        )

    if commit:
        db.commit()
    else:
        db.flush()
    matched_alerts = []
    created = updated = 0
    for alert, is_new in matches:
        db.refresh(alert)
        matched_alerts.append(alert)
        created += int(is_new)
        updated += int(not is_new)

    return {
        "rule_id": SSH_BRUTE_FORCE_RULE_ID,
        "rules_evaluated": [
            SSH_BRUTE_FORCE_RULE_ID, SSH_PASSWORD_SPRAY_RULE_ID,
            AUTH_SUCCESS_AFTER_FAILURES_RULE_ID, PRIVILEGE_ESCALATION_RULE_ID,
            SUSPICIOUS_PROCESS_RULE_ID,
        ],
        "window_minutes": window_minutes, "threshold": threshold,
        "events_evaluated": len(candidates), "alerts_created": created,
        "alerts_updated": updated, "alerts": matched_alerts,
    }

"""Canonical SHA-256 hash-chain writer and verifier for operator audit events."""

import hashlib
import hmac
import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditChainState, SecurityAuditEntry

GENESIS_HASH = "0" * 64


def _canonical_payload(*, sequence, occurred_at, actor, action, resource_type,
                       resource_id, details, previous_hash) -> bytes:
    payload = {
        "sequence": sequence,
        "occurred_at": occurred_at.isoformat(),
        "actor": actor,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details,
        "previous_hash": previous_hash,
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, default=str,
    ).encode("utf-8")


def append_audit_entry(
    db: Session, *, actor: str, action: str, resource_type: str,
    resource_id: str | None = None, details: dict | None = None,
) -> SecurityAuditEntry:
    """Append an audit entry in the caller's transaction.

    A singleton state row serializes writers. PostgreSQL takes a row-level lock;
    the migration seeds that row so concurrent first-writer races do not occur.
    """
    statement = select(AuditChainState).where(AuditChainState.id == 1)
    if db.get_bind().dialect.name == "postgresql":
        statement = statement.with_for_update()
    state = db.scalar(statement)
    if state is None:
        state = AuditChainState(id=1, head_sequence=0, head_hash=GENESIS_HASH)
        db.add(state)
        db.flush()

    sequence = state.head_sequence + 1
    occurred_at = datetime.now(timezone.utc)
    previous_hash = state.head_hash
    safe_details = details or {}
    digest = hashlib.sha256(_canonical_payload(
        sequence=sequence, occurred_at=occurred_at, actor=actor,
        action=action, resource_type=resource_type, resource_id=resource_id,
        details=safe_details, previous_hash=previous_hash,
    )).hexdigest()
    entry = SecurityAuditEntry(
        id=uuid4(), sequence=sequence, occurred_at=occurred_at,
        actor=actor, action=action, resource_type=resource_type,
        resource_id=resource_id, details=safe_details,
        previous_hash=previous_hash, entry_hash=digest,
    )
    state.head_sequence = sequence
    state.head_hash = digest
    state.updated_at = occurred_at
    db.add(entry)
    db.flush()
    return entry


def verify_audit_chain(db: Session) -> dict:
    """Recompute every hash and compare the records with the persisted head."""
    state_statement = select(AuditChainState).where(AuditChainState.id == 1)
    if db.get_bind().dialect.name == "postgresql":
        # Hold the head row so a concurrent append cannot race the verification.
        state_statement = state_statement.with_for_update()
    state = db.scalar(state_statement)
    records = db.scalars(
        select(SecurityAuditEntry).order_by(SecurityAuditEntry.sequence.asc())
        .execution_options(yield_per=1000)
    )
    previous_hash = GENESIS_HASH
    expected_sequence = 1
    record_count = 0
    verified_count = 0
    first_invalid = None

    for entry in records:
        record_count += 1
        occurred_at = entry.occurred_at
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        expected_hash = hashlib.sha256(_canonical_payload(
            sequence=entry.sequence, occurred_at=occurred_at,
            actor=entry.actor, action=entry.action,
            resource_type=entry.resource_type, resource_id=entry.resource_id,
            details=entry.details, previous_hash=entry.previous_hash,
        )).hexdigest()
        if (
            entry.sequence != expected_sequence
            or not hmac.compare_digest(entry.previous_hash, previous_hash)
            or not hmac.compare_digest(entry.entry_hash, expected_hash)
        ):
            first_invalid = entry.sequence
            break
        previous_hash = entry.entry_hash
        expected_sequence += 1
        verified_count += 1

    if first_invalid is None and record_count > 0 and (
        state is None
        or state.head_sequence != record_count
        or not hmac.compare_digest(state.head_hash, previous_hash)
    ):
        first_invalid = expected_sequence
    if first_invalid is None and record_count == 0 and state is not None and (
        state.head_sequence != 0 or not hmac.compare_digest(state.head_hash, GENESIS_HASH)
    ):
        first_invalid = 1

    valid = first_invalid is None
    return {
        "valid": valid,
        "checked_entries": verified_count,
        "head_sequence": state.head_sequence if state else 0,
        "head_hash": state.head_hash if state else GENESIS_HASH,
        "first_invalid_sequence": first_invalid,
        "message": "Audit chain verified" if valid else "Audit chain integrity check failed",
    }

# Threat intelligence and entity correlation

## Phase 1.20 — Curated IOC registry

The registry stores analyst-curated IP addresses, domains and MD5/SHA-1/SHA-256 hashes. Each indicator includes provenance, confidence (0–100), severity, lifecycle state, tags, description and optional expiry. Duplicate type/value pairs are rejected. Analysts and administrators can create or update records; read-only users can inspect them. Changes are written to the tamper-evident audit chain.

- GET /api/v1/threat-intel/indicators — list and filter indicators.
- POST /api/v1/threat-intel/indicators — create an indicator.
- PATCH /api/v1/threat-intel/indicators/{id} — tune confidence, severity, status, provenance or expiry.
- GET /api/v1/threat-intel/lookup?value=... — exact lookup of active, unexpired records.
- GET /api/v1/threat-intel/matches — match active indicators against a bounded sample of recent events.

Matching is deterministic and local. No external reputation requests occur and no telemetry is sent to third parties. Each match links back to the source event ID.

## Phase 1.21 — Cross-source entity correlation

GET /api/v1/threat-intel/entities groups normalized telemetry by source IP, hostname and username over the latest 30 days, bounded to 10,000 events and 5,000 alerts. Results include event/alert counts, source diversity, first/last seen and capped evidence IDs. Filters support entity type and value.

This is an evidence-backed pivot view, not a probabilistic identity engine or graph database. It does not claim that similar usernames or hostnames belong to the same person or device.

## Operational boundaries

- Provider integrations remain opt-in and are not implicitly called.
- Expired and revoked records remain stored for auditability but are excluded from active lookup and matching.
- Use synthetic indicators and telemetry in the lab. Do not upload sensitive event payloads to public reputation services.

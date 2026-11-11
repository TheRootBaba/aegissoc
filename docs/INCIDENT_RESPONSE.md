# Incident response and detection governance

## Incident cases

Cases are the response coordination layer above individual detection alerts. An alert remains an immutable detection finding with its own status, assignment, evidence references, and alert-level notes. A case groups related alerts and provides a single response owner, priority, severity, tags, analyst notes, and a controlled response lifecycle.

### Case lifecycle

| Status | Meaning | Allowed next states |
|---|---|---|
| `open` | New case awaiting triage | investigating, closed |
| `investigating` | Scope and impact being established | contained, closed, open |
| `contained` | Immediate threat activity is contained | eradicated, investigating, closed |
| `eradicated` | Threat artifacts and persistence are removed | recovered, contained, closed |
| `recovered` | Service and monitoring have returned to an acceptable state | closed, investigating |
| `closed` | Response work is formally complete | investigating |

The API rejects invalid transitions with HTTP 409. Reopening a closed case moves it to `investigating`; it does not erase its prior timeline.

### API

- `GET /api/v1/cases`: list cases; supports `status`, `priority`, `assignee`, `search`, `limit`, and `offset`.
- `POST /api/v1/cases`: create a case.
- `GET /api/v1/cases/{case_id}`: retrieve case, linked alerts, analyst notes, and audit timeline.
- `PATCH /api/v1/cases/{case_id}`: update title, description, status, priority, severity, assignee, or tags.
- `POST /api/v1/cases/{case_id}/alerts/{alert_id}`: link alert evidence.
- `DELETE /api/v1/cases/{case_id}/alerts/{alert_id}`: unlink an alert without deleting the alert or its source events.
- `POST /api/v1/cases/{case_id}/notes`: append an analyst note.

Creating, updating, linking, unlinking, and adding notes append server-attributed records to the global tamper-evident audit chain. Notes are not copied into audit metadata; the audit record stores the note identifier only.

Read-only users can inspect cases but cannot create, update, link evidence, or add notes. Administrators and analysts can perform response actions.

### Example

```http
POST /api/v1/cases
Authorization: Bearer <analyst-token>
Content-Type: application/json
```

```json
{
  "title": "Suspected credential compromise",
  "description": "Repeated remote authentication failures followed by a successful login.",
  "priority": "p1",
  "severity": "high",
  "assignee": "soc-analyst",
  "tags": ["credential-access", "identity"]
}
```

Use the returned case UUID to link alert evidence. Alert evidence links are relational and indexed; removing a link does not delete the original alert.

## Detection rule governance

The current built-in rule library is seeded by migration `0011_cases_detection_governance`. Every rule has a persisted enabled state, optional severity override, and optional threshold override.

- `GET /api/v1/detection-rules`: list the built-in rule inventory and effective operator configuration.
- `PATCH /api/v1/detection-rules/{rule_id}`: update settings (administrator only).

Threshold overrides are bounded to 2–100. Severity overrides are limited to `info`, `low`, `medium`, `high`, and `critical`. A null override restores the rule's built-in default. Disabled rules are skipped by both manual and scheduled detection runs. Rule updates are appended to the audit chain.

The first release governs the five existing deterministic rules:

- `AUTH-SSH-001`: SSH brute-force activity.
- `AUTH-SSH-002`: SSH password spraying.
- `AUTH-CHAIN-001`: successful authentication after repeated failures.
- `PRIV-ESC-001`: privilege escalation.
- `PROC-SUSP-001`: suspicious process execution.

This phase does not execute arbitrary user-authored code, install third-party Sigma rules, or claim support for an unrestricted rule language. Rule definitions remain reviewed application code; the database controls operational enablement and bounded tuning.

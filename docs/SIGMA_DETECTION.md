# Sigma rule engineering

Phase 1.27 adds a controlled Sigma import and execution path. It is intentionally a documented subset rather than a claim of complete Sigma specification compatibility.

## Supported rule shape

Rules are imported as YAML through administrator-only `POST /api/v1/sigma/rules/import`. The parser uses safe YAML loading and requires `title`, `logsource`, `detection`, and `level`.

The current evaluator supports:
- Named selectors containing field/value pairs.
- Selector conditions joined by `and` and `or`.
- Scalar and list values.
- Exact and wildcard matching.
- `|contains`, `|startswith`, and `|endswith` modifiers.
- Canonical fields such as `source`, `event_type`, `severity`, `hostname`, `source_ip`, `username`, and `message`.
- Dotted paths into the preserved source `raw` event object.

Parentheses, negation, quantifiers, regular-expression modifiers, field aggregations and other advanced Sigma condition syntax are rejected. The `logsource` block is retained as rule metadata; field selectors determine matching against canonical events and preserved raw payloads. Rules must be tested against representative telemetry before enablement.

## Rule lifecycle

- `GET /api/v1/sigma/rules` lists imported rules.
- `POST /api/v1/sigma/rules/import` validates and stores a rule disabled by default.
- `POST /api/v1/sigma/rules/{rule_id}/test` tests one sample event without persisting an alert.
- `PATCH /api/v1/sigma/rules/{rule_id}/enabled?enabled=true` enables or disables a rule (administrator only).
- `POST /api/v1/sigma/run` evaluates enabled rules over a bounded lookback window and creates evidence-linked alerts.

Rule imports, state changes and executions are audited. Alert fingerprints are deterministic per rule and event, preventing repeat executions from creating duplicate alerts. Evaluation is bounded by a maximum event sample and lookback window.

## Authoring standard

Give each rule a stable ID, a concise title, a clear description, a meaningful severity and a source-specific test fixture. Keep rules disabled until the expected event fields are confirmed in the normalized event and raw payload. Review false positives before increasing coverage.

# Sigma rule engineering

AegisSOC imports and evaluates a deliberately bounded Sigma subset. The implementation uses safe YAML parsing and a local event evaluator; it is not a full Sigma compiler and does not promise backend parity with a general-purpose Sigma pipeline.

## Rule structure and validation

Import YAML with administrator-only `POST /api/v1/sigma/rules/import`. The document must contain a non-empty `title`, a `logsource` mapping and a supported `level`. A detection rule needs one or more named selector mappings and a string `condition`. Rules are disabled by default unless an administrator explicitly requests otherwise.

The evaluator supports:

- Exact and wildcard string matching, case-insensitively.
- Scalar and list selector values; list matching defaults to any-value semantics, with the `all` modifier available for all-value matching.
- `contains`, `startswith`, `endswith`, `cidr` and `exists` field modifiers.
- Selector conditions using `and`, `or`, `not`, parentheses, `N of pattern` and `all of pattern`.
- Canonical field mappings: `source`, `event_type`, `severity`, `hostname` / `host.name`, `source_ip` / `source.ip`, and `username` / `user.name`.
- Dotted paths into the preserved raw source payload for fields that do not map to a canonical column.

The `logsource` block is retained as metadata. It does not automatically translate a vendor taxonomy into a canonical event field. A rule author must verify that the expected values exist in the normalized event or raw payload. Unsupported modifiers, malformed conditions, invalid selector values and unsupported correlation types are rejected during import.

## Multi-event correlation

Correlation rules use the `correlation` mapping and reference existing non-correlation Sigma rule IDs. The supported type is `event_count`:

```yaml
title: Repeated authentication failures from one source
id: AUTH-CORR-001
status: experimental
description: Correlate matching authentication events by source address.
logsource:
  category: authentication
  product: linux
level: high
correlation:
  type: event_count
  rules:
    - AUTH-FAIL-001
  group-by:
    - source_ip
  timespan: 10m
  condition:
    gte: 5
```

The example is a shape illustration: `AUTH-FAIL-001` must already exist as an imported selector rule, and the source event must populate `source_ip`. The engine supports up to 20 referenced rule IDs and 10 group-by fields. The time window must be between one minute and seven days. The threshold is bounded from 2 to 10,000 events and accepts `gte` or `gt`.

Correlation currently counts events matching any referenced rule inside the window, grouped by the selected fields. It does not implement every Sigma correlation type, temporal ordering, sequence correlation, value-count or distinct-count semantics. Correlation alerts retain a bounded set of evidence event IDs and use deterministic fingerprints to avoid duplicate alert creation within a time bucket.

## Rule lifecycle and API

| Operation | Endpoint | Permission |
|---|---|---|
| List rules | `GET /api/v1/sigma/rules` | Authenticated |
| Import and validate YAML | `POST /api/v1/sigma/rules/import` | Administrator |
| Test against one sample event | `POST /api/v1/sigma/rules/{rule_id}/test` | Analyst or administrator |
| Enable or disable a rule | `PATCH /api/v1/sigma/rules/{rule_id}/enabled?enabled=true` | Administrator |
| Run enabled rules | `POST /api/v1/sigma/run` | Analyst or administrator |

A test call evaluates one supplied event and does not create an alert. Scheduled execution runs through the detection scheduler. A manual run accepts a 1–1,440 minute lookback and a bounded event sample. The engine evaluates at most 100 enabled rules per run.

Rule imports, enablement changes and manual executions are audited. Alerts use the common detection alert model and retain evidence event IDs.

## Authoring and review

1. Confirm the source's actual event shape from a sanitized fixture.
2. Prefer canonical fields where available; use raw dotted paths only when needed.
3. Add a fixture for both a positive and a negative match.
4. Import the rule disabled and test it against representative events.
5. Review the selector condition and false-positive behavior before enabling it.
6. For correlation, verify each referenced rule independently before importing the correlation rule.
7. Keep rule IDs stable and review alert evidence after scheduled execution.

Do not describe a rule as production coverage merely because the YAML parses. Coverage requires representative telemetry, negative tests and analyst review.

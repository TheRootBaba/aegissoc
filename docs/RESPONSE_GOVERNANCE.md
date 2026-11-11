# Response action governance

Phase 1.28 introduces a request, approval and execution workflow for external response systems. AegisSOC does not run shell commands, terminate processes, isolate hosts or disable accounts directly.

## Execution model

An administrator registers a `response_webhook` connector with an HTTPS endpoint and an exact `allowed_hosts` entry. HTTP is disabled unless the administrator explicitly opts in for a controlled lab. An optional `credential_ref` uses `env://VARIABLE_NAME`; the secret is loaded by the API process only when the approved action is executed and is used to create an HMAC-SHA256 signature in `X-Aegis-Signature`.

Analysts can create a pending request with an action type (`notify`, `block_ip`, `disable_user`, or `isolate_host`), target, optional case and bounded scalar parameters. A `block_ip` target is validated as an IP address. Action parameters cannot contain nested objects or secret-like keys.

An administrator other than the requester must approve or reject the request with a decision note. Approval does not execute the action. A separate administrator-only execute call sends one signed JSON request to the allowlisted receiver. The payload includes a stable idempotency key; the receiver must enforce it to protect against duplicate downstream processing.

The result records delivery status and HTTP status code, not the receiver's response body. Redirects are disabled and TLS verification remains enabled. The action request and decision/execution transitions are appended to the audit chain.

## Operational safeguards

- No self-approval.
- No execution from a pending or rejected request.
- No implicit execution after approval.
- No arbitrary URL supplied by the analyst.
- No arbitrary shell or SQL action language.
- No secrets in request parameters.
- A failed or interrupted delivery must be reconciled with the receiver using the idempotency key before any manual retry. An action in `executing` state is not automatically replayed.

The receiver is part of the security boundary. It must authenticate the signature, enforce the idempotency key, authorize the action type and target, and maintain its own execution audit.

# Threat intelligence feed synchronization

Phase 1.26 uses the `threat_feed` connector type and the integration worker described in [Integration runtime](INTEGRATION_RUNTIME.md).

## Feed format

The configured endpoint must return JSON containing an array (by default under `items`). A record uses:

```json
{
  "type": "domain",
  "value": "suspicious.example",
  "confidence": 85,
  "severity": "high",
  "source": "partner-feed",
  "description": "Feed-supplied context",
  "tags": ["credential-theft"],
  "expires_at": "2026-12-01T00:00:00Z"
}
```

Supported types are IP address, domain and MD5/SHA-1/SHA-256 hash. Invalid records are counted as rejected; valid records continue through the batch. Repeated values update the existing record rather than creating a second IOC. Feed confidence never lowers an existing confidence score during automatic synchronization. A feed update does not reactivate an indicator an analyst has revoked; the connector provenance is added as a feed tag while the original source field remains intact.

The feed worker records aggregate synchronization results in the audit chain. The existing lookup and event matching APIs continue to exclude revoked and expired indicators.

## Privacy and trust

Feed data is external intelligence, not ground truth. It must retain its source attribution and expiry. Do not forward customer telemetry to public reputation providers as part of synchronization. The worker only retrieves the configured feed; it does not submit AegisSOC event data to the provider.

"""Validated adapter contracts for inbound and outbound event sources."""
from dataclasses import dataclass
from urllib.parse import urlsplit

SENSITIVE_CONFIG_KEYS = {
    "auth", "password", "token", "api_token", "access_token", "secret",
    "secret_key", "api_key", "apikey", "authorization", "private_key",
    "privatekey", "client_secret", "clientsecret", "access_key", "accesskey",
}

@dataclass(frozen=True)
class AdapterCheck:
    valid: bool
    message: str

class IntegrationAdapter:
    connector_type = "generic"
    def validate_config(self, config: dict) -> AdapterCheck:
        def sensitive_keys(value):
            if isinstance(value, dict):
                for key, nested in value.items():
                    normalized = str(key).lower().replace("-", "_")
                    if normalized in SENSITIVE_CONFIG_KEYS or any(
                        normalized.endswith("_" + marker) or normalized.startswith(marker + "_")
                        for marker in ("password", "token", "secret", "api_key", "apikey", "authorization", "private_key", "access_key")
                    ):
                        yield normalized
                    yield from sensitive_keys(nested)
            elif isinstance(value, list):
                for nested in value:
                    yield from sensitive_keys(nested)
        if set(sensitive_keys(config)):
            return AdapterCheck(False, "Secret material is not accepted in connector config; use credential_ref.")
        return AdapterCheck(True, "Configuration is structurally valid.")
    def normalize_payload(self, payload: dict) -> dict:
        return dict(payload)
    def normalize_indicator(self, payload: dict) -> dict:
        return dict(payload)

class WazuhAdapter(IntegrationAdapter):
    connector_type = "wazuh"
    def validate_config(self, config: dict) -> AdapterCheck:
        base = super().validate_config(config)
        if not base.valid: return base
        parsed = urlsplit(config.get("manager_url", ""))
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
            return AdapterCheck(False, "manager_url must be an HTTP(S) URL without embedded credentials.")
        if not config.get("credential_ref"):
            return AdapterCheck(False, "Wazuh connector requires an external credential_ref.")
        return AdapterCheck(True, "Wazuh endpoint and external credential reference are configured.")

class SyslogAdapter(IntegrationAdapter):
    connector_type = "syslog"
    def validate_config(self, config: dict) -> AdapterCheck:
        base = super().validate_config(config)
        if not base.valid: return base
        if config.get("transport", "udp") not in ("udp", "tcp", "tls"):
            return AdapterCheck(False, "Syslog transport must be udp, tcp, or tls.")
        if not isinstance(config.get("port", 514), int) or not 1 <= config.get("port", 514) <= 65535:
            return AdapterCheck(False, "Syslog port must be between 1 and 65535.")
        if not isinstance(config.get("host"), str) or not config["host"].strip():
            return AdapterCheck(False, "Syslog host is required.")
        return AdapterCheck(True, "Syslog listener configuration is valid.")

class HttpEventAdapter(IntegrationAdapter):
    connector_type = "http_event"
    def validate_config(self, config: dict) -> AdapterCheck:
        base = super().validate_config(config)
        if not base.valid: return base
        path = config.get("ingest_path", "/api/v1/events/ingest")
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            return AdapterCheck(False, "ingest_path must be an absolute application path.")
        return AdapterCheck(True, "HTTP event adapter configuration is valid.")

class HttpPollAdapter(IntegrationAdapter):
    connector_type = "http_poll"
    def validate_config(self, config: dict) -> AdapterCheck:
        base = super().validate_config(config)
        if not base.valid: return base
        endpoint = config.get("endpoint")
        parsed = urlsplit(endpoint or "")
        hosts = config.get("allowed_hosts")
        if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password:
            return AdapterCheck(False, "endpoint must be an HTTP(S) URL without embedded credentials.")
        if parsed.scheme != "https" and config.get("allow_http") is not True:
            return AdapterCheck(False, "HTTP polling requires explicit allow_http=true; HTTPS is preferred.")
        if not isinstance(hosts, list) or parsed.hostname.lower() not in [str(x).lower() for x in hosts]:
            return AdapterCheck(False, "endpoint hostname must appear in the explicit allowed_hosts list.")
        interval = config.get("interval_seconds", 60)
        if not isinstance(interval, int) or not 30 <= interval <= 86400:
            return AdapterCheck(False, "interval_seconds must be between 30 and 86400.")
        return AdapterCheck(True, "Polling endpoint and host allowlist are valid.")

class ThreatFeedAdapter(HttpPollAdapter):
    connector_type = "threat_feed"



class WazuhManagerAdapter(HttpPollAdapter):
    connector_type = "wazuh_manager"
    def validate_config(self, config: dict) -> AdapterCheck:
        result = super().validate_config(config)
        if not result.valid:
            return result
        if urlsplit(config["endpoint"]).scheme != "https":
            return AdapterCheck(False, "Wazuh Manager polling requires HTTPS.")
        if not config.get("credential_ref"):
            return AdapterCheck(False, "Wazuh Manager polling requires an external API token reference.")
        return AdapterCheck(True, "Wazuh Manager endpoint, TLS, allowlist, and credential reference are valid.")

    def normalize_payload(self, payload: dict) -> dict:
        source = payload.get("_source") if isinstance(payload.get("_source"), dict) else payload
        return dict(source)


class WazuhIndexerAdapter(HttpPollAdapter):
    connector_type = "wazuh_indexer"

    def validate_config(self, config: dict) -> AdapterCheck:
        result = super().validate_config(config)
        if not result.valid:
            return result
        if urlsplit(config["endpoint"]).scheme != "https":
            return AdapterCheck(False, "Wazuh Indexer polling requires HTTPS.")
        if not config.get("credential_ref"):
            return AdapterCheck(False, "Wazuh Indexer requires a mounted or environment Basic Auth credential reference.")
        if config.get("auth_scheme", "basic") != "basic":
            return AdapterCheck(False, "Wazuh Indexer supports Basic Auth credentials.")
        return AdapterCheck(True, "Wazuh Indexer endpoint, TLS, allowlist, and Basic Auth reference are valid.")

    def normalize_payload(self, payload: dict) -> dict:
        source = payload.get("_source") if isinstance(payload.get("_source"), dict) else payload
        normalized = dict(source)
        if not normalized.get("id") and payload.get("_id"):
            normalized["id"] = payload["_id"]
        return normalized


class MISPAdapter(HttpPollAdapter):
    connector_type = "misp"
    def validate_config(self, config: dict) -> AdapterCheck:
        result = super().validate_config(config)
        if not result.valid:
            return result
        if urlsplit(config["endpoint"]).scheme != "https":
            return AdapterCheck(False, "MISP polling requires HTTPS.")
        if not config.get("credential_ref"):
            return AdapterCheck(False, "MISP requires an external API key reference.")
        return AdapterCheck(True, "MISP REST endpoint, TLS, allowlist, and API key reference are valid.")

    def normalize_indicator(self, payload: dict) -> dict:
        attribute = payload.get("Attribute") if isinstance(payload.get("Attribute"), dict) else payload
        kind = str(attribute.get("type", "")).lower()
        mapped = {
            "ip-src": "ip", "ip-dst": "ip", "ip-src|port": "ip", "ip-dst|port": "ip",
            "domain": "domain", "hostname": "domain",
            "md5": "hash", "sha1": "hash", "sha256": "hash",
        }.get(kind, kind)
        raw_tags = attribute.get("Tag", attribute.get("tags", []))
        tags = [str(item.get("name", "")) for item in raw_tags if isinstance(item, dict)] if isinstance(raw_tags, list) else []
        return {
            "type": mapped,
            "value": str(attribute.get("value", "")).split("|", 1)[0],
            "confidence": 80 if attribute.get("to_ids") else 50,
            "severity": "high" if attribute.get("to_ids") else "medium",
            "source": "MISP",
            "description": str(attribute.get("comment") or attribute.get("category") or "")[:500],
            "tags": tags,
        }


class OpenCTIAdapter(HttpPollAdapter):
    connector_type = "opencti"
    def validate_config(self, config: dict) -> AdapterCheck:
        result = super().validate_config(config)
        if not result.valid:
            return result
        if urlsplit(config["endpoint"]).scheme != "https":
            return AdapterCheck(False, "OpenCTI polling requires HTTPS.")
        if not config.get("credential_ref"):
            return AdapterCheck(False, "OpenCTI requires an external API token reference.")
        return AdapterCheck(True, "OpenCTI GraphQL endpoint, TLS, allowlist, and token reference are valid.")

    def normalize_indicator(self, payload: dict) -> dict:
        item = payload.get("node") if isinstance(payload.get("node"), dict) else payload
        pattern = str(item.get("pattern") or "")
        match = __import__("re").search(
            r"\[(?:ipv4-addr|ipv6-addr|domain-name|file):(?:value|hashes\.(?:MD5|SHA-1|SHA-256))\s*=\s*'([^']+)'\]",
            pattern,
            __import__("re").I,
        )
        if match:
            prefix = pattern.split(":", 1)[0].lstrip("[").lower()
            if "ipv" in prefix:
                kind = "ip"
            elif "domain" in prefix:
                kind = "domain"
            else:
                kind = "hash"
            value = match.group(1)
        else:
            kind = str(item.get("type") or item.get("indicator_type") or "").lower()
            value = item.get("value", "")
        labels = item.get("labels") if isinstance(item.get("labels"), list) else []
        return {
            "type": kind,
            "value": value,
            "confidence": item.get("confidence", 50),
            "severity": item.get("severity", "medium"),
            "source": "OpenCTI",
            "description": str(item.get("description") or "")[:500],
            "tags": [str(label.get("value", "")) for label in labels if isinstance(label, dict)],
            "expires_at": item.get("valid_until"),
        }

class VulnerabilityScannerAdapter(HttpPollAdapter):
    """Authenticated vendor export-job API contract; credentials stay in secret storage."""
    provider = "scanner"
    def validate_config(self, config: dict) -> AdapterCheck:
        result = super().validate_config(config)
        if not result.valid:
            return result
        if not config.get("credential_ref"):
            return AdapterCheck(False, "Scanner connector requires an external credential_ref.")
        if urlsplit(config["endpoint"]).scheme != "https":
            return AdapterCheck(False, "Vulnerability scanner APIs require HTTPS.")
        if not isinstance(config.get("interval_seconds", 300), int) or not 60 <= config.get("interval_seconds", 300) <= 86400:
            return AdapterCheck(False, "Scanner interval_seconds must be between 60 and 86400.")
        return AdapterCheck(True, "Scanner API endpoint, TLS, host allowlist, and external credential reference are valid.")


class NessusAdapter(VulnerabilityScannerAdapter):
    connector_type = "nessus"


class TenableAdapter(VulnerabilityScannerAdapter):
    connector_type = "tenable"


class QualysAdapter(VulnerabilityScannerAdapter):
    connector_type = "qualys"


class ResponseWebhookAdapter(IntegrationAdapter):
    connector_type = "response_webhook"
    def validate_config(self, config: dict) -> AdapterCheck:
        base = super().validate_config(config)
        if not base.valid: return base
        parsed = urlsplit(config.get("endpoint", ""))
        hosts = config.get("allowed_hosts")
        if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password:
            return AdapterCheck(False, "endpoint must be an HTTP(S) URL without embedded credentials.")
        if parsed.scheme != "https" and config.get("allow_http") is not True:
            return AdapterCheck(False, "HTTP response delivery requires explicit allow_http=true.")
        if not isinstance(hosts, list) or parsed.hostname.lower() not in [str(x).lower() for x in hosts]:
            return AdapterCheck(False, "endpoint hostname must appear in the explicit allowed_hosts list.")
        reconciliation = config.get("reconciliation_endpoint")
        if reconciliation:
            status_url = urlsplit(reconciliation)
            if status_url.scheme not in ("https", "http") or not status_url.hostname or status_url.username or status_url.password:
                return AdapterCheck(False, "reconciliation_endpoint must be an HTTP(S) URL without embedded credentials.")
            if status_url.scheme != "https" and config.get("allow_http") is not True:
                return AdapterCheck(False, "HTTP reconciliation requires explicit allow_http=true.")
            if status_url.hostname.lower() not in [str(x).lower() for x in hosts]:
                return AdapterCheck(False, "reconciliation_endpoint hostname must appear in allowed_hosts.")
        return AdapterCheck(True, "Response and optional reconciliation endpoints are allowlisted.")

ADAPTERS = {item.connector_type: item for item in (
    IntegrationAdapter(), WazuhAdapter(), SyslogAdapter(), HttpEventAdapter(),
    HttpPollAdapter(), ThreatFeedAdapter(), WazuhManagerAdapter(), WazuhIndexerAdapter(), MISPAdapter(), OpenCTIAdapter(), NessusAdapter(), TenableAdapter(), QualysAdapter(), ResponseWebhookAdapter(),
)}

def get_adapter(connector_type: str) -> IntegrationAdapter:
    try:
        return ADAPTERS[connector_type]
    except KeyError as exc:
        raise ValueError("Unsupported connector type") from exc

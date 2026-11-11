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
        return AdapterCheck(True, "Response endpoint and host allowlist are valid.")

ADAPTERS = {item.connector_type: item for item in (
    IntegrationAdapter(), WazuhAdapter(), SyslogAdapter(), HttpEventAdapter(),
    HttpPollAdapter(), ThreatFeedAdapter(), ResponseWebhookAdapter(),
)}

def get_adapter(connector_type: str) -> IntegrationAdapter:
    try:
        return ADAPTERS[connector_type]
    except KeyError as exc:
        raise ValueError("Unsupported connector type") from exc

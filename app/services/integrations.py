"""Small, explicit adapter registry for supported event-source contracts."""

from dataclasses import dataclass
from urllib.parse import urlsplit


SENSITIVE_CONFIG_KEYS = {
    "password", "token", "secret", "api_key", "apikey", "authorization",
    "private_key", "client_secret", "access_key",
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
                    normalized = str(key).lower()
                    if normalized in SENSITIVE_CONFIG_KEYS:
                        yield normalized
                    yield from sensitive_keys(nested)
            elif isinstance(value, list):
                for nested in value:
                    yield from sensitive_keys(nested)

        forbidden = set(sensitive_keys(config))
        if forbidden:
            return AdapterCheck(False, "Secret material is not accepted in connector config; use credential_ref.")
        return AdapterCheck(True, "Configuration is structurally valid.")

    def normalize_payload(self, payload: dict) -> dict:
        """Generic adapters preserve the original payload for canonical normalization."""
        return dict(payload)


class WazuhAdapter(IntegrationAdapter):
    connector_type = "wazuh"

    def validate_config(self, config: dict) -> AdapterCheck:
        base = super().validate_config(config)
        if not base.valid:
            return base
        manager_url = config.get("manager_url")
        if not isinstance(manager_url, str):
            return AdapterCheck(False, "Wazuh manager_url is required.")
        parsed = urlsplit(manager_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
            return AdapterCheck(False, "manager_url must be an HTTP(S) URL without embedded credentials.")
        if not config.get("credential_ref"):
            return AdapterCheck(False, "Wazuh connector requires an external credential_ref.")
        return AdapterCheck(True, "Wazuh endpoint and external credential reference are configured.")


class SyslogAdapter(IntegrationAdapter):
    connector_type = "syslog"

    def validate_config(self, config: dict) -> AdapterCheck:
        base = super().validate_config(config)
        if not base.valid:
            return base
        if config.get("transport", "udp") not in ("udp", "tcp", "tls"):
            return AdapterCheck(False, "Syslog transport must be udp, tcp, or tls.")
        port = config.get("port", 514)
        if not isinstance(port, int) or not 1 <= port <= 65535:
            return AdapterCheck(False, "Syslog port must be between 1 and 65535.")
        if not isinstance(config.get("host"), str) or not config["host"].strip():
            return AdapterCheck(False, "Syslog host is required.")
        return AdapterCheck(True, "Syslog listener configuration is valid.")


class HttpEventAdapter(IntegrationAdapter):
    connector_type = "http_event"

    def validate_config(self, config: dict) -> AdapterCheck:
        base = super().validate_config(config)
        if not base.valid:
            return base
        path = config.get("ingest_path", "/api/v1/events/ingest")
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            return AdapterCheck(False, "ingest_path must be an absolute application path.")
        return AdapterCheck(True, "HTTP event adapter configuration is valid.")


ADAPTERS = {
    adapter.connector_type: adapter
    for adapter in (IntegrationAdapter(), WazuhAdapter(), SyslogAdapter(), HttpEventAdapter())
}


def get_adapter(connector_type: str) -> IntegrationAdapter:
    try:
        return ADAPTERS[connector_type]
    except KeyError as exc:
        raise ValueError("Unsupported connector type") from exc

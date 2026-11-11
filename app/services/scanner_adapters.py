"""Normalize exported vulnerability scanner results into AegisSOC's import contract."""

from typing import Any


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _severity(value: Any, provider: str) -> str:
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        numeric = int(value)
        if provider == "qualys":
            return {1: "low", 2: "medium", 3: "high", 4: "high", 5: "critical"}.get(numeric, "medium")
        return {0: "low", 1: "low", 2: "medium", 3: "high", 4: "critical"}.get(numeric, "medium")
    normalized = str(value or "medium").strip().lower()
    aliases = {"info": "low", "informational": "low", "urgent": "critical", "severe": "critical"}
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in {"low", "medium", "high", "critical"} else "medium"


def _finding(item: dict, provider: str) -> dict:
    cve = _first(item.get("cve") or item.get("cves") or item.get("CVE"))
    identifier = cve or item.get("vulnerability_id") or item.get("plugin_id") or item.get("qid") or item.get("id")
    if identifier is None:
        raise ValueError("Scanner finding has no CVE, plugin ID, or QID")
    if not str(identifier).upper().startswith("CVE-") and not item.get("vulnerability_id"):
        prefix = "QID" if provider == "qualys" else "PLUGIN"
        identifier = f"{prefix}-{identifier}"
    title = item.get("title") or item.get("plugin_name") or item.get("name") or item.get("vuln_title")
    if not title:
        title = f"{provider.title()} finding {identifier}"
    return {
        "vulnerability_id": str(identifier),
        "title": str(title)[:200],
        "severity": _severity(item.get("severity") or item.get("risk_factor") or item.get("severity_level"), provider),
        "description": str(item.get("description") or item.get("synopsis") or item.get("solution") or "")[:4000],
    }


def normalize_scanner_export(provider: str, document: dict) -> dict:
    """Map Nessus/Tenable/Qualys exports without contacting the vendor."""
    if not isinstance(document, dict):
        raise ValueError("Scanner export must be a JSON object")
    provider = provider.lower()
    if provider not in {"nessus", "tenable", "qualys"}:
        raise ValueError("Unsupported scanner export provider")
    info = document.get("info") if isinstance(document.get("info"), dict) else {}
    scan_id = document.get("scan_id") or document.get("scan_uuid") or info.get("uuid") or info.get("id")
    if not scan_id:
        raise ValueError("Scanner export must include a scan identifier")
    raw_assets = document.get("assets") or document.get("hosts")
    if not isinstance(raw_assets, list) or not raw_assets or len(raw_assets) > 500:
        raise ValueError("Scanner export must contain between 1 and 500 assets")

    assets = []
    for host in raw_assets:
        if not isinstance(host, dict):
            continue
        hostname = (
            host.get("hostname") or host.get("host-fqdn") or host.get("host_name")
            or host.get("fqdn") or host.get("host-ip") or host.get("ip")
        )
        asset_key = host.get("asset_key") or host.get("asset_id") or host.get("host-fqdn") or host.get("hostname") or host.get("host_name") or host.get("host-ip") or host.get("ip")
        raw_findings = host.get("findings") or host.get("vulnerabilities") or host.get("detectionList") or []
        if not hostname or not asset_key or not isinstance(raw_findings, list):
            continue
        findings = [_finding(item, provider) for item in raw_findings[:100] if isinstance(item, dict)]
        assets.append({
            "asset_key": str(asset_key)[:160],
            "hostname": str(hostname)[:255],
            "findings": findings,
        })
    if not assets:
        raise ValueError("Scanner export contains no usable host records")
    if sum(len(asset["findings"]) for asset in assets) > 5000:
        raise ValueError("A scanner import is limited to 5,000 findings")
    return {
        "scanner_name": provider,
        "scan_id": str(scan_id)[:160],
        "assets": assets,
    }

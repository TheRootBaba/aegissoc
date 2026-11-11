from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.sigma_engine import parse_sigma_document, rule_matches


@pytest.mark.parametrize("filename,raw,expected", [
    ("windows_scheduled_task_creation.yml", {"Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": "schtasks /create /tn test"}, True),
    ("windows_scheduled_task_creation.yml", {"Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": "schtasks /query"}, False),
    ("windows_security_log_cleared.yml", {"Image": "C:\\Windows\\System32\\wevtutil.exe", "CommandLine": "wevtutil cl Security"}, True),
    ("windows_security_log_cleared.yml", {"Image": "wevtutil.exe", "CommandLine": "wevtutil qe Security"}, False),
    ("linux_sudoers_modification.yml", {"CommandLine": "visudo -f /etc/sudoers"}, True),
    ("linux_sudoers_modification.yml", {"CommandLine": "cat /etc/passwd"}, False),
    ("linux_ssh_key_access.yml", {"CommandLine": "ssh -i ~/.ssh/id_rsa host"}, True),
    ("linux_ssh_key_access.yml", {"CommandLine": "ssh-agent -s"}, False),
])
def test_sigma_regression_fixtures(filename, raw, expected):
    source = (Path(__file__).parents[1] / "rules" / "sigma" / filename).read_text(encoding="utf-8")
    parsed = parse_sigma_document(source)
    rule = SimpleNamespace(**parsed, enabled=True)
    event = SimpleNamespace(
        source="endpoint", event_type="process.started", severity="medium",
        hostname="fixture-host", source_ip=None, username="analyst",
        message="process telemetry fixture", raw=raw,
    )
    assert rule_matches(event, rule) is expected


def test_every_bundled_sigma_rule_parses_with_unique_ids():
    from app.services.sigma_engine import parse_sigma_document
    rule_files = sorted((Path(__file__).parents[1] / "rules" / "sigma").glob("*.yml"))
    assert len(rule_files) >= 13
    parsed = [parse_sigma_document(path.read_text(encoding="utf-8")) for path in rule_files]
    ids = [rule["rule_id"] for rule in parsed]
    assert len(ids) == len(set(ids))

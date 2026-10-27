from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from osforge.security.audit import append_event, verify_log
from osforge.security.catalog import discovered_tools, installed_security_extensions
from osforge.security.posture import run_host_posture
from osforge.security.scope import normalize_target, validate_scope_data


def future_expiry() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()


def valid_scope(**updates):
    data = {
        "schema_version": 1,
        "engagement": {
            "name": "Internal defensive review",
            "owner": "Example Security Team",
            "authorization_reference": "CHANGE-1234",
            "expires_at": future_expiry(),
        },
        "targets": ["192.168.1.10", "example.com"],
        "ports": [80, 443],
        "web_urls": ["https://example.com"],
    }
    data.update(updates)
    return data


def test_normalize_ip_domain_and_cidr():
    assert normalize_target("192.168.1.10") == "192.168.1.10"
    assert normalize_target("192.168.1.12/24") == "192.168.1.0/24"
    assert normalize_target("Example.COM.") == "example.com"


@pytest.mark.parametrize("target", ["", "--help", "*.example.com", "https://example.com", "bad host"])
def test_invalid_targets_rejected(target):
    with pytest.raises(ValueError):
        normalize_target(target)


def test_scope_manifest_validation_returns_normalized_data():
    scope = validate_scope_data(valid_scope())
    assert scope.name == "Internal defensive review"
    assert scope.authorization_reference == "CHANGE-1234"
    assert scope.active is True
    assert scope.ports == (80, 443)
    assert "example.com" in scope.targets


def test_expired_scope_rejected():
    data = valid_scope()
    data["engagement"]["expires_at"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with pytest.raises(ValueError, match="expired"):
        validate_scope_data(data)


def test_timezone_required_for_scope_expiry():
    data = valid_scope()
    data["engagement"]["expires_at"] = "2035-01-01T12:00:00"
    with pytest.raises(ValueError, match="timezone"):
        validate_scope_data(data)


def test_url_host_must_be_explicitly_in_scope():
    data = valid_scope()
    data["web_urls"] = ["https://not-in-scope.example"]
    with pytest.raises(ValueError, match="not explicitly covered"):
        validate_scope_data(data)


def test_url_port_must_be_explicitly_allowed():
    data = valid_scope()
    data["web_urls"] = ["https://example.com:8443"]
    with pytest.raises(ValueError, match="also appear in ports"):
        validate_scope_data(data)


def test_explicit_ports_are_validated():
    data = valid_scope()
    data["ports"] = [80, 65536]
    with pytest.raises(ValueError, match="Invalid TCP port"):
        validate_scope_data(data)


def test_hash_linked_audit_log_verifies_and_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_event("test.started", details={"target": "localhost"}, path=path)
    append_event("test.completed", details={"result": "ok"}, path=path)
    valid, count, message = verify_log(path)
    assert valid is True
    assert count == 2
    assert "Verified 2" in message

    rows = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(rows[0])
    entry["event"] = "rewritten"
    rows[0] = json.dumps(entry)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    valid, count, message = verify_log(path)
    assert valid is False
    assert "hash" in message.lower() or "chain" in message.lower()


def test_local_posture_report_has_real_host_fields():
    report = run_host_posture()
    assert report["product"] == "OS Forge Security"
    assert report["host"]["hostname"]
    assert report["summary"]["findings_total"] >= 1
    assert report["findings"]


def test_security_tool_inventory_is_catalogued_not_executed():
    inventory = discovered_tools()
    assert inventory
    assert any(tool.name == "bandit" for tool, _ in inventory)
    # Installed extensions are metadata only; discover never imports their code.
    assert isinstance(installed_security_extensions(), list)

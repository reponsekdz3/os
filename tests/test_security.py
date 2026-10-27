from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timedelta, timezone

import pytest

from osforge.cli import build_parser
from osforge.security.audit import append_event, verify_log
from osforge.security.assessment import run_assessment
from osforge.security.contracts import AssessmentContext
from osforge.security.plugins import evaluate_plugins, validate_plugin_selection
from osforge.security.state import finding_history, list_assessments, list_findings, update_finding
from osforge.security.catalog import discovered_tools, installed_security_extensions
from osforge.security.posture import run_host_posture
from osforge.security.scope import create_scope_manifest, load_scope, normalize_target, validate_scope_data


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



def test_web_url_query_string_rejected_to_avoid_secret_leaks():
    data = valid_scope()
    data["web_urls"] = ["https://example.com/?token=secret"]
    with pytest.raises(ValueError, match="query strings"):
        validate_scope_data(data)


def test_plugin_evidence_rules_flag_headers_without_network_io():
    context = AssessmentContext(
        scope={"name": "offline-test"},
        tcp_observations=[{
            "target": "192.0.2.10", "address": "192.0.2.10", "port": 3389,
            "status": "open", "service_hint": "rdp", "latency_ms": 1.2,
        }],
        web_observations=[{
            "url": "https://example.test/", "scheme": "https", "status_code": 200,
            "headers": {"content-type": "text/html"}, "error": "",
        }],
    )
    findings, errors = evaluate_plugins(context)
    assert not errors
    assert any(item["check_id"] == "tcp-exposure" and item["severity"] == "medium" for item in findings)
    assert any(item["title"] == "HSTS header not observed" for item in findings)
    assert any(item["title"] == "Content-Security-Policy header not observed" for item in findings)


def test_unknown_plugin_rejected_before_assessment():
    with pytest.raises(ValueError, match="Unknown plugin"):
        validate_plugin_selection(("plugin-does-not-exist",))


def test_local_assessment_persists_evidence_and_remediation(tmp_path):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    scope_path = tmp_path / "local-scope.json"
    scope_path.write_text(json.dumps({
        "schema_version": 1,
        "engagement": {
            "name": "Local fixture integration test",
            "owner": "OS Forge tests",
            "authorization_reference": "TEST-LOCAL-ONLY",
            "expires_at": future_expiry(),
        },
        "targets": ["127.0.0.1"],
        "ports": [port],
        "web_urls": [],
    }), encoding="utf-8")
    database = tmp_path / "state.sqlite3"
    audit = tmp_path / "audit.jsonl"
    report_path = tmp_path / "report.json"
    try:
        report = run_assessment(
            scope_path,
            output_path=report_path,
            database_path=database,
            audit_path=audit,
        )
        assert report["summary"]["tcp_probes"] == 1
        assert report["summary"]["tcp_open"] == 1
        assert report["findings"]
        assert report_path.exists()
        saved = json.loads(report_path.read_text(encoding="utf-8"))
        assert saved["assessment_id"] == report["assessment_id"]
        assert report["findings"][0]["finding_id"].startswith("F-")
        assert report["findings"][0]["status"] == "open"

        runs = list_assessments(database_path=database)
        findings = list_findings(database_path=database, status="open")
        assert len(runs) == 1
        assert findings
        finding_id = findings[0]["finding_id"]

        update_finding(
            finding_id,
            status="resolved",
            note="Verified this listener is test-only and removed after this fixture.",
            assignee="security-tests",
            due_date="2030-01-01",
            database_path=database,
        )
        history = finding_history(finding_id, database_path=database)
        assert history[-1]["new_status"] == "resolved"
        with pytest.raises(ValueError, match="non-empty note"):
            update_finding(
                finding_id, status="accepted_risk", note="", database_path=database
            )

        # Re-observing a resolved finding reopens it with the same stable identifier.
        second = run_assessment(
            scope_path,
            output_path=tmp_path / "report-2.json",
            database_path=database,
            audit_path=audit,
        )
        same = next(item for item in second["findings"] if item["finding_id"] == finding_id)
        assert same["status"] == "open"
        assert len(list_assessments(database_path=database)) == 2
        assert verify_log(audit)[0] is True
    finally:
        listener.close()


def test_scope_web_urls_are_carried_into_manifest():
    scope = validate_scope_data(valid_scope())
    assert scope.web_urls == ("https://example.com",)



def test_scope_writer_creates_valid_manifest_without_overwrite(tmp_path):
    scope_path = tmp_path / "new-scope.json"
    created = create_scope_manifest(
        scope_path,
        name="Writer fixture",
        owner="Local tests",
        authorization_reference="TEST-WRITER",
        expires_at=future_expiry(),
        targets=["127.0.0.1"],
        ports=[8080],
    )
    loaded = load_scope(created)
    assert loaded.targets == ("127.0.0.1",)
    assert loaded.ports == (8080,)
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        create_scope_manifest(
            scope_path,
            name="Writer fixture",
            owner="Local tests",
            authorization_reference="TEST-WRITER",
            expires_at=future_expiry(),
            targets=["127.0.0.1"],
            ports=[8080],
        )


def test_local_http_head_assessment_records_security_header_evidence(tmp_path):
    class FixtureHandler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

        def log_message(self, format, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    scope_path = tmp_path / "http-scope.json"
    scope_path.write_text(json.dumps({
        "schema_version": 1,
        "engagement": {
            "name": "Local HTTP fixture",
            "owner": "OS Forge tests",
            "authorization_reference": "TEST-HTTP-LOCAL",
            "expires_at": future_expiry(),
        },
        "targets": ["127.0.0.1"],
        "ports": [port],
        "web_urls": [f"http://127.0.0.1:{port}/"],
    }), encoding="utf-8")
    try:
        report = run_assessment(
            scope_path,
            output_path=tmp_path / "http-report.json",
            database_path=tmp_path / "http-state.sqlite3",
            audit_path=tmp_path / "http-audit.jsonl",
        )
        assert report["summary"]["tcp_open"] == 1
        assert report["summary"]["web_urls_checked"] == 1
        assert report["web_observations"][0]["status_code"] == 200
        assert report["web_observations"][0]["headers"]["content-type"] == "text/html"
        assert any(item["check_id"] == "http-transport" for item in report["findings"])
        assert any(item.get("evidence", {}).get("missing_header") == "content-security-policy"
                   for item in report["findings"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)



def test_cli_exposes_assessment_remediation_and_plugin_commands():
    parser = build_parser()
    assess = parser.parse_args(["security", "assess", "scope.json", "--plugin", "web-headers"])
    assert assess.security_command == "assess"
    assert assess.plugin == ["web-headers"]
    remediate = parser.parse_args([
        "security", "remediate", "F-0123456789abcdef",
        "--status", "resolved", "--note", "Verified fixed", "--yes",
    ])
    assert remediate.status == "resolved"
    assert remediate.yes is True


def test_probe_budget_is_enforced_before_any_tcp_connection(tmp_path, monkeypatch):
    scope_path = tmp_path / "wide-scope.json"
    scope_path.write_text(json.dumps({
        "schema_version": 1,
        "engagement": {
            "name": "Probe-budget test",
            "owner": "OS Forge tests",
            "authorization_reference": "TEST-BUDGET",
            "expires_at": future_expiry(),
        },
        "targets": ["192.0.2.0/24"],
        "ports": list(range(1, 65)),
        "web_urls": [],
    }), encoding="utf-8")
    audit = tmp_path / "budget-audit.jsonl"

    def forbidden_connect(*args, **kwargs):
        raise AssertionError("No socket connection should occur when the probe budget is exceeded.")

    monkeypatch.setattr("osforge.security.assessment.socket.create_connection", forbidden_connect)
    with pytest.raises(ValueError, match="per-run ceiling"):
        run_assessment(
            scope_path,
            output_path=tmp_path / "should-not-exist.json",
            database_path=tmp_path / "budget.sqlite3",
            audit_path=audit,
        )
    assert verify_log(audit)[0] is True
    rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["event"] == "assessment.failed"
    assert not (tmp_path / "should-not-exist.json").exists()

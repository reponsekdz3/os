from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timedelta, timezone

import pytest

from osforge.cli import build_parser
from osforge.security.audit import append_event, verify_log
from osforge.security.approval import (generate_keypair, sign_scope, trust_public_key, trusted_public_key_path, verify_scope_approval)
from osforge.security.assessment import _resolve_exact_target, run_assessment
from osforge.security.contracts import AssessmentContext
from osforge.security.plugins import evaluate_plugins, validate_plugin_selection
from osforge.security.state import finding_history, list_assessments, list_findings, update_finding
from osforge.security.local_tools import generate_sbom, run_local_scan
from osforge.security.reporting import export_report, verify_assessment_report
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




def approve_scope(scope_path, directory, prefix="approval"):
    private_key = directory / f"{prefix}-private.pem"
    public_key = directory / f"{prefix}-public.pem"
    approval = directory / f"{prefix}.json"
    generate_keypair(
        private_key, public_key,
        passphrase="correct-horse-battery-staple",
    )
    sign_scope(
        scope_path, private_key,
        signer_id="CI-TEST-APPROVER",
        passphrase="correct-horse-battery-staple",
        output_path=approval,
    )
    return approval, public_key


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
    approval_path, approval_key = approve_scope(scope_path, tmp_path, "tcp-run")
    database = tmp_path / "state.sqlite3"
    audit = tmp_path / "audit.jsonl"
    report_path = tmp_path / "report.json"
    try:
        report = run_assessment(
            scope_path,
            approval_path=approval_path,
            approval_public_key_path=approval_key,
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
        checked_report = verify_assessment_report(report_path, audit_path=audit)
        assert checked_report["verified"] is True
        assert checked_report["audit_record_match"] is True
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
            approval_path=approval_path,
            approval_public_key_path=approval_key,
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

    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    server.daemon_threads = True
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
    approval_path, approval_key = approve_scope(scope_path, tmp_path, "http-run")
    try:
        report = run_assessment(
            scope_path,
            approval_path=approval_path,
            approval_public_key_path=approval_key,
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
    assess = parser.parse_args(["security", "assess", "scope.json", "--approval", "approval.json", "--plugin", "web-headers"])
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
    approval_path, approval_key = approve_scope(scope_path, tmp_path, "budget-run")
    audit = tmp_path / "budget-audit.jsonl"

    def forbidden_connect(*args, **kwargs):
        raise AssertionError("No socket connection should occur when the probe budget is exceeded.")

    monkeypatch.setattr("osforge.security.assessment.socket.create_connection", forbidden_connect)
    with pytest.raises(ValueError, match="per-run ceiling"):
        run_assessment(
            scope_path,
            approval_path=approval_path,
            approval_public_key_path=approval_key,
            output_path=tmp_path / "should-not-exist.json",
            database_path=tmp_path / "budget.sqlite3",
            audit_path=audit,
        )
    assert verify_log(audit)[0] is True
    rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["event"] == "assessment.failed"
    assert not (tmp_path / "should-not-exist.json").exists()



def test_scope_approval_verifies_exact_scope_and_detects_tampering(tmp_path):
    scope_path = tmp_path / "approved-scope.json"
    scope_path.write_text(json.dumps(valid_scope()), encoding="utf-8")
    approval_path, public_key = approve_scope(scope_path, tmp_path, "tamper-check")
    checked = verify_scope_approval(scope_path, approval_path, public_key)
    assert checked["verified"] is True
    assert checked["signer_id"] == "CI-TEST-APPROVER"

    data = json.loads(scope_path.read_text(encoding="utf-8"))
    data["ports"].append(8443)
    scope_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match the signed approval"):
        verify_scope_approval(scope_path, approval_path, public_key)


def test_scope_approval_rejects_untrusted_public_key(tmp_path):
    scope_path = tmp_path / "approved-scope.json"
    scope_path.write_text(json.dumps(valid_scope()), encoding="utf-8")
    approval_path, _ = approve_scope(scope_path, tmp_path, "trusted")
    other_private = tmp_path / "other-private.pem"
    other_public = tmp_path / "other-public.pem"
    generate_keypair(
        other_private, other_public,
        passphrase="another-correct-horse-battery",
    )
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_scope_approval(scope_path, approval_path, other_public)


def test_keygen_refuses_to_overwrite_existing_files(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_keypair(private_key, public_key, passphrase="correct-horse-battery-staple")
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        generate_keypair(private_key, tmp_path / "next-public.pem",
                         passphrase="correct-horse-battery-staple")


def test_scope_approval_signature_required_before_any_network_io(tmp_path, monkeypatch):
    scope_path = tmp_path / "unsigned-scope.json"
    scope_path.write_text(json.dumps({
        "schema_version": 1,
        "engagement": {
            "name": "Unsigned scope",
            "owner": "Local tests",
            "authorization_reference": "TEST-UNSIGNED",
            "expires_at": future_expiry(),
        },
        "targets": ["127.0.0.1"],
        "ports": [1],
        "web_urls": [],
    }), encoding="utf-8")

    def forbidden_connect(*args, **kwargs):
        raise AssertionError("Network must not be accessed before signed approval is verified.")

    monkeypatch.setattr("osforge.security.assessment.socket.create_connection", forbidden_connect)
    with pytest.raises((ValueError, OSError)):
        run_assessment(
            scope_path,
            approval_path=tmp_path / "missing-approval.json",
            approval_public_key_path=tmp_path / "missing-public-key.pem",
            output_path=tmp_path / "unsigned-report.json",
            database_path=tmp_path / "unsigned.sqlite3",
            audit_path=tmp_path / "unsigned-audit.jsonl",
        )
    assert not (tmp_path / "unsigned-report.json").exists()



def test_local_bandit_scan_uses_argument_array_and_persists_json(tmp_path, monkeypatch):
    target = tmp_path / "source.py"
    target.write_text("password = 'not-a-real-secret'\n", encoding="utf-8")
    monkeypatch.setattr("osforge.security.local_tools.shutil.which", lambda name: "/fake/bandit")
    observed = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed["shell"] = kwargs["shell"]
        kwargs["stdout"].write(json.dumps({
            "results": [{"test_id": "B105", "issue_severity": "LOW", "issue_text": "Possible hardcoded password"}],
            "metrics": {},
        }).encode())
        return __import__("subprocess").CompletedProcess(argv, 1, stderr=b"1 finding")

    monkeypatch.setattr("osforge.security.local_tools.subprocess.run", fake_run)
    output = tmp_path / "local-bandit.json"
    report = run_local_scan(target, engine="bandit", output_path=output)
    assert observed["shell"] is False
    assert observed["argv"] == ["/fake/bandit", str(target.resolve()), "-f", "json"]
    assert report["exit_code"] == 1
    assert report["results"]["results"][0]["test_id"] == "B105"
    assert json.loads(output.read_text(encoding="utf-8"))["engine"] == "bandit"


def test_local_scan_rejects_remote_paths(tmp_path):
    with pytest.raises(ValueError, match="Remote URLs and UNC"):
        run_local_scan("https://example.com/repository", engine="trivy", output_path=tmp_path / "out.json")
    with pytest.raises(ValueError, match="Remote URLs and UNC"):
        run_local_scan("//server/share/repo", engine="bandit", output_path=tmp_path / "out2.json")


def test_sbom_generation_uses_syft_json_and_refuses_overwrite(tmp_path, monkeypatch):
    target = tmp_path / "project"
    target.mkdir()
    monkeypatch.setattr("osforge.security.local_tools.shutil.which", lambda name: "/fake/syft")
    observed = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed["shell"] = kwargs["shell"]
        return __import__("subprocess").CompletedProcess(
            argv, 0, stdout=json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "example"}]}).encode(),
            stderr=b"",
        )

    monkeypatch.setattr("osforge.security.local_tools.subprocess.run", fake_run)
    destination = tmp_path / "sbom.cdx.json"
    result = generate_sbom(target, output_path=destination)
    assert observed["shell"] is False
    assert observed["argv"] == ["/fake/syft", str(target.resolve()), "-o", "cyclonedx-json"]
    assert result["component_count"] == 1
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        generate_sbom(target, output_path=destination)


def test_cli_has_signature_and_local_defensive_tool_commands():
    parser = build_parser()
    keygen = parser.parse_args([
        "security", "keygen", "--private-key", "private.pem", "--public-key", "public.pem"
    ])
    assert keygen.security_command == "keygen"
    signer = parser.parse_args([
        "security", "scope-sign", "scope.json", "--private-key", "private.pem",
        "--signer-id", "approved-team",
    ])
    assert signer.security_command == "scope-sign"
    local_scan = parser.parse_args([
        "security", "local-scan", ".", "--engine", "bandit", "--output", "report.json"
    ])
    assert local_scan.engine == "bandit"
    sbom = parser.parse_args(["security", "sbom", ".", "--output", "sbom.json"])
    assert sbom.security_command == "sbom"



def test_report_integrity_detects_edits_and_exports_sarif_and_csv(tmp_path):
    report_path = tmp_path / "report.json"
    report = {
        "schema_version": 1,
        "assessment_id": "ASMT-TEST",
        "engagement": {"name": "fixture"},
        "scope": {"targets": ["127.0.0.1"], "ports": [8080]},
        "summary": {"findings_total": 1},
        "findings": [{
            "finding_id": "F-1234567890abcdef",
            "check_id": "tcp-exposure",
            "severity": "medium",
            "title": "Example service reachable",
            "asset": "127.0.0.1:8080",
            "evidence": {"port": 8080, "protocol": "tcp"},
            "remediation": "Limit access to authorized clients.",
            "confidence": "high",
            "status": "open",
            "assignee": "IT Security",
            "due_date": "2030-01-01",
        }],
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    import hashlib
    report["integrity"] = {
        "algorithm": "SHA-256",
        "canonicalization": "JSON sorted keys, compact separators, UTF-8; integrity field excluded",
        "canonical_json_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    assert verify_assessment_report(report_path, audit_path=tmp_path / "no-audit.jsonl")["verified"] is True

    sarif_path = tmp_path / "findings.sarif"
    sarif_result = export_report(report_path, output_path=sarif_path, format="sarif")
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif_result["findings_exported"] == 1
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "warning"

    csv_path = tmp_path / "findings.csv"
    csv_result = export_report(report_path, output_path=csv_path, format="csv")
    assert csv_result["findings_exported"] == 1
    assert "F-1234567890abcdef" in csv_path.read_text(encoding="utf-8")

    report["findings"][0]["title"] = "Tampered"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    with pytest.raises(ValueError, match="integrity mismatch"):
        verify_assessment_report(report_path)


def test_export_refuses_to_overwrite_existing_destination(tmp_path):
    source = tmp_path / "report.json"
    source.write_text(json.dumps({"findings": []}), encoding="utf-8")
    dest = tmp_path / "out.csv"
    dest.write_text("preserve existing content", encoding="utf-8")
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        export_report(source, output_path=dest, format="csv")
    assert dest.read_text(encoding="utf-8") == "preserve existing content"



def test_trusted_approver_store_installs_public_key_and_refuses_overwrite(tmp_path):
    private_key = tmp_path / "approver-private.pem"
    public_key = tmp_path / "approver-public.pem"
    generate_keypair(private_key, public_key, passphrase="correct-horse-battery-staple")
    trust_store = tmp_path / "system-trust"

    installed = trust_public_key(public_key, signer_id="IT-Security-2026", trust_store_dir=trust_store)
    assert installed == trust_store / "IT-Security-2026.pem"
    assert trusted_public_key_path("IT-Security-2026", trust_store) == installed
    with pytest.raises(ValueError, match="already exists"):
        trust_public_key(public_key, signer_id="IT-Security-2026", trust_store_dir=trust_store)
    with pytest.raises(ValueError, match="Signer ID"):
        trust_public_key(public_key, signer_id="../attacker", trust_store_dir=trust_store)


def test_cli_requires_signed_approval_but_not_a_user_supplied_trust_anchor():
    parser = build_parser()
    args = parser.parse_args(["security", "assess", "scope.json", "--approval", "scope.approval.json"])
    assert args.approval == "scope.approval.json"
    assert not hasattr(args, "approval_key")

    verify = parser.parse_args([
        "security", "verify-approval", "scope.json", "--approval", "scope.approval.json"
    ])
    assert verify.security_command == "verify-approval"

    trusted = parser.parse_args([
        "security", "trust-key-add", "approver-public.pem", "--signer-id", "IT-Security-2026"
    ])
    assert trusted.signer_id == "IT-Security-2026"



def test_single_address_cidr_resolves_to_one_host():
    assert _resolve_exact_target("192.0.2.7/32") == ["192.0.2.7"]
    assert _resolve_exact_target("2001:db8::7/128") == ["2001:db8::7"]

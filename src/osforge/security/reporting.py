"""Integrity verification and interoperable security report export."""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
from pathlib import Path
from typing import Any

from osforge.security.audit import default_audit_path, verify_log

LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _read_report(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise ValueError(f"Report file does not exist: {source}")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read JSON report {source}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("A report must be a JSON object.")
    return data


def verify_assessment_report(path: str | Path, *, audit_path: str | Path | None = None) -> dict[str, Any]:
    """Validate the canonical SHA-256 digest embedded in an OS Forge assessment report."""
    report = _read_report(path)
    integrity = report.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "SHA-256":
        raise ValueError("Report has no supported OS Forge SHA-256 integrity block.")
    expected = integrity.get("canonical_json_sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        raise ValueError("Report integrity digest is missing or malformed.")
    payload = dict(report)
    payload.pop("integrity", None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ValueError("Assessment report integrity mismatch; its contents may have changed.")
    report_file = Path(path).expanduser().resolve()
    file_sha256 = hashlib.sha256(report_file.read_bytes()).hexdigest()
    journal_path = Path(audit_path).expanduser().resolve() if audit_path else default_audit_path()
    audit_log_valid: bool | None = None
    audit_record_match: bool | None = None
    audit_message = "No audit journal was found to cross-check the file hash."
    if journal_path.is_file():
        audit_log_valid, _, audit_message = verify_log(journal_path)
        if audit_log_valid:
            matches = []
            for line in journal_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    details = entry.get("details") or {}
                    if (
                        entry.get("event") == "assessment.completed"
                        and str(details.get("assessment_id", "")) == str(report.get("assessment_id", ""))
                        and str(Path(str(details.get("report_path", ""))).expanduser().resolve()) == str(report_file)
                    ):
                        matches.append(details)
                except (OSError, ValueError, TypeError):
                    continue
            if matches:
                audit_record_match = True
                expected_file_hash = matches[-1].get("report_sha256")
                if expected_file_hash and not hmac.compare_digest(file_sha256, str(expected_file_hash)):
                    raise ValueError("Report file hash differs from the matching assessment-completion audit event.")
                audit_message = "Report file hash matches the assessment-completion audit event."
            else:
                audit_record_match = False
                audit_message = "Audit journal is valid, but no matching assessment-completion event was found."
        else:
            audit_record_match = False
    return {
        "verified": True,
        "assessment_id": str(report.get("assessment_id", "")),
        "report_path": str(report_file),
        "canonical_json_sha256": actual,
        "file_sha256": file_sha256,
        "audit_log_valid": audit_log_valid,
        "audit_record_match": audit_record_match,
        "audit_message": audit_message,
        "findings_total": int(report.get("summary", {}).get("findings_total", 0)),
    }


def _findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = report.get("findings", [])
    if not isinstance(findings, list) or not all(isinstance(row, dict) for row in findings):
        raise ValueError("Report findings must be an array of JSON objects.")
    return findings


def _sarif(report: dict[str, Any]) -> dict[str, Any]:
    findings = _findings(report)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in findings:
        rule_id = str(item.get("check_id") or "osforge-unknown")
        title = str(item.get("title") or rule_id)
        remediation = str(item.get("remediation") or "Review this finding manually.")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": title[:300]},
                "help": {"text": remediation[:4000]},
                "properties": {"tags": ["security", "osforge"]},
            }
        severity = str(item.get("severity", "info")).lower()
        properties = {
            "asset": str(item.get("asset", "")),
            "confidence": str(item.get("confidence", "medium")),
            "status": str(item.get("status", "open")),
            "assignee": str(item.get("assignee", "")),
            "dueDate": item.get("due_date"),
            "remediation": remediation,
            "evidence": item.get("evidence", {}),
            "plugin": str(item.get("plugin", "core")),
        }
        result = {
            "ruleId": rule_id,
            "level": LEVELS.get(severity, "note"),
            "message": {"text": title},
            "properties": properties,
        }
        finding_id = item.get("finding_id")
        if finding_id:
            result["partialFingerprints"] = {"osforge/findingId": str(finding_id)}
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OS Forge Security",
                    "semanticVersion": "0.1.0",
                    "informationUri": "https://github.com/reponsekdz3/os",
                    "rules": list(rules.values()),
                },
            },
            "automationDetails": {"id": str(report.get("assessment_id", "osforge-assessment"))},
            "results": results,
            "properties": {
                "engagement": report.get("engagement", {}),
                "scope": report.get("scope", {}),
                "summary": report.get("summary", {}),
                "limitations": report.get("limitations", []),
            },
        }],
    }


def _csv_text(report: dict[str, Any]) -> str:
    fields = [
        "finding_id", "severity", "status", "check_id", "title", "asset",
        "confidence", "plugin", "first_seen", "last_seen", "assignee", "due_date",
        "remediation", "evidence",
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for item in _findings(report):
        row = dict(item)
        row["evidence"] = json.dumps(row.get("evidence", {}), ensure_ascii=False, sort_keys=True)
        writer.writerow(row)
    return output.getvalue()


def export_report(
    report_path: str | Path,
    *,
    output_path: str | Path,
    format: str,
) -> dict[str, Any]:
    """Export an assessment JSON report to SARIF 2.1.0 or CSV without overwriting files."""
    if format not in {"sarif", "csv"}:
        raise ValueError("Export format must be 'sarif' or 'csv'.")
    report = _read_report(report_path)
    if "integrity" in report:
        verify_assessment_report(report_path)
    elif report.get("product") == "OS Forge Security":
        raise ValueError("OS Forge assessment report is missing its integrity block.")
    if "findings" not in report:
        raise ValueError("The selected report does not contain a findings array.")
    source = Path(report_path).expanduser().resolve()
    destination = Path(output_path).expanduser().resolve()
    if source == destination:
        raise ValueError("Output path must differ from input report path.")
    if destination.exists():
        raise ValueError(f"Refusing to overwrite existing export: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    try:
        if format == "sarif":
            temporary.write_text(json.dumps(_sarif(report), indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
        else:
            temporary.write_text(_csv_text(report), encoding="utf-8", newline="")
        if destination.exists():
            raise ValueError(f"Export path appeared while writing; refusing to overwrite: {destination}")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "format": format,
        "output_path": str(destination),
        "assessment_id": str(report.get("assessment_id", "")),
        "findings_exported": len(_findings(report)),
    }

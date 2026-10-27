"""SQLite-backed assessment history and remediation workflow."""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

VALID_STATUSES = {"open", "in_progress", "accepted_risk", "false_positive", "resolved"}
NOTE_REQUIRED = {"accepted_risk", "false_positive", "resolved"}


def default_database_path() -> Path:
    return Path.home() / ".osforge" / "security-state.sqlite3"


def _connect(database_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(database_path).expanduser() if database_path else default_database_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS assessments (
            assessment_id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            scope_name TEXT NOT NULL,
            owner TEXT NOT NULL,
            authorization_reference TEXT NOT NULL,
            report_path TEXT NOT NULL,
            target_count INTEGER NOT NULL,
            tcp_probe_count INTEGER NOT NULL,
            finding_count INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            finding_key TEXT NOT NULL UNIQUE,
            check_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            asset TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            remediation TEXT NOT NULL,
            confidence TEXT NOT NULL,
            plugin TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('open','in_progress','accepted_risk','false_positive','resolved')),
            assignee TEXT NOT NULL DEFAULT '',
            due_date TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            status_note TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS assessment_findings (
            assessment_id TEXT NOT NULL REFERENCES assessments(assessment_id) ON DELETE CASCADE,
            finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
            PRIMARY KEY (assessment_id, finding_id)
        );
        CREATE TABLE IF NOT EXISTS finding_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
            event_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            old_status TEXT NOT NULL,
            new_status TEXT NOT NULL,
            note TEXT NOT NULL,
            assignee TEXT NOT NULL,
            due_date TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_findings_status_severity ON findings(status, severity);
        CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen);
        CREATE INDEX IF NOT EXISTS idx_assessments_completed ON assessments(completed_at DESC);
        """
    )
    if os.name != "nt":
        try:
            path.chmod(0o600)
            path.parent.chmod(0o700)
        except OSError:
            pass
    return connection


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_key(finding: dict[str, Any]) -> str:
    identity = {
        "check_id": str(finding.get("check_id", "")),
        "asset": str(finding.get("asset", "")),
        "title": str(finding.get("title", "")),
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def record_assessment(
    report: dict[str, Any],
    *,
    database_path: str | Path | None = None,
) -> dict[str, Any]:
    """Persist one completed assessment and attach stable remediation identities."""
    scope = report.get("engagement", {})
    summary = report.get("summary", {})
    now = _utcnow()
    connection = _connect(database_path)
    try:
        with connection:
            connection.execute(
                """INSERT INTO assessments
                   (assessment_id, started_at, completed_at, scope_name, owner,
                    authorization_reference, report_path, target_count, tcp_probe_count, finding_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    report["assessment_id"], report["started_at"], report["completed_at"],
                    str(scope.get("name", "")), str(scope.get("owner", "")),
                    str(scope.get("authorization_reference", "")), str(report.get("report_path", "")),
                    int(summary.get("target_address_pairs", 0)), int(summary.get("tcp_probes", 0)),
                    len(report.get("findings", [])),
                ),
            )
            attached: list[dict[str, Any]] = []
            for item in report.get("findings", []):
                finding = dict(item)
                key = _stable_key(finding)
                finding_id = "F-" + key[:16]
                evidence_json = json.dumps(finding.get("evidence", {}), sort_keys=True, ensure_ascii=False)
                existing = connection.execute(
                    "SELECT * FROM findings WHERE finding_key = ?", (key,)
                ).fetchone()
                if existing is None:
                    status = "open"
                    connection.execute(
                        """INSERT INTO findings
                           (finding_id, finding_key, check_id, severity, title, asset, evidence_json,
                            remediation, confidence, plugin, status, first_seen, last_seen, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            finding_id, key, str(finding.get("check_id", "unknown")),
                            str(finding.get("severity", "info")), str(finding.get("title", "")),
                            str(finding.get("asset", "")), evidence_json,
                            str(finding.get("remediation", "")), str(finding.get("confidence", "medium")),
                            str(finding.get("plugin", "core")), status, report["completed_at"],
                            report["completed_at"], now,
                        ),
                    )
                    connection.execute(
                        """INSERT INTO finding_events
                           (finding_id, event_at, actor, old_status, new_status, note, assignee, due_date)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (finding_id, now, getpass.getuser(), "", "open",
                         "First observed by assessment " + str(report["assessment_id"]), "", ""),
                    )
                    assignee, due_date, first_seen = "", "", report["completed_at"]
                else:
                    status = str(existing["status"])
                    # A resolved finding that reappears is reopened; accepted risks remain accepted.
                    # A false-positive classification is reopened when its evidence changes.
                    if status == "resolved" or (
                        status == "false_positive" and existing["evidence_json"] != evidence_json
                    ):
                        connection.execute(
                            """INSERT INTO finding_events
                               (finding_id, event_at, actor, old_status, new_status, note, assignee, due_date)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                existing["finding_id"], now, getpass.getuser(), status, "open",
                                "Finding re-observed in assessment " + str(report["assessment_id"]),
                                str(existing["assignee"]), str(existing["due_date"]),
                            ),
                        )
                        status = "open"
                    finding_id = str(existing["finding_id"])
                    connection.execute(
                        """UPDATE findings
                           SET severity=?, title=?, asset=?, evidence_json=?, remediation=?,
                               confidence=?, plugin=?, status=?, last_seen=?, updated_at=?
                           WHERE finding_id=?""",
                        (
                            str(finding.get("severity", "info")), str(finding.get("title", "")),
                            str(finding.get("asset", "")), evidence_json,
                            str(finding.get("remediation", "")), str(finding.get("confidence", "medium")),
                            str(finding.get("plugin", "core")), status,
                            report["completed_at"], now, finding_id,
                        ),
                    )
                    assignee = str(existing["assignee"])
                    due_date = str(existing["due_date"])
                    first_seen = str(existing["first_seen"])
                connection.execute(
                    "INSERT OR IGNORE INTO assessment_findings (assessment_id, finding_id) VALUES (?, ?)",
                    (report["assessment_id"], finding_id),
                )
                finding.update({
                    "finding_id": finding_id,
                    "status": status,
                    "assignee": assignee,
                    "due_date": due_date or None,
                    "first_seen": first_seen,
                    "last_seen": report["completed_at"],
                })
                attached.append(finding)
            report["findings"] = attached
            report["remediation"] = {
                "database_path": str((Path(database_path).expanduser() if database_path else default_database_path()).resolve()),
                "workflow": ["open", "in_progress", "accepted_risk", "false_positive", "resolved"],
                "note": "Status changes and ownership are persisted locally; see finding events for state history.",
            }
    finally:
        connection.close()
    return report


def list_assessments(
    *, database_path: str | Path | None = None, limit: int = 20,
) -> list[dict[str, Any]]:
    if not 1 <= limit <= 500:
        raise ValueError("History limit must be between 1 and 500.")
    connection = _connect(database_path)
    try:
        rows = connection.execute(
            "SELECT * FROM assessments ORDER BY completed_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def list_findings(
    *, database_path: str | Path | None = None, status: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    if not 1 <= limit <= 1000:
        raise ValueError("Finding limit must be between 1 and 1000.")
    if status and status not in VALID_STATUSES:
        raise ValueError(f"Unsupported finding status {status!r}.")
    connection = _connect(database_path)
    try:
        if status:
            rows = connection.execute(
                """SELECT * FROM findings WHERE status=?
                   ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                   WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC LIMIT ?""",
                (status, limit),
            ).fetchall()
        else:
            rows = connection.execute(
                """SELECT * FROM findings
                   ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                   WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["evidence"] = json.loads(item.pop("evidence_json"))
            except json.JSONDecodeError:
                item["evidence"] = {"error": "Stored evidence could not be decoded"}
            result.append(item)
        return result
    finally:
        connection.close()


def update_finding(
    finding_id: str,
    *,
    status: str,
    note: str,
    assignee: str | None = None,
    due_date: str | None = None,
    database_path: str | Path | None = None,
) -> dict[str, Any]:
    if status not in VALID_STATUSES:
        raise ValueError("Status must be one of: " + ", ".join(sorted(VALID_STATUSES)))
    clean_note = note.strip()
    if status in NOTE_REQUIRED and not clean_note:
        raise ValueError(f"A non-empty note is required when setting status to {status!r}.")
    if len(clean_note) > 4000:
        raise ValueError("Remediation note may not exceed 4000 characters.")
    clean_assignee = (assignee or "").strip()
    if len(clean_assignee) > 200:
        raise ValueError("Assignee may not exceed 200 characters.")
    clean_due = (due_date or "").strip()
    if clean_due:
        try:
            date.fromisoformat(clean_due)
        except ValueError as exc:
            raise ValueError("Due date must use YYYY-MM-DD format.") from exc

    connection = _connect(database_path)
    try:
        with connection:
            row = connection.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
            if row is None:
                raise ValueError(f"Finding {finding_id!r} was not found in the remediation database.")
            old_status = str(row["status"])
            if old_status == status and not clean_note and assignee is None and due_date is None:
                return dict(row)
            new_assignee = str(row["assignee"]) if assignee is None else clean_assignee
            new_due = str(row["due_date"]) if due_date is None else clean_due
            connection.execute(
                """UPDATE findings SET status=?, assignee=?, due_date=?, updated_at=?, status_note=?
                   WHERE finding_id=?""",
                (status, new_assignee, new_due, _utcnow(), clean_note, finding_id),
            )
            connection.execute(
                """INSERT INTO finding_events
                   (finding_id, event_at, actor, old_status, new_status, note, assignee, due_date)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding_id, _utcnow(), getpass.getuser(), old_status, status,
                 clean_note, new_assignee, new_due),
            )
            updated = connection.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
            return dict(updated)
    finally:
        connection.close()


def finding_history(
    finding_id: str, *, database_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    connection = _connect(database_path)
    try:
        exists = connection.execute("SELECT 1 FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        if exists is None:
            raise ValueError(f"Finding {finding_id!r} was not found.")
        rows = connection.execute(
            "SELECT * FROM finding_events WHERE finding_id=? ORDER BY event_id ASC", (finding_id,)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()

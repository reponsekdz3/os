"""Local hash-linked audit journal; tamper-evident, not tamper-proof."""
from __future__ import annotations

import getpass
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ZERO_HASH = "0" * 64


def default_audit_path() -> Path:
    return Path.home() / ".osforge" / "security-audit.jsonl"


def append_event(event: str, *, details: dict[str, Any] | None = None, path: str | Path | None = None) -> dict[str, Any]:
    destination = Path(path).expanduser() if path else default_audit_path()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    previous_hash = ZERO_HASH
    if destination.exists():
        try:
            lines = [line for line in destination.read_text(encoding="utf-8").splitlines() if line.strip()]
            if lines:
                previous_hash = json.loads(lines[-1]).get("entry_hash", "INVALID")
        except (OSError, ValueError, AttributeError):
            previous_hash = "INVALID"
    entry: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": getpass.getuser(),
        "event": event,
        "details": details or {},
        "previous_hash": previous_hash,
    }
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    entry["entry_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    with destination.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
    if os.name != "nt":
        try:
            destination.chmod(0o600)
            destination.parent.chmod(0o700)
        except OSError:
            pass
    return entry


def verify_log(path: str | Path | None = None) -> tuple[bool, int, str]:
    destination = Path(path).expanduser() if path else default_audit_path()
    if not destination.exists():
        return True, 0, "Audit log does not exist yet."
    previous_hash, count = ZERO_HASH, 0
    try:
        lines = destination.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return False, 0, f"Cannot read audit log: {exc}"
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            actual = entry.pop("entry_hash")
            if entry.get("previous_hash") != previous_hash:
                return False, count, f"Broken hash chain at line {number}."
            canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if actual != expected:
                return False, count, f"Entry hash mismatch at line {number}."
            previous_hash, count = actual, count + 1
        except (ValueError, KeyError, TypeError):
            return False, count, f"Malformed audit record at line {number}."
    return True, count, f"Verified {count} audit events."

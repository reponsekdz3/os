"""Explicitly invoked local code/dependency scanning and SBOM generation.

No engine accepts a URL or remote target. Scanner binaries are external dependencies and may
access their own vulnerability databases; their source and network behavior must be reviewed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

MAX_REPORT_BYTES = 50 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 300
ENGINES = {"bandit", "trivy"}


def _local_path(value: str | Path) -> Path:
    raw = str(value).strip()
    if not raw:
        raise ValueError("A local file or directory path is required.")
    if "://" in raw or raw.startswith(("\\\\", "//")):
        raise ValueError("Remote URLs and UNC/network paths are not accepted; choose a local filesystem path.")
    candidate = Path(value).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"Local path does not exist or is inaccessible: {exc}") from exc
    if not resolved.exists():
        raise ValueError(f"Local path does not exist: {resolved}")
    return resolved


def _atomic_json(path: str | Path, data: Any) -> Path:
    destination = Path(path).expanduser().resolve()
    if destination.exists():
        raise ValueError(f"Refusing to overwrite existing report: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_suffix(destination.suffix + ".tmp")
    try:
        temp.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
        if destination.exists():
            raise ValueError(f"Report path appeared during write; refusing to overwrite: {destination}")
        temp.replace(destination)
    finally:
        temp.unlink(missing_ok=True)
    return destination


def _scanner_command(engine: str, executable: str, target: Path) -> list[str]:
    if engine == "bandit":
        if target.is_file() and target.suffix.lower() != ".py":
            raise ValueError("Bandit scans Python source: choose a .py file or a directory containing Python code.")
        return [executable, "-r", str(target), "-f", "json"] if target.is_dir() else [
            executable, str(target), "-f", "json"
        ]
    if engine == "trivy":
        return [executable, "fs", "--format", "json", "--scanners", "vuln,misconfig,secret", str(target)]
    raise ValueError(f"Unsupported local scan engine {engine!r}. Supported: {', '.join(sorted(ENGINES))}.")


def run_local_scan(
    path: str | Path,
    *,
    engine: str,
    output_path: str | Path,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    if engine not in ENGINES:
        raise ValueError(f"Unsupported local scan engine {engine!r}. Supported: {', '.join(sorted(ENGINES))}.")
    if not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"Timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds.")
    target = _local_path(path)
    executable = shutil.which(engine)
    if not executable:
        install_hint = "Install Bandit in this Python environment." if engine == "bandit" else "Install Trivy from its official release."
        raise RuntimeError(f"{engine} is not installed or not on PATH. {install_hint}")
    argv = _scanner_command(engine, executable, target)
    started_at = datetime.now(timezone.utc).isoformat()
    start = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="osforge-scan-") as temp_dir:
        raw_path = Path(temp_dir) / "raw.json"
        try:
            with raw_path.open("wb") as stdout_file:
                completed = subprocess.run(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=subprocess.PIPE,
                    timeout=timeout_seconds,
                    check=False,
                    shell=False,
                )
        except subprocess.TimeoutExpired as exc:
            report = {
                "schema_version": 1,
                "product": "OS Forge Security / local scan",
                "engine": engine,
                "target": str(target),
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(time.perf_counter() - start, 3),
                "command": argv,
                "exit_code": 124,
                "results": None,
                "error": f"Scanner exceeded the {timeout_seconds}-second timeout: {exc}",
                "parse_error": "timeout",
                "stderr": "",
                "limitations": ["The scanner timed out; partial output was discarded."],
            }
            destination = _atomic_json(output_path, report)
            return {
                "engine": engine, "target": str(target), "exit_code": 124,
                "report_path": str(destination), "error": report["error"], "parse_error": "timeout",
            }
        stderr = completed.stderr.decode("utf-8", errors="replace")[-12000:]
        size = raw_path.stat().st_size
        if size > MAX_REPORT_BYTES:
            parsed: Any = None
            parse_error = f"Scanner output exceeded the {MAX_REPORT_BYTES}-byte report limit."
        elif size == 0:
            parsed = None
            parse_error = "The selected scanner returned no JSON output."
        else:
            try:
                parsed = json.loads(raw_path.read_text(encoding="utf-8"))
                parse_error = None
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                parsed = None
                parse_error = f"Scanner output could not be parsed as JSON: {exc}"
    completed_at = datetime.now(timezone.utc).isoformat()
    report = {
        "schema_version": 1,
        "product": "OS Forge Security / local scan",
        "engine": engine,
        "target": str(target),
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": round(time.perf_counter() - start, 3),
        "command": argv,
        "exit_code": int(completed.returncode),
        "results": parsed,
        "stderr": stderr,
        "parse_error": parse_error,
        "limitations": [
            "This is a local source/filesystem assessment, not a remote target scan.",
            "The scanner's rule coverage and accuracy remain the responsibility of the scanner publisher.",
            "Trivy may contact external vulnerability-database services to acquire or refresh data.",
            "A successful or empty scan does not prove the target is secure.",
        ],
    }
    destination = _atomic_json(output_path, report)
    report["report_path"] = str(destination)
    return report


def generate_sbom(
    path: str | Path,
    *,
    output_path: str | Path,
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    if not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"Timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds.")
    target = _local_path(path)
    executable = shutil.which("syft")
    if not executable:
        raise RuntimeError("syft is not installed or not on PATH. Install it from its official distribution.")
    argv = [executable, str(target), "-o", "cyclonedx-json"]
    started_at = datetime.now(timezone.utc).isoformat()
    start = time.perf_counter()
    try:
        completed = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_seconds, check=False, shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"syft timed out after {timeout_seconds} seconds: {exc}") from exc
    stderr = completed.stderr.decode("utf-8", errors="replace")[-12000:]
    if completed.returncode != 0:
        raise RuntimeError(f"syft exited with status {completed.returncode}: {stderr}")
    if len(completed.stdout) > MAX_REPORT_BYTES:
        raise RuntimeError(f"Syft output exceeded the {MAX_REPORT_BYTES}-byte SBOM limit.")
    try:
        sbom = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Syft did not return valid JSON: {exc}") from exc
    destination = _atomic_json(output_path, sbom)
    return {
        "tool": "syft",
        "target": str(target),
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.perf_counter() - start, 3),
        "component_count": len(sbom.get("components", [])) if isinstance(sbom, dict) else 0,
        "report_path": str(destination),
        "stderr": stderr,
    }

"""Live process and listening-port inspection."""

from __future__ import annotations

import os
from dataclasses import dataclass

import psutil


@dataclass(frozen=True)
class ProcessRow:
    pid: int
    name: str
    username: str
    status: str
    cpu_percent: float
    memory_percent: float


def list_processes(limit: int = 25) -> list[ProcessRow]:
    if not 1 <= limit <= 500:
        raise ValueError("Process limit must be between 1 and 500.")
    rows: list[ProcessRow] = []
    for proc in psutil.process_iter(["pid", "name", "username", "status", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            rows.append(
                ProcessRow(
                    pid=int(info.get("pid") or 0),
                    name=str(info.get("name") or "unknown"),
                    username=str(info.get("username") or ""),
                    status=str(info.get("status") or "unknown"),
                    cpu_percent=float(info.get("cpu_percent") or 0.0),
                    memory_percent=float(info.get("memory_percent") or 0.0),
                )
            )
        except (psutil.Error, OSError, ValueError):
            continue
    rows.sort(key=lambda row: (row.cpu_percent, row.memory_percent), reverse=True)
    return rows[:limit]


def process_identity(pid: int) -> ProcessRow:
    if pid <= 0:
        raise ValueError("PID must be a positive integer.")
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            return ProcessRow(
                pid=proc.pid,
                name=proc.name(),
                username=proc.username(),
                status=proc.status(),
                cpu_percent=proc.cpu_percent(interval=0.0),
                memory_percent=proc.memory_percent(),
            )
    except psutil.NoSuchProcess as exc:
        raise ValueError(f"No process with PID {pid} exists.") from exc
    except psutil.AccessDenied as exc:
        raise PermissionError(f"Access denied when inspecting PID {pid}.") from exc


def terminate_process(pid: int) -> None:
    """Terminate the chosen process; callers must confirm with the user first."""
    if pid == os.getpid():
        raise ValueError("Refusing to terminate OS Forge itself.")
    try:
        process = psutil.Process(pid)
        process.terminate()
    except psutil.NoSuchProcess as exc:
        raise ValueError(f"No process with PID {pid} exists.") from exc
    except psutil.AccessDenied as exc:
        raise PermissionError(f"Access denied when terminating PID {pid}.") from exc


def listening_ports() -> list[tuple[str, int, int, str]]:
    """Return local listening TCP sockets where the OS exposes them."""
    rows: list[tuple[str, int, int, str]] = []
    for item in psutil.net_connections(kind="tcp"):
        if item.status != psutil.CONN_LISTEN or item.laddr is None:
            continue
        address = item.laddr
        host = getattr(address, "ip", address[0] if address else "")
        port = getattr(address, "port", address[1] if address else 0)
        pid = item.pid or 0
        try:
            process_name = psutil.Process(pid).name() if pid else "unknown"
        except (psutil.Error, OSError):
            process_name = "unavailable"
        rows.append((str(host), int(port), int(pid), process_name))
    return sorted(set(rows), key=lambda row: (row[1], row[0]))

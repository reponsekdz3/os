"""Real host system inventory and health checks."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import sys
import time
from pathlib import Path
from typing import Any

import psutil


def is_admin() -> bool:
    """Return whether this process currently has elevated privileges."""
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    getter = getattr(os, "geteuid", None)
    return bool(getter and getter() == 0)


def system_info() -> dict[str, Any]:
    """Collect live platform, resource, network, and runtime details."""
    boot_time = psutil.boot_time()
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        host_ip = "unavailable"

    try:
        disk = shutil.disk_usage(Path.home())
        disk_total = disk.total
        disk_free = disk.free
    except OSError:
        disk_total = 0
        disk_free = 0

    vm = psutil.virtual_memory()
    return {
        "Operating system": platform.system() or "Unknown",
        "OS release": platform.release() or "Unknown",
        "OS version": platform.version() or "Unknown",
        "Distribution": _distribution(),
        "Architecture": platform.machine() or "Unknown",
        "Hostname": socket.gethostname(),
        "Resolved host IP": host_ip,
        "CPU cores": os.cpu_count() or 1,
        "CPU usage": f"{psutil.cpu_percent(interval=0.1):.1f}%",
        "Memory total": _bytes(vm.total),
        "Memory available": _bytes(vm.available),
        "Memory usage": f"{vm.percent:.1f}%",
        "Home disk total": _bytes(disk_total),
        "Home disk free": _bytes(disk_free),
        "Python": platform.python_version(),
        "Python executable": sys.executable,
        "Uptime": _duration(max(0, time.time() - boot_time)),
        "Elevated": "yes" if is_admin() else "no",
        "Working directory": str(Path.cwd()),
    }


def _distribution() -> str:
    if platform.system() == "Linux":
        try:
            import platform as platform_module

            info = platform_module.freedesktop_os_release()
            return info.get("PRETTY_NAME") or info.get("NAME") or "Linux"
        except (AttributeError, OSError):
            return "Linux (distribution metadata unavailable)"
    if platform.system() == "Darwin":
        return "macOS"
    if platform.system() == "Windows":
        return "Windows"
    return platform.system() or "Unknown"


def _bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if amount < 1024 or unit == "PiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} PiB"


def _duration(seconds: int | float) -> str:
    value = int(seconds)
    days, value = divmod(value, 86_400)
    hours, value = divmod(value, 3_600)
    minutes, _ = divmod(value, 60)
    chunks = []
    if days:
        chunks.append(f"{days}d")
    if hours or days:
        chunks.append(f"{hours}h")
    chunks.append(f"{minutes}m")
    return " ".join(chunks)


def doctor_checks() -> list[tuple[str, str, str]]:
    """Return truthful health checks without modifying the host."""
    resolver_ok = _resolver_status()
    checks: list[tuple[str, str, str]] = [
        ("Python", sys.version.split()[0], "OK" if sys.version_info >= (3, 11) else "OLD"),
        ("Platform", f"{platform.system()} {platform.machine()}", "OK"),
        ("PATH", os.environ.get("PATH", "")[:180] or "empty", "OK" if os.environ.get("PATH") else "WARN"),
        ("Network resolver", "available" if resolver_ok else "unavailable", "OK" if resolver_ok else "WARN"),
        ("Privilege", "elevated" if is_admin() else "standard user", "INFO"),
    ]
    for executable in ("git", "curl", "ssh", "python"):
        location = shutil.which(executable)
        checks.append((executable, location or "not found on PATH", "OK" if location else "INFO"))
    return checks


def _resolver_status() -> bool:
    try:
        socket.getaddrinfo("localhost", None)
        return True
    except OSError:
        return False

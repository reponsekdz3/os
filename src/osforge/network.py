"""Cross-platform host network information and bounded diagnostics."""

from __future__ import annotations

import platform
import socket
import subprocess

import psutil


def interfaces() -> list[tuple[str, str, str]]:
    """Return interface names, addresses, and address families from the host."""
    rows: list[tuple[str, str, str]] = []
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name in sorted(addresses, key=str.casefold):
        state = "up" if stats.get(name) and stats[name].isup else "down"
        for address in addresses[name]:
            if address.family == socket.AF_INET:
                family = "IPv4"
            elif address.family == socket.AF_INET6:
                family = "IPv6"
            else:
                continue
            rows.append((name, family, f"{address.address} ({state})"))
    return rows


def resolve_host(host: str) -> list[tuple[str, str]]:
    """Resolve one hostname using the configured system resolver."""
    target = validate_host(host)
    try:
        results = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"DNS lookup failed for {target}: {exc}") from exc
    unique: set[tuple[str, str]] = set()
    for family, _, _, _, sockaddr in results:
        family_name = "IPv6" if family == socket.AF_INET6 else "IPv4"
        unique.add((family_name, sockaddr[0]))
    return sorted(unique)


def validate_host(host: str) -> str:
    value = host.strip()
    if not value or len(value) > 253 or any(ch.isspace() for ch in value):
        raise ValueError("Host must be a non-empty hostname or IP address without whitespace.")
    if value.startswith("-") or value.startswith("/"):
        raise ValueError("Invalid host.")
    return value


def build_ping_command(host: str, count: int = 4) -> list[str]:
    """Build a bounded host-native ping command."""
    target = validate_host(host)
    if not 1 <= count <= 4:
        raise ValueError("Ping count must be between 1 and 4.")
    if platform.system() == "Windows":
        return ["ping", "-n", str(count), target]
    return ["ping", "-c", str(count), target]


def check_tcp(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    """Attempt a single TCP connection to one explicitly named endpoint."""
    target = validate_host(host)
    if not 1 <= int(port) <= 65535:
        raise ValueError("TCP port must be between 1 and 65535.")
    if not 0.1 <= timeout <= 10:
        raise ValueError("Timeout must be between 0.1 and 10 seconds.")
    try:
        with socket.create_connection((target, int(port)), timeout=timeout):
            return True, f"Connection to {target}:{port} succeeded."
    except (TimeoutError, OSError) as exc:
        return False, f"Connection to {target}:{port} failed: {exc}"


def run_ping(host: str, count: int = 4) -> int:
    argv = build_ping_command(host, count)
    try:
        return subprocess.run(argv, check=False, shell=False, timeout=15).returncode
    except FileNotFoundError:
        raise RuntimeError("The host ping executable was not found on PATH.") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError("Ping exceeded its 15-second safety timeout.") from None

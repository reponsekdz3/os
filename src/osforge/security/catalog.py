"""Discover local defensive security tools without executing them."""
from __future__ import annotations

import importlib.metadata
import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityTool:
    name: str
    category: str
    purpose: str
    executable_names: tuple[str, ...] = ()


TOOLS: tuple[SecurityTool, ...] = (
    SecurityTool("bandit", "SAST", "Python source-code security analysis"),
    SecurityTool("semgrep", "SAST", "Pattern-based source-code analysis"),
    SecurityTool("gitleaks", "Secrets", "Repository secret-pattern detection"),
    SecurityTool("trivy", "SCA / configuration", "Local filesystem dependency and misconfiguration scanning"),
    SecurityTool("grype", "SCA", "Software composition vulnerability analysis"),
    SecurityTool("syft", "SBOM", "Software bill-of-materials generation"),
    SecurityTool("osv-scanner", "SCA", "Dependency vulnerability checks"),
    SecurityTool("checkov", "IaC", "Infrastructure-as-code policy checks"),
    SecurityTool("lynis", "Host audit", "Unix-like host security configuration audit"),
    SecurityTool("clamdscan", "Malware", "ClamAV daemon-backed file scan"),
    SecurityTool("yara", "Malware triage", "Rule-driven file classification"),
    SecurityTool("osqueryi", "Endpoint", "SQL-based endpoint inventory"),
    SecurityTool("falco", "Runtime", "Runtime threat detection"),
    SecurityTool("auditctl", "Linux audit", "Linux kernel audit-rule management"),
    SecurityTool("journalctl", "Logs", "systemd journal inspection"),
    SecurityTool("ss", "Network", "Socket statistics"),
    SecurityTool("nft", "Firewall", "nftables ruleset inspection"),
    SecurityTool("ufw", "Firewall", "Uncomplicated Firewall status"),
    SecurityTool("firewall-cmd", "Firewall", "firewalld management"),
    SecurityTool("powershell", "Windows", "Windows security and event-log administration", ("pwsh", "powershell.exe", "powershell")),
    SecurityTool("manage-bde", "Disk encryption", "Windows BitLocker status"),
    SecurityTool("fdesetup", "Disk encryption", "macOS FileVault status"),
    SecurityTool("spctl", "macOS", "Gatekeeper policy status"),
    SecurityTool("ssh", "Remote administration", "Secure shell client"),
    SecurityTool("openssl", "Cryptography", "TLS certificate and crypto tooling"),
    SecurityTool("docker", "Containers", "Container administration"),
    SecurityTool("podman", "Containers", "Rootless-capable container administration"),
    SecurityTool("kubectl", "Cloud-native", "Kubernetes administration"),
    SecurityTool("terraform", "Cloud-native", "Infrastructure-as-code"),
)


def discovered_tools() -> list[tuple[SecurityTool, str | None]]:
    rows = []
    for tool in TOOLS:
        path = next((shutil.which(item) for item in tool.executable_names or (tool.name,) if shutil.which(item)), None)
        rows.append((tool, path))
    return rows


def installed_security_extensions() -> list[tuple[str, str]]:
    """List Python extension metadata without importing extension code."""
    try:
        entry_points = importlib.metadata.entry_points()
        extensions = entry_points.select(group="osforge.security_checks")
    except (AttributeError, TypeError):
        extensions = []
    return [(entry.name, entry.value) for entry in extensions]

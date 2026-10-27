"""Read-only local host security posture checks."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import psutil

from osforge.security.catalog import discovered_tools
from osforge.system import is_admin


@dataclass(frozen=True)
class PostureFinding:
    check_id: str
    severity: str
    title: str
    status: str
    evidence: str
    remediation: str


def _run_read_only(argv: Sequence[str], timeout: float = 4.0) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False, shell=False,
        )
        return result.returncode, result.stdout[:5000], result.stderr[:1000]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def _finding(check_id: str, severity: str, title: str, status: str, evidence: str, remediation: str) -> PostureFinding:
    return PostureFinding(check_id, severity, title, status, evidence, remediation)


def _firewall_check() -> PostureFinding:
    system = platform.system()
    if system == "Windows":
        executable = shutil.which("powershell.exe") or shutil.which("pwsh") or shutil.which("powershell")
        if not executable:
            return _finding("host-firewall", "unknown", "Windows firewall status unavailable", "UNKNOWN",
                            "PowerShell was not found on PATH.", "Use Windows Security to inspect all firewall profiles.")
        script = "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
        code, out, err = _run_read_only([executable, "-NoProfile", "-NonInteractive", "-Command", script])
        if code == 0:
            try:
                data = json.loads(out)
                profiles = data if isinstance(data, list) else [data]
                disabled = [str(p.get("Name", "unknown")) for p in profiles if not p.get("Enabled", False)]
                if profiles and not disabled:
                    return _finding("host-firewall", "info", "Windows firewall profiles enabled", "PASS",
                                    f"Enabled profiles: {', '.join(str(p.get('Name', 'unknown')) for p in profiles)}.",
                                    "Keep firewall profiles enabled and review inbound rules periodically.")
                return _finding("host-firewall", "medium", "One or more Windows firewall profiles are disabled", "REVIEW",
                                f"Disabled profiles: {', '.join(disabled) or 'profile status could not be parsed'}.",
                                "Enable the appropriate firewall profiles in Windows Security or through managed policy.")
            except (ValueError, TypeError, AttributeError):
                pass
        return _finding("host-firewall", "unknown", "Windows firewall status could not be verified", "UNKNOWN",
                        (err or out or "PowerShell command failed.")[:600],
                        "Inspect the Domain, Private, and Public firewall profiles using Windows Security.")
    if system == "Darwin":
        executable = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        if not Path(executable).exists():
            return _finding("host-firewall", "unknown", "macOS application firewall status unavailable", "UNKNOWN",
                            "socketfilterfw was not found.", "Inspect Firewall settings in System Settings > Network.")
        code, out, err = _run_read_only([executable, "--getglobalstate"])
        text = (out + " " + err).strip()
        if code == 0 and ("enabled" in text.lower() or "state = 1" in text.lower()):
            return _finding("host-firewall", "info", "macOS application firewall enabled", "PASS", text[:500],
                            "Keep the firewall enabled and review application access rules.")
        if "disabled" in text.lower() or "state = 0" in text.lower():
            return _finding("host-firewall", "medium", "macOS application firewall disabled", "REVIEW", text[:500],
                            "Enable the firewall in System Settings > Network > Firewall if appropriate for this host.")
        return _finding("host-firewall", "unknown", "macOS firewall status could not be verified", "UNKNOWN",
                        text[:500] or f"exit status {code}", "Review the firewall state in System Settings.")
    if system == "Linux":
        states: list[tuple[str, bool, str]] = []
        if shutil.which("ufw"):
            code, out, err = _run_read_only(["ufw", "status"])
            states.append(("ufw", code == 0 and "status: active" in out.lower(), (out or err).strip()[:400]))
        if shutil.which("firewall-cmd"):
            code, out, err = _run_read_only(["firewall-cmd", "--state"])
            states.append(("firewalld", code == 0 and "running" in out.lower(), (out or err).strip()[:400]))
        if shutil.which("nft"):
            code, out, err = _run_read_only(["nft", "list", "ruleset"])
            has_rules = code == 0 and bool(out.strip()) and "no such file" not in err.lower()
            states.append(("nftables", has_rules, (out or err).strip()[:400] or "empty ruleset"))
        if shutil.which("iptables"):
            code, out, err = _run_read_only(["iptables", "-S"])
            # A successful query proves access to the rules, not that the rules are protective.
            states.append(("iptables", code == 0 and bool(out.strip()), (out or err).strip()[:400] or "no visible rules"))
        if not states:
            return _finding("host-firewall", "unknown", "Linux firewall tooling not detected", "UNKNOWN",
                            "Could not find ufw, firewall-cmd, nft, or iptables on PATH.",
                            "Inspect the host/network firewall implementation manually; absence of these tools does not prove no firewall exists.")
        active = [name for name, enabled, _ in states if enabled]
        if active:
            evidence = "; ".join(f"{name}: {detail}" for name, _, detail in states)
            return _finding("host-firewall", "info", "Linux firewall rules/tooling appear active", "REVIEW", evidence[:1500],
                            "Review the complete ruleset against the host's intended inbound/outbound policy.")
        evidence = "; ".join(f"{name}: {detail}" for name, _, detail in states)
        return _finding("host-firewall", "medium", "No active firewall was confirmed by available tools", "REVIEW",
                        evidence[:1500], "Check the host and network firewall policy; do not enable rules without testing required services.")
    return _finding("host-firewall", "unknown", "Firewall check unsupported on this platform", "UNKNOWN",
                    system, "Inspect the operating system's native firewall controls.")


def _ssh_config_checks() -> list[PostureFinding]:
    if platform.system() != "Linux":
        return []
    config = Path("/etc/ssh/sshd_config")
    if not config.exists():
        return []
    findings: list[PostureFinding] = []
    values: dict[str, str] = {}
    try:
        for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                values[parts[0].casefold()] = parts[1].strip().casefold()
    except OSError as exc:
        return [_finding("ssh-config", "unknown", "SSH server configuration not readable", "UNKNOWN", str(exc),
                         "Review sshd_config using an administrator-approved method.")]
    if values.get("permitrootlogin") == "yes":
        findings.append(_finding("ssh-root-login", "medium", "SSH root login explicitly enabled", "REVIEW",
                                 "PermitRootLogin yes is set in the main sshd_config file.",
                                 "Prefer named administrator accounts with key-based authentication and disable direct root login where operationally safe. Check included config files and effective sshd settings."))
    if values.get("passwordauthentication") == "yes":
        findings.append(_finding("ssh-password-auth", "low", "SSH password authentication explicitly enabled", "REVIEW",
                                 "PasswordAuthentication yes is set in the main sshd_config file.",
                                 "Evaluate key-based authentication and MFA; verify the effective configuration before changing access policy."))
    if not findings:
        findings.append(_finding("ssh-config", "info", "No obvious risky SSH directives found in the main file", "LIMITED",
                                 "Only uncommented directives in /etc/ssh/sshd_config were checked; includes and effective configuration were not evaluated.",
                                 "Use the distribution's sshd -T output and review Include directives for a complete configuration audit."))
    return findings


def run_host_posture() -> dict[str, object]:
    """Gather defensive posture signals without changing host state."""
    started = datetime.now(timezone.utc).isoformat()
    findings = [_firewall_check(), *_ssh_config_checks()]
    try:
        vm = psutil.virtual_memory()
        if vm.percent >= 95:
            findings.append(_finding("resource-pressure", "low", "System memory pressure is high", "REVIEW",
                                     f"Current memory usage: {vm.percent:.1f}%.",
                                     "Identify resource-heavy processes and confirm whether this pressure is expected."))
        listeners = psutil.net_connections(kind="tcp")
        wildcard = []
        for item in listeners:
            if item.status != psutil.CONN_LISTEN or not item.laddr:
                continue
            address = getattr(item.laddr, "ip", item.laddr[0] if item.laddr else "")
            if address in {"0.0.0.0", "::", "::0"}:
                wildcard.append((address, getattr(item.laddr, "port", item.laddr[1]), item.pid or 0))
        if wildcard:
            sample = ", ".join(f"{address}:{port}/tcp pid={pid}" for address, port, pid in wildcard[:25])
            findings.append(_finding("wildcard-listeners", "low", "Services listen on wildcard interfaces", "REVIEW",
                                     f"{len(wildcard)} listener(s) bound to all IPv4/IPv6 interfaces; examples: {sample}",
                                     "Confirm each service is intended to accept traffic on every interface and restrict with binding/firewall rules as needed."))
        else:
            findings.append(_finding("wildcard-listeners", "info", "No wildcard TCP listeners were observed", "PASS",
                                     "No IPv4/IPv6 wildcard TCP listener was visible to this process.",
                                     "Repeat with appropriate privileges if you need a complete socket inventory."))
    except (psutil.Error, OSError) as exc:
        findings.append(_finding("local-listeners", "unknown", "Listener inventory incomplete", "UNKNOWN", str(exc),
                                 "Run an approved native socket inspection tool if full visibility is required."))

    home = Path.home()
    if os.name != "nt":
        try:
            mode = home.stat().st_mode
            if mode & 0o002:
                findings.append(_finding("home-permissions", "medium", "Home directory is world-writable", "REVIEW",
                                         f"Home directory mode: {oct(mode & 0o777)}.",
                                         "Review directory ownership and permissions before changing them."))
            else:
                findings.append(_finding("home-permissions", "info", "Home directory is not world-writable", "PASS",
                                         f"Home directory mode: {oct(mode & 0o777)}.",
                                         "Keep private files and security credentials protected by least-privilege permissions."))
        except OSError as exc:
            findings.append(_finding("home-permissions", "unknown", "Home directory permissions unavailable", "UNKNOWN",
                                     str(exc), "Inspect home-directory ownership and permissions."))
    found_tools = sum(1 for _, path in discovered_tools() if path)
    findings.append(_finding("security-tooling", "info", "Local security tool availability inventoried", "INFO",
                             f"{found_tools} catalogued security tools found on PATH.",
                             "Install trusted tools selectively and verify their signatures and update mechanisms."))

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "info": 5}
    findings.sort(key=lambda item: (severity_rank.get(item.severity, 6), item.check_id))
    counts = {severity: sum(1 for item in findings if item.severity == severity)
              for severity in ("critical", "high", "medium", "low", "unknown", "info")}
    return {
        "schema_version": 1,
        "product": "OS Forge Security",
        "started_at": started,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "host": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "elevated": is_admin(),
            "python": platform.python_version(),
        },
        "summary": {"findings_total": len(findings), "findings_by_severity": counts},
        "findings": [asdict(finding) for finding in findings],
        "limitations": [
            "Read-only local checks only; this report is not a penetration test.",
            "Some commands expose incomplete information to standard users.",
            "Configuration directives are heuristics, not a guarantee of effective policy.",
        ],
    }

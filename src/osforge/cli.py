"""CLI and interactive launcher for OS Forge."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import sqlite3
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

import psutil
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from osforge import __version__
from osforge.network import check_tcp, interfaces, resolve_host, run_ping
from osforge.packages import (
    build_action_commands,
    build_list_command,
    build_search_command,
    choose_manager,
    detected_managers,
    execute_commands,
)
from osforge.processes import list_processes, listening_ports, process_identity, terminate_process
from osforge.system import doctor_checks, system_info
from osforge.tools import TOOLS, discover_tools
from osforge.security.audit import append_event, verify_log
from osforge.security.approval import (approval_signer_id, default_trust_store_dir, generate_keypair, sign_scope, trust_public_key, trusted_public_key_path, verify_scope_approval)
from osforge.security.assessment import run_assessment
from osforge.security.catalog import discovered_tools, installed_security_extensions
from osforge.security.posture import run_host_posture
from osforge.security.plugins import discover_plugins, validate_plugin_selection
from osforge.security.state import finding_history, list_assessments, list_findings, update_finding
from osforge.security.local_tools import generate_sbom, run_local_scan
from osforge.security.reporting import export_report, verify_assessment_report
from osforge.security.scope import create_scope_manifest, load_scope

console = Console()
BUILTINS = {
    "launch", "info", "doctor", "tools", "processes", "kill", "ports",
    "net", "pkg", "run", "shell", "security",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osforge",
        description="OS Forge — a real Windows/macOS/Linux terminal and host workbench.",
        epilog="Run without arguments to open the interactive launcher.",
    )
    parser.add_argument("--version", action="version", version=f"osforge {__version__}")
    commands = parser.add_subparsers(dest="command")

    commands.add_parser("launch", help="open the interactive terminal launcher")
    commands.add_parser("info", help="show real host system and resource information")
    commands.add_parser("doctor", help="run read-only host and tool diagnostics")

    tool_parser = commands.add_parser("tools", help="discover available administration and developer tools")
    tool_parser.add_argument("query", nargs="?", default="", help="filter by tool name, category, or description")
    tool_parser.add_argument("--all", action="store_true", help="include tools not found on PATH")

    process_parser = commands.add_parser("processes", help="list running host processes")
    process_parser.add_argument("limit", nargs="?", type=int, default=25, help="number of processes to show (1–500)")

    kill_parser = commands.add_parser("kill", help="terminate a process after confirmation")
    kill_parser.add_argument("pid", type=int, help="process ID to terminate")

    commands.add_parser("ports", help="list local TCP listening sockets")

    net_parser = commands.add_parser("net", help="network diagnostics")
    net_commands = net_parser.add_subparsers(dest="net_command", required=True)
    net_commands.add_parser("interfaces", help="show host network interfaces")
    dns_parser = net_commands.add_parser("dns", help="resolve one hostname with the system resolver")
    dns_parser.add_argument("host")
    ping_parser = net_commands.add_parser("ping", help="send up to four host-native ping requests")
    ping_parser.add_argument("host")
    check_parser = net_commands.add_parser("check", help="test one explicitly specified TCP host and port")
    check_parser.add_argument("host")
    check_parser.add_argument("port", type=int)

    pkg_parser = commands.add_parser("pkg", help="manage packages through an installed native package manager")
    pkg_commands = pkg_parser.add_subparsers(dest="pkg_command", required=True)
    for action in ("list", "search", "install", "remove", "update"):
        sub = pkg_commands.add_parser(action, help=f"native package-manager {action} action")
        sub.add_argument("--manager", choices=(
            "winget", "choco", "scoop", "brew", "port", "apt", "apt-get",
            "dnf", "yum", "pacman", "zypper", "apk", "snap", "flatpak", "nix-env", "emerge",
        ))
        if action == "search":
            sub.add_argument("query")
        elif action in {"install", "remove"}:
            sub.add_argument("package")
            sub.add_argument("--yes", action="store_true", help="skip OS Forge confirmation prompt")
        elif action == "update":
            sub.add_argument("--yes", action="store_true", help="skip OS Forge confirmation prompt")

    run_parser = commands.add_parser("run", help="run a real executable without a shell")
    run_parser.add_argument("argv", nargs=argparse.REMAINDER, help="program and arguments to execute")

    security_parser = commands.add_parser("security", help="defensive security posture and local assessment tools")
    security_commands = security_parser.add_subparsers(dest="security_command", required=True)

    keygen_parser = security_commands.add_parser("keygen", help="generate an Ed25519 key pair for approved scope signatures")
    keygen_parser.add_argument("--private-key", required=True, help="new encrypted private key path")
    keygen_parser.add_argument("--public-key", required=True, help="new public trust-anchor path")

    sign_parser = security_commands.add_parser("scope-sign", help="sign a scope manifest after independent authorization review")
    sign_parser.add_argument("scope_file")
    sign_parser.add_argument("--private-key", required=True)
    sign_parser.add_argument("--signer-id", required=True, help="organization approver identity or key ID")
    sign_parser.add_argument("--expires-at", help="optional approval expiry, no later than scope expiry")
    sign_parser.add_argument("--output", default="scope.approval.json")

    approval_parser = security_commands.add_parser("verify-approval", help="verify a signed scope without contacting targets")
    approval_parser.add_argument("scope_file")
    approval_parser.add_argument("--approval", required=True)

    trust_add_parser = security_commands.add_parser("trust-key-add", help="install an approver public key into the system trust store")
    trust_add_parser.add_argument("public_key")
    trust_add_parser.add_argument("--signer-id", required=True)

    security_commands.add_parser("trust-key-list", help="list system-trusted approver key IDs")

    posture_parser = security_commands.add_parser("host-audit", help="run read-only local host posture checks")
    posture_parser.add_argument("--output", help="optional JSON report destination")

    security_commands.add_parser("tools", help="show detected defensive security tools and extensions")

    init_scope_parser = security_commands.add_parser("scope-init", help="create a validated scope manifest without contacting targets")
    init_scope_parser.add_argument("scope_file")
    init_scope_parser.add_argument("--name", required=True)
    init_scope_parser.add_argument("--owner", required=True)
    init_scope_parser.add_argument("--authorization-reference", required=True)
    init_scope_parser.add_argument("--expires-at", required=True, help="ISO-8601 date/time with timezone, e.g. 2027-01-30T18:00:00Z")
    init_scope_parser.add_argument("--target", action="append", required=True, help="exact approved hostname, IP, or bounded CIDR; repeat per target")
    init_scope_parser.add_argument("--port", action="append", required=True, type=int, help="explicit approved TCP port; repeat per port")
    init_scope_parser.add_argument("--web-url", action="append", default=[], help="exact approved HTTP(S) URL without query or credentials")

    scope_parser = security_commands.add_parser("validate-scope", help="validate an authorization manifest without contacting targets")
    scope_parser.add_argument("scope_file", help="JSON file documenting approved targets, ports, owner, and expiry")

    audit_parser = security_commands.add_parser("audit-verify", help="verify the local hash-linked audit journal")
    audit_parser.add_argument("--path", help="optional audit log path; defaults to ~/.osforge/security-audit.jsonl")

    assess_parser = security_commands.add_parser("assess", help="run bounded checks against an active authorized scope")
    assess_parser.add_argument("scope_file", help="manifest listing approved targets, TCP ports, and optional web URLs")
    assess_parser.add_argument("--approval", required=True, help="Ed25519 signed approval document")
    assess_parser.add_argument("--output", default="osforge-assessment-report.json", help="JSON evidence report path")
    assess_parser.add_argument("--db", help="remediation/history database path")
    assess_parser.add_argument("--audit-log", help="audit journal path")
    assess_parser.add_argument("--plugin", action="append", default=[], help="explicitly opt in to an installed check plugin; may be repeated")
    assess_parser.add_argument("--yes", action="store_true", help="confirm assessment and any selected third-party plugin in non-interactive use")

    plugins_parser = security_commands.add_parser("plugins", help="list built-in and installed check plugins")
    findings_parser = security_commands.add_parser("findings", help="list persistent findings and their remediation state")
    findings_parser.add_argument("--status", choices=("open", "in_progress", "accepted_risk", "false_positive", "resolved"))
    findings_parser.add_argument("--limit", type=int, default=100)
    findings_parser.add_argument("--db", help="remediation/history database path")

    history_parser = security_commands.add_parser("history", help="list past assessment runs")
    history_parser.add_argument("--limit", type=int, default=20)
    history_parser.add_argument("--db", help="remediation/history database path")

    remediate_parser = security_commands.add_parser("remediate", help="update finding status, owner, due date, and review note")
    remediate_parser.add_argument("finding_id")
    remediate_parser.add_argument("--status", choices=("open", "in_progress", "accepted_risk", "false_positive", "resolved"), required=True)
    remediate_parser.add_argument("--note", default="", help="required when accepting risk, marking false positive, or resolving")
    remediate_parser.add_argument("--assignee")
    remediate_parser.add_argument("--due-date", help="YYYY-MM-DD")
    remediate_parser.add_argument("--db", help="remediation/history database path")
    remediate_parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    finding_history_parser = security_commands.add_parser("finding-history", help="show status change history for one finding")
    finding_history_parser.add_argument("finding_id")
    finding_history_parser.add_argument("--db", help="remediation/history database path")

    scan_parser = security_commands.add_parser("local-scan", help="run an installed analyzer against a selected local file or directory")
    scan_parser.add_argument("path", help="local filesystem path; network shares and URLs are rejected")
    scan_parser.add_argument("--engine", choices=("bandit", "trivy"), required=True)
    scan_parser.add_argument("--output", default="osforge-local-scan.json")
    scan_parser.add_argument("--timeout", type=int, default=300)
    scan_parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    sbom_parser = security_commands.add_parser("sbom", help="generate a CycloneDX inventory with installed Syft")
    sbom_parser.add_argument("path", help="local filesystem path; network shares and URLs are rejected")
    sbom_parser.add_argument("--output", default="osforge-sbom.cdx.json")
    sbom_parser.add_argument("--timeout", type=int, default=180)
    sbom_parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    report_verify_parser = security_commands.add_parser("report-verify", help="verify the integrity digest of an OS Forge assessment report")
    report_verify_parser.add_argument("report_path")
    report_verify_parser.add_argument("--audit-log", help="optional matching audit journal path")

    export_parser = security_commands.add_parser("export", help="export assessment findings to CSV or SARIF 2.1.0")
    export_parser.add_argument("report_path")
    export_parser.add_argument("--format", choices=("csv", "sarif"), required=True)
    export_parser.add_argument("--output", required=True)

    commands.add_parser("shell", help="open your normal interactive system shell")
    return parser


def print_info() -> None:
    table = Table(title="OS FORGE  /  HOST STATUS", box=box.ROUNDED, border_style="bright_green")
    table.add_column("PROPERTY", style="bright_cyan", no_wrap=True)
    table.add_column("LIVE VALUE", style="white")
    for key, value in system_info().items():
        table.add_row(key, str(value))
    console.print(table)


def print_doctor() -> None:
    table = Table(title="SYSTEM DOCTOR  /  READ-ONLY CHECKS", box=box.SIMPLE_HEAVY)
    table.add_column("CHECK", style="bright_cyan")
    table.add_column("RESULT")
    table.add_column("STATE")
    for name, detail, state in doctor_checks():
        color = {"OK": "green", "WARN": "yellow", "OLD": "red", "INFO": "cyan"}.get(state, "white")
        table.add_row(name, detail, f"[{color}]{state}[/{color}]")
    console.print(table)

    managers = detected_managers()
    manager_table = Table(title="NATIVE PACKAGE MANAGERS", box=box.SIMPLE)
    manager_table.add_column("MANAGER", style="bright_cyan")
    manager_table.add_column("FAMILY")
    manager_table.add_column("PATH")
    for manager, path in managers:
        if path:
            manager_table.add_row(manager.name, manager.family, path)
    console.print(manager_table)
    if not any(path for _, path in managers):
        console.print("[yellow]No supported package manager found on PATH.[/yellow]")


def print_tools(query: str = "", show_all: bool = False) -> None:
    rows = discover_tools(query)
    if not show_all and not query:
        visible = [(tool, path) for tool, path in rows if path]
    else:
        visible = rows
    table = Table(title="TOOLCHAIN  /  LIVE PATH DISCOVERY", box=box.SIMPLE_HEAVY)
    table.add_column("TOOL", style="bright_cyan")
    table.add_column("CATEGORY")
    table.add_column("STATUS")
    table.add_column("RESOLVED EXECUTABLE", overflow="fold")
    for tool, path in visible:
        state = "[green]FOUND[/green]" if path else "[dim]NOT FOUND[/dim]"
        table.add_row(tool.name, tool.category, state, path or "—")
    console.print(table)
    found = sum(1 for _, path in rows if path)
    console.print(f"[bold bright_green]{found}/{len(rows)}[/bold bright_green] matching tools detected on PATH.")
    if not query and not show_all:
        console.print("Use [cyan]osforge tools --all[/cyan] to inspect the complete catalog.")


def print_processes(limit: int) -> None:
    rows = list_processes(limit)
    table = Table(title=f"PROCESS CONTROL  /  TOP {limit}", box=box.SIMPLE_HEAVY)
    table.add_column("PID", justify="right", style="bright_cyan")
    table.add_column("PROCESS", overflow="fold")
    table.add_column("USER", overflow="fold")
    table.add_column("STATE")
    table.add_column("CPU %", justify="right")
    table.add_column("MEM %", justify="right")
    for row in rows:
        table.add_row(str(row.pid), row.name, row.username, row.status, f"{row.cpu_percent:.1f}", f"{row.memory_percent:.1f}")
    console.print(table)


def print_ports() -> None:
    try:
        rows = listening_ports()
    except (psutil.AccessDenied, OSError) as exc:
        console.print(f"[yellow]The OS did not allow full socket inspection: {exc}[/yellow]")
        rows = []
    table = Table(title="LOCAL TCP LISTENERS", box=box.SIMPLE_HEAVY)
    table.add_column("ADDRESS", style="bright_cyan")
    table.add_column("PORT", justify="right")
    table.add_column("PID", justify="right")
    table.add_column("PROCESS")
    for address, port, pid, name in rows:
        table.add_row(address, str(port), str(pid), name)
    console.print(table)
    console.print(f"{len(rows)} listening sockets visible to this user.")


def print_interfaces() -> None:
    table = Table(title="NETWORK INTERFACES", box=box.SIMPLE_HEAVY)
    table.add_column("INTERFACE", style="bright_cyan")
    table.add_column("FAMILY")
    table.add_column("ADDRESS / STATE")
    rows = interfaces()
    for name, family, value in rows:
        table.add_row(name, family, value)
    console.print(table)
    if not rows:
        console.print("[yellow]No IPv4/IPv6 addresses were exposed by the host.[/yellow]")


def _require_confirmation(action: str, yes: bool) -> bool:
    if yes:
        return True
    try:
        return Confirm.ask(f"[bold yellow]Confirm host-changing action:[/bold yellow] {action}", default=False)
    except (EOFError, KeyboardInterrupt):
        console.print("\n[yellow]Cancelled.[/yellow]")
        return False


def _run_package_action(args: argparse.Namespace) -> int:
    action = args.pkg_command
    manager = choose_manager(args.manager)
    if action == "list":
        command = build_list_command(manager.name)
        return execute_commands([[command[0], *command[1:]]])
    if action == "search":
        command = build_search_command(manager.name, args.query)
        return execute_commands([command])
    package = getattr(args, "package", None)
    target = f"{manager.name}: {action}" + (f" {package}" if package else " all applicable packages")
    console.print(Panel(target, title="NATIVE PACKAGE OPERATION", border_style="yellow"))
    yes = bool(getattr(args, "yes", False))
    if not _require_confirmation(target, yes):
        console.print("[yellow]Operation cancelled; no package command was run.[/yellow]")
        return 0
    commands = build_action_commands(manager.name, action, package, assume_yes=yes)
    return execute_commands(commands)


def _run_external(argv: Sequence[str]) -> int:
    if not argv:
        console.print("[yellow]Usage: osforge run PROGRAM [ARG ...][/yellow]")
        return 2
    console.print(f"[bold bright_green]$[/bold bright_green] {' '.join(argv)}")
    try:
        return subprocess.run(list(argv), check=False, shell=False).returncode
    except FileNotFoundError:
        console.print(f"[bold red]Command not found:[/bold red] {argv[0]}")
        return 127
    except OSError as exc:
        console.print(f"[bold red]Could not launch command:[/bold red] {exc}")
        return 126


def launch_shell() -> int:
    if os.name == "nt":
        candidates = [
            os.environ.get("OSFORGE_SHELL", ""),
            shutil.which("pwsh"),
            shutil.which("powershell.exe"),
            os.environ.get("COMSPEC", ""),
            shutil.which("cmd.exe"),
        ]
    else:
        candidates = [
            os.environ.get("OSFORGE_SHELL", ""),
            os.environ.get("SHELL", ""),
            shutil.which("zsh") if sys.platform == "darwin" else "",
            shutil.which("bash"),
            shutil.which("sh"),
        ]
    shell = next((candidate for candidate in candidates if candidate and Path(candidate).exists()), None)
    if not shell:
        console.print("[red]No interactive shell could be found. Set OSFORGE_SHELL to the desired executable.[/red]")
        return 127
    console.print(f"[dim]Launching native shell: {shell}[/dim]")
    try:
        return subprocess.call([shell], shell=False)
    except OSError as exc:
        console.print(f"[red]Could not launch shell: {exc}[/red]")
        return 126



def dispatch_security(args: argparse.Namespace) -> int:
    command = args.security_command
    try:
        if command == "host-audit":
            report = run_host_posture()
            append_event("host-audit.completed", details={
                "hostname": report.get("host", {}).get("hostname", ""),
                "findings_total": report.get("summary", {}).get("findings_total", 0),
            })
            summary = report["summary"]
            console.print(Panel(
                f"Host: [bright_cyan]{report['host']['hostname']}[/bright_cyan]\n"
                f"Platform: {report['host']['platform']}\n"
                f"Elevated process: {report['host']['elevated']}\n"
                f"Findings: {summary['findings_total']}  |  "
                f"Medium: {summary['findings_by_severity']['medium']}  |  "
                f"Low: {summary['findings_by_severity']['low']}",
                title="OS FORGE SECURITY / LOCAL POSTURE",
                border_style="bright_green",
            ))
            table = Table(title="READ-ONLY HOST FINDINGS", box=box.SIMPLE_HEAVY)
            table.add_column("SEVERITY", style="bright_cyan")
            table.add_column("CHECK")
            table.add_column("STATUS")
            table.add_column("FINDING")
            table.add_column("EVIDENCE / NEXT STEP", overflow="fold")
            for item in report["findings"]:
                severity = item["severity"].upper()
                table.add_row(
                    severity, item["check_id"], item["status"], item["title"],
                    (item["evidence"] + "\nRemediation: " + item["remediation"])[:1200],
                )
            console.print(table)
            if args.output:
                destination = Path(args.output).expanduser().resolve()
                destination.parent.mkdir(parents=True, exist_ok=True)
                temporary = destination.with_suffix(destination.suffix + ".tmp")
                temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                temporary.replace(destination)
                console.print(f"[green]JSON report written:[/green] {destination}")
            return 0

        if command == "tools":
            table = Table(title="DEFENSIVE SECURITY TOOLCHAIN / LIVE PATH DISCOVERY", box=box.SIMPLE_HEAVY)
            table.add_column("TOOL", style="bright_cyan")
            table.add_column("CATEGORY")
            table.add_column("STATUS")
            table.add_column("EXECUTABLE")
            for tool, path in discovered_tools():
                table.add_row(
                    tool.name, tool.category,
                    "[green]FOUND[/green]" if path else "[dim]NOT FOUND[/dim]",
                    path or "—",
                )
            console.print(table)
            installed = installed_security_extensions()
            console.print(f"{sum(1 for _, path in discovered_tools() if path)} of {len(discovered_tools())} catalogued tools found on PATH.")
            if installed:
                ext = Table(title="INSTALLED OS FORGE EXTENSION METADATA (NOT EXECUTED)", box=box.SIMPLE)
                ext.add_column("NAME", style="bright_cyan")
                ext.add_column("ENTRY POINT")
                for name, entry in installed:
                    ext.add_row(name, entry)
                console.print(ext)
            console.print("[dim]Discovery does not import or execute third-party extension code.[/dim]")
            return 0

        if command == "trust-key-add":
            console.print(Panel(
                f"Approver signer ID: [bright_cyan]{args.signer_id}[/bright_cyan]\n"
                f"Public key file: {Path(args.public_key).expanduser().resolve()}\n"
                f"System trust store: {default_trust_store_dir()}",
                title="INSTALL APPROVAL TRUST ANCHOR",
                border_style="yellow",
            ))
            console.print("[yellow]Installing a public key changes which signatures are trusted. Use only a key delivered through your organization's independent approval process. This command never elevates permissions.[/yellow]")
            if not Confirm.ask("Do you trust this approver key for this machine?", default=False):
                console.print("[yellow]Trust-key installation cancelled.[/yellow]")
                return 0
            installed = trust_public_key(args.public_key, signer_id=args.signer_id)
            append_event("approval-trust-key.installed", details={
                "signer_id": args.signer_id, "path": str(installed),
            })
            console.print(f"[green]Trusted public key installed:[/green] {installed}")
            return 0

        if command == "trust-key-list":
            directory = default_trust_store_dir()
            table = Table(title="SYSTEM TRUSTED APPROVERS", box=box.SIMPLE_HEAVY)
            table.add_column("SIGNER ID", style="bright_cyan")
            table.add_column("PUBLIC KEY FILE")
            if directory.is_dir():
                for key_file in sorted(directory.glob("*.pem")):
                    table.add_row(key_file.stem, str(key_file))
            console.print(table)
            console.print(f"Trust store: {directory}")
            console.print("[dim]If the trust store is empty, ask an administrator to install an organization-approved public key.[/dim]")
            return 0

        if command == "keygen":
            passphrase = getpass.getpass("Private-key passphrase (minimum 12 characters): ")
            repeated = getpass.getpass("Repeat passphrase: ")
            if passphrase != repeated:
                raise ValueError("Passphrases do not match.")
            private_path, public_path = generate_keypair(
                args.private_key, args.public_key, passphrase=passphrase,
            )
            append_event("approval-keypair.created", details={
                "private_key_path": str(private_path),
                "public_key_path": str(public_path),
                "algorithm": "Ed25519",
            })
            console.print(Panel(
                f"Private key: [bright_cyan]{private_path}[/bright_cyan]\n"
                f"Public trust key: {public_path}\nAlgorithm: Ed25519",
                title="SCOPE-APPROVAL KEY PAIR CREATED",
                border_style="bright_green",
            ))
            console.print("[yellow]Keep the private key off assessment hosts. Configure the public key through your organization's trusted deployment process; generating a key does not itself grant approval authority.[/yellow]")
            return 0

        if command == "scope-sign":
            scope = load_scope(args.scope_file, require_active=True)
            console.print(Panel(
                f"Engagement: [bright_cyan]{scope.name}[/bright_cyan]\n"
                f"Owner: {scope.owner}\nAuthorization reference: {scope.authorization_reference}\n"
                f"Targets: {len(scope.targets)} | ports: {len(scope.ports)} | web URLs: {len(scope.web_urls)}\n"
                f"Expires: {scope.expires_at.isoformat()}",
                title="SCOPE SIGNING / REVIEW REQUIRED",
                border_style="yellow",
            ))
            console.print("[yellow]Only sign after independently confirming the owner's written approval for these exact targets and ports.[/yellow]")
            if not Confirm.ask("Have you reviewed the written authorization for this exact scope?", default=False):
                console.print("[yellow]Signing cancelled.[/yellow]")
                return 0
            passphrase = getpass.getpass("Private-key passphrase: ")
            result = sign_scope(
                args.scope_file, args.private_key,
                signer_id=args.signer_id, passphrase=passphrase,
                output_path=args.output, expires_at=args.expires_at,
            )
            append_event("scope.signed", details={
                "authorization_reference": scope.authorization_reference,
                "signer_id": result["signer_id"],
                "scope_sha256": result["scope_sha256"],
                "approval_path": result["approval_path"],
            })
            console.print(Panel(
                f"Signed approval: [bright_cyan]{result['approval_path']}[/bright_cyan]\n"
                f"Signer: {result['signer_id']}\nExpires: {result['expires_at']}\n"
                f"Scope SHA-256: {result['scope_sha256']}",
                title="SCOPE APPROVAL SIGNED",
                border_style="bright_green",
            ))
            return 0

        if command == "verify-approval":
            signer_id = approval_signer_id(args.approval)
            public_key_path = trusted_public_key_path(signer_id)
            result = verify_scope_approval(args.scope_file, args.approval, public_key_path)
            append_event("scope.approval.verified", details={
                "authorization_reference": result["authorization_reference"],
                "signer_id": result["signer_id"],
                "scope_sha256": result["scope_sha256"],
            })
            console.print(Panel(
                f"Status: [green]VERIFIED[/green]\nSigner: {result['signer_id']}\n"
                f"Authorization reference: {result['authorization_reference']}\n"
                f"Expiry: {result['expires_at']}\nScope SHA-256: {result['scope_sha256']}",
                title="SIGNED SCOPE APPROVAL",
                border_style="bright_green",
            ))
            return 0

        if command == "scope-init":
            destination = create_scope_manifest(
                args.scope_file,
                name=args.name,
                owner=args.owner,
                authorization_reference=args.authorization_reference,
                expires_at=args.expires_at,
                targets=args.target,
                ports=args.port,
                web_urls=args.web_url,
            )
            scope = load_scope(destination, require_active=True)
            append_event("scope-created", details={
                "scope_file": str(destination),
                "authorization_reference": scope.authorization_reference,
                "target_count": len(scope.targets),
                "port_count": len(scope.ports),
            })
            console.print(Panel(
                f"Scope file: [bright_cyan]{destination}[/bright_cyan]\n"
                f"Engagement: {scope.name}\nOwner: {scope.owner}\n"
                f"Authorization reference: {scope.authorization_reference}\n"
                f"Expiry: {scope.expires_at.isoformat()}\n"
                f"Targets: {len(scope.targets)} | ports: {len(scope.ports)} | web URLs: {len(scope.web_urls)}",
                title="AUTHORIZATION MANIFEST CREATED",
                border_style="bright_green",
            ))
            console.print("[yellow]This command only writes a manifest; it does not contact any listed target or independently verify permission.[/yellow]")
            return 0

        if command == "validate-scope":
            scope = load_scope(args.scope_file, require_active=True)
            append_event("scope-validated", details={
                "scope_file": scope.source_path,
                "authorization_reference": scope.authorization_reference,
                "target_count": len(scope.targets),
                "port_count": len(scope.ports),
            })
            table = Table(title="AUTHORIZATION MANIFEST / VALIDATION", box=box.ROUNDED)
            table.add_column("FIELD", style="bright_cyan")
            table.add_column("VALUE", overflow="fold")
            table.add_row("Engagement", scope.name)
            table.add_row("Owner", scope.owner)
            table.add_row("Authorization reference", scope.authorization_reference)
            table.add_row("Expires (UTC)", scope.expires_at.isoformat())
            table.add_row("Active", "yes" if scope.active else "no")
            table.add_row("Explicit targets", "\n".join(scope.targets))
            table.add_row("Allowed TCP ports", ", ".join(str(p) for p in scope.ports))
            table.add_row("Manifest", scope.source_path)
            console.print(table)
            console.print("[yellow]Validation checks the manifest's structure and expiry only; it does not prove ownership or consent.[/yellow]")
            return 0

        if command == "plugins":
            table = Table(title="OS FORGE SECURITY PLUGINS", box=box.SIMPLE_HEAVY)
            table.add_column("NAME", style="bright_cyan")
            table.add_column("VERSION")
            table.add_column("SOURCE")
            table.add_column("TRUST")
            table.add_column("DESCRIPTION", overflow="fold")
            for plugin in discover_plugins():
                table.add_row(
                    plugin.name, plugin.version, plugin.source,
                    "[green]BUILT-IN[/green]" if plugin.trusted else "[yellow]EXTERNAL / OPT-IN[/yellow]",
                    plugin.description,
                )
            console.print(table)
            console.print("[yellow]Third-party plugins execute Python code with your account's privileges when selected. Review and trust their source first.[/yellow]")
            return 0

        if command == "assess":
            scope = load_scope(args.scope_file, require_active=True)
            signer_id = ""
            try:
                signer_id = approval_signer_id(args.approval)
                approval_key_path = trusted_public_key_path(signer_id)
                approval_result = verify_scope_approval(args.scope_file, args.approval, approval_key_path)
            except (ValueError, OSError) as exc:
                append_event("assessment.authorization_rejected", details={
                    "scope_file": str(Path(args.scope_file).expanduser()),
                    "approval_file": str(Path(args.approval).expanduser()),
                    "requested_signer_id": signer_id or "unreadable",
                    "error_type": type(exc).__name__,
                    "message": str(exc)[:500],
                }, path=args.audit_log)
                raise
            validate_plugin_selection(tuple(args.plugin))
            external = [
                plugin for plugin in discover_plugins()
                if plugin.name in set(args.plugin) and not plugin.trusted
            ]
            console.print(Panel(
                f"Engagement: [bright_cyan]{scope.name}[/bright_cyan]\n"
                f"Owner: {scope.owner}\nAuthorization reference: {scope.authorization_reference}\n"
                f"Expires: {scope.expires_at.isoformat()}\n"
                f"Signed approval: VERIFIED by {approval_result['signer_id']} until {approval_result['expires_at']}\n"
                f"Target entries: {len(scope.targets)} | allowed TCP ports: {len(scope.ports)} | "
                f"explicit web URLs: {len(scope.web_urls)}\n"
                "Limits: max 256 target/address pairs, 4096 TCP checks, 8 TCP workers, 4 web workers, "
                "one HEAD request per web URL.",
                title="AUTHORIZED ASSESSMENT REVIEW",
                border_style="yellow",
            ))
            console.print("[yellow]Only targets and TCP ports in this unexpired manifest will be contacted. This tool does not prove that the manifest's author has legal permission.[/yellow]")
            if external:
                console.print("[bold red]THIRD-PARTY PLUGIN CODE WILL EXECUTE:[/bold red] " + ", ".join(p.name for p in external))
                console.print("Review the plugin distribution and its source before proceeding.")
            if not _require_confirmation(
                f"run low-impact assessment for authorization reference {scope.authorization_reference}",
                bool(args.yes),
            ):
                console.print("[yellow]Assessment cancelled; no target checks were started.[/yellow]")
                return 0
            report = run_assessment(
                args.scope_file,
                approval_path=args.approval,
                approval_public_key_path=approval_key_path,
                output_path=args.output,
                database_path=args.db,
                audit_path=args.audit_log,
                plugin_names=tuple(args.plugin),
            )
            counts = {}
            for finding in report["findings"]:
                counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
            table = Table(title="ASSESSMENT RESULTS", box=box.ROUNDED, border_style="bright_green")
            table.add_column("METRIC", style="bright_cyan")
            table.add_column("VALUE")
            table.add_row("Assessment ID", report["assessment_id"])
            table.add_row("TCP probes", str(report["summary"]["tcp_probes"]))
            table.add_row("Open TCP ports", str(report["summary"]["tcp_open"]))
            table.add_row("Web URLs checked", str(report["summary"]["web_urls_checked"]))
            table.add_row("Findings", str(report["summary"]["findings_total"]))
            table.add_row("Remediation database", report.get("remediation", {}).get("database_path", ""))
            table.add_row("Evidence report", report["report_path"])
            console.print(table)
            if counts:
                findings_table = Table(title="FINDINGS / INITIAL REMEDIATION STATE", box=box.SIMPLE_HEAVY)
                findings_table.add_column("ID", style="bright_cyan")
                findings_table.add_column("SEVERITY")
                findings_table.add_column("STATUS")
                findings_table.add_column("ASSET")
                findings_table.add_column("FINDING", overflow="fold")
                for finding in report["findings"]:
                    findings_table.add_row(
                        finding.get("finding_id", ""), finding["severity"].upper(),
                        finding.get("status", "open"), finding["asset"], finding["title"],
                    )
                console.print(findings_table)
            if report.get("plugin_errors"):
                console.print("[yellow]One or more selected checks failed; see plugin_errors in the report.[/yellow]")
            console.print("[dim]An open port is evidence of reachability, not proof of a vulnerability. Review each finding and remediation recommendation.[/dim]")
            return 0

        if command == "findings":
            rows = list_findings(database_path=args.db, status=args.status, limit=args.limit)
            table = Table(title="FINDINGS / REMEDIATION QUEUE", box=box.SIMPLE_HEAVY)
            table.add_column("ID", style="bright_cyan")
            table.add_column("SEVERITY")
            table.add_column("STATUS")
            table.add_column("ASSIGNEE")
            table.add_column("DUE")
            table.add_column("ASSET", overflow="fold")
            table.add_column("TITLE", overflow="fold")
            for item in rows:
                table.add_row(
                    item["finding_id"], item["severity"].upper(), item["status"],
                    item["assignee"] or "—", item["due_date"] or "—", item["asset"], item["title"],
                )
            console.print(table)
            console.print(f"{len(rows)} finding record(s) shown.")
            return 0

        if command == "history":
            rows = list_assessments(database_path=args.db, limit=args.limit)
            table = Table(title="ASSESSMENT HISTORY", box=box.SIMPLE_HEAVY)
            table.add_column("COMPLETED", style="bright_cyan")
            table.add_column("ASSESSMENT")
            table.add_column("ENGAGEMENT")
            table.add_column("TARGETS", justify="right")
            table.add_column("TCP PROBES", justify="right")
            table.add_column("FINDINGS", justify="right")
            table.add_column("REPORT", overflow="fold")
            for item in rows:
                table.add_row(
                    item["completed_at"], item["assessment_id"], item["scope_name"],
                    str(item["target_count"]), str(item["tcp_probe_count"]),
                    str(item["finding_count"]), item["report_path"],
                )
            console.print(table)
            console.print(f"{len(rows)} assessment run(s) shown.")
            return 0

        if command == "remediate":
            if not _require_confirmation(
                f"change finding {args.finding_id} to status {args.status}",
                bool(args.yes),
            ):
                console.print("[yellow]Remediation update cancelled.[/yellow]")
                return 0
            old_items = list_findings(database_path=args.db, limit=1000)
            old = next((item for item in old_items if item["finding_id"] == args.finding_id), None)
            result = update_finding(
                args.finding_id, status=args.status, note=args.note,
                assignee=args.assignee, due_date=args.due_date, database_path=args.db,
            )
            append_event("finding.status.changed", details={
                "finding_id": args.finding_id,
                "previous_status": old["status"] if old else "unknown",
                "new_status": result["status"],
                "assignee": result["assignee"],
                "due_date": result["due_date"],
                "note": args.note[:500],
            })
            console.print(Panel(
                f"Finding: [bright_cyan]{result['finding_id']}[/bright_cyan]\n"
                f"Status: {result['status']}\nAssignee: {result['assignee'] or '—'}\n"
                f"Due date: {result['due_date'] or '—'}",
                title="REMEDIATION STATE UPDATED",
                border_style="bright_green",
            ))
            return 0

        if command == "local-scan":
            target = args.path
            action = f"run local {args.engine} security analysis against {target}"
            console.print("[yellow]This scan is local-only, but the selected scanner can inspect source and dependency metadata. Trivy may contact its vulnerability databases.[/yellow]")
            if not _require_confirmation(action, bool(args.yes)):
                console.print("[yellow]Local scan cancelled.[/yellow]")
                return 0
            append_event("local-scan.started", details={"engine": args.engine, "target": str(Path(target).expanduser())})
            report = run_local_scan(
                target, engine=args.engine, output_path=args.output, timeout_seconds=args.timeout,
            )
            append_event("local-scan.completed", details={
                "engine": args.engine, "target": report["target"],
                "exit_code": report["exit_code"], "report_path": report["report_path"],
                "parse_error": report.get("parse_error"),
            })
            console.print(Panel(
                f"Engine: [bright_cyan]{report['engine']}[/bright_cyan]\n"
                f"Target: {report['target']}\nScanner exit: {report['exit_code']}\n"
                f"Report: {report['report_path']}\n"
                f"JSON parsed: {'yes' if report.get('parse_error') is None else 'no'}",
                title="LOCAL SECURITY SCAN",
                border_style="bright_green" if report.get("parse_error") is None else "yellow",
            ))
            if report.get("parse_error"):
                console.print(f"[yellow]{report['parse_error']}[/yellow]")
                if report.get("stderr"):
                    console.print(report["stderr"][:3000])
                return 1
            console.print("[dim]Interpret scanner results manually; a clean scan is not proof of security.[/dim]")
            # Bandit can use exit code 1 to mean findings were detected; the JSON report remains valid.
            return 0

        if command == "report-verify":
            result = verify_assessment_report(args.report_path, audit_path=args.audit_log)
            console.print(Panel(
                f"Status: [green]VERIFIED[/green]\n"
                f"Assessment: {result['assessment_id']}\n"
                f"Findings: {result['findings_total']}\n"
                f"Canonical SHA-256: {result['canonical_json_sha256']}\n"
                f"Audit record match: {result['audit_record_match']}\n{result['audit_message']}",
                title="ASSESSMENT REPORT INTEGRITY",
                border_style="bright_green",
            ))
            return 0

        if command == "export":
            result = export_report(args.report_path, output_path=args.output, format=args.format)
            append_event("assessment.report.exported", details=result)
            console.print(Panel(
                f"Format: [bright_cyan]{result['format']}[/bright_cyan]\n"
                f"Assessment: {result['assessment_id']}\n"
                f"Findings exported: {result['findings_exported']}\n"
                f"Output: {result['output_path']}",
                title="ASSESSMENT REPORT EXPORTED",
                border_style="bright_green",
            ))
            return 0

        if command == "sbom":
            action = f"generate a CycloneDX software inventory for local path {args.path}"
            if not _require_confirmation(action, bool(args.yes)):
                console.print("[yellow]SBOM generation cancelled.[/yellow]")
                return 0
            append_event("sbom.started", details={"target": str(Path(args.path).expanduser())})
            result = generate_sbom(args.path, output_path=args.output, timeout_seconds=args.timeout)
            append_event("sbom.completed", details=result)
            console.print(Panel(
                f"Tool: [bright_cyan]{result['tool']}[/bright_cyan]\n"
                f"Target: {result['target']}\nComponents: {result['component_count']}\n"
                f"Report: {result['report_path']}",
                title="SOFTWARE BILL OF MATERIALS",
                border_style="bright_green",
            ))
            return 0

        if command == "finding-history":
            rows = finding_history(args.finding_id, database_path=args.db)
            table = Table(title=f"FINDING HISTORY / {args.finding_id}", box=box.SIMPLE_HEAVY)
            table.add_column("WHEN", style="bright_cyan")
            table.add_column("ACTOR")
            table.add_column("FROM")
            table.add_column("TO")
            table.add_column("NOTE", overflow="fold")
            for item in rows:
                table.add_row(
                    item["event_at"], item["actor"], item["old_status"] or "—",
                    item["new_status"], item["note"],
                )
            console.print(table)
            return 0

        if command == "audit-verify":
            valid, count, message = verify_log(args.path)
            if valid:
                console.print(f"[green]{message}[/green]")
                return 0
            console.print(f"[bold red]Audit-log verification failed:[/bold red] {message}")
            return 1
        console.print("[red]Unknown security command.[/red]")
        return 2
    except (ValueError, RuntimeError, PermissionError, OSError, sqlite3.Error) as exc:
        console.print(f"[bold red]SECURITY ERROR[/bold red] {exc}")
        return 1

def dispatch(args: argparse.Namespace) -> int:
    command = args.command
    try:
        if command == "launch":
            interactive()
            return 0
        if command == "info":
            print_info()
            return 0
        if command == "doctor":
            print_doctor()
            return 0
        if command == "tools":
            print_tools(args.query, args.all)
            return 0
        if command == "processes":
            print_processes(args.limit)
            return 0
        if command == "kill":
            row = process_identity(args.pid)
            console.print(Panel(
                f"PID: [bold]{row.pid}[/bold]\nProcess: [bold bright_cyan]{row.name}[/bold bright_cyan]\n"
                f"User: {row.username or 'unknown'}\nState: {row.status}",
                title="PROCESS TERMINATION REVIEW",
                border_style="red",
            ))
            if not Confirm.ask("Send a terminate request to this process?", default=False):
                console.print("[yellow]Cancelled; process left running.[/yellow]")
                return 0
            terminate_process(args.pid)
            console.print(f"[green]Termination request sent to PID {args.pid}.[/green]")
            return 0
        if command == "ports":
            print_ports()
            return 0
        if command == "net":
            if args.net_command == "interfaces":
                print_interfaces()
                return 0
            if args.net_command == "dns":
                table = Table(title=f"DNS RESOLUTION  /  {args.host}", box=box.SIMPLE)
                table.add_column("FAMILY", style="bright_cyan")
                table.add_column("ADDRESS")
                for family, address in resolve_host(args.host):
                    table.add_row(family, address)
                console.print(table)
                return 0
            if args.net_command == "ping":
                return run_ping(args.host)
            if args.net_command == "check":
                success, message = check_tcp(args.host, args.port)
                console.print(f"[{'green' if success else 'yellow'}]{message}[/{'green' if success else 'yellow'}]")
                return 0 if success else 1
        if command == "pkg":
            return _run_package_action(args)
        if command == "run":
            return _run_external(args.argv)
        if command == "security":
            return dispatch_security(args)
        if command == "shell":
            return launch_shell()
        console.print("[red]Unknown command. Use osforge --help.[/red]")
        return 2
    except (ValueError, RuntimeError, PermissionError, OSError) as exc:
        console.print(f"[bold red]ERROR[/bold red] {exc}")
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        return 130


def interactive() -> None:
    console.print(Panel.fit(
        f"[bold bright_green]OS//FORGE[/bold bright_green]  [bright_cyan]v{__version__}[/bright_cyan]\n"
        "[white]CROSS-PLATFORM HOST TERMINAL  /  WINDOWS · macOS · LINUX[/white]\n"
        "[dim]Real commands. Real host data. No simulated system state.[/dim]",
        border_style="bright_green",
    ))
    console.print("Type [cyan]help[/cyan] for the command guide. Use [cyan]shell[/cyan] for pipelines and native shell syntax.")
    while True:
        try:
            raw = input(f"\033[92mosforge\033[0m:\033[96m{Path.cwd()}\033[0m$ ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Session closed.[/dim]")
            return
        if not raw:
            continue
        try:
            tokens = shlex.split(raw, posix=(os.name != "nt"))
        except ValueError as exc:
            console.print(f"[red]Parse error: {exc}[/red]")
            continue
        if not tokens:
            continue
        first = tokens[0].casefold()
        if first in {"exit", "quit"}:
            console.print("[dim]Session closed.[/dim]")
            return
        if first in {"help", "?"}:
            build_parser().print_help()
            console.print("\n[cyan]Interactive extras:[/cyan] cd PATH · clear · exit · type any native executable by name")
            continue
        if first == "clear":
            console.clear()
            continue
        if first == "cd":
            target = Path(tokens[1]).expanduser() if len(tokens) > 1 else Path.home()
            try:
                os.chdir(target)
            except OSError as exc:
                console.print(f"[red]cd: {exc}[/red]")
            continue
        if first not in BUILTINS:
            _run_external(tokens)
            continue
        try:
            args = build_parser().parse_args(tokens)
            dispatch(args)
        except SystemExit:
            continue


def main(argv: Sequence[str] | None = None) -> int:
    tokens = list(sys.argv[1:] if argv is None else argv)
    if not tokens:
        interactive()
        return 0
    try:
        args = build_parser().parse_args(tokens)
    except SystemExit as exc:
        return int(exc.code)
    return dispatch(args)


if __name__ == "__main__":
    raise SystemExit(main())

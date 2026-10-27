"""CLI and interactive launcher for OS Forge."""

from __future__ import annotations

import argparse
import os
import shlex
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

console = Console()
BUILTINS = {
    "launch", "info", "doctor", "tools", "processes", "kill", "ports",
    "net", "pkg", "run", "shell",
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

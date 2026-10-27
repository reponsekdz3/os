"""Safe argument-array adapters for native OS package managers."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence

from rich.console import Console

console = Console()
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~\-]{0,199}$")


@dataclass(frozen=True)
class PackageManager:
    name: str
    executable: str
    family: str
    summary: str


MANAGERS: tuple[PackageManager, ...] = (
    PackageManager("winget", "winget", "Windows", "Windows Package Manager"),
    PackageManager("choco", "choco", "Windows", "Chocolatey"),
    PackageManager("scoop", "scoop", "Windows", "Scoop"),
    PackageManager("brew", "brew", "macOS/Linux", "Homebrew"),
    PackageManager("port", "port", "macOS", "MacPorts"),
    PackageManager("apt", "apt", "Debian", "APT"),
    PackageManager("apt-get", "apt-get", "Debian", "APT command-line interface"),
    PackageManager("dnf", "dnf", "Fedora/RHEL", "DNF"),
    PackageManager("yum", "yum", "RHEL", "YUM"),
    PackageManager("pacman", "pacman", "Arch", "Pacman"),
    PackageManager("zypper", "zypper", "SUSE", "Zypper"),
    PackageManager("apk", "apk", "Alpine", "APK"),
    PackageManager("snap", "snap", "Cross-platform Linux", "Snap"),
    PackageManager("flatpak", "flatpak", "Cross-platform Linux", "Flatpak"),
    PackageManager("nix-env", "nix-env", "Nix", "Nix package manager"),
    PackageManager("emerge", "emerge", "Gentoo", "Portage"),
)

_PREFERENCES = {
    "windows": ("winget", "choco", "scoop"),
    "darwin": ("brew", "port"),
    "linux": ("apt", "apt-get", "dnf", "yum", "pacman", "zypper", "apk", "nix-env", "emerge", "snap", "flatpak"),
}


def detected_managers() -> list[tuple[PackageManager, str | None]]:
    """List supported package managers and their resolved executable paths."""
    rows = []
    for manager in MANAGERS:
        path = shutil.which(manager.executable)
        rows.append((manager, path))
    return rows


def choose_manager(name: str | None = None) -> PackageManager:
    """Resolve a requested manager or select the first installed native default."""
    available = {manager.name: (manager, path) for manager, path in detected_managers() if path}
    if name:
        manager = next((item for item in MANAGERS if item.name == name.casefold()), None)
        if manager is None:
            choices = ", ".join(item.name for item in MANAGERS)
            raise ValueError(f"Unsupported manager {name!r}. Supported managers: {choices}")
        if manager.name not in available:
            raise RuntimeError(f"{manager.name} is not installed or not available on PATH.")
        return manager

    platform_key = {"win32": "windows", "darwin": "darwin"}.get(os.sys.platform, "linux")
    for preferred in _PREFERENCES[platform_key]:
        if preferred in available:
            return available[preferred][0]
    raise RuntimeError(
        "No supported package manager was found on PATH. Install one for this OS, "
        "or use its native installer and reopen the terminal."
    )


def validate_package_name(name: str) -> str:
    """Reject empty and option-like package names before invoking a manager."""
    value = name.strip()
    if not _PACKAGE_RE.fullmatch(value):
        raise ValueError(
            "Invalid package identifier. Use a single package ID containing letters, digits, "
            "periods, underscores, colons, slashes, plus, tilde, @, or hyphens."
        )
    return value


def build_search_command(manager: str, query: str) -> list[str]:
    """Build the native search argv without shell parsing or interpolation."""
    query = query.strip()
    if not query or len(query) > 200:
        raise ValueError("Search text must contain 1–200 characters.")
    words = query.split()
    commands: dict[str, list[str]] = {
        "winget": ["search", *words],
        "choco": ["search", *words],
        "scoop": ["search", *words],
        "brew": ["search", *words],
        "port": ["search", *words],
        "apt": ["search", *words],
        "apt-get": ["search", *words],
        "dnf": ["search", *words],
        "yum": ["search", *words],
        "pacman": ["-Ss", *words],
        "zypper": ["search", *words],
        "apk": ["search", *words],
        "snap": ["find", *words],
        "flatpak": ["search", *words],
        "nix-env": ["-qaP", *words],
        "emerge": ["--search", query],
    }
    if manager not in commands:
        raise ValueError(f"Search is not supported for manager {manager}.")
    executable = "apt-cache" if manager in {"apt", "apt-get"} else manager
    return [executable, *commands[manager]]


def build_list_command(manager: str) -> list[str]:
    """Build the native command used to list installed packages."""
    commands = {
        "winget": ["list"],
        "choco": ["list", "--limit-output"],
        "scoop": ["list"],
        "brew": ["list", "--versions"],
        "port": ["installed"],
        "apt": ["list", "--installed"],
        "apt-get": ["-W", "-f=${binary:Package}\\t${Version}\\n"],
        "dnf": ["list", "installed"],
        "yum": ["list", "installed"],
        "pacman": ["-Q"],
        "zypper": ["packages", "--installed-only"],
        "apk": ["info", "-v"],
        "snap": ["list"],
        "flatpak": ["list", "--app"],
        "nix-env": ["-q"],
    }
    if manager not in commands:
        raise ValueError(f"Listing installed packages is not supported for manager {manager}.")
    executable = {
        "apt-get": "dpkg-query",
        "apt": "apt",
    }.get(manager, manager)
    return [executable, *commands[manager]]


def build_action_commands(
    manager: str,
    action: str,
    package: str | None = None,
    assume_yes: bool = False,
) -> list[list[str]]:
    """Build one or more argument arrays for a package action."""
    if action not in {"install", "remove", "update"}:
        raise ValueError(f"Unsupported package action: {action}")
    if action in {"install", "remove"}:
        if package is None:
            raise ValueError(f"Package name is required for {action}.")
        package = validate_package_name(package)

    yes = assume_yes
    commands: dict[str, dict[str, list[list[str]]]] = {
        "winget": {
            "install": [["install", package or "", "--accept-source-agreements", "--accept-package-agreements"]],
            "remove": [["uninstall", package or "", "--accept-source-agreements"]],
            "update": [["upgrade", "--all", "--accept-source-agreements", "--accept-package-agreements"]],
        },
        "choco": {
            "install": [["install", package or "", *(["-y"] if yes else [])]],
            "remove": [["uninstall", package or "", *(["-y"] if yes else [])]],
            "update": [["upgrade", "all", *(["-y"] if yes else [])]],
        },
        "scoop": {
            "install": [["install", package or ""]],
            "remove": [["uninstall", package or ""]],
            "update": [["update"], ["update", "*"]],
        },
        "brew": {
            "install": [["install", package or ""]],
            "remove": [["uninstall", package or ""]],
            "update": [["update"], ["upgrade"]],
        },
        "port": {
            "install": [["install", package or ""]],
            "remove": [["uninstall", package or ""]],
            "update": [["selfupdate"], ["upgrade", "outdated"]],
        },
        "apt": {
            "install": [["install", *(["-y"] if yes else []), package or ""]],
            "remove": [["remove", *(["-y"] if yes else []), package or ""]],
            "update": [["update"], ["upgrade", *(["-y"] if yes else [])]],
        },
        "apt-get": {
            "install": [["install", *(["-y"] if yes else []), package or ""]],
            "remove": [["remove", *(["-y"] if yes else []), package or ""]],
            "update": [["update"], ["upgrade", *(["-y"] if yes else [])]],
        },
        "dnf": {
            "install": [["install", *(["-y"] if yes else []), package or ""]],
            "remove": [["remove", *(["-y"] if yes else []), package or ""]],
            "update": [["upgrade", "--refresh", *(["-y"] if yes else [])]],
        },
        "yum": {
            "install": [["install", *(["-y"] if yes else []), package or ""]],
            "remove": [["remove", *(["-y"] if yes else []), package or ""]],
            "update": [["update", *(["-y"] if yes else [])]],
        },
        "pacman": {
            "install": [["-S", *(["--noconfirm"] if yes else []), package or ""]],
            "remove": [["-Rns", *(["--noconfirm"] if yes else []), package or ""]],
            "update": [["-Syu", *(["--noconfirm"] if yes else [])]],
        },
        "zypper": {
            "install": [["install", *(["--non-interactive"] if yes else []), package or ""]],
            "remove": [["remove", *(["--non-interactive"] if yes else []), package or ""]],
            "update": [["update", *(["--non-interactive"] if yes else [])]],
        },
        "apk": {
            "install": [["add", *(["--no-progress"] if yes else []), package or ""]],
            "remove": [["del", package or ""]],
            "update": [["update"], ["upgrade", *(["--available"] if yes else [])]],
        },
        "snap": {
            "install": [["install", package or ""]],
            "remove": [["remove", package or ""]],
            "update": [["refresh"]],
        },
        "flatpak": {
            "install": [["install", package or ""]],
            "remove": [["uninstall", package or ""]],
            "update": [["update", *(["--assumeyes"] if yes else [])]],
        },
        "nix-env": {
            "install": [["-iA", package or ""]],
            "remove": [["-e", package or ""]],
            "update": [["-u"]],
        },
        "emerge": {
            "install": [["--ask=n" if yes else "--ask", package or ""]],
            "remove": [["--unmerge", *(["--ask=n"] if yes else ["--ask"]), package or ""]],
            "update": [["--sync"], ["--update", "--deep", "--newuse", "@world", *(["--ask=n"] if yes else ["--ask"])]],
        },
    }
    if manager not in commands:
        raise ValueError(f"Unsupported package manager: {manager}")
    return [[manager, *argv] for argv in commands[manager][action]]


def execute_commands(commands: Sequence[Sequence[str]]) -> int:
    """Run native manager commands without shell=True and stop on first failure."""
    for argv in commands:
        if not argv:
            continue
        console.print(f"[bold bright_green]$[/bold bright_green] {' '.join(argv)}")
        try:
            completed = subprocess.run(list(argv), check=False, shell=False)
        except FileNotFoundError:
            console.print(f"[bold red]Executable not found:[/bold red] {argv[0]}")
            return 127
        except OSError as exc:
            console.print(f"[bold red]Could not launch command:[/bold red] {exc}")
            return 126
        if completed.returncode != 0:
            console.print(f"[yellow]Command exited with status {completed.returncode}.[/yellow]")
            return completed.returncode
    return 0

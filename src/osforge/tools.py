"""Discovery of real tools available on the current PATH."""

from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    category: str
    description: str
    executables: tuple[str, ...] = ()


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("git", "Developer", "Source control"),
    ToolSpec("gh", "Developer", "GitHub CLI"),
    ToolSpec("curl", "Network", "HTTP client"),
    ToolSpec("wget", "Network", "Downloader"),
    ToolSpec("jq", "Developer", "JSON processor"),
    ToolSpec("yq", "Developer", "YAML processor"),
    ToolSpec("rg", "Developer", "Ripgrep text search"),
    ToolSpec("fd", "Developer", "Fast file search"),
    ToolSpec("fzf", "Terminal", "Interactive fuzzy finder"),
    ToolSpec("tmux", "Terminal", "Terminal multiplexer"),
    ToolSpec("screen", "Terminal", "Terminal multiplexer"),
    ToolSpec("ssh", "Network", "Secure shell client"),
    ToolSpec("scp", "Network", "Secure copy"),
    ToolSpec("rsync", "Files", "Incremental file synchronization"),
    ToolSpec("tar", "Files", "Archive utility"),
    ToolSpec("7z", "Files", "7-Zip archive utility", ("7z", "7zz")),
    ToolSpec("zip", "Files", "ZIP archive creator"),
    ToolSpec("unzip", "Files", "ZIP archive extractor"),
    ToolSpec("openssl", "Security", "TLS and cryptography utility"),
    ToolSpec("gpg", "Security", "GnuPG cryptography"),
    ToolSpec("age", "Security", "File encryption utility"),
    ToolSpec("docker", "Containers", "Docker CLI"),
    ToolSpec("podman", "Containers", "Podman CLI"),
    ToolSpec("nerdctl", "Containers", "containerd CLI"),
    ToolSpec("kubectl", "Cloud", "Kubernetes CLI"),
    ToolSpec("helm", "Cloud", "Kubernetes package manager"),
    ToolSpec("terraform", "Cloud", "Infrastructure as code"),
    ToolSpec("ansible", "Cloud", "Configuration automation"),
    ToolSpec("python", "Developer", "Python interpreter", ("python", "python3", "py")),
    ToolSpec("pip", "Developer", "Python package installer", ("pip", "pip3")),
    ToolSpec("node", "Developer", "Node.js runtime"),
    ToolSpec("npm", "Developer", "Node.js package manager"),
    ToolSpec("pnpm", "Developer", "Fast Node.js package manager"),
    ToolSpec("bun", "Developer", "JavaScript runtime and toolkit"),
    ToolSpec("go", "Developer", "Go language toolchain"),
    ToolSpec("rustc", "Developer", "Rust compiler"),
    ToolSpec("cargo", "Developer", "Rust package manager"),
    ToolSpec("java", "Developer", "Java runtime"),
    ToolSpec("javac", "Developer", "Java compiler"),
    ToolSpec("gradle", "Developer", "Gradle build system"),
    ToolSpec("mvn", "Developer", "Apache Maven", ("mvn", "mvn.cmd")),
    ToolSpec("gcc", "Build", "GNU C compiler"),
    ToolSpec("clang", "Build", "LLVM C/C++ compiler"),
    ToolSpec("cmake", "Build", "CMake build configuration"),
    ToolSpec("ninja", "Build", "Ninja build system"),
    ToolSpec("make", "Build", "Make build utility", ("make", "gmake")),
    ToolSpec("gdb", "Debug", "GNU debugger"),
    ToolSpec("lldb", "Debug", "LLVM debugger"),
    ToolSpec("strace", "Debug", "Linux system-call tracer"),
    ToolSpec("ltrace", "Debug", "Linux library-call tracer"),
    ToolSpec("perf", "Debug", "Linux performance analyzer"),
    ToolSpec("bpftrace", "Debug", "Linux eBPF tracing"),
    ToolSpec("ip", "System", "iproute2 network configuration"),
    ToolSpec("ss", "Network", "Socket statistics"),
    ToolSpec("netstat", "Network", "Network statistics"),
    ToolSpec("lsof", "System", "Open file and socket inspection"),
    ToolSpec("tcpdump", "Network", "Packet capture utility"),
    ToolSpec("traceroute", "Network", "Network route tracing", ("traceroute", "tracert")),
    ToolSpec("tracepath", "Network", "Path MTU tracing"),
    ToolSpec("dig", "Network", "DNS query tool"),
    ToolSpec("nslookup", "Network", "DNS lookup utility"),
    ToolSpec("host", "Network", "DNS lookup utility"),
    ToolSpec("whois", "Network", "Domain registration lookup"),
    ToolSpec("nmap", "Network", "Network mapping utility; detected only"),
    ToolSpec("systemctl", "Linux", "systemd service manager"),
    ToolSpec("journalctl", "Linux", "systemd journal reader"),
    ToolSpec("apt", "Packages", "Debian/Ubuntu package manager"),
    ToolSpec("apt-get", "Packages", "Debian package manager"),
    ToolSpec("dpkg", "Packages", "Debian package database"),
    ToolSpec("dnf", "Packages", "Fedora/RHEL package manager"),
    ToolSpec("yum", "Packages", "RHEL-family package manager"),
    ToolSpec("rpm", "Packages", "RPM package database"),
    ToolSpec("pacman", "Packages", "Arch Linux package manager"),
    ToolSpec("zypper", "Packages", "SUSE package manager"),
    ToolSpec("apk", "Packages", "Alpine package manager"),
    ToolSpec("snap", "Packages", "Snap package manager"),
    ToolSpec("flatpak", "Packages", "Flatpak package manager"),
    ToolSpec("brew", "Packages", "Homebrew package manager"),
    ToolSpec("port", "Packages", "MacPorts package manager"),
    ToolSpec("winget", "Packages", "Windows Package Manager"),
    ToolSpec("choco", "Packages", "Chocolatey package manager"),
    ToolSpec("scoop", "Packages", "Scoop package manager"),
    ToolSpec("launchctl", "macOS", "macOS service manager"),
    ToolSpec("powershell", "Windows", "Windows PowerShell", ("pwsh", "powershell.exe", "powershell")),
    ToolSpec("wsl", "Windows", "Windows Subsystem for Linux", ("wsl.exe", "wsl")),
    ToolSpec("tasklist", "Windows", "Windows process listing", ("tasklist.exe", "tasklist")),
    ToolSpec("sc", "Windows", "Windows service controller", ("sc.exe", "sc")),
    ToolSpec("systeminfo", "Windows", "Windows system inventory", ("systeminfo.exe", "systeminfo")),
)


def discover_tools(query: str = "") -> list[tuple[ToolSpec, str | None]]:
    """Return every catalogued tool and its resolved executable if present."""
    needle = query.casefold().strip()
    rows: list[tuple[ToolSpec, str | None]] = []
    for tool in TOOLS:
        haystack = f"{tool.name} {tool.category} {tool.description}".casefold()
        if needle and needle not in haystack:
            continue
        resolved = None
        for executable in tool.executables or (tool.name,):
            resolved = shutil.which(executable)
            if resolved:
                break
        rows.append((tool, resolved))
    return rows

# OS Forge — cross-platform terminal launcher

OS Forge is a real, extensible command-line workbench for **Windows, macOS, and Linux**. It combines a high-contrast terminal interface, host diagnostics, process and port inspection, network checks, command discovery, and native package-manager adapters in one launcher.

It does not emulate an operating system, replace a kernel, or claim that every Linux command is native to Windows/macOS. It detects which tools really exist and invokes the host's native implementations. On Linux it supports Debian-family tools (apt/apt-get/dpkg), Red Hat-family tools (dnf/yum/rpm), and other common package managers. On macOS it supports Homebrew and MacPorts; on Windows it supports winget, Chocolatey, and Scoop when installed.

## Install

Requirements: Python 3.11 or newer. Open a normal terminal; administrator/root access is not required to inspect the machine.

From a checkout:

    python -m pip install -e .
    osforge

Or start the module directly from the source tree:

    python -m osforge

Upgrade pip if your environment needs it:

    python -m pip install --upgrade pip
    python -m pip install -e ".[dev]"
    python -m pytest

## Quick commands

Run these from your existing Windows Terminal, PowerShell, Command Prompt, macOS Terminal, or Linux terminal.

    osforge
    osforge info
    osforge doctor
    osforge tools
    osforge tools docker
    osforge processes
    osforge ports
    osforge net interfaces
    osforge net dns example.com
    osforge net ping example.com
    osforge net check example.com 443
    osforge pkg list
    osforge pkg search ripgrep
    osforge pkg install ripgrep
    osforge pkg remove ripgrep
    osforge pkg update
    osforge shell
    osforge run git --version

Package changes require a visible confirmation. Use the command's --yes option only when running a package action non-interactively; it does not grant administrator rights or bypass the host package manager's own restrictions. The program never auto-elevates itself.

## Interactive launcher

Start osforge with no arguments. The command prompt supports built-ins:

- help — command reference
- info — current OS, CPU, memory, disk, Python, and uptime details
- doctor — diagnostics and detected package managers
- tools [filter] — inspect which developer, administration, and security tools are installed
- processes [limit] — list live processes
- kill PID — request termination after showing the process identity and asking for confirmation
- ports — inspect local listening TCP sockets
- net interfaces — show network interfaces and addresses
- net dns HOST — resolve a hostname through the system resolver
- net ping HOST — send a small, bounded ping request
- net check HOST PORT — check one explicitly supplied TCP endpoint
- pkg list|search|install|remove|update — use a detected native package manager
- run PROGRAM [ARG ...] — run a real executable directly, without a shell
- shell — launch the user's normal interactive system shell
- cd PATH — change the launcher's working directory
- clear, exit

Commands not built into the launcher can be invoked by name, such as git, python, ipconfig, PowerShell cmdlets via the PowerShell shell, or Linux tools available on the host. Use shell for pipelines, redirects, shell functions, and other shell syntax.

## Native package managers

OS Forge chooses an available manager by platform unless --manager is supplied. Supported adapters are:

- Windows: winget, choco, scoop
- macOS: brew, port
- Linux: apt, apt-get, dnf, yum, pacman, zypper, apk, snap, flatpak, nix-env, emerge

A manager must be installed and discoverable on PATH. OS Forge invokes native executable argument arrays rather than interpolating package names into a shell command. Install/remove/update commands can change the host and may require elevation; inspect the printed command and confirmation prompt first.

## Design guarantees

- Real host data and host processes; no simulated process lists, package installs, ports, or system status.
- Cross-platform paths and command discovery.
- Package names are passed as individual process arguments; no shell interpolation is used by package adapters.
- Process termination requires an interactive confirmation and refuses to terminate the launcher itself.
- Network checks require an explicit hostname and port; there is no built-in broad network scanner.
- No hidden startup persistence, credential collection, telemetry, or silent system changes.
- Automated tests run on Windows, macOS, and Ubuntu with supported Python versions in GitHub Actions.

## Scope and honest limits

OS Forge is a **launcher and system administration workbench**, not a new OS distribution or a privileged system service. It cannot make Windows a Debian installation or guarantee Linux-only tools such as systemd, rpm, dnf, or iproute2 are present on every machine. WSL, containers, virtual machines, and compatibility layers can provide additional environments when installed by the user. Availability and privileges remain those of the host.

It intentionally does not apply broad machine-wide tweaks automatically. Use native host tools for specific configuration changes, review their effects, and make backups before changing system settings.

## Development

    python -m pip install -e ".[dev]"
    python -m pytest
    python -m osforge doctor

See docs/SECURITY.md for the execution and safety model.

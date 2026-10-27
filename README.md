# OS Forge — cross-platform terminal and defensive security workbench

OS Forge is a local command-line workbench for Windows, macOS, and Linux. It combines live host diagnostics and native terminal tools with local security-posture checks, authorization-scope validation, security-tool discovery, and an integrity-checked audit journal.

OS Forge is a user-space workbench, not an operating-system replacement. It only has the privileges and network access available to the account running it.

## Install

Requirements: Python 3.11 or newer.

    git clone https://github.com/reponsekdz3/os.git
    cd os
    python -m pip install -e .
    osforge

On Windows, use py -m pip install -e . if python is not on PATH.

For development and tests:

    python -m pip install -e ".[dev]"
    python -m pytest

## Core terminal commands

    osforge
    osforge info
    osforge doctor
    osforge tools --all
    osforge processes
    osforge ports
    osforge net interfaces
    osforge net dns example.com
    osforge net check example.com 443
    osforge pkg search ripgrep
    osforge shell
    osforge run git --version

These commands use actual host data and native executables. Package changes request confirmation and use the platform's package manager.

## Defensive security commands

### Local host posture

    osforge security host-audit
    osforge security host-audit --output host-posture.json

The read-only host audit checks firewall state with native tools where possible, reviews selected Linux SSH configuration directives, inventories TCP listeners bound to wildcard interfaces, checks high memory pressure and home-directory permissions, and reports security-tool availability. Some checks may be incomplete without administrative visibility. Interpret findings in context.

### Security tool inventory

    osforge security tools

This command discovers utilities such as Bandit, Trivy, Syft, Gitleaks, Semgrep, OSV-Scanner, Lynis, ClamAV, YARA, OSQuery, and platform-native administration tools. It reports whether executables are available on PATH; it does not bundle or automatically run them. Third-party extension metadata is listed without importing extension code.

### Validate written authorization scope

An authorization manifest records the approved targets and expiry for a security engagement. It does not independently prove that the operator has permission.

Example scope.json:

    {
      "schema_version": 1,
      "engagement": {
        "name": "Internal network review",
        "owner": "IT Security",
        "authorization_reference": "CHANGE-1234",
        "expires_at": "2027-01-30T18:00:00Z"
      },
      "targets": ["192.168.1.10", "example.org"],
      "ports": [80, 443],
      "web_urls": ["https://example.org"]
    }

Validate the manifest locally without connecting to any listed target:

    osforge security validate-scope scope.json

The validator checks expiry, target syntax, explicit ports, and that web URL hosts appear in the allowlist. Wildcard hosts are not accepted, and each IP network entry is limited to 256 addresses. This release validates the authorization record only; it does not perform a remote assessment.

### Audit journal

    osforge security audit-verify

Security operations append local JSON Lines records under ~/.osforge/security-audit.jsonl. Entries are linked with SHA-256 hashes; verification detects edits or broken links. This is tamper-evident, not tamper-proof. For stronger evidence, forward events to centrally managed logging.

## Native package managers

- Windows: winget, Chocolatey, Scoop
- macOS: Homebrew, MacPorts
- Linux: apt, apt-get, dnf, yum, pacman, zypper, apk, Snap, Flatpak, Nix, and Portage

A package manager must be installed and available on PATH. OS Forge invokes native executable argument arrays and does not silently elevate privileges.

## Extension model

Security utilities are discovered by capability and availability. Future plugins should have versioned metadata, declared permissions, input/output contracts, clear provenance, and explicit administrator trust decisions. Build the ecosystem around reviewed integrations instead of relying on huge, unverified collections.

## Limitations

- Scope validation is a governance check, not a remote penetration test.
- The platform does not perform indiscriminate discovery of devices on public networks.
- No hidden telemetry or inventory uploads are performed by OS Forge.
- Third-party tool behavior and accuracy remain the responsibility of each tool's publisher.
- A clean report is not proof that a system is secure.

See docs/SECURITY.md and tests/ for more details.

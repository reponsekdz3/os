# Security and execution model

OS Forge is a local user-space terminal and defensive host workbench. It does not install a background service, alter startup entries, collect credentials, upload host inventories, or change system settings on startup.

## Defensive checks

- The host posture command reads local firewall state where native tools are available, reviews selected Linux SSH configuration directives, inventories local TCP listeners, and checks a few local indicators. Some results can be incomplete without administrator visibility.
- The authorization-manifest validator checks structure, explicit targets, ports, URL host coverage, and expiry. It is a governance check only. The manifest is self-attested and does not independently establish ownership or permission.
- Security tools are discovered from PATH. The inventory does not execute them. Extension entry-point metadata is listed without importing extension code.
- The local audit journal links JSONL entries with SHA-256 hashes. It can detect edits and broken links, but is not a substitute for independently controlled centralized logging.

## Command execution boundaries

- Package managers use argument arrays with shell execution disabled. Package identifiers are validated before installation or removal.
- Package installs, removals, and upgrades can change the host. The CLI displays the planned action and requests confirmation by default.
- OS Forge does not call sudo, request UAC elevation, or change its own privileges.
- The run command launches an executable and its arguments without shell interpolation. The shell command opens the user's normal interactive shell and operates with the user's current permissions.
- Process termination displays the target identity and requires confirmation; the launcher refuses to terminate its own process.
- Existing network utilities provide explicit DNS lookup, bounded ping, and a single-endpoint TCP check. This release does not provide a remote network assessment engine.

## Audit journal

Security operations can append events under ~/.osforge/security-audit.jsonl. Each entry includes a previous-entry hash and a SHA-256 hash of its canonical representation. The security audit-verify command detects edits or broken links. An administrator can rewrite the file and recompute its hashes, so centralize events in independently controlled storage when stronger evidence is required.

## Authorization and scope

Only work on devices, applications, domains, and networks for which you have clear permission. Use explicit target lists, an owner/contact, an approval or ticket reference, a time-bounded expiry, and an agreed change window. Public reachability is not evidence of permission.

The security validate-scope command validates the authorization document but does not contact any target. The document is an operator record, not independent proof of approval.

## Operational advice

Use a standard user account for routine inspection. Elevate only specific native commands when needed and understand their effects. Install third-party tools from trusted sources, review their licensing and configuration, and back up data before system changes.

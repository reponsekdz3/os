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


## Scoped assessment runner

The security assess command is a separate, explicitly confirmed workflow. It validates an active manifest before making requests, contacts only listed exact targets or bounded CIDR entries, and checks only the configured TCP ports. Runtime ceilings are 256 target/address pairs, 4096 TCP connections, eight concurrent TCP checks, four concurrent web checks, and 64 explicitly listed web URLs. Scope expiry is checked before each TCP connection and before each HTTP check.

TCP checks complete a handshake and close the connection without sending service-specific data. Each configured web URL receives one HTTP HEAD request with a bounded timeout; redirects are not followed, pages are not crawled, and authentication or state-changing requests are not made. URL credentials, fragments, and query strings are rejected. HTTPS uses the platform's default certificate-validation context. Only selected security-related response headers are retained; cookies and response bodies are not collected.

An open port indicates reachability, not a confirmed vulnerability. Missing HTTP headers are configuration observations, not proof of exploitability. Human review is required before changing production controls.

## Evidence and remediation workflow

Evidence reports are JSON. Assessment runs, stable finding identifiers, evidence, status, assignee, due date, and finding state events are kept in a local SQLite database. Status changes are also written to the local hash-linked audit journal. The journal detects edits but is not an independently protected evidence store. Team deployments should forward events and reports to access-controlled centralized storage.

Risk acceptance, false-positive classification, and resolution require review notes. Reobserving a resolved finding reopens the record. State is local to the current OS Forge installation; this release does not include team authentication, a centralized service, distributed locking, or role-based access control.

## Plugin execution model

Built-in rules process only the observations provided by the assessment engine. Third-party plugins register through the osforge.security_checks Python entry-point group. Discovery inspects plugin metadata only. An external plugin is loaded only when the operator names it explicitly and confirms the assessment. The plugin receives a recursively read-only evidence context, but Python plugins are not sandboxed: imported code still runs with the OS Forge user's privileges. Only install reviewed distributions from trusted sources.

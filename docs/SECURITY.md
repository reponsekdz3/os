# Security and execution model

OS Forge is a local user-space launcher. It does not install a background service, alter startup entries, collect credentials, upload host inventories, or change system settings on startup.

## Execution boundaries

- Package adapters use argument arrays with shell execution disabled. Package identifiers are validated before install or removal.
- Native package managers retain their own permission, signature, trust, and confirmation behavior. OS Forge does not call sudo, request UAC elevation, or change its own privileges.
- A package install, uninstall, or update can materially change the host. The CLI displays the planned action and asks for confirmation unless the user explicitly passes --yes.
- The run command launches the exact executable and argument list supplied. It does not interpret pipes, redirections, or shell operators. The shell command intentionally launches the user's normal interactive shell; commands typed there have the same power as commands typed in a regular terminal.
- The process-termination command displays the target process and requires confirmation; it refuses to terminate the OS Forge process itself.
- Network diagnostics are limited to resolver queries, a short bounded ping, and a single explicitly requested TCP endpoint. There is no automatic subnet sweep or packet capture.

## Operational advice

Use a standard user account for routine inspection. Elevate only the specific native command that requires it and understand the command before approving it. Review third-party packages and sources before installing them. Back up important data before system upgrades or configuration changes.

# OS Forge Security Check Plugins

OS Forge ships two evidence rules: tcp-exposure and web-headers. They analyse observations collected by the core engine. The engine owns target selection, expiry enforcement, connection budgets, transport timeouts, and evidence serialization.

## Contract

An installed Python distribution can register an entry point in the osforge.security_checks group. The entry point must resolve to a class or object exposing evaluate(context).

The context is an osforge.security.contracts.AssessmentContext instance:

- scope: mapping of engagement metadata, approved target entries, and allowed ports.
- tcp_observations: sequence of dictionaries containing scoped TCP connection outcomes.
- web_observations: sequence of dictionaries with HTTP HEAD status, selected response headers, TLS metadata, and connection errors.

evaluate(context) returns a list or tuple of findings. Each finding must provide:

    {
      "check_id": "example-rule",
      "severity": "low",
      "title": "A concrete, evidence-supported observation",
      "asset": "in-scope asset identifier",
      "evidence": {"observed": "value", "method": "how it was observed"},
      "remediation": "A specific defensive correction or next step",
      "confidence": "medium"
    }

Supported severities are critical, high, medium, low, and info. Evidence must be JSON-compatible. Strings and fields are length-limited and validated before storage. Plugin output is not allowed to redefine the scope or change collected observations.

## Registering a plugin

Example pyproject.toml for a separately distributed plugin:

    [project.entry-points."osforge.security_checks"]
    example-rule = "example_osforge_plugin:ExampleRule"

Example class:

    class ExampleRule:
        name = "example-rule"
        version = "1.0.0"
        description = "Inspects collected evidence."

        def evaluate(self, context):
            findings = []
            # Evaluate context.tcp_observations and context.web_observations only.
            # Return finding dictionaries that cite concrete evidence.
            return findings

Install the reviewed plugin distribution in the same Python environment as OS Forge. List plugin metadata without loading code:

    osforge security plugins

Run a selected plugin explicitly:

    osforge security assess scope.json --plugin example-rule

The assessment command warns and asks for confirmation before loading a third-party plugin. In non-interactive use, --yes is an explicit operator approval for both the assessment and all selected plugin code.

## Trust model

Python plugins execute in-process with the privileges of the OS Forge user. They are not sandboxed. A plugin can potentially perform filesystem, network, or subprocess operations irrespective of this interface. Only install plugins from reviewed sources; pin versions and hashes in deployment requirements; review their dependencies and code; and run under a dedicated, least-privileged account. The core does not automatically import or execute plugins during discovery.

The plugin contract is for defensive evidence analysis and remediation advice. Do not create plugins that bypass scope, collect secrets, perform destructive actions, or hide activity.

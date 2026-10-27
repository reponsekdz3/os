"""Explicit opt-in plugin discovery and evidence validation."""
from __future__ import annotations

import importlib.metadata
import json
from typing import Any

from osforge.security.contracts import AssessmentContext, PluginMetadata

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
BUILTIN_PLUGIN_METADATA = (
    PluginMetadata("tcp-exposure", "1.0.0", "Classify reachable TCP services from recorded connection evidence.", "built-in", True),
    PluginMetadata("web-headers", "1.0.0", "Review HTTP response headers and observed TLS validation errors.", "built-in", True),
)


def discover_plugins() -> list[PluginMetadata]:
    """Inspect extension metadata only; does not import plugin code."""
    result = list(BUILTIN_PLUGIN_METADATA)
    try:
        entry_points = importlib.metadata.entry_points()
        points = entry_points.select(group="osforge.security_checks")
    except (AttributeError, TypeError):
        points = []
    for point in points:
        result.append(PluginMetadata(
            name=point.name,
            version="installed",
            description="Third-party check. Code is not loaded unless explicitly selected.",
            source=f"python-entry-point:{point.value}",
            trusted=False,
        ))
    return result


def validate_plugin_selection(plugin_names: tuple[str, ...]) -> None:
    names = set(plugin_names)
    known = {metadata.name for metadata in discover_plugins()}
    unknown = names - known
    if unknown:
        raise ValueError(
            f"Unknown plugin(s): {', '.join(sorted(unknown))}. "
            "Use 'osforge security plugins' to see registered extensions."
        )


def _validate_finding(item: Any, plugin_name: str) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError(f"Plugin {plugin_name!r} returned a finding that is not a dictionary.")
    severity = str(item.get("severity", "")).lower()
    if severity not in ALLOWED_SEVERITIES:
        raise ValueError(f"Plugin {plugin_name!r} returned unsupported severity {severity!r}.")
    required = ("check_id", "title", "asset", "evidence", "remediation")
    for field in required:
        if field not in item:
            raise ValueError(f"Plugin {plugin_name!r} omitted required field {field!r}.")
    normalized = dict(item)
    for field, max_len in (("check_id", 96), ("title", 300), ("asset", 800), ("remediation", 4000)):
        value = str(normalized[field]).strip()
        if not value or len(value) > max_len:
            raise ValueError(f"Plugin {plugin_name!r} field {field!r} is empty or too long.")
        normalized[field] = value
    if isinstance(normalized["evidence"], str) and len(normalized["evidence"]) > 6000:
        raise ValueError(f"Plugin {plugin_name!r} evidence is too long.")
    try:
        json.dumps(normalized["evidence"], ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Plugin {plugin_name!r} evidence must be JSON-compatible.") from exc
    normalized["severity"] = severity
    normalized["confidence"] = str(normalized.get("confidence", "medium")).lower()
    normalized["plugin"] = plugin_name
    return normalized


def evaluate_plugins(
    context: AssessmentContext,
    plugin_names: tuple[str, ...] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Run built-in evidence rules and explicitly selected third-party evaluators."""
    from osforge.security.checks import BUILTIN_RULES

    validate_plugin_selection(plugin_names)
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for name, function in BUILTIN_RULES.items():
        try:
            for item in function(context):
                findings.append(_validate_finding(dict(item), name))
        except Exception as exc:
            # Keep the evidence report usable if a single rule fails.
            errors.append({"plugin": name, "error_type": type(exc).__name__, "message": str(exc)[:500]})

    builtin_names = set(BUILTIN_RULES)
    external_selected = set(plugin_names) - builtin_names
    if not external_selected:
        return findings, errors

    try:
        points = importlib.metadata.entry_points()
        all_points = points.select(group="osforge.security_checks")
    except (AttributeError, TypeError):
        all_points = []
    by_name = {point.name: point for point in all_points}
    for name in sorted(external_selected):
        point = by_name.get(name)
        try:
            if point is None:
                raise ValueError(f"Installed extension {name!r} could not be resolved.")
            # Loading executes the distribution's Python code in this process.
            # The CLI must warn and obtain operator confirmation before this function is reached.
            plugin = point.load()
            if isinstance(plugin, type):
                plugin = plugin()
            evaluator = getattr(plugin, "evaluate", None)
            if not callable(evaluator):
                raise ValueError(f"Plugin {name!r} must provide evaluate(context).")
            output = evaluator(context)
            if not isinstance(output, (list, tuple)):
                raise ValueError(f"Plugin {name!r} must return a list or tuple of findings.")
            for item in output:
                findings.append(_validate_finding(item, name))
        except Exception as exc:
            errors.append({
                "plugin": name,
                "error_type": type(exc).__name__,
                "message": str(exc)[:500],
            })
    return findings, errors

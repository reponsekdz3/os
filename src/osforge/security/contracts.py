"""Stable, evidence-only interface for OS Forge security check plugins.

Plugins receive collected evidence and scope metadata; the engine, not plugins, owns
network I/O. Third-party entry points are loaded only when an operator explicitly selects them.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence


@dataclass(frozen=True)
class AssessmentContext:
    scope: Mapping[str, Any]
    tcp_observations: Sequence[Mapping[str, Any]]
    web_observations: Sequence[Mapping[str, Any]]


class SecurityCheckPlugin(Protocol):
    name: str
    version: str
    description: str

    def evaluate(self, context: AssessmentContext) -> Sequence[Mapping[str, Any]]:
        """Return normalized finding dictionaries without performing network I/O."""
        ...


@dataclass(frozen=True)
class PluginMetadata:
    name: str
    version: str
    description: str
    source: str
    trusted: bool

"""Authorization manifest validation for future scoped assessments.

This module validates the written scope; it does not independently verify ownership or consent.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_TARGETS = 1024
MAX_PORTS = 128
_DOMAIN_LABEL = re.compile(r"^(?=.{1,63}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$")


def _expires(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("engagement.expires_at must be an ISO-8601 date/time with timezone.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("engagement.expires_at is not valid ISO-8601.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("engagement.expires_at must include a timezone, such as Z or +00:00.")
    return parsed.astimezone(timezone.utc)


def normalize_target(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Each target must be an IP, CIDR, or exact hostname.")
    target = value.strip()
    if any(ch.isspace() for ch in target) or target.startswith(("-", "/")) or "*" in target:
        raise ValueError(f"Invalid target {value!r}; wildcards and whitespace are not supported.")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid network {target!r}.") from exc
        if network.num_addresses > 256:
            raise ValueError(f"Network {network} contains more than 256 addresses; split it into narrower explicitly authorized ranges.")
        return str(network)
    domain = target.rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid hostname {target!r}.") from exc
    if len(domain) > 253 or not all(_DOMAIN_LABEL.fullmatch(part) for part in domain.split(".")):
        raise ValueError(f"Invalid hostname {target!r}.")
    return domain


@dataclass(frozen=True)
class ScopeManifest:
    name: str
    owner: str
    authorization_reference: str
    expires_at: datetime
    targets: tuple[str, ...]
    ports: tuple[int, ...]
    source_path: str = ""

    @property
    def active(self) -> bool:
        return datetime.now(timezone.utc) < self.expires_at


def validate_scope_data(data: dict[str, Any], source_path: str = "", require_active: bool = True) -> ScopeManifest:
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("schema_version must be 1.")
    engagement = data.get("engagement")
    if not isinstance(engagement, dict):
        raise ValueError("engagement must be an object.")
    name = str(engagement.get("name", "")).strip()
    owner = str(engagement.get("owner", "")).strip()
    reference = str(engagement.get("authorization_reference", "")).strip()
    if not all((name, owner, reference)):
        raise ValueError("engagement.name, owner, and authorization_reference are required.")
    expires_at = _expires(engagement.get("expires_at"))
    if require_active and expires_at <= datetime.now(timezone.utc):
        raise ValueError("This scope has expired; obtain and record renewed authorization.")
    raw_targets = data.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets or len(raw_targets) > MAX_TARGETS:
        raise ValueError(f"targets must contain between 1 and {MAX_TARGETS} explicit entries.")
    targets = tuple(dict.fromkeys(normalize_target(item) for item in raw_targets))
    raw_ports = data.get("ports", [])
    if not isinstance(raw_ports, list) or not raw_ports or len(raw_ports) > MAX_PORTS:
        raise ValueError(f"ports must contain between 1 and {MAX_PORTS} explicit TCP port numbers.")
    ports: list[int] = []
    for value in raw_ports:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise ValueError(f"Invalid TCP port value: {value!r}.")
        if value not in ports:
            ports.append(value)
    urls = data.get("web_urls", [])
    if not isinstance(urls, list) or len(urls) > MAX_TARGETS:
        raise ValueError("web_urls must be a list with at most 1024 entries.")
    for value in urls:
        if not isinstance(value, str) or len(value) > 2048:
            raise ValueError("Each web URL must be a string no longer than 2048 characters.")
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Invalid web URL {value!r}; expected http(s)://host.")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Web URLs must not contain credentials or fragments.")
        target_host = normalize_target(parsed.hostname)
        if target_host not in targets and not _host_in_network(target_host, targets):
            raise ValueError(f"Web URL host {target_host!r} is not explicitly covered by targets.")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in ports:
            raise ValueError(f"Web URL port {port} must also appear in ports.")
    return ScopeManifest(name, owner, reference, expires_at, targets, tuple(ports), source_path)


def _host_in_network(host: str, targets: tuple[str, ...]) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    for target in targets:
        try:
            if "/" in target and address in ipaddress.ip_network(target, strict=False):
                return True
        except ValueError:
            continue
    return False


def load_scope(path: str | Path, require_active: bool = True) -> ScopeManifest:
    source = Path(path).expanduser().resolve()
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Cannot read scope file {source}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Scope file is not valid JSON (line {exc.lineno}).") from exc
    return validate_scope_data(data, str(source), require_active=require_active)

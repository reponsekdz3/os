"""Permission-controlled, low-impact network and web assessment runner.

Network checks run only against active scope-manifest targets and explicitly listed ports.
The runner performs TCP handshakes and single HTTP HEAD requests; it sends no exploit
payloads, credentials, protocol banners, or state-changing requests.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from osforge.security.audit import append_event
from osforge.security.contracts import AssessmentContext
from osforge.security.plugins import evaluate_plugins, validate_plugin_selection
from osforge.security.scope import ScopeManifest, load_scope

MAX_ASSESSMENT_ADDRESSES = 256
MAX_TCP_PROBES = 4096
MAX_WEB_URLS = 64
MAX_WEB_WORKERS = 4
MAX_DNS_ANSWERS_PER_TARGET = 16
MAX_WORKERS = 8
SENSITIVE_PORTS = {
    21: "FTP", 23: "Telnet", 135: "MS RPC", 139: "NetBIOS", 445: "SMB",
    1433: "Microsoft SQL Server", 1521: "Oracle Database", 2049: "NFS",
    2375: "Docker API", 2376: "Docker TLS API", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 5985: "WinRM HTTP",
    5986: "WinRM HTTPS", 6379: "Redis", 6443: "Kubernetes API",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}
SERVICE_HINTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 135: "rpc", 139: "netbios",
    143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle-db", 2049: "nfs", 2375: "container-api",
    2376: "container-api-tls", 3000: "web-app", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5601: "kibana", 5900: "vnc",
    5985: "winrm-http", 5986: "winrm-https", 6379: "redis",
    6443: "kubernetes-api", 8000: "web-app", 8080: "http-alt",
    8443: "https-alt", 9200: "search-api", 11211: "memcached", 27017: "mongodb",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp() -> str:
    return _now().isoformat()


def _safe_web_url(url: str) -> tuple[str, str, str, int]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Invalid scoped web URL: {url!r}")
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("Scoped web URLs may not contain credentials, query strings, or fragments.")
    host = parsed.hostname
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError(f"Invalid port in scoped URL: {url!r}") from exc
    path = parsed.path or "/"
    safe = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    return safe, parsed.scheme, host, port


def _resolve_exact_target(target: str) -> list[str]:
    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        return [str(host) for host in network.hosts()]
    try:
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        pass
    try:
        results = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise OSError(f"System DNS resolution failed for {target}: {exc}") from exc
    addresses = sorted({str(item[4][0]) for item in results})
    if not addresses:
        raise OSError(f"No A/AAAA addresses returned for scoped target {target}.")
    if len(addresses) > MAX_DNS_ANSWERS_PER_TARGET:
        raise ValueError(
            f"Target {target} resolved to more than {MAX_DNS_ANSWERS_PER_TARGET} addresses; "
            "narrow the authorized target or use a dedicated approved asset inventory."
        )
    return addresses


def _expand_assets(scope: ScopeManifest) -> tuple[list[dict[str, str]], list[dict[str, str]], dict[str, list[str]]]:
    assets: list[dict[str, str]] = []
    resolution_errors: list[dict[str, str]] = []
    target_addresses: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()
    for target in scope.targets:
        if not scope.active:
            raise ValueError("Authorization scope expired during asset resolution; assessment stopped.")
        try:
            addresses = _resolve_exact_target(target)
        except (OSError, ValueError) as exc:
            resolution_errors.append({"target": target, "error": f"{type(exc).__name__}: {exc}"[:1200]})
            continue
        target_addresses[target] = addresses
        for address in addresses:
            key = (target, address)
            if key in seen:
                continue
            seen.add(key)
            assets.append({"target": target, "address": address})
            if len(assets) > MAX_ASSESSMENT_ADDRESSES:
                raise ValueError(
                    f"Scope resolves to more than {MAX_ASSESSMENT_ADDRESSES} target/address pairs. "
                    "Split the assessment into separately approved, smaller scopes."
                )
    if not assets:
        raise ValueError("No in-scope targets could be resolved; no TCP requests were sent.")
    return assets, resolution_errors, target_addresses


def _tcp_probe(asset: dict[str, str], port: int, timeout: float, expires_at: datetime) -> dict[str, Any]:
    """Perform one bounded TCP connect; no protocol data is sent."""
    target = asset["target"]
    address = asset["address"]
    if _now() >= expires_at:
        return {
            "target": target, "address": address, "port": port,
            "status": "not-probed-scope-expired", "service_hint": SERVICE_HINTS.get(port, "unknown"),
            "latency_ms": 0.0, "error": "Authorization expired before probe started.",
        }
    started = time.perf_counter()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            status, error = "open", ""
    except ConnectionRefusedError as exc:
        status, error = "closed", str(exc)
    except (socket.timeout, TimeoutError) as exc:
        status, error = "no-response", str(exc) or "Connection attempt timed out."
    except OSError as exc:
        status, error = "unreachable", str(exc)
    return {
        "target": target, "address": address, "port": port, "status": status,
        "service_hint": SERVICE_HINTS.get(port, "unknown"),
        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        "error": error[:240],
    }


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, port: int, ip_address: str, timeout: float) -> None:
        super().__init__(hostname, port, timeout=timeout)
        self._ip_address = ip_address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip_address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, port: int, ip_address: str, timeout: float) -> None:
        super().__init__(hostname, port, timeout=timeout, context=ssl.create_default_context())
        self._ip_address = ip_address

    def connect(self) -> None:
        raw = socket.create_connection((self._ip_address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


_SAFE_HEADERS = {
    "strict-transport-security", "content-security-policy", "x-content-type-options",
    "referrer-policy", "permissions-policy", "location", "content-type",
}


def _web_check(
    scope: ScopeManifest,
    url: str,
    target_addresses: dict[str, list[str]],
    assets: list[dict[str, str]],
) -> dict[str, Any]:
    safe_url, scheme, host, port = _safe_web_url(url)
    if not scope.active:
        return {
            "url": safe_url, "scheme": scheme, "port": port, "status_code": None,
            "headers": {}, "connected_ip": "", "tls_version": "", "error_kind": "scope-expired",
            "error": "Authorization expired before the web check started.",
        }
    if port not in scope.ports:
        raise ValueError(f"Web URL port {port} is not in the active scope's allowed ports.")
    try:
        ipaddress.ip_address(host)
        candidates = [host]
    except ValueError:
        candidates = target_addresses.get(host.lower().rstrip("."), [])
        # A URL host explicitly allowed as an address inside a CIDR may not be a
        # textual scope key, so use the exact address if it is present in assets.
        if not candidates:
            candidates = [item["address"] for item in assets if item["address"] == host]
    if not candidates:
        return {
            "url": safe_url, "scheme": scheme, "port": port, "status_code": None,
            "headers": {}, "connected_ip": "", "tls_version": "", "error_kind": "scope-resolution",
            "error": "No resolved address was associated with this explicitly scoped URL host.",
        }

    path = urlsplit(url).path or "/"
    ip_address = candidates[0]
    connection: http.client.HTTPConnection | None = None
    try:
        if scheme == "https":
            connection = _PinnedHTTPSConnection(host, port, ip_address, 2.0)
        else:
            connection = _PinnedHTTPConnection(host, port, ip_address, 2.0)
        connection.request(
            "HEAD", path,
            headers={"Host": urlsplit(url).netloc, "User-Agent": "OSForge-Authorized-Assessment/1.0", "Connection": "close"},
        )
        response = connection.getresponse()
        headers = {}
        for key, value in response.getheaders():
            normalized = key.lower()
            if normalized in _SAFE_HEADERS:
                headers[normalized] = value.strip()[:600]
        tls_version = ""
        certificate_sha256 = ""
        if scheme == "https" and connection.sock:
            tls_version = connection.sock.version() or ""
            certificate = connection.sock.getpeercert(binary_form=True)
            if certificate:
                certificate_sha256 = hashlib.sha256(certificate).hexdigest()
        return {
            "url": safe_url, "scheme": scheme, "port": port, "connected_ip": ip_address,
            "status_code": response.status, "reason": str(response.reason)[:160],
            "headers": headers, "tls_version": tls_version,
            "certificate_sha256": certificate_sha256, "error_kind": "", "error": "",
        }
    except ssl.SSLCertVerificationError as exc:
        return {
            "url": safe_url, "scheme": scheme, "port": port, "connected_ip": ip_address,
            "status_code": None, "headers": {}, "tls_version": "", "certificate_sha256": "",
            "error_kind": "tls-certificate", "error": f"{type(exc).__name__}: {exc}"[:1200],
        }
    except (ssl.SSLError, OSError, http.client.HTTPException, TimeoutError) as exc:
        return {
            "url": safe_url, "scheme": scheme, "port": port, "connected_ip": ip_address,
            "status_code": None, "headers": {}, "tls_version": "", "certificate_sha256": "",
            "error_kind": "connection", "error": f"{type(exc).__name__}: {exc}"[:1200],
        }
    finally:
        if connection is not None:
            connection.close()




def _freeze(value: Any) -> Any:
    """Build recursively read-only, detached views for extension evaluators."""
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def run_assessment(
    scope_path: str | Path,
    *,
    output_path: str | Path = "osforge-assessment-report.json",
    database_path: str | Path | None = None,
    audit_path: str | Path | None = None,
    plugin_names: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Run the governed assessment workflow and persist findings/remediation state."""
    from osforge.security.state import record_assessment

    scope = load_scope(scope_path, require_active=True)
    # Reject unknown extension names before making any network request.
    validate_plugin_selection(plugin_names)
    if len(scope.web_urls) > MAX_WEB_URLS:
        raise ValueError(f"At most {MAX_WEB_URLS} explicit web URLs are allowed per assessment run.")
    started_at = _timestamp()
    clock_started = time.perf_counter()
    assessment_id = str(uuid.uuid4())
    append_event(
        "assessment.started",
        details={
            "assessment_id": assessment_id,
            "scope_file": scope.source_path,
            "scope_name": scope.name,
            "authorization_reference": scope.authorization_reference,
            "target_entries": len(scope.targets),
            "ports": list(scope.ports),
            "plugins": list(plugin_names),
        },
        path=audit_path,
    )

    try:
        assets, resolution_errors, target_addresses = _expand_assets(scope)
        probe_count = len(assets) * len(scope.ports)
        if probe_count > MAX_TCP_PROBES:
            raise ValueError(
                f"Assessment would run {probe_count} TCP connection checks; the per-run ceiling is "
                f"{MAX_TCP_PROBES}. Reduce explicitly approved targets or ports."
            )
        if not scope.active:
            raise ValueError("Authorization expired before the assessment started.")
    except Exception as exc:
        append_event(
            "assessment.failed",
            details={
                "assessment_id": assessment_id,
                "error_type": type(exc).__name__,
                "message": str(exc)[:500],
            },
            path=audit_path,
        )
        raise

    observations: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [
            pool.submit(_tcp_probe, asset, port, 1.5, scope.expires_at)
            for asset in assets
            for port in scope.ports
        ]
        for future in concurrent.futures.as_completed(futures):
            observations.append(future.result())
    observations.sort(key=lambda row: (row["target"], row["address"], row["port"]))

    web_observations: list[dict[str, Any]] = []
    if scope.web_urls:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(MAX_WEB_WORKERS, len(scope.web_urls))
        ) as pool:
            futures = [
                pool.submit(_web_check, scope, url, target_addresses, assets)
                for url in scope.web_urls
            ]
            for future in concurrent.futures.as_completed(futures):
                web_observations.append(future.result())
        web_observations.sort(key=lambda item: item["url"])
    context = AssessmentContext(
        scope=_freeze({
            "name": scope.name, "owner": scope.owner,
            "authorization_reference": scope.authorization_reference,
            "expires_at": scope.expires_at.isoformat(), "targets": list(scope.targets),
            "ports": list(scope.ports),
        }),
        tcp_observations=tuple(_freeze(item) for item in observations),
        web_observations=tuple(_freeze(item) for item in web_observations),
    )
    findings, plugin_errors = evaluate_plugins(context, plugin_names)
    for error in resolution_errors:
        findings.append({
            "check_id": "asset-resolution", "severity": "low",
            "title": "Explicitly scoped target did not resolve",
            "asset": error["target"], "evidence": {"error": error["error"]},
            "remediation": "Verify the exact target string and DNS records with the system owner; keep the target in scope only if it is approved.",
            "confidence": "high", "plugin": "core",
        })
    for item in web_observations:
        if item.get("error") and item.get("error_kind") not in {"tls-certificate"}:
            findings.append({
                "check_id": "web-check", "severity": "info",
                "title": "Web metadata check did not complete",
                "asset": item["url"], "evidence": {"error_kind": item["error_kind"], "error": item["error"]},
                "remediation": "Confirm the in-scope endpoint is reachable and permits HEAD requests. No redirect was followed.",
                "confidence": "high", "plugin": "core",
            })

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda item: (
        severity_order.get(str(item.get("severity", "info")), 5),
        str(item.get("asset", "")), str(item.get("title", "")),
    ))
    now = _timestamp()
    report: dict[str, Any] = {
        "schema_version": 1,
        "product": "OS Forge Security",
        "assessment_id": assessment_id,
        "started_at": started_at,
        "completed_at": now,
        "duration_seconds": round(time.perf_counter() - clock_started, 3),
        "plugins": ["tcp-exposure", "web-headers", *plugin_names],
        "engagement": {
            "name": scope.name, "owner": scope.owner,
            "authorization_reference": scope.authorization_reference,
            "expires_at": scope.expires_at.isoformat(),
        },
        "scope": {
            "targets": list(scope.targets), "ports": list(scope.ports),
            "web_urls": [_safe_web_url(url)[0] for url in scope.web_urls],
            "max_target_address_pairs": MAX_ASSESSMENT_ADDRESSES,
            "max_tcp_probes": MAX_TCP_PROBES,
            "max_concurrency": MAX_WORKERS,
            "max_web_concurrency": MAX_WEB_WORKERS,
            "timeout_seconds": 1.5,
        },
        "summary": {
            "target_address_pairs": len(assets),
            "tcp_probes": len(observations),
            "tcp_open": sum(1 for row in observations if row["status"] == "open"),
            "tcp_closed": sum(1 for row in observations if row["status"] == "closed"),
            "tcp_no_response": sum(1 for row in observations if row["status"] == "no-response"),
            "web_urls_checked": len(web_observations),
            "findings_total": len(findings),
        },
        "assets": assets,
        "resolution_errors": resolution_errors,
        "tcp_observations": observations,
        "web_observations": web_observations,
        "plugin_errors": plugin_errors,
        "findings": findings,
        "limitations": [
            "Only explicit, active manifest targets and listed TCP ports were checked.",
            "The runner performs TCP connection checks and one HTTP HEAD request per listed URL.",
            "It does not follow redirects, crawl pages, send exploit payloads, authenticate, grab banners, or change remote state.",
            "The operator-provided manifest is not independent proof of legal authorization.",
            "An open TCP port is exposure evidence, not proof of a vulnerability; findings need human review.",
        ],
    }

    destination = Path(output_path).expanduser().resolve()
    report["report_path"] = str(destination)
    report = record_assessment(report, database_path=database_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(destination)
    append_event(
        "assessment.completed",
        details={
            "assessment_id": assessment_id,
            "report_path": str(destination),
            "target_address_pairs": len(assets),
            "tcp_probes": len(observations),
            "findings_total": len(findings),
            "plugin_errors": len(plugin_errors),
        },
        path=audit_path,
    )
    return report

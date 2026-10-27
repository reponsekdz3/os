"""Built-in security finding rules evaluated only against collected evidence."""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from osforge.security.contracts import AssessmentContext


_ADMIN_PORTS = {
    21: "FTP", 23: "Telnet", 135: "MS RPC", 139: "NetBIOS", 445: "SMB",
    1433: "Microsoft SQL Server", 1521: "Oracle Database", 2049: "NFS",
    2375: "Docker API (unencrypted)", 2376: "Docker TLS API", 3306: "MySQL",
    3389: "Remote Desktop", 5432: "PostgreSQL", 5601: "Kibana",
    5900: "VNC", 5985: "WinRM HTTP", 5986: "WinRM HTTPS", 6379: "Redis",
    6443: "Kubernetes API", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB",
}
_HEADER_RULES = {
    "x-content-type-options": (
        "low", "X-Content-Type-Options header not observed",
        "Consider setting X-Content-Type-Options: nosniff after checking application compatibility.",
    ),
    "content-security-policy": (
        "low", "Content-Security-Policy header not observed",
        "Design and test a Content-Security-Policy appropriate to this application's scripts and resources.",
    ),
    "referrer-policy": (
        "low", "Referrer-Policy header not observed",
        "Choose a Referrer-Policy based on the application's privacy requirements.",
    ),
    "permissions-policy": (
        "info", "Permissions-Policy header not observed",
        "Consider restricting browser features that the application does not need.",
    ),
}


def tcp_exposure(context: AssessmentContext) -> Sequence[Mapping[str, Any]]:
    results = []
    for observation in context.tcp_observations:
        if observation.get("status") != "open":
            continue
        port = int(observation["port"])
        service = str(observation.get("service_hint") or "unknown")
        target = str(observation.get("target") or observation.get("address") or "unknown")
        address = str(observation.get("address") or target)
        latency = float(observation.get("latency_ms") or 0.0)
        if port in _ADMIN_PORTS:
            severity = "medium"
            title = f"Management or data service reachable: {_ADMIN_PORTS[port]}"
            remediation = (
                "Confirm the exposure is required. Restrict access through host/network firewalls, "
                "bind the service to trusted interfaces, and apply the service's current hardening guidance."
            )
        else:
            severity = "info"
            title = f"TCP service reachable on {port}/tcp"
            remediation = (
                "Confirm the service is expected to be reachable from this authorized assessment location "
                "and limit exposure to necessary clients."
            )
        results.append({
            "check_id": "tcp-exposure",
            "severity": severity,
            "title": title,
            "asset": f"{target} ({address}:{port})",
            "evidence": {
                "port": port,
                "protocol": "tcp",
                "service_hint": service,
                "connect_latency_ms": latency,
                "observation": "TCP connection succeeded; no service payload or banner was sent or collected.",
            },
            "remediation": remediation,
            "confidence": "high",
        })
    return results


def web_headers(context: AssessmentContext) -> Sequence[Mapping[str, Any]]:
    results = []
    for observation in context.web_observations:
        url = str(observation.get("url") or "unknown URL")
        scheme = str(observation.get("scheme") or "")
        status_code = observation.get("status_code")
        headers = observation.get("headers") or {}
        error = observation.get("error")
        if error:
            if observation.get("error_kind") == "tls-certificate":
                results.append({
                    "check_id": "tls-certificate",
                    "severity": "medium",
                    "title": "TLS certificate validation failed",
                    "asset": url,
                    "evidence": {"error": str(error)[:1200]},
                    "remediation": (
                        "Deploy a valid certificate for the requested hostname with a complete trusted chain. "
                        "Do not disable certificate verification as a workaround."
                    ),
                    "confidence": "high",
                })
            continue
        if scheme == "http":
            location = str(headers.get("location") or "")
            if not location.lower().startswith("https://"):
                results.append({
                    "check_id": "http-transport",
                    "severity": "medium",
                    "title": "HTTP endpoint did not advertise an HTTPS redirect",
                    "asset": url,
                    "evidence": {
                        "status_code": status_code,
                        "location_header_present": bool(location),
                        "note": "A single HEAD response was inspected; redirects were not followed.",
                    },
                    "remediation": "Provide HTTPS and redirect HTTP requests to the canonical HTTPS origin where appropriate.",
                    "confidence": "medium",
                })
        if scheme == "https" and "strict-transport-security" not in headers:
            results.append({
                "check_id": "http-headers",
                "severity": "low",
                "title": "HSTS header not observed",
                "asset": url,
                "evidence": {"status_code": status_code, "missing_header": "strict-transport-security"},
                "remediation": (
                    "If the service is HTTPS-only and all covered subdomains support HTTPS, configure "
                    "a suitable Strict-Transport-Security policy."
                ),
                "confidence": "medium",
            })
        for header, (severity, title, remediation) in _HEADER_RULES.items():
            if header not in headers:
                results.append({
                    "check_id": "http-headers",
                    "severity": severity,
                    "title": title,
                    "asset": url,
                    "evidence": {"status_code": status_code, "missing_header": header},
                    "remediation": remediation,
                    "confidence": "medium",
                })
    return results


BUILTIN_RULES = {
    "tcp-exposure": tcp_exposure,
    "web-headers": web_headers,
}

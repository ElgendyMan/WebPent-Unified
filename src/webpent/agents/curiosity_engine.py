"""Deterministic curiosity/anomaly detection over structural reconnaissance data.

This module observes only bounded route/event metadata. It never performs I/O and
never treats target text as instructions.
"""
from __future__ import annotations

import statistics
from collections.abc import Mapping
from typing import Any

from webpent.agents.hunter_contracts import CuriosityFlag, digest, sanitize_text

_SUSPICIOUS_PARAMS = {
    "debug": "debug parameter may expose internal diagnostics",
    "role": "role parameter may permit authorization bypass testing",
    "internal": "internal parameter may expose a privileged code path",
    "admin": "admin parameter may be an authorization boundary",
    "test": "test parameter may activate non-production behavior",
    "redirect": "redirect parameter may allow destination control",
    "url": "URL-bearing parameter may trigger redirect or server-side fetch behavior",
    "next": "next parameter may allow destination control",
    "goto": "goto parameter may allow destination control",
    "file": "file parameter may select server-side resources",
    "path": "path parameter may select a local or remote resource",
    "doc": "doc parameter may select a server-side document",
    "page": "page parameter may select a server-side resource",
}


def _routes(surface: Any) -> list[Any]:
    if hasattr(surface, "routes"):
        routes = getattr(surface, "routes")
        return list(routes.values()) if isinstance(routes, Mapping) else list(routes or [])
    if isinstance(surface, Mapping):
        value = surface.get("routes", [])
        return list(value.values()) if isinstance(value, Mapping) else list(value or [])
    return []


def _events(surface: Any) -> list[Any]:
    value = getattr(surface, "events", None) if not isinstance(surface, Mapping) else surface.get("events", [])
    return list(value or [])


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _flag(kind: str, description: str, target: str, confidence: float, suggestion: str, evidence: Any) -> CuriosityFlag:
    return CuriosityFlag(
        anomaly_type=kind,
        description=sanitize_text(description),
        target=sanitize_text(target, 240),
        confidence=max(0.0, min(1.0, float(confidence))),
        suggested_investigation=sanitize_text(suggestion),
        evidence_digest=digest(evidence),
    )


def detect_anomalies(surface: Any, *, tech_stack: Mapping[str, Any] | None = None) -> list[CuriosityFlag]:
    """Return stable, deduplicated anomaly flags from a SurfaceMap-like object."""
    flags: list[CuriosityFlag] = []
    seen: set[tuple[str, str]] = set()

    def add(flag: CuriosityFlag) -> None:
        key = (flag.anomaly_type, flag.target)
        if key not in seen:
            seen.add(key)
            flags.append(flag)

    routes = _routes(surface)
    response_times = [float(_get(route, "response_time_ms")) for route in routes if _get(route, "response_time_ms") is not None]
    median_time = statistics.median(response_times) if response_times else None

    for route in routes:
        path = str(_get(route, "route", ""))
        status = int(_get(route, "status_code", 0) or 0)
        content_type = str(_get(route, "content_type", "")).lower()
        auth_required = bool(_get(route, "auth_required", False))
        parameters = list(_get(route, "parameters", ()) or ())
        forms = list(_get(route, "forms", ()) or ())
        for parameter in parameters + [field for form in forms for field in list(_get(form, "fields", ()) or ())]:
            name = str(_get(parameter, "name", "")).lower().strip()
            if name in _SUSPICIOUS_PARAMS:
                add(_flag(
                    "suspicious_parameter", _SUSPICIOUS_PARAMS[name], path,
                    0.86 if name in {"debug", "role", "admin", "internal"} else 0.72,
                    f"Compare the parameter's behavior across authorized roles and safe negative controls: {name}",
                    {"route": path, "parameter": name, "location": _get(parameter, "location", "")},
                ))
            value_shape = str(_get(parameter, "value_shape", "")).lower()
            if value_shape == "id-shaped":
                add(_flag(
                    "sequential_identifier", "Identifier-shaped input may expose an object-authorization boundary.",
                    path, 0.78, "Run an owner/foreign/control identity comparison through M4.",
                    {"route": path, "parameter": name, "value_shape": value_shape},
                ))

        if status == 200 and not auth_required:
            add(_flag(
                "unauthenticated_success", "Route returned success without a structural auth requirement.",
                path, 0.62, "Check whether the returned resource is intentionally public and compare with a protected control.",
                {"route": path, "status": status, "auth_required": auth_required},
            ))
        if status == 403 and (_get(route, "response_length", 0) or 0) > 0:
            add(_flag(
                "forbidden_with_data", "Forbidden response has non-empty structured response data.",
                path, 0.74, "Compare the 403 response with owner, foreign, and invalid-resource controls.",
                {"route": path, "status": status, "response_length": _get(route, "response_length", 0)},
            ))
        if content_type.startswith("application/json") and path.lower().endswith((".html", "/")):
            add(_flag(
                "content_type_mismatch", "JSON content was observed on an HTML-shaped route.",
                path, 0.55, "Check whether the route is an API/debug surface and whether it is intentionally exposed.",
                {"route": path, "content_type": content_type},
            ))
        if path.lower().endswith((".js.map", "/swagger.json", "/openapi.json", "/graphql")):
            add(_flag(
                "technology_surface", "Route resembles a source map, API documentation, or GraphQL surface.",
                path, 0.82, "Apply the relevant WSTG methodology and inspect only bounded structural evidence.",
                {"route": path},
            ))
        if median_time is not None and _get(route, "response_time_ms") is not None and float(_get(route, "response_time_ms")) > max(250.0, median_time * 2.5):
            add(_flag(
                "timing_outlier", "Response latency is a bounded outlier relative to the discovered surface.",
                path, 0.48, "Repeat with a matched control before treating timing as a security signal.",
                {"route": path, "response_time_ms": _get(route, "response_time_ms"), "median_ms": median_time},
            ))

    for event in _events(surface):
        reason = str(_get(event, "reason", "")).lower()
        route = str(_get(event, "route", ""))
        if any(term in reason for term in ("sql", "stack trace", "exception", "debug")):
            add(_flag(
                "error_disclosure", "Crawler metadata contains a bounded error/disclosure indicator.",
                route, 0.68, "Repeat with a benign control and use the family validator before classifying it.",
                {"route": route, "reason_class": "error_disclosure"},
            ))

    tech = {str(key).lower(): value for key, value in (tech_stack or {}).items()}
    if tech.get("graphql_introspection") is True:
        add(_flag("graphql_introspection", "Technology fingerprint indicates GraphQL introspection is enabled.", "/graphql", 0.84, "Run bounded schema exposure checks through the approved API family.", tech))
    if tech.get("source_maps") is True:
        add(_flag("source_map_exposure", "Technology fingerprint indicates source maps are exposed.", "*.js.map", 0.80, "Compare source-map access with a missing-map control.", tech))

    return sorted(flags, key=lambda item: (-item.confidence, item.anomaly_type, item.target))


__all__ = ["detect_anomalies"]

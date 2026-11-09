"""Bounded, scope-gated static JavaScript intelligence.

The module deliberately never returns JavaScript source or raw secret values. It
produces typed observations that are suitable for evidence-first triage; a
candidate is not a finding until a separate safe validator proves impact.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from webpent.models.javascript_intelligence import (
    JavaScriptAsset,
    JavaScriptAuthHint,
    JavaScriptIntelligence,
    JavaScriptRoute,
    JavaScriptSecretCandidate,
    JavaScriptSink,
    JavaScriptTargetedTask,
)

_MAX_SOURCE_BYTES = 2_000_000
_MAX_ROUTES = 1_000
_MAX_SINKS = 1_000
_MAX_SECRETS = 500
_MAX_HINTS = 500
_MAX_TASKS = 1_500
_SENSITIVE_QUERY_KEYS = re.compile(
    r"(?:token|secret|password|passwd|api[_-]?key|authorization|session|cookie|jwt|signature|code)",
    re.IGNORECASE,
)

_FETCH_RE = re.compile(
    r"\bfetch\s*\(\s*[\"'`]([^\"'`\n]{1,1200})[\"'`]",
    re.IGNORECASE,
)
_AXIOS_RE = re.compile(
    r"\baxios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*[\"'`]([^\"'`\n]{1,1200})[\"'`]",
    re.IGNORECASE,
)
_XHR_RE = re.compile(
    r"\.open\s*\(\s*[\"'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']\s*,\s*[\"'`]([^\"'`\n]{1,1200})[\"'`]",
    re.IGNORECASE,
)
_HTTP_CLIENT_RE = re.compile(
    r"\b(?:this\.)?http\s*\.\s*(get|post|put|patch|delete|head|options)"
    r"\s*\(\s*[^\"'`\n]{0,160}[\"'`]([^\"'`\n]{1,1200})[\"'`]",
    re.IGNORECASE,
)
_ROUTE_LITERAL_RE = re.compile(
    r"[\"'`]((?:/)(?:api|graphql|gql|v[0-9]+|auth|admin|internal|private)(?:/[^\"'`\s]{0,300})?)[\"'`]",
    re.IGNORECASE,
)
_SOURCE_MAP_RE = re.compile(r"(?:#|@)\s*sourceMappingURL\s*=\s*([^\s]+)", re.IGNORECASE)

_SINK_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("dom_xss", "innerHTML", re.compile(r"\b(?:innerHTML|outerHTML)\b")),
    ("html_injection", "insertAdjacentHTML", re.compile(r"\binsertAdjacentHTML\s*\(")),
    ("html_injection", "document.write", re.compile(r"\bdocument\.write(?:ln)?\s*\(")),
    ("code_execution", "eval", re.compile(r"\beval\s*\(")),
    ("code_execution", "Function", re.compile(r"\bnew\s+Function\s*\(")),
    ("code_execution", "setTimeout(string)", re.compile(r"\bsetTimeout\s*\(\s*[\"']")),
    ("navigation", "location.assign", re.compile(r"\blocation\s*\.\s*(?:assign|replace|href)\b")),
    ("message_handling", "postMessage", re.compile(r"\bpostMessage\s*\(")),
)
_SECRET_PATTERNS: tuple[str, re.Pattern[str]] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "assignment_secret",
        re.compile(
            r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|password|passwd|private[_-]?key)\b"
            r"\s*[:=]\s*[\"']([^\"'\n]{8,300})[\"']",
            re.IGNORECASE,
        ),
    ),
)
_AUTH_HINT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "role_check",
        re.compile(r"\b(?:isAdmin|is_admin|adminOnly|role|roles|permissions?)\b", re.IGNORECASE),
    ),
    (
        "auth_header",
        re.compile(r"\b(?:authorization|bearer|accessToken|idToken|jwt)\b", re.IGNORECASE),
    ),
    ("csrf_hint", re.compile(r"\b(?:csrf|xsrf|antiForgery|anti-forgery)\b", re.IGNORECASE)),
)


def _sha256(value: str | bytes) -> str:
    data = value if isinstance(value, bytes) else value.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _same_origin(url: str, target_url: str) -> bool:
    parsed = urlparse(url)
    target = urlparse(target_url)
    return (
        parsed.scheme in {"http", "https"}
        and target.scheme in {"http", "https"}
        and parsed.hostname is not None
        and parsed.hostname.lower() == (target.hostname or "").lower()
        and (parsed.port or (443 if parsed.scheme == "https" else 80))
        == (target.port or (443 if target.scheme == "https" else 80))
    )


def _redacted_url(url: str, target_url: str) -> str | None:
    """Resolve a candidate route and reject cross-origin or dangerous schemes."""
    raw = url.strip()
    if not raw or raw.startswith(("javascript:", "data:", "blob:", "mailto:")):
        return None
    resolved = urljoin(target_url.rstrip("/") + "/", raw)
    if not _same_origin(resolved, target_url):
        return None
    parsed = urlparse(resolved)
    query: list[tuple[str, str]] = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        query.append((key, "[REDACTED]") if _SENSITIVE_QUERY_KEYS.search(key) else (key, value))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(query), ""))


def _evidence_ref(kind: str, source_asset: str, locator: str) -> str:
    return f"js://{kind}/{_sha256(source_asset + chr(0) + locator)[:32]}"


def _task_id(task_type: str, target_ref: str, source_asset: str) -> str:
    return _sha256("\0".join((task_type, target_ref, source_asset)))[:32]


def _source_map_info(
    source: str, asset_url: str, target_url: str, source_map_content: str | None
) -> tuple[str | None, list[str]]:
    match = _SOURCE_MAP_RE.search(source)
    if not match:
        return None, []
    raw_url = match.group(1).strip().strip("\"'")
    map_url = None if raw_url.startswith("data:") else _redacted_url(raw_url, asset_url)
    if map_url is not None and not _same_origin(map_url, target_url):
        map_url = None
    sources: list[str] = []
    if (
        source_map_content
        and len(source_map_content.encode("utf-8", "replace")) <= _MAX_SOURCE_BYTES
    ):
        try:
            parsed = json.loads(source_map_content)
            raw_sources = parsed.get("sources", []) if isinstance(parsed, dict) else []
            if isinstance(raw_sources, list):
                for item in raw_sources[:200]:
                    if isinstance(item, str):
                        resolved = _redacted_url(item, asset_url)
                        if resolved and _same_origin(resolved, target_url):
                            sources.append(resolved)
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
            # Intentionally suppressed — reviewed 2026-09-03
    return map_url, list(dict.fromkeys(sources))


def analyze_javascript_source(
    *,
    asset_url: str,
    source: str,
    target_url: str,
    content_type: str = "application/javascript",
    status_code: int = 200,
    source_map_content: str | None = None,
    max_bytes: int = _MAX_SOURCE_BYTES,
) -> JavaScriptIntelligence:
    """Analyze one in-scope JavaScript asset without retaining source content."""
    if not _same_origin(asset_url, target_url):
        return JavaScriptIntelligence(coverage_gaps=["js_asset_out_of_scope"])
    encoded = source.encode("utf-8", "replace")
    if len(encoded) > max_bytes or len(encoded) > _MAX_SOURCE_BYTES:
        digest = _sha256(encoded)
        asset = JavaScriptAsset(
            asset_url=asset_url,
            content_type=content_type,
            status_code=status_code,
            size_bytes=len(encoded),
            content_sha256=digest,
            in_scope=True,
            redacted=True,
        )
        return JavaScriptIntelligence(assets=[asset], coverage_gaps=["js_asset_size_limit"])

    digest = _sha256(encoded)
    source_map_url, source_map_sources = _source_map_info(
        source, asset_url, target_url, source_map_content
    )
    asset = JavaScriptAsset(
        asset_url=asset_url,
        content_type=content_type,
        status_code=status_code,
        size_bytes=len(encoded),
        content_sha256=digest,
        source_map_url=source_map_url,
        source_map_sources=source_map_sources,
        in_scope=True,
        redacted=True,
    )

    routes: list[JavaScriptRoute] = []
    route_keys: set[tuple[str, str]] = set()
    route_gaps: list[str] = []

    def add_route(raw_route: str, method: str, kind: str, offset: int) -> None:
        if len(routes) >= _MAX_ROUTES:
            return
        route = _redacted_url(raw_route, target_url)
        if not route:
            parsed_raw = urlparse(urljoin(target_url.rstrip("/") + "/", raw_route.strip()))
            if parsed_raw.scheme in {"http", "https"} and not _same_origin(
                parsed_raw.geturl(), target_url
            ):
                route_gaps.append("js_route_out_of_scope")
            else:
                route_gaps.append("js_route_rejected")
            return
        key = (route, method.upper())
        if key in route_keys:
            return
        route_keys.add(key)
        routes.append(
            JavaScriptRoute(
                route=route,
                source_asset=asset_url,
                method_hint=method.upper(),
                discovery_kind=kind,  # type: ignore[arg-type]
                line=_line_number(source, offset),
                in_scope=True,
                evidence_ref=_evidence_ref("route", asset_url, f"{kind}:{offset}:{route}"),
            )
        )

    for match in _FETCH_RE.finditer(source):
        add_route(match.group(1), "GET", "fetch", match.start())
    for match in _AXIOS_RE.finditer(source):
        add_route(match.group(2), match.group(1), "axios", match.start())
    for match in _XHR_RE.finditer(source):
        add_route(match.group(2), match.group(1), "xhr", match.start())
    for match in _HTTP_CLIENT_RE.finditer(source):
        add_route(match.group(2), match.group(1), "http_client", match.start())
    for match in _ROUTE_LITERAL_RE.finditer(source):
        kind = (
            "graphql"
            if match.group(1).lower().split("/", 2)[1] in {"graphql", "gql"}
            else "route_literal"
        )
        add_route(match.group(1), "UNKNOWN", kind, match.start())  # type: ignore[arg-type]
    if source_map_url:
        for item in source_map_sources:
            add_route(item, "UNKNOWN", "source_map", source.find(item) if item in source else 0)  # type: ignore[arg-type]

    sinks: list[JavaScriptSink] = []
    sink_keys: set[tuple[str, int]] = set()
    for category, sink_name, pattern in _SINK_PATTERNS:
        for match in pattern.finditer(source):
            line = _line_number(source, match.start())
            key = (sink_name, line)
            if key in sink_keys or len(sinks) >= _MAX_SINKS:
                continue
            sink_keys.add(key)
            snippet = source[max(0, match.start() - 80) : min(len(source), match.end() + 80)]
            sinks.append(
                JavaScriptSink(
                    category=category,  # type: ignore[arg-type]
                    sink=sink_name,
                    source_asset=asset_url,
                    line=line,
                    snippet_sha256=_sha256(snippet),
                    evidence_ref=_evidence_ref("sink", asset_url, f"{sink_name}:{line}"),
                )
            )

    secret_candidates: list[JavaScriptSecretCandidate] = []
    secret_keys: set[tuple[str, int, str]] = set()
    for kind, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(source):
            raw_value = match.group(1) if match.lastindex else match.group(0)
            line = _line_number(source, match.start())
            key = (kind, line, _sha256(raw_value))
            if key in secret_keys or len(secret_candidates) >= _MAX_SECRETS:
                continue
            secret_keys.add(key)
            secret_candidates.append(
                JavaScriptSecretCandidate(
                    kind=kind,
                    source_asset=asset_url,
                    line=line,
                    value_sha256=_sha256(raw_value),
                    confidence="medium" if kind in {"aws_access_key", "private_key"} else "low",
                    validation_status="advisory",
                    evidence_ref=_evidence_ref(
                        "secret", asset_url, f"{kind}:{line}:{_sha256(raw_value)}"
                    ),
                )
            )

    auth_hints: list[JavaScriptAuthHint] = []
    hint_keys: set[tuple[str, str, int]] = set()
    for hint, pattern in _AUTH_HINT_PATTERNS:
        for match in pattern.finditer(source):
            identifier = match.group(0)[:120]
            line = _line_number(source, match.start())
            key = (hint, identifier.lower(), line)
            if key in hint_keys or len(auth_hints) >= _MAX_HINTS:
                continue
            hint_keys.add(key)
            auth_hints.append(
                JavaScriptAuthHint(
                    hint=hint,
                    identifier=identifier,
                    source_asset=asset_url,
                    line=line,
                    evidence_ref=_evidence_ref("auth", asset_url, f"{hint}:{identifier}:{line}"),
                )
            )

    tasks: list[JavaScriptTargetedTask] = []
    task_keys: set[str] = set()

    def add_task(task_type: str, target_ref: str, reason: str) -> None:
        if len(tasks) >= _MAX_TASKS:
            return
        task_id = _task_id(task_type, target_ref, asset_url)
        if task_id in task_keys:
            return
        task_keys.add(task_id)
        tasks.append(
            JavaScriptTargetedTask(
                task_id=task_id,
                task_type=task_type,  # type: ignore[arg-type]
                target_ref=target_ref,
                source_asset=asset_url,
                reason=reason,
                in_scope=True,
                destructive=False,
            )
        )

    for route in routes:
        add_task(
            "js_route_mapping",
            route.route,
            f"JS-discovered {route.method_hint} route requires targeted mapping",
        )
    if auth_hints:
        add_task(
            "js_auth_review",
            asset_url,
            "client-side authorization or authentication hint requires bounded review",
        )
    if source_map_url or source_map_sources:
        add_task(
            "js_source_map_review",
            source_map_url or asset_url,
            "same-origin source map requires targeted source review",
        )

    gaps: list[str] = list(route_gaps)
    if not routes:
        gaps.append("no_in_scope_js_routes_observed")
    if source_map_url and not source_map_content:
        gaps.append("source_map_discovered_not_fetched")
    if secret_candidates:
        gaps.append("secret_candidates_require_safe_validation")
    if sinks:
        gaps.append("client_side_sinks_require_dataflow_validation")

    return JavaScriptIntelligence(
        assets=[asset],
        routes=routes,
        sinks=sinks,
        secret_candidates=secret_candidates,
        auth_hints=auth_hints,
        targeted_tasks=tasks,
        coverage_gaps=list(dict.fromkeys(gaps)),
    )


def merge_javascript_intelligence(items: list[JavaScriptIntelligence]) -> JavaScriptIntelligence:
    """Merge per-asset results deterministically and deduplicate observations/tasks."""
    if not items:
        return JavaScriptIntelligence()
    payload: dict[str, Any] = {
        "assets": [],
        "routes": [],
        "sinks": [],
        "secret_candidates": [],
        "auth_hints": [],
        "targeted_tasks": [],
        "coverage_gaps": [],
    }
    seen: dict[str, set[str]] = {key: set() for key in payload}
    for item in items:
        for key in payload:
            values = getattr(item, key)
            for value in values:
                data = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
                fingerprint = _sha256(json.dumps(data, sort_keys=True, separators=(",", ":")))
                if fingerprint not in seen[key]:
                    seen[key].add(fingerprint)
                    payload[key].append(value)
    return JavaScriptIntelligence(**payload)


__all__ = ["analyze_javascript_source", "merge_javascript_intelligence"]

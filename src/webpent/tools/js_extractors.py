# src/webpent/tools/js_extractors.py
"""Deterministic JS/SPA surface extractors (2026-10-25 Proposal 4).

Pure, regex-only, no code execution and no network I/O: every function
takes JS source text and returns bounded, deduplicated findings. The
``js_discovery`` node (``agents/js_discovery/agent.py``) fetches the
bundles and feeds them here; keeping the extraction pure makes it
unit-testable against synthetic bundles and safe against hostile JS —
a malformed or adversarial bundle can at worst produce no matches.

Redaction discipline: secret-like matches are NEVER returned verbatim.
Every secret hint carries a classified label plus a bounded preview of
at most 6 leading characters and its length — enough for an operator
to locate the string in the bundle, never enough to be the secret.

Bounds: every extractor caps its output (``_MAX_PER_KIND``); the node
caps again at a lower total. Deterministic ordering: matches are
emitted in first-appearance order (no sorting jitter for the tests).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "DiscoveredSurface",
    "MAX_SURFACES_PER_KIND",
    "extract_spa_routes",
    "extract_graphql_operations",
    "extract_api_endpoints",
    "extract_secret_hints",
    "discover_surfaces",
]

# Bounded output per extractor call. The node applies its own, usually
# tighter, budget on top of this.
MAX_SURFACES_PER_KIND = 50

_SECRET_PREVIEW_CHARS = 6
_MAX_MATCH_LENGTH = 200

# SPA route declarations (react-router / vue-router style):
#   path: "/dashboard"   route: "/settings/profile"
_SPA_ROUTE_RE = re.compile(
    r"""\b(?:path|route)\s*:\s*["'](/[^"']{1,%d})["']""" % _MAX_MATCH_LENGTH
)

# Hash-based SPA routes embedded as literals:  "#/orders/42"
_HASH_ROUTE_RE = re.compile(r"""["'](#/[^"']{1,%d})["']""" % (_MAX_MATCH_LENGTH - 1))

# fetch/axios style calls:
#   fetch("/api/orders")      axios.get("/api/user")
#   axios({ url: "/api/x" })  url: "/api/health"
_FETCH_CALL_RE = re.compile(
    r"""\b(?:fetch|axios(?:\.[A-Za-z]+)?)\s*\(\s*["'`]([^"'`\s]{2,%d})["'`]"""
    % _MAX_MATCH_LENGTH
)
_URL_FIELD_RE = re.compile(
    r"""\burl\s*:\s*["']([^"'\s]{2,%d})["']""" % _MAX_MATCH_LENGTH
)

# Bare API path literals, e.g. "/api/v2/orders" or "/graphql".
_API_PATH_RE = re.compile(r'"/(api|graphql|v[0-9]+(?:/[a-zA-Z0-9_\-]+)+)"')

# GraphQL operation declarations in bundles:  query GetOrders($id: ID!) {
_GRAPHQL_OP_RE = re.compile(
    r"""\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)?"""
    r"""(\s*\(\s*\$[A-Za-z0-9_]+\s*:\s*[^)]{1,120}\))?[\s\S]{0,4}\{"""
)
_GRAPHQL_ARG_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^,)!\s]+)")

# Secret heuristics. Labels are classification hints only; values are
# redacted by the extractor before anything leaves this module.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
_KEY_VALUE_RE = re.compile(
    r"""\b(api[_-]?key|apikey|client[_-]?secret|secret|access[_-]?token|"""
    r"""private[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{16,})["']""",
    re.IGNORECASE,
)
_AWS_KEY_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


@dataclass(frozen=True)
class DiscoveredSurface:
    """One bounded extraction result from a JS bundle.

    ``kind`` is one of: ``spa_route`` | ``graphql_operation`` |
    ``api_endpoint`` | ``secret_hint``. ``value`` is the path, operation
    name or (for secrets) a REDACTED preview. ``detail`` carries the
    extractor's classification hint (HTTP-verb hint for endpoints,
    argument list for GraphQL operations, label for secrets).
    """

    kind: str
    value: str
    detail: str = ""
    source_url: str = ""


def _dedup_bounded(values: list[str], limit: int = MAX_SURFACES_PER_KIND) -> list[str]:
    """First-appearance dedup, order-preserving, bounded."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def _redact_secret(value: str) -> str:
    """Bounded preview: first few chars + length, never the full value."""
    head = value[:_SECRET_PREVIEW_CHARS]
    return f"{head}...(len={len(value)})"


def extract_spa_routes(js_text: str) -> list[str]:
    """Route declarations and hash routes, deduplicated and bounded."""
    if not js_text:
        return []
    routes = [m.group(1) for m in _SPA_ROUTE_RE.finditer(js_text)]
    routes += [m.group(1) for m in _HASH_ROUTE_RE.finditer(js_text)]
    return _dedup_bounded(routes)


def extract_graphql_operations(js_text: str) -> list[dict]:
    """GraphQL operation declarations in the bundle.

    Returns records shaped like the crawler's ``graphql_operations``
    entries (``{name, args: [{name, type}], source}``) so they merge
    directly into ``crawled_data["graphql_operations"]`` and feed the
    GraphQL prober's evidence gate. Declarations without a name are
    skipped (anonymous fragments are not probeable evidence).
    """
    if not js_text:
        return []
    ops: list[dict] = []
    seen: set[str] = set()
    for match in _GRAPHQL_OP_RE.finditer(js_text):
        name = match.group(2)
        if not name or name in seen:
            continue
        seen.add(name)
        args = [
            {"name": arg_name, "type": arg_type}
            for arg_name, arg_type in _GRAPHQL_ARG_RE.findall(match.group(3) or "")
        ]
        ops.append({"name": name, "args": args, "source": "js_bundle"})
        if len(ops) >= MAX_SURFACES_PER_KIND:
            break
    return ops


def extract_api_endpoints(js_text: str) -> list[str]:
    """Endpoint strings from fetch/axios calls, url fields and bare
    API path literals. Relative paths are returned as-is (resolution
    against the bundle's origin is the node's job)."""
    if not js_text:
        return []
    endpoints = [m.group(1) for m in _FETCH_CALL_RE.finditer(js_text)]
    endpoints += [m.group(1) for m in _URL_FIELD_RE.finditer(js_text)]
    endpoints += [m.group(0).strip('"') for m in _API_PATH_RE.finditer(js_text)]
    return _dedup_bounded(endpoints)


def extract_secret_hints(js_text: str) -> list[dict]:
    """Heuristically classified secret hints, REDACTED at the source.

    Returns records ``{kind, preview, source}`` where ``kind`` is one
    of ``jwt_on_client`` | ``hardcoded_key_pattern`` | ``aws_key`` |
    ``private_key_block`` and ``preview`` is a bounded redaction (see
    ``_redact_secret``). These are classification hints for operator
    review — never verbatim secrets, never auto-claimed findings.
    """
    if not js_text:
        return []
    hints: list[dict] = []
    seen: set[str] = set()

    def _add(kind: str, preview: str) -> None:
        if preview in seen:
            return
        seen.add(preview)
        hints.append({"kind": kind, "preview": preview, "source": "js_bundle"})

    for match in _JWT_RE.finditer(js_text):
        _add("jwt_on_client", _redact_secret(match.group(0)))
        if len(hints) >= MAX_SURFACES_PER_KIND:
            return hints
    for match in _AWS_KEY_RE.finditer(js_text):
        _add("aws_key", _redact_secret(match.group(1)))
        if len(hints) >= MAX_SURFACES_PER_KIND:
            return hints
    for match in _KEY_VALUE_RE.finditer(js_text):
        _add("hardcoded_key_pattern", _redact_secret(match.group(2)))
        if len(hints) >= MAX_SURFACES_PER_KIND:
            return hints
    if _PRIVATE_KEY_RE.search(js_text):
        _add("private_key_block", _redact_secret("-----BEGIN PRIVATE KEY"))
    return hints


def discover_surfaces(js_text: str, *, source_url: str = "") -> list[DiscoveredSurface]:
    """Run every extractor over one bundle and return the composed,
    bounded surface list (deterministic order: routes, GraphQL,
    endpoints, secrets)."""
    surfaces: list[DiscoveredSurface] = []
    for route in extract_spa_routes(js_text):
        surfaces.append(
            DiscoveredSurface("spa_route", route, source_url=source_url)
        )
    for op in extract_graphql_operations(js_text):
        detail = ",".join(f"${a['name']}:{a['type']}" for a in op.get("args", []))
        surfaces.append(
            DiscoveredSurface(
                "graphql_operation", str(op.get("name") or ""), detail, source_url
            )
        )
    for endpoint in extract_api_endpoints(js_text):
        surfaces.append(
            DiscoveredSurface("api_endpoint", endpoint, source_url=source_url)
        )
    for hint in extract_secret_hints(js_text):
        surfaces.append(
            DiscoveredSurface(
                "secret_hint", hint["preview"], hint["kind"], source_url
            )
        )
    return surfaces

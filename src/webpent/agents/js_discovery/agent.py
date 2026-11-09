# src/webpent/agents/js_discovery/agent.py
"""JS/SPA surface-discovery node (2026-10-25 Proposal 4).

Most of the modern attack surface hides in JS bundles: SPA routes,
embedded GraphQL operations, hardcoded API endpoints and client-side
secrets. HTML crawling alone loses that half of the map. This node
re-fetches the JS bundles the crawl ALREADY saw (same origins only,
through the SSRF-guarded client) and runs the deterministic,
regex-only extractors in ``webpent.tools.js_extractors`` — no code
execution, no AST dependency, no guessing beyond literal patterns.

Hard bounds:

  * ``_MAX_FILES = 20`` bundles per node run, ``_MAX_FILE_BYTES = 5MB``
    per bundle, ``_MAX_TOTAL_PROBES = 20`` HTTP requests total;
  * extraction output is bounded per kind (``MAX_SURFACES_PER_KIND``)
    and again at the node level (``_MAX_TOTAL_SURFACES``);
  * per-request timeout 8s via ``make_safe_httpx_client`` plus a
    node-local ``RequestRateGovernor`` for pacing.

Gating (zero side effects by construction):

  * flag ``enable_js_discovery`` (default False) — off means the node
    returns the state untouched without constructing a client;
  * no JS URLs in ``crawled_data`` means a no-op even with the flag on.

Integration: discovered endpoints and SPA routes merge into
``crawled_data`` (deduplicated first-appearance order), discovered
GraphQL operations merge into ``crawled_data["graphql_operations"]``
so the GraphQL prober's evidence gate picks them up in the same run,
and a bounded summary lands in ``target_knowledge["js_surface"]``.
Secret hints are recorded as CLASSIFIED HINTS ONLY (redacted previews
from the extractor) — they are deliberately NOT emitted as findings:
an unvalidated secret claim would be a false-positive factory, and
the fail-closed discipline requires a canonical validator before any
finding is claimed.
"""
from __future__ import annotations

from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from langchain_core.messages import AIMessage

from webpent.state.state import PentestState
from webpent.config.settings import get_settings
from webpent.shared.http import make_safe_httpx_client
from webpent.shared.rate_governor import RequestRateGovernor
from webpent.tools.js_extractors import discover_surfaces

logger = __import__("logging").getLogger(__name__)

NODE_NAME = "js_discovery"

_MAX_FILES = 20
_MAX_FILE_BYTES = 5 * 1024 * 1024
_MAX_TOTAL_PROBES = 20
_REQUEST_TIMEOUT_S = 8
_MAX_TOTAL_SURFACES = 200
_MAX_MERGED_GRAPHQL_OPS = 50  # aligns with schema_ingestion.MAX_GRAPHQL_OPERATIONS

# ``crawled_data`` keys scanned for JS URLs (mirrors the keys the
# javascript_intelligence node reads).
_JS_URL_KEYS = ("javascript_urls", "js_urls", "urls", "endpoints", "links", "resources")

_FETCHER = Callable[..., Any]


def _probe_budget() -> list[int]:
    return [_MAX_TOTAL_PROBES]


def _fail_soft(step: str, exc: Exception) -> None:
    logger.warning("JS discovery %s failed (skipped): %s", step, exc)


def _is_js_url(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(".js") or path.endswith(".mjs")


def _collect_js_urls(crawled: dict[str, Any], base_url: str) -> list[str]:
    """Same-origin JS bundle URLs from the crawl, deduplicated, bounded."""
    base_origin = urlsplit(base_url)
    origin = (base_origin.scheme, base_origin.netloc) if base_url else ("", "")
    seen: set[str] = set()
    out: list[str] = []
    for key in _JS_URL_KEYS:
        values = crawled.get(key)
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, str) or not value.strip():
                continue
            url = value.strip()
            if not url.startswith("http"):
                if not base_url:
                    continue
                url = urljoin(base_url, url)
            if not _is_js_url(url):
                continue
            parts = urlsplit(url)
            if origin != ("", "") and (parts.scheme, parts.netloc) != origin:
                continue
            if url in seen:
                continue
            seen.add(url)
            out.append(url)
            if len(out) >= _MAX_FILES:
                return out
    return out


def _fetch_bundle(
    client: Any, url: str, budget: list[int], governor: RequestRateGovernor
) -> str | None:
    """One bounded bundle fetch. Returns text or None (fail-soft)."""
    if budget[0] <= 0:
        logger.info("JS discovery: request budget exhausted")
        return None
    budget[0] -= 1
    try:
        with governor.acquire(urlsplit(url).netloc):
            response = client.get(url)
        if response.status_code != 200:
            return None
        # Content-Length can lie or be absent; the hard cap is on the
        # bytes we actually keep.
        return response.text[:_MAX_FILE_BYTES]
    except Exception as exc:  # noqa: BLE001 — per-bundle fail-soft
        _fail_soft(f"fetch {url}", exc)
        return None


def js_discovery_node(
    state: PentestState, *, fetcher: Any = None
) -> dict[str, Any]:
    """Flag-gated JS surface discovery. Never raises; off = untouched."""
    if not get_settings().enable_js_discovery:
        return {}

    crawled: dict[str, Any] = dict(state.get("crawled_data") or {})
    target = state.get("target")
    base_url = str(getattr(target, "url", "") or "")
    if isinstance(target, dict):
        base_url = str(target.get("url") or base_url)
    try:
        js_urls = _collect_js_urls(crawled, base_url)
    except Exception as exc:  # noqa: BLE001 — fail-soft
        _fail_soft("url collection", exc)
        js_urls = []
    if not js_urls:
        return {}

    surfaces_by_url: dict[str, list[Any]] = {}
    try:
        budget = _probe_budget()
        governor = RequestRateGovernor()
        if fetcher is not None:
            for url in js_urls:
                text = fetcher(url)
                if text:
                    surfaces_by_url[url] = discover_surfaces(
                        text[:_MAX_FILE_BYTES], source_url=url
                    )
        else:
            with make_safe_httpx_client(
                timeout=_REQUEST_TIMEOUT_S, follow_redirects=False
            ) as client:
                for url in js_urls:
                    text = _fetch_bundle(client, url, budget, governor)
                    if text:
                        surfaces_by_url[url] = discover_surfaces(text, source_url=url)
    except Exception as exc:  # noqa: BLE001 — probe session, fail-soft
        _fail_soft("bundle session", exc)
        return {}

    # Flatten + node-level bound (first-appearance order across bundles).
    all_surfaces: list[Any] = []
    for url in js_urls:
        all_surfaces.extend(surfaces_by_url.get(url, ()))
        if len(all_surfaces) >= _MAX_TOTAL_SURFACES:
            break
    all_surfaces = all_surfaces[:_MAX_TOTAL_SURFACES]

    # Integration 1 — endpoints and SPA routes into crawled_data.
    existing_endpoints = set()
    for value in crawled.get("js_discovered_endpoints") or []:
        existing_endpoints.add(str(value))
    new_endpoints: list[str] = []
    seen_routes: set[str] = set()
    for surface in all_surfaces:
        if surface.kind == "api_endpoint" and surface.value not in existing_endpoints:
            existing_endpoints.add(surface.value)
            new_endpoints.append(surface.value)
        elif surface.kind == "spa_route" and surface.value not in seen_routes:
            seen_routes.add(surface.value)
            new_endpoints.append(surface.value)

    # Integration 2 — GraphQL operations merge (dedup by name, bounded).
    existing_ops = crawled.get("graphql_operations")
    existing_names: set[str] = set()
    if isinstance(existing_ops, list):
        for op in existing_ops:
            if isinstance(op, dict) and op.get("name"):
                existing_names.add(str(op["name"]))
    new_ops: list[dict[str, Any]] = []
    for surface in all_surfaces:
        if (
            surface.kind == "graphql_operation"
            and surface.value
            and surface.value not in existing_names
        ):
            existing_names.add(surface.value)
            args = [
                {"name": part.lstrip("$").split(":", 1)[0], "type": part.split(":", 1)[-1]}
                for part in surface.detail.split(",") if part
            ]
            new_ops.append(
                {"name": surface.value, "args": args, "source": "js_bundle"}
            )
            if len(new_ops) >= _MAX_MERGED_GRAPHQL_OPS:
                break

    # Integration 3 — bounded summary into target_knowledge.
    secret_hints = [
        {"kind": s.detail, "preview": s.value, "source": s.source_url}
        for s in all_surfaces
        if s.kind == "secret_hint"
    ][:_MAX_TOTAL_SURFACES]
    js_summary: dict[str, Any] = {
        "bundles_analyzed": len(surfaces_by_url),
        "spa_routes": sorted(seen_routes)[:_MAX_TOTAL_SURFACES],
        "endpoints": new_endpoints[:_MAX_TOTAL_SURFACES],
        "graphql_operations": [op["name"] for op in new_ops],
        "secret_hints": secret_hints,
    }

    crawled_update: dict[str, Any] = {
        "js_discovered_endpoints": new_endpoints,
    }
    if new_ops:
        # merge_dicts appends lists: this EXTENDS the crawler's ops.
        crawled_update["graphql_operations"] = new_ops
    update: dict[str, Any] = {
        "messages": [
            AIMessage(
                content=(
                    f"JS discovery: analyzed {len(surfaces_by_url)} bundle(s); "
                    f"{len(new_endpoints)} new endpoint(s)/route(s), "
                    f"{len(new_ops)} new GraphQL operation(s), "
                    f"{len(secret_hints)} secret hint(s)."
                )
            )
        ],
        "current_phase": NODE_NAME,
        "crawled_data": crawled_update,
        "target_knowledge": {"js_surface": js_summary},
    }
    return update


__all__ = ["js_discovery_node", "NODE_NAME"]

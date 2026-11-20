"""webpent.shared.family_feeds — M3 UM-DR-17: the tenant_isolation
qualification seam's data feed.

Registry contract (CANONICAL_PHASE_REGISTRY M3 remaining scope; M1b
residual ② disposition):

    "the tenant_isolation qualification seam (frozen-builder node
    contract)"

M0's CAPABILITY_WIRING_MAP row said it exactly:

    families/execution_node — ``wire_family_execution()`` بلا مستدعٍ من
    builder (no caller from the builder); tenant_isolation/multi_step_auth
    — عقد موجودة لكنها أغلفة سلبية تنتظر بيانات لا يوفرها أحد
    (passive wrappers waiting for data nobody provides).

This module closes the DATA half of that seam (the GRAPH half — wiring
``wire_family_execution`` into the frozen builder behind a flag — lands
with the builder edit in the same window): it derives the family
analyzers' input vocabulary (``endpoint_inventory`` /
``multi_tenant`` / ``auth_flows``) from the REAL PentestState channels
the production graph already populates:

* ``crawled_data`` — ``openapi_routes``, ``surface_records``, ``forms``,
  ``endpoints``/``links`` (URL strings), and the ق8 ``shadow_endpoints``
  projection (JS-only endpoints — exactly where a tenant boundary hides);
* ``identity_profiles`` — roles and their login-flow step names (the
  ``multi_step_auth`` analyzer's vocabulary; secrets never leave the
  vault, only step names and roles);
* ``target`` — explicit multi-tenancy declarations.

Everything is conservative and provenance-honest: an endpoint with no
observed method is GET-by-construction of the crawler's own fallback;
``multi_tenant`` is True only when explicitly declared (never inferred
from heuristics that could fabricate a tenant boundary); auth flows are
only built from step lists that actually exist.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

_MAX_INVENTORY = 2_000
_MAX_FLOWS = 64
_KNOWN_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


def _as_method(value: Any) -> str:
    method = str(value or "GET").upper()
    return method if method in _KNOWN_METHODS else "GET"


def _path_from_url(url: str) -> str:
    try:
        parts = urlsplit(str(url))
    except ValueError:
        return "/"
    return parts.path or "/"


def _inventory_entry(
    *,
    method: str,
    path: str,
    params: list[str] | None = None,
    source: str,
) -> dict[str, Any]:
    return {
        "method": _as_method(method),
        "path": str(path or "/")[:500],
        "params": [str(p)[:120] for p in (params or [])][:40],
        "headers": {},
        "auth_required": False,  # unknown at feed time — never fabricated
        "stateful": _as_method(method) in {"POST", "PUT", "PATCH", "DELETE"},
        "rate_limited": False,
        "idempotent": _as_method(method) in {"GET", "HEAD", "OPTIONS"},
        "object_reference": False,  # analyzers re-derive from path segments
        "hostname_routed": False,
        "roles": [],
        "provenance": f"family_feeds:{source}",
    }


def _normalize_entry(entry: Any, *, source: str) -> dict[str, Any] | None:
    """Accept the family vocabulary's own dict shape (surface_adapter rows
    and pre-existing inventories) unchanged."""
    if not isinstance(entry, dict):
        return None
    method = entry.get("method")
    path = entry.get("path") or entry.get("url")
    if not path:
        return None
    if not method:
        method = "GET"
    item = _inventory_entry(
        method=str(method),
        path=str(path) if str(path).startswith("/") else _path_from_url(str(path)),
        params=[str(p) for p in (entry.get("params") or entry.get("parameters") or [])],
        source=source,
    )
    for key in (
        "auth_required",
        "stateful",
        "rate_limited",
        "idempotent",
        "object_reference",
        "hostname_routed",
    ):
        if isinstance(entry.get(key), bool):
            item[key] = entry[key]
    roles = entry.get("roles")
    if isinstance(roles, (list, tuple)):
        item["roles"] = [str(r)[:80] for r in roles][:20]
    return item


def endpoint_inventory_from_state(state: dict[str, Any] | Any) -> list[dict[str, Any]]:
    """Derive the family analyzers' ``endpoint_inventory`` from real state.

    Precedence per source (first writer of a (method, path) key wins —
    the most structured source lands first):
    explicit ``endpoint_inventory`` → ``openapi_routes`` →
    ``surface_records`` → ``forms`` → ``shadow_endpoints`` →
    ``endpoints``/``links`` URL strings.
    """
    get = _state_get(state)
    inventory: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def push(item: dict[str, Any] | None) -> None:
        if item is None or len(inventory) >= _MAX_INVENTORY:
            return
        key = (item["method"], item["path"])
        if key in seen:
            return
        seen.add(key)
        inventory.append(item)

    # 1. Explicit inventory (family vocabulary already present).
    for entry in get("endpoint_inventory") or []:
        push(_normalize_entry(entry, source="explicit"))

    crawled = get("crawled_data") or {}
    if not isinstance(crawled, dict):
        crawled = {}

    # 2. OpenAPI routes (method+path from a real schema).
    for route in crawled.get("openapi_routes") or []:
        if isinstance(route, dict):
            push(
                _inventory_entry(
                    method=str(route.get("method") or "GET"),
                    path=str(route.get("path") or "/"),
                    params=list(route.get("params") or []),
                    source="openapi_routes",
                )
            )

    # 3. Surface records (observed HTTP GETs with query parameters).
    for record in crawled.get("surface_records") or []:
        if isinstance(record, dict):
            push(
                _inventory_entry(
                    method=str(record.get("method") or "GET"),
                    path=str(record.get("path") or _path_from_url(str(record.get("url") or ""))),
                    params=[str(q) for q in (record.get("query_parameters") or [])],
                    source="surface_records",
                )
            )

    # 4. Forms (observed HTML forms — action+method+field names).
    for form in crawled.get("forms") or []:
        if isinstance(form, dict):
            data = form.get("data") or {}
            push(
                _inventory_entry(
                    method=str(form.get("method") or "GET"),
                    path=_path_from_url(str(form.get("action") or "/")),
                    params=[str(k) for k in data.keys()] if isinstance(data, dict) else [],
                    source="forms",
                )
            )

    # 5. Shadow endpoints (ق8: JS-only endpoints the crawl never documented).
    for shadow in crawled.get("shadow_endpoints") or []:
        if isinstance(shadow, dict):
            path = shadow.get("path") or shadow.get("route") or shadow.get("url")
            if path:
                push(
                    _inventory_entry(
                        method=str(shadow.get("method") or "GET"),
                        path=str(path),
                        source="shadow_endpoints",
                    )
                )
        elif isinstance(shadow, str) and shadow.strip():
            push(_inventory_entry(method="GET", path=_path_from_url(shadow), source="shadow_endpoints"))

    # 6. Crawled URL strings (the crawler's fallback surface).
    for key in ("endpoints", "links"):
        for url in crawled.get(key) or []:
            if isinstance(url, str) and url.strip():
                push(_inventory_entry(method="GET", path=_path_from_url(url), source=f"crawled:{key}"))
            elif isinstance(url, dict) and (url.get("url") or url.get("href")):
                push(
                    _inventory_entry(
                        method=str(url.get("method") or "GET"),
                        path=_path_from_url(str(url.get("url") or url.get("href"))),
                        source=f"crawled:{key}",
                    )
                )

    return inventory


def multi_tenant_from_state(state: dict[str, Any] | Any) -> bool:
    """Multi-tenancy is EXPLICIT-only: declared on the target, the state, or
    the engagement context. Never inferred — a fabricated tenant boundary
    is worse than a missed one (it would fabricate candidates)."""
    get = _state_get(state)
    if bool(get("multi_tenant")):
        return True
    target = get("target")
    for attr in ("multi_tenant", "is_multi_tenant", "multitenant"):
        if bool(getattr(target, attr, False)):
            return True
    engagement = get("engagement") or get("engagement_context")
    if isinstance(engagement, dict) and bool(engagement.get("multi_tenant")):
        return True
    return False


def auth_flows_from_state(state: dict[str, Any] | Any) -> list[dict[str, Any]]:
    """Derive ``multi_step_auth``-analyzer flows from identity profiles.

    Only flows whose step lists actually exist are emitted (a profile
    without login steps is not a flow). Secrets never appear: the
    IdentityProfile contract carries step NAMES and a credentials HANDLE
    only.
    """
    get = _state_get(state)
    profiles = get("identity_profiles") or {}
    flows: list[dict[str, Any]] = []
    if isinstance(profiles, dict):
        for label, profile in profiles.items():
            if len(flows) >= _MAX_FLOWS:
                break
            if not isinstance(profile, dict):
                continue
            steps = profile.get("login_flow") or profile.get("steps") or []
            if not isinstance(steps, (list, tuple)) or not steps:
                continue
            normalized_steps = []
            for step in steps:
                if isinstance(step, str):
                    normalized_steps.append({"name": step[:120], "type": "login"})
                elif isinstance(step, dict):
                    normalized_steps.append(
                        {
                            "name": str(step.get("name") or step.get("label") or "step")[:120],
                            "type": str(step.get("type") or "login")[:40],
                        }
                    )
            if not normalized_steps:
                continue
            flows.append(
                {
                    "name": str(profile.get("name") or label)[:120],
                    "role": str(profile.get("role") or "unknown")[:80],
                    "steps": normalized_steps,
                    "final_step": normalized_steps[-1]["name"],
                    "provenance": "family_feeds:identity_profiles",
                    "credentials_included": False,
                }
            )
    return flows


def _state_get(state: dict[str, Any] | Any) -> Any:
    """Read from dict-style states (the LangGraph TypedDict the nodes hold)
    or attribute-style stage objects, defensively."""

    class _Reader:
        def __init__(self, obj: Any) -> None:
            self._obj = obj

        def __call__(self, key: str) -> Any:
            if isinstance(self._obj, dict):
                return self._obj.get(key)
            return getattr(self._obj, key, None)

    return _Reader(state)


__all__ = [
    "auth_flows_from_state",
    "endpoint_inventory_from_state",
    "multi_tenant_from_state",
]

"""webpent.stateful_api.contracts — M5 (Part 4 §7): the stateful API
contract model.

Part 4 §7 scope: "OpenAPI/observed-traffic contract ingestion;
dependency/state model; bounded sequence generation; BOLA/IDOR with two
authorized identities and negative controls".

This module is the ingestion + dependency half:

* :class:`ApiOperation` — one REST operation from an OpenAPI schema
  (rich: body properties, auth requirements) or from observed traffic
  (thin: method + path + query params), provenance-preserved.
* :func:`operations_from_state` — derives the operation set from the
  channels the production graph already populates
  (``crawled_data["openapi_routes"]`` written by the frozen
  schema-ingestion path, plus the observed surface via
  ``shared.family_feeds``).
* :func:`infer_dependencies` — the deterministic state-dependency
  heuristic: a creator (POST/PUT/PATCH to a collection path) PRODUCES
  the identifier its item-path consumers CONSUME
  (``POST /api/users`` produces ``user_id`` for
  ``GET /api/users/{id}``). Every inferred edge is labelled
  ``inferred`` — nothing here is authoritative truth; it is a bounded,
  reproducible hypothesis input.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ApiOperation",
    "StateDependency",
    "infer_dependencies",
    "operations_from_state",
]

_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_CREATING_METHODS = frozenset({"POST", "PUT", "PATCH"})
_PARAM_RE = re.compile(r"\{([^{}]+)\}")
_MAX_OPERATIONS = 500


class ApiOperation(BaseModel):
    """One REST operation, provenance-preserved."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    method: str
    path: str = Field(min_length=1, max_length=500)
    path_params: list[str] = Field(default_factory=list, max_length=20)
    body_properties: list[str] = Field(default_factory=list, max_length=100)
    query_params: list[str] = Field(default_factory=list, max_length=40)
    auth_required: bool = False
    source: str = Field(default="observed", max_length=40)
    operation_id: str = Field(default="", max_length=240)

    @property
    def collection_path(self) -> str | None:
        """The collection path this operation belongs to (no path params)."""
        if _PARAM_RE.search(self.path):
            return None
        return self.path

    @property
    def item_path_prefix(self) -> str | None:
        """``/api/users`` for ``/api/users/{id}`` (None when static)."""
        if not _PARAM_RE.search(self.path):
            return None
        return _PARAM_RE.sub("", self.path).rstrip("/") or "/"


class StateDependency(BaseModel):
    """One inferred producer→consumer state dependency."""

    model_config = ConfigDict(extra="forbid")

    producer_operation_id: str
    consumer_operation_id: str
    resource_name: str
    provenance: str = "inferred:path_shape"


def _method(value: Any) -> str:
    method = str(value or "GET").upper()
    return method if method in _HTTP_METHODS else "GET"


def _params_of(path: str) -> list[str]:
    return _PARAM_RE.findall(path)[:20]


def operations_from_state(state: Mapping[str, Any] | Any) -> list[ApiOperation]:
    """Derive the operation set from real state channels.

    Priority: OpenAPI routes (rich) first, then the observed surface
    (thin) for (method, path) keys the schema did not cover.
    """
    crawled = (
        state.get("crawled_data")
        if isinstance(state, Mapping)
        else getattr(state, "crawled_data", None)
    )
    crawled = crawled if isinstance(crawled, Mapping) else {}

    operations: list[ApiOperation] = []
    seen: set[tuple[str, str]] = set()

    def push(operation: ApiOperation) -> None:
        if len(operations) >= _MAX_OPERATIONS:
            return
        key = (operation.method, operation.path)
        if key in seen:
            return
        seen.add(key)
        operations.append(operation)

    # 1. OpenAPI routes — the frozen schema-ingestion projection.
    for route in crawled.get("openapi_routes") or []:
        if not isinstance(route, Mapping):
            continue
        path = str(route.get("path") or "").strip()
        if not path:
            continue
        body_properties = [
            str(prop)[:120]
            for prop in (
                route.get("body_properties")
                or route.get("request_body_properties")
                or []
            )
            if str(prop).strip()
        ][:100]
        push(
            ApiOperation(
                method=_method(route.get("method")),
                path=path,
                path_params=_params_of(path),
                body_properties=body_properties,
                query_params=[str(q)[:120] for q in (route.get("params") or [])][:40],
                auth_required=bool(route.get("auth_required")),
                source="openapi",
                operation_id=f"{_method(route.get('method'))} {path}",
            )
        )

    # 2. Observed surface (thin) — family_feeds already normalizes the
    # crawled channels into the inventory vocabulary.
    try:
        from webpent.shared.family_feeds import endpoint_inventory_from_state

        for entry in endpoint_inventory_from_state(state):
            path = str(entry.get("path") or "").strip()
            if not path:
                continue
            push(
                ApiOperation(
                    method=_method(entry.get("method")),
                    path=path,
                    path_params=_params_of(path),
                    query_params=[
                        str(p)[:120] for p in (entry.get("params") or [])
                    ][:40],
                    auth_required=bool(entry.get("auth_required")),
                    source=str(entry.get("provenance") or "observed")
                    .split(":", 1)[-1][:40],
                    operation_id=f"{_method(entry.get('method'))} {path}",
                )
            )
    except Exception:  # noqa: BLE001 — observed surface is best-effort
        pass

    return operations


def infer_dependencies(operations: Iterable[ApiOperation]) -> list[StateDependency]:
    """The deterministic producer→consumer heuristic.

    ``POST /api/users`` (a creator on a collection) produces the
    identifier that ``GET /api/users/{id}`` (an item consumer under the
    same collection) consumes. Every edge is labelled inferred — the
    dependency model is a reproducible planning input, never asserted
    target truth.
    """
    operations = list(operations)
    creators: dict[str, ApiOperation] = {}
    for operation in operations:
        if operation.method in _CREATING_METHODS and operation.collection_path:
            creators.setdefault(operation.collection_path, operation)

    dependencies: list[StateDependency] = []
    seen: set[tuple[str, str]] = set()
    for consumer in operations:
        prefix = consumer.item_path_prefix
        if prefix is None:
            continue
        producer = creators.get(prefix)
        if producer is None or producer.operation_id == consumer.operation_id:
            continue
        key = (producer.operation_id, consumer.operation_id)
        if key in seen:
            continue
        seen.add(key)
        resource = prefix.rstrip("/").rsplit("/", 1)[-1] or "resource"
        dependencies.append(
            StateDependency(
                producer_operation_id=producer.operation_id,
                consumer_operation_id=consumer.operation_id,
                resource_name=f"{resource}_id",
            )
        )
    return dependencies

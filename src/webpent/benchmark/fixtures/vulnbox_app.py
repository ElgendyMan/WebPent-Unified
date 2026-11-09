# src/webpent/benchmark/fixtures/vulnbox_app.py
"""Local vulnerable-app fixtures for the self-test harness (Proposal 6).

A single Starlette ASGI app, parameterized by ``mode``, that plants a
KNOWN set of vulnerabilities — each one corresponding to a canonical
validator family — plus honest negative surfaces. The harness runner
(``benchmark/fixtures/runner.py``) serves this app on loopback and
drives WebPent's REAL probe nodes against it, so the confusion matrix
comes from the actual detection pipeline, never from hand-built
evidence.

Planted behavior by mode
------------------------
``"graphql"`` — a GraphQL endpoint with FULL introspection enabled
    (the planted vulnerability) and a generic error channel WITHOUT
    field suggestions (so the field-suggestion probe has nothing
    false-positive to harvest).

``"web"`` — two planted vulnerabilities on ``/``:
    1. Cache poisoning via ``X-Forwarded-Host`` keying: the poison
       request's response is cached under the bare path, so the
       UNPOISONED victim request is served the poisoned body — the
       exact two-request proof shape the canonical validator requires.
    2. Prototype pollution via ``__proto__[key]=value`` query
       reflection into a JSON ``config`` object (dynamic, never
       cached), while an identical value under a benign key does NOT
       reflect — plain echo is honestly absent.

``"clean"`` — the same surfaces with every vulnerability disabled
    (header ignored, no cache, ``__proto__`` ignored). Probes still
    run and still emit TENTATIVE findings; the validators must REFUTE
    all of them. This is the false-positive gauge.

Design rules:

  * NO network calls — loopback only, ephemeral port, thread daemon;
  * every response is deterministic for a given request sequence;
  * ``app.state.request_count`` counts every served request (honest
    cost metric: requests-per-confirmation);
  * the fixture must not require the poisoned path to be hit first —
    ordering comes from the probe node itself.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote_plus

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

VULNBOX_MODES = ("graphql", "web", "clean")

_SCHEMA_TYPES = [
    {"name": "Query"}, {"name": "User"}, {"name": "Post"},
    {"name": "String"}, {"name": "Int"}, {"name": "ID"},
]

_CLEAN_PAGE = "<html><body>honest static page</body></html>"
_CACHE_MISS = "MISS"
_CACHE_HIT = "HIT"
_PP_PROBE_KEY = "webpent_probe"


class _RequestCounter(BaseHTTPMiddleware):
    """Counts every request the fixture serves (honest cost metric)."""

    def __init__(self, app: Any, counter: dict[str, int]) -> None:
        super().__init__(app)
        self._counter = counter

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        self._counter["requests"] += 1
        return await call_next(request)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# GraphQL mode
# ---------------------------------------------------------------------------
def _answer_graphql_query(query: str) -> dict[str, Any]:
    if "__schema" in query:
        return {"data": {"__schema": {"types": _SCHEMA_TYPES}}}
    if "__typename" in query:
        return {"data": {"__typename": "Query"}}
    # Generic error WITHOUT field suggestions — the fixture deliberately
    # keeps the suggestion channel closed so the field-suggestion probe
    # cannot false-positive here.
    return {"errors": [{"message": "Cannot query field."}]}


async def _graphql_endpoint(request: Request) -> Response:
    if request.method != "POST":
        return JSONResponse({"data": {"__typename": "Query"}})
    try:
        payload = json.loads((await request.body()) or b"{}")
    except ValueError:
        return JSONResponse({"errors": [{"message": "invalid JSON"}]}, status_code=400)
    if isinstance(payload, list):
        # Batched operations (the batching probe sends an array) — answer
        # each element independently.
        return JSONResponse([_answer_graphql_query(str(op.get("query") or ""))
                             if isinstance(op, dict) else {"errors": [{"message": "invalid op"}]}
                             for op in payload])
    return JSONResponse(_answer_graphql_query(str(payload.get("query") or "")))


# ---------------------------------------------------------------------------
# web mode (cache poisoning + prototype pollution) / clean mode
# ---------------------------------------------------------------------------
async def _root_page(request: Request) -> Response:
    mode = request.app.state.vulnbox_mode
    cache: dict[str, str] = request.app.state.vulnbox_cache
    # HTTP clients percent-encode brackets in query strings; decode so the
    # pollution channel matches probe-shaped keys exactly.
    raw_query = unquote_plus(request.url.query)
    key = request.url.path + (f"?{raw_query}" if raw_query else "")
    forwarded_host = request.headers.get("x-forwarded-host")

    # Prototype-pollution channel (dynamic, never cached).
    if "__proto__[" in raw_query:
        if mode == "web":
            value = request.query_params.get(f"__proto__[{_PP_PROBE_KEY}]")
            if value:
                return JSONResponse({"config": {_PP_PROBE_KEY: value}})
        return JSONResponse({"config": {}})
    if "benign[" in raw_query:
        # The benign-key control must NOT reflect the value.
        return JSONResponse({"config": {}})

    if mode != "web":
        # clean mode: static honest page, no cache behavior at all.
        return Response(_CLEAN_PAGE, media_type="text/html")

    # Cache-poisoning channel (web mode only).
    if forwarded_host:
        poisoned = f"<html><body>cdn={forwarded_host}</body></html>"
        cache[key] = poisoned
        return Response(poisoned, media_type="text/html",
                        headers={"X-Cache": _CACHE_MISS})
    cached = cache.get(key)
    if cached is not None:
        return Response(cached, media_type="text/html",
                        headers={"X-Cache": _CACHE_HIT})
    cache[key] = _CLEAN_PAGE
    return Response(_CLEAN_PAGE, media_type="text/html",
                    headers={"X-Cache": _CACHE_MISS})


async def _not_found(request: Request) -> Response:
    return Response("not found", status_code=404)


def build_vulnbox_app(mode: str = "web") -> Starlette:
    """Build the vulnerable fixture app for one of ``VULNBOX_MODES``."""
    if mode not in VULNBOX_MODES:
        raise ValueError(f"unknown vulnbox mode {mode!r}; expected one of {VULNBOX_MODES}")
    app = Starlette(routes=[
        Route("/graphql", _graphql_endpoint, methods=["GET", "POST"]),
        Route("/{path:path}", _root_page, methods=["GET"]),
    ])
    app.state.vulnbox_mode = mode  # type: ignore[attr-defined]
    app.state.vulnbox_cache = {}  # type: ignore[attr-defined]
    app.state.request_count = {"requests": 0}  # type: ignore[attr-defined]
    app.add_middleware(_RequestCounter, counter=app.state.request_count)  # type: ignore[arg-type]
    return app


__all__ = ["VULNBOX_MODES", "build_vulnbox_app"]

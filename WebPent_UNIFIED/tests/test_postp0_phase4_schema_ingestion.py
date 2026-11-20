"""POST-P0 Phase 4 — schema / world-model ingestion acceptance tests.

Pins:
  * an api-docs fixture produces structured route records (params with
    {name, type, required, enum}) with NO DVWA/target keywords anywhere
    in the pipeline,
  * schema-derived hypotheses are produced deterministically
    (mass_assignment / idor / auth_bypass) from structure only,
  * schema hypotheses flow through the NORMAL promotion path — no
    deterministic-bypass for schema producers, no shortcut to
    Tool-Confirmed (strategist refuses promotion without a validator
    route; mass_assignment has none until Phase 5),
  * GraphQL introspection JSON parses into bounded operation records,
  * the mental model receives param-schema metadata for matching
    endpoint nodes,
  * all producers are bounded.
"""

from __future__ import annotations

from webpent.agents.hypothesis_analyzer.agent import (
    _MAX_SCHEMA_HYPOTHESES,
    _schema_route_hypotheses,
)
from webpent.shared.schema_ingestion import (
    MAX_SCHEMA_ROUTES,
    parse_graphql_introspection,
    parse_openapi_routes,
)

# Generic e-commerce style API doc — zero DVWA vocabulary.
_OPENAPI_DOC = {
    "openapi": "3.0.1",
    "info": {"title": "Shop API", "version": "1.0"},
    "servers": [{"url": "https://shop.example.test"}],
    "paths": {
        "/api/v1/users/{userId}": {
            "get": {
                "operationId": "getUser",
                "parameters": [
                    {
                        "name": "userId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
            },
        },
        "/api/v1/admin/roles": {
            "post": {
                "operationId": "createRole",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "isAdmin": {"type": "boolean", "default": False},
                                },
                            }
                        }
                    }
                },
            },
        },
        "/api/v1/items": {
            "get": {
                "operationId": "listItems",
                "parameters": [
                    {
                        "name": "category",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string", "enum": ["a", "b"]},
                    }
                ],
            }
        },
    },
}


def test_openapi_fixture_produces_structured_routes() -> None:
    routes = parse_openapi_routes(
        _OPENAPI_DOC, base_url="https://shop.example.test/openapi.json"
    )
    assert len(routes) == 3
    by_path = {r["path"]: r for r in routes}
    user_route = by_path["/api/v1/users/{userId}"]
    assert user_route["method"] == "GET"
    assert user_route["params"][0]["name"] == "userId"
    assert user_route["params"][0]["type"] == "integer"
    assert user_route["params"][0]["required"] is True
    items_route = by_path["/api/v1/items"]
    assert items_route["params"][0]["enum"] == ["a", "b"]
    role_route = by_path["/api/v1/admin/roles"]
    body_names = [f["name"] for f in role_route["body_fields"]]
    assert body_names == ["name", "isAdmin"]
    # Same-origin absolutization.
    assert all(r["url"].startswith("https://shop.example.test") for r in routes)


def test_schema_hypotheses_from_structure_only() -> None:
    routes = parse_openapi_routes(
        _OPENAPI_DOC, base_url="https://shop.example.test/openapi.json"
    )
    specs = _schema_route_hypotheses(routes)
    pairs = {(s["url"], s["vuln_class"]) for s in specs}
    # Writable body on POST -> mass assignment.
    assert (
        "https://shop.example.test/api/v1/admin/roles",
        "mass_assignment",
    ) in pairs
    # Privileged writable field -> auth bypass candidate.
    assert (
        "https://shop.example.test/api/v1/admin/roles",
        "auth_bypass",
    ) in pairs
    # Templated object reference -> IDOR.
    assert (
        "https://shop.example.test/api/v1/users/{userId}",
        "idor",
    ) in pairs
    # Unprivileged GET with plain query param: no hypothesis.
    assert not any(
        s["url"] == "https://shop.example.test/api/v1/items" for s in specs
    )
    # No target-specific vocabulary anywhere in the emitted details.
    blob = " ".join(s["detail"] for s in specs).lower()
    for forbidden in ("dvwa", "vulnerabilities", "login.php", "exploit"):
        assert forbidden not in blob


def test_schema_producer_is_bounded_and_deduped() -> None:
    routes = [
        {
            "url": f"https://shop.example.test/api/v1/users/{i}",
            "path": "/api/v1/users/{userId}",
            "method": "POST",
            "params": [],
            "body_fields": [{"name": "email", "type": "string", "required": True, "enum": []}],
            "authenticated": True,
            "source": "openapi",
        }
        for i in range(MAX_SCHEMA_ROUTES + 10)
    ]
    specs = _schema_route_hypotheses(routes)
    assert len(specs) <= _MAX_SCHEMA_HYPOTHESES
    # Same route never yields duplicate (url, class) pairs.
    pairs = [(s["url"], s["vuln_class"]) for s in specs]
    assert len(pairs) == len(set(pairs))


def test_graphql_introspection_parses_operations() -> None:
    doc = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [],
            }
        }
    }
    doc["data"]["__schema"]["queryType"]["fields"] = [
        {
            "name": "userById",
            "args": [{"name": "id", "type": {"name": "Int"}}],
        }
    ]
    doc["data"]["__schema"]["mutationType"]["fields"] = [
        {"name": "updateRole", "args": []}
    ]
    ops = parse_graphql_introspection(doc)
    by_name = {o["operation"]: o for o in ops}
    assert by_name["userById"]["kind"] == "query"
    assert by_name["userById"]["args"][0]["name"] == "id"
    assert by_name["updateRole"]["kind"] == "mutation"
    assert parse_graphql_introspection({"nope": True}) == []


def test_no_schema_shortcut_to_deterministic_promotion() -> None:
    # The strategist refuses promotion for classes without a validator
    # route; schema producers must NOT be in the deterministic structural
    # promotion allowlist either — the hypothesis carries the normal
    # heuristic origin (no deterministic_match=True).
    from webpent.shared.prioritization import _DETERMINISTIC_STRUCTURAL_CLASSES

    routes = parse_openapi_routes(
        _OPENAPI_DOC, base_url="https://shop.example.test/openapi.json"
    )
    specs = _schema_route_hypotheses(routes)
    assert specs  # producer is active
    # The schema producer emits plain heuristic hypotheses with no
    # deterministic_match flag — there is no schema shortcut to
    # Tool-Confirmed; confirmation still requires the tool validator.
    for spec in specs:
        assert "deterministic_match" not in spec
    # idor is deliberately excluded from deterministic shortcut promotion.
    # M1-B (E-2): the exclusion now lives in the SET itself, not in
    # statement ordering — the old assertion pinned the dead entry
    # ("idor" in the set) which was protected only by an early-return
    # two lines into _deterministic_promotion_allowed. Updated to the
    # hardened contract with justification (M1_READINESS_REVIEW §4/E-2).
    assert "idor" not in _DETERMINISTIC_STRUCTURAL_CLASSES  # data-level exclusion
    # The schema producer emits heuristic-origin hypotheses (asserted in
    # the strategist contract tests); nothing here changes that.

"""UM-DR-32 identity & business-logic evaluation target — a controlled,
resettable local application (2026-11-09).

Purpose: make each UM-DR-32 capability's contribution MEASURABLE under
identical, controlled conditions (same target, same observations, same
credentials, same budgets, same ground truth — §9.2).

Population honesty (§9.4): this is a TEAM-AUTHORED, author-known
fixture — a development and mechanism-validation population. It is NOT
an independent holdout and proves nothing about generalization beyond
its population. No real-world recall/precision or cross-tool
superiority claim may be derived from it.

Surface (all advertised via ``GET /openapi.json``):

  Identity / alias surface
    GET /api/orders/601 | /api/o/601        alias pair (same in-body id)
    GET /api/orders/602 | /api/o/602        alias pair
    GET /api/orders/701 | /api/o/701        alias pair (authz INCONSISTENT)
    GET /api/orders/123 | /api/o/123        alias pair (safe)
    GET /api/t1/orders/501                  tenant-scoped canonical form
    GET /api/t2/orders/501                  SAME numeric id, OTHER tenant
    GET /api/invoices/501                   SAME numeric id, OTHER type
    GET /api/reports/9?account=1 | ?account=2   query-variant resources
    GET /api/products/my-widget             slug representation
    GET /api/products/77                    id representation
    GET /api/orders                         collection (not an item alias)

  Authorization surface (X-Actor / X-Actor-Role headers)
    /api/orders/601    IDOR ground truth: foreign user B ALSO granted
    /api/orders/123    SAFE: foreign denied, owner granted
    /api/orders/701    SAFE on canonical (foreign denied) — /api/o/701
                       GRANTS foreign (the alias-bypass ground truth)
    /api/t2/orders/501 cross-tenant leak: the t1 owner is granted
    /api/vaults/quote  manager-only blanket restriction (negative
                       control for every differential)
    /api/shared/announcements/1  legitimately public (safe control)

  Workflow surface (order approval)
    POST /api/wf/create -> draft -> submit -> submitted -> approve
                       (approve is role_scoped; the planted flaw
                       accepts ANY authenticated actor)
    POST /api/wf/purge  destructive step (must never execute outside
                       an authorized resettable fixture)

  Out of scope
    /internal/*         must be refused before any request

Ground truth manifest (FIXED before any measurement; see
GROUND_TRUTH_MANIFEST below — never changed after observing results):

  alias pairs (same object):        orders/601<->o/601, orders/602<->o/602,
                                    orders/701<->o/701, orders/123<->o/123
  never-merge pairs:                t1/orders/501 vs t2/orders/501 (namespace),
                                    orders/501 vs invoices/501 (type),
                                    reports/9?account=1 vs ?account=2 (query)
  abstain pair:                     products/my-widget vs products/77
  vulnerabilities (must be found):  V-IDOR-601 (multi-identity differential),
                                    V-ALIAS-701 (cross-representation
                                    differential), V-XTENANT-501 (tenant
                                    boundary), V-APPROVAL (composite workflow)
  safe (must NEVER confirm):        orders/123, shared announcement,
                                    valid workflow, products slug pair

Principal model (the campaign's available identities — §6.2):
  User_A   owner, tenant t1      (owns orders 601/602/123/701)
  User_B   foreign, tenant t1    (same tenant, different user)
  manager  higher privilege      (approval authority)
  viewer   lower privilege       (no approval authority)
  anonymous                       (no credentials)
"""
from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 9231

_state: dict[str, str] = {"wf": "none"}
_state_lock = threading.Lock()
_churn_lock = threading.Lock()
_churn_counter = 0

ALIAS_PAIRS = [(601, 602, 701, 123)]
SAFE_ORDERS = frozenset({123})


def _next_churn() -> int:
    global _churn_counter
    with _churn_lock:
        _churn_counter += 1
        return _churn_counter


def reset_state() -> None:
    """Test hook — the resettable-fixture contract."""
    with _state_lock:
        _state["wf"] = "none"


# --- the FIXED ground-truth manifest (§9.1: recorded before evaluation) ---

GROUND_TRUTH_MANIFEST: dict[str, object] = {
    "alias_same_object": [
        ("/api/orders/601", "/api/o/601"),
        ("/api/orders/602", "/api/o/602"),
        ("/api/orders/701", "/api/o/701"),
        ("/api/orders/123", "/api/o/123"),
    ],
    "never_merge": [
        ("/api/t1/orders/501", "/api/t2/orders/501", "namespace"),
        ("/api/t1/orders/501", "/api/invoices/501", "resource_type"),
        ("/api/reports/9?account=1", "/api/reports/9?account=2", "query_value"),
    ],
    "abstain": [
        ("/api/products/my-widget", "/api/products/77"),
    ],
    "vulnerabilities": {
        "V-IDOR-601": {
            "kind": "idor", "endpoint": "/api/orders/601",
            "description": "foreign same-tenant user reads the owner object",
        },
        "V-ALIAS-701": {
            "kind": "alias_bypass", "endpoint": "/api/o/701",
            "description": "alternate representation loses authorization",
        },
        "V-XTENANT-501": {
            "kind": "cross_tenant", "endpoint": "/api/t2/orders/501",
            "description": "t1 principal reads t2 tenant object",
        },
        "V-APPROVAL": {
            "kind": "unauthorized_approval", "endpoint": "/api/wf/approve",
            "description": "viewer role completes the manager-only approval",
        },
    },
    "safe_controls": [
        "/api/orders/123", "/api/shared/announcements/1",
    ],
    "out_of_scope": ["/internal/*"],
}

PRINCIPALS = {
    "User_A": {"role": "owner", "tenant": "t1"},
    "User_B": {"role": "foreign", "tenant": "t1"},
    "manager": {"role": "admin", "tenant": "t1"},
    "viewer": {"role": "viewer", "tenant": "t1"},
    "anonymous": {"role": "anonymous", "tenant": ""},
}


def _gt_manifest_hash() -> str:
    blob = json.dumps(GROUND_TRUTH_MANIFEST, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()


def openapi_document() -> dict[str, object]:
    """The advertised surface (the ONLY discovery channel)."""
    paths: dict[str, dict[str, object]] = {}
    for n in (601, 602, 701, 123):
        paths[f"/api/orders/{n}"] = {"get": {"summary": "order read"}}
        paths[f"/api/o/{n}"] = {"get": {"summary": "short order read"}}
    for tenant in ("t1", "t2"):
        paths[f"/api/{tenant}/orders/501"] = {"get": {"summary": "tenant order"}}
    paths["/api/invoices/501"] = {"get": {"summary": "invoice read"}}
    paths["/api/reports/9"] = {"get": {"summary": "account report",
                                       "parameters": [{"name": "account"}]}}
    paths["/api/products/my-widget"] = {"get": {"summary": "product slug"}}
    paths["/api/products/77"] = {"get": {"summary": "product id"}}
    paths["/api/orders"] = {"get": {"summary": "orders collection"}}
    paths["/api/vaults/quote"] = {"get": {"summary": "manager vault"}}
    paths["/api/shared/announcements/1"] = {"get": {"summary": "announcement"}}
    for step in ("create", "submit", "approve", "purge"):
        paths[f"/api/wf/{step}"] = {"post": {"summary": f"workflow {step}"}}
    for n in (901, 902):
        paths[f"/internal/admin/orders/{n}"] = {"get": {"summary": "admin"}}
    return {"openapi": "3.0.0", "info": {"title": "acme-identity-lab"},
            "paths": paths}


def _order_body(order_id: int, *, granted: bool, actor: str) -> dict[str, object]:
    churn = _next_churn()
    return {
        "id": str(order_id),              # the in-body stable object id
        "object_id": str(order_id),       # alias-invariant identity field
        "granted": granted,
        "owner": "User_A",
        "requested_by": actor,
        "ts": churn,                       # churn the digest layer must ignore
        "request_id": f"r-{churn}",
    }


def _tenant_order_body(tenant: str, *, granted: bool, actor: str) -> dict[str, object]:
    churn = _next_churn()
    return {
        "id": "501",
        "tenant": tenant,
        "granted": granted,
        "owner": f"{tenant}-owner",
        "requested_by": actor,
        "ts": churn,
    }


class IdentityLabHandler(BaseHTTPRequestHandler):
    """The controlled application. Authorization is driven by the
    X-Actor / X-Actor-Role headers (the campaign's principal model)."""

    def log_message(self, *args) -> None:  # silence
        pass

    # -- helpers ---------------------------------------------------------

    def _actor(self) -> tuple[str, str]:
        return (
            self.headers.get("X-Actor", "anonymous"),
            self.headers.get("X-Actor-Role", "anonymous"),
        )

    def _send(self, code: int, payload: dict, *, actor: str,
              resource_type: str = "orders", resource_id: str = "",
              outcome: str = "granted") -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Actor-Echo", actor)
        self.send_header("X-Actor-Role", self.headers.get("X-Actor-Role", ""))
        self.send_header("X-Resource-Type", resource_type)
        self.send_header("X-Resource-Id", resource_id)
        self.send_header("X-Authorization-Outcome", outcome)
        self.end_headers()
        self.wfile.write(body)

    def _denied(self, actor: str, *, resource_type: str = "orders",
                resource_id: str = "") -> None:
        self._send(403, {"error": "forbidden"}, actor=actor,
                   resource_type=resource_type, resource_id=resource_id,
                   outcome="denied")

    # -- GET --------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        actor, role = self._actor()
        path = self.path.split("?", 1)[0].rstrip("/")
        query = self.path.split("?", 1)[1] if "?" in self.path else ""

        # out-of-scope area (must be refused by the campaign, never served)
        if path.startswith("/internal"):
            self._denied(actor, resource_type="admin")
            return

        if path == "/openapi.json":
            body = json.dumps(openapi_document()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/shared/announcements/1":
            # legitimately public — a SAFE control that must never confirm
            self._send(200, {"id": "1", "title": "hello",
                             "public": True}, actor=actor,
                       resource_type="announcements", resource_id="1")
            return

        if path == "/api/vaults/quote":
            # blanket manager-only restriction: the negative control
            if role == "admin":
                self._send(200, {"vault": "quote", "value": 42},
                           actor=actor, resource_type="vaults",
                           resource_id="quote")
            else:
                self._denied(actor, resource_type="vaults", resource_id="quote")
            return

        if path == "/api/reports/9":
            account = dict(
                p.split("=", 1) for p in query.split("&") if "=" in p
            ).get("account", "")
            if account in {"1", "2"}:
                self._send(200, {
                    "id": "9", "account": account,
                    "data": f"report-for-account-{account}",
                }, actor=actor, resource_type="reports", resource_id="9")
            else:
                self._denied(actor, resource_type="reports", resource_id="9")
            return

        if path == "/api/products/my-widget":
            # slug representation — NO id linkage to /api/products/77
            # (insufficient evidence: the correct answer is ABSTAIN)
            self._send(200, {"slug": "my-widget", "name": "Widget"},
                       actor=actor, resource_type="products",
                       resource_id="my-widget")
            return
        if path == "/api/products/77":
            self._send(200, {"id": "77", "name": "Gadget"},
                       actor=actor, resource_type="products",
                       resource_id="77")
            return

        if path == "/api/orders":
            # the collection is not an alias of any item
            self._send(200, {"items": ["601", "602", "701", "123"]},
                       actor=actor, resource_type="orders",
                       resource_id="collection")
            return

        if path.startswith("/api/t1/orders/501"):
            # tenant t1's order 501: only the t1 owner is granted
            if actor == "User_A":
                self._send(200, _tenant_order_body("t1", granted=True,
                                                   actor=actor),
                           actor=actor, resource_id="501")
            else:
                self._denied(actor, resource_id="501")
            return
        if path.startswith("/api/t2/orders/501"):
            # GROUND TRUTH V-XTENANT-501: the t1 owner is (wrongly)
            # granted on the t2 object; everyone else denied
            if actor == "User_A":
                self._send(200, _tenant_order_body("t2", granted=True,
                                                   actor=actor),
                           actor=actor, resource_id="501")
            else:
                self._denied(actor, resource_id="501")
            return

        if path.startswith("/api/invoices/501"):
            # same numeric id, different resource type — SAFE
            if actor in {"User_A", "manager"}:
                self._send(200, {"id": "501", "total": 99},
                           actor=actor, resource_type="invoices",
                           resource_id="501")
            else:
                self._denied(actor, resource_type="invoices",
                             resource_id="501")
            return

        # canonical / alias order reads
        for prefix, is_alias in (("/api/orders/", False), ("/api/o/", True)):
            if not path.startswith(prefix):
                continue
            tail = path[len(prefix):]
            if not tail.isdigit():
                break
            order_id = int(tail)
            if order_id not in (601, 602, 701, 123):
                self._denied(actor, resource_id=tail)
                return
            granted = self._order_granted(order_id, actor, role, is_alias)
            body = _order_body(order_id, granted=granted, actor=actor)
            self._send(200 if granted else 403, body, actor=actor,
                       resource_id=str(order_id),
                       outcome="granted" if granted else "denied")
            return

        self._send(404, {"error": "not_found"}, actor=actor,
                   outcome="denied")

    @staticmethod
    def _order_granted(order_id: int, actor: str, role: str,
                       is_alias: bool) -> bool:
        """The authorization matrix (compiled in; no truth vocabulary)."""
        if actor == "User_A":                    # owner
            return True
        if actor == "manager":                   # higher privilege
            return True
        if actor in ("anonymous", ""):
            return False                         # anonymous never reads orders
        # User_B (foreign, same tenant) and viewer:
        if order_id == 601:
            return True                          # V-IDOR-601 (planted)
        if order_id == 701:
            return is_alias                      # V-ALIAS-701 (planted)
        return False                             # 602, 123: correctly denied

    # -- POST (the workflow) ----------------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        actor, role = self._actor()
        path = self.path.rstrip("/")
        with _state_lock:
            state = _state["wf"]
            if path == "/api/wf/create":
                _state["wf"] = "draft"
                self._send(201, {"wf": "draft"}, actor=actor,
                           resource_type="workflow")
            elif path == "/api/wf/submit":
                if state != "draft":
                    self._denied(actor, resource_type="workflow")
                    return
                _state["wf"] = "submitted"
                self._send(200, {"wf": "submitted"}, actor=actor,
                           resource_type="workflow")
            elif path == "/api/wf/approve":
                # GROUND TRUTH V-APPROVAL: role_scoped to manager, but ANY
                # authenticated actor is accepted (planted flaw)
                if state != "submitted":
                    self._denied(actor, resource_type="workflow")
                    return
                if actor in ("anonymous", ""):
                    self._denied(actor, resource_type="workflow")
                    return
                _state["wf"] = "approved"
                self._send(200, {
                    "wf": "approved", "granted": True, "approved_by": actor,
                }, actor=actor, resource_type="workflow")
            elif path == "/api/wf/purge":
                # destructive: must NEVER execute outside an authorized
                # resettable isolated fixture
                if state != "approved":
                    self._denied(actor, resource_type="workflow")
                    return
                _state["wf"] = "purged"
                self._send(200, {"wf": "purged"}, actor=actor,
                           resource_type="workflow")
            else:
                self._send(404, {"error": "not_found"}, actor=actor,
                           outcome="denied")


def build_server() -> ThreadingHTTPServer:
    """A server bound to an OS-assigned ephemeral port."""
    return ThreadingHTTPServer(("127.0.0.1", 0), IdentityLabHandler)

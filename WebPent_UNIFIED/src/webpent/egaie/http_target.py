"""EGAIE controlled HTTP ground-truth target.

A deterministic, locally bound HTTP server (127.0.0.1:0) implementing
the real-HTTP benchmark's application surface. The app computes its
own authorization decisions from role/ownership identities and emits
the CausalGuard observation headers from those decisions; nothing in
the response tells a detector which case is "positive" or "negative".
Fixture setup (this module) is fully separated from detection logic
(the EGAIE loop + CausalGuard), and reset() restores the exact
initial application state.

GET routes are read-only and idempotent by construction. POST routes
mutate state, but every mutation is applied at most once per
(family, resource, idempotency-token) key at application level, so a
resumed investigation never applies a mutation twice by re-running a
completed experiment.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)

ACTOR_A = "actor-a"
ACTOR_B = "actor-b"
ACTOR_ADMIN = "actor-admin"
TENANT = "tenant-1"

_ACTOR_ROLES: dict[str, str] = {
    ACTOR_A: "user",
    ACTOR_B: "user",
    ACTOR_ADMIN: "admin",
}

# The application's resource registry: resource id -> (type, owner).
# Deterministic and reset()-restorable.
_INITIAL_RESOURCES: dict[str, tuple[str, str]] = {
    "inv-1": ("invoice", ACTOR_B),
    "doc-1": ("document", ACTOR_B),
    "rec-1": ("record", ACTOR_B),
    "file-1": ("file", ACTOR_B),
    # The attacker actor's own resources: a real authorization
    # baseline is the attacker's legitimate access to their own twin
    # resource, compared against cross-owner access on the victim.
    "inv-2": ("invoice", ACTOR_A),
    "inv-3": ("invoice", ACTOR_A),
    "doc-2": ("document", ACTOR_A),
    "rec-2": ("record", ACTOR_A),
    "file-2": ("file", ACTOR_A),
}

# Archive entries and the archive's stored-input sub-resources.
# The defective note's path is revealed only inside the archive
# response body (multi-step case); the own note is the attacker's
# legitimate baseline for the stage-2 comparison.
# Server-authoritative prices (minor units) and registered coupon
# codes. The invoice GET exposes the authoritative price; the defective
# checkout route lets a client-supplied price override it.
_PRICES: dict[str, int] = {
    "inv-1": 10000,
    "inv-2": 5000,
    "inv-3": 5000,
}
_COUPONS: dict[str, int] = {"SAFE10": 10}

_ARCHIVE_ENTRY_OWNERS: dict[str, str] = {"arc-1": ACTOR_B, "arc-2": ACTOR_A}
_ARCHIVE_NOTE_TOKEN = "ab12cd34"
_ARCHIVE_NOTE_OWNER = ACTOR_B
_OWN_NOTE_TOKEN = "ef01ab23"
_NOTE_OWNERS: dict[str, str] = {
    _ARCHIVE_NOTE_TOKEN: ACTOR_B,
    _OWN_NOTE_TOKEN: ACTOR_A,
}


class ControlledInvestigationTarget:
    """Context-managed controlled HTTP target for the EGAIE benchmark."""

    def __init__(self) -> None:
        self._resources: dict[str, tuple[str, str]] = {}
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._request_count = 0
        self._lock = threading.Lock()

    # -- lifecycle -------------------------------------------------
    def start(self) -> ControlledInvestigationTarget:
        self.reset()
        target = self
        handler = _TargetRequestHandler
        handler.target = target  # type: ignore[attr-defined]
        self._server = ThreadingHTTPServer(
            ("127.0.0.1", 0), handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def __enter__(self) -> ControlledInvestigationTarget:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    def reset(self) -> None:
        with self._lock:
            self._resources = dict(_INITIAL_RESOURCES)
            self._request_count = 0
            self._paid_resources: set[str] = set()
            self._applied_mutations: set[tuple[str, str, str]] = set()
            self._orders: dict[str, dict[str, Any]] = {}

    def applied_mutation_count(self) -> int:
        """How many mutations the target actually applied (idempotency
        introspection for tests; never used by the loop)."""
        with self._lock:
            return len(self._applied_mutations)

    def applied_mutation_identities(self) -> tuple[tuple[str, str, str], ...]:
        """The exact (family, resource, token) identities applied so
        far, sorted (read-only introspection for resume verification;
        never used by the loop). A duplicate application of the same
        identity is structurally impossible in the set, so a caller
        comparing identity sets before and after a resume can tell a
        legitimate new mutation (new token) from a re-applied one."""
        with self._lock:
            return tuple(sorted(self._applied_mutations))

    def applied_count_for(self, resource_id: str) -> int:
        """Distinct idempotency tokens actually applied to one resource."""
        with self._lock:
            return sum(
                1 for _family, rid, _idem in self._applied_mutations
                if rid == resource_id
            )

    def applied_count_for_family(self, family: str, resource_id: str) -> int:
        """Distinct idempotency tokens applied to one resource by one
        mutation family (a family's mutation must never repeat)."""
        with self._lock:
            return sum(
                1 for fam, rid, _idem in self._applied_mutations
                if fam == family and rid == resource_id
            )

    # -- introspection ---------------------------------------------
    @property
    def target_origin(self) -> str:
        if self._server is None:
            raise RuntimeError("target not started")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def request_count(self) -> int:
        with self._lock:
            return self._request_count

    # -- direct test/diagnostic access (not used by the loop) ------
    def get(
        self, path: str, params: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], str]:
        from webpent.shared.http import make_safe_httpx_client

        query = ""
        if params:
            query = "?" + "&".join(
                f"{key}={value}" for key, value in sorted(params.items()))
        target_token = set_engagement_target_hosts(self.target_origin)
        try:
            with make_safe_httpx_client(
                timeout=10.0, follow_redirects=False,
            ) as client:
                response = client.get(self.target_origin + path + query)
        finally:
            clear_engagement_target_hosts(target_token)
        headers = {
            key.lower(): value for key, value in response.headers.items()
        }
        return response.status_code, headers, response.text

    def post(
        self, path: str, params: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], str]:
        from webpent.shared.http import make_safe_httpx_client

        query = ""
        if params:
            query = "?" + "&".join(
                f"{key}={value}" for key, value in sorted(params.items()))
        target_token = set_engagement_target_hosts(self.target_origin)
        try:
            with make_safe_httpx_client(
                timeout=10.0, follow_redirects=False,
            ) as client:
                response = client.post(
                    self.target_origin + path + query,
                    content=b"",
                    headers={"Content-Type": "application/json"},
                )
        finally:
            clear_engagement_target_hosts(target_token)
        headers = {
            key.lower(): value for key, value in response.headers.items()
        }
        return response.status_code, headers, response.text


    # -- request handling (called by the handler thread) -----------
    def handle_get(
        self, path: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        with self._lock:
            self._request_count += 1
        actor = params.get("actor", "anonymous")
        role = _ACTOR_ROLES.get(actor, "none")
        tenant = TENANT if actor in _ACTOR_ROLES else "unknown"
        base_headers = {
            "X-Actor-Echo": actor,
            "X-Actor-Role": role,
            "X-Actor-Tenant": tenant,
            "Content-Type": "application/json",
        }
        route = self._route_target(path)
        if route is None:
            body = json.dumps({"error": "not_found"})
            return 404, {**base_headers,
                         "X-Authorization-Outcome": "denied"}, body
        kind, resource_id = route
        if kind == "control":
            status, headers, body = self._control_response(
                resource_id, actor, role, tenant)
        elif kind == "archive":
            status, headers, body = self._archive_response(
                resource_id, actor, role, tenant)
        elif kind == "archive_note":
            status, headers, body = self._archive_note_response(
                resource_id, actor, role, tenant)
        elif kind == "order":
            status, headers, body = self._order_response(
                resource_id, actor, role, tenant)
        else:
            status, headers, body = self._resource_response(
                resource_id, actor, role, tenant)
        return status, {**base_headers, **headers}, body

    # -- POST handling (state-changing families) --------------------
    def handle_post(
        self, path: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        with self._lock:
            self._request_count += 1
        actor = params.get("actor", "anonymous")
        role = _ACTOR_ROLES.get(actor, "none")
        tenant = TENANT if actor in _ACTOR_ROLES else "unknown"
        base_headers = {
            "X-Actor-Echo": actor,
            "X-Actor-Role": role,
            "X-Actor-Tenant": tenant,
            "Content-Type": "application/json",
        }
        route = self._route_post_target(path)
        if route is None:
            body = json.dumps({"error": "not_found"})
            return 404, {**base_headers,
                         "X-Authorization-Outcome": "denied"}, body
        kind, resource_id = route
        if kind == "control_post":
            status, headers, body = self._control_post_response(
                resource_id, actor, role, tenant)
        elif kind == "payment":
            status, headers, body = self._payment_response(
                resource_id, actor, role, tenant, params)
        elif kind == "wire":
            status, headers, body = self._wire_response(
                resource_id, actor, role, tenant, params)
        elif kind == "charge":
            status, headers, body = self._charge_response(
                resource_id, actor, role, tenant, params)
        elif kind == "checkout":
            status, headers, body = self._checkout_response(
                resource_id, actor, role, tenant, params)
        elif kind == "till":
            status, headers, body = self._till_response(
                resource_id, actor, role, tenant, params)
        elif kind == "coupon":
            status, headers, body = self._coupon_response(
                resource_id, actor, role, tenant, params)
        else:
            body = json.dumps({"error": "not_found"})
            status, headers = 404, {
                "X-Authorization-Outcome": "denied"}
        return status, {**base_headers, **headers}, body

    def _route_post_target(
        self, path: str,
    ) -> tuple[str, str] | None:
        if path.startswith("/control/api/checkout/"):
            resource_id = path[len("/control/api/checkout/"):]
            if resource_id in self._resources:
                return "control_post", resource_id
            return None
        if path.startswith("/control/api/coupons/"):
            resource_id = path[len("/control/api/coupons/"):]
            if resource_id in self._resources:
                return "control_post", resource_id
            return None
        if path.startswith("/control/api/till/"):
            resource_id = path[len("/control/api/till/"):]
            if resource_id in self._resources:
                return "control_post", resource_id
            return None
        if path.startswith("/control/api/payments/"):
            resource_id = path[len("/control/api/payments/"):]
            if resource_id in self._resources:
                return "control_post", resource_id
            return None
        if path.startswith("/control/api/wire/"):
            resource_id = path[len("/control/api/wire/"):]
            if resource_id in self._resources:
                return "control_post", resource_id
            return None
        if path.startswith("/api/payments/"):
            resource_id = path[len("/api/payments/"):]
            if resource_id in self._resources:
                return "payment", resource_id
            return None
        if path.startswith("/api/wire/"):
            resource_id = path[len("/api/wire/"):]
            if resource_id in self._resources:
                return "wire", resource_id
            return None
        if path.startswith("/api/checkout/"):
            resource_id = path[len("/api/checkout/"):]
            if resource_id in self._resources:
                return "checkout", resource_id
            return None
        if path.startswith("/api/till/"):
            resource_id = path[len("/api/till/"):]
            if resource_id in self._resources:
                return "till", resource_id
            return None
        if path.startswith("/api/coupons/"):
            resource_id = path[len("/api/coupons/"):]
            if resource_id in self._resources:
                return "coupon", resource_id
            return None
        if path.startswith("/control/api/charges/"):
            resource_id = path[len("/control/api/charges/"):]
            if resource_id in self._resources:
                return "control_post", resource_id
            return None
        if path.startswith("/api/charges/"):
            resource_id = path[len("/api/charges/"):]
            if resource_id in self._resources:
                return "charge", resource_id
            return None
        return None

    def _apply_mutation(
        self, family: str, resource_id: str, idem: str,
    ) -> bool:
        """Apply a mutation at most once per (family, resource, token).

        Returns True when this request is the one that applied the
        mutation, False for an idempotent replay of a prior apply.
        """
        key = (family, resource_id, idem)
        if key in self._applied_mutations:
            return False
        self._applied_mutations.add(key)
        if self._resources[resource_id][0] == "invoice":
            self._paid_resources.add(resource_id)
        return True

    def _payment_response(
        self, resource_id: str, actor: str, role: str, tenant: str,
        params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        # Intentional defect (mutating-IDOR family): the payment route
        # applies a payment for any authenticated user role without
        # ever checking ownership of the invoice.
        resource_type, owner = self._resources[resource_id]
        if role in ("user", "admin"):
            applied = self._apply_mutation(
                "payment", resource_id, params.get("idem", ""))
            body = json.dumps({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "owner": owner,
                "paid": resource_id in self._paid_resources,
                "applied": applied,
            })
            return 200, self._grant(
                "granted_full", resource_type, resource_id, owner), body
        body = json.dumps({"error": "forbidden"})
        return 403, self._grant(
            "denied", resource_type, resource_id, owner), body

    def _charge_response(
        self, resource_id: str, actor: str, role: str, tenant: str,
        params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        # Intentional defect (multi-step mutating-IDOR family): the
        # charge route applies the mutation for any authenticated user
        # role without checking ownership, but responds with a generic
        # receipt that carries no ownership context, so a single
        # observation cannot confirm the defect. The effect is only
        # observable through a follow-up GET on the invoice, which is
        # what makes this family multi-step.
        resource_type, owner = self._resources[resource_id]
        if role in ("user", "admin"):
            self._apply_mutation(
                "charge", resource_id, params.get("idem", ""))
            body = json.dumps({
                "status": "accepted",
                "receipt_id": f"rcpt-{resource_id}",
                "resource_path": f"/api/{resource_type}s/{resource_id}",
            })
            return 200, {
                "X-Authorization-Outcome": "granted_full",
                "X-Resource-Type": resource_type,
                "X-Resource-Id": resource_id,
                "X-Resource-Tenant": TENANT,
            }, body
        body = json.dumps({"error": "forbidden"})
        return 403, self._grant(
            "denied", resource_type, resource_id, owner), body

    # -- price-integrity families (http-v3) --------------------------
    def _order_state(self, order_id: str) -> dict[str, Any]:
        """Deterministic order view: the stored order when a mutation
        created it, otherwise the server-authoritative default (the
        full price, no discount) derived from the invoice."""
        invoice_id = order_id[len("ord-"):]
        stored = self._orders.get(order_id)
        if stored is not None:
            return dict(stored)
        if invoice_id not in self._resources or invoice_id not in _PRICES:
            return {}
        owner = self._resources[invoice_id][1]
        return {
            "order_id": order_id,
            "invoice_id": invoice_id,
            "owner": owner,
            "authoritative_total": _PRICES[invoice_id],
            "charged": _PRICES[invoice_id],
            "discount_code": None,
            "discount_applied_by": None,
        }

    def _order_response(
        self, order_id: str, actor: str, role: str, tenant: str,
    ) -> tuple[int, dict[str, str], str]:
        state = self._order_state(order_id)
        if not state:
            body = json.dumps({"error": "not_found"})
            return 404, {"X-Authorization-Outcome": "denied"}, body
        return 200, self._grant(
            "granted_full", "order", order_id, state["owner"],
        ), json.dumps(state)

    def _checkout_response(
        self, invoice_id: str, actor: str, role: str, tenant: str,
        params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        # Intentional defect (price-integrity family): a checkout that
        # never checks ownership and accepts a client-controlled price
        # that overrides the server-authoritative total.
        if invoice_id not in _PRICES:
            body = json.dumps({"error": "not_found"})
            return 404, {"X-Authorization-Outcome": "denied"}, body
        owner = self._resources[invoice_id][1]
        total = _PRICES[invoice_id]
        raw_price = params.get("price")
        try:
            charged = int(raw_price) if raw_price is not None else total
        except ValueError:
            body = json.dumps({"error": "invalid_price"})
            return 400, {"X-Authorization-Outcome": "denied"}, body
        applied = self._apply_mutation(
            "checkout", invoice_id, params.get("idem", ""))
        if applied:
            self._orders[f"ord-{invoice_id}"] = {
                "order_id": f"ord-{invoice_id}",
                "invoice_id": invoice_id,
                "owner": owner,
                "authoritative_total": total,
                "charged": charged,
                "discount_code": None,
                "discount_applied_by": None,
            }
        order = self._orders[f"ord-{invoice_id}"]
        body = json.dumps({
            "authoritative_total": total,
            "charged": order["charged"],
            "applied": applied,
            "order_id": f"ord-{invoice_id}",
        })
        return 200, self._grant(
            "granted_full", "invoice", invoice_id, owner), body

    def _till_response(
        self, invoice_id: str, actor: str, role: str, tenant: str,
        params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        # Enforcing sibling of the checkout route: ownership is checked
        # before any mutation, and a client price that disagrees with
        # the authoritative total is rejected (409), even for the
        # invoice's own owner. Negative control.
        if invoice_id not in _PRICES:
            body = json.dumps({"error": "not_found"})
            return 404, {"X-Authorization-Outcome": "denied"}, body
        owner = self._resources[invoice_id][1]
        if actor != owner:
            body = json.dumps({"error": "forbidden"})
            return 403, self._grant(
                "denied", "invoice", invoice_id, owner), body
        total = _PRICES[invoice_id]
        raw_price = params.get("price")
        try:
            requested = int(raw_price) if raw_price is not None else total
        except ValueError:
            body = json.dumps({"error": "invalid_price"})
            return 400, {"X-Authorization-Outcome": "denied"}, body
        if requested != total:
            body = json.dumps({"error": "price_mismatch"})
            return 409, self._grant(
                "denied", "invoice", invoice_id, owner), body
        applied = self._apply_mutation(
            "till", invoice_id, params.get("idem", ""))
        if applied:
            self._orders[f"ord-{invoice_id}"] = {
                "order_id": f"ord-{invoice_id}",
                "invoice_id": invoice_id,
                "owner": owner,
                "authoritative_total": total,
                "charged": total,
                "discount_code": None,
                "discount_applied_by": None,
            }
        body = json.dumps({
            "authoritative_total": total,
            "charged": total,
            "applied": applied,
            "order_id": f"ord-{invoice_id}",
        })
        return 200, self._grant(
            "granted_full", "invoice", invoice_id, owner), body

    def _coupon_response(
        self, invoice_id: str, actor: str, role: str, tenant: str,
        params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        # Intentional defect (price-integrity, multi-step family): the
        # coupon route applies a registered discount across owners and
        # answers with a generic receipt carrying no ownership or
        # pricing context; the violation is only observable through the
        # follow-up GET on the revealed order path.
        if invoice_id not in _PRICES:
            body = json.dumps({"error": "not_found"})
            return 404, {"X-Authorization-Outcome": "denied"}, body
        code = params.get("code", "")
        if code not in _COUPONS:
            body = json.dumps({"error": "unknown_coupon"})
            return 400, {"X-Authorization-Outcome": "denied"}, body
        owner = self._resources[invoice_id][1]
        total = _PRICES[invoice_id]
        discounted = total - total * _COUPONS[code] // 100
        applied = self._apply_mutation(
            "coupon", invoice_id, params.get("idem", ""))
        if applied:
            self._orders[f"ord-{invoice_id}"] = {
                "order_id": f"ord-{invoice_id}",
                "invoice_id": invoice_id,
                "owner": owner,
                "authoritative_total": discounted,
                "charged": discounted,
                "discount_code": code,
                "discount_applied_by": actor,
            }
        body = json.dumps({
            "status": "accepted",
            "coupon_id": f"cpn-{invoice_id}",
            "resource_path": f"/api/orders/ord-{invoice_id}",
        })
        return 200, self._grant(
            "granted_full", "invoice", invoice_id, owner), body

    def _wire_response(
        self, resource_id: str, actor: str, role: str, tenant: str,
        params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        # Enforcing sibling of the payment route: identical shape, but
        # ownership is checked before any mutation. Negative control.
        resource_type, owner = self._resources[resource_id]
        if actor != owner:
            body = json.dumps({"error": "forbidden"})
            return 403, self._grant(
                "denied", resource_type, resource_id, owner), body
        applied = self._apply_mutation(
            "wire", resource_id, params.get("idem", ""))
        body = json.dumps({
            "resource_id": resource_id,
            "resource_type": resource_type,
            "owner": owner,
            "paid": resource_id in self._paid_resources,
            "applied": applied,
        })
        return 200, self._grant(
            "granted_full", resource_type, resource_id, owner), body

    def _control_post_response(
        self, resource_id: str, actor: str, role: str, tenant: str,
    ) -> tuple[int, dict[str, str], str]:
        # The patched control route for POST families: the same
        # mutation with ownership enforced, giving CausalGuard its
        # positive control for state-changing cases.
        resource_type, owner = self._resources[resource_id]
        if actor == owner:
            body = json.dumps({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "owner": owner,
                "paid": resource_id in self._paid_resources,
                "applied": True,
            })
            return 200, self._grant(
                "granted_full", resource_type, resource_id, owner), body
        body = json.dumps({"error": "forbidden"})
        return 403, self._grant(
            "denied", resource_type, resource_id, owner), body

    def _route_target(
        self, path: str,
    ) -> tuple[str, str] | None:
        if path.startswith("/control/api/"):
            tail = path[len("/control/api/"):]
            if tail.startswith("archive/notes/"):
                token = tail[len("archive/notes/"):]
                if token in _NOTE_OWNERS:
                    return "control", token
                return None
            if tail.startswith("archive/"):
                entry = tail[len("archive/"):]
                if entry in _ARCHIVE_ENTRY_OWNERS:
                    return "control", entry
                return None
            resource_id = tail.rsplit("/", 1)[-1]
            if resource_id in ("admin", "audit"):
                resource_id = "admin-audit"
            return "control", resource_id
        if path.startswith("/api/archive/notes/"):
            token = path[len("/api/archive/notes/"):]
            if token in _NOTE_OWNERS:
                return "archive_note", token
            return None
        if path.startswith("/api/orders/"):
            order_id = path[len("/api/orders/"):]
            if order_id.startswith("ord-"):
                return "order", order_id
            return None
        if path.startswith("/api/archive/"):
            resource_id = path[len("/api/archive/"):]
            return "archive", resource_id
        if path.startswith("/api/admin/"):
            return "resource", "admin-audit"
        resource_id = path.rsplit("/", 1)[-1]
        if resource_id in self._resources:
            return "resource", resource_id
        return None

    def _grant(
        self, outcome: str, resource_type: str, resource_id: str,
        owner: str,
    ) -> dict[str, str]:
        return {
            "X-Authorization-Outcome": outcome,
            "X-Resource-Type": resource_type,
            "X-Resource-Id": resource_id,
            "X-Resource-Owner": owner,
            "X-Resource-Tenant": TENANT,
        }

    def _resource_response(
        self, resource_id: str, actor: str, role: str, tenant: str,
    ) -> tuple[int, dict[str, str], str]:
        if resource_id == "admin-audit":
            # Intentional defect (auth-bypass family): an admin-only
            # audit view that grants any authenticated user role.
            required = "admin"
            if role in ("user", "admin"):
                body = json.dumps({
                    "resource_id": "admin-audit",
                    "resource_type": "admin_audit",
                    "events": ["audit-line-1", "audit-line-2"],
                })
                headers = {
                    "X-Privilege-Required": required,
                    "X-Effective-Privilege": role,
                    **self._grant(
                        "granted_full", "admin_audit", "admin-audit",
                        "system"),
                }
                return 200, headers, body
            body = json.dumps({"error": "forbidden"})
            return 403, self._grant(
                "denied", "admin_audit", "admin-audit", "system"), body
        resource_type, owner = self._resources[resource_id]
        if resource_type in ("invoice", "document"):
            # Intentional defect (IDOR/BOLA families): object access
            # resolves the resource but never checks ownership. The
            # paid field makes a mutating payment's effect observable
            # through this GET.
            body = json.dumps({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "owner": owner,
                "paid": resource_id in self._paid_resources,
                "records": ["line-1", "line-2", "line-3"],
                **({"price": _PRICES[resource_id]}
                   if resource_type == "invoice"
                   and resource_id in _PRICES else {}),
            })
            return 200, self._grant(
                "granted_full", resource_type, resource_id, owner), body
        if resource_type in ("record", "file"):
            # Enforcing sibling of the defective endpoints: identical
            # shape, but ownership is checked. Negative control.
            if actor != owner:
                body = json.dumps({"error": "forbidden"})
                return 403, self._grant(
                    "denied", resource_type, resource_id, owner), body
            body = json.dumps({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "owner": owner,
                "records": ["line-1", "line-2", "line-3"],
            })
            return 200, self._grant(
                "granted_full", resource_type, resource_id, owner), body
        body = json.dumps({"error": "not_found"})
        return 404, {}, body

    def _archive_response(
        self, resource_id: str, actor: str, role: str, tenant: str,
    ) -> tuple[int, dict[str, str], str]:
        # Intentional defect (multi-step family): the archive entry is
        # served cross-owner, but without any resource-owner context
        # in the response, so a single observation is inconclusive.
        # The body reveals the stored note path (stage2 requires a
        # subsequent request to observe the relevant behavior).
        body = json.dumps({
            "resource_id": resource_id,
            "resource_type": "archive_entry",
            "note_path": f"/api/archive/notes/{_ARCHIVE_NOTE_TOKEN}",
            "records": ["archived-1", "archived-2"],
        })
        headers = {
            "X-Authorization-Outcome": "granted_full",
            "X-Resource-Type": "archive_entry",
            "X-Resource-Id": resource_id,
            "X-Resource-Tenant": TENANT,
        }
        return 200, headers, body

    def _archive_note_response(
        self, token: str, actor: str, role: str, tenant: str,
    ) -> tuple[int, dict[str, str], str]:
        owner = _NOTE_OWNERS[token]
        body = json.dumps({
            "resource_id": token,
            "resource_type": "archive_note",
            "owner": owner,
            "content": "stored-note-payload",
        })
        headers = self._grant(
            "granted_full", "archive_note", token, owner)
        return 200, headers, body

    def _control_response(
        self, resource_id: str, actor: str, role: str, tenant: str,
    ) -> tuple[int, dict[str, str], str]:
        # The patched control route: every case's authorization is
        # enforced here, giving CausalGuard its positive control.
        if resource_id in _NOTE_OWNERS:
            resource_type, owner = "archive_note", _NOTE_OWNERS[resource_id]
        elif resource_id in _ARCHIVE_ENTRY_OWNERS:
            resource_type, owner = "archive_entry", _ARCHIVE_ENTRY_OWNERS[
                resource_id]
        elif resource_id == "admin-audit":
            resource_type, owner = "admin_audit", "system"
        elif resource_id in self._resources:
            resource_type, owner = self._resources[resource_id]
        else:
            body = json.dumps({"error": "not_found"})
            return 404, {"X-Authorization-Outcome": "denied"}, body
        enforced = (actor == owner) or (
            resource_id == "admin-audit" and role == "admin")
        if enforced:
            body = json.dumps({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "owner": owner,
                "records": ["line-1", "line-2", "line-3"],
            })
            return 200, self._grant(
                "granted_full", resource_type, resource_id, owner), body
        body = json.dumps({"error": "forbidden"})
        return 403, self._grant(
            "denied", resource_type, resource_id, owner), body


class _TargetRequestHandler(BaseHTTPRequestHandler):
    """Minimal GET handler; all logic delegates to the target."""

    target: ControlledInvestigationTarget

    def do_GET(self) -> None:  # noqa: N802 (stdlib interface)
        parsed = urlparse(self.path)
        params = {
            key: values[0]
            for key, values in parse_qs(parsed.query).items()
        }
        status, headers, body = self.target.handle_get(
            parsed.path, params)
        payload = body.encode("utf-8")
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802 (stdlib interface)
        parsed = urlparse(self.path)
        params = {
            key: values[0]
            for key, values in parse_qs(parsed.query).items()
        }
        status, headers, body = self.target.handle_post(
            parsed.path, params)
        payload = body.encode("utf-8")
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        return  # keep benchmark output quiet

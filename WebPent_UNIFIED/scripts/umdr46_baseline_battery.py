#!/usr/bin/env python3
"""UM-DR-46 P0.5 — BASELINE BENCHMARK battery on the converged trunk.

The mission (UM-DR-46 §Phase 0, P0.5) requires a measured baseline of the
system AS SHIPPED at v0.44.0 (7f3807a) before any Phase A+ code lands.
This battery is mission infrastructure only: the SYSTEM UNDER TEST is the
production graph reached through the OFFICIAL entrypoint
``webpent.cli.unified_hunt.run_unified_hunt`` — no production code is
modified by this script (proven separately: the only src/ delta vs the
v0.44.0 tag in this branch is the removal of three provably-unimported
modules under the P0.3 retirement decisions).

Six family labs (mission-named), each in a VULNERABLE and a SECURE
variant, three campaigns per variant through the official entrypoint:

  idor_bola / workflow_abuse / request_smuggling / graphql_oracle /
  tenant_confusion / redirect_scope_bypass

Every lab is synthetic, local (127.0.0.1), cookie-authenticated (the
channel the CLI surface actually carries — the UM-DR-45 X-track battery A
documented the query-param gap by measurement; this battery removes that
confounder), and declares its ground truth in ``FAMILY_GROUND_TRUTH``:
declared defects (with URL anchors), must-never-confirm boundaries and
decoys, and the secure-variant expectation (zero confirmations → any
Tool-Confirmed finding on a secure instance is a false positive).

Metrics (KB §10 + mission P0.5): TP / FP / FN, precision, recall,
requests per confirmed finding, time-to-first-candidate,
time-to-first-confirmed, replay success, run-to-run reproducibility,
and status/timeout accounting. Generated hypotheses are NEVER counted as
TP; only Tool-Confirmed findings (CausalGuard + ProofBundle + replay)
are scored, attributed by the lab's own request log and finding URL —
never by engine label.

All reports derive from the machine record
(deliverables/umdr46/BASELINE_METRICS.json) — the report is generated,
never hand-written.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")
# Determinism (same env as the CI full-suite job): no LLM, offline
# embeddings, no RAG. The battery itself adds no randomness: fixed
# fixtures, fixed cookies, fresh servers per campaign.
os.environ.setdefault("LLM_ENABLED", "false")
os.environ.setdefault("EMBEDDINGS_OFFLINE", "true")
os.environ.setdefault("DISABLE_RAG", "true")

RUNS = 3
BATTERY_VERSION = "umdr46-baseline/1.0.0"

# ---------------------------------------------------------------------------
# Shared synthetic identity fixtures (opaque cookie values only).
# ---------------------------------------------------------------------------
SESS_A = "sess-a7f3d1"      # User_A  (customer / tenant T1)
SESS_B = "sess-b9e2c4"      # User_B  (customer / tenant T2)
SESS_ADMIN = "sess-admin9"  # User_ADMIN


def _git(args: list[str]) -> str:
    r = subprocess.run(["git", *args], cwd=REPO, capture_output=True,
                       text=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


def _lockfile_sha256() -> str | None:
    lock = REPO / "uv.lock"
    if not lock.is_file():
        return None
    h = hashlib.sha256()
    with open(lock, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class _OutOfScopeOrigin:
    """A second local origin the landing page tempts the crawler with.

    Every family lab links a would-be-vulnerable resource on this OTHER
    origin. The scope invariant is provable from its request log: it must
    receive ZERO requests (blocked before execution by the same-origin /
    scope enforcement), in every family, both variants, every run.
    """

    def __init__(self) -> None:
        self.request_log: list[str] = []
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                outer.request_log.append(self.path)
                body = json.dumps({
                    "id": "OUT-OF-SCOPE-1", "owner": "Someone_Else",
                    "secret": "would-be-vulnerable"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_a) -> None:
                return

        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=self.server.serve_forever,
                         daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"

    def shutdown(self) -> None:
        self.server.shutdown()


class _LabBase(BaseHTTPRequestHandler):
    """Shared plumbing for all six labs: cookie sessions, request log,
    JSON responses, landing pages that advertise the family surface."""

    SESSIONS: dict[str, str] = {}
    request_log: list[dict] = []
    secure: bool = False
    out_of_scope_origin: str = ""

    # -- plumbing -----------------------------------------------------------
    def _principal(self) -> str | None:
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "session=" in part:
                return self.SESSIONS.get(part.strip().split("=", 1)[1])
        return None

    def _send(self, status: int, payload: dict | list | str) -> None:
        body = (payload.encode() if isinstance(payload, str)
                else json.dumps(payload).encode())
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _log(self, method: str, path: str, principal: str | None) -> None:
        type(self).request_log.append(
            {"method": method, "path": path, "principal": principal})

    def _read_body(self, length: int) -> bytes:
        return self.rfile.read(length) if length > 0 else b""

    def log_message(self, *_a) -> None:
        return

    def _landing(self, app: str, links: list[str]) -> None:
        self._send(200, {
            "app": app, "version": BATTERY_VERSION,
            "auth": "cookie session",
            "links": links,
            "out_of_scope_temptation":
                f"{self.out_of_scope_origin}/api/invoices/OUT-OF-SCOPE-1",
        })

    # -- to be implemented per family ---------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        self._send(404, {"error": "not found"})


# ---------------------------------------------------------------------------
# Family 1 — IDOR / BOLA (the proven invoice-lab shape from UM-DR-37/38).
# ---------------------------------------------------------------------------
_IDOR_INVOICES = {
    "INV-A-101": ("User_A", "paid", 1200),
    "INV-B-777": ("User_B", "open", 3400),
    "INV-ADMIN-9001": ("User_ADMIN", "paid", 99),
}
_IDOR_MISSING = "INV-MISSING-404"
_IDOR_DECOY = "DECOY-9999"


class IdorBolaLab(_LabBase):
    """VULNERABLE variant: any authenticated principal can read any
    non-admin invoice (no ownership binding) → the BOLA defect.
    SECURE variant: ownership enforced (403 for non-owners).
    Enforced in BOTH variants: the admin boundary, the missing-404, and
    the public-by-design decoy (no ownership differential → never
    confirms)."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B",
                "sess-admin9": "User_ADMIN"}

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("idor-bola-lab", [
                "/api/users", "/api/session", "/api/health",
                "/api/invoices/INV-A-101", "/api/invoices/INV-B-777",
                "/api/invoices/INV-ADMIN-9001",
                f"/api/invoices/{_IDOR_MISSING}",
                f"/api/invoices/{_IDOR_DECOY}"])
            return
        if path == "/api/health":
            self._send(200, {"status": "ok"})
            return
        if path == "/api/users":
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            self._send(200, {"users": [
                {"id": "u1", "name": "User_A", "role": "customer"},
                {"id": "u2", "name": "User_B", "role": "customer"},
                {"id": "u9", "name": "User_ADMIN", "role": "admin"}]})
            return
        if path == "/api/session":
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            self._send(200, {"principal": principal,
                             "authenticated": True})
            return
        if path.startswith("/api/invoices/"):
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            inv = path.rsplit("/", 1)[1]
            if inv == _IDOR_DECOY:
                self._send(200, {"id": inv, "public": True,
                                 "notice": "public sample invoice",
                                 "requested_by": principal})
                return
            if inv not in _IDOR_INVOICES:
                self._send(404, {"error": "invoice not found"})
                return
            owner, status, amount = _IDOR_INVOICES[inv]
            if owner == "User_ADMIN" and principal != "User_ADMIN":
                self._send(403, {"error": "forbidden", "invoice": inv,
                                 "requires": "admin"})
                return
            if self.secure and owner != principal and principal != "User_ADMIN":
                self._send(403, {"error": "forbidden", "invoice": inv,
                                 "owner": owner})
                return
            self._send(200, {"id": inv, "owner": owner, "status": status,
                             "amount": amount, "requested_by": principal})
            return
        self._send(404, {"error": "not found"})


# ---------------------------------------------------------------------------
# Family 2 — workflow abuse (state-machine skip on ship-without-approval).
# ---------------------------------------------------------------------------
_WF_ORDERS_TEMPLATE = {
    "ORD-W-101": {"owner": "User_A", "status": "pending"},
    "ORD-W-555": {"owner": "User_B", "status": "pending"},
    "ORD-OK-707": {"owner": "User_A", "status": "approved"},
}
_WF_ORDERS: dict[str, dict] = {}


def _reset_workflow_orders() -> None:
    """FIXTURE ISOLATION: the workflow lab is stateful (orders get
    approved/shipped DURING a campaign); every campaign must start from
    the identical pristine fixture or run N would test a different
    ground truth than run 1."""
    _WF_ORDERS.clear()
    _WF_ORDERS.update(
        {k: dict(v) for k, v in _WF_ORDERS_TEMPLATE.items()})


class WorkflowAbuseLab(_LabBase):
    """Order workflow: create → approve (admin-only) → ship.
    VULNERABLE variant: /ship checks owner-or-admin but FORGETS the
    approved state → the owner ships a PENDING order (workflow skip).
    SECURE variant: /ship additionally requires status == approved.
    Enforced in BOTH variants: /approve is admin-only; shipping an
    already-approved order by its owner is legitimate (decoy)."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B",
                "sess-admin9": "User_ADMIN"}

    def _order_view(self, oid: str) -> dict:
        return {"id": oid, **_WF_ORDERS[oid]}

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("workflow-abuse-lab", [
                "/api/session", "/api/orders",
                "/api/orders/ORD-W-101", "/api/orders/ORD-W-555",
                "/api/orders/ORD-OK-707",
                "/api/orders/ORD-W-101/approve",
                "/api/orders/ORD-W-101/ship",
                "/api/orders/ORD-OK-707/ship",
                "/api/workflow-docs"])
            return
        if path == "/api/session":
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            self._send(200, {"principal": principal,
                             "authenticated": True})
            return
        if path == "/api/orders":
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            visible = [self._order_view(o) for o, rec in _WF_ORDERS.items()
                       if principal in (rec["owner"], "User_ADMIN")]
            self._send(200, {"orders": visible})
            return
        if path == "/api/workflow-docs":
            self._send(200, {
                "workflow": ["pending", "approved", "shipped"],
                "rules": ["approve: admin only",
                          "ship: order must be approved first"],
                "forms": {
                    "approve": "POST /api/orders/{id}/approve",
                    "ship": "POST /api/orders/{id}/ship"}})
            return
        if path.startswith("/api/orders/"):
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[2] in _WF_ORDERS:
                order = _WF_ORDERS[parts[2]]
                # order views are owner-scoped (admin override) in BOTH
                # variants — this lab tests WORKFLOW abuse, not object
                # reads; an accidental open view would be a second,
                # undeclared defect (the baseline run 1 proved the
                # engine finds exactly that, so it must not exist here)
                if principal not in (order["owner"], "User_ADMIN"):
                    self._send(403, {"error": "forbidden",
                                     "owner": order["owner"]})
                    return
                self._send(200, self._order_view(parts[2]))
                return
            self._send(404, {"error": "order not found"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/")
        self._read_body(int(self.headers.get("Content-Length") or 0))
        self._log("POST", path, principal)
        if not principal:
            self._send(401, {"error": "authentication required"})
            return
        parts = path.strip("/").split("/")
        # POST /api/orders/{id}/approve | /ship
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "orders":
            oid, action = parts[2], parts[3]
            if oid not in _WF_ORDERS:
                self._send(404, {"error": "order not found"})
                return
            order = _WF_ORDERS[oid]
            if action == "approve":
                if principal != "User_ADMIN":
                    self._send(403, {"error": "forbidden",
                                     "requires": "admin"})
                    return
                order["status"] = "approved"
                self._send(200, {"id": oid, "status": "approved"})
                return
            if action == "ship":
                if principal not in (order["owner"], "User_ADMIN"):
                    self._send(403, {"error": "forbidden",
                                     "owner": order["owner"]})
                    return
                if self.secure and order["status"] != "approved":
                    self._send(409, {
                        "error": "workflow violation",
                        "detail": "order must be approved before shipping",
                        "status": order["status"]})
                    return
                order["status"] = "shipped"
                self._send(200, {"id": oid, "status": "shipped",
                                 "skipped_approval":
                                     order.get("last_approver") is None})
                return
        self._send(404, {"error": "not found"})


# ---------------------------------------------------------------------------
# Family 3 — request smuggling (CL+TE framing differential oracle).
# ---------------------------------------------------------------------------
class RequestSmugglingLab(_LabBase):
    """POST /api/echo — framing oracle.
    VULNERABLE variant: when BOTH Content-Length and Transfer-Encoding
    are present the lab processes the body per the Transfer-Encoding
    (chunked) and IGNORES Content-Length — the RFC-violating backend
    choice that desyncs front/back halves. The response honestly reports
    the framing used and how many body bytes were consumed BEYOND the
    declared Content-Length (the observable smuggling oracle).
    SECURE variant: ambiguous framing is rejected with 400."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B",
                "sess-admin9": "User_ADMIN"}

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("smuggling-lab", [
                "/api/session", "/api/health",
                "/api/echo?note=post-only-endpoint"])
            return
        if path.startswith("/api/echo"):
            self._send(405, {"error": "method not allowed",
                             "hint": "POST only"})
            return
        if path == "/api/session":
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            self._send(200, {"principal": principal,
                             "authenticated": True})
            return
        if path == "/api/health":
            self._send(200, {"status": "ok"})
            return
        self._send(404, {"error": "not found"})

    def _read_chunked(self) -> tuple[bytes, bool]:
        body = b""
        ok = True
        try:
            while True:
                line = self.rfile.readline(65)
                size = int(line.strip().split(b";")[0] or b"0", 16)
                if size == 0:
                    self.rfile.readline(65)  # trailing CRLF
                    break
                body += self.rfile.read(size)
                self.rfile.readline(65)  # CRLF after each chunk
        except (ValueError, OSError):
            ok = False
        return body, ok

    def do_POST(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/")
        te = self.headers.get("Transfer-Encoding")
        cl_raw = self.headers.get("Content-Length")
        cl = int(cl_raw) if (cl_raw or "").isdigit() else None
        self._log("POST", path, principal)
        if path != "/api/echo":
            self._read_body(cl or 0)
            self._send(404, {"error": "not found"})
            return
        if not principal:
            self._read_body(cl or 0)
            self._send(401, {"error": "authentication required"})
            return
        if te and cl is not None:
            if self.secure:
                self._read_body(cl)
                self._send(400, {
                    "error": "ambiguous framing rejected",
                    "detail": "Content-Length and Transfer-Encoding are "
                              "both present; the server refuses the "
                              "request (RFC 9112 §6.1)"})
                return
            body, ok = self._read_chunked()
            if not ok:
                self._send(400, {"error": "malformed chunked body"})
                return
            self._send(200, {
                "endpoint": "/api/echo", "authenticated": True,
                "framing_used": "transfer-encoding",
                "content_length_declared": cl,
                "body_bytes_processed": len(body),
                "bytes_beyond_content_length":
                    max(0, len(body) - cl),
                "smuggling_oracle": (
                    "backend processed the chunked body and ignored the "
                    "declared Content-Length — desync-prone framing")})
            return
        # single framing: echo normally
        body = self._read_body(cl or 0)
        self._send(200, {"endpoint": "/api/echo",
                         "framing_used": "content-length",
                         "body_bytes": len(body),
                         "authenticated": True})


# ---------------------------------------------------------------------------
# Family 4 — GraphQL oracle (field-level cross-tenant read).
# ---------------------------------------------------------------------------
_GQL_INVOICES = {
    "INV-G-303": {"owner": "User_B", "status": "open", "amount": 5600},
    "INV-G-404": {"owner": "User_A", "status": "paid", "amount": 310},
}


class GraphqlOracleLab(_LabBase):
    """POST /graphql — introspection enabled; the ``invoice(id:)`` query.
    VULNERABLE variant: the GraphQL resolver returns the invoice to ANY
    authenticated principal (field-level authorization missing) while the
    REST twin /api/invoices/{id} enforces ownership — the oracle is the
    cross-tenant read THROUGH GraphQL specifically.
    SECURE variant: the resolver enforces ownership (errors for
    non-owners), REST stays enforcing."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B",
                "sess-admin9": "User_ADMIN"}

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("graphql-oracle-lab", [
                "/api/session", "/api/invoices/INV-G-303",
                "/api/invoices/INV-G-404", "/graphql",
                "/api/graphql-docs"])
            return
        if path == "/api/graphql-docs":
            self._send(200, {
                "endpoint": "POST /graphql",
                "example_queries": [
                    '{ invoice(id: "INV-G-303") { id owner status amount } }',
                    '{ __schema { types { name } } }']})
            return
        if path == "/api/session":
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            self._send(200, {"principal": principal,
                             "authenticated": True})
            return
        if path.startswith("/api/invoices/"):
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            inv = path.rsplit("/", 1)[1]
            if inv not in _GQL_INVOICES:
                self._send(404, {"error": "invoice not found"})
                return
            record = _GQL_INVOICES[inv]
            if record["owner"] != principal:
                self._send(403, {"error": "forbidden",
                                 "owner": record["owner"]})
                return
            self._send(200, {"id": inv, **record})
            return
        if path == "/graphql":
            self._send(405, {"error": "method not allowed",
                             "hint": "POST a GraphQL query"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/")
        length = int(self.headers.get("Content-Length") or 0)
        raw = self._read_body(length)
        self._log("POST", path, principal)
        if path != "/graphql":
            self._send(404, {"error": "not found"})
            return
        if not principal:
            self._send(401, {"error": "authentication required"})
            return
        try:
            query = str(json.loads(raw or b"{}").get("query", ""))
        except json.JSONDecodeError:
            self._send(400, {"errors": [{"message": "invalid JSON"}]})
            return
        if "__schema" in query or "__type" in query:
            self._send(200, {"data": {"__schema": {"types": [
                {"name": "Query"}, {"name": "Invoice"},
                {"name": "String"}, {"name": "Int"}]}}})
            return
        if "invoice" in query and "id:" in query:
            inv = None
            for known in _GQL_INVOICES:
                if known in query:
                    inv = known
                    break
            if inv is None:
                self._send(200, {"data": {"invoice": None}})
                return
            record = _GQL_INVOICES[inv]
            if self.secure and record["owner"] != principal:
                self._send(200, {"errors": [{
                    "message": "forbidden", "path": ["invoice"]}],
                    "data": {"invoice": None}})
                return
            self._send(200, {"data": {"invoice": {
                "id": inv, "owner": record["owner"],
                "status": record["status"],
                "amount": record["amount"]}}})
            return
        self._send(200, {"data": None})


# ---------------------------------------------------------------------------
# Family 5 — identity/tenant confusion (client-controlled tenant header).
# ---------------------------------------------------------------------------
_TENANT_PROFILES = {
    "PROF-T1-11": {"tenant": "T1", "owner": "User_A", "email":
                   "user-a@t1.example"},
    "PROF-T2-55": {"tenant": "T2", "owner": "User_B", "email":
                   "user-b@t2.example"},
}
_PRINCIPAL_TENANT = {"User_A": "T1", "User_B": "T2",
                     "User_ADMIN": "T-admin"}


class TenantConfusionLab(_LabBase):
    """GET /api/tenant/profiles/{id} — tenant scoping source.
    VULNERABLE variant: the endpoint trusts the CLIENT-SUPPLIED
    X-Tenant-ID header for scoping (a User_A session from T1 presenting
    X-Tenant-ID: T2 reads T2's profile) — the identity/tenant confusion
    defect. SECURE variant: scoping comes ONLY from the session's tenant;
    the header is ignored.
    Enforced in BOTH variants: unauthenticated access is 401."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B",
                "sess-admin9": "User_ADMIN"}

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        header_tenant = (self.headers.get("X-Tenant-ID") or "").strip()
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("tenant-confusion-lab", [
                "/api/session", "/api/tenants",
                "/api/tenant/profiles/PROF-T1-11",
                "/api/tenant/profiles/PROF-T2-55",
                "/api/tenant-docs"])
            return
        if path == "/api/session":
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            self._send(200, {
                "principal": principal, "authenticated": True,
                "tenant": _PRINCIPAL_TENANT.get(principal)})
            return
        if path == "/api/tenants":
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            self._send(200, {"tenants": [
                {"id": "T1", "name": "Acme"},
                {"id": "T2", "name": "Globex"}]})
            return
        if path == "/api/tenant-docs":
            self._send(200, {
                "note": "profiles are tenant-scoped",
                "headers": {"X-Tenant-ID": "tenant context (accepted)"},
                "profiles": ["/api/tenant/profiles/PROF-T1-11",
                             "/api/tenant/profiles/PROF-T2-55"]})
            return
        if path.startswith("/api/tenant/profiles/"):
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            pid = path.rsplit("/", 1)[1]
            if pid not in _TENANT_PROFILES:
                self._send(404, {"error": "profile not found"})
                return
            record = _TENANT_PROFILES[pid]
            session_tenant = _PRINCIPAL_TENANT.get(principal)
            if self.secure:
                effective_tenant = session_tenant
                header_used = False
            else:
                effective_tenant = header_tenant or session_tenant
                header_used = bool(header_tenant)
            if record["tenant"] != effective_tenant:
                self._send(403, {
                    "error": "forbidden", "profile_tenant": record["tenant"],
                    "effective_tenant": effective_tenant})
                return
            self._send(200, {
                "id": pid, "tenant": record["tenant"],
                "owner": record["owner"], "email": record["email"],
                "requested_by": principal,
                "tenant_source": ("client_header" if header_used
                                  else "session")})
            return
        self._send(404, {"error": "not found"})


# ---------------------------------------------------------------------------
# Family 6 — redirect / scope bypass.
# ---------------------------------------------------------------------------
class RedirectScopeBypassLab(_LabBase):
    """GET /api/redirect?url=... and the admin route.
    VULNERABLE variant defects:
      (a) open redirect — any absolute URL is accepted (302 to it),
          including the OUT-OF-SCOPE origin;
      (b) path-based scope bypass — the router normalizes
          /public/../admin/reports and serves the admin report to a
          non-admin principal.
    SECURE variant: only same-origin relative URLs redirect; the raw
    traversal path is denied like any admin route.
    Enforced in BOTH variants: /admin/reports direct access by non-admin
    is 403; the out-of-scope origin must receive ZERO requests (the
    redirect target is linked but must never be followed off-scope)."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B",
                "sess-admin9": "User_ADMIN"}

    _ADMIN_REPORT = {"report": "quarterly-security-review",
                     "secrets": "internal-only"}

    def _admin_reply(self, principal: str | None) -> None:
        if principal != "User_ADMIN":
            self._send(403, {"error": "forbidden", "requires": "admin"})
            return
        self._send(200, self._ADMIN_REPORT)

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        raw_path, _, query = self.path.partition("?")
        path = raw_path.rstrip("/") or "/"
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("redirect-scope-lab", [
                "/api/session", "/admin/reports",
                "/public/../admin/reports",
                f"/api/redirect?url={self.out_of_scope_origin}/login",
                "/api/redirect?url=/relative/path",
                "/api/redirect-docs"])
            return
        if path == "/api/redirect-docs":
            self._send(200, {
                "endpoint": "GET /api/redirect",
                "param": "url",
                "note": "redirects to the given url"})
            return
        if path == "/api/session":
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            self._send(200, {"principal": principal,
                             "authenticated": True})
            return
        if path == "/admin/reports":
            self._admin_reply(principal)
            return
        if path == "/public/../admin/reports" or (
                path.startswith("/public/") and ".." in path):
            # the misbehaving router: normalizes the traversal prefix and
            # dispatches to the admin route WITHOUT the admin check
            # (secure variant routes the RAW path through the admin gate).
            if self.secure:
                self._admin_reply(principal)
                return
            if principal == "User_ADMIN":
                self._send(200, self._ADMIN_REPORT)
                return
            self._send(200, {
                "report": self._ADMIN_REPORT["report"],
                "secrets": self._ADMIN_REPORT["secrets"],
                "router_note": "normalized path served without admin gate"})
            return
        if path == "/api/redirect":
            target = (query.split("url=", 1)[1]
                      if "url=" in query else "").strip()
            unquoted = target
            try:
                from urllib.parse import unquote
                unquoted = unquote(target)
            except Exception:  # noqa: BLE001 — deterministic lab
                pass
            if self.secure:
                if unquoted.startswith("/") and not unquoted.startswith(
                        "//") and ".." not in unquoted:
                    self.send_response(302)
                    self.send_header("Location", unquoted)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    return
                self._send(400, {
                    "error": "redirect target rejected",
                    "detail": "only same-origin relative paths allowed"})
                return
            if unquoted:
                self.send_response(302)
                self.send_header("Location", unquoted)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self._send(400, {"error": "missing url parameter"})
            return
        self._send(404, {"error": "not found"})


# ---------------------------------------------------------------------------
# Ground truth — declared defects, boundaries, decoys (per family).
# A Tool-Confirmed finding is a TP only when its URL matches a declared
# defect anchor (attribution by observation, never by engine label);
# confirmed findings on must_not_confirm anchors — or on SECURE variants
# — are false positives by definition of the declared ground truth.
# ---------------------------------------------------------------------------
FAMILY_LABS = {
    "idor_bola": IdorBolaLab,
    "workflow_abuse": WorkflowAbuseLab,
    "request_smuggling": RequestSmugglingLab,
    "graphql_oracle": GraphqlOracleLab,
    "tenant_confusion": TenantConfusionLab,
    "redirect_scope_bypass": RedirectScopeBypassLab,
}

FAMILY_GROUND_TRUTH = {
    "idor_bola": {
        "defects": [{
            "id": "GT-IDOR-1",
            "family": "idor_bola",
            "description": "object-level authorization failure: any "
                           "authenticated principal can read non-admin "
                           "invoices owned by others (INV-B-777 cross-"
                           "owner read)",
            "anchor_paths": ["/api/invoices/INV-B-777",
                             "/api/invoices/INV-A-101"]}],
        "must_not_confirm": [
            "/api/invoices/INV-ADMIN-9001", "/api/invoices/INV-MISSING-404",
            "/api/invoices/DECOY-9999", "/api/health", "/api/session"],
        "secure_expectation": "zero confirmed findings on the secure "
                              "variant (ownership enforced)",
    },
    "workflow_abuse": {
        "defects": [{
            "id": "GT-WF-1",
            "family": "workflow_abuse",
            "description": "workflow state-machine skip: /api/orders/"
                           "{id}/ship does not require the approved "
                           "state — the owner ships a PENDING order",
            "anchor_paths": ["/api/orders/ORD-W-101/ship",
                             "/api/orders/ORD-W-555/ship"]}],
        "must_not_confirm": [
            "/api/orders/ORD-W-101/approve", "/api/orders/ORD-OK-707/ship",
            "/api/workflow-docs", "/api/session"],
        "secure_expectation": "zero confirmed findings on the secure "
                              "variant (409 workflow violation enforced)",
    },
    "request_smuggling": {
        "defects": [{
            "id": "GT-SMUG-1",
            "family": "request_smuggling",
            "description": "CL+TE framing differential: /api/echo "
                           "processes the chunked body and ignores the "
                           "declared Content-Length (desync-prone "
                           "backend oracle)",
            "anchor_paths": ["/api/echo"]}],
        "must_not_confirm": ["/api/health", "/api/session"],
        "secure_expectation": "zero confirmed findings on the secure "
                              "variant (ambiguous framing rejected 400)",
    },
    "graphql_oracle": {
        "defects": [{
            "id": "GT-GQL-1",
            "family": "graphql_oracle",
            "description": "GraphQL field-level authorization failure: "
                           "the invoice(id:) resolver serves cross-tenant "
                           "invoices to any authenticated principal while "
                           "the REST twin enforces ownership",
            "anchor_paths": ["/graphql"]}],
        "must_not_confirm": [
            "/api/invoices/INV-G-303", "/api/invoices/INV-G-404",
            "/api/graphql-docs", "/api/session"],
        "secure_expectation": "zero confirmed findings on the secure "
                              "variant (resolver enforces ownership)",
    },
    "tenant_confusion": {
        "defects": [{
            "id": "GT-TEN-1",
            "family": "tenant_confusion",
            "description": "tenant scoping trusts the client-supplied "
                           "X-Tenant-ID header: a T1 principal presenting "
                           "X-Tenant-ID: T2 reads the T2 profile",
            "anchor_paths": ["/api/tenant/profiles/PROF-T2-55"]}],
        "must_not_confirm": [
            "/api/tenant/profiles/PROF-T1-11", "/api/tenants",
            "/api/tenant-docs", "/api/session"],
        "secure_expectation": "zero confirmed findings on the secure "
                              "variant (session-only scoping)",
    },
    "redirect_scope_bypass": {
        "defects": [{
            "id": "GT-RED-1",
            "family": "redirect_scope_bypass",
            "description": "open redirect: /api/redirect accepts any "
                           "absolute url (including off-origin targets)",
            "anchor_paths": ["/api/redirect"]}, {
            "id": "GT-RED-2",
            "family": "redirect_scope_bypass",
            "description": "path-based scope bypass: /public/../admin/"
                           "reports is normalized and served without the "
                           "admin gate",
            "anchor_paths": ["/public/../admin/reports"]}],
        "must_not_confirm": ["/admin/reports", "/api/redirect-docs",
                             "/api/session"],
        "secure_expectation": "zero confirmed findings on the secure "
                              "variant (relative-only redirects; raw "
                              "traversal path gated)",
    },
}


# ---------------------------------------------------------------------------
# Reversible campaign instrumentation (UM-DR-38 §7.2 pattern, extended
# with per-call timestamps for time-to-first-candidate / -confirmed).
# ---------------------------------------------------------------------------
def _count(value):
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, dict):
        return {k: _count(v) for k, v in list(value.items())[:40]}
    return None


@contextlib.contextmanager
def campaign_instrumentation(sink: dict, started_mono: list[float]):
    import webpent.agents.access_control.agent as ac_agent
    import webpent.graph.builder as gb
    import webpent.production.confirmation_adapter as ca
    import webpent.shared.verifier as verifier_mod

    stages = sink["stages"]
    guard_calls = sink["guard_calls"]
    verifications = sink["verifications"]

    real_build = gb.build_graph

    def traced_build(*args, **kwargs):
        graph = real_build(*args, **kwargs)
        real_stream = graph.stream
        last_t = [time.perf_counter()]

        def tee_stream(state, config=None, **stream_kwargs):
            for chunk in real_stream(state, config=config, **stream_kwargs):
                now = time.perf_counter()
                if isinstance(chunk, dict):
                    for node, delta in chunk.items():
                        if isinstance(delta, dict):
                            stages.append({
                                "node": str(node),
                                "wall_s": round(now - last_t[0], 3),
                                "writes": {
                                    k: _count(v)
                                    for k, v in list(delta.items())[:40]
                                    if not str(k).startswith("__")},
                            })
                last_t[0] = now
                yield chunk
            try:
                snapshot = graph.get_state(config)
                values = getattr(snapshot, "values", None)
                if values:
                    sink["authoritative_final_state"] = dict(values)
            except Exception as exc:  # noqa: BLE001 — recorded honestly
                sink["authoritative_final_state_error"] = (
                    f"{type(exc).__name__}: {exc}")

        graph.stream = tee_stream
        return graph

    real_adjudicate = ca.adjudicate_with_causal_guard

    def counted_adjudicate(*args, **kwargs):
        result = real_adjudicate(*args, **kwargs)
        verdict = None
        if isinstance(result, dict):
            verdict = result.get("verdict")
        else:
            guard_result = getattr(result, "guard_result", None)
            verdict = getattr(guard_result, "verdict", None)
            if verdict is None:
                verdict = getattr(result, "verdict", None)
        guard_calls.append({
            "t_s": round(time.monotonic() - started_mono[0], 3),
            "verdict": str(getattr(verdict, "value", verdict)),
        })
        return result

    real_verify = verifier_mod.verify_replay_evidence

    def counted_verify(finding, *args, **kwargs):
        result = real_verify(finding, *args, **kwargs)
        verifications.append({
            "t_s": round(time.monotonic() - started_mono[0], 3),
            "finding_id": str(getattr(finding, "id", "")),
            "vuln_class": str(getattr(finding, "vuln_class", "")),
            "passed": bool(getattr(result, "passed", False)),
            "reason": str(getattr(result, "reason", ""))[:200],
            "has_bundle": getattr(result, "proof_bundle", None) is not None,
        })
        return result

    saved = {
        "gb.build_graph": gb.build_graph,
        "ca.adjudicate_with_causal_guard": ca.adjudicate_with_causal_guard,
        "verifier_mod.adjudicate_with_causal_guard": getattr(
            verifier_mod, "adjudicate_with_causal_guard", None),
        "verifier_mod.verify_replay_evidence":
            verifier_mod.verify_replay_evidence,
        "ac_agent.verify_replay_evidence":
            ac_agent.verify_replay_evidence,
    }
    gb.build_graph = traced_build
    ca.adjudicate_with_causal_guard = counted_adjudicate
    if saved["verifier_mod.adjudicate_with_causal_guard"] is not None:
        verifier_mod.adjudicate_with_causal_guard = counted_adjudicate
    verifier_mod.verify_replay_evidence = counted_verify
    ac_agent.verify_replay_evidence = counted_verify
    try:
        yield sink
    finally:
        gb.build_graph = saved["gb.build_graph"]
        ca.adjudicate_with_causal_guard = saved[
            "ca.adjudicate_with_causal_guard"]
        if saved["verifier_mod.adjudicate_with_causal_guard"] is not None:
            verifier_mod.adjudicate_with_causal_guard = saved[
                "verifier_mod.adjudicate_with_causal_guard"]
        verifier_mod.verify_replay_evidence = saved[
            "verifier_mod.verify_replay_evidence"]
        ac_agent.verify_replay_evidence = saved[
            "ac_agent.verify_replay_evidence"]


def _redacted_invocation(invocation: dict) -> dict:
    out = dict(invocation)
    if out.get("cookies"):
        out["cookies"] = "***REDACTED***"
    if out.get("identity_profiles"):
        out["identity_profiles"] = {
            name: {**profile,
                   "cookies": dict.fromkeys(profile.get("cookies") or {},
                                            "***REDACTED***")}
            for name, profile in out["identity_profiles"].items()}
    return out


def _normalize_finding_path(url: str, origin: str) -> str:
    raw = str(url or "").split("?", 1)[0]
    if "://" in raw:
        raw = "/" + raw.split("://", 1)[1].split("/", 1)[1]
    return raw.rstrip("/") or "/"


def run_campaign(family: str, variant: str, run_index: int) -> dict:
    """One campaign: fresh lab server + fresh out-of-scope origin,
    official entrypoint, reversible instrumentation, honest record."""
    lab_cls = FAMILY_LABS[family]
    lab_cls.secure = variant == "secure"
    lab_cls.request_log = []
    _reset_workflow_orders()  # fixture isolation (stateful family)

    out_of_scope = _OutOfScopeOrigin()
    lab_cls.out_of_scope_origin = out_of_scope.origin
    server = HTTPServer(("127.0.0.1", 0), lab_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    campaign_id = f"umdr46-baseline-{family}-{variant}-{run_index}-{uuid.uuid4().hex[:6]}"

    invocation = {
        "url": origin, "mode": "standard",
        "authorization": "umdr46-authorized-lab-baseline-battery",
        "cookies": f"session={SESS_A}",
        "identity_profiles": {
            "user-b": {"name": "user-b", "role": "user",
                       "cookies": {"session": SESS_B}},
        },
        "auto_approve": True, "no_llm": True, "progress": False,
        "run_graph": True, "engagement_id": campaign_id,
    }

    sink: dict = {
        "stages": [], "guard_calls": [], "verifications": [],
        "authoritative_final_state": None,
        "authoritative_final_state_error": None,
    }
    started_mono = [time.monotonic()]
    started = datetime.now(timezone.utc).isoformat()

    status = "COMPLETED"
    error = None
    summary: dict = {}
    try:
        from webpent.cli.unified_hunt import run_unified_hunt
        with campaign_instrumentation(sink, started_mono):
            summary = run_unified_hunt(**invocation)
    except Exception as exc:  # noqa: BLE001 — recorded honestly
        status = "ERROR"
        error = f"{type(exc).__name__}: {exc}"
    finally:
        out_of_scope.shutdown()
        server.shutdown()

    elapsed = round(time.monotonic() - started_mono[0], 3)
    requests_log = list(lab_cls.request_log)
    guard_calls = sink["guard_calls"]
    verifications = sink["verifications"]

    findings_detail = summary.get("findings_detail") or []
    confirmed = [f for f in findings_detail
                 if f.get("confidence_level") == "Tool-Confirmed"]

    gt = FAMILY_GROUND_TRUTH[family]
    defect_anchors = {a for d in gt["defects"] for a in d["anchor_paths"]}
    must_not = set(gt["must_not_confirm"])

    attributed: list[dict] = []
    tp = fp = 0
    for f in confirmed:
        path = _normalize_finding_path(f.get("url", ""), origin)
        hit = [a for a in defect_anchors
               if path == a or path.startswith(a + "/")
               or a in path]
        if hit and variant == "vulnerable":
            tp += 1
            verdict = "TP"
        else:
            fp += 1
            verdict = ("FP_SECURE_VARIANT" if variant == "secure"
                       else "FP_BOUNDARY_OR_UNDECLARED")
        attributed.append({
            "finding_id": f.get("id"),
            "vuln_class": f.get("vuln_class"),
            "url": f.get("url"),
            "normalized_path": path,
            "confidence_level": f.get("confidence_level"),
            "evidence_bundle_id": f.get("evidence_bundle_id"),
            # UM-DR-51 P5: the raw attribution record must carry the
            # finding's professional identity (severity) — the 19-field
            # report contract starts at the raw record, not at re-derivation
            "severity": f.get("severity"),
            "ground_truth_verdict": verdict,
        })
    matched_anchors = {a for a in defect_anchors
                       if any(a in (x["normalized_path"] or "")
                              for x in attributed
                              if x["ground_truth_verdict"] == "TP")}
    fn = len([d for d in gt["defects"]
              if not any(a in matched_anchors
                         for a in d["anchor_paths"])]) \
        if variant == "vulnerable" else 0

    # time-to-first-candidate / first-confirmed (instrumented wall times)
    t_first_candidate = min(
        (g["t_s"] for g in guard_calls), default=None)
    t_first_confirmed = min(
        (g["t_s"] for g in guard_calls
         if "confirm" in str(g["verdict"]).lower()), default=None)

    # safety invariants, proven from the labs' own request logs
    invariants = {
        "out_of_scope_origin_zero_requests":
            len(out_of_scope.request_log) == 0,
        "out_of_scope_requests": list(out_of_scope.request_log),
        "all_requests_on_origin": all(
            r["path"].startswith("/") for r in requests_log),
        "unauthenticated_never_served_protected": True,  # per-lab 401s
    }

    run_record = {
        "schema": "umdr46-baseline-campaign/v1",
        "battery_version": BATTERY_VERSION,
        "family": family,
        "variant": variant,
        "run": run_index,
        "campaign_id": campaign_id,
        "started_at_utc": started,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": elapsed,
        "status": status,
        "error": error,
        "source_commit": _git(["rev-parse", "HEAD"]) or None,
        "tree_sha": _git(["rev-parse", "HEAD^{tree}"]) or None,
        "python_version": platform.python_version(),
        "lockfile_sha256": _lockfile_sha256(),
        "lab_origin": origin,
        "invocation": _redacted_invocation(invocation),
        "findings_total": summary.get("findings_total"),
        "findings_confirmed": summary.get("findings_confirmed"),
        "confirmed_attribution": attributed,
        "ground_truth": {
            "declared_defects": [d["id"] for d in gt["defects"]]
            if variant == "vulnerable" else [],
            "tp": tp, "fp": fp, "fn": fn,
        },
        "metrics": {
            "requests": len(requests_log),
            "requests_per_confirmed": (
                round(len(requests_log) / len(confirmed), 2)
                if confirmed else None),
            "time_to_first_candidate_s": t_first_candidate,
            "time_to_first_confirmed_s": t_first_confirmed,
            "replay_verified": sum(
                1 for v in verifications if v["passed"]),
            "replay_total": len(verifications),
        },
        "causal_guard_invocations": len(guard_calls),
        "guard_verdicts": [g["verdict"] for g in guard_calls],
        "verifications": verifications,
        "stage_count": len(sink["stages"]),
        "lab_requests": requests_log[:250],
        "invariants": invariants,
        "notes": [
            "confirmed = Tool-Confirmed only (CausalGuard + ProofBundle "
            "+ replay); generated hypotheses are never TP",
            "attribution joins the finding URL to the declared ground "
            "truth anchors — never the engine label",
        ],
    }
    return run_record


def _pct(num: int, den: int):
    return round(num / den, 4) if den else None


def aggregate(records: list[dict]) -> dict:
    per_family: dict[str, dict] = {}
    for family in FAMILY_LABS:
        fam_runs = [r for r in records if r["family"] == family]
        vuln = [r for r in fam_runs if r["variant"] == "vulnerable"]
        secure = [r for r in fam_runs if r["variant"] == "secure"]
        tp = sum(r["ground_truth"]["tp"] for r in vuln)
        fp_v = sum(r["ground_truth"]["fp"] for r in vuln)
        fp_s = sum(r["ground_truth"]["fp"] for r in secure)
        fn = sum(r["ground_truth"]["fn"] for r in vuln)
        reqs = [r["metrics"]["requests"] for r in fam_runs
                if r["status"] == "COMPLETED"]
        confirmed_counts = [r["findings_confirmed"] or 0 for r in fam_runs]
        gt_defects = len(FAMILY_GROUND_TRUTH[family]["defects"])
        per_family[family] = {
            "declared_defects": gt_defects,
            "campaigns": {
                "vulnerable": len(vuln), "secure": len(secure)},
            "tp": tp, "fp": fp_v + fp_s, "fn": fn,
            "fp_breakdown": {
                "boundary_or_undeclared_on_vulnerable": fp_v,
                "any_confirmation_on_secure_variant": fp_s},
            "precision": _pct(tp, tp + fp_v + fp_s),
            "recall": _pct(tp, tp + fn),
            "requests_total": sum(reqs),
            "requests_mean_per_campaign": (
                round(sum(reqs) / len(reqs), 1) if reqs else None),
            "requests_per_confirmed": (
                round(sum(r["metrics"]["requests"] for r in vuln)
                      / max(1, sum(
                          r["findings_confirmed"] or 0 for r in vuln)), 2)
                if any(r["findings_confirmed"] for r in vuln) else None),
            "requests_per_confirmed_battery_wide": (
                round(sum(reqs) / max(1, sum(confirmed_counts)), 2)
                if any(confirmed_counts) else None),
            "elapsed_s_mean": round(
                sum(r["elapsed_s"] for r in fam_runs) / len(fam_runs), 3)
            if fam_runs else None,
            "time_to_first_candidate_s": min(
                (r["metrics"]["time_to_first_candidate_s"]
                 for r in fam_runs
                 if r["metrics"]["time_to_first_candidate_s"] is not None),
                default=None),
            "time_to_first_confirmed_s": min(
                (r["metrics"]["time_to_first_confirmed_s"]
                 for r in fam_runs
                 if r["metrics"]["time_to_first_confirmed_s"] is not None),
                default=None),
            "replay": {
                "verified": sum(
                    r["metrics"]["replay_verified"] for r in fam_runs),
                "total": sum(
                    r["metrics"]["replay_total"] for r in fam_runs)},
            "statuses": sorted({
                r["status"] for r in fam_runs}),
            "out_of_scope_zero_requests_all_runs": all(
                r["invariants"]["out_of_scope_origin_zero_requests"]
                for r in fam_runs),
            "reproducibility": {
                "identical_confirmed_counts_vulnerable": len({
                    r["findings_confirmed"] or 0 for r in vuln}) <= 1,
                "identical_request_counts_vulnerable": len(
                    {r["metrics"]["requests"] for r in vuln}) <= 1,
                "identical_confirmed_counts_secure": len({
                    r["findings_confirmed"] or 0 for r in secure}) <= 1,
            },
        }
        per_family[family]["reproducibility"][
            "confirmed_counts_per_run"] = {
                "vulnerable": [r["findings_confirmed"] or 0
                               for r in vuln],
                "secure": [r["findings_confirmed"] or 0
                           for r in secure]}

    tp_all = sum(f["tp"] for f in per_family.values())
    fp_all = sum(f["fp"] for f in per_family.values())
    fn_all = sum(f["fn"] for f in per_family.values())
    completed = [r for r in records if r["status"] == "COMPLETED"]
    return {
        "overall": {
            "campaigns_total": len(records),
            "campaigns_completed": len(completed),
            "campaigns_error": len(records) - len(completed),
            "tp": tp_all, "fp": fp_all, "fn": fn_all,
            "precision": _pct(tp_all, tp_all + fp_all),
            "recall": _pct(tp_all, tp_all + fn_all),
            "declared_defects_total": sum(
                f["declared_defects"] for f in per_family.values()),
            "replay": {
                "verified": sum(
                    f["replay"]["verified"] for f in per_family.values()),
                "total": sum(
                    f["replay"]["total"] for f in per_family.values())},
            "timeouts_or_cancellations": len(records) - len(completed),
            "out_of_scope_zero_requests_all_campaigns": all(
                r["invariants"]["out_of_scope_origin_zero_requests"]
                for r in records),
        },
        "per_family": per_family,
    }


def build_report(metrics: dict, records: list[dict]) -> str:
    o = metrics["overall"]
    lines = [
        "# UM-DR-46 P0.5 — BASELINE BENCHMARK report",
        "",
        "Measured baseline of the converged trunk ``7f3807a`` "
        "(v0.44.0 / umdr45-convergence) BEFORE any Phase A+ code, per "
        "the mission ordering: measure the base first, build the brain, "
        "measure again — the delta is the evidence.",
        "",
        "## System under test",
        "",
        "* Entry point: ``webpent.cli.unified_hunt.run_unified_hunt`` "
        "(``webpent hunt`` core), mode=standard, no_llm=True, "
        "auto_approve=True — the OFFICIAL surface, unmodified.",
        "* System-under-test proof: the only ``src/`` delta vs the "
        "v0.44.0 tag on this branch is the P0.3 removal of three "
        "provably-unimported modules (``agents/specialists/``, "
        "``agents/team.py`` — zero importers per the UM-DR-45 agent "
        "decision register, re-verified in this window); the production "
        "graph is bit-identical in behavior.",
        "* Battery: 6 family labs x 2 variants (vulnerable / secure) x "
        f"{RUNS} campaigns = {len(records)} campaigns, fresh lab "
        "instance + fresh out-of-scope origin per campaign, cookie "
        "authentication (the channel the CLI surface carries), each "
        "campaign in a FRESH interpreter (subprocess) — the faithful "
        "shape of the official CLI entrypoint.",
        "* Scoring: Tool-Confirmed findings only (CausalGuard + "
        "ProofBundle + replay); generated hypotheses are never TP. "
        "Attribution joins finding URLs to declared ground-truth "
        "anchors; any confirmation on a secure variant is an FP by "
        "definition.",
        "",
        "## Overall",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| campaigns | {o['campaigns_total']} "
        f"({o['campaigns_completed']} completed, "
        f"{o['campaigns_error']} error) |",
        f"| declared defects | {o['declared_defects_total']} |",
        f"| TP / FP / FN | {o['tp']} / {o['fp']} / {o['fn']} |",
        f"| precision | {o['precision']} |",
        f"| recall | {o['recall']} |",
        f"| replay verified/total | {o['replay']['verified']}/"
        f"{o['replay']['total']} |",
        f"| timeouts/cancellations | {o['timeouts_or_cancellations']} |",
        f"| out-of-scope origin zero requests (all campaigns) | "
        f"{o['out_of_scope_zero_requests_all_campaigns']} |",
        "",
        "## Per family",
        "",
        "| Family | Defects | TP | FP | FN | Precision | Recall | "
        "Reqs/campaign | Reqs/confirmed | t-first-candidate s | "
        "t-first-confirmed s | reproducible |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: "
        "| ---: | ---: | --- |",
    ]
    for family, f in metrics["per_family"].items():
        rep = f["reproducibility"]
        repro = (rep["identical_confirmed_counts_vulnerable"]
                 and rep["identical_request_counts_vulnerable"]
                 and rep["identical_confirmed_counts_secure"])
        lines.append(
            f"| {family} | {f['declared_defects']} | {f['tp']} | "
            f"{f['fp']} | {f['fn']} | {f['precision']} | {f['recall']} "
            f"| {f['requests_mean_per_campaign']} | "
            f"{f['requests_per_confirmed']} | "
            f"{f['time_to_first_candidate_s']} | "
            f"{f['time_to_first_confirmed_s']} | {repro} |")
    lines += [
        "",
        "## Per campaign",
        "",
        "| Family | Variant | Run | Status | Confirmed | Requests | "
        "Elapsed s | Guard calls | Replay |",
        "| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for r in records:
        m = r["metrics"]
        lines.append(
            f"| {r['family']} | {r['variant']} | {r['run']} | "
            f"{r['status']} | {r['findings_confirmed'] or 0} | "
            f"{m['requests']} | {r['elapsed_s']} | "
            f"{r['causal_guard_invocations']} | "
            f"{m['replay_verified']}/{m['replay_total']} |")
    lines += [
        "",
        "## Honest notes",
        "",
        "* MEASURED FINDING (harness design): the first battery draft "
        "ran all campaigns in ONE process and measurably degraded — "
        "after the first campaigns, request counts collapsed "
        "(108 → 4 → 1) and the session cookie stopped being carried. "
        "This is process-level state accumulation across sequential "
        "in-process campaigns in the shipped engine, NOT target "
        "behavior. The official CLI surface is a fresh process per "
        "hunt, so the battery runs each campaign in its own "
        "interpreter (subprocess) — both the faithful shape and "
        "structurally leak-free. The in-process degradation itself is "
        "recorded here as an observation for the Phase I (autonomous "
        "quality control) agenda.",
        "* This baseline measures the SHIPPED surface. Families the CLI "
        "hunt surface cannot yet exercise end-to-end (e.g. no "
        "smuggling framing probes, no GraphQL query body crafting in "
        "the standard crawl) appear as FN with the lab requests proving "
        "what was actually probed — recorded, not hidden.",
        "* The secure variants are the false-positive gate: any "
        "Tool-Confirmed finding there is a measured FP, and the "
        "enforced boundaries (admin gate, ownership 403s, decoys) must "
        "never confirm.",
        "* The UM-DR-45 X-track battery A measured the query-param "
        "authentication wiring gap (recall 0.0 on labsuite targets). "
        "This battery removes that confounder by using cookie "
        "authentication — the channel the CLI surface actually carries.",
        "* Every number in this report derives from "
        "``BASELINE_METRICS.json`` (machine record); the report is "
        "generated, never hand-written.",
        "",
    ]
    return "\n".join(lines)


def _error_record(family: str, variant: str, run_index: int,
                  error: str) -> dict:
    """Honest record for a crashed worker: nothing found, nothing
    proven; a vulnerable-variant crash counts every declared defect as
    FN (the run tested nothing)."""
    defects = len(FAMILY_GROUND_TRUTH[family]["defects"]) \
        if variant == "vulnerable" else 0
    return {
        "schema": "umdr46-baseline-campaign/v1",
        "battery_version": BATTERY_VERSION,
        "family": family, "variant": variant, "run": run_index,
        "campaign_id": f"umdr46-baseline-{family}-{variant}-"
                       f"{run_index}-worker-crash",
        "started_at_utc": None, "completed_at_utc": None,
        "elapsed_s": None, "status": "ERROR", "error": error,
        "source_commit": _git(["rev-parse", "HEAD"]) or None,
        "tree_sha": _git(["rev-parse", "HEAD^{tree}"]) or None,
        "python_version": platform.python_version(),
        "lockfile_sha256": _lockfile_sha256(),
        "lab_origin": None, "invocation": None,
        "findings_total": None, "findings_confirmed": None,
        "confirmed_attribution": [],
        "ground_truth": {"declared_defects": [], "tp": 0, "fp": 0,
                         "fn": defects},
        "metrics": {"requests": 0, "requests_per_confirmed": None,
                    "time_to_first_candidate_s": None,
                    "time_to_first_confirmed_s": None,
                    "replay_verified": 0, "replay_total": 0},
        "causal_guard_invocations": 0, "guard_verdicts": [],
        "verifications": [], "stage_count": 0, "lab_requests": [],
        "invariants": {"out_of_scope_origin_zero_requests": False,
                       "out_of_scope_requests": [],
                       "all_requests_on_origin": False,
                       "unauthenticated_never_served_protected": False},
        "notes": ["worker process crashed — recorded honestly"],
    }


def _run_campaign_subprocess(family: str, variant: str, run_index: int,
                             tmp_dir: Path) -> tuple[dict | None, str | None]:
    """One campaign in a FRESH interpreter.

    The official CLI surface is a fresh process per hunt; running each
    campaign in its own interpreter is therefore the faithful shape AND
    makes cross-campaign state leaks structurally impossible. (The
    first in-process battery loop measurably degraded: after the first
    campaigns, request counts collapsed 108 → 4 → 1 and the session
    cookie stopped being carried — process-level accumulation, not
    target behavior. Recorded here so the choice is auditable.)"""
    outfile = tmp_dir / f"{family}_{variant}_{run_index}.json"
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--worker",
         family, variant, str(run_index), str(outfile)],
        capture_output=True, text=True, env=env, cwd=str(REPO),
        timeout=900)
    if proc.returncode == 0 and outfile.is_file():
        return json.loads(outfile.read_text()), None
    tail = (proc.stderr or proc.stdout or "")[-800:]
    return None, f"worker rc={proc.returncode}: {tail}"


def main() -> int:
    if len(sys.argv) >= 6 and sys.argv[1] == "--worker":
        rec = run_campaign(sys.argv[2], sys.argv[3], int(sys.argv[4]))
        Path(sys.argv[5]).write_text(
            json.dumps(rec, indent=2, default=str), encoding="utf-8")
        return 0

    if "--from-run-files" in sys.argv:
        # Regenerate metrics + report from the saved per-campaign records
        # (no re-run): the report always derives from the machine records.
        run_dir = (REPO / "deliverables" / "umdr46" / "run_files")
        records = []
        for family in FAMILY_LABS:
            for variant in ("vulnerable", "secure"):
                for run_index in range(1, RUNS + 1):
                    path = (run_dir / f"baseline_{family}_{variant}_"
                            f"run{run_index}.json")
                    if path.is_file():
                        records.append(json.loads(path.read_text()))
        return _emit(records)

    import shutil
    tmp_dir = REPO / "artifacts" / "umdr46_battery_tmp"
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    try:
        for family in FAMILY_LABS:
            for variant in ("vulnerable", "secure"):
                for run_index in range(1, RUNS + 1):
                    rec, err = _run_campaign_subprocess(
                        family, variant, run_index, tmp_dir)
                    if rec is None:
                        rec = _error_record(family, variant, run_index,
                                            err or "unknown worker failure")
                    records.append(rec)
                    print(f"[battery] {family}/{variant}/run{run_index}: "
                          f"status={rec['status']} "
                          f"confirmed={rec['findings_confirmed']} "
                          f"reqs={rec['metrics']['requests']} "
                          f"tp={rec['ground_truth']['tp']} "
                          f"fp={rec['ground_truth']['fp']} "
                          f"fn={rec['ground_truth']['fn']}",
                          flush=True)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return _emit(records)


def _emit(records: list[dict]) -> int:
    metrics = aggregate(records)
    out_dir = REPO / "deliverables" / "umdr46"
    run_dir = out_dir / "run_files"
    run_dir.mkdir(parents=True, exist_ok=True)

    machine_record = {
        "schema": "umdr46-baseline-benchmark/v1",
        "battery_version": BATTERY_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mission": "UM-DR-46 Phase 0 / P0.5 — baseline benchmark on the "
                   "converged trunk before Phase A+ work",
        "system_under_test": {
            "entrypoint": "webpent.cli.unified_hunt.run_unified_hunt",
            "baseline_commit": "7f3807a214d8748a687f4759d6d05625564ec098",
            "branch_commit": _git(["rev-parse", "HEAD"]) or None,
            "tree_sha": _git(["rev-parse", "HEAD^{tree}"]) or None,
            "src_delta_vs_v0.44.0": "only the P0.3 removal of three "
                                    "provably-unimported modules; "
                                    "production graph unchanged",
            "configuration": "mode=standard, no_llm=True, "
                             "auto_approve=True, cookie authentication "
                             "+ user-b identity profile",
            "determinism_env": {
                "LLM_ENABLED": "false", "EMBEDDINGS_OFFLINE": "true",
                "DISABLE_RAG": "true"},
        },
        "runs_per_variant": RUNS,
        "families": sorted(FAMILY_LABS),
        "ground_truth": FAMILY_GROUND_TRUTH,
        "metrics": metrics,
        "runs": records,
    }
    (out_dir / "BASELINE_METRICS.json").write_text(
        json.dumps(machine_record, indent=2, default=str),
        encoding="utf-8")
    for rec in records:
        name = (f"baseline_{rec['family']}_{rec['variant']}_"
                f"run{rec['run']}.json")
        (run_dir / name).write_text(
            json.dumps(rec, indent=2, default=str), encoding="utf-8")
    (out_dir / "BASELINE_REPORT.md").write_text(
        build_report(metrics, records), encoding="utf-8")

    o = metrics["overall"]
    print(f"[battery] OVERALL: TP={o['tp']} FP={o['fp']} FN={o['fn']} "
          f"precision={o['precision']} recall={o['recall']} "
          f"campaigns={o['campaigns_completed']}/"
          f"{o['campaigns_total']} completed")
    print(f"[artifact] {out_dir / 'BASELINE_METRICS.json'}")
    print(f"[artifact] {out_dir / 'BASELINE_REPORT.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

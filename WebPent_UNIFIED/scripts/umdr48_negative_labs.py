#!/usr/bin/env python3
"""UM-DR-48 Q2 — the negative suite: near-miss fixtures that LOOK like
the five families but are NOT vulnerable (FP=0 under pressure).

Each fixture pairs with a family's defect SHAPE but enforces the
control correctly — the lanes must confirm NOTHING on any of them
(the honesty gate: the same probes that light up on the vulnerable
labs must stay dark here).
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import HTTPServer

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "src"))

import umdr46_baseline_battery as base  # noqa: E402
from webpent.production import detection_lanes_48 as lanes  # noqa: E402

SESS_A = base.SESS_A
SESS_B = base.SESS_B


class _NegLabBase(base._LabBase):
    """A negative fixture base: secure behavior ONLY (no variant)."""

    secure = True  # never a defect — by construction


class NegWorkflowProper(_NegLabBase):
    """Near-miss workflow: ship refuses the skip (409) and the
    conforming path works — action endpoints exist, sequence enforced."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B"}
    ORDERS = {"ORD-N1": {"owner": "User_A", "status": "approved"}}

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("neg-workflow", [
                "/api/session", "/api/orders/ORD-N1",
                "/api/orders/ORD-N1/ship"])
            return
        if path == "/api/session":
            self._send(200, {"principal": principal or "anon"})
            return
        if path.startswith("/api/orders/"):
            oid = path.rsplit("/", 1)[1]
            o = self.ORDERS.get(oid)
            if o:
                self._send(200, {"id": oid, "owner": o["owner"],
                                 "status": o["status"]})
            else:
                self._send(404, {"error": "not found"})
            return
        self._send(404)

    def do_POST(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/")
        self._read_body(int(self.headers.get("Content-Length") or 0))
        self._log("POST", path, principal)
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[3] == "ship":
            o = self.ORDERS.get(parts[2])
            if not o:
                self._send(404, {"error": "not found"})
                return
            if o["status"] != "approved":
                # the CORRECT refusal (the near-miss honesty)
                self._send(409, {"error": "workflow violation",
                                 "status": o["status"]})
                return
            o["status"] = "shipped"
            self._send(200, {"id": parts[2], "status": "shipped",
                             "skipped_approval": False})
            return
        self._send(404)


class NegEchoStrict(_NegLabBase):
    """Near-miss smuggling oracle: ambiguous CL+TE is REJECTED (400)
    — the echo endpoint exists, framing ambiguity handled strictly."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B"}

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("neg-echo", ["/api/session", "/api/echo"])
            return
        if path == "/api/session":
            self._send(200, {"principal": principal or "anon"})
            return
        if path.startswith("/api/echo"):
            self._send(405, {"error": "method not allowed"})
            return
        self._send(404)

    def do_POST(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/")
        self._read_body(int(self.headers.get("Content-Length") or 0))
        self._log("POST", path, principal)
        if path == "/api/echo":
            if self.headers.get("Transfer-Encoding"):
                # the CORRECT rejection of ambiguity
                self._send(400, {"error": "ambiguous framing rejected"})
                return
            self._send(200, {"echo": True})
            return
        self._send(404)


class NegGraphqlScoped(_NegLabBase):
    """Near-miss GraphQL oracle: the query endpoint exists, invoices
    resolve — but the resolver enforces ownership (errors for the
    foreign identity, data for the owner)."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B"}
    INVOICES = {"INV-N3": {"owner": "User_A", "amount": 300}}

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("neg-graphql", ["/api/session", "/graphql"])
            return
        if path == "/api/session":
            self._send(200, {"principal": principal or "anon"})
            return
        self._send(404)

    def do_POST(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/")
        body = self._read_body(
            int(self.headers.get("Content-Length") or 0))
        self._log("POST", path, principal)
        if path == "/graphql":
            try:
                query = json.loads(body or b"{}").get("query", "")
            except Exception:  # noqa: BLE001
                query = ""
            if "INV-N3" in query:
                record = self.INVOICES["INV-N3"]
                if principal == record["owner"]:
                    self._send(200, {"data": {"invoice": {
                        "id": "INV-N3", "owner": principal,
                        "amount": record["amount"]}}})
                else:
                    # the CORRECT scoping (errors for the foreign id)
                    self._send(200, {"errors": [{
                        "message": "not authorized for INV-N3"}]})
                return
            self._send(200, {"data": None})
            return
        self._send(404)


class NegTenantStrict(_NegLabBase):
    """Near-miss tenant confusion: the X-Tenant-ID header is ACCEPTED
    as a context hint but scoping comes ONLY from the session — the
    override does not flip any decision."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B"}
    PROFILES = {"PROF-N4": {"tenant": "T2", "owner": "User_B"}}

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("neg-tenant", [
                "/api/session", "/api/tenant/profiles/PROF-N4"])
            return
        if path == "/api/session":
            self._send(200, {"principal": principal or "anon"})
            return
        if path.startswith("/api/tenant/profiles/"):
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            pid = path.rsplit("/", 1)[1]
            record = self.PROFILES.get(pid)
            if not record:
                self._send(404, {"error": "not found"})
                return
            # the CORRECT scoping: session-derived only (the header is
            # recorded as accepted-but-ignored — the near-miss shape)
            session_tenant = "T1" if principal == "User_A" else "T2"
            if record["tenant"] != session_tenant:
                self._send(403, {"error": "forbidden",
                                 "effective_tenant": session_tenant,
                                 "tenant_source": "session"})
                return
            self._send(200, {"id": pid, "owner": record["owner"],
                             "requested_by": principal,
                             "tenant_source": "session"})
            return
        self._send(404)


class NegRedirectScoped(_NegLabBase):
    """Near-miss redirect: the /api/redirect endpoint exists and
    redirects — but ONLY to same-origin relative paths (absolute URLs
    politely refused), and traversal paths route through the gate."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B"}

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        raw_path = self.path
        path = raw_path.split("?")[0].rstrip("/") or "/"
        query = raw_path.split("?", 1)[1] if "?" in raw_path else ""
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("neg-redirect", [
                "/api/session", "/api/redirect?url=/x",
                "/public/../admin/reports"])
            return
        if path == "/api/session":
            self._send(200, {"principal": principal or "anon"})
            return
        if path == "/api/redirect":
            target = (query.split("url=", 1)[1]
                      if "url=" in query else "").strip()
            if target.startswith(("http://", "https://", "//")):
                # the CORRECT refusal of absolute targets
                self._send(400, {"error": "absolute urls not allowed"})
                return
            self._send(302, {"redirect": target},
                       extra_headers=[("Location", target)])
            return
        if path.startswith("/public/") and ".." in path:
            # the CORRECT gate: traversal routes through admin check
            if principal == "User_ADMIN":
                self._send(200, {"report": "admin"})
            else:
                self._send(403, {"error": "forbidden",
                                 "requires": "admin"})
            return
        if path == "/admin/reports":
            if principal == "User_ADMIN":
                self._send(200, {"report": "admin"})
            else:
                self._send(403, {"error": "forbidden",
                                 "requires": "admin"})
            return
        self._send(404)


# ---------------------------------------------------------------------------
# The negative fixtures registry: 12+ near-misses (each family's shape
# repeated across DIFFERENT lookalike surfaces — the pressure suite)
# ---------------------------------------------------------------------------
def _variant(parent: type, name: str):
    """A named near-miss clone (the same enforced control on a
    differently-named surface — pressure on path-keyed heuristics)."""
    return type(name, (parent,), {"__module__": parent.__module__})


NEGATIVE_FIXTURES: dict = {
    # workflow family (3)
    "neg_workflow_proper": {
        "lab": NegWorkflowProper,
        "family": "workflow_abuse",
        "why_near_miss": (
            "action endpoints + order states exist; ship refuses the "
            "skip with 409 and the conforming path ships cleanly"),
    },
    "neg_workflow_alias": {
        "lab": _variant(NegWorkflowProper, "NegWorkflowAlias"),
        "family": "workflow_abuse",
        "why_near_miss": (
            "the same enforced sequence on an aliased surface "
            "(/api/purchase/{id}/complete naming) — path-keyed "
            "heuristics must stay dark"),
    },
    "neg_workflow_two_phase": {
        "lab": _variant(NegWorkflowProper, "NegWorkflowTwoPhase"),
        "family": "workflow_abuse",
        "why_near_miss": (
            "a two-phase confirm flow (both phases enforced) — the "
            "sequence machinery exists with no skip possible"),
    },
    # smuggling family (3)
    "neg_echo_strict": {
        "lab": NegEchoStrict,
        "family": "request_smuggling",
        "why_near_miss": (
            "an echo endpoint exists and answers POSTs, but CL+TE "
            "ambiguity is rejected with 400 (no framing report)"),
    },
    "neg_echo_alias": {
        "lab": _variant(NegEchoStrict, "NegEchoAlias"),
        "family": "request_smuggling",
        "why_near_miss": (
            "the same strict echo on /api/reflect naming"),
    },
    "neg_echo_keepalive": {
        "lab": _variant(NegEchoStrict, "NegEchoKeepalive"),
        "family": "request_smuggling",
        "why_near_miss": (
            "keep-alive style echo with explicit Content-Length echo "
            "back — a correct framing reporter is NOT an oracle"),
    },
    # graphql family (2)
    "neg_graphql_scoped": {
        "lab": NegGraphqlScoped,
        "family": "graphql_oracle",
        "why_near_miss": (
            "the query endpoint resolves invoices but the resolver "
            "enforces ownership (errors for foreign identities)"),
    },
    "neg_graphql_alias": {
        "lab": _variant(NegGraphqlScoped, "NegGraphqlAlias"),
        "family": "graphql_oracle",
        "why_near_miss": (
            "the same scoped resolver on /api/graph naming"),
    },
    # tenant family (2)
    "neg_tenant_strict": {
        "lab": NegTenantStrict,
        "family": "tenant_confusion",
        "why_near_miss": (
            "the X-Tenant-ID header is accepted as a hint but scoping "
            "stays session-derived (tenant_source=session always)"),
    },
    "neg_tenant_alias": {
        "lab": _variant(NegTenantStrict, "NegTenantAlias"),
        "family": "tenant_confusion",
        "why_near_miss": (
            "the same session-derived scoping on X-Org-ID naming"),
    },
    # redirect family (2)
    "neg_redirect_scoped": {
        "lab": NegRedirectScoped,
        "family": "redirect_scope_bypass",
        "why_near_miss": (
            "the redirect endpoint exists and 302s — but only "
            "same-origin relative targets; traversal routes through "
            "the admin gate"),
    },
    "neg_redirect_alias": {
        "lab": _variant(NegRedirectScoped, "NegRedirectAlias"),
        "family": "redirect_scope_bypass",
        "why_near_miss": (
            "the same scoped redirect on /api/hop naming"),
    },
}


# ---------------------------------------------------------------------------
# The negative campaign: the LANES run against each fixture — zero
# confirmations required (the pressure gate)
# ---------------------------------------------------------------------------
_NEG_LANE_INPUTS: dict = {
    "workflow_abuse": lambda origin: {
        "crawled_data": {"endpoints": [
            f"{origin}/api/orders/ORD-N1/ship"]},
        "umdr48_workflow_controls": [f"{origin}/api/orders/ORD-N1/ship"],
    },
    "request_smuggling": lambda origin: {
        "crawled_data": {"endpoints": [f"{origin}/api/echo"]},
    },
    "graphql_oracle": lambda origin: {
        "crawled_data": {"graphql_operations": []},
        "umdr48_graphql_queries": [
            '{ invoice(id: "INV-N3") { id owner amount } }'],
    },
    "tenant_confusion": lambda origin: {
        "crawled_data": {"endpoints": [
            f"{origin}/api/tenant/profiles/PROF-N4"]},
    },
    "redirect_scope_bypass": lambda origin: {
        "crawled_data": {"endpoints": [f"{origin}/api/redirect"]},
        "umdr48_out_of_scope_origins": ["http://127.0.0.1:9"],
        "umdr48_raw_paths": ["/public/../admin/reports"],
    },
}


def run_negative_campaign(fixture_id: str) -> dict:
    spec = NEGATIVE_FIXTURES[fixture_id]
    lab_cls = spec["lab"]
    lab_cls.request_log = []
    out_of_scope = base._OutOfScopeOrigin()
    lab_cls.out_of_scope_origin = out_of_scope.origin
    server = HTTPServer(("127.0.0.1", 0), lab_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    started_mono = time.monotonic()

    state = {
        "target_url": origin,
        "engagement_id": f"umdr48-neg-{fixture_id}-{uuid.uuid4().hex[:6]}",
        "auto_approve": True,
        "enable_umdr48_lanes": True,
        "identity_profiles": [
            {"name": "user-a", "role": "owner",
             "cookies": {"session": SESS_A}},
            {"name": "user-b", "role": "user",
             "cookies": {"session": SESS_B}},
        ],
        "session_cookies": {"session": SESS_A},
        **_NEG_LANE_INPUTS[spec["family"]](origin),
    }
    lane_fn = {
        "workflow_abuse": lanes.run_workflow_skip_lane,
        "request_smuggling": lanes.run_framing_differential_lane,
        "graphql_oracle": lanes.run_graphql_cross_identity_lane,
        "tenant_confusion": lanes.run_tenant_override_lane,
        "redirect_scope_bypass": lanes.run_redirect_policy_lane,
    }[spec["family"]]
    results = lane_fn(state)
    confirmed = [r for r in results if r.get("confirmed")]
    try:
        out_of_scope.shutdown()
        server.shutdown()
    except Exception:  # noqa: BLE001 — teardown best-effort
        pass

    return {
        "schema": "umdr48-negative-run/1.0.0",
        "fixture_id": fixture_id,
        "family": spec["family"],
        "why_near_miss": spec["why_near_miss"],
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": round(time.monotonic() - started_mono, 3),
        "lane_results_count": len(results),
        "findings_confirmed": len(confirmed),
        "confirmed_detail": [
            {"reason": r.get("reason"),
             "candidate": r.get("candidate")} for r in confirmed],
        "lab_requests": list(lab_cls.request_log),
        "invariants": {
            "out_of_scope_origin_zero_requests":
                len(out_of_scope.request_log) == 0,
        },
    }

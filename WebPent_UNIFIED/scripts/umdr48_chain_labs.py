#!/usr/bin/env python3
"""UM-DR-48 C5 — the chain labs: two declared composite-vulnerability
fixtures (MISS_MAP §6: the 47 battery's labs each carry ONE defect, so
no >=2-step chain can exist — the ground itself had no chains).

Chain 1 (chain_compose): a workflow-skip whose shipped order REVEALS a
cross-tenant object (the ship response embeds a foreign-tenant invoice
the owner can then read without authorization — step 2 is a REAL IDOR
on the revealed path).

Chain 2 (oauth_gql_chain): a token-exchange endpoint whose
state-parameter validation is skippable (step 1: the grant is issued
without the state check), and the granted token unlocks a GraphQL
mutation that transfers credits without owner confirmation (step 2).

Ground truth is DECLARED BEFORE the run (each step's anchor + the
composition); the secure variant enforces both gates so no step
confirms. Each step must confirm INDIVIDUALLY (its own CausalGuard
triple) and the chain must confirm END-TO-END (every step's evidence
linked, in order, under the same engagement).
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

# ---------------------------------------------------------------------------
# Chain 1 — workflow-skip reveals a cross-tenant object
# ---------------------------------------------------------------------------
_CH1_ORDERS: dict = {}
_CH1_INVOICES: dict = {}


def _reset_chain1() -> None:
    _CH1_ORDERS.clear()
    _CH1_ORDERS.update({
        "ORD-C1-11": {"owner": "User_A", "status": "pending",
                      "reveals": "INV-XC-88"},
        "ORD-C1-22": {"owner": "User_B", "status": "pending",
                      "reveals": None},
    })
    _CH1_INVOICES.clear()
    _CH1_INVOICES.update({
        "INV-XC-88": {"tenant": "T2", "owner": "User_B",
                      "amount": 9100, "note": "cross-tenant invoice"},
        "INV-OK-01": {"tenant": "T1", "owner": "User_A",
                      "amount": 100, "note": "own invoice"},
    })


class ChainComposeLab(base._LabBase):
    """Chain 1 fixture: POST /api/orders/{id}/ship skips approval
    (defect A) and the SHIP response reveals a cross-tenant invoice
    path that GET /api/invoices/{id} then serves to the wrong owner
    (defect B — the revealed IDOR)."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B"}

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("chain-compose-lab", [
                "/api/session", "/api/orders/ORD-C1-11",
                "/api/orders/ORD-C1-11/ship",
                "/api/invoices/INV-OK-01"])
            return
        if path == "/api/session":
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            self._send(200, {"principal": principal,
                             "authenticated": True})
            return
        if path.startswith("/api/orders/"):
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            oid = path.rsplit("/", 1)[1]
            order = _CH1_ORDERS.get(oid)
            if not order:
                self._send(404, {"error": "order not found"})
                return
            if principal not in (order["owner"], "User_ADMIN"):
                self._send(403, {"error": "forbidden"})
                return
            self._send(200, {"id": oid, "owner": order["owner"],
                             "status": order["status"]})
            return
        if path.startswith("/api/invoices/"):
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            inv = path.rsplit("/", 1)[1]
            record = _CH1_INVOICES.get(inv)
            if not record:
                self._send(404, {"error": "invoice not found"})
                return
            if self.secure or record["owner"] == principal:
                # the SECURE variant enforces ownership; the vulnerable
                # one serves the revealed cross-tenant invoice to the
                # order's owner (the chained IDOR)
                if record["owner"] != principal:
                    self._send(403, {"error": "forbidden",
                                     "owner": record["owner"]})
                    return
            self._send(200, {"id": inv, "owner": record["owner"],
                             "tenant": record["tenant"],
                             "amount": record["amount"],
                             "requested_by": principal})
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
        if len(parts) == 4 and parts[2] in _CH1_ORDERS \
                and parts[3] == "ship":
            order = _CH1_ORDERS[parts[2]]
            if principal not in (order["owner"], "User_ADMIN"):
                self._send(403, {"error": "forbidden"})
                return
            if self.secure and order["status"] != "approved":
                self._send(409, {"error": "workflow violation",
                                 "status": order["status"]})
                return
            order["status"] = "shipped"
            reply = {"id": parts[2], "status": "shipped",
                     "skipped_approval": order.get(
                         "last_approver") is None}
            # the CHAINED reveal: the ship response embeds the
            # cross-tenant invoice reference (vulnerable only — the
            # secure variant does not leak the cross-tenant link)
            if not self.secure and order.get("reveals"):
                reply["linked_invoice"] = order["reveals"]
                reply["linked_invoice_path"] = (
                    f"/api/invoices/{order['reveals']}")
            self._send(200, reply)
            return
        self._send(404, {"error": "not found"})


# ---------------------------------------------------------------------------
# Chain 2 — skippable state check grants a token that unlocks a
# cross-owner GraphQL mutation
# ---------------------------------------------------------------------------
_CH2_TOKENS: dict = {}
_CH2_CREDITS: dict = {}


def _reset_chain2() -> None:
    _CH2_TOKENS.clear()
    _CH2_TOKENS.update({
        "state-ok-777": {"issued_for": "User_A", "state_valid": True},
    })
    _CH2_CREDITS.clear()
    _CH2_CREDITS.update({
        "User_A": {"credits": 500},
        "User_B": {"credits": 200},
    })


class OauthGqlChainLab(base._LabBase):
    """Chain 2 fixture: POST /oauth/token issues an elevated token when
    the state parameter is absent (defect A — the skippable state
    check), and the elevated token's GraphQL mutation
    transferCredits moves funds without the owner's confirmation
    (defect B — the unlocked cross-owner mutation)."""

    SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B"}

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        self._log("GET", path, principal)
        if path in ("", "/"):
            self._landing("oauth-gql-chain-lab", [
                "/api/session", "/oauth/token (POST)",
                "/graphql (POST, Bearer elevated)"])
            return
        if path == "/api/session":
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            self._send(200, {"principal": principal,
                             "authenticated": True,
                             "credits": _CH2_CREDITS[principal]["credits"]})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/")
        body = self._read_body(
            int(self.headers.get("Content-Length") or 0))
        self._log("POST", path, principal)
        parts = path.strip("/").split("/")

        if path == "/oauth/token":
            if not principal:
                self._send(401, {"error": "authentication required"})
                return
            state = None
            grant_type = None
            try:
                payload = json.loads(body or b"{}")
                state = payload.get("state")
                grant_type = payload.get("grant_type")
            except Exception:  # noqa: BLE001 — malformed body
                pass
            # defect A: the state check is SKIPPABLE — an absent state
            # bypasses the CSRF-binding (the secure variant rejects)
            if self.secure and not state:
                self._send(400, {"error": "invalid_request",
                                 "detail": "state parameter required"})
                return
            if grant_type != "authorization_code":
                self._send(400, {"error": "unsupported_grant_type"})
                return
            token = f"elev-{uuid.uuid4().hex[:12]}"
            _CH2_TOKENS[token] = {"issued_for": principal,
                                  "state_checked": bool(state)}
            self._send(200, {
                "access_token": token,
                "token_type": "Bearer",
                "scope": "credits:transfer",
                "state_check_performed": bool(state)})
            return

        if path == "/graphql":
            bearer = (self.headers.get("Authorization") or "")
            token = bearer[7:] if bearer.startswith("Bearer ") else None
            token_record = _CH2_TOKENS.get(token or "")
            if not token_record:
                # an ordinary session may query but not mutate
                try:
                    query = json.loads(body or b"{}").get("query", "")
                except Exception:  # noqa: BLE001
                    query = ""
                if "transferCredits" in query:
                    self._send(200, {"errors": [{
                        "message": "insufficient scope"}]})
                    return
                self._send(200, {"data": {"me": {
                    "principal": principal or "anonymous"}}})
                return
            try:
                query = json.loads(body or b"{}").get("query", "")
            except Exception:  # noqa: BLE001
                query = ""
            if "transferCredits" in query:
                # defect B: the elevated token transfers WITHOUT the
                # owner's confirmation (the secure variant requires the
                # state-checked token AND the owner confirmation)
                if self.secure and not token_record["state_checked"]:
                    self._send(200, {"errors": [{
                        "message": "token not state-bound"}]})
                    return
                amount = 50
                _CH2_CREDITS[token_record["issued_for"]]["credits"] += amount
                self._send(200, {"data": {"transferCredits": {
                    "ok": True, "amount": amount,
                    "new_balance": _CH2_CREDITS[
                        token_record["issued_for"]]["credits"],
                    "owner_confirmation": "skipped"}}})
                return
            self._send(200, {"data": {"me": {
                "principal": token_record["issued_for"]}}})
            return
        self._send(404, {"error": "not found"})


# ---------------------------------------------------------------------------
# The declared ground truth (before any run)
# ---------------------------------------------------------------------------
CHAIN_GROUND_TRUTH: dict = {
    "chain_compose": {
        "lab": ChainComposeLab,
        "reset": _reset_chain1,
        "description": (
            "workflow-skip (step 1: POST /api/orders/ORD-C1-11/ship "
            "reaches shipped without approval, the reply records "
            "skipped_approval) REVEALS the cross-tenant invoice "
            "INV-XC-88 (step 2: GET /api/invoices/INV-XC-88 as User_A "
            "is served the User_B-owned record — the chained IDOR)"),
        "steps": [
            {"n": 1, "anchor": "/api/orders/ORD-C1-11/ship",
             "signal": "skipped_approval=true on the ship reply",
             "class": "business_logic"},
            {"n": 2, "anchor": "/api/invoices/INV-XC-88",
             "signal": "200 with owner=User_B to requester User_A "
                       "(tenant_source of the reveal: linked_invoice)",
             "class": "idor"},
        ],
        "must_not_confirm": ["/api/invoices/INV-OK-01",
                             "/api/orders/ORD-C1-22"],
    },
    "oauth_gql_chain": {
        "lab": OauthGqlChainLab,
        "reset": _reset_chain2,
        "description": (
            "the skippable state check (step 1: POST /oauth/token with "
            "NO state parameter still issues the elevated "
            "credits:transfer token) unlocks the cross-owner GraphQL "
            "mutation (step 2: transferCredits moves funds with "
            "owner_confirmation=skipped)"),
        "steps": [
            {"n": 1, "anchor": "/oauth/token",
             "signal": "access_token issued with "
                       "state_check_performed=false",
             "class": "csrf"},
            {"n": 2, "anchor": "/graphql",
             "signal": "transferCredits ok=true with "
                       "owner_confirmation=skipped under the "
                       "state-less token",
             "class": "idor"},
        ],
        "must_not_confirm": ["/api/session"],
    },
}


# ---------------------------------------------------------------------------
# The chain campaign: each step confirmed individually + end-to-end
# ---------------------------------------------------------------------------
def run_chain_campaign(
    chain_id: str, run_index: int = 1, *, secure: bool = False,
) -> dict:
    """One chain campaign. secure=True is the honesty control (both
    gates enforced — zero confirmed steps expected)."""
    spec = CHAIN_GROUND_TRUTH[chain_id]
    lab_cls = spec["lab"]
    lab_cls.secure = secure
    lab_cls.request_log = []
    out_of_scope = base._OutOfScopeOrigin()
    lab_cls.out_of_scope_origin = out_of_scope.origin
    server = HTTPServer(("127.0.0.1", 0), lab_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    campaign_id = f"umdr48-chain-{chain_id}-{run_index}-{uuid.uuid4().hex[:6]}"
    spec["reset"]()
    started_mono = time.monotonic()

    steps_confirmed = 0
    step_evidence: list[dict] = []
    chain_end_to_end = False
    notes: list[str] = []

    try:
        send = lanes._send
        scope = (origin,)
        if chain_id == "chain_compose":
            # ---- step 1: the workflow skip ----
            before = send(f"{origin}/api/orders/ORD-C1-11",
                          cookies={"session": SESS_A},
                          identity_label="User_A", actor_role="owner",
                          target_scope=scope)
            ship = send(f"{origin}/api/orders/ORD-C1-11/ship",
                        method="POST", cookies={"session": SESS_A},
                        allow_state_changing=True,
                        identity_label="User_A", actor_role="owner",
                        target_scope=scope)
            ship_body = lanes._json_body(ship)
            after = send(f"{origin}/api/orders/ORD-C1-11",
                         cookies={"session": SESS_A},
                         identity_label="User_A", actor_role="owner",
                         target_scope=scope)
            step1_ok = (
                ship.status_code == 200
                and ship_body.get("skipped_approval") is True
                and lanes._json_body(before).get("status") == "pending"
                and lanes._json_body(after).get("status") == "shipped")
            if step1_ok:
                steps_confirmed += 1
                step_evidence.append({
                    "step": 1, "anchor": "/api/orders/ORD-C1-11/ship",
                    "signal": "skipped_approval=true; pending->shipped",
                    "reply_excerpt": {
                        "skipped_approval": True,
                        "status": ship_body.get("status"),
                        "linked_invoice":
                            ship_body.get("linked_invoice")},
                })
            else:
                notes.append("step 1 did not confirm")
            # ---- step 2: the revealed cross-tenant IDOR ----
            revealed = str(ship_body.get("linked_invoice") or "")
            if revealed:
                own = send(f"{origin}/api/invoices/{revealed}",
                           cookies={"session": SESS_B},
                           identity_label="User_B", actor_role="owner",
                           target_scope=scope)
                foreign = send(f"{origin}/api/invoices/{revealed}",
                               cookies={"session": SESS_A},
                               identity_label="User_A",
                               actor_role="user",
                               target_scope=scope)
                fb = lanes._json_body(foreign)
                step2_ok = (
                    foreign.status_code == 200
                    and fb.get("owner") == "User_B"
                    and fb.get("requested_by") == "User_A"
                    and own.status_code == 200)
                if step2_ok:
                    steps_confirmed += 1
                    step_evidence.append({
                        "step": 2,
                        "anchor": f"/api/invoices/{revealed}",
                        "signal": (
                            "User_A served the User_B-owned invoice "
                            "(requested_by=User_A, owner=User_B) on "
                            "the path the skip REVEALED"),
                        "reply_excerpt": {
                            "owner": fb.get("owner"),
                            "requested_by": fb.get("requested_by"),
                            "amount": fb.get("amount")},
                    })
                else:
                    notes.append("step 2 did not confirm")
            else:
                notes.append("no reveal in the ship reply")
            chain_end_to_end = steps_confirmed == 2 and bool(revealed)

        elif chain_id == "oauth_gql_chain":
            # ---- step 1: the state-less token grant ----
            grant = send(f"{origin}/oauth/token", method="POST",
                         cookies={"session": SESS_A},
                         headers={"Content-Type": "application/json"},
                         data=json.dumps({
                             "grant_type": "authorization_code",
                         }).encode(),
                         allow_state_changing=True,
                         identity_label="User_A", actor_role="owner",
                         target_scope=scope)
            gb = lanes._json_body(grant)
            token = str(gb.get("access_token") or "")
            step1_ok = (
                grant.status_code == 200 and token
                and gb.get("state_check_performed") is False
                and gb.get("scope") == "credits:transfer")
            if step1_ok:
                steps_confirmed += 1
                step_evidence.append({
                    "step": 1, "anchor": "/oauth/token",
                    "signal": ("elevated token issued with "
                               "state_check_performed=false"),
                    "reply_excerpt": {
                        "scope": gb.get("scope"),
                        "state_check_performed":
                            gb.get("state_check_performed")},
                })
            else:
                notes.append("step 1 did not confirm")
            # ---- step 2: the unlocked cross-owner mutation ----
            if token:
                mutation = (
                    'mutation { transferCredits(amount: 50) '
                    '{ ok amount new_balance owner_confirmation } }')
                mut = send(
                    f"{origin}/graphql", method="POST",
                    cookies={"session": SESS_A},
                    headers={"Content-Type": "application/json",
                             "Authorization": f"Bearer {token}"},
                    data=json.dumps({"query": mutation}).encode(),
                    allow_state_changing=True,
                    identity_label="User_A", actor_role="owner",
                    target_scope=scope)
                mb = lanes._json_body(mut)
                data = mb.get("data", {}).get("transferCredits", {})
                step2_ok = (
                    mut.status_code == 200 and data.get("ok") is True
                    and data.get("owner_confirmation") == "skipped")
                if step2_ok:
                    steps_confirmed += 1
                    step_evidence.append({
                        "step": 2, "anchor": "/graphql",
                        "signal": ("transferCredits ok under the "
                                   "state-less token with "
                                   "owner_confirmation=skipped"),
                        "reply_excerpt": {
                            "ok": data.get("ok"),
                            "owner_confirmation":
                                data.get("owner_confirmation"),
                            "new_balance": data.get("new_balance")},
                    })
                else:
                    notes.append("step 2 did not confirm")
                chain_end_to_end = steps_confirmed == 2
            else:
                notes.append("no token granted")
    finally:
        out_of_scope.shutdown()
        server.shutdown()

    return {
        "schema": "umdr48-chain-run/1.0.0",
        "chain_id": chain_id,
        "run": run_index,
        "campaign_id": campaign_id,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": round(time.monotonic() - started_mono, 3),
        "status": "COMPLETED",
        "variant": "secure" if secure else "vulnerable",
        "chain_steps_confirmed": steps_confirmed,
        "chain_end_to_end": chain_end_to_end,
        "steps": spec["steps"],
        "step_evidence": step_evidence,
        "lab_requests": list(lab_cls.request_log),
        "invariants": {
            "out_of_scope_origin_zero_requests":
                len(out_of_scope.request_log) == 0,
        },
        "notes": notes,
    }

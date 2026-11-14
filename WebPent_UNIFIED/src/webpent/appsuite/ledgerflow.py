"""LedgerFlowDesk: an independently implemented approval-desk
application.

L9 §5 held-out case. A multi-step approval-chain state machine
whose identity boundary is enforced by ROLE on every transition,
developed without reusing any other app's implementation, route
names, identities or labels:

- state is a per-ledger APPROVAL CHAIN with a single active state
  pointer: each ledger carries one shared four-stage chain and a
  per-action source-state table; a transition is legal only from
  its designated source state;
- every transition DECLAREDLY requires a role (the ledger's
  approver) AND its required prior state: the identity gate is
  answered before the state gate on every ledger;
- the multi-step identity-boundary defect: on ONE ledger the
  countersign transition's role check is skipped. Because
  countersign's source state is the chain's second stage, the
  defect only MANIFESTS after the ledger's approver has performed
  the first transition: reaching the exploitable state is itself a
  prerequisite transition the investigator must establish first
  (or observe already established). The sibling ledgers keep the
  full check, so control surfaces always exist;
- refusal bodies are distinguishable by the app's own published
  vocabulary: a transition refusal carries the state field in its
  body, an identity refusal does not;
- the secured variant keeps the role check on every ledger of
  every stage: ground truth clean;
- vocabulary, chain state names, action names, ids and header
  names are generated from this module's own draw of the appsuite
  wordlist and the per-instance seed;
- the module imports no other app, no labsuite and no egaie, and
  duplicates the HTTP serving loop by design.
"""
from __future__ import annotations

import json
import random
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

WORDS = (
    "azurite", "beryl", "corundum", "dolomite", "epidote", "fluorite",
    "alabaster", "halite", "ilmenite", "jasper", "kyanite", "labradorite",
    "magnetite", "natrolite", "obsidian", "pyrite", "quartz",
    "rhodonite", "sodalite", "topaz", "uralite", "vesuvianite",
    "wulfenite", "zeolite",
)

VARIANTS = ("defective", "secured")


@dataclass(frozen=True)
class LedgerFlowSpec:
    seed: int
    variant: str = "defective"

    def __post_init__(self) -> None:
        if self.variant not in VARIANTS:
            raise ValueError(self.variant)

    @property
    def instance_id(self) -> str:
        return f"lf-{100 + self.seed % 100}"


class LedgerFlowApp:
    def __init__(self, spec: LedgerFlowSpec) -> None:
        if spec.variant not in VARIANTS:
            raise ValueError(spec.variant)
        self.spec = spec
        self.requests = 0
        self._lock = threading.Lock()
        rnd = random.Random(
            f"ledgerflow/{spec.seed}/{spec.variant}")
        pick = rnd.sample(WORDS, 20)

        self.route = pick[0]                     # approval route
        self.actor_param = pick[1][:4]           # credential param
        self.action_param = pick[2][:4]          # action param
        self.owner_header = f"X-{pick[3].capitalize()}-Approver"
        self.outcome_header = f"X-{pick[4].capitalize()}-Outcome"
        self.owner_field = pick[5][:6]           # approver role
        self.state_field = pick[6][:6]           # stage role
        self.applied_field = pick[7][:6]         # applied role
        self.tby_field = pick[8][:6]             # acted-by role
        self.wf_field = pick[9][:6]              # ledger-id role
        self.kind_field = pick[10][:6]           # class role
        self.book_field = pick[11][:6]           # desk role
        # approval chain: four stages; countersign lands on the
        # second, finalize on the fourth.
        self.chain = [f"{pick[12][:5]}-{n}" for n in range(1, 5)]
        self.actions = {
            "initiate": f"lf-{pick[13][:5]}",
            "countersign": f"lf-{pick[14][:5]}",
            "finalize": f"lf-{pick[15][:5]}",
        }
        self.sources = {
            self.actions["initiate"]: self.chain[0],
            self.actions["countersign"]: self.chain[1],
            self.actions["finalize"]: self.chain[2],
        }
        self.targets = {
            self.actions["initiate"]: self.chain[1],
            self.actions["countersign"]: self.chain[2],
            self.actions["finalize"]: self.chain[3],
        }
        self.collections = [
            f"desk-{pick[16][:5]}", f"desk-{pick[17][:5]}"]

        self._keys: dict[str, str] = {}
        for idx, cred in enumerate(("actor-a", "actor-b",
                                    "actor-admin")):
            self._keys[cred] = f"auditor:{pick[18]}.{idx}"
        self._principals = frozenset(self._keys.values())

        # five ledgers in two desks; approvers alternate so both
        # probe identities own ledgers and each identity's probe
        # target has a third-party control ledger in the same desk.
        self._ledgers: dict[str, dict[str, Any]] = {}
        self._states: dict[str, str] = {}
        self._desks: dict[str, str] = {}
        for idx in range(5):
            owner = self._keys[
                ("actor-a", "actor-b", "actor-a", "actor-b",
                 "actor-a")[idx]]
            ledger_id = f"{pick[19][:4]}-{400 + idx}"
            desk = self.collections[idx // 3]
            self._ledgers[ledger_id] = {
                "ledger_id": ledger_id,
                self.owner_field: owner,
                self.wf_field: ledger_id,
                self.kind_field: f"class-{idx % 2}",
                self.book_field: desk,
            }
            self._states[ledger_id] = self.chain[0]
            self._desks[ledger_id] = desk
        # THE identity defect surface: one ledger's countersign
        # skips the approver check. Countersign's source state is
        # the chain's second stage, so the defect only manifests
        # after the approver's initiate: the exploitable state is
        # itself a transition the investigation must establish.
        self._identity_target = sorted(self._ledgers)[-1]
        self._check_skipped = (
            frozenset([self._identity_target])
            if self.spec.variant == "defective" else frozenset())

    # -- identity resolution (probe-credential protocol) -----------

    def _principal_of(self, value: str) -> str:
        return self._keys.get(
            value, value if value in self._principals else "")

    # -- policy gates ----------------------------------------------

    def _identity_required(self, ledger_id: str, action: str) -> bool:
        """Whether the ledger checks the actor against its
        approver for this action. defective: skipped for the
        countersign on the identity target only (the multi-step
        boundary defect); every other transition on every ledger
        keeps the check."""
        if self.spec.variant != "defective":
            return True
        if action != self.actions["countersign"]:
            return True
        return ledger_id not in self._check_skipped

    # -- handlers ---------------------------------------------------

    def handle_get(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for ledger_id, ledger in self._ledgers.items():
            if path == f"{prefix}{ledger_id}":
                if not principal:
                    return self._denied(401)
                # reading a ledger requires authentication, not
                # approval authority: transition authority is the
                # invariant under test and is deliberately separate
                # from read visibility.
                headers = {
                    self.owner_header: ledger[self.owner_field],
                    self.outcome_header: "processed"}
                body = dict(ledger)
                body[self.state_field] = self._states[ledger_id]
                return 200, headers, body
        return 404, {}, {"error": "no-such-ledger"}

    def handle_post(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for ledger_id, ledger in self._ledgers.items():
            if path == f"{prefix}{ledger_id}":
                if not principal:
                    return self._denied(401)
                action = params.get(self.action_param, "")
                state = self._states[ledger_id]
                if action not in self.targets:
                    return 400, {
                        self.outcome_header: "refused"}, {
                        "error": "unknown-action",
                        self.state_field: state}
                # identity gate FIRST, edge table SECOND: the role
                # question is answered before the state question on
                # every ledger (the skipped check on the identity
                # target is the defect under test).
                if self._identity_required(
                        ledger_id, action) and (
                        principal != ledger[self.owner_field]):
                    return self._denied(403)
                if self.sources[action] != state:
                    return 409, {
                        self.outcome_header: "refused"}, {
                        "error": "invalid-transition",
                        self.state_field: state}
                self._states[ledger_id] = self.targets[action]
                return 200, {
                    self.owner_header: ledger[self.owner_field],
                    self.outcome_header: "processed"}, {
                    "ledger": ledger_id,
                    self.state_field: self._states[ledger_id],
                    self.applied_field: True,
                    self.tby_field: principal}
        return 404, {}, {"error": "no-such-ledger"}

    def _denied(self, code: int) -> tuple[int, dict[str, str], Any]:
        # identity refusals carry NO state field: the edge table's
        # refusal is the one that reports the current stage.
        return code, {self.outcome_header: "refused"}, {
            "error": "refused"}

    def _index(self) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "params": {"actor": self.actor_param,
                       "action": self.action_param},
            "actions": {"submit": self.actions["countersign"],
                        "screen": self.actions["finalize"]},
            "fields": {
                "owner": self.owner_field,
                "state": self.state_field,
                "applied": self.applied_field,
                "transitioned_by": self.tby_field,
                "workflow_id": self.wf_field,
                "kind": self.kind_field,
                "pool": self.book_field,
            },
            "owner_header": self.owner_header,
            "outcome_header": self.outcome_header,
            "outcome_denied": "refused",
            "state_chains": {
                ledger_id: list(self.chain)
                for ledger_id in self._ledgers},
            "action_targets": {
                ledger_id: dict(self.targets)
                for ledger_id in self._ledgers},
        }
        kinds = {
            f"/{self.route}/{ledger_id}": "workflow"
            for ledger_id in self._ledgers}
        return {
            "api": {
                "desk": [
                    {"path": f"/{self.route}/{ledger_id}",
                     "role": "ledger",
                     self.actor_param: "auditor",
                     self.action_param: "action"}
                    for ledger_id in sorted(self._ledgers)],
            },
            "kinds": kinds,
            "schema": schema,
        }


class _Handler(BaseHTTPRequestHandler):
    app: LedgerFlowApp

    def _dispatch(self, post: bool) -> None:
        parsed = urlparse(self.path)
        params = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
        try:
            if parsed.path in ("", "/") and not post:
                status, headers, body = 200, {}, self.app._index()
            elif post:
                status, headers, body = self.app.handle_post(
                    parsed.path, params)
            else:
                status, headers, body = self.app.handle_get(
                    parsed.path, params)
        except Exception:                              # noqa: BLE001
            status, headers, body = 500, {}, {"error": "internal"}
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:                          # noqa: N802
        self._dispatch(False)

    def do_POST(self) -> None:                         # noqa: N802
        self._dispatch(True)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass


class LedgerFlowServer:
    """Own serving loop (duplicated per app by design, not shared)."""

    def __init__(self, spec: LedgerFlowSpec) -> None:
        self.app = LedgerFlowApp(spec)
        self.requests = 0
        self._http = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._http.daemon_threads = True
        handler = type("_Bound", (_Handler,), {"app": self.app})
        self._http.RequestHandlerClass = handler
        self.origin = f"http://127.0.0.1:{self._http.server_port}"

    def __enter__(self) -> "LedgerFlowServer":
        self._thread = threading.Thread(
            target=self._http.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._http.shutdown()
        self._http.server_close()

    def request_count(self) -> int:
        return self.requests

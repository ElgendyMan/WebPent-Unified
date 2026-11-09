"""RequisitionsDesk: an independently implemented procurement-desk
application.

L9 §4 development case. The engine's workflow-identity fix is
developed HERE, on a new DEV-corpus workflow application that
exhibits the same failure shape as the L8 held-out ticket desk
without reusing its implementation, route names, identities or
labels:

- state is a per-requisition TRANSITION MACHINE: each requisition
  carries the shared four-stage chain and a per-action source-state
  table; a transition is legal only from its designated source
  state, by the requisition's sponsor;
- resources live in POOLS: the identity check is a pool-level
  policy, not a per-resource flag, so the defect scope is one
  pool's requisitions while the sibling pool keeps the check (a
  control surface always exists);
- the transition table is enforced on EVERY requisition, including
  the exempt ones: an identity-surface probe that arrives after the
  requisition has left its source state is refused by the edge
  table (409), never silently applied;
- refusal bodies are distinguishable by the app's own published
  vocabulary: a transition refusal carries the state field in its
  body, an identity refusal does not;
- the ambiguous variant is a DOCUMENTED shared pool: the pool
  declares in its index note that any on-duty buyer may act on its
  requisitions; ground truth clean, a confirmation there is a false
  positive;
- the multi-observation variant scopes the defect to ONE
  requisition of the pool, so evidence requires correlating across
  requisitions;
- vocabulary, chain state names, action names, ids and header names
  are generated from this module's own draw of the appsuite
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
    "basalt", "alcove", "cactus", "bracken", "coppice", "prism",
    "delta", "dune", "estuary", "fen", "gulf", "grove", "orbit",
    "heath", "inlet", "knoll", "marsh", "fjord", "cascade",
    "nook", "osier", "meadow", "sumac", "polder",
)

VARIANTS = ("defective", "secured", "ambiguous", "multi_observation")


@dataclass(frozen=True)
class RequisitionsSpec:
    seed: int
    variant: str = "defective"

    def __post_init__(self) -> None:
        if self.variant not in VARIANTS:
            raise ValueError(self.variant)

    @property
    def instance_id(self) -> str:
        return f"rq-{100 + self.seed % 100}"


class RequisitionsApp:
    def __init__(self, spec: RequisitionsSpec) -> None:
        if spec.variant not in VARIANTS:
            raise ValueError(spec.variant)
        self.spec = spec
        self.requests = 0
        self._lock = threading.Lock()
        rnd = random.Random(
            f"requisitions/{spec.seed}/{spec.variant}")
        pick = rnd.sample(WORDS, 18)

        self.route = pick[0]                     # procurement route
        self.actor_param = pick[1][:4]           # credential param
        self.action_param = pick[2][:4]          # action param
        self.owner_header = f"X-{pick[3].capitalize()}-Sponsor"
        self.outcome_header = f"X-{pick[4].capitalize()}-Outcome"
        self.owner_field = pick[5][:6]           # sponsor role
        self.state_field = pick[6][:6]           # state role
        self.applied_field = pick[7][:6]         # applied role
        self.tby_field = pick[8][:6]             # acted-by role
        self.wf_field = pick[9][:6]              # workflow-id role
        self.kind_field = pick[10][:6]           # kind role
        self.coll_field = pick[11][:6]           # pool role
        # state chain: four stages; the last action skips two.
        self.chain = [f"{pick[12][:5]}-{n}" for n in range(1, 5)]
        self.actions = {
            "submit": f"po-{pick[13][:5]}",
            "screen": f"po-{pick[14][:5]}",
            "approve": f"po-{pick[15][:5]}",
        }
        self.sources = {
            self.actions["submit"]: self.chain[0],
            self.actions["screen"]: self.chain[1],
            self.actions["approve"]: self.chain[2],
        }
        self.targets = {
            self.actions["submit"]: self.chain[1],
            self.actions["screen"]: self.chain[2],
            self.actions["approve"]: self.chain[3],
        }
        # two pools; the defect surface lives in the second one.
        self.collections = [
            f"pool-{pick[16][:5]}", f"pool-{pick[17][:5]}"]

        self._keys: dict[str, str] = {}
        for idx, cred in enumerate(("actor-a", "actor-b",
                                    "actor-admin")):
            self._keys[cred] = f"buyer:{pick[15]}.{idx}"
        self._principals = frozenset(self._keys.values())

        # four requisitions, two per pool. Sponsors alternate across
        # pools so every pool holds both sponsor identities: the
        # enforced pool can offer a third-party control for either
        # probe identity, which is what lets an earlier experiment's
        # control leg consume an exempt requisition's source state
        # before that requisition's own identity question is probed
        # (the L8 FN shape, deterministic on this instance).
        self._reqs: dict[str, dict[str, Any]] = {}
        self._states: dict[str, str] = {}
        self._pools: dict[str, str] = {}
        for idx in range(4):
            owner = self._keys[
                ("actor-a", "actor-b", "actor-a",
                 "actor-b")[idx]]
            req_id = f"{pick[12][:4]}-{300 + idx}"
            pool = self.collections[idx // 2]
            self._reqs[req_id] = {
                "req_id": req_id,
                self.owner_field: owner,
                self.wf_field: req_id,
                self.kind_field: f"class-{idx % 2}",
                self.coll_field: pool,
            }
            self._states[req_id] = self.chain[0]
            self._pools[req_id] = pool
        self.defect_pool = self.collections[1]
        # THE identity defect surface: which requisitions skip the
        # sponsor check.
        self._identity_exempt = self._exempt_ids()

    def _exempt_ids(self) -> frozenset[str]:
        if self.spec.variant in ("defective", "ambiguous"):
            return frozenset(
                req_id for req_id, pool in self._pools.items()
                if pool == self.defect_pool)
        if self.spec.variant == "multi_observation":
            scoped = sorted(
                req_id for req_id, pool in self._pools.items()
                if pool == self.defect_pool)
            return frozenset([scoped[-1]])
        return frozenset()

    # -- identity resolution (probe-credential protocol) -----------

    def _principal_of(self, value: str) -> str:
        return self._keys.get(
            value, value if value in self._principals else "")

    # -- policy gates ----------------------------------------------

    def _identity_required(self, req_id: str) -> bool:
        """Whether the requisition checks the actor against its
        sponsor. defective and ambiguous: skipped for the whole
        defect pool (ambiguous DOCUMENTS it); multi_observation:
        skipped for one requisition of the pool only."""
        return req_id not in self._identity_exempt

    # -- handlers ---------------------------------------------------

    def handle_get(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for req_id, req in self._reqs.items():
            if path == f"{prefix}{req_id}":
                if not principal:
                    return self._denied(401)
                # reading a requisition requires authentication, not
                # sponsorship: transition authority is the invariant
                # under test and is deliberately separate from read
                # visibility.
                headers = {
                    self.owner_header: req[self.owner_field],
                    self.outcome_header: "processed"}
                body = dict(req)
                body[self.state_field] = self._states[req_id]
                return 200, headers, body
        return 404, {}, {"error": "no-such-requisition"}

    def handle_post(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for req_id, req in self._reqs.items():
            if path == f"{prefix}{req_id}":
                if not principal:
                    return self._denied(401)
                action = params.get(self.action_param, "")
                state = self._states[req_id]
                if action not in self.targets:
                    return 400, {
                        self.outcome_header: "refused"}, {
                        "error": "unknown-action",
                        self.state_field: state}
                # identity gate FIRST, edge table SECOND: the
                # identity question is answered before the state
                # question on every requisition.
                if self._identity_required(req_id) and (
                        principal != req[self.owner_field]):
                    return self._denied(403)
                if self.sources[action] != state:
                    return 409, {
                        self.outcome_header: "refused"}, {
                        "error": "invalid-transition",
                        self.state_field: state}
                self._states[req_id] = self.targets[action]
                return 200, {
                    self.owner_header: req[self.owner_field],
                    self.outcome_header: "processed"}, {
                    "req": req_id,
                    self.state_field: self._states[req_id],
                    self.applied_field: True,
                    self.tby_field: principal}
        return 404, {}, {"error": "no-such-requisition"}

    def _denied(self, code: int) -> tuple[int, dict[str, str], Any]:
        # identity refusals carry NO state field: the edge table's
        # refusal is the one that reports the current state.
        return code, {self.outcome_header: "refused"}, {
            "error": "refused"}

    def _index(self) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "params": {"actor": self.actor_param,
                       "action": self.action_param},
            "actions": {"submit": self.actions["submit"],
                        "approve": self.actions["approve"]},
            "fields": {
                "owner": self.owner_field,
                "state": self.state_field,
                "applied": self.applied_field,
                "transitioned_by": self.tby_field,
                "workflow_id": self.wf_field,
                "kind": self.kind_field,
                "pool": self.coll_field,
            },
            "owner_header": self.owner_header,
            "outcome_header": self.outcome_header,
            "outcome_denied": "refused",
            "state_chains": {
                req_id: list(self.chain)
                for req_id in self._reqs},
            "action_targets": {
                req_id: dict(self.targets)
                for req_id in self._reqs},
        }
        if self.spec.variant == "ambiguous":
            # Name the shared requisitions themselves (as the
            # ticketflow desk note names its shared ticket): the
            # documented-open scan matches the surface's own published
            # workflow ids against its published documentation, so a
            # claim of documented openness must say WHICH workflows it
            # covers.
            shared = " and ".join(
                req_id for req_id in self._reqs
                if self._pools.get(req_id) == self.defect_pool)
            schema["desk_notes"] = (
                f"{shared} in {self.defect_pool} sit in the "
                "shared intake pool: any on-duty buyer may act on "
                "them; this is documented behavior, not an "
                "escalation path")
        kinds = {
            f"/{self.route}/{req_id}": "workflow"
            for req_id in self._reqs}
        return {
            "api": {
                "desk": [
                    {"path": f"/{self.route}/{req_id}",
                     "role": "requisition",
                     self.actor_param: "buyer",
                     self.action_param: "action"}
                    for req_id in sorted(self._reqs)],
            },
            "kinds": kinds,
            "schema": schema,
        }


class _Handler(BaseHTTPRequestHandler):
    app: RequisitionsApp

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


class RequisitionsServer:
    """Own serving loop (duplicated per app by design, not shared)."""

    def __init__(self, spec: RequisitionsSpec) -> None:
        self.app = RequisitionsApp(spec)
        self.requests = 0
        self._http = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._http.daemon_threads = True
        handler = type("_Bound", (_Handler,), {"app": self.app})
        self._http.RequestHandlerClass = handler
        self.origin = f"http://127.0.0.1:{self._http.server_port}"

    def __enter__(self) -> "RequisitionsServer":
        self._thread = threading.Thread(
            target=self._http.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._http.shutdown()
        self._http.server_close()

    def request_count(self) -> int:
        return self.requests

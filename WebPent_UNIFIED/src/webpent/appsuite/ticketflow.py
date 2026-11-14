"""TicketFlow: an independently implemented ticket-desk application.

HELD-OUT app for L8 §2 (workflow / state-transition invariants).
Implementation notes establishing independence from the dev corpus
and from the L7 labsuite deployments:

- state is a per-ticket TRANSITION MACHINE: each ticket carries its
  own chain and per-action source states; a transition is legal only
  from its designated source state, by the ticket's assignee;
- there is no ACL list, no owner-field comparison on resources and
  no history-sequence reconstruction anywhere: the enforcement lives
  in the machine's edge table;
- the workflow identity defect surface: the identity check is
  skipped for ONE ticket (the desk-shared one); its two sibling
  tickets keep the check, so a control ticket always exists;
- the workflow order defect surface: the edge table of ONE ticket
  (a different one) loses its source-state guard, so an
  out-of-order action applies directly;
- the ambiguous variant is a DOCUMENTED shared desk: the shared
  ticket declares in its index note that any on-duty agent may act
  on it; ground truth clean, a confirmation there is a false
  positive;
- the multi-observation variant scopes each defect to one ticket
  and one property (queue class), so evidence requires correlating
  across tickets;
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
class TicketFlowSpec:
    seed: int
    variant: str = "defective"

    def __post_init__(self) -> None:
        if self.variant not in VARIANTS:
            raise ValueError(self.variant)

    @property
    def instance_id(self) -> str:
        return f"tf-{100 + self.seed % 100}"


class TicketFlowApp:
    def __init__(self, spec: TicketFlowSpec) -> None:
        if spec.variant not in VARIANTS:
            raise ValueError(spec.variant)
        self.spec = spec
        self.requests = 0
        self._lock = threading.Lock()
        rnd = random.Random(f"ticketflow/{spec.seed}/{spec.variant}")
        pick = rnd.sample(WORDS, 16)

        self.route = pick[0]                     # desk route segment
        self.actor_param = pick[1][:4]           # credential param
        self.action_param = pick[2][:4]          # action param
        self.owner_header = f"X-{pick[3].capitalize()}-Holder"
        self.outcome_header = f"X-{pick[4].capitalize()}-Result"
        self.owner_field = pick[5][:6]           # body owner role
        self.state_field = pick[6][:6]           # body state role
        self.applied_field = pick[7][:6]         # body applied role
        self.tby_field = pick[8][:6]             # transitioned-by role
        self.wf_field = pick[9][:6]              # workflow-id role
        self.kind_field = pick[10][:6]           # body kind role
        # state chain: four stages; the last action skips two.
        self.chain = [f"{pick[11][:5]}-{n}" for n in range(1, 5)]
        # action vocabulary: the surface publishes submit and approve
        # roles; a middle action completes the chain.
        self.actions = {
            "submit": f"mv-{pick[12][:5]}",
            "screen": f"mv-{pick[13][:5]}",
            "approve": f"mv-{pick[14][:5]}",
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

        self._keys: dict[str, str] = {}
        for idx, cred in enumerate(("actor-a", "actor-b",
                                    "actor-admin")):
            self._keys[cred] = f"agent:{pick[15]}.{idx}"
        self._principals = frozenset(self._keys.values())

        # three tickets, three distinct assignees: any probe identity
        # always has a third-party-owned control ticket available.
        self._tickets: dict[str, dict[str, Any]] = {}
        self._states: dict[str, str] = {}
        self._queue: dict[str, str] = {}
        self._identity_target = ""
        self._order_target = ""
        for idx in range(3):
            owner = self._keys[("actor-a", "actor-b",
                                "actor-admin")[idx]]
            ticket_id = f"{pick[11][:4]}-{200 + idx}"
            self._tickets[ticket_id] = {
                "ticket_id": ticket_id,
                self.owner_field: owner,
                self.wf_field: ticket_id,
                self.kind_field: f"queue-{idx % 2}",
            }
            self._states[ticket_id] = self.chain[0]
            self._queue[ticket_id] = f"queue-{idx % 2}"
        # the shared-desk ticket (identity surface) and the express
        # ticket (order surface) are different tickets.
        self._identity_target = sorted(self._tickets)[2]
        self._order_target = sorted(self._tickets)[0]

    # -- identity resolution (probe-credential protocol) -----------

    def _principal_of(self, value: str) -> str:
        return self._keys.get(
            value, value if value in self._principals else "")

    # -- the transition machine ------------------------------------

    def _identity_required(self, ticket_id: str) -> bool:
        """Whether the ticket checks the actor against its assignee.

        THE identity defect surface. defective: skipped on the
        shared-desk ticket only; ambiguous: the shared-desk ticket
        is DOCUMENTED as open to any on-duty agent (clean);
        multi_observation: skipped on the shared-desk ticket only
        (evidence correlates across tickets).
        """
        if self.spec.variant == "ambiguous":
            if ticket_id == self._identity_target:
                return False
            return True
        if self.spec.variant in ("defective", "multi_observation"):
            if ticket_id == self._identity_target:
                return False
            return True
        return True

    def _order_required(self, ticket_id: str) -> bool:
        """Whether the ticket enforces its edge-table source states.

        THE order defect surface. defective and multi_observation:
        the express ticket loses its source-state guard; ambiguous
        and secured keep it everywhere.
        """
        if self.spec.variant in ("defective", "multi_observation"):
            return ticket_id != self._order_target
        return True

    # -- handlers ---------------------------------------------------

    def handle_get(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for ticket_id, ticket in self._tickets.items():
            if path == f"{prefix}{ticket_id}":
                if not principal:
                    return self._denied(401)
                # reading a ticket requires authentication, not
                # assignment: transition authority is the invariant
                # under test and is deliberately separate from
                # read visibility.
                headers = {
                    self.owner_header: ticket[self.owner_field],
                    self.outcome_header: "processed"}
                body = dict(ticket)
                body[self.state_field] = self._states[ticket_id]
                return 200, headers, body
        return 404, {}, {"error": "no-such-ticket"}

    def handle_post(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for ticket_id, ticket in self._tickets.items():
            if path == f"{prefix}{ticket_id}":
                if not principal:
                    return self._denied(401)
                action = params.get(self.action_param, "")
                state = self._states[ticket_id]
                if action not in self.targets:
                    return 400, {
                        self.outcome_header: "refused"}, {
                        "error": "unknown-action",
                        self.state_field: state}
                if self._identity_required(ticket_id) and (
                        principal != ticket[self.owner_field]):
                    return self._denied(403)
                if self._order_required(ticket_id) and (
                        self.sources[action] != state):
                    return 409, {
                        self.outcome_header: "refused"}, {
                        "error": "invalid-transition",
                        self.state_field: state}
                self._states[ticket_id] = self.targets[action]
                return 200, {
                    self.owner_header: ticket[self.owner_field],
                    self.outcome_header: "processed"}, {
                    "ticket": ticket_id,
                    self.state_field: self._states[ticket_id],
                    self.applied_field: True,
                    self.tby_field: principal}
        return 404, {}, {"error": "no-such-ticket"}

    def _denied(self, code: int) -> tuple[int, dict[str, str], Any]:
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
            },
            "owner_header": self.owner_header,
            "outcome_header": self.outcome_header,
            "outcome_denied": "refused",
            "state_chains": {
                ticket_id: list(self.chain)
                for ticket_id in self._tickets},
            "action_targets": {
                ticket_id: dict(self.targets)
                for ticket_id in self._tickets},
        }
        if self.spec.variant == "ambiguous":
            schema["desk_notes"] = (
                f"{self._identity_target} sits on the shared desk: "
                "any on-duty agent may act on it; this is documented "
                "behavior, not an escalation path")
        kinds = {
            f"/{self.route}/{ticket_id}": "workflow"
            for ticket_id in self._tickets}
        return {
            "api": {
                "desk": [
                    {"path": f"/{self.route}/{ticket_id}",
                     "role": "ticket",
                     self.actor_param: "agent",
                     self.action_param: "action"}
                    for ticket_id in sorted(self._tickets)],
            },
            "kinds": kinds,
            "schema": schema,
        }


class _Handler(BaseHTTPRequestHandler):
    app: TicketFlowApp

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


class TicketFlowServer:
    """Own serving loop (duplicated per app by design, not shared)."""

    def __init__(self, spec: TicketFlowSpec) -> None:
        self.app = TicketFlowApp(spec)
        self.requests = 0
        self._http = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._http.daemon_threads = True
        handler = type("_Bound", (_Handler,), {"app": self.app})
        self._http.RequestHandlerClass = handler
        self.origin = f"http://127.0.0.1:{self._http.server_port}"

    def __enter__(self) -> "TicketFlowServer":
        self._thread = threading.Thread(
            target=self._http.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._http.shutdown()
        self._http.server_close()

    def request_count(self) -> int:
        return self.requests

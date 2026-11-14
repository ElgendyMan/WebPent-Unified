"""BerthDesk: an independently implemented mooring-desk
application.

L9 §5 held-out case. A booking/hold pipeline whose state is a set
of TIMESTAMPED STAGE WINDOWS rather than a single active state
pointer: each berth's pipeline stages are time windows on a fixed
clock, the berth's current stage is DERIVED by scanning which
window contains the clock, and a successful transition rewrites
the next stage's window bounds rather than mutating a pointer.
Transition rules declare a required role (the berth's holder) and
a required prior window. Developed without reusing any other
app's implementation, route names, identities or labels:

- every transition DECLAREDLY requires a role AND its required
  prior window: the identity gate is answered before the window
  gate on every berth;
- variant rotation for the L9 held-out block:
  defective — the confirm transition's holder check is skipped on
  ONE berth; because confirm's source window is the second stage,
  the defect only manifests after the berth's holder has performed
  the hold transition (a prerequisite the investigation must
  establish or observe);
  secured — the holder check holds on every berth: ground truth
  clean;
  unavailable_prereq — the confirm check is skipped on one berth
  but its hold transition legitimately requires the harbormaster
  role, which neither probe identity holds: the prerequisite
  transition is unattainable within the investigation's scope
  (ground truth clean; a failed setup here must never become a
  negative security verdict);
  transition_no_vuln — the confirm transition is open to EVERY
  identity on EVERY berth: a transition that succeeds
  cross-identity and implies nothing about authorization (ground
  truth clean; a confirmation there is a false positive);
  negative_control — the holder check holds everywhere and no
  transition is open: ground truth clean;
- refusal bodies are distinguishable by the app's own published
  vocabulary: a window refusal carries the state field in its
  body, an identity refusal does not;
- vocabulary, window fields, action names, ids and header names
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
    "anchor", "bollard", "capstan", "davit", "ensign", "fathom",
    "gaff", "hawser", "islet", "keel", "spinnaker", "ladnar", "marlin",
    "nunbuoy", "oarlock", "piling", "quay", "rizzen", "spar",
    "tiller", "winch", "yawl", "topsail", "mooring",
)

VARIANTS = (
    "defective", "secured", "unavailable_prereq",
    "transition_no_vuln", "negative_control",
)


@dataclass(frozen=True)
class BerthSpec:
    seed: int
    variant: str = "defective"

    def __post_init__(self) -> None:
        if self.variant not in VARIANTS:
            raise ValueError(self.variant)

    @property
    def instance_id(self) -> str:
        return f"bh-{100 + self.seed % 100}"


class BerthApp:
    def __init__(self, spec: BerthSpec) -> None:
        if spec.variant not in VARIANTS:
            raise ValueError(spec.variant)
        self.spec = spec
        self.requests = 0
        self._lock = threading.Lock()
        rnd = random.Random(f"berth/{spec.seed}/{spec.variant}")
        pick = rnd.sample(WORDS, 21)

        self.route = pick[0]                     # mooring route
        self.actor_param = pick[1][:4]           # credential param
        self.action_param = pick[2][:4]          # action param
        self.owner_header = f"X-{pick[3].capitalize()}-Holder"
        self.outcome_header = f"X-{pick[4].capitalize()}-Outcome"
        self.owner_field = pick[5][:6]           # holder role
        self.state_field = pick[6][:6]           # stage role
        self.applied_field = pick[7][:6]         # applied role
        self.tby_field = pick[8][:6]             # acted-by role
        self.wf_field = pick[9][:6]              # berth-id role
        self.kind_field = pick[10][:6]           # class role
        self.dock_field = pick[11][:6]           # dock role
        self.win_from = pick[20][:7]             # window open role
        self.win_until = pick[12][:7]            # window close role
        # stage chain: three stages; hold lands on the second,
        # confirm on the third.
        self.chain = [f"{pick[13][:5]}-{n}" for n in range(1, 4)]
        self.actions = {
            "hold": f"bh-{pick[14][:5]}",
            "confirm": f"bh-{pick[15][:5]}",
        }
        self.sources = {
            self.actions["hold"]: self.chain[0],
            self.actions["confirm"]: self.chain[1],
        }
        self.targets = {
            self.actions["hold"]: self.chain[1],
            self.actions["confirm"]: self.chain[2],
        }
        self.docks = [f"dock-{pick[16][:5]}",
                      f"dock-{pick[17][:5]}"]

        self._keys: dict[str, str] = {}
        for idx, cred in enumerate(("actor-a", "actor-b",
                                    "actor-admin")):
            self._keys[cred] = f"clerk:{pick[18]}.{idx}"
        self._principals = frozenset(self._keys.values())
        self._harbormaster = self._keys["actor-admin"]

        # five berths in two docks; holders alternate so both probe
        # identities own berths and each probe target has a
        # third-party control berth in the same dock.
        self._berths: dict[str, dict[str, Any]] = {}
        self._windows: dict[str, list[tuple[int, int]]] = {}
        self._docks: dict[str, str] = {}
        base = 10_000 + spec.seed * 17
        durations = [rnd.randrange(60, 200) for _ in self.chain]
        self._now = base + durations[0] // 2
        for idx in range(5):
            owner = self._keys[
                ("actor-a", "actor-b", "actor-a", "actor-b",
                 "actor-a")[idx]]
            berth_id = f"{pick[19][:4]}-{500 + idx}"
            dock = self.docks[idx // 3]
            self._berths[berth_id] = {
                "berth_id": berth_id,
                self.owner_field: owner,
                self.wf_field: berth_id,
                self.kind_field: f"class-{idx % 2}",
                self.dock_field: dock,
            }
            # stage windows on the fixed clock: stage n covers
            # [base + sum(durations[:n]), base + sum(durations[:n+1])).
            lo = base
            bounds: list[tuple[int, int]] = []
            for span in durations:
                bounds.append((lo, lo + span))
                lo += span
            self._windows[berth_id] = bounds
            self._docks[berth_id] = dock
        self._identity_target = sorted(self._berths)[-1]

    # -- state derivation (window scan, not a pointer) --------------

    def _stage_index(self, berth_id: str) -> int:
        """The stage whose window contains the clock: state is
        DERIVED from the windows, and a transition rewrites the
        next stage's bounds rather than mutating a pointer. When
        several windows contain the clock (the rewritten next
        stage starts at the clock while the current one has not
        ended), the LATEST stage wins: the pipeline never rewinds."""
        bounds = self._windows[berth_id]
        stage = len(bounds) - 1
        for i, (lo, hi) in enumerate(bounds):
            if lo <= self._now < hi:
                stage = i
        return stage

    def _state_of(self, berth_id: str) -> str:
        return self.chain[self._stage_index(berth_id)]

    def _window_of(self, berth_id: str) -> tuple[int, int]:
        return self._windows[berth_id][self._stage_index(berth_id)]

    def _advance(self, berth_id: str) -> None:
        """Apply the transition by rewriting the NEXT stage's
        window to start at the clock: the machine never rewinds
        because earlier windows keep their bounds."""
        i = self._stage_index(berth_id)
        _, hi = self._windows[berth_id][i + 1]
        self._windows[berth_id][i + 1] = (self._now, hi)

    # -- identity resolution (probe-credential protocol) -----------

    def _principal_of(self, value: str) -> str:
        return self._keys.get(
            value, value if value in self._principals else "")

    # -- policy gates ----------------------------------------------

    def _identity_required(self, berth_id: str, action: str) -> (
            tuple[bool, str]):
        """(check_holder, required_principal) for this transition.
        defective: skipped for confirm on the identity target only;
        transition_no_vuln: confirm is open to every identity on
        every berth (it implies nothing about authorization);
        unavailable_prereq: confirm's check is skipped on the
        identity target but its prerequisite hold requires the
        harbormaster principal, which no probe identity holds."""
        if action != self.actions["confirm"]:
            return True, ""
        if self.spec.variant == "transition_no_vuln":
            return False, ""
        if (self.spec.variant in ("defective",
                                  "unavailable_prereq")
                and berth_id == self._identity_target):
            return False, ""
        return True, ""

    def _hold_gate(self, berth_id: str, principal: str) -> bool:
        """unavailable_prereq: the target berth's hold transition
        legitimately requires the harbormaster role."""
        if (self.spec.variant == "unavailable_prereq"
                and berth_id == self._identity_target
                and principal != self._harbormaster):
            return False
        return True

    # -- handlers ---------------------------------------------------

    def handle_get(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for berth_id, berth in self._berths.items():
            if path == f"{prefix}{berth_id}":
                if not principal:
                    return self._denied(401)
                # reading a berth requires authentication, not
                # holding authority: transition authority is the
                # invariant under test and is deliberately separate
                # from read visibility.
                lo, hi = self._window_of(berth_id)
                headers = {
                    self.owner_header: berth[self.owner_field],
                    self.outcome_header: "processed"}
                body = dict(berth)
                body[self.state_field] = self._state_of(berth_id)
                body[self.win_from] = str(lo)
                body[self.win_until] = str(hi)
                return 200, headers, body
        return 404, {}, {"error": "no-such-berth"}

    def handle_post(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for berth_id, berth in self._berths.items():
            if path == f"{prefix}{berth_id}":
                if not principal:
                    return self._denied(401)
                action = params.get(self.action_param, "")
                state = self._state_of(berth_id)
                if action not in self.targets:
                    return 400, {
                        self.outcome_header: "refused"}, {
                        "error": "unknown-action",
                        self.state_field: state}
                # identity gate FIRST, window gate SECOND: the role
                # question is answered before the state question on
                # every berth (the skipped check is the defect under
                # test; the harbormaster-only hold is the legitimate
                # prerequisite boundary).
                check_holder, _ = self._identity_required(
                    berth_id, action)
                if check_holder and (
                        principal != berth[self.owner_field]):
                    return self._denied(403)
                if (action == self.actions["hold"]
                        and not self._hold_gate(
                            berth_id, principal)):
                    return self._denied(403)
                if self.sources[action] != state:
                    return 409, {
                        self.outcome_header: "refused"}, {
                        "error": "invalid-transition",
                        self.state_field: state}
                self._advance(berth_id)
                new_state = self._state_of(berth_id)
                return 200, {
                    self.owner_header: berth[self.owner_field],
                    self.outcome_header: "processed"}, {
                    "berth": berth_id,
                    self.state_field: new_state,
                    self.applied_field: True,
                    self.tby_field: principal}
        return 404, {}, {"error": "no-such-berth"}

    def _denied(self, code: int) -> tuple[int, dict[str, str], Any]:
        # identity refusals carry NO state field: the window gate's
        # refusal is the one that reports the current stage.
        return code, {self.outcome_header: "refused"}, {
            "error": "refused"}

    def _index(self) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "params": {"actor": self.actor_param,
                       "action": self.action_param},
            "actions": {"submit": self.actions["confirm"],
                        "approve": self.actions["confirm"]},
            "fields": {
                "owner": self.owner_field,
                "state": self.state_field,
                "applied": self.applied_field,
                "transitioned_by": self.tby_field,
                "workflow_id": self.wf_field,
                "kind": self.kind_field,
                "pool": self.dock_field,
            },
            "owner_header": self.owner_header,
            "outcome_header": self.outcome_header,
            "outcome_denied": "refused",
            "state_chains": {
                berth_id: list(self.chain)
                for berth_id in self._berths},
            "action_targets": {
                berth_id: dict(self.targets)
                for berth_id in self._berths},
        }
        if self.spec.variant == "transition_no_vuln":
            # Name the shared berths themselves: the documented-open
            # scan matches the surface's own published workflow ids
            # against its published documentation, so a claim of
            # documented openness must say WHICH berths it covers.
            shared = " and ".join(sorted(self._berths))
            schema["desk_notes"] = (
                f"{shared} run a shared mooring window: the confirm "
                "step is open to any clerk on every berth; this is "
                "documented behavior, not an escalation path")
        kinds = {
            f"/{self.route}/{berth_id}": "workflow"
            for berth_id in self._berths}
        return {
            "api": {
                "desk": [
                    {"path": f"/{self.route}/{berth_id}",
                     "role": "berth",
                     self.actor_param: "clerk",
                     self.action_param: "action"}
                    for berth_id in sorted(self._berths)],
            },
            "kinds": kinds,
            "schema": schema,
        }


class _Handler(BaseHTTPRequestHandler):
    app: BerthApp

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


class BerthServer:
    """Own serving loop (duplicated per app by design, not shared)."""

    def __init__(self, spec: BerthSpec) -> None:
        self.app = BerthApp(spec)
        self.requests = 0
        self._http = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._http.daemon_threads = True
        handler = type("_Bound", (_Handler,), {"app": self.app})
        self._http.RequestHandlerClass = handler
        self.origin = f"http://127.0.0.1:{self._http.server_port}"

    def __enter__(self) -> "BerthServer":
        self._thread = threading.Thread(
            target=self._http.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._http.shutdown()
        self._http.server_close()

    def request_count(self) -> int:
        return self.requests

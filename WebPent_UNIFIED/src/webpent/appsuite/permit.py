"""PermitDesk: an independently implemented licensing-desk
application.

L10 §Phase 1 development case (generation-3 dev block). A permit
pipeline whose state is a CONJUNCTIVE CHECKLIST — three named
requirement items that must EACH be satisfied before the final
approval operation is even reachable — rather than a linear
transition chain, a window table or a tally. Developed without
reusing any other app's implementation, route names, identities or
labels:

- each permit carries a checklist of the desk's three GLOBAL
  requirement items; state is derived from how many are satisfied
  (intake, review, ready), and approval closes the file
  (approved);
- the satisfy operation advances the LOWEST unmet item and is
  reserved to the permit's assigned examiner; approval requires
  the checklist COMPLETE and the actor to BE the examiner: two
  independent gates over a conjunctive state;
- defective — on ONE permit the approval operation skips the
  examiner check WHENEVER THE CHECKLIST IS COMPLETE: a
  state-conditional authorization flaw that is unobservable until
  the examiner has performed the full multi-step setup (three
  satisfy transitions). Before the checklist is complete a
  cross-identity approval is refused by the identity gate (403),
  never by the checklist gate;
- secured — both gates hold everywhere: ground truth clean;
- transition_no_vuln — satisfy and approve are open to every
  authenticated identity on every permit and DOCUMENTED in the
  index note: transitions that succeed cross-identity and imply
  nothing about authorization (ground truth clean; a confirmation
  there is a false positive). The checklist gate itself still
  applies: an approval with unmet requirements is refused
  regardless of who asks;
- unavailable_prereq — the approval check is skipped on the target
  permit, but satisfying its checklist legitimately requires the
  external inspector principal, which no probe identity holds:
  the prerequisite state is unattainable within the
  investigation's scope (ground truth clean; a failed setup here
  must never become a negative security verdict);
- refusal bodies use a NESTED refusal envelope: an identity
  refusal carries only a reason code, a checklist refusal carries
  the unmet item names and the derived stage;
- vocabulary, stage names, requirement names, action names, ids
  and header names are generated from this module's own draw of
  the appsuite wordlist and the per-instance seed;
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
    "apogee", "bolide", "chromosphere", "azimuth", "parallax",
    "zenith", "nadir", "albedo", "barycenter", "comet", "dust",
    "ecliptic", "flare", "gravity", "horizon", "ionosphere",
    "jovian", "kuiper", "limb", "meteor", "nebula", "radiant",
    "synodic", "transit",
)

VARIANTS = (
    "defective", "secured", "transition_no_vuln",
    "unavailable_prereq",
)


@dataclass(frozen=True)
class PermitSpec:
    seed: int
    variant: str = "defective"

    def __post_init__(self) -> None:
        if self.variant not in VARIANTS:
            raise ValueError(self.variant)

    @property
    def instance_id(self) -> str:
        return f"pm-{100 + self.seed % 100}"


class PermitApp:
    def __init__(self, spec: PermitSpec) -> None:
        if spec.variant not in VARIANTS:
            raise ValueError(spec.variant)
        self.spec = spec
        self.requests = 0
        self._lock = threading.Lock()
        rnd = random.Random(f"permit/{spec.seed}/{spec.variant}")
        pick = rnd.sample(WORDS, 22)

        self.route = pick[0]                     # permit route
        self.actor_param = pick[1][:4]           # credential param
        self.action_param = pick[2][:4]          # action param
        self.owner_header = f"X-{pick[3].capitalize()}-Examiner"
        self.outcome_header = f"X-{pick[4].capitalize()}-Result"
        self.owner_field = pick[5][:6]           # examiner role
        self.state_field = pick[6][:6]           # stage role
        self.applied_field = pick[7][:6]         # applied role
        self.tby_field = pick[8][:6]             # acted-by role
        self.wf_field = pick[9][:6]              # permit-id role
        self.kind_field = pick[10][:6]           # class role
        self.office_field = pick[11][:6]         # office role
        self.items_field = pick[12][:6]          # unmet-items role
        # three GLOBAL requirement items; every permit's checklist
        # holds all three.
        self.items = [f"{pick[13][:5]}-req",
                      f"{pick[14][:5]}-req",
                      f"{pick[15][:5]}-req"]
        # derived stages: intake, review, ready, then approved.
        self.chain = [f"{pick[16][:5]}-{n}" for n in range(1, 5)]
        self.actions = {
            "satisfy": f"pm-{pick[17][:5]}",
            "approve": f"pm-{pick[18][:5]}",
        }
        self.targets = {
            self.actions["satisfy"]: self.chain[1],
            self.actions["approve"]: self.chain[3],
        }
        self.offices = [f"office-{pick[19][:5]}",
                        f"office-{pick[20][:5]}"]

        self._keys: dict[str, str] = {}
        for idx, cred in enumerate(("actor-a", "actor-b",
                                    "actor-admin")):
            self._keys[cred] = f"officer:{pick[21]}.{idx}"
        self._principals = frozenset(self._keys.values())
        # the external inspector is a principal NO probe credential
        # maps to: its role is unreachable within scope.
        self._inspector = f"inspector:{pick[12]}"

        # four permits; examiners alternate so each probe identity
        # examines two permits and every probe target has a
        # third-party control permit in the same office.
        self._permits: dict[str, dict[str, Any]] = {}
        self._satisfied: dict[str, list[str]] = {}
        self._offices: dict[str, str] = {}
        for idx in range(4):
            examiner = self._keys[
                ("actor-a", "actor-b", "actor-a",
                 "actor-b")[idx]]
            pm_id = f"{pick[11][:4]}-{800 + idx}"
            office = self.offices[idx // 2]
            self._permits[pm_id] = {
                "pm_id": pm_id,
                self.owner_field: examiner,
                self.wf_field: pm_id,
                self.kind_field: f"file-{idx % 2}",
                self.office_field: office,
            }
            self._satisfied[pm_id] = []
            self._offices[pm_id] = office
        self._identity_target = sorted(self._permits)[-1]

    # -- state derivation (checklist scan, not a pointer) -----------

    def _unmet(self, pm_id: str) -> list[str]:
        return [item for item in self.items
                if item not in self._satisfied[pm_id]]

    def _stage_of(self, pm_id: str) -> str:
        if self.actions["approve"] in self._satisfied[pm_id]:
            return self.chain[3]
        done = len(self._satisfied[pm_id])
        return self.chain[done] if done < 3 else self.chain[2]

    # -- identity resolution (probe-credential protocol) -----------

    def _principal_of(self, value: str) -> str:
        return self._keys.get(
            value, value if value in self._principals else "")

    # -- policy gates ----------------------------------------------

    def _approve_checks_examiner(self, pm_id: str) -> bool:
        """Whether approval consults the permit's examiner.
        defective: skipped on the identity target ONLY WHEN the
        checklist is complete (the state-conditional flaw);
        transition_no_vuln: skipped everywhere; unavailable_prereq:
        skipped on the target permit (unobservable, because its
        checklist can never be completed in scope)."""
        if self.spec.variant == "transition_no_vuln":
            return False
        return not (self.spec.variant in ("defective",
                                          "unavailable_prereq")
                    and pm_id == self._identity_target
                    and not self._unmet(pm_id))

    def _satisfy_gate(self, pm_id: str, principal: str) -> bool:
        """Who may satisfy the checklist. transition_no_vuln: any
        authenticated identity. unavailable_prereq: the target
        permit legitimately requires the external inspector
        principal. Otherwise: the assigned examiner."""
        if self.spec.variant == "transition_no_vuln":
            return True
        if (self.spec.variant == "unavailable_prereq"
                and pm_id == self._identity_target):
            return principal == self._inspector
        return principal == self._permits[pm_id][self.owner_field]

    def _approve_gate(self, pm_id: str, principal: str) -> bool:
        if not self._approve_checks_examiner(pm_id):
            return True
        return principal == self._permits[pm_id][self.owner_field]

    # -- handlers ---------------------------------------------------

    def handle_get(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for pm_id, pm in self._permits.items():
            if path == f"{prefix}{pm_id}":
                if not principal:
                    return self._denied(401)
                # reading a permit requires authentication, not
                # examination authority: approval authority is the
                # invariant under test and is deliberately separate
                # from read visibility.
                headers = {
                    self.owner_header: pm[self.owner_field],
                    self.outcome_header: "processed"}
                body = dict(pm)
                body[self.state_field] = self._stage_of(pm_id)
                body[self.items_field] = list(
                    self._satisfied[pm_id])
                return 200, headers, body
        return 404, {}, self._refusal("no-such-permit")

    def handle_post(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for pm_id, pm in self._permits.items():
            if path == f"{prefix}{pm_id}":
                if not principal:
                    return self._denied(401)
                action = params.get(self.action_param, "")
                stage = self._stage_of(pm_id)
                if action not in self.targets:
                    return 400, {
                        self.outcome_header: "refused"}, {
                        **self._refusal("unknown-action"),
                        self.state_field: stage}
                if action == self.actions["approve"]:
                    if stage == self.chain[3]:
                        return 409, {
                            self.outcome_header: "refused"}, {
                            **self._refusal("already-approved"),
                            self.state_field: stage}
                    # identity gate FIRST, checklist gate SECOND:
                    # the skipped check is the defect under test, so
                    # a cross-identity approval BEFORE the checklist
                    # is complete is refused by the identity gate.
                    if not self._approve_gate(pm_id, principal):
                        return self._denied(403)
                    unmet = self._unmet(pm_id)
                    if unmet:
                        return 409, {
                            self.outcome_header: "refused"}, {
                            **self._refusal(
                                "requirements-unmet"),
                            self.items_field: unmet,
                            self.state_field: stage}
                    self._satisfied[pm_id].append(
                        self.actions["approve"])
                    return 200, {
                        self.owner_header: pm[self.owner_field],
                        self.outcome_header: "processed"}, {
                        "permit": pm_id,
                        self.state_field: self._stage_of(pm_id),
                        self.applied_field: True,
                        self.tby_field: principal,
                        "changes": ["approved"]}
                # satisfy
                if stage == self.chain[3]:
                    return 409, {
                        self.outcome_header: "refused"}, {
                        **self._refusal("already-approved"),
                        self.state_field: stage}
                if not self._satisfy_gate(pm_id, principal):
                    return self._denied(403)
                item = self._unmet(pm_id)[0]
                self._satisfied[pm_id].append(item)
                return 200, {
                    self.owner_header: pm[self.owner_field],
                    self.outcome_header: "processed"}, {
                    "permit": pm_id,
                    self.state_field: self._stage_of(pm_id),
                    self.applied_field: True,
                    self.tby_field: principal,
                    "changes": [item]}
        return 404, {}, self._refusal("no-such-permit")

    def _refusal(self, reason: str) -> dict[str, Any]:
        # NESTED refusal envelope: a different response shape from
        # the flat error bodies of the earlier corpora.
        return {"refusal": {"reason": reason}}

    def _denied(self, code: int) -> tuple[int, dict[str, str], Any]:
        return code, {self.outcome_header: "refused"}, {
            **self._refusal("not-authorized")}

    def _index(self) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "params": {"actor": self.actor_param,
                       "action": self.action_param},
            "actions": {"submit": self.actions["satisfy"],
                        "approve": self.actions["approve"]},
            "fields": {
                "owner": self.owner_field,
                "state": self.state_field,
                "applied": self.applied_field,
                "transitioned_by": self.tby_field,
                "workflow_id": self.wf_field,
                "kind": self.kind_field,
                "pool": self.office_field,
            },
            "owner_header": self.owner_header,
            "outcome_header": self.outcome_header,
            "outcome_denied": "refused",
            "checklist": {
                pm_id: list(self.items)
                for pm_id in self._permits},
            "state_chains": {
                pm_id: list(self.chain)
                for pm_id in self._permits},
            "action_targets": {
                pm_id: dict(self.targets)
                for pm_id in self._permits},
        }
        if self.spec.variant == "transition_no_vuln":
            # Name the open permits themselves: the documented-open
            # scan matches the surface's own published workflow ids
            # against its published documentation, so a claim of
            # documented openness must say WHICH workflows it
            # covers.
            shared = " and ".join(sorted(self._permits))
            schema["desk_notes"] = (
                f"{shared} run a collective examination desk: any "
                "licensed officer may satisfy requirements and "
                "approve on every permit; this is documented "
                "behavior, not an escalation path")
        kinds = {
            f"/{self.route}/{pm_id}": "workflow"
            for pm_id in self._permits}
        return {
            "api": {
                "desk": [
                    {"path": f"/{self.route}/{pm_id}",
                     "role": "permit",
                     self.actor_param: "officer",
                     self.action_param: "action"}
                    for pm_id in sorted(self._permits)],
            },
            "kinds": kinds,
            "schema": schema,
        }


class _Handler(BaseHTTPRequestHandler):
    app: PermitApp

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
            status, headers, body = 500, {}, {
                "refusal": {"reason": "internal"}}
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


class PermitServer:
    """Own serving loop (duplicated per app by design, not shared)."""

    def __init__(self, spec: PermitSpec) -> None:
        self.app = PermitApp(spec)
        self.requests = 0
        self._http = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._http.daemon_threads = True
        handler = type("_Bound", (_Handler,), {"app": self.app})
        self._http.RequestHandlerClass = handler
        self.origin = f"http://127.0.0.1:{self._http.server_port}"

    def __enter__(self) -> PermitServer:
        self._thread = threading.Thread(
            target=self._http.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._http.shutdown()
        self._http.server_close()

    def request_count(self) -> int:
        return self.requests

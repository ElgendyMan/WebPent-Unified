"""ConsignDesk: an independently implemented consignment/escrow
desk application.

L10 §Phase 1 development case (generation-3 dev block). A funding
and settlement pipeline whose state is a DERIVED TALLY of appended
records rather than a state pointer or a window table, and whose
release authority is resolved through a PER-DESK PAIRING TABLE —
an ownership record that lives OUTSIDE the consignment itself, so
authorization can be miswired to another resource's ownership
record (the cross-resource ownership family). Developed without
reusing any other app's implementation, route names, identities or
labels:

- state is derived by scanning a consignment's record list: a
  settlement record wins, else a funding record, else the initial
  stage; nothing mutates a pointer;
- the release operation is legal only from the funded stage (the
  tally gate), and a funding operation is legal until settled;
- funding is reserved to the consignment's CONSIGNOR on every
  variant: no benign open transition exists on any surface, so a
  cross-identity transition that succeeds anywhere is either the
  defect's miswire or the DOCUMENTED openness of the
  transition-succeeds-no-vuln variant (whose note covers the
  settlement record only, not funding);
- ENFORCEMENT ORDER is the reverse of the L9 apps: the tally gate
  is answered BEFORE the identity question, so an early release
  attempt on an unfunded consignment is refused by the tally gate
  (409 naming the stage field), never by the identity gate;
- release authority is the desk's custodian OF RECORD (the pairing
  table), not the consignment's own custodian field: the check
  consults a resource OTHER than the one being released;
- defective — the defect-desk consignments' releases consult the
  OTHER desk's pairing entry, so one probe identity (a custodian
  of record on the healthy desk) can settle defect-desk
  consignments while the defect desk's own custodian of record is
  refused; the defect only manifests after a funding record exists
  (a prerequisite the investigation must establish);
- secured — the pairing is consulted correctly everywhere: ground
  truth clean;
- transition_no_vuln — release is open to every authenticated
  identity on every consignment and DOCUMENTED in the index note:
  a transition that succeeds cross-identity and implies nothing
  about authorization (ground truth clean; a confirmation there is
  a false positive);
- unavailable_prereq — the release check is skipped on the defect
  desk, but funding a defect-desk consignment legitimately
  requires the external registrar principal, which no probe
  identity holds: the prerequisite stage is unattainable within
  the investigation's scope (ground truth clean; a failed setup
  here must never become a negative security verdict);
- refusal bodies use a NESTED refusal envelope (a reason code
  object) rather than the flat error bodies of the earlier
  corpora: a tally refusal carries the stage field, an identity
  refusal does not;
- vocabulary, stage names, action names, ids and header names are
  generated from this module's own draw of the appsuite wordlist
  and the per-instance seed;
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
    "adit", "borax", "claim", "druse", "euclase", "fissure",
    "geode", "halide", "inclusion", "sluice", "karst", "lode",
    "malachite", "nugget", "opal", "dross", "amethyst", "rimrock",
    "stope", "tourmaline", "vug", "witherite", "xenolith",
    "coprolite",
)

VARIANTS = (
    "defective", "secured", "transition_no_vuln",
    "unavailable_prereq",
)


@dataclass(frozen=True)
class ConsignSpec:
    seed: int
    variant: str = "defective"

    def __post_init__(self) -> None:
        if self.variant not in VARIANTS:
            raise ValueError(self.variant)

    @property
    def instance_id(self) -> str:
        return f"cs-{100 + self.seed % 100}"


class ConsignApp:
    def __init__(self, spec: ConsignSpec) -> None:
        if spec.variant not in VARIANTS:
            raise ValueError(spec.variant)
        self.spec = spec
        self.requests = 0
        self._lock = threading.Lock()
        rnd = random.Random(f"consign/{spec.seed}/{spec.variant}")
        pick = rnd.sample(WORDS, 22)

        self.route = pick[0]                     # consignment route
        self.actor_param = pick[1][:4]           # credential param
        self.action_param = pick[2][:4]          # action param
        self.owner_header = f"X-{pick[3].capitalize()}-Party"
        self.outcome_header = f"X-{pick[4].capitalize()}-Result"
        self.owner_field = pick[5][:6]           # consignor role
        self.custodian_field = pick[6][:6]       # custodian role
        self.state_field = pick[7][:6]           # stage role
        self.applied_field = pick[8][:6]         # applied role
        self.tby_field = pick[9][:6]             # acted-by role
        self.wf_field = pick[10][:6]             # consignment-id role
        self.kind_field = pick[11][:6]           # class role
        self.desk_field = pick[12][:6]           # desk role
        self.records_field = pick[13][:6]        # records role
        # derived stages: funding then settlement.
        self.chain = [f"{pick[14][:5]}-{n}" for n in range(1, 4)]
        self.actions = {
            "pledge": f"cs-{pick[15][:5]}",
            "release": f"cs-{pick[16][:5]}",
        }
        self.targets = {
            self.actions["pledge"]: self.chain[1],
            self.actions["release"]: self.chain[2],
        }
        self.desks = [f"desk-{pick[17][:5]}",
                      f"desk-{pick[18][:5]}"]

        self._keys: dict[str, str] = {}
        for idx, cred in enumerate(("actor-a", "actor-b",
                                    "actor-admin")):
            self._keys[cred] = f"agent:{pick[19]}.{idx}"
        self._principals = frozenset(self._keys.values())
        # the external registrar is a principal NO probe credential
        # maps to: its role is unreachable within scope.
        self._registrar = f"registrar:{pick[20]}"

        # the pairing table: desk -> custodian of record. Release
        # authority is looked up HERE, not on the consignment.
        self._pairing = {
            self.desks[0]: self._keys["actor-a"],
            self.desks[1]: self._keys["actor-b"],
        }
        self.defect_desk = self.desks[1]

        # four consignments, two per desk; parties cross the desks
        # so the healthy desk always offers a third-party control
        # and the defect desk's own custodian of record is a
        # different probe identity than the miswired one.
        self._consignments: dict[str, dict[str, Any]] = {}
        self._records: dict[str, list[dict[str, str]]] = {}
        self._desks: dict[str, str] = {}
        for idx in range(4):
            consignor = self._keys[
                ("actor-a", "actor-b", "actor-a",
                 "actor-b")[idx]]
            custodian = self._keys[
                ("actor-a", "actor-b", "actor-b",
                 "actor-a")[idx]]
            cs_id = f"{pick[21][:4]}-{700 + idx}"
            desk = self.desks[idx // 2]
            self._consignments[cs_id] = {
                "cs_id": cs_id,
                self.owner_field: consignor,
                self.custodian_field: custodian,
                self.wf_field: cs_id,
                self.kind_field: f"lot-{idx % 2}",
                self.desk_field: desk,
            }
            self._records[cs_id] = []
            self._desks[cs_id] = desk

    # -- state derivation (tally scan, not a pointer) ---------------

    def _stage_of(self, cs_id: str) -> str:
        kinds = [rec["type"] for rec in self._records[cs_id]]
        if self.actions["release"] in kinds:
            return self.chain[2]
        if self.actions["pledge"] in kinds:
            return self.chain[1]
        return self.chain[0]

    # -- identity resolution (probe-credential protocol) -----------

    def _principal_of(self, value: str) -> str:
        return self._keys.get(
            value, value if value in self._principals else "")

    # -- policy gates ----------------------------------------------

    def _release_authority(self, cs_id: str) -> str:
        """The principal the release check consults. defective:
        defect-desk consignments consult the OTHER desk's pairing
        entry (the cross-resource miswire); every other variant
        consults the consignment's own desk."""
        desk = self._desks[cs_id]
        if (self.spec.variant == "defective"
                and desk == self.defect_desk):
            desk = self.desks[0]
        return self._pairing[desk]

    def _release_open(self, cs_id: str) -> bool:
        if self.spec.variant == "transition_no_vuln":
            return True
        return (self.spec.variant == "unavailable_prereq"
                and self._desks[cs_id] == self.defect_desk)

    def _pledge_gate(self, cs_id: str, principal: str) -> bool:
        """Funding is reserved to the consignment's CONSIGNOR on
        every variant (the owner field the index publishes), so the
        only cross-identity transition that can succeed anywhere is
        the one the surface documents. unavailable_prereq
        additionally requires the external registrar principal on
        defect-desk consignments."""
        if (self.spec.variant == "unavailable_prereq"
                and self._desks[cs_id] == self.defect_desk
                and principal != self._registrar):
            return False
        return principal == self._consignments[cs_id][
            self.owner_field]

    # -- handlers ---------------------------------------------------

    def handle_get(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for cs_id, cs in self._consignments.items():
            if path == f"{prefix}{cs_id}":
                if not principal:
                    return self._denied(401)
                # reading a consignment requires authentication, not
                # settlement authority: release authority is the
                # invariant under test and is deliberately separate
                # from read visibility.
                headers = {
                    self.owner_header: cs[self.owner_field],
                    self.outcome_header: "processed"}
                body = dict(cs)
                body[self.state_field] = self._stage_of(cs_id)
                body[self.records_field] = [
                    dict(rec) for rec in self._records[cs_id]]
                return 200, headers, body
        return 404, {}, self._refusal("no-such-consignment")

    def handle_post(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for cs_id, cs in self._consignments.items():
            if path == f"{prefix}{cs_id}":
                if not principal:
                    return self._denied(401)
                action = params.get(self.action_param, "")
                stage = self._stage_of(cs_id)
                if action not in self.targets:
                    return 400, {
                        self.outcome_header: "refused"}, {
                        **self._refusal("unknown-action"),
                        self.state_field: stage}
                # tally gate FIRST, identity question SECOND: the
                # order is the reverse of the L9 corpora, so a
                # release attempt on an unfunded consignment is
                # refused by the tally gate regardless of who asks.
                if action == self.actions["release"] and (
                        stage != self.chain[1]):
                    return 409, {
                        self.outcome_header: "refused"}, {
                        **self._refusal("stage-unmet"),
                        self.state_field: stage}
                if action == self.actions["pledge"] and (
                        stage == self.chain[2]):
                    return 409, {
                        self.outcome_header: "refused"}, {
                        **self._refusal("already-settled"),
                        self.state_field: stage}
                if action == self.actions["pledge"]:
                    if not self._pledge_gate(cs_id, principal):
                        return self._denied(403)
                    self._records[cs_id].append(
                        {"type": self.actions["pledge"],
                         self.tby_field: principal})
                else:
                    if self._release_open(cs_id):
                        authority = principal
                    else:
                        authority = self._release_authority(cs_id)
                    if principal != authority:
                        # identity refusals carry NO stage field:
                        # the tally gate's refusal is the one that
                        # reports the derived stage.
                        return self._denied(403)
                    self._records[cs_id].append(
                        {"type": self.actions["release"],
                         self.tby_field: principal})
                return 200, {
                    self.owner_header: cs[self.owner_field],
                    self.outcome_header: "processed"}, {
                    "consignment": cs_id,
                    self.state_field: self._stage_of(cs_id),
                    self.applied_field: True,
                    self.tby_field: principal,
                    "changes": [action]}
        return 404, {}, self._refusal("no-such-consignment")

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
            "actions": {"submit": self.actions["pledge"],
                        "approve": self.actions["release"]},
            "fields": {
                "owner": self.owner_field,
                "custodian": self.custodian_field,
                "state": self.state_field,
                "applied": self.applied_field,
                "transitioned_by": self.tby_field,
                "workflow_id": self.wf_field,
                "kind": self.kind_field,
                "pool": self.desk_field,
            },
            "owner_header": self.owner_header,
            "outcome_header": self.outcome_header,
            "outcome_denied": "refused",
            "state_chains": {
                cs_id: list(self.chain)
                for cs_id in self._consignments},
            "action_targets": {
                cs_id: dict(self.targets)
                for cs_id in self._consignments},
        }
        if self.spec.variant == "transition_no_vuln":
            # Name the open consignments themselves: the
            # documented-open scan matches the surface's own
            # published workflow ids against its published
            # documentation, so a claim of documented openness must
            # say WHICH workflows it covers.
            shared = " and ".join(sorted(self._consignments))
            schema["desk_notes"] = (
                f"{shared} settle under a collective escrow policy: "
                "any authenticated agent may append the settlement "
                "record on every consignment; this is documented "
                "behavior, not an escalation path")
        kinds = {
            f"/{self.route}/{cs_id}": "workflow"
            for cs_id in self._consignments}
        return {
            "api": {
                "desk": [
                    {"path": f"/{self.route}/{cs_id}",
                     "role": "consignment",
                     self.actor_param: "agent",
                     self.action_param: "action"}
                    for cs_id in sorted(self._consignments)],
            },
            "kinds": kinds,
            "schema": schema,
        }


class _Handler(BaseHTTPRequestHandler):
    app: ConsignApp

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


class ConsignServer:
    """Own serving loop (duplicated per app by design, not shared)."""

    def __init__(self, spec: ConsignSpec) -> None:
        self.app = ConsignApp(spec)
        self.requests = 0
        self._http = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._http.daemon_threads = True
        handler = type("_Bound", (_Handler,), {"app": self.app})
        self._http.RequestHandlerClass = handler
        self.origin = f"http://127.0.0.1:{self._http.server_port}"

    def __enter__(self) -> ConsignServer:
        self._thread = threading.Thread(
            target=self._http.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._http.shutdown()
        self._http.server_close()

    def request_count(self) -> int:
        return self.requests

"""SlotDesk: an independently implemented booking-desk application.

HELD-OUT app for L8 §2: the IDEMPOTENT-MUTATION invariant family.
Submitting the same idempotency key twice must apply a hold exactly
once; the second submission must return the first receipt without
changing state. This invariant family was never used to tune the
engine: no engine generator, oracle or binding covers it (the
engine's six families are identity boundary, price integrity,
workflow identity, workflow order, boundary limit and grant replay),
so the app deliberately sits OUTSIDE the engine's hypothesis space.

Design notes establishing independence:

- state is a per-slot HOLD LEDGER: each hold is (actor, idem key,
  receipt); capacity is enforced per slot;
- the defective variant re-applies a duplicate submission for ONE
  queue class, so a second submission with the same key mutates
  state again (double-apply);
- the secured lookalike accepts the same submission shape and
  collapses duplicates to the original receipt;
- the ambiguous variant is a DOCUMENTED waitlist class: every
  submission is deliberately recorded (ground truth clean, a
  confirmation there is a false positive);
- the multi-observation variant scopes the double-apply to one
  queue class only, so evidence requires comparing submissions
  across slots;
- reads are holder-gated (only the holder sees a slot's ledger), so
  identity correlation has material without any owner-field
  comparison defect being present;
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
class SlotDeskSpec:
    seed: int
    variant: str = "defective"

    def __post_init__(self) -> None:
        if self.variant not in VARIANTS:
            raise ValueError(self.variant)

    @property
    def instance_id(self) -> str:
        return f"sd-{100 + self.seed % 100}"


class SlotDeskApp:
    def __init__(self, spec: SlotDeskSpec) -> None:
        if spec.variant not in VARIANTS:
            raise ValueError(spec.variant)
        self.spec = spec
        self.requests = 0
        self._lock = threading.Lock()
        rnd = random.Random(f"slots/{spec.seed}/{spec.variant}")
        pick = rnd.sample(WORDS, 14)

        self.route = pick[0]                     # desk route segment
        self.hold_seg = pick[1]                  # hold sub-segment
        self.actor_param = pick[2][:4]           # credential param
        self.idem_param = pick[3][:4]            # idempotency key
        self.owner_header = f"X-{pick[4].capitalize()}-Holder"
        self.outcome_header = f"X-{pick[5].capitalize()}-Result"
        self.owner_field = pick[6][:6]           # body owner role
        self.kind_field = pick[7][:6]            # body kind role
        self.holds_field = pick[8][:6]           # hold count role
        self.receipt_field = pick[9][:6]         # receipt role
        self.applied_field = pick[10][:6]        # applied role
        self.classes = (f"{pick[11][:5]}-a",
                        f"{pick[12][:5]}-b")
        self.capacity = 4

        self._keys: dict[str, str] = {}
        for idx, cred in enumerate(("actor-a", "actor-b",
                                    "actor-admin")):
            self._keys[cred] = f"guest:{pick[13]}.{idx}"
        self._principals = frozenset(self._keys.values())

        # slots: two per class; each slot is pre-assigned to one
        # principal (holder-gated reads, no owner-comparison defect).
        self._slots: dict[str, dict[str, Any]] = {}
        self._ledger: dict[str, list[dict[str, Any]]] = {}
        self._receipts: dict[str, dict[str, Any]] = {}
        for idx in range(4):
            slot_id = f"{pick[8][:4]}-{300 + idx}"
            owner = self._keys[("actor-a", "actor-b",
                                "actor-admin")[idx % 3]]
            self._slots[slot_id] = {
                "slot_id": slot_id,
                self.owner_field: owner,
                self.kind_field: self.classes[idx % 2],
            }
            self._ledger[slot_id] = []
        # the waitlist class is the second one.
        self._waitlist_class = self.classes[1]

    # -- identity resolution (probe-credential protocol) -----------

    def _principal_of(self, value: str) -> str:
        return self._keys.get(
            value, value if value in self._principals else "")

    # -- the invariant ----------------------------------------------

    def _collapses_duplicates(self, slot_id: str) -> bool:
        """Whether a duplicate submission re-uses the first receipt.

        THE defect surface, and its documented lookalike. On the
        waitlist class the defective and multi_observation variants
        re-apply a duplicate submission (the same idempotency key
        mutates state twice). The ambiguous variant behaves
        IDENTICALLY there, but the behavior is documented in the
        index (waitlist slots deliberately record every submission),
        so ground truth is clean and a confirmation there is a false
        positive. Everywhere else, and in the secured variant
        everywhere at all, duplicates collapse to the first receipt.
        """
        slot = self._slots[slot_id]
        if slot[self.kind_field] != self._waitlist_class:
            return True
        if self.spec.variant in ("defective",
                                 "multi_observation",
                                 "ambiguous"):
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
        for slot_id, slot in self._slots.items():
            if path == f"{prefix}{slot_id}":
                if not principal:
                    return self._denied(401)
                if principal != slot[self.owner_field]:
                    return self._denied(403)
                headers = {
                    self.owner_header: slot[self.owner_field],
                    self.outcome_header: "processed"}
                return 200, headers, {
                    "slot": slot_id,
                    self.owner_field: slot[self.owner_field],
                    self.kind_field: slot[self.kind_field],
                    self.holds_field: len(self._ledger[slot_id])}
        return 404, {}, {"error": "no-such-slot"}

    def handle_post(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        prefix = f"/{self.route}/"
        for slot_id, slot in self._slots.items():
            hold_path = f"{prefix}{slot_id}/{self.hold_seg}"
            if path == hold_path:
                if not principal:
                    return self._denied(401)
                if principal != slot[self.owner_field]:
                    return self._denied(403)
                idem = params.get(self.idem_param, "")
                if not idem:
                    return 400, {
                        self.outcome_header: "refused"}, {
                        "error": "idem-required"}
                receipt = self._receipts.get((slot_id, principal,
                                              idem))
                if receipt is not None:
                    if self._collapses_duplicates(slot_id):
                        return 200, {
                            self.outcome_header: "processed"}, {
                            "slot": slot_id,
                            self.receipt_field: receipt[
                                self.receipt_field],
                            self.holds_field: len(
                                self._ledger[slot_id]),
                            self.applied_field: False}
                    # THE defect: the duplicate applies again.
                    receipt = None
                if len(self._ledger[slot_id]) >= self.capacity:
                    return 409, {
                        self.outcome_header: "refused"}, {
                        "error": "slot-full"}
                new_receipt = (
                    f"rc-{len(self._receipts) + 1}")
                entry = {
                    "actor": principal, "idem": idem,
                    self.receipt_field: new_receipt}
                self._ledger[slot_id].append(entry)
                record = {
                    self.receipt_field: new_receipt,
                    self.holds_field: len(self._ledger[slot_id]),
                    self.applied_field: True}
                self._receipts[(slot_id, principal, idem)] = record
                return 200, {
                    self.outcome_header: "processed"}, {
                    "slot": slot_id, **record}
        return 404, {}, {"error": "no-such-slot"}

    def _denied(self, code: int) -> tuple[int, dict[str, str], Any]:
        return code, {self.outcome_header: "refused"}, {
            "error": "refused"}

    def _index(self) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "params": {"actor": self.actor_param,
                       "idem": self.idem_param},
            "fields": {"owner": self.owner_field,
                       "kind": self.kind_field},
            "owner_header": self.owner_header,
            "outcome_header": self.outcome_header,
            "outcome_denied": "refused",
        }
        if self.spec.variant == "ambiguous":
            schema["waitlist_notes"] = (
                f"{self._waitlist_class} slots are waitlist slots: "
                "every submission is deliberately recorded, "
                "duplicates included; this is documented behavior")
        kinds: dict[str, str] = {}
        slots_group: list[dict[str, str]] = []
        holds_group: list[dict[str, str]] = []
        for slot_id in sorted(self._slots):
            read_path = f"/{self.route}/{slot_id}"
            kinds[read_path] = "read"
            slots_group.append({
                "path": read_path, "role": "slot",
                self.actor_param: "guest"})
            hold_path = f"{read_path}/{self.hold_seg}"
            kinds[hold_path] = "mutate"
            holds_group.append({
                "path": hold_path, "role": "hold",
                self.actor_param: "guest",
                self.idem_param: "idem-key"})
        return {
            "api": {"schedule": slots_group,
                    "holds": holds_group},
            "kinds": kinds,
            "schema": schema,
        }


class _Handler(BaseHTTPRequestHandler):
    app: SlotDeskApp

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


class SlotDeskServer:
    """Own serving loop (duplicated per app by design, not shared)."""

    def __init__(self, spec: SlotDeskSpec) -> None:
        self.app = SlotDeskApp(spec)
        self.requests = 0
        self._http = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._http.daemon_threads = True
        handler = type("_Bound", (_Handler,), {"app": self.app})
        self._http.RequestHandlerClass = handler
        self.origin = f"http://127.0.0.1:{self._http.server_port}"

    def __enter__(self) -> "SlotDeskServer":
        self._thread = threading.Thread(
            target=self._http.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._http.shutdown()
        self._http.server_close()

    def request_count(self) -> int:
        return self.requests

"""L8 appsuite corpus roster.

Two blocks of generation-2 applications (see appsuite/__init__):

- DEV  (docvault, market, requisitions): the only block that may
  drive failure analysis and engine changes (mission section 5).
- HELD-OUT (ticketflow, slots): scored only after investigation
  finishes; if these outcomes ever influence an implementation
  decision, a fresh evaluation set is generated before final claims.
- HELD-OUT L9 (ledgerflow, berth): the stateful-investigation
  mission's own held-out block (per-app variant rotations, see
  _L9_VARIANTS), scored once after the dev block froze.
- L10 DEV (consign, permit): the generation-3 cross-application
  block (see _L10_VARIANTS), four variants each including the
  adversarial controls.

Variant rotation per app: defective, secured lookalike, ambiguous
(documented behavior, ground truth clean), multi-observation; the
L9 held-out apps carry their own rotations (see _L9_VARIANTS). The
seed space is disjoint from the L7 labsuite's (whose seeds run in
the 101-302 range with lab- instance ids); suite instance ids carry
their own app prefix (dv-/mk-/tf-/sd-/rq-/lf-/bh-).
"""
from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from webpent.appsuite.berth import BerthServer, BerthSpec
from webpent.appsuite.consign import ConsignServer, ConsignSpec
from webpent.appsuite.docvault import (
    DocVaultServer,
    DocVaultSpec,
)
from webpent.appsuite.ledgerflow import (
    LedgerFlowServer,
    LedgerFlowSpec,
)
from webpent.appsuite.market import MarketServer, MarketSpec
from webpent.appsuite.permit import PermitServer, PermitSpec
from webpent.appsuite.requisitions import (
    RequisitionsServer,
    RequisitionsSpec,
)
from webpent.appsuite.slots import SlotDeskServer, SlotDeskSpec
from webpent.appsuite.ticketflow import (
    TicketFlowServer,
    TicketFlowSpec,
)

VARIANT_ROTATION = (
    "defective", "secured", "ambiguous", "multi_observation")

# L9 §5 held-out rotation: per-app variant lists for the two apps
# added by the stateful-investigation mission. Each app declares
# its own rotation so seeds stay disjoint per variant and the L8
# blocks' rotation and seeds are untouched.
_L9_VARIANTS: dict[str, tuple[str, ...]] = {
    "ledgerflow": ("defective", "secured"),
    "berth": (
        "defective", "secured", "unavailable_prereq",
        "transition_no_vuln", "negative_control"),
}

# L10 §Phase 1 generation-3 rotation: each new dev app carries the
# mission's adversarial variants directly (transition-succeeds-no-
# vuln and unavailable/forbidden prerequisite) alongside defective
# and secured, instead of the L8 ambiguous/multi-observation pair.
_L10_VARIANTS: dict[str, tuple[str, ...]] = {
    "consign": (
        "defective", "secured", "transition_no_vuln",
        "unavailable_prereq"),
    "permit": (
        "defective", "secured", "transition_no_vuln",
        "unavailable_prereq"),
}

# app -> (seed base, spec class, server class). Seeds are disjoint
# across apps so instance ids never collide.
_APP_TABLE: dict[str, tuple[int, type, type]] = {
    "docvault": (1, DocVaultSpec, DocVaultServer),
    "market": (11, MarketSpec, MarketServer),
    "ticketflow": (21, TicketFlowSpec, TicketFlowServer),
    "slots": (31, SlotDeskSpec, SlotDeskServer),
    "requisitions": (41, RequisitionsSpec, RequisitionsServer),
    "ledgerflow": (51, LedgerFlowSpec, LedgerFlowServer),
    "berth": (61, BerthSpec, BerthServer),
    "consign": (71, ConsignSpec, ConsignServer),
    "permit": (81, PermitSpec, PermitServer),
}

DEV_APPS = ("docvault", "market", "requisitions")
HELDOUT_APPS = ("ticketflow", "slots")
HELDOUT_L9_APPS = ("ledgerflow", "berth")
L10_DEV_APPS = ("consign", "permit")


def _variants_for(app: str) -> tuple[str, ...]:
    return _L9_VARIANTS.get(
        app, _L10_VARIANTS.get(app, VARIANT_ROTATION))


@dataclass(frozen=True)
class SuiteEntry:
    app: str
    variant: str

    @property
    def seed(self) -> int:
        base = _APP_TABLE[self.app][0]
        return base + _variants_for(self.app).index(self.variant)

    @property
    def spec(self) -> Any:
        return _APP_TABLE[self.app][1](
            self.seed, self.variant)

    @property
    def instance_id(self) -> str:
        spec = self.spec
        return spec.instance_id

    @property
    def block(self) -> str:
        if self.app in DEV_APPS:
            return "dev"
        if self.app in HELDOUT_L9_APPS:
            return "heldout_l9"
        return "heldout"

    @property
    def variants(self) -> tuple[str, ...]:
        return _variants_for(self.app)


def dev_block() -> list[SuiteEntry]:
    return [SuiteEntry(app, variant)
            for app in DEV_APPS
            for variant in VARIANT_ROTATION]


def heldout_block() -> list[SuiteEntry]:
    return [SuiteEntry(app, variant)
            for app in HELDOUT_APPS
            for variant in VARIANT_ROTATION]


def heldout_l9_block() -> list[SuiteEntry]:
    """The L9 §5 held-out block: ledgerflow and berth, scored once
    after the dev block is frozen (per-app variant rotations)."""
    return [SuiteEntry(app, variant)
            for app in HELDOUT_L9_APPS
            for variant in _variants_for(app)]


def l10_dev_block() -> list[SuiteEntry]:
    """The L10 §Phase 1 generation-3 dev block: consign and permit,
    four variants each including the adversarial controls."""
    return [SuiteEntry(app, variant)
            for app in L10_DEV_APPS
            for variant in _variants_for(app)]


def all_entries() -> list[SuiteEntry]:
    return dev_block() + heldout_block() + heldout_l9_block()


class SuiteTarget:
    """Engine-facing adapter for one running suite instance.

    Presents a suite server under the measurement harness's target
    protocol: `target_origin`, `request_count`, and handle_get /
    handle_post returning (status, headers, JSON-string body). The
    adapter lives HERE, in the appsuite's measurement side, so the
    engine imports nothing from the appsuite and the apps themselves
    stay untouched by engine-facing naming. The app's own request
    counter keeps serving independently; this counter is the one the
    harness reads.
    """

    def __init__(self, server: Any) -> None:
        self._app = server.app
        self._inner = server
        self._lock = threading.Lock()
        self._requests = 0
        self._http = ThreadingHTTPServer(
            ("127.0.0.1", 0), _SuiteTargetHandler)
        self._http.daemon_threads = True
        handler = type("_Bound", (_SuiteTargetHandler,),
                       {"target": self})
        self._http.RequestHandlerClass = handler
        self._thread = threading.Thread(
            target=self._http.serve_forever, daemon=True)
        self._thread.start()

    @property
    def target_origin(self) -> str:
        host, port = self._http.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def request_count(self) -> int:
        return self._requests

    def handle_get(
        self, path: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        with self._lock:
            self._requests += 1
        if path in ("", "/"):
            # every app's own serving loop answers the bare root with
            # the index document; handle_get itself does not.
            return 200, {}, json.dumps(self._app._index())
        status, headers, body = self._app.handle_get(path, params)
        return status, headers, json.dumps(body)

    def handle_post(
        self, path: str, params: dict[str, str],
    ) -> tuple[int, dict[str, str], str]:
        with self._lock:
            self._requests += 1
        status, headers, body = self._app.handle_post(path, params)
        return status, headers, json.dumps(body)

    def close(self) -> None:
        self._http.shutdown()
        self._http.server_close()


class _SuiteTargetHandler(BaseHTTPRequestHandler):
    """Minimal handler; all logic delegates to the SuiteTarget."""

    target: SuiteTarget

    def _dispatch(self, post: bool) -> None:
        parsed = urlparse(self.path)
        params = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
        try:
            if post:
                status, headers, body = self.target.handle_post(
                    parsed.path, params)
            else:
                status, headers, body = self.target.handle_get(
                    parsed.path, params)
        except Exception:                              # noqa: BLE001
            status, headers, body = 500, {}, '{"error": "internal"}'
        payload = body.encode("utf-8")
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


@contextmanager
def open_instance(entry: SuiteEntry) -> Iterator[SuiteTarget]:
    """Serve one suite instance, wrapped for the harness protocol."""
    server_cls = _APP_TABLE[entry.app][2]
    with server_cls(entry.spec) as server:
        target = SuiteTarget(server)
        try:
            yield target
        finally:
            target.close()

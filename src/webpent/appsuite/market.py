"""Market: an independently implemented storefront application.

DEV-block app for L8 §2 (server-authoritative price / quantity /
discount). Implementation notes establishing independence:

- pricing is a CATALOG + quote-document model: each buyer holds a
  quote whose authoritative total the server computes from catalog
  unit prices; ordering charges against a quote through a bare order
  operation. This is not the labsuite's record-total checkout and
  not the fixture's order path;
- the wire exposes the client's amount claim as an ordering
  parameter; the defective variant charges it verbatim, the secured
  lookalike accepts the same parameter and ignores it, so both
  surfaces mirror each other;
- the ambiguous variant is the DOCUMENTED bulk rule (orders of 90 or
  more units at 80 percent): the charge legitimately differs from
  the naive sum, ground truth clean, a confirmation there is a false
  positive;
- the multi-observation variant honors a client amount only for
  quotes in ONE bucket, so evidence requires comparing orders across
  quotes;
- catalog reads are public (no credential), unlike every labsuite
  read: a deliberate structural difference;
- body field names, route names and header names come from this
  module's own draw of the appsuite wordlist and the per-instance
  seed, and are published through the index schema's role mapping.
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
class MarketSpec:
    seed: int
    variant: str = "defective"

    def __post_init__(self) -> None:
        if self.variant not in VARIANTS:
            raise ValueError(self.variant)

    @property
    def instance_id(self) -> str:
        return f"mk-{100 + self.seed % 100}"


class MarketApp:
    def __init__(self, spec: MarketSpec) -> None:
        if spec.variant not in VARIANTS:
            raise ValueError(spec.variant)
        self.spec = spec
        self.requests = 0
        self._lock = threading.Lock()
        rnd = random.Random(f"market/{spec.seed}/{spec.variant}")
        pick = rnd.sample(WORDS, 16)

        self.catalog_route = pick[0]
        self.quote_route = pick[1]
        self.order_seg = pick[2]
        self.actor_param = pick[3][:4]
        self.amount_param = pick[4][:4]
        self.resource_param = pick[5][:4]
        self.owner_header = f"X-{pick[6].capitalize()}-Holder"
        self.outcome_header = f"X-{pick[7].capitalize()}-Result"
        self.owner_field = pick[8][:6]
        self.charged_field = pick[9][:6]
        self.total_field = pick[10][:6]
        self.kind_field = pick[11][:6]

        # catalog: item id -> unit price (server-side only knowledge
        # of correct pricing; the client is never trusted with it).
        self.catalog: dict[str, int] = {
            f"{pick[12]}-{n}": (9 + n * 13) for n in range(1, 5)}
        # quotes: one per principal; lines are item -> qty.
        self.quotes: dict[str, dict[str, Any]] = {}
        self.orders: dict[str, dict[str, Any]] = {}

        self._keys: dict[str, str] = {}
        for idx, cred in enumerate(("actor-a", "actor-b",
                                    "actor-admin")):
            principal = f"buyer:{pick[13 + idx].capitalize()}"
            self._keys[cred] = principal
            quote_id = f"{pick[13 + idx][:4]}-{100 + idx}"
            self.quotes[quote_id] = {
                "quote_id": quote_id,
                self.owner_field: principal,
                "lines": {
                    f"{pick[12]}-{1 + idx}": 3 + idx * 2},
            }
        self._principals = frozenset(self._keys.values())

    # -- identity resolution (probe-credential protocol) -----------

    def _principal_of(self, value: str) -> str:
        """Map a wire credential onto this app's identity space.

        The literal probe credentials map to their principals; a
        value that already IS a principal passes through unchanged,
        the way a bearer token would; anything else is anonymous.
        """
        return self._keys.get(
            value, value if value in self._principals else "")

    # -- pricing rules engine --------------------------------------

    def _authoritative_total(self, lines: dict[str, int]) -> int:
        units = sum(lines.values())
        total = sum(
            self.catalog[item_id] * qty
            for item_id, qty in lines.items())
        if self.spec.variant == "ambiguous" and units >= 3:
            # documented bulk rule: orders of three or more units are
            # charged at 80 percent. Declared in the index schema.
            total = total * 4 // 5
        return total

    def _bucket(self, quote_id: str) -> int:
        return int(quote_id.rsplit("-", 1)[-1]) % 2

    def _charge(self, quoted: str | None, total: int,
                quote_id: str) -> int:
        # THE defect surface. The amount parameter is a client claim
        # about what the order should cost. The secured lookalike
        # accepts and ignores it; the defective variant charges it
        # verbatim; the multi-observation variant honors it for one
        # quote bucket only, so evidence spans several quotes.
        if quoted is None:
            return total
        if self.spec.variant == "defective":
            return int(quoted)
        if self.spec.variant == "multi_observation" and (
                self._bucket(quote_id) == 0):
            return int(quoted)
        return total

    # -- handlers ---------------------------------------------------

    def handle_get(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        if path == f"/{self.catalog_route}":
            return 200, {}, {
                "catalog": [
                    {"item": item_id, "unit": price}
                    for item_id, price in self.catalog.items()]}
        prefix = f"/{self.quote_route}/"
        for quote_id, quote in self.quotes.items():
            if path == f"{prefix}{quote_id}":
                if not principal:
                    return self._denied(401)
                if principal != quote[self.owner_field]:
                    return self._denied(403)
                lines = quote["lines"]
                headers = {
                    self.owner_header: quote[self.owner_field],
                    self.outcome_header: "processed"}
                return 200, headers, {
                    "quote": quote_id,
                    self.owner_field: quote[self.owner_field],
                    self.kind_field: "quote",
                    "lines": [
                        {"item": k, "qty": v}
                        for k, v in lines.items()],
                    self.total_field: self._authoritative_total(
                        lines)}
        return 404, {}, {"error": "no-such-route"}

    def handle_post(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        principal = self._principal_of(
            params.get(self.actor_param, ""))
        if path == f"/{self.order_seg}":
            if not principal:
                return self._denied(401)
            quote_id = params.get(self.resource_param, "")
            quote = self.quotes.get(quote_id)
            if quote is None:
                return 404, {self.outcome_header: "refused"}, {
                    "error": "no-such-quote"}
            if principal != quote[self.owner_field]:
                return self._denied(403)
            lines = quote["lines"]
            total = self._authoritative_total(lines)
            quoted = params.get(self.amount_param)
            try:
                charged = self._charge(quoted, total, quote_id)
            except ValueError:
                return 400, {self.outcome_header: "refused"}, {
                    "error": "bad-amount"}
            order_id = f"ord-{len(self.orders) + 1}"
            self.orders[order_id] = {
                "order_id": order_id,
                self.owner_field: principal,
                "quote": quote_id,
                self.charged_field: charged,
                self.total_field: total}
            return 200, {self.outcome_header: "processed"}, {
                "order": order_id,
                self.charged_field: charged,
                self.total_field: total}
        return 404, {}, {"error": "no-such-route"}

    def _denied(self, code: int) -> tuple[int, dict[str, str], Any]:
        return code, {self.outcome_header: "refused"}, {
            "error": "refused"}

    def _index(self) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "params": {
                "actor": self.actor_param,
                "amount": self.amount_param,
                "resource": self.resource_param,
            },
            "fields": {
                "owner": self.owner_field,
                "kind": self.kind_field,
                "charged": self.charged_field,
                "authoritative_total": self.total_field,
            },
            "owner_header": self.owner_header,
            "outcome_header": self.outcome_header,
            "outcome_denied": "refused",
            "numeric_fields": [self.total_field,
                               self.charged_field, "unit"],
        }
        if self.spec.variant == "ambiguous":
            schema["pricing_rules"] = (
                "orders of three or more units are charged at 80 "
                "percent; this is documented pricing behavior")
        quote_paths = [
            f"/{self.quote_route}/{quote_id}"
            for quote_id in sorted(self.quotes)]
        kinds = {
            f"/{self.catalog_route}": "read",
            **{p: "read" for p in quote_paths},
            f"/{self.order_seg}": "mutate",
        }
        return {
            "api": {
                "offers": [
                    {"path": f"/{self.catalog_route}",
                     "role": "catalog"},
                    *[{"path": p, "role": "quote",
                       self.resource_param: "quote-id",
                       self.actor_param: "buyer"}
                      for p in quote_paths],
                ],
                "checkout": [
                    {"path": f"/{self.order_seg}",
                     "role": "order",
                     self.resource_param: "quote-id",
                     self.amount_param: "amount",
                     self.actor_param: "buyer"},
                ],
            },
            "kinds": kinds,
            "schema": schema,
        }


class _Handler(BaseHTTPRequestHandler):
    app: MarketApp

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


class MarketServer:
    """Own serving loop (duplicated per app by design, not shared)."""

    def __init__(self, spec: MarketSpec) -> None:
        self.app = MarketApp(spec)
        self.requests = 0
        self._http = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._http.daemon_threads = True
        handler = type("_Bound", (_Handler,), {"app": self.app})
        self._http.RequestHandlerClass = handler
        self.origin = f"http://127.0.0.1:{self._http.server_port}"

    def __enter__(self) -> "MarketServer":
        self._thread = threading.Thread(
            target=self._http.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._http.shutdown()
        self._http.server_close()

    def request_count(self) -> int:
        return self.requests

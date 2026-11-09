"""Campaign stateful-discovery E2E target — a structurally DIFFERENT
controlled application (UM-DR-28, 2026-11-07).

NOT another blind_v3 shape: no own/target/ctrl triplet routes, a
different root grammar (``/api/ledger/...``), an OpenAPI discovery
document instead of a sitemap route, mixed read/stateful surfaces, an
out-of-scope administrative area, and a cross-directory decoy. The
campaign-side integration (``production/stateful_discovery.py``) must
derive everything STRUCTURALLY: read-triples mined from the observed
surface, transitions scoped by directory + resource token, controls
rotated adaptively.

Surface (all advertised via ``GET /openapi.json`` — the discovery
channel the campaign's schema ingestion reads):

  GET  /api/ledger/accounts/acct_1 .. acct_8     (id-bearing reads)
  POST /api/ledger/accounts/settle_<hex>_3       (acct_3 transition)
  POST /api/ledger/accounts/commit_<hex>_5       (acct_5 transition)
  POST /api/ledger/accounts/pend_<hex>_6         (acct_6 transition A)
  POST /api/ledger/accounts/close_<hex>_6        (acct_6 transition B)
  POST /api/ledger/bulk_reconcile                (cross-directory decoy)
  GET  /internal/admin/accounts/acct_9 .. 11     (OUT-OF-SCOPE area)
  POST /internal/admin/accounts/wipe_<hex>_9     (out-of-scope stateful)

Ground truth (compiled in; the server never reads any truth file and
carries no truth vocabulary in responses):

  acct_1  reference own-resource read (granted, owner=attacker)
  acct_2  SAFE (denied)                acct_4  SAFE (denied)
  acct_8  SAFE (denied)                acct_7  SAFE (denied; no transition)
  acct_3  IDOR-after-settle (trap -> foreign-owner granted)
  acct_5  ALIAS-escalation-after-commit (role user -> effective_as admin)
  acct_6  COMPOSITIONAL (pend AND close required together)
  internal/* : out-of-scope (the discovery must refuse, not probe)

Authorization semantics are BODY-represented (rotating field names,
nested resource objects, volatile churn, rotated key order) with only
``X-Actor-Echo`` as a context header — the E2E therefore exercises the
representation oracle together with the stateful discovery.
"""
from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 9224

_state: dict[str, bool] = {"settle_3": False, "commit_5": False,
                           "pend_6": False, "close_6": False}
_state_lock = threading.Lock()
_churn_lock = threading.Lock()
_churn_counter = 0

SAFE_ACCOUNTS = frozenset({2, 4, 7, 8})


def _hex_token(name: str) -> str:
    return hashlib.sha256(f"ledger:{name}".encode()).hexdigest()[:5]


def _next_churn() -> int:
    global _churn_counter
    with _churn_lock:
        _churn_counter += 1
        return _churn_counter


def reset_state() -> None:
    """Test hook."""
    with _state_lock:
        for key in _state:
            _state[key] = False


def openapi_document() -> dict[str, object]:
    """The advertised surface (the ONLY discovery channel)."""
    paths: dict[str, dict[str, object]] = {
        "/api/ledger/accounts/acct_1": {"get": {"summary": "account read"}},
        "/api/ledger/bulk_reconcile": {"post": {"summary": "bulk reconcile"}},
    }
    for n in range(1, 9):
        paths[f"/api/ledger/accounts/acct_{n}"] = {"get": {"summary": "account read"}}
    for name, n in (("settle", 3), ("commit", 5), ("pend", 6), ("close", 6)):
        paths[f"/api/ledger/accounts/{name}_{_hex_token(name)}_{n}"] = {
            "post": {"summary": "account operation"}
        }
    for n in range(9, 12):
        paths[f"/internal/admin/accounts/acct_{n}"] = {"get": {"summary": "admin read"}}
    paths[f"/internal/admin/accounts/wipe_{_hex_token('wipe')}_9"] = {
        "post": {"summary": "admin operation"}
    }
    return {"openapi": "3.0.0", "info": {"title": "ledger"}, "paths": paths}


def _account_body(n: int, *, owner: str, granted: bool, alias: bool = False) -> str:
    churn = _next_churn()
    record: dict[str, object] = {
        "acct": f"acct-{n}",
        "balance": 100 + n,
        "granted": granted,
        "actor": "attacker",
    }
    if n % 3 == 0:
        record["resource"] = {"owner": owner, "ref": f"res-{n}"}
    else:
        record["owned_by"] = owner
    if alias:
        record["role"] = "user"
        record["effective_as"] = "admin"
    record["ts"] = churn
    record["request_id"] = f"req-{churn:06d}"
    items = list(record.items())
    shift = churn % max(len(items), 1)
    return json.dumps(dict(items[shift:] + items[:shift]))


class LedgerHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silent
        pass

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Actor-Echo", "attacker")
        self.end_headers()
        self.wfile.write(body.encode())

    def _account(self, n: int) -> None:
        if n == 1:
            self._send(200, _account_body(n, owner="attacker", granted=True))
            return
        if n in SAFE_ACCOUNTS:
            self._send(403, _account_body(n, owner=f"User_{chr(64 + n)}", granted=False))
            return
        with _state_lock:
            if n == 3:
                activated = _state["settle_3"]
            elif n == 5:
                activated = _state["commit_5"]
            elif n == 6:
                activated = _state["pend_6"] and _state["close_6"]
            else:
                activated = False
        if not activated:
            # the trap: clean-looking (attacker appears to own it)
            self._send(200, _account_body(n, owner="attacker", granted=True))
        elif n == 5:
            # the ALIAS differential: privilege escalation in body
            self._send(200, _account_body(n, owner="attacker", granted=True, alias=True))
        else:
            # the OWNERSHIP differential: foreign owner, still granted
            self._send(200, _account_body(n, owner="User_B", granted=True))

    # ------------------------------------------------------------------
    def do_GET(self):
        path = self.path.strip("/").split("?")[0]
        if path in ("", "openapi.json"):
            self._send(200, json.dumps(openapi_document()))
            return
        parts = [p for p in path.split("/") if p]
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "ledger" \
                and parts[2] == "accounts" and parts[3].startswith("acct_"):
            try:
                n = int(parts[3].rsplit("_", 1)[-1])
            except ValueError:
                n = -1
            if 1 <= n <= 8:
                self._account(n)
                return
        if len(parts) == 4 and parts[0] == "internal" and parts[2] == "accounts":
            # the out-of-scope area: exists, answers, never probed by scope
            try:
                n = int(parts[3].rsplit("_", 1)[-1])
            except ValueError:
                n = -1
            if 9 <= n <= 11:
                self._send(200, _account_body(n, owner="attacker", granted=True))
                return
        self._send(404, json.dumps({"status": "not_found"}))

    # ------------------------------------------------------------------
    def do_POST(self):
        path = self.path.strip("/").split("?")[0]
        parts = [p for p in path.split("/") if p]
        if path == "/api/ledger/bulk_reconcile":
            # the cross-directory decoy: exists, answers, flips nothing.
            self._send(200, json.dumps({"status": "ok", "ref": "bulk"}))
            return
        if len(parts) == 4 and parts[2] == "accounts":
            tail = parts[3]
            mapping = {
                f"settle_{_hex_token('settle')}_3": "settle_3",
                f"commit_{_hex_token('commit')}_5": "commit_5",
                f"pend_{_hex_token('pend')}_6": "pend_6",
                f"close_{_hex_token('close')}_6": "close_6",
                f"wipe_{_hex_token('wipe')}_9": None,  # out-of-scope op
            }
            key = mapping.get(tail)
            if key is None and tail.startswith(f"wipe_{_hex_token('wipe')}"):
                self._send(200, json.dumps({"status": "ok", "ref": "admin"}))
                return
            if key is not None:
                with _state_lock:
                    _state[key] = True
                self._send(200, json.dumps({"status": "ok", "ref": key}))
                return
        self._send(404, json.dumps({"status": "not_found"}))


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), LedgerHandler)
    print(f"campaign stateful-discovery target listening on 127.0.0.1:{PORT}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

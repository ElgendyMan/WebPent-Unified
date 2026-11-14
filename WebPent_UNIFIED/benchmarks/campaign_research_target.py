"""UM-DR-31 adaptive-research-loop ablation target — a two-directory
controlled application (2026-11-07).

Purpose: make the research loop's contribution MEASURABLE under a
constrained budget. The surface carries two in-scope directories:

  /api/aaa/records  — alphabetically FIRST (the unhinted probing order
                      spends the budget here) and entirely SAFE
  /api/zzz/vaults   — alphabetically LAST, carries the ONE ground-truth
                      vulnerability and the observed cross-identity
                      stateful transition that makes it a research
                      priority

plus an out-of-scope administrative area. With a request budget that
cannot cover both directories, the unhinted (baseline) order confirms
nothing; the research-hinted order (priority on /api/zzz/vaults,
derived from the observed workflow boundary) reaches the ground truth.
Same cases, same budgets, same scope checks — ordering only.

Surface (all advertised via ``GET /openapi.json``):

  GET  /api/aaa/records/rec_1 .. rec_4    (id-bearing reads, ALL SAFE)
  POST /api/aaa/records/touch_<hex>_2     (stateful route, flips nothing)
  GET  /api/zzz/vaults/vlt_1 .. vlt_4     (id-bearing reads)
  POST /api/zzz/vaults/seal_<hex>_3       (vlt_3 transition)
  GET  /internal/admin/vaults/vlt_9 .. 11 (OUT-OF-SCOPE area)

Ground truth (compiled in; no truth vocabulary in responses):

  rec_1  reference own-resource read (granted, owner=attacker)
  rec_2/rec_3/rec_4  SAFE (denied, foreign owner)
  vlt_1  reference own-resource read
  vlt_2/vlt_4  SAFE (denied)
  vlt_3  IDOR-after-seal (seal transition -> foreign-owner granted)
  internal/* : out-of-scope (must be refused, never probed)

HONESTY: team-authored, author-known fixture — this target exists to
make each loop input's contribution isolatable (UM-DR-31 §9.4); it is
NOT an independent holdout and proves nothing about generalization
beyond its population.
"""
from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 9227

_state: dict[str, bool] = {"seal_3": False, "touch_2": False}
_state_lock = threading.Lock()
_churn_lock = threading.Lock()
_churn_counter = 0

SAFE_RECORDS = frozenset({2, 3, 4})
SAFE_VAULTS = frozenset({2, 4})


def _hex_token(name: str) -> str:
    return hashlib.sha256(f"vault:{name}".encode()).hexdigest()[:5]


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
    paths: dict[str, dict[str, object]] = {}
    for n in range(1, 5):
        paths[f"/api/aaa/records/rec_{n}"] = {"get": {"summary": "record read"}}
    paths[f"/api/aaa/records/touch_{_hex_token('touch')}_2"] = {
        "post": {"summary": "record operation"}
    }
    for n in range(1, 5):
        paths[f"/api/zzz/vaults/vlt_{n}"] = {"get": {"summary": "vault read"}}
    paths[f"/api/zzz/vaults/seal_{_hex_token('seal')}_3"] = {
        "post": {"summary": "vault operation"}
    }
    for n in range(9, 12):
        paths[f"/internal/admin/vaults/vlt_{n}"] = {"get": {"summary": "admin read"}}
    return {"openapi": "3.0.0", "info": {"title": "vaults"}, "paths": paths}


def _body(n: int, *, owner: str, granted: bool) -> str:
    churn = _next_churn()
    record: dict[str, object] = {
        "ref": f"obj-{n}",
        "granted": granted,
        "actor": "attacker",
        "value": 10 + n,
    }
    if n % 3 == 0:
        record["resource"] = {"owner": owner, "id": f"res-{n}"}
    else:
        record["owned_by"] = owner
    record["ts"] = churn
    record["request_id"] = f"req-{churn:06d}"
    items = list(record.items())
    shift = churn % max(len(items), 1)
    return json.dumps(dict(items[shift:] + items[:shift]))


class VaultHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silent
        pass

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Actor-Echo", "attacker")
        self.end_headers()
        self.wfile.write(body.encode())

    def _record(self, n: int) -> None:
        if n == 1:
            self._send(200, _body(n, owner="attacker", granted=True))
            return
        if n in SAFE_RECORDS:
            self._send(403, _body(n, owner=f"User_{chr(64 + n)}", granted=False))
            return
        self._send(404, json.dumps({"status": "not_found"}))

    def _vault(self, n: int) -> None:
        if n == 1:
            self._send(200, _body(n, owner="attacker", granted=True))
            return
        if n in SAFE_VAULTS:
            self._send(403, _body(n, owner=f"User_{chr(64 + n)}", granted=False))
            return
        with _state_lock:
            sealed = _state["seal_3"]
        if n == 3 and sealed:
            # the OWNERSHIP differential: foreign owner, still granted
            self._send(200, _body(n, owner="User_B", granted=True))
            return
        # the trap: clean-looking (attacker appears to own it)
        self._send(200, _body(n, owner="attacker", granted=True))

    # ------------------------------------------------------------------
    def do_GET(self):
        path = self.path.strip("/").split("?")[0]
        if path in ("", "openapi.json"):
            self._send(200, json.dumps(openapi_document()))
            return
        parts = [p for p in path.split("/") if p]
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "aaa" \
                and parts[2] == "records" and parts[3].startswith("rec_"):
            try:
                n = int(parts[3].rsplit("_", 1)[-1])
            except ValueError:
                n = -1
            if 1 <= n <= 4:
                self._record(n)
                return
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "zzz" \
                and parts[2] == "vaults" and parts[3].startswith("vlt_"):
            try:
                n = int(parts[3].rsplit("_", 1)[-1])
            except ValueError:
                n = -1
            if 1 <= n <= 4:
                self._vault(n)
                return
        if len(parts) == 4 and parts[0] == "internal" and parts[2] == "vaults":
            # the out-of-scope area: exists, answers, never probed by scope
            try:
                n = int(parts[3].rsplit("_", 1)[-1])
            except ValueError:
                n = -1
            if 9 <= n <= 11:
                self._send(200, _body(n, owner="attacker", granted=True))
                return
        self._send(404, json.dumps({"status": "not_found"}))

    # ------------------------------------------------------------------
    def do_POST(self):
        path = self.path.strip("/").split("?")[0]
        parts = [p for p in path.split("/") if p]
        if len(parts) == 4 and parts[2] in ("records", "vaults"):
            tail = parts[3]
            if tail == f"touch_{_hex_token('touch')}_2":
                with _state_lock:
                    _state["touch_2"] = True
                self._send(200, json.dumps({"status": "ok", "ref": "touch"}))
                return
            if tail == f"seal_{_hex_token('seal')}_3":
                with _state_lock:
                    _state["seal_3"] = True
                self._send(200, json.dumps({"status": "ok", "ref": "seal"}))
                return
        self._send(404, json.dumps({"status": "not_found"}))


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), VaultHandler)
    print(f"UM-DR-31 ablation target listening on 127.0.0.1:{PORT}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

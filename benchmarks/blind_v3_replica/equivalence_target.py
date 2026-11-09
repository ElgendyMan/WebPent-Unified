"""blind_v3 EQUIVALENCE target server — same spec, BODY-represented
authorization semantics (the comparator-oracle miss shapes).

UM-DR-28 (the representation-equivalence repair window, 2026-11-07).
The M10 RCA (docs/engineering/M10_RECALL_RCA.md §2.4) root-caused 15
of the 63 recorded blind_v3 false negatives as read-only misses whose
differential EXISTED but lived in response shapes the deterministic
comparator could not separate: 8 representation_equivalence /
alias_bypass and 7 ownership_bypass, all INCONCLUSIVE under a guard
that read authorization context from X-* headers the original target
did not emit. The original target is absent (never committed), so the
exact miss bytes are unrecoverable; this fixture reproduces the miss
CLASS: the same committed ground-truth spec, the same trap grammar,
but authorization semantics represented in the response BODY under
VARIED field names, key orders, and volatile churn:

  * NO X-Authorization-* / X-Resource-* / X-Privilege-* headers —
    only ``X-Actor-Echo`` (the minimal realistic session echo);
  * ownership rotates representation per case: flat ``owner`` / flat
    ``owned_by`` / nested ``resource.owner``;
  * every case n divisible by 4 uses the ALIAS shape for its
    activated state (``role: user`` + ``effective_as: admin`` — the
    alias_bypass class; the guard's privilege-escalation branch);
  * volatile fields (``timestamp``-like counter, ``request_id``)
    change on EVERY response — raw digests never repeat;
  * key order is rotated deterministically per request.

Behavior grammar (per the same committed spec — the server never
reads ground truth at runtime):

  simple (d1)        — single-observation authorization differential;
  reasoning (d2)     — ONE token transition flips trap → differential;
  compositional (d3) — TWO token transitions required together.

HONESTY CONTRACT (mirrors the replica's, enforced by
tests/test_umdr28_representation_oracle.py):
  * measurements against this server are REPLICA-CORPUS,
    EQUIVALENCE-FIXTURE measurements — they never replace the
    recorded blind baseline and never feed the production_qualified
    label;
  * response bodies carry no mechanism/family/truth vocabulary;
  * the route index is the ONLY discovery surface.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:  # pragma: no cover - path bootstrap
    sys.path.insert(0, _HERE)
from replica_target import (  # noqa: E402  # type: ignore[no-redef]
    COMPOSITIONAL_VULN,
    REASONING_VULN,
    SIMPLE_VULN,
)

PORT = 9223

_case_state: dict[tuple[str, int], dict[str, bool]] = {}
_state_lock = threading.Lock()
_churn_lock = threading.Lock()
_churn_counter = 0


def _token(family: str, kind: str, n: int) -> str:
    """Deterministic unguessable per-case route token (4 hex chars)."""
    digest = hashlib.sha256(f"eqv:{family}:{kind}:{n}".encode()).hexdigest()[:4]
    return f"{'s' if kind == 'state' else 'f'}{digest}"


def _state(family: str, n: int) -> dict[str, bool]:
    key = (family, n)
    with _state_lock:
        if key not in _case_state:
            _case_state[key] = {"state": False, "flag": False}
        return _case_state[key]


def reset_state() -> None:
    """Test hook: clear all per-case transition state."""
    with _state_lock:
        _case_state.clear()


def _next_churn() -> int:
    global _churn_counter
    with _churn_lock:
        _churn_counter += 1
        return _churn_counter


def route_index() -> list[dict[str, str]]:
    """The advertised surface: every route, method included (the
    fixture's ONLY discovery channel)."""
    family_ranges = {"simp": range(1, 41), "rsng": range(41, 81), "comp": range(81, 121)}
    routes: list[dict[str, str]] = [{"method": "GET", "path": "/bv3/map"}]
    for family, numbers in family_ranges.items():
        routes.append({"method": "POST", "path": f"/bv3/{family}/reset_all"})
        for n in numbers:
            routes.append({"method": "GET", "path": f"/bv3/{family}/own_{n}"})
            routes.append({"method": "GET", "path": f"/bv3/{family}/target_{n}"})
            routes.append({"method": "GET", "path": f"/bv3/{family}/ctrl_{n}"})
            routes.append({"method": "POST", "path": f"/bv3/{family}/{_token(family, 'state', n)}_{n}"})
            routes.append({"method": "POST", "path": f"/bv3/{family}/{_token(family, 'flag', n)}_{n}"})
    return routes


def _body(n: int, route: str, *, owner: str, granted: bool,
          alias: bool = False, rotate: int | None = None) -> str:
    """The BODY-represented authorization semantics.

    ``rotate`` selects the ownership representation (0 flat ``owner``,
    1 flat ``owned_by``, 2 nested ``resource.owner``). Volatile churn
    (``ts`` counter + ``request_id``) changes on every response; key
    order is rotated deterministically so raw digests never repeat.
    """
    churn = _next_churn()
    record: dict[str, object] = {
        "ref": f"r-{n}",
        "data": f"{route}-block-{n}",
        "granted": granted,
        "actor": "attacker",
    }
    rot = n % 3 if rotate is None else rotate
    if rot == 0:
        record["owner"] = owner
    elif rot == 1:
        record["owned_by"] = owner
    else:
        record["resource"] = {"owner": owner, "ref": f"res-{n}"}
    if alias:
        record["role"] = "user"
        record["effective_as"] = "admin"
    record["ts"] = churn
    record["request_id"] = f"req-{churn:06d}"
    items = list(record.items())
    shift = churn % max(len(items), 1)
    ordered = dict(items[shift:] + items[:shift])  # rotated key order
    return json.dumps(ordered)


class EquivalenceHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silent
        pass

    def _send(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        # The ONLY context header: the session echo (realistic minimum).
        self.send_header("X-Actor-Echo", "attacker")
        self.end_headers()
        self.wfile.write(body.encode())

    def _parse(self, path: str):
        parts = [p for p in path.strip("/").split("?")[0].split("/") if p]
        if len(parts) < 3 or parts[0] != "bv3":
            return None, None, None
        family, segment = parts[1], parts[2]
        try:
            n = int(segment.rsplit("_", 1)[-1])
        except (IndexError, ValueError):
            return None, None, None
        return family, segment.rsplit("_", 1)[0], n

    # ------------------------------------------------------------------
    def do_GET(self):
        if self.path.strip("/").split("?")[0] in ("", "bv3/map"):
            self._send(200, json.dumps({"routes": route_index()}))
            return
        family, seg, n = self._parse(self.path)
        if n is None:
            self._send(404, json.dumps({"status": "not_found", "ref": "null"}))
            return
        vuln = self._is_vulnerable(family, n)
        state = _state(family, n)
        if family == "comp":
            activated = state["state"] and state["flag"]
        elif family == "simp":
            activated = True  # no transition mechanic in this family
        else:
            activated = state["state"]
        alias_case = (n % 4 == 0)

        if seg == "own":
            # baseline: the actor's OWN object — authorized reference.
            self._send(200, _body(n, "own", owner="attacker", granted=True))
        elif seg == "target":
            if not vuln:
                # safe: the authorization layer holds — denied.
                self._send(403, _body(n, "target", owner="User_B", granted=False))
            elif not activated:
                # the TRAP: clean-looking (attacker appears to own it).
                self._send(200, _body(n, "target", owner="attacker", granted=True))
            elif alias_case:
                # the ALIAS differential: privilege escalation in body.
                self._send(200, _body(n, "target", owner="attacker", granted=True, alias=True))
            else:
                # the OWNERSHIP differential: foreign owner, still granted.
                self._send(200, _body(n, "target", owner="User_B", granted=True))
        elif seg == "ctrl":
            self._send(403, _body(n, "ctrl", owner="User_C", granted=False))
        else:
            self._send(404, json.dumps({"status": "not_found", "ref": "null"}))

    # ------------------------------------------------------------------
    def do_POST(self):
        parts = [p for p in self.path.strip("/").split("?")[0].split("/") if p]
        if len(parts) == 3 and parts[2] == "reset_all":
            # the global decoy: exists, answers, flips nothing.
            self._send(200, json.dumps({"status": "ok", "ref": "bulk"}))
            return
        family, seg, n = self._parse(self.path)
        if n is None:
            self._send(404, json.dumps({"status": "not_found", "ref": "null"}))
            return
        state_token = _token(family or "", "state", n)
        flag_token = _token(family or "", "flag", n)
        if seg == state_token:
            _state(family, n)["state"] = True
        elif seg == flag_token:
            _state(family, n)["flag"] = True
        else:
            self._send(404, json.dumps({"status": "not_found", "ref": "null"}))
            return
        self._send(200, _body(n, seg, owner="attacker", granted=True))

    @staticmethod
    def _is_vulnerable(family: str, n: int) -> bool:
        if family == "simp":
            return n in SIMPLE_VULN
        if family == "rsng":
            return n in REASONING_VULN
        if family == "comp":
            return n in COMPOSITIONAL_VULN
        return False


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), EquivalenceHandler)
    print(f"blind_v3 equivalence target listening on 127.0.0.1:{PORT}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

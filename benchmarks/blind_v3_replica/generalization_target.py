"""blind_v3 GENERALIZATION target server — same spec, UNKNOWN grammar.

UM-DR-27 (the recall-program generalization window, 2026-11-07). The
replica target (``replica_target.py``) answers the UM-DR-25 name grammar
(``state_<n>`` / ``flag_<n>``), so a 1.0/1.0 prober measurement on it
cannot demonstrate DISCOVERY — only the differential + composition +
budget machinery. This fixture removes that confound:

  * the transition routes carry UNGUESSABLE per-case tokens
    (``/bv3/rsng/s3f9c1a7_46`` — the token is sha256-derived, not any
    dictionary verb), so the legacy name grammar 404s on every one of
    them;
  * the target ADVERTISES its surface the way real applications do
    (a root route index — the sitemap/OpenAPI/GraphQL-introspection
    posture): ``GET /`` returns the full route listing, exactly once
    fetchable, from which an observed-surface discovery derives the
    candidates;
  * one GLOBAL decoy transition (``POST /bv3/<fam>/reset_all``) exists
    in the index — realistic, harmless, and out of every case's
    resource-id scope (it must never confirm anything).

Behavior grammar (per the same committed ground-truth spec — the same
compiled sets as the replica; the server never reads ground truth at
runtime):

  simple (d1)        — single-observation authorization differential;
  reasoning (d2)     — ONE transition (the case's state-token route)
                       flips the candidate clean-looking → differential;
  compositional (d3) — TWO token routes (state-kind AND flag-kind)
                       required together.

HONESTY CONTRACT (mirrors the replica's, enforced by
tests/test_transition_sources.py):
  * measurements against this server are REPLICA-CORPUS,
    GENERALIZATION-FIXTURE measurements — they never replace the
    recorded blind baseline (recall 0.137) and never feed the
    production_qualified label;
  * response bodies carry no mechanism/family/truth vocabulary;
  * the route index is the ONLY discovery surface — no other channel
    leaks the token routes.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Sibling import (works both as a subprocess entry point and under the
# tests' importlib file-location loading — no package assumption).
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:  # pragma: no cover - path bootstrap
    sys.path.insert(0, _HERE)
from replica_target import (  # noqa: E402  # type: ignore[no-redef]
    COMPOSITIONAL_VULN,
    REASONING_VULN,
    SIMPLE_VULN,
)

PORT = 9222

_case_state: dict[tuple[str, int], dict[str, bool]] = {}
_state_lock = threading.Lock()


def _token(family: str, kind: str, n: int) -> str:
    """Deterministic unguessable per-case route token (4 hex chars)."""
    digest = hashlib.sha256(f"{family}:{kind}:{n}".encode()).hexdigest()[:4]
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


def route_index() -> list[dict[str, str]]:
    """The advertised surface: every route, method included. This is the
    fixture's ONLY discovery channel (the prober fetches it once)."""
    # The manifest's continuous case numbering: simp 1-40, rsng 41-80,
    # comp 81-120 (the ground-truth spec sets use the same numbers).
    family_ranges = {"simp": range(1, 41), "rsng": range(41, 81), "comp": range(81, 121)}
    routes: list[dict[str, str]] = [{"method": "GET", "path": "/bv3/map"}]
    for family, numbers in family_ranges.items():
        routes.append({"method": "POST", "path": f"/bv3/{family}/reset_all"})
        for n in numbers:
            routes.append({"method": "GET", "path": f"/bv3/{family}/own_{n}"})
            routes.append({"method": "GET", "path": f"/bv3/{family}/target_{n}"})
            routes.append({"method": "GET", "path": f"/bv3/{family}/ctrl_{n}"})
            state_path = f"/bv3/{family}/{_token(family, 'state', n)}_{n}"
            flag_path = f"/bv3/{family}/{_token(family, 'flag', n)}_{n}"
            routes.append({"method": "POST", "path": state_path})
            routes.append({"method": "POST", "path": flag_path})
    return routes


def _neutral_body(n: int, route: str) -> str:
    tags = {"own": "owner", "target": "resource", "ctrl": "gateway"}
    return json.dumps({
        "status": "ok",
        "ref": f"r-{n}",
        "data": f"{tags.get(route, 'resource')}-block-{n}",
    })


class GeneralizationHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silent
        pass

    def _send(self, status: int, body: str, headers: dict[str, str]) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body.encode())

    def _ctx(self, *, owner: str, outcome: str, rid: str) -> dict[str, str]:
        return {
            "X-Actor-Echo": "attacker",
            "X-Actor-Role": "user",
            "X-Resource-Type": "document",
            "X-Resource-Id": rid,
            "X-Resource-Owner": owner,
            "X-Resource-Tenant": "t-main",
            "X-Actor-Tenant": "t-main",
            "X-Privilege-Required": "owner",
            "X-Authorization-Outcome": outcome,
        }

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
            self._send(200, json.dumps({"routes": route_index()}), self._ctx(
                owner="", outcome="denied", rid=""))
            return
        family, seg, n = self._parse(self.path)
        if n is None:
            self._send(404, json.dumps({"status": "not_found", "ref": "null"}),
                       self._ctx(owner="", outcome="denied", rid=""))
            return
        vuln = self._is_vulnerable(family, n)
        state = _state(family, n)
        if family == "comp":
            activated = state["state"] and state["flag"]
        elif family == "simp":
            activated = True
        else:
            activated = state["state"]

        if seg == "own":
            self._send(200, _neutral_body(n, "own"),
                       self._ctx(owner="attacker", outcome="granted_full",
                                 rid=f"own-{n}"))
        elif seg == "target":
            if not vuln:
                self._send(403, _neutral_body(n, "target"),
                           self._ctx(owner="User_B", outcome="denied",
                                     rid=f"doc-{n}"))
            elif not activated:
                self._send(200, _neutral_body(n, "target"),
                           self._ctx(owner="attacker", outcome="granted_full",
                                     rid=f"doc-{n}"))
            else:
                self._send(200, _neutral_body(n, "target"),
                           self._ctx(owner="User_B", outcome="granted_full",
                                     rid=f"doc-{n}"))
        elif seg == "ctrl":
            self._send(403, _neutral_body(n, "ctrl"),
                       self._ctx(owner="User_C", outcome="denied",
                                 rid=f"ctrl-{n}"))
        else:
            self._send(404, json.dumps({"status": "not_found", "ref": "null"}),
                       self._ctx(owner="", outcome="denied", rid=""))

    # ------------------------------------------------------------------
    def do_POST(self):
        parts = [p for p in self.path.strip("/").split("?")[0].split("/") if p]
        if len(parts) == 3 and parts[2] == "reset_all":
            # the global decoy: exists, answers, flips nothing.
            self._send(200, json.dumps({"status": "ok", "ref": "bulk"}),
                       self._ctx(owner="attacker", outcome="granted_full",
                                 rid="reset"))
            return
        family, seg, n = self._parse(self.path)
        if n is None:
            self._send(404, json.dumps({"status": "not_found", "ref": "null"}),
                       self._ctx(owner="", outcome="denied", rid=""))
            return
        state_token = _token(family or "", "state", n)
        flag_token = _token(family or "", "flag", n)
        if seg == state_token:
            _state(family, n)["state"] = True
        elif seg == flag_token:
            _state(family, n)["flag"] = True
        else:
            self._send(404, json.dumps({"status": "not_found", "ref": "null"}),
                       self._ctx(owner="", outcome="denied", rid=""))
            return
        self._send(200, _neutral_body(n, seg),
                   self._ctx(owner="attacker", outcome="granted_full",
                             rid=f"{seg}-{n}"))

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
    server = ThreadingHTTPServer(("127.0.0.1", PORT), GeneralizationHandler)
    print(f"blind_v3 generalization target listening on 127.0.0.1:{PORT}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

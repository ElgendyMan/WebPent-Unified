"""blind_v3 REPLICA target server — the same-spec reconstruction.

UM-DR-25 (red-team window 2026-11-06). The ORIGINAL blind_v3 target was
never committed (blind-benchmark discipline: the runtime must never read
the server's source), so the recorded mode_a baseline (recall 0.137 /
precision 0.6667, reports/goed_v1_8_4/differential_v184.json) cannot be
re-run from repo contents. This replica is reconstructed from the
COMMITTED ground-truth spec (benchmarks/blind_v3/ground_truth.json: 73
vulnerable / 47 safe; simple d1 / reasoning d2 / compositional d3) and
the documented no-leakage design grammar (neutral bodies, X-* context
headers only — same grammar as differential_v2's target).

HONESTY CONTRACT (tests/test_blind_v3_replica.py enforces):
  * measurements against this server are REPLICA-CORPUS measurements —
    they never replace the recorded blind baseline and never feed the
    production_qualified label (that requires operator-deployed
    holdouts);
  * the server NEVER reads ground_truth.json at runtime — the spec is
    compiled into the table below;
  * response bodies carry no mechanism/family/truth vocabulary (the
    leakage-audit test greps for it).

Behavior grammar (per ground-truth spec):
  simple (d1)      — single-observation authorization differential;
                     vulnerable candidate GETs answer granted_full with
                     a foreign resource owner; safe candidates deny.
  reasoning (d2)   — one state transition (POST .../state_<n>) flips the
                     candidate from clean-looking to the differential;
                     GET-only probes observe nothing.
  compositional (d3) — TWO transitions (POST .../state_<n> AND
                     POST .../flag_<n>) are required together; either
                     alone leaves the candidate clean-looking.
Negative controls always answer denied (403) — the causal guard's
authorization-enforcement reference.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 9221

# Compiled spec: per-family vulnerable case numbers — the exact sets
# from the committed ground truth (regenerate with
# benchmarks/blind_v3_replica/build_spec_table.py; the server never
# reads ground truth at runtime).
SIMPLE_VULN = frozenset(
    [1, 2, 4, 5, 7, 8, 10, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, 26,
     28, 30, 32, 34, 36, 38, 40])                      # 25 of 40
REASONING_VULN = frozenset(
    [41, 43, 44, 46, 47, 49, 50, 52, 53, 55, 56, 58, 59, 62, 64, 66,
     68, 70, 72, 74, 76, 78, 80])                      # 23 of 40
COMPOSITIONAL_VULN = frozenset(
    [82, 83, 85, 86, 88, 89, 91, 92, 94, 95, 96, 98, 100, 102, 104,
     106, 108, 109, 110, 112, 113, 115, 116, 118, 119])  # 25 of 40

_case_state: dict[tuple[str, int], dict[str, bool]] = {}
_state_lock = threading.Lock()


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


def _neutral_body(n: int, route: str) -> str:
    tags = {"own": "owner", "target": "resource", "ctrl": "gateway",
            "state": "transition", "flag": "marker"}
    return json.dumps({
        "status": "ok",
        "ref": f"r-{n}",
        "data": f"{tags.get(route, 'resource')}-block-{n}",
    })


class ReplicaHandler(BaseHTTPRequestHandler):
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
        """The observable authorization context (X-* headers only)."""
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
            activated = True  # no transition mechanic in this family
        else:
            activated = state["state"]

        if seg == "own":
            # baseline: the actor's OWN object — authorized reference.
            self._send(200, _neutral_body(n, "own"),
                       self._ctx(owner="attacker", outcome="granted_full",
                                 rid=f"own-{n}"))
        elif seg == "target":
            if not vuln:
                # safe: the authorization layer holds — denied.
                self._send(403, _neutral_body(n, "target"),
                           self._ctx(owner="User_B", outcome="denied",
                                     rid=f"doc-{n}"))
            elif not activated:
                # vulnerable, pre-transition: looks clean (the trap the
                # 3-GET methodology fell into on the original server).
                self._send(200, _neutral_body(n, "target"),
                           self._ctx(owner="attacker", outcome="granted_full",
                                     rid=f"doc-{n}"))
            else:
                # vulnerable, post-transition: the authorization
                # differential is observable.
                self._send(200, _neutral_body(n, "target"),
                           self._ctx(owner="User_B", outcome="granted_full",
                                     rid=f"doc-{n}"))
        elif seg == "ctrl":
            # negative control: blanket-restricted, always denied.
            self._send(403, _neutral_body(n, "ctrl"),
                       self._ctx(owner="User_C", outcome="denied",
                                 rid=f"ctrl-{n}"))
        else:
            self._send(404, json.dumps({"status": "not_found", "ref": "null"}),
                       self._ctx(owner="", outcome="denied", rid=""))

    # ------------------------------------------------------------------
    def do_POST(self):
        family, seg, n = self._parse(self.path)
        if n is None or seg not in ("state", "flag", "target", "transition",
                                    "activate"):
            self._send(404, json.dumps({"status": "not_found", "ref": "null"}),
                       self._ctx(owner="", outcome="denied", rid=""))
            return
        state = _state(family, n)
        if seg in ("state", "transition", "activate", "target"):
            state["state"] = True
        if seg == "flag":
            state["flag"] = True
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
    server = ThreadingHTTPServer(("127.0.0.1", PORT), ReplicaHandler)
    print(f"blind_v3 replica target listening on 127.0.0.1:{PORT}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

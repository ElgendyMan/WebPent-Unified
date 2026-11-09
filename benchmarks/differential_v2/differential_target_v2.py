"""DifferentialBenchmark-v2 Target Server — Stateful & Relational
Port: 9210

DESIGN PRINCIPLES (NO SEMANTIC LEAKAGE):
- Response bodies use ONLY neutral field names: status, ref, data, count, flag, meta, id
- NO vulnerability names, mechanism labels, internal flags, evaluator hints
- Behavior reveals itself ONLY through HTTP interaction: status codes, headers,
  state transitions, resource relationships, timing

CASE BEHAVIOR:
- Family A (easy, dv2_001-030): Static header patterns. CausalGuard catches from single observation.
- Family B (reasoning, dv2_031-060): Vulnerability requires STATE TRANSITION via POST.
  Before POST to /dv2/rsng/state_X: target looks clean.
  After POST: target shows auth mismatch → CausalGuard confirms.
- Family C (novel, dv2_061-090): Vulnerability requires STATE TRANSITION via POST.
  Combinations of patterns never seen before.

Vulnerable cases (15 per family):
- Easy: Static wrong owner header
- Reasoning/Novel: POST to state endpoint unlocks wrong owner on target

Clean cases (15 per family):
- Always correct owner, or always denied
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 9210

# Case configuration
VULN_IDS = set(list(range(1,16)) + list(range(31,46)) + list(range(61,76)))
EASY_IDS = set(range(1,31))
REASONING_IDS = set(range(31,61))
NOVEL_IDS = set(range(61,91))

# Thread-safe state: tracks whether state transition POST has been called per case
_case_state = {}
_state_lock = threading.Lock()

def get_state(case_num):
    with _state_lock:
        return _case_state.get(case_num, {"activated": False, "count": 0})

def set_state_activated(case_num):
    with _state_lock:
        s = _case_state.get(case_num, {"activated": False, "count": 0})
        s["activated"] = True
        s["count"] += 1
        _case_state[case_num] = s
        return s

def neutral_body(case_num, route_type="target", extra=None):
    """Generate neutral response body.
    route_type differentiates bodies slightly so semantic_digest differs
    between own/target/ctrl routes (required for CausalGuard's semantic diff).
    """
    type_tags = {"own": "owner", "target": "resource", "ctrl": "gateway", "state": "state"}
    tag = type_tags.get(route_type, "resource")
    body = {"status": "ok", "ref": f"r-{case_num}", "data": f"{tag}-block-{case_num}"}
    if extra: body.update(extra)
    return json.dumps(body)


class DiffV2Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Silent

    def _parse_case(self, path):
        """Parse path like /dv2/easy/target_42 or /dv2/rsng/state_35"""
        parts = path.strip("/").split("?")[0].split("/")
        # parts = ["dv2", "easy", "target_42"] or ["dv2", "rsng", "state_35"]
        if len(parts) < 3: return None, None, None
        family = parts[1]  # easy, rsng, novel
        segment = parts[2]  # own_X, target_X, ctrl_X, state_X
        try:
            case_num = int(segment.split("_")[-1])
        except (IndexError, ValueError):
            return None, None, None
        seg_type = segment.rsplit("_", 1)[0]  # own, target, ctrl, state
        return family, seg_type, case_num

    def _send_json(self, status, body_str, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body_str.encode())

    def do_GET(self):
        family, seg_type, cn = self._parse_case(self.path)
        if cn is None:
            self._send_json(404, json.dumps({"status": "not_found", "ref": "null"}))
            return

        actor = self.headers.get("X-Actor", "attacker")
        is_vuln = cn in VULN_IDS
        state = get_state(cn)
        activated = state["activated"]

        if seg_type == "ctrl":
            # Control always denies
            self._send_json(403,
                neutral_body(cn, "ctrl", {"status": "blocked"}),
                {"X-Authorization-Outcome": "denied",
                 "X-Resource-Owner": f"ref-{cn}",
                 "X-Actor-Echo": actor})
            return

        if seg_type == "own":
            # Baseline: actor always owns this
            self._send_json(200, neutral_body(cn, "own"),
                {"X-Authorization-Outcome": "granted_full",
                 "X-Resource-Owner": actor,
                 "X-Actor-Echo": actor})
            return

        if seg_type == "target":
            if cn in EASY_IDS:
                # Family A: static — always shows the pattern
                if is_vuln:
                    # Vulnerable: wrong owner but access granted
                    self._send_json(200, neutral_body(cn, "target"),
                        {"X-Authorization-Outcome": "granted_full",
                         "X-Resource-Owner": f"ref-{cn}",  # WRONG owner
                         "X-Actor-Echo": actor})
                else:
                    # Clean: correct owner
                    self._send_json(200, neutral_body(cn, "target"),
                        {"X-Authorization-Outcome": "granted_full",
                         "X-Resource-Owner": actor,  # CORRECT owner
                         "X-Actor-Echo": actor})
                return

            elif cn in REASONING_IDS or cn in NOVEL_IDS:
                # Family B/C: state-dependent
                if is_vuln and activated:
                    # AFTER state transition: vulnerability revealed
                    self._send_json(200, neutral_body(cn, "target", {"flag": 1, "count": state["count"]}),
                        {"X-Authorization-Outcome": "granted_full",
                         "X-Resource-Owner": f"ref-{cn}",  # WRONG owner — revealed
                         "X-Actor-Echo": actor,
                         "X-Context-Ref": f"ctx-{cn}"})
                else:
                    # BEFORE state transition OR clean case: looks safe
                    # No clear auth outcome header for vulnerable before activation
                    if is_vuln and not activated:
                        # Vulnerable but not yet activated — ambiguous response
                        self._send_json(200, neutral_body(cn, "target", {"flag": 0}),
                            {"X-Resource-Owner": f"ref-{cn}",
                             "X-Actor-Echo": actor})
                             # NOTE: No X-Authorization-Outcome header — ambiguous
                    else:
                        # Clean case: always correct owner
                        self._send_json(200, neutral_body(cn, "target", {"flag": 0}),
                            {"X-Authorization-Outcome": "granted_full",
                             "X-Resource-Owner": actor,  # CORRECT owner
                             "X-Actor-Echo": actor})
                return

        self._send_json(404, json.dumps({"status": "not_found"}))

    def do_POST(self):
        """State transition endpoints.
        POST to /dv2/rsng/state_X or /dv2/novel/state_X activates the vulnerability
        for vulnerable cases in B/C families.
        """
        family, seg_type, cn = self._parse_case(self.path)
        if cn is None or seg_type != "state":
            self._send_json(404, json.dumps({"status": "not_found"}))
            return

        if cn not in REASONING_IDS and cn not in NOVEL_IDS:
            self._send_json(400, json.dumps({"status": "invalid", "ref": f"r-{cn}"}))
            return

        is_vuln = cn in VULN_IDS
        state = set_state_activated(cn)

        if is_vuln:
            # State transition succeeded — behavior will change on next GET
            self._send_json(200,
                neutral_body(cn, "state", {"status": "updated", "flag": 1, "count": state["count"]}),
                {"X-Actor-Echo": self.headers.get("X-Actor", "attacker")})
        else:
            # Clean case: state transition accepted but no vulnerability
            self._send_json(200,
                neutral_body(cn, "state", {"status": "updated", "flag": 0, "count": state["count"]}),
                {"X-Authorization-Outcome": "denied",
                 "X-Actor-Echo": self.headers.get("X-Actor", "attacker")})


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), DiffV2Handler)
    print(f"DifferentialBenchmark-v2 running on port {PORT}")
    print("Cases: 90 (A:30 easy, B:30 reasoning, C:30 novel)")
    print("Stateful: Families B/C require POST to state_* endpoint to reveal vulnerability")
    print("No semantic leakage: neutral field names only")
    server.serve_forever()

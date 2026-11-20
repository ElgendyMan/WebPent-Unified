"""DifferentialBenchmark-v1 Target Server
Port: 9200

Design:
- Family A (easy, diff_001-020): Clear ownership headers — deterministic catches
- Family B (reasoning, diff_021-040): Subtle patterns — deterministic may miss,
  but response bodies contain reasoning-language that LLM can pick up
- Family C (novel, diff_041-060): Complex compositions — deterministic likely misses,
  response bodies contain novel composition language

Ground truth is stored INDEPENDENTLY in ground_truth.json.
This server NEVER serves labels, mechanisms, or difficulty info.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 9200

# Case configuration: which cases are vulnerable and their behavior
# Vulnerable cases: candidate returns 200 with wrong owner
# Clean cases: candidate returns 200 with correct owner
# Control always returns 403
VULN_IDS = set(list(range(1,11)) + list(range(21,31)) + list(range(41,51)))

# Which cases have CLEAR ownership headers (deterministic catches)
CLEAR_HEADER_IDS = set(range(1,21))  # Family A only

# Reasoning keywords in response bodies for B/C families
REASONING_KEYWORDS = {
    21: "multi-step workflow chain dependency",
    22: "hidden prerequisite state required",
    23: "group relationship derived access",
    24: "delayed side effect consequence",
    25: "cross resource invariant linkage",
    26: "equivalent representation alternative form",
    27: "nested business workflow approval",
    28: "indirect object relationship transitive",
    29: "state dependent permission conditional",
    30: "counter based access control",
    31: "multi-step dependency chain",
    32: "prerequisite workflow step",
    33: "relationship group membership",
    34: "consequence delayed write",
    35: "invariant cross resource",
    36: "representation equivalent path",
    37: "workflow nested three level",
    38: "relationship indirect ownership",
    39: "permission state dependent draft",
    40: "access counter decrement",
    41: "state plus relationship composition",
    42: "delayed plus multistep chain",
    43: "equivalent plus workflow bypass",
    44: "counter plus state interaction",
    45: "indirect plus equivalent form",
    46: "workflow plus side effect novel",
    47: "cross resource plus counter",
    48: "hidden plus relationship chain",
    49: "prerequisite plus state dependency",
    50: "composition three level novel",
}


def make_body(case_num, is_vuln, is_patched):
    """Generate response body. For reasoning/novel cases, include language
    that an LLM can pick up but deterministic pattern matching cannot."""
    base = {"status": "ok", "resource_id": f"res_{case_num}", "data": f"content_{case_num}"}

    if is_patched:
        return json.dumps({"error": "forbidden", "reason": "authorization_required"})

    if case_num in REASONING_KEYWORDS:
        base["context_note"] = REASONING_KEYWORDS[case_num]
        base["access_pattern"] = "requires_analysis"

    if is_vuln and case_num not in CLEAR_HEADER_IDS:
        # Subtle: don't explicitly state the vulnerability, but give clues
        base["behavior_note"] = "access_granted_to_requesting_actor"
        base["internal_flag"] = "ownership_check_bypassed"

    return json.dumps(base)


class DiffHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Silent

    def do_GET(self):
        path = self.path.split("?")[0]
        actor = self.headers.get("X-Actor", "attacker")

        # Parse case number from path like /diff/v1/target_res_XX or /patched/diff/v1/target_res_XX
        parts = path.strip("/").split("/")
        is_patched = parts[0] == "patched"
        if is_patched:
            parts = parts[1:]  # strip "patched"

        try:
            # parts = ["diff", "v1", "target_res_XX"] or ["diff", "v1", "own_res_XX"]
            res_part = parts[2]
            case_num = int(res_part.split("_")[-1])
            is_own = "own_res" in res_part
        except (IndexError, ValueError):
            self.send_response(404)
            self.end_headers()
            return

        is_vuln = case_num in VULN_IDS
        has_clear_headers = case_num in CLEAR_HEADER_IDS

        if is_patched:
            # Control always denies
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Authorization-Outcome", "denied")
            self.send_header("X-Resource-Owner", f"owner_{case_num}")
            self.send_header("X-Actor-Echo", actor)
            self.end_headers()
            self.wfile.write(make_body(case_num, is_vuln, True).encode())
            return

        # Baseline or candidate — both return 200
        self.send_response(200)
        self.send_header("Content-Type", "application/json")

        if is_own:
            # Baseline: actor owns this resource
            self.send_header("X-Authorization-Outcome", "granted_full")
            self.send_header("X-Resource-Owner", actor)
            self.send_header("X-Actor-Echo", actor)
        else:
            # Candidate
            if has_clear_headers:
                # Family A: clear headers — deterministic catches vuln
                if is_vuln:
                    self.send_header("X-Authorization-Outcome", "granted_full")
                    self.send_header("X-Resource-Owner", f"owner_{case_num}")  # WRONG owner
                    self.send_header("X-Actor-Echo", actor)
                else:
                    self.send_header("X-Authorization-Outcome", "granted_full")
                    self.send_header("X-Resource-Owner", actor)  # CORRECT owner
                    self.send_header("X-Actor-Echo", actor)
            else:
                # Family B/C: subtle — no clear auth outcome header
                # Deterministic engine may miss this
                self.send_header("X-Resource-Owner", f"owner_{case_num}")
                self.send_header("X-Actor-Echo", actor)
                # No X-Authorization-Outcome header — engine can't be certain

        self.end_headers()
        self.wfile.write(make_body(case_num, is_vuln, False).encode())


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), DiffHandler)
    print(f"DifferentialBenchmark-v1 running on port {PORT}")
    print("Cases: 60 (A:20 easy, B:20 reasoning, C:20 novel)")
    server.serve_forever()

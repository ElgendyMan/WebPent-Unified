#!/usr/bin/env python3
"""UM-DR-37 Phase 2 — instrumented production root-cause campaign.

Runs the TRUE production entrypoint
(``webpent.cli.unified_hunt.run_unified_hunt``) against the authorized
local IDOR lab while tee-ing the LangGraph update stream, so every
node's writes are recorded with counts, timings and drop reason codes.

Usage:
    python scripts/umdr37_production_root_cause_campaign.py before
    python scripts/umdr37_production_root_cause_campaign.py after

``before`` is expected to run against the UNFIXED tree (git stash),
``after`` against the fixed tree. Both traces land in
``artifacts/umdr37_graph_trace_<phase>.json``.

This script observes only: discovery, candidates and confirmation all
happen inside the production graph. Nothing is confirmed here.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

# Documented launch surface for the production spine's entrypoint
# provenance gate (same as the UM-DR-36.1 campaigns): this script launches
# the programmatic core of the CLI, webpent.cli.unified_hunt.run_unified_hunt.
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

PHASE = sys.argv[1] if len(sys.argv) > 1 else "after"
assert PHASE in {"before", "after"}, "phase must be before|after"

ENGAGEMENT = f"umdr37-rootcause-{PHASE}-{uuid.uuid4().hex[:8]}"

# --- the authorized local IDOR lab (same scenario as UM-DR-36.1) --------
INVOICES = {
    "INV-A-101": ("User_A", "paid", 1200),
    "INV-B-777": ("User_B", "open", 3400),
    # known resource with an ENFORCED boundary -> must never confirm
    "INV-ADMIN-9001": ("User_ADMIN", "paid", 99),
}
SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B",
            "sess-admin9": "User_ADMIN"}
MISSING = "INV-MISSING-404"  # 404 resource -> must never confirm


class _IdorLab(BaseHTTPRequestHandler):
    def _principal(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "session=" in part:
                return SESSIONS.get(part.strip().split("=", 1)[1])
        return None

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path in ("", "/"):
            self._send(200, json.dumps({
                "app": "invoice-lab", "version": "1.5.0",
                "auth": "cookie session",
                "links": ["/api/users", "/api/session", "/api/health",
                          "/api/invoices/INV-A-101",
                          "/api/invoices/INV-B-777",
                          "/api/invoices/INV-ADMIN-9001",
                          f"/api/invoices/{MISSING}"]}).encode())
            return
        if path == "/api/health":
            self._send(200, b'{"status":"ok"}')
            return
        if path == "/api/users":
            if not principal:
                self._send(401, b'{"error":"authentication required"}')
                return
            self._send(200, json.dumps({"users": [
                {"id": "u1", "name": "User_A", "role": "customer"},
                {"id": "u2", "name": "User_B", "role": "customer"},
                {"id": "u9", "name": "User_ADMIN", "role": "admin"}]}).encode())
            return
        if path == "/api/session":
            if not principal:
                self._send(401, b'{"error":"authentication required"}')
                return
            self._send(200, json.dumps({"principal": principal,
                                        "authenticated": True}).encode())
            return
        if path.startswith("/api/invoices/"):
            if not principal:
                self._send(401, b'{"error":"authentication required"}')
                return
            inv = path.rsplit("/", 1)[1]
            if inv not in INVOICES:
                self._send(404, b'{"error":"invoice not found"}')
                return
            owner, status, amount = INVOICES[inv]
            if owner == "User_ADMIN" and principal != "User_ADMIN":
                self._send(403, json.dumps({
                    "error": "forbidden", "invoice": inv,
                    "requires": "admin"}).encode())
                return
            body = {"id": inv, "owner": owner, "status": status,
                    "amount": amount, "requested_by": principal}
            self._send(200, json.dumps(body).encode())
            return
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *_a) -> None:
        return


# --- instrumentation: tee the graph update stream -----------------------
def _count(value) -> int | dict | None:
    """Best-effort size of a state delta value."""
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, dict):
        return {k: _count(v) for k, v in list(value.items())[:40]}


def main() -> int:
    server = HTTPServer(("127.0.0.1", 0), _IdorLab)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"[lab] authorized local IDOR lab: {origin}")

    import webpent.cli.unified_hunt as uh
    import webpent.graph.builder as gb
    import webpent.production.confirmation_adapter as ca
    import webpent.shared.verifier as verifier_mod

    stages: list[dict] = []
    access_control_findings: list = []
    guard_calls: list[dict] = []
    last_t = [time.perf_counter()]

    real_build = gb.build_graph

    def traced_build(*args, **kwargs):
        graph = real_build(*args, **kwargs)
        real_stream = graph.stream

        def tee_stream(state, config=None, **stream_kwargs):
            for chunk in real_stream(state, config=config, **stream_kwargs):
                now = time.perf_counter()
                if isinstance(chunk, dict):
                    for node, delta in chunk.items():
                        if isinstance(delta, dict):
                            stages.append({
                                "node": str(node),
                                "wall_s": round(now - last_t[0], 3),
                                "writes": {
                                    k: _count(v)
                                    for k, v in list(delta.items())[:40]
                                    if not str(k).startswith("__")
                                },
                            })
                            if str(node) == "access_control" and isinstance(
                                    delta.get("findings"), list):
                                access_control_findings.extend(
                                    delta["findings"][:10])
                last_t[0] = now
                yield chunk

        graph.stream = tee_stream
        return graph

    # unified_hunt imports build_graph lazily inside the function body, so
    # patching the source module is what reaches the production call.
    gb.build_graph = traced_build

    real_adjudicate = ca.adjudicate_with_causal_guard

    def counted_adjudicate(*args, **kwargs):
        t0 = time.perf_counter()
        result = real_adjudicate(*args, **kwargs)
        if isinstance(result, dict):
            summary_result = {
                k: str(v)[:200] for k, v in result.items()
                if k in {"verdict", "passed", "reason", "causal_signal"}
            }
        else:
            summary_result = {
                "verdict": str(getattr(result, "verdict", None))[:200],
                "passed": getattr(result, "passed", None),
                "reason": str(getattr(result, "reason", ""))[:300],
            }
        summary_result["duration_s"] = round(time.perf_counter() - t0, 3)
        guard_calls.append(summary_result)
        return result

    ca.adjudicate_with_causal_guard = counted_adjudicate
    if hasattr(verifier_mod, "adjudicate_with_causal_guard"):
        verifier_mod.adjudicate_with_causal_guard = counted_adjudicate

    import webpent.agents.access_control.agent as ac_agent

    verifications: list[dict] = []
    real_verify = verifier_mod.verify_replay_evidence

    def counted_verify(finding, *args, **kwargs):
        result = real_verify(finding, *args, **kwargs)
        verifications.append({
            "finding_id": str(getattr(finding, "id", "")),
            "vuln_class": str(getattr(finding, "vuln_class", "")),
            "passed": bool(getattr(result, "passed", False)),
            "reason": str(getattr(result, "reason", ""))[:400],
            "has_bundle": getattr(result, "proof_bundle", None) is not None,
            "guard_verdict": str(
                (getattr(result, "evidence", {}) or {}).get(
                    "causal_guard", {}).get("verdict")),
            "guard_block_reason": str(
                (getattr(result, "evidence", {}) or {}).get(
                    "causal_guard", {}).get("block_reason")),
        })
        return result

    verifier_mod.verify_replay_evidence = counted_verify
    ac_agent.verify_replay_evidence = counted_verify

    from webpent.cli.unified_hunt import run_unified_hunt

    invocation = {
        "url": origin,
        "mode": "standard",
        "authorization": "umdr37-authorized-lab-engagement",
        "cookies": "session=sess-a7f3d1",
        "identity_profiles": {
            "user-b": {"name": "user-b", "role": "user",
                       "cookies": {"session": "sess-b9e2c4"}},
        },
        "auto_approve": True,
        "no_llm": True,
        "progress": False,
        "run_graph": True,
        "engagement_id": ENGAGEMENT,
    }
    started = datetime.now(timezone.utc).isoformat()
    summary = run_unified_hunt(**invocation)
    completed = datetime.now(timezone.utc).isoformat()

    # ---- derive funnel numbers from the trace itself -------------------
    def latest(key: str):
        out = None
        for st in stages:
            if key in st["writes"]:
                out = st["writes"][key]
        return out

    def latest_raw(key: str):
        """Recover the raw value by replaying merges is not possible from
        counts; use the summary / recompute below instead."""
        return None

    endpoints_count = None
    for st in stages:
        w = st["writes"].get("crawled_data")
        if isinstance(w, dict) and "endpoints" in w:
            endpoints_count = w["endpoints"]

    # candidate extraction on the real final crawled_data: recompute via
    # the production extractor using the recorded discovery outputs is not
    # possible from counts alone; instead re-run extraction on a rebuilt
    # surface from the lab (documented in the trace as derived_from_lab).
    from webpent.agents.access_control.agent import _extract_candidate_records
    surface = {"endpoints": [
        f"{origin}/api/invoices/{inv}" for inv in INVOICES
    ] + [f"{origin}/api/invoices/{MISSING}", f"{origin}/api/users",
         f"{origin}/api/session", f"{origin}/api/health", origin]}
    candidate_records = _extract_candidate_records(surface)

    findings_detail = summary.get("findings_detail") or []
    derived = {
        "endpoints_in_crawled_delta": endpoints_count,
        "lab_surface_candidate_records": len(candidate_records),
        "findings_total": summary.get("findings_total"),
        "findings_confirmed": summary.get("findings_confirmed"),
        "causal_guard_invocations": len(guard_calls),
        "causal_guard_verdicts": [g["verdict"] for g in guard_calls],
    }

    # ---- drop-off analysis with reason codes (mission 4.4) -------------
    drop_offs: list[dict] = []
    if endpoints_count is not None and endpoints_count <= 1:
        drop_offs.append({
            "stage": "crawler",
            "reason_code": "RESOURCE_NOT_DISCOVERED",
            "detail": f"crawled_data.endpoints={endpoints_count} "
                      "(origin only) — JSON manifest links invisible "
                      "(RC-1)",
        })
    if derived["lab_surface_candidate_records"] < 3:
        drop_offs.append({
            "stage": "access_control.candidate_extraction",
            "reason_code": "CANDIDATE_EXTRACTION_FAILED",
            "detail": "structured short ids filtered by the 10-char "
                      "identifier gate (RC-2)",
        })
    if not findings_detail:
        drop_offs.append({
            "stage": "findings",
            "reason_code": "NO_FINDINGS_PRODUCED",
            "detail": "no candidate reached the confirmation chain",
        })
    skip_flags = [
        {"stage": st["node"], "flag": k, "value": v}
        for st in stages for k, v in st["writes"].items()
        if "skip" in str(k) and v
    ]

    trace = {
        "schema": "umdr37-graph-trace/v1",
        "phase": PHASE,
        "campaign_id": ENGAGEMENT,
        "started_at_utc": started,
        "completed_at_utc": completed,
        "lab": {
            "origin": origin,
            "scenario": "invoice-lab v1.5.0 (User_A owner, User_B foreign, "
                        "admin negative control, missing resource, public "
                        "health resource)",
            "vulnerable_boundary": "GET /api/invoices/INV-A-101 as User_B",
            "enforced_boundary": "GET /api/invoices/INV-ADMIN-9001 as "
                                 "non-admin -> 403",
            "missing_resource": f"GET /api/invoices/{MISSING} -> 404",
        },
        "invocation": invocation,
        "stage_count": len(stages),
        "stages": stages,
        "skip_flags": skip_flags,
        "verifications": verifications,
        "access_control_findings": [
            {
                "id": str(getattr(f, "id", "")),
                "vuln_class": str(getattr(f, "vuln_class", "")),
                "confidence_level": str(getattr(f, "confidence_level", "")),
                "reasoning": str(getattr(f, "reasoning", ""))[:400],
                "has_bundle": bool(getattr(f, "evidence_bundle", None)),
                "evidence_keys": sorted(
                    (getattr(f, "evidence", None) or {}).keys()),
            }
            for f in access_control_findings
        ],
        "derived": derived,
        "drop_offs": drop_offs,
        "summary_from_entrypoint": {
            k: summary.get(k)
            for k in ("findings_total", "findings_confirmed",
                      "hypotheses_total", "mode")
            if k in summary
        },
        "findings_detail": [
            {
                "id": f.get("id"),
                "vuln_class": f.get("vuln_class"),
                "confidence_level": f.get("confidence_level"),
                "confidence": f.get("confidence"),
                "url": f.get("url"),
                "reasoning": str(f.get("reasoning"))[:400],
                "evidence_keys": sorted((f.get("evidence") or {}).keys()),
                "has_bundle": bool(f.get("evidence_bundle")),
            }
            for f in findings_detail[:20]
        ],
        "notes": [
            "input counts per stage are the previous stage's outputs "
            "(updates stream exposes writes only)",
            "lab_surface_candidate_records is recomputed from the known "
            "lab surface with the production extractor — it isolates "
            "RC-2 from crawling behavior",
            "guard invocations are counted by wrapping "
            "adjudicate_with_causal_guard (observation only)",
        ],
    }

    out = REPO / "artifacts" / f"umdr37_graph_trace_{PHASE}.json"
    out.write_text(json.dumps(trace, indent=2, default=str), encoding="utf-8")
    print(f"[trace] {out}")
    print(f"[result] phase={PHASE} endpoints={endpoints_count} "
          f"findings={derived['findings_total']} "
          f"confirmed={derived['findings_confirmed']} "
          f"guard_calls={len(guard_calls)} "
          f"drop_offs={[d['reason_code'] for d in drop_offs]}")
    server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

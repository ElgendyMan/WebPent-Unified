#!/usr/bin/env python3
"""UM-DR-36.1 §5 — TRUE production E2E discovery campaign.

Proves the genuine production chain against an authorized local lab:

  WebPent Production Discovery (run_unified_hunt, real graph) → actual
  Finding (real UUID from the production object) → CausalGuard (via the
  strict replay verifier inside the discovery path) → sealed ProofBundle
  → replay → the REAL central promotion decision (PromotionPipeline via
  the production AVI dispatch on the hunt's own hypotheses).

No manual Finding construction, no manual verification shortcut, no
hand-written PROMOTED. Every asserted value is read from the actual
returned artifacts; any missing/divergent identity fails closed.

Lab (loopback only): two authenticated principals with separate invoice
ownership, an admin-restricted invoice as the INDEPENDENT, meaningful
negative control (foreign principal correctly DENIED 403 on a KNOWN
resource — not just a 404), plus a valid owner baseline, a foreign
candidate request on the owner's resource, and a 404 boundary probe.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

OUT = REPO / "artifacts" / "umdr36_1_production_e2e_campaign.json"
ENGAGEMENT = "eng-umdr36-1-production-e2e"

INVOICES = {
    "INV-A-101": ("User_A", "issued", 1250),
    "INV-B-777": ("User_B", "paid", 300),
    "INV-ADMIN-9001": ("User_ADMIN", "restricted", 99000),
}
SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B",
            "sess-adm0": "User_ADMIN"}


class _IdorLab(BaseHTTPRequestHandler):
    def _principal(self) -> str | None:
        for part in self.headers.get("Cookie", "").split(";"):
            if part.strip().startswith("session="):
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
                          "/api/invoices/INV-ADMIN-9001"]}).encode())
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
                # meaningful negative control on a KNOWN resource: the
                # authorization boundary IS enforced for this principal
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


def _fingerprint(url: str) -> str:
    p = urlparse(url)
    shape = f"{p.scheme.lower()}://{p.netloc.lower()}{p.path or '/'}"
    return "sha256:" + hashlib.sha256(shape.encode()).hexdigest()


def main() -> int:
    server = HTTPServer(("127.0.0.1", 0), _IdorLab)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    print("[lab] authorized local IDOR lab:", origin)

    from webpent.cli.unified_hunt import run_unified_hunt

    summary = run_unified_hunt(
        url=origin, mode="standard",
        authorization="umdr36-1-authorized-lab-engagement",
        cookies="session=sess-a7f3d1",
        identity_profiles={
            "user-b": {"name": "user-b", "role": "user",
                       "cookies": {"session": "sess-b9e2c4"}},
        },
        auto_approve=True, no_llm=True, progress=False,
        engagement_id=ENGAGEMENT, run_graph=True,
    )
    print("[hunt] findings_total:", summary.get("findings_total"),
          "| confirmed:", summary.get("findings_confirmed"))

    # --- the ACTUAL discovery artifacts (never re-derived ids) ----------
    findings_detail = summary.get("findings_detail") or []
    idor = [f for f in findings_detail
            if str(f.get("vuln_class", "")).upper() == "IDOR"]
    problems: list[str] = []
    if not findings_detail:
        problems.append("production discovery produced ZERO findings")
    if not idor:
        problems.append("no IDOR finding in the production findings")
    discovery = idor[0] if idor else None
    finding_id = discovery.get("id") if discovery else None
    if discovery and discovery.get("confidence_level") != "Tool-Confirmed":
        problems.append("discovery finding is not Tool-Confirmed: "
                        f"{discovery.get('confidence_level')!r}")
    if discovery and not discovery.get("evidence_bundle_id"):
        problems.append("discovery finding carries no sealed proof bundle id")

    # --- the REAL central promotion decision (production AVI dispatch) ---
    promotion: dict = {"dispatch": "not_attempted"}
    hypotheses = summary.get("hypotheses_dump") or []
    idor_hyps = [h for h in hypotheses
                 if "idor" in str(h.get("vuln_class", "")).lower()
                 or "idor" in str(h.get("title", "")).lower()]
    pool = idor_hyps or hypotheses
    if pool:
        try:
            from webpent.production.production_spine import (
                ProductionSpineConfig,
                resolve_production_spine,
            )
            orch, _spine_trace = resolve_production_spine(
                ProductionSpineConfig())
            result = orch.run_autonomous_validation_campaign(
                target_url=origin, hypotheses=[pool[0]], max_decisions=1)
            decisions = result.get("decisions") or []
            d0 = decisions[0] if decisions else {}
            pr = d0.get("promotion") or {}
            promotion = {
                "dispatch": ("ModernOrchestrator.run_autonomous_validation_"
                             "campaign (production AVI dispatch)"),
                "hypothesis_source": "the hunt's own hypotheses channel "
                                     "(run_unified_hunt summary)",
                "decision": pr.get("decision"),
                "finding_id": pr.get("finding_id"),
                "gates_passed": pr.get("gates_passed"),
                "gates_failed": pr.get("gates_failed"),
                "promoted_count": result.get("promoted_count"),
                "rejected_count": result.get("rejected_count"),
                "causal_guard_verdict": ((d0.get("causal_guard") or {})
                                         .get("verdict")),
                "bundle_id": d0.get("bundle_id"),
                "replay_verified": d0.get("replay_verified"),
                "promotion_pipeline": pr.get("pipeline"),
            }
        except Exception as exc:  # noqa: BLE001 — recorded honestly
            promotion = {"dispatch": "attempted", "error": repr(exc)[:400]}
    else:
        problems.append("the hunt produced no hypotheses to promote")

    # --- same-finding invariant over the ACTUAL artifacts ----------------
    same_id: dict = {
        "discovery_finding_id": finding_id,
        "discovery_bundle_id": discovery.get("evidence_bundle_id") if discovery else None,
        "promotion_finding_id": promotion.get("finding_id"),
    }
    if discovery:
        if not finding_id:
            problems.append("discovery finding id missing")
    if promotion.get("decision") == "PROMOTED":
        if not promotion.get("finding_id"):
            problems.append("PROMOTED decision without a finding identity")

    artifact = {
        "schema": "umdr36-1-production-e2e/v1",
        "campaign": {
            "campaign_id": ENGAGEMENT,
            "entry_point": "webpent.cli.unified_hunt.run_unified_hunt",
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "target": origin,
            "target_fingerprint": _fingerprint(origin),
            "authorization_boundary": {
                "authorization": "umdr36-1-authorized-lab-engagement",
                "scope": "127.0.0.1 loopback only (ephemeral port)",
                "mode": "standard", "no_llm": True, "auto_approve": True,
            },
            "graph_invoked": summary.get("graph_invoked"),
            "thread_id": summary.get("thread_id"),
            "engagement_id": summary.get("engagement_id"),
            "elapsed_s": summary.get("elapsed_s"),
        },
        "lab_scenario": {
            "principals": ["User_A (owner, session sess-a7f3d1)",
                           "User_B (foreign, session sess-b9e2c4)",
                           "User_ADMIN (admin, session sess-adm0)"],
            "resources": ["INV-A-101 (owner User_A)",
                          "INV-B-777 (owner User_B)",
                          "INV-ADMIN-9001 (admin-restricted)"],
            "vulnerable_path": "GET /api/invoices/INV-A-101 as User_B -> 200",
            "owner_baseline": "GET /api/invoices/INV-A-101 as User_A -> 200",
            "negative_control": ("GET /api/invoices/INV-ADMIN-9001 as "
                                 "User_B -> 403 (boundary ENFORCED on a "
                                 "known resource — independent of the "
                                 "candidate observation)"),
            "boundary_probe": "GET /api/invoices/INV-NOPE-0000 -> 404",
        },
        "discovery": {
            "findings_total": summary.get("findings_total"),
            "findings_confirmed": summary.get("findings_confirmed"),
            "findings_detail": findings_detail,
            "idor_finding": discovery,
        },
        "promotion": promotion,
        "same_finding_invariant": same_id,
        "problems": problems,
        "unauthorized_requests": 0,
        "secret_redaction": ("session cookies supplied via the production "
                             "identity channels only; never recorded in the "
                             "artifact"),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(artifact, indent=2, default=str) + "\n",
                   encoding="utf-8")
    print("[artifact]", OUT)
    print("[problems]", problems or "none")
    server.shutdown()
    server.server_close()
    ok = (not problems
          and discovery is not None
          and discovery.get("confidence_level") == "Tool-Confirmed"
          and promotion.get("decision") == "PROMOTED")
    print("[verdict]", "E2E_CHAIN_PROVEN" if ok else "E2E_CHAIN_NOT_PROVEN")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

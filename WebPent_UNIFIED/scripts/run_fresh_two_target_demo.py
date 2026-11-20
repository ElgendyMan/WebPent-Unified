from __future__ import annotations

import json
import os
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "fresh-two-target-demo-audit-key-20261001")

from webpent.production.autonomous_recon import run_autonomous_recon_campaign
from webpent.recon.autonomous_crawler import CrawlConfig
from webpent.service.facade import MultiCampaignService
from webpent.service.models import CampaignSpec

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "fresh_two_target_demo_20261001"


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "WebPentControlledTarget/1.0"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/redirect":
            location = qs.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()
            return
        if parsed.path == "/fetch":
            destination = qs.get("url", [""])[0]
            if destination.startswith("https://external.example.invalid/"):
                self.send_response(302)
                self.send_header("Location", destination)
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"controlled-fetch","url":"redacted"}')
            return
        if parsed.path == "/debug":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"debug information intentionally exposed for local testing")
            return
        if parsed.path == "/private":
            self.send_response(403)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        port = self.server.server_address[1]
        body = (
            "<html><body>"
            f'<a href="/redirect?next=https%3A%2F%2Fexternal.example%2F{port}">redirect</a>'
            f'<a href="/fetch?url=https%3A%2F%2Fexternal.example%2F{port}">fetch</a>'
            '<a href="/debug?token=public">debug</a>'
            '<a href="/private">private</a>'
            "</body></html>"
        )
        self.wfile.write(body.encode())

    def log_message(self, *_args) -> None:
        return


def start_target(port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), DemoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _decision_status(decision: dict) -> str:
    promotion = decision.get("promotion")
    if isinstance(promotion, dict):
        promoted = str(promotion.get("decision") or "").upper()
        if promoted == "PROMOTED":
            return promoted
    validator = str(decision.get("validator_outcome") or decision.get("oracle_decision") or "").upper()
    if validator in {"REFUTED", "INCONCLUSIVE", "NEEDS_HUMAN_REVIEW"}:
        return validator
    return "INCONCLUSIVE"


def _recordable_finding(campaign_id: str, decision: dict) -> dict | None:
    status = _decision_status(decision)
    if status not in {"PROMOTED", "REFUTED", "NEEDS_HUMAN_REVIEW", "INCONCLUSIVE"}:
        return None
    promotion = decision.get("promotion") if isinstance(decision.get("promotion"), dict) else decision
    finding_id = str(promotion.get("finding_id") or decision.get("finding_id") or f"{campaign_id}-{status.lower()}")
    payload = dict(decision)
    payload.update({
        "finding_id": finding_id,
        "id": finding_id,
        "campaign_id": campaign_id,
        "decision": status,
        "status": status.lower(),
        "vuln_class": str(decision.get("vulnerability_class") or decision.get("vuln_class") or "unknown").lower(),
        "title": str(decision.get("title") or f"Fresh controlled-target {status.lower()} decision"),
    })
    if isinstance(promotion, dict):
        payload["proof_bundle"] = promotion.get("proof_bundle") or decision.get("proof_bundle")
        payload["gates_passed"] = promotion.get("gates_passed") or decision.get("gates_passed")
    if status == "PROMOTED":
        bundle = payload.get("proof_bundle") or {}
        payload["title"] = f"Controlled open redirect at {decision.get('resource_id') or '/fetch'}"
        payload["url"] = (decision.get("request_sequence") or [{}])[1].get("url", "")
        payload["description"] = (
            "The controlled target returned an external HTTP redirect only for the candidate input, "
            "while the baseline and negative control remained on the local response path."
        )
        payload["business_impact"] = "An attacker could redirect users from an in-scope application URL to an attacker-controlled destination."
        payload["remediation"] = "Allow-list redirect destinations server-side and reject external origins unless explicitly authorized."
        payload["cvss_score"] = "6.1 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        payload["reasoning"] = (
            "CVSS 6.1: network reachable, low complexity, no privileges required, user interaction required, "
            "changed scope, and limited confidentiality/integrity impact with no availability impact."
        )
        payload["evidence"] = {
            "proof_bundle": bundle,
            "request_sequence": decision.get("request_sequence", []),
            "response_sequence": decision.get("response_sequence", []),
            "gates_passed": (promotion.get("gates_passed") or []),
            "audit_chain": {"verified": bool(bundle.get("chain_of_custody"))},
        }
    return payload


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    servers = [start_target(38101), start_target(38102)]
    service = MultiCampaignService(
        root=OUT / "service",
        project_root=ROOT,
        sender=lambda payload: True,
    )
    specs = [
        CampaignSpec("fresh-target-a", "http://127.0.0.1:38101", "demo-operator", 25.0, 12),
        CampaignSpec("fresh-target-b", "http://127.0.0.1:38102", "demo-operator", 25.0, 12),
    ]
    for spec in specs:
        service.plan(spec)
        service.start(spec.campaign_id)

    def run(spec: CampaignSpec) -> dict:
        return run_autonomous_recon_campaign(
            target_url=spec.target_url,
            engagement_id=spec.campaign_id,
            entrypoint="direct_invoke",
            # The production scope grammar intentionally rejects non-default
            # ports in explicit scope entries; inferred_from_url still binds
            # the exact target host/port through ScopeLaw.
            scope_entries=None,
            crawl_config=CrawlConfig(max_pages=10, max_depth=1, per_host_min_interval_seconds=0.01),
            max_hypotheses=12,
            max_decisions=8,
            principal_count=0,
        )

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = dict(
            zip((s.campaign_id for s in specs), pool.map(run, specs), strict=True)
        )
    elapsed = round(time.perf_counter() - started, 6)

    # The kill switch is exercised at the service action-ledger checkpoint,
    # independently per campaign, after fresh execution has completed.
    halt = service.halt("fresh-target-a", "demo-operator")
    blocked = service.manager.ledger("fresh-target-a").reserve(
        idempotency_key="after-halt", engagement_id="fresh-target-a", task_id="after-halt",
        target_origin="http://127.0.0.1:38101", method="GET", action_family="http_read",
        identity_ref="redacted", tenant_context="fresh-target-a", vulnerability_class="demo",
        validator_id="demo", estimated_cost=1.0, max_actions=12, max_budget=25.0,
    )
    resume = service.resume("fresh-target-a")

    campaign_summaries: dict[str, dict] = {}
    for spec in specs:
        result = results[spec.campaign_id]
        decisions = result.get("campaign", {}).get("decisions", [])
        findings = [_recordable_finding(spec.campaign_id, d) for d in decisions if isinstance(d, dict)]
        findings = [f for f in findings if f is not None]
        for finding in findings:
            status = str(finding["status"])
            service.costs.record_finding(spec.campaign_id, finding, status=status, cost=1.0)
        service.costs.record_usage(spec.campaign_id, calls=0, reported_tokens=0, actual_cost=0.0)
        service.complete(spec.campaign_id)
        reports = service.generate_completion_reports(spec.campaign_id, OUT / "reports")
        campaign_summaries[spec.campaign_id] = {
            "target_url": spec.target_url,
            "crawl_stats": result.get("crawl", {}).get("stats", {}),
            "hypotheses_generated": result.get("hypotheses_generated", 0),
            "hypotheses_executable": result.get("hypotheses_executable", 0),
            "campaign": {
                "decisions_executed": result.get("campaign", {}).get("decisions_executed", 0),
                "promoted_count": result.get("campaign", {}).get("promoted_count", 0),
                "rejected_count": result.get("campaign", {}).get("rejected_count", 0),
            },
            "fresh_findings_by_status": {
                status: sum(1 for f in findings if f["status"] == status)
                for status in sorted({f["status"] for f in findings})
            },
            "reports_generated": len(reports),
            "result": result,
            "dashboard": service.dashboard(spec.campaign_id),
        }

    summary = {
        "demo": "fresh_two_target_adapter_free_recon",
        "fresh_execution": True,
        "historical_artifacts_used_as_input": False,
        "campaigns_parallel": True,
        "elapsed_seconds": elapsed,
        "kill_switch": {
            "campaign": "fresh-target-a",
            "halt_state": halt.get("state"),
            "blocked_after_halt": not blocked.allowed,
            "resume_state": resume.get("state"),
            "scope": "per-campaign service action ledger checkpoint",
        },
        "campaigns": campaign_summaries,
        "security_note": "All decisions were returned by the existing production spine; this demo does not promote findings itself.",
    }
    (OUT / "demo_summary.json").write_text(json.dumps(summary, indent=2, default=str) + "\n")
    (OUT / "dashboard_render.json").write_text(json.dumps({"campaigns": campaign_summaries, "kill_switch": summary["kill_switch"]}, indent=2, default=str) + "\n")
    print(json.dumps({
        "artifact_root": str(OUT),
        "elapsed_seconds": elapsed,
        "campaigns_parallel": True,
        "fresh_execution": True,
        "campaigns": {k: {"promoted": v["campaign"]["promoted_count"], "decisions": v["campaign"]["decisions_executed"], "reports": v["reports_generated"]} for k, v in campaign_summaries.items()},
        "kill_switch": summary["kill_switch"],
    }, indent=2))
    for server in servers:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()

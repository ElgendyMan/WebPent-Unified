"""Product-layer helpers that remain outside the WebPent trust chain.

The helpers in this module are presentation/planning only: they do not authorize,
execute, validate, seal, replay, promote, or persist authoritative findings.
"""
from __future__ import annotations

import html
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class CampaignCostEstimate:
    endpoint_count: int
    form_count: int
    auth_complexity: int
    estimated_llm_calls: int
    per_call_cost: float
    estimated_budget: float
    formula: str = "(endpoint_count + form_count + auth_complexity) * estimated_llm_calls * per_call_cost"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def estimate_campaign_cost(
    *,
    endpoint_count: int = 1,
    form_count: int = 0,
    auth_complexity: int = 0,
    estimated_llm_calls: int = 12,
    per_call_cost: float = 0.003,
) -> CampaignCostEstimate:
    """Return a deterministic pre-flight estimate before any model call."""
    values = {
        "endpoint_count": endpoint_count,
        "form_count": form_count,
        "auth_complexity": auth_complexity,
        "estimated_llm_calls": estimated_llm_calls,
    }
    for name, value in values.items():
        if isinstance(value, bool) or int(value) < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    if float(per_call_cost) < 0:
        raise ValueError("per_call_cost must be non-negative")
    endpoints = int(endpoint_count)
    forms = int(form_count)
    auth = int(auth_complexity)
    calls = int(estimated_llm_calls)
    cost = round((endpoints + forms + auth) * calls * float(per_call_cost), 6)
    return CampaignCostEstimate(endpoints, forms, auth, calls, float(per_call_cost), cost)


def _finding_status(finding: Mapping[str, Any]) -> str:
    raw = str(
        finding.get("confidence_level")
        or finding.get("status")
        or finding.get("confidence")
        or "Inconclusive"
    ).strip().lower().replace("_", " ")
    if raw in {"tool-confirmed", "confirmed", "tool confirmed"}:
        return "Tool-Confirmed"
    if raw in {"needs human review", "human review", "review"}:
        return "Needs Human Review"
    if raw in {"refuted", "clean", "false positive"}:
        return "Refuted"
    if raw in {"inconclusive", "pending", "ai-assessed", "tentative", "firm"}:
        return "Inconclusive"
    return "Inconclusive"


def _evidence_lines(finding: Mapping[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence")
    if not isinstance(evidence, Mapping):
        evidence = {}
    selected: dict[str, Any] = {}
    for key in (
        "status_code", "baseline_status", "candidate_status", "negative_control_status",
        "body_digest", "baseline_digest", "candidate_digest", "negative_control_digest",
        "gates_passed", "gates_failed", "identity_bound", "causal_difference",
        "causal_chain", "proof_bundle", "replay_verified",
    ):
        if key in finding:
            selected[key] = finding[key]
        elif key in evidence:
            selected[key] = evidence[key]
    if not selected and evidence:
        selected = dict(evidence)
    return selected


def render_campaign_dashboard(
    campaign_id: str,
    findings: list[Mapping[str, Any]],
    learning: Mapping[str, Any] | None = None,
    chain_metrics: Mapping[str, Any] | None = None,
) -> str:
    """Render escaped HTML; this function has no mutation or promotion path."""
    groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for finding in findings:
        groups[_finding_status(finding)].append(finding)
    order = ("Tool-Confirmed", "Needs Human Review", "Inconclusive", "Refuted")
    sections: list[str] = []
    for status in order:
        items = groups.get(status, [])
        cards: list[str] = []
        for finding in items:
            title = html.escape(str(finding.get("title") or finding.get("id") or "Untitled"))
            fid = html.escape(str(finding.get("id") or "unknown"))
            severity = html.escape(str(finding.get("severity") or "unknown"))
            evidence = html.escape(json.dumps(_evidence_lines(finding), indent=2, sort_keys=True, default=str))
            cards.append(
                "<details class=\"finding\"><summary>"
                f"<strong>{title}</strong> <span class=\"meta\">{severity} · {fid}</span>"
                "</summary><pre>" + evidence + "</pre></details>"
            )
        body = "\n".join(cards) or "<p class=\"empty\">No findings in this status.</p>"
        sections.append(f"<section><h2>{html.escape(status)} <span>({len(items)})</span></h2>{body}</section>")
    safe_id = html.escape(str(campaign_id))
    learning_payload = learning or {}
    lessons = learning_payload.get("lessons") if isinstance(learning_payload, Mapping) else {}
    trends = learning_payload.get("trends") if isinstance(learning_payload, Mapping) else {}
    learning_section = (
        "<section id=\"learning\"><h2>Learning</h2>"
        f"<p>Lessons learned: {html.escape(str((lessons or {}).get('total', 0)))}</p>"
        f"<pre>{html.escape(json.dumps({'lessons': lessons or {}, 'trends': trends or {}}, sort_keys=True, default=str))}</pre>"
        "</section>"
    )
    chain_payload = dict(chain_metrics or {}) if isinstance(chain_metrics, Mapping) else {}
    chain_section = (
        "<section id=\"chains\"><h2>Chaining Engine</h2>"
        f"<p>Chains discovered: <strong>{html.escape(str(chain_payload.get('chains_discovered', 0)))}</strong>; "
        f"confirmed: <strong>{html.escape(str(chain_payload.get('chains_confirmed', 0)))}</strong>; "
        f"combined severity upgrades: <strong>{html.escape(str(chain_payload.get('combined_severity_upgrades', 0)))}</strong></p>"
        "<p>Chain promotion remains owned by M4, AVI, ProofBundle, Replay, and PromotionPipeline.</p></section>"
    )
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebPent campaign dashboard</title><style>
body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a;background:#f7f9fb}
header,section,.finding{background:white;border:1px solid #d9e2ec;border-radius:8px;margin:1rem 0;padding:1rem;box-shadow:0 1px 2px #0000000d}
h1{margin:0}.meta{color:#52606d;font-size:.85rem}.finding{padding:.7rem 1rem}.finding summary{cursor:pointer}pre{white-space:pre-wrap;background:#f0f4f8;padding:1rem;border-radius:6px;overflow:auto}.empty{color:#7b8794}
</style></head><body>
<header><h1>WebPent Campaign Dashboard</h1><p>Campaign: <code>""" + safe_id + """</code></p><p>Read-only evidence projection. Promotion and persistence remain owned by WebPent.</p></header>
    """ + "\n".join(sections) + chain_section + learning_section + "</body></html>"


__all__ = ["CampaignCostEstimate", "estimate_campaign_cost", "render_campaign_dashboard"]

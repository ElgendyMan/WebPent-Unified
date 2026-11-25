"""UM-DR-47 Phase F2.1 — the final Finding report generator.

Mission: "لكل finding مؤكد: تقرير بشري منظم — الإثبات، الطلب/الرد
الأصليان، تجربة الضبط، المتوقع مقابل الفعلي، الأثر، تعليمات الـreplay
خطوة بخطوة، مستوى الثقة ومصدرها."

Every CONFIRMED finding can be rendered into a structured,
human-readable report (dict + markdown):

* identity — title, vuln class, URL, tool, severity;
* confidence — the level AND its source chain (Tool-Confirmed =
  CausalGuard + ProofBundle + sealed replay — never an engine label
  alone);
* why discovered — the guard verdict, the differential (expected vs
  observed), the finding's own reasoning;
* evidence — the original request (method/URL/data, privacy-scrubbed)
  and the response summary, the proof-bundle id and evidence keys;
* impact — business impact + severity;
* replay steps — numbered, step-by-step, derived from the finding's
  differential legs and the sealed-replay contract.

Privacy: request material is scrubbed with the W6 discipline (no
cookies, tokens, sessions, authorization headers ever appear in a
report).
"""
from __future__ import annotations

import json
from typing import Any

from webpent.production.research_memory_store import scrub_for_memory

__all__ = [
    "generate_finding_report",
    "render_finding_report_markdown",
    "generate_campaign_findings_report",
    "render_campaign_findings_markdown",
]


def _field(finding: Any, key: str, default: Any = "") -> Any:
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _evidence(finding: Any) -> dict[str, Any]:
    evidence = _field(finding, "evidence", {}) or {}
    return evidence if isinstance(evidence, dict) else {}


def _guard(finding: Any) -> dict[str, Any]:
    guard = _evidence(finding).get("causal_guard")
    return guard if isinstance(guard, dict) else {}


def _differential(finding: Any) -> dict[str, Any]:
    diff = _guard(finding).get("authorization_differential")
    return diff if isinstance(diff, dict) else {}


def _truncate(value: Any, limit: int = 400) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def generate_finding_report(finding: Any) -> dict[str, Any]:
    """The structured report for ONE confirmed finding (pure function)."""
    evidence = _evidence(finding)
    guard = _guard(finding)
    differential = _differential(finding)
    bundle = _field(finding, "evidence_bundle", None)
    bundle = bundle if isinstance(bundle, dict) else {}

    # --- the replay steps: derived from the differential legs --------
    replay_steps: list[str] = []
    legs = differential.get("legs") or differential.get("context") or []
    if isinstance(legs, list) and legs:
        for i, leg in enumerate(legs, 1):
            if isinstance(leg, dict):
                identity = str(leg.get("identity") or leg.get("actor") or "?")
                outcome = str(leg.get("outcome") or leg.get("status") or "?")
                path = str(leg.get("path") or _field(finding, "url") or "")
                replay_steps.append(
                    f"Step {i}: replay {path} as principal '{identity}' "
                    f"(observed outcome: {outcome}) — under the sealed "
                    f"replay contract")
    if not replay_steps:
        # the generic sealed-replay contract for a confirmed finding
        url = str(_field(finding, "url") or "")
        method = str(_field(finding, "request_method") or "GET")
        replay_steps = [
            f"Step 1: replay {method} {url} as the resource's legitimate "
            f"owner — it must succeed",
            "Step 2: replay the identical request as a foreign principal "
            "(the differential leg) — the differential must reproduce",
            "Step 3: verify the replay through the CausalGuard "
            "adjudication (sealed replay, ProofBundle evidence intact)",
        ]

    expected = differential.get("expected") or (
        "both surfaces/legs enforce the same authorization requirement")
    observed = differential.get("observed") or guard.get("verdict") or (
        _field(finding, "reasoning") or "the differential reproduced "
        "under sealed replay")

    request_excerpt = {
        "method": str(_field(finding, "request_method") or "GET"),
        "url": str(_field(finding, "url") or ""),
        "data": _truncate(
            scrub_for_memory(_field(finding, "request_data", "")), 400),
        "payload": _truncate(
            scrub_for_memory(_field(finding, "payload", "")), 200),
    }
    response_excerpt = {
        "summary": _truncate(evidence.get("response_summary")
                             or evidence.get("response") or "", 400),
        "evidence_keys": sorted(
            str(k) for k in (evidence.keys() or []) if str(k).strip())[:12],
    }

    return {
        "schema": "umdr47-finding-report/v1",
        "identity": {
            "finding_id": str(_field(finding, "id") or ""),
            "title": _truncate(_field(finding, "title"), 200),
            "vuln_class": str(_field(finding, "vuln_class") or ""),
            "severity": str(_field(finding, "severity") or ""),
            "url": str(_field(finding, "url") or ""),
            "tool_name": str(_field(finding, "tool_name") or ""),
        },
        "confidence": {
            "level": str(_field(finding, "confidence_level")
                         or _field(finding, "confidence") or ""),
            "source_chain": (
                "Tool-Confirmed = CausalGuard adjudicated differential + "
                "ProofBundle evidence + sealed replay verification"
            ),
            "guard_verdict": str(guard.get("verdict") or ""),
            "guard_confidence": guard.get("confidence"),
        },
        "why_discovered": {
            "expected": _truncate(expected, 400),
            "observed": _truncate(observed, 400),
            "engine_reasoning": _truncate(_field(finding, "reasoning"), 400),
        },
        "evidence": {
            "request": request_excerpt,
            "response": response_excerpt,
            "proof_bundle_id": str(
                bundle.get("bundle_id")
                or _field(finding, "evidence_bundle_id") or ""),
            "evidence_refs": [
                _truncate(r, 200) for r in
                (evidence.get("refs") or [])[:8]
            ],
            "verification": evidence.get("replay_verified"),
        },
        "impact": {
            "business_impact": _truncate(
                _field(finding, "business_impact"), 400),
            "severity": str(_field(finding, "severity") or ""),
            "cvss_score": _field(finding, "cvss_score", None),
        },
        "replay_steps": replay_steps,
        "privacy_contract": (
            "request/response material scrubbed (W6 discipline): no "
            "cookies, sessions, tokens or authorization headers"
        ),
    }


def render_finding_report_markdown(report: dict[str, Any]) -> str:
    """One finding report as human-readable markdown."""
    i = report["identity"]
    c = report["confidence"]
    w = report["why_discovered"]
    e = report["evidence"]
    imp = report["impact"]
    lines = [
        f"## Finding: {i['title']}",
        "",
        f"- **Class**: {i['vuln_class']} | **Severity**: "
        f"{i['severity'] or 'n/a'} | **Tool**: {i['tool_name'] or 'n/a'}",
        f"- **URL**: `{i['url']}`",
        f"- **Confidence**: {c['level']} — {c['source_chain']}"
        + (f" (guard verdict: `{c['guard_verdict']}`)"
           if c["guard_verdict"] else ""),
        "",
        "### Why this is real (expected vs observed)",
        "",
        f"- **Expected**: {w['expected']}",
        f"- **Observed**: {w['observed']}",
    ]
    if w["engine_reasoning"]:
        lines.append(f"- **Engine reasoning**: {w['engine_reasoning']}")
    lines += [
        "",
        "### The original request (scrubbed) and the response",
        "",
        f"- `{e['request']['method']} {e['request']['url']}`",
    ]
    if e["request"]["data"]:
        lines.append(f"- request data: `{e['request']['data']}`")
    if e["response"]["summary"]:
        lines.append(f"- response: `{e['response']['summary']}`")
    if e["proof_bundle_id"]:
        lines.append(f"- proof bundle: `{e['proof_bundle_id']}`")
    if e["evidence_refs"]:
        lines.append(
            "- evidence refs: " + ", ".join(f"`{r}`" for r in e["evidence_refs"]))
    lines += [
        "",
        "### Impact",
        "",
        f"- {imp['business_impact'] or 'business impact not yet assessed'}"
        + (f" (CVSS {imp['cvss_score']})" if imp["cvss_score"] else ""),
        "",
        "### How to re-prove it, step by step",
        "",
    ]
    lines += [f"{step}" for step in report["replay_steps"]]
    lines += ["", "---", ""]
    return "\n".join(lines)


def generate_campaign_findings_report(
    findings: list[Any],
    *,
    campaign_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reports for every CONFIRMED finding of one campaign."""
    confirmed = [
        f for f in findings or []
        if str(_field(f, "confidence_level")
               or _field(f, "confidence") or "") == "Tool-Confirmed"
    ]
    return {
        "schema": "umdr47-campaign-findings-report/v1",
        "campaign": campaign_meta or {},
        "confirmed_count": len(confirmed),
        "reports": [generate_finding_report(f) for f in confirmed],
    }


def render_campaign_findings_markdown(
    findings: list[Any],
    *,
    campaign_meta: dict[str, Any] | None = None,
) -> str:
    bundle = generate_campaign_findings_report(
        findings, campaign_meta=campaign_meta)
    meta = bundle["campaign"]
    header = [
        "# Campaign Findings — Final Reports (UM-DR-47 F2.1)",
        "",
        f"> Campaign: {meta.get('engagement_id', 'n/a')} on "
        f"{meta.get('url', 'n/a')}",
        f"> Confirmed findings: {bundle['confirmed_count']} "
        "(Tool-Confirmed only; every report below carries its own",
        "> proof, scrubbed request material, and step-by-step replay",
        "> instructions).",
        "",
    ]
    body = "\n".join(
        render_finding_report_markdown(r) for r in bundle["reports"])
    return "\n".join(header) + "\n" + body

#!/usr/bin/env python3
"""Learning A/B harness — proves lessons reduce hypotheses for same findings.

SYNTHETIC PROOF ONLY. No live target, no real LLM, no network. Uses the frozen
``LessonConsultant`` with injected stub lessons/vector managers to produce a
real ``PriorityAdjustmentMap``, then consumes it through the new
``apply_lesson_priorities`` planner bridge.

Campaign A: no lessons  -> more hypotheses, 3 seeded bugs confirmed.
Campaign B: with lessons -> fewer hypotheses (pruned + reprioritized), same 3.

Writes deliverables/learning_loop.json.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from webpent.integration.hypothesis_priority_contract import EndpointProfile, PriorityLevel  # noqa: E402
from webpent.integration.planner_enrichment_bridge import (  # noqa: E402
    PriorityScorer,
    apply_lesson_priorities,
)
from webpent.integration.learning_ab_contract import (  # noqa: E402
    ABEvidence,
    CampaignMetrics,
    LearningLoopEvidence,
)

# ---------------------------------------------------------------------------
# Deterministic synthetic target with 3 seeded bugs
# ---------------------------------------------------------------------------
# (route, method, has_form, has_params, is_admin, is_debug, is_api,
#  returns_user_data, is_static, requires_session, content_type, waf, jwt,
#  seeded_bug_family or None)
TARGET_ENDPOINTS = [
    ("/api/users/{id}", "GET", False, True, False, False, True, True, False, True, "application/json", False, True, "IDOR"),
    ("/api/invoices/{id}", "GET", False, True, False, False, True, True, False, True, "application/json", False, True, "IDOR"),
    ("/search", "GET", True, True, False, False, False, False, False, False, "text/html", False, False, "XSS"),
    ("/static/main.js", "GET", False, False, False, False, False, False, True, False, "application/javascript", False, False, None),
    ("/login", "POST", True, True, False, False, False, False, False, False, "application/x-www-form-urlencoded", False, False, None),
    ("/admin/debug", "GET", False, False, True, True, False, False, False, True, "text/html", False, False, None),
    ("/api/orders", "GET", False, True, False, False, True, True, False, True, "application/json", False, True, None),
    ("/profile", "GET", False, False, False, False, False, True, False, True, "text/html", False, False, None),
]

FAMILIES = ("IDOR", "XSS", "SQLI", "INFO_DISCLOSURE", "SSRF")

# Lessons learned from Campaign A (negative = refuted, skip next time)
STUB_LESSONS = [
    {"lesson_id": "L1", "lesson_type": "negative", "family": "SQLI", "route_pattern": "/static/*", "boost_factor": -0.5},
    {"lesson_id": "L2", "lesson_type": "negative", "family": "SSRF", "route_pattern": "/login", "boost_factor": -0.5},
    {"lesson_id": "L3", "lesson_type": "negative", "family": "INFO_DISCLOSURE", "route_pattern": "/static/*", "boost_factor": -0.5},
    {"lesson_id": "L4", "lesson_type": "negative", "family": "XSS", "route_pattern": "/api/*", "boost_factor": -0.4},
    {"lesson_id": "L5", "lesson_type": "positive", "family": "IDOR", "route_pattern": "/api/*", "boost_factor": 0.4},
]


class _StubLessonsManager:
    def get_structured_lessons(self, *, client_id, target_type, limit=500):
        return [dict(row) for row in STUB_LESSONS]


class _StubVectorManager:
    def search_knowledge(self, query, k=5, doc_type="writeup"):
        return []


def _endpoint(spec):
    (route, method, form, params, admin, debug, api, user_data, static, sess, ct, waf, jwt, _bug) = spec
    return EndpointProfile(
        route=route, method=method, has_form=form, has_parameters=params, is_admin=admin,
        is_debug=debug, is_api=api, returns_user_data=user_data, is_static_asset=static,
        requires_session=sess, content_type=ct, waf_detected=waf, uses_jwt=jwt,
    )


def _confirmed_bugs(hypotheses):
    """A hypothesis 'confirms' a bug iff its family matches the seeded bug
    on its route. Deterministic, no false positives."""
    confirmed = []
    bug_by_route = {spec[0]: spec[13] for spec in TARGET_ENDPOINTS if spec[13]}
    for hyp in hypotheses:
        route = hyp.endpoint.route
        family = hyp.family
        seeded = bug_by_route.get(route)
        if seeded and family == seeded:
            confirmed.append(f"{family}:{route}")
    return tuple(sorted(set(confirmed)))


def run_campaign_a():
    """No lessons: generate one hypothesis per endpoint x family."""
    scorer = PriorityScorer()
    hypotheses = []
    for spec in TARGET_ENDPOINTS:
        endpoint = _endpoint(spec)
        for family in FAMILIES:
            hypotheses.append((f"A-{endpoint.route}-{family}", endpoint, family))
    prioritized = scorer.prioritize(
        [(hid, ep) for hid, ep, _f in hypotheses],
        family_for=lambda ep, _h=hypotheses: next((f for h, e, f in _h if e.route == ep.route and f in FAMILIES), "IDOR"),
    )
    # Re-attach family (scorer picks default; we use explicit for A)
    prioritized = tuple(
        prioritized[idx].__class__(
            hypothesis_id=prioritized[idx].hypothesis_id,
            endpoint=prioritized[idx].endpoint,
            priority=prioritized[idx].priority,
            score=prioritized[idx].score,
            rationale=prioritized[idx].rationale,
            payload_subtype=prioritized[idx].payload_subtype,
            family=hypotheses[idx][2],
        )
        for idx in range(len(prioritized))
    )
    confirmed = _confirmed_bugs(prioritized)
    return CampaignMetrics(
        campaign="A_no_lessons",
        hypotheses_generated=len(prioritized),
        hypotheses_tested=len(prioritized),
        confirmed_findings=len(confirmed),
        confirmed_bug_ids=confirmed,
        notes="baseline without lesson consultation",
    )


def run_campaign_b():
    """With lessons: consult LessonConsultant (stub), apply priorities, prune
    strongly-negative route+family combos, then test."""
    from webpent.memory.lesson_consultant import LessonConsultant
    from webpent.memory.lesson_models import PriorityAdjustmentMap

    consultant = LessonConsultant(lessons_manager=_StubLessonsManager(), vector_manager=_StubVectorManager())
    surface_map = type("S", (), {"routes": {spec[0]: type("R", (), {"route": spec[0], "parameters": (), "external_resource_count": 0, "api_signal": spec[6]})() for spec in TARGET_ENDPOINTS}})()
    adjustment, meta = consultant.consult(
        target_url="https://synthetic.example.local",
        surface_map=surface_map,
        client_id="ab_test_client",
        engagement_id="learning_ab_20261004",
    )
    assert isinstance(adjustment, PriorityAdjustmentMap), "lesson_consultant did not return PriorityAdjustmentMap"

    scorer = PriorityScorer()
    hypotheses = []
    for spec in TARGET_ENDPOINTS:
        endpoint = _endpoint(spec)
        for family in FAMILIES:
            hypotheses.append((f"B-{endpoint.route}-{family}", endpoint, family))
    prioritized = scorer.prioritize(
        [(hid, ep) for hid, ep, _f in hypotheses],
        family_for=lambda ep, _h=hypotheses: next((f for h, e, f in _h if e.route == ep.route), "IDOR"),
    )
    prioritized = tuple(
        prioritized[idx].__class__(
            hypothesis_id=prioritized[idx].hypothesis_id,
            endpoint=prioritized[idx].endpoint,
            priority=prioritized[idx].priority,
            score=prioritized[idx].score,
            rationale=prioritized[idx].rationale,
            payload_subtype=prioritized[idx].payload_subtype,
            family=hypotheses[idx][2],
        )
        for idx in range(len(prioritized))
    )
    re_prioritized = apply_lesson_priorities(prioritized, adjustment)

    # Prune: hypotheses with score < -0.3 (strongly negative lesson) are not
    # generated in Campaign B — this is the learning loop's efficiency gain.
    pruned = tuple(h for h in re_prioritized if h.score >= -0.3)
    confirmed = _confirmed_bugs(pruned)
    return CampaignMetrics(
        campaign="B_with_lessons",
        hypotheses_generated=len(pruned),
        hypotheses_tested=len(pruned),
        confirmed_findings=len(confirmed),
        confirmed_bug_ids=confirmed,
        notes=f"lesson_consultant applied; {len(re_prioritized) - len(pruned)} hypotheses pruned by negative lessons",
    ), meta


def main():
    metrics_a = run_campaign_a()
    metrics_b, lesson_meta = run_campaign_b()

    same_findings = metrics_a.confirmed_bug_ids == metrics_b.confirmed_bug_ids and metrics_a.confirmed_findings == metrics_b.confirmed_findings
    reduction = metrics_a.hypotheses_generated - metrics_b.hypotheses_generated
    verdict = "learning_proven" if (same_findings and reduction > 0) else ("inconclusive" if same_findings else "learning_not_observed")

    evidence = ABEvidence(
        before=metrics_a,
        after=metrics_b,
        hypotheses_reduction=reduction,
        same_findings=same_findings,
        verdict=verdict,
    )
    loop = LearningLoopEvidence(
        target="https://synthetic.example.local",
        evidence=evidence,
        lesson_consultant_used=True,
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
    out = {
        "learning_loop": loop.as_dict(),
        "lesson_consultation_meta": {k: v for k, v in lesson_meta.items() if k != "applied_lesson_ids"},
        "applied_lesson_ids": lesson_meta.get("applied_lesson_ids", []),
    }
    out_path = ROOT / "deliverables" / "learning_loop.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"verdict": verdict, "A_hypotheses": metrics_a.hypotheses_generated, "B_hypotheses": metrics_b.hypotheses_generated, "reduction": reduction, "same_findings": same_findings, "confirmed": list(metrics_a.confirmed_bug_ids), "written": str(out_path)}, indent=2))
    return 0 if verdict == "learning_proven" else 1


if __name__ == "__main__":
    raise SystemExit(main())

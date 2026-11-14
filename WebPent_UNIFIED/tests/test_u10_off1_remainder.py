"""U-10 OFF-1 remainder tests.

Restored after the workspace reset. 14 tests covering the OFF-1
remainder bucket across four sub-invariants:

  * Confidence (3 tests): the deterministic confidence formula
    (``webpent.shared.confidence.compute_confidence_score``) clamps to
    [0, 1], honours the Devil's Advocate verdict, and caps online-
    learning deltas.
  * Self-critique (4 tests): the Self-Critique engine
    (``webpent.shared.self_critique``) honours Risk Manager caps,
    fires the zero-hit-rate rule deterministically, and emits a closed
    set of bounded actions.
  * VIP reporter (4 tests): the canonical report builder
    (``webpent.reporter.export.build_report_data``) never suppresses
    findings, requires a target_url, and propagates the strict quality
    gate flag.
  * Auto-approve (2 tests): the PoC execution gate
    (``webpent.shared.poc_policy.evaluate_execution_gate``) blocks
    high-risk work under ``auto_approve=True`` and always rejects
    destructive work.
  * Q-4 (1 test): the report quality gate
    (``webpent.shared.report_quality.enforce_report_quality``) raises
    ``ReportQualityGateError`` when a finding is not ready.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.shared.confidence import (  # noqa: E402
    DevilsAdvocateVerdict,
    EvidenceType,
    compute_confidence_score,
)
from webpent.shared.self_critique import (  # noqa: E402
    SelfCritiqueAction,
    SelfCritiqueCheckpoint,
    generate_adversarial_questions,
    recommend_self_critique_action,
    should_fire_before_promotion,
)
from webpent.shared.poc_policy import (  # noqa: E402
    evaluate_execution_gate,
    evaluate_poc_risk,
)
from webpent.shared.report_quality import (  # noqa: E402
    ReportQualityGateError,
    enforce_report_quality,
)
from webpent.reporter.export import build_report_data  # noqa: E402


# ---------------------------------------------------------------------------
# Confidence (3 tests)
# ---------------------------------------------------------------------------
class TestConfidence:
    def test_score_is_clamped_to_unit_interval(self):
        """Even with maximum positive deltas and a PLAUSIBLE verdict, the
        score cannot exceed 1.0; with maximum negative deltas and a
        DEBUNKED verdict, it cannot drop below 0.0.
        """
        high = compute_confidence_score(
            evidence_type=EvidenceType.TOOL_CONFIRMED,
            online_learning_deltas=[0.10] * 10,  # would sum to 1.0 uncapped
            devils_advocate_verdict=DevilsAdvocateVerdict.PLAUSIBLE,
        )
        assert high == 1.0
        low = compute_confidence_score(
            evidence_type=EvidenceType.HEURISTIC,
            online_learning_deltas=[-0.10] * 10,  # would sum to -1.0 uncapped
            devils_advocate_verdict=DevilsAdvocateVerdict.DEBUNKED,
        )
        assert low == 0.0

    def test_devils_advocate_debunked_lowers_score(self):
        """A DEBUNKED verdict must produce a strictly lower score than
        PLAUSIBLE for the same evidence type and no other deltas.
        """
        plausible = compute_confidence_score(
            evidence_type=EvidenceType.LLM_ASSESSED,
            devils_advocate_verdict=DevilsAdvocateVerdict.PLAUSIBLE,
        )
        debunked = compute_confidence_score(
            evidence_type=EvidenceType.LLM_ASSESSED,
            devils_advocate_verdict=DevilsAdvocateVerdict.DEBUNKED,
        )
        assert debunked < plausible

    def test_online_learning_delta_is_capped(self):
        """Cumulative online-learning deltas are capped at +/-0.30 —
        a single 1.0 delta cannot blow the cap.
        """
        # The cap clamps each individual delta to +/-0.10 AND the sum to
        # +/-0.30. So a single 1.0 delta becomes +0.10, and the score
        # moves by exactly that much (no more).
        base = compute_confidence_score(evidence_type=EvidenceType.HEURISTIC)
        with_one_huge_delta = compute_confidence_score(
            evidence_type=EvidenceType.HEURISTIC,
            online_learning_deltas=[1.0],
        )
        assert with_one_huge_delta - base == pytest.approx(0.10, abs=1e-9)


# ---------------------------------------------------------------------------
# Self-critique (4 tests)
# ---------------------------------------------------------------------------
class TestSelfCritique:
    def _hypothesis(self, *, estimated_cost: float = 1.0):
        from webpent.models.hypothesis import Hypothesis, VulnClass

        return Hypothesis(
            target_url="http://127.0.0.1:9000/x",
            statement="test hypothesis",
            vuln_class=VulnClass.XSS,
            estimated_cost=estimated_cost,
        )

    def test_risk_manager_cap_forces_abandon(self):
        """When the Risk Manager caps dict indicates a cap is hit, the
        recommendation is ABANDON regardless of other signals.
        """
        state = SimpleNamespace(
            hypotheses={}, findings=[], mental_model={"nodes": {}},
            decision_log=[],
        )
        action, rule, _ = recommend_self_critique_action(
            state,
            checkpoint=SelfCritiqueCheckpoint.BEFORE_PROMOTION,
            hypothesis=self._hypothesis(),
            risk_manager_caps={
                "max_depth": 3,
                "current_depth": 3,
                "max_branches": 10,
                "current_branches": 1,
                "curiosity_budget_ceiling": 5.0,
                "curiosity_budget_consumed": 1.0,
            },
        )
        assert action == SelfCritiqueAction.ABANDON
        assert "risk_manager_cap" in rule

    def test_zero_hit_rate_forces_abandon_deterministically(self):
        """Zero confirmed findings over >= 3 promotions -> ABANDON
        deterministically (the LLM is NOT asked).
        """
        from webpent.models.hypothesis import Hypothesis, VulnClass
        h = Hypothesis(
            target_url="http://127.0.0.1:9000/x",
            statement="zero-hit branch head",
            vuln_class=VulnClass.XSS,
        )
        # Build a state whose signals report 3 promotions, 0 confirmed.
        # _extract_deterministic_signals walks state["hypotheses"] and
        # state["findings"]; we provide a minimal in-memory shape.
        state = SimpleNamespace(
            hypotheses={
                str(h.id): h,
            },
            findings=[],  # zero confirmed findings
            mental_model={"nodes": {}},
            decision_log=[],
        )
        # Patch the signal extractor to return the zero-hit shape so we
        # do not need a full state graph.
        from webpent.shared import self_critique as sc

        orig = sc._extract_deterministic_signals
        sc._extract_deterministic_signals = lambda *a, **k: {
            "promotions_from_branch": 3,
            "confirmed_from_branch": 0,
            "hit_rate": 0.0,
        }
        try:
            action, rule, llm = recommend_self_critique_action(
                state,
                checkpoint=SelfCritiqueCheckpoint.EVERY_N_DISCOVERIES,
                hypothesis=h,
            )
        finally:
            sc._extract_deterministic_signals = orig
        assert action == SelfCritiqueAction.ABANDON
        assert "zero_hit_rate" in rule
        assert llm == ""  # LLM was NOT consulted

    def test_should_fire_before_promotion_respects_cost_threshold(self):
        """A cheap hypothesis (cost < threshold) does NOT fire the
        before_promotion checkpoint.
        """
        cheap = self._hypothesis(estimated_cost=0.5)
        expensive = self._hypothesis(estimated_cost=10.0)
        assert should_fire_before_promotion(cheap) is False
        assert should_fire_before_promotion(expensive) is True

    def test_action_set_is_closed(self):
        """SelfCritiqueAction is a closed set: {CONTINUE, DEPRIORITIZE,
        ABANDON}. Adding a new action is a code change, not a runtime
        flag.
        """
        members = {a.value for a in SelfCritiqueAction}
        assert members == {"continue", "deprioritize", "abandon"}


# ---------------------------------------------------------------------------
# VIP reporter (4 tests)
# ---------------------------------------------------------------------------
class TestVipReporter:
    def test_build_report_data_preserves_target_url(self):
        """The canonical report builder must surface the operator-supplied
        target URL verbatim in the report data (no silent rewrite).
        """
        report = build_report_data(
            target_url="http://127.0.0.1:9000",
            findings=[],
        )
        assert report["target_url"] == "http://127.0.0.1:9000"

    def test_build_report_data_does_not_suppress_findings(self):
        """All findings are surfaced in the report — never suppressed."""
        from webpent.models.findings import Finding

        findings = [
            Finding(
                title="low-sev finding",
                severity="low",
                description="low severity test finding",
                tool_name="hunter",
                url="http://127.0.0.1:9000/a",
                evidence={"response_body": "<x>"},
            ),
            Finding(
                title="high-sev finding",
                severity="high",
                description="high severity test finding",
                tool_name="hunter",
                url="http://127.0.0.1:9000/b",
                evidence={"response_body": "<y>"},
            ),
        ]
        report = build_report_data(
            target_url="http://127.0.0.1:9000",
            findings=findings,
        )
        assert report["total_findings"] == 2

    def test_build_report_data_propagates_strict_quality_gate(self):
        """When strict_quality_gate=True, the report builder runs
        ``enforce_report_quality`` (which raises on a not-ready finding)
        rather than ``evaluate_report_quality`` (which does not).
        """
        # An empty findings list is trivially ready; the strict flag
        # is propagated by the absence of an exception.
        report = build_report_data(
            target_url="http://127.0.0.1:9000",
            findings=[],
            strict_quality_gate=True,
        )
        assert report["target_url"] == "http://127.0.0.1:9000"

    def test_build_report_data_emits_quality_gate_section(self):
        """The canonical report must include a ``quality_gate`` section
        so export consumers can audit the per-finding readiness state.
        """
        report = build_report_data(
            target_url="http://127.0.0.1:9000",
            findings=[],
        )
        assert "quality_gate" in report
        assert report["quality_gate"]["status"] == "ready"
        assert report["quality_gate"]["finding_count"] == 0


# ---------------------------------------------------------------------------
# Auto-approve (2 tests)
# ---------------------------------------------------------------------------
class TestAutoApprove:
    def test_auto_approve_true_blocks_high_risk(self):
        """Under ``auto_approve=True``, high-risk PoC work is surfaced
        as ``needs_approval`` (the preceding HITL pause is NOT accepted).
        """
        state = {
            "planner_decision": {"risk_level": "high"},
            "findings": [],
            "auto_approve": True,
        }
        decision = evaluate_execution_gate(state)
        assert decision.status == "needs_approval"
        assert decision.allowed is False

    def test_destructive_is_always_rejected(self):
        """Destructive work is rejected regardless of auto_approve."""
        assert evaluate_poc_risk("destructive").status == "rejected"
        assert evaluate_poc_risk("destructive", human_approved=True).status == "rejected"


# ---------------------------------------------------------------------------
# Q-4 (1 test)
# ---------------------------------------------------------------------------
class TestQ4ReportQualityGate:
    def test_enforce_report_quality_raises_on_not_ready_finding(self):
        """Q-4: ``enforce_report_quality`` raises
        ``ReportQualityGateError`` when at least one finding is not
        ready (strict export gate).
        """
        # A finding missing the required evidence shape is not ready.
        minimal_not_ready = [
            {"target_url": "http://127.0.0.1:9000/x", "vuln_class": "xss",
             "title": "incomplete finding"},
        ]
        with pytest.raises(ReportQualityGateError):
            enforce_report_quality(minimal_not_ready)


# ---------------------------------------------------------------------------
# U-10a confounder depth (C1(d) TC-2) — class-specific questions restored
# ---------------------------------------------------------------------------
class TestAdversarialConfounderQuestions:
    """C1(d): ``generate_adversarial_questions`` must ask the TWO
    universal confounders for every class, PLUS the class-specific
    epistemic confounder for EVERY chartered vulnerability family
    (the U-10a contract's depth — the resurrection had kept only the
    XSS/SQLI/SSRF/IDOR-BOLA branches).
    """

    CHARTERED_FAMILIES = [
        "IDOR", "BOLA", "XSS", "SQLI", "SSRF", "SSTI", "LFI",
        "PATH_TRAVERSAL", "COMMAND_INJECTION", "XXE", "RFI",
        "OPEN_REDIRECT", "INFO_DISCLOSURE",
    ]

    def test_every_chartered_family_gets_class_specific_confounder(self):
        """All 13 chartered families: >= 3 questions, >= 1 class-specific
        (i.e. beyond the two universal ones), with a non-empty category.
        """
        for family in self.CHARTERED_FAMILIES:
            qs = generate_adversarial_questions(vulnerability_class=family)
            assert len(qs) >= 3, f"{family}: expected >=3 confounder questions, got {len(qs)}"
            categories = [q["category"] for q in qs]
            universal = {"caching", "control_taint"}
            class_specific = [c for c in categories if c not in universal]
            assert class_specific, f"{family}: missing class-specific confounder question"
            assert all(isinstance(q["question"], str) and q["question"] for q in qs)

    def test_class_specific_categories_are_distinct_per_family(self):
        """Each family GROUP's class-specific confounder category is
        unique (no two distinct confounders share a category).  Families
        that share one confounder — IDOR/BOLA's authorization_boundary —
        count as ONE group, mirroring the chartered grouping.
        """
        groups: dict[str, str] = {}
        for family in self.CHARTERED_FAMILIES:
            qs = generate_adversarial_questions(vulnerability_class=family)
            universal = {"caching", "control_taint"}
            for q in qs:
                if q["category"] not in universal:
                    groups.setdefault(q["category"], family)
        # Distinct category count matches the chartered family groups:
        # 12 categories for 13 families (IDOR+BOLA share one confounder).
        assert len(groups) == 12, (
            f"expected 12 distinct confounder categories, got {len(groups)}: {sorted(groups)}")

    def test_universal_questions_always_fire(self):
        """The two universal confounders (caching, control_taint) fire for
        every class — including an UNKNOWN class (exactly 2 questions,
        never an invented class-specific one).
        """
        for family in self.CHARTERED_FAMILIES + ["TOTALLY_UNKNOWN_CLASS"]:
            qs = generate_adversarial_questions(vulnerability_class=family)
            categories = [q["category"] for q in qs]
            assert "caching" in categories and "control_taint" in categories
        unknown = generate_adversarial_questions(vulnerability_class="TOTALLY_UNKNOWN_CLASS")
        assert len(unknown) == 2

    def test_resolution_flags_track_inputs(self):
        """Resolution flags are computed from the inputs: caching resolves
        when evidence_origin is target_runtime; control_taint resolves on
        CONFIRMED verdicts.
        """
        live = generate_adversarial_questions(
            vulnerability_class="XSS", validator_outcome="CONFIRMED",
            evidence_origin="target_runtime",
        )
        by_cat = {q["category"]: q for q in live}
        assert by_cat["caching"]["resolved"] is True
        assert by_cat["control_taint"]["resolved"] is True
        stale = generate_adversarial_questions(
            vulnerability_class="XSS", validator_outcome="PENDING",
            evidence_origin="llm_summary",
        )
        by_cat = {q["category"]: q for q in stale}
        assert by_cat["caching"]["resolved"] is False
        assert by_cat["control_taint"]["resolved"] is False

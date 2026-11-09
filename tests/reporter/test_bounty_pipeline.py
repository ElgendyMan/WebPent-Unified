"""FEATURE_PROPOSALS ق10 — end-to-end bounty pipeline.

Pins:
  * one pipeline: confirmed finding → evidence-backed report →
    platform-native render → preview → submission,
  * draft() returns None (never a partial draft) for: non-promoted /
    refuted findings, missing sealed ProofBundle, unsupported platform,
    export flag off — each with a recorded stage trace,
  * submit() is fail-closed on approval: no explicit approval and no
    callback verdict ⇒ ``approval_required`` and the draft goes
    NOWHERE; a denied callback or explicit False also refuses,
  * require_tier3=True demands a GRANTED tier-3 authority check from
    the ق2 autonomy cage (missing cage ⇒ refusal),
  * NO platform API calls: the only destinations are the injected
    submission sink or the operator themselves (paste-it-yourself),
  * identical finding + platform ⇒ byte-identical markdown.
"""

from __future__ import annotations

import pytest

GATES = [
    "real_runtime_observations",
    "baseline_present",
    "candidate_present",
    "negative_control_present",
    "causal_validator_confirmed",
    "proof_bundle_signed",
    "replay_verified",
    "no_external_scanner_authority",
]


@pytest.fixture()
def promoted_finding(monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.setenv("WEBPENT_AUDIT_SECRET_KEY", "x" * 48)
    from webpent.models.proof_bundle import build_proof_bundle

    requests = [
        {"role": "baseline", "method": "GET", "url": "http://127.0.0.1:3000/api/item?id=1"},
        {"role": "candidate", "method": "GET", "url": "http://127.0.0.1:3000/api/item?id=2"},
        {"role": "negative_control", "method": "GET", "url": "http://127.0.0.1:3000/api/item?id=999"},
    ]
    responses = [
        {"status_code": 403, "body": "baseline"},
        {"status_code": 200, "body": "candidate"},
        {"status_code": 403, "body": "control"},
    ]
    bundle = build_proof_bundle(
        engagement_id="juice-shop-campaign",
        campaign_id="juice-shop-campaign",
        run_id="run-001",
        finding_id="finding-001",
        hypothesis_id="hyp-001",
        vulnerability_class="broken_access_control",
        evidence=[*responses],
        evidence_refs=["execution:baseline", "execution:candidate", "execution:negative-control"],
        negative_control=responses[2],
        target_fingerprint="juice-shop-loopback",
        target_identity="regular-user",
        scope_context={"authorized": True, "target": "127.0.0.1:3000"},
        identity_context={"principal": "regular-user", "authenticated": True},
        baseline=responses[0],
        request_evidence=requests,
        response_evidence=responses,
        causal_oracle={
            "causal_signal": True,
            "negative_control_complete": True,
            "requires_target_backed": True,
            "baseline_access_result": 403,
            "candidate_access_result": 200,
            "negative_control_result": 403,
        },
        target_backed=True,
        negative_control_independent=True,
        validator_id="juice-shop-validator",
        validator_version="1.0",
        replay_metadata={"replayable": True, "requests_executed": 3},
        cleanup_status="not_applicable",
        baseline_evidence_ref="execution:baseline",
        candidate_evidence_ref="execution:candidate",
        negative_control_evidence_ref="execution:negative-control",
        oracle_decision="CONFIRMED",
        validator_result={"gates_passed": GATES},
        evidence_origin="target_runtime",
    ).seal(actor="test")
    return {
        "id": "finding-001",
        "title": "Regular user can read another user's item",
        "severity": "high",
        "description": "The item endpoint does not enforce ownership.",
        "vuln_class": "broken_access_control",
        "url": requests[1]["url"],
        "confidence_level": "Tool-Confirmed",
        "tool_confirmed_by": "test.fixture",
        "cvss_score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 7.1",
        "reasoning": "The CVSS vector reflects network reachability, low complexity, low privileges, and high confidentiality impact.",
        "business_impact": "An authenticated user can read another user's protected record.",
        "evidence": {
            # M1-B (E-3): report-contract fields for the strict platform
            # export gate (hypothesis back-reference + reproduction steps).
            "hypothesis": {"hypothesis_id": "hyp-fixture-001"},
            "reproduction": [
                "Login as the regular user.",
                "Request the item endpoint with another user's item id.",
                "Observe the 200 response with the foreign record (candidate), "
                "while the negative control is rejected with 403.",
            ],
            "proof_bundle": bundle.model_dump(mode="json"),
            "gates_passed": GATES,
            "request_sequence": requests,
            "response_sequence": responses,
            "baseline": {"request": requests[0], "response": responses[0]},
            "candidate": {"request": requests[1], "response": responses[1]},
            "negative_control": {"request": requests[2], "response": responses[2]},
            "promotion": {"decision": "PROMOTED", "gates_passed": GATES},
            "audit_chain": {"verified": True, "root": "sha256:audit-root"},
        },
    }


@pytest.fixture()
def export_on():
    from webpent.config.settings import Settings, activate_settings

    with activate_settings(Settings(enable_platform_export=True)):
        yield


from webpent.reporter.bounty_pipeline import (
    BountyPipeline,
    PipelineStage,
    SubmissionDraft,
    SubmissionResult,
)


# ---------------------------------------------------------------------------
# draft → render → preview
# ---------------------------------------------------------------------------


def test_pipeline_drafts_renders_and_previews(promoted_finding, export_on) -> None:
    pipeline = BountyPipeline()
    draft = pipeline.draft(promoted_finding, platform="hackerone")
    assert isinstance(draft, SubmissionDraft)
    assert draft.report_id
    assert draft.finding_id == "finding-001"
    assert draft.platform == "hackerone"
    # platform-native section vocabulary
    assert "## Steps To Reproduce" in draft.markdown
    # canonical preview is the platform-neutral BountyReport markdown
    assert "## Steps to Reproduce" in draft.preview
    assert "## Evidence" in draft.preview
    stages = {s.stage: s for s in draft.stages}
    assert stages["draft"].ok and stages["render"].ok and stages["preview"].ok
    # no invented content: the finding's URL is present verbatim
    assert promoted_finding["url"] in draft.markdown


def test_pipeline_is_deterministic_for_identical_inputs(promoted_finding, export_on) -> None:
    pipeline = BountyPipeline()
    first = pipeline.draft(promoted_finding, platform="bugcrowd")
    second = pipeline.draft(promoted_finding, platform="bugcrowd")
    assert first is not None and second is not None
    # The SUBMITTED artifact (platform markdown, built only from finding
    # data) is byte-identical for identical inputs.
    assert first.markdown == second.markdown
    # The canonical preview is a submission RECORD: it legitimately
    # carries report_id (uuid4 per build) and generated_at (build
    # time) — determinism applies to the report body, not the receipt.
    def _body(preview: str) -> str:
        return "\n".join(
            line
            for line in preview.splitlines()
            if not line.startswith("**Report ID:**")
            and "generated" not in line.lower()
        )

    assert _body(first.preview) == _body(second.preview)
    assert first.report["title"] == second.report["title"]


def test_refuted_finding_never_enters_the_pipeline(promoted_finding, export_on) -> None:
    finding = promoted_finding
    finding["evidence"]["promotion"] = {"decision": "REFUTED", "gates_passed": GATES}
    pipeline = BountyPipeline()
    assert pipeline.draft(finding) is None  # stage-traced refusal, no draft


def test_unpromoted_finding_never_enters_the_pipeline(export_on) -> None:
    pipeline = BountyPipeline()
    assert pipeline.draft({"id": "x", "title": "not confirmed"}) is None


def test_unsupported_platform_is_a_stage_refusal(promoted_finding, export_on) -> None:
    pipeline = BountyPipeline()
    assert pipeline.draft(promoted_finding, platform="synack") is None


def test_export_flag_off_refuses_the_render(promoted_finding) -> None:
    from webpent.config.settings import Settings, activate_settings

    with activate_settings(Settings(enable_platform_export=False)):
        pipeline = BountyPipeline()
        assert pipeline.draft(promoted_finding) is None


def test_all_three_platform_templates_render(promoted_finding, export_on) -> None:
    pipeline = BountyPipeline()
    for platform, steps_header in (
        ("hackerone", "Steps To Reproduce"),
        ("bugcrowd", "Steps to Reproduce"),
        ("intigriti", "Steps to reproduce"),
    ):
        draft = pipeline.draft(promoted_finding, platform=platform)
        assert draft is not None
        assert f"## {steps_header}" in draft.markdown


# ---------------------------------------------------------------------------
# submit — fail-closed on approval, optional tier-3
# ---------------------------------------------------------------------------


def _draft(pipeline: BountyPipeline, finding: dict) -> SubmissionDraft:
    draft = pipeline.draft(finding, platform="hackerone")
    assert draft is not None
    return draft


def test_submit_without_any_approval_refuses_and_sends_nowhere(promoted_finding, export_on) -> None:
    pipeline = BountyPipeline()
    result = pipeline.submit(_draft(pipeline, promoted_finding))
    assert isinstance(result, SubmissionResult)
    assert result.submitted is False
    assert result.refusal == "approval_required"
    assert result.handed_to == "nowhere"


def test_submit_with_explicit_approval_hands_to_operator(promoted_finding, export_on) -> None:
    pipeline = BountyPipeline()
    result = pipeline.submit(_draft(pipeline, promoted_finding), approved=True)
    assert result.submitted is True
    assert result.handed_to == "operator"
    assert result.refusal == ""


def test_explicit_false_denial_beats_granting_callback(promoted_finding, export_on) -> None:
    pipeline = BountyPipeline(approval_callback=lambda draft: True)
    result = pipeline.submit(_draft(pipeline, promoted_finding), approved=False)
    assert result.submitted is False
    assert result.refusal == "approval_required"


def test_denying_callback_refuses(promoted_finding, export_on) -> None:
    pipeline = BountyPipeline(approval_callback=lambda draft: False)
    result = pipeline.submit(_draft(pipeline, promoted_finding))
    assert result.submitted is False
    assert result.refusal == "approval_required"


def test_callback_exception_counts_as_denial(promoted_finding, export_on) -> None:
    def boom(draft):
        raise RuntimeError("operator away")

    pipeline = BountyPipeline(approval_callback=boom)
    result = pipeline.submit(_draft(pipeline, promoted_finding))
    assert result.submitted is False
    assert result.refusal == "approval_required"


def test_submit_none_draft_refuses_cleanly() -> None:
    pipeline = BountyPipeline()
    result = pipeline.submit(None, approved=True)
    assert result.submitted is False
    assert result.refusal == "no_draft"


def test_approved_draft_reaches_injected_sink(promoted_finding, export_on) -> None:
    handed: list[SubmissionDraft] = []

    def sink(draft: SubmissionDraft):
        handed.append(draft)
        return {"ticket": "H1-12345"}

    pipeline = BountyPipeline(submission_sink=sink)
    result = pipeline.submit(_draft(pipeline, promoted_finding), approved=True)
    assert result.submitted is True
    assert result.handed_to == "sink"
    assert len(handed) == 1
    assert result.sink_response == {"ticket": "H1-12345"}


def test_sink_failure_is_an_inspectable_refusal(promoted_finding, export_on) -> None:
    def sink(draft):
        raise RuntimeError("queue down")

    pipeline = BountyPipeline(submission_sink=sink)
    result = pipeline.submit(_draft(pipeline, promoted_finding), approved=True)
    assert result.submitted is False
    assert result.refusal == "submission_sink_failed"


# ---------------------------------------------------------------------------
# tier-3 authority (ق2 cage integration)
# ---------------------------------------------------------------------------


class _FakeDecision:
    def __init__(self, granted: bool) -> None:
        self.granted = granted
        self.reason = "granted" if granted else "tier 3 exceeds authority"


class _FakeCage:
    def __init__(self, granted: bool) -> None:
        self.granted = granted
        self.calls = 0

    def may_execute(self, requested: int) -> _FakeDecision:
        self.calls += 1
        assert requested == 3
        return _FakeDecision(self.granted)


def test_require_tier3_without_cage_refuses(promoted_finding, export_on) -> None:
    pipeline = BountyPipeline(require_tier3=True)
    result = pipeline.submit(_draft(pipeline, promoted_finding), approved=True)
    assert result.submitted is False
    assert result.refusal == "tier3_authority_required"


def test_require_tier3_with_denied_cage_refuses(promoted_finding, export_on) -> None:
    cage = _FakeCage(granted=False)
    pipeline = BountyPipeline(require_tier3=True, cage=cage)
    result = pipeline.submit(_draft(pipeline, promoted_finding), approved=True)
    assert result.submitted is False
    assert result.refusal == "tier3_authority_required"
    assert cage.calls == 1


def test_require_tier3_with_granted_cage_submits(promoted_finding, export_on) -> None:
    cage = _FakeCage(granted=True)
    pipeline = BountyPipeline(require_tier3=True, cage=cage)
    result = pipeline.submit(_draft(pipeline, promoted_finding), approved=True)
    assert result.submitted is True
    assert cage.calls == 1


def test_stage_records_are_json_safe(promoted_finding, export_on) -> None:
    pipeline = BountyPipeline()
    draft = _draft(pipeline, promoted_finding)
    result = pipeline.submit(draft, approved=False)
    payload = result.as_dict()
    assert payload["submitted"] is False
    assert all(set(s.keys()) == {"stage", "ok", "detail"} for s in payload["stages"])
    assert all(isinstance(s, PipelineStage) for s in result.stages)
    draft_payload = draft.as_dict()
    assert draft_payload["stages"] and draft_payload["report"]["report_id"]

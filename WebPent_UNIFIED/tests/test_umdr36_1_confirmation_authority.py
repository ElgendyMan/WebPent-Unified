"""UM-DR-36.1 §5.5 — adversarial confirmation-authority regression tests.

Pins the closed bypasses:

* the family-validator CONFIRMED verdict alone can NEVER mint
  Tool-Confirmed / CONFIRMED confidence — without canonical verification
  the finding is an explicit Pending candidate, and a FAILED
  verification is equally non-authoritative;
* only a passed verify_replay_evidence result attaches Tool-Confirmed
  and the sealed bundle;
* the stateful-discovery probe finding is a Pending candidate, never
  CONFIRMED (its guard verdict is evidence, not authority);
* the Finding model itself refuses Tool-Confirmed without sealed-proof
  provenance (existing M1-B/E-1 enforcement, pinned here as part of the
  same authority matrix).
"""
from __future__ import annotations

import pytest

from webpent.agents.validator.family_checks import (
    FamilyValidationResult,
    FamilyVerdict,
)
from webpent.families.promotion import (
    promote_confirmed_batch,
    promote_confirmed_finding,
)
from webpent.models.findings import Finding, Severity, VulnClass


def _confirmed(vuln_class: str = "tenant_isolation") -> FamilyValidationResult:
    return FamilyValidationResult(
        vuln_class, "TENANT-cross", FamilyVerdict.CONFIRMED,
        "foreign tenant data observed", evidence_refs=("d1",),
        proof_bundle_spec={"causal_oracle": "x"},
    )


class _FakeVerification:
    """Duck-typed VerificationResult stand-in (avoids building a real
    bundle here — the authority tests only need passed/failed shape)."""

    def __init__(self, passed: bool, reason: str = "why",
                 bundle_id: str | None = None) -> None:
        self.passed = passed
        self.reason = reason
        self.proof_bundle = (
            type("B", (), {
                "bundle_id": bundle_id or "b-1", "finding_id": "f-1",
                "model_dump": lambda self, **kw: {
                    "bundle_id": bundle_id or "b-1",
                    "finding_id": "f-1"}})()
            if passed else None)


def test_non_confirmed_never_promotes() -> None:
    result = FamilyValidationResult("race_condition", "RACE",
                                    FamilyVerdict.NEEDS_HUMAN_REVIEW, "r")
    assert promote_confirmed_finding(result) is None


def test_family_confirmed_without_verification_is_pending_candidate() -> None:
    finding = promote_confirmed_finding(_confirmed(), engagement_id="e1")
    assert isinstance(finding, Finding)
    assert finding.confidence_level == "Pending"
    assert finding.confidence != "confirmed"
    assert "Tool-Confirmed" not in str(finding.confidence_level)
    assert finding.evidence["family_candidate_pending_canonical_confirmation"] is True
    assert finding.evidence["canonical_verification"] == "absent"
    # the historical D2-merge marker is preserved (candidate insertion
    # remains the module's job; only the authority claim changed)
    assert finding.evidence["family_promoted"] is True


def test_family_confirmed_with_failed_verification_stays_pending() -> None:
    finding = promote_confirmed_finding(
        _confirmed(), verification=_FakeVerification(False, "guard blocked"))
    assert finding.confidence_level == "Pending"
    assert finding.evidence["canonical_verification"] == "failed"
    assert finding.evidence_bundle is None


def test_family_confirmed_with_passed_verification_is_tool_confirmed() -> None:
    finding = promote_confirmed_finding(
        _confirmed(),
        verification=_FakeVerification(True, "verified_replay"))
    assert finding.confidence_level == "Tool-Confirmed"
    assert finding.evidence["canonical_verification"] == "verify_replay_evidence:passed"
    assert finding.evidence_bundle["bundle_id"] == "b-1"


def test_batch_carries_the_same_authority_contract() -> None:
    confirmed = _confirmed("oauth")
    not_conf = FamilyValidationResult("race", "RACE",
                                      FamilyVerdict.NOT_CONFIRMED, "held")
    out = promote_confirmed_batch(
        [(confirmed, None), (not_conf, None)],
        verifications=[_FakeVerification(True), None])
    assert len(out) == 1
    assert out[0].confidence_level == "Tool-Confirmed"

    out2 = promote_confirmed_batch([(confirmed, None)])
    assert len(out2) == 1
    assert out2[0].confidence_level == "Pending"


def test_stateful_discovery_finding_is_non_authoritative_candidate() -> None:
    """The stateful probe must never mint CONFIRMED on its own."""
    import inspect

    from webpent.production import stateful_discovery as sd
    src = inspect.getsource(sd._finding_from_outcome)
    assert "Confidence.TENTATIVE" in src, (
        "stateful_discovery._finding_from_outcome must insert a TENTATIVE "
        "candidate (UM-DR-36.1 §5.5: no ProofBundle/replay/promotion there, "
        "so CONFIRMED would be a second confirmation authority)")
    assert '"Pending"' in src
    assert "stateful_candidate_pending_canonical_confirmation" in src
    assert "Confidence.CONFIRMED" not in src


def test_finding_model_refuses_tool_confirmed_without_provenance() -> None:
    """M1-B/E-1 enforcement: the model itself fails closed."""
    with pytest.raises(ValueError):
        Finding(
            title="unproven claim",
            severity=Severity.HIGH,
            description="no bundle, no provenance key",
            tool_name="t",
            url="https://example.invalid/",
            vuln_class=VulnClass.IDOR,
            confidence_level="Tool-Confirmed",
        )


def test_execution_node_routes_through_the_authority_contract() -> None:
    """The family execution spine may only insert via promote_confirmed_finding."""
    import inspect

    from webpent.families import execution_node
    src = inspect.getsource(execution_node)
    assert "promote_confirmed_finding" in src
    # and it must not claim confirmation authority itself
    assert 'confidence_level="Tool-Confirmed"' not in src
    assert "Confidence.CONFIRMED" not in src

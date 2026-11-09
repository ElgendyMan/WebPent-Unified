"""M1-B (ب1) precondition-integrity regression tests (2026-11-05).

M0 H-3/1.3a: the chained-exploit analyzer used to FABRICATE composite
preconditions from a finding class alone (``ssrf`` ⇒
``cloud_metadata_reachable`` with no probe anywhere). These tests pin the
M1-B contract:

  * a finding class proves ONLY its ``<class>_finding`` fact;
  * composite preconditions count ONLY when a probe recorded them in
    ``evidence["observed_conditions"]``;
  * unprobed composites ⇒ scenario NOT applicable + SPECULATIVE
    candidate explicitly marked ``unverified_precondition:<name>`` +
    coverage gap; the impact amplifier flags the hypothesis as
    unprobed.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.chained_exploits.analyzer import (  # noqa: E402
    ChainImpactAmplifier,
    PreconditionGraphBuilder,
    _split_observed_conditions,
)
from webpent.families.base import CandidateConfidence  # noqa: E402

CHAIN_003 = "CHAIN-003-ssrf-to-metadata-credential-theft"


class TestPreconditionIntegrity:
    def test_ssrf_class_alone_does_not_verify_cloud_metadata(self):
        """THE M0 ب1 regression: an SSRF finding without any probe must
        NOT observe cloud_metadata_reachable."""
        verified, unverified = _split_observed_conditions(
            [{"vuln_class": "ssrf"}]
        )
        assert "ssrf_finding" in verified
        assert "cloud_metadata_reachable" not in verified
        assert "cloud_metadata_reachable" in unverified

    def test_probe_backed_observed_conditions_are_verified(self):
        verified, unverified = _split_observed_conditions(
            [
                {
                    "vuln_class": "ssrf",
                    "evidence": {"observed_conditions": ["cloud_metadata_reachable"]},
                }
            ]
        )
        assert "cloud_metadata_reachable" in verified
        assert "cloud_metadata_reachable" not in unverified

    def test_scenario_not_applicable_without_probe(self):
        analysis = PreconditionGraphBuilder().analyze(
            [{"vuln_class": "ssrf"}], target_id="t", engagement_id="e"
        )
        assert CHAIN_003 not in analysis.applicable_scenarios
        # The candidate that exists is explicitly SPECULATIVE and marked.
        chain3 = [c for c in analysis.candidates if c.scenario_id == CHAIN_003]
        assert chain3, "expected an unverified-precondition candidate"
        assert chain3[0].confidence == CandidateConfidence.SPECULATIVE
        assert any(
            ref == "unverified_precondition:cloud_metadata_reachable"
            for ref in chain3[0].evidence_refs
        )
        # And the gap is surfaced for the coverage report.
        assert "unverified_precondition:cloud_metadata_reachable" in analysis.coverage_gaps

    def test_scenario_applicable_with_probe(self):
        analysis = PreconditionGraphBuilder().analyze(
            [
                {
                    "vuln_class": "ssrf",
                    "evidence": {"observed_conditions": ["cloud_metadata_reachable"]},
                }
            ],
            target_id="t",
            engagement_id="e",
        )
        assert CHAIN_003 in analysis.applicable_scenarios
        chain3 = [c for c in analysis.candidates if c.scenario_id == CHAIN_003]
        assert chain3
        assert chain3[0].confidence in {
            CandidateConfidence.SUGGESTIVE,
            CandidateConfidence.SUBSTANTIAL,
        }
        assert not any(
            ref.startswith("unverified_precondition:")
            for ref in chain3[0].evidence_refs
        )

    def test_all_seven_scenarios_require_probes_for_composites(self):
        """Every scenario's composite preconditions must not be verifiable
        from class facts alone (systematic — the pre-M1-B pattern was
        generalized, so the guard must be too)."""
        class_to_scenario = {
            "info_disclosure": "CHAIN-001-info-disclosure-to-auth-bypass",
            "open_redirect": "CHAIN-002-open-redirect-oauth-state-theft",
            "ssrf": CHAIN_003,
            "mass_assignment": "CHAIN-004-mass-assignment-privilege-escalation",
            "race_condition": "CHAIN-005-race-bypass-to-otp-brute",
            "csp": "CHAIN-006-cors-to-data-exfiltration",
            "xss": "CHAIN-007-stored-xss-to-csrf-token-theft",
        }
        for vuln_class, scenario_id in class_to_scenario.items():
            analysis = PreconditionGraphBuilder().analyze(
                [{"vuln_class": vuln_class}], target_id="t", engagement_id="e"
            )
            assert scenario_id not in analysis.applicable_scenarios, (
                f"{vuln_class} class alone made {scenario_id} applicable — "
                "composite precondition fabrication regressed"
            )

    def test_amplifier_flags_unverified_preconditions(self):
        analysis = PreconditionGraphBuilder().analyze(
            [{"vuln_class": "ssrf"}], target_id="t", engagement_id="e"
        )
        chain3 = next(
            c for c in analysis.candidates if c.scenario_id == CHAIN_003
        )
        amplified = ChainImpactAmplifier().amplify(chain3)
        assert "preconditions_unverified_no_probe_observation" in amplified["rationale"]
        assert amplified.get("unverified_preconditions")

    def test_amplifier_clean_when_probed(self):
        analysis = PreconditionGraphBuilder().analyze(
            [
                {
                    "vuln_class": "ssrf",
                    "evidence": {"observed_conditions": ["cloud_metadata_reachable"]},
                }
            ],
            target_id="t",
            engagement_id="e",
        )
        chain3 = next(
            c for c in analysis.candidates if c.scenario_id == CHAIN_003
        )
        amplified = ChainImpactAmplifier().amplify(chain3)
        assert "preconditions_unverified_no_probe_observation" not in amplified["rationale"]

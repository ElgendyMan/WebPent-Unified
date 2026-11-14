"""Expert-level vulnerability reasoning without finding or qualification authority."""

from __future__ import annotations

from collections.abc import Sequence

from .contracts import VulnerabilityReasoningReport


class ExpertVulnerabilityReasoningEngine:
    """Structure senior reasoning over supplied hypotheses and evidence references."""

    def analyze(
        self,
        *,
        hypothesis_id: str,
        security_boundary: str,
        attacker_capability: str,
        required_conditions: Sequence[str] = (),
        impact: str = "",
        alternative_explanations: Sequence[str] = (),
        evidence_refs: Sequence[str] = (),
        causal_oracle_present: bool = False,
        validation_requirements: Sequence[str] = (),
    ) -> VulnerabilityReasoningReport:
        refs = tuple(
            dict.fromkeys(
                str(item).strip() for item in evidence_refs if str(item).strip()
            )
        )
        alternatives = tuple(
            dict.fromkeys(
                str(item).strip() for item in alternative_explanations if str(item).strip()
            )
        )
        strength = min(1.0, len(refs) / 4.0)
        if causal_oracle_present:
            strength = min(1.0, strength + 0.2)
        disposition = "advisory_candidate" if causal_oracle_present and refs else "blocked"
        if alternatives:
            disposition = "advisory_with_alternatives"
        return VulnerabilityReasoningReport(
            hypothesis_id=str(hypothesis_id).strip(),
            security_boundary=str(security_boundary).strip(),
            attacker_capability=str(attacker_capability).strip(),
            required_conditions=tuple(
                dict.fromkeys(
                    str(item).strip()
                    for item in required_conditions
                    if str(item).strip()
                )
            ),
            impact=str(impact).strip(),
            alternative_explanations=alternatives,
            evidence_strength=strength,
            evidence_refs=refs,
            causal_oracle_present=bool(causal_oracle_present),
            validation_requirements=tuple(
                dict.fromkeys(
                    str(item).strip() for item in validation_requirements if str(item).strip()
                )
            ),
            disposition=disposition,
        )

    reason_about = analyze


VulnerabilityReasoningEngine = ExpertVulnerabilityReasoningEngine
ExpertReasoningEngine = ExpertVulnerabilityReasoningEngine

__all__ = [
    "ExpertReasoningEngine",
    "ExpertVulnerabilityReasoningEngine",
    "VulnerabilityReasoningEngine",
]

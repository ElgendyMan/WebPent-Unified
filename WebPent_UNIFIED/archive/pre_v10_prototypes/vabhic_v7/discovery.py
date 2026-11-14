"""Reasoning-first unknown vulnerability discovery, advisory only."""

from __future__ import annotations

from hashlib import sha256

from .contracts import DiscoveryCandidateV2, Disposition
from .mental_model import SecurityMentalModel
from .utils import text, values


class UnknownVulnerabilityDiscoveryV2:
    """Derive questions from relationships and assumptions without confirming them."""

    def discover(
        self,
        *,
        model: SecurityMentalModel,
        attack_graph: object | None = None,
        recorded_results: object | None = None,
    ) -> tuple[DiscoveryCandidateV2, ...]:
        candidates: list[DiscoveryCandidateV2] = []
        gaps = list(model.unresolved_questions)
        for relation in values(attack_graph, "relations", "edges"):
            relation_text = text(
                relation, "relation", "kind", "label", "description", default="relationship"
            )
            if any(
                token in relation_text.lower()
                for token in (
                    "permission",
                    "privilege",
                    "identity",
                    "role",
                    "tenant",
                    "owner",
                    "workflow",
                    "state",
                )
            ):
                gaps.append(f"validate boundary behavior for {relation_text}")
        if not model.authorization_boundaries:
            gaps.append("authorization boundary is not sufficiently modeled")
        if not model.sensitive_workflows:
            gaps.append("sensitive workflow preconditions are not sufficiently modeled")
        for result in values(recorded_results, "inconsistent", "anomalies", "observations"):
            description = text(
                result,
                "description",
                "summary",
                "observation",
                "label",
                default="recorded inconsistency",
            )
            if description:
                gaps.append(f"explain recorded inconsistency: {description}")
        unique = tuple(dict.fromkeys(gaps))[:32]
        for _index, assumption in enumerate(unique, start=1):
            candidate_id = (
                "unknown:" + sha256(f"{model.model_id}|{assumption}".encode()).hexdigest()[:16]
            )
            candidates.append(
                DiscoveryCandidateV2(
                    candidate_id=candidate_id,
                    security_assumption=assumption,
                    observed_evidence=model.evidence_refs,
                    reasoning_chain=(
                        "model an explicit security assumption",
                        "search for missing control or inconsistent boundary",
                        "keep alternative explanations open",
                        "require causal validation before promotion",
                    ),
                    possible_impact=(
                        "impact is unverified until the required boundary and oracle "
                        "are demonstrated"
                    ),
                    validation_path=(
                        "identify a safe authorized precondition",
                        "collect candidate and independent negative-control observations",
                        "apply the central causal oracle",
                        "seal and replay evidence",
                    ),
                    source_refs=model.evidence_refs,
                    confidence=min(0.8, model.confidence),
                    disposition=Disposition.HYPOTHESIS,
                )
            )
        return tuple(candidates)


__all__ = ["UnknownVulnerabilityDiscoveryV2"]

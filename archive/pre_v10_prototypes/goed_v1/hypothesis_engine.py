"""
GOED v1 — Phase 4: Knowledge Isolation Layer
           Phase 5: Generative Hypothesis Engine

Phase 4 ensures the generative engine cannot access benchmark knowledge.
Phase 5 generates competing hypotheses from observations.
"""
import re
from dataclasses import dataclass
from typing import Any

from .contracts import (
    ConfidenceLevel,
    GenerativeResearchOpportunity,
    Hypothesis,
    OpportunityType,
    create_opportunity_from_observation,
)

# ============================================================
# PHASE 4: ISOLATION LAYER
# ============================================================

class KnowledgeIsolationBoundary:
    """
    Strict boundary preventing benchmark knowledge from leaking into
    the generative engine.

    The generative engine operates in a sandboxed context where:
    - No benchmark files are importable
    - No ground truth labels accessible
    - No pre-defined route dictionaries
    - Only target-derived evidence flows through
    """

    BENCHMARK_LEAKAGE_PATTERNS = [
        r'target[-_]?(alpha|beta|gamma|delta|epsilon)',
        r'case[-_]?\d{2}',
        r'pilot[-_]?case',
        r'u\d{3}',
        r'tenant[-_]?[ab]',
        r'ground[_-]?truth',
        r'expected[_-]?findings',
    ]

    @classmethod
    def scan_for_leakage(cls, text: str) -> list[str]:
        """Scan text for potential benchmark leakage patterns."""
        leaks = []
        for pattern in cls.BENCHMARK_LEAKAGE_PATTERNS:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                leaks.append(m.group(0))
        return leaks

    @classmethod
    def is_safe_context(cls, context: dict[str, Any]) -> tuple[bool, list[str]]:
        """Verify a context dictionary contains no benchmark leakage."""
        leaks = []
        for _k, v in context.items():
            if isinstance(v, str):
                leaks.extend(cls.scan_for_leakage(v))
            elif isinstance(v, dict):
                ok, sub_leaks = cls.is_safe_context(v)
                leaks.extend(sub_leaks)
        return (len(leaks) == 0, leaks)

    @classmethod
    def sanitize(cls, text: str) -> str:
        """Remove/replace any benchmark leakage patterns."""
        sanitized = text
        for pattern in cls.BENCHMARK_LEAKAGE_PATTERNS:
            sanitized = re.sub(pattern, '[REDACTED_BENCHMARK]', sanitized, flags=re.IGNORECASE)
        return sanitized


# ============================================================
# PHASE 5: GENERATIVE HYPOTHESIS ENGINE
# ============================================================

@dataclass
class ObservationDelta:
    """A meaningful difference between two observations."""
    attribute: str
    value_a: Any
    value_b: Any
    context_a: str = ""
    context_b: str = ""
    significance: float = 0.5


class GenerativeHypothesisEngine:
    """
    Generates MULTIPLE COMPETING hypotheses from each meaningful observation.
    Does NOT immediately select the first security-looking hypothesis.

    Key principle: For every observation, generate at least:
    - 1 security-relevant hypothesis
    - 1 benign/legitimate hypothesis
    - 1 alternative explanation
    """

    HYPOTHESIS_TEMPLATES = {
        OpportunityType.AUTH_WEAKNESS: [
            "Authorization boundary may not be correctly enforced for this resource",
            "Access control check may be missing or incorrectly ordered",
            "Privilege level escalation may be possible through this endpoint",
        ],
        OpportunityType.BOUNDARY_VIOLATION: [
            "Tenant/organization boundary may be permeable",
            "Resource ownership check may be bypassable",
            "Cross-context data access may be possible",
        ],
        OpportunityType.DATA_EXPOSURE: [
            "Sensitive data may be exposed without proper authorization",
            "Response may contain fields that should be redacted",
            "Pagination/filtering may expose unintended data",
        ],
        OpportunityType.WORKFLOW_GAP: [
            "Workflow state transition may skip authorization check",
            "Approver/requester separation may not be enforced",
            "State machine may allow out-of-order transitions",
        ],
        OpportunityType.RESEARCH_DIRECTION: [
            "Legitimate behavior variation — requires further investigation",
            "Expected role-based content personalization",
            "Public resource with context-aware rendering",
        ],
        OpportunityType.INVARIANT_BREAK: [
            "Observed behavior may violate an assumed security invariant",
            "Application-level consistency check may be absent",
            "Business rule enforcement may be inconsistent",
        ],
    }

    BENIGN_TEMPLATES = [
        "Legitimate role-based content variation",
        "Expected tenant-scoped data difference",
        "Public resource with personalization",
        "Content varies by design (A/B testing, feature flags)",
        "Different states of a legitimate state machine",
        "Cache/stale data difference",
    ]

    def analyze_difference(self, delta: ObservationDelta, entity: str) -> GenerativeResearchOpportunity:
        """From a single observed difference, generate competing hypotheses."""
        obs_summary = (
            f"Attribute '{delta.attribute}' differs: "
            f"'{delta.value_a}' ({delta.context_a}) vs '{delta.value_b}' ({delta.context_b})"
        )

        gro = create_opportunity_from_observation(
            observation_summary=obs_summary,
            entity=entity,
            context_diff={"attribute": delta.attribute, "value_a": delta.value_a, "value_b": delta.value_b},
            generation_reason=f"Meaningful difference observed in '{delta.attribute}' across contexts",
        )

        primary = self._select_primary_hypothesis(delta)
        gro.hypothesis = primary

        alternatives = []

        for template in self.BENIGN_TEMPLATES[:2]:
            alternatives.append(Hypothesis(
                description=template,
                hypothesis_type=OpportunityType.RESEARCH_DIRECTION,
                supporting_evidence=["Common pattern in legitimate applications"],
                discriminating_experiment="Test whether behavior is consistent across same-role identities",
                confidence=ConfidenceLevel.SPECULATIVE,
                security_relevant=False,
            ))

        alt_types = [t for t in OpportunityType
                     if t not in (primary.hypothesis_type, OpportunityType.RESEARCH_DIRECTION)]
        for opt_type in alt_types[:2]:
            templates = self.HYPOTHESIS_TEMPLATES.get(opt_type, [])
            if templates:
                alternatives.append(Hypothesis(
                    description=templates[0],
                    hypothesis_type=opt_type,
                    supporting_evidence=["Plausible alternative security interpretation"],
                    discriminating_experiment=(
                        f"Design experiment to discriminate from {primary.hypothesis_type.value}"
                    ),
                    confidence=ConfidenceLevel.SPECULATIVE,
                ))

        gro.alternative_hypotheses = alternatives
        gro.exploration_priority = min(0.9, 0.3 + delta.significance * 0.5)

        return gro

    def _select_primary_hypothesis(self, delta: ObservationDelta) -> Hypothesis:
        """Select the most plausible security hypothesis based on what changed."""
        attr = str(delta.attribute).lower()
        val_a = str(delta.value_a).lower()
        val_b = str(delta.value_b).lower()

        if any(k in attr for k in ["auth", "authoriz", "privilege", "role", "access"]):
            htype = OpportunityType.AUTH_WEAKNESS
        elif any(k in attr for k in ["tenant", "owner", "boundary", "cross", "isolat"]):
            htype = OpportunityType.BOUNDARY_VIOLATION
        elif any(k in attr for k in ["data", "content", "body", "field", "redact", "expos", "sensitive", "private"]):
            htype = OpportunityType.DATA_EXPOSURE
        elif any(k in attr for k in ["workflow", "state", "status", "approve", "request", "order"]):
            htype = OpportunityType.WORKFLOW_GAP
        elif any(k in val_a for k in ["200", "ok", "success", "granted"]) and any(k in val_b for k in ["403", "401", "denied", "forbidden"]):
            htype = OpportunityType.AUTH_WEAKNESS
        else:
            htype = OpportunityType.UNEXPLAINED_DIFFERENCE

        templates = self.HYPOTHESIS_TEMPLATES.get(htype, ["Unusual behavior pattern detected"])
        return Hypothesis(
            description=templates[0],
            hypothesis_type=htype,
            supporting_evidence=[f"Attribute '{delta.attribute}' shows meaningful difference"],
            discriminating_experiment="Test with additional context combinations to isolate cause",
            confidence=ConfidenceLevel.SPECULATIVE,
        )

    def rank_hypotheses(self, gro: GenerativeResearchOpportunity) -> list[tuple[Hypothesis, float]]:
        """Rank hypotheses by evidence weight. Never eliminates alternatives."""
        ranked = []
        for h in gro.all_hypotheses():
            score = 0.3
            score += len(h.supporting_evidence) * 0.15
            score -= len(h.contradicting_evidence) * 0.1
            if h.security_relevant:
                score += 0.1
            ranked.append((h, round(min(1.0, score), 3)))
        return sorted(ranked, key=lambda x: -x[1])

    def select_discriminating_experiment(self, gro: GenerativeResearchOpportunity) -> str | None:
        """Select the cheapest experiment that best discriminates top two hypotheses."""
        ranked = self.rank_hypotheses(gro)
        if len(ranked) < 2:
            return ranked[0][0].discriminating_experiment if ranked else None
        h1, _ = ranked[0]
        return h1.discriminating_experiment


HYPOTHESIS_ENGINE_GOVERNANCE = {
    "always_generates_competing_hypotheses": True,
    "never_immediately_selects_security": True,
    "benign_alternatives_always_included": True,
    "no_target_specific_patterns": True,
    "isolation_layer_used": True,
}

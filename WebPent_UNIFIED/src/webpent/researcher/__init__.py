"""webpent.researcher package init — UM-DR-46 Phase B + C.

The deterministic Researcher Brain and the adaptive hypothesis engine:
evidence-backed understanding + evolution components over the Security
Knowledge Graph and the hypothesis pool. Advisory only — no I/O, no
authorization, no confirmation authority, no lifecycle power.
"""
from webpent.researcher.brain import (
    classify_endpoint_behavior,
    contradiction_vuln_class,
    detect_contradictions,
    discover_invariants,
    infer_business_rules,
    transition_semantics,
)
from webpent.researcher.evolution import (
    competing_hypotheses,
    decompose_hypothesis,
    learn_from_negative_evidence,
    mutate_hypothesis,
    select_by_info_gain,
)

__all__ = [
    "classify_endpoint_behavior",
    "competing_hypotheses",
    "contradiction_vuln_class",
    "decompose_hypothesis",
    "detect_contradictions",
    "discover_invariants",
    "infer_business_rules",
    "learn_from_negative_evidence",
    "mutate_hypothesis",
    "select_by_info_gain",
    "transition_semantics",
]

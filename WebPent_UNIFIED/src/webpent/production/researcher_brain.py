"""UM-DR-46 Phase B — the researcher-brain production node.

Wires the deterministic Researcher Brain (researcher/brain.py) into
the graph AFTER the appmodel node and BEFORE the hypothesis node:

1. rebuilds the Security Knowledge Graph from the real state channels
   (deterministic — identical to what appmodel_node produced);
2. runs the five understanding components (behavioral profiles,
   business rules, transition semantics, invariants, contradictions);
3. records contradictions in the SSOT (``mark_contradicted`` — both
   evidences kept) and emits ONE canonical hypothesis per contradiction
   through ``canonical_hypothesis`` (ordinary pool citizen — same
   strategist ranking, same promotion gates, same authorized execution
   path; never a finding, never a confirmation);
4. writes the bounded advisory channels ``researcher_brain``,
   ``researcher_brain_rules`` and ``researcher_brain_contradictions``.

Hard limits: no network I/O, no authorization, no scope expansion, no
execution, and it can NEVER confirm a vulnerability or bypass
CausalGuard / ProofBundle / Replay.
"""
from __future__ import annotations

import logging
from typing import Any

from webpent.appmodel.skg import build_security_knowledge_graph
from webpent.researcher.brain import (
    classify_endpoint_behavior,
    contradiction_vuln_class,
    detect_contradictions,
    discover_invariants,
    infer_business_rules,
    transition_semantics,
)

logger = logging.getLogger(__name__)

__all__ = ["researcher_brain_node"]


def _get(state: Any, key: str) -> Any:
    if isinstance(state, dict):
        return state.get(key)
    return getattr(state, key, None)

_MAX_SUMMARY_PROFILES = 64
_MAX_SUMMARY_SEMANTICS = 64

_EXPECTED_BEHAVIOR = {
    "surface_marker_mismatch": (
        "both surfaces of the same resource enforce the SAME "
        "authorization requirement; the marker difference disappears "
        "under a role-differential replay"
    ),
    "workflow_protocol_bypass": (
        "the transition through the bypassing endpoint is rejected or "
        "requires the intermediate state; the observed shortcut is not "
        "reproducible for a non-privileged principal"
    ),
    "ownership_change_without_marker": (
        "the ownership change is rejected for a principal outside the "
        "resource's ownership boundary; only authorized principals "
        "succeed"
    ),
}

_NEGATIVE_CONTROL = {
    "surface_marker_mismatch": (
        "replay the identical request pair as the resource owner — it "
        "must succeed on both surfaces, and the differential must be "
        "reproducible under sealed replay"
    ),
    "workflow_protocol_bypass": (
        "replay the bypassing transition with a legitimate completed "
        "workflow state — it must behave identically for the legitimate "
        "principal, isolating the bypass as the only difference"
    ),
    "ownership_change_without_marker": (
        "replay the ownership change as the resource owner — it must "
        "succeed; replay it as a foreign principal — it must be denied; "
        "both under sealed replay"
    ),
}


def _contradiction_hypothesis(contradiction: dict[str, Any],
                              target_url: str) -> Any:
    import hashlib
    import json
    from uuid import NAMESPACE_URL, uuid5

    from webpent.production.hypothesis_adapter import canonical_hypothesis

    kind = str(contradiction.get("kind") or "")
    # deterministic identity (the UM-DR-31/43C convention): same
    # contradiction ⇒ same hypothesis id ⇒ the pool reducer dedupes
    # re-emissions instead of duplicating them
    fingerprint_blob = json.dumps(
        {"t": str(target_url or "").strip().rstrip("/").lower(),
         "k": kind,
         "c": str(contradiction.get("contradiction_id") or "")},
        sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(
        fingerprint_blob.encode("utf-8")).hexdigest()[:40]
    return canonical_hypothesis(
        id=uuid5(NAMESPACE_URL, f"webpent:umdr46b:{fingerprint}"),
        statement=(
            f"{contradiction.get('statement', '')} — verify with a "
            f"CausalGuard-guarded differential experiment"
        ),
        vuln_class=contradiction_vuln_class(kind),
        origin="researcher_brain",
        origin_detail=(
            f"SKG contradiction {contradiction.get('contradiction_id', '')} "
            f"(kind {kind}); entities: "
            f"{', '.join(contradiction.get('entity_ids', [])[:6])}"
        ),
        target_url=target_url,
        expected_behavior=_EXPECTED_BEHAVIOR.get(
            kind, "the evidence conflict resolves under a guarded differential"),
        negative_control=_NEGATIVE_CONTROL.get(
            kind, "owner-principal replay must succeed; foreign replay must be denied"),
        deterministic_match=True,
        evidence_contract={
            "evidence_refs": list(contradiction.get("evidence_refs", []))[:12],
            "contradiction_id": contradiction.get("contradiction_id"),
            "kind": kind,
        },
    )


def researcher_brain_node(state: Any) -> dict[str, Any]:
    """Run the deterministic Researcher Brain over the SKG."""
    try:
        model = build_security_knowledge_graph(state)
    except Exception as exc:  # noqa: BLE001 — advisory node, never fatal
        logger.warning("researcher brain failed (advisory node): %s", exc)
        return {
            "researcher_brain": {
                "built": False,
                "error": str(exc)[:200],
                "advisory_only": True,
            },
            "researcher_brain_rules": [],
            "researcher_brain_contradictions": [],
            "hypotheses": [],
        }

    profiles = classify_endpoint_behavior(model)
    rules = infer_business_rules(model)
    semantics = transition_semantics(model)
    invariants = discover_invariants(model)
    contradictions = detect_contradictions(model, mark=True)

    hypotheses = [
        _contradiction_hypothesis(c, str(_get(state, "target_url") or ""))
        for c in contradictions
    ]

    summary = {
        "built": True,
        "advisory_only": True,
        "behavioral_profile_count": len(profiles),
        "business_rule_count": len(rules),
        "transition_semantics_count": len(semantics),
        "invariant_count": len(invariants),
        "contradiction_count": len(contradictions),
        "hypothesis_count": len(hypotheses),
        "behavioral_profiles": {
            profile_id: {
                "path": profile["path"],
                "reads": profile["reads"],
                "writes": profile["writes"],
                "state_trigger": profile["state_trigger"],
                "authz_marked": profile["authz_marked"],
            }
            for profile_id, profile in list(profiles.items())[
                :_MAX_SUMMARY_PROFILES]
        },
        "transition_semantics": semantics[:_MAX_SUMMARY_SEMANTICS],
        "invariants": invariants,
        "influence_contract": (
            "advisory for research prioritization only — never authorizes, "
            "never confirms, never bypasses CausalGuard/ProofBundle/Replay"
        ),
    }
    return {
        "researcher_brain": summary,
        "researcher_brain_rules": rules,
        "researcher_brain_contradictions": contradictions,
        "hypotheses": hypotheses,
    }

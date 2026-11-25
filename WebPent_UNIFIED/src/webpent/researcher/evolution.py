"""UM-DR-46 Phase C — the adaptive hypothesis engine (evolution).

Five deterministic components over the hypothesis pool (mission
Phase C), all pure functions — no LLM, no I/O, no lifecycle authority
(they never promote, confirm or close; they only ADD candidates,
DECAY priorities of relatives after negative evidence, and ORDER
selection for research prioritization):

1. ``mutate_hypothesis``            — deterministic mutation templates
   per vuln_class for RESOLVED_FALSE parents (parameter/method/
   surface/context variants), ids derived from the parent's (pool
   dedup on re-emission);
2. ``decompose_hypothesis``         — compound statements split into
   per-step sub-hypotheses (deterministic marker detection);
3. ``competing_hypotheses``         — SKG-grounded alternative
   explanations (multi-path / public-resource / principal-context
   bases) for a hypothesis about a modeled resource;
4. ``learn_from_negative_evidence`` — relatives (same target + class)
   decay (info_gain ×0.7) and a deterministic lesson record is
   returned (consumed by Phase H research memory);
5. ``select_by_info_gain``          — open hypotheses ordered
   deterministic-match first, then info_gain desc, id asc ties.

Everything flows into the ordinary pool through ``merge_hypotheses``
(same strategist ranking, same promotion gates).
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from webpent.appmodel.models import ApplicationModel
from webpent.models.hypothesis import Hypothesis

__all__ = [
    "competing_hypotheses",
    "decompose_hypothesis",
    "learn_from_negative_evidence",
    "mutate_hypothesis",
    "select_by_info_gain",
]

_MAX_MUTATIONS = 3
_MAX_COMPETITORS = 3
_MAX_REFUTED_PER_PASS = 4
_MUTATION_DECAY = 0.5
_NEGATIVE_DECAY = 0.7
_OPEN_STATUSES = {"unexplored", "investigating", "learned"}

#: (template_id, phrase, expected_behavior, negative_control) per class.
_MUTATION_TEMPLATES: dict[str, list[tuple[str, str, str, str]]] = {
    "idor": [
        ("param_format", "with a differently-formatted object identifier",
         "the access is still denied for the non-owner under the "
         "alternate identifier format",
         "owner replay must succeed; sealed replay reproduces the "
         "differential"),
        ("role_context", "from a different low-privilege principal context",
         "the access is denied for the alternate low-privilege principal",
         "the legitimate principal's replay must succeed under sealed "
         "replay"),
        ("http_method", "via an alternate HTTP method on the same resource",
         "the alternate method is authorization-checked the same way",
         "the original method's legitimate use must remain intact"),
    ],
    "auth_bypass": [
        ("surface_variant", "on the alternate UI/API surface of the same resource",
         "both surfaces enforce the same authorization requirement",
         "the marked surface must keep enforcing; sealed replay isolates "
         "the difference"),
        ("session_context", "with an alternate session context",
         "the bypass does not survive a fresh session context",
         "the legitimate session must remain functional"),
        ("boundary_variant", "across a different trust boundary",
         "the boundary is enforced independently of the entry point",
         "the in-boundary request must remain allowed"),
    ],
    "workflow_abuse": [
        ("transition_entry", "entering the transition from an alternate state",
         "the transition is rejected from the unauthorized entry state",
         "the legitimate entry-state replay must succeed"),
        ("role_context", "as a different role on the same workflow",
         "the role boundary holds for the alternate role",
         "the authorized role must still complete the workflow"),
        ("http_method", "through an alternate method on the trigger endpoint",
         "the trigger is method-consistent",
         "the original trigger use must remain intact"),
    ],
}
_FALLBACK_TEMPLATES: list[tuple[str, str, str, str]] = [
    ("param_variant", "with an alternate parameter shape on the same target",
     "the behavior is parameter-consistent under the alternate shape",
     "the original shape's legitimate use must remain intact"),
    ("method_variant", "via an alternate HTTP method on the same target",
     "the behavior is method-consistent",
     "the original method's legitimate use must remain intact"),
    ("context_variant", "from an alternate principal context",
     "the behavior is principal-scoped",
     "the legitimate principal's replay must succeed"),
]


def _fingerprint(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(blob.encode("utf-8")).hexdigest()[:40]


def _evolution_hypothesis(
    *,
    parent: Hypothesis,
    kind: str,
    key: str,
    statement: str,
    expected_behavior: str,
    negative_control: str,
    evidence: dict[str, Any],
    info_gain: float | None = None,
) -> Hypothesis:
    from webpent.production.hypothesis_adapter import canonical_hypothesis

    payload = {"t": str(parent.target_url or ""), "k": kind, "p": str(
        parent.id), "c": key}
    hyp_id = uuid5(NAMESPACE_URL, f"webpent:umdr46c:{_fingerprint(payload)}")
    contract = dict(evidence)
    contract["evolution_kind"] = kind
    contract["parent_hypothesis_id"] = str(parent.id)
    gain = (parent.info_gain if info_gain is None else info_gain) or 0.0
    return canonical_hypothesis(
        id=hyp_id,
        statement=statement,
        vuln_class=str(parent.vuln_class),
        origin="researcher_brain",
        origin_detail=(
            f"UM-DR-46 Phase C {kind} of hypothesis {parent.id} "
            f"(deterministic; same strategist ranking, same promotion "
            f"gates)"
        ),
        target_url=parent.target_url,
        expected_behavior=expected_behavior,
        negative_control=negative_control,
        deterministic_match=True,
        evidence_contract=contract,
        info_gain=max(0.0, min(1.0, float(gain))),
    )


def _is_refuted(hypothesis: Hypothesis) -> bool:
    return str(getattr(hypothesis, "status", "")).lower().endswith(
        "resolved_false")


# ---------------------------------------------------------------------------
# 1. Mutation
# ---------------------------------------------------------------------------


def mutate_hypothesis(hypothesis: Hypothesis) -> list[Hypothesis]:
    """Deterministic mutations of a refuted hypothesis (≤3)."""
    if not _is_refuted(hypothesis):
        return []
    vuln_class = str(hypothesis.vuln_class)
    templates = _MUTATION_TEMPLATES.get(vuln_class, _FALLBACK_TEMPLATES)
    contract = hypothesis.evidence_contract or {}
    refs = [str(r)[:200] for r in (contract.get("evidence_refs") or [])][:8]
    mutations: list[Hypothesis] = []
    for template_id, phrase, expected, control in templates[:_MAX_MUTATIONS]:
        mutations.append(_evolution_hypothesis(
            parent=hypothesis,
            kind="mutation",
            key=template_id,
            statement=f"{hypothesis.statement} — retried {phrase}",
            expected_behavior=expected,
            negative_control=control,
            evidence={
                "mutation_template": template_id,
                "evidence_refs": refs,
            },
            info_gain=float(hypothesis.info_gain or 0.0) * _MUTATION_DECAY,
        ))
    return mutations


# ---------------------------------------------------------------------------
# 2. Decomposition
# ---------------------------------------------------------------------------

_STEP_MARKERS = (" then ", "→", " -> ")


def decompose_hypothesis(hypothesis: Hypothesis) -> list[Hypothesis]:
    """Split a compound statement into per-step sub-hypotheses."""
    statement = str(hypothesis.statement or "")
    marker = next((m for m in _STEP_MARKERS if m in statement), None)
    if marker is None:
        return []
    parts = [part.strip() for part in statement.split(marker, 1)]
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return []
    contract = hypothesis.evidence_contract or {}
    refs = [str(r)[:200] for r in (contract.get("evidence_refs") or [])][:8]
    steps: list[Hypothesis] = []
    for index, part in enumerate(parts[:4]):
        steps.append(_evolution_hypothesis(
            parent=hypothesis,
            kind="decomposition",
            key=f"step{index}",
            statement=(
                f"{part} (isolated step {index + 1} of {len(parts[:4])} "
                f"from a compound hypothesis)"
            ),
            expected_behavior=(
                f"the isolated step behaves as the compound hypothesis "
                f"predicts for step {index + 1}"
            ),
            negative_control=(
                f"{hypothesis.negative_control} — with the other steps "
                f"held at their legitimate state"
            ),
            evidence={
                "step_index": index,
                "step_count": len(parts[:4]),
                "evidence_refs": refs,
            },
            info_gain=float(hypothesis.info_gain or 0.0) * _MUTATION_DECAY,
        ))
    return steps


# ---------------------------------------------------------------------------
# 3. Competing hypotheses (SKG-grounded)
# ---------------------------------------------------------------------------


def competing_hypotheses(
    hypothesis: Hypothesis,
    model: ApplicationModel,
) -> list[Hypothesis]:
    """SKG-grounded alternative explanations (≤3), evidence-backed."""
    statement = str(hypothesis.statement or "")
    resource = next(
        (e for e in model.entities.values()
         if str(e.kind) == "resource"
         and str(e.label).removeprefix("resource:") in statement),
        None,
    )
    if resource is None:
        return []
    from webpent.appmodel.skg_queries import get_all_paths_to

    paths = get_all_paths_to(model, resource.id)["paths"]
    owners = {
        relation.source_id
        for relation in model.relations
        if str(relation.kind) == "owns" and relation.target_id == resource.id
    }
    principals = sorted({
        str(model.entities[r.source_id].label)
        for r in model.relations
        if r.target_id == resource.id and str(r.kind) in {
            "accesses", "reads", "modifies", "owns"}
        and model.entities.get(r.source_id) is not None
        and str(model.entities[r.source_id].kind) == "identity"
    })
    path_refs = sorted({
        ref for p in paths for ref in p["evidence_refs"]
    })[:8]
    competitors: list[Hypothesis] = []
    if len(paths) > 1:
        competitors.append(_evolution_hypothesis(
            parent=hypothesis,
            kind="competitor",
            key="multi_path",
            statement=(
                f"the observed access to {resource.label} is explained by "
                f"another legitimate path through the model, not by the "
                f"claimed authorization failure"
            ),
            expected_behavior=(
                "the alternative path reproduces the observation for a "
                "legitimate principal"
            ),
            negative_control=(
                "the claimed differential must disappear when the "
                "alternative path is blocked"
            ),
            evidence={"competitor_basis": "multi_path",
                      "path_count": len(paths),
                      "evidence_refs": path_refs},
        ))
    if not owners:
        competitors.append(_evolution_hypothesis(
            parent=hypothesis,
            kind="competitor",
            key="public_resource",
            statement=(
                f"{resource.label} may be anonymous/public-accessible, "
                f"making the observed access unremarkable"
            ),
            expected_behavior=(
                "an unauthenticated request to the resource succeeds if "
                "it is public"
            ),
            negative_control=(
                "an authenticated owner-context request must behave "
                "identically to the anonymous one for a public resource"
            ),
            evidence={"competitor_basis": "public_resource",
                      "evidence_refs": path_refs},
        ))
    if len(principals) > 1:
        competitors.append(_evolution_hypothesis(
            parent=hypothesis,
            kind="competitor",
            key="principal_context",
            statement=(
                f"the differential on {resource.label} requires a "
                f"different principal context than the one claimed "
                f"(observed principals: {', '.join(principals[:3])})"
            ),
            expected_behavior=(
                "re-running the differential under each observed "
                "principal isolates the real boundary"
            ),
            negative_control=(
                "each observed principal's legitimate access must "
                "succeed under sealed replay"
            ),
            evidence={"competitor_basis": "principal_context",
                      "principals": principals[:4],
                      "evidence_refs": path_refs},
        ))
    return competitors[:_MAX_COMPETITORS]


# ---------------------------------------------------------------------------
# 4. Negative-evidence learning
# ---------------------------------------------------------------------------


def learn_from_negative_evidence(
    pool: list[Hypothesis],
    refuted: Hypothesis,
) -> tuple[list[Hypothesis], dict[str, Any]]:
    """Decay related open hypotheses; return (new_pool, lesson).

    Pure: the input pool is not mutated. Related = same target_url +
    same vuln_class, open, not the refuted one. Each relative is
    replaced by a copy with decayed info_gain and a negative_lesson_id
    stamped into its evidence contract. The lesson record is
    deterministic (uuid5 of the refuted id) and carries both the
    refutation evidence and the affected ids — Phase H's research
    memory consumes it.
    """
    refuted_id = str(refuted.id)
    lesson_id = uuid5(
        NAMESPACE_URL,
        f"webpent:umdr46c:lesson:{_fingerprint({'r': refuted_id})}",
    )
    contract = refuted.evidence_contract or {}
    refs = [str(r)[:200] for r in (contract.get("evidence_refs") or [])][:8]
    related_ids: list[str] = []
    new_pool: list[Hypothesis] = []
    for hyp in pool:
        same_class = str(hyp.vuln_class) == str(refuted.vuln_class)
        same_target = str(hyp.target_url or "") == str(refuted.target_url or "")
        is_open = str(getattr(hyp, "status", "")).lower().split(".")[
            -1] in _OPEN_STATUSES
        if str(hyp.id) != refuted_id and same_class and same_target and is_open:
            related_ids.append(str(hyp.id))
            merged = dict(hyp.evidence_contract or {})
            merged["negative_lesson_id"] = str(lesson_id)
            new_pool.append(hyp.model_copy(update={
                "info_gain": max(
                    0.0, float(hyp.info_gain or 0.0) * _NEGATIVE_DECAY),
                "evidence_contract": merged,
            }))
        else:
            new_pool.append(hyp)
    lesson = {
        "lesson_id": str(lesson_id),
        "refuted_hypothesis_id": refuted_id,
        "vuln_class": str(refuted.vuln_class),
        "statement": str(refuted.statement)[:500],
        "evidence_refs": refs,
        "related_hypothesis_ids": related_ids,
        "learned": (
            f"hypothesis {refuted_id} was resolved FALSE; the {refuted.vuln_class} "
            f"family on {refuted.target_url} is deprioritized by "
            f"{_NEGATIVE_DECAY} until new evidence arrives"
        ),
    }
    return new_pool, lesson


# ---------------------------------------------------------------------------
# 5. Information-gain selection
# ---------------------------------------------------------------------------


def select_by_info_gain(
    pool: list[Hypothesis],
    *,
    limit: int = 8,
) -> list[Hypothesis]:
    """Open hypotheses ordered deterministic-match first, info_gain desc."""
    def _status(h: Hypothesis) -> str:
        raw = str(getattr(h, "status", ""))
        return raw.split(".")[-1].lower() if raw else ""

    open_items = [h for h in pool if _status(h) in _OPEN_STATUSES]

    def _gain(h: Hypothesis) -> float:
        # UM-DR-49 W2.4 (real-ground finding): hypotheses created by the
        # graph path may carry info_gain=None (the field is optional on
        # the model); the ORIGINAL float(h.info_gain) crashed the whole
        # hypothesis_evolution task on the first real SPA campaign.
        # None sorts LAST (no observed gain yet — deterministic matches
        # still lead), never crashes.
        raw = getattr(h, "info_gain", None)
        if raw is None:
            return -1.0
        try:
            return float(raw)
        except (TypeError, ValueError):
            return -1.0

    ordered = sorted(
        open_items,
        key=lambda h: (
            0 if bool(getattr(h, "deterministic_match", False)) else 1,
            -_gain(h),
            str(h.id),
        ),
    )
    return ordered[: max(0, int(limit))]

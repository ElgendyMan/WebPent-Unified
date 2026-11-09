# src/webpent/shared/prioritization.py
"""webpent.shared.prioritization

V7 Cognitive Upgrade — Phase 3: Dynamic Prioritization.

Replaces "always process findings/hypotheses in discovery order" with
a real ranking. This module is a **deterministic scoring function**
(not an LLM decision) that ranks the current frontier of open
hypotheses / goal-tree leaves.

Inputs (per Phase 3 step 1):
  * severity class (from Hypothesis.vuln_class -> Severity mapping)
  * confidence score (Phase 4 — Hypothesis.confidence_score, 0.0-1.0)
  * evidence quality (Phase 6 batch — stub returns 0.5 until Phase 6
    lands; the function signature is stable so Phase 6 just plugs in
    the real scorer)
  * estimated cost (Hypothesis.estimated_cost; lower cost = higher rank)
  * novelty/curiosity bonus (capped, decay-based on how many times
    similar hypotheses have been promoted)
  * asset criticality inferred from the Mental Model (e.g. "credential"
    ranks above "generic endpoint")

Design principles (per Phase 3 spec):
  * **Plain Python formula over numeric inputs.** Structurally
    identical in spirit to the existing ``_SEVERITY_RANKS`` lookup
    table already used in ``route_after_validator`` — extending an
    established pattern, not introducing a new paradigm.
  * **The LLM may be used upstream** to propose a qualitative "value
    estimate" for a hypothesis (similar to how ``exploit_chainer``
    lets the LLM draft a chain narrative only after a deterministic
    gate already matched) — but the actual comparison, sorting, and
    selection of what to work on next is 100% deterministic
    arithmetic. No LLM ever directly picks "what happens next."
  * **This is the mechanism that decides**: promote a hypothesis to
    a Finding now, defer it, or (once Phase 5/7 exist) enter a
    Rabbit Hole branch.
  * **Every prioritization decision writes one entry to the Decision
    Log** (Phase 6 batch) — this is what makes the system's ordering
    explainable after the fact. The Decision Log call is stubbed here
    and will be wired up when Phase 6 lands; the function signature
    is stable.

Weights:
    The weights below are the deterministic formula's coefficients.
    They are NOT LLM-tunable at runtime — changing a weight is a code
    change, reviewable in the diff, auditable in the Decision Log.
    This is the "no LLM deciding critical values alone" discipline
    applied to the prioritization formula itself.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from webpent.models.findings import Finding, VulnClass
from webpent.models.hypothesis import Hypothesis
from webpent.models.mental_model import (
    Criticality,
    NodeKind,
    _coerce_to_mental_model,
)

logger = logging.getLogger(__name__)


# V9 FIX B-02: Normalize Finding URLs for SQLi paths so the persisted
# Finding matches what sqlmap actually scans.
def _normalize_finding_url(url: str, vuln_class: str) -> str:
    """Normalize a Finding URL for tool reproducibility.

    For SQLi vuln_class, delegates to sqlmap's normalize_sqli_url to
    ensure the Finding's url field includes the query parameters
    (id=1&Submit=Submit) that sqlmap needs. For other vuln classes,
    returns the URL unchanged.
    """
    if vuln_class == VulnClass.SQLI.value:
        try:
            from webpent.tools.exploitation.sqlmap import normalize_sqli_url
            return normalize_sqli_url(url)
        except ImportError:
            pass
            # Intentionally suppressed — reviewed 2026-09-03
    return url


# ---------------------------------------------------------------------------
# Deterministic severity rank (extends _SEVERITY_RANKS from builder.py)
# ---------------------------------------------------------------------------
# Phase 3 step 2: "structurally identical in spirit to the existing
# _SEVERITY_RANKS lookup table already used in route_after_validator".
# We map each VulnClass to a Severity-equivalent rank so hypotheses
# can be ranked on the same 0-4 scale that findings already use.
#
# The mapping is conservative: exploitable classes (XSS, SQLi, SSRF,
# RCE, etc.) rank as HIGH (3) because they're the classes the
# framework knows how to actually exploit; info-disclosure / unknown
# rank as MEDIUM (2); the rest default to MEDIUM. CRITICAL (4) is
# reserved for promoted findings whose severity has been confirmed by
# a tool — a Hypothesis never starts at CRITICAL.
_VULN_CLASS_TO_SEVERITY_RANK: dict[str, int] = {
    VulnClass.XSS.value: 3,
    VulnClass.SQLI.value: 3,
    VulnClass.SSRF.value: 3,
    VulnClass.RCE.value: 3,
    VulnClass.LFI.value: 3,
    VulnClass.RFI.value: 3,
    VulnClass.SSTI.value: 3,
    VulnClass.OPEN_REDIRECT.value: 2,
    VulnClass.XXE.value: 3,
    VulnClass.CSRF.value: 2,
    VulnClass.DESERIALIZATION.value: 3,
    VulnClass.PATH_TRAVERSAL.value: 3,
    VulnClass.COMMAND_INJECTION.value: 3,
    VulnClass.INFO_DISCLOSURE.value: 2,
    VulnClass.UNKNOWN.value: 2,
}

# Criticality rank — mirrors Criticality enum order.
_CRITICALITY_RANK: dict[str, int] = {
    Criticality.LOW.value: 0,
    Criticality.MEDIUM.value: 1,
    Criticality.HIGH.value: 2,
    Criticality.CRITICAL.value: 3,
}

# Default criticality by Hypothesis.vuln_class, used when the Mental
# Model doesn't yet have an explicit node for the hypothesis's
# target_url. Keeps the formula deterministic even before the Mental
# Model has been populated.
_DEFAULT_CRITICALITY_BY_VULN_CLASS: dict[str, str] = {
    VulnClass.XSS.value: Criticality.MEDIUM.value,
    VulnClass.SQLI.value: Criticality.HIGH.value,
    VulnClass.SSRF.value: Criticality.HIGH.value,
    VulnClass.RCE.value: Criticality.CRITICAL.value,
    VulnClass.LFI.value: Criticality.HIGH.value,
    VulnClass.RFI.value: Criticality.HIGH.value,
    VulnClass.SSTI.value: Criticality.HIGH.value,
    VulnClass.OPEN_REDIRECT.value: Criticality.LOW.value,
    VulnClass.XXE.value: Criticality.HIGH.value,
    VulnClass.CSRF.value: Criticality.MEDIUM.value,
    VulnClass.DESERIALIZATION.value: Criticality.HIGH.value,
    VulnClass.PATH_TRAVERSAL.value: Criticality.HIGH.value,
    VulnClass.COMMAND_INJECTION.value: Criticality.CRITICAL.value,
    VulnClass.INFO_DISCLOSURE.value: Criticality.MEDIUM.value,
    VulnClass.UNKNOWN.value: Criticality.LOW.value,
}


# ---------------------------------------------------------------------------
# Deterministic formula weights
# ---------------------------------------------------------------------------
# Phase 3 step 1: "a plain Python formula over numeric inputs". These
# weights are the formula's coefficients. They are NOT runtime-tunable
# — changing a weight is a code change, reviewable in the diff.
#
# Formula:
#   score = (
#       W_SEVERITY    * severity_rank          (0-4, normalised to 0-1)
#     + W_CONFIDENCE  * confidence_score       (0-1, from Hypothesis)
#     + W_EVIDENCE    * evidence_quality       (0-1, Phase 6 stub = 0.5)
#     - W_COST        * cost_normalised        (0-1, lower cost = higher rank)
#     + W_NOVELTY     * novelty_bonus          (0-0.2, capped)
#     + W_CRITICALITY * criticality_rank       (0-3, normalised to 0-1)
#   )
#
# All weights are non-negative except W_COST (which subtracts). The
# formula's output is clamped to [0, 1] before sorting — a hypothesis
# with a negative raw score still gets 0, not a negative priority.
W_SEVERITY: float = 0.25
W_CONFIDENCE: float = 0.20
W_EVIDENCE: float = 0.10
W_COST: float = 0.15
W_NOVELTY: float = 0.10
W_CRITICALITY: float = 0.20

# Sum of weights — used to normalise the raw score back to [0, 1].
# If the weights are changed, this MUST be updated to match.
_W_SUM: float = (
    W_SEVERITY + W_CONFIDENCE + W_EVIDENCE + W_COST + W_NOVELTY + W_CRITICALITY
)

# Novelty bonus cap (Phase 3 step 1: "novelty/curiosity bonus (capped)").
_NOVELTY_CAP: float = 0.25


def compute_novelty_bonus(hypothesis: Hypothesis, state: Any | None = None) -> float:
    """Compute a bounded curiosity bonus from structural novelty signals.

    Novelty changes ordering only; it never bypasses evidence, scope, HITL,
    or validator gates. Repeated memory patterns decay the bonus.
    """
    try:
        bonus = max(0.0, min(_NOVELTY_CAP, float(getattr(hypothesis, "novelty_score", 0.0) or 0.0)))
    except (TypeError, ValueError):
        bonus = 0.0
    provenance = getattr(hypothesis, "hint_provenance", []) or []
    if not isinstance(provenance, list):
        provenance = []
    if "memory_pattern" not in provenance:
        bonus += 0.05
    if "policy_assumption" in provenance:
        bonus += 0.05
    if "llm_intent" in provenance:
        bonus += 0.03
    if str(getattr(hypothesis, "vuln_class", "unknown")) == VulnClass.UNKNOWN.value:
        bonus += 0.08
    if state:
        if state.get("pattern_hints") and "memory_pattern" in provenance:
            bonus *= 0.75
        try:
            from webpent.shared.trust_matrix import trust_adjustment
            bonus += max(0.0, trust_adjustment(state.get("trust_matrix"), hypothesis))
        except Exception:
            pass
            # Intentionally suppressed — reviewed 2026-09-03
    return round(max(0.0, min(_NOVELTY_CAP, bonus)), 6)

# Cost normalisation ceiling — hypotheses with estimated_cost >= this
# value are treated as cost=1.0 (maximum cost penalty). Below this,
# cost is linearly normalised.
_COST_CEILING: float = 10.0


# ---------------------------------------------------------------------------
# Phase 6 wiring — real implementations now exist in
# webpent.shared.cognitive_components and webpent.memory.decision_log.
# ---------------------------------------------------------------------------
def _evidence_quality_score(hypothesis: Hypothesis, state: Any) -> float:
    """Phase 6 Evidence Quality Assessment — wired to the real implementation.

    Composes a score from: presence of ``evidence_bundle`` (mini-HAR),
    presence and validity of ``evidence_hash``, whether
    ``canary_token`` was matched, and whether
    ``shared/grounding.py``'s existing
    ``verify_citation``/``baseline_differential_test`` primitives
    passed. No new evidence-capture mechanism is needed — Phase 6 is
    purely "write the scoring function over data that's already
    collected."

    The function reads Finding-level evidence fields via ``state``
    (the hypothesis's evidence_refs point at Findings; we look up the
    first related Finding and score its evidence). A hypothesis with
    no related Finding yet (pure heuristic) gets a neutral 0.5 —
    there's no evidence to score either way.
    """
    try:
        from webpent.shared.cognitive_components import (
            compute_evidence_quality_score,
        )
    except Exception:
        return 0.5

    # Find the first Finding related to this hypothesis via
    # hypothesis.evidence_refs (finding IDs) or via Finding.hypothesis_id
    # (the back-reference added in Phase 4).
    try:
        findings: list[Any] = list(state.get("findings") or [])
    except Exception:
        findings = []

    related_finding = None
    # First, check if any Finding's hypothesis_id matches this hypothesis.
    for f in findings:
        try:
            f_hyp_id = getattr(f, "hypothesis_id", None)
            if f_hyp_id is not None and str(f_hyp_id) == str(hypothesis.id):
                related_finding = f
                break
        except Exception:
            continue

    # Fall back to evidence_refs (finding IDs in the hypothesis's list).
    if related_finding is None and hypothesis.evidence_refs:
        for f in findings:
            try:
                if str(f.id) in hypothesis.evidence_refs:
                    related_finding = f
                    break
            except Exception:
                continue

    if related_finding is None:
        # No related Finding yet — neutral score.
        return 0.5

    # Extract the four boolean signals from the related Finding.
    has_bundle = getattr(related_finding, "evidence_bundle", None) is not None
    evidence_hash = getattr(related_finding, "evidence_hash", None)
    # Validate the hash if both bundle and hash are present.
    hash_valid = False
    if has_bundle and evidence_hash:
        try:
            from webpent.utils.crypto import hash_evidence_bundle
            hash_valid = hash_evidence_bundle(related_finding.evidence_bundle) == evidence_hash
        except Exception:
            hash_valid = False
    canary_matched = bool(getattr(related_finding, "canary_token", None))
    # Grounding primitives (verify_citation / baseline_differential_test)
    # are checked at validation time, not here — we approximate
    # "grounding passed" as "confidence_level is Tool-Confirmed or
    # AI-Assessed" (i.e., the validator's grounding checks already
    # ran and didn't block the finding).
    conf_level = getattr(related_finding, "confidence_level", "Pending")
    # POST-P0 Phase 1: a REFUTED related finding is negative evidence.
    # Refuted findings carry sealed negative-control bundles, so without
    # this branch the bundle/hash signals could push a refuted
    # hypothesis's evidence quality ABOVE the 0.5 no-evidence neutral —
    # i.e. refuted claims outranking untouched heuristics. Honest
    # semantics: refutation demotes to the floor (0.0), deterministically.
    if conf_level == "Refuted":
        return 0.0
    grounding_passed = conf_level in ("Tool-Confirmed", "AI-Assessed")

    return compute_evidence_quality_score(
        has_evidence_bundle=has_bundle,
        evidence_hash_valid=hash_valid,
        canary_matched=canary_matched,
        grounding_passed=grounding_passed,
    )


def _write_decision_log_entry(
    *,
    state: Any,
    hypothesis: Hypothesis,
    score: float,
    action: str,
    rule_fired: str,
    llm_contribution: str = "",
) -> None:
    """Phase 6 Decision Log writer — wired to the real implementation.

    Phase 3 step 5: "Every prioritization decision writes one entry to
    the Decision Log (Phase 6 batch)". Now that Phase 6 has landed,
    this calls :func:`webpent.memory.decision_log.log_decision` with
    a ``prioritization`` decision type. The Decision Log entry is
    persisted to the SQLite ``decision_log`` table AND appended to
    ``state["decision_log"]`` for in-graph consumers.

    Failures here are non-fatal — a Decision Log write error must
    never crash the engagement. Errors are logged at warning level
    and swallowed.
    """
    try:
        from webpent.memory.decision_log import log_decision
        log_decision(
            decision_type="prioritization",
            rule_fired=rule_fired,
            outcome=action,
            llm_contribution=llm_contribution,
            entity_refs=[str(hypothesis.id)],
            metadata={"score": float(score)},
        )
    except Exception as exc:
        logger.warning(
            "Decision Log write failed (non-fatal): hypothesis_id=%s "
            "action=%s rule=%s exc=%s",
            hypothesis.id, action, rule_fired, exc,
        )
    # Also log at debug for the engagement transcript.
    logger.debug(
        "Prioritization decision: hypothesis_id=%s score=%.4f action=%s "
        "rule=%s llm=%r",
        hypothesis.id, score, action, rule_fired, llm_contribution,
    )


# ---------------------------------------------------------------------------
# Public scoring + ranking API
# ---------------------------------------------------------------------------
def score_hypothesis(
    hypothesis: Hypothesis,
    state: Any,
    *,
    novelty_bonus: float | None = None,
) -> float:
    """Compute the deterministic priority score for a single hypothesis.

    Returns a float in [0, 1]. Higher = more worth investigating next.

    Args:
        hypothesis: The :class:`Hypothesis` to score. Must have a
            ``vuln_class`` and ``confidence_score``; the rest of the
            inputs are derived from ``state`` (Mental Model) or
            defaults.
        state: The current :class:`PentestState`. Used to look up the
            Mental Model node for the hypothesis's target_url (for
            criticality) and to pass to the Phase 6 evidence-quality
            stub. Accepting ``state`` here (rather than just the
            Mental Model slice) keeps the signature stable for when
            Phase 6 needs to read Finding-level evidence fields.
        novelty_bonus: Optional pre-computed novelty bonus in [0,
            ``_NOVELTY_CAP``]. When omitted, a bounded deterministic bonus
            is derived from provenance and cross-engagement pattern hints.
            The scoring function remains side-effect free.

    Returns:
        A float in [0, 1]. The formula is:

            raw = W_SEVERITY * sev_rank_norm
                + W_CONFIDENCE * confidence_score
                + W_EVIDENCE * evidence_quality
                - W_COST * cost_norm
                + W_NOVELTY * novelty
                + W_CRITICALITY * crit_rank_norm

            score = clamp(raw / W_SUM, 0.0, 1.0)
    """
    # Severity rank (0-4) -> normalised to [0, 1].
    vc = hypothesis.vuln_class
    vc_str = vc.value if hasattr(vc, "value") else str(vc)
    sev_rank = _VULN_CLASS_TO_SEVERITY_RANK.get(vc_str, 2)
    sev_norm = sev_rank / 4.0

    # Confidence (already in [0, 1]).
    conf = float(hypothesis.confidence_score or 0.0)

    # Evidence quality (Phase 6 stub).
    evidence = _evidence_quality_score(hypothesis, state)

    # Estimated cost -> normalised to [0, 1]. None = unknown -> treat
    # as median cost (0.5) so it neither helps nor hurts.
    if hypothesis.estimated_cost is None:
        cost_norm = 0.5
    else:
        cost_norm = min(1.0, float(hypothesis.estimated_cost) / _COST_CEILING)

    # Novelty (capped). Explicit values remain backward-compatible; omitted
    # values use the deterministic structural novelty calculation.
    if novelty_bonus is None:
        novelty_bonus = compute_novelty_bonus(hypothesis, state)
    try:
        novelty = max(0.0, min(_NOVELTY_CAP, float(novelty_bonus or 0.0)))
    except (TypeError, ValueError):
        novelty = 0.0

    # Criticality rank (0-3) -> normalised to [0, 1]. Look up the
    # Mental Model node for the hypothesis's target_url; fall back to
    # the per-vuln-class default if no node exists yet.
    crit_str = _DEFAULT_CRITICALITY_BY_VULN_CLASS.get(vc_str, Criticality.LOW.value)
    mental_model_state = (
        getattr(state, "get", lambda *_a, **_kw: None)("mental_model") if state else None
    )
    if mental_model_state:
        try:
            model = _coerce_to_mental_model(mental_model_state)
            # Find the endpoint node matching this hypothesis's target_url.
            from webpent.models.mental_model import _normalise_url
            target_norm = _normalise_url(hypothesis.target_url)
            for node in model.nodes.values():
                if node.identity_key == target_norm and node.kind == NodeKind.ENDPOINT.value:
                    crit_str = node.criticality
                    break
        except Exception:
            pass
            # Intentionally suppressed — reviewed 2026-09-03
    crit_rank = _CRITICALITY_RANK.get(crit_str, 0)
    crit_norm = crit_rank / 3.0

    raw = (
        W_SEVERITY * sev_norm
        + W_CONFIDENCE * conf
        + W_EVIDENCE * evidence
        - W_COST * cost_norm
        + W_NOVELTY * novelty
        + W_CRITICALITY * crit_norm
    )
    score = max(0.0, min(1.0, raw / _W_SUM))
    return score


def _coerce_hypothesis(h: Any) -> Hypothesis | None:
    """Re-hydrate a possibly dict-shaped hypothesis into a real Hypothesis.

    V10 EXHAUSTIVE AUDIT (reviewer follow-up, same bug class as P0-1):
    after a LangGraph checkpoint round-trip (e.g. any HITL pause/resume),
    ``state["hypotheses"]`` entries can be plain dicts instead of
    :class:`Hypothesis` instances — exactly the scenario P0-1 hardened
    ``route_after_validator``/``route_after_chainer``/``exploit_chainer_node``/
    ``promote_hypothesis_to_finding`` against. This file's own
    ``promote_hypothesis_to_finding`` was fixed for it, but the upstream
    ranking/scoring/decision pipeline (``score_hypothesis``,
    ``rank_open_hypotheses``, ``recommend_action``) was not — and unlike
    ``Finding``, a dict-shaped ``Hypothesis`` doesn't just risk a wrong
    *value*, it crashes outright: ``rank_open_hypotheses`` calls
    ``h.is_open()`` directly (no ``model_get`` involved, since it's a
    method, not a field), and ``strategist_node`` later calls
    ``hypothesis.model_copy(update=...)`` on whatever this returns — a
    dict has neither. Confirmed by reproduction: a dict-shaped
    ``deterministic_match=True`` hypothesis (the ground-truth
    URL-path-classified case this flag exists for — see the field's
    docstring) raised ``AttributeError: 'dict' object has no attribute
    'is_open'`` from ``rank_open_hypotheses``, uncaught, on the very
    node the P0-1 dict-safety pass was supposed to make crash-proof.

    Returns None (caller should skip/log, never raise) if the dict
    can't validate as a Hypothesis at all — a malformed single record
    must not take down the whole ranking pass.
    """
    if isinstance(h, Hypothesis):
        return h
    if isinstance(h, dict):
        try:
            return Hypothesis.model_validate(h)
        except Exception as exc:
            logger.warning(
                "prioritization: dropping unparseable dict-shaped "
                "hypothesis (id=%s): %s",
                h.get("id", "<unknown>"), exc,
            )
            return None
    # Unknown shape — same fail-safe stance as model_get's default path:
    # don't guess, don't raise, just drop it and let the caller log why.
    logger.warning(
        "prioritization: hypothesis has unexpected type %s, dropping",
        type(h).__name__,
    )
    return None


def rank_open_hypotheses(
    hypotheses: list[Hypothesis],
    state: Any,
    *,
    novelty_lookup: dict[str, float] | None = None,
) -> list[tuple[Hypothesis, float]]:
    """Rank open hypotheses by deterministic priority score, desc.

    Args:
        hypotheses: The full hypothesis pool. Only ``is_open()``
            hypotheses (status ``unexplored`` or ``investigating``)
            are ranked — closed hypotheses (promoted / abandoned /
            resolved) are filtered out.
        state: The current :class:`PentestState`. Passed through to
            :func:`score_hypothesis`.
        novelty_lookup: Optional ``{hypothesis_id_str: novelty_bonus}``
            map. Hypotheses not in the map get novelty_bonus=0.0.
            The caller is responsible for any decay-based novelty
            computation — this function stays pure.

    Returns:
        A list of ``(hypothesis, score)`` tuples, sorted with
        deterministic-match hypotheses first (see
        :attr:`Hypothesis.deterministic_match` — V9 P0 Fix 2-B), then
        by score descending. Ties are broken by ``created_at``
        ascending (earlier hypotheses win) and then by ``id`` for full
        determinism. The list is empty if no open hypotheses exist.

        V9 P0 Fix 2-B: deterministic-match hypotheses are sorted
        ahead of probabilistic ones (even when their raw score is
        lower) so ``strategist_node``'s ``_MAX_PROMOTIONS_PER_PASS``
        cap cannot starve a ground-truth path classification behind a
        pile of merely-probable heuristic guesses. Their score is
        still computed and returned unchanged — this only affects
        ordering, not the score value or the Decision Log entry.
    """
    novelty_lookup = novelty_lookup or {}
    # V10 EXHAUSTIVE AUDIT (reviewer follow-up): coerce dict-shaped
    # hypotheses to real Hypothesis instances BEFORE calling .is_open()
    # — see _coerce_hypothesis docstring. None entries (unparseable)
    # are dropped rather than propagated.
    coerced = [_coerce_hypothesis(h) for h in hypotheses]
    open_hyps = [h for h in coerced if h is not None and h.is_open()]
    scored: list[tuple[Hypothesis, float]] = []
    for h in open_hyps:
        novelty = novelty_lookup.get(str(h.id))
        score = score_hypothesis(h, state, novelty_bonus=novelty)
        scored.append((h, score))
    # Deterministic sort: deterministic_match first, then score desc,
    # then created_at asc, then id asc.
    scored.sort(
        key=lambda t: (
            0 if getattr(t[0], "deterministic_match", False) else 1,
            -t[1],
            (
                t[0].created_at.isoformat()
                if hasattr(t[0].created_at, "isoformat")
                else str(t[0].created_at)
            ),
            str(t[0].id),
        )
    )
    return scored


# ---------------------------------------------------------------------------
# Phase 3 step 4: promote / defer / rabbit-hole decision
# ---------------------------------------------------------------------------
class PrioritizationAction(str, Enum):
    """Closed set of actions Dynamic Prioritization can recommend.

    Phase 3 step 4: "This is the mechanism that decides: promote a
    hypothesis to a Finding now, defer it, or (once Phase 5/7 exist)
    enter a Rabbit Hole branch." The action set is deliberately
    closed — adding a new one is a code change, not an LLM output.

    The actual promotion (turning a Hypothesis into a Finding and
    injecting it into ``state["findings"]``) is a separate function
    (:func:`promote_hypothesis_to_finding`) — Dynamic Prioritization
    only *recommends* an action, it does not execute it. The
    execution path stays the same as today: payload_generator picks
    up findings from ``state["findings"]``, hits the HITL-gated
    execution_sandbox, etc. This is the same "rank and recommend;
    cannot authorize execution" discipline ``exploit_chainer``
    already follows.
    """

    PROMOTE = "promote"        # Promote to Finding now -> enters payload_generator pipeline
    DEFER = "defer"            # Leave in hypothesis pool, revisit next cycle
    RABBIT_HOLE = "rabbit_hole"  # Enter a Rabbit Hole branch (Phase 7 only)
    ABANDON = "abandon"        # Close as abandoned (informed by Phase 5 Self-Critique)


# Promotion threshold — a hypothesis with score >= this is recommended
# for promotion. Calibrated so that a hypothesis with sev_rank=3 (HIGH),
# confidence=0.5, evidence=0.5, cost=0.5, novelty=0, crit=2 (HIGH)
# scores ~0.55 and just clears the threshold. Below this, defer.
_PROMOTION_THRESHOLD: float = 0.5

# Abandon threshold — a hypothesis with score <= this is recommended
# for abandonment. Calibrated low so only clearly-not-worth-it
# hypotheses (low severity + low confidence + low criticality) get
# abandoned. Phase 5 Self-Critique can also recommend ABANDON for a
# branch that's been unproductive — that path bypasses this threshold
# and respects the Risk Manager's caps regardless.
_ABANDON_THRESHOLD: float = 0.15

# Deterministic hypotheses may bypass the weighted score only when a real
# downstream validator exists. INFO_DISCLOSURE is allowed here because the
# structural validator performs a bounded fetch and requires disclosure
# markers; a weak source-code/HTML hint still remains unconfirmed.
# M1-B (E-2, 2026-11-05): IDOR removed. It was listed here while
# ``_deterministic_promotion_allowed`` short-circuits it with an explicit
# ``return False`` two lines into that function — i.e. the entry was dead,
# protected ONLY by statement ordering. A silent reorder (early-return
# moved below the membership check) would have made IDOR
# deterministically promotable from a path match alone, with no
# owner-vs-foreign differential — the exact class of finding the central
# verifier exists to reject. The guard test
# tests/test_m1b_prioritization_guards.py pins this: IDOR can never be
# deterministically promotable, and the exclusion lives in the set itself
# rather than in statement order.
_DETERMINISTIC_STRUCTURAL_CLASSES: frozenset[str] = frozenset({
    VulnClass.CSP.value,
    VulnClass.WEAK_SESSION.value,
    VulnClass.JAVASCRIPT.value,
    VulnClass.AUTH_BYPASS.value,
    VulnClass.API_ISSUE.value,
    VulnClass.CRYPTOGRAPHY.value,
    VulnClass.CAPTCHA.value,
    VulnClass.BRUTE_FORCE.value,
    VulnClass.MASS_ASSIGNMENT.value,
    VulnClass.REQUEST_SMUGGLING.value,
    VulnClass.RACE_CONDITION.value,
    VulnClass.INFO_DISCLOSURE.value,
})


def _deterministic_promotion_allowed(
    vuln_class: str,
    *,
    deterministic_match: bool = False,
) -> bool:
    """Return whether a hypothesis has a safe downstream validator."""
    try:
        from webpent.models.findings import EXPLOITABLE_CLASSES
        # IDOR/BAC requires live owner-vs-foreign observations and the
        # central verifier; a path match alone is never a safe validator.
        if vuln_class == VulnClass.IDOR.value:
            return False
        return vuln_class in EXPLOITABLE_CLASSES or (
            deterministic_match and vuln_class in _DETERMINISTIC_STRUCTURAL_CLASSES
        )
    except ImportError:
        # Security gates fail closed if the authoritative model cannot load.
        return False


def recommend_action(
    hypothesis: Hypothesis,
    state: Any,
    *,
    novelty_bonus: float | None = None,
    rabbit_hole_available: bool = False,
) -> tuple[PrioritizationAction, float, str]:
    """Recommend a deterministic action for a single hypothesis.

    Phase 3 step 4: "This is the mechanism that decides: promote a
    hypothesis to a Finding now, defer it, or (once Phase 5/7 exist)
    enter a Rabbit Hole branch."

    The LLM is NEVER asked to pick the action. The action is a pure
    function of the deterministic score and the two thresholds above.
    An LLM may have contributed a qualitative "value estimate"
    upstream (which would have influenced the ``confidence_score``),
    but the action itself is deterministic arithmetic.

    Args:
        hypothesis: The :class:`Hypothesis` to recommend an action for.
        state: The current :class:`PentestState`.
        novelty_bonus: Optional pre-computed novelty bonus.
        rabbit_hole_available: Whether Rabbit Hole (Phase 7) is
            available. When False, RABBIT_HOLE is never recommended
            (the action falls back to DEFER). Phase 7 sets this to
            True once it's wired up.

    Returns:
        A tuple of ``(action, score, rule_fired)``. ``rule_fired`` is
        a short deterministic-rule description for the Decision Log
        (Phase 6) — e.g. ``"score=0.62 >= PROMOTION_THRESHOLD=0.50"``.

    V9 P0 Fix 2-B: hypotheses with ``deterministic_match=True`` (set
    by hypothesis_analyzer_node's ``_classify_by_url_path`` — a known
    vuln-path signature, e.g. ``/vulnerabilities/sqli/``) may bypass the
    weighted threshold only when a safe downstream validator exists.
    IDOR is deliberately excluded: it requires live owner/foreign BAC
    observations and the central ProofBundle verifier, so path evidence
    remains a deferred hypothesis rather than a reportable finding.
    It exists because the probabilistic formula was calibrated for
    genuinely uncertain heuristic beliefs and can mathematically never
    clear 0.5 for a path-classified hypothesis under the current
    Mental Model criticality defaults (max attainable ~0.44 — see
    Hypothesis.deterministic_match docstring for the full trace) —
    gating a deterministic classification behind a probabilistic
    formula it cannot pass is the bug this closes, not a threshold
    change for probabilistic hypotheses in general. The score is
    still computed and logged for audit-trail transparency; only the
    ABANDON/PROMOTE branch selection changes.
    """
    # V10 EXHAUSTIVE AUDIT (reviewer follow-up): recommend_action is
    # independently exported/called (strategist_node calls it directly
    # per-hypothesis), so it needs its own dict-safety, not just
    # inherited from rank_open_hypotheses's coercion. A dict here would
    # otherwise: (a) always evaluate deterministic_match as False via
    # getattr's silent default, defeating the V9 P0 Fix 2-B bypass this
    # docstring describes, and (b) crash inside score_hypothesis on the
    # first hypothesis.vuln_class access.
    coerced_hypothesis = _coerce_hypothesis(hypothesis)
    if coerced_hypothesis is None:
        return (
            PrioritizationAction.DEFER,
            0.0,
            (
                "hypothesis could not be parsed (unexpected shape) — deferring, "
                "not abandoning, so it is not silently lost"
            ),
        )
    hypothesis = coerced_hypothesis

    score = score_hypothesis(hypothesis, state, novelty_bonus=novelty_bonus)
    is_deterministic = getattr(hypothesis, "deterministic_match", False)

    vuln_class = str(getattr(hypothesis, "vuln_class", ""))
    if vuln_class == VulnClass.IDOR.value:
        action = PrioritizationAction.DEFER
        rule = (
            "IDOR/BAC promotion guard: live owner/foreign observations and "
            "central ProofBundle verifier are required; hypothesis retained "
            f"for access-control coverage, score={score:.4f}"
        )
    elif is_deterministic and _deterministic_promotion_allowed(
        vuln_class, deterministic_match=True
    ):
        action = PrioritizationAction.PROMOTE
        rule = (
            f"deterministic_match=True (path-classified, validator-available) — "
            f"promotion threshold bypassed; score={score:.4f} (informational, "
            f"not gating)"
        )
    elif is_deterministic:
        action = PrioritizationAction.DEFER
        rule = (
            f"deterministic_match=True but vuln_class={vuln_class} has no safe "
            "downstream validator — deferred as observation"
        )
    elif score >= _PROMOTION_THRESHOLD:
        action = PrioritizationAction.PROMOTE
        rule = (
            f"score={score:.4f} >= PROMOTION_THRESHOLD={_PROMOTION_THRESHOLD:.2f}"
        )
    elif score <= _ABANDON_THRESHOLD:
        action = PrioritizationAction.ABANDON
        rule = (
            f"score={score:.4f} <= ABANDON_THRESHOLD={_ABANDON_THRESHOLD:.2f}"
        )
    elif rabbit_hole_available:
        # Mid-score hypotheses are Rabbit Hole candidates IF Phase 7
        # is available. The Rabbit Hole classification gate (Phase 6 /
        # Phase 7) decides whether the hypothesis's target is actually
        # a followable artifact — that's a separate deterministic
        # check, not made here. Here we only say "this is mid-score,
        # worth a Rabbit Hole look if one is available."
        action = PrioritizationAction.RABBIT_HOLE
        rule = (
            f"{_ABANDON_THRESHOLD:.2f} < score={score:.4f} < "
            f"{_PROMOTION_THRESHOLD:.2f}; rabbit_hole_available=True"
        )
    else:
        action = PrioritizationAction.DEFER
        rule = (
            f"{_ABANDON_THRESHOLD:.2f} < score={score:.4f} < "
            f"{_PROMOTION_THRESHOLD:.2f}; rabbit_hole_available=False "
            f"(deferred until score improves or Rabbit Hole lands)"
        )

    # Phase 3 step 5: every prioritization decision writes to the
    # Decision Log (Phase 6 stub for now).
    _write_decision_log_entry(
        state=state,
        hypothesis=hypothesis,
        score=score,
        action=action.value,
        rule_fired=rule,
        llm_contribution="",  # No LLM contributes to the action itself.
    )

    return action, score, rule


def promote_hypothesis_to_finding(
    hypothesis: Hypothesis,
    state: Any,
) -> Finding | None:
    """Promote a Hypothesis to a Finding, ready for the existing pipeline.

    Phase 3 step 3: "a hypothesis becomes an actionable Finding (and
    enters the existing payload_generator pipeline) only when it is
    selected by Dynamic Prioritization."

    This function constructs a :class:`Finding` from the hypothesis,
    carrying over the audit-trail back-reference
    (``Finding.hypothesis_id`` — added in Phase 4) so the chain
    belief -> investigation -> finding is always traceable. The
    Finding enters ``state["findings"]`` with
    ``confidence_level="Pending"`` — exactly the state
    ``payload_generator`` expects for a finding it should generate
    payloads for.

    V8 P0 A4 — DEFENSE-IN-DEPTH EXPLOITABILITY GATE: refuses to
    promote hypotheses whose ``vuln_class`` is not in
    :data:`webpent.models.findings.EXPLOITABLE_CLASSES`. The
    payload_generator already enforces this gate downstream, but
    adding it here at the promotion layer closes the audit loop
    end-to-end — a future change that weakens or removes the
    payload_generator gate cannot open a bypass because non-exploitable
    hypotheses (notably Rabbit Hole's UNKNOWN hypotheses) never become
    Findings in the first place. The rejection is logged as a
    Decision Log entry with ``decision_type="risk_gate_blocked"``,
    outcome ``"blocked_non_exploitable"``, so the audit trail records
    why a high-scoring hypothesis was not promoted.

    The hypothesis's ``status`` transitions to ``promoted`` (one-way
    per the state machine in :class:`HypothesisStatus`'s docstring)
    ONLY when the gate passes. When the gate blocks the promotion,
    the hypothesis is left in its current open state (UNEXPLORED or
    INVESTIGATING) so the strategist can re-evaluate it on a future
    pass — the rejection is not a permanent verdict. The caller is
    responsible for persisting any status transition.

    Args:
        hypothesis: The :class:`Hypothesis` to promote. Should have
            been recommended PROMOTE by :func:`recommend_action`.
        state: The current :class:`PentestState`. Used to derive the
            Finding's ``severity`` from the hypothesis's
            ``vuln_class`` (via the same severity-rank map the
            scoring function uses).

    Returns:
        A new :class:`Finding` instance, or ``None`` if the import
        failed OR the exploitability gate blocked the promotion
        (defensive — never raises). The caller appends the Finding
        to ``state["findings"]`` only when non-None.

    V10 EXHAUSTIVE AUDIT (P0-1): the entire function body is now wrapped
    in a try/except Exception that returns None on ANY error — making
    the "never raises" docstring claim TRUE. All attribute access uses
    :func:`model_get` so dict-shaped hypotheses (after checkpoint
    round-trip) don't crash with AttributeError.
    """
    try:
        from webpent.models.findings import Confidence, Finding, Severity
    except ImportError:
        logger.error("promote_hypothesis_to_finding: Finding model import failed")
        return None

    # V10 EXHAUSTIVE AUDIT (P0-1): wrap the entire promotion logic so
    # the "never raises" docstring is actually true. Previously, any
    # AttributeError on a dict-shaped hypothesis would propagate.
    try:
        from webpent.state.reducers import model_get

        # Derive severity from the vuln_class severity rank.
        vc = model_get(hypothesis, "vuln_class")
        vc_str = vc.value if hasattr(vc, "value") else str(vc)
        sev_rank = _VULN_CLASS_TO_SEVERITY_RANK.get(vc_str, 2)
        severity_map = {
            0: Severity.INFO.value,
            1: Severity.LOW.value,
            2: Severity.MEDIUM.value,
            3: Severity.HIGH.value,
            4: Severity.CRITICAL.value,
        }
        severity = severity_map[sev_rank]

        # V8 P0 A4: defense-in-depth exploitability gate.
        # V10 EXHAUSTIVE AUDIT (P3-8): fail CLOSED on import error,
        # not open. A security gate must never be disabled silently.
        #
        # V10 P2 (RCA follow-up): probabilistic non-exploitable
        # hypotheses remain blocked. A deterministic path match may pass
        # only when a payload validator or explicit structural validator
        # exists. This prevents read-only source-code artifacts from being
        # promoted merely because their URL matched a path token.
        is_deterministic = bool(model_get(hypothesis, "deterministic_match", False))
        try:
            if not _deterministic_promotion_allowed(vc_str, deterministic_match=is_deterministic):
                logger.info(
                    "promote_hypothesis_to_finding: blocked non-exploitable "
                    "hypothesis %s (vuln_class=%s not in EXPLOITABLE_CLASSES). "
                    "Leaving hypothesis in open state; logging to Decision Log.",
                    model_get(hypothesis, "id"), vc_str,
                )
                _write_decision_log_entry(
                    state=state,
                    hypothesis=hypothesis,
                    score=float(model_get(hypothesis, "confidence_score", 0.0)),
                    action="risk_gate_blocked",
                    rule_fired=(
                        f"defense_in_depth: vuln_class={vc_str} not in "
                        f"EXPLOITABLE_CLASSES — promotion refused"
                    ),
                    llm_contribution="",
                )
                return None
            # If is_deterministic is True, fall through to promotion
            # for non-EXPLOITABLE_CLASSES classes with a safe structural
            # validator. IDOR is intentionally excluded because its
            # validator is the strict BAC access-control path, not this
            # evidence-free hypothesis promotion path.
            # The structural validator will run and produce either a
            # Tool-Confirmed finding or an explicit Not Scanned signal.
        except ImportError:
            # V10 EXHAUSTIVE AUDIT (P3-8): fail CLOSED — refuse to
            # promote when the security gate cannot be enforced.
            logger.warning(
                "promote_hypothesis_to_finding: EXPLOITABLE_CLASSES import "
                "failed — FAILING CLOSED (promotion refused) to avoid "
                "promoting non-exploitable hypotheses without the gate."
            )
            return None

        h_id = model_get(hypothesis, "id")
        h_origin = model_get(hypothesis, "origin", "")
        h_score = float(model_get(hypothesis, "confidence_score", 0.0))
        h_statement = model_get(hypothesis, "statement", "")
        h_origin_detail = model_get(hypothesis, "origin_detail", "")
        h_target_url = model_get(hypothesis, "target_url", "")
        h_request_method = model_get(hypothesis, "request_method", "GET") or "GET"
        h_request_data = model_get(hypothesis, "request_data", {}) or {}
        h_target_param = model_get(hypothesis, "target_param", None)
        h_evidence_contract = model_get(hypothesis, "evidence_contract", None)
        h_hint_provenance = list(model_get(hypothesis, "hint_provenance", []) or [])[:8]
        h_novelty_score = float(model_get(hypothesis, "novelty_score", 0.0) or 0.0)

        reasoning = (
            f"Promoted from hypothesis {h_id} "
            f"(origin={h_origin}, "
            f"confidence_score={h_score:.3f}). "
            f"Original statement: {h_statement}"
        )

        finding = Finding(
            title=h_statement[:120],
            severity=severity,
            description=(
                f"Promoted from hypothesis {h_id}.\n\n"
                f"Statement: {h_statement}\n\n"
                f"Origin detail: {h_origin_detail or '(none)'}"
            ),
            tool_name="dynamic_prioritization",
            url=_normalize_finding_url(h_target_url, vc_str),
            confidence=Confidence.TENTATIVE.value,
            confidence_level="Pending",
            vuln_class=vc_str,
            strategic_confidence_score=h_score,
            hypothesis_id=h_id,
            evidence_contract=h_evidence_contract,
            hint_provenance=h_hint_provenance,
            reasoning=(
                f"{reasoning} novelty_score={h_novelty_score:.3f}."
            ),
            request_method=h_request_method,
            request_data=h_request_data,
            target_param=h_target_param,
        )

        _write_decision_log_entry(
            state=state,
            hypothesis=hypothesis,
            score=h_score,
            action="hypothesis_promoted",
            rule_fired=f"promoted to finding {finding.id}",
            llm_contribution="",
        )

        return finding
    except Exception as exc:
        logger.error(
            "promote_hypothesis_to_finding: unexpected error (defensive "
            "catch — returning None to honor 'never raises' contract): %s",
            exc,
        )
        return None

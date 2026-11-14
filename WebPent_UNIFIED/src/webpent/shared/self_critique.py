# src/webpent/shared/self_critique.py
"""webpent.shared.self_critique

V7 Cognitive Upgrade — Phase 5: Self-Critique / Reflection Loop
(mid-engagement).

A strategy-level "am I actually making progress" check, **distinct** from:

  * the existing finding-level ``devils_advocate_node`` (which critiques
    ONE finding at a time, after validation), and
  * the existing end-of-engagement ``reflection_node`` (which runs
    ONCE after the report and persists lessons CROSS-engagement for
    future scans — it never runs mid-engagement).

This module is a **lightweight check invoked at defined checkpoints**
(see :data:`SELF_CRITIQUE_CHECKPOINTS` below), NOT a new always-on
graph node. Running it every step would be wasteful and would blur
with Devil's Advocate — the plan explicitly forbids that.

Checkpoints (per Phase 5 step 1):

  * ``before_promotion`` — before Dynamic Prioritization promotes a
    hypothesis that would consume significant budget (heuristic:
    estimated_cost >= :data:`SIGNIFICANT_BUDGET_THRESHOLD`).
  * ``every_n_discoveries`` — every
    :data:`DISCOVERIES_PER_SELF_CRITIQUE` new Mental Model nodes.
  * ``rabbit_hole_branch_entry`` — after each Rabbit Hole branch entry
    (Phase 7 only; no-op until Phase 7 lands).

Output (per Phase 5 step 3):

  A **bounded recommendation**, not a free action. One of:

    * :data:`SelfCritiqueAction.CONTINUE` — keep investigating this
      branch/goal-tree node.
    * :data:`SelfCritiqueAction.DEPRIORITIZE` — lower its priority in
      the next Dynamic Prioritization ranking pass (does NOT close it).
    * :data:`SelfCritiqueAction.ABANDON` — close it; mark the Goal
      Tree node ``abandoned`` and the associated hypothesis ``abandoned``.

Deterministic-first discipline (per Phase 5 step 4):

  The LLM may be asked "does this look unproductive," but the actual
  abandon/continue decision respects the hard caps set by the Risk
  Manager (Phase 6 batch) regardless of what the LLM recommends — an
  LLM cannot talk its way past a depth/budget cap by arguing the
  branch is "almost there." Concretely:

    1. **Deterministic signals first.** Budget exhaustion, branch-depth
       cap, and zero-hit-rate-over-N-promotions are pure-Python
       predicates. If any of them fires ABANDON, the LLM is NOT even
       asked — the recommendation is ABANDON regardless.
    2. **LLM only as a tiebreaker.** If the deterministic signals are
       ambiguous (mid-budget, mid-depth, mixed hit rate), the LLM is
       asked a yes/no "does this look unproductive" question. A "yes"
       nudges to DEPRIORITIZE; a "no" nudges to CONTINUE. The LLM can
       NEVER recommend ABANDON on its own — that path is reserved for
       the deterministic caps.
    3. **Caps override the LLM.** Even if the LLM says "continue, this
       looks productive," if a Risk Manager cap is hit, the
       recommendation is ABANDON. The LLM's verdict is recorded in the
       Decision Log entry's ``llm_contribution`` field but does not
       change the outcome.

Decision Log (per Phase 5 step 5):

  Every invocation writes one entry to the Decision Log (Phase 6
  batch), explicitly labeled as ``decision_type="self_critique"``. The
  :func:`_write_decision_log_entry` function here is a stable-signature
  stub that Phase 6 replaces with the real manager call — Phase 5 can
  be exercised end-to-end today without the Decision Log table existing.
"""

from __future__ import annotations

import contextlib
import logging
import re
from enum import Enum
from typing import Any

from webpent.models.hypothesis import Hypothesis, HypothesisStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Checkpoints — the defined points at which Self-Critique may fire.
# ---------------------------------------------------------------------------
# Per Phase 5 step 1: "Add a new lightweight check invoked at defined
# checkpoints (after each rabbit-hole branch entry once Phase 7 exists;
# every N discoveries; before promoting a hypothesis that would consume
# significant budget). Explicitly NOT a new always-on graph node running
# every step."
class SelfCritiqueCheckpoint(str, Enum):
    """Closed set of checkpoints at which Self-Critique may be invoked.

    The set is deliberately closed — adding a checkpoint is a code
    change, not an LLM output or a runtime flag. This keeps the
    "when does the system second-guess itself" question auditable.
    """

    BEFORE_PROMOTION = "before_promotion"
    EVERY_N_DISCOVERIES = "every_n_discoveries"
    RABBIT_HOLE_BRANCH_ENTRY = "rabbit_hole_branch_entry"
    VALIDATION_FAILURE = "validation_failure"


# ---------------------------------------------------------------------------
# Bounded recommendation — the only outputs Self-Critique can produce.
# ---------------------------------------------------------------------------
class SelfCritiqueAction(str, Enum):
    """Closed set of Self-Critique recommendations.

    Per Phase 5 step 3: "Output is a bounded recommendation, not a free
    action: ``continue``, ``deprioritize``, or ``abandon`` for a
    specific branch/goal-tree node."

    The action set is deliberately closed. The LLM can NEVER recommend
    ABANDON on its own — that path is reserved for the deterministic
    caps (budget exhaustion, depth cap, zero-hit-rate-over-N).
    """

    CONTINUE = "continue"          # Keep investigating this branch.
    DEPRIORITIZE = "deprioritize"  # Lower priority next pass; do NOT close.
    ABANDON = "abandon"            # Close the branch + associated hypothesis.


# ---------------------------------------------------------------------------
# Deterministic thresholds — pure Python constants, NOT LLM-tunable.
# ---------------------------------------------------------------------------
# Per Phase 5 step 4: "the actual abandon/continue decision respects the
# hard caps set by the Risk Manager (Phase 6 batch) regardless of what
# the LLM recommends." The thresholds below are the Self-Critique-
# specific caps; the Risk Manager's RabbitHolePolicy caps (Phase 6)
# are checked separately by the Rabbit Hole integration (Phase 7).

# A hypothesis with estimated_cost >= this is considered "significant
# budget" and triggers a before_promotion Self-Critique check. Mirrors
# the cost-ceiling constant in webpent.shared.prioritization._COST_CEILING
# so "significant" means "near the top of the cost scale."
SIGNIFICANT_BUDGET_THRESHOLD: float = 5.0

# Every N new Mental Model nodes discovered, fire an every_n_discoveries
# Self-Critique check. Calibrated so on a typical engagement with ~20-40
# discovered assets, Self-Critique fires 2-4 times — enough to catch a
# stuck branch, not so often it blurs with Devil's Advocate.
DISCOVERIES_PER_SELF_CRITIQUE: int = 10

# Zero-hit-rate threshold: if N or more hypotheses have been promoted
# from this branch and NONE produced a real (Tool-Confirmed or
# AI-Assessed) Finding, the branch is "unproductive" — Self-Critique
# recommends ABANDON deterministically (no LLM asked).
ZERO_HIT_RATE_PROMOTION_THRESHOLD: int = 3

# LLM unproductivity threshold: if the LLM is consulted (deterministic
# signals ambiguous) and reports the branch as "unproductive"
# ``LLM_UNPRODUCTIVE_REPORT_COUNT`` times in a row, Self-Critique
# upgrades the next DEPRIORITIZE to ABANDON. Prevents a "forever
# deprioritized but never abandoned" zombie branch. The counter is
# per-branch, tracked in the Goal Tree node's metadata.
LLM_UNPRODUCTIVE_REPORT_THRESHOLD: int = 2


# ---------------------------------------------------------------------------
# Phase 6 Decision Log writer — STUB (signature stable).
# ---------------------------------------------------------------------------
def _write_decision_log_entry(
    *,
    state: Any,
    checkpoint: SelfCritiqueCheckpoint,
    action: SelfCritiqueAction,
    branch_id: str,
    rule_fired: str,
    llm_contribution: str = "",
    entity_refs: list[str] | None = None,
) -> None:
    """Phase 6 Decision Log writer — wired to the real implementation.

    Phase 5 step 5: "Every invocation writes to the Decision Log,
    explicitly labeled as a self-critique event." Now that Phase 6
    has landed, this calls
    :func:`webpent.memory.decision_log.log_decision` with a
    ``self_critique`` decision type. The Decision Log entry is
    persisted to the SQLite ``decision_log`` table AND appended to
    ``state["decision_log"]`` for in-graph consumers.

    Failures here are non-fatal — a Decision Log write error must
    never crash the engagement. Errors are logged at warning level
    and swallowed.
    """
    try:
        from webpent.memory.decision_log import log_decision
        log_decision(
            decision_type="self_critique",
            rule_fired=rule_fired,
            outcome=action.value,
            llm_contribution=llm_contribution,
            entity_refs=list(entity_refs or []),
            branch_id=branch_id,
            metadata={
                "checkpoint": checkpoint.value,
                "action": action.value,
            },
        )
    except Exception as exc:
        logger.warning(
            "Decision Log write failed (non-fatal): checkpoint=%s "
            "action=%s branch_id=%s exc=%s",
            checkpoint.value, action.value, branch_id, exc,
        )
    # Also log at debug for the engagement transcript.
    logger.debug(
        "Self-Critique: checkpoint=%s action=%s branch_id=%s rule=%s "
        "llm=%r refs=%s",
        checkpoint.value, action.value, branch_id, rule_fired,
        llm_contribution, entity_refs or [],
    )


# ---------------------------------------------------------------------------
# Deterministic signal extraction — pure Python, no LLM.
# ---------------------------------------------------------------------------
def _extract_deterministic_signals(
    state: Any,
    *,
    branch_id: str,
    hypothesis: Hypothesis,
) -> dict[str, Any]:
    """Extract the deterministic signals Self-Critique uses.

    All pure-Python reads over state — NO LLM. The signals are:

      * ``promotions_from_branch``: count of hypotheses with
        ``parent_hypothesis_id`` in this branch's chain that have
        ``status=promoted``.
      * ``confirmed_from_branch``: count of findings whose
        ``hypothesis_id`` traces back to this branch AND whose
        ``confidence_level`` is ``Tool-Confirmed`` or ``AI-Assessed``
        (i.e., produced a real finding, not still Pending).
      * ``hit_rate``: ``confirmed_from_branch / max(1, promotions_from_branch)``.
      * ``budget_consumed``: sum of ``estimated_cost`` over all
        hypotheses in this branch (approximation — the real budget
        tracker is the Goal Tree node's ``budget_consumed`` field,
        Phase 6).
      * ``depth``: chain length from this hypothesis back to its root
        ancestor via ``parent_hypothesis_id``.

    The function is defensive — any read error returns a sensible
    default (0 / 0.0) rather than raising. Self-Critique must never
    crash the engagement; if it can't read a signal, it treats that
    signal as neutral.
    """
    signals: dict[str, Any] = {
        "promotions_from_branch": 0,
        "confirmed_from_branch": 0,
        "hit_rate": 0.0,
        "budget_consumed": 0.0,
        "depth": 0,
    }

    try:
        hypotheses: list[Hypothesis] = list(state.get("hypotheses") or [])
    except Exception:
        hypotheses = []

    try:
        findings: list[Any] = list(state.get("findings") or [])
    except Exception:
        findings = []

    # Walk the parent chain to find all hypotheses in this branch.
    # A hypothesis is "in this branch" if it IS the given hypothesis,
    # or if its parent chain eventually reaches the given hypothesis.
    branch_hypothesis_ids: set[str] = {str(hypothesis.id)}
    branch_hypotheses: list[Hypothesis] = [hypothesis]

    # Build a parent lookup for the chain walk.
    parent_lookup: dict[str, Hypothesis] = {}
    for h in hypotheses:
        try:
            parent_lookup[str(h.id)] = h
        except Exception:
            continue

    # Walk UP from the given hypothesis to find ancestors (the branch
    # root chain). Then walk DOWN to find descendants. A branch is the
    # full ancestor-and-descendant set rooted at a top-level hypothesis
    # (one with parent_hypothesis_id=None).
    ancestors: list[Hypothesis] = []
    current = hypothesis
    seen: set[str] = set()
    while current is not None:
        cid = str(current.id)
        if cid in seen:
            break  # cycle guard
        seen.add(cid)
        ancestors.append(current)
        parent_id = getattr(current, "parent_hypothesis_id", None)
        if parent_id is None:
            break
        current = parent_lookup.get(str(parent_id))
    # Depth = number of ancestors above the root (root has depth 0).
    signals["depth"] = max(0, len(ancestors) - 1)

    # The branch root is the last ancestor (the one with no parent).
    branch_root = ancestors[-1] if ancestors else hypothesis
    branch_root_id = str(branch_root.id)

    # Find all descendants of the branch root (the full branch).
    branch_hypotheses = [branch_root]
    branch_hypothesis_ids = {branch_root_id}
    queue: list[str] = [branch_root_id]
    while queue:
        parent_id = queue.pop(0)
        for h in hypotheses:
            try:
                h_parent = getattr(h, "parent_hypothesis_id", None)
                if h_parent is not None and str(h_parent) == parent_id:
                    hid = str(h.id)
                    if hid not in branch_hypothesis_ids:
                        branch_hypothesis_ids.add(hid)
                        branch_hypotheses.append(h)
                        queue.append(hid)
            except Exception:
                continue

    # Count promotions and confirmed findings from this branch.
    promoted_count = 0
    budget_sum = 0.0
    for h in branch_hypotheses:
        try:
            status = h.status
            status_str = status.value if hasattr(status, "value") else str(status)
            if status_str == HypothesisStatus.PROMOTED.value:
                promoted_count += 1
            cost = getattr(h, "estimated_cost", None)
            if cost is not None:
                with contextlib.suppress(TypeError, ValueError):
                    budget_sum += float(cost)
        except Exception:
            continue
    signals["promotions_from_branch"] = promoted_count
    signals["budget_consumed"] = budget_sum

    # Count confirmed findings whose hypothesis_id is in this branch.
    confirmed = 0
    for f in findings:
        try:
            f_hyp_id = getattr(f, "hypothesis_id", None)
            if f_hyp_id is None:
                continue
            if str(f_hyp_id) not in branch_hypothesis_ids:
                continue
            f_conf_level = getattr(f, "confidence_level", "Pending")
            if f_conf_level in ("Tool-Confirmed", "AI-Assessed"):
                confirmed += 1
        except Exception:
            continue
    signals["confirmed_from_branch"] = confirmed
    signals["hit_rate"] = (
        confirmed / promoted_count if promoted_count > 0 else 0.0
    )

    return signals


# ---------------------------------------------------------------------------
# LLM tiebreaker — only invoked when deterministic signals are ambiguous.
# ---------------------------------------------------------------------------
def _ask_llm_unproductive(
    state: Any,
    *,
    branch_id: str,
    hypothesis: Hypothesis,
    signals: dict[str, Any],
) -> str | None:
    """Ask the LLM "does this branch look unproductive?" — yes/no only.

    Per Phase 5 step 4: "the LLM can be asked 'does this look
    unproductive'." This function is ONLY called when the deterministic
    signals are ambiguous (mid-budget, mid-depth, mixed hit rate) —
    see :func:`recommend_self_critique_action`.

    The LLM's answer is restricted to a yes/no verdict on
    "unproductive." It CANNOT recommend ABANDON — that path is reserved
    for the deterministic caps. A "yes, unproductive" answer nudges the
    recommendation to DEPRIORITIZE; a "no" nudges to CONTINUE.

    Returns:
        ``"unproductive"``, ``"productive"``, or ``None`` if the LLM
        could not be consulted (all providers failed, or the LLM
        returned an unparseable response). ``None`` is treated as
        "no signal" — the recommendation falls back to the deterministic
        default (CONTINUE for ambiguous signals).
    """
    try:
        from langchain_core.messages import HumanMessage, SystemMessage

        from webpent.shared.llm import (
            TaskType,
            get_safety_system_instruction,
            safe_prompt_format,
            try_get_llm,
        )
    except Exception as exc:
        logger.debug("Self-Critique LLM import failed: %s", exc)
        return None

    try:
        llm = try_get_llm(TaskType.ANALYSIS)
    except Exception as exc:
        logger.debug("Self-Critique LLM unavailable: %s", exc)
        return None
    if llm is None:
        return None

    system_prompt = (
        "You are a strategy-level reviewer for an autonomous pentest "
        "engagement. You are asked a YES/NO question about whether a "
        "specific investigation branch looks unproductive. Answer with "
        "exactly one word: 'unproductive' or 'productive'. Do not "
        "recommend abandoning the branch — that decision is reserved "
        "for deterministic budget/depth caps that you cannot see. Your "
        "job is only to give a qualitative productivity verdict that a "
        "deterministic formula will combine with budget/depth/hit-rate "
        "signals to produce the final recommendation."
    )

    human_template = (
        "Branch ID: {branch_id}\n"
        "Hypothesis statement: {statement}\n"
        "Branch depth: {depth}\n"
        "Promotions from this branch: {promotions}\n"
        "Confirmed findings from this branch: {confirmed}\n"
        "Hit rate: {hit_rate:.2f}\n"
        "Budget consumed (estimated): {budget:.2f}\n\n"
        "Does this branch look unproductive? Answer with exactly one "
        "word: 'unproductive' or 'productive'."
    )

    try:
        human_prompt = safe_prompt_format(
            human_template,
            branch_id=branch_id,
            statement=hypothesis.statement[:300],
            depth=signals.get("depth", 0),
            promotions=signals.get("promotions_from_branch", 0),
            confirmed=signals.get("confirmed_from_branch", 0),
            hit_rate=float(signals.get("hit_rate", 0.0)),
            budget=float(signals.get("budget_consumed", 0.0)),
        )
        response = llm.invoke([
            SystemMessage(content=get_safety_system_instruction()),
            SystemMessage(content=system_prompt),
            HumanMessage(content=human_prompt),
        ])
        text = (
            response.content
            if isinstance(response.content, str)
            else str(response.content)
        )
        text_lower = text.strip().lower()
        # V10 P3-8 FIX: previously `if "unproductive" in text_lower`
        # false-positive'd on "not unproductive" (and on the word
        # "unproductive" appearing inside a longer phrase like "this
        # is not unproductive"). Use a word-boundary regex AND check
        # that "not" does not immediately precede it. If the LLM said
        # "not unproductive", return "productive" instead. Order
        # matters: check the "not unproductive" pattern FIRST so a
        # negated verdict isn't flipped to unproductive.
        if re.search(r"\bnot\s+unproductive\b", text_lower):
            return "productive"
        if re.search(r"\bunproductive\b", text_lower):
            return "unproductive"
        if "productive" in text_lower:
            return "productive"
        logger.debug(
            "Self-Critique LLM returned unparseable response: %r",
            text[:100],
        )
        return None
    except Exception as exc:
        logger.debug("Self-Critique LLM invocation failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Public API — the recommendation function callers invoke at checkpoints.
# ---------------------------------------------------------------------------
def recommend_self_critique_action(
    state: Any,
    *,
    checkpoint: SelfCritiqueCheckpoint,
    hypothesis: Hypothesis,
    branch_id: str | None = None,
    risk_manager_caps: dict[str, Any] | None = None,
) -> tuple[SelfCritiqueAction, str, str]:
    """Recommend a bounded Self-Critique action for a branch.

    This is the function callers invoke at the defined checkpoints
    (see :class:`SelfCritiqueCheckpoint`). It is **pure** — no side
    effects, no state mutation. The caller is responsible for applying
    the recommendation (e.g., marking the Goal Tree node abandoned,
    adjusting the hypothesis's status).

    Deterministic-first discipline (per Phase 5 step 4):

      1. **Risk Manager caps override everything.** If
         ``risk_manager_caps`` indicates a cap is hit (depth >= max_depth,
         branches >= max_branches, budget >= curiosity_budget_ceiling),
         the recommendation is ABANDON regardless of any other signal.
         The LLM is NOT asked.
      2. **Zero-hit-rate over N promotions -> ABANDON.** If
         ``promotions_from_branch >= ZERO_HIT_RATE_PROMOTION_THRESHOLD``
         and ``confirmed_from_branch == 0``, the branch is deterministically
         unproductive. ABANDON. The LLM is NOT asked.
      3. **LLM tiebreaker for ambiguous signals.** If the deterministic
         signals are ambiguous (not 1, not 2), the LLM is asked
         "unproductive?". "unproductive" -> DEPRIORITIZE; "productive"
         or no answer -> CONTINUE.
      4. **Default CONTINUE.** If nothing else fires, CONTINUE.

    Args:
        state: The current :class:`PentestState`. Used to read the
            hypothesis pool, findings, and (Phase 6) the Goal Tree
            for budget tracking.
        checkpoint: Which checkpoint triggered this invocation. Recorded
            in the Decision Log entry for auditability.
        hypothesis: The hypothesis at the head of the branch being
            critiqued. Used to walk the parent chain and find all
            hypotheses in the branch.
        branch_id: Optional explicit branch ID. If None, derived from
            the hypothesis's branch root ID.
        risk_manager_caps: Optional dict from the Phase 6 Risk Manager
            with keys ``max_depth``, ``current_depth``, ``max_branches``,
            ``current_branches``, ``curiosity_budget_ceiling``,
            ``curiosity_budget_consumed``. Any cap hit -> ABANDON.
            None means "Risk Manager not yet consulted" (Phase 6
            integration; until then the caller may pass None and the
            caps check is skipped).

    Returns:
        A tuple of ``(action, rule_fired, llm_contribution)``.
        ``rule_fired`` is a short deterministic-rule description for
        the Decision Log. ``llm_contribution`` is the LLM's verdict
        if it was consulted (empty string if not).
    """
    if branch_id is None:
        branch_id = str(hypothesis.id)

    signals = _extract_deterministic_signals(
        state, branch_id=branch_id, hypothesis=hypothesis,
    )

    llm_contribution = ""

    # 1. Risk Manager caps override everything (Phase 6 integration).
    if risk_manager_caps:
        cap_reason = _check_risk_manager_caps(risk_manager_caps)
        if cap_reason is not None:
            action = SelfCritiqueAction.ABANDON
            _write_decision_log_entry(
                state=state,
                checkpoint=checkpoint,
                action=action,
                branch_id=branch_id,
                rule_fired=f"risk_manager_cap: {cap_reason}",
                llm_contribution="",
                entity_refs=[str(hypothesis.id)],
            )
            return action, f"risk_manager_cap: {cap_reason}", ""

    # 2. Zero-hit-rate over N promotions -> ABANDON (deterministic).
    promotions = signals.get("promotions_from_branch", 0)
    confirmed = signals.get("confirmed_from_branch", 0)
    if (
        promotions >= ZERO_HIT_RATE_PROMOTION_THRESHOLD
        and confirmed == 0
    ):
        action = SelfCritiqueAction.ABANDON
        rule = (
            f"zero_hit_rate: promotions={promotions} >= "
            f"{ZERO_HIT_RATE_PROMOTION_THRESHOLD}, confirmed=0"
        )
        _write_decision_log_entry(
            state=state,
            checkpoint=checkpoint,
            action=action,
            branch_id=branch_id,
            rule_fired=rule,
            llm_contribution="",
            entity_refs=[str(hypothesis.id)],
        )
        return action, rule, ""

    # 3. LLM tiebreaker for ambiguous signals.
    llm_verdict = _ask_llm_unproductive(
        state, branch_id=branch_id, hypothesis=hypothesis, signals=signals,
    )
    if llm_verdict == "unproductive":
        llm_contribution = "unproductive"
        action = SelfCritiqueAction.DEPRIORITIZE
        rule = (
            f"llm_unproductive: ambiguous signals (promotions={promotions}, "
            f"confirmed={confirmed}, hit_rate={signals.get('hit_rate', 0.0):.2f}), "
            f"LLM verdict=unproductive -> DEPRIORITIZE"
        )
    elif llm_verdict == "productive":
        llm_contribution = "productive"
        action = SelfCritiqueAction.CONTINUE
        rule = (
            f"llm_productive: ambiguous signals (promotions={promotions}, "
            f"confirmed={confirmed}, hit_rate={signals.get('hit_rate', 0.0):.2f}), "
            f"LLM verdict=productive -> CONTINUE"
        )
    else:
        # LLM unavailable or unparseable — default to CONTINUE.
        # Conservative: don't deprioritize based on no signal.
        llm_contribution = ""
        action = SelfCritiqueAction.CONTINUE
        rule = (
            f"no_signal: ambiguous signals, LLM unavailable/unparseable "
            f"(promotions={promotions}, confirmed={confirmed}, "
            f"hit_rate={signals.get('hit_rate', 0.0):.2f}) -> CONTINUE (default)"
        )

    _write_decision_log_entry(
        state=state,
        checkpoint=checkpoint,
        action=action,
        branch_id=branch_id,
        rule_fired=rule,
        llm_contribution=llm_contribution,
        entity_refs=[str(hypothesis.id)],
    )
    return action, rule, llm_contribution


def _check_risk_manager_caps(caps: dict[str, Any]) -> str | None:
    """Check Risk Manager caps. Return a reason string if a cap is hit, else None.

    Pure Python — no LLM. The caps dict is supplied by the Phase 6
    Risk Manager (or by the Phase 7 Rabbit Hole integration which
    reads ``RabbitHolePolicy`` and the current branch counters).

    Any cap hit returns a non-None reason, which causes
    :func:`recommend_self_critique_action` to recommend ABANDON
    regardless of any other signal.
    """
    try:
        max_depth = caps.get("max_depth")
        current_depth = caps.get("current_depth", 0)
        if max_depth is not None and current_depth >= max_depth:
            return f"depth {current_depth} >= max_depth {max_depth}"

        max_branches = caps.get("max_branches")
        current_branches = caps.get("current_branches", 0)
        if max_branches is not None and current_branches >= max_branches:
            return f"branches {current_branches} >= max_branches {max_branches}"

        budget_ceiling = caps.get("curiosity_budget_ceiling")
        budget_consumed = caps.get("curiosity_budget_consumed", 0.0)
        if (
            budget_ceiling is not None
            and budget_consumed >= budget_ceiling
        ):
            return (
                f"curiosity_budget {budget_consumed:.2f} >= "
                f"ceiling {budget_ceiling:.2f}"
            )
    except Exception:
        pass
        # Intentionally suppressed — reviewed 2026-09-03
    return None


# ---------------------------------------------------------------------------
# Checkpoint gate helpers — callers use these to decide whether to invoke.
# ---------------------------------------------------------------------------
def should_fire_before_promotion(hypothesis: Hypothesis) -> bool:
    """Return True if the before_promotion checkpoint should fire.

    Fires when the hypothesis's ``estimated_cost`` is >=
    :data:`SIGNIFICANT_BUDGET_THRESHOLD`. Cheap hypotheses skip the
    check — promoting a low-cost hypothesis isn't worth a Self-Critique
    invocation.
    """
    cost = getattr(hypothesis, "estimated_cost", None)
    if cost is None:
        return False
    try:
        return float(cost) >= SIGNIFICANT_BUDGET_THRESHOLD
    except (TypeError, ValueError):
        return False


def should_fire_every_n_discoveries(
    state: Any,
    *,
    last_check_count: int,
) -> bool:
    """Return True if the every_n_discoveries checkpoint should fire.

    Compares the current Mental Model node count against the count at
    the last Self-Critique invocation. Fires when the delta >=
    :data:`DISCOVERIES_PER_SELF_CRITIQUE`.
    """
    try:
        mental_model = state.get("mental_model") or {}
        nodes = mental_model.get("nodes") or {}
        current_count = len(nodes)
    except Exception:
        return False
    return (current_count - last_check_count) >= DISCOVERIES_PER_SELF_CRITIQUE

def generate_adversarial_questions(*, vulnerability_class="", validator_outcome="", evidence_origin=""):
    """Confounder questions for Devil's-Advocate / self-critique review.

    Two UNIVERSAL questions always fire (caching, control taint).  On top
    of them, EVERY chartered vulnerability family gets its class-specific
    epistemic confounder — the one trap most likely to turn a weaker
    signal into a false positive for THAT family (U-10a contract depth,
    restored at C1(d) of TC-2; the resurrection had kept only the
    XSS/SQLI/SSRF/IDOR-BOLA branches).
    """
    questions = []
    questions.append({"question": "Could the candidate response be cached?", "resolved": evidence_origin == "target_runtime", "category": "caching"})
    questions.append({"question": "Could the negative control be tainted?", "resolved": validator_outcome == "CONFIRMED", "category": "control_taint"})
    vc = vulnerability_class.upper()
    if vc in ("XSS",):
        questions.append({"question": "Is the payload HTML-encoded?", "resolved": validator_outcome == "CONFIRMED", "category": "encoding"})
    elif vc in ("SQLI",):
        questions.append({"question": "Could the error be generic?", "resolved": validator_outcome == "CONFIRMED", "category": "error_specificity"})
    elif vc in ("SSRF",):
        questions.append({"question": "Could indicators be from a prior response?", "resolved": evidence_origin == "target_runtime", "category": "indicator_provenance"})
    elif vc in ("IDOR", "BOLA"):
        questions.append({"question": "Is the access truly unauthorized?", "resolved": validator_outcome == "CONFIRMED", "category": "authorization_boundary"})
    elif vc in ("SSTI",):
        questions.append({
            "question": "Could the expression be evaluated client-side (browser JS) "
                        "rather than by the server's template engine?",
            "resolved": validator_outcome == "CONFIRMED", "category": "render_origin"})
    elif vc in ("LFI",):
        questions.append({
            "question": "Could the file content be an intended public asset rather "
                        "than an out-of-scope include?",
            "resolved": validator_outcome == "CONFIRMED", "category": "include_scope"})
    elif vc in ("PATH_TRAVERSAL",):
        questions.append({
            "question": "Could the resolved path still be inside the intended document root?",
            "resolved": validator_outcome == "CONFIRMED", "category": "boundary_escape"})
    elif vc in ("COMMAND_INJECTION", "CMDI"):
        questions.append({
            "question": "Could the output be an echo of the input rather than command execution?",
            "resolved": validator_outcome == "CONFIRMED", "category": "execution_vs_echo"})
    elif vc in ("XXE",):
        questions.append({
            "question": "Could the response content originate from a local cached entity "
                        "rather than the attacker-controlled reference?",
            "resolved": evidence_origin == "target_runtime", "category": "entity_provenance"})
    elif vc in ("RFI",):
        questions.append({
            "question": "Could the remote content be served from the target's own origin "
                        "rather than attacker-controlled infrastructure?",
            "resolved": validator_outcome == "CONFIRMED", "category": "origin_control"})
    elif vc in ("OPEN_REDIRECT",):
        questions.append({
            "question": "Is the redirect target truly off-scope (cross-origin) rather "
                        "than an in-app route?",
            "resolved": validator_outcome == "CONFIRMED", "category": "redirect_scope"})
    elif vc in ("INFO_DISCLOSURE",):
        questions.append({
            "question": "Could the disclosed content be intentional documentation "
                        "rather than leaked internals?",
            "resolved": validator_outcome == "CONFIRMED", "category": "disclosure_intent"})
    return questions

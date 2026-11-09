"""Minimal live-graph LLM Researcher integration adapter (Team-1) — V3.

V3: distinguishes USEFUL NOVELTY from BLIND RISK AVERSION. Three separate
dimensions (never collapsed into one boolean):
  A) SEMANTIC REDUNDANCY  — semantic_redundancy_factor (overlap with observed info)
  B) EXPERIMENT REPETITION — prior_execution_count / previously_executed
  C) RESEARCH JUSTIFICATION — unresolved_question_refs / actor_variant /
     parameter_variant / control / new hypothesis implication

Derived labels (advisory only): redundancy_class ∈ {NOVEL, LOW_REDUNDANCY,
MODERATE_REDUNDANCY, HIGH_REDUNDANCY}; justification_class ∈ {NEW_QUESTION,
CONTROL_REQUIRED, ACTOR_VARIANT, PARAMETER_VARIANT, NO_NEW_JUSTIFICATION}.

Policy: JUSTIFIED REPEAT = ALLOWED; BLIND REPEAT = DISFAVORED. The LLM is
explicitly told NOT to automatically avoid HIGH_REDUNDANCY candidates. High
expected IG alone does not override strong redundancy; strong redundancy alone
does not forbid repetition.

5-class diagnostic classification (never replaces the LLM choice):
ALIGNED / JUSTIFIED_DEVIATION / UNJUSTIFIED_DEVIATION / REDUNDANT_DEVIATION /
INVALID_SELECTION.

Context sanitization: raw target path/auth/headers/cookies never reach the LLM;
only structural representations (path_shape, has_auth, actor_role, resource_class).
Activation OFF by default -> deterministic path byte-identical. Fail-closed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Sequence
from typing import Any

from webpent.integration.hypothesis_portfolio import HypothesisPortfolio
from webpent.llm_researcher.experiment_outcome_tracker import ExperimentOutcomeTracker
from webpent.llm_researcher.interface import LLMResearcher
from webpent.llm_researcher.providers.factory import get_provider_from_env
from webpent.llm_researcher.semantic_fingerprint import semantic_fingerprint_from_candidate
from webpent.models.research import CandidateAction
from webpent.shared.research_contracts import ResearchContext, ResearchDecision

_OPT_IN_ENV = "WEBPENT_LLM_RESEARCH_ENABLED"
_MAX_CANDIDATES_EXPOSED = 8

_SELECTOR_REGISTRY: dict[tuple, LLMResearchSelector] = {}


def llm_research_enabled() -> bool:
    return os.environ.get(_OPT_IN_ENV, "").strip().lower() == "true"


def clear_session(session_key: tuple) -> None:
    _SELECTOR_REGISTRY.pop(session_key, None)


def _path_shape(target_ref: str) -> str:
    """Structural path shape: replace numeric/uuid segments with {id}. No raw path."""
    path = str(target_ref or "").split("?")[0]
    path = re.sub(r"://[^/]+", "://<host>", path)
    path = re.sub(r"/\d+", "/{id}", path)
    path = re.sub(r"/[0-9a-f-]{8,}", "/{id}", path)
    return path[:120]


def _redundancy_class(factor: float, prior_count: int) -> str:
    if prior_count == 0:
        return "NOVEL"
    if factor >= 0.8:
        return "LOW_REDUNDANCY"
    if factor >= 0.5:
        return "MODERATE_REDUNDANCY"
    return "HIGH_REDUNDANCY"


def _justification_class(
    candidate: CandidateAction, unresolved_refs: list[str], prior_count: int
) -> str:
    if unresolved_refs:
        return "NEW_QUESTION"
    if prior_count == 0:
        return "NOVEL"
    meta = candidate.metadata or {}
    if meta.get("control_required") or meta.get("independent_control"):
        return "CONTROL_REQUIRED"
    if meta.get("actor_variant"):
        return "ACTOR_VARIANT"
    if meta.get("parameter_variant"):
        return "PARAMETER_VARIANT"
    return "NO_NEW_JUSTIFICATION"


class LLMResearchSelector:
    """Advisory LLM selector over an already-ranked admissible candidate set."""

    def __init__(
        self,
        researcher: LLMResearcher,
        outcome_tracker: ExperimentOutcomeTracker | None = None,
    ) -> None:
        self.researcher = researcher
        self.outcome_tracker = outcome_tracker or ExperimentOutcomeTracker()
        self.portfolio = HypothesisPortfolio()  # session-scoped branch portfolio
        self.diagnostics: list[dict[str, Any]] = []
        self.provenance_log: list[dict[str, Any]] = []
        self.decision_sequence = 0
        self._ingested_fact_hashes: set[str] = set()

    @classmethod
    def build_if_enabled(cls, session_key: tuple | None = None) -> LLMResearchSelector | None:
        if not llm_research_enabled():
            return None
        if session_key is not None and session_key in _SELECTOR_REGISTRY:
            return _SELECTOR_REGISTRY[session_key]
        try:
            provider = get_provider_from_env()
        except Exception:
            return None
        if type(provider).__name__.lower().startswith("mock"):
            return None
        selector = cls(LLMResearcher(llm_client=provider), ExperimentOutcomeTracker())
        if session_key is not None:
            _SELECTOR_REGISTRY[session_key] = selector
        return selector

    def _ingest_sanitized_context(self, context: ResearchContext) -> None:
        for fact in list(getattr(context, "known_facts", []) or [])[:50]:
            fact_str = str(fact)[:300]
            h = hashlib.sha256(fact_str.encode()).hexdigest()[:16]
            if h in self._ingested_fact_hashes:
                continue
            self._ingested_fact_hashes.add(h)
            self.researcher.ingest_observation(
                {"source": "known_fact", "fact_digest": h, "loop_index": self.decision_sequence}
            )

    def record_outcome(self, candidate: CandidateAction, observation: Any) -> None:
        """Record actual execution outcome (V4: outcome-aware value adjustment).

        Deterministic structural summary only — never raw prompts/credentials.
        Closes the loop: actual outcomes feed future redundancy factors.
        """
        try:
            from webpent.llm_researcher.experiment_outcome_tracker import (
                ExperimentOutcome,
                InformationValue,
            )
            fp = semantic_fingerprint_from_candidate(candidate)
            obs_status = str(getattr(observation, "status", "") or "")
            new_obs = obs_status not in {"blocked", "negative", "infrastructure_failure"}
            info_value = InformationValue.classify(
                new_observation_added=new_obs,
                new_semantic_pattern=new_obs,
                anomaly_detected=False,
            )
            self.outcome_tracker.record(ExperimentOutcome(
                semantic_fingerprint=fp,
                information_value=info_value,
                evidence_classes={obs_status} if obs_status else set(),
            ))
            # V5: update hypothesis portfolio (exploration/exploitation).
            branch_id = str((candidate.metadata or {}).get("branch_id", "unknown"))[:80]
            hyp_id = str(getattr(candidate, "hypothesis_id", ""))[:80]
            self.portfolio.record_branch_outcome(
                branch_id, info_value.value, new_question_count=0, hypothesis_id=hyp_id
            )
            # OBSERVED_OUTCOME_STATE (separate from PREDICTED selection state)
            if self.provenance_log:
                self.provenance_log[-1]["observed_outcome_state"] = info_value.value
        except Exception:
            pass  # outcome recording must never break the research loop

    def _repetition_state(self, candidate: CandidateAction) -> dict[str, Any]:
        fp = None
        try:
            fp = semantic_fingerprint_from_candidate(candidate)
        except Exception:
            fp = None
        if fp and self.outcome_tracker is not None:
            count = self.outcome_tracker.execution_count(fp)
            factor = self.outcome_tracker.semantic_redundancy_factor(fp)
            last = self.outcome_tracker.last_information_value(fp).value
        else:
            count = 0
            factor = 1.0
            last = "UNKNOWN"
        return {
            "semantic_redundancy_factor": round(float(factor), 4),
            "prior_execution_count": int(count),
            "previously_executed": count > 0,
            "last_information_value": last,
            "redundancy_class": _redundancy_class(float(factor), int(count)),
        }

    def _sanitized_candidate_context(
        self, admissible: list[ResearchDecision], context: ResearchContext
    ) -> list[dict[str, Any]]:
        attempted = set(getattr(context, "attempted_action_fingerprints", []) or [])
        unresolved = dict(getattr(context, "unresolved_questions", {}) or {})
        out = []
        for rank, d in enumerate(admissible[:_MAX_CANDIDATES_EXPOSED], start=1):
            c = d.candidate
            rep = self._repetition_state(c)
            meta = c.metadata or {}
            branch_id = str(meta.get("branch_id", ""))[:80]
            unresolved_refs = sorted(unresolved.get(branch_id, []))[:5]
            just_class = _justification_class(c, unresolved_refs, rep["prior_execution_count"])
            actor = str(getattr(c, "identity_context", "anonymous"))[:60]
            # V6 closeout: portfolio value signal makes reactivation visible in
            # candidate-visible value. Advisory only — deterministic ranking
            # authority unchanged, no forcing, no second scheduler.
            bp_sig = self.portfolio.branch_signal(branch_id)
            _adj_util = round(float(getattr(d, "score", 0.0)) * (0.4 + 0.6 * bp_sig["exploitation_value"]), 4)
            out.append({
                "candidate_id": c.action_id,
                "branch_id": branch_id,
                "hypothesis_id": str(getattr(c, "hypothesis_id", ""))[:80],
                "deterministic_rank": rank,
                "deterministic_utility": round(float(getattr(d, "score", 0.0)), 4),
                "research_value": {
                    "expected_information_gain": float(c.expected_information_gain or 0.0),
                    "novelty": float(c.novelty or 0.5),
                    "coverage_value": float(c.coverage_value or 0.5),
                },
                "repetition_state": rep,
                "justification_class": just_class,
                "research_context": {
                    "unresolved_question_refs": unresolved_refs,
                    "lineage_refs": [str(meta.get("lineage_ref", ""))[:32]] if meta.get("lineage_ref") else [],
                },
                # V5/V6: branch portfolio signal. Value-only advisory — never
                # forces branch switch, never hard-filters, never overrides LLM.
                "branch_portfolio_signal": bp_sig,
                "portfolio_value_signal": {
                    "exploitation_value": bp_sig["exploitation_value"],
                    "exploration_pressure": bp_sig["exploration_pressure"],
                    "saturation_state": bp_sig["saturation_state"],
                    "adjusted_utility": _adj_util,
                },
                # Structural sanitized representations only — never raw path/auth.
                "target_shape": {
                    "path_shape": _path_shape(str(getattr(c, "target_ref", ""))),
                    "method": str(getattr(c, "method", "GET"))[:10],
                    "has_auth": actor != "anonymous",
                    "actor_role": actor,
                    "resource_class": str(meta.get("resource_class", "unknown"))[:40],
                },
                "action_class": c.action_class,
                "capability": c.capability,
                "objective": c.objective[:200],
                "requires_approval": bool(c.requires_approval),
            })
        return out

    def _build_candidate_selection_prompt(
        self, candidates: list[dict[str, Any]], policy_hash: str
    ) -> str:
        return (
            f"SYSTEM INSTRUCTION (TRUSTED — research policy v{policy_hash[:8]}):\n"
            "You select ONE research action. You MAY ONLY choose a candidate_id\n"
            "from the ADMISSIBLE set below. You cannot confirm vulnerabilities,\n"
            "cannot bypass scope/budget/authorization, cannot fabricate actions.\n\n"
            "SELECTION POLICY (bounded, advisory):\n"
            "1. Only valid/admissible candidates may be selected.\n"
            "2. Prefer candidates with meaningful information value.\n"
            "3. When research value is otherwise COMPARABLE, prefer novel/non-redundant\n"
            "   candidates (low semantic_redundancy_factor, low prior_execution_count).\n"
            "4. deterministic_utility is a STRONG signal (rank 1 = highest).\n"
            "5. expected_information_gain is IMPORTANT but NOT DOMINANT: high IG alone\n"
            "   does NOT justify a highly redundant, already-executed candidate.\n"
            "6. CRITICAL — DO NOT practice blind risk aversion: a PREVIOUSLY EXECUTED\n"
            "   candidate may still be the BEST choice when it has a concrete research\n"
            "   justification (justification_class = NEW_QUESTION / ACTOR_VARIANT /\n"
            "   PARAMETER_VARIANT / CONTROL_REQUIRED). JUSTIFIED REPEAT = ALLOWED.\n"
            "   BLIND REPEAT (NO_NEW_JUSTIFICATION, HIGH_REDUNDANCY) = DISFAVORED.\n"
            "7. Do NOT automatically avoid HIGH_REDUNDANCY candidates. Do NOT always\n"
            "   select rank #1. Do NOT always avoid rank #1. Choose by research value.\n\n"
            f"RESEARCH POLICY HASH: {policy_hash}\n"
            f"DECISION_SEQUENCE: {self.decision_sequence}\n"
            f"ADMISSIBLE_CANDIDATES (already passed deterministic gates):\n"
            f"{json.dumps(candidates, indent=2)}\n\n"
            'Return ONE JSON object only: {"selected_candidate_id": "<exact id>", "decision_reason": "<short>"}\n'
        )

    @staticmethod
    def _parse_candidate_decision(response_text: str) -> str | None:
        try:
            if "```json" in response_text:
                s = response_text.split("```json")[1].split("```")[0]
            elif "```" in response_text:
                s = response_text.split("```")[1].split("```")[0]
            else:
                s = response_text
            data = json.loads(s)
            if not isinstance(data, dict):
                return None
            cid = str(data.get("selected_candidate_id", "")).strip()
            return cid or None
        except (json.JSONDecodeError, ValueError, AttributeError):
            return None

    @staticmethod
    def _classify_selection(
        selected: dict[str, Any], candidates: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """5-class deterministic diagnostic. Never replaces the LLM choice."""
        top = candidates[0]
        sel_rank = selected["deterministic_rank"]
        sel_util = selected["deterministic_utility"]
        sel_red = selected["repetition_state"]["semantic_redundancy_factor"]
        sel_count = selected["repetition_state"]["prior_execution_count"]
        sel_just = selected["justification_class"]
        top_util = top["deterministic_utility"]
        utility_gap = round(top_util - sel_util, 4)
        redundancy_gap = round(top["repetition_state"]["semantic_redundancy_factor"] - sel_red, 4)
        unresolved_diff = len(selected["research_context"]["unresolved_question_refs"]) - len(
            top["research_context"]["unresolved_question_refs"]
        )
        if sel_rank == 1:
            cls = "ALIGNED"
        elif sel_count > 0 and sel_red < 1.0 and sel_just == "NO_NEW_JUSTIFICATION":
            cls = "REDUNDANT_DEVIATION"
        elif sel_just in {"NEW_QUESTION", "ACTOR_VARIANT", "PARAMETER_VARIANT", "CONTROL_REQUIRED", "NOVEL"}:
            cls = "JUSTIFIED_DEVIATION"
        else:
            cls = "UNJUSTIFIED_DEVIATION"
        return {
            "classification": cls,
            "selected_rank": sel_rank,
            "selected_utility": sel_util,
            "selected_redundancy_factor": sel_red,
            "selected_prior_execution_count": sel_count,
            "selected_justification_class": sel_just,
            "top_rank": 1,
            "top_utility": top_util,
            "utility_gap": utility_gap,
            "redundancy_gap": redundancy_gap,
            "unresolved_question_difference": unresolved_diff,
        }

    def select_from_candidates(
        self,
        context: ResearchContext,
        ranked_decisions: Sequence[ResearchDecision],
    ) -> CandidateAction | None:
        admissible = [d for d in ranked_decisions if d.status == "ranked"]
        if not admissible:
            return None

        self._ingest_sanitized_context(context)
        self.decision_sequence += 1

        candidates_ctx = self._sanitized_candidate_context(admissible, context)
        valid_ids = {c["candidate_id"] for c in candidates_ctx}

        obs_count = len(self.researcher.memory.observations)
        fact_count = len(self._ingested_fact_hashes)
        input_digest = hashlib.sha256(
            json.dumps({
                "observation_count": obs_count,
                "known_fact_count": fact_count,
                "candidate_ids": sorted(valid_ids),
                "decision_sequence": self.decision_sequence,
            }, sort_keys=True).encode()
        ).hexdigest()
        provenance: dict[str, Any] = {
            "decision_sequence": self.decision_sequence,
            "observation_count": obs_count,
            "known_fact_count": fact_count,
            "context_input_hash": input_digest,
            "admissible_candidate_count": len(admissible),
            "candidate_ids_presented": sorted(valid_ids),
            "lineage": {
                "prior_fact_digests": sorted(self._ingested_fact_hashes)[-8:],
                "influenced_by_prior_observations": fact_count > 0,
                "top_hypothesis_ref": str(getattr(admissible[0].candidate, "hypothesis_id", ""))[:80],
            },
        }

        prompt = self._build_candidate_selection_prompt(
            candidates_ctx, self.researcher.get_policy_hash()
        )
        try:
            response = self.researcher.llm_client.generate(prompt, max_tokens=400)
        except Exception as exc:
            provenance["outcome"] = "provider_failed"
            provenance["reason"] = type(exc).__name__
            self.provenance_log.append(provenance)
            self.diagnostics.append({"phase": "provider", "reason": type(exc).__name__})
            return None

        response_text = response.content if hasattr(response, "content") else str(response)
        selected_id = self._parse_candidate_decision(response_text)

        if selected_id is None:
            provenance["outcome"] = "malformed_rejected"
            self.provenance_log.append(provenance)
            self.diagnostics.append({"phase": "decision", "reason": "malformed_or_missing_id"})
            return None

        if selected_id not in valid_ids:
            provenance["outcome"] = "unknown_candidate_rejected"
            provenance["rejected_id"] = selected_id[:80]
            self.provenance_log.append(provenance)
            self.diagnostics.append({"phase": "validation", "reason": "unknown_candidate_id"})
            return None

        chosen_ctx = next(c for c in candidates_ctx if c["candidate_id"] == selected_id)
        provenance["selection_classification"] = self._classify_selection(chosen_ctx, candidates_ctx)
        # PREDICTED_SELECTION_STATE (at selection time) — separate from
        # OBSERVED_OUTCOME_STATE (set by record_outcome after execution).
        provenance["predicted_selection_state"] = (
            f"{chosen_ctx['repetition_state']['redundancy_class']}/"
            f"{chosen_ctx['justification_class']}"
        )
        provenance["observed_outcome_state"] = "PENDING"
        provenance["outcome"] = "selected"
        provenance["selected_candidate_id"] = selected_id
        self.provenance_log.append(provenance)
        self.diagnostics.append({"phase": "selected", "candidate_id": selected_id})
        return next(d.candidate for d in admissible if d.candidate.action_id == selected_id)

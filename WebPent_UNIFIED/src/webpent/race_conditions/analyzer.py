"""Passive race-condition analyzers.

Emits candidates and evidence requirements only. No HTTP, no promotion.
The actual burst execution lives in the deterministic validator
(``webpent.agents.validator.family_checks``) behind scope policy.
"""
from __future__ import annotations

import uuid
from typing import Any

from webpent.families.base import (
    CandidateConfidence,
    FamilyAnalysis,
    FamilyAnalyzer,
    FamilyCandidate,
    FamilyId,
)
from webpent.race_conditions.scenarios import RACE_SCENARIOS


def _cid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class BurstPatternDetector(FamilyAnalyzer):
    """Identifies endpoints where a synchronized burst is worth attempting."""

    family = FamilyId.RACE_CONDITION
    scenarios = RACE_SCENARIOS

    def analyze(
        self,
        endpoint_inventory: list[dict[str, Any]],
        *,
        target_id: str,
        engagement_id: str,
        is_production: bool = False,
    ) -> FamilyAnalysis:
        if not target_id.strip() or not engagement_id.strip():
            raise ValueError("target_and_engagement_context_required")
        observed: set[str] = set()
        mutating: list[dict[str, Any]] = []
        for ep in endpoint_inventory:
            method = str(ep.get("method", "")).upper()
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                observed.add("mutating_endpoint")
                mutating.append(ep)
            path = str(ep.get("path", ""))
            if any(k in path for k in ("withdraw", "transfer", "balance", "purchase", "order", "checkout", "pay")):
                observed.add("stateful_balance")
            if any(k in path for k in ("coupon", "promo", "discount", "redeem")):
                observed.add("promo_code")
                observed.add("checkout_endpoint")
            if any(k in path for k in ("upload", "import", "validate", "verify")):
                observed.add("two_step_resource_flow")
                observed.add("upload_or_import")
            if any(k in path for k in ("reset", "forgot", "otp", "mfa", "verify-token")):
                observed.add("password_reset_flow")
                observed.add("otp_or_mfa")
            if ep.get("rate_limited"):
                observed.add("rate_limited_endpoint")

        applicable = self.applicable_scenarios(observed)
        candidates: list[FamilyCandidate] = []
        for scenario in applicable:
            for ep in mutating[:32]:  # bound candidate fan-out
                if scenario.scenario_id == "RACE-001-double-spend" and "stateful_balance" not in observed:
                    continue
                candidates.append(
                    FamilyCandidate(
                        candidate_id=_cid("RACE"),
                        family=FamilyId.RACE_CONDITION,
                        vuln_class="race_condition",
                        scenario_id=scenario.scenario_id,
                        affected_endpoint=f"{ep.get('method','GET')} {ep.get('path','/')}",
                        hypothesis=(
                            f"{scenario.name}: synchronized burst on "
                            f"{ep.get('method','GET')} {ep.get('path','/')} "
                            "may commit >1 side effect where rules permit 1."
                        ),
                        confidence=CandidateConfidence.SPECULATIVE,
                    )
                )
        candidates = self.dedupe(candidates)
        candidates, dropped = self.filter_safety(candidates, self.scenarios, is_production=is_production)
        gaps = self.coverage_gaps_for(observed, candidates)
        for d in dropped:
            gaps.append(f"production_safety_suppressed:{d}")
        return FamilyAnalysis(
            target_id=target_id.strip()[:200],
            engagement_id=engagement_id.strip()[:200],
            family=FamilyId.RACE_CONDITION,
            candidates=candidates,
            applicable_scenarios=[s.scenario_id for s in applicable],
            coverage_gaps=sorted(gaps),
        )


class IdempotencyInvariant(FamilyAnalyzer):
    """Checks whether mutating endpoints declare idempotency keys / retries.

    Absence of an idempotency contract is a coverage gap, not a finding.
    """

    family = FamilyId.RACE_CONDITION
    scenarios = RACE_SCENARIOS

    def analyze(
        self,
        endpoint_inventory: list[dict[str, Any]],
        *,
        target_id: str,
        engagement_id: str,
    ) -> FamilyAnalysis:
        if not target_id.strip() or not engagement_id.strip():
            raise ValueError("target_and_engagement_context_required")
        gaps: set[str] = set()
        mutating = [
            ep for ep in endpoint_inventory
            if str(ep.get("method", "")).upper() in {"POST", "PUT", "PATCH", "DELETE"}
        ]
        without_idempotency = [
            ep for ep in mutating
            if not ep.get("idempotent") and "Idempotency-Key" not in ep.get("headers", {})
        ]
        if mutating and len(without_idempotency) == len(mutating):
            gaps.add("no_idempotency_contract_observed")
        if not mutating:
            gaps.add("no_mutating_endpoints_observed")
        observed: set[str] = set()
        if mutating:
            observed.add("mutating_endpoint")
        applicable = [s.scenario_id for s in self.applicable_scenarios(observed)]
        return FamilyAnalysis(
            target_id=target_id.strip()[:200],
            engagement_id=engagement_id.strip()[:200],
            family=FamilyId.RACE_CONDITION,
            candidates=[],
            applicable_scenarios=applicable,
            coverage_gaps=sorted(gaps),
        )


__all__ = ["BurstPatternDetector", "IdempotencyInvariant"]

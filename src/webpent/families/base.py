"""Shared primitives for the five high-level logic test families.

FIVE-FAMILY COVERAGE (gap-closure sprint)
=========================================
This module is the single source of truth for the cross-family contract
shared by: business_logic, race_conditions, multi_step_auth, tenant_isolation,
and chained_exploits.

Design invariants (mirrors ``webpent.business_logic``):
  * Passive only. Analyzers emit candidates, hypotheses, and evidence
    requirements. They NEVER construct a Finding, NEVER promote, and NEVER
    issue an HTTP request. Execution stays behind scope policy,
    ActionAuthority, and the central proof-bundle / replay validators.
  * Pydantic models with ``extra="forbid"`` so a typo in a scenario field
    fails loudly instead of silently dropping coverage.
  * Every scenario carries an explicit discriminator experiment and the
    negative control required to confirm it — a candidate without both is
    a coverage gap, not a finding.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FamilyId(str, Enum):
    """Stable identifiers for the five logic families."""

    BUSINESS_LOGIC = "business_logic"
    RACE_CONDITION = "race_condition"
    MULTI_STEP_AUTH_BYPASS = "multi_step_auth_bypass"
    TENANT_ISOLATION = "tenant_isolation"
    CHAINED_EXPLOIT = "chained_exploit"
    OAUTH = "oauth"


class CandidateConfidence(str, Enum):
    SPECULATIVE = "speculative"
    SUGGESTIVE = "suggestive"
    SUBSTANTIAL = "substantial"


class EvidenceRequirement(BaseModel):
    """One piece of evidence a validator must produce before promotion."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    kind: str = Field(..., min_length=1, max_length=64)
    description: str = Field(..., min_length=1, max_length=500)
    requires_negative_control: bool = True


class ScenarioSpec(BaseModel):
    """A single testable scenario within a family.

    A scenario is a *recipe*, not a result: it declares the preconditions
    that make it worth trying, the discriminating experiment, and the exact
    signal + negative control that would confirm it.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    scenario_id: str = Field(..., min_length=1, max_length=128)
    family: FamilyId
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=1000)
    preconditions: list[str] = Field(default_factory=list, max_length=32)
    discriminator_experiment: str = Field(..., min_length=1, max_length=1000)
    expected_signal: str = Field(..., min_length=1, max_length=500)
    negative_control: str = Field(..., min_length=1, max_length=500)
    evidence_requirements: list[EvidenceRequirement] = Field(
        default_factory=list, max_length=16
    )
    severity: str = Field("medium", pattern="^(info|low|medium|high|critical)$")
    references: list[str] = Field(default_factory=list, max_length=16)
    safe_in_production: bool = False

    def is_applicable(self, observed_capabilities: set[str]) -> bool:
        """A scenario is applicable iff ALL its preconditions are observed."""
        return all(p in observed_capabilities for p in self.preconditions)


class FamilyCandidate(BaseModel):
    """A candidate emitted by an analyzer. Candidate-only — never promoted."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    candidate_id: str = Field(..., min_length=1, max_length=128)
    family: FamilyId
    vuln_class: str = Field(..., min_length=1, max_length=64)
    scenario_id: str = Field(..., min_length=1, max_length=128)
    affected_endpoint: str = Field("", max_length=2048)
    hypothesis: str = Field(..., min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=64)
    confidence: CandidateConfidence = CandidateConfidence.SPECULATIVE
    promotion_status: str = "candidate_only"
    # Dedupe coordination with existing detectors (e.g. business_logic_fuzzer
    # race node). Two candidates with the same dedupe_key represent the same
    # hypothesis and must be merged, not double-reported. source marks which
    # detector emitted it. Auto-populated when empty (see model_validator).
    source: str = Field("family_analyzer", max_length=64)
    dedupe_key: str = Field("", max_length=256)

    @model_validator(mode="after")
    def _autofill_dedupe_key(self) -> "FamilyCandidate":
        if not self.dedupe_key:
            fam = str(self.family.value if hasattr(self.family, "value") else self.family)
            object.__setattr__(
                self, "dedupe_key",
                f"{self.source}:{fam}:{self.scenario_id}:{self.affected_endpoint}",
            )
        return self


class FamilyAnalysis(BaseModel):
    """Aggregate analyzer output for one family on one target."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_id: str = Field(..., min_length=1, max_length=200)
    engagement_id: str = Field(..., min_length=1, max_length=200)
    family: FamilyId
    candidates: list[FamilyCandidate] = Field(default_factory=list, max_length=512)
    applicable_scenarios: list[str] = Field(default_factory=list, max_length=256)
    coverage_gaps: list[str] = Field(default_factory=list, max_length=64)
    promotion_status: str = "candidate_only"


class FamilyAnalyzer:
    """Base contract. Subclasses implement ``analyze``; no I/O allowed."""

    family: FamilyId
    scenarios: tuple[ScenarioSpec, ...] = ()

    def applicable_scenarios(self, observed_capabilities: set[str]) -> list[ScenarioSpec]:
        return [s for s in self.scenarios if s.is_applicable(observed_capabilities)]

    def coverage_gaps_for(
        self, observed_capabilities: set[str], candidates: list[FamilyCandidate]
    ) -> list[str]:
        gaps: set[str] = set()
        applicable = self.applicable_scenarios(observed_capabilities)
        covered = {c.scenario_id for c in candidates}
        for scenario in applicable:
            if scenario.scenario_id not in covered:
                gaps.add(f"scenario_not_attempted:{scenario.scenario_id}")
        if not applicable:
            gaps.add("no_applicable_scenarios")
        return sorted(gaps)

    @staticmethod
    def dedupe(candidates: list[FamilyCandidate]) -> list[FamilyCandidate]:
        """Deduplicate by (scenario_id, affected_endpoint) — first wins."""
        seen: set[tuple[str, str]] = set()
        out: list[FamilyCandidate] = []
        for c in candidates:
            key = (c.scenario_id, c.affected_endpoint)
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
        return out

    @staticmethod
    def filter_safety(
        candidates: list[FamilyCandidate],
        scenarios: tuple[ScenarioSpec, ...],
        *,
        is_production: bool,
    ) -> tuple[list[FamilyCandidate], list[str]]:
        """Drop unsafe-in-production candidates when target is production.
        Returns (kept, dropped_scenario_ids)."""
        unsafe = {s.scenario_id for s in scenarios if not s.safe_in_production}
        if not is_production:
            return list(candidates), []
        kept = [c for c in candidates if c.scenario_id not in unsafe]
        dropped = sorted({c.scenario_id for c in candidates if c.scenario_id in unsafe})
        return kept, dropped

    def analyze(self, *args: Any, **kwargs: Any) -> FamilyAnalysis:  # pragma: no cover
        raise NotImplementedError


__all__ = [
    "CandidateConfidence",
    "EvidenceRequirement",
    "FamilyAnalysis",
    "FamilyAnalyzer",
    "FamilyCandidate",
    "FamilyId",
    "ScenarioSpec",
]

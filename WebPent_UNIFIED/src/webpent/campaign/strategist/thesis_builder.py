"""U-CAMPAIGN-1 — ThesisBuilder.

The thesis is the ONLY entry point to a campaign (L-1). The builder is
pure, deterministic arithmetic over three upstream signals:

- Oracle-shaped report   — what the target looks like (stack, surface,
  leaks, crown-jewel hints)
- Prism-shaped matches   — which archetype the target resembles
- Economist-shaped score — what the target is worth attacking

Published constants (L-9: the arithmetic is reviewable, not hidden):

- Evidence weights live in thesis_evidence.py.
- Confidence = weighted average of evidence weights
              + archetype bonus (a strong pattern match adds up to +0.10)
              + source-count bonus (up to +0.15, 0.05 per distinct source).
- Family scores start from pattern-implied probabilities (or a flat
  0.10 prior with no patterns), then documented boosts from the oracle:
  node/express stack → BOLA +0.30, SQLI +0.25; django stack → SSTI +0.35,
  SQLI +0.30, INFO_DISCLOSURE +0.25; legacy markers → IDOR +0.30,
  INFO_DISCLOSURE +0.25; leaked signals → AUTH_BYPASS +0.35,
  INFO_DISCLOSURE +0.20. Likely = score >= 0.30; unlikely = score < 0.30
  (the two sets are disjoint by construction); scores are normalized to
  sum <= 1.0.
"""
from __future__ import annotations

from typing import Any

from webpent.campaign.errors import (
    InsufficientDataError,
    ThesisValidationError,
)
from webpent.campaign.schemas import (
    Family,
    TargetThesis,
    ThesisEvidence,
)
from webpent.campaign.strategist.phase_templates import (
    TYPICAL_HYPOTHESIS_COUNT,
)
from webpent.campaign.strategist.thesis_evidence import (
    evidence_from_economist,
    evidence_from_oracle,
    evidence_from_prism,
)
from webpent.campaign.strategist.validators import (
    validate_thesis,
)

MIN_EVIDENCE_TO_BUILD = 2

# The proceeding floor for family scores.
LIKELY_FLOOR = 0.30

# Tech-stack family boosts (documented, deterministic).
_TECH_FAMILY_BOOSTS: dict[str, list[tuple[Family, float]]] = {
    "node": [(Family.BOLA, 0.30), (Family.SQLI, 0.25)],
    "express": [(Family.BOLA, 0.30), (Family.SQLI, 0.25)],
    "javascript": [(Family.BOLA, 0.30), (Family.SQLI, 0.25)],
    "django": [(Family.SSTI, 0.35), (Family.SQLI, 0.30),
               (Family.INFO_DISCLOSURE, 0.25)],
    "python": [(Family.SSTI, 0.30), (Family.SQLI, 0.25)],
    "spring": [(Family.SSRF, 0.30), (Family.SQLI, 0.20)],
    "java": [(Family.SSRF, 0.25), (Family.SQLI, 0.20)],
}
_LEGACY_BOOSTS: list[tuple[Family, float]] = [
    (Family.IDOR, 0.30), (Family.INFO_DISCLOSURE, 0.25),
]
_LEAK_BOOSTS: list[tuple[Family, float]] = [
    (Family.AUTH_BYPASS, 0.35), (Family.INFO_DISCLOSURE, 0.20),
]
_FAMILY_PRIOR = 0.10
_ARCHETYPE_BONUS_CAP = 0.10
_SOURCE_COUNT_BONUS_STEP = 0.05
_SOURCE_COUNT_BONUS_CAP = 0.15


class ThesisBuilder:
    """Builds, refines and validates a TargetThesis (L-1, L-9)."""

    def build(self, target_id: str, oracle: Any,
              patterns: list[Any], economist: Any) -> TargetThesis:
        """Deterministically derive a thesis from the three signals.

        Raises InsufficientDataError when the evidence is too thin to
        stand on, and ThesisValidationError when the derived thesis
        misses the proceeding floor — the builder refuses to return a
        thesis it would not defend to the operator.
        """
        evidence: list[ThesisEvidence] = (
            evidence_from_oracle(oracle)
            + evidence_from_prism(patterns)
            + evidence_from_economist(economist)
        )
        if len(evidence) < MIN_EVIDENCE_TO_BUILD:
            raise InsufficientDataError(
                f"only {len(evidence)} evidence piece(s) for {target_id}; "
                f"a thesis needs at least {MIN_EVIDENCE_TO_BUILD} — the "
                "builder refuses to guess (L-1)")

        confidence = self._derive_confidence(evidence, patterns)
        likely, unlikely = self._derive_families(oracle, patterns)

        if not likely:
            raise InsufficientDataError(
                "no vulnerability family reaches the likely floor "
                f"({LIKELY_FLOOR:.2f}) — nothing to plan a campaign around")

        crown_jewels = [str(j) for j in (oracle.crown_jewel_hints or [])]
        entry_points = [str(e) for e in (oracle.historical_endpoints or [])]
        archetype = patterns[0].archetype_name if patterns else None
        statement = self._compose_statement(target_id, evidence, archetype)

        thesis = TargetThesis.create(
            target_id=target_id,
            statement=statement,
            confidence=confidence,
            likely_vuln_families=likely,
            unlikely_vuln_families=unlikely,
            crown_jewels=crown_jewels,
            likely_entry_points=entry_points,
            evidence=evidence,
            reasoning=self._compose_reasoning(evidence, likely, confidence),
        )

        errors = validate_thesis(thesis)
        if errors:
            raise ThesisValidationError(errors)
        return thesis

    def refine(self, prior: TargetThesis,
               additional_evidence: list[ThesisEvidence]) -> TargetThesis:
        """New evidence supersedes the thesis; it never edits it (L-1).

        The prior stays intact for the campaign memory; the refined
        thesis chains to it through ``supersedes`` with version + 1.
        """
        if not additional_evidence:
            raise InsufficientDataError(
                "refine called with no new evidence — refusing to bump a "
                "version for nothing")
        evidence = list(prior.evidence) + list(additional_evidence)
        bump = min(0.10, 0.05 * len(additional_evidence))
        confidence = min(1.0, prior.confidence + bump)
        return TargetThesis.create(
            target_id=prior.target_id,
            statement=prior.statement,
            confidence=confidence,
            likely_vuln_families=list(prior.likely_vuln_families),
            unlikely_vuln_families=list(prior.unlikely_vuln_families),
            crown_jewels=list(prior.crown_jewels),
            likely_entry_points=list(prior.likely_entry_points),
            evidence=evidence,
            reasoning=(prior.reasoning
                       + f" | refined with {len(additional_evidence)} new "
                         "evidence piece(s)"),
            supersedes=prior.thesis_id,
        )

    def validate(self, thesis: TargetThesis) -> None:
        """Raise unless the thesis meets the proceeding floor."""
        errors = validate_thesis(thesis)
        if errors:
            raise ThesisValidationError(errors)

    # ------------------------------------------------------------------
    # Derivation internals (published arithmetic)
    # ------------------------------------------------------------------

    def _derive_confidence(self, evidence: list[ThesisEvidence],
                           patterns: list[Any]) -> float:
        weights = [e.weight for e in evidence]
        avg = sum(weights) / len(weights)
        archetype_bonus = 0.0
        if patterns:
            strongest = max(float(p.confidence or 0.0) for p in patterns)
            archetype_bonus = min(_ARCHETYPE_BONUS_CAP, strongest * 0.12)
        sources = len({e.source for e in evidence})
        count_bonus = min(_SOURCE_COUNT_BONUS_CAP,
                          _SOURCE_COUNT_BONUS_STEP * sources)
        return round(min(1.0, avg + archetype_bonus + count_bonus), 4)

    def _derive_families(self, oracle: Any,
                         patterns: list[Any]
                         ) -> tuple[list[tuple[Family, float]],
                                    list[tuple[Family, float]]]:
        scores: dict[Family, float] = {}
        for pattern in patterns or []:
            confidence = float(pattern.confidence or 0.0)
            for family, prob in (pattern.typical_families or {}).items():
                scores[family] = scores.get(family, 0.0) + prob * confidence
        if not scores:
            scores = {f: _FAMILY_PRIOR for f in Family}

        def _apply_boosts(boosts: list[tuple[Family, float]]) -> None:
            for family, boost in boosts:
                scores[family] = scores.get(family, _FAMILY_PRIOR) + boost

        tech = oracle.tech_stack or {}
        for value in tech.values():
            boosts = _TECH_FAMILY_BOOSTS.get(str(value).lower())
            if boosts:
                _apply_boosts(boosts)
        if any(m in s.lower() for s in (oracle.subdomains or [])
               for m in ("legacy", "old", "dev", "staging", "internal")):
            _apply_boosts(_LEGACY_BOOSTS)
        if oracle.leaked_signals:
            _apply_boosts(_LEAK_BOOSTS)

        # Normalize so likely scores sum <= 1.0 (over 1.0 only when the
        # boosts push past it; the normalization keeps the vocabulary
        # honest).
        likely = sorted(
            ((f, p) for f, p in scores.items() if p >= LIKELY_FLOOR),
            key=lambda item: item[1], reverse=True)
        total = sum(p for _, p in likely)
        if total > 1.0:
            likely = [(f, round(p / total, 4)) for f, p in likely]
            # Rounding to 4 decimals can leave a 0.0001 drift above 1.0;
            # the top-scored family absorbs it so the sum stays honest.
            drift = round(sum(p for _, p in likely) - 1.0, 4)
            if drift > 0 and likely:
                f0, p0 = likely[0]
                likely[0] = (f0, round(p0 - drift, 4))
        unlikely = sorted(
            ((f, p) for f, p in scores.items() if p < LIKELY_FLOOR),
            key=lambda item: item[1])
        return likely, unlikely

    def _compose_statement(self, target_id: str,
                           evidence: list[ThesisEvidence],
                           archetype: str | None) -> str:
        parts = [
            f"Target {target_id} presents a bounded attack surface with "
            "identifiable crown jewels"]
        archetype_text = (f"resembling the '{archetype}' archetype"
                          if archetype else "of uncategorized shape")
        parts.append(archetype_text)
        return (f"{parts[0]}, {archetype_text}. "
                f"Basis: {len(evidence)} weighted evidence pieces; the "
                "likely families below are ranked by derivation score.")

    def _compose_reasoning(self, evidence: list[ThesisEvidence],
                           likely: list[tuple[Family, float]],
                           confidence: float) -> str:
        ev_lines = "; ".join(
            f"{e.source}:{e.claim} (w={e.weight:.2f})" for e in evidence)
        fam_lines = ", ".join(f"{f.value}={p:.2f}" for f, p in likely)
        return (
            f"Confidence {confidence:.2f} is the weighted average of "
            f"{len(evidence)} evidence pieces plus archetype and "
            f"source-count bonuses. Evidence: {ev_lines}. Likely families "
            f"(normalized): {fam_lines}. Derivation is deterministic — "
            "no model call sits between the signals and this reasoning.")

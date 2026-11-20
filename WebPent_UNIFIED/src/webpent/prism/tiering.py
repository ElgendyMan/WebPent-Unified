"""THE PRISM — U-PRISM-4, the Multi-Signal Integrator (v89).

Combines several scored pieces of evidence into one integrated verdict.
Coherence rises with the number of independent signals of the same
evidence type, corroborated evidence earns a bonus, and conflicts
(an anomaly arguing against a direct or side-effect signal) apply a
penalty scaled by severity. Conflicts are resolved deterministically:
the higher-scored signal wins, ties break on the lower evidence hash —
and both sides are retained for audit (PRISM-L-4/L-9). The integrator
is advisory-only (PRISM-L-2).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from webpent.prism.errors import PrismLawError
from webpent.prism.scorer import ScoreResult
from webpent.prism.taxonomy import Corroboration, EvidenceProfile, EvidenceType

ACTIVE_TYPES = (EvidenceType.DIRECT, EvidenceType.SIDE_EFFECT)

COHERENCE_KEYS = ("three_or_more", "two", "one")

# numeric strength values for conflict severity, mirroring the taxonomy
# weights in one place so severity stays deterministic.
_STRENGTH_NUMBERS = {
    "decisive": 1.0,
    "strong": 0.8,
    "moderate": 0.55,
    "weak": 0.3,
    "negligible": 0.1,
}


@dataclass(frozen=True)
class IntegrationResult:
    integrated_score: float
    coherence: float
    corroboration_bonus: float
    conflict_penalty: float
    verdict: str
    conflicts: tuple[dict[str, Any], ...]
    signal_count: int
    mode: str = "advisory-only (PRISM-L-2)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "integrated_score": round(self.integrated_score, 6),
            "coherence": self.coherence,
            "corroboration_bonus": self.corroboration_bonus,
            "conflict_penalty": round(self.conflict_penalty, 6),
            "verdict": self.verdict,
            "conflicts": list(self.conflicts),
            "signal_count": self.signal_count,
            "mode": self.mode,
        }


class MultiSignalIntegrator:
    """Deterministic multi-signal integration (U-PRISM-4)."""

    def __init__(self, config_path: Path | str) -> None:
        path = Path(config_path)
        if not path.is_file():
            raise PrismLawError(
                f"integrator config not found: {path}", law="PRISM-L-4"
            )
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        integration = data.get("integration")
        if not isinstance(integration, dict) or not integration:
            raise PrismLawError(
                "integrator config: missing non-empty 'integration' block",
                law="PRISM-L-1",
            )
        coherence = integration.get("coherence")
        if not isinstance(coherence, dict) or set(coherence) != set(COHERENCE_KEYS):
            raise PrismLawError(
                f"integrator config: coherence must define {COHERENCE_KEYS}",
                law="PRISM-L-1",
            )
        bonus = integration.get("corroboration_bonus")
        if not isinstance(bonus, dict) or set(bonus) != {
            "independent_multiple", "corroborated"
        }:
            raise PrismLawError(
                "integrator config: corroboration_bonus must define "
                "independent_multiple and corroborated",
                law="PRISM-L-1",
            )
        thresholds = integration.get("verdict_thresholds")
        if not isinstance(thresholds, dict) or set(thresholds) != {
            "confirmed", "likely", "possible", "weak"
        }:
            raise PrismLawError(
                "integrator config: verdict_thresholds must define "
                "confirmed, likely, possible, weak",
                law="PRISM-L-1",
            )
        t_conf, t_likely, t_possible, t_weak = (
            float(thresholds["confirmed"]), float(thresholds["likely"]),
            float(thresholds["possible"]), float(thresholds["weak"]),
        )
        if not (t_conf >= t_likely >= t_possible >= t_weak):
            raise PrismLawError(
                "integrator config: verdict_thresholds must descend "
                "(confirmed >= likely >= possible >= weak)",
                law="PRISM-L-1",
            )
        weight = integration.get("conflict_severity_weight")
        if not isinstance(weight, (int, float)) or not 0.0 <= float(weight) <= 1.0:
            raise PrismLawError(
                "integrator config: conflict_severity_weight must be in [0, 1]",
                law="PRISM-L-1",
            )
        self._config = integration

    def _coherence(self, signals: Sequence[tuple[EvidenceProfile, ScoreResult]]) -> float:
        groups: dict[str, int] = {}
        for profile, _ in signals:
            groups[profile.evidence_type.value] = (
                groups.get(profile.evidence_type.value, 0) + 1
            )
        # largest group; ties break on the alphabetically first type name
        largest = max(
            sorted(groups.items()), key=lambda item: (item[1], item[0])
        )[1]
        coherence = self._config["coherence"]
        if largest >= 3:
            return float(coherence["three_or_more"])
        if largest == 2:
            return float(coherence["two"])
        return float(coherence["one"])

    def _corroboration_bonus(
        self, signals: Sequence[tuple[EvidenceProfile, ScoreResult]]
    ) -> float:
        bonus = self._config["corroboration_bonus"]
        corroborations = {p.corroboration for p, _ in signals}
        if Corroboration.INDEPENDENT_MULTIPLE in corroborations:
            return float(bonus["independent_multiple"])
        if Corroboration.CORROBORATED in corroborations:
            return float(bonus["corroborated"])
        return 0.0

    def _conflicts(
        self, signals: Sequence[tuple[EvidenceProfile, ScoreResult]]
    ) -> tuple[float, tuple[dict[str, Any], ...]]:
        anomalies = [(p, s) for p, s in signals if p.evidence_type is EvidenceType.ANOMALY]
        actives = [(p, s) for p, s in signals if p.evidence_type in ACTIVE_TYPES]
        if not anomalies or not actives:
            return 0.0, ()
        # A conflict is genuine disagreement (the docstring's semantics):
        # an anomaly whose score is strictly below the active signal it
        # pairs with — the indirect evidence argues against the verdict's
        # strength. A corroborating anomaly (score >= the active signal)
        # earns no penalty; agreeing signals must not be punished.
        pairs = [
            (a_score, act_score)
            for _ap, a_score, _pp, act_score in (
                (a_p, a_s, p_p, p_s)
                for a_p, a_s in anomalies
                for p_p, p_s in actives
            )
            if a_score.score < act_score.score
        ]
        if not pairs:
            return 0.0, ()
        severity = max(
            max(
                self._strength_value(p)
                for p, a_score in anomalies
                if any(a_score.score < act_score.score
                       for _p2, act_score in actives)
            ),
            max(
                self._strength_value(p)
                for p, act_score in actives
                if any(a_score.score < act_score.score
                       for _p1, a_score in anomalies)
            ),
        )
        penalty = float(self._config["conflict_severity_weight"]) * severity
        records: list[dict[str, Any]] = []
        for a_score, act_score in pairs:
            # deterministic resolution: the higher score wins; ties
            # break on the lexicographically lower evidence hash
            if act_score.score > a_score.score or (
                act_score.score == a_score.score
                and act_score.evidence_hash < a_score.evidence_hash
            ):
                winner, loser = act_score, a_score
            else:
                winner, loser = a_score, act_score
            records.append({
                "winner": winner.evidence_hash,
                "loser": loser.evidence_hash,
                "winner_score": round(winner.score, 6),
                "loser_score": round(loser.score, 6),
                "resolution": "higher-scored signal wins; both retained for audit",
            })
        return penalty, tuple(sorted(
            records, key=lambda r: (r["winner"], r["loser"])
        ))

    @staticmethod
    def _strength_value(profile: EvidenceProfile) -> float:
        return _STRENGTH_NUMBERS[profile.strength.value]

    def _verdict(self, score: float, has_active: bool) -> str:
        thresholds = self._config["verdict_thresholds"]
        if score >= float(thresholds["confirmed"]) and has_active:
            return "confirmed"
        if score >= float(thresholds["likely"]):
            return "likely"
        if score >= float(thresholds["possible"]):
            return "possible"
        if score >= float(thresholds["weak"]):
            return "weak"
        return "noise"

    def integrate(
        self, signals: Sequence[tuple[EvidenceProfile, ScoreResult]]
    ) -> IntegrationResult:
        if not signals:
            raise PrismLawError(
                "cannot integrate zero signals", law="PRISM-L-4"
            )
        base = sum(s.score for _, s in signals) / len(signals)
        coherence = self._coherence(signals)
        bonus = self._corroboration_bonus(signals)
        penalty, conflict_records = self._conflicts(signals)
        integrated = min(1.0, max(0.0, base * coherence + bonus - penalty))
        has_active = any(p.evidence_type in ACTIVE_TYPES for p, _ in signals)
        return IntegrationResult(
            integrated_score=integrated,
            coherence=coherence,
            corroboration_bonus=bonus,
            conflict_penalty=penalty,
            verdict=self._verdict(integrated, has_active),
            conflicts=conflict_records,
            signal_count=len(signals),
        )


__all__ = ["IntegrationResult", "MultiSignalIntegrator", "ACTIVE_TYPES"]

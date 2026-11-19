# src/webpent/causal_reasoning_v2/structural_knowledge_base.py
"""StructuralKnowledgeBase — Deep-fix Phase 3.

A GLOBAL, cross-engagement library of architectural flaw patterns that
accumulates and self-corrects over time.  Fixes three v1/v2 flaws:

  1. Transfers FULL STRUCTURAL PATTERNS (not just route lists) — a pattern
     carries its structural signature, detection indicators, and fix hint.
  2. Bayesian confidence with per-component weight refinement: on a failed
     prediction, ONLY the component that caused the error is down-weighted,
     not the whole pattern (fixes "blind global confidence drop").
  3. Dynamic acceptance thresholds: critical targets use 0.9, exploratory
     targets use 0.6.  No one-size-fits-all 0.75.

Persistence: single JSON file, atomic writes, corruption-tolerant.
No secrets stored — signatures are structural (canonical AST prefixes) and
route globs, never credentials or raw URLs.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

DEFAULT_PATH = Path.home() / ".webpent" / "structural_kb" / "patterns.json"

# Three independent confidence components.  Each is refined separately on
# prediction outcomes, so a structural mismatch does not penalise the
# historical-success component and vice versa.
_COMPONENTS = ("structural_match", "historical_success", "relevance")


@dataclass
class ArchitecturalPattern:
    pattern_id: str
    cause_type: str
    structural_signature: str          # canonical AST prefix or shared-dep name
    description: str
    fix_hint: str = ""
    total_observations: int = 0
    confirmed_count: int = 0
    affected_route_globs: tuple[str, ...] = ()
    # Per-component weights, each in (0, 2].  Start neutral at 1.0.
    component_weights: dict[str, float] = field(default_factory=lambda: {c: 1.0 for c in _COMPONENTS})
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def bayes_confidence(self) -> float:
        """Beta(confirmed+1, total+2) mean — smoothed, never 0 or 1."""
        return (self.confirmed_count + 1) / (self.total_observations + 2)

    def effective_score(self, structural_match: float = 1.0, relevance: float = 1.0) -> float:
        """Combined score = bayes_confidence × weighted components."""
        w = self.component_weights
        comp = (
            min(1.0, structural_match) * w.get("structural_match", 1.0) * 0.4
            + self.bayes_confidence * w.get("historical_success", 1.0) * 0.4
            + min(1.0, relevance) * w.get("relevance", 1.0) * 0.2
        )
        return round(min(1.0, max(0.0, comp)), 4)


class StructuralKnowledgeBase:
    """Global pattern library with bayesian confidence + per-component refinement."""

    STRUCTURAL_MATCH_THRESHOLD = 0.85

    def __init__(self, storage_path: str | Path = DEFAULT_PATH):
        self.storage = Path(storage_path)
        self.storage.parent.mkdir(parents=True, exist_ok=True)
        self.patterns: dict[str, ArchitecturalPattern] = {}
        self._load()

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------
    def add_observation(
        self,
        *,
        structural_signature: str,
        cause_type: str,
        confirmed: bool,
        project_id: str,
        description: str = "",
        fix_hint: str = "",
        route_globs: Iterable[str] = (),
        failed_component: str | None = None,
    ) -> str:
        """Record one observation.  Matches existing pattern structurally.

        On a refuted prediction, pass failed_component to down-weight ONLY
        that component (structural_match | historical_success | relevance).
        On confirmation, the relevant component is up-weighted slightly.
        """
        signature = str(structural_signature)[:256]
        cause = str(cause_type)[:80]
        pattern = self._match_pattern(signature, cause)
        if pattern is None:
            pid = f"pat_{cause}_{abs(hash(signature)) % 10**10}"
            pattern = ArchitecturalPattern(
                pattern_id=pid, cause_type=cause, structural_signature=signature,
                description=description[:500], fix_hint=fix_hint[:500],
            )
            self.patterns[pid] = pattern

        pattern.total_observations += 1
        if confirmed:
            pattern.confirmed_count += 1
            # Up-weight: on success, boost all components slightly (capped at 2.0).
            for c in _COMPONENTS:
                pattern.component_weights[c] = min(2.0, pattern.component_weights.get(c, 1.0) * 1.05)
        else:
            # Down-weight ONLY the failed component; others untouched.
            if failed_component in _COMPONENTS:
                pattern.component_weights[failed_component] = max(
                    0.1, pattern.component_weights.get(failed_component, 1.0) * 0.90,
                )
            else:
                # Unknown failure cause: small penalty on all, capped.
                for c in _COMPONENTS:
                    pattern.component_weights[c] = max(0.5, pattern.component_weights.get(c, 1.0) * 0.97)
        globs = tuple(sorted({str(g)[:240] for g in route_globs if g}))
        if globs:
            pattern.affected_route_globs = tuple(sorted(set(pattern.affected_route_globs) | set(globs)))[:32]
        pattern.last_updated_at = datetime.now(UTC).isoformat()
        self._save()
        return pattern.pattern_id

    # ------------------------------------------------------------------
    # Read path — query for a new target
    # ------------------------------------------------------------------
    def query_for_target(
        self,
        *,
        target_profile: Mapping[str, Any] | None = None,
        structural_signatures: Iterable[str] = (),
        top_k: int = 8,
        confidence_threshold: float | None = None,
    ) -> list[dict[str, Any]]:
        """Return patterns applicable to a new target, above dynamic threshold.

        Threshold is dynamic: critical/high-value target -> 0.9; exploratory
        -> 0.6; default 0.75.  Override with confidence_threshold.
        """
        profile = dict(target_profile or {})
        if confidence_threshold is None:
            critical = bool(profile.get("critical") or profile.get("high_value") or profile.get("production"))
            exploratory = bool(profile.get("exploratory") or profile.get("research"))
            confidence_threshold = 0.9 if critical else (0.6 if exploratory else 0.75)

        sigs = list(structural_signatures)
        results: list[dict[str, Any]] = []
        for pat in self.patterns.values():
            # Structural match: max overlap with any target signature.
            if sigs:
                struct_match = max(
                    (self._structural_overlap(pat.structural_signature, s) for s in sigs), default=0.0
                )
                if struct_match < self.STRUCTURAL_MATCH_THRESHOLD:
                    continue  # not structurally relevant to this target
                relevance = struct_match
            else:
                # No target signatures provided: be neutral — structural_match
                # and relevance default to the pattern's own bayes confidence,
                # never to 1.0 (which would inflate scores above threshold).
                struct_match = pat.bayes_confidence
                relevance = pat.bayes_confidence
            score = pat.effective_score(structural_match=struct_match, relevance=relevance)
            if score < confidence_threshold:
                continue  # hard gate — never surface below threshold
            results.append({
                "pattern_id": pat.pattern_id,
                "cause_type": pat.cause_type,
                "description": pat.description,
                "fix_hint": pat.fix_hint,
                "bayes_confidence": round(pat.bayes_confidence, 4),
                "effective_score": score,
                "route_globs": list(pat.affected_route_globs),
                "total_observations": pat.total_observations,
                "confirmed_count": pat.confirmed_count,
                "component_weights": dict(pat.component_weights),
            })
        results.sort(key=lambda r: r["effective_score"], reverse=True)
        return results[: max(1, int(top_k))]

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        total = len(self.patterns)
        above = sum(1 for p in self.patterns.values() if p.bayes_confidence >= 0.75)
        return {
            "pattern_count": total,
            "patterns_above_075": above,
            "patterns_below_threshold_internal_only": total - above,
            "total_observations": sum(p.total_observations for p in self.patterns.values()),
            "total_confirmed": sum(p.confirmed_count for p in self.patterns.values()),
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _match_pattern(self, signature: str, cause_type: str) -> ArchitecturalPattern | None:
        for p in self.patterns.values():
            if p.cause_type == cause_type and self._structural_overlap(p.structural_signature, signature) >= 0.85:
                return p
        return None

    @staticmethod
    def _structural_overlap(a: str, b: str) -> float:
        """Token-set Jaccard on the structural signature strings."""
        ta, tb = set(a.split()), set(b.split())
        if not ta and not tb:
            return 1.0 if a == b else 0.0
        union = ta | tb
        if not union:
            return 0.0
        return len(ta & tb) / len(union)

    def _save(self) -> None:
        data = {pid: asdict(p) for pid, p in self.patterns.items()}
        tmp = self.storage.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, sort_keys=True, indent=2), encoding="utf-8")
        os.replace(tmp, self.storage)

    def _load(self) -> None:
        if not self.storage.exists():
            return
        try:
            data = json.loads(self.storage.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        for pid, row in data.items():
            try:
                self.patterns[pid] = ArchitecturalPattern(
                    pattern_id=row["pattern_id"],
                    cause_type=row["cause_type"],
                    structural_signature=row["structural_signature"],
                    description=row.get("description", ""),
                    fix_hint=row.get("fix_hint", ""),
                    total_observations=int(row.get("total_observations", 0)),
                    confirmed_count=int(row.get("confirmed_count", 0)),
                    affected_route_globs=tuple(row.get("affected_route_globs", [])),
                    component_weights={c: float(row.get("component_weights", {}).get(c, 1.0)) for c in _COMPONENTS},
                    created_at=row.get("created_at", ""),
                    last_updated_at=row.get("last_updated_at", ""),
                )
            except (KeyError, ValueError, TypeError):
                continue  # skip corrupt rows, never crash


__all__ = ["StructuralKnowledgeBase", "ArchitecturalPattern"]

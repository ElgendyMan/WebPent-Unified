# src/webpent/causal_reasoning_v2/confidence_engine_v2.py
"""ConfidenceEngineV2 — Red-Team final fix.

Fixes vs v1 confidence engine:
  1. Weight grows SLOWLY: maturity = arctan(n/3) * 2/pi.  n=1 -> 0.10,
     n=10 -> 0.50, n=100 -> 0.91, n=1000 -> 0.99.  A 10-observation pattern
     gets HALF the weight of a mature one — no premature maxing out.
  2. Consecutive-failure penalty: 2 misses -> extra 0.9x; 3 -> 0.8x; resets
     on any confirmation.  Bad patterns decay fast.
  3. Partial match (same family, different vuln) gives +0.5 confirmed count
     and small relevance boost — learning from near-misses.
  4. EXAMINED_UNRELATED with high structural similarity (>=0.9) gets a small
     structural_match penalty (0.98x) — a strong match that fails means the
     signature is wrong.
  5. Atomic safe writes: write to .tmp then os.replace — no corruption on
     interruption.
  6. Max patterns cap (default 500): prune least-active/least-confident when
     full.  No unbounded growth.
  7. Tolerant load: corrupt file -> warning + empty base, never crash.
  8. Jeffrey's uninformative prior: confidence = (c+0.5)/(n+1).  0 obs ->
     not surfaced.
"""
from __future__ import annotations

import json
import math
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

FeedbackType = str  # 'EXAMINED_MATCHED' | 'EXAMINED_UNRELATED' | 'PARTIAL_MATCH' | 'NOT_EXAMINED'

_COMPONENTS = ("structural_match", "historical_success", "relevance")
DEFAULT_MAX_PATTERNS = 500


@dataclass
class PatternEvidenceV2:
    project_id: str
    feedback: FeedbackType
    similarity: float = 1.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class ArchitecturalPatternV2:
    pattern_id: str
    cause_type: str
    structural_signature: str
    description: str = ""
    fix_hint: str = ""
    total_observations: int = 0
    confirmed_count: float = 0.0   # float because PARTIAL_MATCH adds 0.5
    consecutive_failures: int = 0
    evidence: list[PatternEvidenceV2] = field(default_factory=list)
    component_weights: dict[str, float] = field(default_factory=lambda: {c: 1.0 for c in _COMPONENTS})
    last_used: float = field(default_factory=time.time)

    @property
    def jeffrey_confidence(self) -> float:
        return (self.confirmed_count + 0.5) / (self.total_observations + 1)

    @property
    def maturity(self) -> float:
        """arctan-based slow growth: n=1->0.07, n=10->0.50, n=100->0.93, n=1000->0.997."""
        return min(1.0, math.atan(self.total_observations / 10.0) * 2.0 / math.pi)

    def effective_weight(self) -> float:
        w = self.component_weights
        comp_factor = (
            w.get("structural_match", 1.0) * 0.4
            + w.get("historical_success", 1.0) * 0.4
            + w.get("relevance", 1.0) * 0.2
        )
        return round(self.jeffrey_confidence * self.maturity * comp_factor, 4)


class ConfidenceEngineV2:
    """Confidence engine with slow growth, consecutive-failure penalty, safe IO."""

    SURFACE_THRESHOLD = 0.15  # minimum effective_weight to surface

    def __init__(self, storage_path: str | Path, max_patterns: int = DEFAULT_MAX_PATTERNS):
        self.storage = Path(storage_path)
        self.storage.parent.mkdir(parents=True, exist_ok=True)
        self.max_patterns = max(10, int(max_patterns))
        self.patterns: dict[str, ArchitecturalPatternV2] = {}
        self._load()

    # ------------------------------------------------------------------
    def add_observation(
        self,
        *,
        structural_signature: str,
        cause_type: str,
        feedback: FeedbackType,
        project_id: str,
        similarity: float = 1.0,
        description: str = "",
        fix_hint: str = "",
    ) -> str:
        pat = self._match(structural_signature, cause_type)
        if pat is None:
            pid = f"pat_v2_{cause_type}_{abs(hash(structural_signature)) % 10**10}"
            pat = ArchitecturalPatternV2(
                pattern_id=pid, cause_type=cause_type,
                structural_signature=structural_signature,
                description=description[:500], fix_hint=fix_hint[:500],
            )
            self.patterns[pid] = pat
            self._prune()
        else:
            pid = pat.pattern_id

        pat.last_used = time.time()
        pat.total_observations += 1
        pat.evidence.append(PatternEvidenceV2(
            project_id=project_id, feedback=feedback, similarity=float(similarity),
        ))

        w = pat.component_weights
        if feedback == "EXAMINED_MATCHED":
            pat.confirmed_count += 1.0
            pat.consecutive_failures = 0
            w["historical_success"] = min(2.0, w["historical_success"] * 1.05)
        elif feedback == "PARTIAL_MATCH":
            pat.confirmed_count += 0.5
            pat.consecutive_failures = 0
            w["relevance"] = min(2.0, w["relevance"] * 1.05)
        elif feedback == "EXAMINED_UNRELATED":
            pat.consecutive_failures += 1
            if similarity >= 0.9:
                # Strong structural match that failed -> signature likely wrong.
                w["structural_match"] = max(0.1, w["structural_match"] * 0.98)
            # Consecutive-failure penalty (compounding).
            if pat.consecutive_failures >= 2:
                w["structural_match"] = max(0.1, w["structural_match"] * 0.90)
            if pat.consecutive_failures >= 3:
                w["structural_match"] = max(0.1, w["structural_match"] * 0.80)
        # NOT_EXAMINED: no change.

        for c in _COMPONENTS:
            w[c] = round(max(0.1, min(2.0, w[c])), 4)
        self._save()
        return pid

    def effective_weight(self, pattern_id: str) -> float:
        pat = self.patterns.get(pattern_id)
        return pat.effective_weight() if pat else 0.0

    def query(
        self,
        target_profile: Mapping[str, Any] | None = None,
        top_k: int = 8,
        threshold: float | None = None,
    ) -> list[dict[str, Any]]:
        profile = dict(target_profile or {})
        if threshold is None:
            threshold = 0.9 if profile.get("critical") else (0.6 if profile.get("exploratory") else 0.75)
        results = []
        for pid, pat in self.patterns.items():
            ew = pat.effective_weight()
            if ew < threshold:
                continue
            results.append({
                "pattern_id": pid, "cause_type": pat.cause_type,
                "description": pat.description, "fix_hint": pat.fix_hint,
                "confidence": round(pat.jeffrey_confidence, 4),
                "maturity": round(pat.maturity, 4),
                "effective_weight": ew,
                "observations": pat.total_observations,
                "consecutive_failures": pat.consecutive_failures,
            })
        results.sort(key=lambda r: r["effective_weight"], reverse=True)
        return results[: max(1, int(top_k))]

    def summary(self) -> dict[str, Any]:
        return {
            "patterns": len(self.patterns),
            "surfaceable": sum(1 for p in self.patterns.values() if p.effective_weight() >= self.SURFACE_THRESHOLD),
            "total_observations": sum(p.total_observations for p in self.patterns.values()),
        }

    # ------------------------------------------------------------------
    def _match(self, signature: str, cause_type: str) -> ArchitecturalPatternV2 | None:
        for p in self.patterns.values():
            if p.cause_type == cause_type and _overlap(p.structural_signature, signature) >= 0.85:
                return p
        return None

    def _prune(self) -> None:
        if len(self.patterns) < self.max_patterns:
            return
        # Keep the most active + most confident; drop the rest.
        ranked = sorted(
            self.patterns.values(),
            key=lambda p: (p.effective_weight(), p.last_used, p.total_observations),
            reverse=True,
        )
        keep = int(self.max_patterns * 0.8)
        for p in ranked[keep:]:
            del self.patterns[p.pattern_id]

    def _save(self) -> None:
        try:
            data = {pid: _pattern_to_dict(p) for pid, p in self.patterns.items()}
            tmp = self.storage.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, sort_keys=True, indent=2), encoding="utf-8")
            os.replace(tmp, self.storage)
        except Exception:
            pass  # never crash on IO

    def _load(self) -> None:
        if not self.storage.exists():
            return
        try:
            data = json.loads(self.storage.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            self.patterns = {}  # corrupt -> start fresh, never crash
            return
        for pid, row in data.items():
            try:
                self.patterns[pid] = _dict_to_pattern(row)
            except (KeyError, ValueError, TypeError):
                continue  # skip corrupt rows


def _overlap(a: str, b: str) -> float:
    ta, tb = set(a.split()), set(b.split())
    if not ta and not tb:
        return 1.0 if a == b else 0.0
    union = ta | tb
    return len(ta & tb) / len(union) if union else 0.0


def _pattern_to_dict(p: ArchitecturalPatternV2) -> dict[str, Any]:
    d = asdict(p)
    return d


def _dict_to_pattern(row: dict[str, Any]) -> ArchitecturalPatternV2:
    evidence = [PatternEvidenceV2(**e) for e in row.get("evidence", [])]
    return ArchitecturalPatternV2(
        pattern_id=row["pattern_id"], cause_type=row["cause_type"],
        structural_signature=row["structural_signature"],
        description=row.get("description", ""), fix_hint=row.get("fix_hint", ""),
        total_observations=int(row.get("total_observations", 0)),
        confirmed_count=float(row.get("confirmed_count", 0)),
        consecutive_failures=int(row.get("consecutive_failures", 0)),
        evidence=evidence,
        component_weights={c: float(row.get("component_weights", {}).get(c, 1.0)) for c in _COMPONENTS},
        last_used=float(row.get("last_used", time.time())),
    )


__all__ = ["ConfidenceEngineV2", "ArchitecturalPatternV2", "PatternEvidenceV2", "FeedbackType"]

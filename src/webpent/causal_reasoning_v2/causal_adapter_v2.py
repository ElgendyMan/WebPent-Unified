# src/webpent/causal_reasoning_v2/causal_adapter_v2.py
"""CausalAdapterV2 — Red-Team final fix.

Fixes vs v1 adapter:
  1. Strict TYPE validation, not just field presence.  Every emitted dict's
     values are checked against expected types.  Wrong-type entries pass
     through UNMODIFIED (never silently corrupted).
  2. Clean disable via WEBPENT_CAUSAL_V2_DISABLED env var — returns base
     candidates unchanged, byte-for-byte.
  3. Precise feedback classification:
       examined + finding + high similarity -> EXAMINED_MATCHED
       examined + finding + low similarity  -> PARTIAL_MATCH
       examined + no finding                -> EXAMINED_UNRELATED
       not examined                          -> NOT_EXAMINED (no confidence change)
  4. Pending-hint tracking: every recommendation stays in the queue until
     explicitly resolved.  No silent removal.
  5. Fail-safe: any exception returns base candidates unchanged.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from webpent.causal_reasoning_v2.confidence_engine_v2 import ConfidenceEngineV2

DISABLE_FLAG = "WEBPENT_CAUSAL_V2_DISABLED"

# Strict type schemas.  A candidate must match these to be modified.
_CANDIDATE_SCHEMA = {
    "endpoint": (str,),
    "priority": (int, float),
}
_PRIORITY_CAP = 1.0


@dataclass
class _PendingHint:
    endpoint: str
    pattern_id: str | None
    base_priority: float
    causal_boost: float
    examined: bool = False
    found: bool = False
    resolved_at: float | None = None


class CausalAdapterV2:
    """Strict-typed, clean-disable, precise-feedback adapter."""

    def __init__(self, confidence_engine: ConfidenceEngineV2 | None = None):
        self.engine = confidence_engine
        self.disabled = os.environ.get(DISABLE_FLAG, "").strip() in ("1", "true", "yes")
        self._pending: dict[str, _PendingHint] = {}
        self._failures: list[str] = []

    def is_enabled(self) -> bool:
        return not self.disabled

    # ------------------------------------------------------------------
    def generate_priorities(
        self,
        base_candidates: Iterable[Mapping[str, Any]],
        target_profile: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Merge causal recommendations.  Returns NEW dicts; base is untouched.
        On disable or any error, returns base candidates unchanged."""
        base = [dict(c) for c in base_candidates]
        if self.disabled or self.engine is None:
            return base
        try:
            return self._generate(base, dict(target_profile or {}))
        except Exception as e:
            self._failures.append(f"generate:{type(e).__name__}")
            return base  # fail-safe: unchanged

    def _generate(self, base: list[dict[str, Any]], profile: dict[str, Any]) -> list[dict[str, Any]]:
        patterns = self.engine.query(profile) if self.engine else []
        scored: list[dict[str, Any]] = []
        for c in base:
            # Strict type check — only modify if schema-compliant.
            if not _matches_schema(c, _CANDIDATE_SCHEMA):
                scored.append(c)
                continue
            route = str(c["endpoint"])
            base_prio = float(c["priority"])
            boost = 0.0
            matched_pid: str | None = None
            for pat in patterns:
                # Simple route-glob match on cause_type-derived prefix.
                if _route_match(pat.get("cause_type", ""), route):
                    if pat["effective_weight"] > boost:
                        boost = pat["effective_weight"]
                        matched_pid = pat["pattern_id"]
            final_prio = min(_PRIORITY_CAP, base_prio * 0.6 + boost * 0.4)
            entry = dict(c)
            entry["priority"] = round(final_prio, 4)
            entry["reasoning"] = (
                f"causal pattern {matched_pid} weight={boost:.3f}" if matched_pid else "direct scan"
            )
            entry["source"] = "causal_inference" if matched_pid else "direct_scan"
            scored.append(entry)
            if matched_pid:
                self._pending[route] = _PendingHint(
                    endpoint=route, pattern_id=matched_pid,
                    base_priority=base_prio, causal_boost=boost,
                )
        scored.sort(key=lambda x: float(x.get("priority", 0)), reverse=True)
        return scored

    # ------------------------------------------------------------------
    def submit_feedback(
        self,
        endpoint: str,
        examined: bool,
        finding: Mapping[str, Any] | None = None,
        similarity: float = 1.0,
    ) -> None:
        """Classify feedback precisely and update engine.  Never raises."""
        try:
            hint = self._pending.get(endpoint)
            if hint is None:
                return
            hint.examined = bool(examined)
            hint.found = finding is not None
            hint.resolved_at = time.time()
            if not examined:
                ftype = "NOT_EXAMINED"
            elif finding and similarity >= 0.85:
                ftype = "EXAMINED_MATCHED"
            elif finding:
                ftype = "PARTIAL_MATCH"
            else:
                ftype = "EXAMINED_UNRELATED"
            if self.engine and hint.pattern_id and ftype != "NOT_EXAMINED":
                pat = self.engine.patterns.get(hint.pattern_id)
                if pat:
                    self.engine.add_observation(
                        structural_signature=pat.structural_signature,
                        cause_type=pat.cause_type,
                        feedback=ftype,
                        project_id="current",
                        similarity=float(similarity),
                        description=pat.description,
                    )
        except Exception:
            pass  # feedback must never break the pipeline

    # ------------------------------------------------------------------
    def pending_count(self) -> int:
        return sum(1 for h in self._pending.values() if not h.examined)

    @property
    def failures(self) -> tuple[str, ...]:
        return tuple(self._failures)


def _matches_schema(d: Mapping[str, Any], schema: dict[str, tuple]) -> bool:
    # P2-10 (0.33.0): the loop variable shadowed the dataclasses/attr `field`
    # import (ruff F402) — renamed so a future import of `field` cannot
    # silently break this schema matcher.
    for fname, types in schema.items():
        if fname not in d:
            return False
        if not isinstance(d[fname], types):
            return False
    return True


def _route_match(cause_type: str, route: str) -> bool:
    """Deterministic route match — cause_type prefix vs route segments."""
    if not cause_type or not route:
        return False
    # Simple: if any word of cause_type appears in route, or route starts with
    # a slug derived from cause_type.
    words = cause_type.replace("_", " ").split()
    return any(w in route.lower() for w in words if len(w) > 3)


__all__ = ["CausalAdapterV2", "DISABLE_FLAG"]

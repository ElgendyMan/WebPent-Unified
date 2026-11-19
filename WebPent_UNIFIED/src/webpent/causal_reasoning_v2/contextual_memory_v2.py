# src/webpent/causal_reasoning_v2/contextual_memory_v2.py
"""ContextualMemoryV2 — Phase 2 fix.

Two-layer model replacing v1's single-layer fingerprint store:

  Layer 1 — OBSERVATION STORE (immutable, raw, no interpretation).
      Records exactly what was seen: behavior profile + which causal labels
      were confirmed + on which structural segments.  Never edited.

  Layer 2 — INFERENCE STORE (derived, statistical, self-correcting).
      Patterns of the form "behavior profile P -> causal label L with
      confidence C", where C is computed STATISTICALLY:
          support     = count(engagements with P that confirmed L)
                        / count(engagements with P)
          consistency = 1 - variance across sub-samples
          confidence  = support * consistency * (1 - 2^(-n))   [n = sample size]
      Predictions are tracked: when the engine suggests a pattern and it is
      later confirmed/refuted in the current engagement, a Bayesian update
      adjusts the pattern's confidence.  Patterns below the acceptance
      threshold (default 0.75) are NEVER surfaced to the planner — they
      remain internal as low-confidence hypotheses only.

Behavior similarity is computed on BEHAVIORAL attributes (auth flow type,
verification placement, error handling style, data binding style, session
management) — NOT on framework names.  Two targets built on different
frameworks but with identical behavioral architecture receive high
similarity; two targets on the same framework with different architectures
receive low similarity.  This fixes v1's "same name != same weakness"
generalisation error.
"""
from __future__ import annotations

import json
import math
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

# ---------------------------------------------------------------------------
# Behavior profile — behavioral attributes only, no framework names
# ---------------------------------------------------------------------------

_BEHAVIOR_FIELDS = (
    "auth_flow_type",        # stateless_token | stateful_session | oauth_redirect | api_key | none
    "verification_placement",  # edge_middleware | per_handler_decorator | inline_in_handler | absent
    "error_handling_style",  # global_handler_verbose | global_handler_generic | per_try_catch | blank_200
    "data_binding_style",    # explicit_dto | auto_bind_all_fields | schema_validated | manual_parse
    "session_management",    # server_side_rotating | signed_cookie | jwt_stateless | none
    "object_resolution",     # shared_scoped_resolver | per_route_direct_lookup | orm_global_queryset
    "input_validation",      # shared_contract_layer | per_route_checks | absent
    "query_construction",    # parameterised_orm | string_concat | mixed
)
# Behavioral weights — how strongly each attribute correlates with weakness
# patterns (derived from security literature, fixed and documented).
_BEHAVIOR_WEIGHTS = {
    "verification_placement": 0.22,
    "object_resolution": 0.20,
    "input_validation": 0.16,
    "data_binding_style": 0.14,
    "auth_flow_type": 0.12,
    "session_management": 0.08,
    "error_handling_style": 0.05,
    "query_construction": 0.03,
}
assert abs(sum(_BEHAVIOR_WEIGHTS.values()) - 1.0) < 1e-9


@dataclass(frozen=True)
class BehaviorProfile:
    """Behavioral fingerprint.  All fields are closed-vocabulary strings."""
    profile_id: str
    engagement_id: str
    values: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Normalise: only known fields, lowercased, bounded.
        clean = {}
        for f in _BEHAVIOR_FIELDS:
            v = str(self.values.get(f, "unknown")).strip().lower()[:60]
            clean[f] = v if v else "unknown"
        object.__setattr__(self, "values", clean)

    def similarity(self, other: "BehaviorProfile") -> float:
        """Weighted match on behavioral attributes.  Deterministic [0,1]."""
        if not isinstance(other, BehaviorProfile):
            return 0.0
        score = 0.0
        for f, w in _BEHAVIOR_WEIGHTS.items():
            a, b = self.values.get(f, "unknown"), other.values.get(f, "unknown")
            if a == "unknown" and b == "unknown":
                continue  # neither side knows — don't penalise
            if a == b:
                score += w
        return round(score, 4)

    def digest(self) -> str:
        import hashlib
        payload = json.dumps(self.values, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()[:24]


# ---------------------------------------------------------------------------
# Inference pattern — statistically scored, self-correcting
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InferencePattern:
    """behavior-profile digest -> causal label, with statistical confidence."""
    pattern_id: str
    behavior_digest: str
    causal_label: str
    typical_segments: tuple[str, ...]       # structural segment signatures
    support: float                          # 0..1
    consistency: float                      # 0..1
    sample_size: int
    confidence: float                       # support * consistency * finite-sample factor
    confirmed_hits: int = 0
    refuted_hits: int = 0

    @property
    def bayes_strength(self) -> float:
        """Self-correction multiplier.

        Neutral (1.0) when no prediction outcomes have been recorded — the
        statistical confidence stands unmodified.  Once outcomes exist, this
        becomes the empirical confirmation rate confirmed/(confirmed+refuted),
        so refuted patterns decay and eventually fall below the acceptance
        threshold.  Never below 0, never above 1.
        """
        total = self.confirmed_hits + self.refuted_hits
        if total == 0:
            return 1.0
        return self.confirmed_hits / total

    def effective_confidence(self) -> float:
        """Confidence after self-correction.  Never below 0, never above 1."""
        return round(min(1.0, self.confidence * self.bayes_strength), 4)


@dataclass
class TransferredInsight:
    """A surfaced insight — always above the acceptance threshold."""
    pattern_id: str
    causal_label: str
    typical_segments: tuple[str, ...]
    confidence: float
    source_engagement_ids: tuple[str, ...]
    sample_size: int


# ---------------------------------------------------------------------------
# Two-layer memory
# ---------------------------------------------------------------------------

DEFAULT_DIR = Path.home() / ".webpent" / "causal_memory_v2"


class ContextualMemoryV2:
    """Two-layer contextual memory with statistical confidence + self-correction."""

    def __init__(self, memory_dir: Path = DEFAULT_DIR, acceptance_threshold: float = 0.75):
        self.memory_dir = Path(memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.acceptance_threshold = float(acceptance_threshold)
        self._obs_path = self.memory_dir / "observations.jsonl"
        self._inf_path = self.memory_dir / "inferences.json"
        self._observations: list[dict[str, Any]] = self._load_observations()
        self._inferences: dict[str, InferencePattern] = self._load_inferences()
        # Pending predictions for the current engagement (for self-correction).
        self._pending_predictions: dict[str, str] = {}  # suggestion_key -> pattern_id

    # ------------------------------------------------------------------
    # Layer 1 — observation recording (immutable append)
    # ------------------------------------------------------------------
    def record_observation(
        self,
        profile: BehaviorProfile,
        *,
        confirmed_causal_labels: Mapping[str, Iterable[str]],  # label -> structural segments
        total_findings: int = 0,
    ) -> None:
        """Append one immutable observation.  Then re-derive inferences."""
        obs = {
            "observed_at": datetime.now(UTC).isoformat(),
            "engagement_id": profile.engagement_id,
            "behavior_digest": profile.digest(),
            "behavior_values": profile.values,
            "confirmed_labels": {
                str(k): sorted({str(s)[:120] for s in v}) for k, v in confirmed_causal_labels.items()
            },
            "total_findings": max(0, int(total_findings)),
        }
        self._observations.append(obs)
        self._flush_observations()
        self._rederive_inferences()

    # ------------------------------------------------------------------
    # Layer 2 — inference derivation (statistical)
    # ------------------------------------------------------------------
    def _rederive_inferences(self) -> None:
        """Recompute all inference patterns from the observation store.

        For each (behavior_digest, causal_label) pair:
          n        = number of engagements with that behavior digest
          k        = number that confirmed the label
          support  = k / n
          consistency = 1 - (variance of k across time-sorted sub-batches)
          confidence = support * consistency * (1 - 2**(-n))
        Preserves confirmed/refuted hit counts for self-correction.
        """
        by_digest: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for obs in self._observations:
            by_digest[obs["behavior_digest"]].append(obs)

        new_inferences: dict[str, InferencePattern] = {}
        for digest, obs_list in by_digest.items():
            n = len(obs_list)
            # collect label -> segment sets
            label_segments: dict[str, set[str]] = defaultdict(set)
            label_counts: dict[str, int] = defaultdict(int)
            for obs in obs_list:
                for label, segs in obs.get("confirmed_labels", {}).items():
                    label_counts[label] += 1
                    label_segments[label].update(segs)
            for label, k in label_counts.items():
                support = k / n
                # consistency: split observations into up-to-3 time-sorted
                # sub-batches, compute variance of per-batch support.
                batches = self._split_batches(obs_list, label)
                if len(batches) > 1:
                    mean = sum(batches) / len(batches)
                    var = sum((b - mean) ** 2 for b in batches) / len(batches)
                    consistency = max(0.0, 1.0 - math.sqrt(var))
                else:
                    consistency = 1.0
                finite_sample = 1.0 - (2.0 ** (-n))
                confidence = support * consistency * finite_sample
                pid = f"pat:{digest}:{label}"
                prev = self._inferences.get(pid)
                new_inferences[pid] = InferencePattern(
                    pattern_id=pid, behavior_digest=digest, causal_label=label,
                    typical_segments=tuple(sorted(label_segments[label]))[:16],
                    support=round(support, 4), consistency=round(consistency, 4),
                    sample_size=n, confidence=round(confidence, 4),
                    confirmed_hits=prev.confirmed_hits if prev else 0,
                    refuted_hits=prev.refuted_hits if prev else 0,
                )
        self._inferences = new_inferences
        self._flush_inferences()

    @staticmethod
    def _split_batches(obs_list: list[dict[str, Any]], label: str) -> list[float]:
        n = len(obs_list)
        if n < 2:
            return [1.0 if label in obs_list[0].get("confirmed_labels", {}) else 0.0]
        size = max(1, n // 3)
        batches: list[float] = []
        for i in range(0, n, size):
            chunk = obs_list[i:i + size]
            if not chunk:
                continue
            hits = sum(1 for o in chunk if label in o.get("confirmed_labels", {}))
            batches.append(hits / len(chunk))
        return batches

    # ------------------------------------------------------------------
    # Knowledge transfer — only surface patterns above threshold
    # ------------------------------------------------------------------
    def transfer_insights(
        self,
        profile: BehaviorProfile,
        *,
        similarity_floor: float = 0.6,
    ) -> list[TransferredInsight]:
        """Return insights from behaviorally analogous past engagements.

        A pattern is surfaced ONLY if:
          (a) its behavior digest is similar to the target (>= floor) OR
              identical, AND
          (b) its effective_confidence >= acceptance_threshold (default 0.75).
        Low-confidence patterns are NEVER returned — they stay internal.
        """
        candidates: list[tuple[float, InferencePattern, list[str]]] = []
        for pid, pat in self._inferences.items():
            # Find observations with this digest to compute similarity to target.
            digest_profiles = self._profiles_for_digest(pat.behavior_digest)
            best_sim = max((profile.similarity(p) for p in digest_profiles), default=0.0)
            if best_sim < similarity_floor:
                continue
            eff_conf = pat.effective_confidence()
            if eff_conf < self.acceptance_threshold:
                continue  # hard gate: no low-confidence suggestions
            source_ids = sorted({o["engagement_id"] for o in self._observations
                                 if o["behavior_digest"] == pat.behavior_digest})
            candidates.append((best_sim * eff_conf, pat, source_ids))

        candidates.sort(key=lambda t: t[0], reverse=True)
        insights: list[TransferredInsight] = []
        seen_labels: set[str] = set()
        for score, pat, source_ids in candidates:
            if pat.causal_label in seen_labels:
                continue
            seen_labels.add(pat.causal_label)
            insights.append(TransferredInsight(
                pattern_id=pat.pattern_id, causal_label=pat.causal_label,
                typical_segments=pat.typical_segments,
                confidence=round(pat.effective_confidence(), 4),
                source_engagement_ids=tuple(source_ids)[:8],
                sample_size=pat.sample_size,
            ))
            # Register as pending prediction for self-correction.
            self._pending_predictions[f"{pat.causal_label}:{pat.typical_segments[0] if pat.typical_segments else 'any'}"] = pat.pattern_id
        return insights

    def _profiles_for_digest(self, digest: str) -> list[BehaviorProfile]:
        result: list[BehaviorProfile] = []
        seen: set[str] = set()
        for obs in self._observations:
            if obs["behavior_digest"] != digest:
                continue
            eid = obs["engagement_id"]
            if eid in seen:
                continue
            seen.add(eid)
            result.append(BehaviorProfile(
                profile_id=f"prof:{eid}", engagement_id=eid,
                values=obs.get("behavior_values", {}),
            ))
        return result

    # ------------------------------------------------------------------
    # Self-correction — Bayesian update on prediction outcomes
    # ------------------------------------------------------------------
    def record_prediction_outcome(self, causal_label: str, segment: str, confirmed: bool) -> None:
        """Update a pattern's confirmed/refuted counts based on what actually happened.

        If the engine suggested 'causal_label on segment' and it was later
        confirmed -> confirmed_hits += 1 (confidence rises).  If refuted ->
        refuted_hits += 1 (effective confidence drops via bayes_strength).
        Patterns that accumulate refutations eventually fall below the
        acceptance threshold and stop being surfaced.
        """
        key = f"{causal_label}:{segment}"
        pid = self._pending_predictions.get(key)
        if pid is None or pid not in self._inferences:
            return
        pat = self._inferences[pid]
        if confirmed:
            conf_hits, ref_hits = pat.confirmed_hits + 1, pat.refuted_hits
        else:
            conf_hits, ref_hits = pat.confirmed_hits, pat.refuted_hits + 1
        updated = InferencePattern(
            pattern_id=pat.pattern_id, behavior_digest=pat.behavior_digest,
            causal_label=pat.causal_label, typical_segments=pat.typical_segments,
            support=pat.support, consistency=pat.consistency, sample_size=pat.sample_size,
            confidence=pat.confidence, confirmed_hits=conf_hits, refuted_hits=ref_hits,
        )
        self._inferences[pid] = updated
        self._pending_predictions.pop(key, None)
        self._flush_inferences()

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def pattern_summary(self) -> dict[str, Any]:
        above = sum(1 for p in self._inferences.values() if p.effective_confidence() >= self.acceptance_threshold)
        return {
            "observation_count": len(self._observations),
            "inference_pattern_count": len(self._inferences),
            "patterns_above_threshold": above,
            "patterns_below_threshold_internal_only": len(self._inferences) - above,
            "acceptance_threshold": self.acceptance_threshold,
            "patterns": [
                {"pattern_id": p.pattern_id, "causal_label": p.causal_label,
                 "effective_confidence": p.effective_confidence(),
                 "sample_size": p.sample_size, "confirmed_hits": p.confirmed_hits,
                 "refuted_hits": p.refuted_hits}
                for p in sorted(self._inferences.values(), key=lambda p: p.effective_confidence(), reverse=True)
            ],
        }

    # ------------------------------------------------------------------
    # Persistence (atomic, corruption-tolerant)
    # ------------------------------------------------------------------
    def _load_observations(self) -> list[dict[str, Any]]:
        if not self._obs_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        try:
            for line in self._obs_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # skip corrupt line, never crash
        except OSError:
            return []
        return rows

    def _flush_observations(self) -> None:
        tmp = self._obs_path.with_suffix(".tmp")
        tmp.write_text(
            "\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in self._observations) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp, self._obs_path)

    def _load_inferences(self) -> dict[str, InferencePattern]:
        if not self._inf_path.exists():
            return {}
        try:
            data = json.loads(self._inf_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        out: dict[str, InferencePattern] = {}
        for pid, row in data.items():
            try:
                out[pid] = InferencePattern(
                    pattern_id=row["pattern_id"], behavior_digest=row["behavior_digest"],
                    causal_label=row["causal_label"],
                    typical_segments=tuple(row.get("typical_segments", [])),
                    support=float(row.get("support", 0)), consistency=float(row.get("consistency", 0)),
                    sample_size=int(row.get("sample_size", 0)), confidence=float(row.get("confidence", 0)),
                    confirmed_hits=int(row.get("confirmed_hits", 0)), refuted_hits=int(row.get("refuted_hits", 0)),
                )
            except (KeyError, ValueError, TypeError):
                continue
        return out

    def _flush_inferences(self) -> None:
        data = {
            pid: {
                "pattern_id": p.pattern_id, "behavior_digest": p.behavior_digest,
                "causal_label": p.causal_label, "typical_segments": list(p.typical_segments),
                "support": p.support, "consistency": p.consistency,
                "sample_size": p.sample_size, "confidence": p.confidence,
                "confirmed_hits": p.confirmed_hits, "refuted_hits": p.refuted_hits,
            }
            for pid, p in self._inferences.items()
        }
        tmp = self._inf_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, sort_keys=True, indent=2), encoding="utf-8")
        os.replace(tmp, self._inf_path)


__all__ = [
    "ContextualMemoryV2", "BehaviorProfile", "InferencePattern", "TransferredInsight",
    "_BEHAVIOR_FIELDS", "_BEHAVIOR_WEIGHTS", "DEFAULT_DIR",
]

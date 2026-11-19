# src/webpent/causal_reasoning/contextual_memory.py
"""ContextualMemory — Proposal #1, Component 2.

Persistent, cross-engagement contextual memory.  Unlike the existing
lessons layer (which stores route/family boost factors), this store keeps
the *technical context* of each target — framework stack, auth policy
pattern, validation pattern, error behaviour — and transfers knowledge
between analogous targets.

Capabilities:
  * `begin_engagement(fingerprint)`  — find analogous past engagements and
    emit TransferredLesson list ("framework X typically suffers weakness Y
    in paths Z; probe these globs first").
  * `record_outcome(...)`            — at engagement end, distill what was
    actually found and persist it, so the store learns over time.
  * `pattern_summary()`              — the distilled "X -> Y in Z" rules
    accumulated from all engagements (audit-friendly).

Persistence: a single append-only JSONL file under a configurable directory
(default ~/.webpent/causal_memory/).  No secrets are ever written — the
ContextFingerprint contract already strips them at the boundary.  The store
is deterministic: same inputs -> same outputs, replay-safe.
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from webpent.causal_reasoning.contracts import (
    ContextFingerprint,
    EngagementContextRecord,
    TransferStrength,
    TransferredLesson,
    WeaknessCategory,
    route_to_glob,
    stable_id,
)

DEFAULT_MEMORY_DIR = Path.home() / ".webpent" / "causal_memory"
_RECORDS_FILE = "engagement_records.jsonl"
_PATTERNS_FILE = "distilled_patterns.json"
_SIMILARITY_THRESHOLD = 0.45  # below this, no transfer (avoid noise)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _safe_load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # never let one corrupt line break the store
    except OSError:
        return []
    return records


@dataclass
class ContextualMemory:
    """Append-only contextual memory with fingerprint similarity lookup.

    Thread-safety: writes are append-only and atomic (write temp + rename).
    Reads are immutable snapshots.  No locking required for the inference
    use-case (best-effort, eventually consistent).
    """

    memory_dir: Path = field(default_factory=lambda: DEFAULT_MEMORY_DIR)
    similarity_threshold: float = _SIMILARITY_THRESHOLD
    max_transferred_lessons: int = 12

    def __post_init__(self) -> None:
        self.memory_dir = Path(self.memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self._records_path = self.memory_dir / _RECORDS_FILE
        self._patterns_path = self.memory_dir / _PATTERNS_FILE

    # ------------------------------------------------------------------
    # Write path (engagement end)
    # ------------------------------------------------------------------
    def record_engagement_outcome(
        self,
        fingerprint: ContextFingerprint,
        *,
        finding_families: Iterable[str] = (),
        confirmed_weaknesses: Iterable[WeaknessCategory | str] = (),
        routes_by_weakness: Mapping[str, Iterable[str]] | None = None,
        total_findings: int = 0,
    ) -> EngagementContextRecord:
        """Persist one engagement's context + outcome.  Append-only."""
        weakness_cats = tuple(
            WeaknessCategory(str(w).strip()) if str(w).strip() in {c.value for c in WeaknessCategory}
            else WeaknessCategory.UNKNOWN
            for w in confirmed_weaknesses
        )
        routes_safe: dict[str, tuple[str, ...]] = {}
        for weak, routes in (routes_by_weakness or {}).items():
            globs = tuple(sorted({route_to_glob(r) for r in routes}))[:64]
            if globs:
                routes_safe[str(weak)[:80]] = globs

        record = EngagementContextRecord(
            record_id=stable_id("rec", fingerprint.engagement_id, fingerprint.digest()),
            fingerprint=fingerprint,
            finding_families_observed=tuple(finding_families),
            weakness_categories_confirmed=weakness_cats,
            routes_affected_by_weakness=routes_safe,
            total_findings=max(0, int(total_findings)),
            ended_at=datetime.now(UTC),
        )
        # Atomic append: read all, append, write temp, rename.
        existing = _safe_load_jsonl(self._records_path)
        existing.append(record.model_dump(mode="json"))
        tmp = self._records_path.with_suffix(".jsonl.tmp")
        tmp.write_text(
            "\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in existing) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp, self._records_path)
        self._redistill_patterns()
        return record

    # ------------------------------------------------------------------
    # Read path (engagement start) — knowledge transfer
    # ------------------------------------------------------------------
    def begin_engagement(self, fingerprint: ContextFingerprint) -> list[TransferredLesson]:
        """Return transferred lessons from analogous past engagements.

        For each past record above similarity_threshold, emit one
        TransferredLesson per confirmed weakness category, carrying the
        typical route globs and parameters observed for that weakness.
        Sorted by (similarity * confidence) desc, capped.
        """
        past = self._load_records()
        if not past:
            return []

        scored: list[tuple[float, EngagementContextRecord]] = []
        for rec in past:
            sim = fingerprint.similarity(rec.fingerprint)
            if sim >= self.similarity_threshold:
                scored.append((sim, rec))
        scored.sort(key=lambda t: t[0], reverse=True)

        lessons: list[TransferredLesson] = []
        seen_keys: set[str] = set()
        for sim, rec in scored:
            if sim >= 0.8:
                strength = TransferStrength.DIRECT
                base_conf = 0.85
            elif sim >= 0.6:
                strength = TransferStrength.ANALOGOUS
                base_conf = 0.65
            else:
                strength = TransferStrength.SPECULATIVE
                base_conf = 0.45

            for weak in rec.weakness_categories_confirmed:
                if weak == WeaknessCategory.UNKNOWN:
                    continue
                key = f"{weak.value}|{strength.value}"
                if key in seen_keys:
                    continue  # dedupe: strongest analogue already covers it
                seen_keys.add(key)
                globs = rec.routes_affected_by_weakness.get(weak.value, ())
                if not globs:
                    globs = self._patterns_for_weakness(weak.value)
                recommendation = self._recommendation_text(weak, rec.fingerprint)
                lessons.append(TransferredLesson(
                    lesson_id=stable_id("tlesson", fingerprint.engagement_id, weak.value, strength.value),
                    source_engagement_id=rec.fingerprint.engagement_id,
                    source_fingerprint_digest=rec.fingerprint.digest(),
                    transfer_strength=strength,
                    similarity_score=round(sim, 4),
                    weakness_category=weak,
                    typical_route_globs=globs[:12],
                    recommendation=recommendation,
                    confidence=round(min(1.0, base_conf * sim), 4),
                ))
                if len(lessons) >= self.max_transferred_lessons:
                    break
            if len(lessons) >= self.max_transferred_lessons:
                break

        lessons.sort(key=lambda l: (l.similarity_score * l.confidence), reverse=True)
        return lessons

    # ------------------------------------------------------------------
    # Distilled patterns ("framework X -> weakness Y in paths Z")
    # ------------------------------------------------------------------
    def pattern_summary(self) -> dict[str, Any]:
        """Return the accumulated distilled rules (audit-friendly)."""
        if self._patterns_path.exists():
            try:
                return json.loads(self._patterns_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return self._redistill_patterns()

    def _redistill_patterns(self) -> dict[str, Any]:
        """Recompute distilled patterns from all records.  Deterministic."""
        records = self._load_records()
        # key: (framework_tuple, weakness) -> Counter of route globs
        pattern_counter: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        framework_counter: Counter[tuple[str, ...]] = Counter()
        for rec in records:
            fw_key = ",".join(rec.fingerprint.frameworks) or "unknown"
            framework_counter[tuple(rec.fingerprint.frameworks)] += 1
            for weak in rec.weakness_categories_confirmed:
                if weak == WeaknessCategory.UNKNOWN:
                    continue
                globs = rec.routes_affected_by_weakness.get(weak.value, ())
                if not globs:
                    continue
                for g in globs:
                    pattern_counter[(fw_key, weak.value)][g] += 1

        patterns: list[dict[str, Any]] = []
        for (fw, weak), counter in sorted(pattern_counter.items()):
            top_globs = [g for g, _ in counter.most_common(8)]
            total_obs = sum(counter.values())
            patterns.append({
                "frameworks": fw.split(",") if fw != "unknown" else [],
                "weakness_category": weak,
                "typical_route_globs": top_globs,
                "observation_count": total_obs,
                "confidence": round(min(0.95, 0.4 + 0.1 * min(6, total_obs)), 4),
            })

        summary = {
            "generated_at": _now_iso(),
            "engagement_count": len(records),
            "distinct_frameworks": len(framework_counter),
            "patterns": patterns,
        }
        tmp = self._patterns_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(summary, sort_keys=True, indent=2), encoding="utf-8")
        os.replace(tmp, self._patterns_path)
        return summary

    def _patterns_for_weakness(self, weakness_value: str) -> tuple[str, ...]:
        summary = self.pattern_summary()
        globs: list[str] = []
        for p in summary.get("patterns", []):
            if p.get("weakness_category") == weakness_value:
                globs.extend(p.get("typical_route_globs", []))
        return tuple(dict.fromkeys(globs))[:12]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _load_records(self) -> list[EngagementContextRecord]:
        rows = _safe_load_jsonl(self._records_path)
        records: list[EngagementContextRecord] = []
        for row in rows:
            try:
                records.append(EngagementContextRecord.model_validate(row))
            except Exception:
                continue  # skip unparseable rows, never crash the caller
        return records

    @staticmethod
    def _recommendation_text(weak: WeaknessCategory, fp: ContextFingerprint) -> str:
        fw = ",".join(fp.frameworks) or "this stack"
        base = {
            WeaknessCategory.DIRECT_OBJECT_REFERENCE_WITHOUT_SCOPE:
                f"On {fw}, object-id endpoints resolved without caller-scope "
                "checks recur. Probe every /<resource>/{id} sibling with a "
                "different-identity token before deep injection testing.",
            WeaknessCategory.AUTH_CHECK_AFTER_MUTATION:
                f"On {fw}, handlers that mutate before the auth check recur. "
                "Replay state-changing requests with the auth header stripped "
                "on sibling routes sharing the same handler pattern.",
            WeaknessCategory.BROKEN_ACCESS_CONTROL_LAYER:
                f"On {fw}, the shared ACL layer under-enforces role bounds. "
                "Enumerate all role-protected endpoints and cross-test each "
                "role against every other role's routes.",
            WeaknessCategory.MASS_ASSIGNMENT_UNBOUND_FIELDS:
                f"On {fw}, model binding without a field allow-list recurs. "
                "For every write endpoint, add privileged fields (role, is_admin, "
                "account_balance) to the request body and observe acceptance.",
            WeaknessCategory.INCONSISTENT_INPUT_SANITISATION:
                f"On {fw}, sanitisation is applied per-route not in a shared "
                "layer. Fuzz every reflected parameter on endpoints sharing the "
                "data-access/render layer, not just the confirmed one.",
            WeaknessCategory.TRUSTED_CLIENT_SIDE_CONTROL:
                f"On {fw}, server-side fetch of user-supplied URLs without an "
                "allow-list recurs. Probe every parameter that accepts a URL/"
                "host/callback value with internal-IP payloads.",
            WeaknessCategory.WEAK_OR_MISSING_AUTHN_POLICY:
                f"On {fw}, the JWT/session verifier is misconfigured globally. "
                "Test alg=none, weak-secret forgery, and expired-token acceptance "
                "on ONE endpoint; if confirmed, all authenticated endpoints share it.",
            WeaknessCategory.ERROR_HANDLING_LEAKS_INTERNALS:
                f"On {fw}, the global error handler leaks internals. Force "
                "exceptions (malformed JSON, out-of-range ids, bad encodings) on "
                "a sample of endpoints across each service to map the blast radius.",
            WeaknessCategory.SESSION_FIXATION_OR_WEAK_BINDING:
                f"On {fw}, the session manager does not rebind on privilege "
                "change. Test login/role-change/password-reset workflows for "
                "session fixation across the full auth surface.",
            WeaknessCategory.MISSING_SHARED_VALIDATION:
                f"On {fw}, a shared validation layer is absent. Apply the same "
                "malformed-input battery to every endpoint on the API surface.",
            WeaknessCategory.CORS_MISCONFIGURATION_WILDCARD:
                f"On {fw}, CORS reflects arbitrary origins. Probe the "
                "Origin/Access-Control-Request-* headers on every credentialed "
                "endpoint, not just the confirmed one.",
            WeaknessCategory.UNPATCHED_FRAMEWORK_PATTERN:
                f"On {fw}, an unpatched framework-level pattern was confirmed. "
                "Check every endpoint handled by the vulnerable component version.",
        }.get(weak, f"Probe sibling regions sharing weakness {weak.value} on {fw}.")
        return base[:600]


__all__ = ["ContextualMemory", "DEFAULT_MEMORY_DIR"]

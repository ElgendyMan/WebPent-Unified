# src/webpent/causal_reasoning_v2/pattern_versioning.py
"""PatternVersioning — Red-Team fix Phase 5.

Fixes: no versioning meant a logic change silently invalidated all prior
evidence, with no way to tell which results were produced by which definition.

Provides:
  * ENGINE_VERSION — bumped on any causal-logic change.
  * signature_version per pattern — increments when structural_signature
    changes (detected by hash).
  * EvidenceRecord — every observation carries engine_version +
    signature_version, so we know exactly which definition produced it.
  * RunFingerprint — recorded at engagement start: engine version, config
    hash, KB version, timestamp — makes every run reproducible.
  * stale_evidence() — evidence from older signature versions is flagged;
    patterns with only stale evidence have their confidence discounted.
  * migrate_pattern() — when a signature changes, old evidence is preserved
    but marked stale; confidence recomputed from fresh evidence only.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable, Mapping

ENGINE_VERSION = "2.1.0"  # bump on any causal-logic change


@dataclass(frozen=True)
class EvidenceRecord:
    project_id: str
    confirmed: bool
    engine_version: str
    signature_version: int
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    route_globs: tuple[str, ...] = ()
    failed_component: str | None = None


@dataclass
class VersionedPattern:
    pattern_id: str
    cause_type: str
    structural_signature: str
    signature_version: int = 1
    description: str = ""
    fix_hint: str = ""
    evidence: list[EvidenceRecord] = field(default_factory=list)

    @property
    def signature_hash(self) -> str:
        return hashlib.sha256(
            f"{self.cause_type}|{self.structural_signature}".encode()
        ).hexdigest()[:16]

    def fresh_evidence(self) -> list[EvidenceRecord]:
        """Evidence matching current signature_version + current engine."""
        return [
            e for e in self.evidence
            if e.signature_version == self.signature_version and e.engine_version == ENGINE_VERSION
        ]

    def stale_evidence(self) -> list[EvidenceRecord]:
        return [e for e in self.evidence if e not in self.fresh_evidence()]

    def confidence(self) -> float:
        """Jeffrey prior on FRESH evidence only.  Stale evidence is excluded."""
        fresh = self.fresh_evidence()
        if not fresh:
            return 0.0  # no fresh evidence -> cannot trust this pattern
        confirmed = sum(1 for e in fresh if e.confirmed)
        return (confirmed + 0.5) / (len(fresh) + 1)

    def migrate_signature(self, new_signature: str) -> "VersionedPattern":
        """When signature changes, bump version; old evidence becomes stale."""
        self.structural_signature = new_signature
        self.signature_version += 1
        return self


@dataclass(frozen=True)
class RunFingerprint:
    engine_version: str
    config_hash: str
    kb_version: str
    project_id: str
    timestamp: str
    fingerprint: str

    @staticmethod
    def compute(*, project_id: str, config: Mapping[str, Any], kb_pattern_count: int) -> "RunFingerprint":
        config_str = json.dumps(dict(config), sort_keys=True, default=str)
        config_hash = hashlib.sha256(config_str.encode()).hexdigest()[:12]
        kb_version = f"patterns={kb_pattern_count}"
        ts = datetime.now(UTC).isoformat()
        fp = hashlib.sha256(
            f"{ENGINE_VERSION}|{config_hash}|{kb_version}|{project_id}|{ts}".encode()
        ).hexdigest()[:16]
        return RunFingerprint(
            engine_version=ENGINE_VERSION, config_hash=config_hash,
            kb_version=kb_version, project_id=project_id, timestamp=ts, fingerprint=fp,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine_version": self.engine_version,
            "config_hash": self.config_hash,
            "kb_version": self.kb_version,
            "project_id": self.project_id,
            "timestamp": self.timestamp,
            "fingerprint": self.fingerprint,
        }


class VersionedKnowledgeBase:
    """Wraps patterns with versioning + evidence tracking."""

    def __init__(self) -> None:
        self.patterns: dict[str, VersionedPattern] = {}

    def add_evidence(
        self,
        *,
        pattern_id: str,
        cause_type: str,
        structural_signature: str,
        confirmed: bool,
        project_id: str,
        route_globs: Iterable[str] = (),
        failed_component: str | None = None,
        description: str = "",
        fix_hint: str = "",
    ) -> str:
        pat = self.patterns.get(pattern_id)
        if pat is None:
            pat = VersionedPattern(
                pattern_id=pattern_id, cause_type=cause_type,
                structural_signature=structural_signature,
                description=description, fix_hint=fix_hint,
            )
            self.patterns[pattern_id] = pat
        else:
            # If signature changed, migrate (bump version).
            if pat.structural_signature != structural_signature:
                pat.migrate_signature(structural_signature)
        rec = EvidenceRecord(
            project_id=project_id, confirmed=confirmed,
            engine_version=ENGINE_VERSION, signature_version=pat.signature_version,
            route_globs=tuple(route_globs), failed_component=failed_component,
        )
        pat.evidence.append(rec)
        return pattern_id

    def confidence(self, pattern_id: str) -> float:
        pat = self.patterns.get(pattern_id)
        return pat.confidence() if pat else 0.0

    def stale_report(self) -> dict[str, Any]:
        total_stale = sum(len(p.stale_evidence()) for p in self.patterns.values())
        total_fresh = sum(len(p.fresh_evidence()) for p in self.patterns.values())
        return {
            "patterns": len(self.patterns),
            "fresh_evidence": total_fresh,
            "stale_evidence": total_stale,
            "patterns_with_only_stale": sum(
                1 for p in self.patterns.values() if p.fresh_evidence() == [] and p.evidence
            ),
            "engine_version": ENGINE_VERSION,
        }


__all__ = [
    "VersionedKnowledgeBase", "VersionedPattern", "EvidenceRecord",
    "RunFingerprint", "ENGINE_VERSION",
]

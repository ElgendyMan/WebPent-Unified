"""FORGE schemas — the corpus vocabulary (U-FORGE-3 attribution schema
plus the U-FORGE-4/6 dataclass contract, per THE FORGE spec).

All dataclasses are frozen: a corpus entry is a historical record, not
a mutable scratchpad (FORGE-L-10 CORPUS_IS_VERSIONED).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Family(Enum):
    """Payload families the corpus indexes.

    Not a superset of the campaign layer's families: the two enums
    overlap on the injectable classes (SQLI, XSS, SSRF, SSTI) while
    each carries members the other lacks — the campaign's access-
    control families (BOLA, IDOR, AUTH_BYPASS, INFO_DISCLOSURE) have
    no forge counterpart, and forge's injection families (XXE, LFI,
    RCE, ...) have no campaign counterpart. The divergence is pinned
    by test (UNMAPPABLE_CAMPAIGN_FAMILIES in the integration layer).
    """
    SQLI = "SQLI"
    XSS = "XSS"
    SSRF = "SSRF"
    SSTI = "SSTI"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    LFI = "LFI"
    CMD_INJECTION = "CMD_INJECTION"
    XXE = "XXE"
    OPEN_REDIRECT = "OPEN_REDIRECT"
    RCE = "RCE"


@dataclass(frozen=True)
class PayloadAttribution:
    """Who made this payload, where it came from, under what license.

    ATTRIBUTION_IS_SACRED (FORGE-L-7): every payload carries this from
    the moment of ingestion; nothing enters the corpus anonymously.
    """
    payload_id: str
    original_source: str
    original_url: str
    original_author: str | None
    license: str
    license_url: str
    ingested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_trust: float = 0.0
    verified_by: str | None = None


@dataclass(frozen=True)
class SourceConfig:
    """One ingest source (the spec's sources.yaml, as code).

    Trust scores and licenses are the spec's published values.
    """
    source_id: str
    kind: str                     # "github_repo" | "api"
    url: str
    license: str
    license_url: str
    trust_score: float
    update_cadence: str = "weekly"


@dataclass(frozen=True)
class QualitySignal:
    """The gate's inputs for one payload (U-FORGE-2)."""
    payload_id: str
    score: float
    from_curated_source: bool
    has_cve: bool
    has_writeup: bool
    tested_publicly: bool
    is_deprecated: bool
    is_too_common: bool
    is_high_risk: bool
    has_documented_impact: bool
    is_known_malware: bool
    complexity: str               # simple | moderate | advanced | expert
    requires_specific_context: bool
    context_list: tuple[str, ...] = ()
    source_trust: float = 0.0


@dataclass(frozen=True)
class NormalizedPayload:
    """The one schema every ingested payload is normalized into."""
    payload_id: str
    family: Family
    subfamily: str
    raw: str
    encoded_variants: dict[str, str] = field(default_factory=dict)
    target_tech: tuple[str, ...] = ()
    target_waf: tuple[str, ...] = ()
    target_context: tuple[str, ...] = ()
    complexity: str = "simple"
    source: str = ""
    attribution: PayloadAttribution | None = None
    quality_score: float = 0.0
    novelty_score: float = 0.0
    is_polyglot: bool = False
    chains_with: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()


@dataclass(frozen=True)
class TargetContext:
    """What the Oracle knows about the target (U-FORGE-6 input)."""
    tech_stack: list[str] = field(default_factory=list)
    waf_detected: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    response_content_type: str = ""
    param_context: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ScoredPayload:
    """A query hit with its transparent score breakdown (L-9)."""
    payload: NormalizedPayload
    score: float
    breakdown: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class IngestReport:
    """What one ingest run found and what it kept (L-1, L-2)."""
    source_id: str
    payloads_found: int
    payloads_stored: int
    duplicates_removed: int
    source_trust: float
    payloads: list[NormalizedPayload] = field(default_factory=list)


@dataclass(frozen=True)
class StoredOutcome:
    """One real-world test result against one target (L-5)."""
    outcome_id: str
    payload_id: str
    target_id: str
    success: bool
    evidence: str


def _row_to_payload(row: Any, encodings: dict[str, str],
                    tech: list[str], waf: list[str],
                    context: list[str],
                    attribution: PayloadAttribution | None) -> NormalizedPayload:
    """Rebuild a NormalizedPayload from indexer rows (storage contract)."""
    return NormalizedPayload(
        payload_id=row["payload_id"],
        family=Family(row["family"]),
        subfamily=row["subfamily"] or "",
        raw=row["raw"],
        encoded_variants=encodings,
        target_tech=tuple(tech),
        target_waf=tuple(waf),
        target_context=tuple(context),
        complexity=row["complexity"] or "simple",
        source=row["source"] or "",
        attribution=attribution,
        quality_score=row["quality_score"],
        novelty_score=row["novelty_score"],
        is_polyglot=bool(row["is_polyglot"]),
    )

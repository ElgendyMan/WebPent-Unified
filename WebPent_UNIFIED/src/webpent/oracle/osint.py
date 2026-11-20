"""THE ORACLE — U-ORACLE-1, the OSINT Aggregator (v88).

The foundation of Wave 1: passive intelligence from configured third-party
sources, with the laws wired into the machinery rather than written on a
wall. ORACLE-L-1/L-2: every request an operator fetcher makes must pass
the ZeroTouchGuard, which refuses any URL containing the target host; a
breach aborts the gather loudly. ORACLE-L-3: secret-valued keys are
reduced to hash + prefix. ORACLE-L-4: PII is redacted before storage.
ORACLE-L-5: a source without a documented legal basis cannot load.
Rate limits are per-source token-bucket ceilings enforced here, in one
place, not left to each fetcher.

This module imports no network primitive. Real fetching is the operator's
deployment concern: fetchers are injected callables.
"""

from __future__ import annotations

import math
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from webpent.oracle.models import (
    Finding,
    OracleLawError,
    Target,
    ZeroTouchViolation,
    canonical_hash,
    sanitize_payload,
)

SourceFetcher = Callable[[str, str, str | None, "ZeroTouchGuard"], list[dict]]


class ZeroTouchGuard:
    """ORACLE-L-2: the one gate every outbound URL must pass. The law
    forbids requests TO the target, so the judgment is on the URL's own
    host: a third-party query *about* the target (crt.sh, a search
    engine) is passive intelligence and passes; a URL whose host is the
    target or a subdomain of it is a law breach. Proxies and redirects
    are the operator's deployment concern and are covered by the socket
    ban in tests and the package-wide network-import guard."""

    def __init__(self, target_host: str) -> None:
        self.target_host = target_host.lower().strip()

    def _url_host(self, url: str) -> str:
        from urllib.parse import urlsplit

        netloc = urlsplit(url).netloc.lower()
        netloc = netloc.split("@")[-1]  # strip userinfo
        if netloc.startswith("["):  # IPv6 literal, possibly with a port
            return netloc.split("]")[0].strip("[]")
        host = netloc.rsplit(":", 1)[0] if ":" in netloc else netloc
        # a trailing root dot names the same host (RT-01)
        return host.rstrip(".")

    def check(self, url: str) -> None:
        host = self._url_host(url)
        if not host:
            # FAIL CLOSED (RT-01): a URL the guard cannot attribute to a
            # host (relative, scheme-less, mangled) must never pass —
            # fetchers are required to pass absolute URLs.
            raise ZeroTouchViolation(
                f"zero-touch violation: unattributable URL {url!r} — "
                "fetchers must pass absolute URLs (ORACLE-L-2)"
            )
        if host == self.target_host or host.endswith("." + self.target_host):
            raise ZeroTouchViolation(
                f"zero-touch violation: request to the target {url!r} "
                "is forbidden during passive intelligence (ORACLE-L-1/L-2)"
            )

    def proof(self) -> dict[str, Any]:
        return {
            "guard": "ZeroTouchGuard",
            "target": self.target_host,
            "active": True,
        }


@dataclass
class SourceConfig:
    source_id: str
    priority: int
    category: str  # credential | endpoint | tech | data_leak | subdomain
    rate_limit_per_minute: int
    requires_key: bool
    legal_basis: str


VALID_CATEGORIES = {"credential", "endpoint", "tech", "data_leak", "subdomain"}


def _core_hash(raw: dict[str, Any]) -> str:
    """Hash of the stable content of a finding: volatile scoring fields
    (confidence) are excluded so two sources reporting the same evidence
    at different confidences still corroborate."""
    return canonical_hash(
        {k: v for k, v in raw.items() if k != "confidence"}
    )


@dataclass
class OsintFinding:
    source: str
    category: str
    raw_data: dict[str, Any]
    confidence: float
    extracted_at: datetime
    evidence_hash: str
    core_hash: str = ""
    is_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "category": self.category,
            "raw_data": self.raw_data,
            "confidence": self.confidence,
            "extracted_at": self.extracted_at.isoformat(),
            "evidence_hash": self.evidence_hash,
            "core_hash": self.core_hash,
            "is_verified": self.is_verified,
        }


@dataclass
class OsintReport:
    target_id: str
    sources_used: list[str]
    findings: list[OsintFinding]
    duration_seconds: float
    coverage: dict[str, str]  # source_id → success | failed | rate_limited | needs_key | no_fetcher
    zero_touch_proof: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "sources_used": self.sources_used,
            "findings": [f.to_dict() for f in self.findings],
            "duration_seconds": self.duration_seconds,
            "coverage": self.coverage,
            "zero_touch_proof": self.zero_touch_proof,
        }


def load_source_configs(sources_path: Path) -> list[SourceConfig]:
    data = yaml.safe_load(Path(sources_path).read_text(encoding="utf-8"))
    configs: list[SourceConfig] = []
    for row in (data or {}).get("sources", []):
        legal = str(row.get("legal_basis", "")).strip()
        if not legal:
            raise OracleLawError(
                f"source {row.get('source_id')!r} has no legal basis "
                "(ORACLE-L-5): refusing to load"
            )
        rate = int(row.get("rate_limit_per_minute", 0))
        if rate <= 0:
            raise OracleLawError(
                f"source {row.get('source_id')!r} needs a positive "
                "rate_limit_per_minute"
            )
        category = str(row.get("category", "")).strip()
        if category not in VALID_CATEGORIES:
            raise OracleLawError(
                f"source {row.get('source_id')!r} has unknown category "
                f"{category!r}"
            )
        configs.append(
            SourceConfig(
                source_id=str(row["source_id"]),
                priority=int(row.get("priority", 99)),
                category=category,
                rate_limit_per_minute=rate,
                requires_key=bool(row.get("requires_key", False)),
                legal_basis=legal,
            )
        )
    if len({c.source_id for c in configs}) != len(configs):
        raise OracleLawError("duplicate source_id in osint_sources.yaml")
    return sorted(configs, key=lambda c: c.priority)


class OSINTAggregator:
    """Gathers passive intelligence with the laws enforced in code."""

    def __init__(
        self,
        sources_path: Path,
        fetchers: dict[str, SourceFetcher] | None = None,
        api_keys: dict[str, str] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._configs = load_source_configs(Path(sources_path))
        self._fetchers = fetchers or {}
        self._api_keys = api_keys or {}
        self._clock = clock
        self._last_call: dict[str, float] = {}
        self._last_findings: list[OsintFinding] = []

    # -- config surface ------------------------------------------------------

    def source_ids(self) -> list[str]:
        return [c.source_id for c in self._configs]

    def legal_basis(self) -> dict[str, str]:
        return {c.source_id: c.legal_basis for c in self._configs}

    # -- rate limits -----------------------------------------------------------

    def _min_interval(self, config: SourceConfig) -> float:
        return 60.0 / config.rate_limit_per_minute

    def rate_limit_status(self) -> dict[str, dict[str, Any]]:
        status: dict[str, dict[str, Any]] = {}
        for config in self._configs:
            last = self._last_call.get(config.source_id)
            wait = 0.0
            if last is not None:
                wait = max(0.0, self._min_interval(config) - (self._clock() - last))
            status[config.source_id] = {
                "rate_limit_per_minute": config.rate_limit_per_minute,
                "last_call_ts": last,
                "seconds_until_next_allowed": round(wait, 3),
            }
        return status

    # -- gathering ------------------------------------------------------------

    def gather(
        self, target: Target, sources: list[str] | None = None
    ) -> OsintReport:
        guard = ZeroTouchGuard(target.host)
        started = self._clock()
        selected = [
            c
            for c in self._configs
            if sources is None or c.source_id in sources
        ]
        coverage: dict[str, str] = {}
        findings: list[OsintFinding] = []
        for config in selected:
            if sources is not None and config.source_id not in sources:
                continue
            # ORACLE-L-1: rate limits are enforced per source, centrally.
            last = self._last_call.get(config.source_id)
            if last is not None and (
                self._clock() - last < self._min_interval(config)
            ):
                coverage[config.source_id] = "rate_limited"
                continue
            fetcher = self._fetchers.get(config.source_id)
            if config.requires_key and not self._api_keys.get(config.source_id):
                coverage[config.source_id] = "needs_key"
                continue
            if fetcher is None:
                coverage[config.source_id] = "no_fetcher"
                continue
            try:
                raw_rows = fetcher(
                    config.source_id,
                    target.host,
                    self._api_keys.get(config.source_id),
                    guard,
                )
            except ZeroTouchViolation:
                raise  # a law breach is never an isolatable failure
            except Exception:
                coverage[config.source_id] = "failed"
                self._last_call[config.source_id] = self._clock()
                continue
            self._last_call[config.source_id] = self._clock()
            coverage[config.source_id] = "success"
            for raw in raw_rows or []:
                findings.append(self._make_finding(config, raw))
        duration = self._clock() - started
        report = OsintReport(
            target_id=target.host,
            sources_used=[c.source_id for c in selected],
            findings=findings,
            duration_seconds=round(duration, 3),
            coverage=coverage,
            zero_touch_proof=guard.proof(),
        )
        self._last_findings = findings
        return report

    def _make_finding(self, config: SourceConfig, raw: dict) -> OsintFinding:
        # ORACLE-L-3 first: secret-valued keys at ANY depth never survive
        # as values (RT-03), and PII is redacted in the same pass.
        sanitized = sanitize_payload(raw)
        confidence = raw.get("confidence")
        if isinstance(confidence, bool) or not isinstance(
            confidence, (int, float)
        ):
            confidence = 0.5
        confidence = float(confidence)
        if not math.isfinite(confidence):
            # NaN/inf would poison every downstream sort and score.
            confidence = 0.5
        # ORACLE-L-6: a confidence outside [0, 1] carries no meaning.
        confidence = max(0.0, min(1.0, confidence))
        return OsintFinding(
            source=config.source_id,
            category=config.category,
            raw_data=sanitized,
            confidence=confidence,
            extracted_at=datetime.now(timezone.utc),
            evidence_hash=canonical_hash(sanitized),
            core_hash=_core_hash(sanitized),
        )

    # -- verification (cross-source corroboration, zero target touch) ---------

    def verify(self, finding: OsintFinding) -> bool:
        """A finding is verified when another, independent source produced
        the same core evidence in the same category. No request is made."""
        for other in self._last_findings:
            if other.source == finding.source:
                continue
            if other.category == finding.category and (
                other.core_hash == finding.core_hash
            ):
                return True
        return False

    # -- async surface ----------------------------------------------------------

    async def gather_async(
        self, target: Target, sources: list[str] | None = None
    ) -> AsyncIterator[OsintFinding]:
        for finding in self.gather(target, sources).findings:
            yield finding


__all__ = [
    "OsintFinding",
    "OsintReport",
    "OSINTAggregator",
    "SourceConfig",
    "SourceFetcher",
    "ZeroTouchGuard",
    "ZeroTouchViolation",
    "load_source_configs",
    "Finding",
]

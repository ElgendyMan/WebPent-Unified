"""THE ORACLE — U-ORACLE-3, the Signal Aggregator (v88).

Converts raw OSINT evidence and stack profiles into ranked, deduplicated
OracleSignals — the vocabulary the Brain and the attack graph consume.
Strengths come from the static table in attack_signatures.yaml
(ORACLE-L-6: only confirmed evidence produces signals; a verified finding
gets a corroboration boost, never a new strength invented here).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from webpent.oracle.models import OracleLawError
from webpent.oracle.osint import OsintFinding, OsintReport
from webpent.oracle.stack_inferrer import TechStackProfile

SignalConsumer = Callable[[list["OracleSignal"]], None]


@dataclass
class OracleSignal:
    signal_id: str
    signal_type: str
    source: str
    strength: float
    target_id: str
    extracted_at: datetime
    evidence_hash: str
    hints: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_type": self.signal_type,
            "source": self.source,
            "strength": round(self.strength, 3),
            "target_id": self.target_id,
            "extracted_at": self.extracted_at.isoformat(),
            "evidence_hash": self.evidence_hash,
            "hints": self.hints,
            "sources": sorted(set(self.sources)),
        }


class SignalAggregator:
    def __init__(self, signatures_path: Path) -> None:
        data = yaml.safe_load(
            Path(signatures_path).read_text(encoding="utf-8")
        ) or {}
        rules = data.get("signal_rules")
        strengths = data.get("signal_strengths")
        if not rules or strengths is None:
            raise OracleLawError(
                "attack_signatures.yaml needs signal_rules and "
                "signal_strengths sections"
            )
        for signal_type, base in strengths.items():
            if not 0.0 <= float(base) <= 1.0:
                raise OracleLawError(
                    f"strength for {signal_type!r} out of range"
                )
        self._rules = rules
        self._strengths = {
            k: float(v) for k, v in strengths.items()
        }

    # -- aggregation -----------------------------------------------------------

    def aggregate(
        self,
        report: OsintReport,
        stack_profile: TechStackProfile | None = None,
    ) -> list[OracleSignal]:
        signals: dict[tuple[str, str], OracleSignal] = {}
        for finding in report.findings:
            for signal in self._signal_from_finding(finding, report.target_id):
                key = (signal.signal_type, signal.evidence_hash)
                existing = signals.get(key)
                if existing is None:
                    signals[key] = signal
                else:
                    # dedupe: merge sources, keep the strongest strength
                    existing.sources.extend(signal.sources)
                    existing.strength = max(existing.strength, signal.strength)
                    if finding.is_verified:
                        existing.strength = min(
                            1.0, existing.strength + 0.1
                        )
        if stack_profile is not None:
            for comp in stack_profile.components:
                if comp.name in stack_profile.cves:
                    signal_id = f"sig-outdated-{comp.name}-{comp.version or 'x'}"
                    key = ("outdated_component", signal_id)
                    signals[key] = OracleSignal(
                        signal_id=signal_id,
                        signal_type="outdated_component",
                        source=f"stack:{comp.name}",
                        strength=self._strengths["outdated_component"],
                        target_id=stack_profile.target_id,
                        extracted_at=datetime.now(timezone.utc),
                        evidence_hash=signal_id,
                        hints=[
                            f"{comp.name} "
                            f"{comp.version or 'version unknown'} has known "
                            "CVEs; check for unpatched deployments"
                        ],
                        sources=["stack_inferrer"],
                    )
        return sorted(signals.values(), key=lambda s: -s.strength)

    def _signal_from_finding(
        self, finding: OsintFinding, target_id: str
    ) -> list[OracleSignal]:
        import json as _json
        import uuid

        haystack = _json.dumps(finding.raw_data, default=str).lower()
        produced: list[OracleSignal] = []
        for rule in self._rules:
            if rule.get("from_category") != finding.category:
                continue
            keywords = [str(k).lower() for k in rule.get("keywords", [])]
            if keywords and not any(k in haystack for k in keywords):
                continue
            signal_type = str(rule["signal_type"])
            base = self._strengths.get(
                signal_type, float(rule.get("base_strength", 0.5))
            )
            strength = base * finding.confidence
            if finding.is_verified:
                strength = min(1.0, strength + 0.1)
            produced.append(
                OracleSignal(
                    signal_id=f"sig-{uuid.uuid4().hex[:12]}",
                    signal_type=signal_type,
                    source=finding.source,
                    strength=strength,
                    target_id=target_id,
                    extracted_at=finding.extracted_at,
                    evidence_hash=finding.core_hash or finding.evidence_hash,
                    hints=[str(h) for h in rule.get("hints", [])],
                    sources=[finding.source],
                )
            )
        return produced

    # -- ranking is implicit (sorted desc); feeding is explicit -----------------

    def rank(self, signals: list[OracleSignal]) -> list[OracleSignal]:
        return sorted(signals, key=lambda s: -s.strength)

    def feed_to_brain(self, signals: list[OracleSignal], brain: SignalConsumer) -> None:
        brain(signals)

    def feed_to_graph(self, signals: list[OracleSignal], graph: SignalConsumer) -> None:
        graph(signals)


__all__ = ["OracleSignal", "SignalAggregator"]

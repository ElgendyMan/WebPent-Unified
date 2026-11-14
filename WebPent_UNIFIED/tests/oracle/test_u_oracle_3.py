"""U-ORACLE-3 — the Signal Aggregator (v88, plan 2026-10-17-v88-oracle.md)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from webpent.oracle.models import OracleLawError
from webpent.oracle.osint import OsintFinding, OsintReport
from webpent.oracle.signal_aggregator import SignalAggregator
from webpent.oracle.stack_inferrer import Component, ComponentCVE, TechStackProfile

WORK = Path(__file__).resolve().parents[2]
SIGS = WORK / "config" / "oracle" / "attack_signatures.yaml"


def _finding(source: str, category: str, raw: dict, conf: float = 0.9,
             verified: bool = False) -> OsintFinding:
    return OsintFinding(
        source=source, category=category, raw_data=raw, confidence=conf,
        extracted_at=datetime.now(timezone.utc),
        evidence_hash="0" * 64, core_hash="0" * 64, is_verified=verified,
    )


def _report(findings: list[OsintFinding]) -> OsintReport:
    return OsintReport(
        target_id="target.test", sources_used=[], findings=findings,
        duration_seconds=0.0, coverage={},
    )


# -- spec test 1: credential leak → high-strength signal ------------------------

def test_credential_leak_high_strength() -> None:
    signals = SignalAggregator(SIGS).aggregate(
        _report([
            _finding("github_secret_scanning", "credential",
                     {"repo": "org/x", "api_key": {"sha256": "h"}},
                     conf=0.9),
        ])
    )
    cred = [s for s in signals if s.signal_type == "credential_leak"]
    assert cred and cred[0].strength >= 0.7


# -- spec test 2: outdated component from stack profile ---------------------------

def test_outdated_component_detection() -> None:
    profile = TechStackProfile(target_id="target.test")
    profile.components = [Component(name="nginx", version="1.18.0",
                                    confidence=0.9)]
    profile.cves["nginx"] = [
        ComponentCVE(cve="CVE-2021-23017", severity="high", summary="x")
    ]
    signals = SignalAggregator(SIGS).aggregate(_report([]), profile)
    outdated = [s for s in signals if s.signal_type == "outdated_component"]
    assert outdated and "nginx" in outdated[0].hints[0]


# -- spec test 3: dedupe ------------------------------------------------------------

def test_signal_dedup_merges_sources() -> None:
    raw = {"repo": "org/x", "api_key": {"sha256": "same-hash"}}
    signals = SignalAggregator(SIGS).aggregate(
        _report([
            _finding("github_secret_scanning", "credential", raw),
            _finding("hibp", "credential", raw),
        ])
    )
    cred = [s for s in signals if s.signal_type == "credential_leak"]
    assert len(cred) == 1
    assert set(cred[0].sources) == {"github_secret_scanning", "hibp"}


# -- spec test 4: ranking descending ----------------------------------------------------

def test_ranking_desc() -> None:
    signals = SignalAggregator(SIGS).aggregate(
        _report([
            _finding("cloud_buckets", "data_leak", {"bucket": "s3://x"},
                     conf=0.7),
            _finding("github_secret_scanning", "credential",
                     {"repo": "o/x", "api_key": {"sha256": "h"}}, conf=1.0),
            _finding("shodan", "tech", {"banner": "nginx"}, conf=0.6),
        ])
    )
    strengths = [s.strength for s in signals]
    assert strengths == sorted(strengths, reverse=True)


# -- spec test 5: hints present -----------------------------------------------------------

def test_hints_present() -> None:
    signals = SignalAggregator(SIGS).aggregate(
        _report([
            _finding("github_secret_scanning", "credential",
                     {"repo": "o/x", "api_key": {"sha256": "h"}}),
        ])
    )
    assert signals and all(s.hints for s in signals)


# -- spec test 6: feed to brain and graph ---------------------------------------------------

def test_feed_to_brain_and_graph() -> None:
    signals = SignalAggregator(SIGS).aggregate(
        _report([
            _finding("github_secret_scanning", "credential",
                     {"repo": "o/x", "api_key": {"sha256": "h"}}),
        ])
    )
    got_brain: list = []
    got_graph: list = []
    agg = SignalAggregator(SIGS)
    agg.feed_to_brain(signals, got_brain.extend)
    agg.feed_to_graph(signals, got_graph.extend)
    assert got_brain and got_graph == got_brain


# -- parametrized law checks -------------------------------------------------------------------

def test_missing_signal_sections_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "sig.yaml"
    bad.write_text("signal_rules: []\n", encoding="utf-8")
    with pytest.raises(OracleLawError):
        SignalAggregator(bad)


@pytest.mark.parametrize(
    "signal_type,base",
    yaml.safe_load(SIGS.read_text(encoding="utf-8"))["signal_strengths"].items(),
    ids=list(yaml.safe_load(SIGS.read_text(encoding="utf-8"))["signal_strengths"]),
)
def test_every_strength_in_range(signal_type: str, base: float) -> None:
    assert 0.0 < base <= 1.0

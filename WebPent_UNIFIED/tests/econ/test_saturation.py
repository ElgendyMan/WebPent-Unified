"""U-ECON-8 — SaturationEstimator tests (NC-ECON-1 charter, exact test names)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webpent.econ.competitive import CompetitiveRadar
from webpent.econ.market_kb import Target
from webpent.econ.saturation import SaturationEstimator

REPO = Path(__file__).resolve().parents[2]
PARAMS = REPO / "config" / "econ" / "competition_params.yaml"
NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
TARGET = Target(target_id="t-1", program_id="example-corp")


def _radar(tmp_path: Path, n_recent: int = 0, n_old: int = 0,
           sub: str = "a") -> CompetitiveRadar:
    radar = CompetitiveRadar(
        tmp_path / "econ" / f"competitive_{sub}.db", params_path=PARAMS
    )
    findings = [
        {
            "program_id": "example-corp",
            "severity": "high",
            "vuln_class": "IDOR",
            "endpoint_signature": f"/api/v2/item{i}",
            "disclosed_at": (NOW - timedelta(days=5)).isoformat(),
        }
        for i in range(n_recent)
    ] + [
        {
            "program_id": "example-corp",
            "severity": "medium",
            "vuln_class": "XSS",
            "endpoint_signature": f"/old{i}",
            "disclosed_at": (NOW - timedelta(days=60)).isoformat(),
        }
        for i in range(n_old)
    ]
    snap = tmp_path / "snap.json"
    snap.write_text(
        json.dumps({"source": "hackerone_hacktivity", "findings": findings}),
        encoding="utf-8",
    )
    radar.ingest(str(snap), dry_run=False)
    return radar


def test_saturation_deterministic(tmp_path):
    radar = _radar(tmp_path, n_recent=3)
    est = SaturationEstimator(params_path=PARAMS)
    r1 = est.estimate(TARGET, radar, now=NOW, mentions=10, reporters=4)
    r2 = est.estimate(TARGET, radar, now=NOW, mentions=10, reporters=4)
    assert r1.as_dict() == r2.as_dict()
    # components follow the charter weights: 0.5 / 0.3 / 0.2
    expected = (
        0.5 * min(1.0, 3 / 5) + 0.3 * min(1.0, 10 / 20) + 0.2 * min(1.0, 4 / 10)
    ) / 1.0 * 100.0
    assert abs(r1.index - expected) < 1e-9


def test_low_findings_rate_gives_low_index(tmp_path):
    radar = _radar(tmp_path, n_recent=1)  # 1 finding in 30 days, ref is 5
    est = SaturationEstimator(params_path=PARAMS)
    r = est.estimate(TARGET, radar, now=NOW)
    assert r.index <= 30.0
    assert r.tier == "LOW"
    # partial weights were renormalized over what exists
    assert "mentions" in r.recommendation
    assert r.confidence < 1.0


def test_high_findings_rate_gives_high_index(tmp_path):
    radar = _radar(tmp_path, n_recent=5, n_old=7)
    est = SaturationEstimator(params_path=PARAMS)
    r = est.estimate(TARGET, radar, now=NOW, mentions=50, reporters=20)
    # findings 5/5=1.0, mentions 50/20 clamps to 1.0, reporters 20/10 clamps 1.0
    assert r.index == 100.0
    assert r.tier == "SATURATED"
    # only findings inside the 30-day window count; the old ones do not
    radar2 = _radar(tmp_path, n_recent=0, n_old=7, sub="b")
    r2 = est.estimate(TARGET, radar2, now=NOW)
    assert r2.index == 0.0


def test_missing_data_returns_insufficient_signal(tmp_path):
    radar = _radar(tmp_path, n_recent=0)  # empty DB for this program
    est = SaturationEstimator(params_path=PARAMS)
    r = est.estimate(TARGET, radar, now=NOW)
    assert "insufficient_signal" in r.recommendation
    assert r.confidence == 0.0
    assert r.components == {}


def test_index_clamped_0_100(tmp_path):
    radar = _radar(tmp_path, n_recent=99)  # far beyond the reference
    est = SaturationEstimator(params_path=PARAMS)
    r = est.estimate(TARGET, radar, now=NOW, mentions=999, reporters=999)
    assert 0.0 <= r.index <= 100.0
    assert r.index == 100.0
    # and the floor: no findings at all but mentions given -> clamps at 0
    radar_empty = _radar(tmp_path, n_recent=0, sub="c")
    r2 = est.estimate(TARGET, radar_empty, now=NOW, mentions=0.0)
    assert r2.index == 0.0
    assert 0.0 <= r2.index <= 100.0

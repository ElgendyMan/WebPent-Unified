"""U-ECON-4 — ROIOptimizer tests (NC-ECON-1 charter, exact test names)."""

from __future__ import annotations

import math
from pathlib import Path

from webpent.econ.market_kb import MarketKB
from webpent.econ.roi_optimizer import Finding, ROIOptimizer, ValueContext, load_roi_params

REPO = Path(__file__).resolve().parents[2]
SEED_CONFIG = REPO / "config" / "econ" / "programs.yaml"
NOW = 1_800_000_000.0


def _opt(tmp_path: Path) -> ROIOptimizer:
    return ROIOptimizer(
        MarketKB(SEED_CONFIG, payout_curves_path=REPO / "config" / "econ" / "payout_curves.yaml"),
        params_path=REPO / "config" / "econ" / "roi_params.yaml",
    )


def _ctx(**kw) -> ValueContext:
    return ValueContext(now=NOW, **kw)


def test_ev_formula_matches_charter_exactly(tmp_path):
    opt = _opt(tmp_path)
    # example-corp critical typical = 10000, dup_rate 0.35
    finding = Finding(
        "F-1", "ATO", "critical", "example-corp",
        effort_hours=2.0, reputation_risk=0.0, class_accept_rate=0.8,
    )
    val = opt.value(finding, _ctx(timing_bonus=1.0))
    expected = 0.8 * 10000.0 * (1.0 - 0.35) * 1.0 / (2.0 + 0.0)
    assert math.isclose(val.ev_usd, expected, rel_tol=1e-9)
    assert val.components["p_accept"] == 0.8
    assert val.components["payout_usd"] == 10000.0
    assert val.components["p_dup"] == 0.35
    # range brackets the point estimate
    assert val.ev_range[0] <= val.ev_usd <= val.ev_range[1]


def test_high_payout_low_effort_recommended(tmp_path):
    opt = _opt(tmp_path)
    finding = Finding(
        "F-2", "ATO", "critical", "example-bank",
        effort_hours=0.5, class_accept_rate=0.9,
    )
    val = opt.value(finding, _ctx(saturation=10.0))
    assert val.recommendation == "submit"
    assert val.ev_usd >= 100.0
    assert val.rationale.endswith("(submit)")


def test_high_dup_risk_discounts_ev(tmp_path):
    opt = _opt(tmp_path)
    # example-social dup_rate 0.55 vs example-bank 0.20, same everything else
    dup_heavy = Finding("F-3", "ATO", "critical", "example-social",
                        effort_hours=1.0, class_accept_rate=0.8)
    dup_light = Finding("F-4", "ATO", "critical", "example-bank",
                        effort_hours=1.0, class_accept_rate=0.8)
    val_heavy = opt.value(dup_heavy, _ctx(saturation=100.0))
    val_light = opt.value(dup_light, _ctx(saturation=100.0))
    assert val_heavy.ev_usd < val_light.ev_usd
    assert val_heavy.components["p_dup"] > val_light.components["p_dup"]


def test_batch_value_equals_value_per_item(tmp_path):
    opt = _opt(tmp_path)
    findings = [
        Finding(f"F-{i}", "ATO", "high", "example-ecom", effort_hours=1.0,
                class_accept_rate=0.7)
        for i in range(5)
    ]
    batch = opt.batch_value(findings, _ctx())
    singles = [opt.value(f, _ctx()) for f in findings]
    assert len(batch) == len(singles) == 5
    for b, s in zip(batch, singles, strict=False):
        assert b.ev_usd == s.ev_usd
        assert b.recommendation == s.recommendation
        assert b.components == s.components


def test_recommendation_thresholds_from_config(tmp_path):
    # custom thresholds: everything below 10000 becomes skip/upgrade ladder
    custom = tmp_path / "roi_params.yaml"
    custom.write_text(
        "roi:\n"
        "  submit_threshold_usd: 10000.0\n"
        "  improve_threshold_usd: 5000.0\n",
        encoding="utf-8",
    )
    opt = ROIOptimizer(
        MarketKB(SEED_CONFIG, payout_curves_path=REPO / "config" / "econ" / "payout_curves.yaml"),
        params_path=custom,
    )
    finding = Finding("F-5", "ATO", "critical", "example-corp", effort_hours=1.0,
                      class_accept_rate=0.8)
    val = opt.value(finding, _ctx())
    # EV of that finding is ~5200 USD: default config says submit,
    # strict config says improve_first — thresholds come from the file
    assert val.recommendation == "improve_first"
    defaults = load_roi_params(REPO / "config" / "econ" / "roi_params.yaml")
    assert defaults["submit_threshold_usd"] == 100.0
    # corrupt file -> defaults, never a raise
    broken = tmp_path / "broken.yaml"
    broken.write_text("roi: [unclosed", encoding="utf-8")
    assert load_roi_params(broken)["submit_threshold_usd"] == 100.0
    assert load_roi_params(tmp_path / "missing.yaml")["submit_threshold_usd"] == 100.0


def test_unknown_class_uses_default_weights(tmp_path):
    opt = _opt(tmp_path)
    # unknown severity falls back to the medium default accept rate
    weird = Finding("F-6", "NOVEL-CLASS", "unheard-of", "example-corp", effort_hours=1.0)
    val = opt.value(weird, _ctx())
    # severity not in defaults -> medium 0.5; program unknown -> dup 0.5,
    # payout 0 (no curve) -> EV 0 -> skip, confidence discounted
    assert val.components["p_accept"] == 0.5
    assert val.recommendation == "skip"
    assert val.confidence < 1.0
    # unknown program with a known severity still uses the global curve
    known_sev = Finding("F-7", "ATO", "critical", "not-a-program", effort_hours=1.0,
                        class_accept_rate=0.8)
    val2 = opt.value(known_sev, _ctx())
    assert val2.components["payout_usd"] == 8000.0  # global fallback curve
    assert val2.confidence < 1.0

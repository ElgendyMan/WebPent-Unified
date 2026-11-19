"""U-ORACLE-8 — the Multi-Perspective Analyzer (v88, plan 2026-10-17-v88-oracle.md)."""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from webpent.oracle.models import OracleLawError
from webpent.oracle.osint import OsintFinding, OsintReport
from webpent.oracle.perspectives import PerspectiveAnalyzer

WORK = Path(__file__).resolve().parents[2]
PERSP = WORK / "config" / "oracle" / "perspectives.yaml"

CONFIG = yaml.safe_load(PERSP.read_text(encoding="utf-8"))


def _finding(category: str, conf: float = 0.9) -> OsintFinding:
    return OsintFinding(
        source="crtsh", category=category, raw_data={}, confidence=conf,
        extracted_at=datetime.now(timezone.utc),
        evidence_hash="0" * 64, core_hash="0" * 64,
    )


def _report(findings: list[OsintFinding]) -> OsintReport:
    return OsintReport(
        target_id="target.test", sources_used=[], findings=findings,
        duration_seconds=0.0, coverage={},
    )


# -- parametrized law checks ------------------------------------------------------

def test_config_defines_six_perspectives() -> None:
    assert len(CONFIG["perspectives"]) == 6
    names = {p["name"] for p in CONFIG["perspectives"]}
    assert len(names) == 6


@pytest.mark.parametrize(
    "perspective",
    CONFIG["perspectives"],
    ids=[p["perspective_id"] for p in CONFIG["perspectives"]],
)
def test_every_perspective_well_formed(perspective: dict) -> None:
    assert perspective["name"] and perspective["description"]
    assert perspective["weights"]
    assert all(0.0 <= w <= 1.0 for w in perspective["weights"].values())
    assert all(t.get("observation") for t in perspective["triggers"])


# -- spec test 1: six views returned ------------------------------------------------

def test_six_views_returned() -> None:
    views = PerspectiveAnalyzer(PERSP).analyze(
        _report([_finding("credential")])
    )
    assert len(views) == 6
    assert len({v.perspective_id for v in views}) == 6


# -- spec test 2: attacker lens weighs credentials -------------------------------------

def test_attacker_lens_weights_credentials() -> None:
    views = PerspectiveAnalyzer(PERSP).analyze(
        _report([_finding("credential", conf=1.0)])
    )
    attacker = [v for v in views if v.name == "attacker"][0]
    assert attacker.observations
    assert "credential" in attacker.observations[0]
    # the attacker view outranks a lens that ignores credentials
    assert attacker.priority > 0.5


# -- spec test 3: defender lens prioritizes remediation ------------------------------------

def test_defender_lens_prioritizes_remediation() -> None:
    views = PerspectiveAnalyzer(PERSP).analyze(
        _report([_finding("endpoint", conf=0.8)])
    )
    defender = [v for v in views if v.name == "defender"][0]
    assert defender.observations
    # with only endpoint evidence the defender lens outranks the researcher's
    researcher = [v for v in views if v.name == "researcher"][0]
    assert defender.priority > researcher.priority


# -- spec test 4: every view carries observations on a rich report ---------------------------

def test_views_have_observations() -> None:
    views = PerspectiveAnalyzer(PERSP).analyze(
        _report([
            _finding("credential"), _finding("data_leak"),
            _finding("endpoint"), _finding("subdomain"),
            _finding("tech"),
        ])
    )
    for view in views:
        assert view.observations, f"{view.name} produced no observations"


# -- spec test 5: empty report yields silent views, no crash ------------------------------------

def test_empty_report_returns_views_without_observations() -> None:
    views = PerspectiveAnalyzer(PERSP).analyze(_report([]))
    assert len(views) == 6
    assert all(not v.observations for v in views)
    assert all(v.priority == 0.0 for v in views)


# -- spec test 6: priorities ranked and deterministic ---------------------------------------------

def test_priorities_ranked_and_deterministic() -> None:
    report = _report([_finding("credential", 1.0), _finding("tech", 0.7)])
    analyzer = PerspectiveAnalyzer(PERSP)
    first = analyzer.analyze(report)
    second = analyzer.analyze(report)
    priorities = [v.priority for v in first]
    assert priorities == sorted(priorities, reverse=True)
    assert [v.to_dict() for v in first] == [v.to_dict() for v in second]


# -- spec test 7: passive only

def test_passive_only(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_socket(*args, **kwargs):
        raise AssertionError("perspective analyzer opened a socket")

    monkeypatch.setattr(socket, "socket", _no_socket)
    assert PerspectiveAnalyzer(PERSP).analyze(
        _report([_finding("credential")])
    )


# -- guards ----------------------------------------------------------------------------------------

def test_missing_section_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text("lenses: []\n", encoding="utf-8")
    with pytest.raises(OracleLawError):
        PerspectiveAnalyzer(bad)


def test_unknown_trigger_category_rejected(tmp_path: Path) -> None:
    bad_perspective = dict(CONFIG["perspectives"][0])
    bad_perspective["triggers"] = [{"category": "bitcoin",
                                    "observation": "x"}]
    bad = tmp_path / "p.yaml"
    bad.write_text(
        yaml.safe_dump({"perspectives": [bad_perspective]}),
        encoding="utf-8",
    )
    with pytest.raises(OracleLawError):
        PerspectiveAnalyzer(bad)


def test_out_of_range_weight_rejected(tmp_path: Path) -> None:
    bad_perspective = dict(CONFIG["perspectives"][0])
    bad_perspective["weights"] = dict(bad_perspective["weights"])
    bad_perspective["weights"]["credential"] = 1.5
    bad = tmp_path / "p.yaml"
    bad.write_text(
        yaml.safe_dump({"perspectives": [bad_perspective]}),
        encoding="utf-8",
    )
    with pytest.raises(OracleLawError):
        PerspectiveAnalyzer(bad)

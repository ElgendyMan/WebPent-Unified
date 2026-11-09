"""U-APEX-8 — The Result Fusion Engine (v87).

Law under proof: APEX-L-6 FUSE RESULTS — multiple tools' findings become
one picture: grouped by (vuln_class, endpoint), consensus computed,
conflicts resolved to the higher-confidence finding with the disagreement
recorded, confidence weighted by tool accuracy. Deterministic order.
Every FusedFinding is advisory (APEX-L-9).
"""

from __future__ import annotations

import pytest

from webpent.apex.result_fusion import (
    PREAMBLE_LINE,
    Evidence,
    ExecResult,
    FusedFinding,
    ResultFusion,
)


def _result(tool_id: str, vuln_class: str, endpoint: str,
            confidence: float = 0.6, severity: str = "high") -> ExecResult:
    return ExecResult(
        tool_id=tool_id,
        findings=[
            Evidence(
                vuln_class=vuln_class,
                endpoint=endpoint,
                severity=severity,
                confidence=confidence,
                detail=f"{tool_id} saw it",
            )
        ],
    )


def test_fuse_groups_by_class_and_endpoint() -> None:
    fused = ResultFusion().fuse(
        [
            _result("nuclei", "sqli", "/api/users"),
            _result("sqlmap", "sqli", "/api/users"),
            _result("httpx", "exposure", "/api/users"),
        ]
    )
    classes = {f.vuln_class for f in fused}
    assert classes == {"sqli", "exposure"}
    sqli = next(f for f in fused if f.vuln_class == "sqli")
    assert sorted(sqli.sources) == ["nuclei", "sqlmap"]
    assert all(isinstance(f, FusedFinding) for f in fused)
    assert PREAMBLE_LINE in fused[0].advisory_note


def test_consensus_calculated() -> None:
    fused = ResultFusion().fuse(
        [
            _result("nuclei", "sqli", "/api/users"),
            _result("sqlmap", "sqli", "/api/users"),
            _result("dalfox", "sqli", "/api/other"),
        ]
    )
    sqli = next(f for f in fused if f.vuln_class == "sqli"
                and f.endpoint == "/api/users")
    # 2 of the 3 reporting tools support this finding
    assert sqli.consensus == pytest.approx(2 / 3)
    solo = next(f for f in fused if f.endpoint == "/api/other")
    assert solo.consensus < 1.0  # only 1 of 3 total tools reported it
    assert solo.consensus < sqli.consensus


def test_conflict_resolution_picks_higher_confidence() -> None:
    acc = {"nuclei": 1.0, "sqlmap": 1.0}
    a = ResultFusion().fuse(
        [_result("nuclei", "sqli", "/x", confidence=0.4, severity="medium")],
        accuracy=acc,
    )[0]
    b = ResultFusion().fuse(
        [_result("sqlmap", "sqli", "/x", confidence=0.9, severity="critical")],
        accuracy=acc,
    )[0]
    winner = ResultFusion().resolve_conflict([a, b])
    assert winner.confidence == 0.9
    assert winner.severity == "critical"
    assert winner.disagreements, "the disagreement must be recorded"
    assert any("nuclei" in d for d in winner.disagreements)


def test_confidence_weighted_by_tool_accuracy() -> None:
    fusion = ResultFusion()
    plain = fusion.fuse([_result("tool_a", "sqli", "/e", confidence=0.8)])[0]
    weighted = fusion.fuse(
        [_result("tool_a", "sqli", "/e", confidence=0.8)],
        accuracy={"tool_a": 0.9},
    )[0]
    other = fusion.fuse(
        [_result("tool_a", "sqli", "/e", confidence=0.8)],
        accuracy={"tool_a": 0.1},
    )[0]
    assert weighted.confidence > other.confidence, (
        "higher tool accuracy must raise the fused confidence"
    )
    assert plain.confidence != weighted.confidence, (
        "an accuracy entry must change the weighting"
    )


def test_deterministic_fusion() -> None:
    results = [
        _result("zeta", "xss", "/a"),
        _result("alpha", "xss", "/b"),
        _result("mid", "sqli", "/c"),
    ]
    first = ResultFusion().fuse(results)
    second = ResultFusion().fuse(list(reversed(results)))
    assert [f.to_dict() for f in first] == [f.to_dict() for f in second]


def test_empty_results_fuse_to_nothing() -> None:
    assert ResultFusion().fuse([]) == []

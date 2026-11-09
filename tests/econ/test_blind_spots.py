"""U-ECON-9 — BlindSpotLocator tests (NC-ECON-1 charter, exact test names)."""

from __future__ import annotations

import json
import socket
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from webpent.econ.blind_spots import BlindSpotLocator, region_of
from webpent.econ.competitive import CompetitiveRadar
from webpent.econ.market_kb import Target
from webpent.econ.scope_negotiator import ScopeAnalysis

REPO = Path(__file__).resolve().parents[2]
PARAMS = REPO / "config" / "econ" / "competition_params.yaml"
NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """L-2 guard: any socket/urllib use inside locate() fails the test."""

    def _blocked(*args, **kwargs):
        raise AssertionError("network access attempted from BlindSpotLocator")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(urllib.request, "urlopen", _blocked)
    yield


def _radar(tmp_path: Path, findings: list[dict], sub: str = "a") -> CompetitiveRadar:
    radar = CompetitiveRadar(
        tmp_path / "econ" / f"competitive_{sub}.db", params_path=PARAMS
    )
    snap = tmp_path / f"snap_{sub}.json"
    snap.write_text(
        json.dumps({"source": "hackerone_hacktivity", "findings": findings}),
        encoding="utf-8",
    )
    radar.ingest(str(snap), dry_run=False)
    return radar


def _finding(vuln_class="IDOR", endpoint="/api/v2/users/{id}", days_ago=3):
    return {
        "program_id": "example-corp",
        "severity": "high",
        "vuln_class": vuln_class,
        "endpoint_signature": endpoint,
        "disclosed_at": (NOW - timedelta(days=days_ago)).isoformat(),
    }


SCOPE = ScopeAnalysis(
    in_scope=[
        "/api/v1/orders",
        "/api/v1/refunds",
        "/api/v2/users/{id}",
        "vault.example-corp.com",
        "admin.example-corp.com",
    ],
    out_of_scope=[],
    ambiguities=[],
)


def test_blind_spot_finds_uncovered_region(tmp_path):
    radar = _radar(tmp_path, [_finding(endpoint="/api/v2/users/{id}")])
    locator = BlindSpotLocator(params_path=PARAMS)
    spots = locator.locate(Target("t-1", "example-corp"), radar, SCOPE, now=NOW)
    kinds = {(s.kind, s.identifier) for s in spots}
    # /api/v1/* has two scope paths and zero public findings
    assert ("path_region", "/api/v1/*") in kinds
    # covered region /api/v2/* must NOT appear
    assert ("path_region", "/api/v2/*") not in kinds
    # subdomains in scope with no findings are spots too
    assert ("subdomain", "vault.example-corp.com") in kinds
    assert ("subdomain", "admin.example-corp.com") in kinds


def test_blind_spot_ignores_covered_region(tmp_path):
    radar = _radar(
        tmp_path,
        [
            _finding(endpoint="/api/v1/orders/42"),
            _finding(endpoint="/api/v1/refunds/7"),
        ],
    )
    locator = BlindSpotLocator(params_path=PARAMS)
    spots = locator.locate(Target("t-1", "example-corp"), radar, SCOPE, now=NOW)
    assert ("path_region", "/api/v1/*") not in {(s.kind, s.identifier) for s in spots}
    # region_of collapses signatures to two-segment patterns
    assert region_of("/api/v1/orders/42?x=1") == "/api/v1/*"
    assert region_of("not-a-path") == ""


def test_blind_spot_ranks_by_ev(tmp_path):
    radar = _radar(tmp_path, [_finding() for _ in range(4)])
    locator = BlindSpotLocator(params_path=PARAMS)
    spots = locator.locate(Target("t-1", "example-corp"), radar, SCOPE, now=NOW)
    evs = [s.estimated_ev for s in spots]
    assert evs == sorted(evs, reverse=True)
    # RCE (weight 1.5) outscores INFO_DISCLOSURE (0.6): severity x coverage
    by_id = {s.identifier: s for s in spots if s.kind == "vuln_class"}
    assert by_id["RCE"].estimated_ev > by_id["INFO_DISCLOSURE"].estimated_ev
    # /api/v1/* region: 2 uncovered entries x base 400 = 800
    by_kind = {(s.kind, s.identifier): s for s in spots}
    assert by_kind[("path_region", "/api/v1/*")].estimated_ev == 800.0


def test_no_network_calls(tmp_path):
    radar = _radar(tmp_path, [_finding()])
    locator = BlindSpotLocator(params_path=PARAMS)
    # the autouse fixture above makes any socket/urllib use raise; this
    # call must complete without tripping it
    spots = locator.locate(Target("t-1", "example-corp"), radar, SCOPE, now=NOW)
    assert all(s.as_dict()["advisory"] is True for s in spots)


def test_deterministic_ordering(tmp_path):
    radar = _radar(tmp_path, [_finding()])
    locator = BlindSpotLocator(params_path=PARAMS)
    target = Target("t-1", "example-corp")
    run1 = [s.as_dict() for s in locator.locate(target, radar, SCOPE, now=NOW)]
    run2 = [s.as_dict() for s in locator.locate(target, radar, SCOPE, now=NOW)]
    assert run1 == run2
    # a second locator instance agrees (pure function of inputs)
    run3 = [s.as_dict() for s in BlindSpotLocator(params_path=PARAMS).locate(
        target, radar, SCOPE, now=NOW)]
    assert run1 == run3


def test_confidence_reflects_data_volume(tmp_path):
    locator = BlindSpotLocator(params_path=PARAMS)
    target = Target("t-1", "example-corp")
    thin = locator.locate(
        Target("t-1", "example-corp"), _radar(tmp_path, [_finding()]), SCOPE, now=NOW
    )
    rich = locator.locate(
        target,
        # 12 DISTINCT findings: identical rows dedup since R2-econ-03,
        # and confidence reflects observed data volume, not repeated rows
        _radar(
            tmp_path,
            [_finding(endpoint=f"/api/v2/users{i}") for i in range(12)],
            sub="b",
        ),
        SCOPE,
        now=NOW,
    )
    thin_conf = {s.confidence for s in thin}
    rich_conf = {s.confidence for s in rich}
    assert max(thin_conf) < max(rich_conf)
    assert max(rich_conf) == 1.0  # 12 findings >= the reference of 10
    assert all(s.reasoning for s in thin + rich)

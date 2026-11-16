"""UM-DR-37 Part 7.1 — unified lifecycle-view tests."""

from __future__ import annotations

import pytest

from webpent.models.hypothesis import HypothesisStatus
from webpent.research.lifecycle_view import (
    lifecycle_stage,
    lifecycle_snapshot,
)


def test_every_main_status_maps_exactly_once() -> None:
    mapped = {
        status: lifecycle_stage(status)
        for status in HypothesisStatus
    }
    assert mapped == {
        HypothesisStatus.UNEXPLORED: "GENERATED",
        HypothesisStatus.INVESTIGATING: "EXECUTED",
        HypothesisStatus.PROMOTED: "SUPPORTED",
        HypothesisStatus.RESOLVED_TRUE: "SUPPORTED",
        HypothesisStatus.RESOLVED_FALSE: "REFUTED",
        HypothesisStatus.ABANDONED: "CLOSED",
        HypothesisStatus.LEARNED: "LEARNED",
    }


def test_egaie_statuses_map() -> None:
    for value, expected in {
        "proposed": "GENERATED", "supported": "SUPPORTED",
        "contradicted": "REFUTED", "confirmed": "SUPPORTED",
        "refuted": "REFUTED",
    }.items():
        assert lifecycle_stage(value) == expected


def test_unknown_status_fails_closed() -> None:
    with pytest.raises(ValueError, match="unmapped"):
        lifecycle_stage("frobnicated")


def test_snapshot_counts_and_views() -> None:
    hypotheses = [
        {"id": "h-1", "status": "unexplored", "vuln_class": "idor"},
        {"id": "h-2", "status": "investigating", "vuln_class": "ssrf"},
        {"hypothesis_id": "h-3", "status": "resolved_true"},
        {"id": "h-4", "status": "abandoned"},
    ]
    snapshot = lifecycle_snapshot(hypotheses)
    assert snapshot["total"] == 4
    assert snapshot["stage_counts"] == {
        "GENERATED": 1, "EXECUTED": 1, "SUPPORTED": 1, "CLOSED": 1,
    }
    assert snapshot["stages"][1] == {
        "id": "h-2", "status": "investigating", "stage": "EXECUTED",
        "vuln_class": "ssrf",
    }
    assert snapshot["stages"][2]["id"] == "h-3"


def test_snapshot_accepts_model_objects() -> None:
    class _H:
        def __init__(self, identifier: str, status: str) -> None:
            self.id = identifier
            self.status = HypothesisStatus(status)
            self.vuln_class = "idor"

    snapshot = lifecycle_snapshot([_H("h-9", "investigating")])
    assert snapshot["stage_counts"] == {"EXECUTED": 1}
    assert snapshot["stages"][0]["status"] == "investigating"

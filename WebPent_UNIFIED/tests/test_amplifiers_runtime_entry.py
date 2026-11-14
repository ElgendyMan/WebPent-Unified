"""v82 Task 16: optional advisory aggregation entry points in hunt_runtime."""

from __future__ import annotations

from webpent.autonomous.hunt_runtime import (
    advisory_cross_target_suggestions,
    advisory_recon_summary,
)


def test_recon_summary_counts_leads_per_source() -> None:
    reports = {
        "takeover": {"candidates": [{"host": "a"}, {"host": "b"}]},
        "wayback": {"candidates": [{"path": "/old"}]},
        "js_analyzer": {"open_candidates": [], "candidates": [{"url": "x"}]},
        "not_a_dict": "junk",
    }
    summary = advisory_recon_summary(reports)
    assert summary["sources"] == {"takeover": 2, "wayback": 1, "js_analyzer": 1}
    assert summary["total_leads"] == 4
    assert summary["advisory"] is True


def test_recon_summary_degrades_on_garbage() -> None:
    assert advisory_recon_summary(None)["total_leads"] == 0
    assert advisory_recon_summary("junk")["sources"] == {}
    assert advisory_recon_summary({"takeover": "not-a-dict"})["sources"] == {}


def test_cross_target_suggestions_pass_through() -> None:
    class FakeStore:
        def suggestions_for(self, stack):
            return [{"vuln_class": "sqli", "hits": 2, "advisory": True}]

    out = advisory_cross_target_suggestions(FakeStore(), ["nginx"])
    assert out[0]["vuln_class"] == "sqli"


def test_cross_target_suggestions_fail_soft() -> None:
    assert advisory_cross_target_suggestions(None, ["nginx"]) == []
    assert advisory_cross_target_suggestions(object(), ["nginx"]) == []

    class Exploding:
        def suggestions_for(self, stack):
            raise RuntimeError("store down")

    assert advisory_cross_target_suggestions(Exploding(), ["nginx"]) == []

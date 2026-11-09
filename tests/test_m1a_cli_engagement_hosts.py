"""M1-A (L-3) regression: the CLI hunt path declares engagement target
hosts around the graph stream.

Contract (M1_READINESS_REVIEW §3, L-3):
  * during ``graph.stream(...)`` the engagement target-host contextvar
    IS set to the hunt's target URL — SSRF-guarded recon tools
    (katana/subfinder/dalfox seed gates, the pinned transport's
    engagement exemption) can actually run on the CLI path;
  * after ``_invoke_with_progress`` returns (or raises), the contextvar
    is CLEARED — a thread reused for a different engagement never
    inherits this target (worker pattern, pentest_worker.py:692).
"""
from __future__ import annotations

from types import SimpleNamespace

from webpent.cli.unified_hunt import _invoke_with_progress
from webpent.shared.engagement_scope import get_engagement_target_hosts


class _RecordingGraph:
    """Fake graph: records what the engagement context looks like
    while the stream is live, then returns a final state."""

    def __init__(self, *, fail: bool = False) -> None:
        self.seen_hosts: set[str] | None = None
        self.fail = fail

    def stream(self, initial_state, config=None, stream_mode=None):
        self.seen_hosts = set(get_engagement_target_hosts())
        yield {"recon": {"surface_metrics": {"endpoints": 1}}}
        if self.fail:
            raise RuntimeError("stream blew up mid-hunt")

    def get_state(self, config):
        return SimpleNamespace(values={"findings": [], "surface_metrics": {"endpoints": 1}})


def _preset() -> dict:
    return {
        "mode": "quick",
        "llm_budget_usd": 1.0,
        "max_llm_calls": 5,
        "max_hypotheses": 10,
    }


def _target() -> SimpleNamespace:
    return SimpleNamespace(url="https://target-l3.test/app")


def _patch_initial_state(monkeypatch):
    import webpent.state.initial_state as initial_state_module

    monkeypatch.setattr(
        initial_state_module,
        "build_initial_state",
        lambda target, **kwargs: {"target_url": getattr(target, "url", "")},
    )


def test_engagement_hosts_set_during_stream(monkeypatch):
    _patch_initial_state(monkeypatch)
    graph = _RecordingGraph()
    final = _invoke_with_progress(
        graph, _target(), _preset(), "thread-l3", "eng-l3",
        credentials={}, session_cookies={}, settings=None,
        no_llm=True, report_format=None, renderer=None, announcer=None,
    )
    assert graph.seen_hosts is not None
    assert "target-l3.test" in graph.seen_hosts, (
        "L-3 REGRESSION: engagement target hosts are NOT visible to graph "
        "nodes during the CLI hunt stream — external recon is lost"
    )
    assert final.get("surface_metrics") == {"endpoints": 1}
    # cleared after return
    assert "target-l3.test" not in get_engagement_target_hosts()


def test_engagement_hosts_cleared_on_stream_failure(monkeypatch):
    _patch_initial_state(monkeypatch)
    graph = _RecordingGraph(fail=True)
    try:
        _invoke_with_progress(
            graph, _target(), _preset(), "thread-l3", "eng-l3",
            credentials={}, session_cookies={}, settings=None,
            no_llm=True, report_format=None, renderer=None, announcer=None,
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected the stream failure to propagate")
    assert "target-l3.test" not in get_engagement_target_hosts(), (
        "L-3 REGRESSION: engagement target hosts leaked after a failed hunt"
    )

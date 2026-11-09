"""POST-P0 Phase 8 — business-logic minimum (stateful flow replay).

Pins:
  * crawler-recorded multi-step form sequences yield bounded skip/reorder
    probes with a DETERMINISTIC validation attempt (the probe sequence
    itself),
  * a corrupted-order acceptance (final step succeeds skipped or out of
    order while the honest baseline succeeds) produces a hypothesis
    candidate — advisory only, routed through normal validation,
  * a server that enforces order (skip/reorder fail) produces NO
    hypothesis (honest negative),
  * the request budget is bounded (<=3 flows, bounded requests per flow)
    — no unbounded request storms,
  * without an authenticated session the flow replay is skipped
    honestly (Phase 3 contract: stateful probes need a session),
  * race double-submit testing remains bounded (existing behavior).
"""

from __future__ import annotations

from webpent.agents.business_logic_fuzzer.agent import (
    _MAX_FLOW_REPLAYS,
    _MAX_FLOW_STEPS,
    _bounded_flow_replay,
    _sequential_form_flows,
)
from webpent.models.targets import Target
from webpent.state.initial_state import build_initial_state


def _forms() -> list[dict]:
    return [
        {
            "action": "http://lab.local/checkout/step1",
            "method": "POST",
            "data": {"item": "1"},
            "source_url": "http://lab.local/checkout",
        },
        {
            "action": "http://lab.local/checkout/step2",
            "method": "POST",
            "data": {"pay": "1"},
            "source_url": "http://lab.local/checkout",
        },
    ]


def _scripted_request(outcomes: dict[str, int]):
    """Script status codes by URL substring."""

    def fake(url, method, form_data, cookies=None):
        for fragment, code in outcomes.items():
            if fragment in url:
                return code
        return 0

    return fake


def test_flows_grouped_and_bounded() -> None:
    forms = _forms()
    extra = [
        {
            "action": f"http://lab.local/other/step{i}",
            "method": "POST",
            "data": {},
            "source_url": "http://lab.local/other",
        }
        for i in range(_MAX_FLOW_STEPS + 4)
    ]
    flows = _sequential_form_flows(forms + extra)
    assert flows  # at least the checkout flow
    for flow in flows:
        assert 2 <= len(flow) <= _MAX_FLOW_STEPS
    # Flows bounded to the replay budget when more groups exist.
    many_groups = [
        {
            "action": f"http://lab.local/g{i}/step1",
            "method": "POST",
            "data": {},
            "source_url": f"http://lab.local/g{i}",
        }
        for i in range(_MAX_FLOW_REPLAYS + 5)
    ] + [
        {
            "action": f"http://lab.local/g{i}/step2",
            "method": "POST",
            "data": {},
            "source_url": f"http://lab.local/g{i}",
        }
        for i in range(_MAX_FLOW_REPLAYS + 5)
    ]
    assert len(_sequential_form_flows(many_groups)) <= _MAX_FLOW_REPLAYS


def test_corrupted_order_acceptance_yields_hypothesis(monkeypatch) -> None:
    # Server accepts step2 even without step1 (skip) and out of order.
    import webpent.agents.business_logic_fuzzer.agent as mod

    monkeypatch.setattr(
        mod,
        "_single_form_request",
        _scripted_request(
            {"step1": 200, "step2": 200}
        ),
    )
    observations, hypotheses = _bounded_flow_replay(_forms(), cookies={"sid": "x"})
    assert len(observations) == 1
    assert len(hypotheses) == 1
    obs = observations[0]
    # Deterministic validation attempt recorded: baseline + skip + reorder.
    assert len(obs["baseline_statuses"]) == 2
    assert obs["skip_step_status"] == 200
    assert obs["requests_used"] == 4
    hyp = hypotheses[0]
    assert hyp["advisory_only"] is True
    assert hyp["requires_validation"] is True
    assert "corrupted sequence" in hyp["statement"]


def test_enforced_order_yields_no_hypothesis(monkeypatch) -> None:
    # Honest negative: skip/reorder rejected (403), baseline succeeds.
    import webpent.agents.business_logic_fuzzer.agent as mod

    def scripted(url, method, form_data, cookies=None):
        if "step2" in url:
            # _bounded_flow_replay calls baseline last step first? No —
            # baseline order: step1 then step2; skip: step2 alone;
            # reorder: step2 then step1. Distinguish by call sequence:
            return 200
        return 200

    # Track call order to simulate enforcement: the first step2 call is
    # the baseline's final step (succeeds); skip/reorder step2 -> 403.
    calls: list[str] = []

    def ordered(url, method, form_data, cookies=None):
        if "step2" in url:
            calls.append(url)
            # baseline's step2 is the 2nd overall request; skip/reorder
            # step2 calls come afterwards.
            if len(calls) == 1:
                return 200
            return 403
        return 200

    monkeypatch.setattr(mod, "_single_form_request", ordered)
    observations, hypotheses = _bounded_flow_replay(_forms(), cookies={"sid": "x"})
    assert len(observations) == 1
    assert hypotheses == []


def test_no_session_skips_flow_replay_honestly() -> None:
    from webpent.agents.business_logic_fuzzer.agent import business_logic_fuzzer_node

    state = build_initial_state(target=Target(url="http://lab.local"), thread_id="t")
    state["crawled_data"] = {"forms": _forms(), "endpoints": []}
    result = business_logic_fuzzer_node(state)
    # Without session cookies: no flow observations or hypotheses.
    assert not (result.get("workflow_observations") or [])
    assert not (result.get("flow_hypotheses") or [])


def test_flow_replay_emits_observations_with_session(monkeypatch) -> None:
    import webpent.agents.business_logic_fuzzer.agent as mod
    from webpent.agents.business_logic_fuzzer.agent import business_logic_fuzzer_node

    monkeypatch.setattr(
        mod,
        "_single_form_request",
        _scripted_request({"step1": 200, "step2": 200}),
    )
    state = build_initial_state(target=Target(url="http://lab.local"), thread_id="t")
    state["crawled_data"] = {"forms": _forms(), "endpoints": []}
    state["session_cookies"] = {"sid": "live"}
    result = business_logic_fuzzer_node(state)
    assert result.get("flow_hypotheses")
    observations = [
        o for o in (result.get("workflow_observations") or [])
        if isinstance(o, dict) and o.get("probe") == "bounded_stateful_flow_replay"
    ]
    assert observations
    # Hypothesis candidates stay advisory: no finding was fabricated and
    # no confirmation authority claimed.
    assert all(isinstance(h, dict) and h.get("advisory_only") for h in result["flow_hypotheses"])


def test_race_double_submit_remains_bounded() -> None:
    # Existing bounded race behavior preserved (regression pin).
    from webpent.agents.business_logic_fuzzer.agent import _BURST_SIZE

    assert _BURST_SIZE == 10

"""Tests for the adaptive discovery engine (suggestion 3).

The engine is advisory-only: every function here must produce candidates,
never requests, findings, or executions. These tests pin the properties
that make that safe:

* thresholds are paired with minimum-sample rules (no two-outlier signals),
* the ``strong`` tier requires repetition ACROSS rounds, not magnitude,
* minted route/parameter/endpoint candidates stay same-origin and dedup
  against everything already attempted,
* hybrid scenarios only pair evidence-backed capabilities,
* the orchestrator wiring merges seeds through the same bounded
  re-hypothesis path, and a discovery-only round with no new evidence
  still converges to a typed stop,
* the report exposes machine-derived discovery counts, and the registry
  marks producer-gap classes honestly.
"""

from __future__ import annotations

from typing import Any

from webpent.agents.validator.registry import coverage_gap
from webpent.autonomous import (
    AutonomousHuntOrchestrator,
    AutonomousHuntState,
    HuntStopReason,
)
from webpent.autonomous.hunt_discovery import (
    allocate_uncertainty_budget,
    anomalies_to_hypotheses,
    classify_anomalies,
    discover_from_records,
    generate_hybrid_scenarios,
    infer_parameters,
    infer_route_patterns,
    mine_endpoints,
    monitor_anomalies,
)


class _FakeController:
    """A controller double that returns a scripted update per iteration."""

    def __init__(self, updates: list[dict[str, Any]]) -> None:
        self._updates = updates
        self.calls = 0

    def run(self, state, *, handler, iterations=1):  # noqa: ANN001
        update = self._updates[min(self.calls, len(self._updates) - 1)]
        self.calls += 1
        return dict(update)


def _outcome(
    url: str = "http://lab.example/api/item/17",
    *,
    sizes: list[int] | None = None,
    timings: list[int] | None = None,
    statuses: list[int] | None = None,
    errors: list[str] | None = None,
    params: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    task_id: str | None = None,
) -> dict[str, Any]:
    """Build one outcome record with per-observation response metadata.

    ``monitor_anomalies`` groups by probe identity and reads one value
    per record; to simulate N samples of one probe, pass N records whose
    sizes/timings/statuses/errors lists each carry one value.
    """
    record: dict[str, Any] = {"url": url, "status": "executed"}
    if task_id:
        record["task_id"] = task_id
    if sizes:
        record["content_length"] = sizes.pop(0)
    if timings:
        record["elapsed_ms"] = timings.pop(0)
    if statuses:
        record["status_code"] = statuses.pop(0)
    if errors:
        record["reason"] = errors.pop(0)
    if params:
        record["params"] = list(params)
    if evidence_refs:
        record["evidence_refs"] = list(evidence_refs)
        record["detail"] = "observed public-media media-url and media-unauthorized"
    return record


# ---------------------------------------------------------------------------
# 1) anomaly monitoring: thresholds + minimum samples
# ---------------------------------------------------------------------------


def test_monitor_needs_minimum_samples_before_any_signal() -> None:
    records = [
        _outcome(sizes=[100]),
        _outcome(sizes=[900]),
    ]
    # Two same-probe records: min samples met, 89% divergence -> fires.
    assert any(a["kind"] == "size_divergence" for a in monitor_anomalies(records))


def test_monitor_single_sample_is_never_a_signal() -> None:
    records = [_outcome(sizes=[100])]
    assert monitor_anomalies(records) == []


def test_monitor_size_below_threshold_is_silent() -> None:
    # 15% divergence is below the 20% size threshold.
    records = [
        _outcome(sizes=[1000]),
        _outcome(sizes=[1150]),
    ]
    assert monitor_anomalies(records) == []


def test_monitor_timing_threshold_is_30_percent() -> None:
    # 500/1400 divergence is ~0.36, above the 30% timing threshold.
    records = [
        _outcome(timings=[900]),
        _outcome(timings=[1400]),
    ]
    anomalies = monitor_anomalies(records)
    timing = [a for a in anomalies if a["kind"] == "timing_divergence"]
    assert len(timing) == 1
    assert timing[0]["detail"] == {"min_ms": 900, "max_ms": 1400}


def test_monitor_status_divergence_needs_two_distinct_statuses() -> None:
    same = [_outcome(statuses=[200]), _outcome(statuses=[200])]
    assert monitor_anomalies(same) == []
    divergent = [_outcome(statuses=[200]), _outcome(statuses=[403])]
    kinds = {a["kind"] for a in monitor_anomalies(divergent)}
    assert "status_divergence" in kinds


def test_monitor_error_text_shift() -> None:
    records = [
        _outcome(errors=["timeout upstream"]),
        _outcome(errors=["validation failed"]),
    ]
    kinds = {a["kind"] for a in monitor_anomalies(records)}
    assert "error_text_shift" in kinds


def test_monitor_caps_anomaly_output() -> None:
    from webpent.autonomous.hunt_discovery import _MAX_ANOMALIES

    records = []
    for index in range(_MAX_ANOMALIES + 10):
        probe = f"http://lab.example/api/p{index}"
        records.extend([_outcome(url=probe, sizes=[10]), _outcome(url=probe, sizes=[990])])
    assert len(monitor_anomalies(records)) == _MAX_ANOMALIES


# ---------------------------------------------------------------------------
# 2) classification: repetition across rounds gates the strong tier
# ---------------------------------------------------------------------------


def _strong_candidate() -> list[dict[str, Any]]:
    return classify_anomalies(
        monitor_anomalies([_outcome(statuses=[200]), _outcome(statuses=[403])])
    )


def test_one_round_high_confidence_is_interesting_never_strong() -> None:
    classified = _strong_candidate()
    assert len(classified) == 1
    assert classified[0]["tier"] == "interesting"
    assert classified[0]["repeat_count"] == 1


def test_two_rounds_of_same_signal_reach_strong() -> None:
    first = _strong_candidate()
    second = classify_anomalies(_strong_candidate(), history=first)
    assert second[0]["tier"] == "strong"
    assert second[0]["repeat_count"] == 2


def test_low_confidence_singletons_are_noise() -> None:
    noise = [{"probe": "p", "kind": "size_divergence", "confidence": 0.4}]
    assert classify_anomalies(noise)[0]["tier"] == "noise"


# ---------------------------------------------------------------------------
# 3) hypothesis seeds from strong anomalies only
# ---------------------------------------------------------------------------


def test_only_strong_anomalies_become_seeds() -> None:
    interesting = _strong_candidate()  # one round -> interesting
    assert anomalies_to_hypotheses(interesting) == []
    strong = classify_anomalies(_strong_candidate(), history=_strong_candidate())
    seeds = anomalies_to_hypotheses(strong)
    assert len(seeds) == 1
    seed = seeds[0]
    assert seed["origin"] == "discovery-anomaly"
    assert seed["source"] == "discovery"
    assert seed["gap_id"].startswith("discovery:")
    assert "negative_control" in seed["required_evidence"]


def test_seed_gap_ids_are_stable_across_rounds() -> None:
    strong_a = classify_anomalies(_strong_candidate(), history=_strong_candidate())
    strong_b = classify_anomalies(_strong_candidate(), history=_strong_candidate())
    assert anomalies_to_hypotheses(strong_a)[0]["gap_id"] == (
        anomalies_to_hypotheses(strong_b)[0]["gap_id"]
    )


def test_hypothesis_seeds_are_capped() -> None:
    from webpent.autonomous.hunt_discovery import _MAX_HYPOTHESES

    strong = []
    for index in range(_MAX_HYPOTHESES + 4):
        strong.append(
            {"probe": f"probe-{index}", "kind": "status_divergence",
             "confidence": 0.8, "samples": 2, "tier": "strong",
             "repeat_count": 2, "detail": {}}
        )
    assert len(anomalies_to_hypotheses(strong)) == _MAX_HYPOTHESES


# ---------------------------------------------------------------------------
# 4) route / parameter / endpoint inference: scope + dedup + caps
# ---------------------------------------------------------------------------


def test_route_variants_are_minted_for_id_templates() -> None:
    candidates = infer_route_patterns(
        ["/api/items/12345"], admin_evidence=True
    )
    paths = {c["path"] for c in candidates}
    # The versioned sibling does NOT double the /api prefix (red-team R5).
    assert "/api/items/1" in paths
    assert "/api/v2/items/1" in paths
    assert "/api/v2/api/items/1" not in paths
    assert "/admin/api/items/1" in paths
    # No placeholder path is ever minted (red-team R5b).
    assert not any("{id}" in p for p in paths)
    assert all(c["origin"] == "discovery-route" for c in candidates)
    assert all(c["signature"] for c in candidates)


def test_admin_variant_requires_observed_evidence() -> None:
    # Speculation is not evidence: without observed admin evidence the
    # /admin sibling is never minted (red-team R6).
    candidates = infer_route_patterns(["/api/items/12345"])
    assert not any("/admin" in c["path"] for c in candidates)
    gated = infer_route_patterns(["/api/items/12345"], admin_evidence=True)
    assert any("/admin" in c["path"] for c in gated)


def test_pipeline_gates_admin_variants_on_observed_evidence() -> None:
    records = [
        {"url": "http://lab.example/api/items/177", "content_length": 1000},
        {"url": "http://lab.example/api/items/178", "content_length": 1900},
    ]
    without = discover_from_records(records)
    assert not any(
        "/admin" in r["path"] for r in without["routes"]
    )
    with_admin = discover_from_records(
        [
            {**record, "detail": "admin panel noted here"}
            for record in records
        ]
    )
    assert any("/admin" in r["path"] for r in with_admin["routes"])


def test_route_candidates_respect_seen_signatures() -> None:
    first = infer_route_patterns(["/api/items/12345"])
    seen = {c["signature"] for c in first}
    second = infer_route_patterns(["/api/items/12345"], seen_signatures=seen)
    assert second == []


def test_static_and_non_path_inputs_are_ignored() -> None:
    assert infer_route_patterns(["/static/app.js", "not-a-path", "", "/api/v2/data"]) == []


def test_route_candidates_are_capped() -> None:
    from webpent.autonomous.hunt_discovery import _MAX_ROUTES

    paths = [f"/api/resource{i}/777" for i in range(_MAX_ROUTES + 6)]
    assert len(infer_route_patterns(paths)) == _MAX_ROUTES


def test_parameter_siblings_are_minted_and_deduped() -> None:
    first = infer_parameters(["id"])
    names = {c["param"] for c in first}
    assert "user_id" in names
    seen = {c["signature"] for c in first}
    assert infer_parameters(["id"], seen_signatures=seen) == []


def test_unknown_parameters_mint_nothing() -> None:
    assert infer_parameters(["totally_unknown_param"]) == []


def test_endpoints_mined_from_metadata_only_and_capped() -> None:
    records = [
        {"url": "http://lab.example/", "reason": "redirect noted to /internal/admin/panel"},
        {"url": "http://lab.example/", "reason": "asset /static/site.css is not interesting"},
    ]
    found = mine_endpoints(records)
    paths = {c["path"] for c in found}
    assert "/internal/admin/panel" in paths
    assert not any(".css" in p for p in paths)
    assert all(c["origin"] == "discovery-endpoint" for c in found)


# ---------------------------------------------------------------------------
# 5) hybrid scenarios: evidence-backed capabilities only
# ---------------------------------------------------------------------------


def test_hybrids_require_evidence_on_records() -> None:
    bare = [{"url": "http://lab.example/", "detail": "svg upload accepts image/svg"}]
    assert generate_hybrid_scenarios(bare) == []
    backed = [
        {"url": "http://lab.example/", "detail": "svg upload accepts image/svg",
         "evidence_refs": ["obs:1"]},
        {"url": "http://lab.example/", "detail": "svg-render preview rendered_svg",
         "evidence_refs": ["obs:2"]},
    ]
    scenarios = generate_hybrid_scenarios(backed)
    assert len(scenarios) == 1
    scenario = scenarios[0]
    assert scenario["origin"] == "discovery-hybrid"
    assert scenario["capabilities"] == ["accepts_svg_upload", "renders_svg_content"]
    assert scenario["required_evidence"] == [
        "baseline_response", "candidate_response", "negative_control",
    ]


# ---------------------------------------------------------------------------
# 6) uncertainty budget + agenda + one-call pipeline
# ---------------------------------------------------------------------------


def test_uncertainty_budget_weights_unknown_regions_higher() -> None:
    weighted = allocate_uncertainty_budget(
        [
            {"region": "doc", "knowledge_level": "documented"},
            {"region": "anom", "knowledge_level": "anomalous_unexplained",
             "unexplained_anomalies": 2},
        ]
    )
    by_region = {w["region"]: w["budget_share"] for w in weighted}
    assert by_region["anom"] > by_region["doc"]
    assert abs(sum(by_region.values()) - 1.0) < 0.01


def test_discover_from_records_pipeline_shape() -> None:
    records = [
        _outcome(sizes=[1000], params=["id"]),
        _outcome(sizes=[1900], params=["id"]),
    ]
    result = discover_from_records(records)
    assert result["origin"] == "discovery"
    for key in (
        "anomalies", "hypotheses", "routes", "endpoints", "params",
        "hybrids", "uncertainty_budget", "agenda",
    ):
        assert key in result
    assert len(result["anomalies"]) == 1
    assert result["anomalies"][0]["tier"] == "interesting"


def test_pipeline_mints_hypotheses_with_cross_round_history() -> None:
    records = [
        _outcome(sizes=[1000]),
        _outcome(sizes=[1900]),
    ]
    first = discover_from_records(records)
    assert first["hypotheses"] == []
    second = discover_from_records(records, prior_anomalies=first["anomalies"])
    assert len(second["hypotheses"]) == 1
    assert second["hypotheses"][0]["origin"] == "discovery-anomaly"


def test_agenda_counts_match_pipeline_output() -> None:
    records = [
        _outcome(sizes=[1000], params=["id"]),
        _outcome(sizes=[1900], params=["id"]),
    ]
    result = discover_from_records(records)
    agenda = result["agenda"]
    assert agenda["new_parameters"] == len(result["params"])
    assert agenda["new_routes"] == len(result["routes"])
    assert agenda["unvalidated_hypotheses"] == len(result["hypotheses"])
    assert agenda["hybrid_scenarios"] == len(result["hybrids"])
    assert agenda["order"][0] == "discovery-anomaly-hypotheses"


# ---------------------------------------------------------------------------
# 7) orchestrator wiring: advisory merge, dedup, convergence, report
# ---------------------------------------------------------------------------


def _anomaly_update() -> dict[str, Any]:
    """A scripted controller update carrying two same-probe outcomes."""
    return {
        "campaign_task_outcomes": [
            {"task_id": "t1", "url": "http://lab.example/api/item/177",
             "status_code": 200, "content_length": 1000},
            {"task_id": "t1", "url": "http://lab.example/api/item/177",
             "status_code": 200, "content_length": 1900},
        ],
        "stop_reason": "",
    }


def _growing_updates(rounds: int = 3) -> list[dict[str, Any]]:
    """Scripted updates whose evidence ledgers grow each round.

    The hunt's convergence fingerprint digests ledger lengths, so without
    growth the loop would stop after the first round; growing ledgers let
    the test walk the loop forward to the stall-and-rehypothesize path.
    """
    base = _anomaly_update()
    updates: list[dict[str, Any]] = []
    for index in range(rounds):
        update = dict(base)
        update["negative_evidence_ledger"] = [{"n": j} for j in range(index + 1)]
        updates.append(update)
    return updates + [updates[-1]]


def _run_hunt(updates: list[dict[str, Any]], *, max_iterations: int = 6):
    controller = _FakeController(updates)
    orch = AutonomousHuntOrchestrator(
        action_executor=object(),
        handler=lambda task: None,
        controller=controller,
        max_iterations=max_iterations,
    )
    state = AutonomousHuntState(engagement_id="e1", target_url="http://lab.example/")
    return orch.run(state)


def test_orchestrator_populates_discovery_state() -> None:
    state = _run_hunt([_anomaly_update()], max_iterations=1)
    assert state.discovery is not None
    assert len(state.discovery["anomalies"]) == 1
    assert state.discovery["anomalies"][0]["tier"] == "interesting"
    # One round of repetition is never enough for a hypothesis seed.
    assert state.discovery["hypotheses"] == []


def test_orchestrator_merges_repeated_signal_as_discovery_hypothesis() -> None:
    state = _run_hunt(_growing_updates(), max_iterations=6)
    origins = {item.get("origin") for item in state.hypotheses}
    assert "discovery-anomaly" in origins
    seed = next(item for item in state.hypotheses if item["origin"] == "discovery-anomaly")
    assert seed["target_url"].startswith("http://lab.example")
    # The merge is recorded in the phase trace under the hypothesis phase.
    assert any(
        record.status == "ok" and record.detail.get("source") == "discovery"
        for record in state.phase_trace
        if record.phase.value == "hypothesis"
    )


def test_discovery_seeds_dedup_across_rounds_and_loop_converges() -> None:
    state = _run_hunt(_growing_updates(), max_iterations=6)
    assert state.stop_reason is HuntStopReason.NO_NEW_EVIDENCE
    # Exactly one discovery seed was merged despite repeated discovery rounds.
    seeds = [h for h in state.hypotheses if h.get("origin") == "discovery-anomaly"]
    assert len(seeds) == 1


def test_minted_candidate_signatures_are_remembered() -> None:
    route_update = {
        "campaign_task_outcomes": [
            {"task_id": "t1", "url": "http://lab.example/api/items/4200",
             "status_code": 200, "content_length": 10},
        ],
        "stop_reason": "",
    }
    round_one = dict(route_update)
    round_one["negative_evidence_ledger"] = [{"n": 0}]
    round_two = dict(route_update)
    round_two["negative_evidence_ledger"] = [{"n": 0}, {"n": 1}]
    state = _run_hunt([round_one, round_two, round_two], max_iterations=4)
    assert state.discovery is not None
    assert state.discovery_signatures, "minted route candidates must be remembered"
    # Round two mints nothing new: every candidate signature is already known.
    assert state.discovery["routes"] == []
    assert state.discovery["endpoints"] == []


def test_report_carries_machine_derived_discovery_summary() -> None:
    state = _run_hunt(_growing_updates(), max_iterations=6)
    report = state.to_report_json()
    summary = report["discovery_summary"]
    assert summary["present"] is True
    assert summary["anomalies"] == 1
    assert summary["hypotheses"] == 1
    assert summary["agenda"]["origin"] == "discovery-agenda"
    assert report["hypothesis_origins"].get("discovery-anomaly") == 1


def test_report_discovery_summary_is_zeroed_for_empty_round() -> None:
    state = _run_hunt([{"campaign_task_outcomes": [], "stop_reason": ""}], max_iterations=1)
    summary = state.to_report_json()["discovery_summary"]
    assert summary["present"] is True
    assert summary["anomalies"] == 0
    assert summary["hypotheses"] == 0
    assert summary["minted_candidate_signatures"] == 0


# ---------------------------------------------------------------------------
# 8) registry honesty: producer gap is machine-readable
# ---------------------------------------------------------------------------


def test_producer_gap_is_true_only_for_producerless_classes() -> None:
    assert coverage_gap("elasticsearch_snapshot_traversal")["producer_gap"] is True
    assert coverage_gap("xslt_injection")["producer_gap"] is True
    assert coverage_gap("sqli")["producer_gap"] is False
    assert coverage_gap("cloud_storage_exposure")["producer_gap"] is False
    assert coverage_gap("unknown_future_class")["producer_gap"] is False


# ---------------------------------------------------------------------------
# 9) red-team fixes (docs/plans/2026-10-14-v75-redteam.md)
# ---------------------------------------------------------------------------

from webpent.autonomous.hunt_discovery import _stringify_strings  # noqa: E402


def _status_records(statuses: list[int]) -> list[dict[str, Any]]:
    return [
        {"url": "http://lab.example/x", "status_code": status}
        for status in statuses
    ]


def test_stringify_walks_flat_records_fully() -> None:
    # Red-team R1: the old depth counter stopped after ~7 stack pops,
    # dropping flat records' later fields.
    record = {f"field_{index}": f"value{index}" for index in range(10)}
    strings = _stringify_strings(record)
    assert len(strings) == 10
    assert set(strings) == {f"value{i}" for i in range(10)}


def test_stringify_reaches_deep_nesting_within_bounds() -> None:
    record: dict[str, Any] = {"leaf": "bottom"}
    # Seven wraps put "bottom" exactly at nesting depth 8 (the cap).
    for level in range(7):
        record = {"nested": record, f"level_{level}": f"s{level}"}
    strings = _stringify_strings(record)
    assert "bottom" in strings
    assert "s0" in strings


def test_stringify_caps_at_200_strings() -> None:
    record = {f"k{i}": f"v{i}" for i in range(250)}
    assert len(_stringify_strings(record)) == 200


def test_absolute_floors_block_tiny_magnitude_noise() -> None:
    # Red-team R2: 3 vs 4 bytes and 10 vs 20 ms both clear the relative
    # thresholds; the absolute floors must keep them from firing.
    records = [
        {"url": "http://lab.example/x", "content_length": 3},
        {"url": "http://lab.example/x", "content_length": 4},
        {"url": "http://lab.example/y", "elapsed_ms": 10},
        {"url": "http://lab.example/y", "elapsed_ms": 20},
    ]
    assert monitor_anomalies(records) == []


def test_status_confidence_scales_with_distinct_statuses() -> None:
    anomalies = monitor_anomalies(_status_records([200, 404]))
    assert anomalies[0]["confidence"] == 0.75
    anomalies = monitor_anomalies(_status_records([200, 404, 500]))
    assert anomalies[0]["confidence"] == 0.85
    anomalies = monitor_anomalies(_status_records([200, 404, 500, 502, 503]))
    assert anomalies[0]["confidence"] == 0.9


def test_skip_round_signal_never_reaches_strong() -> None:
    # Red-team R9: repetition is judged across CONSECUTIVE rounds; a
    # signal in rounds 1 and 3 with a quiet round 2 stays interesting.
    first = monitor_anomalies(
        [
            {"url": "http://lab.example/x", "elapsed_ms": 900},
            {"url": "http://lab.example/x", "elapsed_ms": 1400},
        ]
    )
    classified_first = classify_anomalies(first)
    assert classified_first[0]["tier"] == "interesting"
    # Round 2: quiet.
    quiet: list[dict[str, Any]] = []
    classified_second = classify_anomalies(quiet, history=classified_first)
    # Round 3: the signal returns, but history (round 2) does not hold it.
    third = monitor_anomalies(
        [
            {"url": "http://lab.example/x", "elapsed_ms": 900},
            {"url": "http://lab.example/x", "elapsed_ms": 1400},
        ]
    )
    classified_third = classify_anomalies(third, history=classified_second)
    assert classified_third[0]["tier"] == "interesting"


def test_endpoints_skip_url_scheme_and_host_fragments() -> None:
    # Red-team R12: mining a record's own URL must not mint the host or
    # scheme fragments as "endpoints".
    records = [
        {"url": "https://lab.example/api/items/177", "status_code": 200},
        {"reason": "redirect -> /dashboard/settings"},
    ]
    endpoints = mine_endpoints(records)
    paths = {e["path"] for e in endpoints}
    assert not any("lab.example" in p for p in paths)
    assert "/dashboard/settings" in paths


def test_budget_counts_only_unexplained_anomalies() -> None:
    # Red-team R14: noise anomalies are explained away; they must not
    # inflate any region's unexplained count.
    records = [
        {"url": "http://lab.example/x", "content_length": 1000},
        {"url": "http://lab.example/x", "content_length": 1900},
    ]
    result = discover_from_records(records)
    tiers = {a["tier"] for a in result["anomalies"]}
    assert tiers == {"interesting"}
    documented = next(
        r for r in result["uncertainty_budget"] if r["region"] == "observed-paths"
    )
    anomalous = next(
        r for r in result["uncertainty_budget"] if r["region"] == "anomalous-probes"
    )
    assert documented["unexplained_anomalies"] == 0
    assert anomalous["unexplained_anomalies"] == 1


def test_param_signature_scoped_to_source_name() -> None:
    # Red-team R11: `uid` minted from `id` must not block minting `uid`
    # from `user_id` observed elsewhere.
    first = infer_parameters(["id"])
    assert any(c["param"] == "uid" for c in first)
    seen = {c["signature"] for c in first}
    second = infer_parameters(["user_id"], seen_signatures=set(seen))
    assert any(c["param"] == "uid" for c in second)


def test_hybrids_dedup_across_rounds() -> None:
    records = [
        {
            "url": "http://lab.example/upload",
            "status_code": 200,
            "evidence_refs": ["ev-1"],
            "note": "accepts svg upload and svg-render preview",
        }
    ]
    first = discover_from_records(records)
    assert first["hybrids"], "evidence-backed capability pair must mint once"
    seen = {s for c in first["routes"] for s in [c["signature"]]}
    seen |= {c["signature"] for c in first["endpoints"]}
    seen |= {c["signature"] for c in first["params"]}
    seen |= {
        c["scenario_id"].removeprefix("discovery:") for c in first["hybrids"]
    }
    second = discover_from_records(records, seen_signatures=set(seen))
    assert second["hybrids"] == []


def _merge_state_with_probe(probe: str) -> Any:
    """A hunt state whose discovery holds one seed with the given probe."""
    state = AutonomousHuntState(
        engagement_id="e1", target_url="http://lab.example/"
    )
    state.discovery = {
        "hypotheses": [
            {
                "gap_id": "gap-status_divergence-x",
                "origin": "discovery-anomaly",
                "anomaly": {"probe": probe, "kind": "status_divergence"},
            }
        ]
    }
    orch = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda task: None, controller=None
    )
    return state, orch


def test_seed_target_points_at_divergent_probe_when_same_origin() -> None:
    # Red-team R17: the divergent endpoint is the actionable payload.
    state, orch = _merge_state_with_probe("http://lab.example/api/item/177")
    added = orch._merge_discovery_hypotheses(state)
    assert added == 1
    assert state.hypotheses[0]["target_url"] == "http://lab.example/api/item/177"


def test_foreign_origin_probe_keeps_generic_target_pin() -> None:
    state, orch = _merge_state_with_probe("http://foreign.example/api/item/177")
    orch._merge_discovery_hypotheses(state)
    assert state.hypotheses[0]["target_url"] == "http://lab.example/"


def test_report_pattern_id_falls_back_to_gap_id() -> None:
    # Red-team R10: merged discovery seeds must not render a blank
    # pattern_id in the report.
    state, orch = _merge_state_with_probe("http://lab.example/api/item/177")
    orch._merge_discovery_hypotheses(state)
    report = state.to_report_json()
    assert report["hypotheses"][0]["pattern_id"].startswith("gap:")


def test_discovery_phase_record_has_distinct_reason() -> None:
    # Red-team R16: a phase-trace reader must be able to tell a
    # discovery round from an observation record.
    state = _run_hunt([_anomaly_update()], max_iterations=1)
    assert any(
        record.phase.value == "observe"
        and record.reason == "discovery_candidates"
        for record in state.phase_trace
    )


def test_discovery_agenda_shape_is_enforced() -> None:
    # Red-team R31b: the agenda flows into the report wholesale, so its
    # shape (counts and static strings only) is part of the redaction
    # contract and must be pinned.
    agenda = discover_from_records(
        [{"url": "http://lab.example/api/items/177", "content_length": 1000},
         {"url": "http://lab.example/api/items/177", "content_length": 1900}]
    )["agenda"]
    assert set(agenda) == {
        "origin", "unvalidated_hypotheses", "new_routes", "new_endpoints",
        "new_parameters", "hybrid_scenarios", "order", "coverage_packs",
    }
    static_keys = {"origin"}
    for key, value in agenda.items():
        if key == "order":
            assert isinstance(value, list)
            assert all(isinstance(entry, str) for entry in value)
        elif key == "coverage_packs":
            # v80: honest per-class coverage rows; static internal content
            # only (class labels, statuses, advisory probe descriptions).
            assert isinstance(value, list) and len(value) == 4
            classes = {row["class"] for row in value}
            assert classes == {"ssti", "xxe", "ssrf", "backup_files"}
            assert all(row["status"] == "missing-validator" for row in value)
        elif key in static_keys:
            assert isinstance(value, str)
        else:
            assert isinstance(value, int) and value >= 0

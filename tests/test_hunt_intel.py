"""v80 Task 1 + Task 3: cross-session intel store and mid-hunt auth recheck.

Proven properties:

* only proof-verified bundles enter the intel store (candidates never do),
* no secrets and no query values survive into the stored intel file,
* bounds (classes/endpoints/origins) are enforced,
* persistence round-trips and a corrupt file degrades to "no memory",
* intel memory actually changes the next round's hypotheses (advisory),
* a mid-hunt authorization refusal stops the hunt BLOCKED before any
  further execution, and a None recheck changes nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from webpent.autonomous import (
    AutonomousHuntOrchestrator,
    AutonomousHuntState,
    HuntOutcome,
    HuntStopReason,
)
from webpent.autonomous.hunt_intel import (
    MAX_CLASSES_PER_ORIGIN,
    MAX_ENDPOINTS_PER_ORIGIN,
    MAX_ORIGINS,
    IntelStore,
)


class _FakeController:
    """A controller double returning the same evidence-free update."""

    def __init__(self) -> None:
        self.calls = 0

    def run(self, state, *, handler, iterations=1):  # noqa: ANN001
        self.calls += 1
        return {"campaign_task_outcomes": []}


def _bundle(vuln_class: str, url: str) -> dict[str, Any]:
    return {"vuln_class": vuln_class, "url": url, "sealed": True}


class _FakeState:
    """Minimal state double carrying only what IntelStore reads."""

    def __init__(self, target_url: str, bundles: list[dict[str, Any]]) -> None:
        self.target_url = target_url
        self.proof_bundles = bundles
        self.findings: list[dict[str, Any]] = []


def _hunt_state(target_url: str) -> AutonomousHuntState:
    return AutonomousHuntState(
        engagement_id="e1", target_url=target_url, target_knowledge={}, max_iterations=3
    )


# -- update_from_state --------------------------------------------------


def test_only_verified_bundles_enter_the_store(tmp_path: Path) -> None:
    store = IntelStore(tmp_path / "intel.json")
    state = _FakeState(
        "http://lab.example/login",
        [_bundle("sqli", "http://lab.example/login")],
    )
    state.findings = [{"finding_id": "candidate", "vuln_class": "xss"}]
    store.update_from_state(state)
    record = store.record_for("http://lab.example/login")
    assert record["verified_classes"] == {"sqli": 1}
    # The unverified candidate finding must not appear anywhere.
    dumped = json.dumps(store._origins)
    assert "xss" not in dumped
    assert "candidate" not in dumped


def test_no_secrets_and_no_query_values_stored(tmp_path: Path) -> None:
    store = IntelStore(tmp_path / "intel.json")
    state = _FakeState(
        "http://lab.example/admin",
        [
            _bundle(
                "sqli",
                "http://lab.example/admin?password=hunter2&token=abc123def456&page=2",
            )
        ],
    )
    store.update_from_state(state)
    store.save()
    dumped = (tmp_path / "intel.json").read_text(encoding="utf-8")
    assert "hunter2" not in dumped
    assert "abc123def456" not in dumped
    assert "?" not in dumped.replace('{"', "")
    hints = store.record_for("http://lab.example/admin")["endpoint_hints"]
    assert hints == ["http://lab.example/admin"]


def test_bounds_are_enforced(tmp_path: Path) -> None:
    store = IntelStore(tmp_path / "intel.json")
    bundles = [
        _bundle(f"class{i}", f"http://lab.example/path{i}") for i in range(50)
    ]
    store.update_from_state(_FakeState("http://lab.example/", bundles))
    record = store.record_for("http://lab.example/")
    assert len(record["verified_classes"]) <= MAX_CLASSES_PER_ORIGIN
    assert len(record["endpoint_hints"]) <= MAX_ENDPOINTS_PER_ORIGIN
    for i in range(MAX_ORIGINS + 4):
        store.update_from_state(_FakeState(f"http://host{i}.example/", []))
    assert len(store.origins()) <= MAX_ORIGINS


def test_repeated_bundles_accumulate_counts(tmp_path: Path) -> None:
    store = IntelStore(tmp_path / "intel.json")
    for _ in range(3):
        store.update_from_state(
            _FakeState("http://lab.example/", [_bundle("sqli", "http://lab.example/")])
        )
    assert store.record_for("http://lab.example/")["verified_classes"] == {"sqli": 3}


# -- persistence --------------------------------------------------------


def test_save_load_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "intel.json"
    store = IntelStore(path)
    store.update_from_state(
        _FakeState("http://lab.example/", [_bundle("sqli", "http://lab.example/login")])
    )
    store.save()
    reloaded = IntelStore(path)
    assert reloaded.record_for("http://lab.example/login") == store.record_for(
        "http://lab.example/login"
    )


def test_corrupt_file_degrades_to_empty_store(tmp_path: Path) -> None:
    path = tmp_path / "intel.json"
    path.write_text("{not valid json", encoding="utf-8")
    store = IntelStore(path)
    assert store.origins() == []
    # A wrong-typed document degrades the same way.
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert IntelStore(path).origins() == []


def test_save_is_atomic_no_temp_litter(tmp_path: Path) -> None:
    path = tmp_path / "intel.json"
    IntelStore(path).save()
    assert path.is_file()
    assert [item.name for item in tmp_path.iterdir()] == ["intel.json"]


# -- seeds --------------------------------------------------------------


def test_seeds_rank_proven_classes_first_and_cap_priority(tmp_path: Path) -> None:
    store = IntelStore(tmp_path / "intel.json")
    bundles = [_bundle("sqli", "http://lab.example/a") for _ in range(7)]
    bundles += [_bundle("xss", "http://lab.example/b")]
    store.update_from_state(_FakeState("http://lab.example/", bundles))
    seeds = store.hypothesis_seeds("http://lab.example/")
    assert [seed["vuln_class"] for seed in seeds] == ["sqli", "xss"]
    for seed in seeds:
        assert seed["advisory"] is True
        assert seed["source"] == "intel"
        assert 0.0 <= seed["priority"] <= 0.75
    # A target with no record yields no seeds.
    assert store.hypothesis_seeds("http://other.example/") == []


def test_intel_changes_the_next_round_hypotheses(tmp_path: Path) -> None:
    """The v80 completion criterion: memory changes the next hunt.

    Two identical evidence-free hunts over the same target; the only
    difference is a populated intel store. With intel, the rehypothesize
    phase merges ``advisory:intel:*`` seeds; without it, none appear.
    """
    store = IntelStore(tmp_path / "intel.json")
    store.update_from_state(
        _FakeState("http://lab.example/", [_bundle("sqli", "http://lab.example/login")])
    )

    def _run(intel: Any) -> AutonomousHuntState:
        orchestrator = AutonomousHuntOrchestrator(
            action_executor=object(), handler=lambda task: None, controller=_FakeController()
        )
        if intel is not None:
            orchestrator.intel = intel
        return orchestrator.run(_hunt_state("http://lab.example/"))

    without = _run(None)
    assert not [h for h in without.hypotheses if str(h.get("source")) == "intel"]

    with_intel = _run(store)
    intel_seeds = [h for h in with_intel.hypotheses if str(h.get("source")) == "intel"]
    assert intel_seeds, "intel memory must produce hypothesis seeds"
    assert intel_seeds[0]["hypothesis_id"].startswith("advisory:intel:sqli")
    assert intel_seeds[0]["advisory"] is True


# -- orchestrator wiring: advisory merge + auth recheck -----------------


def test_coverage_pack_seeds_merge_advisory_into_round(tmp_path: Path) -> None:
    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda task: None, controller=_FakeController()
    )
    state = _hunt_state("http://lab.example/")
    orchestrator.run(state)
    pack_seeds = [h for h in state.hypotheses if str(h.get("source")) == "coverage_pack"]
    assert pack_seeds, "coverage packs must seed the uncovered classes"
    assert all(seed["advisory"] is True for seed in pack_seeds)
    assert all(float(seed["priority"]) <= 0.75 for seed in pack_seeds)


def test_advisory_seeds_dedup_across_rounds(tmp_path: Path) -> None:
    calls = {"n": 0}

    class _TwoRoundController:
        def run(self, state, *, handler, iterations=1):  # noqa: ANN001
            calls["n"] += 1
            return {"campaign_task_outcomes": []}

    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda task: None, controller=_TwoRoundController()
    )
    state = _hunt_state("http://lab.example/")
    orchestrator.run(state)
    ids = [str(h.get("hypothesis_id")) for h in state.hypotheses]
    assert len(ids) == len(set(ids)), "advisory seeds must dedup across rounds"


def test_auth_recheck_blocks_mid_hunt_before_further_execution() -> None:
    controller = _FakeController()
    decisions = [None, "authorization expired at 2020-01-01T00:00:00+00:00"]

    def recheck() -> str | None:
        decision = decisions.pop(0) if decisions else "expired"
        return decision

    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda task: None, controller=controller
    )
    orchestrator.auth_recheck = recheck
    state = _hunt_state("http://lab.example/")
    orchestrator.run(state)
    # The refusal arrived at the top of iteration 2: execute ran once, the
    # hunt stopped BLOCKED with the typed reason, and the refusal is
    # recorded redacted in the phase trace.
    assert controller.calls == 1
    assert state.stop_reason is HuntStopReason.AUTHORIZATION_REVOKED
    assert state.outcome is HuntOutcome.BLOCKED
    blocked = [
        record
        for record in state.phase_trace
        if record.reason == "authorization_revoked_mid_hunt"
    ]
    assert blocked, "the refusal must be recorded in the phase trace"


def test_auth_recheck_none_is_a_noop() -> None:
    controller = _FakeController()
    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda task: None, controller=controller
    )
    state = _hunt_state("http://lab.example/")
    orchestrator.run(state)
    assert state.stop_reason is not HuntStopReason.AUTHORIZATION_REVOKED
    assert controller.calls >= 1


def test_intel_failure_never_breaks_a_hunt(tmp_path: Path) -> None:
    class _BrokenIntel:
        def hypothesis_seeds(self, target_url):  # noqa: ANN001
            raise RuntimeError("boom")

        def update_from_state(self, state):  # noqa: ANN001
            raise RuntimeError("boom")

        def save(self):  # noqa: ANN001
            raise RuntimeError("boom")

    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda task: None, controller=_FakeController()
    )
    orchestrator.intel = _BrokenIntel()
    state = _hunt_state("http://lab.example/")
    orchestrator.run(state)
    assert state.stop_reason is not None
    reasons = [record.reason for record in state.phase_trace]
    assert "intel_update_failed" in reasons or "intel_seeds_unavailable" in reasons


def test_empty_hunt_creates_no_intel_record(tmp_path: Path) -> None:
    """CR-2: a hunt with zero bundles must not pollute origin memory."""
    store = IntelStore(tmp_path / "intel.json")
    store.update_from_state(_FakeState("http://lab.example/", []))
    assert store.origins() == []


def test_foreign_origin_bundle_urls_stay_out_of_target_hints(tmp_path: Path) -> None:
    """CR-4: hints are per-origin; another origin's URL must not leak in."""
    store = IntelStore(tmp_path / "intel.json")
    store.update_from_state(
        _FakeState(
            "http://lab.example/",
            [
                _bundle("sqli", "http://lab.example/login"),
                _bundle("xss", "http://other.example/search"),
            ],
        )
    )
    hints = store.record_for("http://lab.example/")["endpoint_hints"]
    assert hints == ["http://lab.example/login"]


# -- v81: dead-end memory integration ------------------------------------


class _DeadEndState:
    """Fake state double carrying decisively-negative outcomes."""

    def __init__(self, outcomes: list[dict[str, Any]]) -> None:
        self.target_url = "http://lab.example/"
        self.outcomes = outcomes


def _populated_deadends(tmp_path: Path, name: str = "deadends.json"):
    from webpent.autonomous.hunt_deadends import DeadEndStore

    store = DeadEndStore(tmp_path / name)
    store.update_from_state(
        _DeadEndState(
            [
                {
                    "status": "executed",
                    "vulnerability_class": "ssti",
                    "vulnerable": False,
                    "url": "http://lab.example/render",
                },
                {
                    "status": "clean",
                    "vulnerability_class": "ssti",
                    "url": "http://lab.example/api",
                },
            ]
        )
    )
    return store


def test_dead_end_memory_demotes_pack_seeds_but_keeps_them(tmp_path: Path) -> None:
    deadends = _populated_deadends(tmp_path)
    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda task: None, controller=_FakeController()
    )
    orchestrator.deadends = deadends
    state = _hunt_state("http://lab.example/")
    orchestrator.run(state)
    pack = [h for h in state.hypotheses if str(h.get("source")) == "coverage_pack"]
    ssti = [h for h in pack if h.get("vuln_class") == "ssti"]
    others = [h for h in pack if h.get("vuln_class") != "ssti"]
    assert ssti and others, "pack seeds must still exist"
    # Demoted but kept: the ssti seed ranks below its intact siblings.
    assert all(float(s["priority"]) < min(float(o["priority"]) for o in others) for s in ssti)
    assert all("dead-end" in str(s.get("rationale", "")).lower() for s in ssti)
    demoted_records = [
        r
        for r in state.phase_trace
        if getattr(r, "detail", {}).get("dead_end_demoted", 0) > 0
        if isinstance(getattr(r, "detail", None), dict)
    ]
    assert demoted_records, "the demotion must be visible in the phase trace"


def test_intel_verified_class_is_never_demoted(tmp_path: Path) -> None:
    """Proof history outranks negative memory: a class verified on this
    target keeps its intel priority even with dead-end pairs recorded."""
    intel = IntelStore(tmp_path / "intel.json")
    intel.update_from_state(
        _FakeState("http://lab.example/", [_bundle("ssti", "http://lab.example/render")])
    )
    deadends = _populated_deadends(tmp_path)
    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda task: None, controller=_FakeController()
    )
    orchestrator.intel = intel
    orchestrator.deadends = deadends
    state = _hunt_state("http://lab.example/")
    orchestrator.run(state)
    intel_seeds = [h for h in state.hypotheses if str(h.get("source")) == "intel"]
    assert intel_seeds, "intel memory must still seed the hunt"
    # The intel seed's priority is untouched by the dead-end store.
    uncapped = 0.5 + min(1, 5) * 0.05
    assert all(abs(float(h["priority"]) - uncapped) < 1e-9 for h in intel_seeds)
    assert all("dead-end" not in str(h.get("rationale", "")).lower() for h in intel_seeds)


def test_fresh_discovery_seeds_are_never_demoted(tmp_path: Path) -> None:
    deadends = _populated_deadends(tmp_path)
    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda task: None, controller=_FakeController()
    )
    orchestrator.deadends = deadends
    state = _hunt_state("http://lab.example/")
    state.discovery = {
        "hypotheses": [
            {"gap_id": "g1", "vuln_class": "ssti", "priority": 0.9},
        ]
    }
    # Merged directly: _phase_discover would overwrite the injected dict,
    # and the guarantee under test is that the discovery merge path itself
    # never applies the dead-end penalty (only _merge_advisory_seeds does).
    assert orchestrator._merge_discovery_hypotheses(state) == 1
    seeds = [h for h in state.hypotheses if h.get("hypothesis_id") == "gap:g1"]
    assert seeds, "the discovery seed must survive"
    assert float(seeds[0]["priority"]) == 0.9, "fresh evidence is never suppressed"


def test_dead_end_ratio_caps_quiet_rehypothesize_rounds(tmp_path: Path) -> None:
    """A fully-mapped target stops after one quiet round instead of burning
    the loop's iterations on known dead ends. Without the store the old
    behavior is unchanged."""
    from webpent.autonomous.hunt_deadends import DeadEndStore

    deadends = DeadEndStore(tmp_path / "deadends.json")
    deadends.update_from_state(
        _DeadEndState(
            [
                {
                    "status": "clean",
                    "vulnerability_class": f"c{i}",
                    "url": f"http://lab.example/p{i}",
                }
                for i in range(16)
            ]
        )
    )
    assert deadends.dead_end_ratio("http://lab.example/") == 1.0

    calls = {"n": 0}

    class _Counting:
        def run(self, state, *, handler, iterations=1):  # noqa: ANN001
            calls["n"] += 1
            return {"campaign_task_outcomes": []}

    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda task: None, controller=_Counting()
    )
    orchestrator.deadends = deadends
    state = _hunt_state("http://lab.example/")
    orchestrator.run(state)
    # Stopped after a single executed round: no burning iterations on a
    # fully-mapped target.
    assert calls["n"] == 1
    assert state.stop_reason is HuntStopReason.NO_NEW_EVIDENCE
    capped = [
        r
        for r in state.phase_trace
        if getattr(r, "reason", "") == "budget_capped_rehypothesis"
    ]
    assert capped, "the budget cap must be visible in the phase trace"
    detail = capped[0].detail
    assert detail["recommended_rounds"] == 1
    assert detail["quiet_rounds"] >= 1


def test_without_deadend_store_the_quiet_round_behavior_is_unchanged() -> None:
    calls = {"n": 0}

    class _CountingController:
        def run(self, state, *, handler, iterations=1):  # noqa: ANN001
            calls["n"] += 1
            return {"campaign_task_outcomes": []}

    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda task: None, controller=_CountingController()
    )
    state = _hunt_state("http://lab.example/")
    orchestrator.run(state)
    # Pack seeds occupy the first quiet round; the second finds them deduped
    # and converges — two controller calls, the pre-v81 behavior.
    assert calls["n"] == 2
    assert state.stop_reason is HuntStopReason.NO_NEW_EVIDENCE

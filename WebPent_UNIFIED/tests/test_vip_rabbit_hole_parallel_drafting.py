"""Tests for parallel Rabbit Hole LLM-drafting (VIP speed initiative,
Track 3 — see
docs/archive/2026-11-01-plan-exec-root-reports/UNFREEZE_TRACK3_RABBIT_HOLE_DRAFTING_20261020.md).

Mirrors the structure of ``tests/test_vip_parallel_recon.py`` (Track 2).
Covers three layers:

  1. Settings flag — fail-closed resolution, default off, same pattern
     as ``enable_parallel_recon``.
  2. ``rabbit_hole_node`` end-to-end, real gate loop + real Phase
     B/C split, with a fake-but-deterministic LLM stub that records
     which thread invoked it and sleeps briefly to simulate network
     latency: flag off runs strictly sequentially (no overlapping
     invocations, in the original order); flag on runs the *approved*
     candidates' drafts concurrently (provably overlapping intervals)
     and is measurably faster — while producing EXACTLY the same
     hypotheses/ledger/goal-tree/decision-log content as the
     sequential run (same candidates approved, in the same order,
     because gate-checking is untouched by this change).
  3. Fail-closed settings resolution inside the node itself (a broken
     settings backend must never silently enable concurrency).
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from webpent.agents.rabbit_hole.agent import rabbit_hole_node
from webpent.models.mental_model import MentalModel, MentalModelNode, NodeKind
from webpent.models.targets import Target

TARGET_URL = "https://target.test"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, content):
        self.content = content


class _FakeLLM:
    """Deterministic stand-in for a real LangChain Runnable.

    Records which thread invoked it and when, with a small sleep to
    simulate network latency -- lets tests prove (a) sequential mode
    never overlaps calls, (b) parallel mode does, and (c) the content
    returned is identical regardless of call order (keyed by the URL
    embedded in the human prompt, not by call sequence).
    """

    def __init__(self, delay: float = 0.05):
        self.delay = delay
        self.invocations: list[tuple[str, float, float]] = []
        self.lock = threading.Lock()

    def invoke(self, messages):
        start = time.monotonic()
        human = messages[-1].content
        time.sleep(self.delay)
        end = time.monotonic()
        with self.lock:
            self.invocations.append((threading.current_thread().name, start, end))
        for line in human.splitlines():
            if line.startswith("Artifact URL/identity:"):
                url = line.split(":", 1)[1].strip()
                return _FakeResponse(f"Follow up on backup at {url}.")
        return _FakeResponse("Follow up on artifact.")


def _intervals_overlap(intervals: list[tuple[float, float]]) -> bool:
    ordered = sorted(intervals, key=lambda iv: iv[0])
    return any(
        ordered[i][1] > ordered[i + 1][0] for i in range(len(ordered) - 1)
    )


def _build_mental_model(n: int) -> MentalModel:
    model = MentalModel()
    for i in range(n):
        node = MentalModelNode(
            id=f"artifact-{i}",
            kind=NodeKind.ARTIFACT,
            identity_key=f"sha256:fakehash{i}",
            discovery_source="crawler_node",
            in_scope=True,
            metadata={"type": "archive", "url": f"{TARGET_URL}/backup{i}.zip"},
        )
        model.nodes[node.id] = node
    return model


def _build_state(mental_model: MentalModel) -> dict:
    return {
        "target": Target(url=TARGET_URL, domain="target.test"),
        "mental_model": mental_model.model_dump(mode="json"),
        "rabbit_hole_ledger": {},
        "goal_tree": {},
        "client_id": "c1",
        "engagement_id": "e1",
    }


def _run_rabbit_hole(monkeypatch, *, parallel: bool, n_artifacts: int = 3, delay: float = 0.05):
    import webpent.agents.rabbit_hole.agent as rh_module  # noqa: F401
    import webpent.config.settings as settings_module
    import webpent.shared.llm as llm_module

    fake_llm = _FakeLLM(delay=delay)
    monkeypatch.setattr(llm_module, "try_get_llm", lambda *a, **kw: fake_llm)
    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(enable_parallel_rabbit_hole_drafting=parallel),
    )

    state = _build_state(_build_mental_model(n_artifacts))
    start = time.monotonic()
    result = rabbit_hole_node(state)
    elapsed = time.monotonic() - start
    return result, fake_llm, elapsed


# ---------------------------------------------------------------------------
# Layer 1: settings flag resolution
# ---------------------------------------------------------------------------


def test_parallel_drafting_disabled_by_default_runs_sequentially(monkeypatch):
    result, fake_llm, _ = _run_rabbit_hole(monkeypatch, parallel=False)

    assert len(result["hypotheses"]) == 3
    assert len(fake_llm.invocations) == 3
    intervals = [(s, e) for _, s, e in fake_llm.invocations]
    assert not _intervals_overlap(intervals), "sequential mode must never overlap LLM calls"
    # Sequential mode uses the calling thread directly (no pool).
    assert all(name == "MainThread" for name, _, _ in fake_llm.invocations)


def test_parallel_drafting_enabled_runs_concurrently_and_faster(monkeypatch):
    result, fake_llm, elapsed_parallel = _run_rabbit_hole(
        monkeypatch, parallel=True, delay=0.05
    )
    assert len(result["hypotheses"]) == 3
    assert len(fake_llm.invocations) == 3

    intervals = [(s, e) for _, s, e in fake_llm.invocations]
    assert _intervals_overlap(intervals), "parallel mode must overlap LLM calls"

    thread_names = {name for name, _, _ in fake_llm.invocations}
    assert len(thread_names) == 3, "each draft should run on its own pool thread"
    assert all(name.startswith("webpent-rabbit-hole-draft") for name in thread_names)

    # 3 sequential 0.05s calls would take >=0.15s; concurrent should be
    # well under that (generous bound to avoid flakiness on slow CI).
    assert elapsed_parallel < 0.15


def test_parallel_drafting_fails_closed_on_settings_error(monkeypatch):
    """A broken settings backend must fall back to sequential drafting,
    never silently enable concurrency."""
    import webpent.config.settings as settings_module
    import webpent.shared.llm as llm_module

    fake_llm = _FakeLLM(delay=0.02)
    monkeypatch.setattr(llm_module, "try_get_llm", lambda *a, **kw: fake_llm)

    def _raise():
        raise RuntimeError("settings backend unavailable")

    monkeypatch.setattr(settings_module, "get_settings", _raise)

    state = _build_state(_build_mental_model(3))
    result = rabbit_hole_node(state)

    assert len(result["hypotheses"]) == 3
    intervals = [(s, e) for _, s, e in fake_llm.invocations]
    assert not _intervals_overlap(intervals), (
        "settings resolution error must fail closed to sequential drafting"
    )


# ---------------------------------------------------------------------------
# Layer 2: sequential vs parallel produce EQUIVALENT results
# ---------------------------------------------------------------------------


def test_sequential_and_parallel_produce_equivalent_results(monkeypatch):
    seq_result, _, _ = _run_rabbit_hole(monkeypatch, parallel=False)
    par_result, _, _ = _run_rabbit_hole(monkeypatch, parallel=True)

    seq_statements = sorted(h.statement for h in seq_result["hypotheses"])
    par_statements = sorted(h.statement for h in par_result["hypotheses"])
    assert seq_statements == par_statements

    seq_urls = sorted(h.target_url for h in seq_result["hypotheses"])
    par_urls = sorted(h.target_url for h in par_result["hypotheses"])
    assert seq_urls == par_urls

    seq_ledger_keys = sorted((seq_result.get("rabbit_hole_ledger") or {}).keys())
    par_ledger_keys = sorted((par_result.get("rabbit_hole_ledger") or {}).keys())
    assert seq_ledger_keys == par_ledger_keys

    seq_goal_nodes = (seq_result.get("goal_tree") or {}).get("nodes") or {}
    par_goal_nodes = (par_result.get("goal_tree") or {}).get("nodes") or {}
    assert len(seq_goal_nodes) == len(par_goal_nodes) == 3

    seq_rules = sorted(
        d.get("rule_fired", "") for d in (seq_result.get("decision_log") or [])
    )
    par_rules = sorted(
        d.get("rule_fired", "") for d in (par_result.get("decision_log") or [])
    )
    assert seq_rules == par_rules


def test_parallel_drafting_respects_max_branches_per_pass_cap(monkeypatch):
    """More than _MAX_BRANCHES_PER_PASS (3) followable artifacts exist,
    but only 3 branches are entered/drafted either way -- the cap is
    enforced in the untouched Phase A gate loop, before drafting."""
    result, fake_llm, _ = _run_rabbit_hole(monkeypatch, parallel=True, n_artifacts=10)

    assert len(result["hypotheses"]) == 3
    assert len(fake_llm.invocations) == 3


def test_no_followable_artifacts_skips_drafting_entirely(monkeypatch):
    import webpent.config.settings as settings_module
    import webpent.shared.llm as llm_module

    fake_llm = _FakeLLM()
    monkeypatch.setattr(llm_module, "try_get_llm", lambda *a, **kw: fake_llm)
    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(enable_parallel_rabbit_hole_drafting=True),
    )

    state = _build_state(MentalModel())  # empty — no artifact/credential nodes
    result = rabbit_hole_node(state)

    assert result.get("hypotheses") in (None, [])
    assert len(fake_llm.invocations) == 0


# ---------------------------------------------------------------------------
# Layer 3: Phase C construction failure — same propagation in both modes
# ---------------------------------------------------------------------------
#
# Adversarial self-review finding (2026-10-21): the Track 3 refactor moves
# the branches_entered/current_branches increments from the END of the
# original single-pass loop (after Hypothesis(...) succeeded and was
# appended to new_hypotheses) to immediately after a candidate clears
# Phase A's gates -- BEFORE Hypothesis(...) is ever called in Phase C.
# Manual code reading concluded this has no observable behavioral effect,
# because neither the pre-Track-3 nor the post-Track-3 code wraps
# Hypothesis(...) construction in any try/except: an exception there
# propagates all the way out of rabbit_hole_node (through graph/builder.py's
# _trace_wrap, which calls the node function with no protective try/except
# either) in BOTH versions, with no partial/intermediate return in either
# case -- so the moved counters are never observed by anything before the
# crash. This test turns that manual-reading conclusion into an executable
# assertion instead of leaving it as an unverified claim in the unfreeze doc.
def test_hypothesis_construction_failure_propagates_like_legacy_code(monkeypatch):
    """A failure inside Hypothesis(...) construction (Phase C) must still
    raise out of rabbit_hole_node entirely -- not be swallowed, and not
    leave any of Phase A's bookkeeping (branches_entered/current_branches)
    observably different from the pre-Track-3 single-pass loop, which also
    had no try/except around Hypothesis(...) and would equally propagate
    the exception out of the whole function."""
    import webpent.agents.rabbit_hole.agent as rh_module
    import webpent.config.settings as settings_module
    import webpent.shared.llm as llm_module

    fake_llm = _FakeLLM(delay=0.0)
    monkeypatch.setattr(llm_module, "try_get_llm", lambda *a, **kw: fake_llm)
    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(enable_parallel_rabbit_hole_drafting=False),
    )

    class _BoomHypothesis:
        def __init__(self, *a, **kw):
            raise ValueError("simulated Hypothesis construction failure")

    monkeypatch.setattr(rh_module, "Hypothesis", _BoomHypothesis)

    state = _build_state(_build_mental_model(3))

    # The pre-Track-3 code had no try/except around Hypothesis(...) either,
    # so this MUST raise out of rabbit_hole_node entirely -- never return a
    # partial dict, never swallow the error.
    with pytest.raises(ValueError, match="simulated Hypothesis construction failure"):
        rabbit_hole_node(state)

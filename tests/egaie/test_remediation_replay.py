"""L9 §3/§5: remediated re-runs are distinct investigation steps;
plain repetitions replay the original idempotency tokens.

The remediation loop re-executes a blocked experiment after the
planner established its transition preconditions. For that re-run
to reach the production executor at all, its steps must carry
idempotency tokens distinct from the first pass (which was
deduplicated by the executor's replay guard). For every OTHER
repetition — a blind replay, a resumed sweep, a selector
re-selection — the tokens must stay the original ones so the
executor still prevents a double-applied mutation (G-02).
"""
from __future__ import annotations

from webpent.egaie import discovery_runner as dr
from webpent.egaie.differential import DifferentialProposer
from webpent.appsuite.corpus import SuiteEntry, open_instance


def _all_status_codes(composites) -> list:
    return [
        step.get("status_code")
        for composite in composites
        for step in composite.get("steps", [])
    ]


def test_plain_repetition_replays_tokens_and_deduplicates() -> None:
    entry = SuiteEntry("ledgerflow", "secured")
    with open_instance(entry) as target:
        port = dr._build_port(target, entry.seed)
        state = dr._seed_state(target, entry.instance_id)
        experiment = DifferentialProposer(port).propose(state)[0]
        port.execute(experiment)
        replay = port.execute(experiment)
    codes = _all_status_codes(replay)
    assert codes, "replay produced no steps at all"
    assert all(code is None for code in codes), (
        "a plain repetition of an experiment reached the executor "
        "with fresh idempotency tokens: the target's state machine "
        "could be double-applied")


def test_remediation_rerun_reaches_executor_with_own_tokens() -> None:
    entry = SuiteEntry("ledgerflow", "secured")
    with open_instance(entry) as target:
        port = dr._build_port(target, entry.seed)
        state = dr._seed_state(target, entry.instance_id)
        experiment = DifferentialProposer(port).propose(state)[0]
        port.execute(experiment)
        port.mark_remediated(experiment.experiment_id)
        rerun = port.execute(experiment)
    codes = _all_status_codes(rerun)
    assert codes, "remediated re-run produced no steps at all"
    assert any(code is not None for code in codes), (
        "the remediated re-run was still deduplicated against the "
        "first pass: the planner's post-remediation re-evaluation "
        "can never observe the established state")

# tests/test_integration_reconciliation.py
"""Staged reconciliation tests (capability matrix A9, protocol §22)."""

from __future__ import annotations

import pytest

from webpent.integration.reconciliation import (
    FORBIDDEN_INTERNAL_KEYS,
    Observation,
    reconcile,
)


def _row(**overrides):
    base = {
        "producer_id": "recon-agent-1",
        "kind": "endpoint_signal",
        "endpoint_path": "/api/users/{id}",
        "parameter": "id",
        "role": "object_reference",
        "payload": {"status": 200, "len_delta": 120},
        "source_refs": ["obs:1"],
    }
    base.update(overrides)
    return base


def test_reconcile_groups_by_typed_identity_with_stable_refs():
    rows = [
        _row(),
        _row(producer_id="crawler-agent-1", source_refs=["obs:2"]),
        _row(kind="auth_signal", endpoint_path="/api/admin"),
    ]
    result = reconcile(rows)
    assert len(result.tasks) == 2
    refs = [t.task_ref for t in result.tasks]
    assert refs == sorted(refs)
    assert all(t.task_ref.startswith("REC-") for t in result.tasks)
    # Deterministic/idempotent: same inputs → same refs.
    assert reconcile(rows).tasks == result.tasks


def test_reconcile_collapses_duplicate_observations():
    rows = [_row(), _row()]  # identical content → same observation id
    result = reconcile(rows)
    assert result.duplicate_observations_collapsed == 1
    assert len(result.tasks) == 1
    assert len(result.tasks[0].observation_ids) == 1


def test_reconcile_scrubs_forbidden_internal_keys():
    row = _row(payload={"status": 200, "ground_truth": "tp-1", "confirmed": True})
    result = reconcile([row])
    assert "ground_truth" in result.scrubbed_keys
    assert "confirmed" in result.scrubbed_keys
    assert all("ground_truth" not in o.payload for o in result.prepared)
    assert all("confirmed" not in o.payload for o in result.prepared)


def test_reconcile_rejects_structurally_invalid_rows_fail_closed():
    rows = [
        _row(),
        {"kind": "x"},  # no producer
        {"producer_id": "p-1"},  # no kind
        {"producer_id": "p-1", "kind": "k", "payload": {}},  # empty payload
        "not-a-dict",
    ]
    result = reconcile(rows)
    assert len(result.prepared) == 1
    assert len(result.rejected) == 4
    assert all(rejected.startswith("row[") for rejected in result.rejected)


def test_producer_namespace_validation():
    with pytest.raises(ValueError, match="producer_id_namespace_violation"):
        Observation(producer_id="nospace", kind="k", payload={"a": 1})


def test_observation_id_is_content_stable_and_scrub_aware():
    a = Observation(producer_id="p-1", kind="k", payload={"x": 1})
    b = Observation(producer_id="p-1", kind="k", payload={"x": 1})
    assert a.observation_id == b.observation_id
    assert a.observation_id.startswith("obs-")
    # Ground-truth keys never influence identity (Evaluator ≠ Executor).
    c = Observation(producer_id="p-1", kind="k", payload={"x": 1, "ground_truth": "zzz"})
    assert c.observation_id == a.observation_id


def test_suggested_hypothesis_id_is_deterministic():
    result = reconcile([_row()])
    task = result.tasks[0]
    assert task.suggested_hypothesis_id().startswith("hyp-")
    assert task.suggested_hypothesis_id() == reconcile([_row()]).tasks[0].suggested_hypothesis_id()


def test_forbidden_key_registry_covers_ground_truth_family():
    required = {"ground_truth", "hidden_oracle", "expected_finding", "benchmark_label", "confirmed"}
    assert required.issubset(FORBIDDEN_INTERNAL_KEYS)


def test_evidence_candidate_refs_collected_across_producers():
    result = reconcile(
        [
            _row(source_refs=["obs:1", "obs:2"]),
            _row(producer_id="c-2", source_refs=["obs:3"]),
        ]
    )
    task = result.tasks[0]
    assert task.evidence_candidate_refs == ("obs:1", "obs:2", "obs:3")
    assert set(task.producer_ids) == {"recon-agent-1", "c-2"}

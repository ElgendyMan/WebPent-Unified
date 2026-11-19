"""L7 Step 5: per-confirmed-finding provenance, red-first.

Mission section 5: every reported finding carries machine-readable
provenance, and ground truth may score results only after the
investigation finishes. These tests pin both:

- provenance is built only from a finished state, only for CONFIRMED
  hypotheses, and carries the full chain: initial-observation
  inventory, experiments with outcomes, evidence, selection decisions,
  proposal-log entries and the sealed-bundle replay summary;
- the classification field is None at build time and can be attached
  only after investigation, on an unmodified record;
- the module is isolated: it builds valid records in a fresh
  interpreter with no lab, fixture or target code loaded.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from webpent.egaie import discovery_runner as dr
from webpent.egaie.benchmark.provenance import (
    attach_classification,
    build_finding_provenance,
    findings_provenance,
)
from webpent.egaie.schemas import (
    HypothesisRecord,
    HypothesisStatus,
    InvestigationState,
)
from webpent.labsuite import corpus
from webpent.labsuite.lab_target import LabTarget

SRC = Path(__file__).resolve().parents[2] / "src" / "webpent"


def _run_adaptive_102():
    spec = corpus.lab_instance(102)
    with LabTarget(spec) as target:
        port = dr._build_port(target, spec.seed)
        state = dr._seed_state(target, spec.instance_id)
        orch = dr._build_orchestrator(port, "adaptive")
        result = orch.run(state, max_rounds=96)
    return result


# ------------------------------------------------------------- gating


def test_provenance_requires_confirmed_finding() -> None:
    state = InvestigationState(
        engagement_id="eng-x", target_url="http://lab.test")
    state.add_hypothesis(HypothesisRecord(
        hypothesis_id="h-1", family="IDENTITY_BOUNDARY",
        statement="unresolved hypothesis"))
    with pytest.raises(ValueError):
        build_finding_provenance(state, "h-1")
    with pytest.raises(KeyError):
        build_finding_provenance(state, "h-missing")


# --------------------------------------------------------------- shape


def test_provenance_record_carry_full_chain() -> None:
    result = _run_adaptive_102()
    confirmed = [h for h in result.hypotheses
                 if h.status is HypothesisStatus.CONFIRMED]
    assert confirmed
    for record in findings_provenance(result):
        assert record["provenance_version"] == "l7-provenance-1"
        finding = record["finding"]
        assert finding["origin_is_advisory"] is True
        investigation = record["investigation"]
        assert investigation["terminal_reason"], finding
        observations = investigation["initial_observations"]
        assert observations["count"] > 0
        assert len(observations["digests_sha256"]) == (
            observations["count"])
        chain = record["confirmation"]
        assert chain["experiments"]
        for experiment in chain["experiments"]:
            assert experiment["outcome"] == "confirmed"
            assert experiment["hypothesis_id"] == (
                finding["hypothesis_id"])
        assert chain["evidence"], finding
        assert chain["selection_decisions"], finding
        assert chain["proposal_log_entries"], finding
        seal = record["seal_summary"]
        assert seal["bundle_count"] >= 1
        assert seal["all_replay_valid"] is True
        # Machine-readable: every record serializes losslessly.
        assert json.loads(json.dumps(record)) == record


# ------------------------------------------------------ classification


def test_classification_attaches_only_after_investigation() -> None:
    result = _run_adaptive_102()
    confirmed = next(
        h for h in result.hypotheses
        if h.status is HypothesisStatus.CONFIRMED)
    record = build_finding_provenance(result, confirmed.hypothesis_id)
    assert record["classification"] is None
    assert record["classified_after_investigation"] is False

    classified = attach_classification(record, {
        "verdict": "true_positive",
        "family": "identity_read",
        "scored_by": "held-out evaluator",
    })
    assert classified["classified_after_investigation"] is True
    assert classified["classification"]["verdict"] == "true_positive"
    assert classified["provenance_digest"] != record[
        "provenance_digest"]
    # The pre-classification record is untouched and still verifiable.
    assert record["classification"] is None

    with pytest.raises(ValueError):
        attach_classification(record, {})

    # Tampering before classification is detected: the digest of the
    # modified record no longer matches the one carried in it.
    tampered = json.loads(json.dumps(record))
    tampered["finding"]["family"] = "PRICE_INTEGRITY"
    with pytest.raises(ValueError):
        attach_classification(tampered, {"verdict": "x"})


# ------------------------------------------------------------ isolation


def test_provenance_module_isolated_in_subprocess() -> None:
    """A fresh interpreter builds a valid record from a synthetic
    state with no lab, fixture or target code loaded."""
    code = (
        "import json, sys\n"
        "import webpent.egaie.benchmark.provenance as prov\n"
        "from webpent.egaie.schemas import (\n"
        "    EvidenceItem, EvidenceKind, HypothesisRecord,\n"
        "    HypothesisStatus, InvestigationState,\n"
        ")\n"
        "state = InvestigationState(\n"
        "    engagement_id='eng-x', target_url='http://lab.test')\n"
        "state.observations.append({'kind': 'obs'})\n"
        "state.round, state.terminal_reason = 7, 'objectives_complete'\n"
        "state.add_hypothesis(HypothesisRecord(\n"
        "    hypothesis_id='h-9', family='IDENTITY_BOUNDARY',\n"
        "    statement='s', origin='independent:recon:ident-1'))\n"
        "state.set_hypothesis_status('h-9', "
        "HypothesisStatus.CONFIRMED)\n"
        "record = prov.build_finding_provenance(state, 'h-9')\n"
        "assert record['classification'] is None\n"
        "assert record['finding']['origin_is_advisory'] is True\n"
        "assert json.loads(json.dumps(record)) == record\n"
        "bad = [m for m in sys.modules if 'labsuite' in m]\n"
        "assert not bad, bad\n"
        "print('ok')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True,
        env={"PYTHONPATH": str(SRC.parent), "PATH": "/usr/bin:/bin"},
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"

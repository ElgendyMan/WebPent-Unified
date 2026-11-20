"""L7 Step 3: independent lab corpus isolation, red-first.

These tests pin the claims that make the L7 held-out evaluation
independent rather than a relabeled copy of the L6 fixtures:

- the lab package imports NOTHING from webpent.egaie (no fixture
  generation code, no fixture target classes, no fixture data);
- the engine package (webpent.egaie) never imports the lab's ground
  truth (webpent.labsuite.evaluator) or any of the lab package;
- the lab's vocabulary (wordlist, prefixes, role names) is disjoint
  from the L6 canonical fixture vocabulary, so surface randomization
  cannot be satisfied by copying fixture names;
- the deployment's index document carries no enforcement flags or
  defect descriptors (hidden labels stay hidden);
- a blind engine investigation confirms the declared defects on a
  DEV instance and confirms NOTHING on a fully secured instance;
- the negative roster is fully secured (zero declared defects);
- the evaluator attributes IDENTITY_BOUNDARY findings to the read or
  mutation sub-family by probed path, and never label-feeds.

No fixture code runs inside the lab: everything under webpent.labsuite
is the lab's own implementation.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

from webpent.labsuite import corpus
from webpent.labsuite.evaluator import (
    ENGINE_FAMILY,
    defects_for,
    score_instance,
)
from webpent.labsuite.lab_target import LabTarget

SRC = Path(__file__).resolve().parents[2] / "src" / "webpent"
RECON_ORIGIN = "differential:recon:"


# --------------------------------------------------------------- isolation


def test_labsuite_imports_no_egaie_modules() -> None:
    """The lab shares no code with the L6 fixture generation."""
    offenders: list[str] = []
    for path in (SRC / "labsuite").rglob("*.py"):
        for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith(("import ", "from ")):
                continue
            if "webpent.egaie" in stripped:
                offenders.append(f"{path.name}:{lineno}: {stripped}")
    assert not offenders, (
        "labsuite must not import webpent.egaie modules "
        f"(fixture generation code): {offenders}")


def test_egaie_never_imports_labsuite() -> None:
    """Ground truth is invisible to the engine, always."""
    offenders: list[str] = []
    for path in (SRC / "egaie").rglob("*.py"):
        for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith(("import ", "from ")):
                continue
            if "labsuite" in stripped:
                offenders.append(f"{path.name}:{lineno}: {stripped}")
    assert not offenders, (
        "engine must never reference the lab's ground truth: "
        f"{offenders}")


def test_engine_package_imports_without_labsuite_loaded() -> None:
    """Importing the engine in a fresh interpreter pulls in no lab
    module (the isolation must hold at runtime, not just lexically)."""
    code = (
        "import sys\n"
        "import webpent.egaie.differential\n"
        "import webpent.egaie.discovery_runner\n"
        "bad = [m for m in sys.modules if 'labsuite' in m]\n"
        "assert not bad, bad\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True,
        env={"PYTHONPATH": str(SRC.parent), "PATH": "/usr/bin:/bin"},
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_lab_vocabulary_disjoint_from_l6() -> None:
    """No lab name appears in the L6 canonical vocabulary and vice
    versa: routes, ids and state representations are independently
    randomized, not renamed fixtures."""
    from webpent.egaie.eval_instances import _ROLE_NAMES, _WORDLIST
    from webpent.labsuite import lab_target

    lab_words = set(lab_target._WORDLIST)
    l6_words = set(_WORDLIST)
    assert lab_words.isdisjoint(l6_words), lab_words & l6_words

    lab_prefixes = {"rcd", "apv", "bal"}
    l6_prefixes = set(_ROLE_NAMES.values())
    assert lab_prefixes.isdisjoint(l6_prefixes), (
        lab_prefixes & l6_prefixes)


def test_index_document_hides_enforcement_labels() -> None:
    """The surface the engine observes carries no defect flags: a
    read-defective deployment's index must look like any other."""
    spec = corpus.lab_instance(101)  # identity_mutation defective
    with LabTarget(spec) as target:
        status, _headers, body = target.get("/")
    assert status == 200
    text = repr(body)
    for forbidden in ("enforced", "defect", "defective", "vulnerable",
                      "impl", "grant_impl", "spend_impl",
                      "checkout_impl", "identity_read"):
        assert forbidden not in text, forbidden
    # The documented contract is present: groups, kinds, schema.
    assert set(body["api"]) == set(spec.group_names.values())
    assert body["kinds"]
    assert "schema" in body


# -------------------------------------------------------------- corpus


def test_negative_block_fully_secured() -> None:
    for spec in corpus.negative_block():
        assert defects_for(spec) == [], spec.instance_id


def test_dev_and_heldout_carry_defects() -> None:
    for block in (corpus.dev_block(), corpus.heldout_block()):
        for spec in block:
            assert defects_for(spec), spec.instance_id


# ------------------------------------------------------------- scoring


def test_evaluator_attributes_identity_by_probed_path() -> None:
    spec = corpus.lab_instance(101)
    # identity_read enforced, identity_mutation defective on 101.
    assert "identity_mutation" in {
        d["family"] for d in defects_for(spec)}
    assert "identity_read" not in {
        d["family"] for d in defects_for(spec)}
    # A finding probing the mutate segment is a TP for mutation.
    mutation = score_instance(spec, [{"family": "IDENTITY_BOUNDARY",
                                      "hypothesis_id": "h1",
                                      "path": f"/{spec.mutate_segment}"}])
    assert mutation["families"]["identity_mutation"]["tp"] == 1
    assert mutation["families"]["identity_read"]["fp"] == 0
    assert mutation["families"]["identity_read"]["fn"] == 0
    # A finding probing a record path is a FALSE POSITIVE for read.
    read = score_instance(spec, [{"family": "IDENTITY_BOUNDARY",
                                  "hypothesis_id": "h2",
                                  "path": f"/{spec.record_segment}/x"}])
    assert read["families"]["identity_read"]["fp"] == 1
    assert read["families"]["identity_read"]["tp"] == 0


def test_evaluator_reports_grant_as_missing_not_forgiven() -> None:
    spec = corpus.lab_instance(102)  # grant replayable on 102
    assert "grant" in {d["family"] for d in defects_for(spec)}
    # A grant defect with no confirming finding is an FN (the engine
    # family mapping no longer exempts grant; the FN only clears when
    # an investigation actually confirms it).
    score = score_instance(spec, [])
    assert score["families"]["grant"]["fn"] == 1


def test_engine_family_map_is_total_for_engine_labels() -> None:
    mapped = {v for v in ENGINE_FAMILY.values() if v is not None}
    for label in ("IDENTITY_BOUNDARY", "PRICE_INTEGRITY",
                  "WORKFLOW_IDENTITY", "WORKFLOW_ORDER",
                  "BOUNDARY_LIMIT"):
        assert label in mapped


# ------------------------------------------------------- blind engine


def _findings(state: Any, port: Any) -> list[dict[str, Any]]:
    from webpent.egaie.schemas import HypothesisStatus
    out = []
    for record in state.hypotheses:
        if record.status is not HypothesisStatus.CONFIRMED:
            continue
        slug = record.origin.split(RECON_ORIGIN)[-1]
        experiment = next(
            (e for e in state.experiments
             if e.experiment_id == f"e-{slug}"), None)
        path = None
        if experiment is not None:
            try:
                plan = port.plan_for(experiment.signature)
            except ValueError:
                plan = None
            if plan is not None:
                path = next(
                    (step.path for step in plan.steps
                     if step.path != "{revealed}"), None)
        out.append({"family": record.family,
                    "hypothesis_id": record.hypothesis_id,
                    "path": path})
    return out


def test_blind_investigation_finds_declared_defects() -> None:
    """Red-first: a blind engine run on a DEV instance confirms every
    defect family, attributed by probed path. Section 6 closed the
    original grant gap after the failure analysis demonstrated it: the
    engine grew a grant-replay generator (backed by ProbeStep's
    response capture), so the grant family is now scored like the rest
    and its former absence is pinned as history in the failure
    analysis document, never as a scoring carve-out."""
    from webpent.egaie import discovery_runner as dr

    spec = corpus.lab_instance(102)
    with LabTarget(spec) as target:
        port = dr._build_port(target, spec.seed)
        state = dr._seed_state(target, spec.instance_id)
        result = dr._build_orchestrator(
            port, "adaptive").run(state, max_rounds=96)
    findings = _findings(result, port)
    score = score_instance(spec, findings)
    for family, expected in (
            ("identity_read", 1), ("price", 1),
            ("workflow_identity", 1), ("workflow_order", 1),
            ("spend", 1), ("grant", 1)):
        assert score["families"][family]["tp"] == expected, family
        assert score["families"][family]["fp"] == 0, family
    assert score["families"]["grant"]["fn"] == 0
    for family, entry in score["families"].items():
        assert entry["fp"] == 0, (family, entry)


def test_blind_investigation_silent_on_secured_instance() -> None:
    """A fully secured deployment yields ZERO confirmations."""
    from webpent.egaie import discovery_runner as dr

    spec = corpus.lab_instance(301)
    with LabTarget(spec) as target:
        port = dr._build_port(target, spec.seed)
        state = dr._seed_state(target, spec.instance_id)
        result = dr._build_orchestrator(
            port, "adaptive").run(state, max_rounds=96)
    score = score_instance(spec, _findings(result, port))
    for family, entry in score["families"].items():
        assert entry["tp"] == 0, (family, entry)
        assert entry["fp"] == 0, (family, entry)

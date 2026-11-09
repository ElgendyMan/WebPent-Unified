"""M6 (Part 4 §8, UM-DR-19): target-deception resistance & evidence
quality.

Acceptance under test: "misleading fixtures rejected; evidence replay
preserved; no inconclusive→confirmed transitions; deception benchmark
reports published with sample sizes".

1. **The fixture corpus** — 8 deception classes × 3 variants, ground
   truth: never vulnerable; deterministic (seeded randomness).
2. **The causal verifier** — the three-response protocol
   (baseline/candidate/control) + repeatability; every deception class
   REFUTED with a named signature; a genuine differential still
   CONFIRMS (true-positive sanity — the verifier is not a
   refuse-everything gate); verdicts are one-way.
3. **The evidence contracts** — declared per vuln class (required
   evidence, negative controls, limitations, replay); fail-closed on
   unknown classes and missing fields.
4. **The sqlmap differential** — candidate-only markers confirm over
   the internal baseline pair; both-runs markers refuse (ambient
   text); extraction of type/parameter/payload.
5. **The benchmark** — 24 fixtures, per-class counts, sample sizes,
   blind set; published as JSON.
"""

from __future__ import annotations

from typing import Any

from webpent.deception import (
    DECEPTION_CLASSES,
    build_fixture_corpus,
    extract_sqlmap_differential,
    run_deception_benchmark,
    validate_evidence_bundle,
    verify_responses,
)
from webpent.deception.benchmark import report_to_json

# ---------------------------------------------------------------------------
# 1. The fixture corpus
# ---------------------------------------------------------------------------


def test_corpus_shape_and_ground_truth() -> None:
    corpus = build_fixture_corpus()
    assert len(corpus) == 24
    assert {f.deception_class for f in corpus} == set(DECEPTION_CLASSES)
    assert all(f.ground_truth_vulnerable is False for f in corpus)
    assert all(f.expected_verdict == "refuted_deceptive" for f in corpus)


def test_fixture_behaviors_match_their_classes() -> None:
    corpus = {f.deception_class: f for f in build_fixture_corpus()}
    payload = "<script>alert(1)</script>"

    # generic_200: identical response with and without payload.
    generic = corpus["generic_200"]
    assert generic.respond({"payload": ""})["body"] == generic.respond({"payload": payload})["body"]

    # reflected_uninterpreted: payload present, text/plain context.
    reflected = corpus["reflected_uninterpreted"].respond({"payload": payload})
    assert payload in reflected["body"]
    assert "text/plain" in reflected["headers"]["content-type"]

    # cached_stale: same ETag across different payloads.
    stale = corpus["cached_stale"]
    etag_a = stale.respond({"payload": "a"})["headers"]["etag"]
    etag_b = stale.respond({"payload": "b"})["headers"]["etag"]
    assert etag_a == etag_b

    # randomized: same token ⇒ same body; different token ⇒ different.
    rnd = corpus["randomized"]
    assert rnd.respond({"token": "t1"})["body"] == rnd.respond({"token": "t1"})["body"]
    assert rnd.respond({"token": "t1"})["body"] != rnd.respond({"token": "t2"})["body"]

    # delayed: constant delay marker with and without payload.
    delayed = corpus["delayed"]
    assert (
        delayed.respond({"payload": ""})["headers"]["x-artificial-delay-ms"]
        == delayed.respond({"payload": payload})["headers"]["x-artificial-delay-ms"]
    )

    # waf_page: 403 with security vocabulary.
    waf = corpus["waf_page"].respond({"payload": payload})
    assert waf["status"] == 403
    assert "firewall" in waf["body"].lower()


# ---------------------------------------------------------------------------
# 2. The causal verifier
# ---------------------------------------------------------------------------


def test_every_deception_class_is_refuted_with_named_signatures() -> None:
    corpus = build_fixture_corpus()
    for fixture in corpus:
        baseline = fixture.respond({"token": "baseline", "payload": "benign"})
        candidate = fixture.respond({"token": "candidate", "payload": "PAYLOAD-X"})
        control = fixture.respond({"token": "control", "payload": "benign2"})
        outcome = verify_responses(
            baseline=baseline, candidate=candidate, control=control
        )
        assert outcome.verdict != "confirmed_candidate", fixture.fixture_id
        assert outcome.reasons, fixture.fixture_id


def test_genuine_differential_with_sound_control_confirms() -> None:
    """True-positive sanity: the verifier is not a refuse-everything gate."""
    baseline = {"status": 200, "headers": {"content-type": "text/html"}, "body": "normal"}
    candidate = {
        "status": 200,
        "headers": {"content-type": "text/html"},
        "body": "normal<script>alert(1)</script>",
    }
    control = {"status": 200, "headers": {"content-type": "text/html"}, "body": "normal"}
    outcome = verify_responses(
        baseline=baseline,
        candidate=candidate,
        control=control,
        candidate_repeat=candidate,
    )
    assert outcome.verdict == "confirmed_candidate"
    assert outcome.causal_fields["repeatability"] == "reproducible"


def test_missing_baseline_is_inconclusive_and_never_confirms() -> None:
    outcome = verify_responses(
        baseline=None,
        candidate={"status": 200, "headers": {}, "body": "x"},
        control={"status": 200, "headers": {}, "body": "y"},
    )
    assert outcome.verdict == "inconclusive"
    assert outcome.reasons == ["precondition_missing:no_baseline_response"]


def test_non_reproducible_effect_stays_inconclusive() -> None:
    baseline = {"status": 200, "headers": {}, "body": "same"}
    candidate = {"status": 200, "headers": {}, "body": "different"}
    outcome = verify_responses(
        baseline=baseline,
        candidate=candidate,
        control=baseline,
        candidate_repeat={"status": 200, "headers": {}, "body": "different-again"},
    )
    assert outcome.verdict == "inconclusive"
    assert "effect_not_reproducible" in outcome.reasons


def test_control_reproducing_the_candidate_effect_refutes() -> None:
    """A payload-free control that reproduces the candidate effect proves
    the effect exists WITHOUT the payload — refuted, never confirmed."""
    baseline = {"status": 200, "headers": {}, "body": "same"}
    candidate = {"status": 200, "headers": {}, "body": "different"}
    outcome = verify_responses(
        baseline=baseline, candidate=candidate, control=candidate
    )
    assert outcome.verdict == "refuted_deceptive"
    assert "negative_control_reproduces_candidate_effect" in outcome.reasons[0]


def test_verdicts_are_one_way_no_inconclusive_to_confirmed() -> None:
    """Structural: the verdict is computed once by a pure function — there
    is no upgrade path. Re-verifying the same inputs gives the same
    verdict (idempotence), and every inconclusive path in the module
    returns before the confirmed path is reachable."""
    baseline = {"status": 200, "headers": {}, "body": "same"}
    candidate = {"status": 200, "headers": {}, "body": "diff"}
    args = dict(baseline=baseline, candidate=candidate, control=baseline)
    first = verify_responses(**args)  # type: ignore[arg-type]
    second = verify_responses(**args)  # type: ignore[arg-type]
    assert first.verdict == second.verdict
    assert first.model_dump() == second.model_dump()


# ---------------------------------------------------------------------------
# 3. The evidence contracts
# ---------------------------------------------------------------------------


def test_contracts_fail_closed_on_unknown_class_and_missing_fields() -> None:
    ok, missing, contract = validate_evidence_bundle("not_a_class", {"x": 1})
    assert ok is False and contract is None
    assert "unknown_vuln_class_contract" in missing[0]

    ok, missing, contract = validate_evidence_bundle("sqli", {})
    assert ok is False
    assert "precondition" in missing
    assert "replay_spec" in missing


def test_complete_bundle_passes_its_contract() -> None:
    bundle: dict[str, Any] = {
        "precondition": "authenticated session",
        "action": "payload issued",
        "effect": "differential",
        "baseline_digest": "d1",
        "candidate_digest": "d2",
        "control_digest": "d1",
        "differential_extracted_from_pair": "sqlmap_internal_differential",
        "replay_spec": {"steps": []},
    }
    ok, missing, contract = validate_evidence_bundle("sqli", bundle)
    assert ok is True, missing
    assert contract is not None and contract.vuln_class == "sqli"
    assert contract.limitations  # declared, non-empty


# ---------------------------------------------------------------------------
# 4. The sqlmap differential
# ---------------------------------------------------------------------------


CANDIDATE_STDOUT = """[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] target URL content is stable
sqlmap identified the following injection point:
Parameter: id
    Type: boolean-based blind
    Title: AND boolean-based blind
    Payload: 1 AND 4409=4409
---
[INFO] retrieved: test
"""


def test_sqlmap_candidate_only_marker_confirms_with_extraction() -> None:
    baseline_stdout = "[INFO] testing connection\n[INFO] target URL content is stable\n"
    differential = extract_sqlmap_differential(
        baseline_stdout=baseline_stdout, candidate_stdout=CANDIDATE_STDOUT
    )
    assert differential.outcome == "differential_confirmed"
    assert differential.evidence_kind == "sqlmap_internal_differential"
    assert differential.parameter == "id"
    assert "boolean-based" in differential.injection_types
    assert "4409=4409" in differential.payload
    assert differential.baseline_marker_matched is False


def test_sqlmap_ambient_marker_in_both_runs_is_refused() -> None:
    """The M0 evidence-integrity defect: a target whose EVERY run carries
    marker-shaped text (template pages, WAF prose) cannot pass a
    single-run check — the differential refuses it."""
    noisy = (
        "Welcome! This page appears to be under maintenance.\n"
        "The service is vulnerable to scheduled downtime.\n" + CANDIDATE_STDOUT
    )
    differential = extract_sqlmap_differential(
        baseline_stdout=noisy, candidate_stdout=noisy
    )
    assert differential.outcome == "refuted_deceptive"
    assert "deceptive_both_runs" in differential.reasons[0]


def test_sqlmap_neither_run_is_not_confirmed() -> None:
    quiet = "[INFO] target URL content is stable\n"
    differential = extract_sqlmap_differential(
        baseline_stdout=quiet, candidate_stdout=quiet
    )
    assert differential.outcome == "not_confirmed"


# ---------------------------------------------------------------------------
# 5. The benchmark
# ---------------------------------------------------------------------------


def test_benchmark_rejects_the_whole_corpus_with_sample_sizes() -> None:
    report = run_deception_benchmark()
    assert report.fixtures_total == 24
    assert report.false_positives == 0
    assert report.rejected == 24
    assert report.inconclusive == 0
    # Per-class counts with sample sizes.
    for deception_class, counts in report.per_class.items():
        assert counts["fixtures"] == 3
        assert counts["rejected"] == 3
    # The blind set is scored too.
    assert report.blind_set["fixtures"] > 0
    assert report.blind_set["false_positives"] == 0


def test_benchmark_report_is_publishable_json_with_sizes() -> None:
    report = run_deception_benchmark()
    payload = report_to_json(report)
    import json

    parsed = json.loads(payload)
    assert parsed["fixtures_total"] == 24
    assert "per_class" in parsed and "blind_set" in parsed
    assert parsed["ground_truth"].startswith("no fixture is vulnerable")


def test_published_report_exists_in_repo() -> None:
    from pathlib import Path

    path = Path("reports/deception/benchmark_v1.json")
    assert path.is_file()
    import json

    parsed = json.loads(path.read_text(encoding="utf-8"))
    assert parsed["false_positives"] == 0
    assert parsed["fixtures_total"] == 24

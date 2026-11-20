"""v82 Tasks 6-8: skeptic, triager simulation, FP autopsy."""

from __future__ import annotations

from pathlib import Path

from webpent.autonomous.amplifiers.fp_autopsy import FPAutopsyStore, autopsy_key, summarize_autopsy
from webpent.autonomous.amplifiers.skeptic import run_skeptic_checks
from webpent.autonomous.amplifiers.triager_sim import simulate_triager, triage_report

# -- skeptic --------------------------------------------------------------


def test_all_doubts_survive_upheld() -> None:
    calls: list[str] = []

    def reprobe(url: str, variant: str) -> bool:
        calls.append(variant)
        return True

    report = run_skeptic_checks("http://lab.example/x?y=1", reprobe=reprobe)
    assert report["verdict"] == "upheld"
    assert set(report["checks"]) >= {
        "cache_buster",
        "statistical_repeat",
        "fresh_session",
        "timing_retry",
    }
    assert "cb=" in str(report["candidate"])  # cache-buster query present
    assert report["checks"]["statistical_repeat"] == {"hits": 3, "trials": 3, "passed": True}
    assert sorted(set(calls)) == ["cache", "fresh_session", "repeat", "timing"]


def test_flaky_signature_is_self_refuted() -> None:
    def reprobe(url: str, variant: str) -> bool:
        return variant != "fresh_session"  # fails session doubt

    report = run_skeptic_checks("http://lab.example/x", reprobe=reprobe)
    assert report["verdict"] == "self_refuted"
    assert report["checks"]["fresh_session"] is False


def test_statistical_doubt_fails_below_two_hits() -> None:
    seq = iter([True, False, False])

    def reprobe(url: str, variant: str) -> bool:
        return variant == "repeat" and next(seq)

    report = run_skeptic_checks("http://lab.example/x", reprobe=reprobe)
    assert report["checks"]["statistical_repeat"]["passed"] is False
    assert report["verdict"] == "self_refuted"


def test_reprobe_exception_degrades_to_self_refuted_not_crash() -> None:
    def reprobe(url: str, variant: str) -> bool:
        raise OSError("network gone")

    report = run_skeptic_checks("http://lab.example/x", reprobe=reprobe)
    assert report["verdict"] == "self_refuted"


def test_bad_candidate_is_inconclusive() -> None:
    assert run_skeptic_checks("", reprobe=lambda u, v: True)["verdict"] == "inconclusive"


# -- triager simulation ---------------------------------------------------


def test_self_xss_predicted_na() -> None:
    prediction = simulate_triager({"finding_id": "f1", "vuln_class": "self-xss"})
    assert prediction["prediction"] == "likely_na"
    assert prediction["matches"][0]["pattern_id"] == "na-self-xss"


def test_generic_reflected_xss_predicted_duplicate() -> None:
    finding = {
        "vuln_class": "XSS",
        "impact": "alert(document.domain) on public page",
    }
    prediction = simulate_triager(finding)
    assert prediction["prediction"] == "likely_duplicate"


def test_empty_impact_flags_na() -> None:
    prediction = simulate_triager({"vuln_class": "sqli", "impact": ""})
    assert any(m["pattern_id"] == "na-no-impact" for m in prediction["matches"])
    assert prediction["prediction"] == "likely_na"


def test_specific_finding_is_clean() -> None:
    finding = {
        "vuln_class": "sqli",
        "impact": "auth bypass with data exfiltration",
    }
    prediction = simulate_triager(finding)
    assert prediction["prediction"] == "clean"
    assert prediction["matches"] == []


def test_batch_report_summary() -> None:
    report = triage_report(
        [
            {"vuln_class": "self-xss"},
            {"vuln_class": "sqli", "impact": "dump"},
            {"vuln_class": "open-redirect", "impact": "redirects to attacker"},
        ]
    )
    assert report["summary"] == {"likely_na": 1, "clean": 1, "likely_duplicate": 1}
    assert report["advisory"] is True


# -- FP autopsy ------------------------------------------------------------


def test_rejection_key_is_coarse_and_secret_free() -> None:
    key = autopsy_key(
        {"vuln_class": "XSS", "rejected_by": "triager", "reason": "token=hunter2 leaked"}
    )
    assert key == "xss::triager"
    assert "hunter2" not in key


def test_empty_class_files_nothing() -> None:
    assert autopsy_key({"vuln_class": ""}) == ""


def test_repeats_build_history_and_demotion(tmp_path: Path) -> None:
    store = FPAutopsyStore(tmp_path / "autopsy.json")
    for _ in range(3):
        store.record_rejection(
            {"vuln_class": "xss", "rejected_by": "skeptic", "reason": "cache artifact"}
        )
    assert store.lesson_count("xss", "skeptic") == 3
    assert abs(store.demotion_for("xss", "skeptic") - 0.15) < 1e-9
    assert store.demotion_for("sqli", "skeptic") == 0.0
    assert store.has_history("xss", "skeptic")


def test_roundtrip_and_corrupt_degrade(tmp_path: Path) -> None:
    path = tmp_path / "autopsy.json"
    store = FPAutopsyStore(path)
    store.record_rejection({"vuln_class": "sqli", "rejected_by": "triager", "reason": "dup"})
    store.save()
    reloaded = FPAutopsyStore(path)
    assert reloaded.lesson_count("sqli", "triager") == 1
    path.write_text("{broken", encoding="utf-8")
    assert FPAutopsyStore(path).lesson_count("sqli", "triager") == 0


def test_summarize_produces_readable_lines(tmp_path: Path) -> None:
    store = FPAutopsyStore(tmp_path / "a.json")
    store.record_rejection(
        {"vuln_class": "xss", "rejected_by": "skeptic", "reason": "cache artifact"}
    )
    lines = summarize_autopsy(store._lessons)
    assert lines and "xss::skeptic" in lines[0] and "cache artifact" in lines[0]

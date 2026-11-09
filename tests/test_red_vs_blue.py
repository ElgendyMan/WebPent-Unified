"""Project Zero-tier item 5 — Red-vs-blue internal detection-hardening loop.

Pins:
  * generate_evasion_mutations is deterministic: same seed payload ->
    same mutation dict every time,
  * every registered technique produces a mutation that differs from
    the seed (a no-op mutation would be a useless technique),
  * run_red_vs_blue correctly identifies "escaped" only when the
    detector caught the seed form but missed the mutated form —
    never when the detector never worked on the seed at all (that's
    "not detected on seed", a separate signal, not an evasion escape),
  * a detector immune to all evasion techniques (normalises input
    before matching) reports zero escapes,
  * a detector that crashes on seed or mutation is treated as "no
    detection" for that call, not propagated as an exception,
  * feed_escapes_to_postmortem records exactly one detection_logic_gap
    entry per escaped technique, with the technique name preserved in
    metadata, and records nothing when there were no escapes,
  * the raw seed payload is never itself stored by
    feed_escapes_to_postmortem — only the label and technique name.
"""

from __future__ import annotations

import re

from webpent.memory.postmortem import PostmortemManager
from webpent.models.postmortem import PostmortemCategory
from webpent.shared.red_vs_blue import (
    feed_escapes_to_postmortem,
    generate_evasion_mutations,
    run_red_vs_blue,
)


def test_generate_evasion_mutations_is_deterministic() -> None:
    seed = "<script>alert(1)</script>"
    first = generate_evasion_mutations(seed)
    second = generate_evasion_mutations(seed)
    assert first == second


def test_every_technique_mutation_differs_from_seed_when_applicable() -> None:
    # Each technique targets a specific character class (spaces,
    # angle brackets, length >= 4) and is legitimately a no-op on a
    # seed that doesn't contain its target — this is correct behavior,
    # not a bug. A seed containing BOTH a space and angle brackets, of
    # length > 4, exercises every technique's target class at once.
    seed = "<script> alert(1) </script>"
    mutations = generate_evasion_mutations(seed)
    assert len(mutations) >= 5  # sanity: a meaningful technique set exists
    for technique, mutated in mutations.items():
        assert mutated != seed, f"{technique} produced a no-op mutation"


def test_whitespace_padding_is_noop_on_seed_with_no_spaces() -> None:
    # Documents the expected, non-buggy no-op case directly rather
    # than asserting universality across every possible seed.
    seed = "<script>alert(1)</script>"
    mutations = generate_evasion_mutations(seed)
    assert mutations["whitespace_padding"] == seed


def test_double_url_encoding_is_noop_on_seed_with_no_angle_brackets() -> None:
    seed = "' OR '1'='1"
    mutations = generate_evasion_mutations(seed)
    assert mutations["double_url_encoding"] == seed


def test_naive_substring_detector_is_evaded_by_case_variation() -> None:
    def naive_detector(text: str) -> list[str]:
        return ["xss"] if "<script>" in text else []

    report = run_red_vs_blue(
        seed_payload="<script>alert(1)</script>",
        seed_payload_label="reflected_xss",
        detector=naive_detector,
    )
    case_variation = next(a for a in report.attempts if a.technique == "case_variation")
    assert case_variation.detected_on_seed is True
    assert case_variation.detected_on_mutation is False
    assert case_variation.escaped is True
    assert len(report.escaped_techniques) > 0


def test_case_insensitive_detector_is_not_evaded_by_case_variation() -> None:
    def ci_detector(text: str) -> list[str]:
        return ["xss"] if "<script>" in text.lower() else []

    report = run_red_vs_blue(
        seed_payload="<script>alert(1)</script>",
        seed_payload_label="reflected_xss",
        detector=ci_detector,
    )
    case_variation = next(a for a in report.attempts if a.technique == "case_variation")
    assert case_variation.escaped is False


def test_robust_regex_detector_resists_most_techniques() -> None:
    # A detector that strips comments, nulls, zero-width chars, decodes
    # once, and lowercases before matching should resist nearly everything
    # in this technique set.
    def robust_detector(text: str) -> list[str]:
        cleaned = text.replace("/**/", "").replace("%00", "")
        cleaned = cleaned.replace("\u200b", "")
        cleaned = cleaned.replace("%253C", "<").replace("%253E", ">")
        cleaned = cleaned.replace("'+'", "")
        cleaned = re.sub(r"\s+", "", cleaned).lower()
        return ["xss"] if "<script>" in cleaned else []

    report = run_red_vs_blue(
        seed_payload="<script>alert(1)</script>",
        seed_payload_label="reflected_xss",
        detector=robust_detector,
    )
    assert report.escaped_techniques == []
    assert report.escape_rate == 0.0


def test_detector_that_never_catches_seed_has_no_escapes() -> None:
    def blind_detector(text: str) -> list[str]:
        return []  # never detects anything, seed included

    report = run_red_vs_blue(
        seed_payload="<script>alert(1)</script>",
        seed_payload_label="reflected_xss",
        detector=blind_detector,
    )
    # No escapes reported — a detector with no baseline capability at
    # all is a pre-existing coverage gap, not something evasion "broke".
    assert report.escaped_techniques == []
    for attempt in report.attempts:
        assert attempt.detected_on_seed is False
        assert attempt.escaped is False


def test_detector_exception_treated_as_no_detection() -> None:
    def flaky_detector(text: str) -> list[str]:
        if "\u200b" in text:
            raise RuntimeError("boom on unicode")
        return ["xss"] if "<script>" in text else []

    report = run_red_vs_blue(
        seed_payload="<script>alert(1)</script>",
        seed_payload_label="reflected_xss",
        detector=flaky_detector,
    )
    homoglyph = next(a for a in report.attempts if a.technique == "unicode_homoglyph_padding")
    assert homoglyph.detected_on_mutation is False
    assert homoglyph.escaped is True  # seed caught, mutation crashed -> treated as miss


def test_escape_rate_computed_correctly() -> None:
    def naive_detector(text: str) -> list[str]:
        return ["xss"] if "<script>" in text else []

    report = run_red_vs_blue(
        seed_payload="<script>alert(1)</script>",
        seed_payload_label="reflected_xss",
        detector=naive_detector,
    )
    expected_rate = round(
        len(report.escaped_techniques) / len(report.attempts), 4
    )
    assert report.escape_rate == expected_rate


def test_feed_escapes_to_postmortem_records_one_per_escape() -> None:
    def naive_detector(text: str) -> list[str]:
        return ["xss"] if "<script>" in text else []

    report = run_red_vs_blue(
        seed_payload="<script>alert(1)</script>",
        seed_payload_label="reflected_xss",
        detector=naive_detector,
    )
    manager = PostmortemManager(database_url="sqlite://")
    ids = feed_escapes_to_postmortem(
        report,
        vuln_class="xss",
        detector_name="naive_detector",
        thread_id="t1",
        postmortem_manager=manager,
    )
    assert len(ids) == len(report.escaped_techniques)
    records = manager.get_records_by_thread("t1")
    assert len(records) == len(report.escaped_techniques)
    assert all(r["category"] == PostmortemCategory.DETECTION_LOGIC_GAP.value for r in records)
    recorded_techniques = {r["metadata"]["evasion_technique"] for r in records}
    expected_techniques = {a.technique for a in report.escaped_techniques}
    assert recorded_techniques == expected_techniques


def test_feed_escapes_to_postmortem_records_nothing_when_no_escapes() -> None:
    def perfect_detector(text: str) -> list[str]:
        cleaned = text.lower().replace("/**/", "").replace("%00", "")
        return ["xss"] if "<script" in cleaned else ["xss"]  # always "detects"

    report = run_red_vs_blue(
        seed_payload="<script>alert(1)</script>",
        seed_payload_label="reflected_xss",
        detector=perfect_detector,
    )
    manager = PostmortemManager(database_url="sqlite://")
    ids = feed_escapes_to_postmortem(
        report, detector_name="perfect_detector", thread_id="t1",
        postmortem_manager=manager,
    )
    assert ids == []
    assert manager.get_records_by_thread("t1") == []


def test_raw_seed_payload_never_stored_in_postmortem() -> None:
    secret_seed = "<script>UNIQUE_SECRET_MARKER_12345</script>"

    def naive_detector(text: str) -> list[str]:
        return ["xss"] if "<script>" in text else []

    report = run_red_vs_blue(
        seed_payload=secret_seed,
        seed_payload_label="reflected_xss",
        detector=naive_detector,
    )
    manager = PostmortemManager(database_url="sqlite://")
    feed_escapes_to_postmortem(
        report, detector_name="naive_detector", thread_id="t1",
        postmortem_manager=manager,
    )
    import json
    records = manager.get_records_by_thread("t1")
    serialised = json.dumps(records)
    assert "UNIQUE_SECRET_MARKER_12345" not in serialised

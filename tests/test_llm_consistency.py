"""Tests for webpent.shared.llm_consistency (Ultimate plan, proposal 8).

All tests run offline: the LLM invocation is always an injected fake
(the module is dependency-injected by design — it never imports the
LLM stack).
"""

from __future__ import annotations

import threading

import pytest

from webpent.shared.llm_consistency import (
    MAX_PROMPT_VARIANTS,
    RESPONSE_SNIPPET_MAX_CHARS,
    ConsistencyResult,
    annotate_finding_confidence,
    verify_llm_consistency,
)

VARIANTS = [
    "Does this response indicate a real SQL injection? Answer yes or no.",
    "Is the shown HTTP response evidence of actual SQL injection? Yes/no.",
    "Review the response: is genuine SQL injection present? Answer yes/no.",
]


def _echo(answer: str):
    """Build an invoke_fn that always returns the same answer."""
    calls: list[str] = []

    def invoke(prompt: str) -> str:
        calls.append(prompt)
        return answer

    invoke.calls = calls  # type: ignore[attr-defined]
    return invoke


def _rotating(answers: list[str]):
    """Build an invoke_fn that returns the answers in order (cycling)."""
    state = {"n": 0}
    calls: list[str] = []

    def invoke(prompt: str) -> str:
        calls.append(prompt)
        answer = answers[state["n"] % len(answers)]
        state["n"] += 1
        return answer

    invoke.calls = calls  # type: ignore[attr-defined]
    return invoke


# ---------------------------------------------------------------------------
# Agreement scoring
# ---------------------------------------------------------------------------


def test_identical_answers_are_consistent_with_score_one() -> None:
    result = verify_llm_consistency(_echo("no, this is a benign error page"), VARIANTS)
    assert isinstance(result, ConsistencyResult)
    assert result.agreement_score == 1.0
    assert result.interpretation == "consistent"
    assert result.error is None
    assert result.variants_used == 3
    assert result.responses == ["no, this is a benign error page"] * 3


def test_case_and_punctuation_variants_still_agree() -> None:
    invoke = _rotating(
        [
            "Yes. This is a real, exploitable SQL injection!",
            "yes, this is a real exploitable sql injection",
            "YES THIS IS A REAL EXPLOITABLE SQL INJECTION.",
        ]
    )
    result = verify_llm_consistency(invoke, VARIANTS)
    # All pairs normalise to the same token set -> agreement 1.0.
    assert result.agreement_score == 1.0
    assert result.interpretation == "consistent"


def test_disagreeing_answers_are_inconsistent() -> None:
    invoke = _rotating(
        [
            "yes, this is a real sql injection",
            "yes, this is a real sql injection",
            "no, this is a benign database error page",
        ]
    )
    result = verify_llm_consistency(invoke, VARIANTS)
    # Pairs: (0,1) agree; (0,2) and (1,2) disagree -> 1/3.
    assert result.agreement_score == pytest.approx(1 / 3)
    assert result.interpretation == "inconsistent"
    assert result.error is None


def test_partial_agreement_score_is_the_agreeing_pair_fraction() -> None:
    invoke = _rotating(["yes it is vulnerable", "yes it is vulnerable", "no it is not"])
    result = verify_llm_consistency(invoke, VARIANTS[:3])
    assert result.agreement_score == pytest.approx(1 / 3)
    assert result.interpretation == "inconsistent"


# ---------------------------------------------------------------------------
# Fail-closed behaviour
# ---------------------------------------------------------------------------


def test_raising_invoke_fn_is_inconclusive_and_never_raises() -> None:
    def boom(prompt: str) -> str:
        raise RuntimeError("provider quota exhausted")

    result = verify_llm_consistency(boom, VARIANTS)
    assert result.agreement_score == 0.0
    assert result.interpretation == "inconclusive"
    assert result.error is not None
    assert "RuntimeError" in result.error
    assert "quota exhausted" in result.error


def test_failure_on_later_variant_records_collected_responses() -> None:
    answers = iter(["yes", "yes"])

    def flaky(prompt: str) -> str:
        try:
            return next(answers)
        except StopIteration:
            raise ValueError("variant 3 exploded") from None

    result = verify_llm_consistency(flaky, VARIANTS)
    assert result.interpretation == "inconclusive"
    assert result.agreement_score == 0.0
    assert result.responses == ["yes", "yes"]
    assert result.variants_used == 3


def test_too_few_variants_is_honest_inconclusive() -> None:
    result = verify_llm_consistency(_echo("yes"), ["only one variant"])
    assert result.interpretation == "inconclusive"
    assert result.agreement_score == 0.0
    assert result.error is not None
    assert "variants" in result.error.lower()


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


def test_more_than_five_variants_are_truncated() -> None:
    invoke = _echo("yes")
    many = [f"variant wording number {i}" for i in range(9)]
    result = verify_llm_consistency(invoke, many)
    assert result.variants_used == MAX_PROMPT_VARIANTS
    assert len(invoke.calls) == MAX_PROMPT_VARIANTS  # type: ignore[attr-defined]


def test_stored_responses_are_bounded_to_200_chars() -> None:
    long_answer = "x" * 5000
    result = verify_llm_consistency(_echo(long_answer), VARIANTS)
    assert all(len(r) <= RESPONSE_SNIPPET_MAX_CHARS for r in result.responses)
    assert result.responses == [long_answer[:RESPONSE_SNIPPET_MAX_CHARS]] * 3


# ---------------------------------------------------------------------------
# Threshold + annotation contract
# ---------------------------------------------------------------------------


def test_threshold_flips_interpretation_for_the_same_score() -> None:
    variants = VARIANTS[:3]
    lenient = verify_llm_consistency(
        _rotating(["yes vulnerable", "yes vulnerable", "no not vulnerable"]),
        variants,
        threshold=0.3,
    )
    strict = verify_llm_consistency(
        _rotating(["yes vulnerable", "yes vulnerable", "no not vulnerable"]),
        variants,
        threshold=0.9,
    )
    assert lenient.interpretation == "consistent"
    assert strict.interpretation == "inconsistent"
    assert lenient.agreement_score == strict.agreement_score
    assert lenient.threshold == 0.3
    assert strict.threshold == 0.9


def test_annotate_finding_returns_new_dict_and_never_mutates_input() -> None:
    finding = {"id": "f-1", "severity": "high", "title": "SQLi"}
    original = dict(finding)
    consistency = verify_llm_consistency(_echo("yes confirmed"), VARIANTS[:2])

    annotated = annotate_finding_confidence(finding, consistency)

    assert finding == original  # input untouched
    assert annotated is not finding
    assert annotated["id"] == "f-1"
    assert annotated["severity"] == "high"
    extra = annotated["llm_consistency"]
    assert extra["advisory_only"] is True
    assert extra["interpretation"] == "consistent"
    assert extra["agreement_score"] == 1.0
    # The annotation is metadata only: no verdict-ish keys are added.
    assert set(annotated.keys()) - set(finding.keys()) == {"llm_consistency"}


def test_annotate_finding_works_for_inconclusive_results() -> None:
    def boom(prompt: str) -> str:
        raise ValueError("no provider configured")

    consistency = verify_llm_consistency(boom, VARIANTS)
    annotated = annotate_finding_confidence({"id": "f-2"}, consistency)
    assert annotated["llm_consistency"]["interpretation"] == "inconclusive"
    assert annotated["llm_consistency"]["advisory_only"] is True


def test_thread_safety_of_pure_helpers_smoke() -> None:
    """verify_llm_consistency is stateless; concurrent calls must not interfere."""
    results: list[ConsistencyResult] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            results.append(verify_llm_consistency(_echo("yes it is"), VARIANTS[:2]))
        except BaseException as exc:  # surface failures from the thread
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(results) == 8
    assert all(r.agreement_score == 1.0 for r in results)

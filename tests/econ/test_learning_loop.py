"""U-ECON-11 — LearningLoop tests (NC-ECON-1 charter, exact test names)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webpent.econ.learning_loop import (
    KIND_CLASS_FOCUS,
    KIND_DUP_PATTERN,
    KIND_PROGRAM_FOCUS,
    KIND_TIMING_ADJUST,
    MIN_DATA_POINTS,
    LearningLoop,
    SchedulerDelta,
)

NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)


def _rec(vuln_class="IDOR", program="example-corp", status="accepted", days_ago=5,
         resolve_days=10, payout=100.0, endpoint="/api/v2/users/{id}"):
    submitted = NOW - timedelta(days=days_ago)
    return {
        "finding_id": f"F-{vuln_class}-{days_ago}-{endpoint}",
        "vuln_class": vuln_class,
        "program_id": program,
        "submitted_at": submitted.isoformat(),
        "resolved_at": (submitted + timedelta(days=resolve_days)).isoformat(),
        "status": status,
        "payout_usd": payout if status == "accepted" else 0.0,
        "endpoint_signature": endpoint,
    }


def _loop(tmp_path: Path, records: list[dict], name="journal") -> LearningLoop:
    journal = tmp_path / f"{name}.jsonl"
    journal.write_text(
        "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8"
    )
    return LearningLoop(
        journal,
        log_path=tmp_path / f"{name}_insights.jsonl",
        now=NOW,
    )


def test_insight_requires_min_data_points(tmp_path):
    # 9 accepted IDOR submissions: below the significance threshold
    records = [_rec(vuln_class="IDOR", days_ago=i) for i in range(1, 10)]
    assert len(records) == MIN_DATA_POINTS - 1
    insights = _loop(tmp_path, records).analyze()
    kinds = [i.kind for i in insights]
    assert KIND_CLASS_FOCUS not in kinds
    # a 2/2 acceptance rate says nothing -> no recommendation is produced
    assert not any("IDOR" in i.recommendation for i in insights)
    # the 10th accepted record crosses the threshold -> insight appears
    records.append(_rec(vuln_class="IDOR", days_ago=10))
    insights2 = _loop(tmp_path, records, name="journal2").analyze()
    assert any(
        i.kind == KIND_CLASS_FOCUS and "IDOR" in i.recommendation for i in insights2
    )


def test_class_focus_insight_math(tmp_path):
    records = (
        [_rec(vuln_class="IDOR", days_ago=i, endpoint=f"/api/v{i}/a") for i in range(1, 9)]
        + [_rec(vuln_class="IDOR", days_ago=9, status="rejected", endpoint="/x/1"),
           _rec(vuln_class="IDOR", days_ago=10, status="rejected", endpoint="/x/2")]
    )
    records += (
        [_rec(vuln_class="XSS", days_ago=i, status="rejected", endpoint=f"/web/{i}")
         for i in range(1, 9)]
        + [_rec(vuln_class="XSS", days_ago=9, endpoint="/web/9"),
           _rec(vuln_class="XSS", days_ago=10, endpoint="/web/10")]
    )
    insights = _loop(tmp_path, records).analyze()
    by_class = {i.recommendation.rsplit(" ", 1)[-1]: i
                for i in insights if i.kind == KIND_CLASS_FOCUS}
    # 8/10 accepted -> increase; 2/10 accepted -> decrease
    assert by_class["IDOR"].recommendation == "increase focus on IDOR"
    assert by_class["IDOR"].data_points == 10
    assert "8/10 accepted" in by_class["IDOR"].rationale
    assert by_class["IDOR"].confidence == 0.5  # 10 / (2 * MIN_DATA_POINTS)
    assert by_class["XSS"].recommendation == "decrease focus on XSS"
    assert "2/10 accepted" in by_class["XSS"].rationale
    # every insight carries a rationale (DoD)
    assert all(i.rationale for i in insights)


def test_deterministic_across_runs(tmp_path):
    records = (
        [_rec(vuln_class="IDOR", days_ago=i) for i in range(1, 11)]
        + [_rec(vuln_class="IDOR", days_ago=i, status="duplicate", endpoint="/dup/1")
           for i in range(11, 21)]
        + [_rec(vuln_class="RCE", days_ago=i, status="rejected", payout=0)
           for i in range(1, 11)]
    )
    loop = _loop(tmp_path, records)
    first = [i.as_dict() for i in loop.analyze()]
    second = [i.as_dict() for i in loop.analyze()]
    assert first == second  # identical inputs -> identical insights (L-3)


def test_no_insights_on_empty_data(tmp_path):
    # missing journal file
    assert _loop(tmp_path, []).analyze() == []
    # corrupt lines are skipped, never raised
    bad = tmp_path / "corrupt.jsonl"
    bad.write_text("{not json\n[]\n" + json.dumps(_rec(days_ago=1)) + "\n", encoding="utf-8")
    loop = LearningLoop(bad, log_path=tmp_path / "c.jsonl", now=NOW)
    assert loop.analyze() == []


def test_scheduler_delta_is_advisory_only(tmp_path):
    records = (
        [_rec(vuln_class="IDOR", days_ago=i, payout=200.0) for i in range(1, 11)]
        + [_rec(vuln_class="XSS", days_ago=i, status="duplicate", endpoint="/dup/x")
           for i in range(1, 11)]
        + [_rec(vuln_class="RCE", program="slow-corp", days_ago=i, resolve_days=95)
           for i in range(1, 11)]
        + [_rec(vuln_class="SQLI", program="poor-corp", days_ago=i, payout=10.0)
           for i in range(1, 11)]
    )
    loop = _loop(tmp_path, records)
    insights = loop.analyze()
    kinds = {i.kind for i in insights}
    assert kinds == {KIND_CLASS_FOCUS, KIND_PROGRAM_FOCUS, KIND_TIMING_ADJUST,
                     KIND_DUP_PATTERN}
    delta = loop.apply_to_scheduler(insights)
    # a pure data record: no mutation, no calls, no sends (L-1, L-8)
    assert isinstance(delta, SchedulerDelta)
    assert delta.as_dict()["advisory"] is True
    assert all(isinstance(v, (dict, float, int)) for v in
               (delta.class_focus_multipliers, delta.program_budget_multipliers,
                delta.dup_rate_adjustments, delta.timing_bias_days))
    assert not [a for a in dir(delta) if a.startswith(("apply", "save", "send", "push"))]
    # suggested multipliers follow the insight math
    assert delta.class_focus_multipliers.get("IDOR") == 1.25
    assert delta.program_budget_multipliers.get("example-corp") == 1.25
    assert delta.timing_bias_days > 0  # 45d mean > 30d threshold
    assert delta.dup_rate_adjustments  # duplicate pattern present
    # applying the delta mutates nothing: the insights are untouched
    before = [i.as_dict() for i in insights]
    loop.apply_to_scheduler(insights)
    assert [i.as_dict() for i in insights] == before


def test_insights_logged(tmp_path):
    records = [_rec(vuln_class="IDOR", days_ago=i) for i in range(1, 11)]
    log_path = tmp_path / "insights.jsonl"
    loop = LearningLoop(tmp_path / "journal.jsonl", log_path=log_path, now=NOW)
    (tmp_path / "journal.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8"
    )
    insights = loop.analyze()
    assert insights
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(insights)
    parsed = [json.loads(line) for line in lines]
    assert {p["kind"] for p in parsed} == {i.kind for i in insights}
    assert all(p["advisory"] is True for p in parsed)

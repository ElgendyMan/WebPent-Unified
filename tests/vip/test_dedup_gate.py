# tests/vip/test_dedup_gate.py
"""Track 11 item 5 — dedup-before-nomination gate.

Covers: pure classification, annotation, reporter split, report
summaries, and the fail-safe node paths (no engagement context, prior
base failure). No database or network is touched.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.vip.dedup_gate import (
    DedupDecision,
    DedupRecord,
    DedupReport,
    annotate_finding,
    classify_against_prior_base,
    dedup_gate_node,
    render_duplicates_appendix,
    split_duplicate_findings,
)


def _finding(
    *,
    url: str = "https://app.example.com/search?q=1",
    vuln_class: VulnClass = VulnClass.XSS,
    title: str = "Reflected XSS in search",
    fid=None,
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        id=fid or uuid4(),
        title=title,
        severity=Severity.MEDIUM,
        description="deterministic test finding",
        tool_name="test",
        url=url,
        confidence=Confidence.FIRM,
        vuln_class=vuln_class,
        evidence=evidence,
    )


class TestClassifyAgainstPriorBase:
    def test_new_finding_when_prior_base_empty(self):
        finding = _finding()
        records = classify_against_prior_base([finding], [])
        assert len(records) == 1
        assert records[0].decision == DedupDecision.NEW
        assert records[0].duplicate_of is None

    def test_duplicate_detected_by_fingerprint(self):
        prior = _finding()
        current = _finding()  # same class/url/title → same fingerprint
        records = classify_against_prior_base([current], [prior])
        assert records[0].decision == DedupDecision.DUPLICATE
        assert records[0].duplicate_of == str(prior.id)

    def test_different_class_is_not_duplicate(self):
        prior = _finding(vuln_class=VulnClass.XSS)
        current = _finding(vuln_class=VulnClass.SQLI)
        records = classify_against_prior_base([current], [prior])
        assert records[0].decision == DedupDecision.NEW

    def test_idor_is_endpoint_scoped_not_title_scoped(self):
        prior = _finding(vuln_class=VulnClass.IDOR, title="IDOR on document A")
        current = _finding(vuln_class=VulnClass.IDOR, title="Access control on document A")
        records = classify_against_prior_base([current], [prior])
        assert records[0].decision == DedupDecision.DUPLICATE

    def test_same_physical_record_is_not_duplicate(self):
        finding = _finding()
        records = classify_against_prior_base([finding], [finding])
        assert records[0].decision == DedupDecision.NEW


class TestAnnotationAndSplit:
    def test_annotate_preserves_existing_evidence(self):
        finding = _finding(evidence={"http_status": 200})
        record = DedupRecord(
            finding_id=str(finding.id),
            fingerprint="x",
            decision=DedupDecision.DUPLICATE,
            duplicate_of="abc",
        )
        annotated = annotate_finding(finding, record)
        assert annotated.evidence["http_status"] == 200
        assert annotated.evidence["dedup_review"]["decision"] == "duplicate"
        assert annotated.evidence["dedup_review"]["duplicate_of"] == "abc"
        # original untouched
        assert "dedup_review" not in (finding.evidence or {})

    def test_split_moves_only_annotated_duplicates(self):
        dup = annotate_finding(
            _finding(),
            DedupRecord(
                finding_id="x",
                fingerprint="f",
                decision=DedupDecision.DUPLICATE,
                duplicate_of="prior-1",
            ),
        )
        fresh = _finding()
        nominated, duplicates = split_duplicate_findings([fresh, dup])
        assert duplicates == [dup]
        assert nominated == [fresh]

    def test_split_fail_open_without_annotation(self):
        finding = _finding()
        nominated, duplicates = split_duplicate_findings([finding])
        assert nominated == [finding]
        assert duplicates == []


class TestDedupGateNode:
    def test_no_engagement_context_is_clean_no_history(self):
        finding = _finding()
        result = dedup_gate_node({"findings": [finding]})
        report = DedupReport.model_validate(result["dedup_report"])
        assert report.status == "clean_no_history"
        assert report.duplicate_count == 0
        assert len(result["findings"]) == 1

    def test_prior_base_failure_is_indeterminate_and_suppresses_nothing(self, monkeypatch):
        def _boom(*args, **kwargs):
            raise RuntimeError("db unavailable")

        monkeypatch.setattr("webpent.vip.dedup_gate.load_prior_findings", _boom)
        finding = _finding()
        result = dedup_gate_node(
            {"findings": [finding], "engagement_id": "eng-1", "thread_id": "t1"}
        )
        report = DedupReport.model_validate(result["dedup_report"])
        assert report.status == "indeterminate"
        assert report.duplicate_count == 0
        # fail-safe: finding still present, flagged for human review
        assert len(result["findings"]) == 1
        annotated = result["findings"][0]
        assert annotated.evidence["dedup_review"]["decision"] == "indeterminate"

    def test_applied_path_marks_duplicate(self, monkeypatch):
        prior = _finding()
        current = _finding()

        def _fake_load(engagement_id, **kwargs):
            return [prior], "prior base: 1 findings"

        monkeypatch.setattr("webpent.vip.dedup_gate.load_prior_findings", _fake_load)
        result = dedup_gate_node(
            {"findings": [current], "engagement_id": "eng-1", "thread_id": "t-current"}
        )
        report = DedupReport.model_validate(result["dedup_report"])
        assert report.status == "applied"
        assert report.duplicate_count == 1
        assert report.new_count == 0
        assert report.suppressed_ids == [str(current.id)]
        annotated = result["findings"][0]
        assert annotated.evidence["dedup_review"]["duplicate_of"] == str(prior.id)

    def test_current_thread_excluded_from_prior_base(self, monkeypatch):
        calls = {}

        def _fake_load(engagement_id, *, owner_username="", client_id="", exclude_thread_ids=None):
            calls["excluded"] = set(exclude_thread_ids or set())
            return [], "no prior threads"

        monkeypatch.setattr("webpent.vip.dedup_gate.load_prior_findings", _fake_load)
        dedup_gate_node(
            {"findings": [], "engagement_id": "eng-1", "thread_id": "t-current"}
        )
        assert calls["excluded"] == {"t-current"}


class TestAppendix:
    def test_appendix_renders_table_for_duplicates(self):
        dup = annotate_finding(
            _finding(),
            DedupRecord(
                finding_id="x",
                fingerprint="f",
                decision=DedupDecision.DUPLICATE,
                duplicate_of="prior-9",
            ),
        )
        text = render_duplicates_appendix([dup])
        assert "Duplicates of Previously Reported Findings" in text
        assert "prior-9" in text
        assert dup.url in text

    def test_appendix_empty_when_no_duplicates(self):
        assert render_duplicates_appendix([]) == ""


class TestReportModel:
    def test_suppressed_ids_property(self):
        report = DedupReport(
            status="applied",
            records=[
                DedupRecord(finding_id="a", fingerprint="f1", decision=DedupDecision.NEW),
                DedupRecord(
                    finding_id="b",
                    fingerprint="f2",
                    decision=DedupDecision.DUPLICATE,
                    duplicate_of="p",
                ),
            ],
        )
        assert report.suppressed_ids == ["b"]


@pytest.mark.parametrize(
    "decision_value",
    ["new", "duplicate", "indeterminate"],
)
def test_decision_vocabulary_is_stable(decision_value):
    assert DedupDecision(decision_value).value == decision_value

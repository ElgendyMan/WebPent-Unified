# tests/vip/test_retest.py
"""Track 11 item 7 — controlled retest.

Covers the fail-closed gates, the deterministic verdicts, the status
update rules (never a promotion), and the append-only comparison ledger.
Network is never touched: probe paths are exercised through ProbeResult
objects and a monkeypatched replay, plus a real scope-block decision.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.vip.retest import (
    ProbeResult,
    RetestLedger,
    RetestOutcome,
    RetestResult,
    apply_retest,
    decide_outcome,
    load_scope_policy,
    run_retest,
    validate_authorization,
)

SCOPE_YAML = """
description: "test scope"
in_scope:
  - url: "https://app.example.com"
out_of_scope:
  - url: "https://app.example.com"
    path: "/admin"
    allow: false
limits:
  no_destructive: true
"""


def _finding(
    *,
    url: str = "https://app.example.com/search?q=1",
    vuln_class: VulnClass = VulnClass.XSS,
    confidence_level: str = "Tool-Confirmed",
    canary_token: str | None = "canary-abc123",
    evidence_bundle: dict | None = None,
    evidence: dict | None = None,
) -> Finding:
    # UM-DR-25: the M1-B/E-1 contract hardened Finding so that
    # Tool-Confirmed requires provenance (evidence naming the confirming
    # gate). The retest fixtures predate that hardening and built
    # proof-less Tool-Confirmed findings — supply the canonical key.
    if confidence_level == "Tool-Confirmed" and not evidence_bundle:
        evidence = dict(evidence or {})
        if not any(
            key in evidence
            for key in ("tool_confirmed_by", "validator_tool",
                        "promotion_guard", "oob_confirmed", "avi_promoted")
        ):
            evidence["tool_confirmed_by"] = "test-validator"
    return Finding(
        id=uuid4(),
        title="Reflected XSS in search",
        severity=Severity.MEDIUM,
        description="test finding",
        tool_name="test",
        url=url,
        confidence=Confidence.CONFIRMED,
        vuln_class=vuln_class,
        confidence_level=confidence_level,
        canary_token=canary_token,
        evidence_bundle=evidence_bundle,
        evidence=evidence,
    )


def _bundle(status: int = 200) -> dict:
    return {
        "request": {"method": "GET", "url": "https://app.example.com/search?q=1", "headers": {}},
        "response": {"status_code": status},
        "verified_markers": ["canary-abc123"],
    }


def _result(outcome: RetestOutcome, finding: Finding | None = None) -> RetestResult:
    finding = finding or _finding()
    return RetestResult(
        finding_id=str(finding.id),
        fingerprint="fp",
        outcome=outcome,
        prior_confidence_level=finding.confidence_level,
        new_confidence_level=finding.confidence_level,
        checked_at="2026-10-28T00:00:00+00:00",
        authorization_ref="test-auth",
    )


class TestGates:
    def test_authorization_is_mandatory(self):
        with pytest.raises(ValueError):
            validate_authorization("")
        with pytest.raises(ValueError):
            validate_authorization(None)
        assert validate_authorization("  ref-1  ") == "ref-1"

    def test_scope_file_is_mandatory(self):
        with pytest.raises(ValueError):
            load_scope_policy("")

    def test_scope_file_must_exist(self, tmp_path):
        from webpent.scope.parser import ScopeParseError

        with pytest.raises(ScopeParseError):
            load_scope_policy(str(tmp_path / "missing.yaml"))


class TestDecideOutcome:
    def test_probe_failure_is_inconclusive(self):
        finding = _finding(evidence_bundle=_bundle())
        outcome, notes = decide_outcome(finding, ProbeResult(ok=False, error="timeout"))
        assert outcome is RetestOutcome.INCONCLUSIVE
        assert any("probe failed" in n for n in notes)

    def test_signature_reproduced_is_still_present(self):
        finding = _finding(evidence_bundle=_bundle(status=200))
        probe = ProbeResult(ok=True, status_code=200, body_excerpt="...canary-abc123...")
        outcome, notes = decide_outcome(finding, probe)
        assert outcome is RetestOutcome.STILL_PRESENT
        assert any("reproduced" in n for n in notes)

    def test_marker_absent_is_fixed(self):
        finding = _finding(evidence_bundle=_bundle(status=200))
        probe = ProbeResult(ok=True, status_code=200, body_excerpt="normal page, no marker")
        outcome, _ = decide_outcome(finding, probe)
        assert outcome is RetestOutcome.FIXED

    def test_status_drift_without_markers_is_inconclusive(self):
        # No markers anywhere (bundle has none, no canary) → only status
        # comparison is possible; 404 vs stored 200 is ambiguous drift.
        bundle = _bundle(status=200)
        bundle.pop("verified_markers")
        finding = _finding(evidence_bundle=bundle, canary_token=None)
        probe = ProbeResult(ok=True, status_code=404, body_excerpt="")
        outcome, notes = decide_outcome(finding, probe)
        assert outcome is RetestOutcome.INCONCLUSIVE
        assert any("status drift" in n for n in notes)

    def test_no_signature_at_all_is_inconclusive(self):
        finding = _finding(evidence_bundle=None, canary_token=None)
        probe = ProbeResult(ok=True, status_code=200, body_excerpt="anything")
        outcome, notes = decide_outcome(finding, probe)
        assert outcome is RetestOutcome.INCONCLUSIVE
        assert any("human review" in n for n in notes)


class TestApplyRetest:
    def test_inconclusive_downgrades_to_needs_human_review(self):
        finding = _finding()
        updated = apply_retest(finding, _result(RetestOutcome.INCONCLUSIVE, finding))
        assert updated.confidence_level == "Needs Human Review"
        assert updated.evidence["retest"]["outcome"] == "inconclusive"
        assert "retest" in updated.reasoning

    def test_still_present_never_promotes_or_demotes(self):
        finding = _finding(confidence_level="Tool-Confirmed")
        updated = apply_retest(finding, _result(RetestOutcome.STILL_PRESENT, finding))
        assert updated.confidence_level == "Tool-Confirmed"
        assert updated.evidence["retest"]["outcome"] == "still_present"

    def test_fixed_keeps_level_closure_is_human(self):
        finding = _finding(confidence_level="Tool-Confirmed")
        updated = apply_retest(finding, _result(RetestOutcome.FIXED, finding))
        assert updated.confidence_level == "Tool-Confirmed"
        assert updated.evidence["retest"]["outcome"] == "fixed"

    def test_original_finding_untouched(self):
        # UM-DR-25: evidence carries the M1-B/E-1 provenance key so the
        # Tool-Confirmed construction is legal; apply_retest must not
        # mutate the ORIGINAL finding's evidence dict either way.
        original_evidence = {"x": 1, "tool_confirmed_by": "test-validator"}
        finding = _finding(evidence=original_evidence)
        updated = apply_retest(finding, _result(RetestOutcome.INCONCLUSIVE, finding))
        assert finding.evidence == original_evidence
        assert finding.confidence_level == "Tool-Confirmed"
        assert updated.evidence["x"] == 1


class TestLedger:
    def test_roundtrip_and_filtering(self, tmp_path):
        ledger = RetestLedger(tmp_path / "retest.jsonl")
        f1, f2 = _finding(), _finding()
        ledger.append(_result(RetestOutcome.STILL_PRESENT, f1))
        ledger.append(_result(RetestOutcome.FIXED, f1))
        ledger.append(_result(RetestOutcome.INCONCLUSIVE, f2))
        rows = ledger.history_for(f1.id)
        assert [r["outcome"] for r in rows] == ["still_present", "fixed"]
        assert rows[0]["authorization_ref"] == "test-auth"
        assert ledger.history_for("nonexistent") == []

    def test_history_empty_when_no_file(self, tmp_path):
        ledger = RetestLedger(tmp_path / "absent.jsonl")
        assert ledger.history_for(uuid4()) == []


class TestRunRetest:
    def test_blocked_by_scope_sends_nothing_and_records(self, tmp_path, monkeypatch):
        scope_path = tmp_path / "scope.yaml"
        scope_path.write_text(SCOPE_YAML, encoding="utf-8")
        policy = load_scope_policy(str(scope_path))
        # URL outside the allow-list → blocked before any network call.
        finding = _finding(url="https://evil.example.com/x")

        def _no_network(*args, **kwargs):  # any network attempt fails the test
            raise AssertionError("network replay must not run when scope blocks")

        monkeypatch.setattr("webpent.vip.retest.replay_probe", _no_network)
        ledger = RetestLedger(tmp_path / "retest.jsonl")
        result = run_retest(
            finding,
            scope_policy=policy,
            authorization="ref-42",
            ledger=ledger,
        )
        assert result.outcome is RetestOutcome.BLOCKED_BY_SCOPE
        assert result.new_confidence_level == result.prior_confidence_level
        rows = ledger.history_for(finding.id)
        assert rows and rows[0]["outcome"] == "blocked_by_scope"
        assert rows[0]["authorization_ref"] == "ref-42"

    def test_path_admin_is_out_of_scope(self, tmp_path, monkeypatch):
        scope_path = tmp_path / "scope.yaml"
        scope_path.write_text(SCOPE_YAML, encoding="utf-8")
        policy = load_scope_policy(str(scope_path))
        finding = _finding(url="https://app.example.com/admin/users")

        monkeypatch.setattr(
            "webpent.vip.retest.replay_probe",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network")),
        )
        result = run_retest(
            finding,
            scope_policy=policy,
            authorization="ref-42",
            ledger=RetestLedger(tmp_path / "retest.jsonl"),
        )
        assert result.outcome is RetestOutcome.BLOCKED_BY_SCOPE

    def test_happy_path_still_present_updates_level_field_only_by_rule(self, tmp_path, monkeypatch):
        scope_path = tmp_path / "scope.yaml"
        scope_path.write_text(SCOPE_YAML, encoding="utf-8")
        policy = load_scope_policy(str(scope_path))
        finding = _finding(evidence_bundle=_bundle(status=200))

        monkeypatch.setattr(
            "webpent.vip.retest.replay_probe",
            lambda *a, **k: ProbeResult(
                ok=True, status_code=200, body_excerpt="echo canary-abc123"
            ),
        )
        ledger = RetestLedger(tmp_path / "retest.jsonl")
        result = run_retest(
            finding,
            scope_policy=policy,
            authorization="ref-7",
            ledger=ledger,
        )
        assert result.outcome is RetestOutcome.STILL_PRESENT
        assert result.new_confidence_level == "Tool-Confirmed"

        updated = apply_retest(finding, result)
        assert updated.evidence["retest"]["outcome"] == "still_present"
        assert "retest" in updated.reasoning

    def test_dry_run_never_touches_network(self, tmp_path, monkeypatch):
        scope_path = tmp_path / "scope.yaml"
        scope_path.write_text(SCOPE_YAML, encoding="utf-8")
        policy = load_scope_policy(str(scope_path))
        finding = _finding()

        monkeypatch.setattr(
            "webpent.vip.retest.replay_probe",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network in dry-run")),
        )
        result = run_retest(
            finding,
            scope_policy=policy,
            authorization="ref-1",
            ledger=RetestLedger(tmp_path / "retest.jsonl"),
            skip_network=True,
        )
        assert result.outcome is RetestOutcome.INCONCLUSIVE
        assert any("dry-run" in n for n in result.notes)


class TestResultModel:
    def test_ledger_row_shape(self):
        finding = _finding()
        result = _result(RetestOutcome.FIXED, finding)
        row = result.to_ledger_row()
        assert row["finding_id"] == str(finding.id)
        assert row["outcome"] == "fixed"
        assert "probe" in row and "notes" in row

    def test_outcome_vocabulary_is_closed(self):
        # The outcome vocabulary is a closed enum: no "escalated" or any
        # other auto-escalation verdict can exist.
        with pytest.raises(ValueError):
            RetestOutcome("escalated")
        assert {o.value for o in RetestOutcome} == {
            "still_present",
            "fixed",
            "inconclusive",
            "blocked_by_scope",
        }


def test_finding_model_rejects_unknown_extra_fields():
    # Finding uses extra="forbid": an unknown field must raise, keeping
    # the retest evidence contract strict.
    with pytest.raises(ValidationError):
        Finding(
            title="t",
            severity="medium",
            description="d",
            tool_name="t",
            url="https://app.example.com/",
            unknown_field="nope",
        )

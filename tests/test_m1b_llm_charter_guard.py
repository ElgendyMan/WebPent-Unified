"""M1-B LLM Charter guard tests (2026-11-05).

The missing sentinel test from M0 TEST_QUALITY_REPORT §4 / LLM Charter §3+§8:

    "Tests include a gate that fails if any LLM path wrote into decision
     fields." / "صفر مخرجات LLM في حقول قرار | gate آلي في كل CI"

These tests drive the SAME deterministic evidence through the tool
validator with three different LLM behaviors — absent (offline), YES, NO —
and assert the promotion decision is IDENTICAL in all three. Any code
path that lets an LLM verdict approve or veto a promotion breaks the
invariant test below.

Covers M0 findings H-3/1.3d + the two new facts from M1_READINESS_REVIEW
§6.2/§6.3 (general-path LLM veto that made offline XSS confirmation
impossible, and the LLM term inside causal_signal).
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.agents.validator import agent as validator_agent  # noqa: E402
from webpent.models.findings import Confidence, Finding, VulnClass  # noqa: E402

# dalfox's proven deterministic marker (V9 P0-A-3 — the precise string,
# verified against the project's own fixtures).
DALFOX_POSITIVE = "[V] Triggered XSS Payload (GET): localhost:8080"
SQLMAP_POSITIVE = (
    "[15:41:05] [INFO] GET parameter 'id' is vulnerable. Do you want to "
    "keep testing the others (if any)? [y/N] N\n"
    "sqlmap identified the following injection point(s) with a total of "
    "47 HTTP(s) requests:\n"
    "---\n"
    "Parameter: id (GET)\n"
    "    Type: boolean-based blind\n"
    "---\n"
)


def _make_xss_finding() -> Finding:
    # Query-string finding with a candidate payload so Stage 0 builds a
    # differential observation and the strict replay gate is reachable.
    return Finding(
        id=uuid.uuid4(),
        title="Reflected XSS in search parameter",
        url="http://192.168.40.128/vulnerabilities/xss_d/?name=test",
        vuln_class=VulnClass.XSS.value,
        severity="high",
        confidence=Confidence.TENTATIVE.value,
        description="test",
        payload="name=<script>alert(1)</script>",
        tool_name="dalfox",
    )


def _make_sqli_reauth_finding() -> Finding:
    # session_reauth is set by the validator's own re-login flow; the
    # deterministic reauth-promotion gate reads it back from evidence.
    return Finding(
        id=uuid.uuid4(),
        title="SQLi at /vulnerabilities/sqli/",
        url="http://192.168.40.128/vulnerabilities/sqli/?id=1&Submit=Submit",
        vuln_class=VulnClass.SQLI.value,
        severity="high",
        confidence=Confidence.TENTATIVE.value,
        description="test",
        payload="id=1",
        tool_name="sqlmap",
        evidence={"session_reauth": True, "reauth_source": "credentials"},
    )


_NOT_FALSE_POSITIVE = SimpleNamespace(is_false_positive=False, reason="")


def _valid_differential() -> SimpleNamespace:
    """A Stage-0 differential result that is NOT a false positive.

    Digests are arbitrary non-empty hex — the strict observation
    formatter (_strict_replay_observation) prefixes and passes them
    through; the test runs without target_url/engagement_id so the
    target-backed strictness path is not the subject here.
    """
    hexd = lambda n: f"{n:064x}"  # noqa: E731
    return SimpleNamespace(
        is_false_positive=False,
        reason="",
        baseline_status=200,
        baseline_length=1200,
        payload_status=200,
        payload_length=1450,
        body_delta=250,
        status_delta=0,
        negative_control_status=200,
        negative_control_length=1201,
        target_fingerprint=hexd(1),
        baseline_request_digest=hexd(2),
        baseline_response_digest=hexd(3),
        payload_request_digest=hexd(4),
        payload_response_digest=hexd(5),
        negative_control_request_digest=hexd(6),
        negative_control_response_digest=hexd(7),
    )


def _run_validator(finding: Finding, vuln_class: str, llm_behavior: str, tool_output: str):
    """Run _validate_with_tool with identical deterministic evidence and a
    controlled LLM behavior: 'offline' (llm=None), 'yes', or 'no'."""
    if llm_behavior == "offline":
        llm = None
        verdict_patch = patch(
            "webpent.agents.validator.agent._llm_supervisor_verdict",
            return_value=False,
        )
    else:
        llm = MagicMock()
        verdict_patch = patch(
            "webpent.agents.validator.agent._llm_supervisor_verdict",
            return_value=(llm_behavior == "yes"),
        )

    tool_entry = MagicMock()
    tool_entry.func = MagicMock(return_value=tool_output)

    with patch(
        "webpent.agents.validator.agent.get_tool",
        return_value=tool_entry,
    ), patch(
        "webpent.agents.validator.agent.baseline_differential_test",
        return_value=_valid_differential(),
    ), patch(
        "webpent.agents.validator.agent._persist_finding_incrementally",
        return_value=True,
    ), verdict_patch:
        return validator_agent._validate_with_tool(
            finding,
            vuln_class,
            llm=llm,
            engagement_id="eng-m1b-charter-guard-001",
        )


class TestLLMCharterGuardNoLlmInDecisionFields:
    """Charter §3/§8: zero LLM outputs in decision fields."""

    def test_xss_decision_invariant_under_llm_behavior(self):
        """Same deterministic evidence + three LLM behaviors => identical
        decision. This is THE charter gate test."""
        results = {
            behavior: _run_validator(
                _make_xss_finding(), "xss", behavior, DALFOX_POSITIVE
            )
            for behavior in ("offline", "yes", "no")
        }
        levels = {b: r.confidence_level for b, r in results.items()}
        assert levels["offline"] == levels["yes"] == levels["no"], (
            f"LLM output leaked into a decision field: {levels}"
        )
        # And the invariant must hold for the confidence enum too.
        confs = {b: r.confidence for b, r in results.items()}
        assert len(set(confs.values())) == 1, f"confidence diverged: {confs}"

    def test_offline_xss_confirms_with_valid_differential(self):
        """M1_READINESS_REVIEW §6.2 regression: with LLM_ENABLED=false
        (llm=None) a dalfox-confirmed XSS with a valid differential
        observation MUST reach Tool-Confirmed. Before M1-B this was
        structurally impossible (llm=None => verdict False => veto)."""
        result = _run_validator(
            _make_xss_finding(), "xss", "offline", DALFOX_POSITIVE
        )
        assert result.confidence_level == "Tool-Confirmed"
        assert result.confidence == Confidence.CONFIRMED.value
        # The advisory verdict is still recorded for downstream review.
        assert result.evidence.get("supervisor_verdict") is False

    def test_llm_dissent_cannot_veto_deterministic_confirmation(self):
        """Charter §3: the LLM is 'eyes and imagination, not judge'. A NO
        verdict with a deterministic marker + valid differential must NOT
        block Tool-Confirmed (it is recorded as advisory dissent)."""
        result = _run_validator(
            _make_xss_finding(), "xss", "no", DALFOX_POSITIVE
        )
        assert result.confidence_level == "Tool-Confirmed"
        assert result.evidence.get("supervisor_verdict") is False
        assert result.evidence.get("deterministic_marker") is True

    def test_llm_yes_alone_cannot_confirm_without_marker(self):
        """Negative control: LLM YES with NO deterministic marker must not
        confirm — the deterministic check is the only positive gate."""
        negative_dalfox = (
            "[+] [scan] do not take more than a minute\n"
            "[CRITICAL] could not create a request"
        )
        result = _run_validator(_make_xss_finding(), "xss", "yes", negative_dalfox)
        assert result.confidence_level != "Tool-Confirmed"


class TestSQLiReauthGateDeterministicOnly:
    """M0 H-3/1.3d + UM-DR-35: the historical SQLi reauth tool-native
    promotion was a DOCUMENTED BYPASS of verify_replay_evidence (a sqlmap
    marker + a recorded re-auth fact promoted Tool-Confirmed with no
    differential replay, no ProofBundle and no CausalGuard adjudication).
    The UM-DR-35 corrective closure REMOVED the bypass: the gate is now
    fail-closed — without a differential observation routed through the
    universal authority the finding stays Needs Human Review regardless
    of LLM behavior."""

    def test_reauth_promotion_ignores_llm_verdict(self):
        """session_reauth + sqlmap marker + LLM says NO => still BLOCKED.
        The reauth bypass no longer promotes; the LLM verdict remains
        advisory-only (recorded in evidence) and is irrelevant to the
        deterministic fail-closed outcome."""
        result = _run_validator(
            _make_sqli_reauth_finding(), "sqli", "no", SQLMAP_POSITIVE
        )
        assert result.confidence_level == "Needs Human Review"
        guard = result.evidence.get("promotion_guard") or {}
        assert guard.get("status") == "blocked"
        assert guard.get("reason") == "sqli_session_reauth_bypass_removed_umdr35"
        assert guard.get("sqlmap_marker") is True
        assert guard.get("fresh_session_reauth") is True
        # The deterministic marker is recorded; on the sqlmap path the
        # deterministic check is authoritative (LLM skipped — the
        # recorded supervisor_verdict reflects that, not an LLM output),
        # and the OUTCOME is invariant across LLM behaviors (proven by
        # test_reauth_promotion_offline using llm=None).

    def test_reauth_promotion_offline(self):
        """Offline (llm=None) reauth path behaves identically (blocked).
        The LLM's absence changes nothing: the universal confirmation
        boundary is deterministic-only and fail-closed."""
        result = _run_validator(
            _make_sqli_reauth_finding(), "sqli", "offline", SQLMAP_POSITIVE
        )
        assert result.confidence_level == "Needs Human Review"
        guard = result.evidence.get("promotion_guard") or {}
        assert guard.get("status") == "blocked"
        assert guard.get("reason") == "sqli_session_reauth_bypass_removed_umdr35"

    def test_no_reauth_stays_fail_closed_even_with_llm_yes(self):
        """Without a fresh session_reauth, SQLi without differential
        evidence remains Needs Human Review — an LLM YES cannot rescue
        it (fail-closed)."""
        finding = _make_sqli_reauth_finding()
        finding = finding.model_copy(update={"evidence": {}})
        result = _run_validator(finding, "sqli", "yes", SQLMAP_POSITIVE)
        assert result.confidence_level == "Needs Human Review"
        guard = result.evidence.get("promotion_guard") or {}
        assert guard.get("status") == "blocked"


class TestCausalSignalDeterministic:
    """M1_READINESS_REVIEW §6.3: causal_signal must not feed the LLM term
    into the strict verifier."""

    def test_causal_signal_ignores_llm_verdict(self):
        """A det-confirmed finding with LLM dissent AND a differential
        observation must still pass the strict verifier's causal-signal
        input (previously causal_signal included llm_confirmed, which
        would have wrongly blocked exactly this case after M1-B)."""
        result = _run_validator(
            _make_xss_finding(), "xss", "no", DALFOX_POSITIVE
        )
        assert result.confidence_level == "Tool-Confirmed"
        # The verifier's evidence must show causal_signal=True despite the
        # advisory dissent.
        assert result.evidence.get("causal_signal") is True

    def test_source_declares_deterministic_causal_basis(self):
        import inspect

        source = inspect.getsource(validator_agent._validate_with_tool)
        assert "deterministic_tool_marker_with_differential_replay" in source
        assert (
            "deterministic_tool_marker_and_supervisor_verdict_with_"
            "differential_replay"
        ) not in source.replace(
            "deterministic_tool_marker_with_differential_replay", ""
        )
        # The promotion condition must not contain the llm co-gate.
        assert "and det_confirmed and llm_confirmed" not in source


class TestCharterGuardSourceContract:
    """Structural sentinel: the promotion decision expression itself."""

    def test_general_gate_is_det_only(self):
        import inspect

        source = inspect.getsource(validator_agent._validate_with_tool)
        assert "confirmed = det_confirmed\n" in source
        assert "confirmed = det_confirmed and llm_confirmed" not in source

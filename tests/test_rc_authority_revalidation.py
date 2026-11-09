# tests/test_rc_authority_revalidation.py
"""R-C authority-law + revalidation locks.

Live context (rb_on campaign evidence): the validator confirmed an XSS
finding in-graph via real dalfox (deterministic=True, llm=True) and
persisted it Tool-Confirmed — then the Devil's Advocate's LLM-only
DEBUNKED verdict silently demoted it in graph state, and the promised
"one bounded revalidation" (Phase 5.2) never ran because the
validator's idempotency guard skipped the revalidation pass.

Locks proven here:

1. AUTHORITY LAW: an LLM-only DA debunk cannot demote a tool-backed
   finding (Tool-Confirmed label or deterministic_marker+validator_tool
   evidence).  The counter-argument is appended to reasoning, the label
   is untouched.  Non-tool-backed findings keep the existing downgrade
   behavior.
2. REVALIDATION WIRING: a finding in the DA revalidation batch is
   unblocked for exactly one deterministic re-run (skip keys + gate
   flags consumed); findings outside the batch keep the idempotency
   skip.
3. DB INTEGRITY: save_finding's Tool-Confirmed preservation keeps the
   sealed evidence + bundle coherent with the preserved label.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from webpent.agents.devils_advocate.agent import (
    _devils_advocate_finding,
    _is_tool_backed,
)
from webpent.models.findings import Confidence, Finding


def _finding(**overrides: Any) -> Finding:
    base: dict[str, Any] = {
        "id": uuid.uuid4(),
        "thread_id": "rc-lock",
        "url": "http://127.0.0.1:1/a",
        "vuln_class": "xss",
        "title": "candidate finding",
        "severity": "high",
        "description": "d",
        "confidence": Confidence.CONFIRMED.value,
        "confidence_level": "Tool-Confirmed",
        "tool_name": "dalfox",
        "evidence": {
            "validator_tool": "dalfox",
            "deterministic_marker": True,
            "supervisor_verdict": True,
        },
    }
    base.update(overrides)
    return Finding(**base)


class _FakeLLM:
    """Deterministic LLM stub returning a HIGH-confidence DEBUNKED verdict."""

    def __init__(self) -> None:
        self.calls = 0

    def invoke(self, messages: Any) -> Any:
        self.calls += 1

        class _Resp:
            content = (
                "VERDICT: DEBUNKED\n"
                "CONFIDENCE: HIGH\n"
                "ARGUMENT: the reflected parameter is HTML-escaped "
                "according to the evidence."
            )

        return _Resp()


# ---------------------------------------------------------------------------
# 1. Authority law: LLM-only debunk cannot demote tool-backed evidence
# ---------------------------------------------------------------------------

def test_da_debunk_cannot_demote_tool_confirmed_label() -> None:
    finding = _finding()  # Tool-Confirmed label
    llm = _FakeLLM()
    updated = _devils_advocate_finding(finding, llm, allow_downgrade=True)
    assert llm.calls == 1
    assert updated.confidence_level == "Tool-Confirmed"
    # The skeptic's take is preserved for the operator.
    assert "Devil's Advocate Assessment" in (updated.reasoning or "")


def test_da_debunk_cannot_demote_marker_backed_evidence() -> None:
    finding = _finding(
        confidence_level="Pending",
        evidence={
            "validator_tool": "sqlmap",
            "deterministic_marker": True,
        },
    )
    updated = _devils_advocate_finding(finding, _FakeLLM(), allow_downgrade=True)
    assert updated.confidence_level == "Pending"
    assert updated.evidence.get("validator_tool") == "sqlmap"


def test_da_still_downgrades_non_tool_backed_findings() -> None:
    """Existing downgrade behavior is preserved for LLM-only candidates."""
    finding = _finding(
        confidence_level="AI-Assessed",
        tool_name="strategist",
        evidence={"heuristic": True},
    )
    updated = _devils_advocate_finding(finding, _FakeLLM(), allow_downgrade=True)
    assert updated.confidence_level == "Needs Human Review"


def test_is_tool_backed_detection() -> None:
    assert _is_tool_backed(_finding()) is True
    assert _is_tool_backed(
        _finding(
            confidence_level="Pending",
            evidence={"validator_tool": "dalfox", "deterministic_marker": True},
        )
    )
    assert (
        _is_tool_backed(
            _finding(
                confidence_level="AI-Assessed",
                tool_name="strategist",
                evidence={"heuristic": True},
            )
        )
        is False
    )


def test_da_offline_mode_still_never_downgrades() -> None:
    """llm=None keeps the pre-existing no-op contract."""
    finding = _finding(confidence_level="AI-Assessed", evidence={"x": 1})
    updated = _devils_advocate_finding(finding, None, allow_downgrade=True)
    assert updated.confidence_level == "AI-Assessed"


# ---------------------------------------------------------------------------
# 2. Revalidation wiring: the DA batch unblocks exactly one re-run
# ---------------------------------------------------------------------------

def _validator_state(finding: Finding, revalidation_ids: list[str]) -> dict[str, Any]:
    return {
        "findings": [finding],
        "hypotheses": [],
        "evidence_ledger": [],
        "devils_advocate_revalidation_ids": revalidation_ids,
        "devils_advocate_revalidation_count": 1,
        "payloads_to_test": {},
        "optimization_retries": {},
        "optimization_attempt_fingerprints": {},
    }


def _revalidation_candidate() -> Finding:
    return _finding(
        id=uuid.uuid4(),
        confidence_level="Pending",
        confidence=Confidence.TENTATIVE.value,
        tool_name="strategist",
        evidence={
            "validation_attempted": True,
            "devils_advocate_gate": "rejected",
            "devils_advocate_revalidation_required": True,
            "devils_advocate_revalidation_reason": "test gate",
            "evidence_contract": {"required": ["marker"]},
        },
    )


def test_validator_unblocks_da_revalidation_batch() -> None:
    """The revalidation pass consumes the gate flags and re-runs."""
    from webpent.agents.validator.agent import validator_node

    finding = _revalidation_candidate()
    state = _validator_state(finding, revalidation_ids=[str(finding.id)])
    update = validator_node(state)
    out = {str(f.id): f for f in update["findings"]}[str(finding.id)]
    evidence = out.evidence or {}
    assert "devils_advocate_revalidation_required" not in evidence
    assert "devils_advocate_gate" not in evidence


def test_validator_keeps_idempotent_skip_outside_batch() -> None:
    """Findings outside the DA batch keep the no-duplicate-tool guarantee."""
    from webpent.agents.validator.agent import validator_node

    finding = _revalidation_candidate()
    state = _validator_state(finding, revalidation_ids=[])  # not in batch
    update = validator_node(state)
    out = {str(f.id): f for f in update["findings"]}[str(finding.id)]
    evidence = out.evidence or {}
    assert evidence.get("devils_advocate_revalidation_required") is True
    assert evidence.get("validation_attempted") is True


# ---------------------------------------------------------------------------
# 4. R-C-4: dalfox [R] reflection-only output is NOT a deterministic confirm
# ---------------------------------------------------------------------------

_DALFOX_R_ONLY_OUTPUT = """
{
  "messages": [
    {"confidence": "low",
     "confidence_reason": "payload echoed in the response; no executable position confirmed",
     "message_str": "[R] Triggered XSS Payload (reflected): body=' onerror=alert(1) '",
     "type": "R",
     "type_description": "Reflected - payload appears in the response, but its position was not confirmed exploitable; confirm manually"}
  ],
  "meta": {"findings_count": 1}
}
"""

_DALFOX_V_OUTPUT = """
{
  "messages": [
    {"confidence": "high",
     "confidence_reason": "payload reached an executable position in the parsed response",
     "message_str": "Triggered XSS Payload (DOM marker): name=<svg onload=alert(1)>",
     "type": "V",
     "type_description": "Vulnerable - dalfox asserts this input is exploitable; act on it"}
  ],
  "meta": {"findings_count": 1}
}
"""


def test_dalfox_reflection_only_output_is_not_confirmed() -> None:
    """dalfox's own low-confidence [R] findings must not det-confirm."""
    from webpent.agents.validator.agent import _deterministic_check

    assert _deterministic_check("xss", _DALFOX_R_ONLY_OUTPUT) is False


def test_dalfox_verified_marker_still_confirms() -> None:
    """A [V]-verified / high-confidence dalfox assertion still confirms."""
    from webpent.agents.validator.agent import _deterministic_check

    assert _deterministic_check("xss", _DALFOX_V_OUTPUT) is True


def test_dalfox_negative_guard_unchanged() -> None:
    from webpent.agents.validator.agent import _deterministic_check

    assert _deterministic_check("xss", "[V] No XSS vulnerability found") is False
    assert _deterministic_check("xss", "") is False


# ---------------------------------------------------------------------------
# 5. R-C-5: the confirmed finding must CARRY its confirmation evidence
# ---------------------------------------------------------------------------

def test_tool_confirmed_finding_carries_confirmation_evidence(monkeypatch) -> None:
    """R-C-5: the success path must attach validator_tool/marker/verdict
    evidence — the label alone is not the artifact (live defect: the
    DB row showed validator_tool='' with label Tool-Confirmed)."""
    from types import SimpleNamespace

    import webpent.agents.validator.agent as vagent

    dalfox_stdout = (
        '{"messages":[{"confidence":"high",'
        '"message_str":"Triggered XSS Payload (DOM marker): name=<svg onload=alert(1)>",'
        '"type":"V",'
        '"type_description":"Vulnerable - dalfox asserts this input is exploitable; act on it"}],'
        '"meta":{"findings_count":1}}'
    )

    def fake_run_dalfox(*args, **kwargs):
        return dalfox_stdout

    monkeypatch.setattr(
        vagent, "get_tool",
        lambda name: SimpleNamespace(func=fake_run_dalfox)
        if name == "dalfox" else None,
    )

    fake_bundle = SimpleNamespace(
        model_dump=lambda mode="json": {"schema_version": 1, "stub": True}
    )
    monkeypatch.setattr(
        vagent, "verify_replay_evidence",
        lambda *a, **kw: SimpleNamespace(
            passed=True, reason="", proof_bundle=fake_bundle, evidence={}
        ),
    )
    monkeypatch.setattr(
        vagent, "generate_canary_token", lambda: "canary-stub"
    )
    monkeypatch.setattr(
        vagent, "_persist_finding_incrementally",
        lambda finding, thread_id=None: True,
    )

    finding = _finding(
        confidence_level="Pending",
        confidence=Confidence.TENTATIVE.value,
        evidence={},
    )
    updated = vagent._validate_with_tool(
        finding,
        vuln_class="xss",
        llm=_YesQuoteLLM(dalfox_stdout),
        stealth_mode=False,
        playwright_enabled=False,
        auth_state=None,
        session_cookies=None,
        credentials=None,
        target_url="http://127.0.0.1:1/xss/reflected",
        identity_profiles=None,
        thread_id="rc-lock",
        target_scope=("http://127.0.0.1:1",),
    )

    assert updated.confidence_level == "Tool-Confirmed"
    evidence = updated.evidence or {}
    assert evidence.get("validator_tool") == "dalfox", (
        "R-C-5 regression: Tool-Confirmed finding must carry validator_tool"
    )
    assert evidence.get("deterministic_marker") is True
    assert evidence.get("supervisor_verdict") is True
    assert updated.evidence_bundle is not None


class _YesQuoteLLM:
    """LLM stub that answers YES with a grounded <quote> citation."""

    def __init__(self, tool_output: str) -> None:
        self._tool_output = tool_output

    def invoke(self, messages: Any) -> Any:
        marker = "Triggered XSS Payload"

        class _Resp:
            content = (
                f"YES\n<quote>{marker}</quote>"
            )

        return _Resp()


# ---------------------------------------------------------------------------
# 3. DB integrity: preservation keeps evidence coherent with the label
# ---------------------------------------------------------------------------

def test_save_finding_preserves_evidence_with_label(tmp_path, monkeypatch) -> None:
    """A late stale save cannot leave label=Tool-Confirmed + evidence=unconfirmed."""

    monkeypatch.setenv("WEBPENT_DATABASE_URL", f"sqlite:///{tmp_path}/rc.db")
    from webpent.memory.db import DatabaseManager

    db = DatabaseManager()
    db.init_db()

    confirmed = _finding()
    db.save_finding(confirmed)

    # Late stale snapshot: same id, lower label, DIFFERENT evidence.
    stale = _finding(
        confidence_level="Pending",
        confidence=Confidence.TENTATIVE.value,
        evidence={"validation_attempted": True, "evidence_quality": "unconfirmed"},
    )
    db.save_finding(stale)

    row = db._connect() and None
    with db._connect() as conn:
        r = conn.execute(
            "SELECT confidence_level, evidence FROM findings WHERE id=?",
            (str(confirmed.id),),
        ).fetchone()
    assert r["confidence_level"] == "Tool-Confirmed"
    saved_evidence = json.loads(r["evidence"]) if r["evidence"] else {}
    # The sealed confirmation evidence survived — not the stale snapshot.
    assert saved_evidence.get("validator_tool") == "dalfox"
    assert saved_evidence.get("deterministic_marker") is True

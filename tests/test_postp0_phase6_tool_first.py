"""POST-P0 Phase 6 — tool-first confirmation coverage expansion.

Pins:
  * when LLM payload generation FAILS (empty payloads), a sqli finding
    still receives the synthetic tool-driven marker so the execution
    sandbox is not skipped, and the validator still invokes sqlmap
    (tool runs exactly once, payload-independent),
  * the same guarantee now holds for xss (POST-P0 Phase 6 extension):
    dalfox tool invocation is payload-independent and the sandbox gate
    stays open on LLM failure,
  * an explicit negative remains possible: when the tool runs and finds
    nothing (empty/marker-free output) the finding is NOT confirmed —
    no fake confirm exists on the tool path,
  * Stage-0/baseline causality guards are untouched (the marker strings
    are distinct from the tool-confirmed markers).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from webpent.agents.payload_generator.agent import (
    payload_generator_node,
)
from webpent.agents.validator.agent import (
    _DALFOX_CONFIRMED_MARKER,
    _SQLMAP_CONFIRMED_MARKER,
    _validate_with_tool,
)
from webpent.models.findings import Confidence, Finding, Severity
from webpent.models.targets import Target
from webpent.state.initial_state import build_initial_state


def _finding(vuln_class: str) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        title=f"fixture {vuln_class} candidate",
        severity=Severity.HIGH.value,
        description="phase6 fixture",
        tool_name="hypothesis",
        url="http://lab.local/item?id=1",
        confidence=Confidence.TENTATIVE,
        confidence_level="Pending",
        reasoning="fixture",
        vuln_class=vuln_class,
        created_at=datetime.now(timezone.utc),
        thread_id="t",
    )


def _state(finding: Finding) -> dict:
    state = build_initial_state(target=Target(url="http://lab.local"), thread_id="t")
    state["findings"] = [finding]
    return state


def test_synth_markers_distinct_from_confirmation_markers() -> None:
    # A tool-driven marker must never be confusable with a confirmed
    # marker (Stage-0 causality guard integrity).
    assert _SQLMAP_CONFIRMED_MARKER != "__SQLMAP_TOOL_DRIVEN__"
    assert _DALFOX_CONFIRMED_MARKER != "__DALFOX_TOOL_DRIVEN__"
    assert "__SQLMAP_TOOL_DRIVEN__" not in _DALFOX_CONFIRMED_MARKER
    assert "__DALFOX_TOOL_DRIVEN__" not in _SQLMAP_CONFIRMED_MARKER


def test_sqli_llm_failure_still_seeds_payloads_and_invokes_sqlmap(
    monkeypatch,
) -> None:
    finding = _finding("sqli")
    state = _state(finding)
    # LLM payload generation fails (empty payloads, no canary).
    monkeypatch.setattr(
        "webpent.agents.payload_generator.agent._generate_payloads_for_finding",
        lambda finding, llm, waf_vendor=None: ([], None),
    )
    update = payload_generator_node(state)
    # Synthetic marker seeded despite LLM failure.
    assert update["payloads_to_test"][str(finding.id)] == ["__SQLMAP_TOOL_DRIVEN__"]
    # Sandbox gate stays open.
    from webpent.agents.execution_sandbox.agent import _has_payloads

    merged_state = {**state, "payloads_to_test": update["payloads_to_test"]}
    assert _has_payloads(merged_state) is True
    # Validator invokes sqlmap regardless of payloads.
    calls: list = []

    def fake_run_fn(url, **kwargs):
        calls.append(url)
        return ""  # tool produced no marker -> explicit negative

    monkeypatch.setattr(
        "webpent.agents.validator.agent.get_tool",
        lambda name: type("E", (), {"func": staticmethod(fake_run_fn)})(),
    )
    updated_finding = next(f for f in update["findings"] if f.id == finding.id)
    result = _validate_with_tool(
        updated_finding,
        vuln_class="sqli",
        llm=None,
        session_cookies={},
        target_scope=("lab.local",),
        identity_profiles=[],
        engagement_id="eng-1",
        thread_id="t",
        stealth_mode=False,
        playwright_enabled=False,
        target_package=None,
        target_url="http://lab.local/item?id=1",
    )
    assert calls == ["http://lab.local/item?id=1"]
    assert result.confidence_level != "Tool-Confirmed"


def test_xss_llm_failure_still_seeds_payloads_and_invokes_dalfox(
    monkeypatch,
) -> None:
    finding = _finding("xss")
    state = _state(finding)
    monkeypatch.setattr(
        "webpent.agents.payload_generator.agent._generate_payloads_for_finding",
        lambda finding, llm, waf_vendor=None: ([], None),
    )
    update = payload_generator_node(state)
    # POST-P0 Phase 6: synthetic marker seeded for XSS too.
    assert update["payloads_to_test"][str(finding.id)] == ["__DALFOX_TOOL_DRIVEN__"]
    from webpent.agents.execution_sandbox.agent import _has_payloads

    merged_state = {**state, "payloads_to_test": update["payloads_to_test"]}
    assert _has_payloads(merged_state) is True
    # dalfox invocation is payload-independent: run with empty payloads.
    calls: list = []

    def fake_run_fn(url, **kwargs):
        calls.append(url)
        return "no injection points found"

    monkeypatch.setattr(
        "webpent.agents.validator.agent.get_tool",
        lambda name: type("E", (), {"func": staticmethod(fake_run_fn)})(),
    )
    updated_finding = next(f for f in update["findings"] if f.id == finding.id)
    result = _validate_with_tool(
        updated_finding,
        vuln_class="xss",
        llm=None,
        session_cookies={},
        target_scope=("lab.local",),
        identity_profiles=[],
        engagement_id="eng-1",
        thread_id="t",
        stealth_mode=False,
        playwright_enabled=False,
        target_package=None,
        target_url="http://lab.local/item?id=1",
    )
    assert calls == ["http://lab.local/item?id=1"]
    # Explicit negative: tool ran, no deterministic marker, NOT confirmed.
    assert result.confidence_level != "Tool-Confirmed"


def test_sqli_tool_native_path_does_not_need_llm(monkeypatch) -> None:
    # Even with the LLM entirely unavailable, the sqlmap run happens.
    finding = _finding("sqli")
    state = _state(finding)
    monkeypatch.setattr(
        "webpent.agents.payload_generator.agent.try_get_llm",
        lambda task: None,
    )
    update = payload_generator_node(state)
    assert str(finding.id) in update["payloads_to_test"]

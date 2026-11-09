# src/webpent/agents/devils_advocate/agent.py
"""webpent.agents.devils_advocate.agent

V5 Sprint 10 — Devil's Advocate Node.

A secondary LLM pass that attempts to debunk each finding before it is
finalized as ``"AI-Assessed"`` or ``"Tool-Confirmed"``. The node prompts
the LLM to assume the role of a skeptical defender and produce the
strongest technical argument against the finding's validity.

If the LLM generates a high-confidence counter-argument (verdict
``DEBUNKED``), the finding is downgraded to ``"Needs Human Review"``
with the counter-argument appended to the ``reasoning`` field. This
prevents over-confident LLM assessments from propagating false positives
into the final report.

Integration:
    Inserted between ``NODE_VALIDATOR`` and ``NODE_CVSS_ENGINE`` in the
    LangGraph state machine. Runs on every finding regardless of
    confidence level — even ``"Tool-Confirmed"`` findings get a
    devil's-advocate pass, because tool output can be misleading (e.g.
    dalfox false positives on reflected content that is not actually
    executable).
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from webpent.models.findings import Finding
from webpent.models.postmortem import PostmortemCategory
from webpent.shared.grounding import verify_all_citations
from webpent.shared.llm import (
    TaskType,
    get_safety_system_instruction,
    safe_prompt_format,
    try_get_llm,
)
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a skeptical security defender acting as a Devil's Advocate. "
    "Your job is to challenge the validity of a vulnerability finding by "
    "constructing the strongest possible technical argument that it is a "
    "FALSE POSITIVE.\n\n"
    "Consider: WAF blocking, input validation, output encoding, "
    "content-type mismatches, CSP headers, SameSite cookies, "
    "context-dependent execution (JSON vs HTML vs attribute), "
    "authentication requirements, error handling that prevents "
    "exploitation, and tool false-positive patterns.\n\n"
    "Respond in EXACTLY this format:\n"
    "VERDICT: DEBUNKED | PLAUSIBLE\n"
    "CONFIDENCE: HIGH | MEDIUM | LOW\n"
    "ARGUMENT: <one-paragraph technical argument>\n"
    "Do not include any other text."
)

_HUMAN_TEMPLATE = (
    "Finding title: {title}\n"
    "Vulnerability class: {vuln_class}\n"
    "Severity: {severity}\n"
    "URL: {url}\n"
    "Description: {description}\n"
    "Current confidence level: {confidence_level}\n"
    "Payload used: {payload}\n"
    "Existing reasoning: {reasoning}\n\n"
    "Assume this finding is a FALSE POSITIVE. Provide the strongest "
    "technical argument against it."
)

# V5 Sprint 10: Only HIGH-confidence debunking triggers a downgrade.
# MEDIUM/LOW counter-arguments are recorded in the reasoning trail but
# do not override the validator's verdict — the goal is to catch clear
# false positives, not to paralyze the pipeline with skepticism.
_DEBUNK_DOWNGRADE_THRESHOLD = "HIGH"

# V10 P1-2 FIX: HARD CAP on downgrades per Devil's Advocate pass.
# Without a cap, a mis-calibrated LLM (or a prompt-injected context)
# can mass-downgrade an entire engagement's findings to "Needs Human
# Review" in a single pass — destroying confirmed-signal coverage and
# forcing the operator to manually re-promote every finding. The cap
# bounds the blast radius: at most ``_MAX_DOWNGRADES_PER_PASS``
# findings may be downgraded per pass; the LLM's counter-arguments for
# any further findings are still appended to the reasoning trail (so
# the operator sees them) but the ``confidence_level`` is NOT changed.
_MAX_DOWNGRADES_PER_PASS = 5


def _parse_devils_advocate_response(
    response_text: str,
) -> tuple[str, str, str]:
    """Parse the LLM's structured response into (verdict, confidence, argument).

    Expected format::
        VERDICT: DEBUNKED
        CONFIDENCE: HIGH
        ARGUMENT: <text>

    Returns:
        A tuple of ``(verdict, confidence, argument)``. Any field that
        cannot be parsed defaults to an empty string (verdict/confidence)
        or the raw response (argument).
    """
    verdict = ""
    confidence = ""
    argument = ""

    for line in response_text.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("VERDICT:"):
            verdict = stripped[len("VERDICT:"):].strip().upper()
        elif stripped.upper().startswith("CONFIDENCE:"):
            confidence = stripped[len("CONFIDENCE:"):].strip().upper()
        elif stripped.upper().startswith("ARGUMENT:"):
            argument = stripped[len("ARGUMENT:"):].strip()

    # If the argument field was multi-line, capture the rest of the
    # response after the ARGUMENT: prefix.
    if not argument and response_text:
        argument = response_text.strip()

    return verdict, confidence, argument


def _should_downgrade(verdict: str, confidence: str) -> bool:
    """Determine whether the Devil's Advocate response warrants a downgrade.

    V5 Sprint 10: A finding is downgraded to ``"Needs Human Review"``
    only when the LLM produces a HIGH-confidence DEBUNKED verdict.
    MEDIUM/LOW confidence counter-arguments are recorded in the
    reasoning trail but do not override the validator's verdict.
    """
    return (
        verdict == "DEBUNKED"
        and confidence == _DEBUNK_DOWNGRADE_THRESHOLD
    )


def _is_tool_backed(finding: Finding) -> bool:
    """Authority law guard (R-C-1 fix): is this finding sealed tool evidence?

    A finding is tool-backed when it carries the validator's
    Tool-Confirmed label OR deterministic tool confirmation evidence
    (``validator_tool`` + ``deterministic_marker``).  Per the project
    authority law (LLM-only verdicts can neither confirm nor refute
    causal, tool-gated evidence — see replay_validator / Phase 10 locks
    / P1C refutation lifecycle), an ungrounded LLM-only Devil's
    Advocate opinion must not DEMOTE such evidence either.  The
    skeptic's counter-argument is still appended to the reasoning
    trail for operator visibility — it just cannot silently outrank a
    sealed tool artifact.
    """
    if finding.confidence_level == "Tool-Confirmed":
        return True
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    return bool(evidence.get("deterministic_marker")) and bool(
        evidence.get("validator_tool")
    )


def _devils_advocate_finding(
    finding: Finding,
    llm: Any,
    *,
    allow_downgrade: bool = True,
) -> Finding:
    """Run the Devil's Advocate LLM pass on a single finding.

    Returns the finding unchanged if the LLM could not produce a
    high-confidence debunk. Returns a downgraded finding (confidence_level
    = "Needs Human Review") if the LLM produced a HIGH-confidence
    DEBUNKED verdict.

    V5 Sprint 10: Also performs a Grounding Check on the LLM's
    counter-argument — if the LLM cites strings that do not appear in
    the finding's evidence_bundle.tool_output, the counter-argument is
    discarded (the Devil's Advocate hallucinated).

    V10 P1-2: ``allow_downgrade`` gates whether a HIGH-confidence
    DEBUNKED verdict actually triggers the confidence-level downgrade.
    When False (used by :func:`devils_advocate_node` after the
    ``_MAX_DOWNGRADES_PER_PASS`` cap has been reached), the
    counter-argument is still appended to ``reasoning`` (so the
    operator sees the skeptical take) but ``confidence_level`` is left
    unchanged — this bounds the blast radius of a mis-calibrated or
    prompt-injected DA pass.
    """
    if llm is None:
        # Offline deterministic mode has no semantic debunker provider.
        # Preserve validator evidence and do not manufacture a downgrade.
        return finding

    human_prompt = safe_prompt_format(
        _HUMAN_TEMPLATE,
        title=finding.title,
        vuln_class=finding.vuln_class,
        severity=finding.severity,
        url=finding.url,
        description=finding.description,
        confidence_level=finding.confidence_level,
        payload=finding.payload or "(none)",
        reasoning=finding.reasoning or "(none)",
    )

    try:
        response = llm.invoke(
            [
                SystemMessage(content=get_safety_system_instruction()),
                SystemMessage(content=_SYSTEM_PROMPT),
                HumanMessage(content=human_prompt),
            ]
        )
        raw: str = (
            response.content
            if isinstance(response.content, str)
            else str(response.content)
        )
    except Exception as exc:  # noqa: BLE001 — LLM failures must not abort the graph
        logger.warning(
            "Devil's Advocate LLM failed for finding %s: %s",
            finding.id, exc,
        )
        return finding

    verdict, confidence, argument = _parse_devils_advocate_response(raw)

    if not verdict:
        logger.debug(
            "Devil's Advocate: could not parse verdict for finding %s "
            "(raw: %s)", finding.id, raw[:100],
        )
        return finding

    # V5 Sprint 10: Grounding Check on the counter-argument. If the
    # LLM cited strings not present in the tool output, discard the
    # debunk (the Devil's Advocate hallucinated).
    tool_output = ""
    if finding.evidence_bundle and isinstance(finding.evidence_bundle, dict):
        tool_output = str(finding.evidence_bundle.get("tool_output") or "")
    if tool_output and argument:
        all_grounded, hallucinated, _quote_count = verify_all_citations(
            argument, tool_output
        )
        if not all_grounded:
            logger.info(
                "Devil's Advocate counter-argument for finding %s "
                "DISCARDED — hallucinated %d citation(s): %s",
                finding.id, len(hallucinated),
                [h[:50] for h in hallucinated[:2]],
            )
            return finding

    # Append the Devil's Advocate assessment to the reasoning trail
    # regardless of the verdict — the operator should see the
    # counter-argument even if it didn't trigger a downgrade.
    da_note = (
        f"\n\nDevil's Advocate Assessment: verdict={verdict}, "
        f"confidence={confidence}. Argument: {argument}"
    )
    updated_reasoning = (finding.reasoning or "") + da_note

    if _should_downgrade(verdict, confidence) and allow_downgrade:
        if _is_tool_backed(finding):
            # R-C-1 authority law: an LLM-only debunk cannot demote
            # sealed tool evidence (real binary + deterministic marker
            # + supervisor + strict verifier + ProofBundle).  The
            # counter-argument is preserved in the reasoning trail so
            # the operator sees the skeptical take.
            logger.info(
                "Devil's Advocate DEBUNKED verdict for TOOL-BACKED "
                "finding %s (%s) recorded as counter-argument only — "
                "LLM-only verdicts cannot demote sealed tool evidence.",
                finding.id,
                finding.title,
            )
            return finding.model_copy(
                update={"reasoning": updated_reasoning}
            )
        logger.info(
            "Devil's Advocate DOWNGRADED finding %s (%s) from %s to "
            "Needs Human Review — HIGH-confidence DEBUNKED verdict",
            finding.id, finding.title, finding.confidence_level,
        )
        return finding.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "reasoning": updated_reasoning,
            }
        )

    if _should_downgrade(verdict, confidence) and not allow_downgrade:
        # V10 P1-2: cap reached — record the skeptical counter-argument
        # in the reasoning trail but do NOT downgrade confidence_level.
        logger.warning(
            "Devil's Advocate HIGH-confidence DEBUNKED verdict for "
            "finding %s (%s) NOT applied — downgrade cap "
            "_MAX_DOWNGRADES_PER_PASS=%d has been reached this pass. "
            "Counter-argument recorded in reasoning; confidence_level "
            "left unchanged at %s.",
            finding.id, finding.title,
            _MAX_DOWNGRADES_PER_PASS, finding.confidence_level,
        )
        return finding.model_copy(
            update={"reasoning": updated_reasoning}
        )

    logger.debug(
        "Devil's Advocate did NOT downgrade finding %s (verdict=%s, "
        "confidence=%s)", finding.id, verdict, confidence,
    )
    return finding.model_copy(
        update={"reasoning": updated_reasoning}
    )


def _record_devils_advocate_postmortem(
    finding: Finding,
    *,
    thread_id: str | None,
) -> None:
    """Best-effort Postmortem record for a Devil's Advocate downgrade.

    Project Zero-tier item 6: a finding that was raised with enough
    confidence to reach the Devil's Advocate pass, and was then
    downgraded on a HIGH-confidence DEBUNKED verdict, is exactly the
    "false positive caught before publication" case item 6 asks to be
    recorded in a fixed, aggregable shape — not just appended to the
    finding's own ``reasoning`` trail.

    Deliberately defensive: a Postmortem write must never itself cause
    the Devil's Advocate node (or the graph) to fail. Any exception is
    logged and swallowed.
    """
    try:
        from webpent.memory.postmortem import get_postmortem_manager

        manager = get_postmortem_manager()
        reasoning_tail = (finding.reasoning or "")[-500:]
        manager.record_false_positive(
            category=PostmortemCategory.LLM_HALLUCINATION,
            root_cause_detail=(
                "Devil's Advocate HIGH-confidence DEBUNKED verdict on "
                f"finding '{finding.title}' ({finding.vuln_class}). "
                f"Counter-argument tail: {reasoning_tail}"
            ),
            proposed_fix=(
                "Review whether the originating detector/tool "
                f"('{finding.tool_name}') needs a stricter confirmation "
                "check for this vulnerability class, or whether the "
                "Devil's Advocate verdict itself was the miscalibrated "
                "party (see grounding-check pass rate for this run)."
            ),
            finding_id=finding.id,
            vuln_class=str(finding.vuln_class)
            if finding.vuln_class is not None
            else None,
            campaign_id=finding.campaign_id,
            thread_id=thread_id,
            detector_name="devils_advocate",
            metadata={"original_confidence_level": finding.confidence_level},
        )
    except Exception as exc:  # noqa: BLE001 — postmortem writes must not break DA
        logger.warning(
            "Devil's Advocate: postmortem record for finding %s failed: %s",
            finding.id, exc,
        )


def _pz_run_red_vs_blue_selfcheck(*, thread_id: str | None) -> dict[str, Any] | None:
    """Project Zero-tier items 3 + 5 (2026-10-22): red-vs-blue detection
    self-check, run inside the Devil's Advocate node.

    Composes two already-built Project Zero pieces rather than adding a
    new mechanism: :mod:`webpent.shared.red_vs_blue` (the deterministic
    evasion-mutation loop, which itself composes the shadow-detector
    key-extraction from item 3) and :mod:`webpent.memory.postmortem`
    (item 6, the destination for every detected escape).

    The detector under test is :func:`webpent.production.validators.
    extract_ssrf_indicators`, the same indicator extractor used by the
    production SSRF validator — so this self-check probes the exact
    logic that guards real findings. A mutation the canonical payload
    fails to survive is recorded as a ``detection_logic_gap``
    Postmortem entry (strengthen-detection feedback), and the result is
    returned as an ADVISORY state dict only: this never touches
    findings, never promotes or downgrades anything, and never sends a
    request.

    Default-off via ``enable_red_vs_blue_selfcheck``; deliberately
    fail-soft — any failure logs and returns None so the Devil's
    Advocate node behaves exactly as before.
    """
    try:
        from webpent.config.settings import get_settings
        from webpent.production.validators import extract_ssrf_indicators
        from webpent.shared.red_vs_blue import (
            feed_escapes_to_postmortem,
            run_red_vs_blue,
        )

        settings = get_settings()
        if not bool(getattr(settings, "enable_red_vs_blue_selfcheck", False)):
            return None

        # Canonical seed the detector is known to flag: a cloud-metadata
        # SSRF probe. Used only in-process to drive mutation and
        # detection; never stored (feed_escapes_to_postmortem strips it).
        report = run_red_vs_blue(
            seed_payload=(
                "http://169.254.169.254/latest/meta-data/iam/"
                "security-credentials/"
            ),
            seed_payload_label="da_selfcheck_cloud_metadata_ssrf",
            detector=extract_ssrf_indicators,
        )
        escaped = report.escaped_techniques
        feed_escapes_to_postmortem(
            report,
            vuln_class="ssrf",
            detector_name="extract_ssrf_indicators",
            thread_id=thread_id,
        )
        summary = report.as_dict()
        result: dict[str, Any] = {
            "detector": "extract_ssrf_indicators",
            "vuln_class": "ssrf",
            "techniques_tested": summary.get("total_techniques_tried"),
            "escapes": [a.technique for a in escaped],
        }
        if result["escapes"]:
            logger.warning(
                "Red-vs-blue self-check: %d evasion technique(s) escaped "
                "extract_ssrf_indicators (%s); recorded as "
                "detection_logic_gap postmortem entries.",
                len(result["escapes"]),
                ", ".join(result["escapes"]),
            )
        else:
            logger.info(
                "Red-vs-blue self-check: no escapes; detector held all %s "
                "technique(s).", result["techniques_tested"],
            )
        return result
    except Exception as exc:  # noqa: BLE001 — PZ self-check must degrade safely
        logger.warning("Red-vs-blue self-check skipped safely: %s", exc)
        return None


def devils_advocate_node(state: PentestState) -> dict:
    """LangGraph node implementing the Devil's Advocate secondary LLM pass.

    V5 Sprint 10: Runs after the validator and before the CVSS engine.
    For each finding, asks a second LLM to construct the strongest
    counter-argument against the finding's validity. Findings that
    receive a HIGH-confidence DEBUNKED verdict are downgraded to
    ``"Needs Human Review"``.

    The node is resilient: LLM failures on individual findings do not
    abort the graph. Findings that fail the Devil's Advocate pass are
    returned unchanged (the validator's original verdict stands).
    """
    findings: list[Finding] = list(state.get("findings") or [])

    logger.info(
        "Devil's Advocate node starting: %d finding(s) to challenge",
        len(findings),
    )

    if not findings:
        return {
            "messages": [
                AIMessage(content="Devil's Advocate: no findings to challenge.")
            ],
            "current_phase": "devils_advocate",
        }

    llm = try_get_llm(TaskType.ANALYSIS)
    findings_by_id: dict[UUID, Finding] = {f.id: f for f in findings}

    # V10 P1-2: read thread_id from state so we can incrementally persist
    # any downgrades via the validator's helper. The worker stamps
    # thread_id on state at scan start (see PentestState thread_id field).
    thread_id: str | None = state.get("thread_id")
    # Lazy import to avoid a hard cross-agent dependency at module load
    # (validator agent is heavy — pulls in the entire tool registry).
    try:
        from webpent.agents.validator.agent import (
            _persist_finding_incrementally,
        )
    except Exception:  # noqa: BLE001 — keep DA resilient to import failures
        _persist_finding_incrementally = None  # type: ignore[assignment]
        logger.warning(
            "Devil's Advocate: could not import "
            "_persist_finding_incrementally from validator agent — "
            "downgrades will NOT be incrementally persisted (the final "
            "graph-state persist still applies).",
        )

    debunked_count = 0
    challenged_count = 0
    downgrades_this_pass = 0
    revalidation_count = int(state.get("devils_advocate_revalidation_count") or 0)
    revalidation_ids: list[str] = []

    for finding in findings:
        # V10 P1-2: cap downgrades per pass to bound the blast radius of
        # a mis-calibrated or prompt-injected DA LLM. Findings past the
        # cap still get their counter-argument appended to reasoning,
        # but their confidence_level is NOT changed.
        allow_downgrade = downgrades_this_pass < _MAX_DOWNGRADES_PER_PASS
        try:
            updated = _devils_advocate_finding(
                finding, llm, allow_downgrade=allow_downgrade
            )
            challenged_count += 1
            # A "fresh" downgrade is one where the confidence_level
            # actually changed TO "Needs Human Review" as a result of
            # this pass (the finding wasn't already at that level).
            if (
                updated.confidence_level == "Needs Human Review"
                and finding.confidence_level != "Needs Human Review"
            ):
                debunked_count += 1
                downgrades_this_pass += 1
                # Project Zero-tier item 6: record a structured
                # Postmortem for every fresh false-positive downgrade,
                # independent of and in addition to incremental persist
                # below (see _record_devils_advocate_postmortem).
                _record_devils_advocate_postmortem(
                    updated, thread_id=thread_id
                )
                # V10 P1-2: persist the downgrade immediately so the
                # DB-backed API (/findings) reflects the new
                # confidence_level even if the graph is interrupted
                # before the final state persist.
                if _persist_finding_incrementally is not None:
                    try:
                        _persist_finding_incrementally(
                            updated, thread_id=thread_id
                        )
                    except Exception as persist_exc:  # noqa: BLE001
                        logger.warning(
                            "Devil's Advocate: incremental persist of "
                            "downgraded finding %s failed: %s (the final "
                            "graph-state persist will retry).",
                            finding.id, persist_exc,
                        )
                # Phase 5.2: a fresh high-confidence rejection is a hard
                # gate, not a terminal advisory downgrade. Re-open the
                # finding exactly once for deterministic validator review.
                if revalidation_count == 0:
                    updated = updated.model_copy(
                        update={
                            "confidence_level": "Pending",
                            "evidence": {
                                **(updated.evidence or {}),
                                "devils_advocate_gate": "rejected",
                                "devils_advocate_revalidation_required": True,
                                "devils_advocate_revalidation_reason": (
                                    "High-confidence DEBUNKED verdict; returned "
                                    "to validator for one bounded revalidation"
                                ),
                            },
                        }
                    )
                    revalidation_ids.append(str(finding.id))
                findings_by_id[finding.id] = updated

        except Exception as exc:  # noqa: BLE001 — per-finding resilience
            logger.warning(
                "Devil's Advocate failed for finding %s: %s",
                finding.id, exc,
            )

    if downgrades_this_pass >= _MAX_DOWNGRADES_PER_PASS:
        logger.warning(
            "Devil's Advocate: downgrade cap "
            "_MAX_DOWNGRADES_PER_PASS=%d REACHED this pass — additional "
            "HIGH-confidence DEBUNKED verdicts had their counter-arguments "
            "recorded in reasoning but did NOT trigger a confidence_level "
            "downgrade. Review the reasoning trails of the remaining "
            "findings manually.",
            _MAX_DOWNGRADES_PER_PASS,
        )

    updated_findings: list[Finding] = [
        findings_by_id[f.id] for f in findings if f.id in findings_by_id
    ]

    # Project Zero production wiring (2026-10-22) — items 3 + 5: a
    # red-vs-blue self-check of the production SSRF indicator detector,
    # with escapes fed back into the Postmortem store. Advisory-only and
    # default-off; a result is attached to state, findings untouched.
    red_vs_blue_selfcheck: dict[str, Any] | None = None
    try:
        red_vs_blue_selfcheck = _pz_run_red_vs_blue_selfcheck(
            thread_id=thread_id
        )
    except Exception as exc:  # noqa: BLE001 — PZ wiring must degrade safely
        logger.warning("Red-vs-blue self-check wiring skipped safely: %s", exc)

    summary = (
        f"Devil's Advocate completed. Challenged {challenged_count} "
        f"finding(s); {debunked_count} downgraded to Needs Human Review."
    )
    logger.info(summary)

    update: dict[str, Any] = {
        "findings": updated_findings,
        "messages": [AIMessage(content=summary)],
        "current_phase": "devils_advocate",
        "devils_advocate_gate_active": bool(revalidation_ids),
        **(
            {
                "devils_advocate_revalidation_count": revalidation_count + 1,
                "devils_advocate_revalidation_ids": revalidation_ids,
            }
            if revalidation_ids
            else {}
        ),
    }
    if red_vs_blue_selfcheck is not None:
        update["red_vs_blue_selfcheck"] = red_vs_blue_selfcheck
    return update

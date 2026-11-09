# src/webpent/agents/payload_optimizer/agent.py
"""webpent.agents.payload_optimizer.agent

LangGraph node that generates WAF-bypass payloads for unconfirmed
findings and feeds them back into the Execution Sandbox.

Phase 2 introduces a self-healing loop:

    payload_generator -> execution_sandbox -> validator
        -> [if unconfirmed & retries < 3] -> payload_optimizer
        -> execution_sandbox (retry with obfuscated payloads)
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from webpent.models.findings import (
    EXPLOITABLE_CLASSES,
    Confidence,
    Finding,
    Severity,
)
from webpent.shared.llm import (
    TaskType,
    get_safety_system_instruction,
    safe_prompt_format,
    try_get_llm,
)
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are an expert Exploit Developer specialising in WAF bypass. "
    "Given a vulnerability description, a URL, and a list of payloads "
    "that FAILED to bypass the WAF, generate exactly 3 new payloads "
    "that use aggressive obfuscation/encoding to evade detection. "
    "Use techniques such as: Hex encoding, Unicode escaping, HTML "
    "entities, JSFuck, double-encoding, case variation, and comment "
    "breaking. Output ONLY the payloads, one per line. No markdown, "
    "no explanations."
)

_HUMAN_TEMPLATE = (
    "Vulnerability title: {title}\n"
    "Severity: {severity}\n"
    "Affected URL: {url}\n"
    "Description: {description}\n\n"
    "Failed payloads:\n{failed_payloads}\n\n"
    "Generate exactly 3 new, highly obfuscated WAF-bypass payloads."
)

# V8 P0 C3: Strategy-specific system prompts keyed by validator failure reason.
# The validator records evidence["validation_failure_reason"] = one of these
# keys (see agents/validator/agent.py:_classify_validator_failure). The
# optimizer picks the matching strategy prompt to focus the LLM on the
# specific bypass technique that addresses the actual failure mode, instead
# of always using the generic "WAF bypass" prompt.
#
# Closed set — adding a new reason requires:
#   1. Adding the reason string to _classify_validator_failure in validator.
#   2. Adding a matching strategy prompt here.
# This keeps the failure-reason vocabulary auditable and bounded.
_FAILURE_STRATEGY_PROMPTS: dict[str, str] = {
    # Default / unknown failure: the existing generic WAF-bypass prompt.
    # Used when the validator didn't record a reason (e.g. older findings
    # from before V8 P0 C3) or when the reason is "tool_no_marker".
    "tool_no_marker": _SYSTEM_PROMPT,

    # WAF block detected: focus on encoding/obfuscation techniques that
    # defeat signature-based WAFs (ModSecurity, Cloudflare, Imperva, etc.).
    "waf_blocked": (
        "You are an expert Exploit Developer. The target's WAF has "
        "BLOCKED the previous payloads (HTTP 403 or WAF signature "
        "detected). Generate exactly 3 new payloads that use AGGRESSIVE "
        "multi-layer obfuscation to evade signature detection: "
        "double-URL-encoding, Unicode normalization tricks, HTML "
        "entity encoding, mixed-case keyword splitting (e.g. "
        "<ScRiPt>), comment-breaking inside keywords, and base64-"
        "wrapped payloads where applicable. Avoid any token that "
        "appears literally in the failed payloads — the WAF has "
        "likely fingerprinted them. Output ONLY the payloads, one "
        "per line. No markdown, no explanations."
    ),

    # Auth required: the target redirected to a login page. NO payload
    # obfuscation can fix this — the finding needs authenticated session
    # cookies, not a different payload. The optimizer should skip these
    # findings entirely (handled in _is_actionable_and_unconfirmed), but
    # if reached, the prompt tells the LLM not to retry.
    "auth_required": (
        "You are an expert Exploit Developer. The target redirected "
        "the previous payloads to a LOGIN PAGE — the vulnerability "
        "appears to require authenticated session cookies, not a "
        "different payload. Do NOT generate obfuscated variants of "
        "the failed payloads. Instead, output exactly 3 payloads that "
        "test for auth-bypass / IDOR / unauthenticated-access variants "
        "(e.g. path traversal to reach the endpoint without login, "
        "HTTP method override, host-header injection). Output ONLY "
        "the payloads, one per line. No markdown, no explanations."
    ),

    # LLM rejected: the deterministic tool found its marker, but the LLM
    # supervisor said the finding is a false positive. Retrying with
    # obfuscation won't help — the LLM already saw the marker and
    # rejected it. The optimizer should skip these (handled in
    # _is_actionable_and_unconfirmed), but if reached, the prompt asks
    # for alternative attack vectors rather than obfuscation.
    "llm_rejected": (
        "You are an expert Exploit Developer. The previous payloads "
        "triggered the tool's success marker, but an LLM supervisor "
        "REJECTED them as false positives. Do NOT generate more "
        "obfuscated variants of the same payload class — the LLM has "
        "already seen and rejected them. Instead, output exactly 3 "
        "payloads that use a DIFFERENT attack vector for the same "
        "vulnerability class (e.g. if the failed payloads were "
        "reflected-XSS, try DOM-based or stored variants; if they "
        "were error-based SQLi, try blind/time-based). Output ONLY "
        "the payloads, one per line. No markdown, no explanations."
    ),
}

_MAX_RETRIES = 3


def optimization_attempt_fingerprint(
    finding: Finding | dict[str, Any], payloads: list[str] | None,
) -> str:
    """Return a stable, redaction-safe fingerprint for one optimizer state.

    The material is hashed and never returned or logged. Query values, payload
    bodies, request data, cookies, and evidence bodies are not persisted; only
    query parameter names and a small allow-list of validation status fields
    participate in the digest. This lets the graph distinguish real progress
    from a retry that repeats the same finding/payload/evidence state.
    """
    def _get(key: str, default: Any = None) -> Any:
        if isinstance(finding, dict):
            return finding.get(key, default)
        return getattr(finding, key, default)

    raw_url = str(_get("url", ""))
    parsed = urlsplit(raw_url)
    query_names = sorted(
        {key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    )
    try:
        hostname = parsed.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        safe_netloc = hostname.lower()
        if parsed.port is not None:
            safe_netloc = f"{safe_netloc}:{parsed.port}"
    except ValueError:
        # Malformed port/userinfo must not leak through the fallback shape.
        safe_netloc = parsed.netloc.rsplit("@", 1)[-1].lower()
    target_shape = urlunsplit((
        parsed.scheme.lower(), safe_netloc, parsed.path or "/", "", ""
    ))
    evidence = _get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}
    status = {
        key: evidence.get(key)
        for key in (
            "validation_failure_reason",
            "validation_unavailable",
            "tool_infra_failure",
            "causal_signal",
            "negative_control_complete",
            "promotion_guard",
        )
        if key in evidence
    }
    promotion_guard = status.get("promotion_guard")
    if isinstance(promotion_guard, dict):
        status["promotion_guard"] = promotion_guard.get("status")
    material = {
        "finding_id": str(_get("id", "")),
        "vuln_class": str(_get("vuln_class", "")),
        "target_shape": target_shape,
        "query_names": query_names,
        "target_param": str(_get("target_param", "") or ""),
        "request_method": str(_get("request_method", "GET") or "GET").upper(),
        "payloads": sorted({str(item) for item in (payloads or [])}),
        "confidence": str(_get("confidence", "")),
        "confidence_level": str(_get("confidence_level", "")),
        "validation_status": status,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


# V3.5 Obsidian Master: Import from central location (models/findings.py).
_EXPLOITABLE_CLASSES = EXPLOITABLE_CLASSES

_MIN_SEVERITY_VALUE = Severity.MEDIUM.value
_SEVERITY_RANKS: dict[str, int] = {
    Severity.INFO.value: 0, Severity.LOW.value: 1, Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3, Severity.CRITICAL.value: 4,
}


def _is_exploitable(finding: Finding) -> bool:
    """Return True if ``finding.vuln_class`` is in the exploitable set.

    V3.5: Replaces fragile keyword matching on titles/descriptions with
    a deterministic check on the ``vuln_class`` enum field.
    """
    return finding.vuln_class in _EXPLOITABLE_CLASSES


def _meets_severity_threshold(finding: Finding) -> bool:
    rank = _SEVERITY_RANKS.get(str(finding.severity), 0)
    return rank >= _SEVERITY_RANKS[_MIN_SEVERITY_VALUE]


def _is_actionable_and_unconfirmed(finding: Finding) -> bool:
    if not _meets_severity_threshold(finding):
        return False
    if not _is_exploitable(finding):
        return False
    # V7 Ready-For-Kali P0 FIX (confirmed via a real production
    # GraphRecursionError): validator marks
    # evidence["tool_infra_failure"]=True when the confirmation TOOL
    # itself failed to run (crashed, not installed, unexpected error)
    # rather than the payload failing to bypass a WAF — see
    # agents/validator/agent.py's ToolExecutionError handling. Payload
    # re-generation cannot fix a crashing binary, so these findings are
    # explicitly excluded here instead of being retried forever.
    if finding.evidence and finding.evidence.get("tool_infra_failure"):
        return False
    # V8 P0 C3: also skip findings whose validator failure reason is
    # NOT addressable by payload re-generation:
    #   - "auth_required" — the target redirected to login. No payload
    #     obfuscation can fix this; the finding needs authenticated
    #     session cookies. Retrying wastes an LLM call and a retry slot.
    #   - "llm_rejected" — the LLM supervisor already saw the marker
    #     and rejected it as a false positive. More obfuscation of the
    #     same payload class won't change the LLM's verdict.
    # Both are still eligible for human review (their confidence_level
    # is "Needs Human Review" or "Pending"), just not for automated
    # payload optimization.
    if finding.evidence:
        failure_reason = finding.evidence.get("validation_failure_reason")
        if failure_reason in ("auth_required", "llm_rejected"):
            return False
    return finding.confidence != Confidence.CONFIRMED.value


def _parse_payloads(raw_response: str) -> list[str]:
    lines: list[str] = []
    for line in raw_response.splitlines():
        cleaned = line.strip().strip("`").strip()
        if cleaned.startswith(("-", "*", "•")):
            cleaned = cleaned[1:].strip()
        if len(cleaned) > 2 and cleaned[0].isdigit() and cleaned[1] == ".":
            cleaned = cleaned[2:].strip()
        if cleaned:
            lines.append(cleaned)
    return lines[:3]


def _generate_optimized_payloads(
    finding: Finding, failed_payloads: list[str], llm: Any
) -> list[str]:
    if llm is None:
        logger.info(
            "LLM disabled/unavailable for payload optimization (finding=%s); "
            "no optimized payloads generated",
            finding.id,
        )
        return []

    # V8 P0 C3: pick a strategy-specific system prompt based on the
    # validator's recorded failure reason. Falls back to the generic
    # _SYSTEM_PROMPT (the original WAF-bypass prompt) when no reason
    # is recorded or the reason is "tool_no_marker" — preserving the
    # V7 behavior as the default.
    failure_reason = ""
    if finding.evidence:
        failure_reason = str(finding.evidence.get("validation_failure_reason") or "")
    system_prompt = _FAILURE_STRATEGY_PROMPTS.get(failure_reason, _SYSTEM_PROMPT)

    # V8 P0 C3: include the failure reason in the human prompt so the
    # LLM knows WHY the previous payloads failed (not just that they
    # failed). This is the concrete failure signal the C3 plan calls
    # for — the LLM can now reason about "WAF blocked my last 3
    # payloads" vs "my last 3 payloads didn't reflect" vs "the LLM
    # supervisor rejected my last 3 payloads as false positives".
    failure_reason_text = (
        f"Validator failure reason: {failure_reason}\n"
        if failure_reason
        else "Validator failure reason: (not recorded — assume generic WAF block)\n"
    )
    human_prompt = safe_prompt_format(
        _HUMAN_TEMPLATE,
        title=finding.title, severity=finding.severity, url=finding.url,
        description=finding.description,
        failed_payloads="\n".join(f"  - {p}" for p in failed_payloads) or "  (none)",
    )
    # Splice the failure-reason line into the human prompt, right
    # before the "Failed payloads:" section, so the LLM sees the
    # reason first and the failed payloads second.
    human_prompt = human_prompt.replace(
        "Failed payloads:",
        f"{failure_reason_text}Failed payloads:",
    )

    try:
        response = llm.invoke(
            [
                SystemMessage(content=get_safety_system_instruction()),
                SystemMessage(content=system_prompt),
                HumanMessage(content=human_prompt),
            ]
        )
        raw_text: str = (
            response.content if isinstance(response.content, str)
            else str(response.content)
        )
    except Exception as exc:
        logger.error("LLM failed for payload optimizer (finding=%s): %s", finding.id, exc)
        return []
    return _parse_payloads(raw_text)


def payload_optimizer_node(state: PentestState) -> dict:
    """LangGraph node implementing the payload-optimization phase."""
    findings: list[Finding] = list(state.get("findings") or [])
    payloads_to_test: dict[str, list[str]] = dict(state.get("payloads_to_test") or {})
    retries: dict[str, int] = dict(state.get("optimization_retries") or {})
    logger.info("Payload optimizer starting: %d total finding(s)", len(findings))

    llm = try_get_llm(TaskType.CODE)

    new_payloads: dict[str, list[str]] = {}
    updated_retries: dict[str, int] = {}
    updated_attempt_fingerprints: dict[str, str] = {}
    requeued_findings: list[Finding] = []
    optimized_count = 0
    skipped_count = 0

    for finding in findings:
        fid = str(finding.id)
        if not _is_actionable_and_unconfirmed(finding):
            continue
        if fid not in payloads_to_test:
            continue

        current_retry = retries.get(fid, 0)
        if current_retry >= _MAX_RETRIES:
            skipped_count += 1
            logger.info("Finding %s hit retry cap (%d) — skipping", fid, current_retry)
            continue

        failed = payloads_to_test.get(fid, [])
        if not failed:
            # The key may survive a reducer merge even when generation or a
            # browser-only pass produced no payloads. There is no meaningful
            # retry to perform, so close this candidate for this pass.
            updated_retries[fid] = _MAX_RETRIES
            skipped_count += 1
            logger.info(
                "Finding %s has no actionable payloads — skipping optimizer",
                fid,
            )
            continue

        # V10 HOSTILE P2-2 FIX: skip the SQLi synthetic marker. The
        # payload_generator injects "__SQLMAP_TOOL_DRIVEN__" into
        # payloads_to_test for SQLi findings so _has_payloads returns
        # True and execution_sandbox does not skip. But this marker is
        # NOT a real payload — it's a placeholder. The optimizer must
        # NOT try to LLM-optimize it. sqlmap generates its own payloads
        # internally; the validator calls run_sqlmap regardless. Skip
        # the marker and let the validator's deterministic check handle
        # confirmation. Without this skip, the optimizer wastes an LLM
        # call trying to "improve" a sentinel string.
        _sqli_synthetic_marker = "__SQLMAP_TOOL_DRIVEN__"
        if (
            len(failed) == 1
            and failed[0] == _sqli_synthetic_marker
        ):
            skipped_count += 1
            logger.info(
                "Finding %s has SQLi synthetic marker — skipping "
                "optimization (sqlmap generates its own payloads).",
                fid,
            )
            continue

        current_fingerprint = optimization_attempt_fingerprint(finding, failed)
        updated_attempt_fingerprints[fid] = current_fingerprint
        new_pl = _generate_optimized_payloads(finding, failed, llm)

        # V3.5 Fix: Always increment the retry counter, even if the LLM
        # returns an empty list or parsing fails. This prevents an infinite
        # loop where a persistently-failing LLM never increments the
        # counter, causing the validator to route back to the optimizer
        # indefinitely.
        updated_retries[fid] = current_retry + 1

        if new_pl:
            new_payloads[fid] = new_pl
            # Explicitly reopen only this finding for the next validator
            # pass. validator_node uses this marker to distinguish a real
            # optimizer retry from a later chain/rabbit-hole re-entry, which
            # otherwise carries the complete findings list.
            requeued_findings.append(finding.model_copy(update={
                "evidence": {
                    **(finding.evidence or {}),
                    "validation_requeue": True,
                },
            }))
            optimized_count += 1
            logger.info(
                "Optimized finding %s (retry %d -> %d): %d new payload(s)",
                fid, current_retry, current_retry + 1, len(new_pl),
            )
        else:
            logger.warning(
                "No optimized payloads generated for finding %s "
                "(retry %d -> %d incremented to prevent infinite loop)",
                fid, current_retry, current_retry + 1,
            )

    summary = (
        f"Payload optimization completed. Optimized {optimized_count} "
        f"finding(s); skipped {skipped_count} at retry cap."
    )
    logger.info(summary)

    result: dict[str, Any] = {
        "payloads_to_test": new_payloads,
        "optimization_retries": updated_retries,
        "optimization_attempt_fingerprints": updated_attempt_fingerprints,
        "messages": [AIMessage(content=summary)],
        "current_phase": "payload_optimization",
    }
    if requeued_findings:
        result["findings"] = requeued_findings
    return result

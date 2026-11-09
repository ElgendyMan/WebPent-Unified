"""Bounded, evidence-preserving ensemble review for high-risk findings."""
from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping
from typing import Any

from webpent.models.findings import Finding, Severity
from webpent.shared.llm import TaskType, get_independent_llm

logger = logging.getLogger(__name__)
_MAX_RESPONSE_CHARS = 2_000


def _field(finding: Any, name: str, default: Any = None) -> Any:
    if isinstance(finding, Mapping):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _invoke_review(runnable: Any, finding: Finding) -> str:
    payload = (
        finding.model_dump(mode="json")
        if hasattr(finding, "model_dump")
        else dict(finding)
    )
    prompt = (
        "You are an independent security reviewer. Review the finding below. "
        "Return exactly one JSON object with verdict 'agree' or 'disagree' "
        "and a short reason. Do not invent evidence.\n"
        f"finding={json.dumps(payload, default=str)}"
    )
    response = runnable.invoke(prompt)
    content = getattr(response, "content", response)
    if isinstance(content, list):
        content = " ".join(str(item) for item in content)
    return str(content)[:_MAX_RESPONSE_CHARS]


def _parse_signal(raw: str) -> tuple[str, str | None]:
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return "unparsed", None
    if not isinstance(data, dict):
        return "unparsed", None
    verdict = str(data.get("verdict", "")).lower().strip()
    if verdict not in {"agree", "disagree"}:
        return "unparsed", None
    reason = str(data.get("reason", ""))[:500] or None
    return verdict, reason


def apply_ensemble_review(
    findings: Iterable[Finding],
    *,
    primary_provider: str | None = None,
    get_reviewer=get_independent_llm,
) -> list[Finding]:
    """Attach an independent-provider signal to High/Critical findings.

    This function never changes categorical confidence and never creates a
    finding. If no distinct provider is configured, findings are returned
    unchanged, preserving deterministic/offline behavior.
    """
    output: list[Finding] = []
    finding_list = list(findings)
    reviewer = None
    if any(
        _field(finding, "severity") in {Severity.HIGH.value, Severity.CRITICAL.value}
        for finding in finding_list
    ):
        try:
            reviewer = get_reviewer(TaskType.ANALYSIS, exclude_provider=primary_provider)
        except Exception as exc:  # noqa: BLE001 - optional capability boundary
            logger.info("Ensemble reviewer unavailable: %s", exc)

    for finding in finding_list:
        if _field(finding, "severity") not in {Severity.HIGH.value, Severity.CRITICAL.value}:
            output.append(finding)
            continue
        if reviewer is None:
            output.append(finding)
            continue
        provider, runnable = reviewer
        try:
            raw = _invoke_review(runnable, finding)
            verdict, reason = _parse_signal(raw)
            evidence = dict(_field(finding, "evidence", {}) or {})
            review = {
                "provider": provider,
                "verdict": verdict,
                "reason": reason,
                "evidence_preserved": True,
            }
            evidence["ensemble_review"] = review
            bundle = dict(evidence.get("evidence_bundle") or {})
            bundle["ensemble_review"] = review
            evidence["evidence_bundle"] = bundle
            output.append(
                finding.model_copy(update={"evidence": evidence})
                if hasattr(finding, "model_copy")
                else {**dict(finding), "evidence": evidence}
            )
        except Exception as exc:  # noqa: BLE001 - finding-level resilience
            logger.warning(
                "Ensemble review failed for %s: %s",
                _field(finding, "id", "unknown"),
                exc,
            )
            output.append(finding)
    return output

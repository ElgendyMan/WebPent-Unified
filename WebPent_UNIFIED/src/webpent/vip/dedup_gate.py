# src/webpent/vip/dedup_gate.py
"""webpent.vip.dedup_gate — Track 11, item 5: dedup before nomination.

Roadmap contract (المسار 11، البند 5):

    منع التكرار: جعل مراجعة النتائج السابقة شرطًا قبل ترشيح finding
    للتقرير النهائي.

    ("Deduplication: make reviewing the previous findings base a
    CONDITION before a finding is nominated to the final report.")

Design
------
The gate is a LangGraph node wired between ``executive_summary`` and
``reporter`` (flag-gated via ``enable_dedup_gate``). For every finding
about to be reported it:

1. Loads the PRIOR findings base from the operational DB — the sibling
   threads of the same engagement (same client / owner), never cross-client
   (the platform privacy rule: raw data is never shared across clients).
2. Computes the stable logical fingerprint of each current finding
   (``webpent.shared.finding_aggregation.finding_fingerprint``) and
   compares it against the prior base.
3. Classifies each finding: ``new`` / ``duplicate`` (with the prior
   finding id it duplicates) / ``indeterminate``.
4. Annotates duplicates in ``evidence["dedup_review"]`` and returns a
   ``dedup_report`` summary for the state. The REPORTER — not this node —
   moves duplicates out of the main nomination table into an explicit
   appendix section, so suppression is visible and reversible by a human.

Fail-safe semantics (the plan's validator rule: on exception or missing
evidence the system never escalates silently):

* DB unreadable → status ``indeterminate``: NOTHING is suppressed, every
  finding is flagged for human review. The campaign continues.
* No engagement context → status ``clean_no_history``: nothing to compare
  against; no false suppression.
* The node NEVER deletes findings. It only annotates and reports.

Audit: the dedup report (with prior-finding references and fingerprints)
travels in state, is persisted with checkpoints, and is rendered by the
reporter, so every suppression decision is reviewable after the fact.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from webpent.models.findings import Finding
from webpent.shared.finding_aggregation import finding_fingerprint

logger = logging.getLogger(__name__)

__all__ = [
    "DedupDecision",
    "DedupRecord",
    "DedupReport",
    "classify_against_prior_base",
    "load_prior_findings",
    "split_duplicate_findings",
    "dedup_gate_node",
]


class DedupDecision(str, Enum):
    """Per-finding dedup decision vocabulary."""

    NEW = "new"
    DUPLICATE = "duplicate"
    INDETERMINATE = "indeterminate"


class DedupRecord(BaseModel):
    """One finding's dedup outcome (auditable, redaction-safe)."""

    finding_id: str
    fingerprint: str
    decision: DedupDecision
    duplicate_of: str | None = Field(
        default=None,
        description="ID of the prior finding this one duplicates, when known.",
    )
    prior_thread_id: str | None = Field(
        default=None,
        description="Thread id of the prior finding (redaction-safe context).",
    )
    note: str = ""

    model_config = {"use_enum_values": True}


class DedupReport(BaseModel):
    """Aggregate dedup-gate report persisted with the campaign state."""

    status: str = Field(
        description=(
            "'applied' (prior base reviewed), 'clean_no_history' (nothing "
            "to compare against), or 'indeterminate' (prior base unreadable "
            "— nothing suppressed, human review required)."
        ),
    )
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    engagement_id: str = ""
    reviewed: int = 0
    new_count: int = 0
    duplicate_count: int = 0
    indeterminate_count: int = 0
    prior_base_size: int = 0
    records: list[DedupRecord] = Field(default_factory=list)
    note: str = ""

    @property
    def suppressed_ids(self) -> list[str]:
        """IDs the reporter should move out of the nomination table."""
        return [
            record.finding_id
            for record in self.records
            if record.decision == DedupDecision.DUPLICATE
        ]


def load_prior_findings(
    engagement_id: str,
    *,
    owner_username: str = "",
    client_id: str = "",
    exclude_thread_ids: set[str] | frozenset[str] | None = None,
) -> tuple[list[Finding], str]:
    """Load the prior findings base for one engagement (client-isolated).

    Returns ``(prior_findings, status_note)``. Raises on DB failure so the
    caller can apply fail-safe semantics (the exception is never swallowed
    here — the gate node decides the conservative outcome).

    Isolation guarantees:

    * Only sibling threads of the SAME engagement are loaded (the
      engagement id already binds owner/client via
      ``get_thread_ids_by_engagement_id``).
    * The current run's own threads are excluded, so a finding is only a
      duplicate of something reported BEFORE this run.
    """
    from webpent.api.scan_registry import get_thread_ids_by_engagement_id
    from webpent.memory.db import get_db_manager

    threads = get_thread_ids_by_engagement_id(
        engagement_id,
        owner_username=owner_username,
        client_id=client_id,
    )
    excluded = exclude_thread_ids or frozenset()
    prior_threads = [t for t in threads if str(t) not in excluded]
    if not prior_threads:
        return [], "no prior threads for engagement"
    prior = get_db_manager().get_findings_by_threads(prior_threads)
    return prior, f"prior base: {len(prior)} findings across {len(prior_threads)} threads"


def classify_against_prior_base(
    findings: list[Finding],
    prior_findings: list[Finding],
) -> list[DedupRecord]:
    """Pure deterministic classification of findings against a prior base.

    Idempotent, side-effect free, and unit-testable without a database.
    """
    prior_index: dict[str, tuple[str, str | None]] = {}
    for prior in prior_findings:
        try:
            fp = finding_fingerprint(prior)
        except Exception:  # noqa: BLE001 — a malformed prior must not crash the gate
            logger.warning("dedup_gate: unparseable prior finding %s", getattr(prior, "id", "?"))
            continue
        # First occurrence wins (oldest prior report is the canonical one).
        prior_index.setdefault(fp, (str(prior.id), getattr(prior, "thread_id", None)))

    records: list[DedupRecord] = []
    for finding in findings:
        try:
            fp = finding_fingerprint(finding)
        except Exception as exc:  # noqa: BLE001
            records.append(
                DedupRecord(
                    finding_id=str(finding.id),
                    fingerprint="",
                    decision=DedupDecision.INDETERMINATE,
                    note=f"fingerprint error: {type(exc).__name__}",
                )
            )
            continue
        hit = prior_index.get(fp)
        if hit is None:
            records.append(
                DedupRecord(
                    finding_id=str(finding.id),
                    fingerprint=fp,
                    decision=DedupDecision.NEW,
                )
            )
        else:
            prior_id, prior_thread = hit
            if str(prior_id) == str(finding.id):
                # Same physical record re-read from history — not a duplicate.
                records.append(
                    DedupRecord(
                        finding_id=str(finding.id),
                        fingerprint=fp,
                        decision=DedupDecision.NEW,
                        note="same record as prior base entry",
                    )
                )
                continue
            records.append(
                DedupRecord(
                    finding_id=str(finding.id),
                    fingerprint=fp,
                    decision=DedupDecision.DUPLICATE,
                    duplicate_of=str(prior_id),
                    prior_thread_id=str(prior_thread) if prior_thread else None,
                    note="matches a previously reported finding (same logical identity)",
                )
            )
    return records


def annotate_finding(finding: Finding, record: DedupRecord) -> Finding:
    """Return a copy of the finding with its ``dedup_review`` evidence block.

    Additive: existing evidence keys are preserved untouched. The
    annotation is data for the reporter and the human reviewer — never an
    instruction and never a confidence change.
    """
    evidence = dict(finding.evidence) if isinstance(finding.evidence, dict) else {}
    evidence["dedup_review"] = record.model_dump(mode="json")
    return finding.model_copy(update={"evidence": evidence})


def split_duplicate_findings(
    findings: list[Finding],
) -> tuple[list[Finding], list[Finding]]:
    """Split (nominated, duplicates) using the ``dedup_review`` annotation.

    Used by the reporter. Fail-open by construction: findings without the
    annotation (gate disabled / legacy state) always stay nominated.
    """
    nominated: list[Finding] = []
    duplicates: list[Finding] = []
    for finding in findings:
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        review = evidence.get("dedup_review")
        if isinstance(review, dict) and review.get("decision") == DedupDecision.DUPLICATE.value:
            duplicates.append(finding)
        else:
            nominated.append(finding)
    return nominated, duplicates


def render_duplicates_appendix(duplicates: list[Finding]) -> str:
    """Render the report appendix section for prior-report duplicates.

    Suppression must stay visible: the appendix lists every duplicate with
    its prior-finding reference so a human can reverse any decision. Empty
    input renders an empty string (no section in the report).
    """
    if not duplicates:
        return ""
    lines = [
        "",
        "## Appendix — Duplicates of Previously Reported Findings",
        "",
        "The following findings matched the prior findings base of this "
        "engagement (dedup gate, Track 11 item 5) and were therefore NOT "
        "renominated in the main findings table. Each row keeps a reference "
        "to the previously reported record for human verification.",
        "",
        "| # | Finding ID | Class | URL | Duplicate of |",
        "|---|------------|-------|-----|--------------|",
    ]
    for index, finding in enumerate(duplicates, 1):
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        raw_review = evidence.get("dedup_review")
        review = raw_review if isinstance(raw_review, dict) else {}
        duplicate_of = review.get("duplicate_of", "unknown")
        lines.append(
            f"| {index} | {finding.id} | {finding.vuln_class} "
            f"| {finding.url[:120]} | {duplicate_of} |"
        )
    lines.append("")
    return "\n".join(lines)


def dedup_gate_node(state: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node: review the prior findings base before nomination.

    Never raises: any failure degrades to ``indeterminate`` with zero
    suppression (fail-safe). Returns ``{"findings": [...], "dedup_report":
    <DedupReport>}`` — annotated copies preserve every finding id.
    """
    findings: list[Finding] = [
        f for f in (state.get("findings") or []) if isinstance(f, Finding)
    ]
    engagement_id = str(state.get("engagement_id") or "")
    current_thread = str(state.get("thread_id") or "")

    if not engagement_id:
        report = DedupReport(
            status="clean_no_history",
            reviewed=len(findings),
            new_count=len(findings),
            note="no engagement context — prior base not consulted (nothing suppressed)",
        )
        return {"findings": list(findings), "dedup_report": report.model_dump(mode="json")}

    try:
        prior, note = load_prior_findings(
            engagement_id,
            owner_username=str(state.get("owner_username") or ""),
            client_id=str(state.get("client_id") or ""),
            exclude_thread_ids={current_thread} if current_thread else None,
        )
    except Exception as exc:  # noqa: BLE001 — fail-safe: review impossible → flag, never suppress
        logger.warning("dedup_gate: prior base unavailable (%s: %s)", type(exc).__name__, exc)
        records = [
            DedupRecord(
                finding_id=str(f.id),
                fingerprint="",
                decision=DedupDecision.INDETERMINATE,
                note="prior findings base unreadable — human review required",
            )
            for f in findings
        ]
        report = DedupReport(
            status="indeterminate",
            reviewed=len(findings),
            indeterminate_count=len(findings),
            engagement_id=engagement_id,
            records=records,
            note=f"prior base unavailable: {type(exc).__name__}",
        )
        annotated = [annotate_finding(f, r) for f, r in zip(findings, records, strict=False)]
        return {"findings": annotated, "dedup_report": report.model_dump(mode="json")}

    records = classify_against_prior_base(findings, prior)
    annotated = [annotate_finding(f, r) for f, r in zip(findings, records, strict=False)]
    duplicates = sum(1 for r in records if r.decision == DedupDecision.DUPLICATE)
    indeterminate = sum(1 for r in records if r.decision == DedupDecision.INDETERMINATE)
    report = DedupReport(
        status="applied",
        engagement_id=engagement_id,
        reviewed=len(findings),
        new_count=len(findings) - duplicates - indeterminate,
        duplicate_count=duplicates,
        indeterminate_count=indeterminate,
        prior_base_size=len(prior),
        records=records,
        note=note,
    )
    logger.info(
        "dedup_gate: reviewed=%d new=%d duplicate=%d indeterminate=%d (engagement=%s)",
        report.reviewed,
        report.new_count,
        report.duplicate_count,
        report.indeterminate_count,
        engagement_id,
    )
    return {"findings": annotated, "dedup_report": report.model_dump(mode="json")}

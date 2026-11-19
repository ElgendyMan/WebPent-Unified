# src/webpent/reporter/bounty_pipeline.py
"""webpent.reporter.bounty_pipeline — ق10 end-to-end bounty pipeline (FEATURE_PROPOSALS ق10).

Proposal contract (ق10، WebPent_FEATURE_PROPOSALS.md):

    تقارير bounty آلية من طرف لنهاية: reporter/platform_export (legacy)
    + قوالب HackerOne/Bugcrowd الموجودة في 0.26.0 → خط إنتاج: finding
    مؤكد → تقرير مصاغ بـevidence → معاينة → إرسال بموافقة المشغل
    (tier-3 اختياري).

    ("Automated end-to-end bounty reports: reporter/platform_export
    (legacy) + the HackerOne/Bugcrowd templates from 0.26.0 → one
    pipeline: confirmed finding → evidence-backed report → preview →
    submission with operator approval (optional tier-3).")

New module — the engines it chains are imported, never edited
(``bounty_report.py`` sits behind the frozen gate;
``platform_export.py`` is free and stays the rendering engine).

The pipeline stages, in order, each recorded in the result trace:

1. **draft** — ``bounty_report.build_bounty_report`` runs first: a
   finding that is not PROMOTED (or lacks a sealed, promotion-ready
   ProofBundle) never enters the pipeline at all (its error becomes a
   stage record, not an escape).
2. **render** — ``platform_export.export_finding`` renders the
   platform-native paste-ready Markdown (HackerOne/Bugcrowd/Intigriti
   vocabularies); the platform-neutral ``BountyReport.to_markdown()``
   is attached as the canonical preview.
3. **preview** — the draft is surfaced for operator review; nothing is
   sent, anywhere, at this stage.
4. **submit** — fail-closed on approval: a draft with no explicit
   operator approval (callback verdict or the ``approved`` argument)
   is refused (``approval_required``). When the engagement runs under
   the ق2 autonomy cage AND ``require_tier3`` is set, submission
   additionally requires a GRANTED tier-3 authority check
   (``tier3_authority_required``). There are NO platform API calls,
   ever: the injected ``submission_sink`` (default: the operator
   themselves) is the only destination, and the module records what it
   handed over — byte-identical drafts for identical findings.

All failures are stage records (``PipelineStage``), not exceptions —
the pipeline returns a result the operator can inspect; nothing is
silently dropped.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Mapping

from webpent.reporter.platform_export import (
    PLATFORMS,
    PlatformExportError,
    export_finding,
    platform_export_refusal,
)

logger = logging.getLogger(__name__)

__all__ = [
    "PLATFORMS",
    "PipelineStage",
    "SubmissionDraft",
    "SubmissionResult",
    "BountyPipeline",
]

ApprovalCallback = Callable[["SubmissionDraft"], bool]
SubmissionSink = Callable[["SubmissionDraft"], Any]


@dataclass(frozen=True)
class PipelineStage:
    """One recorded pipeline stage — inspectable, never silent."""

    stage: str  # draft | render | preview | submit
    ok: bool
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {"stage": self.stage, "ok": self.ok, "detail": self.detail}


@dataclass
class SubmissionDraft:
    """The evidence-backed report draft awaiting operator review."""

    report_id: str
    finding_id: str
    platform: str
    markdown: str
    preview: str
    report: dict[str, Any]
    stages: list[PipelineStage] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "finding_id": self.finding_id,
            "platform": self.platform,
            "markdown": self.markdown,
            "preview": self.preview,
            "report": self.report,
            "stages": [s.as_dict() for s in self.stages],
        }

    def __bool__(self) -> bool:
        return bool(self.markdown)


@dataclass
class SubmissionResult:
    """The outcome of a submit attempt (fail-closed, inspectable)."""

    submitted: bool
    refusal: str
    handed_to: str
    stages: list[PipelineStage] = field(default_factory=list)
    sink_response: Any = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "submitted": self.submitted,
            "refusal": self.refusal,
            "handed_to": self.handed_to,
            "stages": [s.as_dict() for s in self.stages],
            "sink_response_type": type(self.sink_response).__name__ if self.sink_response is not None else None,
        }


class BountyPipeline:
    """confirmed finding → report → preview → operator-approved submission.

    No network. No platform API. The ``submission_sink`` (a callable the
    OPERATOR wires to their own submission mechanism, or leaves unset to
    acknowledge paste-it-yourself) is the only destination a draft can
    reach, and only after approval.
    """

    def __init__(
        self,
        *,
        approval_callback: ApprovalCallback | None = None,
        submission_sink: SubmissionSink | None = None,
        require_tier3: bool = False,
        cage: Any = None,
    ) -> None:
        self._approval_callback = approval_callback
        self._submission_sink = submission_sink
        self._require_tier3 = bool(require_tier3)
        self._cage = cage

    # ------------------------------------------------------------------
    # draft → render → preview
    # ------------------------------------------------------------------

    def draft(self, finding: Any, *, platform: str = "hackerone") -> SubmissionDraft | None:
        """Build the evidence-backed draft; None when the finding cannot.

        A non-promoted finding, a missing ProofBundle, an unsupported
        platform or a flag-off export all return None with the stage
        trace attached — the operator sees WHY, nothing is invented.
        """
        from webpent.reporter.bounty_report import BountyReportError, build_bounty_report

        stages: list[PipelineStage] = []
        try:
            report = build_bounty_report(finding)
        except BountyReportError as exc:
            stages.append(PipelineStage("draft", False, str(exc)))
            logger.debug("bounty pipeline draft refused: %s", exc)
            return self._refused_draft(finding, platform, stages)
        stages.append(
            PipelineStage("draft", True, f"report_id={report.report_id} status=promoted")
        )

        try:
            if platform not in PLATFORMS:
                raise PlatformExportError("platform_export_unsupported")
            refusal = platform_export_refusal()
            if refusal is not None:
                raise PlatformExportError(refusal)
            markdown = export_finding(finding, platform)
        except PlatformExportError as exc:
            stages.append(PipelineStage("render", False, str(exc)))
            return self._refused_draft(finding, platform, stages)
        stages.append(PipelineStage("render", True, f"platform={platform}"))

        stages.append(PipelineStage("preview", True, "awaiting operator review"))
        return SubmissionDraft(
            report_id=report.report_id,
            finding_id=report.finding_id,
            platform=platform,
            markdown=markdown,
            preview=report.to_markdown(),
            report=report.to_json(),
            stages=stages,
        )

    def _refused_draft(
        self, finding: Any, platform: str, stages: list[PipelineStage]
    ) -> None:
        # A refused draft carries no content to preview; the stage trace
        # is logged (bounded) for operator visibility instead. Returning
        # None IS the refusal signal — no partial draft can leak.
        logger.info(
            "bounty draft refused platform=%s stages=%s",
            platform,
            [s.as_dict() for s in stages],
        )
        return None

    # ------------------------------------------------------------------
    # submit — fail-closed on approval, optional tier-3 authority
    # ------------------------------------------------------------------

    def submit(
        self,
        draft: SubmissionDraft | None,
        *,
        approved: bool | None = None,
    ) -> SubmissionResult:
        """Submit an approved draft to the sink; refuse everything else.

        Approval comes from EITHER the explicit ``approved`` argument or
        the injected ``approval_callback`` (operator interaction). With
        neither, the submission is refused (``approval_required``).
        ``require_tier3=True`` additionally demands a GRANTED tier-3
        authority check from the ق2 cage.
        """
        stages: list[PipelineStage] = []
        if draft is None or not draft:
            return SubmissionResult(
                submitted=False,
                refusal="no_draft",
                handed_to="nowhere",
                stages=[PipelineStage("submit", False, "no draft to submit")],
            )

        approved_by_callback = None
        if self._approval_callback is not None:
            try:
                approved_by_callback = bool(self._approval_callback(draft))
            except Exception:  # noqa: BLE001 — callback failure = no approval
                approved_by_callback = False
            stages.append(
                PipelineStage(
                    "submit",
                    approved_by_callback,
                    f"approval_callback={'granted' if approved_by_callback else 'denied'}",
                )
            )
        if approved is not None:
            stages.append(
                PipelineStage(
                    "submit",
                    bool(approved),
                    f"explicit_approval={'granted' if approved else 'denied'}",
                )
            )

        granted = (
            approved if approved is not None
            else approved_by_callback if approved_by_callback is not None
            else None
        )
        # Both an explicit False and an absent approval refuse.
        if granted is not True:
            return SubmissionResult(
                submitted=False,
                refusal="approval_required",
                handed_to="nowhere",
                stages=stages or [PipelineStage("submit", False, "no approval provided")],
            )

        if self._require_tier3:
            if self._cage is None:
                return SubmissionResult(
                    submitted=False,
                    refusal="tier3_authority_required",
                    handed_to="nowhere",
                    stages=stages + [PipelineStage("submit", False, "no autonomy cage configured")],
                )
            decision = self._cage.may_execute(3)
            stages.append(
                PipelineStage(
                    "submit",
                    bool(decision.granted),
                    f"tier3={decision.reason}",
                )
            )
            if not decision.granted:
                return SubmissionResult(
                    submitted=False,
                    refusal="tier3_authority_required",
                    handed_to="nowhere",
                    stages=stages,
                )

        if self._submission_sink is None:
            stages.append(
                PipelineStage(
                    "submit", True, "handed_to=operator (paste-it-yourself; no platform API)"
                )
            )
            return SubmissionResult(
                submitted=True,
                refusal="",
                handed_to="operator",
                stages=stages,
                sink_response=None,
            )

        try:
            response = self._submission_sink(draft)
        except Exception as exc:  # noqa: BLE001 — sink failure is inspectable
            stages.append(PipelineStage("submit", False, f"sink_error:{type(exc).__name__}"))
            return SubmissionResult(
                submitted=False,
                refusal="submission_sink_failed",
                handed_to="sink",
                stages=stages,
            )
        stages.append(PipelineStage("submit", True, "handed_to=sink"))
        return SubmissionResult(
            submitted=True,
            refusal="",
            handed_to="sink",
            stages=stages,
            sink_response=response,
        )

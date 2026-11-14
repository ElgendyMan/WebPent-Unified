# src/webpent/learning/feedback_loop.py
"""Market feedback loop (PROPOSALS_ULTIMATE_V3 §1, 2026-10-31).

Where §11 (technique library) learns from INTERNAL evidence (payload
success/failure), this module closes the EXTERNAL loop: what the bug
bounty platform actually did with each report — accepted (bounty,
severity), or flipped (duplicate / NFA / informative / spam). That is
the only signal that measures the tool's real market quality, and the
ground truth for prioritization.

Design:
  - One ``OutcomeRecord`` per report, appended to a LOCAL JSONL file
    (append-only: no edit, no delete — history is the dataset).
  - ``record_outcome`` is fail-closed on anything malformed (unknown
    outcome, negative bounty, empty finding ref, corrupt file) and
    doubly gated: the operator's flag AND a non-empty path.
  - ``class_stats`` / ``worst_classes`` are read-only aggregations that
    inform the operator (and, optionally, targeting). They are ADVISORY
    in every direction: worst_classes is printed as awareness, never
    auto-blocks, and the decision is always the operator's.
  - Privacy: the outcomes file lives entirely on the operator's disk
    (``feedback_outcomes_path``); nothing is sent anywhere.

With the flag off there is NO read and NO write of any outcomes file —
the gate helper refuses before any path is touched.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "OUTCOMES",
    "ACCEPTED",
    "OutcomeRecord",
    "FeedbackLoopError",
    "feedback_loop_refusal",
    "record_outcome",
    "load_outcomes",
    "class_stats",
    "all_class_stats",
    "worst_classes",
]

OUTCOMES = frozenset({"accepted", "duplicate", "nfa", "informative", "spam"})
ACCEPTED = "accepted"
# Everything else flips the report — these drive worst_classes.
FLIPPED = ("duplicate", "nfa", "informative", "spam")


class FeedbackLoopError(ValueError):
    """Raised when feedback recording/reading cannot proceed fail-closed."""


@dataclass
class OutcomeRecord:
    """One external report outcome (append-only JSONL line)."""

    finding_ref: str
    campaign_id: str
    vuln_class: str
    outcome: str
    platform_report_id: str = ""
    bounty_usd: float | None = None
    severity_offered: str = ""
    operator_note: str = ""
    recorded_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_ref": self.finding_ref,
            "campaign_id": self.campaign_id,
            "vuln_class": self.vuln_class,
            "outcome": self.outcome,
            "platform_report_id": self.platform_report_id,
            "bounty_usd": self.bounty_usd,
            "severity_offered": self.severity_offered,
            "operator_note": self.operator_note,
            "recorded_at": self.recorded_at,
        }

    @classmethod
    def from_dict(cls, doc: Any) -> "OutcomeRecord":
        if not isinstance(doc, dict):
            raise FeedbackLoopError(
                f"feedback_loop_schema: line must be an object, got {type(doc).__name__}"
            )
        known = {
            "finding_ref",
            "campaign_id",
            "vuln_class",
            "outcome",
            "platform_report_id",
            "bounty_usd",
            "severity_offered",
            "operator_note",
            "recorded_at",
        }
        unknown = set(doc) - known
        if unknown:
            raise FeedbackLoopError(
                f"feedback_loop_schema: unknown field(s) {sorted(unknown)}"
            )
        for required in ("finding_ref", "outcome"):
            if not doc.get(required):
                raise FeedbackLoopError(
                    f"feedback_loop_schema: missing required field {required!r}"
                )
        rec = cls(
            finding_ref=str(doc["finding_ref"]),
            campaign_id=str(doc.get("campaign_id", "")),
            vuln_class=str(doc.get("vuln_class", "")).lower() or "unknown",
            outcome=str(doc["outcome"]),
            platform_report_id=str(doc.get("platform_report_id", "")),
            bounty_usd=doc.get("bounty_usd"),
            severity_offered=str(doc.get("severity_offered", "")),
            operator_note=str(doc.get("operator_note", "")),
            recorded_at=doc.get("recorded_at", time.time()),
        )
        _validate(rec)
        return rec


def _validate(rec: OutcomeRecord) -> None:
    if not rec.finding_ref.strip():
        raise FeedbackLoopError("feedback_loop_schema: empty finding_ref")
    if rec.outcome not in OUTCOMES:
        raise FeedbackLoopError(
            f"feedback_loop_unknown_outcome: {rec.outcome!r} "
            f"(expected one of {sorted(OUTCOMES)})"
        )
    if rec.bounty_usd is not None:
        if isinstance(rec.bounty_usd, bool) or not isinstance(rec.bounty_usd, (int, float)):
            raise FeedbackLoopError(
                f"feedback_loop_schema: bounty_usd must be a number, got {type(rec.bounty_usd).__name__}"
            )
        if rec.bounty_usd < 0:
            raise FeedbackLoopError(
                f"feedback_loop_negative_bounty: {rec.bounty_usd!r}"
            )


def feedback_loop_refusal() -> str | None:
    """Refusal code when the operator's flag/path gate is closed, else None.

    Doubly gated: the flag must be on AND the path configured (an empty
    path disables the loop even with the flag on — a loop with nowhere
    to write is not a loop). Reads settings through
    ``webpent.config.settings.get_settings`` at call time.
    """
    from webpent.config.settings import get_settings

    settings = get_settings()
    if not settings.enable_feedback_loop:
        return "feedback_loop_flag_off"
    if not str(settings.feedback_outcomes_path or "").strip():
        return "feedback_loop_path_missing"
    return None


def record_outcome(path: str | Path, record: OutcomeRecord) -> dict[str, Any]:
    """Append one outcome record to the JSONL file (fail-closed, gated).

    The operator gate is checked FIRST (no path touch while closed),
    then validation, then the append. The file is opened in append mode
    and one JSON line is written — no rewrite, no edit, no delete.
    """
    refusal = feedback_loop_refusal()
    if refusal:
        raise FeedbackLoopError(refusal)
    _validate(record)
    doc = record.to_dict()
    try:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(doc, sort_keys=True) + "\n")
    except OSError as exc:
        raise FeedbackLoopError(f"feedback_loop_write_failed: {exc}") from exc
    return doc


def load_outcomes(path: str | Path) -> list[OutcomeRecord]:
    """Read all outcome records; fail-closed on any corrupt line."""
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise FeedbackLoopError(f"feedback_loop_unreadable: {exc}") from exc
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FeedbackLoopError(f"feedback_loop_invalid_encoding: {exc}") from exc
    records: list[OutcomeRecord] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FeedbackLoopError(
                f"feedback_loop_invalid_json at line {lineno}: {exc}"
            ) from exc
        records.append(OutcomeRecord.from_dict(doc))
    return records


def all_class_stats(records: list[OutcomeRecord]) -> dict[str, dict[str, Any]]:
    """Aggregate outcome records per vuln class (pure — no path, no flag)."""
    stats: dict[str, dict[str, Any]] = {}
    for rec in records:
        bucket = stats.setdefault(
            rec.vuln_class,
            {
                "reports": 0,
                "accepted": 0,
                "duplicate": 0,
                "nfa": 0,
                "informative": 0,
                "spam": 0,
                "acceptance_rate": 0.0,
                "total_bounty_usd": 0.0,
            },
        )
        bucket["reports"] += 1
        if rec.outcome in bucket and isinstance(bucket[rec.outcome], int):
            bucket[rec.outcome] += 1
        if rec.bounty_usd is not None:
            bucket["total_bounty_usd"] = round(
                bucket["total_bounty_usd"] + rec.bounty_usd, 2
            )
    for bucket in stats.values():
        if bucket["reports"]:
            bucket["acceptance_rate"] = bucket["accepted"] / bucket["reports"]
    return stats


def class_stats(path: str | Path, vuln_class: str) -> dict[str, Any]:
    """Stats for one vuln class from the outcomes file ({} if unknown)."""
    return all_class_stats(load_outcomes(path)).get(
        str(vuln_class or "").lower() or "unknown", {}
    )


def worst_classes(path: str | Path, k: int = 5) -> list[dict[str, Any]]:
    """The k classes most often flipped by the platform — awareness only.

    Ranked by flip count descending (duplicate + nfa + informative +
    spam), ties by acceptance rate ascending. Purely advisory: the
    output never blocks or disables anything; the operator decides.
    """
    stats = all_class_stats(load_outcomes(path))
    ranked = sorted(
        stats.items(),
        key=lambda item: (
            -sum(item[1][flip] for flip in FLIPPED),
            item[1]["acceptance_rate"],
        ),
    )[: max(0, int(k))]
    return [
        {"vuln_class": name, **counts}
        for name, counts in ranked
    ]

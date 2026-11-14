"""POST-P0 Phase 2 — memory read-back service (lessons + hypothesis ledger).

Learning must change behaviour WITHOUT poisoning truth. This module is
the single read-back seam that turns persisted memory (negative lessons
and the structured-hypothesis ledger) into a *retrieved-only* advisory
record — a ``LearnedStrategy`` projection that:

  * is scoped fail-closed to (client_id, engagement_id, target) — any
    missing scope component returns ``None`` (no data at all),
  * never grants confirmation: every record is marked
    ``advisory_only=True`` / ``never_confirmation_evidence=True`` and
    consumers are permitted to DEMOTE or inform, never to confirm,
  * is bounded (record counts + per-item char caps) so a poisoned or
    bloated memory store cannot blow up a prompt or a ranking pass,
  * is retrieved-only: nothing here is LLM-authored fact; rows come
    from deterministic writers (validator negative lessons, strategist
    ledger persistence) and are projected verbatim (post
    write-side sanitisation).

Data-only prompt injection stays with the callers (they must route the
content through :func:`webpent.shared.llm.safe_prompt_format`).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "LEARNED_STRATEGY_SCHEMA_VERSION",
    "MAX_NEGATIVE_LESSONS",
    "MAX_LEDGER_ENTRIES",
    "NEGATIVE_LEDGER_STATUSES",
    "retrieve_learned_strategy",
    "negative_outcome_classes",
]

LEARNED_STRATEGY_SCHEMA_VERSION = "learned-strategy-v1"
MAX_NEGATIVE_LESSONS = 8
MAX_LEDGER_ENTRIES = 12
MAX_LESSON_CHARS = 300
MAX_STATEMENT_CHARS = 200

# Ledger statuses that count as a negative outcome for the target.
# Promoted/pending/unexplored entries are NOT negative evidence.
# Aligned with the HypothesisStatus vocabulary (abandoned /
# resolved_false); "refuted" is accepted defensively for forward
# compatibility but is not a status the strategist writes today.
NEGATIVE_LEDGER_STATUSES = frozenset({"abandoned", "resolved_false", "refuted"})

# The negative-lesson content format is written by
# LessonsManager.save_negative_lesson as closed-format plain text:
#   "negative_lesson target_signature <16hex> vulnerability_class <cls> ..."
_LESSON_CLASS_RE = re.compile(r"vulnerability_class\s+([A-Za-z0-9_\-]+)")


def _scoped(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def retrieve_learned_strategy(
    *,
    target_url: Any,
    client_id: Any,
    engagement_id: Any,
    max_lessons: int = MAX_NEGATIVE_LESSONS,
    max_ledger: int = MAX_LEDGER_ENTRIES,
    manager: Any = None,
) -> dict[str, Any] | None:
    """Retrieve the bounded, scoped ``LearnedStrategy`` projection.

    Args:
        target_url: The engagement's primary target URL (exact-scope key).
        client_id: Mandatory client scope — missing/empty fails closed.
        engagement_id: Mandatory engagement scope — missing/empty fails closed.
        max_lessons: Cap on negative lessons retrieved (clamped to
            [0, MAX_NEGATIVE_LESSONS]).
        max_ledger: Cap on ledger entries retrieved (clamped to
            [0, MAX_LEDGER_ENTRIES]).
        manager: Optional explicit LessonsManager (dependency injection
            for tests/tools); defaults to the workspace-scoped singleton.

    Returns:
        The advisory record dict, or ``None`` when scope is incomplete or
        the memory store is unavailable (fail-closed, never raise).
    """
    scoped_target = _scoped(target_url)
    scoped_client = _scoped(client_id)
    scoped_engagement = _scoped(engagement_id)
    if not (scoped_target and scoped_client and scoped_engagement):
        # Fail closed: memory read-back without complete scope is refused.
        return None
    try:
        bounded_lessons = max(0, min(MAX_NEGATIVE_LESSONS, int(max_lessons)))
        bounded_ledger = max(0, min(MAX_LEDGER_ENTRIES, int(max_ledger)))
    except (TypeError, ValueError):
        bounded_lessons = MAX_NEGATIVE_LESSONS
        bounded_ledger = MAX_LEDGER_ENTRIES

    try:
        from webpent.memory.lessons import target_signature

        if manager is not None:
            mgr = manager
        else:
            from webpent.memory.lessons import get_lessons_manager

            mgr = get_lessons_manager()
        signature = target_signature(scoped_target)
        prefix = f"target_signature {signature}"

        # Negative lessons: scoped query + exact target-signature filter
        # (same pattern as hypothesis_analyzer's boundary path).
        lessons: list[str] = []
        try:
            raw = mgr.search_lessons(
                "negative_lesson",
                client_id=scoped_client,
                engagement_id=scoped_engagement,
                limit=min(50, max(bounded_lessons * 4, 10)),
            )
        except TypeError:
            # Defensive: older signature without keyword support.
            raw = []
        for content in raw or []:
            text = str(content or "")
            if prefix in text and "negative_lesson" in text:
                lessons.append(text[:MAX_LESSON_CHARS])
            if len(lessons) >= bounded_lessons:
                break

        # Structured-hypothesis ledger: exact target_url narrowing.
        ledger: list[dict[str, Any]] = []
        try:
            rows = mgr.get_structured_hypotheses(target_url=scoped_target)
        except TypeError:
            rows = []
        for row in rows or []:
            ledger.append(
                {
                    "statement": str(row.get("statement") or "")[:MAX_STATEMENT_CHARS],
                    "vuln_class": str(row.get("vuln_class") or "unknown"),
                    "status": str(row.get("status") or "unknown"),
                    "confidence_score": row.get("confidence_score"),
                }
            )
            if len(ledger) >= bounded_ledger:
                break
    except Exception as exc:  # pragma: no cover - defensive, fail-closed
        logger.warning("Learned-strategy retrieval failed closed: %s", exc)
        return None

    return {
        "schema_version": LEARNED_STRATEGY_SCHEMA_VERSION,
        "target_url": scoped_target,
        "target_signature": signature,
        "advisory_only": True,
        "never_confirmation_evidence": True,
        "negative_lessons": lessons,
        "hypothesis_ledger": ledger,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }


def negative_outcome_classes(learned: dict[str, Any] | None) -> frozenset[str]:
    """Derive the set of vuln classes with a NEGATIVE outcome for the target.

    Sources (both scoped to the same target by construction of
    :func:`retrieve_learned_strategy`):
      * negative-lesson contents (closed-format ``vulnerability_class`` field),
      * structured-ledger rows whose status is in ``NEGATIVE_LEDGER_STATUSES``.

    The result can only ever be used to DEMOTE — there is no API here
    that could promote or confirm anything.
    """
    if not learned or not isinstance(learned, dict):
        return frozenset()
    classes: set[str] = set()
    for text in learned.get("negative_lessons") or []:
        match = _LESSON_CLASS_RE.search(str(text or ""))
        if match:
            classes.add(match.group(1).lower())
    for row in learned.get("hypothesis_ledger") or []:
        try:
            status = str(row.get("status") or "").strip().lower()
        except Exception:
            continue
        if status in NEGATIVE_LEDGER_STATUSES:
            classes.add(str(row.get("vuln_class") or "unknown").lower())
    return frozenset(classes)


def retrieve_learned_strategy_from_state(state: Any) -> dict[str, Any]:
    """State-based wrapper: pull scope from a PentestState and retrieve.

    Fail-closed: missing target/client/engagement scope returns ``{}``
    (no memory influence). Shared by the strategist and planner read
    paths so both consume the identical scoped projection.
    """
    try:
        target = state.get("target")
        target_url = None
        if target is not None:
            target_url = (
                target.get("url") if isinstance(target, dict) else getattr(target, "url", None)
            )
        learned = retrieve_learned_strategy(
            target_url=target_url,
            client_id=state.get("client_id"),
            engagement_id=state.get("engagement_id") or state.get("thread_id"),
        )
        return learned or {}
    except Exception as exc:  # pragma: no cover - defensive, fail-closed
        logger.warning("Learned-strategy state retrieval failed closed: %s", exc)
        return {}


def format_learned_context_for_prompt(learned: dict[str, Any] | None) -> str:
    """Render the learned record as a bounded, data-only prompt block.

    The output is plain advisory text with an explicit non-evidence
    banner. Callers MUST inject it through
    :func:`webpent.shared.llm.safe_prompt_format` so the block is
    wrapped as untrusted content.
    """
    if not learned or not isinstance(learned, dict):
        return "(no prior memory for this target)"
    lines: list[str] = [
        "Prior memory for this target (retrieved-only, advisory; "
        "NEVER confirmation evidence):"
    ]
    for lesson in (learned.get("negative_lessons") or [])[:MAX_NEGATIVE_LESSONS]:
        lines.append(f"- negative lesson: {str(lesson or '')[:MAX_LESSON_CHARS]}")
    for row in (learned.get("hypothesis_ledger") or [])[:MAX_LEDGER_ENTRIES]:
        try:
            lines.append(
                "- prior hypothesis [{status}] {cls}: {stmt}".format(
                    status=str(row.get("status") or "unknown")[:40],
                    cls=str(row.get("vuln_class") or "unknown")[:60],
                    stmt=str(row.get("statement") or "")[:MAX_STATEMENT_CHARS],
                )
            )
        except Exception:
            continue
    if len(lines) == 1:
        return "(no prior memory for this target)"
    text = "\n".join(lines)
    return text[:2000]

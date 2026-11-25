"""UM-DR-47 Phase W6 — the campaign research-memory store.

The 46 research-memory node compacted THIS campaign's lessons in
graph-state; nothing crossed campaign boundaries. This module makes
the memory durable ACROSS campaigns for the same target, behind the
brain-engine flag:

* ``load_research_memory`` — read at campaign start (the strategist's
  ``retrieve_learned_strategy`` read-back seam merges the store's
  demotion classes through the EXISTING closed-format negative-lesson
  projection — demotion-only, bounded, fail-closed);
* ``save_research_memory`` — written at campaign end from the final
  state (lesson summaries + confirmed/refuted vulnerability classes
  + FP causes), PRIVACY-SCRUBBED: no cookies, no session values, no
  tokens, no authorization headers ever cross a campaign boundary
  (the W6 negative privacy tests assert this on real cookie-shaped
  input).

Storage: one JSON file per target key under ``WEBPENT_RESEARCH_MEMORY_DIR``
(default ``.webpent-research-memory``). Deterministic: no clock in
the record content (a monotonic ``revision`` counter instead).
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "RESEARCH_MEMORY_ENV",
    "default_store_dir",
    "target_memory_key",
    "load_research_memory",
    "save_research_memory",
    "research_memory_demotion_classes",
    "scrub_for_memory",
]

RESEARCH_MEMORY_ENV = "WEBPENT_RESEARCH_MEMORY_DIR"
_SCHEMA = "umdr47-research-memory-v1"
_MAX_CLASSES = 12
_MAX_FP_CAUSES = 16
_MAX_LESSONS = 16
_MAX_LESSON_CHARS = 300

# W6 privacy: these keys NEVER survive into a memory record, whatever
# their value — the negative privacy tests feed real cookie-shaped
# values through save_research_memory and assert none survives.
_REDACT_KEYS = re.compile(
    r"(cookie|session|token|secret|authorization|password|api[_-]?key|"
    r"bearer|credential)",
    re.IGNORECASE,
)
_REDACTED = "[redacted-by-w6-privacy]"


def default_store_dir() -> str:
    override = os.environ.get(RESEARCH_MEMORY_ENV, "").strip()
    if override:
        return override
    return os.path.join(os.getcwd(), ".webpent-research-memory")


def target_memory_key(target_url: str) -> str:
    """Stable cross-campaign key: scheme+host(+normalized path), hashed."""
    import hashlib
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(str(target_url or ""))
        host = (parts.hostname or "").strip().lower()
        path = (parts.path or "").rstrip("/")
        seed = f"{parts.scheme.lower()}://{host}{path}"
    except ValueError:
        seed = str(target_url or "").strip().lower().rstrip("/")
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]


def _memory_path(target_url: str, store_dir: str | None) -> str:
    directory = store_dir if store_dir is not None else default_store_dir()
    return os.path.join(directory, f"{target_memory_key(target_url)}.json")


def scrub_for_memory(value: Any) -> Any:
    """Recursive privacy scrub (the W6 negative-privacy contract).

    Any dict key matching the redaction pattern has its value replaced
    wholesale; lists/tuples are scrubbed element-wise; strings are
    scrubbed for cookie-shaped assignments (``session=...``,
    ``token=...``) after the key-level pass.
    """
    if isinstance(value, dict):
        return {
            str(k): (_REDACTED if _REDACT_KEYS.search(str(k)) else scrub_for_memory(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [scrub_for_memory(v) for v in value]
    if isinstance(value, str):
        # bearer-token shapes FIRST ("Authorization: Bearer x"): the
        # assignment pattern would otherwise eat the word Bearer and
        # leave the token itself untouched
        scrubbed = re.sub(
            r"(?i)(bearer\s+)[A-Za-z0-9._\-]+",
            r"\1" + _REDACTED,
            value,
        )
        # cookie-shaped pairs: session=abc123, token=..., set-cookie: ...
        scrubbed = re.sub(
            r"(?i)\b(session|token|secret|password|api[_-]?key|authorization)"
            r"\s*[=:]\s*[^\s;,]+",
            r"\1=" + _REDACTED,
            scrubbed,
        )
        return scrubbed
    return value


def load_research_memory(
    target_url: str,
    store_dir: str | None = None,
) -> dict[str, Any]:
    """Read the durable research memory for this target (fail-closed).

    Returns ``{}`` when absent/corrupt — never raises, never invents.
    """
    try:
        path = _memory_path(target_url, store_dir)
        if not os.path.isfile(path):
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            record = json.load(fh)
        if not isinstance(record, dict) or record.get("schema") != _SCHEMA:
            return {}
        return record
    except Exception as exc:  # noqa: BLE001 — fail-closed read
        logger.warning("research-memory load failed closed: %s", exc)
        return {}


def save_research_memory(
    target_url: str,
    *,
    demotion_classes: list[str] | None = None,
    fp_causes: list[str] | None = None,
    lesson_summaries: list[str] | None = None,
    patterns: dict[str, Any] | None = None,
    store_dir: str | None = None,
) -> str | None:
    """Merge + persist the scrubbed memory record; returns the path.

    The store is append-only by class/cause (a class confirmed once
    stays recorded); ``revision`` increments monotonically instead of
    any wall-clock timestamp (deterministic replay).
    """
    try:
        path = _memory_path(target_url, store_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        current = load_research_memory(target_url, store_dir)
        classes = list(current.get("demotion_classes") or [])
        for cls in (demotion_classes or []):
            cls = str(cls or "").strip().lower()
            if cls and cls not in classes and len(classes) < _MAX_CLASSES:
                classes.append(cls)
        causes = list(current.get("fp_causes") or [])
        for cause in (fp_causes or []):
            cause = str(scrub_for_memory(cause) or "").strip()
            if cause and cause not in causes and len(causes) < _MAX_FP_CAUSES:
                causes.append(cause)
        lessons = list(current.get("lesson_summaries") or [])
        for lesson in (lesson_summaries or []):
            lesson = str(scrub_for_memory(lesson) or "")[:_MAX_LESSON_CHARS]
            if lesson and lesson not in lessons and len(lessons) < _MAX_LESSONS:
                lessons.append(lesson)
        record = {
            "schema": _SCHEMA,
            "target_key": target_memory_key(target_url),
            "revision": int(current.get("revision") or 0) + 1,
            "demotion_classes": classes,
            "fp_causes": causes,
            "lesson_summaries": lessons,
            "patterns": scrub_for_memory(
                {**(current.get("patterns") or {}), **(patterns or {})}
            ),
            "privacy_contract": (
                "scrubbed at write time — no cookies, sessions, tokens or "
                "authorization material ever cross a campaign boundary"
            ),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=1, sort_keys=True)
        return path
    except Exception as exc:  # noqa: BLE001 — fail-safe write
        logger.warning("research-memory save failed: %s", exc)
        return None


def research_memory_demotion_classes(
    target_url: str,
    store_dir: str | None = None,
) -> frozenset[str]:
    """The store's demotion classes for this target (bounded read)."""
    record = load_research_memory(target_url, store_dir)
    return frozenset(
        str(c).lower() for c in (record.get("demotion_classes") or [])[:_MAX_CLASSES]
    )

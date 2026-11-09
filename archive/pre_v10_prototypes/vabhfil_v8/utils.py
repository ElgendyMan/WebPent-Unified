"""Small deterministic helpers for recorded, target-neutral v8 reasoning."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any


def get_value(source: object | None, *names: str, default: Any = None) -> Any:
    """Read an attribute or mapping key; never invoke callables."""
    if source is None:
        return default
    for name in names:
        if isinstance(source, dict) and name in source:
            value = source[name]
        else:
            value = getattr(source, name, default)
        if value is not None and not callable(value):
            return value
    return default


def strings(value: object | None) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if isinstance(value, Iterable):
        return tuple(" ".join(str(item).split()) for item in value if str(item).strip())
    return (" ".join(str(value).split()),)


def stable_id(prefix: str, *parts: object) -> str:
    payload = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({" ".join(str(value).split()) for value in values if str(value).strip()}))


def evidence_refs(source: object | None) -> tuple[str, ...]:
    return unique_sorted(strings(get_value(source, "evidence_refs", "source_refs", "refs")))


def gap_values(*sources: object | None) -> tuple[str, ...]:
    values: list[str] = []
    for source in sources:
        values.extend(
            strings(
                get_value(
                    source,
                    "coverage_gaps",
                    "gaps",
                    "unresolved_questions",
                    "missing_evidence",
                    "unresolved_dependencies",
                )
            )
        )
    return unique_sorted(values)


__all__ = ["evidence_refs", "gap_values", "get_value", "stable_id", "strings", "unique_sorted"]

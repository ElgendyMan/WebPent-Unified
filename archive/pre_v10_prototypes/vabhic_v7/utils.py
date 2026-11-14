"""Small deterministic helpers for the VABHIC v7 advisory layer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


def values(value: object | None, *names: str) -> tuple[object, ...]:
    if value is None:
        return ()
    for name in names:
        item = value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)
        if isinstance(item, Mapping):
            return tuple(item.values())
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
            return tuple(item)
    return ()


def field(item: object, *names: str, default: object = "") -> object:
    for name in names:
        value = item.get(name) if isinstance(item, Mapping) else getattr(item, name, None)
        if value is not None:
            return value
    return default


def text(item: object, *names: str, default: str = "") -> str:
    return " ".join(str(field(item, *names, default=default) or "").split())[:400]


def refs(item: object) -> tuple[str, ...]:
    value = field(item, "source_refs", "evidence_refs", default=())
    if isinstance(value, str):
        value = (value,)
    return tuple(dict.fromkeys(str(ref).strip() for ref in (value or ()) if str(ref).strip()))[:32]


def strings(value: object, limit: int = 32) -> tuple[str, ...]:
    if isinstance(value, str):
        value = (value,)
    if not isinstance(value, Sequence):
        return ()
    return tuple(dict.fromkeys(" ".join(str(item).split()) for item in value if str(item).strip()))[
        :limit
    ]


def score(value: object, default: float = 0.0) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default

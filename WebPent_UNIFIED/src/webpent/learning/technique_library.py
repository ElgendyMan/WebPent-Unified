# src/webpent/learning/technique_library.py
"""Cross-campaign technique library (PROPOSALS_ULTIMATE_V2 §11, 2026-10-31).

A versioned JSON library keyed by (vuln_class, waf_category, tech)
holding the payloads each key historically succeeded or failed with
across CAMPAIGNS. It solves the "broken memory" problem: today's
framework rediscovers in campaign 7 what campaign 2 already knew. The
library is learned (beta-style outcome updates with a remembering cap
so old ratios fade) and CONSUMED by payload optimization as context —
recommendations, never canned answers.

Fail-closed on load (unreadable / invalid JSON / schema violations),
flag-gated on write (a library is never written without the operator's
cross-campaign learning flag), and fail-soft at the consumption point
(a library problem must never break an in-flight optimization).
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

__all__ = [
    "LIBRARY_SCHEMA_VERSION",
    "REMEMBERING_CAP",
    "TechniqueLibraryError",
    "empty_library",
    "load_library",
    "save_library",
    "record_outcome",
    "success_rate",
    "top_payloads",
    "prompt_hint_for_finding",
]

LIBRARY_SCHEMA_VERSION = 1

# Remembering cap: when an entry's total outcomes reaches this bound its
# counters are halved before the next update — recent evidence keeps
# outweighing ancient evidence, and no stale payload freezes at the top
# forever.
REMEMBERING_CAP = 100


class TechniqueLibraryError(ValueError):
    """Raised when library load/save cannot proceed fail-closed."""


def empty_library() -> dict[str, Any]:
    return {"schema_version": LIBRARY_SCHEMA_VERSION, "entries": {}}


def _key(vuln_class: str, waf_category: str, tech: str) -> str:
    return f"{str(vuln_class or 'unknown').lower()}|{str(waf_category or 'none').lower()}|{str(tech or 'generic').lower()}"


def load_library(path: str | Path) -> dict[str, Any]:
    """Load the technique library; fail-closed on any structural problem."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise TechniqueLibraryError(f"technique_library_unreadable: {exc}") from exc
    try:
        doc = json.loads(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise TechniqueLibraryError(
            f"technique_library_invalid_encoding: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise TechniqueLibraryError(f"technique_library_invalid_json: {exc}") from exc
    if not isinstance(doc, dict):
        raise TechniqueLibraryError("technique_library_schema: top level must be an object")
    version = doc.get("schema_version")
    if version != LIBRARY_SCHEMA_VERSION:
        raise TechniqueLibraryError(
            f"technique_library_schema: unsupported schema_version {version!r} "
            f"(expected {LIBRARY_SCHEMA_VERSION})"
        )
    entries = doc.get("entries")
    if not isinstance(entries, dict):
        raise TechniqueLibraryError("technique_library_schema: entries must be an object")
    for key, entry in entries.items():
        if not isinstance(key, str) or key.count("|") != 2:
            raise TechniqueLibraryError(
                "technique_library_schema: entry keys must be 'class|waf|tech'"
            )
        if not isinstance(entry, dict) or not isinstance(entry.get("payloads"), dict):
            raise TechniqueLibraryError(
                "technique_library_schema: each entry needs a payloads object"
            )
        for payload, stats in entry["payloads"].items():
            if not isinstance(payload, str) or not isinstance(stats, dict):
                raise TechniqueLibraryError(
                    "technique_library_schema: payloads must map strings to stat objects"
                )
            for field in ("successes", "failures"):
                value = stats.get(field, 0)
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise TechniqueLibraryError(
                        f"technique_library_schema: {field} must be a non-negative int"
                    )
    return doc


def save_library(
    path: str | Path, library: dict[str, Any], *, write_enabled: bool
) -> None:
    """Persist the library atomically; the flag gates the write entirely.

    Without ``write_enabled`` (the operator's cross-campaign learning
    flag) this refuses outright — learning artifacts are never written
    to disk silently. With it, the write is atomic (tmp file + rename).
    """
    if not write_enabled:
        raise TechniqueLibraryError("technique_library_write_disabled")
    tmp_fd, tmp_name = tempfile.mkstemp(
        dir=str(Path(path).parent), prefix=".technique_library_", suffix=".tmp"
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(library, fh, indent=2, sort_keys=True)
        os.replace(tmp_name, str(path))
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _halve(stats: dict[str, int]) -> None:
    stats["successes"] = stats["successes"] // 2
    stats["failures"] = stats["failures"] // 2


def record_outcome(
    library: dict[str, Any],
    vuln_class: str,
    waf_category: str,
    tech: str,
    payload: str,
    success: bool,
) -> dict[str, int]:
    """Record one outcome (beta-style update with the remembering cap).

    Deterministic and additive: the same sequence of outcomes always
    yields the same counters.
    """
    entries = library.setdefault("entries", {})
    entry = entries.setdefault(_key(vuln_class, waf_category, tech), {"payloads": {}})
    payloads = entry.setdefault("payloads", {})
    stats = payloads.setdefault(str(payload), {"successes": 0, "failures": 0})
    if stats["successes"] + stats["failures"] >= REMEMBERING_CAP:
        _halve(stats)
    if success:
        stats["successes"] += 1
    else:
        stats["failures"] += 1
    return stats


def success_rate(stats: dict[str, int]) -> float:
    """Laplace-smoothed success rate: (s+1)/(s+f+2).

    An unseen payload starts at 0.5 — neither trusted nor dismissed.
    """
    total = stats.get("successes", 0) + stats.get("failures", 0)
    return (stats.get("successes", 0) + 1) / (total + 2)


def top_payloads(
    library: dict[str, Any],
    vuln_class: str,
    waf_category: str | None = None,
    tech: str | None = None,
    k: int = 5,
) -> list[tuple[str, float]]:
    """Top-k payloads for a vuln class, deterministic.

    With an exact (class, waf, tech) match those payloads rank first;
    otherwise the class is aggregated across its keys. Ties break by
    payload text so the ordering is a pure function of the counters.
    """
    entries = library.get("entries", {})
    class_lower = str(vuln_class or "").lower()
    ranked: dict[str, list[float]] = {}
    exact: list[tuple[str, float]] = []
    if waf_category is not None and tech is not None:
        entry = entries.get(_key(class_lower, waf_category, tech))
        if entry:
            for payload, stats in entry["payloads"].items():
                exact.append((payload, success_rate(stats)))
    for key, entry in entries.items():
        if key.split("|")[0] != class_lower:
            continue
        for payload, stats in entry["payloads"].items():
            ranked.setdefault(payload, []).append(success_rate(stats))
    merged: dict[str, float] = {}
    for payload, rates in ranked.items():
        merged[payload] = max(rates)
    for payload, rate in exact:
        merged[payload] = max(merged.get(payload, rate), rate)
    ordered = sorted(merged.items(), key=lambda kv: (-kv[1], kv[0]))
    return ordered[: max(0, int(k))]


def prompt_hint_for_finding(vuln_class: str) -> str:
    """Consumption hook for the payload optimizer (fail-soft, flag-gated).

    Reads the operator's settings: with the cross-campaign learning
    flag off, or no library path configured, this returns "" and the
    optimizer behaves exactly as before. With the flag on and a
    readable library, it returns a short CONTEXT block of historically
    successful payloads. Any failure returns "" — a library problem
    must never break an in-flight optimization.
    """
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        if not settings.enable_cross_campaign_learning:
            return ""
        path = settings.technique_library_path
        if not path:
            return ""
        library = load_library(path)
        top = top_payloads(library, vuln_class)
        if not top:
            return ""
        lines = [
            "HISTORICALLY SUCCESSFUL PAYLOADS for this vuln class "
            "(aggregated from past campaigns; treat as context, not answers):"
        ]
        lines += [
            f"- {payload!r} (historical success rate {rate:.2f})"
            for payload, rate in top
        ]
        return "\n".join(lines)
    except Exception:  # noqa: BLE001 — fail-soft by contract
        return ""

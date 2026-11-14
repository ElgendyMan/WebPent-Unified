"""Source-map secret and inventory scanning (V2 §3, 2026-10-29).

Scans ``sourcesContent`` — the ORIGINAL sources shipped with a map — with
the same canonical secret patterns the JS surface discovery uses
(``webpent.shared.javascript_intelligence._SECRET_PATTERNS``), so a key
that would be flagged in a bundle is flagged identically in the original
that produced it, attributed to the real source file and line. Also emits
a bounded source-inventory finding: the original tree layout itself is
information disclosure (paths, module names, test file names).

Every finding value is stored as a bounded PREVIEW (truncated SHA-256
thumb) rather than the full secret, matching the framework's
fingerprint-before-evidence rule — the operator sees enough to verify the
finding in the map itself, and no secret ever lands in evidence stores.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .parser import SourceMap

__all__ = ["SourceMapFinding", "scan_sources"]

_PREVIEW_CHARS = 12
_MAX_FINDINGS_PER_SOURCE = 20
_MAX_INVENTORY_ENTRIES = 100
_MAX_TOTAL_FINDINGS = 200


@dataclass(frozen=True)
class SourceMapFinding:
    """One secret/inventory hit inside an original source file."""

    kind: str  # "secret_hint" | "source_inventory"
    detail: str  # secret kind or inventory summary
    source_file: str
    line: int
    thumb: str  # bounded fingerprint of the matched value, never the value
    preview: str  # first few chars of the match, for the operator's eye


def _thumb(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def _preview(match_text: str) -> str:
    return match_text[:_PREVIEW_CHARS]


def _line_of(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def scan_sources(source_map: SourceMap) -> list[SourceMapFinding]:
    """Scan every original source for secrets; bounded and deterministic."""
    from webpent.shared.javascript_intelligence import _SECRET_PATTERNS

    findings: list[SourceMapFinding] = []
    for index, content in enumerate(source_map.sources_content):
        if not content:
            continue
        if index >= len(source_map.sources):
            continue
        source_file = source_map.sources[index]
        per_source = 0
        for kind, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(content):
                if per_source >= _MAX_FINDINGS_PER_SOURCE:
                    break
                value = match.group(1) if match.groups() else match.group(0)
                findings.append(
                    SourceMapFinding(
                        kind="secret_hint",
                        detail=kind,
                        source_file=source_file,
                        line=_line_of(content, match.start()),
                        thumb=_thumb(value),
                        preview=_preview(match.group(0)),
                    )
                )
                per_source += 1
        if len(findings) >= _MAX_TOTAL_FINDINGS:
            break
    # inventory: the original tree layout, bounded, one finding per map
    entries = [src for src in source_map.sources if src][:_MAX_INVENTORY_ENTRIES]
    if entries:
        summary = f"{len(entries)} original source files shipped with the map"
        findings.append(
            SourceMapFinding(
                kind="source_inventory",
                detail=summary,
                source_file="(map)",
                line=0,
                thumb=_thumb("\n".join(entries)),
                preview=_preview(entries[0]),
            )
        )
    return findings[:_MAX_TOTAL_FINDINGS]

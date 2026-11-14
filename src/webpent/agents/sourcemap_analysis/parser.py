"""Source-map v3 parser: VLQ decode + generated→original resolution.

(V2 §3, 2026-10-29.) Stdlib-only. A source map is the deployed bundle's
debugging file; when operators ship it, the ORIGINAL TypeScript/JS sources
ride along in ``sourcesContent``. This module parses the map and can
attribute any generated position back to an original file/line — the same
work a real hunter does when they open ``/app.js.map`` in a browser.

Fail-closed rules:
  * only ``version: 3`` maps parse; anything else raises SourceMapError,
  * ``max_sources`` bounds the sources array — an oversized map is refused,
    never truncated silently,
  * ``max_content_chars`` bounds the total sourcesContent bytes kept,
  * malformed VLQ, truncated segments, or out-of-range indices are errors,
    never a partial tree.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

__all__ = [
    "SourceMap",
    "SourceMapError",
    "decode_vlq_segment",
    "parse_source_map",
    "resolve_position",
]

_B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_INDEX = {c: i for i, c in enumerate(_B64_CHARS)}

_MAX_MAPPINGS_CHARS = 8_000_000


class SourceMapError(ValueError):
    """A source map is malformed, unsupported, or over budget."""


@dataclass(frozen=True)
class SourceMap:
    """A parsed, bounded source map."""

    version: int
    sources: tuple[str, ...]
    sources_content: tuple[str | None, ...]
    mappings: str

    @property
    def total_content_chars(self) -> int:
        return sum(len(c) for c in self.sources_content if c)


@dataclass(frozen=True)
class ResolvedPosition:
    """Where a generated position really came from."""

    source_index: int
    source: str
    original_line: int  # 1-based, like the spec
    original_column: int  # 0-based, like the spec


def decode_vlq_segment(segment: str) -> list[int]:
    """Decode one VLQ segment (the comma-free part of a mappings line)."""
    values: list[int] = []
    shift = 0
    value = 0
    for char in segment:
        digit = _B64_INDEX.get(char)
        if digit is None:
            raise SourceMapError(f"invalid base64 VLQ character: {char!r}")
        continuation = digit & 32
        digit &= 31
        value += digit << shift
        if continuation:
            shift += 5
            continue
        # sign bit is the LSB of the accumulated value
        negative = value & 1
        value >>= 1
        values.append(-value if negative else value)
        shift = 0
        value = 0
    if shift != 0:
        raise SourceMapError("truncated VLQ segment (dangling continuation)")
    return values


def _decode_mappings(mappings: str) -> list[list[tuple[int, int, int, int, int]]]:
    """Decode ``mappings`` into per-generated-line absolute segments.

    Each segment is ``(generated_col, src_index, orig_line, orig_col,
    name_index)`` with 0-based generated/original lines (the spec's
    original lines are 0-based internally; +1 on presentation). Relative
    deltas are accumulated per the v3 spec: src_index/orig_line/name
    deltas carry across the whole map, generated_col and orig_col reset
    per line.
    """
    if len(mappings) > _MAX_MAPPINGS_CHARS:
        raise SourceMapError("mappings string exceeds the decode budget")
    lines: list[list[tuple[int, int, int, int, int]]] = []
    src_index = 0
    orig_line = 0
    orig_col = 0
    name_index = 0
    for mappings_line in mappings.split(";"):
        segments: list[tuple[int, int, int, int, int]] = []
        gen_col = 0
        if mappings_line:
            for raw in mappings_line.split(","):
                if not raw:
                    continue
                fields = decode_vlq_segment(raw)
                if not fields:
                    continue
                if len(fields) == 1:
                    gen_col += fields[0]
                    segments.append((gen_col, -1, -1, -1, -1))
                    continue
                if len(fields) not in (4, 5):
                    raise SourceMapError(f"VLQ segment with {len(fields)} fields")
                gen_col += fields[0]
                src_index += fields[1]
                orig_line += fields[2]
                orig_col += fields[3]
                name = 0
                if len(fields) == 5:
                    name_index += fields[4]
                    name = name_index
                segments.append((gen_col, src_index, orig_line, orig_col, name))
        lines.append(segments)
    return lines


def parse_source_map(
    json_text: str, *, max_sources: int, max_content_chars: int
) -> SourceMap:
    """Parse a ``.map`` JSON document under hard budgets."""
    if int(max_sources) < 1 or int(max_content_chars) < 1:
        raise SourceMapError("max_sources and max_content_chars must be >= 1 (fail-closed)")
    try:
        raw = json.loads(str(json_text))
    except json.JSONDecodeError as exc:
        raise SourceMapError(f"map is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise SourceMapError("map root is not an object")
    version = raw.get("version")
    if version != 3:
        raise SourceMapError(f"unsupported source map version: {version!r} (only 3)")
    sources_raw = raw.get("sources")
    if not isinstance(sources_raw, list):
        raise SourceMapError("map has no sources array")
    if len(sources_raw) > int(max_sources):
        raise SourceMapError(
            f"map has {len(sources_raw)} sources, ceiling is {max_sources} — refusing"
        )
    sources: list[str] = []
    for entry in sources_raw:
        sources.append(entry if isinstance(entry, str) else "<non-string-source>")
    content_raw = raw.get("sourcesContent")
    contents: list[str | None] = []
    total = 0
    if isinstance(content_raw, list):
        if len(content_raw) > len(sources):
            raise SourceMapError("sourcesContent longer than sources")
        for entry in content_raw:
            if entry is None or not isinstance(entry, str):
                contents.append(None)
                continue
            total += len(entry)
            if total > int(max_content_chars):
                raise SourceMapError(
                    f"sourcesContent exceeds {max_content_chars} chars — refusing"
                )
            contents.append(entry)
    while len(contents) < len(sources):
        contents.append(None)
    mappings = raw.get("mappings")
    if not isinstance(mappings, str):
        raise SourceMapError("map has no mappings string")
    # decode eagerly: a malformed mappings string is a refusal, not a
    # lazy surprise later
    _decode_mappings(mappings)
    return SourceMap(
        version=3,
        sources=tuple(sources),
        sources_content=tuple(contents),
        mappings=mappings,
    )


class _MappingIndex:
    """Decoded mappings with a binary search per generated line."""

    def __init__(self, mappings: str) -> None:
        self._lines = _decode_mappings(mappings)

    def resolve(self, generated_line: int, generated_column: int) -> tuple[int, int, int] | None:
        """Best segment at or before the column; None when the line is
        unmapped or precedes any mapping."""
        if generated_line < 0 or generated_line >= len(self._lines):
            return None
        segments = self._lines[generated_line]
        if not segments:
            return None
        low, high = 0, len(segments) - 1
        chosen: tuple[int, int, int, int, int] | None = None
        while low <= high:
            mid = (low + high) // 2
            if segments[mid][0] <= generated_column:
                chosen = segments[mid]
                low = mid + 1
            else:
                high = mid - 1
        if chosen is None:
            return None
        _gen_col, src_index, orig_line, orig_col, _name = chosen
        if src_index < 0:
            return None
        return src_index, orig_line, orig_col


def resolve_position(
    source_map: SourceMap, generated_line: int, generated_column: int
) -> ResolvedPosition | None:
    """Map a generated (0-based line? no — 1-based line, 0-based column)
    position back to its original source. Returns None when unmapped."""
    # callers pass 1-based lines (as in stack traces); the wire format is
    # 0-based, so shift here once, internally.
    index = _MappingIndex(source_map.mappings)
    resolved = index.resolve(int(generated_line) - 1, int(generated_column))
    if resolved is None:
        return None
    src_index, orig_line, orig_col = resolved
    if src_index >= len(source_map.sources):
        return None
    return ResolvedPosition(
        source_index=src_index,
        source=source_map.sources[src_index],
        original_line=orig_line + 1,
        original_column=orig_col,
    )

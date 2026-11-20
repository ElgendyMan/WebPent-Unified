"""Source-map exposure analysis (PROPOSALS_ULTIMATE_V2 §3, 2026-10-29).

Flag-gated (enable_source_maps, default False). Parses shipped ``.map``
files (JSON v3), decodes the VLQ mappings, and scans ``sourcesContent``
(the developers' ORIGINAL sources) for secrets and inventory leaks.
All parsing is stdlib-only and fail-closed on malformed or oversized maps.
"""

from .agent import SourceMapAgent, SourceMapResult, SourceMapSkip, build_source_map_agent, extract_source_map_url, sourcemap_node
from .parser import SourceMap, SourceMapError, decode_vlq_segment, parse_source_map, resolve_position
from .secrets import SourceMapFinding, scan_sources

__all__ = [
    "SourceMap",
    "SourceMapAgent",
    "SourceMapError",
    "SourceMapFinding",
    "SourceMapResult",
    "build_source_map_agent",
    "decode_vlq_segment",
    "parse_source_map",
    "resolve_position",
    "scan_sources",
]

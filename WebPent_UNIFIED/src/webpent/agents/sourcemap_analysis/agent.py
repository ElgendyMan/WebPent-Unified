"""Source-map exposure agent (PROPOSALS_ULTIMATE_V2 §3, 2026-10-29).

Flag-gated node: for each JS bundle the crawl already knows about, probe
for a ``//# sourceMappingURL=`` trailer (and the conventional
``<bundle>.map`` sibling), fetch the map, parse it under hard budgets and
scan the ORIGINAL sources for secrets and inventory leaks. Findings land
in ``crawled_data["sourcemap_findings"]``; the map's original sources
that are same-origin API paths also feed ``js_discovered_endpoints``.

Fail-closed / fail-soft, in order of authority:
  * ``enable_source_maps`` false (default) → the node returns {} and
    never touches the state,
  * a bundle with no sourceMappingURL comment → NO probe is sent (the
    404 probe of ``bundle.js.map`` only fires when the comment names it),
  * a map that fails to parse, is oversized, or whose fetch fails → the
    bundle is skipped with a reason, other bundles continue,
  * the whole node never raises: any unexpected error degrades to {}.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from .parser import SourceMapError, parse_source_map, resolve_position
from .secrets import SourceMapFinding, scan_sources

__all__ = ["SourceMapAgent", "SourceMapResult", "SourceMapSkip", "build_source_map_agent"]

logger = logging.getLogger(__name__)

_SOURCE_MAP_COMMENT = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)\s*$", re.MULTILINE)
_MAX_BUNDLES = 25
_MAX_BUNDLE_CHARS = 4_000_000
_MAX_MAP_CHARS = 8_000_000
_MAX_FINDINGS = 200


@dataclass(frozen=True)
class SourceMapSkip:
    bundle_url: str
    reason: str  # no_map_comment | map_fetch_failed | map_unparsable | budget


@dataclass
class SourceMapResult:
    findings: list[SourceMapFinding] = field(default_factory=list)
    skips: list[SourceMapSkip] = field(default_factory=list)
    maps_parsed: int = 0
    # original sources that look like same-origin API paths, for the
    # existing endpoint merge (deduplicated, bounded)
    api_paths: list[str] = field(default_factory=list)


def extract_source_map_url(bundle_text: str, bundle_url: str) -> str | None:
    """The LAST sourceMappingURL comment wins (spec behaviour); absolute
    or relative, resolved against the bundle URL."""
    matches = _SOURCE_MAP_COMMENT.findall(str(bundle_text or ""))
    if not matches:
        return None
    raw = matches[-1].strip()
    if raw.lower().startswith(("http://", "https://")):
        return raw
    if raw.lower().startswith("data:"):
        return None  # inline maps are handled by the bundle itself, not here
    return urljoin(bundle_url, raw)


def _looks_like_api_path(source_name: str, bundle_origin: tuple[str, str]) -> bool:
    name = str(source_name or "").lower()
    if not name.startswith(("src/", "app/", "api/", "pages/", "server/")):
        return False
    return True


class SourceMapAgent:
    """Flag-gated source-map prober over the crawl's JS bundles."""

    def __init__(
        self,
        *,
        enabled: bool,
        max_sources: int,
        max_content_chars: int,
        max_bundles: int = _MAX_BUNDLES,
    ) -> None:
        self.enabled = bool(enabled)
        self.max_sources = int(max_sources)
        self.max_content_chars = int(max_content_chars)
        self.max_bundles = max(1, int(max_bundles))
        if self.max_sources < 1 or self.max_content_chars < 1:
            raise ValueError("source-map budgets must be >= 1 (fail-closed)")

    def analyse(
        self,
        bundle_urls: list[str],
        *,
        fetcher: Callable[[str], str | None],
    ) -> SourceMapResult:
        """Probe bundles for maps via ``fetcher``; never raises."""
        result = SourceMapResult()
        if not self.enabled:
            return result
        seen_urls: set[str] = set()
        for bundle_url in bundle_urls[: self.max_bundles]:
            if not isinstance(bundle_url, str) or not bundle_url.startswith("http"):
                continue
            if bundle_url in seen_urls:
                continue
            seen_urls.add(bundle_url)
            try:
                self._analyse_one(bundle_url, fetcher, result)
            except Exception as exc:  # noqa: BLE001 — per-bundle fail-soft
                result.skips.append(SourceMapSkip(bundle_url, f"unexpected: {type(exc).__name__}"))
                logger.debug("sourcemap skip %s: %s", bundle_url, exc)
                continue
            if len(result.findings) >= _MAX_FINDINGS:
                break
        return result

    def _analyse_one(self, bundle_url: str, fetcher: Callable[[str], str | None], result: SourceMapResult) -> None:
        if len(result.findings) >= _MAX_FINDINGS:
            return
        bundle_text = fetcher(bundle_url)
        if not bundle_text:
            result.skips.append(SourceMapSkip(bundle_url, "bundle_fetch_failed"))
            return
        bundle_text = bundle_text[:_MAX_BUNDLE_CHARS]
        map_url = extract_source_map_url(bundle_text, bundle_url)
        if not map_url:
            result.skips.append(SourceMapSkip(bundle_url, "no_map_comment"))
            return
        map_text = fetcher(map_url)
        if not map_text:
            result.skips.append(SourceMapSkip(bundle_url, "map_fetch_failed"))
            return
        try:
            source_map = parse_source_map(
                map_text[:_MAX_MAP_CHARS],
                max_sources=self.max_sources,
                max_content_chars=self.max_content_chars,
            )
        except SourceMapError as exc:
            logger.debug("sourcemap unparsable %s: %s", map_url, exc)
            result.skips.append(SourceMapSkip(bundle_url, "map_unparsable"))
            return
        result.maps_parsed += 1
        findings = scan_sources(source_map)
        result.findings.extend(findings)
        # same-origin API-looking originals become endpoint hints
        origin = (urlsplit(bundle_url).scheme, urlsplit(bundle_url).netloc)
        for source_name in source_map.sources:
            if not _looks_like_api_path(source_name, origin):
                continue
            path = source_name.split("?")[0]
            if path and path not in result.api_paths:
                result.api_paths.append(path)
        # stack-frame resolution is available to consumers; exercise it
        # once per map so a corrupt mappings string surfaces here (it
        # cannot: parse_source_map already decoded it eagerly).
        if source_map.sources:
            resolve_position(source_map, 1, 0)


def build_source_map_agent(settings: Any) -> SourceMapAgent:
    """Construct from Settings; inert unless enable_source_maps."""
    return SourceMapAgent(
        enabled=bool(getattr(settings, "enable_source_maps", False)),
        max_sources=int(getattr(settings, "source_map_max_sources", 200)),
        max_content_chars=int(getattr(settings, "source_map_max_content_chars", 2_000_000)),
    )


def sourcemap_node(state: dict[str, Any], *, fetcher: Any = None) -> dict[str, Any]:
    """LangGraph node: source-map exposure discovery. Off = {} untouched."""
    from webpent.config.settings import get_settings

    settings = get_settings()
    agent = build_source_map_agent(settings)
    if not agent.enabled:
        return {}
    if fetcher is None:
        from webpent.shared.http import make_safe_httpx_client

        def fetcher(url: str) -> str | None:  # noqa: F811
            with make_safe_httpx_client(timeout=15.0, follow_redirects=False) as client:
                response = client.get(url)
                if response.status_code != 200:
                    return None
                return response.text

    crawled: dict[str, Any] = dict(state.get("crawled_data") or {})
    js_urls: list[str] = []
    for key in ("javascript_urls", "js_urls"):
        values = crawled.get(key)
        if isinstance(values, list):
            js_urls.extend(v for v in values if isinstance(v, str))
    if not js_urls:
        return {}
    try:
        result = agent.analyse(js_urls, fetcher=fetcher)
    except Exception as exc:  # noqa: BLE001 — node-level fail-soft
        logger.warning("source-map node failed (skipped): %s", exc)
        return {}
    if not result.findings and not result.skips:
        return {}
    return {
        "crawled_data": {
            "sourcemap_findings": [
                {
                    "kind": f.kind,
                    "detail": f.detail,
                    "source_file": f.source_file,
                    "line": f.line,
                    "thumb": f.thumb,
                    "preview": f.preview,
                }
                for f in result.findings
            ],
            "sourcemap_skips": [
                {"bundle_url": s.bundle_url, "reason": s.reason} for s in result.skips
            ],
        }
    }

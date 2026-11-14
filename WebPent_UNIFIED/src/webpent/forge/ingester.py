"""U-FORGE-1 — The Multi-Source Ingester.

Parses PRE-FETCHED content only: the caller (a scheduled, supervised
external task) hands content in as strings, so the core performs zero
live network I/O (FORGE-L-1 INGEST_DONT_INVENT, L-9
SCHEDULED_INGESTION). Every payload keeps its license and attribution
(FORGE-L-7); nothing is invented — a line that parses as a payload is
stored, everything else is dropped.
"""
from __future__ import annotations

import json
import re
from typing import Callable

from webpent.forge.normalizer import Normalizer
from webpent.forge.schemas import IngestReport, NormalizedPayload
from webpent.forge.sources import get_source

_FENCE_RE = re.compile(r"```[a-zA-Z0-9_-]*\n(.*?)```", re.DOTALL)
_HEADING_RE = re.compile(r"^(#{1,3})\s+(.+)$", re.MULTILINE)


def _markdown_section_heading(content: str, position: int) -> str:
    """Nearest `#` heading before position, lowercased."""
    heading = ""
    for match in _HEADING_RE.finditer(content[:position]):
        heading = match.group(2).lower()
    return heading


class MultiSourceIngester:
    """Parses the 8 registered sources; stores through the indexer."""

    def __init__(self, indexer) -> None:
        self._indexer = indexer
        self._normalizer = Normalizer()
        self._parsers: dict[str, Callable[[str, str], list[str]]] = {
            "payloadsallthethings": self.parse_payloadsallthethings,
            "hacktricks": self.parse_hacktricks,
            "seclists": self.parse_seclists,
            "hackerone_disclosures": self.parse_hackerone_disclosures,
            "exploitdb": self.parse_exploitdb,
            "nvd": self.parse_api_descriptions,
            "pentest_cheatsheets": self.parse_markdown_fenced,
            "waf_bypass_lists": self.parse_markdown_fenced,
        }

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def ingest(self, source_id: str, *, content: str,
               dry_run: bool = True) -> IngestReport:
        source = get_source(source_id)
        lines: list[tuple[str, str]] = self._parsers[source_id](content, "")
        lines = [(raw.strip(), subfamily) for raw, subfamily in lines
                 if raw.strip()]
        payloads: list[NormalizedPayload] = []
        seen: set[str] = set()
        duplicates = 0
        for raw, subfamily in lines:
            if raw.startswith("#"):
                continue
            payload_id = self._normalizer.payload_id(raw)
            if payload_id in seen:
                duplicates += 1
                continue
            seen.add(payload_id)
            payloads.append(self._normalizer.normalize(
                raw, self._attribution_for(source_id), subfamily=subfamily))
        found = len(lines) - sum(
            1 for raw, _ in lines if raw.startswith("#"))
        stored = 0
        if not dry_run:
            for payload in payloads:
                if self._indexer.store_payload(payload):
                    stored += 1
        return IngestReport(
            source_id=source_id,
            payloads_found=found,
            payloads_stored=stored,
            duplicates_removed=duplicates,
            source_trust=source.trust_score,
            payloads=payloads,
        )

    def _attribution_for(self, source_id: str):
        from webpent.forge.schemas import PayloadAttribution
        source = get_source(source_id)
        return PayloadAttribution(
            payload_id="pending",
            original_source=source.source_id,
            original_url=source.url,
            original_author=None,
            license=source.license,
            license_url=source.license_url,
            source_trust=source.trust_score,
        )

    # ------------------------------------------------------------------
    # Parsers (one per source shape)
    # ------------------------------------------------------------------

    @staticmethod
    def parse_markdown_fenced(content: str, _hint: str) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for match in _FENCE_RE.finditer(content):
            section = _markdown_section_heading(content[:match.start()],
                                                match.start())
            for line in match.group(1).splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    pairs.append((line, section))
        return pairs

    def parse_payloadsallthethings(self, content: str, _hint: str):
        return self.parse_markdown_fenced(content, _hint)

    def parse_hacktricks(self, content: str, _hint: str):
        return self.parse_markdown_fenced(content, _hint)

    def parse_seclists(self, content: str, _hint: str) -> list[tuple[str, str]]:
        return [(line.strip(), "")
                for line in content.splitlines() if line.strip()]

    def parse_hackerone_disclosures(self, content: str,
                                    _hint: str) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        items = json.loads(content)
        for item in items:
            weakness = str(item.get("weakness", "")).lower()
            subfamily = weakness.replace(" ", "_") or "disclosure"
            for match in _FENCE_RE.finditer(str(item.get("body", ""))):
                for line in match.group(1).splitlines():
                    line = line.strip()
                    if line:
                        pairs.append((line, subfamily))
            for line in str(item.get("body", "")).splitlines():
                line = line.strip()
                if line and not line.startswith("```") \
                        and not line.startswith("#") \
                        and self._looks_like_payload(line):
                    pairs.append((line, subfamily))
        return pairs

    def parse_exploitdb(self, content: str, _hint: str) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            columns = line.split("|")
            payload = columns[-1].strip()
            description = columns[2].strip().lower() if len(columns) >= 4 else ""
            if payload:
                pairs.append((payload, description.replace(" ", "_")))
        return pairs

    def parse_api_descriptions(self, content: str,
                               _hint: str) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for line in content.splitlines():
            line = line.strip()
            if line and self._looks_like_payload(line):
                pairs.append((line, "cve"))
        return pairs

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_payload(line: str) -> bool:
        """A conservative, documented heuristic (L-1: ingest, don't
        invent): lines that are prose are dropped, lines carrying
        classic payload syntax are kept."""
        markers = ("'", "\"", "<", "://", "../", "%", "${", "SELECT")
        return any(m in line for m in markers) and len(line) <= 500

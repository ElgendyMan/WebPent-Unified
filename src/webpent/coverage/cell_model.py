# src/webpent/coverage/cell_model.py
"""Coverage-cell model (2026-10-25 proposals, Proposal 2).

A coverage cell is the smallest addressable unit of attack surface:
(URL template, HTTP method, parameter-name set, vuln-class family).
Campaigns become measurable when surface is countable: "خلايا مكتشفة /
مغطاة / متبقية" are the numbers the scheduler and the plateau detector
work on.

Generalization rule: path segments that look like identifiers (all
digits, UUID-shaped, or long hex) collapse to ``{id}`` so
``/api/users/42`` and ``/api/users/99`` are ONE cell, not two. Query
strings contribute parameter NAMES only (never values — values are
payload data and must not become cell identity).

Pure functions only: everything here derives from an explicit state
mapping and never executes requests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

_UUIDISH = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEXISH = re.compile(r"^[0-9a-fA-F]{12,}$")


@dataclass(frozen=True)
class CoverageCell:
    """One addressable unit of attack surface."""

    url_template: str
    method: str = "GET"
    param_names: frozenset[str] = field(default=frozenset())
    vuln_class: str = ""

    @property
    def key(self) -> str:
        """Deterministic identity for dedup, ordering, and ledger keys."""
        params = ",".join(sorted(self.param_names))
        vuln = self.vuln_class or "-"
        return f"{self.method.upper()} {self.url_template} [{params}] {{{vuln}}}"


def generalize_url(url: str) -> str:
    """Collapse identifier-looking path segments to ``{id}`` (deterministic)."""
    try:
        parts = urlsplit(str(url))
    except Exception:
        return str(url)
    path = parts.path or "/"
    segments: list[str] = []
    for raw in path.split("/"):
        seg = raw
        if seg and (seg.isdigit() or _UUIDISH.match(seg) or _HEXISH.match(seg)):
            seg = "{id}"
        segments.append(seg)
    generalized = "/".join(segments) or "/"
    if (parts.netloc or "") and generalized != "/":
        return f"{parts.scheme or 'http'}://{parts.netloc.lower()}{generalized}"
    return generalized


def _param_names_of(url: str) -> frozenset[str]:
    try:
        query = urlsplit(str(url)).query
    except Exception:
        return frozenset()
    names: set[str] = set()
    for chunk in query.split("&"):
        if chunk:
            names.add(chunk.split("=", 1)[0])
    return frozenset(names)


def build_cells(state: Mapping[str, Any]) -> tuple[CoverageCell, ...]:
    """Derive the campaign's coverage cells from explicit state data.

    Sources (all explicit campaign outputs, never inference):
      * ``crawled_data["endpoints"]`` — discovered URL strings;
      * ``findings`` — a finding's URL + vuln class pair becomes a
        class-scoped cell so scheduler yield can be computed per family;
      * ``campaign_ledger["entries"]`` / ``campaign_task_outcomes`` —
        keys look like ``METHOD path`` and carry a vuln class.

    Deterministic: same state -> same cells, sorted by key.
    """
    cells: dict[str, CoverageCell] = {}

    crawled = state.get("crawled_data") if isinstance(state, Mapping) else None
    endpoints = []
    if isinstance(crawled, Mapping):
        raw_endpoints = crawled.get("endpoints")
        if isinstance(raw_endpoints, (list, tuple)):
            endpoints.extend(str(u) for u in raw_endpoints if u)

    for url in endpoints:
        cell = CoverageCell(
            url_template=generalize_url(url),
            method="GET",
            param_names=_param_names_of(url),
        )
        cells.setdefault(cell.key, cell)

    findings = state.get("findings") if isinstance(state, Mapping) else None
    if isinstance(findings, (list, tuple)):
        for finding in findings:
            if not isinstance(finding, Mapping):
                continue
            vuln_raw = finding.get("vuln_class")
            vuln = getattr(vuln_raw, "value", None) or (
                str(vuln_raw) if vuln_raw is not None else ""
            )
            url = str(finding.get("url") or finding.get("evidence", {}).get("url") or "")
            if not url or not vuln:
                continue
            cell = CoverageCell(
                url_template=generalize_url(url),
                method=str(finding.get("method") or "GET").upper(),
                param_names=_param_names_of(url),
                vuln_class=vuln,
            )
            cells.setdefault(cell.key, cell)

    ledger = state.get("campaign_ledger") if isinstance(state, Mapping) else None
    entries = []
    if isinstance(ledger, Mapping):
        entries.extend(ledger.get("entries") or [])
    if isinstance(state, Mapping):
        entries.extend(state.get("campaign_task_outcomes") or [])
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        vuln_raw = entry.get("vulnerability_class") or entry.get("campaign_key") or ""
        vuln = str(vuln_raw)
        if not vuln:
            continue
        key = str(entry.get("campaign_key") or vuln)
        method, _, path = key.partition(" ")
        url_template = generalize_url(path) if path.startswith("/") else path
        cell = CoverageCell(
            url_template=url_template or "/",
            method=method.upper() if method else "GET",
            vuln_class=vuln,
        )
        cells.setdefault(cell.key, cell)

    return tuple(sorted(cells.values(), key=lambda c: c.key))


__all__ = ["CoverageCell", "build_cells", "generalize_url"]

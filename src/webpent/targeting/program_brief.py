# src/webpent/targeting/program_brief.py
"""Program brief (PROPOSALS_ULTIMATE_V2 §10, 2026-10-30).

An operator-supplied description of ONE bug-bounty program: its scope
(wildcard host patterns), its explicit out-of-scope list, its bounty
table, and free-form notes. The brief is IMPORTED BY HAND from the
operator (JSON file or a simple Markdown layout) — nothing here crawls
a platform or fetches program pages: program data arrives only because
a human put it in front of the framework.

Fail-closed: a brief without a scope section (or with an empty scope)
is a hard refusal — a selector that ranks targets it cannot scope-check
would recommend out-of-program work. The scope ENFORCER stays the final
judge over any request; the brief only informs selection.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "ProgramBriefError",
    "ProgramBrief",
    "load_program_brief",
    "matches_scope",
    "expected_bounty",
]


class ProgramBriefError(ValueError):
    """Raised when a program brief cannot be loaded fail-closed."""


@dataclass
class ProgramBrief:
    """One bug-bounty program, as supplied by the operator."""

    name: str
    scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    # vuln class (lowercased) -> expected bounty
    bounties: dict[str, float] = field(default_factory=dict)
    default_bounty: float = 0.0
    notes: list[str] = field(default_factory=list)
    source: str = ""


_SCOPE_SECTION = re.compile(
    r"^#{1,4}\s*(?:in\s+scope|scope)\s*$", re.IGNORECASE | re.MULTILINE
)
_OUT_SECTION = re.compile(
    r"^#{1,4}\s*(?:out\s+of\s+scope|out-of-scope|exclusions?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_BOUNTY_SECTION = re.compile(
    r"^#{1,4}\s*(?:bounty(?:\s+table)?|rewards?)\s*$", re.IGNORECASE | re.MULTILINE
)
_NOTES_SECTION = re.compile(
    r"^#{1,4}\s*(?:notes?|description)\s*$", re.IGNORECASE | re.MULTILINE
)
_HEADING = re.compile(r"^#{1,4}\s+(.*?)\s*$", re.MULTILINE)
_BULLET = re.compile(r"^\s*[-*+]\s+(.*)$")
_BOUNTY_LINE = re.compile(
    r"^\s*`?([\w .\-/]+?)`?\s*[:=]\s*(?:\$|USD\s*)?([0-9][0-9_,]*)\s*$"
)


def _sections(text: str) -> dict[str, list[str]]:
    """Split a Markdown brief into {heading_lower: [bullet/line texts]}."""
    out: dict[str, list[str]] = {}
    current: str | None = None
    for raw in text.splitlines():
        head = _HEADING.match(raw)
        if head:
            current = head.group(1).strip().lower()
            out.setdefault(current, [])
            continue
        if current is None:
            continue
        m = _BULLET.match(raw)
        line = m.group(1).strip() if m else raw.strip()
        if line:
            out[current].append(line)
    return out


def _find_section(sections: dict[str, list[str]], pattern: re.Pattern[str]) -> list[str]:
    for name, lines in sections.items():
        if pattern.match(f"## {name}"):
            return lines
    return []


def _parse_markdown(text: str, *, source: str) -> ProgramBrief:
    sections = _sections(text)
    name_match = re.search(r"^#\s+(.+?)\s*$", text, re.MULTILINE)
    scope = [
        ln
        for ln in _find_section(sections, _SCOPE_SECTION)
        if not ln.startswith("`") or "`" in ln[1:]
    ]
    # Strip markdown backticks around hosts: `*.example.com` -> *.example.com
    scope = [ln.strip("` ") for ln in scope]
    out_of_scope = [ln.strip("` ") for ln in _find_section(sections, _OUT_SECTION)]
    bounties: dict[str, float] = {}
    for line in _find_section(sections, _BOUNTY_SECTION):
        m = _BOUNTY_LINE.match(line)
        if m:
            cls = m.group(1).strip().lower()
            amount = float(m.group(2).replace(",", "").replace("_", ""))
            bounties[cls] = amount
    notes = _find_section(sections, _NOTES_SECTION)
    if not scope:
        raise ProgramBriefError("program_brief_no_scope")
    return ProgramBrief(
        name=(name_match.group(1) if name_match else Path(source).stem),
        scope=scope,
        out_of_scope=out_of_scope,
        bounties=bounties,
        notes=notes,
        source=source,
    )


def _parse_json(data: bytes, *, source: str) -> ProgramBrief:
    try:
        doc = json.loads(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ProgramBriefError(f"program_brief_invalid_encoding: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ProgramBriefError(f"program_brief_invalid_json: {exc}") from exc
    if not isinstance(doc, dict):
        raise ProgramBriefError("program_brief_schema: top level must be an object")
    scope = doc.get("scope")
    if not isinstance(scope, list) or not scope:
        raise ProgramBriefError("program_brief_no_scope")
    if not all(isinstance(s, str) and s.strip() for s in scope):
        raise ProgramBriefError("program_brief_schema: scope entries must be non-empty strings")
    oos = doc.get("out_of_scope", [])
    if not isinstance(oos, list) or not all(isinstance(s, str) for s in oos):
        raise ProgramBriefError("program_brief_schema: out_of_scope must be a list of strings")
    bounties = doc.get("bounties", {})
    if not isinstance(bounties, dict) or not all(
        isinstance(k, str) and isinstance(v, (int, float)) for k, v in bounties.items()
    ):
        raise ProgramBriefError(
            "program_brief_schema: bounties must map vuln-class strings to numbers"
        )
    default_bounty = doc.get("default_bounty", 0.0)
    if not isinstance(default_bounty, (int, float)):
        raise ProgramBriefError("program_brief_schema: default_bounty must be a number")
    notes = doc.get("notes", [])
    if not isinstance(notes, list) or not all(isinstance(n, str) for n in notes):
        raise ProgramBriefError("program_brief_schema: notes must be a list of strings")
    name = doc.get("name")
    if name is not None and not isinstance(name, str):
        raise ProgramBriefError("program_brief_schema: name must be a string")
    return ProgramBrief(
        name=name or Path(source).stem,
        scope=[str(s).strip() for s in scope],
        out_of_scope=[str(s).strip() for s in oos],
        bounties={str(k).lower(): float(v) for k, v in bounties.items()},
        default_bounty=float(default_bounty),
        notes=[str(n) for n in notes],
        source=source,
    )


def load_program_brief(path: str | Path) -> ProgramBrief:
    """Load an operator-supplied program brief (JSON or Markdown).

    Fail-closed refusals: ``program_brief_unreadable``,
    ``program_brief_invalid_json`` / ``program_brief_invalid_encoding``,
    ``program_brief_schema:*``, and ``program_brief_no_scope`` (a brief
    that declares no scope, or an empty one).
    """
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ProgramBriefError(f"program_brief_unreadable: {exc}") from exc
    text_l = p.name.lower()
    if text_l.endswith(".json") or (not text_l.endswith((".md", ".markdown", ".txt"))):
        return _parse_json(data, source=str(p))
    # Markdown / text: sniff — a leading '{' is still JSON.
    if data.lstrip().startswith(b"{"):
        return _parse_json(data, source=str(p))
    try:
        md = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProgramBriefError(f"program_brief_invalid_encoding: {exc}") from exc
    return _parse_markdown(md, source=str(p))


def _host_of(candidate: str) -> str:
    """Extract the comparable host from a URL or bare host pattern."""
    text = str(candidate).strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    text = text.split("@", 1)[-1]  # strip credentials
    text = text.split(":", 1)[0]  # strip port
    return text.lower()


def matches_scope(host_or_url: str, brief: ProgramBrief) -> bool:
    """Scope check against the brief (selection-level only).

    Wildcard patterns are fnmatch-style over the HOST
    (``*.example.com`` matches ``api.example.com`` but NOT
    ``example.com`` itself unless the bare domain is also listed).
    The out-of-scope list overrides any scope match. This NEVER
    replaces the scope enforcer — it only pre-filters recommendations.
    """
    host = _host_of(host_or_url)
    if not host:
        return False
    for pattern in brief.out_of_scope:
        if fnmatch.fnmatch(host, _host_of(pattern)):
            return False
    for pattern in brief.scope:
        if fnmatch.fnmatch(host, _host_of(pattern)):
            return True
    return False


def expected_bounty(brief: ProgramBrief, vuln_class: str) -> float:
    """Expected bounty for a vuln class (unknown classes -> default).

    Unknown classes fall back to ``default_bounty`` rather than zero
    guesswork in the other direction: an unlisted class is priced at
    the program default, never silently treated as worthless.
    """
    return brief.bounties.get(str(vuln_class or "").lower(), brief.default_bounty)

"""Economist — the scope negotiator (NC-ECON-1, U-ECON-3).

Scope is sacred. The negotiator reads an engagement's scope document
(from a *local file or pasted text* — it never fetches anything, L-2),
parses YAML/JSON/markdown/plain-text entries, and flags every ambiguity
that could later turn an authorized test into an unauthorized one:

* wildcard entries (``*.example.com`` — does it cover deeper subdomains?)
* bare domains without a dot (a TLD alone is never a scope)
* IP ranges / CIDR (which hosts inside the range, exactly?)
* vague qualifiers (``and subsidiaries``, ``related domains``, ``etc``)
* path- or port-only fragments that authorize no host at all

``generate_inquiry`` drafts the clarification questions for the program
owner as *text only*; nothing here sends anything (L-1, L-8). The
resulting analysis carries confidence that falls with every ambiguity
(L-4), and identical input yields identical analysis (L-3).
"""

from __future__ import annotations

import contextlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_SCOPE_ENTRIES = 256
MAX_AMBIGUITIES = 64

WILDCARD_PATTERN = re.compile(r"\*")
CIDR_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")
IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
VAGUE_WORDS = (
    "subsidiaries",
    "related domains",
    "related properties",
    "etc",
    "and others",
    "any domain",
    "associated",
)
FRAGMENT_PATTERN = re.compile(r"^(?:/|(?=.*:)[^/.]*:\d)")


@dataclass
class ScopeAmbiguity:
    """One ambiguity worth a question to the program owner."""

    entry: str
    ambiguity_type: str  # wildcard | bare_domain | cidr | vague_qualifier | fragment
    description: str
    suggested_question: str

    def as_dict(self) -> dict[str, str]:
        return {
            "entry": self.entry,
            "ambiguity_type": self.ambiguity_type,
            "description": self.description,
            "suggested_question": self.suggested_question,
        }


@dataclass
class ScopeAnalysis:
    """Full transparency record of a scope read (L-4)."""

    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    gray_zones: list[str] = field(default_factory=list)
    ambiguities: list[ScopeAmbiguity] = field(default_factory=list)
    inquiry_needed: bool = False
    confidence: float = 1.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "in_scope": list(self.in_scope),
            "out_of_scope": list(self.out_of_scope),
            "gray_zones": list(self.gray_zones),
            "ambiguities": [a.as_dict() for a in self.ambiguities],
            "inquiry_needed": self.inquiry_needed,
            "confidence": round(self.confidence, 3),
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


def _clean_entry(raw: Any) -> str:
    if not isinstance(raw, str):
        return ""
    cleaned = raw.strip()
    # strip a markdown bullet or leading dash
    cleaned = re.sub(r"^[-•]\s*", "", cleaned).strip()
    # drop inline comments after whitespace
    cleaned = cleaned.split("#", 1)[0].strip()
    # strip markdown emphasis/backticks without eating wildcard asterisks
    cleaned = cleaned.strip("`")
    if cleaned.startswith("**") and cleaned.endswith("**"):
        cleaned = cleaned[2:-2]
    elif not cleaned.startswith("*."):
        cleaned = cleaned.strip("*")
    return cleaned[:200]


def parse_scope_entries(scope_source: Any) -> list[str]:
    """Extract candidate scope entries from YAML/JSON/markdown/text.

    Accepts a path, a raw string, or an already-parsed list. Never
    fetches: a path is read from the local filesystem only.
    """
    rows: list[Any] = []
    if isinstance(scope_source, (list, tuple, set)):
        rows = list(scope_source)
        if isinstance(scope_source, set):
            # R2-econ-09: set iteration order is process-dependent
            # (PYTHONHASHSEED); sort so ambiguities and inquiry question
            # numbers stay deterministic (L-3). list/tuple order is kept.
            rows = sorted(rows, key=str)
    elif isinstance(scope_source, (str, Path)):
        text = str(scope_source)
        payload: Any = None
        try:
            path = Path(text)
            raw_text = path.read_text(encoding="utf-8") if path.exists() else text
        except OSError:
            raw_text = text
        stripped = raw_text.strip()
        if stripped.startswith(("[", "{")):
            with contextlib.suppress(ValueError):
                payload = json.loads(stripped)
        if payload is None and ("\n" in stripped or stripped.endswith(":")):
            with contextlib.suppress(Exception):
                import yaml

                payload = yaml.safe_load(stripped)
        if isinstance(payload, dict):
            for key in ("in_scope", "scope", "domains", "entries"):
                if isinstance(payload.get(key), list):
                    rows = list(payload[key])
                    break
            else:
                rows = [v for v in payload.values() if isinstance(v, str)]
        elif isinstance(payload, list):
            rows = payload
        else:
            rows = stripped.splitlines()
    else:
        return []

    entries: list[str] = []
    seen: set[str] = set()
    for row in rows[:MAX_SCOPE_ENTRIES]:
        cleaned = _clean_entry(row)
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            entries.append(cleaned)
    return entries


def _is_domain_like(entry: str) -> bool:
    return bool(re.match(r"^\*?\*?\.?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+\.?$",
                         entry.lower().rstrip("/")))


def detect_ambiguities(entries: list[str]) -> tuple[list[ScopeAmbiguity], list[str]]:
    """Flag ambiguous entries; gray zones are entries kept in scope but flagged."""
    ambiguities: list[ScopeAmbiguity] = []
    gray: list[str] = []
    lowered = [(e, e.lower()) for e in entries]
    for entry, low in lowered:
        if WILDCARD_PATTERN.search(entry):
            ambiguities.append(
                ScopeAmbiguity(
                    entry,
                    "wildcard",
                    "wildcard scope: does it authorize deeper subdomains and all ports?",
                    f"Does '{entry}' cover sub-subdomains and all ports, or only "
                    "first-level subdomains over HTTPS?",
                )
            )
            gray.append(entry)
        elif CIDR_PATTERN.search(entry) or IP_PATTERN.search(entry):
            ambiguities.append(
                ScopeAmbiguity(
                    entry,
                    "cidr",
                    "IP range: which hosts inside the range are authorized?",
                    f"Which exact hosts or services inside '{entry}' are authorized for testing?",
                )
            )
            gray.append(entry)
        elif any(word in low for word in VAGUE_WORDS):
            ambiguities.append(
                ScopeAmbiguity(
                    entry,
                    "vague_qualifier",
                    "vague qualifier: 'related' or 'etc' entries expand without bound",
                    f"Please enumerate the exact hosts covered by '{entry}'.",
                )
            )
            gray.append(entry)
        elif "." not in entry:
            ambiguities.append(
                ScopeAmbiguity(
                    entry,
                    "bare_domain",
                    "no dot: a bare word authorizes no verifiable host",
                    f"'{entry}' has no dot and cannot be verified; what is the exact domain?",
                )
            )
        elif FRAGMENT_PATTERN.search(entry) or (":" in entry and "/" in entry.split(":")[0]):
            ambiguities.append(
                ScopeAmbiguity(
                    entry,
                    "fragment",
                    "path or port fragment authorizes no host by itself",
                    f"'{entry}' names no host; which domain does it belong to?",
                )
            )
    return ambiguities[:MAX_AMBIGUITIES], gray[:MAX_AMBIGUITIES]


class ScopeNegotiator:
    """Parse a scope, surface its ambiguities, draft clarifying questions."""

    def analyze(self, scope_source: Any, *, now: float | None = None) -> ScopeAnalysis:
        entries = parse_scope_entries(scope_source)
        ambiguities, gray = detect_ambiguities(entries)
        flagged = {a.entry for a in ambiguities}
        # ambiguous entries stay gray (potential scope) pending clarification
        gray_zones = sorted(flagged | set(gray))
        in_scope = [e for e in entries if _is_domain_like(e) and e not in flagged]
        out_of_scope = [e for e in entries if e not in in_scope and e not in flagged]

        ambiguity_ratio = len(ambiguities) / len(entries) if entries else 0.0
        confidence = max(0.0, min(1.0, 1.0 - ambiguity_ratio))
        analysis = ScopeAnalysis(
            in_scope=sorted(set(in_scope)),
            out_of_scope=sorted(set(out_of_scope)),
            gray_zones=gray_zones,
            ambiguities=ambiguities,
            inquiry_needed=bool(ambiguities),
            confidence=confidence,
        )
        if now is not None:
            analysis.timestamp = datetime.fromtimestamp(float(now), tz=timezone.utc)
        return analysis

    def generate_inquiry(self, analysis: ScopeAnalysis) -> str:
        """Draft clarification questions as text. Nothing is sent (L-1, L-8)."""
        if not analysis.ambiguities:
            return (
                "No ambiguities detected in the analyzed scope; "
                "no clarification inquiry is needed."
            )
        lines = [
            "Subject: scope clarification before testing begins",
            "",
            "Hello,",
            "",
            "Before we begin, we would like to confirm a few scope details:",
            "",
        ]
        for index, ambiguity in enumerate(analysis.ambiguities, start=1):
            lines.append(f"{index}. {ambiguity.suggested_question}")
        lines += [
            "",
            "We will not touch anything outside your written confirmation.",
            "",
            "Thanks,",
        ]
        return "\n".join(lines)


__all__ = [
    "MAX_SCOPE_ENTRIES",
    "ScopeAmbiguity",
    "ScopeAnalysis",
    "ScopeNegotiator",
    "parse_scope_entries",
]

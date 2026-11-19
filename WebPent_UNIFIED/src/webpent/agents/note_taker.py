"""Persistent sanitized Markdown notes for an active hunter campaign."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from webpent.agents.hunter_contracts import sanitize_text

_SECRET_VALUE = re.compile(r"(?i)(?:bearer\s+|password\s*[:=]|api[_-]?key\s*[:=]|token\s*[:=])[^\s,;]+")
_SECTIONS = (
    "Authentication", "Interesting Endpoints", "Curiosity Flags", "Attempts",
    "Confirmed Findings", "Refuted Attempts", "Hypotheses", "Chains to Explore",
)


@dataclass(frozen=True)
class NoteEntry:
    event_id: str
    role: str
    section: str
    text: str
    reference: str = ""

    def sanitized(self) -> "NoteEntry":
        text = _SECRET_VALUE.sub("[REDACTED_SECRET]", sanitize_text(self.text, 600))
        reference = _SECRET_VALUE.sub("[REDACTED_SECRET]", sanitize_text(self.reference, 220))
        section = self.section if self.section in _SECTIONS else "Attempts"
        return NoteEntry(self.event_id[:100], self.role[:40], section, text, reference)


class NoteTaker:
    """Append-only notes with deterministic event IDs and bounded rendering."""

    def __init__(self, *, campaign_id: str, target: str, path: str | Path | None = None) -> None:
        self.campaign_id = str(campaign_id)[:120]
        self.target = sanitize_text(target, 240)
        self.path = Path(path) if path else None
        self._entries: list[NoteEntry] = []
        self._event_ids: set[str] = set()

    @property
    def entries(self) -> tuple[NoteEntry, ...]:
        return tuple(self._entries)

    def append(self, *, role: str, section: str, text: str, reference: str = "", event_id: str | None = None) -> NoteEntry:
        clean = NoteEntry(
            event_id=event_id or hashlib.sha256(f"{role}|{section}|{text}|{reference}".encode()).hexdigest()[:24],
            role=role,
            section=section,
            text=text,
            reference=reference,
        ).sanitized()
        if clean.event_id in self._event_ids:
            return next(item for item in self._entries if item.event_id == clean.event_id)
        self._event_ids.add(clean.event_id)
        self._entries.append(clean)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(self.render_markdown(), encoding="utf-8")
        return clean

    def extend(self, entries: Iterable[NoteEntry]) -> None:
        for entry in entries:
            self.append(role=entry.role, section=entry.section, text=entry.text, reference=entry.reference, event_id=entry.event_id)

    def search(self, query: str, *, section: str | None = None) -> list[NoteEntry]:
        terms = [term.lower() for term in re.findall(r"[a-z0-9_-]+", str(query or ""))]
        if not terms:
            return []
        return [
            item for item in self._entries
            if (not section or item.section == section)
            and all(term in f"{item.section} {item.role} {item.text} {item.reference}".lower() for term in terms)
        ]

    def render_markdown(self) -> str:
        lines = [f"# Hunt Notes — {self.target}", "", f"- Campaign: `{self.campaign_id}`", "- Content policy: sanitized structural evidence only", ""]
        grouped = {section: [] for section in _SECTIONS}
        for entry in self._entries:
            grouped.setdefault(entry.section, []).append(entry)
        for section in _SECTIONS:
            lines.extend([f"## {section}", ""])
            for entry in grouped.get(section, []):
                suffix = f" ({entry.reference})" if entry.reference else ""
                lines.append(f"- [{entry.role}] {entry.text}{suffix} `event:{entry.event_id}`")
            if not grouped.get(section):
                lines.append("- None recorded.")
            lines.append("")
        return "\n".join(lines)

    def save(self) -> Path | None:
        if not self.path:
            return None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(self.render_markdown(), encoding="utf-8")
        return self.path


__all__ = ["NoteEntry", "NoteTaker"]

"""Deterministic, bounded PayloadsAllTheThings parser and query API.

The upstream repository is treated as data only. Markdown and fenced code are
never executed. Entries are advisory test inputs; existing scope, action,
credential, validator, proof, replay, and promotion authorities remain in
control of execution and trust decisions.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

PARSER_VERSION = "payloads-all-the-things-v1"
MAX_PAYLOAD_LENGTH = 512
MAX_ENTRIES_PER_FILE = 80
MAX_DESCRIPTION_LENGTH = 360
DEFAULT_EXPORT = Path(__file__).resolve().parents[3] / "docs" / "payload_library.json"

_FAMILY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("SQL_INJECTION", ("sql injection", "nosql injection", "graphql injection", "orm leak")),
    ("XSS", ("cross-site scripting", "xss", "dom clobbering")),
    ("IDOR", ("insecure direct object references", "idor")),
    ("OPEN_REDIRECT", ("open redirect", "redirect")),
    ("SSRF", ("server side request forgery", "ssrf", "server-side request forgery", "dns rebinding")),
    ("INFO_DISCLOSURE", ("insecure source code management", "api key leaks", "information disclosure", "debug")),
    ("AUTH_BYPASS", ("account takeover", "authentication", "auth bypass", "json web token")),
)

_FAMILY_ALIASES = {
    "SQLI": "SQL_INJECTION",
    "SQL-INJECTION": "SQL_INJECTION",
    "SQL INJECTION": "SQL_INJECTION",
}


def _canonical_family(value: str | None) -> str:
    key = str(value or "").strip().upper()
    return _FAMILY_ALIASES.get(key, key)


def _family_for_directory(name: str) -> str | None:
    lowered = re.sub(r"[^a-z0-9]+", " ", name.lower()).strip()
    for family, needles in _FAMILY_RULES:
        if any(needle in lowered for needle in needles):
            return family
    return None


def _subtype_for_context(context: str, filename: str, language: str = "") -> str:
    text = f"{context} {filename} {language}".lower()
    rules = (
        ("time_based", ("time", "sleep", "benchmark", "waitfor", "pg_sleep")),
        ("blind", ("blind", "boolean", "true", "false")),
        ("error_based", ("error", "exception", "syntax")),
        ("union", ("union",)),
        ("waf_bypass", ("waf", "bypass", "filter", "encoding")),
        ("auth_bypass", ("auth", "login", "credential", "default")),
        ("polyglot", ("polyglot",)),
        ("attribute_context", ("attribute", "href", "input")),
        ("js_context", ("javascript", "js context", "script")),
        ("cloud_metadata", ("metadata", "aws", "gcp", "azure")),
        ("internal_url", ("internal", "localhost", "loopback")),
        ("file_protocol", ("file protocol", "file://")),
        ("admin_panels", ("admin", "panel", "console")),
        ("config_files", ("config", ".env", "settings")),
        ("api_docs", ("swagger", "openapi", "api documentation")),
        ("git", ("git", ".git")),
        ("sequential", ("sequential", "numeric", "id")),
        ("parameter_swap", ("parameter", "swap", "object")),
        ("method_confusion", ("method", "post", "get")),
    )
    for subtype, needles in rules:
        if any(needle in text for needle in needles):
            return subtype
    return "general"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def _clean_line(line: str) -> str:
    line = re.sub(r"\s+", " ", line.strip())
    return line.strip("` ")


def _is_candidate(line: str) -> bool:
    if not line or len(line) > MAX_PAYLOAD_LENGTH:
        return False
    if line.startswith(("#", "<!--", "[", "|", "- ", "* ")):
        return False
    lowered = line.lower()
    if lowered.startswith(("curl ", "wget ", "python ", "import ", "const ", "function ", "select * from", "<?php")):
        return False
    if re.fullmatch(r"[a-z0-9 _.-]{1,80}", line, re.I) and not re.search(r"[=/?'\"<>:;]|\d", line):
        return False
    return True


def _description(lines: list[str], block_start: int) -> str:
    candidates: list[str] = []
    for line in reversed(lines[max(0, block_start - 8):block_start]):
        cleaned = _clean_line(line)
        if not cleaned or cleaned.startswith(("#", ">", "-", "*", "|", "```")):
            continue
        if len(cleaned) >= 20:
            candidates.append(cleaned)
            break
    return candidates[0][:MAX_DESCRIPTION_LENGTH] if candidates else ""


def _fenced_blocks(text: str) -> Iterable[tuple[str, int, list[str]]]:
    lines = text.splitlines()
    in_block = False
    language = ""
    start = 0
    block: list[str] = []
    for index, line in enumerate(lines):
        match = re.match(r"^\s*```\s*([^\s]*)", line)
        if match and not in_block:
            in_block = True
            language = match.group(1)[:40]
            start = index
            block = []
            continue
        if in_block and line.strip().startswith("```"):
            yield language, start, block
            in_block = False
            continue
        if in_block:
            block.append(line)


def _entry_id(family: str, subtype: str, value: str, source: str) -> str:
    return f"pat-{_digest('|'.join((family, subtype, value, source)))}"


@dataclass(frozen=True)
class PayloadEntry:
    payload_id: str
    family: str
    sub_type: str
    value: str
    purpose: str
    context: str
    safety_class: str
    executable: bool
    source_repository: str
    source_path: str
    source_section: str
    source_digest: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class PayloadLibrary:
    def __init__(self, entries: Iterable[PayloadEntry], provenance: Mapping[str, Any] | None = None) -> None:
        unique: dict[str, PayloadEntry] = {}
        for entry in entries:
            unique.setdefault(entry.payload_id, entry)
        self._entries = tuple(sorted(unique.values(), key=lambda item: (item.family, item.sub_type, item.payload_id)))
        self.provenance = dict(provenance or {})

    @classmethod
    def from_source(cls, root: str | Path, provenance: Mapping[str, Any] | None = None) -> "PayloadLibrary":
        root_path = Path(root).resolve()
        entries: list[PayloadEntry] = []
        for path in sorted(root_path.iterdir()):
            if not path.is_dir() or path.name.startswith("."):
                continue
            family = _family_for_directory(path.name)
            if family is None:
                continue
            for document in sorted(path.rglob("*.md")):
                relative = document.relative_to(root_path).as_posix()
                text = document.read_text(encoding="utf-8", errors="replace")
                source_digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
                lines = text.splitlines()
                seen_values: set[str] = set()
                count = 0
                for language, block_start, block_lines in _fenced_blocks(text):
                    context = " ".join(_clean_line(line.lstrip("# ")) for line in lines[max(0, block_start - 6):block_start] if line.strip().startswith("#"))[-240:]
                    subtype = _subtype_for_context(context, document.name, language)
                    purpose = _description(lines, block_start)
                    for raw in block_lines:
                        value = _clean_line(raw)
                        if not _is_candidate(value) or value in seen_values:
                            continue
                        seen_values.add(value)
                        catalog_only = language.lower() in {"bash", "sh", "shell", "python", "javascript", "php", "powershell"} or subtype in {"auth_bypass", "default_credentials"}
                        entries.append(PayloadEntry(
                            payload_id=_entry_id(family, subtype, value, relative),
                            family=family,
                            sub_type=subtype,
                            value=value,
                            purpose=purpose,
                            context=context,
                            safety_class="catalog_only" if catalog_only else "local_authorized_probe",
                            executable=not catalog_only,
                            source_repository="PayloadsAllTheThings",
                            source_path=relative,
                            source_section=context,
                            source_digest=source_digest,
                        ))
                        count += 1
                        if count >= MAX_ENTRIES_PER_FILE:
                            break
        return cls(entries, provenance)

    @classmethod
    def from_json(cls, path: str | Path) -> "PayloadLibrary":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls((PayloadEntry(**item) for item in data.get("entries", [])), data.get("provenance"))

    def get_payloads(self, family: str, sub_type: str | None = None, context: str | None = None, limit: int = 3) -> list[PayloadEntry]:
        if limit < 0:
            raise ValueError("limit must be non-negative")
        family_key = _canonical_family(family)
        subtype_key = str(sub_type or "").lower()
        context_key = str(context or "").lower()
        candidates = [entry for entry in self._entries if entry.family == family_key and (not subtype_key or entry.sub_type == subtype_key)]
        if context_key:
            candidates.sort(key=lambda item: (0 if context_key in f"{item.context} {item.purpose}".lower() else 1, item.payload_id))
        return list(candidates[:limit])

    def get_all_for_family(self, family: str) -> dict[str, list[PayloadEntry]]:
        grouped: dict[str, list[PayloadEntry]] = defaultdict(list)
        for entry in self._entries:
            if entry.family == _canonical_family(family):
                grouped[entry.sub_type].append(entry)
        return {key: list(value) for key, value in sorted(grouped.items())}

    def search(self, query: str, family: str | None = None, sub_type: str | None = None, limit: int = 20) -> list[PayloadEntry]:
        terms = [term for term in re.findall(r"[a-z0-9_:-]+", str(query or "").lower()) if term]
        if not terms or limit < 0:
            return []
        family_key = _canonical_family(family)
        subtype_key = str(sub_type or "").lower()
        scored: list[tuple[int, PayloadEntry]] = []
        for entry in self._entries:
            if family_key and entry.family != family_key:
                continue
            if subtype_key and entry.sub_type != subtype_key:
                continue
            haystack = f"{entry.value} {entry.purpose} {entry.context} {entry.sub_type}".lower()
            score = sum(2 if term in entry.value.lower() else 1 for term in terms if term in haystack)
            if score:
                scored.append((-score, entry))
        scored.sort(key=lambda item: (item[0], item[1].payload_id))
        return [entry for _, entry in scored[:limit]]

    def export(self) -> dict[str, Any]:
        family_counts = Counter(entry.family for entry in self._entries)
        subtype_counts = Counter(f"{entry.family}:{entry.sub_type}" for entry in self._entries)
        return {
            "schema": "webpent.payload_library.v1",
            "parser_version": PARSER_VERSION,
            "provenance": dict(self.provenance),
            "limits": {"max_payload_length": MAX_PAYLOAD_LENGTH, "max_entries_per_file": MAX_ENTRIES_PER_FILE},
            "counts": {"entries": len(self._entries), "families": dict(sorted(family_counts.items())), "subtypes": dict(sorted(subtype_counts.items()))},
            "entries": [entry.as_dict() for entry in self._entries],
        }

    def __len__(self) -> int:
        return len(self._entries)

    def iter_entries(self) -> tuple[PayloadEntry, ...]:
        """Return the immutable parsed entry projection for advisory consumers."""
        return self._entries


_DEFAULT_LIBRARY: PayloadLibrary | None = None


def load_library(path: str | Path | None = None) -> PayloadLibrary:
    global _DEFAULT_LIBRARY
    selected = Path(path) if path is not None else DEFAULT_EXPORT
    if _DEFAULT_LIBRARY is None or path is not None:
        if selected.exists():
            library = PayloadLibrary.from_json(selected)
        else:
            library = PayloadLibrary(())
        if path is None:
            _DEFAULT_LIBRARY = library
        return library
    return _DEFAULT_LIBRARY


def build_export(source_root: str | Path, output: str | Path, provenance: Mapping[str, Any] | None = None) -> dict[str, Any]:
    library = PayloadLibrary.from_source(source_root, provenance)
    data = library.export()
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return data


def get_payloads(family: str, sub_type: str | None = None, context: str | None = None, limit: int = 3) -> list[PayloadEntry]:
    return load_library().get_payloads(family, sub_type, context, limit)


def get_all_for_family(family: str) -> dict[str, list[PayloadEntry]]:
    return load_library().get_all_for_family(family)


def search(query: str, family: str | None = None, sub_type: str | None = None, limit: int = 20) -> list[PayloadEntry]:
    return load_library().search(query, family, sub_type, limit)


__all__ = ["PayloadEntry", "PayloadLibrary", "build_export", "get_payloads", "get_all_for_family", "load_library", "search"]

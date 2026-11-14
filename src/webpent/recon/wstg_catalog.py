"""Deterministic OWASP WSTG catalog parser and family query API."""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

PARSER_VERSION = "owasp-wstg-v1"
DEFAULT_EXPORT = Path(__file__).resolve().parents[3] / "docs" / "wstg_catalog.json"
MAX_SECTION_LENGTH = 2400

# The current WSTG repository uses INJT for injection tests. Older plans and
# checklists used INPV for these same concepts; aliases are explicit and
# auditable rather than inventing source entries.
WSTG_ALIASES: dict[str, str] = {
    "WSTG-INPV-01": "WSTG-INJT-01",
    "WSTG-INPV-02": "WSTG-INJT-02",
    "WSTG-INPV-05": "WSTG-INJT-05",
    "WSTG-INPV-09": "WSTG-INJT-19",
}

FAMILY_MAP: dict[str, tuple[str, ...]] = {
    "WSTG-ATHZ-02": ("AUTH_BYPASS",),
    "WSTG-ATHZ-04": ("IDOR",),
    "WSTG-INJT-01": ("XSS",),
    "WSTG-INJT-02": ("XSS",),
    "WSTG-INJT-05": ("SQLI",),
    "WSTG-INJT-19": ("SSRF",),
    "WSTG-BUSL-01": ("AUTH_BYPASS",),
    "WSTG-IDNT-01": ("INFO_DISCLOSURE",),
}


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _bounded(text: str, limit: int = MAX_SECTION_LENGTH) -> str:
    lines = [re.sub(r"\s+", " ", line.strip()) for line in text.splitlines()]
    return " ".join(line for line in lines if line)[:limit]


def _section(text: str, heading: str) -> str:
    pattern = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.IGNORECASE | re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return ""
    tail = text[match.end():]
    next_heading = re.search(r"^##\s+", tail, re.MULTILINE)
    return _bounded(tail[: next_heading.start()] if next_heading else tail)


def _title(text: str, fallback: str) -> str:
    match = re.search(r"^#\s+(.+?)\s*$", text, re.MULTILINE)
    return _bounded(match.group(1), 240) if match else fallback


def _id(text: str) -> str | None:
    match = re.search(r"WSTG-[A-Z]{4}-\d{2}", text)
    return match.group(0) if match else None


def _family_for(title: str, path: str, wstg_id: str) -> tuple[str, ...]:
    if wstg_id in FAMILY_MAP:
        return FAMILY_MAP[wstg_id]
    value = f"{title} {path}".lower()
    if "cross site scripting" in value or "xss" in value:
        return ("XSS",)
    if "sql injection" in value:
        return ("SQLI",)
    if "server-side request forgery" in value or "ssrf" in value:
        return ("SSRF",)
    if "direct object" in value or "bola" in value:
        return ("IDOR",)
    if "authorization" in value or "authentication" in value or "business logic" in value:
        return ("AUTH_BYPASS",)
    if "information" in value or "role definitions" in value or "fingerprint" in value:
        return ("INFO_DISCLOSURE",)
    return ()


def _payload_subtypes(family: str, text: str) -> tuple[str, ...]:
    lower = text.lower()
    candidates = {
        "SQLI": ("error_based", "blind", "time_based", "union", "auth_bypass"),
        "XSS": ("attribute_context", "js_context", "polyglot"),
        "SSRF": ("internal_url", "cloud_metadata", "file_protocol"),
        "IDOR": ("sequential", "parameter_swap", "method_confusion"),
        "OPEN_REDIRECT": ("absolute_url", "protocol_relative"),
        "INFO_DISCLOSURE": ("admin_panels", "config_files", "api_docs", "git"),
        "AUTH_BYPASS": ("auth_bypass", "default_credentials"),
    }.get(family, ())
    return tuple(item for item in candidates if item.replace("_", " ") in lower or item.split("_")[0] in lower) or candidates[:1]


@dataclass(frozen=True)
class WSTGTest:
    wstg_id: str
    title: str
    category: str
    families: tuple[str, ...]
    summary: str
    test_objectives: str
    methodology: str
    expected_behavior: str
    remediation: str
    related_payload_subtypes: tuple[str, ...]
    source_repository: str
    source_path: str
    source_digest: str
    aliases: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class WSTGCatalog:
    def __init__(self, tests: Iterable[WSTGTest], provenance: Mapping[str, Any] | None = None) -> None:
        unique: dict[str, WSTGTest] = {}
        for item in tests:
            unique.setdefault(item.wstg_id, item)
        self._tests = tuple(sorted(unique.values(), key=lambda item: item.wstg_id))
        self.provenance = dict(provenance or {})
        self._by_id = {item.wstg_id: item for item in self._tests}
        self._aliases = {alias: canonical for alias, canonical in WSTG_ALIASES.items()}

    @classmethod
    def from_source(cls, root: str | Path, provenance: Mapping[str, Any] | None = None) -> "WSTGCatalog":
        root_path = Path(root).resolve()
        tests: list[WSTGTest] = []
        for path in sorted((root_path / "document").rglob("*.md")):
            text = path.read_text(encoding="utf-8", errors="replace")
            wstg_id = _id(text)
            if not wstg_id:
                continue
            relative = path.relative_to(root_path).as_posix()
            title = _title(text, path.stem.replace("_", " "))
            families = _family_for(title, relative, wstg_id)
            family = families[0] if families else ""
            tests.append(WSTGTest(
                wstg_id=wstg_id,
                title=title,
                category=path.parent.name,
                families=families,
                summary=_section(text, "Summary"),
                test_objectives=_section(text, "Test Objectives"),
                methodology=_section(text, "How to Test"),
                expected_behavior=_section(text, "Expected Results") or _section(text, "Expected Behavior") or _section(text, "Summary"),
                remediation=_section(text, "Remediation") or _section(text, "Remediation Guidance"),
                related_payload_subtypes=_payload_subtypes(family, text),
                source_repository="OWASP-WSTG",
                source_path=relative,
                source_digest=_digest(text),
                aliases=tuple(alias for alias, canonical in WSTG_ALIASES.items() if canonical == wstg_id),
            ))
        return cls(tests, provenance)

    @classmethod
    def from_json(cls, path: str | Path) -> "WSTGCatalog":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls((WSTGTest(**item) for item in data.get("tests", [])), data.get("provenance"))

    def get_test(self, wstg_id: str) -> WSTGTest | None:
        requested = str(wstg_id or "").upper()
        canonical = self._aliases.get(requested, requested)
        return self._by_id.get(canonical)

    def tests_for_family(self, family: str) -> list[WSTGTest]:
        key = str(family or "").upper()
        return [item for item in self._tests if key in item.families]

    def tests_for_surface(self, route: str, method: str = "GET", context: str = "") -> list[WSTGTest]:
        haystack = f"{route} {method} {context}".lower()
        preferred: list[WSTGTest] = []
        for item in self._tests:
            terms = f"{item.title} {item.summary} {item.methodology}".lower()
            score = sum(1 for token in re.findall(r"[a-z0-9]+", haystack) if token in terms and len(token) > 2)
            if score:
                preferred.append((score, item))  # type: ignore[arg-type]
        preferred.sort(key=lambda pair: (-pair[0], pair[1].wstg_id))
        return [item for _, item in preferred[:20]]

    def search(self, query: str, limit: int = 20) -> list[WSTGTest]:
        terms = [term for term in re.findall(r"[a-z0-9-]+", str(query or "").lower()) if term]
        scored: list[tuple[int, WSTGTest]] = []
        for item in self._tests:
            haystack = f"{item.wstg_id} {item.title} {item.summary} {item.methodology} {item.remediation}".lower()
            score = sum(2 if term in item.title.lower() else 1 for term in terms if term in haystack)
            if score:
                scored.append((-score, item))
        scored.sort(key=lambda pair: (pair[0], pair[1].wstg_id))
        return [item for _, item in scored[:max(0, limit)]]

    def export(self) -> dict[str, Any]:
        family_counts = Counter(family for item in self._tests for family in item.families)
        return {
            "schema": "webpent.wstg_catalog.v1",
            "parser_version": PARSER_VERSION,
            "provenance": dict(self.provenance),
            "aliases": dict(sorted(WSTG_ALIASES.items())),
            "counts": {"tests": len(self._tests), "mapped_tests": sum(bool(item.families) for item in self._tests), "families": dict(sorted(family_counts.items()))},
            "tests": [item.as_dict() for item in self._tests],
        }

    def __len__(self) -> int:
        return len(self._tests)


_DEFAULT_CATALOG: WSTGCatalog | None = None


def load_catalog(path: str | Path | None = None) -> WSTGCatalog:
    global _DEFAULT_CATALOG
    selected = Path(path) if path is not None else DEFAULT_EXPORT
    if _DEFAULT_CATALOG is None or path is not None:
        catalog = WSTGCatalog.from_json(selected) if selected.exists() else WSTGCatalog(())
        if path is None:
            _DEFAULT_CATALOG = catalog
        return catalog
    return _DEFAULT_CATALOG


def build_export(source_root: str | Path, output: str | Path, provenance: Mapping[str, Any] | None = None) -> dict[str, Any]:
    catalog = WSTGCatalog.from_source(source_root, provenance)
    data = catalog.export()
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return data


def get_test(wstg_id: str) -> WSTGTest | None:
    return load_catalog().get_test(wstg_id)


def tests_for_family(family: str) -> list[WSTGTest]:
    return load_catalog().tests_for_family(family)


def tests_for_surface(route: str, method: str = "GET", context: str = "") -> list[WSTGTest]:
    return load_catalog().tests_for_surface(route, method, context)


def search(query: str, limit: int = 20) -> list[WSTGTest]:
    return load_catalog().search(query, limit)


__all__ = ["WSTGTest", "WSTGCatalog", "WSTG_ALIASES", "FAMILY_MAP", "build_export", "get_test", "load_catalog", "search", "tests_for_family", "tests_for_surface"]

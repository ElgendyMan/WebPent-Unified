"""Operator-injected advisory catalogs (Project Zero wiring fix, 2026-10-24).

Two advisory catalogs were previously read from PentestState without any
declaration or producer, so the consumer sites always saw an empty feed:

  * ``cve_feed_catalog`` — read by ``agents/crawler/agent.py`` for
    tech-stack CVE correlation (the key was not even declared on the state
    schema, and LangGraph silently drops undeclared keys).
  * ``kev_catalog`` — declared on the state schema but produced nowhere;
    read by ``agents/reporter/agent.py`` for KEV enrichment.

This module gives both an operator-visible injection point that never
depends on a producer node existing: a JSON file on disk, referenced by a
settings path (``cve_feed_catalog_path`` / ``kev_catalog_path``). If state
already carries a populated list, it wins (a node producer can still be
added later without touching the operator surface); otherwise the loader
reads the file once per call.

Every loader is fail-soft: any problem (missing file, bad JSON, wrong
shape) returns an empty catalog and never raises into the caller, so the
advisory wiring degrades exactly as it did when the catalog was empty.

Nothing here fetches anything from the network, and nothing here writes to
findings or state: it only reads an operator-provided local file.
"""
from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

_CATALOG_ID_KEYS = ("cve_id", "id", "cve")


def _settings_value(attr: str) -> str:
    """Read a settings attribute fail-soft (settings may not be loadable)."""
    try:
        from webpent.config.settings import get_settings

        return str(getattr(get_settings(), attr, "") or "")
    except Exception:  # noqa: BLE001 — catalog loading must degrade safely
        return ""


def _read_json_list(path_value: str) -> list[Any]:
    """Load a JSON file into a list, or return [] on any problem."""
    if not path_value:
        return []
    try:
        raw = json.loads(Path(path_value).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, Mapping):
        # Accept {"cves": [...]}, {"kev": [...]}, {"entries": [...]}, or a
        # single catalog dict with an id field.
        for key in ("cves", "kev", "entries", "items", "catalog"):
            candidate = raw.get(key)
            if isinstance(candidate, list):
                return candidate
        return [raw]
    return []


def _normalize_ids(entries: Sequence[Any]) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        value: Any = entry
        if isinstance(entry, Mapping):
            for key in _CATALOG_ID_KEYS:
                if entry.get(key):
                    value = entry[key]
                    break
        if not isinstance(value, str):
            continue
        text = value.strip().upper()
        if text and text not in seen:
            seen.add(text)
            ids.append(text)
    return ids


def load_cve_feed_catalog(
    state_value: Any, *, settings_attr: str = "cve_feed_catalog_path"
) -> list[dict[str, Any]]:
    """Resolve the CVE feed catalog: state first, then the operator file.

    ``state_value`` is whatever the calling site got from
    ``state.get("cve_feed_catalog")``. If it is already a non-empty list it
    is returned as-is (only real mappings/dicts kept). Otherwise the JSON
    file named by the settings attribute is loaded (fail-soft, []).
    """
    if isinstance(state_value, list) and state_value:
        kept = [entry for entry in state_value if isinstance(entry, Mapping)]
        return kept if kept else []
    entries = _read_json_list(_settings_value(settings_attr))
    return [entry for entry in entries if isinstance(entry, Mapping)]


def load_kev_catalog(
    state_value: Any, *, settings_attr: str = "kev_catalog_path"
) -> list[str]:
    """Resolve the KEV id catalog: state first, then the operator file.

    Accepts bare CVE strings or mapping entries with a ``cve_id``/``id``/
    ``cve`` field; normalizes to uppercase strings and de-duplicates.
    Fails soft to [] exactly like the pre-wiring empty-feed behavior.
    """
    if isinstance(state_value, list) and state_value:
        return _normalize_ids(state_value)
    return _normalize_ids(_read_json_list(_settings_value(settings_attr)))


__all__ = ["load_cve_feed_catalog", "load_kev_catalog"]

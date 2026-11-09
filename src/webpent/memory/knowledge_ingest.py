"""Payload/WSTG knowledge ingestion with provenance and client-safe metadata.

The module is deliberately additive: it uses the existing VectorStoreManager
contract and never participates in scope, execution, validation, or promotion.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from webpent.recon.payload_library import PayloadLibrary, build_export
from webpent.recon.wstg_catalog import WSTGCatalog
from webpent.recon.wstg_catalog import build_export as build_wstg_export


def _payload_text(entry: Any) -> str:
    # This is a bounded knowledge projection. It contains source/test data, not
    # target content, credentials, or instructions for changing authority.
    return (
        f"Payload test input. Family={entry.family}; subtype={entry.sub_type}; "
        f"context={entry.context[:200]}; payload={entry.value[:512]}; "
        f"purpose={entry.purpose[:240]}; payload_id={entry.payload_id}."
    )


def _wstg_text(item: Any) -> str:
    return (
        f"OWASP WSTG test {item.wstg_id}. Title={item.title[:240]}; "
        f"families={','.join(item.families)}; summary={item.summary[:700]}; "
        f"methodology={item.methodology[:1000]}; expected={item.expected_behavior[:600]}; "
        f"remediation={item.remediation[:600]}."
    )


def ingest_payloads(manager: Any, library: PayloadLibrary) -> int:
    entries = list(library.get_all_for_family(family) for family in sorted({item.family for item in library._entries}))
    flat = [entry for group in entries for values in group.values() for entry in values]
    texts = [_payload_text(entry) for entry in flat]
    metadata = [
        {
            "source_id": f"payload:{entry.payload_id}",
            "source_type": "payload_library",
            "family": entry.family,
            "sub_type": entry.sub_type,
            "payload_id": entry.payload_id,
            "source_path": entry.source_path,
            "source_digest": entry.source_digest,
            "scope": "global_advisory",
        }
        for entry in flat
    ]
    return int(manager.add_knowledge_batch(texts, metadata, doc_type="payload")) if flat else 0


def ingest_wstg(manager: Any, catalog: WSTGCatalog) -> int:
    items = list(catalog._tests)
    texts = [_wstg_text(item) for item in items]
    metadata = [
        {
            "source_id": f"wstg:{item.wstg_id}:{item.source_digest[:16]}",
            "source_type": "wstg_catalog",
            "wstg_id": item.wstg_id,
            "aliases": ",".join(item.aliases),
            "family": item.families[0] if item.families else "",
            "source_path": item.source_path,
            "source_digest": item.source_digest,
            "scope": "global_advisory",
        }
        for item in items
    ]
    return int(manager.add_knowledge_batch(texts, metadata, doc_type="methodology")) if items else 0


def update_knowledge(
    payload_root: str | Path,
    wstg_root: str | Path,
    docs_dir: str | Path,
    manager: Any | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    docs = Path(docs_dir)
    docs.mkdir(parents=True, exist_ok=True)
    payload_path = docs / "payload_library.json"
    wstg_path = docs / "wstg_catalog.json"
    payload_data = build_export(payload_root, payload_path, (provenance or {}).get("payloads_all_the_things", provenance or {}))
    wstg_data = build_wstg_export(wstg_root, wstg_path, (provenance or {}).get("owasp_wstg", provenance or {}))
    payload_library = PayloadLibrary.from_json(payload_path)
    wstg_catalog = WSTGCatalog.from_json(wstg_path)
    added_payloads = ingest_payloads(manager, payload_library) if manager is not None else 0
    added_wstg = ingest_wstg(manager, wstg_catalog) if manager is not None else 0
    result = {
        "status": "ok",
        "payload_export": str(payload_path),
        "wstg_export": str(wstg_path),
        "payload_counts": payload_data["counts"],
        "wstg_counts": wstg_data["counts"],
        "ingested": {"payloads": added_payloads, "wstg": added_wstg},
        "provenance": {"payloads_all_the_things": payload_data.get("provenance", {}), "owasp_wstg": wstg_data.get("provenance", {})},
    }
    (docs / "payload_wstg_update.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def knowledge_status(docs_dir: str | Path) -> dict[str, Any]:
    docs = Path(docs_dir)
    result: dict[str, Any] = {"status": "ok", "sources": {}}
    for name, key in (("payload_library.json", "payloads_all_the_things"), ("wstg_catalog.json", "owasp_wstg")):
        path = docs / name
        if not path.exists():
            result["sources"][key] = {"status": "missing", "path": str(path)}
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        result["sources"][key] = {"status": "loaded", "path": str(path), "parser_version": data.get("parser_version"), "counts": data.get("counts", {}), "provenance": data.get("provenance", {})}
    return result


def knowledge_search(query: str, docs_dir: str | Path, limit: int = 10) -> list[dict[str, Any]]:
    docs = Path(docs_dir)
    results: list[dict[str, Any]] = []
    payload_path = docs / "payload_library.json"
    wstg_path = docs / "wstg_catalog.json"
    if payload_path.exists():
        library = PayloadLibrary.from_json(payload_path)
        for entry in library.search(query, limit=limit):
            results.append({"source_type": "payload_library", "source_id": entry.payload_id, "family": entry.family, "sub_type": entry.sub_type, "value": entry.value, "source_path": entry.source_path})
    if wstg_path.exists():
        catalog = WSTGCatalog.from_json(wstg_path)
        for item in catalog.search(query, limit=limit):
            results.append({"source_type": "wstg_catalog", "source_id": item.wstg_id, "family": ",".join(item.families), "title": item.title, "methodology": item.methodology[:500], "source_path": item.source_path})
    return results[: max(0, limit)]


__all__ = ["ingest_payloads", "ingest_wstg", "knowledge_search", "knowledge_status", "update_knowledge"]

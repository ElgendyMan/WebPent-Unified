from __future__ import annotations

import hashlib
import json
from pathlib import Path

from webpent.memory.knowledge_ingest import ingest_payloads, ingest_wstg, knowledge_search
from webpent.recon.autonomous_crawler import RouteSurface, SurfaceMap, SurfaceParameter
from webpent.recon.hypothesis_generator import HypothesisGenerator
from webpent.recon.payload_advisor import advise_payloads
from webpent.recon.payload_library import PayloadLibrary, build_export
from webpent.recon.wstg_catalog import WSTGCatalog
from webpent.recon.wstg_catalog import build_export as build_wstg_export

ROOT = Path(__file__).resolve().parents[1]


class FakeStore:
    def __init__(self) -> None:
        self.batches: list[tuple[str, list[str], list[dict[str, object]]]] = []

    def add_knowledge_batch(self, texts, metadatas, doc_type="report"):
        self.batches.append((doc_type, list(texts), list(metadatas)))
        return len(texts)


def test_checked_in_exports_load_and_selection_is_bounded() -> None:
    library = PayloadLibrary.from_json(ROOT / "docs/payload_library.json")
    assert len(library) >= 100
    selected = library.get_payloads("SQL_INJECTION", "auth_bypass", limit=3)
    assert len(selected) <= 3
    assert all(item.family == "SQL_INJECTION" for item in selected)
    assert library.search("sleep", limit=10)
    assert library.get_all_for_family("SSRF")
    before = tuple(item.payload_id for item in library.get_payloads("XSS", limit=5))
    library.get_payloads("XSS", limit=1).clear()
    assert before == tuple(item.payload_id for item in library.get_payloads("XSS", limit=5))


def test_payload_parser_extracts_code_without_executing_it(tmp_path: Path) -> None:
    source = tmp_path / "SQL Injection"
    source.mkdir()
    marker = tmp_path / "executed"
    (source / "README.md").write_text(
        "# SQL Injection\n\n## Time Based\n\n```sql\n' AND SLEEP(5)--\n```\n\n```python\nopen(%r, 'w').write('bad')\n```\n" % marker,
        encoding="utf-8",
    )
    output = tmp_path / "payload_library.json"
    data = build_export(source.parent, output, {"commit": "fixture"})
    library = PayloadLibrary.from_json(output)
    assert data["counts"]["entries"] >= 1
    assert library.search("sleep")
    assert not marker.exists()


def test_wstg_aliases_and_family_mapping() -> None:
    catalog = WSTGCatalog.from_json(ROOT / "docs/wstg_catalog.json")
    assert catalog.get_test("WSTG-ATHZ-04") is not None
    assert "IDOR" in catalog.get_test("WSTG-ATHZ-04").families
    assert catalog.get_test("WSTG-INPV-05") is not None
    assert catalog.get_test("WSTG-INPV-05").wstg_id == "WSTG-INJT-05"
    assert "SQLI" in catalog.get_test("WSTG-INPV-05").families
    assert catalog.tests_for_family("XSS")


def test_wstg_parser_reads_local_fixture_sections(tmp_path: Path) -> None:
    file_path = tmp_path / "document" / "4-Web_Application_Security_Testing" / "05-Authorization"
    file_path.mkdir(parents=True)
    (file_path / "04-Insecure_Direct_Object_References.md").write_text(
        "# Insecure Direct Object References\n\n|WSTG-ATHZ-04|\n\n## Summary\nSummary text.\n\n## Test Objectives\nObjective text.\n\n## How to Test\nMethodology text.\n\n## Expected Results\nExpected text.\n\n## Remediation\nFix text.\n",
        encoding="utf-8",
    )
    output = tmp_path / "wstg_catalog.json"
    build_wstg_export(tmp_path, output, {"commit": "fixture"})
    catalog = WSTGCatalog.from_json(output)
    item = catalog.get_test("WSTG-ATHZ-04")
    assert item is not None
    assert "Methodology text" in item.methodology
    assert "Expected text" in item.expected_behavior


def test_rag_batches_are_typed_and_source_attributed() -> None:
    library = PayloadLibrary.from_json(ROOT / "docs/payload_library.json")
    catalog = WSTGCatalog.from_json(ROOT / "docs/wstg_catalog.json")
    store = FakeStore()
    assert ingest_payloads(store, library) > 0
    assert ingest_wstg(store, catalog) > 0
    assert {batch[0] for batch in store.batches} == {"payload", "methodology"}
    for _, _, metadata in store.batches:
        assert all(item.get("source_id") for item in metadata)
        assert all(item.get("scope") == "global_advisory" for item in metadata)
        assert all(item.get("source_type") in {"payload_library", "wstg_catalog"} for item in metadata)


def test_knowledge_search_returns_bounded_source_projections() -> None:
    results = knowledge_search("IDOR", ROOT / "docs", limit=5)
    assert results
    assert all(item["source_type"] in {"payload_library", "wstg_catalog"} for item in results)
    assert all(len(json.dumps(item)) < 2000 for item in results)


def test_hypotheses_carry_payload_and_wstg_metadata() -> None:
    parameter = SurfaceParameter("q", "query", "query-shaped", 4, "/rest/products/search")
    route = RouteSurface(
        route="/rest/products/search", method="GET", status_code=200,
        content_type="application/json", response_digest="digest", response_length=10,
        depth=0, auth_required=False, login_signal=False, api_signal=True,
        parameters=(parameter,), execution_url="http://127.0.0.1:3000/rest/products/search?q=test",
    )
    surface = SurfaceMap(
        target_url="http://127.0.0.1:3000", target_fingerprint="target",
        scope_fingerprint="scope", routes={route.route: route}, events=[],
    )
    library = PayloadLibrary.from_json(ROOT / "docs/payload_library.json")
    catalog = WSTGCatalog.from_json(ROOT / "docs/wstg_catalog.json")
    hypotheses = HypothesisGenerator(max_hypotheses=20, payload_library=library, wstg_catalog=catalog).generate(surface)
    assert hypotheses
    assert any(item.get("payload_id") for item in hypotheses)
    assert any(item.get("wstg_reference") for item in hypotheses)
    assert all(item["metadata"].get("payload_safety_class") in {None, "local_authorized_probe", "catalog_only"} for item in hypotheses)


def test_advisor_prompt_contains_bounded_wstg_methodology_and_external_ids() -> None:
    parameter = SurfaceParameter("q", "query", "query-shaped", 4, "/rest/products/search")
    route = RouteSurface(
        route="/rest/products/search", method="GET", status_code=200,
        content_type="application/json", response_digest="digest", response_length=10,
        depth=0, auth_required=False, login_signal=False, api_signal=True,
        parameters=(parameter,), execution_url="http://127.0.0.1:3000/rest/products/search?q=test",
    )
    surface = SurfaceMap(
        target_url="http://127.0.0.1:3000", target_fingerprint="target",
        scope_fingerprint="scope", routes={route.route: route}, events=[],
    )
    library = PayloadLibrary.from_json(ROOT / "docs/payload_library.json")
    catalog = WSTGCatalog.from_json(ROOT / "docs/wstg_catalog.json")

    class FakeLLM:
        def __init__(self):
            self.prompts = []

        def invoke(self, messages):
            self.prompts.append(str(messages[-1].content))
            return type("Response", (), {"content": '{"suggestions": []}'})()

    fake = FakeLLM()
    advice, records = advise_payloads(
        surface_map=surface, llm=fake, batch_size=1,
        payload_library_data=library, wstg_catalog=catalog,
    )
    assert advice == []
    assert records[0]["prompt_policy"].startswith("structural")
    assert "WSTG-" in fake.prompts[0]
    assert "payload_library" in fake.prompts[0]
    assert len(fake.prompts[0]) < 30000


def test_exports_are_deterministic() -> None:
    for name in ("payload_library.json", "wstg_catalog.json"):
        data = json.loads((ROOT / "docs" / name).read_text(encoding="utf-8"))
        canonical = json.dumps(data, indent=2, sort_keys=True) + "\n"
        assert hashlib.sha256(canonical.encode()).hexdigest() == hashlib.sha256((ROOT / "docs" / name).read_bytes()).hexdigest()

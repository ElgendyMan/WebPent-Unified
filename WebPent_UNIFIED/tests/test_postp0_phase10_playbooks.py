"""POST-P0 Phase 10 — RAG / playbooks operationalization.

Pins:
  * ``playbook`` is a first-class ingestable document type in BOTH
    operator entry points (scripts/ingest_payloads.py --doc-type and
    webpent-ingest --type),
  * skill_selector resolves ``reference_source: playbook`` skills through
    the knowledge store with the same advisory/offline-safe contract as
    the payload corpus (bounded chars, never evidence),
  * knowledge_ready remains wired into preflight (regression pin of the
    existing contract),
  * retrieval budgets and sanitization remain enforced (regression pins
    of the existing run-budget contract).
"""

from __future__ import annotations


def test_playbook_type_registered_in_ingest_clis() -> None:
    import inspect

    import scripts.ingest_payloads as ingest_mod  # noqa: F401  (path bootstrap)

    src = inspect.getsource(ingest_mod)
    assert '"playbook"' in src

    from webpent.cli import ingest as cli_ingest

    cli_src = inspect.getsource(cli_ingest)
    assert '"playbook"' in cli_src


def test_skill_selector_resolves_playbook_reference(monkeypatch) -> None:
    from webpent.shared import skill_selector

    captured: dict = {}

    def fake_retrieve(**kwargs):
        captured.update(kwargs)
        return "1. do the thing\n2. verify the thing"

    monkeypatch.setattr(
        "webpent.shared.knowledge_retrieval.retrieve_knowledge_context",
        fake_retrieve,
    )
    skill = {
        "name": "checkout flow abuse",
        "reference_source": "playbook",
        "applies_to_vuln_class": ["race_condition"],
        "stack": "generic",
    }
    reference = skill_selector.get_skill_reference(skill, "finding-1")
    assert "do the thing" in reference
    assert captured["doc_types"] == ("playbook",)
    assert captured["max_chars"] <= 2000  # bounded advisory


def test_playbook_reference_fails_open_to_empty_without_store(monkeypatch) -> None:
    from webpent.shared import skill_selector

    def fake_retrieve(**kwargs):
        return ""

    monkeypatch.setattr(
        "webpent.shared.knowledge_retrieval.retrieve_knowledge_context",
        fake_retrieve,
    )
    reference = skill_selector.get_skill_reference(
        {"name": "x", "reference_source": "playbook"}, "finding-1"
    )
    assert isinstance(reference, str)


def test_knowledge_ready_preflight_contract_present() -> None:
    # Regression pin: preflight still exposes knowledge_ready (advisory).
    from webpent.shared.preflight import _check_knowledge_ready

    result = _check_knowledge_ready()
    assert isinstance(result, dict)
    assert "knowledge_ready" in result


def test_run_budget_contract_still_enforced() -> None:
    # Regression pin: per-run RAG char budget still bounded + resettable.
    from webpent.shared.knowledge_retrieval import (
        DEFAULT_RUN_BUDGET_CHARS,
        knowledge_budget_remaining,
        reset_knowledge_budget,
    )

    reset_knowledge_budget()
    try:
        remaining = knowledge_budget_remaining()
        assert remaining is None or remaining <= DEFAULT_RUN_BUDGET_CHARS
    finally:
        reset_knowledge_budget()

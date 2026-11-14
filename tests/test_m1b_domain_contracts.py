"""M1b acceptance: domain-contract catalog + isolation + state consistency.

CANONICAL_PHASE_REGISTRY M1b (Part 4 §3):
  * schema-versioned exported contracts → ``export_contracts()`` is
    deterministic, JSON-serializable, every entry carries a declared
    schema version and a real source-of-truth row whose owner module
    imports;
  * isolation proven → an engagement's findings are reachable ONLY
    through its own threads in the real sqlite store; the engagement
    contract cannot be constructed without its client;
  * state consistency → ``UnifiedState`` remains a structural superset
    of ``PentestState`` (same reducers), and the legacy bridge round-
    trips a representative state without key loss.
"""
from __future__ import annotations

import importlib
import json

import pytest
from pydantic import ValidationError

from webpent.adapters.legacy_state_bridge import (
    pentest_state_to_unified,
    unified_to_pentest_state,
)
from webpent.models.contracts import (
    CONTRACTS_SCHEMA_VERSION,
    DATA_SOURCE_OF_TRUTH,
    DOMAIN_CONTRACTS,
    EngagementContract,
    export_contracts,
)
from webpent.state.state import PentestState
from webpent.state.unified_state import UnifiedState


# ---------------------------------------------------------------------------
# Contract catalog
# ---------------------------------------------------------------------------

def test_export_is_deterministic_and_serializable():
    first = export_contracts()
    second = export_contracts()
    assert first == second
    assert json.loads(json.dumps(first)) == first
    assert first["schema_version"] == CONTRACTS_SCHEMA_VERSION


def test_every_entry_has_declared_version_and_real_owner():
    export = export_contracts()
    assert export["contracts"], "the catalog must not be empty"
    for name, entry in export["contracts"].items():
        assert entry["schema_version"] != "undeclared", name
        assert entry["source_of_truth"]["store"], name
        owner = entry["source_of_truth"]["owner_module"]
        assert owner != "undeclared", name
        importlib.import_module(owner)  # moved/renamed owner = loud failure


def test_catalog_entities_resolve_to_their_declared_classes():
    for name, entry in DOMAIN_CONTRACTS.items():
        module_path, _, qualname = entry.entity.rpartition(".")
        cls = getattr(importlib.import_module(module_path), qualname)
        assert cls is not None, name


def test_engagement_contract_requires_client_isolation_root():
    # Isolation BY CONSTRUCTION: no client → no engagement.
    with pytest.raises(ValidationError):
        EngagementContract(engagement_id="eng-1", client_id="")
    with pytest.raises(ValidationError):
        EngagementContract(engagement_id="")
    # The well-formed case round-trips.
    engagement = EngagementContract(
        engagement_id="eng-1",
        client_id="client-9",
        targets=("https://lab.example",),
        authorization_ref="auth-record-42",
    )
    payload = engagement.model_dump()
    assert EngagementContract(**payload) == engagement
    assert payload["schema_version"] == "webpent-engagement-v1"


def test_scoping_fields_are_declared_for_every_scoped_entity():
    for name, entry in DOMAIN_CONTRACTS.items():
        if entry.scope == "engagement":
            assert entry.client_scoping_field, (
                f"{name} is engagement-scoped but declares no scoping field"
            )
        elif entry.scope == "client":
            assert entry.client_scoping_field == "client_id"


# ---------------------------------------------------------------------------
# Isolation proof — real sqlite store, two engagements
# ---------------------------------------------------------------------------

def _finding(title: str, thread_id: str):
    from webpent.models.findings import Confidence, Finding, Severity, VulnClass

    return Finding(
        title=title,
        severity=Severity.LOW,
        description="M1b isolation fixture.",
        tool_name="test",
        url="https://lab.example/x",
        vuln_class=VulnClass.INFO_DISCLOSURE,
        confidence=Confidence.TENTATIVE,
        confidence_level="Pending",
        evidence={"validation_attempted": False},
        thread_id=thread_id,
    )


def test_findings_are_thread_scoped_in_the_real_store(tmp_path, monkeypatch):
    from webpent.memory import db as db_module

    db_path = tmp_path / "isolation.db"
    monkeypatch.setenv("WEBPENT_DATABASE_URL", f"sqlite:///{db_path}")
    db_module.get_db_manager.cache_clear() if hasattr(
        db_module.get_db_manager, "cache_clear"
    ) else None
    manager = db_module.DatabaseManager(f"sqlite:///{db_path}")

    try:
        manager.save_finding(_finding("eng-A finding", "thread-A"))
        manager.save_finding(_finding("eng-B finding", "thread-B"))

        only_a = manager.get_findings_by_threads(["thread-A"])
        assert [f.title for f in only_a] == ["eng-A finding"], (
            "ISOLATION REGRESSION: engagement A's query returned foreign data"
        )
        only_b = manager.get_findings_by_threads(["thread-B"])
        assert [f.title for f in only_b] == ["eng-B finding"]
        both = manager.get_findings_by_threads(["thread-A", "thread-B"])
        assert len(both) == 2
        empty = manager.get_findings_by_threads([])
        assert empty == []
    finally:
        monkeypatch.delenv("WEBPENT_DATABASE_URL", raising=False)
        if hasattr(db_module.get_db_manager, "cache_clear"):
            db_module.get_db_manager.cache_clear()


# ---------------------------------------------------------------------------
# State consistency — UnifiedState ⊇ PentestState, bridge round-trip
# ---------------------------------------------------------------------------

def _representative_state() -> dict:
    return {
        "target": None,
        "findings": [],
        "hypotheses": [],
        "messages": [],
        "current_phase": "recon",
        "thread_id": "thread-consistency",
        "engagement_id": "eng-consistency",
        "credentials": {},
        "session_cookies": {},
        "crawled_data": {},
        "error_count": 0,
    }


def test_unified_state_is_a_structural_superset_of_pentest_state():
    pentest_keys = set(PentestState.__annotations__)
    unified_keys = set(UnifiedState.__annotations__)
    missing = pentest_keys - unified_keys
    assert not missing, (
        f"STATE CONSISTENCY REGRESSION: UnifiedState lost PentestState "
        f"channel(s): {sorted(missing)}"
    )
    # Same semantics on the shared channels: a channel re-declared in
    # UnifiedState must keep the parent's EXACT annotation — in particular
    # an ``Annotated[T, reducer]`` channel must never be shadowed by a
    # plain ``T`` (the reducer-loss regression this suite exists to catch:
    # merge semantics silently gone in unified runs). Annotations are
    # compared by their ARGUMENT text (ForwardRef unwrapped) so the
    # declaring module's name never masks real drift.
    def _annotation_text(annotation) -> str:
        arg = getattr(annotation, "__forward_arg__", None)
        return str(arg if arg is not None else annotation)

    for key in pentest_keys & unified_keys:
        parent = _annotation_text(PentestState.__annotations__[key])
        child = _annotation_text(UnifiedState.__annotations__[key])
        assert child == parent, (
            f"reducer/annotation drift on shared channel {key!r}: "
            f"pentest={parent!r} unified={child!r}"
        )


def test_bridge_round_trip_preserves_keys():
    state = _representative_state()
    unified = pentest_state_to_unified(state, mode="standard")
    # existing keys are never overwritten; budget fields are ADDED
    for key, value in state.items():
        if value is not None:
            assert unified[key] == value, key
    narrowed = unified_to_pentest_state(unified)
    for key in state:
        assert key in narrowed, f"bridge round-trip lost {key!r}"
    assert narrowed["thread_id"] == "thread-consistency"
    assert narrowed["engagement_id"] == "eng-consistency"

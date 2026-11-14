# src/webpent/models/contracts.py
"""webpent.models.contracts — M1b: the versioned domain-contract catalog.

CANONICAL_PHASE_REGISTRY M1b (Part 4 §3): «unified, versioned domain
models; truth/hypothesis separation; data ownership per type; tenant
isolation proven» with acceptance «state consistency + isolation tests
pass; schema-versioned exported contracts».

This module is a RECONCILIATION, not a re-declaration: every domain
entity already exists somewhere in the tree (``models/findings.py``,
``models/hypothesis.py``, ``models/proof_bundle.py``, ``models/targets.py``,
``models/evidence.py``, ``models/campaigns.py``, ``vip/retest.py``) —
the M1b gap was that nothing declared, in one place and in a
machine-checkable form:

* WHICH types form the domain contract (the entity set),
* WHICH schema version each carries,
* WHICH store is the single source of truth for each data type,
* WHICH identity fields make an entity client/engagement-scoped.

What this module deliberately does NOT do:

* it never re-declares or re-implements an existing entity — the
  catalog IMPORTS the authoritative class, so drift between the
  catalog and the tree is an import error, not a silent divergence;
* it never invents a new persistence layer — the source-of-truth
  registry DOCUMENTS the existing stores (the registry's own test
  imports every owner module, so a moved owner is a loud failure);
* it contains no behavior — the isolation and consistency PROOFS live
  in ``tests/test_m1b_domain_contracts.py``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.campaigns import CampaignExecutionContract
from webpent.models.evidence import Observation, ToolExecution
from webpent.models.findings import Finding
from webpent.models.hypothesis import Hypothesis
from webpent.models.proof_bundle import ProofBundle
from webpent.models.targets import Target

# ---------------------------------------------------------------------------
# The catalog's own schema version — bump on any structural change to the
# catalog shape (new field semantics, entry removal), never on additive
# entries alone.
# ---------------------------------------------------------------------------
CONTRACTS_SCHEMA_VERSION = "webpent-domain-contracts-v1"

# The engagement contract's own schema version (the one NEW entity M1b
# adds; every other entry carries its module's existing version).
ENGAGEMENT_CONTRACT_SCHEMA_VERSION = "webpent-engagement-v1"


class EngagementContract(BaseModel):
    """The engagement identity contract — the isolation root of the domain.

    This is the entity M0/M1 found implicitly threaded through thread_ids,
    engagement_ids, and client ids across the DB, API, and graph state
    without a single declared type. Isolation is BY CONSTRUCTION here:
    ``client_id`` and ``engagement_id`` are both required and
    non-empty — an engagement that does not name its client cannot be
    constructed, so no caller can create an unscoped engagement and
    retrofit ownership later.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(
        default=ENGAGEMENT_CONTRACT_SCHEMA_VERSION,
        description="Contract schema version (catalog integrity).",
    )
    engagement_id: str = Field(
        min_length=1,
        description="Globally unique engagement identifier (the thread root).",
    )
    client_id: str = Field(
        min_length=1,
        description=(
            "Owning client identifier. REQUIRED: engagement data is never "
            "client-agnostic — every query path that scopes by engagement "
            "must be able to derive the client from this field."
        ),
    )
    targets: tuple[str, ...] = Field(
        default=(),
        description=(
            "Operator-declared target URLs/hosts for this engagement. "
            "Order-preserving, de-duplicated by the constructor caller; "
            "the engagement-scope allowlist is seeded from these."
        ),
    )
    authorization_ref: str = Field(
        default="",
        description=(
            "Reference to the operator's authorization record (manifest "
            "id once M2's structured manifest lands; free-text ref until "
            "then). Empty = the engagement has NO authorization claim — "
            "admission gates must refuse targets, not assume."
        ),
    )
    status: str = Field(
        default="open",
        description="open | paused | closed (lifecycle marker only).",
    )
    created_at: str = Field(
        default="",
        description="UTC ISO-8601 creation stamp (set by the factory).",
    )


# ---------------------------------------------------------------------------
# Source-of-truth registry (Part 4 §3: "data ownership per type").
# Each entry names the ONE store that owns the data type and the module
# that owns the access code. The catalog test imports every owner module,
# so a moved or renamed owner is a loud failure, not a stale sentence.
# ---------------------------------------------------------------------------
DATA_SOURCE_OF_TRUTH: dict[str, dict[str, str]] = {
    "findings": {
        "store": "sqlite (memory/db.py findings table)",
        "owner_module": "webpent.memory.db",
    },
    "evidence_bundles": {
        "store": "sqlite findings.evidence_bundle column (hash-anchored)",
        "owner_module": "webpent.models.proof_bundle",
    },
    "hypotheses": {
        "store": "graph state (LangGraph channel) + sqlite where persisted",
        "owner_module": "webpent.models.hypothesis",
    },
    "campaign_state_checkpoints": {
        "store": "langgraph sqlite checkpoint (graph/checkpoints.py)",
        "owner_module": "webpent.graph.checkpoints",
    },
    "decision_log": {
        "store": "sqlite via memory/decision_log.py (redaction enforced)",
        "owner_module": "webpent.memory.decision_log",
    },
    "retest_ledger": {
        "store": "JSONL append-only (vip/retest.py RetestLedger)",
        "owner_module": "webpent.vip.retest",
    },
    "embeddings_vector": {
        "store": "chroma (memory/global/chroma_db) — derived, rebuildable",
        "owner_module": "webpent.memory.vectorstore",
    },
    "reports": {
        "store": "filesystem (per-target workspace output dirs)",
        "owner_module": "webpent.agents.reporter.agent",
    },
    "engagement_registry": {
        "store": "sqlite via api/scan_registry.py (thread↔engagement index)",
        "owner_module": "webpent.api.scan_registry",
    },
}


# ---------------------------------------------------------------------------
# The domain entity catalog. Order is catalog order (deterministic export);
# every entry imports the AUTHORITATIVE class — a moved/renamed entity
# breaks this import loudly.
# ---------------------------------------------------------------------------
class ContractEntry(BaseModel):
    """One catalog row: the entity, its version, its owning store."""

    model_config = ConfigDict(extra="forbid")

    name: str
    entity: str  # dotted path of the authoritative class
    schema_version: str
    data_type: str  # key into DATA_SOURCE_OF_TRUTH
    scope: str  # "engagement" | "client" | "global"
    client_scoping_field: str  # "" for global entities


def _entity_path(cls: type) -> str:
    return f"{cls.__module__}.{cls.__qualname__}"


# Declared contract versions, per entity. M1b increment 1 declares the
# versions HERE (the catalog is the version authority for the exported
# contract) rather than adding a schema_version field to six FROZEN
# model files for a purely additive change. When an owning module next
# opens a refreeze window, the declared version moves into the entity
# class itself and the catalog reads it from there — the catalog test
# keeps both paths honest.
_DECLARED_VERSIONS: dict[str, str] = {
    "Engagement": ENGAGEMENT_CONTRACT_SCHEMA_VERSION,
    "Target": "webpent-target-v1",
    "Finding": "webpent-finding-v1",
    "Hypothesis": "webpent-hypothesis-v1",
    "ProofBundle": "webpent-proof-bundle-v1",
    "Observation": "webpent-observation-v1",
    "ToolExecution": "webpent-tool-execution-v1",
    "CampaignExecutionContract": "webpent-campaign-contract-v1",
}

_CONTRACT_CLASSES: tuple[tuple[str, type, str, str], ...] = (
    # (name, class, data_type, scope)
    ("Engagement", EngagementContract, "engagement_registry", "client"),
    ("Target", Target, "findings", "engagement"),
    ("Finding", Finding, "findings", "engagement"),
    ("Hypothesis", Hypothesis, "hypotheses", "engagement"),
    ("ProofBundle", ProofBundle, "evidence_bundles", "engagement"),
    ("Observation", Observation, "hypotheses", "engagement"),
    ("ToolExecution", ToolExecution, "campaign_state_checkpoints", "engagement"),
    ("CampaignExecutionContract", CampaignExecutionContract, "hypotheses", "engagement"),
)


def _build_catalog() -> dict[str, ContractEntry]:
    catalog: dict[str, ContractEntry] = {}
    for name, cls, data_type, scope in _CONTRACT_CLASSES:
        if name not in _DECLARED_VERSIONS:
            raise RuntimeError(
                f"contract catalog integrity: entity {name!r} has no declared "
                "schema version — add it to _DECLARED_VERSIONS"
            )
        scoping_field = ""
        if scope == "engagement":
            scoping_field = (
                "thread_id" if "thread_id" in cls.model_fields else "engagement_id"
            )
        elif scope == "client":
            scoping_field = "client_id"
        catalog[name] = ContractEntry(
            name=name,
            entity=_entity_path(cls),
            schema_version=_DECLARED_VERSIONS[name],
            data_type=data_type,
            scope=scope,
            client_scoping_field=scoping_field,
        )
    return catalog


DOMAIN_CONTRACTS: dict[str, ContractEntry] = _build_catalog()


def export_contracts() -> dict[str, Any]:
    """Deterministic, JSON-serializable export of the whole contract.

    The CI-facing artifact (M1b acceptance: «schema-versioned exported
    contracts»): two calls in the same tree produce byte-identical
    dicts, and the export embeds every entity's dotted path + declared
    schema version + source-of-truth row, so a consumer can validate a
    payload against the exact authoritative class.
    """
    entries: dict[str, Any] = {}
    for name in sorted(DOMAIN_CONTRACTS):
        entry = DOMAIN_CONTRACTS[name]
        truth = DATA_SOURCE_OF_TRUTH.get(entry.data_type, {})
        entries[name] = {
            "entity": entry.entity,
            "schema_version": entry.schema_version,
            "data_type": entry.data_type,
            "scope": entry.scope,
            "client_scoping_field": entry.client_scoping_field,
            "source_of_truth": {
                "store": truth.get("store", "undeclared"),
                "owner_module": truth.get("owner_module", "undeclared"),
            },
        }
    return {
        "schema_version": CONTRACTS_SCHEMA_VERSION,
        "contracts": entries,
        "source_of_truth": dict(sorted(DATA_SOURCE_OF_TRUTH.items())),
    }


__all__ = [
    "CONTRACTS_SCHEMA_VERSION",
    "ENGAGEMENT_CONTRACT_SCHEMA_VERSION",
    "DATA_SOURCE_OF_TRUTH",
    "DOMAIN_CONTRACTS",
    "EngagementContract",
    "ContractEntry",
    "export_contracts",
]

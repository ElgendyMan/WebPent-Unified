# tests/test_v1_chain_composer.py
"""TC-3 §2 V-1 — Chain Composer unit tests.

The anti-fake core (FRP-1 applied to chains): an unproven chain NEVER
surfaces in reports; PROVEN requires execution + dependency digest +
the semantic owner/viewer gate; the inflation guards reject self-owned
and already-covered objects.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

cc = importlib.import_module("webpent.production.chain_composer")

REGISTRY_BODY = {
    "service": "doc-registry",
    "config_path": "/app/internal/registry.json",
    "credential_ref": "secret:internal-registry-ro",
    "registry": {
        "User_A": {"email": "user-a@lab.internal", "document_ids": ["DOC-A-11"]},
        "User_B": {"email": "user-b@lab.internal",
                   "document_ids": ["DOC-B-PUB", "DOC-B-7f3a91c"]},
    },
}


def _disclosure_finding() -> cc.ChainFinding:
    return cc.ChainFinding(
        finding_id="f_disc", family="INFO_DISCLOSURE", path="/api/admin/debug",
        engagement_id="e1", promoted_at="t", evidence_ref="p1",
        observed=REGISTRY_BODY, resource_owner="")


def _idor_finding(covered: list[str] | None = None) -> cc.ChainFinding:
    return cc.ChainFinding(
        finding_id="f_idor", family="IDOR", path="/api/documents/{doc_id}",
        engagement_id="e2", promoted_at="t", evidence_ref="p2",
        observed={}, resource_owner="User_B",
        covered_object_ids=covered if covered is not None else ["DOC-B-PUB"])


# ---------------------------------------------------------------------------
# Proposal rules
# ---------------------------------------------------------------------------
def test_no_proposal_with_single_finding():
    composer = cc.ChainComposer()
    new = composer.ingest(_disclosure_finding())
    assert new == []
    assert composer.proposal_register() == []


def test_no_proposal_for_incompatible_pair():
    composer = cc.ChainComposer()
    sql_finding = cc.ChainFinding(
        finding_id="f_sql", family="SQLI", path="/api/x", engagement_id="e1",
        promoted_at="t", evidence_ref="p3", observed={})
    composer.ingest(_disclosure_finding())
    new = composer.ingest(sql_finding)
    assert new == []


def test_proposal_is_deterministic_with_dependency_contract():
    composer = cc.ChainComposer()
    composer.ingest(_disclosure_finding())
    new = composer.ingest(_idor_finding())
    assert len(new) == 1
    p = new[0]
    assert p.llm_authority is False
    assert p.chain_type == cc.CHAIN_TYPE_CROSS_ACCOUNT_EXFIL
    assert p.dependency_contract["extract"] == "registry.User_B.document_ids"
    assert p.dependency_contract["resource_owner"] == "User_B"
    assert p.chain_potential == pytest.approx(cc.CHAIN_POTENTIAL_MULTIPLIER)


def test_same_root_cause_pair_rejected():
    """Two findings of the same family on the same path = ONE root cause —
    not chain material (inflation guard)."""
    composer = cc.ChainComposer()
    composer.ingest(_idor_finding())
    same = cc.ChainFinding(
        finding_id="f_idor2", family="IDOR", path="/api/documents/",
        engagement_id="e3", promoted_at="t", evidence_ref="p4", observed={},
        resource_owner="User_B")
    assert composer.ingest(same) == []


# ---------------------------------------------------------------------------
# Anti-fake: the proven surface
# ---------------------------------------------------------------------------
def test_unproven_chain_never_surfaces():
    composer = cc.ChainComposer()
    composer.ingest(_disclosure_finding())
    composer.ingest(_idor_finding())
    assert composer.proven_chains() == []
    assert len(composer.proposal_register()) == 1


def test_hypothesis_targets_non_enumerable_non_self_object():
    """The extraction must select the HIDDEN id — excluding the standalone
    finding's covered object AND the acting principal's own ids.  A chain
    over a self-owned object is a FALSE chain (the DOC-A-11 catch)."""
    composer = cc.ChainComposer()
    composer.ingest(_disclosure_finding())
    composer.ingest(_idor_finding(covered=["DOC-B-PUB"]))
    (chain_id, ) = [p["chain_id"] for p in composer.proposal_register()]
    hyp = composer.build_chain_hypothesis(
        chain_id, engagement_id="e_chain", step1_observed=REGISTRY_BODY)
    assert hyp is not None
    cand_path = hyp["requests"]["candidate"]["path"]
    assert cand_path.endswith("DOC-B-7f3a91c")   # the hidden object
    excluded = hyp["chain_metadata"]["excluded_object_ids"]
    assert "DOC-A-11" in excluded and "DOC-B-PUB" in excluded


def test_unbuildable_when_no_uncovered_object_remains():
    """If every disclosed id is covered or self-owned, the chain is
    UNBUILDABLE — never executed with a guessed id."""
    composer = cc.ChainComposer()
    composer.ingest(_disclosure_finding())
    composer.ingest(_idor_finding(
        covered=["DOC-B-PUB", "DOC-B-7f3a91c"]))
    (chain_id, ) = [p["chain_id"] for p in composer.proposal_register()]
    assert composer.build_chain_hypothesis(
        chain_id, engagement_id="e_chain",
        step1_observed=REGISTRY_BODY) is None
    reg = composer.proposal_register()[0]
    assert reg["status"] == "UNBUILDABLE"


def test_proven_requires_digest_and_semantic_gate():
    composer = cc.ChainComposer()
    composer.ingest(_disclosure_finding())
    composer.ingest(_idor_finding())
    (chain_id, ) = [p["chain_id"] for p in composer.proposal_register()]
    hyp = composer.build_chain_hypothesis(
        chain_id, engagement_id="e_chain", step1_observed=REGISTRY_BODY)
    used = hyp["requests"]["candidate"]["path"].rsplit("/", 1)[-1]

    # mechanics pass but the semantic gate is missing -> NOT proven
    p = composer.record_execution(
        chain_id, step1_promoted=True, step2_validator_outcome="CONFIRMED",
        step2_promotion_decision="PROMOTED", step2_used_value=used,
        step2_response_body=None)
    assert p.status != "PROVEN"

    # a self-access response (viewer == owner) -> FALSE chain, NOT proven
    p = composer.record_execution(
        chain_id, step1_promoted=True, step2_validator_outcome="CONFIRMED",
        step2_promotion_decision="PROMOTED", step2_used_value=used,
        step2_response_body={"owner": "User_B", "viewer": "User_B"})
    assert p.status != "PROVEN"

    # a guessed value breaks the dependency digest -> NOT proven
    p = composer.record_execution(
        chain_id, step1_promoted=True, step2_validator_outcome="CONFIRMED",
        step2_promotion_decision="PROMOTED", step2_used_value="DOC-GUESSED",
        step2_response_body={"owner": "User_B", "viewer": "User_A"})
    assert p.executed["dependency_digest_match"] is False
    assert p.status != "PROVEN"

    # the honest execution: digest match + owner=User_B viewed by User_A
    p = composer.record_execution(
        chain_id, step1_promoted=True, step2_validator_outcome="CONFIRMED",
        step2_promotion_decision="PROMOTED", step2_used_value=used,
        step2_response_body={"owner": "User_B", "viewer": "User_A"})
    assert p.status == "PROVEN"
    proven = composer.proven_chains()
    assert len(proven) == 1
    assert proven[0]["leg_finding_ids"] == ["f_disc", "f_idor"]
    assert proven[0]["dep_digest"]


def test_refuted_execution_stays_out_of_proven():
    composer = cc.ChainComposer()
    composer.ingest(_disclosure_finding())
    composer.ingest(_idor_finding())
    (chain_id, ) = [p["chain_id"] for p in composer.proposal_register()]
    composer.build_chain_hypothesis(
        chain_id, engagement_id="e_chain", step1_observed=REGISTRY_BODY)
    p = composer.record_execution(
        chain_id, step1_promoted=True, step2_validator_outcome="REFUTED",
        step2_promotion_decision="REJECTED", step2_used_value="DOC-B-7f3a91c",
        step2_response_body=None)
    assert p.status == "REFUTED"
    assert composer.proven_chains() == []


# ---------------------------------------------------------------------------
# Impact uplift via the REAL EVScheduler's ChainPotential
# ---------------------------------------------------------------------------
def test_chain_potential_multiplier_uplift_through_real_scheduler():
    base = {"vulnerability_class": "IDOR", "recon_signal_matches": 2,
            "estimated_cost": 6, "estimated_llm_calls": 1}
    receipt = cc.chain_ev_uplift_report(base)
    assert receipt["ev_chain_multiplier"] == pytest.approx(1.8)
    assert receipt["uplift_ratio"] == pytest.approx(1.8)
    assert receipt["ev_chained"] == pytest.approx(
        receipt["ev_standalone_basis"] * 1.8, rel=1e-4)

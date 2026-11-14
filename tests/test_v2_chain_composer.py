# tests/test_v2_chain_composer.py
"""Proposal 2 Phase 2 — ChainTypeSpec generalization and the THIRD chain
type (idor_plus_mass_assignment).

The acceptance bar mirrors tests/test_v1_chain_composer.py exactly: the
new chain type must prove under the SAME rigor — real execution, byte-
identical dependency digest, semantic ownership gate, register-until-
proven, and the inflation guards (same-root-cause, self-owned,
covered-object exclusion).  An unproven proposed chain NEVER surfaces in
reports (the anti-fake rule holds for every chain type, old or new).
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
    "registry": {
        "User_A": {"email": "user-a@lab.internal", "document_ids": ["DOC-A-11"]},
        "User_B": {"email": "user-b@lab.internal",
                   "document_ids": ["DOC-B-PUB", "DOC-B-7f3a91c"]},
    },
}


def _idor_finding(covered: list[str] | None = None) -> cc.ChainFinding:
    """The chain's step-1 leg: an IDOR whose response leaked the registry
    (ids BEYOND the object it read — covered_object_ids carries only what
    the standalone finding itself proved)."""
    return cc.ChainFinding(
        finding_id="f_idor_leak", family="IDOR",
        path="/api/documents/{doc_id}", engagement_id="e1",
        promoted_at="t", evidence_ref="p1",
        observed=REGISTRY_BODY, resource_owner="User_B",
        covered_object_ids=covered if covered is not None else ["DOC-B-PUB"])


def _mass_assignment_finding() -> cc.ChainFinding:
    return cc.ChainFinding(
        finding_id="f_mass", family="MASS_ASSIGNMENT",
        path="/api/documents/{doc_id}", engagement_id="e1",
        promoted_at="t", evidence_ref="p2",
        observed={}, resource_owner="")


def _ingest_third_type(composer: cc.ChainComposer) -> list[cc.ChainProposal]:
    new = composer.ingest(_idor_finding())
    assert new == []          # single finding -> no proposal
    return composer.ingest(_mass_assignment_finding())


# ---------------------------------------------------------------------------
# Proposal rules for the third chain type
# ---------------------------------------------------------------------------
def test_third_type_proposed_from_idor_plus_mass_assignment():
    composer = cc.ChainComposer()
    new = _ingest_third_type(composer)
    assert len(new) == 1
    p = new[0]
    assert p.chain_type == cc.CHAIN_TYPE_IDOR_MASS_ASSIGNMENT
    assert p.llm_authority is False
    assert p.leg_finding_ids == ["f_idor_leak", "f_mass"]
    contract = p.dependency_contract
    assert contract["extract"] == "registry.User_B.document_ids"
    assert contract["resource_owner"] == "User_B"
    assert contract["hypothesis_vuln_class"] == "MASS_ASSIGNMENT"
    assert contract["step2_method"] == "PUT"
    assert contract["step2_body_template"] == {"role": "admin"}
    assert contract["semantic_gate"] == "protected_field"
    assert "admin" in contract["protected_field_markers"]


def test_third_type_not_confused_with_exfiltration_chain():
    """An IDOR + MASS_ASSIGNMENT pair must NOT produce the exfiltration
    chain (that pair needs INFO_DISCLOSURE as its step-1 leg), and the
    two specs never cross-pair families."""
    composer = cc.ChainComposer()
    new = _ingest_third_type(composer)
    assert [p.chain_type for p in new] == [cc.CHAIN_TYPE_IDOR_MASS_ASSIGNMENT]


def test_two_registered_chains_coexist():
    """With all three families promoted, BOTH chain types are proposed
    through the identical machinery, in registry order."""
    composer = cc.ChainComposer()
    composer.ingest(cc.ChainFinding(
        finding_id="f_disc", family="INFO_DISCLOSURE",
        path="/api/admin/debug", engagement_id="e1", promoted_at="t",
        evidence_ref="p0", observed=REGISTRY_BODY, resource_owner=""))
    composer.ingest(_idor_finding())
    new = composer.ingest(_mass_assignment_finding())
    assert [p.chain_type for p in new] == [cc.CHAIN_TYPE_IDOR_MASS_ASSIGNMENT]
    register = composer.proposal_register()
    assert sorted(p["chain_type"] for p in register) == sorted(
        [cc.CHAIN_TYPE_CROSS_ACCOUNT_EXFIL, cc.CHAIN_TYPE_IDOR_MASS_ASSIGNMENT])


def test_proposal_is_deterministic_for_third_type():
    c1, c2 = cc.ChainComposer(), cc.ChainComposer()
    p1 = _ingest_third_type(c1)[0]
    p2 = _ingest_third_type(c2)[0]
    assert p1.chain_id == p2.chain_id
    assert p1.rationale == p2.rationale
    assert p1.dependency_contract == p2.dependency_contract


# ---------------------------------------------------------------------------
# Hypothesis construction + inflation guards (identical discipline)
# ---------------------------------------------------------------------------
def test_hypothesis_targets_non_enumerable_non_self_object():
    """DOC-B-PUB is covered by the standalone finding, DOC-A-11 is the
    acting principal's own object (self-owned exclusion reads every
    leg's registry) — only DOC-B-7f3a91c remains, and the request shape
    is the spec's write leg (PUT + protected field in the body)."""
    composer = cc.ChainComposer()
    proposal = _ingest_third_type(composer)[0]
    hyp = composer.build_chain_hypothesis(
        proposal.chain_id, engagement_id="e1",
        step1_observed=REGISTRY_BODY)
    assert hyp is not None
    assert hyp["vulnerability_class"] == "MASS_ASSIGNMENT"
    assert hyp["chain_potential"] == pytest.approx(
        cc.CHAIN_POTENTIAL_MULTIPLIER)
    md = hyp["chain_metadata"]
    assert md["selected_object_id"] == "DOC-B-7f3a91c"
    assert md["chain_type"] == cc.CHAIN_TYPE_IDOR_MASS_ASSIGNMENT
    cand = hyp["requests"]["candidate"]
    assert cand["method"] == "PUT"
    assert cand["path"] == "/api/documents/DOC-B-7f3a91c"
    assert cand["headers"]["X-User"] == "User_A"
    assert cand["body"] == {"role": "admin"}
    baseline = hyp["requests"]["baseline"]
    assert baseline["headers"]["X-User"] == "User_B"
    assert baseline["body"] == {"role": "admin"}


def test_unbuildable_when_no_uncovered_object_remains():
    composer = cc.ChainComposer()
    proposal = _ingest_third_type(composer)[0]
    hyp = composer.build_chain_hypothesis(
        proposal.chain_id, engagement_id="e1",
        step1_observed=REGISTRY_BODY,
        idor_path_prefix="/api/documents/")
    assert hyp is not None  # sane baseline
    composer2 = cc.ChainComposer()
    # a second composer where the standalone finding covered EVERYTHING
    composer2.ingest(_idor_finding(
        covered=["DOC-B-PUB", "DOC-B-7f3a91c"]))
    proposal2 = composer2.ingest(_mass_assignment_finding())[0]
    result = composer2.build_chain_hypothesis(
        proposal2.chain_id, engagement_id="e1",
        step1_observed=REGISTRY_BODY)
    assert result is None
    assert proposal2.status == cc._STATUS_UNBUILDABLE


def test_unbuildable_when_extraction_fails():
    composer = cc.ChainComposer()
    proposal = _ingest_third_type(composer)[0]
    result = composer.build_chain_hypothesis(
        proposal.chain_id, engagement_id="e1", step1_observed={})
    assert result is None
    assert proposal.status == cc._STATUS_UNBUILDABLE


def test_unknown_chain_type_fails_closed():
    """A proposal whose chain type was never registered has no proofable
    shape — it is NEVER executed (status -> UNBUILDABLE, no hypothesis)."""

    class _ForeignProposer:
        def propose(self, findings):
            return [cc.ChainProposal(
                chain_id="chain_foreign_1",
                chain_type="mystery_chain_from_causal_layer",
                leg_finding_ids=[f.finding_id for f in findings],
                rationale="unregistered", proposed_by="foreign",
                llm_authority=False,
                dependency_contract={"extract": "registry.User_B.document_ids",
                                     "resource_owner": "User_B"})]

    composer = cc.ChainComposer(proposer=_ForeignProposer())
    new = composer.ingest(_idor_finding())
    assert len(new) == 1
    result = composer.build_chain_hypothesis(
        "chain_foreign_1", engagement_id="e1",
        step1_observed=REGISTRY_BODY)
    assert result is None
    assert new[0].status == cc._STATUS_UNBUILDABLE


# ---------------------------------------------------------------------------
# Proof rules — the SAME anti-fake gates as the existing chain type
# ---------------------------------------------------------------------------
def _record(composer, proposal, *, body=None, outcome="CONFIRMED",
            decision="PROMOTED", used="DOC-B-7f3a91c",
            step1_promoted=True):
    return composer.record_execution(
        proposal.chain_id, step1_promoted=step1_promoted,
        step2_validator_outcome=outcome, step2_promotion_decision=decision,
        step2_used_value=used, step2_response_body=body,
        proof_ref="proof-x")


def test_unproven_third_type_never_surfaces():
    composer = cc.ChainComposer()
    proposal = _ingest_third_type(composer)[0]
    composer.build_chain_hypothesis(proposal.chain_id, engagement_id="e1",
                                    step1_observed=REGISTRY_BODY)
    # executed mechanics-only: no response body -> semantic gate fails
    _record(composer, proposal, body=None)
    assert proposal.status == cc._STATUS_PROPOSED
    assert composer.proven_chains() == []


def test_proven_requires_digest_and_semantic_gate_third_type():
    composer = cc.ChainComposer()
    proposal = _ingest_third_type(composer)[0]
    composer.build_chain_hypothesis(proposal.chain_id, engagement_id="e1",
                                    step1_observed=REGISTRY_BODY)

    # mechanics-only (no response body): NOT proven
    _record(composer, proposal, body=None)
    assert proposal.status == cc._STATUS_PROPOSED
    # self-access: the acting principal mutating its OWN object
    _record(composer, proposal, body={"owner": "User_A",
                                      "viewer": "User_A",
                                      "role": "admin"})
    assert proposal.status == cc._STATUS_PROPOSED
    # third-party viewer: the mutation came from neither the acting
    # principal nor the owner — no cross-principal proof
    _record(composer, proposal, body={"owner": "User_B",
                                      "viewer": "User_C",
                                      "role": "admin"})
    assert proposal.status == cc._STATUS_PROPOSED
    # owner hit + acting principal, but NO escalated marker in the body
    _record(composer, proposal, body={"owner": "User_B",
                                      "viewer": "User_A",
                                      "role": "viewer"})
    assert proposal.status == cc._STATUS_PROPOSED
    # guessed value: the dependency digest does not match
    _record(composer, proposal, used="DOC-GUESSED-000",
            body={"owner": "User_B", "viewer": "User_A", "role": "admin"})
    assert proposal.status == cc._STATUS_PROPOSED
    # honest execution: the protected write hit the resource owner's
    # object, performed by the acting principal, with the escalated value
    final = _record(composer, proposal,
                    body={"owner": "User_B", "viewer": "User_A",
                          "role": "admin", "name": "doc"})
    assert final.status == cc._STATUS_PROVEN
    proven = composer.proven_chains()
    assert len(proven) == 1
    assert proven[0]["chain_type"] == cc.CHAIN_TYPE_IDOR_MASS_ASSIGNMENT
    assert proven[0]["executed"]["semantic_owner_viewer_gate"] is True


def test_wrong_digest_on_third_type_stays_out_of_proven():
    """A chain executed with a guessed parameter must never reach
    proven — even with a perfect semantic body (the digest gate is
    independent of the semantic gate)."""
    composer = cc.ChainComposer()
    proposal = _ingest_third_type(composer)[0]
    composer.build_chain_hypothesis(proposal.chain_id, engagement_id="e1",
                                    step1_observed=REGISTRY_BODY)
    record = _record(composer, proposal, used="DOC-OTHER-123",
                     body={"owner": "User_B", "viewer": "User_A",
                           "role": "admin"})
    assert record.status == cc._STATUS_PROPOSED
    assert record.executed["dependency_digest_match"] is False


def test_refuted_third_type_execution_stays_out_of_proven():
    composer = cc.ChainComposer()
    proposal = _ingest_third_type(composer)[0]
    composer.build_chain_hypothesis(proposal.chain_id, engagement_id="e1",
                                    step1_observed=REGISTRY_BODY)
    record = _record(composer, proposal, outcome="REFUTED", decision=None,
                     body={"owner": "User_B", "viewer": "User_A",
                           "role": "admin"})
    assert record.status == cc._STATUS_REFUTED
    assert composer.proven_chains() == []


def test_refuted_leg_promotion_required_third_type():
    """A CONFIRMED step-2 whose promotion decision never landed is not a
    proven chain — promotion is part of the proof, not a formality."""
    composer = cc.ChainComposer()
    proposal = _ingest_third_type(composer)[0]
    composer.build_chain_hypothesis(proposal.chain_id, engagement_id="e1",
                                    step1_observed=REGISTRY_BODY)
    record = _record(composer, proposal, outcome="CONFIRMED",
                     decision="HOLD",
                     body={"owner": "User_B", "viewer": "User_A",
                           "role": "admin"})
    assert record.status == cc._STATUS_PROPOSED
    assert composer.proven_chains() == []


# ---------------------------------------------------------------------------
# Dynamic registration seam (fail-closed)
# ---------------------------------------------------------------------------
def test_register_rejects_duplicate_and_collision():
    dup = cc.ChainTypeSpec(
        chain_type=cc.CHAIN_TYPE_IDOR_MASS_ASSIGNMENT,
        step1_family="IDOR", step2_family="MASS_ASSIGNMENT",
        id_source_template="registry.{resource_owner}.document_ids",
        hypothesis_vuln_class="MASS_ASSIGNMENT", rationale_template="x")
    assert cc.register_chain_type_spec(dup) is False
    # family-pair collision with the exfiltration spec (same leg pairing)
    collision = cc.ChainTypeSpec(
        chain_type="another_exfil_variant",
        step1_family="INFO_DISCLOSURE", step2_family="IDOR",
        id_source_template="registry.{resource_owner}.document_ids",
        hypothesis_vuln_class="IDOR", rationale_template="x")
    assert cc.register_chain_type_spec(collision) is False
    # malformed spec: empty id_source_template
    malformed = cc.ChainTypeSpec(
        chain_type="valid_looking", step1_family="A", step2_family="B",
        id_source_template="  ", hypothesis_vuln_class="IDOR",
        rationale_template="x")
    assert cc.register_chain_type_spec(malformed) is False
    # protected_field gate without markers
    no_markers = cc.ChainTypeSpec(
        chain_type="no_marker_gate", step1_family="A", step2_family="B",
        id_source_template="x", hypothesis_vuln_class="IDOR",
        rationale_template="x", semantic_gate="protected_field")
    assert cc.register_chain_type_spec(no_markers) is False
    assert cc.get_chain_type_spec("valid_looking") is None


def test_registered_spec_flows_through_identical_machinery():
    """A NEWLY registered chain type proposes, builds, and proves through
    the same gates with zero edits to the proof machinery — then is
    removed so other tests see the default registry."""
    try:
        spec = cc.ChainTypeSpec(
            chain_type="idor_plus_protected_read",
            step1_family="IDOR", step2_family="PROTECTED_READ",
            id_source_template="registry.{resource_owner}.document_ids",
            hypothesis_vuln_class="PROTECTED_READ",
            rationale_template="{s1_family} + {s2_family}",
            semantic_gate="owner_viewer")
        assert cc.register_chain_type_spec(spec) is True
        assert cc.get_chain_type_spec("idor_plus_protected_read") is spec

        composer = cc.ChainComposer()
        composer.ingest(_idor_finding())
        new = composer.ingest(cc.ChainFinding(
            finding_id="f_pread", family="PROTECTED_READ",
            path="/api/audit/{doc_id}", engagement_id="e1", promoted_at="t",
            evidence_ref="p9", observed={}, resource_owner=""))
        assert len(new) == 1 and new[0].chain_type == "idor_plus_protected_read"
        hyp = composer.build_chain_hypothesis(
            new[0].chain_id, engagement_id="e1",
            step1_observed=REGISTRY_BODY)
        assert hyp is not None
        assert hyp["vulnerability_class"] == "PROTECTED_READ"
        assert hyp["requests"]["candidate"]["method"] == "GET"
        final = _record(composer, new[0],
                        body={"owner": "User_B", "viewer": "User_A"})
        assert final.status == cc._STATUS_PROVEN
        # NOTE: the owner_viewer gate applies — no protected marker needed
        assert composer.proven_chains()[0]["chain_type"] == \
            "idor_plus_protected_read"
    finally:
        cc._CHAIN_TYPE_SPECS.pop("idor_plus_protected_read", None)
    assert cc.get_chain_type_spec("idor_plus_protected_read") is None


def test_registered_chain_types_order_is_deterministic():
    assert cc.registered_chain_types() == (
        cc.CHAIN_TYPE_CROSS_ACCOUNT_EXFIL,
        cc.CHAIN_TYPE_IDOR_MASS_ASSIGNMENT,
    )


def test_default_proposer_excludes_unregistered_documented_type():
    """ACCOUNT_TAKEOVER stays documented-but-unregistered: registering it
    without lanes would only produce permanent PROPOSED entries."""
    assert cc.CHAIN_TYPE_ACCOUNT_TAKEOVER not in cc.registered_chain_types()

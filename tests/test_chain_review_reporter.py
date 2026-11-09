# tests/test_chain_review_reporter.py
"""Proposal 2 Phase 3 — the optional 'suggested chains under review'
report section.

The anti-fake rule holds in the reporter: the suggested section is
STRUCTURALLY ABSENT when the flag is off, always labeled advisory when
on, and can never merge into proven chains or findings.
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
review = importlib.import_module("webpent.reporter.chain_review")

from webpent.config.settings import get_settings


@pytest.fixture(autouse=True)
def _reset_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _composer_with_proposals():
    composer = cc.ChainComposer()
    composer.ingest(cc.ChainFinding(
        finding_id="f_disc", family="INFO_DISCLOSURE",
        path="/api/admin/debug", engagement_id="e1", promoted_at="t",
        evidence_ref="p0", resource_owner="",
        observed={"registry": {
            "User_A": {"document_ids": ["DOC-A-11"]},
            "User_B": {"document_ids": ["DOC-B-PUB", "DOC-B-7f3a91c"]},
        }}))
    composer.ingest(cc.ChainFinding(
        finding_id="f_idor", family="IDOR", path="/api/documents/{doc_id}",
        engagement_id="e1", promoted_at="t", evidence_ref="p1",
        resource_owner="User_B", covered_object_ids=["DOC-B-PUB"]))
    return composer


def _composer_with_proven_chain():
    composer = _composer_with_proposals()
    (proposal,) = composer.proposal_register()
    composer.build_chain_hypothesis(
        proposal["chain_id"], engagement_id="e1",
        step1_observed={"registry": {
            "User_A": {"document_ids": ["DOC-A-11"]},
            "User_B": {"document_ids": ["DOC-B-PUB", "DOC-B-7f3a91c"]},
        }})
    composer.record_execution(
        proposal["chain_id"], step1_promoted=True,
        step2_validator_outcome="CONFIRMED",
        step2_promotion_decision="PROMOTED",
        step2_used_value="DOC-B-7f3a91c",
        step2_response_body={"owner": "User_B", "viewer": "User_A"},
        proof_ref="proof-1")
    return composer


def test_flag_default_off():
    assert get_settings().enable_chain_review_section is False


def test_flag_off_suggested_section_structurally_absent():
    sections = review.chain_review_sections(
        _composer_with_proposals(), include_suggested=False)
    assert "suggested_chains_under_review" not in sections
    assert sections["proven_chains"] == []


def test_flag_on_under_review_section_is_advisory_and_separate():
    composer = _composer_with_proposals()
    sections = review.chain_review_sections(
        composer, include_suggested=True)
    suggested = sections["suggested_chains_under_review"]
    assert suggested["advisory"] is True
    assert "UNPROVEN" in suggested["warning"]
    assert len(suggested["chains"]) == 1
    entry = suggested["chains"][0]
    assert entry["review_status"] == "under_review_unproven"
    assert entry["status"] == "PROPOSED"
    # the proven section stays empty — nothing was proven
    assert sections["proven_chains"] == []


def test_causal_candidates_labeled_with_provenance():
    composer = _composer_with_proposals()
    state = {"causal_chain_candidates": [
        {"id": "cand-1", "statement": "[causal sibling] probe"}]}
    sections = review.chain_review_sections(
        composer, include_suggested=True, state=state)
    chains = sections["suggested_chains_under_review"]["chains"]
    provenances = {c["provenance"] for c in chains}
    assert provenances == {"chain_composer_register",
                           "causal_reasoning_v2"}
    causal = [c for c in chains if c["provenance"] == "causal_reasoning_v2"]
    assert causal[0]["review_status"] == "under_review_candidate"


def test_proven_chain_lands_only_in_proven_section():
    composer = _composer_with_proven_chain()
    sections = review.chain_review_sections(
        composer, include_suggested=True)
    assert len(sections["proven_chains"]) == 1
    assert sections["proven_chains"][0]["status"] == "PROVEN"
    # the proven chain no longer appears under review
    ids_under_review = {
        c.get("chain_id")
        for c in sections["suggested_chains_under_review"]["chains"]}
    assert sections["proven_chains"][0]["chain_id"] not in ids_under_review


def test_render_keeps_warning_inline():
    sections = review.chain_review_sections(
        _composer_with_proposals(), include_suggested=True)
    rendered = review.render_chain_review_markdown(sections)
    assert "## Proven Chains (0)" in rendered
    assert "UNPROVEN, advisory" in rendered
    assert "under review only" in rendered
    assert "PROPOSED" in rendered


def test_render_without_suggested_section_renders_proven_only():
    sections = review.chain_review_sections(
        _composer_with_proven_chain(), include_suggested=False)
    rendered = review.render_chain_review_markdown(sections)
    assert "Proven Chains (1)" in rendered
    assert "Suggested Chains" not in rendered

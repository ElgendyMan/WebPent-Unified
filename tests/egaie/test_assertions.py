"""L10 Phase 2 — generalized four-valued assertion ledger.

Red-first unit tests for the three behaviors the mission names —
promotion, invalidation, reconciliation — plus the rules that make
the ledger evidence-integrity-safe:

- no auto-promotion: INFERRED/UNKNOWN is never VERIFIED, and no
  path creates a VERIFIED assertion without an observation id;
- contradiction invalidates (never overwrites) and demotes every
  transitive dependent to UNKNOWN, returning the re-evaluation set;
- INVALIDATED is terminal until an investigator re-asserts on
  purpose;
- assertions are beliefs, not evidence: the status survives into
  any summary verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from webpent.egaie.assertions import (
    AssertionLedger,
    AssertionStatus,
    summarize,
)

# ------------------------------------------------------------- promotion

def test_verified_requires_an_observation_id() -> None:
    ledger = AssertionLedger()
    ledger.infer("state:/x", "draft")
    with pytest.raises(ValueError, match="observation id"):
        ledger.verify("state:/x", "draft", "")
    assert ledger.status("state:/x") is AssertionStatus.INFERRED


def test_inferred_never_promotes_itself() -> None:
    """No operation short of verify()/reconcile() changes status."""
    ledger = AssertionLedger()
    ledger.infer("state:/x", "draft")
    ledger.depends_on("state:/x", "state:/x/child")
    ledger.infer("state:/x/child", "draft-child")
    # re-inferring, reading, tallying: all read-only for status.
    ledger.infer("state:/x", "draft", detail="again")
    assert ledger.status("state:/x") is AssertionStatus.INFERRED
    assert not ledger.is_fact("state:/x")


def test_verify_promotes_only_with_matching_value_and_cites_provenance(
) -> None:
    ledger = AssertionLedger()
    ledger.infer("state:/x", "draft")
    verified, reevaluate = ledger.verify("state:/x", "draft", "obs-1")
    assert verified.status is AssertionStatus.VERIFIED
    assert verified.provenance.observation_id == "obs-1"
    assert verified.provenance.source == "observation"
    assert reevaluate == set()
    assert ledger.is_fact("state:/x")
    # the provenance trail carries both the inference and the
    # verification.
    assert [p.source for p in verified.history] == [
        "inference", "observation"]


def test_verify_never_creates_an_assertion() -> None:
    ledger = AssertionLedger()
    with pytest.raises(KeyError):
        ledger.verify("state:/never-asserted", "draft", "obs-1")


def test_verify_after_invalidation_is_refused() -> None:
    ledger = AssertionLedger()
    ledger.infer("state:/x", "draft")
    ledger.invalidate("state:/x", "obs-0", reason="superseded")
    with pytest.raises(ValueError, match="INVALIDATED"):
        ledger.verify("state:/x", "draft", "obs-2")


# --------------------------------------------------------- invalidation

def test_contradiction_invalidates_instead_of_overwriting() -> None:
    ledger = AssertionLedger()
    ledger.infer("state:/x", "draft")
    invalidated, _ = ledger.verify(
        "state:/x", "funded", "obs-2")
    assert invalidated.status is AssertionStatus.INVALIDATED
    assert invalidated.value == "draft"      # value preserved
    assert invalidated.provenance.observation_id == "obs-2"
    assert "funded" in invalidated.provenance.detail
    assert ledger.status("state:/x") is AssertionStatus.INVALIDATED
    # nothing silently became verified.
    assert not ledger.is_fact("state:/x")


def test_invalidation_demotes_dependents_transitively() -> None:
    ledger = AssertionLedger()
    ledger.infer("state:/a", "s0")
    ledger.infer("state:/b", "s1")
    ledger.infer("state:/c", "s2")
    ledger.depends_on("state:/a", "state:/b")
    ledger.depends_on("state:/b", "state:/c")
    verified_b, _ = ledger.verify("state:/b", "s1", "obs-b")
    assert verified_b.is_fact
    invalidated, reevaluate = ledger.invalidate(
        "state:/a", "obs-a", reason="contradicted by re-read")
    assert invalidated.status is AssertionStatus.INVALIDATED
    # both downstream beliefs lost their basis and are UNKNOWN.
    assert ledger.status("state:/b") is AssertionStatus.UNKNOWN
    assert ledger.status("state:/c") is AssertionStatus.UNKNOWN
    assert reevaluate == {"state:/b", "state:/c"}
    # a demoted dependent keeps its value (the belief content) but
    # is never a fact.
    assert ledger.value("state:/b") == "s1"
    assert not ledger.is_fact("state:/b")


def test_reverification_after_demotion() -> None:
    """Downstream re-evaluation: an UNKNOWN dependent can be
    re-verified by a fresh observation on purpose."""
    ledger = AssertionLedger()
    ledger.infer("state:/a", "s0")
    ledger.infer("state:/b", "s1")
    ledger.depends_on("state:/a", "state:/b")
    ledger.verify("state:/b", "s1", "obs-b")
    ledger.invalidate("state:/a", "obs-a")
    assert ledger.status("state:/b") is AssertionStatus.UNKNOWN
    verified, reevaluate = ledger.verify("state:/b", "s1", "obs-b2")
    assert verified.is_fact
    assert reevaluate == set()


def test_invalidation_is_terminal_until_reasserted() -> None:
    ledger = AssertionLedger()
    ledger.infer("state:/x", "draft")
    ledger.invalidate("state:/x", "obs-1")
    # a later agreeing observation does NOT auto-recover it.
    with pytest.raises(ValueError, match="INVALIDATED"):
        ledger.reconcile("state:/x", "draft", "obs-2")
    # an investigator re-asserts on purpose, then verifies.
    ledger.infer("state:/x", "draft", detail="re-asserted after "
                                            "re-reading")
    verified, _ = ledger.verify("state:/x", "draft", "obs-3")
    assert verified.is_fact


def test_dependency_cycles_are_tolerated() -> None:
    ledger = AssertionLedger()
    ledger.infer("state:/a", "s0")
    ledger.infer("state:/b", "s1")
    ledger.depends_on("state:/a", "state:/b")
    ledger.depends_on("state:/b", "state:/a")
    invalidated, reevaluate = ledger.invalidate("state:/a", "obs-1")
    assert invalidated.status is AssertionStatus.INVALIDATED
    assert reevaluate == {"state:/b"}


def test_invalidation_spares_invalidated_dependents() -> None:
    """An already-INVALIDATED dependent stays INVALIDATED (its own
    terminal state) and is not re-demoted to UNKNOWN."""
    ledger = AssertionLedger()
    ledger.infer("state:/a", "s0")
    ledger.infer("state:/b", "s1")
    ledger.depends_on("state:/a", "state:/b")
    ledger.invalidate("state:/b", "obs-b")
    ledger.invalidate("state:/a", "obs-a")
    assert ledger.status("state:/b") is AssertionStatus.INVALIDATED


# -------------------------------------------------------- reconciliation

def test_reconcile_agreement_keeps_verified() -> None:
    ledger = AssertionLedger()
    ledger.infer("state:/x", "draft")
    ledger.verify("state:/x", "draft", "obs-1")
    reconciled, reevaluate = ledger.reconcile(
        "state:/x", "draft", "obs-2")
    assert reconciled.status is AssertionStatus.VERIFIED
    assert reevaluate == set()
    assert [p.source for p in reconciled.history] == [
        "inference", "observation", "observation"]


def test_reconcile_disagreement_invalidates() -> None:
    ledger = AssertionLedger()
    ledger.infer("state:/x", "draft")
    ledger.verify("state:/x", "draft", "obs-1")
    reconciled, _ = ledger.reconcile("state:/x", "funded", "obs-2")
    assert reconciled.status is AssertionStatus.INVALIDATED


def test_mark_unknown_explicitly_parks() -> None:
    ledger = AssertionLedger()
    ledger.infer("state:/x", "draft")
    ledger.verify("state:/x", "draft", "obs-1")
    parked = ledger.mark_unknown("state:/x", detail="investigation "
                                                   "budget exhausted")
    assert parked.status is AssertionStatus.UNKNOWN
    assert parked.value == "draft"
    assert not ledger.is_fact("state:/x")


# ------------------------------------------------------- surface adapter

def test_seed_from_view_infers_state_beliefs_never_facts() -> None:
    @dataclass
    class _View:
        workflow_paths: tuple[str, ...] = ()
        workflow_state: dict[str, str] = field(default_factory=dict)

        # the ledger reads only these two attributes.
        def __getattr__(self, name: str) -> Any:
            raise AttributeError(name)

    ledger = AssertionLedger()
    seeded = ledger.seed_from_view(_View(
        workflow_paths=("/desk/a", "/desk/b"),
        workflow_state={"/desk/a": "received",
                        "/desk/b": "funded"}))
    assert [a.key for a in seeded] == [
        "state:/desk/a", "state:/desk/b"]
    for a in seeded:
        assert a.status is AssertionStatus.INFERRED
        assert not a.is_fact
    assert ledger.value("state:/desk/b") == "funded"


def test_seed_from_view_skips_paths_without_state() -> None:
    @dataclass
    class _View:
        workflow_paths: tuple[str, ...] = ("/desk/a", "/desk/b")
        workflow_state: dict[str, str] = field(default_factory=dict)

    ledger = AssertionLedger()
    seeded = ledger.seed_from_view(_View(
        workflow_state={"/desk/a": "received"}))
    assert [a.key for a in seeded] == ["state:/desk/a"]


# ---------------------------------------------------------- accounting

def test_tally_counts_by_status() -> None:
    ledger = AssertionLedger()
    ledger.infer("state:/a", "s0")
    ledger.infer("state:/b", "s1")
    ledger.verify("state:/b", "s1", "obs-b")
    ledger.infer("state:/c", "s2")
    ledger.invalidate("state:/c", "obs-c")
    tally = ledger.tally()
    assert tally == {"verified": 1, "inferred": 1, "unknown": 0,
                     "invalidated": 1}


def test_summarize_preserves_belief_status_verbatim() -> None:
    """A summary never renders an INFERRED assertion as fact."""
    ledger = AssertionLedger()
    ledger.infer("state:/a", "s0")
    ledger.verify("state:/a", "s0", "obs-a")
    ledger.infer("state:/b", "s1")
    rows = summarize(ledger, ("state:/a", "state:/b", "state:/z"))
    assert rows == [
        {"key": "state:/a", "value": "s0", "status": "verified",
         "source": "observation", "observation_id": "obs-a"},
        {"key": "state:/b", "value": "s1", "status": "inferred",
         "source": "inference", "observation_id": ""},
    ]

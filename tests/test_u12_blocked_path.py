"""U-12 Blocked-Path Protocol tests.

Restored after the workspace reset. 7 tests over
``webpent.brain.blocked_path.BlockedPathProtocol``:

  1. record_block creates a BlockedRecord with the required fields.
  2. check_invariant passes when >=2 alternatives were considered.
  3. check_invariant passes when a campaign_terminal_justification is
     supplied (the terminal branch is a valid end-state, not a dead-end).
  4. check_invariant FAILS when neither alternatives nor a terminal
     justification is supplied (true dead-end — fail-closed).
  5. check_no_dead_ends is an alias for check_invariant.
  6. check_no_blind_repeats detects when the same (stage, reason_class)
     pair recurs more than max_retries times.
  7. BlockedRecord.to_dict round-trips the reason_class enum as its
     string value (stable serialization for the audit trail).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.brain.blocked_path import (  # noqa: E402
    BlockedPathProtocol,
    BlockedRecord,
    ReasonClass,
)


# ---------------------------------------------------------------------------
# Test 1: record_block creates a record with the required fields
# ---------------------------------------------------------------------------
def test_record_block_creates_record_with_required_fields():
    proto = BlockedPathProtocol()
    rec = proto.record_block(
        stage="recon.fetch",
        reason_class=ReasonClass.AUTH_FAILURE,
        evidence="401 from /api/v1/users",
        alternatives=[
            {"action": "retry_with_reauth", "rejected": "credential_missing"},
            {"action": "skip_endpoint", "rejected": "leaves_coverage_gap"},
        ],
        chosen_next="terminal",
    )
    assert isinstance(rec, BlockedRecord)
    assert rec.stage == "recon.fetch"
    assert rec.reason_class == ReasonClass.AUTH_FAILURE
    assert rec.evidence == "401 from /api/v1/users"
    assert len(rec.alternatives_considered) == 2
    assert rec.chosen_next == "terminal"
    assert proto.get_records() == [rec]


# ---------------------------------------------------------------------------
# Test 2: invariant passes with >=2 alternatives
# ---------------------------------------------------------------------------
def test_check_invariant_passes_with_two_alternatives():
    proto = BlockedPathProtocol()
    proto.record_block(
        stage="recon.fetch",
        reason_class=ReasonClass.TRANSIENT,
        evidence="503 from /api/v1/users",
        alternatives=[
            {"action": "retry", "rejected": "still_503"},
            {"action": "backoff", "rejected": "out_of_budget"},
        ],
    )
    assert proto.check_invariant() is True


# ---------------------------------------------------------------------------
# Test 3: invariant passes with a campaign_terminal_justification
# ---------------------------------------------------------------------------
def test_check_invariant_passes_with_terminal_justification():
    proto = BlockedPathProtocol()
    proto.record_block(
        stage="exploit.confirm",
        reason_class=ReasonClass.EVIDENCE_INSUFFICIENT,
        evidence="differential too weak to seal proof",
        alternatives=[],  # no alternatives considered
        campaign_terminal_justification=(
            "candidate had <2 indicator classes; further attempts cannot "
            "manufacture evidence and would burn budget"
        ),
    )
    assert proto.check_invariant() is True


# ---------------------------------------------------------------------------
# Test 4: invariant FAILS with no alternatives and no justification
# ---------------------------------------------------------------------------
def test_check_invariant_fails_with_no_alternatives_or_justification():
    proto = BlockedPathProtocol()
    proto.record_block(
        stage="recon.fetch",
        reason_class=ReasonClass.LLM_FAILURE,
        evidence="LLM returned empty response",
        alternatives=[],  # dead-end
    )
    assert proto.check_invariant() is False


# ---------------------------------------------------------------------------
# Test 5: check_no_dead_ends is an alias for check_invariant
# ---------------------------------------------------------------------------
def test_check_no_dead_ends_aliases_invariant():
    proto = BlockedPathProtocol()
    proto.record_block(
        stage="recon.fetch",
        reason_class=ReasonClass.SCOPE_DENIAL,
        evidence="out of engagement scope",
        alternatives=[],
    )
    # Both methods must agree — they implement the same invariant.
    assert proto.check_no_dead_ends() == proto.check_invariant()


# ---------------------------------------------------------------------------
# Test 6: check_no_blind_repeats detects excessive repeats
# ---------------------------------------------------------------------------
def test_check_no_blind_repeats_detects_excessive_repeats():
    proto = BlockedPathProtocol()
    # Same (stage, reason_class) repeated 4 times with no progress —
    # exceeds the default max_retries=3.
    for _ in range(4):
        proto.record_block(
            stage="recon.fetch",
            reason_class=ReasonClass.TRANSIENT,
            evidence="503 again",
            alternatives=[
                {"action": "retry", "rejected": "still_503"},
                {"action": "backoff", "rejected": "out_of_budget"},
            ],
        )
    assert proto.check_no_blind_repeats(max_retries=3) is False
    # Lowering max_retries to 4 (>= observed count) flips the check.
    assert proto.check_no_blind_repeats(max_retries=4) is True


# ---------------------------------------------------------------------------
# Test 7: to_dict round-trips reason_class as its string value
# ---------------------------------------------------------------------------
def test_to_dict_round_trip_preserves_reason_class_value():
    proto = BlockedPathProtocol()
    rec = proto.record_block(
        stage="exploit.confirm",
        reason_class=ReasonClass.FABRIC_GAP,
        evidence="validator produced no sealed proof",
        alternatives=[
            {"action": "re_run", "rejected": "deterministic"},
            {"action": "terminal", "rejected": "no_justification_yet"},
        ],
        lesson_proposal="fabric_gap_at_confirm_stage",
    )
    serialised = rec.to_dict()
    # reason_class is serialised as its enum string value, not the
    # enum object — stable for the audit trail.
    assert serialised["reason_class"] == "FABRIC_GAP"
    assert isinstance(serialised["reason_class"], str)
    assert serialised["lesson_proposal"] == "fabric_gap_at_confirm_stage"
    assert serialised["stage"] == "exploit.confirm"

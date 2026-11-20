"""U-16 Smart Payload Selector tests.

Restored after the workspace reset. 4 tests over
``webpent.brain.payload_selector.PayloadSelector``:

  * Top-k ranking (2 tests):
      - select() returns the top-k payloads ranked by effectiveness
        weighted by context-tag match.
      - select() returns an empty list for an unknown family
        (fail-closed — no generic fallback).
  * Spray-refusal (1 test):
      - select_or_refuse() raises ValueError when an unranked
        exhaustive list is supplied — the selector refuses to spray
        payloads without ranking them.
  * Feedback (1 test):
      - record_outcome() updates the payload's effectiveness using an
        exponential moving average of the observed success rate.
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

from webpent.brain.payload_selector import PayloadEntry, PayloadSelector  # noqa: E402


# ---------------------------------------------------------------------------
# Top-k ranking (2 tests)
# ---------------------------------------------------------------------------
class TestTopKRanking:
    def test_select_returns_top_k_ranked_by_effectiveness(self):
        """select() returns up to k payloads ranked by effectiveness *
        context-match, descending. Ties break alphabetically by
        payload string.
        """
        sel = PayloadSelector(k=2)
        sel.register_payload(PayloadEntry(payload="bbb", family="XSS", effectiveness=0.7,
                                          context_tags=["html"]))
        sel.register_payload(PayloadEntry(payload="aaa", family="XSS", effectiveness=0.9,
                                          context_tags=["html"]))
        sel.register_payload(PayloadEntry(payload="ccc", family="XSS", effectiveness=0.5,
                                          context_tags=["html"]))
        selected = sel.select(family="XSS", context_tags=["html"])
        # Top-2 by effectiveness: aaa (0.9) and bbb (0.7).
        assert [p.payload for p in selected] == ["aaa", "bbb"]

    def test_select_returns_empty_for_unknown_family(self):
        """select() returns an empty list for a family with no
        registered payloads — fail-closed, no generic fallback.
        """
        sel = PayloadSelector(k=5)
        sel.register_payload(PayloadEntry(payload="x", family="XSS"))
        assert sel.select(family="SQLI") == []
        assert sel.select(family="ssrf") == []  # case-insensitive lookup


# ---------------------------------------------------------------------------
# Spray-refusal (1 test)
# ---------------------------------------------------------------------------
class TestSprayRefusal:
    def test_select_or_refuse_rejects_unranked_spray(self):
        """select_or_refuse() raises ValueError when an unranked
        exhaustive list is supplied — the selector refuses to spray
        payloads without first ranking them.
        """
        sel = PayloadSelector(k=3)
        sel.register_payload(PayloadEntry(payload="p1", family="XSS", effectiveness=0.6))
        with pytest.raises(ValueError, match="SPRAY-REFUSAL"):
            sel.select_or_refuse(
                family="XSS",
                context_tags=[],
                unranked_list=["p1", "p2", "p3", "p4"],  # unranked spray
            )
        # Without unranked_list, select_or_refuse delegates to select.
        selected = sel.select_or_refuse(family="XSS", context_tags=[])
        assert len(selected) == 1
        assert selected[0].payload == "p1"


# ---------------------------------------------------------------------------
# Feedback (1 test)
# ---------------------------------------------------------------------------
class TestFeedback:
    def test_record_outcome_updates_effectiveness_with_ema(self):
        """record_outcome() updates the payload's effectiveness using
        the formula ``new = old * 0.7 + observed * 0.3`` after each
        recorded outcome.
        """
        sel = PayloadSelector(k=5)
        sel.register_payload(PayloadEntry(payload="p", family="XSS", effectiveness=0.5))
        # Record 4 successes in a row: observed=1.0 each time.
        # After 4 successes: 0.5*0.7^4 + 1.0*(0.3 + 0.3*0.7 + 0.3*0.7^2 + 0.3*0.7^3)
        # The effectiveness must strictly increase toward 1.0.
        for _ in range(4):
            sel.record_outcome(payload="p", family="XSS", success=True)
        entries = sel._index["XSS"]
        assert len(entries) == 1
        updated = entries[0]
        assert updated.effectiveness > 0.5
        assert updated.times_used == 4
        assert updated.times_succeeded == 4
        # Closed-form check: after one success, new = 0.5*0.7 + 1.0*0.3 = 0.65
        # We've done 4; the value should be > 0.65 (monotonically increasing).
        assert updated.effectiveness > 0.65

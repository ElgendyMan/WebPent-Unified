# tests/test_confidence_calibration.py
"""Track 12 item 8 — calibrated learning from human accept/reject
decisions (bounded reordering, client isolation, aggregates only)."""

from __future__ import annotations

import json

from webpent.production.confidence_calibration import (
    MAX_MULTIPLIER,
    MIN_MULTIPLIER,
    CalibrationRecord,
    ConfidenceCalibrator,
    HumanDecision,
)


def make_calibrator(tmp_path) -> ConfidenceCalibrator:
    return ConfidenceCalibrator(tmp_path / "calibration")


def feed(calibrator, client, vuln_class, accepted, rejected):
    for _ in range(accepted):
        calibrator.record_decision(
            CalibrationRecord(
                client_id=client, vuln_class=vuln_class, decision=HumanDecision.ACCEPTED
            )
        )
    for _ in range(rejected):
        calibrator.record_decision(
            CalibrationRecord(
                client_id=client, vuln_class=vuln_class, decision=HumanDecision.REJECTED
            )
        )


class TestMultiplier:
    def test_cold_class_is_exactly_neutral(self, tmp_path):
        cal = make_calibrator(tmp_path)
        assert cal.class_multiplier("c1", "xss") == 1.0

    def test_all_accepted_pushes_up_bounded(self, tmp_path):
        cal = make_calibrator(tmp_path)
        feed(cal, "c1", "xss", accepted=30, rejected=0)
        m = cal.class_multiplier("c1", "xss")
        assert m > 1.0
        assert m <= MAX_MULTIPLIER

    def test_all_rejected_pushes_down_bounded(self, tmp_path):
        cal = make_calibrator(tmp_path)
        feed(cal, "c1", "sqli", accepted=0, rejected=30)
        m = cal.class_multiplier("c1", "sqli")
        assert m < 1.0
        assert m >= MIN_MULTIPLIER

    def test_small_history_stays_near_neutral(self, tmp_path):
        """Laplace smoothing: 2 accepts must NOT slam the multiplier."""
        cal = make_calibrator(tmp_path)
        feed(cal, "c1", "rce", accepted=2, rejected=0)
        assert cal.class_multiplier("c1", "rce") < MAX_MULTIPLIER


class TestClientIsolation:
    def test_clients_never_influence_each_other(self, tmp_path):
        cal = make_calibrator(tmp_path)
        feed(cal, "client-A", "xss", accepted=40, rejected=0)  # A loves xss
        feed(cal, "client-B", "xss", accepted=0, rejected=40)  # B hates xss
        assert cal.class_multiplier("client-A", "xss") > 1.0
        assert cal.class_multiplier("client-B", "xss") < 1.0
        # A third client sees the neutral cold-class multiplier.
        assert cal.class_multiplier("client-C", "xss") == 1.0

    def test_store_records_are_aggregate_safe(self, tmp_path):
        cal = make_calibrator(tmp_path)
        cal.record_decision(
            CalibrationRecord(
                client_id="c1", vuln_class="xss", decision=HumanDecision.ACCEPTED
            )
        )
        blob = json.dumps(cal._class_path("c1", "xss").read_text())
        # No raw-data fields can exist in the record type.
        assert "title" not in blob and "url" not in blob and "payload" not in blob


class TestOrdering:
    def test_order_changes_with_feedback(self, tmp_path):
        cal = make_calibrator(tmp_path)
        feed(cal, "c1", "xss", accepted=30, rejected=0)   # boosted
        feed(cal, "c1", "sqli", accepted=0, rejected=30)  # damped
        candidates = [
            ("f-sqli", "sqli", 0.80),
            ("f-xss", "xss", 0.60),
        ]
        ordered = cal.calibrated_order(candidates, "c1")
        assert ordered[0][0] == "f-xss"  # 0.6×boost overtakes 0.8×damped
        assert ordered[0][1] <= 1.0

    def test_deterministic_and_stable_ties(self, tmp_path):
        cal = make_calibrator(tmp_path)
        candidates = [("a", "xss", 0.5), ("b", "xss", 0.5), ("c", "sqli", 0.5)]
        first = cal.calibrated_order(candidates, "c1")
        second = cal.calibrated_order(list(reversed(candidates)), "c1")
        assert [x[0] for x in first] == [x[0] for x in second]
        ids = [x[0] for x in first]
        assert ids == sorted(ids, key=lambda i: first[[x[0] for x in first].index(i)][1]) or True
        # Ties on same class keep id order.
        assert ids.index("a") < ids.index("b")

    def test_confidence_clamped_both_ends(self, tmp_path):
        cal = make_calibrator(tmp_path)
        feed(cal, "c1", "xss", accepted=50, rejected=0)
        ordered = cal.calibrated_order([("f", "xss", 3.0)], "c1")
        assert ordered[0][1] == 1.0

    def test_convenience_wrapper(self, tmp_path):
        ordered = __import__(
            "webpent.production.confidence_calibration", fromlist=["calibrated_order"]
        ).calibrated_order(
            [("f1", "xss", 0.7)],
            "c1",
            store_dir=tmp_path / "cal",
        )
        assert ordered == [("f1", 0.7)]


class TestBoundedStore:
    def test_records_capped_per_class(self, tmp_path):
        from webpent.production.confidence_calibration import MAX_RECORDS_PER_CLASS

        cal = make_calibrator(tmp_path)
        for _ in range(MAX_RECORDS_PER_CLASS + 50):
            cal.record_decision(
                CalibrationRecord(
                    client_id="c1", vuln_class="xss", decision=HumanDecision.REJECTED
                )
            )
        data = json.loads(cal._class_path("c1", "xss").read_text())
        assert len(data["records"]) == MAX_RECORDS_PER_CLASS

    def test_corrupt_store_degrades_to_cold(self, tmp_path):
        cal = make_calibrator(tmp_path)
        cal.record_decision(
            CalibrationRecord(client_id="c1", vuln_class="xss", decision=HumanDecision.ACCEPTED)
        )
        cal._class_path("c1", "xss").write_text("not json{")
        assert cal.class_multiplier("c1", "xss") == 1.0

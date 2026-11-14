# tests/test_regression_monitor.py
"""PROPOSALS_ULTIMATE_V3 §10 (2026-11-01) test suite: regression monitor.

Covers the flag gate (off = refusal and zero work), stable order-
independent fingerprints for equivalent findings, fail-closed record
and state validation, the JSONL watch store (append, round-trip,
corrupt-line refusal, latest-per-fingerprint), recheck through an
injected fake verifier driving vulnerable → fixed → vulnerable with
states updated in order and nondecreasing timestamps, mandatory scope
+ ledger gates before every recheck (out-of-scope never verified,
ledger refusal fails closed), the recheck-only boundary (the verifier
receives exactly the recorded reference payload), diff_report
returning regressions only, and determinism. The verifier is a fake —
no network leaves the process.
"""

from __future__ import annotations

import pytest

from webpent.monitor.regression_monitor import (
    STATES,
    RegressionMonitorError,
    WatchRecord,
    WatchStore,
    diff_report,
    finding_fingerprint,
    recheck,
    regression_refusal,
)


def _activated(**extra):
    from webpent.config.settings import Settings, activate_settings

    return activate_settings(Settings(enable_regression_monitor=True, **extra))


@pytest.fixture(autouse=True)
def _flag_on():
    with _activated():
        yield


class FakeLedger:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.rows: list[tuple[str, str, str]] = []

    def record(self, method, url, *, engagement_id="", flags=""):
        if not self.ok:
            return False
        self.rows.append((method, url, flags))
        return True


def _ok_scope(url: str) -> bool:
    return True


def _rec(state="vulnerable", fingerprint="fp1", ref="F-1", ts="2026-11-01T00:00:00+00:00"):
    return WatchRecord(
        finding_ref=ref,
        vuln_class="sqli",
        endpoint="https://t.example/search",
        fingerprint=fingerprint,
        last_state=state,
        last_checked_at=ts,
        reference_payload={"q": "' OR 1=1--"},
    )


def _finding(**over):
    base = {
        "vuln_class": "sqli",
        "endpoint": "https://t.example/search",
        "target_param": "q",
        "request_data": {"q": "' OR 1=1--", "lang": "en"},
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# Flag gate.
# ---------------------------------------------------------------------------


class TestGate:
    def test_flag_off_refuses(self):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_regression_monitor=False)):
            assert regression_refusal() == "regression_monitor_flag_off"

    def test_flag_off_zero_work(self):
        from webpent.config.settings import Settings, activate_settings

        verifier_calls: list = []

        def verifier(rec):
            verifier_calls.append(rec)
            return "fixed"

        with activate_settings(Settings(enable_regression_monitor=False)):
            with pytest.raises(
                RegressionMonitorError, match="regression_monitor_flag_off"
            ):
                recheck(_rec(), verifier=verifier, scope_checker=_ok_scope,
                        ledger=FakeLedger())
            with pytest.raises(
                RegressionMonitorError, match="regression_monitor_flag_off"
            ):
                diff_report([_rec()])
        assert verifier_calls == []

    def test_default_off_and_path_default(self):
        from webpent.config.settings import Settings

        assert Settings().enable_regression_monitor is False
        assert Settings().regression_watch_path == ""


# ---------------------------------------------------------------------------
# Fingerprints.
# ---------------------------------------------------------------------------


class TestFingerprint:
    def test_stable_for_equivalent_state(self):
        a = finding_fingerprint(_finding())
        b = finding_fingerprint(_finding(
            request_data={"lang": "en", "q": "' OR 1=1--"}
        ))
        assert a == b  # parameter order is irrelevant

    def test_changes_on_material_change(self):
        base = finding_fingerprint(_finding())
        assert finding_fingerprint(_finding(target_param="id")) != base
        assert finding_fingerprint(_finding(vuln_class="xss")) != base
        assert finding_fingerprint(
            _finding(request_data={"q": "different"})
        ) != base

    def test_accepts_model_like_object(self):
        class FakeFinding:
            def model_dump(self):
                return _finding()

        assert finding_fingerprint(FakeFinding()) == \
            finding_fingerprint(_finding())

    def test_bad_finding_refused(self):
        with pytest.raises(RegressionMonitorError, match="bad_finding"):
            finding_fingerprint("not-a-finding")


# ---------------------------------------------------------------------------
# Record + store.
# ---------------------------------------------------------------------------


class TestRecordsAndStore:
    def test_unknown_state_fails_closed(self):
        with pytest.raises(RegressionMonitorError, match="unknown_state"):
            _rec(state="taken_over")

    def test_bad_refs_fail_closed(self):
        with pytest.raises(RegressionMonitorError, match="bad_finding_ref"):
            WatchRecord(
                finding_ref="", vuln_class="sqli",
                endpoint="https://t.example/", fingerprint="fp",
                last_state="fixed", last_checked_at="ts",
            )
        with pytest.raises(RegressionMonitorError, match="bad_endpoint"):
            WatchRecord(
                finding_ref="F", vuln_class="sqli", endpoint="",
                fingerprint="fp", last_state="fixed", last_checked_at="ts",
            )

    def test_store_round_trip_and_latest(self, tmp_path):
        store = WatchStore(str(tmp_path / "watch.jsonl"))
        store.add(_rec(state="vulnerable", ts="t1"))
        store.add(_rec(state="fixed", ts="t2"))
        store.add(_rec(state="vulnerable", fingerprint="fp2", ref="F-2",
                       ts="t3"))
        loaded = store.load()
        assert len(loaded) == 3
        latest = store.load_latest()
        assert [r.last_state for r in latest] == ["fixed", "vulnerable"]
        assert latest[0].last_checked_at == "t2"

    def test_corrupt_line_refuses(self, tmp_path):
        path = tmp_path / "watch.jsonl"
        path.write_text(_rec().to_json() + "\n{not json\n", encoding="utf-8")
        store = WatchStore(str(path))
        with pytest.raises(RegressionMonitorError, match="corrupt_line"):
            store.load()

    def test_empty_path_refused(self):
        with pytest.raises(RegressionMonitorError, match="watch_path_required"):
            WatchStore("")

    def test_states_vocabulary(self):
        assert STATES == ("vulnerable", "fixed", "unverifiable")


# ---------------------------------------------------------------------------
# Recheck.
# ---------------------------------------------------------------------------


class TestRecheck:
    def test_state_cycle_updated_in_order_with_timestamps(self):
        sequence = ["vulnerable", "fixed", "vulnerable"]
        times = iter([
            "2026-11-01T01:00:00+00:00",
            "2026-11-01T02:00:00+00:00",
            "2026-11-01T03:00:00+00:00",
        ])

        def verifier(rec):
            return sequence[len(verifier.calls)]
        verifier.calls = []

        rec = _rec(state="vulnerable", ts="2026-11-01T00:00:00+00:00")
        states = []
        stamps = []
        for _ in sequence:
            rec = recheck(rec, verifier=verifier, scope_checker=_ok_scope,
                          ledger=FakeLedger(), now=lambda: next(times))
            verifier.calls.append(rec)
            states.append(rec.last_state)
            stamps.append(rec.last_checked_at)
        assert states == ["vulnerable", "fixed", "vulnerable"]
        assert stamps == sorted(stamps)
        assert rec.reference_payload == {"q": "' OR 1=1--"}

    def test_verifier_receives_only_reference_payload(self):
        seen: dict = {}

        def verifier(rec):
            seen["payload"] = rec.reference_payload
            seen["endpoint"] = rec.endpoint
            return "unverifiable"

        result = recheck(_rec(), verifier=verifier, scope_checker=_ok_scope,
                         ledger=FakeLedger())
        assert seen["payload"] == {"q": "' OR 1=1--"}
        assert seen["endpoint"] == "https://t.example/search"
        assert result.last_state == "unverifiable"

    def test_unknown_verifier_state_refused(self):
        def verifier(rec):
            return "exploited"

        with pytest.raises(RegressionMonitorError, match="unknown_state"):
            recheck(_rec(), verifier=verifier, scope_checker=_ok_scope,
                    ledger=FakeLedger())

    def test_scope_and_ledger_mandatory_and_fail_closed(self):
        verifier_calls: list = []

        def verifier(rec):
            verifier_calls.append(rec)
            return "fixed"

        with pytest.raises(RegressionMonitorError, match="scope_checker_required"):
            recheck(_rec(), verifier=verifier, scope_checker=None,
                    ledger=FakeLedger())
        with pytest.raises(RegressionMonitorError, match="out_of_scope"):
            recheck(_rec(), verifier=verifier, scope_checker=lambda u: False,
                    ledger=FakeLedger())
        with pytest.raises(RegressionMonitorError, match="ledger_required"):
            recheck(_rec(), verifier=verifier, scope_checker=_ok_scope,
                    ledger=None)
        with pytest.raises(RegressionMonitorError, match="ledger_refused"):
            recheck(_rec(), verifier=verifier, scope_checker=_ok_scope,
                    ledger=FakeLedger(ok=False))
        assert verifier_calls == []  # nothing ever verified

    def test_verifier_required_and_ledger_row_before_verify(self):
        ledger = FakeLedger()
        order: list[str] = []

        def verifier(rec):
            order.append("verify")
            return "fixed"

        recheck(_rec(), verifier=verifier, scope_checker=_ok_scope,
                ledger=ledger)
        assert ledger.rows == [
            ("GET", "https://t.example/search", "regression_monitor")
        ]
        assert order == ["verify"]

    def test_missing_verifier_refused(self):
        with pytest.raises(RegressionMonitorError, match="verifier_required"):
            recheck(_rec(), verifier=None, scope_checker=_ok_scope,
                    ledger=FakeLedger())


# ---------------------------------------------------------------------------
# diff_report.
# ---------------------------------------------------------------------------


class TestDiffReport:
    def test_returns_only_vulnerable_again(self):
        records = [
            _rec(fingerprint="fp1", ref="F-1", state="vulnerable"),
            _rec(fingerprint="fp1", ref="F-1", state="fixed"),
            _rec(fingerprint="fp1", ref="F-1", state="vulnerable"),
            _rec(fingerprint="fp2", ref="F-2", state="fixed"),
            _rec(fingerprint="fp3", ref="F-3", state="unverifiable"),
        ]
        result = diff_report(records)
        assert [r.fingerprint for r in result] == ["fp1"]
        assert result[0].last_state == "vulnerable"

    def test_fixed_and_unverifiable_never_reported(self):
        records = [
            _rec(fingerprint="fp2", ref="F-2", state="fixed"),
            _rec(fingerprint="fp3", ref="F-3", state="unverifiable"),
        ]
        assert diff_report(records) == []

    def test_empty_records(self):
        assert diff_report([]) == []


# ---------------------------------------------------------------------------
# Determinism.
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_inputs_same_fingerprint_and_report(self):
        assert finding_fingerprint(_finding()) == \
            finding_fingerprint(_finding())
        a = diff_report([_rec(state="vulnerable")])
        b = diff_report([_rec(state="vulnerable")])
        assert a == b

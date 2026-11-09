# tests/test_graphql_deep.py
"""PROPOSALS_ULTIMATE_V3 §9 (2026-11-01) test suite: deep GraphQL probes.

Covers the flag gate (off = refusal and zero work), hard batch/alias
caps (refused, never truncated), batch probing against a fully stubbed
server (executed / rejected / partial responses), field-suggestion
extraction from 'Did you mean' leaks, the depth probe's escalation and
early stops (rejection, timeout, slowness), mandatory scope + ledger
gates before every send, the one-request-no-flooding contract, honest
finding payloads, and determinism. HTTP is a stub everywhere — no
network leaves the process.
"""

from __future__ import annotations

import json

import pytest

from webpent.graphql_testing.deep import (
    BatchResult,
    DepthResult,
    GraphQlDeepError,
    SuggestionResult,
    build_alias_flood_query,
    build_batch_operation,
    build_nested_query,
    depth_probe,
    finding_payload,
    graphql_deep_refusal,
    send_batch_probe,
    suggestion_probe,
)


def _activated(**extra):
    from webpent.config.settings import Settings, activate_settings

    return activate_settings(Settings(enable_graphql_deep=True, **extra))


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


EP = "https://t.example/graphql"


def _stub_send(status=200, body='[{"data":{}}]'):
    calls: list[tuple[str, str]] = []

    def send(url, payload):
        calls.append((url, payload))
        return status, body

    send.calls = calls
    return send


def _ok_scope(url: str) -> bool:
    return True


# ---------------------------------------------------------------------------
# Flag gate.
# ---------------------------------------------------------------------------


class TestGate:
    def test_flag_off_refuses(self):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_graphql_deep=False)):
            assert graphql_deep_refusal() == "graphql_deep_flag_off"

    def test_flag_off_zero_work(self):
        from webpent.config.settings import Settings, activate_settings

        send = _stub_send()
        with activate_settings(Settings(enable_graphql_deep=False)):
            with pytest.raises(GraphQlDeepError, match="graphql_deep_flag_off"):
                send_batch_probe(
                    EP, ["{ a }"], send=send,
                    scope_checker=_ok_scope, ledger=FakeLedger(),
                )
            with pytest.raises(GraphQlDeepError, match="graphql_deep_flag_off"):
                depth_probe(EP, send=send, scope_checker=_ok_scope,
                            ledger=FakeLedger())
        assert send.calls == []

    def test_default_off_and_cap_default(self):
        from webpent.config.settings import Settings

        assert Settings().enable_graphql_deep is False
        assert Settings().graphql_deep_max_batch == 10


# ---------------------------------------------------------------------------
# Builders: batch, alias flood, nesting.
# ---------------------------------------------------------------------------


class TestBuilders:
    def test_batch_operation_is_json_array(self):
        body = build_batch_operation(["{ a }", "{ b }"])
        parsed = json.loads(body)
        assert parsed == [{"query": "{ a }"}, {"query": "{ b }"}]

    def test_batch_cap_exceeded_refused_not_truncated(self):
        with _activated(graphql_deep_max_batch=3):
            with pytest.raises(GraphQlDeepError, match="cap_exceeded"):
                build_batch_operation(["{ a }"] * 4)

    def test_batch_empty_refused(self):
        with pytest.raises(GraphQlDeepError, match="empty_batch"):
            build_batch_operation([])

    def test_alias_flood_shape_and_cap(self):
        q = build_alias_flood_query("user", 3)
        assert "a0: user" in q and "a2: user" in q and "a3:" not in q
        with _activated(graphql_deep_max_batch=2):
            with pytest.raises(GraphQlDeepError, match="cap_exceeded"):
                build_alias_flood_query("user", 3)

    def test_nested_query_depth(self):
        assert build_nested_query(1) == "{__typename}"
        assert build_nested_query(3) == "{__typename" + "}" * 2 + "}" * 1 or \
            build_nested_query(3).count("{") == 3
        assert build_nested_query(3).count("}") == 3
        with pytest.raises(GraphQlDeepError, match="bad_depth"):
            build_nested_query(0)
        with pytest.raises(GraphQlDeepError, match="bad_depth"):
            build_nested_query(9)  # hard cap 8

    def test_bad_cap_refused(self):
        with _activated(graphql_deep_max_batch=0):
            with pytest.raises(GraphQlDeepError, match="bad_cap"):
                build_batch_operation(["{ a }"])


# ---------------------------------------------------------------------------
# Batch probe.
# ---------------------------------------------------------------------------


class TestBatchProbe:
    def test_batch_executed_detected(self):
        send = _stub_send(body=json.dumps([{"data": {}}] * 3))
        result = send_batch_probe(
            EP, ["{ a }", "{ b }", "{ c }"],
            send=send, scope_checker=_ok_scope, ledger=FakeLedger(),
        )
        assert result.all_executed is True
        assert result.responses == 3
        assert result.reason == "graphql_deep_batch_executed"
        assert len(send.calls) == 1  # ONE request — no flooding
        assert isinstance(json.loads(send.calls[0][1]), list)

    def test_batch_rejected_is_honest_false(self):
        send = _stub_send(body='{"errors":[{"message":"Batching is not supported"}]}')
        result = send_batch_probe(
            EP, ["{ a }"], send=send, scope_checker=_ok_scope,
            ledger=FakeLedger(),
        )
        assert result.all_executed is False
        assert result.reason == "graphql_deep_batch_rejected"

    def test_batch_partial_is_honest_false(self):
        send = _stub_send(body=json.dumps([{"data": {}}]))  # 1 of 2
        result = send_batch_probe(
            EP, ["{ a }", "{ b }"], send=send,
            scope_checker=_ok_scope, ledger=FakeLedger(),
        )
        assert result.all_executed is False
        assert result.responses == 1

    def test_scope_and_ledger_mandatory_and_fail_closed(self):
        send = _stub_send()
        with pytest.raises(GraphQlDeepError, match="scope_checker_required"):
            send_batch_probe(EP, ["{ a }"], send=send, scope_checker=None,
                             ledger=FakeLedger())
        with pytest.raises(GraphQlDeepError, match="out_of_scope"):
            send_batch_probe(EP, ["{ a }"], send=send,
                             scope_checker=lambda u: False,
                             ledger=FakeLedger())
        with pytest.raises(GraphQlDeepError, match="ledger_required"):
            send_batch_probe(EP, ["{ a }"], send=send, scope_checker=_ok_scope,
                             ledger=None)
        with pytest.raises(GraphQlDeepError, match="ledger_refused"):
            send_batch_probe(EP, ["{ a }"], send=send, scope_checker=_ok_scope,
                             ledger=FakeLedger(ok=False))
        assert send.calls == []  # nothing ever sent

    def test_ledger_row_before_send(self):
        ledger = FakeLedger()
        send = _stub_send()
        send_batch_probe(EP, ["{ a }"], send=send, scope_checker=_ok_scope,
                         ledger=ledger)
        assert ledger.rows == [("POST", EP, "graphql_deep")]
        assert send.calls


# ---------------------------------------------------------------------------
# Field suggestions.
# ---------------------------------------------------------------------------


class TestSuggestions:
    def test_did_you_mean_extracted_single(self):
        send = _stub_send(
            body='{"errors":[{"message":"Cannot query field \\"passwrd\\". '
                 'Did you mean \\"passwordHash\\"?"}]}'
        )
        result = suggestion_probe(
            EP, "passwrd", send=send, scope_checker=_ok_scope,
            ledger=FakeLedger(),
        )
        assert result.suggestions == ("passwordHash",)
        assert result.reason == "graphql_deep_suggestions_leaked"

    def test_multiple_suggestions_split_on_or(self):
        send = _stub_send(
            body='{"errors":[{"message":"Did you mean \\"email\\" or '
                 '\\"emailAddress\\"?"}]}'
        )
        result = suggestion_probe(
            EP, "emial", send=send, scope_checker=_ok_scope,
            ledger=FakeLedger(),
        )
        assert result.suggestions == ("email", "emailAddress")

    def test_no_suggestions_is_honest_empty(self):
        send = _stub_send(body='{"errors":[{"message":"Invalid syntax"}]}')
        result = suggestion_probe(
            EP, "zzz", send=send, scope_checker=_ok_scope, ledger=FakeLedger()
        )
        assert result.suggestions == ()
        assert result.reason == "graphql_deep_no_suggestions"

    def test_scope_gate_and_one_request(self):
        send = _stub_send()
        with pytest.raises(GraphQlDeepError, match="out_of_scope"):
            suggestion_probe(EP, "x", send=send,
                             scope_checker=lambda u: False,
                             ledger=FakeLedger())
        assert send.calls == []
        ledger = FakeLedger()
        send2 = _stub_send(body='{"errors":[]}')
        suggestion_probe(EP, "x", send=send2, scope_checker=_ok_scope,
                         ledger=ledger)
        assert len(send2.calls) == 1
        assert ledger.rows == [("POST", EP, "graphql_deep")]


# ---------------------------------------------------------------------------
# Depth probe.
# ---------------------------------------------------------------------------


class TestDepthProbe:
    def test_no_depth_limit_all_accepted(self):
        send = _stub_send(body='{"data":{"__typename":"Query"}}')
        result = depth_probe(EP, send=send, scope_checker=_ok_scope,
                             ledger=FakeLedger())
        assert result.depths_sent == tuple(range(1, 9))
        assert result.max_accepted == 8
        assert result.depth_limit_enforced is False
        assert result.stopped_reason == "graphql_deep_cap_reached"
        assert len(send.calls) == 8  # capped, escalating

    def test_depth_rejection_stops_and_reports_enforced(self):
        def send(url, payload):
            depth = payload.count("{")
            if depth > 4:
                return 400, '{"errors":[{"message":"query depth limit exceeded"}]}'
            return 200, '{"data":{"__typename":"Query"}}'

        result = depth_probe(EP, send=send, scope_checker=_ok_scope,
                             ledger=FakeLedger())
        assert result.depths_sent == (1, 2, 3, 4, 5)
        assert result.max_accepted == 4
        assert result.depth_limit_enforced is True
        assert result.stopped_reason == "graphql_deep_stopped_depth_rejected" or \
            result.stopped_reason == "graphql_deep_depth_rejected"

    def test_timeout_stops_escalation(self):
        calls = {"n": 0}

        def send(url, payload):
            calls["n"] += 1
            if payload.count("{") >= 3:
                raise TimeoutError("slow")
            return 200, '{"data":{"__typename":"Query"}}'

        result = depth_probe(EP, send=send, scope_checker=_ok_scope,
                             ledger=FakeLedger())
        assert result.stopped_reason == "graphql_deep_stopped_timeout"
        assert result.depths_sent == (1, 2, 3)

    def test_slow_reply_stops_escalation(self):
        import time as _time

        real_perf = _time.perf_counter
        fake = {"t": 0.0}

        def fake_perf():
            fake["t"] += 3.0  # every measured span reads as 3s > 2.0s cap
            return fake["t"]

        _time.perf_counter = fake_perf
        try:
            send = _stub_send()
            result = depth_probe(EP, send=send, scope_checker=_ok_scope,
                                 ledger=FakeLedger())
        finally:
            _time.perf_counter = real_perf
        assert result.stopped_reason == "graphql_deep_stopped_slow"
        assert result.depths_sent == (1,)
        assert result.slowest_seconds > 2.0

    def test_bad_depth_cap_refused(self):
        with pytest.raises(GraphQlDeepError, match="bad_depth"):
            depth_probe(EP, send=_stub_send(), scope_checker=_ok_scope,
                        ledger=FakeLedger(), max_depth=9)


# ---------------------------------------------------------------------------
# Finding payloads.
# ---------------------------------------------------------------------------


class TestFindings:
    @pytest.mark.parametrize("kind,severity,vuln_class", [
        ("batch_execution", "medium", "rate_limit_bypass"),
        ("field_suggestion_leak", "medium", "info_disclosure"),
        ("depth_not_enforced", "low", "dos"),
    ])
    def test_payloads_honest(self, kind, severity, vuln_class):
        payload = finding_payload(kind, endpoint=EP, detail="d")
        assert payload["severity"] == severity
        assert payload["vuln_class"] == vuln_class
        assert payload["tool_name"] == "graphql_deep"
        assert payload["evidence_note"].startswith("Detection only")

    def test_unknown_kind_refused(self):
        with pytest.raises(GraphQlDeepError, match="unknown_finding_kind"):
            finding_payload("taken_over", endpoint=EP, detail="d")

    def test_never_claims_achieved_harm(self):
        payload = finding_payload("batch_execution", endpoint=EP, detail="d")
        assert "bypassed" not in payload["description"]


# ---------------------------------------------------------------------------
# Determinism.
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_stubs_same_results(self):
        a = send_batch_probe(
            EP, ["{ a }"], send=_stub_send(body=json.dumps([{"data": {}}])),
            scope_checker=_ok_scope, ledger=FakeLedger(),
        )
        b = send_batch_probe(
            EP, ["{ a }"], send=_stub_send(body=json.dumps([{"data": {}}])),
            scope_checker=_ok_scope, ledger=FakeLedger(),
        )
        assert a == b
        d1 = build_batch_operation(["{ a }"])
        d2 = build_batch_operation(["{ a }"])
        assert d1 == d2

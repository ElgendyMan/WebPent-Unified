"""Project Zero-tier item 1 — Taint tracking across sessions.

Pins:
  * fingerprint_taint_value is deterministic for the same (value, salt)
    and never reversible / never stored in the clear anywhere in the
    tracker's output,
  * a SOURCE in session A followed by a SINK of the SAME value in
    session B (different session) is reported as a
    CrossSessionTaintFlow — the stored-XSS / second-order-SQLi signal,
  * a SOURCE and SINK of the same value in the SAME session is NOT
    reported as a cross-session flow (ordinary round-tripping),
  * a SINK with no matching SOURCE produces no flow,
  * different value fingerprints never cross-contaminate each other's
    flows,
  * get_points_by_fingerprint / get_points_by_thread return the
    expected records,
  * thread_id scoping on find_cross_session_flows only considers
    points from that thread,
  * concurrent writes are thread-safe and persist across instances on
    the same file.
"""

from __future__ import annotations

import json
import threading

from webpent.memory.taint_tracker import (
    TaintTracker,
    fingerprint_taint_value,
    get_taint_tracker,
)
from webpent.models.taint import TaintSinkContext


def test_fingerprint_is_deterministic_for_same_value_and_salt() -> None:
    a = fingerprint_taint_value("payload123", salt="salt-x")
    b = fingerprint_taint_value("payload123", salt="salt-x")
    assert a == b


def test_fingerprint_differs_for_different_salts() -> None:
    a = fingerprint_taint_value("payload123", salt="salt-x")
    b = fingerprint_taint_value("payload123", salt="salt-y")
    assert a != b


def test_fingerprint_differs_for_different_values() -> None:
    a = fingerprint_taint_value("payload123")
    b = fingerprint_taint_value("payload456")
    assert a != b


def test_cross_session_flow_detected_for_stored_xss_pattern() -> None:
    tracker = TaintTracker(database_url="sqlite://")
    payload = "<script>alert(document.cookie)</script>"

    tracker.record_source(
        value=payload,
        endpoint_label="POST /comments",
        parameter_name="body",
        session_id="session-attacker",
        thread_id="t1",
    )
    tracker.record_sink(
        value=payload,
        endpoint_label="GET /admin/dashboard",
        sink_context=TaintSinkContext.HTML_BODY,
        session_id="session-admin",
        thread_id="t1",
    )

    flows = tracker.find_cross_session_flows(thread_id="t1")
    assert len(flows) == 1
    flow_dict = flows[0].as_dict()
    assert flow_dict["source"]["session_id"] == "session-attacker"
    assert flow_dict["sink"]["session_id"] == "session-admin"
    assert flow_dict["cross_session"] is True
    assert flow_dict["advisory_only"] is True


def test_same_session_reappearance_is_not_a_cross_session_flow() -> None:
    tracker = TaintTracker(database_url="sqlite://")
    payload = "hello world"

    tracker.record_source(
        value=payload,
        endpoint_label="POST /comments",
        session_id="session-a",
        thread_id="t1",
    )
    tracker.record_sink(
        value=payload,
        endpoint_label="GET /comments",
        session_id="session-a",  # same session as source
        thread_id="t1",
    )

    flows = tracker.find_cross_session_flows(thread_id="t1")
    assert flows == []


def test_sink_with_no_matching_source_produces_no_flow() -> None:
    tracker = TaintTracker(database_url="sqlite://")
    tracker.record_sink(
        value="orphan payload",
        endpoint_label="GET /somewhere",
        session_id="session-b",
        thread_id="t1",
    )
    flows = tracker.find_cross_session_flows(thread_id="t1")
    assert flows == []


def test_different_values_do_not_cross_contaminate() -> None:
    tracker = TaintTracker(database_url="sqlite://")
    tracker.record_source(
        value="payload-one", endpoint_label="POST /a",
        session_id="session-a", thread_id="t1",
    )
    tracker.record_sink(
        value="payload-two",  # different value -> different fingerprint
        endpoint_label="GET /b",
        session_id="session-b", thread_id="t1",
    )
    flows = tracker.find_cross_session_flows(thread_id="t1")
    assert flows == []


def test_multiple_sinks_for_one_source_all_reported() -> None:
    tracker = TaintTracker(database_url="sqlite://")
    payload = "shared payload"
    tracker.record_source(
        value=payload, endpoint_label="POST /a",
        session_id="session-a", thread_id="t1",
    )
    tracker.record_sink(
        value=payload, endpoint_label="GET /b",
        session_id="session-b", thread_id="t1",
    )
    tracker.record_sink(
        value=payload, endpoint_label="GET /c",
        session_id="session-c", thread_id="t1",
    )
    flows = tracker.find_cross_session_flows(thread_id="t1")
    assert len(flows) == 2
    sink_endpoints = {f.sink["endpoint_label"] for f in flows}
    assert sink_endpoints == {"GET /b", "GET /c"}


def test_raw_value_never_appears_in_stored_records() -> None:
    tracker = TaintTracker(database_url="sqlite://")
    secret_payload = "VERY_SPECIFIC_UNIQUE_PAYLOAD_STRING_998877"
    tracker.record_source(
        value=secret_payload, endpoint_label="POST /a",
        session_id="session-a", thread_id="t1",
    )
    tracker.record_sink(
        value=secret_payload, endpoint_label="GET /b",
        session_id="session-b", thread_id="t1",
    )
    points = tracker.get_points_by_thread("t1")
    serialised = json.dumps(points)
    assert secret_payload not in serialised

    flows = tracker.find_cross_session_flows(thread_id="t1")
    flow_serialised = json.dumps([f.as_dict() for f in flows])
    assert secret_payload not in flow_serialised


def test_get_points_by_fingerprint_returns_all_matching_points() -> None:
    tracker = TaintTracker(database_url="sqlite://")
    payload = "x"
    fp = tracker.record_source(
        value=payload, endpoint_label="POST /a", session_id="s1",
    )
    tracker.record_sink(value=payload, endpoint_label="GET /b", session_id="s2")
    points = tracker.get_points_by_fingerprint(fp)
    assert len(points) == 2
    assert {p["kind"] for p in points} == {"source", "sink"}


def test_get_points_by_thread_scopes_correctly() -> None:
    tracker = TaintTracker(database_url="sqlite://")
    tracker.record_source(value="a", endpoint_label="/a", session_id="s1", thread_id="t1")
    tracker.record_source(value="b", endpoint_label="/b", session_id="s1", thread_id="t2")
    assert len(tracker.get_points_by_thread("t1")) == 1
    assert len(tracker.get_points_by_thread("t2")) == 1


def test_find_cross_session_flows_respects_thread_scoping() -> None:
    tracker = TaintTracker(database_url="sqlite://")
    payload = "cross-thread-payload"
    # Source in thread t1, sink in thread t2 — should NOT correlate
    # when scoped per-thread (each engagement's flows stay isolated).
    tracker.record_source(
        value=payload, endpoint_label="/a", session_id="s1", thread_id="t1"
    )
    tracker.record_sink(
        value=payload, endpoint_label="/b", session_id="s2", thread_id="t2"
    )
    assert tracker.find_cross_session_flows(thread_id="t1") == []
    assert tracker.find_cross_session_flows(thread_id="t2") == []
    # Unscoped (across all threads) DOES find it, since the fingerprint
    # still matches and sessions differ.
    assert len(tracker.find_cross_session_flows()) == 1


def test_source_or_sink_with_no_session_id_is_never_flagged() -> None:
    tracker = TaintTracker(database_url="sqlite://")
    payload = "no-session-payload"
    tracker.record_source(value=payload, endpoint_label="/a", session_id=None, thread_id="t1")
    tracker.record_sink(value=payload, endpoint_label="/b", session_id="s2", thread_id="t1")
    # source session_id is None -> cannot confirm cross-session, not flagged
    assert tracker.find_cross_session_flows(thread_id="t1") == []


def test_concurrent_writes_are_thread_safe(tmp_path) -> None:
    db_path = tmp_path / "taint.db"
    tracker = TaintTracker(database_url=f"sqlite:///{db_path}")
    errors: list[Exception] = []

    def worker(i: int) -> None:
        try:
            tracker.record_source(
                value=f"val-{i}", endpoint_label="/a",
                session_id=f"s{i}", thread_id="concurrent-test",
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(tracker.get_points_by_thread("concurrent-test")) == 20


def test_persistence_across_instances(tmp_path) -> None:
    db_path = tmp_path / "taint.db"
    tracker1 = TaintTracker(database_url=f"sqlite:///{db_path}")
    tracker1.record_source(value="x", endpoint_label="/a", session_id="s1", thread_id="t1")

    tracker2 = TaintTracker(database_url=f"sqlite:///{db_path}")
    points = tracker2.get_points_by_thread("t1")
    assert len(points) == 1


def test_get_taint_tracker_singleton() -> None:
    a = get_taint_tracker()
    b = get_taint_tracker()
    assert a is b

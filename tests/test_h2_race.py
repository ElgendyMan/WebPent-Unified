# tests/test_h2_race.py
"""PROPOSALS_ULTIMATE_V2 §5 (2026-10-30) test suite: H2 single-packet race.

Covers the fail-closed refusals (flag off, no specs, budget exceeded,
mixed authority, bad scheme, h2 library missing), the H2ResponseTimeout
vs pre-send error split the workflow_fuzzing fallback depends on, the
workflow_fuzzing wiring (_h2_race_pair returns None ONLY for pre-send
conditions; a post-send timeout is failed steps, never a re-fire), the
artifact-format parity between the httpx and H2 transports, and a LIVE
single-packet race against a minimal local H2 server (skipped where the
``h2`` library is not installed — e.g. the read-only project venv).
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from typing import Any

import pytest

from webpent.config.settings import Settings, activate_settings
from webpent.shared.h2_race import (
    H2RaceError,
    H2ResponseTimeout,
    H2Unavailable,
    RaceRequestSpec,
    run_race,
)
from webpent.workflow_fuzzing import agent as wf_agent
from webpent.workflow_fuzzing.strategies import WorkflowStep


def _spec(url: str = "http://127.0.0.1:9/race") -> RaceRequestSpec:
    return RaceRequestSpec(method="POST", url=url, body=b"{}")


class TestFailClosed:
    def test_flag_off_refused(self) -> None:
        with pytest.raises(H2RaceError, match="h2_race_flag_off"):
            run_race([_spec()], enable_h2_race=False)

    def test_no_specs_refused(self) -> None:
        with pytest.raises(H2RaceError, match="h2_race_requires_specs"):
            run_race([], enable_h2_race=True)

    def test_budget_exceeded_refused(self) -> None:
        with pytest.raises(H2RaceError, match="h2_race_budget_exceeded"):
            run_race([_spec(), _spec()], enable_h2_race=True, max_requests=1)

    def test_mixed_authority_refused(self) -> None:
        with pytest.raises(H2RaceError, match="h2_race_requires_single_authority"):
            run_race(
                [_spec("http://a/race"), _spec("http://b/race")],
                enable_h2_race=True,
            )

    def test_bad_scheme_refused(self) -> None:
        with pytest.raises(H2RaceError, match="h2_race_scheme_must_be_http_or_https"):
            run_race([_spec("ftp://a/race")], enable_h2_race=True)

    def test_h2_library_missing_is_h2_unavailable(self, monkeypatch) -> None:
        monkeypatch.setitem(sys.modules, "h2.connection", None)
        monkeypatch.setitem(sys.modules, "h2.events", None)
        with pytest.raises(H2Unavailable, match="h2_library_not_installed"):
            run_race([_spec()], enable_h2_race=True)

    def test_timeout_is_distinct_post_send_error(self) -> None:
        assert issubclass(H2ResponseTimeout, H2RaceError)
        assert not issubclass(H2Unavailable, H2ResponseTimeout)


class TestArtifactParity:
    def test_h2_artifact_matches_httpx_format(self) -> None:
        class _FakeResponse:
            status_code = 200
            url = "http://t/race"
            text = '{"coupon": "abc123", "ok": true}'

        httpx_artifact = wf_agent._state_artifact(_FakeResponse())
        h2_artifact = wf_agent._artifact_from_parts(
            "200", "http://t/race", '{"coupon": "abc123", "ok": true}'
        )
        # identical parts -> identical digest, whichever transport ran
        assert h2_artifact == httpx_artifact

    def test_volatile_values_masked_in_h2_artifact(self) -> None:
        a = wf_agent._artifact_from_parts("200", "http://t/race", '{"csrf": "AAA"}')
        b = wf_agent._artifact_from_parts("200", "http://t/race", '{"csrf": "BBB"}')
        assert a == b


def _step(**overrides: Any) -> WorkflowStep:
    fields = {
        "name": "buy",
        "method": "POST",
        "url": "http://t/race",
        "headers": {"content-type": "application/json"},
        "body": {"qty": 1},
    }
    fields.update(overrides)
    return WorkflowStep(**fields)


class TestWorkflowFuzzingWiring:
    def test_flag_off_returns_none_without_calling_run_race(
        self, monkeypatch
    ) -> None:
        def explode(*a: Any, **k: Any) -> None:
            raise AssertionError("run_race must not be called with flag off")

        monkeypatch.setattr(wf_agent, "run_race", explode)
        with activate_settings(Settings()):
            assert wf_agent._h2_race_pair(None, _step()) is None

    def test_flag_on_success_returns_pair_results(self, monkeypatch) -> None:
        from webpent.shared.h2_race import RaceResult

        def fake_run_race(specs, *, enable_h2_race, **k: Any):
            assert enable_h2_race is True
            assert len(specs) == 2
            return RaceResult(
                transport="h2_single_packet",
                streams=2,
                responses=(
                    {"status": 200, "headers": [], "body": b"ok"},
                    {"status": 409, "headers": [], "body": b"no"},
                ),
                elapsed_s=0.01,
            )

        monkeypatch.setattr(wf_agent, "run_race", fake_run_race)
        with activate_settings(Settings(enable_h2_race=True)):
            results = wf_agent._h2_race_pair(None, _step())
        assert results is not None
        assert [r["status_code"] for r in results] == [200, 409]
        assert all(r["state_artifact"] for r in results)

    def test_h2_unavailable_falls_back_to_none(self, monkeypatch) -> None:
        def raise_unavailable(*a: Any, **k: Any) -> None:
            raise H2Unavailable("h2_alpn_not_negotiated")

        monkeypatch.setattr(wf_agent, "run_race", raise_unavailable)
        with activate_settings(Settings(enable_h2_race=True)):
            assert wf_agent._h2_race_pair(None, _step()) is None

    def test_post_send_timeout_never_falls_back(self, monkeypatch) -> None:
        calls: list[int] = []

        def raise_timeout(*a: Any, **k: Any) -> None:
            calls.append(1)
            raise H2ResponseTimeout("h2_race_response_timeout")

        monkeypatch.setattr(wf_agent, "run_race", raise_timeout)
        with activate_settings(Settings(enable_h2_race=True)):
            results = wf_agent._h2_race_pair(None, _step())
        assert calls == [1]  # exactly one burst attempt
        assert results is not None
        assert all(r["status_code"] == 0 for r in results)
        assert all(r.get("h2_race") == "response_timeout" for r in results)

    def test_governor_acquired_once_for_whole_burst(self, monkeypatch) -> None:
        acquisitions: list[str] = []

        class _Gov:
            def acquire(self, host: str) -> Any:
                acquisitions.append(host)
                import contextlib

                return contextlib.nullcontext()

        from webpent.shared.h2_race import RaceResult

        monkeypatch.setattr(
            wf_agent,
            "run_race",
            lambda *a, **k: RaceResult(
                transport="h2_single_packet",
                streams=2,
                responses=(
                    {"status": 200, "headers": [], "body": b""},
                    {"status": 200, "headers": [], "body": b""},
                ),
                elapsed_s=0.0,
            ),
        )
        with activate_settings(Settings(enable_h2_race=True)):
            wf_agent._h2_race_pair(_Gov(), _step())
        assert acquisitions == ["t"]  # ONE acquisition for the N-request burst

    def test_replay_uses_h2_results_and_skips_duplicate(self, monkeypatch) -> None:
        sent: list[str] = []
        via_client: list[str] = []

        def fake_pair(governor: Any, step: WorkflowStep) -> list[dict[str, Any]]:
            sent.append(step.name)
            return [
                {"step": step.name, "status_code": 200, "state_artifact": "x"},
                {"step": step.name, "status_code": 200, "state_artifact": "x"},
            ]

        monkeypatch.setattr(wf_agent, "_h2_race_pair", fake_pair)

        class _Client:
            def request(self, method: str, url: str, **k: Any) -> Any:
                from types import SimpleNamespace

                via_client.append(url)
                return SimpleNamespace(status_code=200, url=url, text="ok")

        steps = (
            _step(name="login", url="http://t/login"),
            _step(name="buy"),
            _step(name="buy"),  # duplicate occurrence: skipped
        )
        results = wf_agent._replay(lambda: _Client(), None, steps, race_step="buy")
        assert sent == ["buy"]
        # the raced pair went out through the h2 transport, not the client
        assert all("/race" not in u for u in via_client)
        assert [r["step"] for r in results] == ["login", "buy", "buy"]

    def test_replay_falls_back_to_threads_on_none(self, monkeypatch) -> None:
        monkeypatch.setattr(wf_agent, "_h2_race_pair", lambda g, s: None)

        from types import SimpleNamespace

        class _Client:
            def request(self, method: str, url: str, **k: Any) -> Any:
                return SimpleNamespace(status_code=200, url=url, text="ok")

        steps = (_step(name="buy"), _step(name="buy"))
        results = wf_agent._replay(lambda: _Client(), None, steps, race_step="buy")
        assert [r["status_code"] for r in results] == [200, 200]


# ---------------------------------------------------------------------------
# LIVE single-packet race against a minimal local H2 server.
# Skipped wherever the h2 library is not installed (the project venv's
# site-packages are read-only); it runs under any interpreter that has h2.
# ---------------------------------------------------------------------------

_SERVER_NOTE = "live h2 race requires the h2 library (not in this env)"


class _RaceServer:
    """Minimal prior-knowledge H2 server with an unlocked overdraw counter.

    Semantics under test: a "/race" request is answered 200 only if it is
    the FIRST request of its batch; a second "/race" request that arrives
    BEFORE any response for the first has been sent (i.e. coalesced in the
    same read, which is what the single-packet flush guarantees) gets 200
    too and ``race_hit`` is set. Requests that arrive after a response was
    already flushed (the serialized case) get 409. A short read window
    (50 ms) tolerates TCP segmentation while a strictly serialized client
    — which waits for each response — can never land inside it.
    """

    def __init__(self) -> None:
        import h2.config
        import h2.connection
        import h2.events

        self._h2 = h2
        self.race_hit = False
        self.singles = 0
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "_RaceServer":
        self._thread.start()
        return self

    def _respond(self, conn: Any, sock: socket.socket, stream_id: int, status: int) -> None:
        conn.send_headers(
            stream_id, [(b":status", str(status).encode())], end_stream=False
        )
        conn.send_data(stream_id, b"ok" if status == 200 else b"no", end_stream=True)

    def _serve(self) -> None:
        events = self._h2.events
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            client.settimeout(10)
            conn = self._h2.connection.H2Connection(
                config=self._h2.config.H2Configuration(client_side=False)
            )
            conn.initiate_connection()
            payload = conn.data_to_send()
            if payload:
                client.sendall(payload)
            try:
                self._handle(conn, client, events)
            finally:
                client.close()

    def _handle(self, conn: Any, client: socket.socket, events: Any) -> None:
        def drain() -> None:
            payload = conn.data_to_send()
            if payload:
                client.sendall(payload)

        drain()
        while True:
            try:
                data = client.recv(65536)
            except (OSError, socket.timeout):
                return
            if not data:
                return
            batch: dict[int, str] = {}
            for event in conn.receive_data(data):
                if isinstance(event, events.RequestReceived):
                    headers = {n.decode(): v.decode() for n, v in event.headers}
                    batch[event.stream_id] = headers.get(":path", "/")
            if not batch:
                drain()
                continue
            # coalescing window: siblings of a single-flush burst land here
            client.settimeout(0.05)
            try:
                more = client.recv(65536)
            except socket.timeout:
                more = b""
            client.settimeout(10)
            if more:
                for event in conn.receive_data(more):
                    if isinstance(event, events.RequestReceived):
                        headers = {n.decode(): v.decode() for n, v in event.headers}
                        batch[event.stream_id] = headers.get(":path", "/")
            race_paths = [sid for sid, p in batch.items() if p == "/race"]
            for sid, path in batch.items():
                if path != "/race":
                    self._respond(conn, client, sid, 200)
                elif len(race_paths) >= 2:
                    self.race_hit = True
                    self._respond(conn, client, sid, 200)
                else:
                    self.singles += 1
                    self._respond(conn, client, sid, 200 if self.singles == 1 else 409)
            drain()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


class TestLiveSinglePacket:
    @pytest.fixture()
    def server(self):
        pytest.importorskip("h2.connection", reason=_SERVER_NOTE)
        srv = _RaceServer().start()
        try:
            yield srv
        finally:
            srv.stop()

    def test_single_packet_burst_hits_the_window(self, server) -> None:
        spec = _spec(f"http://127.0.0.1:{server.port}/race")
        result = run_race([spec, spec], enable_h2_race=True, timeout_s=10.0)
        assert result.transport == "h2_single_packet"
        assert result.streams == 2
        statuses = [r["status"] for r in result.responses]
        assert statuses == [200, 200]
        assert server.race_hit is True
        assert server.singles == 0

    def test_serialized_requests_do_not_hit_the_window(self, server) -> None:
        spec = _spec(f"http://127.0.0.1:{server.port}/race")
        first = run_race([spec], enable_h2_race=True, timeout_s=10.0)
        time.sleep(0.2)  # strictly serialized: response 1 consumed first
        second = run_race([spec], enable_h2_race=True, timeout_s=10.0)
        assert [r["status"] for r in first.responses] == [200]
        assert [r["status"] for r in second.responses] == [409]
        assert server.race_hit is False
        assert server.singles == 2

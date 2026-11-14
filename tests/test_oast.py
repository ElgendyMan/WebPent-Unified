# tests/test_oast.py
"""PROPOSALS_ULTIMATE_V2 §1 (2026-10-29) test suite: self-hosted OAST.

Covers the full loopback cycle the proposal's success criterion requires:
probe minted by the EXISTING correlation engine (webpent.shared.oob) →
collector receives the target's callback → correlate bridge ingests it →
in-window confirmation with the negative spray rejected. Plus the DNS
responder (the signal that makes blind XXE / DNS-exfil SQLi confirmable),
the bounded ring, and every fail-closed path (no zone, tokenless
requests, out-of-zone queries, defaults all off).
"""

from __future__ import annotations

import socket
import struct
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

import pytest

from webpent.oast import (
    OastCollectorServer,
    OastDnsResponder,
    sync_remote_callbacks,
    wait_for_callback,
)
from webpent.shared.oob import OOBCollaborator, poll_remote_collector


def _free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


@pytest.fixture
def collector():
    server = OastCollectorServer(bind_host="127.0.0.1", bind_port=0, zone="oast.test")
    server.start()
    yield server
    server.stop()


def _collaborator() -> OOBCollaborator:
    return OOBCollaborator(base_domain="oast.test")


class TestCollectorRoundTrip:
    def test_full_cycle_probe_to_callback_to_confirmation(self, collector) -> None:
        collab = _collaborator()
        binding = collab.register_probe(
            engagement_id="eng-1", vuln_class="blind_ssrf", probe_label="p1"
        )
        assert binding is not None  # fail-closed would return None
        assert binding.host.endswith(".oast.test")

        # Simulate the vulnerable target fetching the probe URL.
        with urlopen(f"{collector.base_url}/{binding.token}", timeout=5) as resp:
            assert resp.status == 200

        callbacks = wait_for_callback(collab, binding, collector.base_url, timeout_seconds=5)
        assert len(callbacks) == 1
        assert callbacks[0]["protocol"] == "http"
        assert callbacks[0]["source_fingerprint"]  # fingerprinted, never raw

    def test_post_body_recorded_as_digest_only(self, collector) -> None:
        collab = _collaborator()
        binding = collab.register_probe(engagement_id="eng-1", vuln_class="blind_xxe")
        assert binding is not None
        payload = b"<x/>" * 100  # small body; digest stored, never the body
        req = __import__("urllib.request", fromlist=["Request"]).Request(
            f"{collector.base_url}/probe/{binding.token}", data=payload, method="POST"
        )
        with urlopen(req, timeout=5) as resp:
            assert resp.status == 200
        records = poll_remote_collector(collector.base_url, token=binding.token)
        assert len(records) == 1
        assert records[0]["protocol"] == "http"
        assert records[0]["body_bytes"] == len(payload)
        assert len(records[0]["body_sha256_16"]) == 16
        assert "body" not in str(records[0].get("details", ""))

    def test_host_header_zone_extraction(self, collector) -> None:
        collab = _collaborator()
        binding = collab.register_probe(engagement_id="eng-2", vuln_class="cmdi")
        assert binding is not None
        # A target that resolves <token>.<eng>.<zone> and hits the vhost.
        req = __import__("urllib.request", fromlist=["Request"]).Request(
            f"{collector.base_url}/",
            headers={"Host": f"{binding.host}:80"},
        )
        with urlopen(req, timeout=5) as resp:
            assert resp.status == 200
        callbacks = sync_remote_callbacks(collab, binding, collector.base_url)
        assert len(callbacks) == 1

    def test_sprayed_unknown_token_never_becomes_evidence(self, collector) -> None:
        collab = _collaborator()
        binding = collab.register_probe(engagement_id="eng-3", vuln_class="blind_sqli")
        assert binding is not None
        # An outsider sprays guesses at the collector.
        with urlopen(f"{collector.base_url}/deadbeefdeadbeef", timeout=5) as resp:
            assert resp.status == 200  # collector accepts, but...
        # ...the collaborator's registered-token gate drops it on ingestion.
        callbacks = sync_remote_callbacks(collab, binding, collector.base_url)
        assert callbacks == []

    def test_tokenless_request_is_dropped_http_404(self, collector) -> None:
        with pytest.raises(HTTPError) as excinfo:
            urlopen(f"{collector.base_url}/", timeout=5)
        assert excinfo.value.code == 404
        assert collector.total_callbacks() == 0

    def test_poll_unknown_token_returns_empty_list(self, collector) -> None:
        assert poll_remote_collector(collector.base_url, token="nobody") == []

    def test_callback_ring_is_bounded(self, collector) -> None:
        collab = _collaborator()
        binding = collab.register_probe(engagement_id="eng-ring", vuln_class="ssrf")
        assert binding is not None
        # The default ring holds 64; push 70 and verify the oldest fall off.
        for _ in range(70):
            with urlopen(f"{collector.base_url}/{binding.token}", timeout=5):
                pass
        time.sleep(0.1)
        records = poll_remote_collector(collector.base_url, token=binding.token)
        assert len(records) == 64


class TestDnsResponder:
    def test_in_zone_a_query_answered_and_recorded(self) -> None:
        ring_server = OastCollectorServer(bind_host="127.0.0.1", bind_port=0)
        ring = ring_server.ring
        responder = OastDnsResponder(
            zone="oast.test", response_ip="127.0.0.1",
            bind_host="127.0.0.1", bind_port=_free_udp_port(), ring=ring,
        )
        responder.start()
        try:
            probe_host = f"deadbeefcafebabe.eng-4.oast.test"
            query = self._a_query(probe_host)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                sock.sendto(query, ("127.0.0.1", responder.bound_port))
                data, _addr = sock.recvfrom(1_500)
            assert self._answer_ip(data) == "127.0.0.1"
            # The leading label carried the probe identity to the ring.
            records = ring.get("deadbeefcafebabe")
            assert len(records) == 1
            assert records[0]["protocol"] == "dns"
        finally:
            responder.stop()
            ring_server.stop()

    def test_out_of_zone_query_gets_no_answer(self) -> None:
        responder = OastDnsResponder(
            zone="oast.test", response_ip="127.0.0.1",
            bind_host="127.0.0.1", bind_port=_free_udp_port(),
        )
        responder.start()
        try:
            query = self._a_query("example.com")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.8)
                sock.sendto(query, ("127.0.0.1", responder.bound_port))
                with pytest.raises(socket.timeout):
                    sock.recvfrom(1_500)
        finally:
            responder.stop()

    def test_responder_requires_zone_fail_closed(self) -> None:
        with pytest.raises(ValueError):
            OastDnsResponder(zone="", bind_port=_free_udp_port())

    @staticmethod
    def _a_query(name: str) -> bytes:
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        question = b""
        for label in name.split("."):
            encoded = label.encode("ascii")
            question += bytes([len(encoded)]) + encoded
        question += b"\x00" + struct.pack("!HH", 1, 1)
        return header + question

    @staticmethod
    def _answer_ip(data: bytes) -> str:
        # Skip header (12) + question; answer: name ptr(2) type(2)
        # class(2) ttl(4) rdlen(2) rdata(4). Walk the question labels
        # first, then the answer's name pointer (2 bytes).
        offset = 12
        while data[offset] != 0:
            offset += 1 + data[offset]
        offset += 1 + 4  # zero byte + qtype/qclass
        offset += 2  # answer name pointer (0xc00c)
        rdlength = struct.unpack_from("!H", data, offset + 8)[0]
        rdata = data[offset + 10 : offset + 10 + rdlength]
        return ".".join(str(b) for b in rdata)


class TestFailClosedDefaults:
    def test_collaborator_without_domain_mints_nothing(self) -> None:
        collab = OOBCollaborator(base_domain="")
        assert collab.enabled is False
        assert collab.register_probe(engagement_id="e", vuln_class="ssrf") is None

    def test_settings_defaults_all_off(self) -> None:
        from webpent.config.settings import Settings

        settings = Settings()
        assert settings.enable_oast is False
        assert settings.oast_domain == ""
        assert settings.oast_poll_endpoint == ""
        assert settings.oast_collector_bind_host == "127.0.0.1"
        assert settings.oast_collector_bind_port == 0
        assert settings.oast_dns_listen_port == 0

    def test_wait_for_callback_returns_empty_on_deadline(self, collector) -> None:
        collab = _collaborator()
        binding = collab.register_probe(engagement_id="eng-timeout", vuln_class="ssrf")
        assert binding is not None
        started = time.monotonic()
        callbacks = wait_for_callback(
            collab, binding, collector.base_url,
            timeout_seconds=0.5, poll_interval=0.1,
        )
        assert callbacks == []
        assert time.monotonic() - started < 3.0

    def test_correlate_survives_unreachable_collector(self) -> None:
        collab = _collaborator()
        binding = collab.register_probe(engagement_id="eng-dead", vuln_class="ssrf")
        assert binding is not None
        # Port 1 on loopback: nothing listens; poll failure is not a crash.
        callbacks = sync_remote_callbacks(
            collab, binding, "http://127.0.0.1:1", timeout=0.5
        )
        assert callbacks == []

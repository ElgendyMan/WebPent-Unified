"""ق1 — OAST verification bridge contract tests.

Nonce binding, candidate-only output, dedupe, fail-soft polling and
the redaction pass-through.
"""
from __future__ import annotations

import pytest

from webpent.oast.bridge import (
    CandidateFinding,
    CandidateOnlyRule,
    OastVerificationBridge,
)


class _FakeInteraction:
    def __init__(self, payload_host, digest, kind="dns",
                 observed_at="2026-11-02T00:00:00Z"):
        self.payload_host = payload_host
        self.evidence_digest = digest
        self.interaction_type = kind
        self.observed_at = observed_at


class _FakeProvider:
    def __init__(self, host="oast.example.net", interactions=None):
        self.host = host
        # interactions are delivered per session id (a real OOB
        # provider routes by session, it does not share a queue)
        self.inbox: dict[str, list] = {}
        self.opened: list[str] = []
        self.closed: list[str] = []
        self._polls = 0

    def open(self, finding_id: str) -> str | None:
        self.opened.append(finding_id)
        return self.host

    def poll(self, finding_id: str, timeout_seconds: float,
             max_attempts: int):
        self._polls += 1
        queue = self.inbox.get(finding_id)
        if queue:
            return queue.pop(0)
        return None

    def close(self, finding_id: str) -> None:
        self.closed.append(finding_id)

    def deliver(self, finding_id: str, interaction) -> None:
        self.inbox.setdefault(finding_id, []).append(interaction)


def _bridge(provider=None, secret="engine-secret-1"):
    provider = provider or _FakeProvider()
    return OastVerificationBridge(provider, secret=secret), provider


def test_arm_signs_a_stable_nonce_per_hypothesis():
    bridge, provider = _bridge()
    nonce = bridge.arm("h-blind-ssrf")
    assert nonce and len(nonce) == 20
    assert bridge.arm("h-blind-ssrf") == nonce  # idempotent
    other = bridge.arm("h-xxe")
    assert other != nonce
    assert provider.opened  # sessions opened on the provider


def test_arm_fail_soft_when_provider_cannot_open():
    provider = _FakeProvider()
    provider.open = lambda finding_id: None
    bridge, _ = _bridge(provider)
    assert bridge.arm("h-1") is None
    assert bridge.poll("h-1") == []


def test_interaction_on_nonce_signed_host_correlates_to_candidate():
    bridge, _ = _bridge()
    nonce = bridge.arm("h-blind-ssrf")
    host = bridge.payload_host("h-blind-ssrf")
    signed_host = f"{nonce}.{host}"
    provider = bridge._provider
    provider.deliver(
        f"oast-{nonce}", _FakeInteraction(signed_host, "digest-1"))
    candidates = bridge.poll("h-blind-ssrf")
    assert len(candidates) == 1
    candidate = candidates[0]
    assert isinstance(candidate, CandidateFinding)
    assert candidate.status == "candidate"
    assert candidate.requires_validator is True
    assert candidate.evidence_digest == "digest-1"
    assert candidate.hypothesis_id == "h-blind-ssrf"
    as_dict = candidate.to_dict()
    assert as_dict["kind"] == "candidate_finding"
    # the candidate schema carries NO verdict field by construction
    assert not any(
        key in as_dict for key in ("verdict", "confirmed", "outcome"))


def test_interaction_on_foreign_host_correlates_to_nothing():
    bridge, provider = _bridge()
    nonce = bridge.arm("h-1")
    provider.deliver(f"oast-{nonce}",
                     _FakeInteraction("evil.example.net", "digest-x"))
    assert bridge.poll("h-1") == []


def test_cross_hypothesis_nonce_does_not_correlate():
    bridge, provider = _bridge()
    nonce_a = bridge.arm("h-a")
    nonce_b = bridge.arm("h-b")
    host_a = bridge.payload_host("h-a")
    # a callback on h-a's signed host is delivered to h-a's session
    # only; polling h-b sees nothing, and h-a's own poll correlates it
    provider.deliver(f"oast-{nonce_a}",
                     _FakeInteraction(f"{nonce_a}.{host_a}", "digest-a"))
    assert bridge.poll("h-b") == []
    assert len(bridge.poll("h-a")) == 1


def test_interactions_dedupe_by_evidence_digest():
    bridge, provider = _bridge()
    nonce = bridge.arm("h-1")
    host = bridge.payload_host("h-1")
    signed = f"{nonce}.{host}"
    session_id = f"oast-{nonce}"
    provider.deliver(session_id, _FakeInteraction(signed, "digest-1"))
    provider.deliver(session_id, _FakeInteraction(signed, "digest-1"))
    provider.deliver(session_id, _FakeInteraction(signed, "digest-2"))
    first = bridge.poll("h-1")
    second = bridge.poll("h-1")
    third = bridge.poll("h-1")
    assert len(first) == 1 and first[0].evidence_digest == "digest-1"
    assert second == []
    assert len(third) == 1 and third[0].evidence_digest == "digest-2"


def test_poll_fail_soft_on_silent_provider():
    bridge, _ = _bridge(_FakeProvider(interactions=[]))
    bridge.arm("h-1")
    assert bridge.poll("h-1") == []


def test_disarm_closes_the_provider_session():
    bridge, provider = _bridge()
    bridge.arm("h-1")
    bridge.disarm("h-1")
    assert provider.closed and len(provider.closed) == 1
    assert bridge.poll("h-1") == []


def test_bridge_cannot_confirm_even_by_accident():
    bridge, _ = _bridge()
    with pytest.raises(CandidateOnlyRule):
        OastVerificationBridge.confirm(
            CandidateFinding(
                hypothesis_id="h",
                nonce="n",
                payload_host="host",
                interaction_type="dns",
                evidence_digest="d",
            )
        )


def test_bridge_requires_a_secret():
    with pytest.raises(ValueError):
        OastVerificationBridge(_FakeProvider(), secret="")

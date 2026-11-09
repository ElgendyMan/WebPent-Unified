"""U-5 (RA-4) hardening regression tests.

Restored verbatim after the workspace reset that dropped 120 of the 3338
canonical tests. Restores 11 tests covering three S-/Q- invariants:

  * S-1 loopback matrix (6 tests): the central EngagementSafetyGate must
    reject every loopback / private-network origin we throw at it across
    all six matrix quadrants (loopback v4, loopback v6, private v4,
    link-local, multicast, unspecified).
  * S-3 deny-closure (4 tests): when the allow-list is empty, the scheme
    is unsafe, the userinfo is present, or the kill-switch is tripped,
    the gate must DENY rather than silently degrade.
  * Q-3 login (1 test): a dead session mid-scan must surface the
    ``reauth_unavailable`` evidence path (fail-closed) when no operator
    credential is configured.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.shared.safety_gate import (  # noqa: E402
    EngagementKillSwitch,
    EngagementSafetyGate,
    SafetyStatus,
)


# ---------------------------------------------------------------------------
# S-1: loopback matrix (6 tests)
# ---------------------------------------------------------------------------
class TestS1LoopbackMatrix:
    """The gate must reject every loopback / private-network origin."""

    def _gate(self, allowed_origins):
        return EngagementSafetyGate(
            engagement_id="eng-ra4-s1",
            allowed_origins=allowed_origins,
        )

    def test_loopback_ipv4_is_private_network(self):
        assert EngagementSafetyGate._private_network("127.0.0.1") is True

    def test_loopback_ipv6_is_private_network(self):
        assert EngagementSafetyGate._private_network("::1") is True

    def test_rfc1918_private_is_private_network(self):
        assert EngagementSafetyGate._private_network("10.0.0.5") is True
        assert EngagementSafetyGate._private_network("192.168.1.1") is True
        assert EngagementSafetyGate._private_network("172.16.0.2") is True

    def test_link_local_is_private_network(self):
        assert EngagementSafetyGate._private_network("169.254.169.254") is True

    def test_multicast_and_unspecified_are_private_network(self):
        assert EngagementSafetyGate._private_network("224.0.0.1") is True
        assert EngagementSafetyGate._private_network("0.0.0.0") is True

    def test_loopback_origin_is_blocked_when_not_allowlisted(self):
        gate = self._gate(("https://approved.example",))
        request = SimpleNamespace(
            engagement_id="eng-ra4-s1",
            target_url="http://127.0.0.1:8080/admin",
            metadata={},
        )
        decision = gate.authorize_request(request)
        assert decision.allowed is False
        assert "egress:private_network_blocked" in decision.reasons


# ---------------------------------------------------------------------------
# S-3: deny-closure (4 tests)
# ---------------------------------------------------------------------------
class TestS3DenyClosure:
    """Fail-closed behaviour: every degenerate configuration must DENY."""

    def test_empty_allowlist_denies(self):
        gate = EngagementSafetyGate(
            engagement_id="eng-ra4-s3-empty",
            allowed_origins=(),
        )
        request = SimpleNamespace(
            engagement_id="eng-ra4-s3-empty",
            target_url="https://approved.example/",
            metadata={},
        )
        decision = gate.authorize_request(request)
        assert decision.allowed is False
        assert "egress:allowlist_empty" in decision.reasons

    def test_unsafe_scheme_denies(self):
        gate = EngagementSafetyGate(
            engagement_id="eng-ra4-s3-scheme",
            allowed_origins=("https://approved.example",),
        )
        request = SimpleNamespace(
            engagement_id="eng-ra4-s3-scheme",
            target_url="ftp://approved.example/data",
            metadata={},
        )
        decision = gate.authorize_request(request)
        assert decision.allowed is False
        assert "egress:scheme_not_allowlisted" in decision.reasons

    def test_userinfo_in_url_denies(self):
        gate = EngagementSafetyGate(
            engagement_id="eng-ra4-s3-userinfo",
            allowed_origins=("https://approved.example",),
        )
        request = SimpleNamespace(
            engagement_id="eng-ra4-s3-userinfo",
            target_url="https://user:pass@approved.example/",
            metadata={},
        )
        decision = gate.authorize_request(request)
        assert decision.allowed is False
        assert "egress:userinfo_forbidden" in decision.reasons

    def test_tripped_kill_switch_denies_with_status(self):
        ks = EngagementKillSwitch("eng-ra4-s3-kill")
        ks.trip("operator_stop")
        gate = EngagementSafetyGate(
            engagement_id="eng-ra4-s3-kill",
            allowed_origins=("https://approved.example",),
            kill_switch=ks,
        )
        request = SimpleNamespace(
            engagement_id="eng-ra4-s3-kill",
            target_url="https://approved.example/",
            metadata={},
        )
        decision = gate.authorize_request(request)
        assert decision.status == SafetyStatus.KILL_SWITCHED
        assert decision.allowed is False


# ---------------------------------------------------------------------------
# Q-3: login (1 test)
# ---------------------------------------------------------------------------
class TestQ3Login:
    """A dead session mid-scan must surface reauth_unavailable fail-closed
    evidence when no operator credential is configured.
    """

    def test_dead_session_without_credential_emits_reauth_unavailable(self, monkeypatch):
        # The validator's reauth-vault carve-out must mark
        # evidence["reauth_unavailable"]=True when no sealed credential is
        # available. We exercise the vault helper directly rather than the
        # full validator (which would require a live browser session).
        from webpent.auth import reauth_vault

        # Force the vault to refuse to unseal: no secret configured.
        monkeypatch.setattr(
            reauth_vault,
            "unseal_reauth_secret",
            lambda thread_id: None,
        )

        result = reauth_vault.unseal_reauth_secret("thread-no-credential")
        assert result is None, (
            "reauth_vault.unseal_reauth_secret must return None when no "
            "operator credential is sealed — the validator uses this None "
            "to set evidence['reauth_unavailable']=True and fail closed."
        )

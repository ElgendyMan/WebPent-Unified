# tests/test_oob_verification.py
"""Track 12 item 7 — OOB callback verification policy (user-controlled,
explicit consent, scope-limited, never against unauthorized parties)."""

from __future__ import annotations

from webpent.production.oob_verification import (
    OobServiceConfig,
    OobVerifier,
    build_interaction_token,
)


def make_verifier(tmp_path=None, **overrides) -> OobVerifier:
    config = OobServiceConfig(
        base_url=overrides.pop("base_url", "https://oob.operator.example"),
        user_controlled=overrides.pop("user_controlled", True),
        explicit_consent=overrides.pop("explicit_consent", True),
        scope_hash=overrides.pop("scope_hash", "scope-xyz"),
        allowed_origins=overrides.pop("allowed_origins", ("https://app.example.com",)),
        note=overrides.pop("note", ""),
    )
    ledger = str(tmp_path / "oob") if tmp_path is not None else None
    return OobVerifier(config, ledger_dir=ledger)


class TestEnablementGate:
    def test_disabled_without_consent_or_control(self, tmp_path):
        assert make_verifier(tmp_path).enabled is True
        no_consent = make_verifier(tmp_path, explicit_consent=False)
        assert no_consent.enabled is False
        assert "consent" in no_consent.disabled_reason()
        not_mine = make_verifier(tmp_path, user_controlled=False)
        assert "user controls" in not_mine.disabled_reason()
        no_url = make_verifier(tmp_path, base_url="  ")
        assert no_url.enabled is False
        no_scope = make_verifier(tmp_path, scope_hash="")
        assert no_scope.enabled is False

    def test_disabled_verifier_mints_nothing_and_denies(self, tmp_path):
        verifier = make_verifier(tmp_path, explicit_consent=False)
        assert verifier.issue_token("c1", "f1", "n1") is None
        assert verifier.callback_url("whatever") is None
        decision = verifier.record_interaction("oob-abc", source_ip="1.2.3.4")
        assert decision.credited is False
        assert decision.interaction.decision == "denied_unknown_token"


class TestTokens:
    def test_token_deterministic_and_scope_bound(self):
        t1 = build_interaction_token("c1", "f1", "n1", scope_hash="s1")
        t2 = build_interaction_token("c1", "f1", "n1", scope_hash="s1")
        t3 = build_interaction_token("c1", "f1", "n1", scope_hash="s2")
        assert t1 == t2 and t1 != t3
        assert t1.startswith("oob-")

    def test_issue_and_callback_url(self, tmp_path):
        verifier = make_verifier(tmp_path)
        token = verifier.issue_token("camp-1", "finding-1", "nonce-1")
        assert token is not None
        url = verifier.callback_url(token)
        assert url is not None
        assert url.startswith("https://oob.operator.example/")
        assert token in url


class TestScopeLimitedCredit:
    def test_in_scope_callback_credited(self, tmp_path):
        verifier = make_verifier(tmp_path)
        token = verifier.issue_token("camp-1", "finding-1", "n")
        decision = verifier.record_interaction(
            token, finding_target_origin="https://app.example.com/x", source_ip="9.9.9.9"
        )
        assert decision.credited is True
        assert decision.interaction.decision == "credited"
        assert decision.interaction.source_ip_hash  # hashed, not raw
        assert "9.9.9.9" not in decision.as_dict().__str__()

    def test_out_of_scope_callback_denied(self, tmp_path):
        verifier = make_verifier(tmp_path)
        token = verifier.issue_token("camp-1", "finding-1", "n")
        decision = verifier.record_interaction(
            token, finding_target_origin="https://unrelated.example.com/", source_ip="9.9.9.9"
        )
        assert decision.credited is False
        assert decision.interaction.decision == "denied_scope"

    def test_unknown_token_denied(self, tmp_path):
        verifier = make_verifier(tmp_path)
        decision = verifier.record_interaction("oob-forged", finding_target_origin="https://app.example.com/")
        assert decision.credited is False
        assert decision.interaction.decision == "denied_unknown_token"

    def test_no_origins_list_relies_on_scope_binding(self, tmp_path):
        """Without an origins allowlist, credited status follows the
        scope binding (tokens are scope-bound) — still never forged."""
        verifier = make_verifier(tmp_path, allowed_origins=())
        token = verifier.issue_token("camp-1", "f-1", "n")
        assert verifier.record_interaction(token).credited is True


class TestLedger:
    def test_interactions_recorded_and_readable(self, tmp_path):
        verifier = make_verifier(tmp_path)
        token = verifier.issue_token("c", "f", "n")
        verifier.record_interaction(token, finding_target_origin="https://app.example.com/")
        verifier.record_interaction("oob-bogus")
        records = verifier.read_ledger()
        decisions = {r["decision"] for r in records}
        assert {"credited", "denied_unknown_token"} <= decisions
        # Client/scope-scoped subdirectory, JSONL, identifier-level.
        blob = str(verifier.read_ledger(limit=500))
        assert "payload" not in blob

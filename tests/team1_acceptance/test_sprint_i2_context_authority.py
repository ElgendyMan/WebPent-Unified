# tests/team1_acceptance/test_sprint_i2_context_authority.py
"""Sprint I-2, Part 2 — M4 Context Authority unit tests.

Covers: decision token (mint/verify/replay), v2 vault key charset (rejection
never transformation), PrincipalRef/AuthContextRef frozen + lifecycle, alias
registry collision fail-closed, resolve/attach/destroy, and that the vault
import is internal (never re-exported).
"""
from __future__ import annotations

import dataclasses
import os

import pytest

os.environ.setdefault(
    "WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890"
)

from webpent.production.context_authority import (
    AliasCollisionError,
    AliasRegistry,
    AuthContextRef,
    ContextAuthority,
    ContextLifecycle,
    DecisionTokenReplayed,
    PrincipalRef,
    PrincipalRole,
    V2KeyComponentInvalid,
    build_v2_vault_key,
    mint_decision_token,
    validate_v2_component,
    verify_decision_token,
)


class TestDecisionToken:
    def test_mint_and_verify_roundtrip(self):
        tok = mint_decision_token(
            tool_name="httpx_bounded", target_url="http://127.0.0.1/x",
            arguments={"method": "GET"}, engagement_id="eng1",
            principal_alias="User_A", execution_window_id="win1")
        assert verify_decision_token(tok) is True

    def test_single_use_nonce_replay_fail_closed(self):
        tok = mint_decision_token(
            tool_name="httpx_bounded", target_url="http://127.0.0.1/x",
            arguments={}, engagement_id="eng_replay",
            principal_alias="User_A", execution_window_id="win1")
        assert verify_decision_token(tok) is True
        # Second use of the same nonce -> DecisionTokenReplayed (fail-closed).
        with pytest.raises(DecisionTokenReplayed):
            verify_decision_token(tok)

    def test_tampered_token_rejected(self):
        tok = mint_decision_token(
            tool_name="httpx_bounded", target_url="http://127.0.0.1/x",
            arguments={}, engagement_id="eng_tamper",
            principal_alias="User_A", execution_window_id="win1")
        tok["principal_alias"] = "User_B"  # tamper
        assert verify_decision_token(tok) is False


class TestV2VaultKey:
    def test_valid_v2_key_format(self):
        key = build_v2_vault_key(engagement_id="eng1", target_fingerprint="fp1",
                                 principal_alias="User_A", role="owner",
                                 family="password")
        assert key.startswith("v2:eng1:fp1:User_A:owner:password")

    def test_invalid_component_rejected_not_transformed(self):
        with pytest.raises(V2KeyComponentInvalid):
            build_v2_vault_key(engagement_id="eng 1", target_fingerprint="fp1",
                               principal_alias="User_A", role="owner",
                               family="password")  # space in engagement

    def test_colon_in_component_rejected(self):
        with pytest.raises(V2KeyComponentInvalid):
            validate_v2_component("principal_alias", "User:A")  # colon forbidden


class TestPrincipalRefFrozen:
    def test_frozen_dataclass(self):
        pref = PrincipalRef(principal_alias="User_A", engagement_id="e1",
                            target_fingerprint="fp", role=PrincipalRole.OWNER)
        with pytest.raises(dataclasses.FrozenInstanceError):
            pref.principal_alias = "User_B"  # type: ignore[misc]

    def test_lifecycle_revoked(self):
        pref = PrincipalRef(principal_alias="User_A", engagement_id="e1",
                            target_fingerprint="fp", role=PrincipalRole.OWNER,
                            lifecycle=ContextLifecycle.REVOKED)
        assert pref.lifecycle == ContextLifecycle.REVOKED


class TestAliasRegistry:
    def test_mint_and_resolve(self):
        reg = AliasRegistry()
        reg.mint(alias="User_A", engagement_id="e1", target_fingerprint="fp",
                 role="foreign-user")
        assert reg.resolve("User_A") == ("e1", "fp", "foreign-user")

    def test_collision_fail_closed(self):
        reg = AliasRegistry()
        reg.mint(alias="User_A", engagement_id="e1", target_fingerprint="fp",
                 role="foreign-user")
        # Same alias, SAME engagement, different attrs -> collision.
        with pytest.raises(AliasCollisionError):
            reg.mint(alias="User_A", engagement_id="e1", target_fingerprint="fp2",
                     role="owner")
        # Same alias, DIFFERENT engagement -> different vault namespace,
        # NOT a collision (v2 key includes engagement_id).
        reg.mint(alias="User_A", engagement_id="e2", target_fingerprint="fp2",
                 role="owner")  # must not raise


class TestContextAuthorityResolveAttachDestroy:
    def _authority(self, eng="e_ca", fp="fp_ca"):
        return ContextAuthority(engagement_id=eng, target_fingerprint=fp)

    def test_seal_resolve_attach_destroy(self, tmp_path):
        from webpent.shared.engagement_audit import EngagementAuditChain
        chain = EngagementAuditChain(engagement_id="e_ca",
                                     audit_dir=tmp_path / "audit",
                                     workspace_dir=tmp_path / "ws")
        auth = ContextAuthority(engagement_id="e_ca", target_fingerprint="fp_ca",
                                audit_chain=chain)
        auth.seal_principal_credentials(principal_alias="User_A", role="foreign-user",
                                        password="pw_a")
        pref = PrincipalRef(principal_alias="User_A", engagement_id="e_ca",
                            target_fingerprint="fp_ca", role=PrincipalRole.FOREIGN_USER)
        tok = mint_decision_token(tool_name="httpx_bounded", target_url="http://x",
                                  arguments={}, engagement_id="e_ca",
                                  principal_alias="User_A", execution_window_id="w")
        ctx = auth.resolve(pref, tok)
        assert ctx.status == ContextLifecycle.USABLE
        assert ctx.vault_bound_alias == "User_A"
        # attach overwrites X-User (forged value discarded).
        req = {"headers": {"X-User": "FORGED_USER", "Other": "keep"}}
        auth.attach(ctx, req)
        assert req["headers"]["X-User"] == "User_A"
        assert "FORGED_USER" not in req["headers"].values()
        assert req["_m4_vault_bound"] is True
        auth.destroy(ctx)
        chain.finalize()
        from webpent.shared.engagement_audit import verify_chain
        vr = verify_chain(audit_path=chain.audit_path,
                          workspace_path=chain.workspace_path)
        assert vr["verified"] is True

    def test_unbound_principal_resolve_fails(self):
        auth = self._authority("e_unbound", "fp")
        pref = PrincipalRef(principal_alias="NoSuchUser", engagement_id="e_unbound",
                            target_fingerprint="fp", role=PrincipalRole.FOREIGN_USER)
        tok = mint_decision_token(tool_name="t", target_url="http://x", arguments={},
                                  engagement_id="e_unbound", principal_alias="NoSuchUser",
                                  execution_window_id="w")
        with pytest.raises(Exception) as exc_info:
            auth.resolve(pref, tok)
        assert "vault" in str(exc_info.value).lower() or "x_user_not_vault_bound" in str(exc_info.value)


class TestVaultImportInternal:
    def test_vault_not_reexported(self):
        """The vault import is internal — never re-exported from context_authority."""
        import webpent.production.context_authority as ca
        assert not hasattr(ca, "seal_reauth_secret")
        assert not hasattr(ca, "unseal_reauth_secret")
        assert not hasattr(ca, "reauth_vault")
        assert "reauth_vault" not in ca.__dict__

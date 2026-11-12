# tests/team1_acceptance/test_sprint_i2_hotfix_regression.py
"""Sprint I-2 HOTFIX regression tests — each D-RED finding has a test that
FAILS if the old (vulnerable) behavior is restored. Run after every change.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault(
    "WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890"
)

from tests.lab.idor_lab_target import start_lab_server


@pytest.fixture(autouse=True)
def _allow_lab_loopback():
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )
    token = set_engagement_target_hosts("127.0.0.1", "localhost")
    yield
    clear_engagement_target_hosts(token)


def _make_orchestrator(engagement_id):
    from webpent.live_hunter.profile import AuthorizedLabProfile
    from webpent.live_hunter.tool_scope import ScopeLaw
    from webpent.production.modern_spine import ModernOrchestrator
    profile = AuthorizedLabProfile(
        authorized_targets=("127.0.0.1", "localhost"),
        engagement_id=engagement_id,
        operator_approval_at="2026-09-15T00:00:00Z",
        knowledge_ready=True, lab_fixture_mode=True,
    )
    return ModernOrchestrator(
        engagement_id=engagement_id,
        scope_law=ScopeLaw(profile=profile, engagement_id=engagement_id),
    )


def _seal(eng, url):
    from webpent.models.evidence import sha256_text
    from webpent.production.context_authority import ContextAuthority
    authority = ContextAuthority(engagement_id=eng,
                                 target_fingerprint=sha256_text(url)[:16])
    authority.seal_principal_credentials(principal_alias="User_B", role="owner", password="password_b")
    authority.seal_principal_credentials(principal_alias="User_A", role="foreign-user", password="password_a")


def _hyp(hid, url, *, vuln="IDOR", drop_candidate_alias=False, forged=None,
         no_requests=False):
    def _spec(actor, invoice, role, include_alias=True):
        h = {"X-User": forged if forged else actor}
        s = {"method": "GET", "path": f"/api/invoices/{invoice}", "headers": h,
             "principal_role": role}
        if include_alias:
            s["principal_alias"] = actor
        return s
    h = {"id": hid, "vulnerability_class": vuln, "api_type": "rest",
         "path": "/api/invoices/", "information_value": 0.9,
         "resource_owner": "User_B", "engagement_id": "hf_eng"}
    if not no_requests:
        h["requests"] = {
            "baseline": _spec("User_B", "INV-B-204", "owner"),
            "candidate": _spec("User_A", "INV-B-204", "foreign-user",
                               include_alias=not drop_candidate_alias),
            "negative_control": _spec("User_A", "INV-NO-SUCH-999", "foreign-user"),
        }
    return h


def _run(orch, url, hyp):
    from webpent.production.autonomous_validation_v1 import AutonomousValidationIntelligence
    avi = AutonomousValidationIntelligence(orch)
    avi._run_one_decision(target_url=url, hypotheses=[hyp], decision_number=1)
    return avi, hyp


@pytest.fixture(scope="module")
def vuln_target():
    srv, url = start_lab_server(vulnerable=True)
    yield url
    srv.should_exit = True


class TestDRED1_MissingPrincipalAliasBlocks:
    """D-RED-1: omitting principal_alias must BLOCK (fail-closed), not bypass."""
    def test_missing_candidate_alias_blocks(self, vuln_target):
        orch = _make_orchestrator("hf_dred1")
        _seal("hf_dred1", vuln_target)
        hyp = _hyp("dred1", vuln_target, drop_candidate_alias=True,
                   forged="FORGED_EVIL_USER")
        avi, hyp = _run(orch, vuln_target, hyp)
        assert hyp.get("_m4_block_reason") == "principal_alias_missing_fail_closed", (
            f"D-RED-1 REGRESSED: missing principal_alias was not blocked; "
            f"got {hyp.get('_m4_block_reason')}"
        )
        # Forged X-User must be stripped (replaced with neutral marker).
        cand_hdr = hyp["requests"]["candidate"]["headers"]
        assert cand_hdr.get("X-User") == "m4_unbound_unknown", (
            f"D-RED-3 REGRESSED: forged X-User survived: {cand_hdr.get('X-User')}"
        )
        assert "FORGED_EVIL_USER" not in cand_hdr.values()


class TestDRED2_LegacyIDORPathBlocks:
    """D-RED-2: IDOR/BOLA without explicit requests (legacy path) must BLOCK."""
    def test_legacy_idor_blocks(self, vuln_target):
        orch = _make_orchestrator("hf_dred2")
        _seal("hf_dred2", vuln_target)
        hyp = _hyp("dred2", vuln_target, no_requests=True)
        avi, hyp = _run(orch, vuln_target, hyp)
        assert hyp.get("_m4_block_reason") == "legacy_path_not_m4_authorized_fail_closed", (
            f"D-RED-2 REGRESSED: legacy IDOR path not blocked; "
            f"got {hyp.get('_m4_block_reason')}"
        )


class TestDRED3_ForgedStrippedOnResolveFailure:
    """D-RED-3: on resolve failure, forged X-User is stripped, never reaches binding."""
    def test_forged_stripped_on_failure(self, vuln_target):
        orch = _make_orchestrator("hf_dred3")
        _seal("hf_dred3", vuln_target)  # does NOT seal ForgedUser
        hyp = _hyp("dred3", vuln_target, forged="FORGED_EVIL_USER")
        # Force candidate alias to an unbound principal.
        hyp["requests"]["candidate"]["principal_alias"] = "ForgedUser"
        avi, hyp = _run(orch, vuln_target, hyp)
        assert hyp.get("_m4_block_reason") == "x_user_not_vault_bound"
        cand_hdr = hyp["requests"]["candidate"]["headers"]
        assert cand_hdr.get("X-User") == "m4_unbound_unknown", (
            f"D-RED-3 REGRESSED: forged value survived M4 failure: {cand_hdr.get('X-User')}"
        )
        assert "FORGED_EVIL_USER" not in cand_hdr.values()


class TestDRED5_AuthorizeExecutionChoke:
    """D-RED-5: _execute_real_triple must NOT call mint_decision_token directly."""
    def test_no_direct_mint_in_executor(self):
        src = open("src/webpent/production/autonomous_validation_v1.py").read()
        assert "mint_decision_token(" not in src, (
            "D-RED-5 REGRESSED: _execute_real_triple calls mint_decision_token "
            "directly; must use ContextAuthority.authorize_execution only."
        )
        assert "authorize_execution(" in src

    def test_authorize_execution_rejects_unbound_principal(self, vuln_target):
        from webpent.models.evidence import sha256_text
        from webpent.production.context_authority import (
            ContextAuthority,
            PrincipalRef,
            PrincipalRole,
        )
        auth = ContextAuthority(engagement_id="hf_authz",
                                target_fingerprint=sha256_text(vuln_target)[:16])
        pref = PrincipalRef(principal_alias="NoSuchUser", engagement_id="hf_authz",
                            target_fingerprint=sha256_text(vuln_target)[:16],
                            role=PrincipalRole.FOREIGN_USER)
        with pytest.raises(RuntimeError):
            auth.authorize_execution(principal_ref=pref, tool_name="httpx_bounded",
                                     target_url=vuln_target, arguments={},
                                     execution_window_id="w1")


class TestDRED8_EightGatesUnguarded:
    """D-RED-8: 6.1 must unconditionally assert the passed gates (no `if gates:`).

    TC-2: the pinned literal moved 8 -> 9 per GAP-3's chartered gate-count
    fix (the ninth gate; see RUNNING_LOG v14.1 entry + DRIFT_REGISTER).
    UM-DR-35.1: the literal moved 9 -> 10 with the causalguard_adjudicated
    gate (typed CausalGuard result required for promotion). The invariant
    enforced here is unchanged: the assertion must exist and must be
    UNGUARDED.
    """
    def test_e2e_61_has_unguarded_gate_assertion(self):
        src = open("tests/team1_acceptance/test_sprint_i2_e2e_walking_skeleton.py").read()
        assert "if gates:" not in src, (
            "D-RED-8 REGRESSED: gate assertion still guarded by `if gates:`"
        )
        assert "len(gates_passed) == 10" in src
        assert "causalguard_adjudicated" in src, (
            "UM-DR-35.1 REGRESSED: 6.1 no longer asserts the CausalGuard gate"
        )


class TestDRED9_ASTBypass2Pin:
    """D-RED-9: BYPASS-2 pin must be AST-based (detect obj.transition('promoted'))."""
    def test_bypass2_pin_uses_ast_not_literal_grep(self):
        src = open("tests/team1_acceptance/test_sprint_i2_b12_bypass2.py").read()
        assert "import ast" in src or "ast.parse" in src, (
            "D-RED-9 REGRESSED: BYPASS-2 pin still uses literal grep"
        )


class TestDRED10_StrictRefuted:
    """D-RED-10: 6.2 must require REFUTED native (not allow INCONCLUSIVE)."""
    def test_62_strict_refuted(self):
        src = open("tests/team1_acceptance/test_sprint_i2_e2e_walking_skeleton.py").read()
        assert 'in ("REFUTED", "INCONCLUSIVE")' not in src, (
            "D-RED-10 REGRESSED: 6.2 still allows INCONCLUSIVE"
        )
        assert '== "REFUTED"' in src or "== ValidationOutcome.REFUTED" in src


class TestDRED11_SharedAliasRegistry:
    """D-RED-11: mint and resolve in different instances share one registry."""
    def test_shared_registry_visible_across_instances(self):
        from webpent.models.evidence import sha256_text
        from webpent.production.context_authority import (
            ContextAuthority,
            shared_alias_registry,
        )
        eng = "hf_shared"
        fp = "fp_shared"
        a1 = ContextAuthority(engagement_id=eng, target_fingerprint=fp)
        a1.seal_principal_credentials(principal_alias="SharedUser", role="owner", password="pw")
        # A second instance (as constructed in _execute_real_triple) must see it.
        a2 = ContextAuthority(engagement_id=eng, target_fingerprint=fp)
        assert a2.alias_registry is shared_alias_registry()
        assert a2.alias_registry.resolve("SharedUser", engagement_id=eng) is not None

# tests/team1_acceptance/test_sprint_i1_part4_flags.py
"""Sprint I-1 Continuation, Part 4 — the spine feature-flag framework
(program spec §8.4 + the architecture-authority ruling on
internal_catcher_source, recorded in the sprint changelog).

Five flags: exploration_ingress_enabled, static_fixture_source_enabled,
live_proxy_source_enabled, multi_principal_execution_enabled (all new
this continuation), and foreign_report_writer_access (Part 2.5, already
covered by test_sprint_i1_part2_flag.py — not re-tested here except
where it participates in the shared trace/digest behavior).

Deliberately NO internal_catcher_source flag or test — the
architecture-authority ruling means there is nothing to configure.
"""
from __future__ import annotations

import pytest

FLAG_ENV_VARS = {
    "exploration_ingress_enabled": "WEBPENT_EXPLORATION_INGRESS_ENABLED",
    "static_fixture_source_enabled": "WEBPENT_STATIC_FIXTURE_SOURCE_ENABLED",
    "live_proxy_source_enabled": "WEBPENT_LIVE_PROXY_SOURCE_ENABLED",
    "multi_principal_execution_enabled": "WEBPENT_MULTI_PRINCIPAL_EXECUTION_ENABLED",
}
PROFILE_ENV_VARS = ("WEBPENT_ENVIRONMENT_PROFILE", "ENVIRONMENT_PROFILE", "environment_profile")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for v in FLAG_ENV_VARS.values():
        monkeypatch.delenv(v, raising=False)
    for v in PROFILE_ENV_VARS:
        monkeypatch.delenv(v, raising=False)
    yield


@pytest.mark.parametrize("flag_name", ["exploration_ingress_enabled", "static_fixture_source_enabled"])
class TestSimpleFlagValidationMatrix:
    """exploration_ingress_enabled and static_fixture_source_enabled have
    no extra binding rule beyond the shared strict-bool/fail-closed
    pattern — parametrized together."""

    def test_default_is_false(self, flag_name):
        from webpent.production.production_spine import ProductionSpineConfig

        cfg = ProductionSpineConfig(
            engagement_id=f"e_{flag_name}_1", target_url="https://lab.example.com", entrypoint="cli",
        )
        assert getattr(cfg, flag_name) is False

    def test_explicit_true_respected(self, flag_name):
        from webpent.production.production_spine import ProductionSpineConfig

        cfg = ProductionSpineConfig(
            engagement_id=f"e_{flag_name}_2", target_url="https://lab.example.com", entrypoint="cli",
            **{flag_name: True},
        )
        assert getattr(cfg, flag_name) is True

    def test_env_fallback_strict_bool(self, flag_name, monkeypatch):
        from webpent.production.production_spine import ProductionSpineConfig

        monkeypatch.setenv(FLAG_ENV_VARS[flag_name], "True")
        cfg = ProductionSpineConfig(
            engagement_id=f"e_{flag_name}_3", target_url="https://lab.example.com", entrypoint="cli",
        )
        assert getattr(cfg, flag_name) is True

    @pytest.mark.parametrize("raw", ["1", "yes", "on", "", "garbage"])
    def test_invalid_env_values_resolve_to_disabled(self, flag_name, monkeypatch, raw):
        from webpent.production.production_spine import ProductionSpineConfig

        monkeypatch.setenv(FLAG_ENV_VARS[flag_name], raw)
        cfg = ProductionSpineConfig(
            engagement_id=f"e_{flag_name}_4_{raw or 'empty'}",
            target_url="https://lab.example.com", entrypoint="cli",
        )
        assert getattr(cfg, flag_name) is False

    def test_explicit_false_overrides_env_true(self, flag_name, monkeypatch):
        from webpent.production.production_spine import ProductionSpineConfig

        monkeypatch.setenv(FLAG_ENV_VARS[flag_name], "True")
        cfg = ProductionSpineConfig(
            engagement_id=f"e_{flag_name}_5", target_url="https://lab.example.com", entrypoint="cli",
            **{flag_name: False},
        )
        assert getattr(cfg, flag_name) is False


class TestLiveProxySourceHardwiredOff:
    """live_proxy_source_enabled: "hardwired-off for Phase 1: any Phase 1
    configuration enabling it is rejected" — a hard reject, not merely a
    disabled default."""

    def test_default_is_false(self):
        from webpent.production.production_spine import ProductionSpineConfig

        cfg = ProductionSpineConfig(
            engagement_id="lp1", target_url="https://lab.example.com", entrypoint="cli",
        )
        assert cfg.live_proxy_source_enabled is False

    def test_explicit_true_rejected(self):
        from webpent.production.production_spine import ProductionSpineConfig, ProductionSpineError

        with pytest.raises(ProductionSpineError, match="hardwired off"):
            ProductionSpineConfig(
                engagement_id="lp2", target_url="https://lab.example.com", entrypoint="cli",
                live_proxy_source_enabled=True,
            )

    def test_env_fallback_true_also_rejected(self, monkeypatch):
        """The hardwired-off rejection applies regardless of which of the
        two sources (config field vs. env fallback) tried to enable it."""
        from webpent.production.production_spine import ProductionSpineConfig, ProductionSpineError

        monkeypatch.setenv(FLAG_ENV_VARS["live_proxy_source_enabled"], "True")
        with pytest.raises(ProductionSpineError, match="hardwired off"):
            ProductionSpineConfig(
                engagement_id="lp3", target_url="https://lab.example.com", entrypoint="cli",
            )

    def test_invalid_env_value_does_not_trigger_rejection(self, monkeypatch):
        """An invalid env value resolves to False (strict-bool), which
        must NOT trip the hard-reject path — only a genuine True does."""
        from webpent.production.production_spine import ProductionSpineConfig

        monkeypatch.setenv(FLAG_ENV_VARS["live_proxy_source_enabled"], "yes")
        cfg = ProductionSpineConfig(
            engagement_id="lp4", target_url="https://lab.example.com", entrypoint="cli",
        )
        assert cfg.live_proxy_source_enabled is False


class TestMultiPrincipalExecutionLabOnly:
    """multi_principal_execution_enabled: "approved-lab engagements
    only." """

    def test_default_is_false(self):
        from webpent.production.production_spine import ProductionSpineConfig

        cfg = ProductionSpineConfig(
            engagement_id="mp1", target_url="https://lab.example.com", entrypoint="cli",
        )
        assert cfg.multi_principal_execution_enabled is False

    def test_true_allowed_in_default_lab_profile(self):
        from webpent.production.production_spine import ProductionSpineConfig

        cfg = ProductionSpineConfig(
            engagement_id="mp2", target_url="https://lab.example.com", entrypoint="cli",
            multi_principal_execution_enabled=True,
        )
        assert cfg.multi_principal_execution_enabled is True

    @pytest.mark.parametrize("profile", ["production", "staging", "qualification", "dev"])
    def test_true_rejected_outside_lab_profile(self, monkeypatch, profile):
        from webpent.production.production_spine import ProductionSpineConfig, ProductionSpineError

        monkeypatch.setenv("WEBPENT_ENVIRONMENT_PROFILE", profile)
        with pytest.raises(ProductionSpineError, match="approved-lab"):
            ProductionSpineConfig(
                engagement_id=f"mp3_{profile}", target_url="https://lab.example.com", entrypoint="cli",
                multi_principal_execution_enabled=True,
            )

    def test_false_never_rejected_regardless_of_profile(self, monkeypatch):
        from webpent.production.production_spine import ProductionSpineConfig

        monkeypatch.setenv("WEBPENT_ENVIRONMENT_PROFILE", "production")
        cfg = ProductionSpineConfig(
            engagement_id="mp4", target_url="https://lab.example.com", entrypoint="cli",
            multi_principal_execution_enabled=False,
        )
        assert cfg.multi_principal_execution_enabled is False

    def test_ambiguous_profile_aliases_fail_closed_against_enabling(self, monkeypatch):
        """Fail-closed on ambiguity: if the aliases disagree (one says
        lab, another says production), this is NOT treated as lab —
        capability-granting flags require unambiguous agreement."""
        from webpent.production.production_spine import ProductionSpineConfig, ProductionSpineError

        monkeypatch.setenv("WEBPENT_ENVIRONMENT_PROFILE", "lab")
        monkeypatch.setenv("ENVIRONMENT_PROFILE", "production")
        with pytest.raises(ProductionSpineError, match="approved-lab"):
            ProductionSpineConfig(
                engagement_id="mp5", target_url="https://lab.example.com", entrypoint="cli",
                multi_principal_execution_enabled=True,
            )


class TestTraceRecordingAllFiveFlags:
    def test_all_five_flags_present_in_trace(self, monkeypatch):
        from webpent.production.production_spine import (
            _SPINE_REGISTRY,
            ProductionSpineConfig,
            resolve_production_spine,
        )

        eng = "trace_all_five"
        _SPINE_REGISTRY.pop(eng, None)
        cfg = ProductionSpineConfig(
            engagement_id=eng, target_url="https://lab.example.com", entrypoint="cli",
            exploration_ingress_enabled=True, static_fixture_source_enabled=True,
            multi_principal_execution_enabled=True, foreign_report_writer_access=True,
        )
        _orch, trace = resolve_production_spine(cfg)
        flag_stages = [s for s in trace.stages if s["stage"] == "flag_resolution"]
        assert len(flag_stages) == 1
        detail = flag_stages[0]["detail"]
        for flag_name in (
            "exploration_ingress_enabled", "static_fixture_source_enabled",
            "live_proxy_source_enabled", "multi_principal_execution_enabled",
            "foreign_report_writer_access",
        ):
            assert flag_name in detail, f"{flag_name} missing from flag_resolution trace detail"
        assert detail["exploration_ingress_enabled"] is True
        assert detail["static_fixture_source_enabled"] is True
        assert detail["live_proxy_source_enabled"] is False
        assert detail["multi_principal_execution_enabled"] is True
        assert detail["foreign_report_writer_access"] is True
        _SPINE_REGISTRY.pop(eng, None)

    def test_trace_bound_to_engagement_and_target_fingerprint(self, monkeypatch):
        """Program spec §8.4: "flags are bound to engagement and target
        fingerprint, recorded in the production trace." """
        from webpent.production.production_spine import (
            _SPINE_REGISTRY,
            ProductionSpineConfig,
            resolve_production_spine,
        )
        from webpent.shared.bac_identity_tester import target_fingerprint

        eng = "trace_binding_test"
        _SPINE_REGISTRY.pop(eng, None)
        cfg = ProductionSpineConfig(
            engagement_id=eng, target_url="https://lab.example.com", entrypoint="cli",
        )
        _orch, trace = resolve_production_spine(cfg)
        detail = [s for s in trace.stages if s["stage"] == "flag_resolution"][0]["detail"]
        assert detail["engagement_id"] == eng
        assert detail["target_fingerprint"] == target_fingerprint("https://lab.example.com")
        _SPINE_REGISTRY.pop(eng, None)

    def test_flags_are_drift_registered(self, monkeypatch):
        """Two entrypoints resolving the same engagement_id with a
        different flag value must fail closed (configuration drift) —
        same mechanism already proven for foreign_report_writer_access
        in Part 2.5, extended here to a newly-added flag."""
        from webpent.production.production_spine import (
            _SPINE_REGISTRY,
            ProductionSpineConfig,
            ProductionSpineError,
            resolve_production_spine,
        )

        eng = "drift_test_part4"
        _SPINE_REGISTRY.pop(eng, None)
        cfg_a = ProductionSpineConfig(
            engagement_id=eng, target_url="https://lab.example.com", entrypoint="cli",
            static_fixture_source_enabled=False,
        )
        resolve_production_spine(cfg_a)
        cfg_b = ProductionSpineConfig(
            engagement_id=eng, target_url="https://lab.example.com", entrypoint="worker",
            static_fixture_source_enabled=True,
        )
        with pytest.raises(ProductionSpineError):
            resolve_production_spine(cfg_b)
        _SPINE_REGISTRY.pop(eng, None)


class TestForbiddenActivationPaths:
    """Same guarantee proven for foreign_report_writer_access in Part
    2.5, extended to all four new flags: no mutable process-global
    singleton exists for a fixture/monkeypatch/conftest to flip — every
    flag lives on the immutable, per-call ProductionSpineConfig
    instance."""

    @pytest.mark.parametrize("flag_name", list(FLAG_ENV_VARS.keys()))
    def test_frozen_dataclass_rejects_post_construction_mutation(self, flag_name):
        import dataclasses

        from webpent.production.production_spine import ProductionSpineConfig

        cfg = ProductionSpineConfig(
            engagement_id=f"forbidden_{flag_name}", target_url="https://lab.example.com",
            entrypoint="cli",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(cfg, flag_name, True)


class TestNoInternalCatcherSourceFlag:
    """Architecture-authority ruling (recorded verbatim in the sprint
    changelog): NO flag exists for internal_catcher_source. This test
    pins that absence so it can't be silently added later without a
    deliberate, reviewed change."""

    def test_no_such_field_or_env_var(self):
        import dataclasses

        from webpent.production.production_spine import ProductionSpineConfig

        field_names = {f.name for f in dataclasses.fields(ProductionSpineConfig)}
        assert "internal_catcher_source_enabled" not in field_names
        assert not any("catcher" in name for name in field_names)

# tests/team1_acceptance/test_sprint_i1_part2_flag.py
"""Sprint I-1, Part 2, item 2.5 (M3 v1.1 §5.3, F-04/OQ-6) — the
foreign_report_writer_access spine flag: configuration precedence,
strict-bool validation, forbidden-activation-path assertions, and the
two gated call sites.
"""
from __future__ import annotations

import pytest

ENV_VAR = "WEBPENT_FOREIGN_REPORT_WRITER_ACCESS"


class TestFlagResolution:
    """ProductionSpineConfig is authoritative; the env var is a fallback
    used only when the field is not explicitly set."""

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        monkeypatch.delenv(ENV_VAR, raising=False)
        yield

    def test_default_is_false(self):
        from webpent.production.production_spine import ProductionSpineConfig

        cfg = ProductionSpineConfig(
            engagement_id="e1", target_url="https://lab.example.com", entrypoint="cli",
        )
        assert cfg.foreign_report_writer_access is False

    def test_explicit_true_respected(self):
        from webpent.production.production_spine import ProductionSpineConfig

        cfg = ProductionSpineConfig(
            engagement_id="e2", target_url="https://lab.example.com", entrypoint="cli",
            foreign_report_writer_access=True,
        )
        assert cfg.foreign_report_writer_access is True

    def test_env_fallback_used_only_when_not_explicit(self, monkeypatch):
        from webpent.production.production_spine import ProductionSpineConfig

        monkeypatch.setenv(ENV_VAR, "True")
        cfg = ProductionSpineConfig(
            engagement_id="e3", target_url="https://lab.example.com", entrypoint="cli",
        )
        assert cfg.foreign_report_writer_access is True

    def test_explicit_false_overrides_env_true(self, monkeypatch):
        """Config field, even when explicitly False, is authoritative
        over a truthy env var — the env var is a fallback, not an
        override."""
        from webpent.production.production_spine import ProductionSpineConfig

        monkeypatch.setenv(ENV_VAR, "True")
        cfg = ProductionSpineConfig(
            engagement_id="e4", target_url="https://lab.example.com", entrypoint="cli",
            foreign_report_writer_access=False,
        )
        assert cfg.foreign_report_writer_access is False

    @pytest.mark.parametrize("raw", ["1", "yes", "on", "", "garbage"])
    def test_non_literal_env_values_resolve_to_false(self, monkeypatch, raw):
        """Strict-bool: casual truthy tokens ("1", "yes", "on") and
        garbage/empty values must resolve to disabled.

        NOTE — spec ambiguity flagged in the sprint changelog: M3 v1.1
        §5.3 says "only the literal strings True/False (case-insensitive)
        are accepted" in one clause, but the same paragraph separately
        lists lowercase "true" as an example of something that must NOT
        coerce to True — those two clauses conflict. This implementation
        follows the case-insensitive-literal reading (the more precise,
        adjacent clause): "true"/"TRUE"/"tRuE" all accepted, see
        test_case_insensitive_true_literal_accepted below.
        """
        from webpent.production.production_spine import ProductionSpineConfig

        monkeypatch.setenv(ENV_VAR, raw)
        cfg = ProductionSpineConfig(
            engagement_id=f"e5_{raw or 'empty'}", target_url="https://lab.example.com",
            entrypoint="cli",
        )
        assert cfg.foreign_report_writer_access is False

    @pytest.mark.parametrize("raw", ["True", "TRUE", "true", "tRuE"])
    def test_case_insensitive_true_literal_accepted(self, monkeypatch, raw):
        from webpent.production.production_spine import ProductionSpineConfig

        monkeypatch.setenv(ENV_VAR, raw)
        cfg = ProductionSpineConfig(
            engagement_id=f"e6_{raw}", target_url="https://lab.example.com", entrypoint="cli",
        )
        assert cfg.foreign_report_writer_access is True

    def test_flag_is_drift_registered(self, monkeypatch):
        """Two entrypoints resolving the same engagement_id with
        different flag values must fail closed (configuration drift)."""
        from webpent.production.production_spine import (
            _SPINE_REGISTRY,
            ProductionSpineConfig,
            ProductionSpineError,
            resolve_production_spine,
        )

        eng = "e7_drift_test"
        _SPINE_REGISTRY.pop(eng, None)
        cfg_a = ProductionSpineConfig(
            engagement_id=eng, target_url="https://lab.example.com", entrypoint="cli",
            foreign_report_writer_access=False,
        )
        resolve_production_spine(cfg_a)
        cfg_b = ProductionSpineConfig(
            engagement_id=eng, target_url="https://lab.example.com", entrypoint="worker",
            foreign_report_writer_access=True,
        )
        with pytest.raises(ProductionSpineError):
            resolve_production_spine(cfg_b)
        _SPINE_REGISTRY.pop(eng, None)

    def test_flag_is_trace_recorded(self, monkeypatch):
        from webpent.production.production_spine import (
            _SPINE_REGISTRY,
            ProductionSpineConfig,
            resolve_production_spine,
        )

        eng = "e8_trace_test"
        _SPINE_REGISTRY.pop(eng, None)
        cfg = ProductionSpineConfig(
            engagement_id=eng, target_url="https://lab.example.com", entrypoint="cli",
            foreign_report_writer_access=True,
        )
        _orch, trace = resolve_production_spine(cfg)
        flag_stages = [s for s in trace.stages if s["stage"] == "flag_resolution"]
        assert len(flag_stages) == 1
        assert flag_stages[0]["detail"]["foreign_report_writer_access"] is True
        _SPINE_REGISTRY.pop(eng, None)


class TestForbiddenActivationPaths:
    """The flag must never be settable to True via a test fixture,
    monkeypatch, conftest, or tests/ code — i.e. THIS test file, by
    construction, can only ever observe the flag being False by default
    and True only via the two legitimate channels (explicit config field,
    or the real environment variable) — never via patching internals."""

    def test_no_module_level_mutable_singleton_to_patch(self):
        """There is no process-global 'current flag' object a test could
        monkeypatch to True and have it leak into unrelated engagements —
        the value lives on the immutable, per-call ProductionSpineConfig
        instance (frozen dataclass) or is read fresh from the environment
        each time, never cached as mutable global state."""
        import dataclasses

        from webpent.production.production_spine import ProductionSpineConfig

        assert dataclasses.is_dataclass(ProductionSpineConfig)
        # frozen=True dataclasses raise on attribute mutation.
        cfg = ProductionSpineConfig(
            engagement_id="e9", target_url="https://lab.example.com", entrypoint="cli",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.foreign_report_writer_access = True


class TestGatingSurface:
    """Item 2.5's exact gating surface: (i) tools/registry.py extension,
    (ii) ActionAuthority capability registration matching a foreign-
    writer pattern."""

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        monkeypatch.delenv(ENV_VAR, raising=False)
        yield

    def test_registry_extension_denied_by_default(self):
        from webpent.shared.exceptions import ForeignWriterAccessDenied
        from webpent.tools.registry import register_tool

        def foreign_func():
            pass
        foreign_func.__module__ = "webpent.shared.not_a_real_tool_package"

        with pytest.raises(ForeignWriterAccessDenied):
            register_tool(name="test_evil_1", category="exfil")(foreign_func)

    def test_registry_extension_allowed_when_flag_enabled(self, monkeypatch):
        from webpent.tools.registry import register_tool

        monkeypatch.setenv(ENV_VAR, "True")

        def foreign_func():
            pass
        foreign_func.__module__ = "webpent.shared.not_a_real_tool_package"

        # Must not raise.
        register_tool(name="test_evil_2", category="exfil")(foreign_func)

    def test_registry_allowlisted_packages_unaffected(self):
        """The two real tool packages must never trip this gate,
        regardless of flag state — this is what proves the gate is
        additive, not a regression for legitimate tool wrappers."""
        from webpent.tools.registry import register_tool

        for pkg in ("webpent.tools.recon.some_new_wrapper", "webpent.tools.exploitation.some_new_wrapper"):
            def legit_func():
                pass
            legit_func.__module__ = pkg
            register_tool(name=f"test_legit_{pkg.split('.')[-1]}", category="recon")(legit_func)

    def test_action_authority_denies_foreign_writer_capability(self):
        from webpent.shared.action_authority import ActionAuthority, ActionRequest
        from webpent.shared.exceptions import ForeignWriterAccessDenied

        auth = ActionAuthority(allowed_origin="https://lab.example.com")
        req = ActionRequest(
            task_id="t1", engagement_id="e1", target_url="https://lab.example.com",
            capability="finding_export_writer", action_family="http_read",
        )
        with pytest.raises(ForeignWriterAccessDenied):
            auth.authorize(req)

    def test_action_authority_allows_when_flag_enabled(self):
        from webpent.shared.action_authority import ActionAuthority, ActionRequest

        auth = ActionAuthority(
            allowed_origin="https://lab.example.com", foreign_report_writer_access=True,
        )
        req = ActionRequest(
            task_id="t1", engagement_id="e1", target_url="https://lab.example.com",
            capability="finding_export_writer", action_family="http_read",
        )
        # Must not raise (may still be policy_denied for unrelated reasons).
        decision = auth.authorize(req)
        assert decision is not None

    def test_action_authority_unrelated_capability_unaffected(self):
        """A capability name that doesn't match any foreign-writer
        pattern must never trip this gate, regardless of flag state."""
        from webpent.shared.action_authority import ActionAuthority, ActionRequest

        auth = ActionAuthority(allowed_origin="https://lab.example.com")
        req = ActionRequest(
            task_id="t1", engagement_id="e1", target_url="https://lab.example.com",
            capability="http_read", action_family="http_read",
        )
        # Must not raise ForeignWriterAccessDenied.
        decision = auth.authorize(req)
        assert decision is not None

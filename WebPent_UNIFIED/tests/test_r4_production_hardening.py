"""R4 production-hardening window (2026-11-02, DR-020) — regression pins.

Covers the four sanctioned units of the window:

  W1  strict production key guard — ``shared/preflight.py`` refuses boot on
      ANY non-loopback bind (not just ``0.0.0.0``/``::``) when auth is
      disabled or a secret key sits at a publicly-known insecure default;
      the explicit ``I_UNDERSTAND_THIS_IS_INSECURE`` override and the
      documented deployment paths keep working.
  W2  attack-detector wiring — ``VulnClass`` members, registry capability,
      dispatch, deterministic fail-closed validator outcomes for
      prototype_pollution / cache_poisoning, and the scope-gated graph nodes.
  W3  re-freeze-queue items — ``--version`` / ``--build-info`` CLI options
      and the security-headers middleware (HSTS only over real TLS).

The window's frozen-law record: ``scripts/refreeze_r4_20261102.py`` (8 files,
in place, 719 entries) + the extended drift union in
``tests/test_frozen_module_gate.py`` + DR-020.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from webpent.models.findings import Confidence, Finding, Severity, VulnClass

# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def _finding(vuln_class: str, **kwargs) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        title=f"fixture {vuln_class}",
        severity=Severity.HIGH.value,
        description="r4 fixture",
        tool_name="producer",
        url=kwargs.pop("url", "http://lab.local/api"),
        confidence=Confidence.TENTATIVE,
        confidence_level=kwargs.pop("confidence_level", "Needs Human Review"),
        reasoning="fixture",
        vuln_class=vuln_class,
        created_at=datetime.now(UTC),
        thread_id="t",
        **kwargs,
    )


def _dig_canary(node):
    """Return the run canary planted in a probe payload (strip the sentinel)."""
    if isinstance(node, dict):
        for value in node.values():
            found = _dig_canary(value)
            if found:
                return found
    if isinstance(node, list):
        for value in node:
            found = _dig_canary(value)
            if found:
                return found
    if isinstance(node, str) and node.endswith("_true"):
        return node[: -len("_true")]
    return None


class _FakeSettings:
    """Posture-test double: same attribute surface the guard reads.

    The insecure-default sets mirror config/settings.py literals (stable
    public knowledge — the dev defaults are printed in the warnings).
    """

    _INSECURE_JWT_DEFAULTS = frozenset(
        {
            "webpent-dev-secret-key-change-in-production",
            "change-me-in-production",
            "",
        }
    )
    _INSECURE_AUDIT_DEFAULTS = frozenset({"webpent-dev-audit-key-change-in-production"})
    _INSECURE_CELERY_PAYLOAD_DEFAULTS = frozenset({"webpent-dev-celery-payload-key-change-in-production", ""})

    def __init__(
        self,
        *,
        auth_enabled: bool = False,
        environment_profile: str = "lab",
        jwt_secret_key: str = "",
        audit_secret_key: str = "",
        celery_payload_key: str = "",
    ) -> None:
        self.auth_enabled = auth_enabled
        self.environment_profile = SimpleNamespace(value=environment_profile)
        self.jwt_secret_key = jwt_secret_key
        self.audit_secret_key = audit_secret_key
        self.celery_payload_key = celery_payload_key


@pytest.fixture()
def guard(monkeypatch):
    """Isolate the strict key guard: inject settings, clear the override."""
    from webpent.shared import preflight

    monkeypatch.delenv("I_UNDERSTAND_THIS_IS_INSECURE", raising=False)
    holder: dict[str, object] = {}

    def _install(settings: object) -> None:
        holder["settings"] = settings
        monkeypatch.setattr("webpent.config.settings.get_settings", lambda: settings, raising=False)
        monkeypatch.setattr(
            preflight,
            "_check_redis_security",
            lambda: {
                "status": "ok",
                "broker": {"configured": False},
                "rate_limit": {"configured": False},
            },
        )

    def _enforce(host: str | None):
        report: dict[str, dict[str, object]] = {}
        preflight._enforce_api_security_posture(host=host, report=report)
        return report

    return SimpleNamespace(install=_install, enforce=_enforce)


# ---------------------------------------------------------------------------
# W1 — strict production key guard
# ---------------------------------------------------------------------------


class TestNonlocalBindClassifier:
    def test_loopback_and_unknown_are_local(self):
        from webpent.shared.preflight import _is_nonlocal_bind

        assert _is_nonlocal_bind("") is False
        assert _is_nonlocal_bind("localhost") is False
        assert _is_nonlocal_bind("::1") is False
        assert _is_nonlocal_bind("127.0.0.1") is False
        assert _is_nonlocal_bind("127.9.9.9") is False

    def test_wildcard_lan_and_public_are_nonlocal(self):
        from webpent.shared.preflight import _is_nonlocal_bind

        assert _is_nonlocal_bind("0.0.0.0") is True
        assert _is_nonlocal_bind("::") is True
        assert _is_nonlocal_bind("192.168.1.10") is True
        assert _is_nonlocal_bind("10.0.0.5") is True
        assert _is_nonlocal_bind("api.example.com") is True


class TestStrictKeyGuard:
    def test_lan_bind_with_auth_disabled_is_blocked(self, guard):
        guard.install(_FakeSettings(auth_enabled=False))
        with pytest.raises(SystemExit, match="auth disabled"):
            guard.enforce("192.168.1.10")

    def test_lan_bind_with_default_keys_and_auth_on_is_blocked(self, guard):
        # The headline R4-01 hole: auth enabled (dev warnings only) with
        # default keys, audible on the LAN — must now refuse boot.
        guard.install(_FakeSettings(auth_enabled=True))
        with pytest.raises(SystemExit, match="insecure default secret"):
            guard.enforce("192.168.1.10")

    def test_block_message_names_the_insecure_keys(self, guard):
        guard.install(
            _FakeSettings(
                auth_enabled=True,
                jwt_secret_key="K" * 40,
                audit_secret_key="",
            )
        )
        with pytest.raises(SystemExit, match="AUDIT_SECRET_KEY"):
            guard.enforce("10.0.0.5")

    def test_lan_bind_with_operator_keys_and_auth_on_passes(self, guard):
        guard.install(
            _FakeSettings(
                auth_enabled=True,
                jwt_secret_key="K" * 40,
                audit_secret_key="A" * 40,
                celery_payload_key="C" * 40,
            )
        )
        report = guard.enforce("192.168.1.10")
        assert report.get("api_security_posture") is None

    def test_loopback_and_unknown_bind_keep_passing_in_dev(self, guard):
        guard.install(_FakeSettings(auth_enabled=False))
        assert guard.enforce("127.0.0.1") == {}
        assert guard.enforce("localhost") == {}
        assert guard.enforce(None) == {}

    def test_zero_zero_bind_regression_kept(self, guard):
        # Existing pin (test_vip_auth_posture): 0.0.0.0 + auth off blocks.
        guard.install(_FakeSettings(auth_enabled=False))
        with pytest.raises(SystemExit, match="auth disabled"):
            guard.enforce("0.0.0.0")

    def test_override_remains_the_lab_escape_hatch(self, guard, monkeypatch):
        monkeypatch.setenv("I_UNDERSTAND_THIS_IS_INSECURE", "1")
        guard.install(_FakeSettings(auth_enabled=False))
        report = guard.enforce("192.168.1.10")
        assert "OVERRIDDEN" in str(report["api_security_posture"]["status"])

    def test_unreadable_settings_fail_closed_on_nonlocal_bind(self, guard, monkeypatch):
        monkeypatch.setattr(
            "webpent.config.settings.get_settings",
            lambda: (_ for _ in ()).throw(RuntimeError("boom")),
            raising=False,
        )
        from webpent.shared import preflight

        monkeypatch.setattr(
            preflight,
            "_check_redis_security",
            lambda: {"status": "ok", "broker": {}, "rate_limit": {}},
        )
        report: dict[str, dict[str, object]] = {}
        with pytest.raises(SystemExit, match="non-local bind"):
            preflight._enforce_api_security_posture(host="192.168.1.10", report=report)

    def test_strict_profile_auth_off_still_blocks_first(self, guard):
        guard.install(_FakeSettings(auth_enabled=False, environment_profile="production"))
        with pytest.raises(SystemExit, match="staging/production"):
            guard.enforce("127.0.0.1")


# ---------------------------------------------------------------------------
# W2 — attack-detector wiring
# ---------------------------------------------------------------------------


class TestDetectorWiring:
    def test_vuln_class_members_exist(self):
        assert VulnClass.PROTOTYPE_POLLUTION.value == "prototype_pollution"
        assert VulnClass.CACHE_POISONING.value == "cache_poisoning"
        from webpent.models.findings import EXPLOITABLE_CLASSES

        # Same routing shape as request_smuggling: validator-owned
        # confirmation, not the payload-injection pipeline.
        assert "prototype_pollution" not in EXPLOITABLE_CLASSES
        assert "cache_poisoning" not in EXPLOITABLE_CLASSES

    def test_finding_construction_with_new_classes(self):
        for vuln_class in ("prototype_pollution", "cache_poisoning"):
            finding = _finding(vuln_class)
            assert finding.vuln_class == vuln_class

    def test_registry_promotes_both_classes_next_to_request_smuggling(self):
        from webpent.agents.validator.registry import (
            _ALL_CLASSES,
            capability_for,
            validator_id_for,
        )

        for cls in ("prototype_pollution", "cache_poisoning"):
            assert validator_id_for(cls) == cls
            capability = capability_for(cls)
            assert capability.status == "tested"
            assert capability.evidence_mode == "deterministic"
        assert "prototype_pollution" in _ALL_CLASSES
        assert "cache_poisoning" in _ALL_CLASSES

    def test_dispatch_branches_route_to_postp0_validators(self):
        from webpent.agents.validator.agent import _classify_finding

        for cls in ("prototype_pollution", "cache_poisoning"):
            assert _classify_finding(_finding(cls)) == cls

    def test_validator_exports(self):
        from webpent.agents.validator import postp0_checks

        assert "validate_prototype_pollution" in postp0_checks.__all__
        assert "validate_cache_poisoning" in postp0_checks.__all__


class TestPrototypePollutionValidator:
    @pytest.fixture()
    def validator(self, monkeypatch):
        import webpent.agents.validator.postp0_checks as mod

        sent: list[str] = []

        def _fake_request(finding, cookies, *, method, body, headers=None):
            sent.append(body)
            from webpent.agents.validator.active_checks import Replay

            canary = json.loads(body or "{}")
            marker = _dig_canary(canary)

            def _make(status_code: int, body_text: str) -> Replay:
                return Replay(
                    method=method,
                    url=finding.url,
                    request_body=body,
                    status_code=status_code,
                    body=body_text,
                    headers={},
                    elapsed_ms=5,
                )

            if marker is None:
                return _make(200, '{"ok": "benign-control"}')
            return _make(200, f'{{"echo": "{marker}"}}')

        monkeypatch.setattr(mod, "_safe_http_request", _fake_request)
        monkeypatch.setattr(
            mod,
            "_confirmed",
            lambda finding, evidence, reasoning, payload_label, verification_context=None: finding.model_copy(
                update={
                    "confidence_level": "Tool Confirmed",
                    "evidence": {**(finding.evidence or {}), **evidence},
                    "reasoning": reasoning,
                }
            ),
        )
        return SimpleNamespace(sent=sent, mod=mod)

    def test_confirms_only_on_full_reflection_triangle(self, validator):
        finding = _finding("prototype_pollution", request_method="POST")
        result = validator.mod.validate_prototype_pollution(finding)
        assert result.confidence_level == "Tool Confirmed"
        evidence = result.evidence
        assert evidence["causal_signal"] is True
        assert evidence["negative_control_complete"] is True
        assert evidence["causal_basis"] == "canary_reflection_reprobe_confirmed"
        assert any(v == "confirmed" for v in evidence["probe_outcomes"].values())

    def test_explicit_negative_when_canary_never_reflects(self, validator, monkeypatch):
        def _clean_request(finding, cookies, *, method, body, headers=None):
            from webpent.agents.validator.active_checks import Replay

            return Replay(
                method=method,
                url=finding.url,
                request_body=body,
                status_code=200,
                body='{"ok": "constant"}',
                headers={},
                elapsed_ms=5,
            )

        monkeypatch.setattr(validator.mod, "_safe_http_request", _clean_request)
        finding = _finding("prototype_pollution", request_method="POST")
        result = validator.mod.validate_prototype_pollution(finding)
        assert result.confidence_level == "Needs Human Review"
        assert result.evidence["outcome"] == "explicit_negative"
        assert result.evidence["causal_signal"] is False

    def test_inconclusive_when_baseline_control_unreachable(self, validator, monkeypatch):
        def _dead_request(finding, cookies, *, method, body, headers=None):
            return None

        monkeypatch.setattr(validator.mod, "_safe_http_request", _dead_request)
        finding = _finding("prototype_pollution", request_method="POST")
        result = validator.mod.validate_prototype_pollution(finding)
        assert result.confidence_level == "Needs Human Review"
        assert result.evidence["reason"] == "baseline_control_unreachable"


class TestCachePoisoningValidator:
    @pytest.fixture()
    def validator(self, monkeypatch):
        import webpent.agents.validator.postp0_checks as mod

        # Stateful cache: once an attack request lands, later plain requests
        # are served the poisoned cached body — canary grafted onto the
        # clean shape so the shape-equivalence check passes exactly.
        cache = {"last_attack_value": ""}

        def _fake_get(url, cookies, *, headers=None):
            from webpent.agents.validator.active_checks import Replay

            def _make(body_text: str) -> Replay:
                return Replay(
                    method="GET",
                    url=url,
                    request_body=None,
                    status_code=200,
                    body=body_text,
                    headers={},
                    elapsed_ms=5,
                )

            attack_value = ""
            for value in (headers or {}).values():
                if "attacker" in value or "canary-path" in value or value == "javascript":
                    attack_value = value
            if "utm_content=cp-canary" in url:
                attack_value = "cp-canary"

            if attack_value:
                cache["last_attack_value"] = attack_value
                return _make(f"<html>service: {attack_value}</html>")
            if cache["last_attack_value"]:
                # Victim served from the poisoned cache: control shape + canary.
                return _make(f"<html>service: normal{cache['last_attack_value']}</html>")
            return _make("<html>service: normal</html>")

        monkeypatch.setattr(mod, "_safe_http_get", _fake_get)
        monkeypatch.setattr(
            mod,
            "_confirmed",
            lambda finding, evidence, reasoning, payload_label, verification_context=None: finding.model_copy(
                update={
                    "confidence_level": "Tool Confirmed",
                    "evidence": {**(finding.evidence or {}), **evidence},
                    "reasoning": reasoning,
                }
            ),
        )
        return SimpleNamespace(mod=mod)

    def test_confirms_on_full_two_request_differential(self, validator):
        finding = _finding("cache_poisoning", url="http://lab.local/")
        result = validator.mod.validate_cache_poisoning(finding)
        assert result.confidence_level == "Tool Confirmed"
        evidence = result.evidence
        assert evidence["causal_signal"] is True
        assert evidence["negative_control_complete"] is True
        assert evidence["causal_basis"] == "two_request_differential_reprobe_confirmed"
        assert evidence["probe_kind"] in {"header", "param_variant"}

    def test_explicit_negative_when_nothing_reflects(self, validator, monkeypatch):
        def _flat_get(url, cookies, *, headers=None):
            from webpent.agents.validator.active_checks import Replay

            return Replay(
                method="GET",
                url=url,
                request_body=None,
                status_code=200,
                body="<html>constant</html>",
                headers={},
                elapsed_ms=5,
            )

        monkeypatch.setattr(validator.mod, "_safe_http_get", _flat_get)
        finding = _finding("cache_poisoning", url="http://lab.local/")
        result = validator.mod.validate_cache_poisoning(finding)
        assert result.confidence_level == "Needs Human Review"
        assert result.evidence["outcome"] == "explicit_negative"


class TestDetectorGraphNodes:
    def _state(self, url: str | None):
        target = SimpleNamespace(url=url) if url else None
        return {"target": target, "findings": [], "messages": [], "crawled_data": {}}

    def test_node_skips_without_target_url(self):
        from webpent.agents.prototype_pollution.agent import prototype_pollution_node

        result = prototype_pollution_node(self._state(None))
        # Skip paths omit the "findings" key entirely (LangGraph: no update).
        assert result.get("findings", []) == []
        assert "skipping" in result["messages"][0].content

    def test_node_fails_closed_outside_engagement_scope(self, monkeypatch):
        import webpent.shared.engagement_scope as scope_mod
        from webpent.agents.cache_poisoning.agent import cache_poisoning_node
        from webpent.agents.prototype_pollution.agent import prototype_pollution_node

        monkeypatch.setattr(scope_mod, "is_engagement_target_host", lambda host: False)
        for node in (prototype_pollution_node, cache_poisoning_node):
            result = node(self._state("http://outsider.example/"))
            assert result.get("findings", []) == []
            assert "fail-closed" in result["messages"][0].content

    def test_node_fails_closed_when_scope_module_missing(self, monkeypatch):
        import builtins

        from webpent.agents.prototype_pollution.agent import prototype_pollution_node

        real_import = builtins.__import__

        def _no_scope(name, *args, **kwargs):
            if name.startswith("webpent.shared.engagement_scope"):
                raise ImportError("blocked for test")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _no_scope)
        result = prototype_pollution_node(self._state("http://lab.local/"))
        assert result.get("findings", []) == []
        assert "skipped" in result["messages"][0].content

    def test_graph_builder_exposes_detector_nodes(self):
        from webpent.graph.builder import NODE_CACHE_POISONING, NODE_PROTOTYPE_POLLUTION

        assert NODE_PROTOTYPE_POLLUTION == "prototype_pollution"
        assert NODE_CACHE_POISONING == "cache_poisoning"


# ---------------------------------------------------------------------------
# W3 — CLI self-identification + security headers
# ---------------------------------------------------------------------------


class TestCliSelfIdentification:
    def test_version_option_reports_the_build(self):
        from typer.testing import CliRunner

        from webpent.cli.commands import app

        result = CliRunner().invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "webpent" in result.output.lower()

    def test_build_info_option_prints_provenance(self):
        from typer.testing import CliRunner

        from webpent.cli.commands import app

        result = CliRunner().invoke(app, ["--build-info"])
        assert result.exit_code == 0
        assert "build_name" in result.output

    def test_normal_help_still_works(self):
        from typer.testing import CliRunner

        from webpent.cli.commands import app

        result = CliRunner().invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "--version" in result.output


class TestSecurityHeadersMiddleware:
    @pytest.fixture()
    def client(self):
        from fastapi import FastAPI
        from starlette.testclient import TestClient

        from webpent.api.app import security_headers_middleware

        probe = FastAPI()

        @probe.middleware("http")
        async def _wrap(request, call_next):
            return await security_headers_middleware(request, call_next)

        @probe.get("/ping")
        def _ping():
            return {"ok": True}

        return TestClient(probe)

    def test_defensive_headers_on_plain_http(self, client):
        response = client.get("/ping")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
        assert "Strict-Transport-Security" not in response.headers

    def test_hsts_only_when_actually_over_tls(self, client):
        response = client.get("/ping", headers={"X-Forwarded-Proto": "https"})
        assert response.headers["Strict-Transport-Security"].startswith("max-age=")

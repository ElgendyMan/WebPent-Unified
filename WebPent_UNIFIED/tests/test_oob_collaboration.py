# tests/test_oob_collaboration.py
"""OOB collaboration engine tests (2026-10-25 Proposal 3).

Covers the engine (shared/oob.py), the canonical blind-OOB validator
(production/oob_validator.py), the memory/db.py persistence tables, the
flag-gated payload_generator injection point, and the accelerated-pulse
end-to-end confirmation/refutation scenario set the proposal requires:

  * CONFIRMED  — token-matched callback inside the window, silent control
  * REFUTED    — no callback; control fires; mismatched token; no token
  * INCONCLUSIVE — collaborator/transport failure (never a halt)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from webpent.config.settings import Settings, activate_settings
from webpent.models.findings import Confidence, EXPLOITABLE_CLASSES, Finding, Severity, VulnClass
from webpent.production.validators import (
    VALIDATORS,
    ValidationOutcome,
    ValidatorError,
    run_validator,
)
from webpent.shared.oob import (
    DEFAULT_CALLBACK_TTL_SECONDS,
    DEFAULT_EVIDENCE_WINDOW_SECONDS,
    DatabaseOOBStore,
    MemoryOOBStore,
    OOBCollaborator,
    attach_oob_probes,
    oob_probe_payloads,
)

# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


class _FakeClock:
    """Accelerated-pulse clock: deterministic, never sleeps."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)


def _collab(clock: _FakeClock | None = None, domain: str = "oob.example.com") -> tuple[OOBCollaborator, _FakeClock]:
    clock = clock or _FakeClock()
    return (
        OOBCollaborator(
            base_domain=domain,
            store=MemoryOOBStore(),
            now=clock,
            evidence_window_seconds=DEFAULT_EVIDENCE_WINDOW_SECONDS,
        ),
        clock,
    )


def _finding(vuln_class: str, **overrides: Any) -> Finding:
    base: dict[str, Any] = dict(
        id=uuid.uuid4(),
        title=f"fixture {vuln_class} candidate",
        severity=Severity.HIGH.value,
        description="proposal3 fixture",
        tool_name="hypothesis",
        url="http://lab.local/item?id=1",
        confidence=Confidence.TENTATIVE,
        confidence_level="Pending",
        reasoning="fixture",
        vuln_class=vuln_class,
        created_at=datetime.now(timezone.utc),
        thread_id="t",
    )
    base.update(overrides)
    return Finding(**base)


def _cb(token: str, seen_at: float, **extra: Any) -> dict[str, Any]:
    return {"token": token, "seen_at": seen_at, **extra}


# --------------------------------------------------------------------------
# Engine: registration and fail-closed identity
# --------------------------------------------------------------------------


class TestProbeRegistration:
    def test_empty_domain_fails_closed(self) -> None:
        collab, _ = _collab(domain="")
        assert collab.enabled is False
        assert collab.register_probe(engagement_id="e1", vuln_class="ssrf") is None

    def test_token_is_128bit_hex_and_unique_per_probe(self) -> None:
        collab, _ = _collab()
        b1 = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        b2 = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        assert b1 is not None and b2 is not None
        assert len(b1.token) == 32
        assert int(b1.token, 16) >= 0  # hex
        assert b1.token != b2.token

    def test_host_is_per_engagement_and_dns_safe(self) -> None:
        collab, _ = _collab()
        binding = collab.register_probe(
            engagement_id="Campaign/../X_9", vuln_class="xxe"
        )
        assert binding is not None
        assert binding.host.endswith(".campaignx-9.oob.example.com")
        assert binding.host.split(".")[0] == binding.token

    def test_registered_token_accepts_callback(self) -> None:
        collab, _ = _collab()
        binding = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        assert binding is not None
        assert collab.record_callback(binding.token, protocol="dns") is True

    def test_unknown_token_is_dropped_fail_closed(self) -> None:
        collab, _ = _collab()
        assert collab.record_callback("f" * 32) is False

    def test_callback_never_stores_raw_source_identity(self) -> None:
        collab, clock = _collab()
        binding = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        assert binding is not None
        collab.record_callback(
            binding.token, source_ip="203.0.113.7", details="GET /probe"
        )
        callbacks = collab.poll_callbacks(binding)
        assert len(callbacks) == 1
        raw = {cb.source_fingerprint for cb in callbacks} | {
            cb.details for cb in callbacks
        }
        assert "203.0.113.7" not in raw
        assert callbacks[0].source_fingerprint  # fingerprinted, not empty
        assert callbacks[0].source_fingerprint != "203.0.113.7"

    def test_callback_details_are_bounded(self) -> None:
        collab, _ = _collab()
        binding = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        assert binding is not None
        collab.record_callback(binding.token, details="x" * 9999)
        callbacks = collab.poll_callbacks(binding)
        assert len(callbacks) == 1
        assert len(callbacks[0].details) <= 256


# --------------------------------------------------------------------------
# Engine: deterministic matcher and TTL
# --------------------------------------------------------------------------


class TestDeterministicMatcher:
    def test_callback_before_registration_never_matches(self) -> None:
        collab, clock = _collab()
        binding = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        assert binding is not None
        # Callback timestamped BEFORE the probe existed: excluded.
        collab.record_callback(binding.token, seen_at=clock.now - 500.0)
        assert collab.poll_callbacks(binding) == []

    def test_callback_inside_window_matches(self) -> None:
        collab, clock = _collab()
        binding = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        assert binding is not None
        clock.advance(2.0)
        collab.record_callback(binding.token, seen_at=clock.now)
        assert len(collab.poll_callbacks(binding)) == 1

    def test_callback_after_window_never_matches(self) -> None:
        collab, clock = _collab()
        binding = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        assert binding is not None
        clock.advance(DEFAULT_EVIDENCE_WINDOW_SECONDS + 1.0)
        collab.record_callback(binding.token, seen_at=clock.now)
        assert collab.poll_callbacks(binding) == []

    def test_window_override_is_honored(self) -> None:
        collab, clock = _collab()
        binding = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        assert binding is not None
        clock.advance(30.0)
        collab.record_callback(binding.token, seen_at=clock.now)
        assert collab.poll_callbacks(binding, window_seconds=5.0) == []
        assert len(collab.poll_callbacks(binding, window_seconds=60.0)) == 1

    def test_prune_enforces_ttl(self) -> None:
        collab, clock = _collab()
        binding = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        assert binding is not None
        collab.record_callback(binding.token, seen_at=clock.now)
        clock.advance(DEFAULT_CALLBACK_TTL_SECONDS + 1)
        removed = collab.prune_callbacks()
        assert removed == 1
        assert collab.poll_callbacks(binding, window_seconds=10**9) == []


# --------------------------------------------------------------------------
# Persistence: memory/db.py OOB tables via DatabaseOOBStore
# --------------------------------------------------------------------------


class TestDatabaseStoreRoundTrip:
    @pytest.fixture()
    def db(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.delenv("WEBPENT_DATABASE_URL", raising=False)
        from webpent.memory.db import DatabaseManager

        manager = DatabaseManager(f"sqlite:///{tmp_path}/oob_test.db")
        manager.init_db()
        return manager

    def test_binding_and_callback_round_trip(self, db) -> None:
        collab = OOBCollaborator(
            base_domain="oob.example.com",
            store=DatabaseOOBStore(db),
            now=_FakeClock(),
        )
        binding = collab.register_probe(engagement_id="e1", vuln_class="sqli")
        assert binding is not None
        assert collab.record_callback(binding.token, protocol="http", source_ip="10.0.0.1") is True
        callbacks = collab.poll_callbacks(binding)
        assert len(callbacks) == 1
        assert callbacks[0].token == binding.token
        # A second process reading the same DB sees the binding (the
        # fail-closed identity check survives restarts).
        collab2 = OOBCollaborator(
            base_domain="oob.example.com", store=DatabaseOOBStore(db)
        )
        assert collab2.record_callback(binding.token) is True

    def test_unknown_token_dropped_in_db_store(self, db) -> None:
        store = DatabaseOOBStore(db)
        collab = OOBCollaborator(
            base_domain="oob.example.com", store=store, now=_FakeClock()
        )
        assert collab.record_callback("a" * 32) is False

    def test_prune_removes_expired_rows_only(self, db) -> None:
        clock = _FakeClock()
        store = DatabaseOOBStore(db)
        collab = OOBCollaborator(base_domain="oob.example.com", store=store, now=clock)
        b1 = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        clock.advance(1.0)
        b2 = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        assert b1 is not None and b2 is not None
        collab.record_callback(b1.token, seen_at=clock.now)
        clock.advance(2.0)
        collab.record_callback(b2.token, seen_at=clock.now)
        clock.advance(DEFAULT_CALLBACK_TTL_SECONDS + 5)
        # b2 gets a fresh callback at the new "now": only b1's is expired.
        collab.record_callback(b2.token, seen_at=clock.now)
        removed = collab.prune_callbacks()
        # Two expired rows (b1's and b2's first callback) are gone;
        # b2's fresh callback survives.
        assert removed == 2
        remaining = store.callbacks_for_token(b2.token)
        assert len(remaining) == 1


# --------------------------------------------------------------------------
# Canonical validator
# --------------------------------------------------------------------------


class TestBlindOOBValidator:
    def test_family_contract_rejects_missing_evidence(self) -> None:
        from webpent.production.oob_validator import validate_blind_ssrf

        with pytest.raises(ValidatorError):
            validate_blind_ssrf(baseline=None, candidate=None, negative_control=None)

    def test_confirmed_on_token_match_with_silent_control(self) -> None:
        token = "1" * 32
        result = run_validator(
            "BLIND_SSRF",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/f", "oob_token": token,
                       "oob_registered_at": 1000.0},
            negative_control={"url": "http://lab.local/c", "oob_token": "2" * 32},
            oob_callbacks=[_cb(token, 1002.0)],
        )
        assert result.outcome is ValidationOutcome.CONFIRMED
        assert result.evidence_quality.name == "OBSERVED_DIFFERENTIAL"

    def test_no_callback_is_refuted_not_inconclusive(self) -> None:
        result = run_validator(
            "BLIND_SSRF",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/f", "oob_token": "1" * 32,
                       "oob_registered_at": 1000.0},
            negative_control={"url": "http://lab.local/c", "oob_token": "2" * 32},
            oob_callbacks=[],
        )
        assert result.outcome is ValidationOutcome.REFUTED
        assert result.refutation_path == "no_oob_callback"

    def test_control_callback_fires_refutes_fail_closed(self) -> None:
        result = run_validator(
            "BLIND_SSRF",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/f", "oob_token": "1" * 32,
                       "oob_registered_at": 1000.0},
            negative_control={"url": "http://lab.local/c", "oob_token": "2" * 32},
            oob_callbacks=[_cb("2" * 32, 1001.0)],
        )
        assert result.outcome is ValidationOutcome.REFUTED
        assert result.refutation_path == "control_callback_fired"

    def test_mismatched_token_never_confirms(self) -> None:
        result = run_validator(
            "XXE_OOB",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/f", "oob_token": "1" * 32,
                       "oob_registered_at": 1000.0},
            negative_control={"url": "http://lab.local/c"},
            oob_callbacks=[_cb("9" * 32, 1002.0), _cb("a" * 32, 1003.0)],
        )
        assert result.outcome is ValidationOutcome.REFUTED

    def test_no_oob_token_is_refuted(self) -> None:
        result = run_validator(
            "BLIND_SQLI",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/f"},
            negative_control={"url": "http://lab.local/c"},
            oob_callbacks=[_cb("1" * 32, 1002.0)],
        )
        assert result.outcome is ValidationOutcome.REFUTED
        assert result.refutation_path == "no_oob_token"

    def test_callback_before_registered_at_excluded(self) -> None:
        token = "1" * 32
        result = run_validator(
            "BLIND_SSRF",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/f", "oob_token": token,
                       "oob_registered_at": 1000.0},
            negative_control={"url": "http://lab.local/c"},
            oob_callbacks=[_cb(token, 999.0)],
        )
        assert result.outcome is ValidationOutcome.REFUTED

    def test_collaborator_failure_is_inconclusive_not_halt(self) -> None:
        class BrokenCollaborator:
            def poll_callbacks(self, binding, *, window_seconds=None):
                raise RuntimeError("transport down")

        result = run_validator(
            "BLIND_SSRF",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/f", "oob_token": "1" * 32},
            negative_control={"url": "http://lab.local/c"},
            oob_collaborator=BrokenCollaborator(),
            oob_binding=object(),
        )
        assert result.outcome is ValidationOutcome.INCONCLUSIVE

    def test_live_mode_confirms_via_collaborator(self) -> None:
        collab, clock = _collab()
        binding = collab.register_probe(engagement_id="e1", vuln_class="ssrf")
        assert binding is not None
        clock.advance(2.0)
        collab.record_callback(binding.token, seen_at=clock.now)
        result = run_validator(
            "BLIND_SSRF",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/f", "oob_token": binding.token},
            negative_control={"url": "http://lab.local/c",
                              "oob_token": "2" * 32},
            oob_collaborator=collab,
            oob_binding=binding,
        )
        assert result.outcome is ValidationOutcome.CONFIRMED

    def test_control_silence_with_candidate_hit_is_required(self) -> None:
        # Control token ALSO fired: even a perfect candidate match
        # cannot confirm (callbacks are not differential on this host).
        token = "1" * 32
        result = run_validator(
            "BLIND_SSRF",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/f", "oob_token": token,
                       "oob_registered_at": 1000.0},
            negative_control={"url": "http://lab.local/c", "oob_token": "2" * 32},
            oob_callbacks=[_cb(token, 1002.0), _cb("2" * 32, 1003.0)],
        )
        assert result.outcome is ValidationOutcome.REFUTED
        assert result.refutation_path == "control_callback_fired"

    @pytest.mark.parametrize(
        "family,wrapper",
        [
            ("BLIND_SSRF", "validate_blind_ssrf"),
            ("XXE_OOB", "validate_xxe_oob"),
            ("BLIND_SQLI", "validate_blind_sqli"),
        ],
    )
    def test_registry_families_route_to_oob_authority(self, family, wrapper) -> None:
        assert family in VALIDATORS
        from webpent.production import oob_validator as ov

        assert getattr(ov, wrapper) is not None
        token = "3" * 32
        result = run_validator(
            family,
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/f", "oob_token": token,
                       "oob_registered_at": 1000.0},
            negative_control={"url": "http://lab.local/c"},
            oob_callbacks=[_cb(token, 1001.0)],
        )
        assert result.vulnerability_class == family
        assert result.outcome is ValidationOutcome.CONFIRMED


# --------------------------------------------------------------------------
# Model layer
# --------------------------------------------------------------------------


class TestVulnClassAdditions:
    @pytest.mark.parametrize("member", ["BLIND_SSRF", "XXE_OOB", "BLIND_SQLI"])
    def test_members_exist(self, member: str) -> None:
        assert VulnClass[member] is not None

    @pytest.mark.parametrize("member", ["BLIND_SSRF", "XXE_OOB", "BLIND_SQLI"])
    def test_blind_families_are_never_exploitable_class(self, member: str) -> None:
        # Confirmation is callback differential, not payload-injection
        # exploitation; these must not route into the exploit path.
        assert VulnClass[member].value not in EXPLOITABLE_CLASSES


# --------------------------------------------------------------------------
# Payload-generator injection point
# --------------------------------------------------------------------------


class TestAttachOOBProbes:
    def test_empty_domain_is_full_passthrough(self) -> None:
        finding = _finding("ssrf")
        updated, payloads = attach_oob_probes(
            [finding], base_domain="", engagement_id="e1"
        )
        assert updated == [finding]
        assert payloads == {}
        assert (finding.evidence or {}).get("oob_token") is None

    def test_flag_on_stamps_blind_families_and_bounds_payloads(self) -> None:
        findings = [_finding(c) for c in ("ssrf", "xxe", "sqli")]
        updated, payloads = attach_oob_probes(
            findings, base_domain="oob.example.com", engagement_id="e1"
        )
        assert len(payloads) == 3
        for original, stamped in zip(findings, updated):
            evidence = stamped.evidence
            assert len(evidence["oob_token"]) == 32
            assert evidence["oob_host"].endswith(".e1.oob.example.com")
            assert "oob_registered_at" in evidence
            assert stamped is not original  # model_copy, not in-place
        assert len(payloads[str(updated[0].id)]) == 2  # http + https probe
        assert all("oob.example.com" in p for p in payloads[str(updated[0].id)])
        # Bounded probe shapes per family.
        assert len(payloads[str(updated[1].id)]) == 1  # single XXE doc
        assert len(payloads[str(updated[2].id)]) == 2  # MSSQL + MySQL markers

    def test_non_oob_and_stamped_findings_untouched(self) -> None:
        stamped = _finding("ssrf", evidence={"oob_token": "z" * 32})
        other = _finding("xss")
        updated, payloads = attach_oob_probes(
            [stamped, other], base_domain="oob.example.com", engagement_id="e1"
        )
        assert payloads == {}
        assert (updated[0].evidence or {})["oob_token"] == "z" * 32
        assert (updated[1].evidence or {}).get("oob_token") is None

    def test_payload_generator_flag_off_is_byte_identical(self, monkeypatch) -> None:
        from webpent.agents.payload_generator.agent import payload_generator_node
        from webpent.state.initial_state import build_initial_state
        from webpent.models.targets import Target

        settings = Settings()
        assert settings.enable_oob_collaboration is False  # default off
        assert settings.oob_collaborator_domain == ""

        monkeypatch.setattr(
            "webpent.agents.payload_generator.agent._generate_payloads_for_finding",
            lambda finding, llm: ([], None),
        )
        finding = _finding("ssrf")
        state = build_initial_state(
            target=Target(url="http://lab.local"), thread_id="t"
        )
        state["findings"] = [finding]
        update = payload_generator_node(state)
        stamped = next(f for f in update["findings"] if f.id == finding.id)
        assert (stamped.evidence or {}).get("oob_token") is None
        assert str(finding.id) not in update["payloads_to_test"]

    def test_payload_generator_flag_on_stamps_probe(self, monkeypatch) -> None:
        from webpent.agents.payload_generator.agent import payload_generator_node
        from webpent.state.initial_state import build_initial_state
        from webpent.models.targets import Target

        settings = Settings(
            enable_oob_collaboration=True,
            oob_collaborator_domain="oob.example.com",
        )
        with activate_settings(settings):
            monkeypatch.setattr(
                "webpent.agents.payload_generator.agent._generate_payloads_for_finding",
                lambda finding, llm: ([], None),
            )
            finding = _finding("ssrf")
            state = build_initial_state(
                target=Target(url="http://lab.local"), thread_id="t"
            )
            state["findings"] = [finding]
            update = payload_generator_node(state)

        stamped = next(f for f in update["findings"] if f.id == finding.id)
        assert len(stamped.evidence.get("oob_token", "")) == 32
        assert stamped.evidence["oob_host"].endswith(".t.oob.example.com")
        probes = update["payloads_to_test"].get(str(finding.id), [])
        assert probes, "flag-on pass must append the bounded OOB probes"
        assert all(stamped.evidence["oob_host"] in p for p in probes)


# --------------------------------------------------------------------------
# End-to-end: accelerated-pulse blind-SSRF scenario set
# --------------------------------------------------------------------------


class TestBlindSSRFEndToEnd:
    """Proposal success criterion: real blind-SSRF confirmation flow.

    The "server" is simulated by an accelerated pulse on the injected
    clock; the callback store is in-memory; the validator is the
    canonical registry entry (run_validator), not a bypass.
    """

    def _probe(self, collab: OOBCollaborator) -> Any:
        binding = collab.register_probe(
            engagement_id="engagement-e2e", vuln_class="ssrf"
        )
        assert binding is not None
        return binding

    def test_confirmed_via_registry_on_matching_callback(self) -> None:
        collab, clock = _collab()
        binding = self._probe(collab)
        # Candidate payload fires server-side at t+3 (pulse).
        clock.advance(3.0)
        collab.record_callback(binding.token, protocol="http", source_ip="10.1.1.5")
        result = run_validator(
            "BLIND_SSRF",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/fetch", "oob_token": binding.token},
            negative_control={"url": "http://lab.local/fetch",
                              "oob_token": "c" * 32},
            oob_collaborator=collab,
            oob_binding=binding,
        )
        assert result.outcome is ValidationOutcome.CONFIRMED
        assert result.evidence_quality.name == "OBSERVED_DIFFERENTIAL"

    def test_refuted_when_no_callback_arrives(self) -> None:
        collab, clock = _collab()
        binding = self._probe(collab)
        clock.advance(5.0)  # pulse, but nothing phones home
        result = run_validator(
            "BLIND_SSRF",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/fetch", "oob_token": binding.token},
            negative_control={"url": "http://lab.local/fetch",
                              "oob_token": "c" * 32},
            oob_collaborator=collab,
            oob_binding=binding,
        )
        assert result.outcome is ValidationOutcome.REFUTED
        assert result.refutation_path == "no_oob_callback"

    def test_refuted_when_control_fires(self) -> None:
        collab, clock = _collab()
        binding = self._probe(collab)
        # The CONTROL (same request shape, no triggering payload) is a
        # registered probe whose token ALSO phones home.
        control_binding = collab.register_probe(
            engagement_id="engagement-e2e", vuln_class="ssrf"
        )
        assert control_binding is not None
        clock.advance(2.0)
        collab.record_callback(control_binding.token, protocol="http")
        result = run_validator(
            "BLIND_SSRF",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/fetch", "oob_token": binding.token},
            negative_control={"url": "http://lab.local/fetch",
                              "oob_token": control_binding.token},
            oob_collaborator=collab,
            oob_binding=binding,
        )
        assert result.outcome is ValidationOutcome.REFUTED
        assert result.refutation_path == "control_callback_fired"

    def test_refuted_on_mismatched_token(self) -> None:
        collab, clock = _collab()
        binding = self._probe(collab)
        other = collab.register_probe(
            engagement_id="engagement-e2e", vuln_class="ssrf"
        )
        assert other is not None
        clock.advance(2.0)
        # A DIFFERENT probe's callback arrives (e.g. a concurrent scan).
        collab.record_callback(other.token, protocol="http")
        result = run_validator(
            "BLIND_SSRF",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/fetch", "oob_token": binding.token},
            negative_control={"url": "http://lab.local/fetch",
                              "oob_token": "c" * 32},
            oob_collaborator=collab,
            oob_binding=binding,
        )
        assert result.outcome is ValidationOutcome.REFUTED

    def test_inconclusive_on_transport_failure_not_halt(self) -> None:
        collab, clock = _collab()
        binding = self._probe(collab)

        class BrokenStore(MemoryOOBStore):
            def callbacks_for_token(self, token: str):
                raise RuntimeError("dns resolver unavailable")

        broken = OOBCollaborator(
            base_domain="oob.example.com", store=BrokenStore(), now=clock
        )
        result = run_validator(
            "BLIND_SSRF",
            baseline={"url": "http://lab.local/"},
            candidate={"url": "http://lab.local/fetch", "oob_token": binding.token},
            negative_control={"url": "http://lab.local/fetch",
                              "oob_token": "c" * 32},
            oob_collaborator=broken,
            oob_binding=binding,
        )
        assert result.outcome is ValidationOutcome.INCONCLUSIVE

    def test_probe_payloads_embed_the_token_host(self) -> None:
        collab, _ = _collab()
        binding = self._probe(collab)
        probes = oob_probe_payloads(binding)
        assert all(binding.host in p for p in probes)
        assert len(probes) == 2  # ssrf: http + https

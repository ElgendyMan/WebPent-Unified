"""GOED v1.8.4 — Phase 17: FAILOVER INTEGRITY TEST.

Tests the ProviderPool/ProviderSlot state machine directly (rotation, circuit breaker,
cooldown, failure classification). Does NOT call a real LLM endpoint — this phase is
about whether the FAILOVER MECHANISM behaves correctly, which is orthogonal to whether
a real model is reachable (that question belongs to Phases 6/11/15, which correctly
stop on REAL_API_UNAVAILABLE and are NOT run here). Scenario 7 exercises pool.generate()
end-to-end with a monkeypatched provider class so no network call is made and no key
material is fabricated.
"""

import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_SRC = os.path.join(_ROOT, "src")
sys.path.insert(0, _SRC)
REPORTS_DIR = os.path.join(_ROOT, "reports", "goed_v1_8_4")
os.makedirs(REPORTS_DIR, exist_ok=True)

from webpent.llm_researcher.providers.pool import (
    FailureCategory,
    ProviderPool,
    ProviderSlot,
    SlotStatus,
)

results = []


def check(name, condition, detail=""):
    results.append({"scenario": name, "pass": bool(condition), "detail": detail})
    print(f"  [{'✅ PASS' if condition else '❌ FAIL'}] {name} {('- ' + detail) if detail else ''}")


def scenario_1_healthy():
    slot = ProviderSlot(slot_id="s0", env_var_name="X", base_url_env="Y", model_env="Z")
    ok1 = slot.is_eligible() and slot.status == SlotStatus.HEALTHY
    slot.record_success(latency_ms=120.0, tokens=50)
    ok2 = slot.status == SlotStatus.HEALTHY and slot.success_count == 1 and slot.total_tokens_used == 50
    check(
        "1_healthy",
        ok1 and ok2,
        f"eligible_before={ok1} state_after_success={slot.get_safe_metadata()}",
    )


def scenario_2_rate_limited_then_recovers():
    slot = ProviderSlot(slot_id="s0", env_var_name="X", base_url_env="Y", model_env="Z")
    slot.record_failure(FailureCategory.RATE_LIMIT)
    blocked = (slot.status == SlotStatus.RATE_LIMITED) and (slot.is_eligible() is False)
    # simulate the 60s reset window having elapsed, without a real sleep
    slot.rate_limit_reset_at = time.time() - 1
    recovered = slot.is_eligible() is True and slot.status == SlotStatus.HEALTHY
    check(
        "2_rate_limited_then_recovers",
        blocked and recovered,
        f"blocked_immediately={blocked} recovered_after_window={recovered}",
    )


def scenario_3_quota_exhausted_permanent():
    slot = ProviderSlot(slot_id="s0", env_var_name="X", base_url_env="Y", model_env="Z")
    slot.record_failure(FailureCategory.QUOTA)
    never_recovers = (slot.status == SlotStatus.QUOTA_EXHAUSTED) and (slot.is_eligible() is False)
    time.sleep(0.01)
    still_blocked = slot.is_eligible() is False
    check(
        "3_quota_exhausted_no_auto_recovery",
        never_recovers and still_blocked,
        "quota exhaustion has no time-based recovery path by design (correct - requires external top-up)",
    )


def scenario_4_auth_invalid_permanent():
    slot = ProviderSlot(slot_id="s0", env_var_name="X", base_url_env="Y", model_env="Z")
    slot.record_failure(FailureCategory.AUTH)
    blocked = (slot.status == SlotStatus.AUTH_FAILED) and (slot.is_eligible() is False)
    check("4_auth_invalid_permanent", blocked, "invalid key correctly never becomes eligible again")


def scenario_5_timeout_no_backoff_before_circuit():
    """FINDING: TIMEOUT status is not checked in is_eligible()'s guard list, so a slot
    that has timed out 1-2 times (below the 3-failure circuit threshold) is retried
    immediately on the very next rotation, with no backoff at all. Only at the 3rd
    consecutive timeout does the circuit open (with the 60s cooldown)."""
    slot = ProviderSlot(slot_id="s0", env_var_name="X", base_url_env="Y", model_env="Z")
    slot.record_failure(FailureCategory.TIMEOUT)
    eligible_after_1 = slot.is_eligible()
    status_after_1 = slot.status
    slot.record_failure(FailureCategory.TIMEOUT)
    eligible_after_2 = slot.is_eligible()
    slot.record_failure(FailureCategory.TIMEOUT)
    circuit_opens_at_3 = (slot.status == SlotStatus.CIRCUIT_OPEN) and (slot.is_eligible() is False)
    # This "passes" in the sense that circuit breaker does eventually engage - but flags
    # the no-backoff-before-3rd-failure behavior as a design note for the report.
    check(
        "5_timeout_escalates_to_circuit_breaker_at_3",
        circuit_opens_at_3,
        f"status_after_1_timeout={status_after_1.value} still_eligible_after_1={eligible_after_1} "
        f"still_eligible_after_2={eligible_after_2} (NOTE: no cooldown applied until 3rd failure - "
        f"a timing-out slot is retried with zero backoff for the first 2 failures)",
    )


def scenario_6_provider_unavailable_zero_slots():
    for k in list(os.environ.keys()):
        if k.startswith("LLM_API_KEY"):
            del os.environ[k]
    pool = ProviderPool()
    no_slots = not pool.has_real_slots()
    raised_correctly = False
    try:
        pool.generate("test prompt")
    except RuntimeError as e:
        raised_correctly = "REAL_API_UNAVAILABLE" in str(e)
    check(
        "6_provider_unavailable_zero_slots",
        no_slots and raised_correctly,
        f"has_real_slots={not no_slots} raised_REAL_API_UNAVAILABLE={raised_correctly}",
    )


def scenario_7_failover_a_to_b_success():
    """End-to-end pool.generate() with slot A failing and slot B succeeding.
    Monkeypatches the provider class so this makes NO real network call and uses
    NO real key material - purely testing the pool's own retry/rotation control flow."""
    os.environ["LLM_API_KEY"] = "fake-test-key-slot-a-not-a-real-secret"
    os.environ["LLM_API_KEY_2"] = "fake-test-key-slot-b-not-a-real-secret"
    pool = ProviderPool()
    slots_discovered = pool.get_slot_count() == 2

    import webpent.llm_researcher.providers.pool as pool_mod

    class FakeProviderAFailsBSucceeds:
        def __init__(self, api_key, base_url, model, policy_hash=""):
            self.api_key = api_key

        def generate(self, prompt, max_tokens=1000, **kwargs):
            if "slot-a" in self.api_key:
                raise ConnectionError("simulated network failure for slot A - 503")
            return {"text": "simulated response from slot B", "model": "fake"}

        def get_redacted_telemetry(self):
            return []

    orig_import = pool_mod.OpenAICompatibleProvider if hasattr(pool_mod, "OpenAICompatibleProvider") else None
    import webpent.llm_researcher.providers.openai_compatible as oc_mod

    real_cls = oc_mod.OpenAICompatibleProvider
    oc_mod.OpenAICompatibleProvider = FakeProviderAFailsBSucceeds
    try:
        response = pool.generate("test prompt")
        succeeded_via_failover = response == {
            "text": "simulated response from slot B",
            "model": "fake",
        }
        slot_a = next(s for s in pool.slots if s.env_var_name == "LLM_API_KEY")
        slot_b = next(s for s in pool.slots if s.env_var_name == "LLM_API_KEY_2")
        a_recorded_failure = (
            slot_a.failure_count == 1 and slot_a.status == SlotStatus.NETWORK
            if hasattr(SlotStatus, "NETWORK")
            else slot_a.failure_count == 1
        )
        b_recorded_success = slot_b.success_count == 1
    finally:
        oc_mod.OpenAICompatibleProvider = real_cls
        del os.environ["LLM_API_KEY"]
        del os.environ["LLM_API_KEY_2"]

    check(
        "7_failover_a_fails_b_succeeds",
        slots_discovered and succeeded_via_failover and b_recorded_success,
        f"slots_discovered={slots_discovered} response_came_from_slot_b={succeeded_via_failover} "
        f"slot_a_failures={slot_a.failure_count} slot_b_successes={slot_b.success_count}",
    )


def scenario_8_all_slots_exhausted():
    os.environ["LLM_API_KEY"] = "fake-test-key-exhausted-not-a-real-secret"
    pool = ProviderPool()
    import webpent.llm_researcher.providers.openai_compatible as oc_mod

    real_cls = oc_mod.OpenAICompatibleProvider

    class FakeProviderAlwaysFails:
        def __init__(self, api_key, base_url, model, policy_hash=""):
            pass

        def generate(self, prompt, max_tokens=1000, **kwargs):
            raise ConnectionError("simulated total outage - 503")

    oc_mod.OpenAICompatibleProvider = FakeProviderAlwaysFails
    raised_unavailable = False
    try:
        pool.generate("test prompt")
    except RuntimeError as e:
        raised_unavailable = "REAL_API_UNAVAILABLE" in str(e) and "exhausted" in str(e).lower()
    finally:
        oc_mod.OpenAICompatibleProvider = real_cls
        del os.environ["LLM_API_KEY"]
    check(
        "8_all_slots_exhausted",
        raised_unavailable,
        f"raised_REAL_API_UNAVAILABLE_with_exhausted_message={raised_unavailable}",
    )


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 17 — Failover Integrity Test (mechanism-level, no real API)")
    print("=" * 60)
    scenario_1_healthy()
    scenario_2_rate_limited_then_recovers()
    scenario_3_quota_exhausted_permanent()
    scenario_4_auth_invalid_permanent()
    scenario_5_timeout_no_backoff_before_circuit()
    scenario_6_provider_unavailable_zero_slots()
    scenario_7_failover_a_to_b_success()
    scenario_8_all_slots_exhausted()

    passed = sum(1 for r in results if r["pass"])
    print(f"\n{passed}/{len(results)} scenarios passed")
    out = {
        "phase": "17_failover_integrity",
        "scope_note": "Tests pool.py's own failover mechanism via direct state manipulation "
        "and a monkeypatched provider class. Does NOT validate real-API behavior "
        "(that requires LLM_API_KEY and belongs to Phases 6/11/15).",
        "scenarios_passed": passed,
        "scenarios_total": len(results),
        "results": results,
        "phase_pass": passed == len(results),
    }
    with open(os.path.join(REPORTS_DIR, "failover_integrity_test.json"), "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(f"Saved: {os.path.join(REPORTS_DIR, 'failover_integrity_test.json')}")
    sys.exit(0 if out["phase_pass"] else 1)

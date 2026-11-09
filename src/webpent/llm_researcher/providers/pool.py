"""
Provider Pool / Router for GOED v1.8.4.

Architecture:
    LLM Request -> Provider Pool / Router -> Key A/B/C -> Health/Quota/Circuit Breaker
    -> REAL API OK -> Continue research
    -> REAL API FAIL -> Retry/rotate -> Key next / Provider next -> all exhausted -> SAFE DEFER/STOP

NEVER silently downgrades to Mock. Returns REAL_API_UNAVAILABLE when all real slots exhausted.
"""

import logging
import os
import threading
import time
import warnings
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class SlotStatus(Enum):
    HEALTHY = "healthy"
    RATE_LIMITED = "rate_limited"
    QUOTA_EXHAUSTED = "quota_exhausted"
    AUTH_FAILED = "auth_failed"
    TIMEOUT = "timeout"
    CIRCUIT_OPEN = "circuit_open"


class FailureCategory(Enum):
    TRANSIENT = "transient"
    RATE_LIMIT = "rate_limit"
    QUOTA = "quota"
    AUTH = "auth"
    TIMEOUT = "timeout"
    NETWORK = "network"


@dataclass
class ProviderSlot:
    """A single API key slot with health tracking."""
    slot_id: str
    env_var_name: str
    base_url_env: str
    model_env: str
    status: SlotStatus = SlotStatus.HEALTHY
    request_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    failure_category: FailureCategory | None = None
    circuit_opened_at: float | None = None
    cooldown_seconds: float = 60.0
    rate_limit_reset_at: float | None = None
    last_latency_ms: float | None = None
    total_tokens_used: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def is_eligible(self) -> bool:
        with self._lock:
            if self.status == SlotStatus.CIRCUIT_OPEN:
                if self.circuit_opened_at and (time.time() - self.circuit_opened_at) > self.cooldown_seconds:
                    self.status = SlotStatus.HEALTHY
                    return True
                return False
            if self.status == SlotStatus.RATE_LIMITED:
                if self.rate_limit_reset_at and time.time() > self.rate_limit_reset_at:
                    self.status = SlotStatus.HEALTHY
                    return True
                return False
            return self.status not in (SlotStatus.QUOTA_EXHAUSTED, SlotStatus.AUTH_FAILED)

    def record_success(self, latency_ms: float, tokens: int = 0):
        with self._lock:
            self.status = SlotStatus.HEALTHY
            self.request_count += 1
            self.success_count += 1
            self.last_latency_ms = latency_ms
            self.total_tokens_used += tokens
            self.failure_category = None

    def record_failure(self, category: FailureCategory):
        with self._lock:
            self.request_count += 1
            self.failure_count += 1
            self.failure_category = category
            if category == FailureCategory.QUOTA:
                self.status = SlotStatus.QUOTA_EXHAUSTED
            elif category == FailureCategory.AUTH:
                self.status = SlotStatus.AUTH_FAILED
            elif category == FailureCategory.RATE_LIMIT:
                self.status = SlotStatus.RATE_LIMITED
                self.rate_limit_reset_at = time.time() + 60.0
            elif category in (FailureCategory.TIMEOUT, FailureCategory.NETWORK, FailureCategory.TRANSIENT):
                self.status = SlotStatus.TIMEOUT
                if self.failure_count >= 3:
                    self.status = SlotStatus.CIRCUIT_OPEN
                    self.circuit_opened_at = time.time()

    def get_api_key(self) -> str | None:
        return os.environ.get(self.env_var_name)

    def get_safe_metadata(self) -> dict[str, Any]:
        key = self.get_api_key()
        prefix = (key[:4] + "...") if key else None
        return {
            "slot_id": self.slot_id,
            "status": self.status.value,
            "request_count": self.request_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "failure_category": self.failure_category.value if self.failure_category else None,
            "last_latency_ms": self.last_latency_ms,
            "total_tokens_used": self.total_tokens_used,
            "api_key_prefix": prefix,
            "has_key": bool(key),
        }


class ProviderPool:
    """Manages multiple API key slots with health tracking, rotation, and circuit breaking.
    NEVER silently downgrades to Mock. Returns REAL_API_UNAVAILABLE when all real slots exhausted.
    """

    def __init__(self, policy_hash: str = ""):
        self.policy_hash = policy_hash
        self.slots: list[ProviderSlot] = []
        self._current_idx = 0
        self._lock = threading.Lock()
        self._discover_slots()

    def _discover_slots(self):
        # Primary: LLM_API_KEY (slot 0)
        if os.environ.get("LLM_API_KEY"):
            self.slots.append(ProviderSlot(
                slot_id="slot_0",
                env_var_name="LLM_API_KEY",
                base_url_env="LLM_BASE_URL",
                model_env="LLM_MODEL",
            ))
        # Additional: LLM_API_KEY_2, LLM_API_KEY_3, ...
        i = 2
        while True:
            key_var = f"LLM_API_KEY_{i}"
            if os.environ.get(key_var):
                self.slots.append(ProviderSlot(
                    slot_id=f"slot_{i-1}",
                    env_var_name=key_var,
                    base_url_env=f"LLM_BASE_URL_{i}",
                    model_env=f"LLM_MODEL_{i}",
                ))
                i += 1
            else:
                break

    def has_real_slots(self) -> bool:
        return len(self.slots) > 0

    def get_slot_count(self) -> int:
        return len(self.slots)

    def get_eligible_slot(self) -> ProviderSlot | None:
        with self._lock:
            if not self.slots:
                return None
            for attempt in range(len(self.slots)):
                idx = (self._current_idx + attempt) % len(self.slots)
                slot = self.slots[idx]
                if slot.is_eligible():
                    self._current_idx = (idx + 1) % len(self.slots)
                    return slot
            return None

    def _classify_error(self, e: Exception) -> FailureCategory:
        msg = str(e).lower()
        if any(k in msg for k in ["auth", "unauthorized", "401", "403", "invalid key", "api key"]):
            return FailureCategory.AUTH
        if any(k in msg for k in ["rate limit", "429", "too many requests"]):
            return FailureCategory.RATE_LIMIT
        if any(k in msg for k in ["quota", "exceeded", "billing", "insufficient"]):
            return FailureCategory.QUOTA
        if any(k in msg for k in ["timeout", "timed out", "504"]):
            return FailureCategory.TIMEOUT
        if any(k in msg for k in ["connection", "network", "dns", "502", "503"]):
            return FailureCategory.NETWORK
        return FailureCategory.TRANSIENT

    def generate(self, prompt: str, max_tokens: int = 1000, **kwargs) -> Any:
        """Generate with failover across slots. Raises RuntimeError('REAL_API_UNAVAILABLE')."""
        if not self.has_real_slots():
            raise RuntimeError("REAL_API_UNAVAILABLE: No LLM_API_KEY slots configured")

        attempted_slots = set()
        last_error = None

        for _rotation in range(len(self.slots) * 2):
            slot = self.get_eligible_slot()
            if slot is None:
                raise RuntimeError(
                    f"REAL_API_UNAVAILABLE: All {len(self.slots)} slots exhausted. "
                    f"Last error: {last_error}"
                )

            try:
                attempted_slots.add(slot.slot_id)
                key = slot.get_api_key()
                if not key:
                    slot.record_failure(FailureCategory.AUTH)
                    continue

                base_url = os.environ.get(slot.base_url_env) or os.environ.get("LLM_BASE_URL")
                model = os.environ.get(slot.model_env) or os.environ.get("LLM_MODEL", "gpt-4o-mini")

                from .openai_compatible import OpenAICompatibleProvider
                # F-02 (0.33.0): the old call passed api_key=/base_url=/
                # policy_hash= which do NOT exist on OpenAICompatibleProvider
                # — every generate() raised TypeError, the bare except below
                # rotated every slot into failure, and the pool died with
                # REAL_API_UNAVAILABLE even with valid keys. The provider now
                # accepts explicit overrides; env-var names stay pinned to
                # the slot so per-slot credential isolation is preserved.
                provider = OpenAICompatibleProvider(
                    model=model,
                    prompt_version_hash=self.policy_hash,
                    api_key_env=slot.env_var_name,
                    base_url_env=slot.base_url_env,
                    api_key=key,
                    base_url=base_url,
                )

                t0 = time.time()
                try:
                    response = provider.generate(prompt, max_tokens=max_tokens, **kwargs)
                    latency_ms = (time.time() - t0) * 1000

                    tokens = 0
                    try:
                        telemetry = provider.get_redacted_telemetry()
                        if telemetry:
                            tokens = telemetry[-1].get("tokens_used", 0) if telemetry else 0
                    except Exception:
                        pass

                    # F-02 (0.33.0) honest failure: BaseLLMProvider.generate
                    # returns an error-carrying LLMResponse instead of raising,
                    # so without this branch a failing API call was recorded as
                    # slot SUCCESS and returned to the caller as if it worked.
                    error_text = getattr(response, "error", None)
                    if error_text:
                        last_error = str(error_text)[:200]
                        if "HTTP_401" in last_error or "HTTP_403" in last_error:
                            slot.record_failure(FailureCategory.AUTH)
                        elif "HTTP_429" in last_error:
                            slot.record_failure(FailureCategory.RATE_LIMIT)
                        else:
                            slot.record_failure(FailureCategory.TRANSIENT)
                        continue

                    slot.record_success(latency_ms, tokens)
                    return response
                finally:
                    # F-03 (0.33.0): one provider is built per call — close its
                    # httpx client or the connection pool leaks per request.
                    provider.close()

            except Exception as e:
                last_error = str(e)[:200]
                category = self._classify_error(e)
                slot.record_failure(category)
                continue

        raise RuntimeError(
            f"REAL_API_UNAVAILABLE: All real provider slots exhausted after "
            f"{len(attempted_slots)} slots attempted. Last error: {last_error}"
        )

    def get_pool_status(self) -> dict[str, Any]:
        return {
            "slot_count": len(self.slots),
            "has_real_slots": self.has_real_slots(),
            "healthy_slots": sum(1 for s in self.slots if s.status == SlotStatus.HEALTHY),
            "slots": [s.get_safe_metadata() for s in self.slots],
            "current_index": self._current_idx,
        }

    def get_provider_metadata(self) -> dict[str, Any]:
        status = self.get_pool_status()
        return {
            "provider_type": "REAL_API_POOL",
            "mock_provider": False,
            "slot_count": status["slot_count"],
            "healthy_slots": status["healthy_slots"],
            "slots": status["slots"],
            "policy_hash": self.policy_hash,
        }


class LLMRouter:
    """High-level router. Single entry point for ALL LLM calls in v1.8.4.
    Uses ProviderPool for real API. Falls back to mock ONLY when ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION=true.
    """

    def __init__(self, policy_hash: str = ""):
        self.policy_hash = policy_hash
        self.pool = ProviderPool(policy_hash=policy_hash)
        self._allow_mock = os.environ.get("ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION", "").lower() == "true"
        self._mock_provider = None
        self._last_provider_type = None

    def generate(self, prompt: str, max_tokens: int = 1000, **kwargs) -> Any:
        if self.pool.has_real_slots():
            try:
                result = self.pool.generate(prompt, max_tokens=max_tokens, **kwargs)
                self._last_provider_type = "REAL_API"
                return result
            except RuntimeError as e:
                if "REAL_API_UNAVAILABLE" in str(e):
                    self._last_provider_type = "REAL_API_UNAVAILABLE"
                    if self._allow_mock:
                        warnings.warn(
                            "ALL REAL_API_SLOTS_EXHAUSTED. Falling back to MOCK. "
                            "Engineering verification mode only.", stacklevel=2
                        )
                        from .mock_provider import MockLLMProvider
                        if self._mock_provider is None:
                            self._mock_provider = MockLLMProvider()
                        self._last_provider_type = "MOCK_SIMULATION_FALLBACK"
                        return self._mock_provider.generate(prompt, max_tokens=max_tokens, **kwargs)
                    raise
                raise
        else:
            if self._allow_mock:
                warnings.warn("No real API slots configured. Using MOCK (engineering mode).", stacklevel=2)
                from .mock_provider import MockLLMProvider
                if self._mock_provider is None:
                    self._mock_provider = MockLLMProvider()
                self._last_provider_type = "MOCK_SIMULATION"
                return self._mock_provider.generate(prompt, max_tokens=max_tokens, **kwargs)
            raise RuntimeError("REAL_API_UNAVAILABLE: No LLM_API_KEY configured and mock fallback disabled")

    def get_status(self) -> dict[str, Any]:
        ps = self.pool.get_pool_status()
        ps.update({
            "allow_mock": self._allow_mock,
            "last_provider_type": self._last_provider_type,
        })
        return ps

    def get_provider_metadata(self) -> dict[str, Any]:
        if self._last_provider_type and "MOCK" in self._last_provider_type:
            from .mock_provider import MockLLMProvider
            m = MockLLMProvider().get_provider_metadata()
            m["fallback_note"] = "Mock used as fallback - NOT real API validation"
            return m
        return self.pool.get_provider_metadata()

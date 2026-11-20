"""Provider factory — keeps security core provider-neutral.
STRICT RUNTIME GATE (v1.8.3):
- LLM_PROVIDER=openai_compatible WITHOUT LLM_API_KEY → RuntimeError("REAL_API_UNAVAILABLE")
- NO silent downgrade to Mock
- Optional ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION=true permits mock fallback
  with EXPLICIT warning that it is NOT real API.
"""
import os
import warnings
from typing import Any

from .base import BaseLLMProvider

_PROVIDER_RUNTIME_GATE_STATUS = {
    "status": "NOT_CHECKED",
    "real_api_requested": False,
    "api_key_available": False,
    "engineering_verification_mode": False,
}


def get_provider(provider_type: str, model: str,
                 prompt_version_hash: str = "", **kwargs) -> BaseLLMProvider:
    pt = provider_type.lower()
    # B-4 (RA-3): per-call factory — no shared global state.
    global _PROVIDER_RUNTIME_GATE_STATUS
    gate_status = {"status": "NOT_CHECKED", "real_api_requested": False, "api_key_available": False, "engineering_verification_mode": False}

    if pt in ("openai", "openai_compatible"):
        gate_status["real_api_requested"] = True
        api_key = os.environ.get("LLM_API_KEY", "")

        if not api_key:
            eng_verify = os.environ.get("ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION", "").lower() == "true"
            gate_status["api_key_available"] = False

            if eng_verify:
                gate_status["engineering_verification_mode"] = True
                gate_status["status"] = "ENGINEERING_VERIFICATION_MOCK"
                warnings.warn(
                    "REAL_API_UNAVAILABLE: LLM_API_KEY not set. "
                    "Falling back to MockLLMProvider because ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION=true. "
                    "THIS IS NOT REAL API EXECUTION. Results are engineering verification only.",
                    RuntimeWarning, stacklevel=2
                )
                from .mock_provider import MockLLMProvider
                p = MockLLMProvider(model=model, prompt_version_hash=prompt_version_hash)
                p._provider_runtime_gate = gate_status.copy()
                return p
            else:
                gate_status["status"] = "REAL_API_UNAVAILABLE"
                _PROVIDER_RUNTIME_GATE_STATUS.clear()
                _PROVIDER_RUNTIME_GATE_STATUS.update(gate_status)
                raise RuntimeError(
                    "REAL_API_UNAVAILABLE: LLM_PROVIDER=openai_compatible requested but "
                    "LLM_API_KEY environment variable is not set. "
                    "Set LLM_API_KEY for real API execution, or set "
                    "ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION=true for engineering verification with Mock "
                    "(results will be explicitly labeled as non-real-API)."
                )

        gate_status["api_key_available"] = True
        gate_status["status"] = "REAL_API_CONFIGURED"
        from .openai_compatible import OpenAICompatibleProvider
        p = OpenAICompatibleProvider(model=model, prompt_version_hash=prompt_version_hash, **kwargs)
        p._provider_runtime_gate = gate_status.copy()
        return p

    if pt == "mock":
        gate_status["status"] = "MOCK_REQUESTED"
        from .mock_provider import MockLLMProvider
        p = MockLLMProvider(model=model, prompt_version_hash=prompt_version_hash, **kwargs)
        p._provider_runtime_gate = gate_status.copy()
        return p

    raise ValueError(f"Unknown provider: {provider_type}. Supported: mock, openai_compatible")




def get_provider_status() -> dict:
    """Return current provider status without creating a provider instance."""
    provider_name = os.environ.get("LLM_PROVIDER", "mock")
    allow_mock = os.environ.get("ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION", "").lower() == "true"
    has_key = bool(os.environ.get("LLM_API_KEY"))

    if provider_name == "mock":
        return {"mode": "MOCK_SIMULATION", "reason": "LLM_PROVIDER=mock explicitly set"}
    elif provider_name in ("openai_compatible", "openai"):
        if has_key:
            return {"mode": "REAL_API_AVAILABLE", "reason": "LLM_API_KEY present"}
        elif allow_mock:
            return {"mode": "MOCK_SIMULATION", "reason": "Engineering verification mode - ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION=true"}
        else:
            return {"mode": "REAL_API_UNAVAILABLE", "reason": "LLM_API_KEY not set and mock fallback disabled"}
    else:
        return {"mode": "UNKNOWN", "reason": f"Unknown provider: {provider_name}"}


def get_provider_from_env(prompt_version_hash: str = "") -> BaseLLMProvider:
    """Create from env: LLM_PROVIDER, LLM_MODEL."""
    provider_type = os.environ.get("LLM_PROVIDER", "mock")
    model = os.environ.get("LLM_MODEL", "mock-deterministic-v1")
    return get_provider(provider_type, model, prompt_version_hash)


def get_runtime_gate_status() -> dict[str, Any]:
    """Return the current provider runtime gate status."""
    return _PROVIDER_RUNTIME_GATE_STATUS.copy()

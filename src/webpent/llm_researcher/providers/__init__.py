from .pool import FailureCategory, LLMRouter, ProviderPool, ProviderSlot, SlotStatus

"""LLM Provider adapters — pluggable, provider-neutral security core.
v1.8.3: STRICT RUNTIME GATE — no silent mock downgrade.
Credentials from environment ONLY. No API keys in source/reports/artifacts.
"""
from .base import BaseLLMProvider, LLMResponse, TelemetryRecord
from .factory import (
           get_provider,
           get_provider_from_env,
           get_provider_status,
           get_runtime_gate_status,
)
from .mock_provider import MockLLMProvider
from .openai_compatible import OpenAICompatibleProvider

__all__ = ["BaseLLMProvider", "LLMResponse", "TelemetryRecord",
           "MockLLMProvider", "OpenAICompatibleProvider",
           "get_provider", "get_provider_from_env", "get_runtime_gate_status"]

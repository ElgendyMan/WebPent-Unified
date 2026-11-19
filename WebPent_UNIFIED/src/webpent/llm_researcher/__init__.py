"""WebPent LLM Researcher Layer — bounded, deterministic-safe.
GOED v1.8.3: Causal Feedback Bridge added.
LLM → Tool → Observation → WorldModel → CausalGuard
"""
from .causal_feedback_bridge import CausalFeedbackBridge
from .interface import Hypothesis, HypothesisStatus, LLMResearcher, ResearchMemory
from .mock_llm import MockLLMClient
from .providers import (
                        BaseLLMProvider,
                        FailureCategory,
                        LLMRouter,
                        MockLLMProvider,
                        OpenAICompatibleProvider,
                        ProviderPool,
                        ProviderSlot,
                        SlotStatus,
                        get_provider,
                        get_provider_from_env,
                        get_provider_status,
                        get_runtime_gate_status,
)
from .research_loop import LoopResult, ResearchLoop
from .tool_boundary import ALLOWED_TOOLS, FORBIDDEN_TOOLS, ToolBoundary, ToolCall, ToolName
from .world_model import ObservationStore, StoredObservation, WorldModel

__all__ = [
    "LLMResearcher", "Hypothesis", "HypothesisStatus", "ResearchMemory",
    "ToolBoundary", "ToolCall", "ToolName", "ALLOWED_TOOLS", "FORBIDDEN_TOOLS",
    "ResearchLoop", "LoopResult", "MockLLMClient",
    "WorldModel", "ObservationStore", "StoredObservation",
    "CausalFeedbackBridge",
    "BaseLLMProvider", "MockLLMProvider", "OpenAICompatibleProvider",
    "get_provider", "get_provider_from_env", "get_runtime_gate_status", "get_provider_status",
]

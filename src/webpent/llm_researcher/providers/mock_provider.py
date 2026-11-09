"""Mock LLM Provider — deterministic simulation, no external API calls."""
import hashlib
import json
import time
from typing import Any

from .base import BaseLLMProvider, LLMResponse


class MockLLMProvider(BaseLLMProvider):
    def __init__(self, model: str = "mock-deterministic-v1",
                 prompt_version_hash: str = "",
                 hallucination_rate: float = 0.0,
                 reasoning_quality: float = 0.7):
        super().__init__(model, prompt_version_hash)
        self.hallucination_rate = hallucination_rate
        self.reasoning_quality = reasoning_quality

    def _call_api(self, prompt: str, max_tokens: int, **kwargs) -> LLMResponse:
        start = time.time()
        seed = int(hashlib.sha256(prompt.encode()).hexdigest()[:8], 16)
        simulated_latency = 0.05 + (seed % 150) / 1000.0

        hypotheses = []
        if "ownership" in prompt.lower() or "resource_owner" in prompt.lower():
            hypotheses.append({"description": "Ownership boundary violation: resource accessed by non-owner actor",
                               "confidence": 0.7 * self.reasoning_quality,
                               "rationale": "authorization_outcome=granted_full but resource_owner differs from actor_echo"})
        if "tenant" in prompt.lower() and "actor_tenant" in prompt.lower():
            hypotheses.append({"description": "Tenant isolation failure: cross-tenant resource accessible",
                               "confidence": 0.75 * self.reasoning_quality,
                               "rationale": "resource_tenant differs from actor_tenant but access granted"})
        if "missing authorization" in prompt.lower() or "no authorization" in prompt.lower():
            hypotheses.append({"description": "Missing authorization enforcement on endpoint",
                               "confidence": 0.4 * self.reasoning_quality,
                               "rationale": "HTTP 200 with body but no authorization outcome header"})
        if "workflow" in prompt.lower() or "multi-step" in prompt.lower() or "chain" in prompt.lower():
            hypotheses.append({"description": "Business workflow manipulation: multi-step authorization chain may be bypassable",
                               "confidence": 0.5 * self.reasoning_quality,
                               "rationale": "Nested workflow detected — intermediate steps may lack individual authorization checks"})
        if "state" in prompt.lower() or "status" in prompt.lower() or "draft" in prompt.lower():
            hypotheses.append({"description": "State-dependent permission: authorization behavior may change with resource state",
                               "confidence": 0.45 * self.reasoning_quality,
                               "rationale": "State indicators present — same path may have different authorization in different states"})
        if "relationship" in prompt.lower() or "group" in prompt.lower() or "indirect" in prompt.lower():
            hypotheses.append({"description": "Indirect relationship-derived authorization: transitive ownership may grant unintended access",
                               "confidence": 0.4 * self.reasoning_quality,
                               "rationale": "Relationship indicators present — CausalGuard direct comparison may miss transitive chains"})
        if "delayed" in prompt.lower() or "side effect" in prompt.lower() or "consequence" in prompt.lower():
            hypotheses.append({"description": "Delayed consequence: write operation may create vulnerability in different endpoint",
                               "confidence": 0.35 * self.reasoning_quality,
                               "rationale": "Side effect language detected — cross-endpoint consequence possible"})
        if "equivalent" in prompt.lower() or "representation" in prompt.lower() or "same data" in prompt.lower():
            hypotheses.append({"description": "Equivalent representations with different authorization behavior",
                               "confidence": 0.42 * self.reasoning_quality,
                               "rationale": "Multiple representations detected — authorization may not be consistent across all forms"})

        if not hypotheses:
            hypotheses.append({"description": "Endpoint behavior requires structured investigation",
                               "confidence": 0.2 * self.reasoning_quality,
                               "rationale": "Insufficient pattern match from bounded observations"})

        if self.hallucination_rate > 0 and (seed % 1000) / 1000.0 < self.hallucination_rate:
            hypotheses.append({"description": "SIMULATED_HALLUCINATION: pattern not present in observations",
                               "confidence": 0.15,
                               "rationale": "Controlled hallucination for resistance testing"})

        content = json.dumps({"model": self.model, "hypotheses": hypotheses,
                              "note": "MOCK_PROVIDER — deterministic simulation"}, indent=2)
        actual_latency = time.time() - start
        estimated_tokens = len(prompt) // 4 + len(content) // 4

        return LLMResponse(model=self.model, content=content, raw_content=content,
                           tokens_used=estimated_tokens,
                           latency_seconds=max(actual_latency, simulated_latency),
                           finish_reason="stop")

    @property
    def provider_type(self) -> str:
        return "MOCK_SIMULATION"

    @property
    def is_mock(self) -> bool:
        return True

    def get_provider_metadata(self) -> dict[str, Any]:
        return {
            "provider_type": self.provider_type,
            "mock_provider": self.is_mock,
            "provider_class": self.__class__.__name__,
            "model": self.model,
            "reasoning_quality": self.reasoning_quality,
            "hallucination_rate": self.hallucination_rate,
            "prompt_version_hash": self.prompt_version_hash,
        }

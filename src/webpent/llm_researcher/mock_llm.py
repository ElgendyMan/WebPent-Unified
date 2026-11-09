"""Mock LLM Client — deterministic simulation for testing without external APIs.

Used for:
- Testing the LLM Researcher infrastructure
- LLM OFF baseline mode (deterministic only)
- LLM ON mode with simulated reasoning (no external API calls)
- Reproducible experiments
- Prompt injection resistance testing

This is NOT a real LLM. It simulates plausible behavior based on
deterministic pattern matching.
"""
import hashlib
import json
from typing import Any


class MockLLMClient:
    """Deterministic mock that simulates LLM behavior.

    Produces plausible but bounded outputs based on input patterns.
    All behavior is deterministic given the same input — no randomness.
    """

    def __init__(self, model_name: str = "mock-deterministic-v1",
                 hallucination_rate: float = 0.0,
                 reasoning_quality: float = 0.7):
        self.model_name = model_name
        self.hallucination_rate = max(0.0, min(1.0, hallucination_rate))
        self.reasoning_quality = max(0.0, min(1.0, reasoning_quality))
        self.call_count = 0
        self.total_tokens = 0

    def generate(self, prompt: str, max_tokens: int = 2000, **kwargs) -> str:
        """Simulate LLM generation deterministically."""
        self.call_count += 1
        self.total_tokens += min(max_tokens, 500)

        # Deterministic seed from prompt content
        seed = int(hashlib.sha256(prompt.encode()).hexdigest()[:8], 16)

        # Pattern-based hypothesis generation
        hypotheses = []

        if "ownership boundary violation" in prompt.lower() or "resource_owner" in prompt:
            hypotheses.append({
                "description": "Ownership boundary violation: resource accessed by non-owner actor",
                "confidence": 0.7 * self.reasoning_quality,
                "rationale": "Observation shows authorization_outcome=granted_full "
                           "but resource_owner differs from actor_echo"
            })

        if "tenant" in prompt.lower() and ("actor_tenant" in prompt.lower() or "resource_tenant" in prompt.lower()):
            hypotheses.append({
                "description": "Tenant isolation failure: resource from different tenant accessible",
                "confidence": 0.75 * self.reasoning_quality,
                "rationale": "resource_tenant differs from actor_tenant but access was granted"
            })

        if "missing authorization" in prompt.lower() or "no authorization" in prompt.lower():
            hypotheses.append({
                "description": "Missing authorization enforcement on endpoint returning HTTP 200",
                "confidence": 0.4 * self.reasoning_quality,
                "rationale": "HTTP 200 response with body content but no authorization outcome header"
            })

        if not hypotheses:
            hypotheses.append({
                "description": "Endpoint behavior requires further structured investigation",
                "confidence": 0.2 * self.reasoning_quality,
                "rationale": "Insufficient pattern match from current bounded observations"
            })

        # Optional simulated hallucination (controlled)
        if self.hallucination_rate > 0 and (seed % 1000) / 1000.0 < self.hallucination_rate:
            hypotheses.append({
                "description": "SIMULATED_HALLUCINATION: pattern that does not exist in observations",
                "confidence": 0.15,
                "rationale": "This is a controlled hallucination for testing resistance"
            })

        response = {
            "model": self.model_name,
            "call_id": self.call_count,
            "reasoning_quality_simulated": self.reasoning_quality,
            "hallucination_rate": self.hallucination_rate,
            "policy_note": "This is a MOCK LLM. All outputs are deterministic simulations.",
            "hypotheses": hypotheses,
        }

        return json.dumps(response, indent=2)

    def get_stats(self) -> dict[str, Any]:
        """Return usage statistics."""
        return {
            "model": self.model_name,
            "call_count": self.call_count,
            "total_tokens_estimated": self.total_tokens,
            "type": "mock_deterministic",
            "is_real_llm": False,
        }

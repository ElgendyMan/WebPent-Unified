"""Base LLM Provider interface — provider-neutral security core.
The security core never depends on vendor-specific logic.
"""
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LLMResponse:
    response_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    model: str = ""
    content: str = ""
    raw_content: str = ""
    tokens_used: int = 0
    latency_seconds: float = 0.0
    finish_reason: str = ""
    error: str | None = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class TelemetryRecord:
    """REDACTED telemetry — no prompt/response content, only aggregate metrics."""
    call_id: str
    model: str
    tokens_used: int
    latency_seconds: float
    finish_reason: str
    had_error: bool
    timestamp: float


class BaseLLMProvider(ABC):
    """Abstract base class for all LLM providers.

    Security invariants:
    - Credentials come ONLY from environment injection
    - No filesystem access beyond what Python runtime needs
    - No arbitrary command execution
    - Telemetry is redacted (no prompt/response content)
    - Model identifier and prompt version are always recorded
    """

    def __init__(self, model: str, prompt_version_hash: str = ""):
        self.model = model
        self.prompt_version_hash = prompt_version_hash
        self.telemetry_log: list[TelemetryRecord] = []
        self.call_count = 0
        self.total_tokens = 0

    @abstractmethod
    def _call_api(self, prompt: str, max_tokens: int, **kwargs) -> LLMResponse:
        """Vendor-specific API call. Must be implemented by subclass."""
        ...

    def generate(self, prompt: str, max_tokens: int = 2000, **kwargs) -> LLMResponse:
        """Public generate method — wraps vendor call with redacted telemetry.

        r6c wiring: the LLM funnel boundary is where the spend cap is
        enforced — the response's token usage is recorded against the active
        engagement and, at the cap, the completion is replaced by the
        ``LLM_SPEND_CAP_REACHED`` error response (fail closed, spend
        preserved for accounting).  Flag-off behaviour is unchanged.
        """
        self.call_count += 1
        start = time.time()
        try:
            response = self._call_api(prompt, max_tokens, **kwargs)
        except Exception as e:
            response = LLMResponse(
                model=self.model,
                error=f"PROVIDER_ERROR: {str(e)[:200]}",
                latency_seconds=time.time() - start,
            )
        try:
            from webpent.config.settings import get_settings

            if get_settings().enable_llm_spend_cap:
                from webpent.safety.spend_governor import enforce_spend_cap

                response = enforce_spend_cap(response)
        except Exception:  # noqa: BLE001 — the cap never breaks a real call
            pass

        telemetry = TelemetryRecord(
            call_id=response.response_id,
            model=self.model,
            tokens_used=response.tokens_used,
            latency_seconds=response.latency_seconds,
            finish_reason=response.finish_reason,
            had_error=response.error is not None,
            timestamp=response.timestamp,
        )
        self.telemetry_log.append(telemetry)
        self.total_tokens += response.tokens_used
        return response

    def get_redacted_telemetry(self) -> list[dict[str, Any]]:
        """Return telemetry WITHOUT any content — safe for reports."""
        return [{
            "call_id": t.call_id,
            "model": t.model,
            "tokens_used": t.tokens_used,
            "latency_seconds": round(t.latency_seconds, 3),
            "finish_reason": t.finish_reason,
            "had_error": t.had_error,
            "timestamp": t.timestamp,
        } for t in self.telemetry_log]

    def get_usage_stats(self) -> dict[str, Any]:
        """Return aggregate usage statistics."""
        return {
            "provider": self.__class__.__name__,
            "model": self.model,
            "prompt_version_hash": self.prompt_version_hash,
            "call_count": self.call_count,
            "total_tokens": self.total_tokens,
            "avg_latency": round(
                sum(t.latency_seconds for t in self.telemetry_log) / max(len(self.telemetry_log), 1), 3
            ),
            "error_rate": round(
                sum(1 for t in self.telemetry_log if t.had_error) / max(len(self.telemetry_log), 1), 3
            ),
        }

    @property
    def provider_type(self) -> str:
        """Return provider type identifier: 'REAL_API' or 'MOCK_SIMULATION'."""
        raise NotImplementedError

    @property
    def is_mock(self) -> bool:
        """Return True if this is a mock/simulation provider."""
        raise NotImplementedError

    @property
    def mock_provider(self) -> bool:
        """Alias for is_mock — backward compatibility with attribute checks."""
        return self.is_mock

    def get_provider_metadata(self) -> dict[str, Any]:
        """Return structured provider metadata. MUST NOT contain secrets."""
        raise NotImplementedError

"""OpenAI-compatible LLM provider. Credentials from environment ONLY.
Env vars: LLM_API_KEY (required), LLM_BASE_URL (optional), LLM_ORGANIZATION (optional)
NEVER commit API keys. NEVER include in reports/ZIPs.
"""
import hashlib
import os
import time
from typing import Any

from .base import BaseLLMProvider, LLMResponse


class OpenAICompatibleProvider(BaseLLMProvider):
    def __init__(self, model: str, prompt_version_hash: str = "",
                 api_key_env: str = "LLM_API_KEY",
                 base_url_env: str = "LLM_BASE_URL",
                 org_env: str = "LLM_ORGANIZATION",
                 api_key: str | None = None,
                 base_url: str | None = None):
        super().__init__(model, prompt_version_hash)
        # F-02 (0.33.0): explicit api_key/base_url overrides so ProviderPool
        # can pass its RESOLVED values (slot env fallbacks) without re-reading
        # env here — the old pool call passed api_key=/base_url= which did not
        # exist in this signature and raised TypeError on EVERY generate().
        self.api_key = api_key if api_key is not None else os.environ.get(api_key_env, "")
        self.base_url = (base_url if base_url is not None
                         else os.environ.get(base_url_env, "https://api.openai.com/v1"))
        self.organization = os.environ.get(org_env, "")
        self._client = None
        self._api_key_env_var = api_key_env
        self.successful_requests = 0
        self._first_success_evidence = None

    def close(self) -> None:
        """Close the lazy httpx client (F-03, 0.33.0).

        ProviderPool builds one provider per generate() call; without an
        explicit close each call leaked a full httpx connection pool
        (sockets/FDs) until GC. Safe to call multiple times.
        """
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "OpenAICompatibleProvider":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _get_client(self):
        if self._client is not None:
            return self._client
        if not self.api_key:
            raise RuntimeError(
                f"{self._api_key_env_var} environment variable not set. "
                f"Provider cannot make API calls without credentials."
            )
        try:
            import httpx
            self._client = httpx.Client(
                base_url=self.base_url,
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                timeout=60.0,
            )
            if self.organization:
                self._client.headers["OpenAI-Organization"] = self.organization
            return self._client
        except ImportError as exc:
            raise RuntimeError("httpx is required for OpenAI-compatible provider") from exc

    def _call_api(self, prompt: str, max_tokens: int, **kwargs) -> LLMResponse:
        start = time.time()
        try:
            client = self._get_client()
            r = client.post("/chat/completions", json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": kwargs.get("temperature", 0.2),
            })
            latency = time.time() - start
            if r.status_code != 200:
                return LLMResponse(model=self.model, error=f"HTTP_{r.status_code}: {r.text[:200]}",
                                   latency_seconds=latency)
            data = r.json()
            choice = data.get("choices", [{}])[0]
            msg = choice.get("message", {})
            usage = data.get("usage", {})
            self.successful_requests += 1
            if self._first_success_evidence is None:
                self._first_success_evidence = {
                    "response_id": data.get("id", "unknown"),
                    "model": data.get("model", self.model),
                    "finish_reason": choice.get("finish_reason", "unknown"),
                    "timestamp": time.time(),
                    "tokens_used": usage.get("total_tokens", 0),
                }
            return LLMResponse(model=self.model, content=msg.get("content", ""),
                               raw_content=msg.get("content", ""),
                               tokens_used=usage.get("total_tokens", 0),
                               latency_seconds=latency,
                               finish_reason=choice.get("finish_reason", ""))
        except Exception as e:
            return LLMResponse(model=self.model, error=f"REQUEST_FAILED: {str(e)[:200]}",
                               latency_seconds=time.time() - start)

    @property
    def provider_type(self) -> str:
        return "REAL_API"

    @property
    def is_mock(self) -> bool:
        return False

    def get_provider_metadata(self) -> dict[str, Any]:
        """Return provider metadata. API key is NOT included — only prefix for verification."""
        config_str = f"{self.base_url}|{self.organization}|{self.model}"
        return {
            "provider_type": self.provider_type,
            "mock_provider": self.is_mock,
            "provider_class": self.__class__.__name__,
            "model": self.model,
            "base_url": self.base_url,
            "has_organization": bool(self.organization),
            "api_key_env_var": self._api_key_env_var,
            "api_key_configured": bool(self.api_key),
            "api_key_prefix": self.api_key[:4] + "..." if self.api_key else "",
            "config_hash": hashlib.sha256(config_str.encode()).hexdigest(),
            "prompt_version_hash": self.prompt_version_hash,
            "api_requests_succeeded": self.successful_requests,
            "first_successful_response_evidence": self._first_success_evidence,
        }

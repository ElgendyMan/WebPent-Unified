"""Secure multi-provider credential pool for WebPent LLM routing.

Secrets are accepted only from process environment or an explicitly ignored local
JSON file. Public snapshots never contain secret values; they expose only opaque
fingerprints and bounded health metadata.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


class KeyStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    RATE_LIMITED = "RATE_LIMITED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    AUTH_FAILED = "AUTH_FAILED"
    TEMPORARILY_UNAVAILABLE = "TEMPORARILY_UNAVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class ProviderModel:
    provider: str
    model: str
    role: str = "general"
    priority: int = 100
    free: bool = True
    cost_per_1k_tokens: float | None = 0.0
    rate_limit_rpm: int | None = None
    api_key_env: str | None = None
    base_url: str | None = None
    account_id_env: str | None = None


@dataclass
class KeyHealth:
    status: KeyStatus = KeyStatus.AVAILABLE
    last_used: float | None = None
    requests_today: int = 0
    tokens_today: int = 0
    budget_used: float = 0.0
    rate_limit_hit_at: float | None = None
    retry_at: float | None = None
    last_error_type: str | None = None
    _round_robin: int = 0


@dataclass
class ProviderCredential:
    definition: ProviderModel
    secret: str
    fingerprint: str
    health: KeyHealth = field(default_factory=KeyHealth)

    def public_dict(self) -> dict[str, Any]:
        h = self.health
        return {
            "provider": self.definition.provider,
            "model": self.definition.model,
            "role": self.definition.role,
            "priority": self.definition.priority,
            "free": self.definition.free,
            "cost_per_1k_tokens": h_cost(self.definition),
            "key_fingerprint": self.fingerprint,
            "status": h.status.value,
            "last_used": h.last_used,
            "requests_today": h.requests_today,
            "tokens_today": h.tokens_today,
            "budget_used": round(h.budget_used, 8),
            "rate_limit_hit_at": h.rate_limit_hit_at,
            "retry_at": h.retry_at,
            "last_error_type": h.last_error_type,
        }


def h_cost(definition: ProviderModel) -> float | None:
    if definition.free:
        return 0.0
    return definition.cost_per_1k_tokens


_DEFAULT_MODELS: tuple[ProviderModel, ...] = (
    ProviderModel("openai", "gpt-5-mini", "general", 0, False, None, api_key_env="OPENAI_API_KEY", base_url="https://api.openai.com/v1"),
    ProviderModel("anthropic", "claude-sonnet-4-6", "reasoning", 0, False, None, api_key_env="ANTHROPIC_API_KEY"),
    ProviderModel("openrouter", "cognitivecomputations/dolphin-mistral-24b-venice-edition:free", "analysis", 1, True, 0.0, api_key_env="OPENROUTER_API_KEY", base_url="https://openrouter.ai/api/v1"),
    ProviderModel("openrouter", "qwen/qwen3-coder:free", "code", 1, True, 0.0, api_key_env="OPENROUTER_API_KEY", base_url="https://openrouter.ai/api/v1"),
    ProviderModel("openrouter", "nvidia/nemotron-3-ultra-550b-a55b:free", "reasoning", 1, True, 0.0, api_key_env="OPENROUTER_API_KEY", base_url="https://openrouter.ai/api/v1"),
    ProviderModel("openrouter", "meta-llama/llama-3.3-70b-instruct:free", "general", 1, True, 0.0, api_key_env="OPENROUTER_API_KEY", base_url="https://openrouter.ai/api/v1"),
    ProviderModel("groq", "llama-3.3-70b-versatile", "general", 2, True, 0.0, 30, "GROQ_API_KEY", "https://api.groq.com/openai/v1"),
    ProviderModel("groq", "mixtral-8x7b-32768", "analysis", 2, True, 0.0, 30, "GROQ_API_KEY", "https://api.groq.com/openai/v1"),
    ProviderModel("cerebras", "llama-3.3-70b", "general", 3, True, 0.0, api_key_env="CEREBRAS_API_KEY", base_url="https://api.cerebras.ai/v1"),
    ProviderModel("gemini", "gemini-2.0-flash", "fast", 4, True, 0.0, api_key_env="GEMINI_API_KEY"),
    ProviderModel("gemini", "gemma-4-31b", "code", 4, True, 0.0, api_key_env="GEMINI_API_KEY"),
    ProviderModel("mistral", "mistral-large-latest", "reasoning", 5, True, 0.0, api_key_env="MISTRAL_API_KEY", base_url="https://api.mistral.ai/v1"),
    ProviderModel("mistral", "codestral-latest", "code", 5, True, 0.0, api_key_env="MISTRAL_API_KEY", base_url="https://api.mistral.ai/v1"),
    ProviderModel("cloudflare", "@cf/meta/llama-3.1-8b-instruct", "fast", 6, True, 0.0, api_key_env="CLOUDFLARE_API_TOKEN", account_id_env="CLOUDFLARE_ACCOUNT_ID"),
    ProviderModel("cohere", "command-r-plus", "reasoning", 7, True, 0.0, api_key_env="COHERE_API_KEY"),
    ProviderModel("zai", "glm-5.1", "code", 8, True, 0.0, api_key_env="ZAI_API_KEY", base_url="https://open.bigmodel.cn/api/paas/v4/"),
    ProviderModel("zai", "glm-4-plus", "automation", 8, True, 0.0, api_key_env="ZAI_API_KEY", base_url="https://open.bigmodel.cn/api/paas/v4/"),
    ProviderModel("local", "llama3.1:8b", "general", 100, True, 0.0, api_key_env="OLLAMA_API_KEY", base_url="http://localhost:11434/v1"),
)

_DEFAULT_POOL: KeyPool | None = None
_DEFAULT_POOL_LOCK = threading.Lock()


def _fingerprint(secret: str) -> str:
    return "key_" + hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]


def _default_config_path() -> Path:
    return Path(os.getenv("WEBPENT_LLM_KEYS_FILE", ".llm_keys.json")).expanduser()


def _secret_from_config(raw: Any, env: Mapping[str, str]) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    value = raw.strip()
    return env.get(value) if value.isidentifier() and value.upper() == value else value


def _provider_overrides(path: Path | None, env: Mapping[str, str]) -> dict[tuple[str, str], dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("LLM key config must be a JSON object")
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for item in data.get("providers", []):
        if not isinstance(item, dict):
            raise ValueError("Each LLM provider config must be an object")
        provider = str(item.get("name") or item.get("provider") or "").strip().lower()
        if not provider:
            raise ValueError("LLM provider config is missing name/provider")
        models = item.get("models") or []
        if not isinstance(models, list):
            raise ValueError(f"models for {provider} must be a list")
        secret = _secret_from_config(item.get("api_key"), env)
        for model in models:
            model_id = str(model.get("id") if isinstance(model, dict) else model).strip()
            if model_id:
                result[(provider, model_id)] = {"secret": secret, "provider": item, "model": model}
    return result


def _status_from_exception(exc: BaseException) -> tuple[KeyStatus, float | None]:
    codes: list[int] = []
    for attr in ("status_code", "statusCode", "code"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            codes.append(value)
    response = getattr(exc, "response", None)
    if response is not None:
        for attr in ("status_code", "statusCode"):
            value = getattr(response, attr, None)
            if isinstance(value, int):
                codes.append(value)
    if 429 in codes:
        return KeyStatus.RATE_LIMITED, time.time() + 60.0
    if 402 in codes:
        return KeyStatus.QUOTA_EXCEEDED, None
    if any(code in {401, 403} for code in codes):
        return KeyStatus.AUTH_FAILED, None
    if any(code >= 500 for code in codes):
        return KeyStatus.TEMPORARILY_UNAVAILABLE, time.time() + 30.0
    if codes:
        return KeyStatus.UNAVAILABLE, None
    return KeyStatus.TEMPORARILY_UNAVAILABLE, time.time() + 30.0


class KeyPool:
    """Thread-safe provider/model pool with redacted operational snapshots."""

    def __init__(self, credentials: list[ProviderCredential] | None = None) -> None:
        self._credentials = credentials or []
        self._lock = threading.RLock()
        self._cursor: dict[tuple[str, int], int] = {}

    @classmethod
    def load(cls, *, config_path: str | Path | None = None, env: Mapping[str, str] | None = None) -> "KeyPool":
        env = env or os.environ
        path = Path(config_path).expanduser() if config_path else _default_config_path()
        overrides = _provider_overrides(path, env)
        credentials: list[ProviderCredential] = []
        for definition in _DEFAULT_MODELS:
            item = overrides.get((definition.provider, definition.model), {})
            provider_cfg = item.get("provider", {}) if isinstance(item, dict) else {}
            secret = item.get("secret") if isinstance(item, dict) else None
            env_name = definition.api_key_env
            env_secret = env.get(env_name) if env_name else None
            if env_secret:
                secret = env_secret
            if definition.provider == "local":
                secret = env_secret or secret or ("local-runtime" if env.get("OLLAMA_URL") else None)
            if definition.provider == "cloudflare" and not env.get("CLOUDFLARE_ACCOUNT_ID"):
                secret = None
            if secret:
                credentials.append(ProviderCredential(definition, secret, _fingerprint(secret)))
            elif isinstance(provider_cfg, dict) and provider_cfg.get("api_key"):
                fallback_secret = _secret_from_config(provider_cfg.get("api_key"), env)
                if fallback_secret:
                    credentials.append(ProviderCredential(definition, fallback_secret, _fingerprint(fallback_secret)))
        return cls(credentials)

    def available(self, provider: str | None = None, model: str | None = None) -> list[ProviderCredential]:
        now = time.time()
        with self._lock:
            return [c for c in self._credentials if
                    (provider is None or c.definition.provider == provider) and
                    (model is None or c.definition.model == model) and
                    c.health.status == KeyStatus.AVAILABLE and
                    (c.health.retry_at is None or c.health.retry_at <= now)]

    def select(self, provider: str, model: str | None = None) -> ProviderCredential | None:
        candidates = self.available(provider, model)
        if not candidates:
            return None
        with self._lock:
            priority = min(c.definition.priority for c in candidates)
            candidates = [c for c in candidates if c.definition.priority == priority]
            key = (provider, priority)
            index = self._cursor.get(key, 0) % len(candidates)
            self._cursor[key] = index + 1
            return candidates[index]

    def find(self, provider: str, model: str | None = None) -> ProviderCredential | None:
        """Find a credential for telemetry without rotating or counting a request."""
        with self._lock:
            for credential in self._credentials:
                if credential.definition.provider == provider and (model is None or credential.definition.model == model):
                    return credential
        return None

    def mark_success(self, credential: ProviderCredential, *, tokens: int = 0, cost: float = 0.0) -> None:
        with self._lock:
            credential.health.last_used = time.time()
            credential.health.requests_today += 1
            credential.health.status = KeyStatus.AVAILABLE
            credential.health.retry_at = None
            credential.health.tokens_today += max(0, int(tokens))
            credential.health.budget_used += max(0.0, float(cost))
            credential.health.last_error_type = None

    def mark_failure(self, credential: ProviderCredential, exc: BaseException) -> KeyStatus:
        status, retry_at = _status_from_exception(exc)
        with self._lock:
            credential.health.last_used = time.time()
            credential.health.requests_today += 1
            credential.health.status = status
            credential.health.rate_limit_hit_at = time.time() if status == KeyStatus.RATE_LIMITED else credential.health.rate_limit_hit_at
            credential.health.retry_at = retry_at
            credential.health.last_error_type = type(exc).__name__[:120]
        return status

    def status(self) -> list[dict[str, Any]]:
        with self._lock:
            return [c.public_dict() for c in sorted(self._credentials, key=lambda x: (x.definition.priority, x.definition.provider, x.definition.model))]

    def providers(self) -> list[str]:
        return sorted({c.definition.provider for c in self._credentials})

    def reset(self) -> None:
        with self._lock:
            for c in self._credentials:
                c.health = KeyHealth()
            self._cursor.clear()


def default_key_pool() -> KeyPool:
    """Return the process-local pool used by normal application routing."""
    global _DEFAULT_POOL
    with _DEFAULT_POOL_LOCK:
        if _DEFAULT_POOL is None:
            _DEFAULT_POOL = KeyPool.load()
        return _DEFAULT_POOL


def reset_default_key_pool() -> None:
    global _DEFAULT_POOL
    with _DEFAULT_POOL_LOCK:
        _DEFAULT_POOL = None


def resolve_api_key(provider: str, *, env: Mapping[str, str] | None = None, config_path: str | Path | None = None) -> str | None:
    """Resolve one provider key without exposing it in any returned diagnostics."""
    pool = KeyPool.load(config_path=config_path, env=env)
    selected = pool.select(provider)
    return selected.secret if selected else None


def redacted_status(*, config_path: str | Path | None = None, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    pool = KeyPool.load(config_path=config_path, env=env)
    return {"providers": pool.status(), "configured_providers": pool.providers()}


__all__ = [
    "KeyPool", "KeyStatus", "KeyHealth", "ProviderCredential", "ProviderModel",
    "default_key_pool", "reset_default_key_pool", "redacted_status", "resolve_api_key",
]

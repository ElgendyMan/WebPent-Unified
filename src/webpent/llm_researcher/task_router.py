"""Task-to-model routing for the multi-provider LLM key pool."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from webpent.llm_researcher.key_pool import KeyPool, ProviderModel


class LLMTask(str, Enum):
    RECON_ANALYZE_PAGE = "recon_analyze_page"
    HYPOTHESIS_GENERATE = "hypothesis_generate"
    PAYLOAD_SELECT = "payload_select"
    CODE_EXPLOIT_WRITE = "code_exploit_write"
    OUTPUT_ANALYZE = "output_analyze"
    ERROR_FIX = "error_fix"
    ENDPOINT_EXTRACT = "endpoint_extract"
    LIGHTWEIGHT_CLASSIFY = "lightweight_classify"
    WEB_RECON_SEARCH = "web_recon_search"


@dataclass(frozen=True)
class RouteCandidate:
    provider: str
    model: str
    prompt_style: str
    tier: str
    reason: str

    def public_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "model": self.model,
            "prompt_style": self.prompt_style,
            "tier": self.tier,
            "reason": self.reason,
        }


# Entries intentionally use aliases and concrete provider/model pairs. The key
# pool filters unavailable entries; no route entry grants execution authority.
_ROUTE_TABLE: dict[LLMTask, tuple[str, tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]] = {
    LLMTask.RECON_ANALYZE_PAGE: ("analytical", (("openrouter", "meta-llama/llama-3.3-70b-instruct:free"), ("zai", "glm-5.1"), ("groq", "llama-3.3-70b-versatile")), (("cerebras", "llama-3.3-70b"), ("openrouter", "cognitivecomputations/dolphin-mistral-24b-venice-edition:free"))),
    LLMTask.HYPOTHESIS_GENERATE: ("creative_analytical", (("zai", "glm-5.1"), ("openrouter", "nvidia/nemotron-3-ultra-550b-a55b:free"), ("groq", "llama-3.3-70b-versatile")), (("mistral", "mistral-large-latest"), ("cerebras", "llama-3.3-70b"))),
    LLMTask.PAYLOAD_SELECT: ("technical", (("zai", "glm-4-plus"), ("openrouter", "qwen/qwen3-coder:free"), ("mistral", "codestral-latest")), (("groq", "llama-3.3-70b-versatile"), ("openrouter", "meta-llama/llama-3.3-70b-instruct:free"))),
    LLMTask.CODE_EXPLOIT_WRITE: ("code", (("zai", "glm-5.1"), ("openrouter", "qwen/qwen3-coder:free"), ("mistral", "codestral-latest")), (("groq", "llama-3.3-70b-versatile"), ("cerebras", "llama-3.3-70b"))),
    LLMTask.OUTPUT_ANALYZE: ("analytical", (("openrouter", "meta-llama/llama-3.3-70b-instruct:free"), ("zai", "glm-5.1"), ("groq", "llama-3.3-70b-versatile")), (("cerebras", "llama-3.3-70b"), ("openrouter", "cognitivecomputations/dolphin-mistral-24b-venice-edition:free"))),
    LLMTask.ERROR_FIX: ("fast_fix", (("zai", "glm-4.7-flash"), ("openrouter", "qwen/qwen3-coder:free")), (("gemini", "gemma-4-31b"), ("mistral", "codestral-latest"))),
    LLMTask.ENDPOINT_EXTRACT: ("extraction", (("zai", "glm-5.1"), ("openrouter", "qwen/qwen3-coder:free")), (("openrouter", "nvidia/nemotron-3-ultra-550b-a55b:free"), ("groq", "llama-3.3-70b-versatile"))),
    LLMTask.LIGHTWEIGHT_CLASSIFY: ("fast", (("zai", "glm-4.7-flash"), ("gemini", "gemini-2.0-flash"), ("groq", "mixtral-8x7b-32768")), (("cerebras", "llama-3.3-70b"), ("openrouter", "meta-llama/llama-3.3-70b-instruct:free"))),
    LLMTask.WEB_RECON_SEARCH: ("search", (("zai", "search-prime"),), (("zai", "web-reader"), ("gemini", "gemini-2.0-flash"))),
}


def _available_pairs(pool: KeyPool, pairs: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(provider, model) for provider, model in pairs if pool.available(provider, model)]


class TaskRouter:
    def __init__(self, pool: KeyPool | None = None) -> None:
        self.pool = pool or KeyPool.load()

    def route(self, task_type: str | LLMTask) -> tuple[RouteCandidate, ...]:
        task = task_type if isinstance(task_type, LLMTask) else LLMTask(str(task_type))
        prompt_style, preferred, fallback = _ROUTE_TABLE[task]
        result: list[RouteCandidate] = []
        for tier, pairs in (("preferred", preferred), ("fallback", fallback)):
            for provider, model in _available_pairs(self.pool, pairs):
                result.append(RouteCandidate(provider, model, prompt_style, tier, f"{tier}:{task.value}"))
        if not result:
            # The built-in OpenAI-compatible proxy is an explicit compatibility
            # route when no free third-party provider is configured. It is not
            # labeled as a free model and does not imply multi-provider use.
            for provider, model in _available_pairs(self.pool, (("openai", "gpt-5-mini"),)):
                result.append(RouteCandidate(provider, model, prompt_style, "compatibility", "configured_openai_compatible"))
        if not result:
            # Local fallback is included only when the local endpoint was
            # actually configured/represented by the pool.
            for provider, model in _available_pairs(self.pool, (("local", "llama3.1:8b"),)):
                result.append(RouteCandidate(provider, model, prompt_style, "local", "local_fallback"))
        return tuple(result)

    def diagnostics(self) -> dict[str, object]:
        return {
            "tasks": {task.value: [c.public_dict() for c in self.route(task)] for task in LLMTask},
            "configured_providers": self.pool.providers(),
        }


def route_for(task_type: str | LLMTask, *, pool: KeyPool | None = None) -> tuple[RouteCandidate, ...]:
    return TaskRouter(pool).route(task_type)


__all__ = ["LLMTask", "RouteCandidate", "TaskRouter", "route_for"]

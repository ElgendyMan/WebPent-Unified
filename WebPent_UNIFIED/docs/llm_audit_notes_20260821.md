# LLM audit working notes — 2026-08-21

## Initial observations

The central integration is `src/webpent/shared/llm.py`. It uses LangChain `BaseChatModel`, task-based provider/model preference chains, a provider circuit breaker, and a per-run `llm_enabled_override` context variable. The module advertises automatic fallbacks and skips providers whose API keys are absent.

The preference table currently contains legacy model IDs such as Groq `llama-3.3-70b-versatile`, OpenRouter `meta-llama/llama-3.3-70b-instruct:free`, GitHub `gpt-4o`, Anthropic `claude-3-5-sonnet-20241022`, Gemini `gemini-2.0-flash`, and Mistral `mistral-large-latest`. These IDs must be verified against each user's provider catalog at runtime; a model working for one provider does not imply that a different provider or model supports the same request shape.

The built-in LLM guidance says that GPT-5 uses `max_completion_tokens`, Claude uses `max_tokens` strictly greater than its thinking budget, and Gemini uses `max_tokens` rather than `max_completion_tokens`. It also recommends strict JSON Schema with `additionalProperties: false` for structured outputs. These are compatibility constraints for the audit, not proof that arbitrary external providers implement them identically.

No conclusion of production readiness has been made yet. The next checks must inspect provider builders, response parsing, prompt construction, settings/env documentation, tests, and the actual failure isolation behavior of every LLM-enabled graph node.

## Compatibility constraints from the reference

The reference distinguishes GPT `max_completion_tokens`, Claude `max_tokens` with thinking-budget rules, and Gemini `max_tokens`; provider-specific structured-output support must not be assumed for arbitrary external endpoints without a live probe. WebPent's LangChain adapters do not currently expose a generic provider-specific model catalog or dynamic capability negotiation.

The audit must therefore verify the actual external-provider path separately from the Manus built-in proxy. The built-in proxy credentials (`OPENAI_API_KEY`/`OPENAI_API_BASE`) are not the same as WebPent's provider keys and should not be silently mixed.

# LLM Security Boundary

## Purpose

WebPent treats target responses, crawler output, tool output, retrieved lessons, and model-generated text as untrusted data. The LLM layer is advisory only: it cannot authorize actions, widen target scope, promote a candidate, or create a confirmation without deterministic target-backed verification and an independently sealed replayable proof bundle.

## Verified controls

`safe_prompt_format()` wraps untrusted string and structured values in the `<untrusted_data>` boundary after recursive sanitization. Structured values include strings, lists, dictionaries, and tuples. Tuple support is important because direct `str.format()` of a tuple previously inserted its representation without the wrapper, allowing an attacker-controlled containment tag to bypass the trust boundary.

The sanitizer preserves the content as data while neutralizing containment tags, including encoded, zero-width, full-width, and covered homoglyph variants. It does not treat the sanitized text as an instruction.

`get_llm_diagnostics()` returns only redaction-safe provider names, routing state, dead-provider state, and task labels. It performs no provider request and never returns API-key values. LLM usage telemetry is diagnostic and bounded; it is not evidence, authorization, or finding confirmation.

## Regression coverage

The Security Invariant Suite includes:

- tuple prompt values are recursively sanitized and wrapped;
- the attacker-controlled containment tag is neutralized while its text remains ordinary data;
- configured provider diagnostics expose the provider label but not the configured secret;
- existing provider fallback, circuit-breaker, cache, and deterministic-disabled paths remain covered by the existing LLM test suite.

The phase gate passed with 26 focused LLM tests and the broader security/contract gate passing. The direct-I/O inventory remains deterministic at 283 records.

## Explicit limits

These tests prove boundary behavior only. They do not prove that a model is reliable, that a provider is reachable, that a target is vulnerable, or that a candidate is confirmed. Live qualification remains subject to the existing scope, causal-signal, independent-negative-control, sealed ProofBundle, and replay gates.

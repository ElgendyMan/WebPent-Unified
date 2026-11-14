#!/usr/bin/env python3
"""scripts/doctor.py — V6 DX-Final Preflight LLM Doctor.

Tests every configured LLM provider by sending a minimal prompt
("Reply with OK") and printing a table of which providers are
ACTIVE, MISSING_KEY, or FAILING. Also surfaces the current
circuit-breaker state (dead providers + TTL remaining).

Wired into the Makefile as ``make doctor`` — run this BEFORE
starting a scan to catch misconfigured API keys, expired tokens,
or quota exhaustion early.

Usage:
    python scripts/doctor.py
    python scripts/doctor.py --json        # machine-readable output
    python scripts/doctor.py --timeout 10  # per-provider timeout

Exit codes:
    0 — at least one provider is ACTIVE, or deterministic LLM fallback is enabled
    1 — no providers are usable while LLM assistance is enabled
    2 — harness error (could not load settings / imports failed)

R-06 (TEAM-2 residual): the doctor now also reports the offline
knowledge-pack readiness (``knowledge_ready``) by reusing the EXACT
check from ``webpent.shared.preflight`` — no second implementation that
could drift. The check is ADVISORY by design: knowledge/RAG is
guidance-only and never authoritative, so a not-ready result is printed
but never changes the exit code.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path bootstrap — make sure we can import webpent.* from src/
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("doctor")


# ---------------------------------------------------------------------------
# Minimal provider probe
# ---------------------------------------------------------------------------
# Each provider entry maps to:
#   - settings attribute name holding the API key
#   - a callable that builds a one-shot LangChain chat model
#   - the model name used for the probe (cheap model preferred)
#
# We deliberately reuse the framework's own _build_* helpers from
# webpent.shared.llm so the doctor exercises the EXACT same code path
# the framework uses at runtime — no separate client implementation
# that could drift.

# Probe model per provider — chosen for low cost / low latency so the
# doctor stays fast even with many providers configured. These mirror
# the FAST task preference chain in llm.py.
#
# V7 Phase 6 FIX: openrouter + gemini slugs updated to match the
# matching entries in _TASK_PREFERENCE_ORDER in src/webpent/shared/llm.py.
# The doctor and the real router MUST stay in sync — if a slug is ever
# bumped here, bump it in llm.py too (and vice versa), otherwise the
# doctor can report a provider as ACTIVE while the real router 404s
# (or vice versa). The previous slugs (qwen/qwen3-coder:free,
# gemini-1.5-flash) were stale/deprecated and caused exactly that
# class of false-negative in the doctor's pre-V7 output.
_PROBE_MODELS: dict[str, str] = {
    "groq": "llama-3.1-8b-instant",
    "openrouter": "meta-llama/llama-3.3-70b-instruct:free",
    "github": "gpt-4o-mini",
    "cerebras": "llama3.1-8b",
    "zai": "glm-4.7-flash",
    "mistral": "mistral-small-latest",
    "gemini": "gemini-2.0-flash",
    "cohere": "command-r",
    # Cloudflare requires account_id too; handled specially below.
    "cloudflare": "@cf/meta/llama-3-8b-instruct",
}

_PROBE_PROMPT = "Reply with OK"


def _get_api_key(settings: Any, provider: str) -> str | None:
    """Return the API key for ``provider`` from settings, or None."""
    if provider == "cloudflare":
        if settings.cloudflare_api_key and settings.cloudflare_account_id:
            return settings.cloudflare_api_key
        return None
    return getattr(settings, f"{provider}_api_key", None)


def _build_probe_model(provider: str, settings: Any):
    """Build a LangChain chat model for the probe.

    Reuses webpent.shared.llm's internal builders so the doctor
    exercises the same code path as the framework.
    """
    from webpent.shared import llm as llm_mod

    api_key = _get_api_key(settings, provider)
    if not api_key:
        return None

    model_name = _PROBE_MODELS.get(provider, "gpt-4o-mini")

    # Use the framework's _build_model — it handles every provider
    # branch (OpenAI-compatible, Mistral, Gemini, Cohere, Cloudflare).
    # We bypass the circuit-breaker check (so the doctor can probe a
    # provider even if it was previously marked dead) by calling the
    # underlying builders directly.
    if provider in llm_mod._OPENAI_COMPATIBLE_BASE_URLS:
        return llm_mod._build_openai_compatible(
            base_url=llm_mod._OPENAI_COMPATIBLE_BASE_URLS[provider],
            api_key=api_key,
            model_name=model_name,
            settings=settings,
        )
    if provider == "mistral":
        return llm_mod._build_mistral(
            api_key=api_key,
            model_name=model_name,
            settings=settings,
        )
    if provider == "gemini":
        return llm_mod._build_gemini(
            api_key=api_key,
            model_name=model_name,
            settings=settings,
        )
    if provider == "cohere":
        return llm_mod._build_cohere(
            api_key=api_key,
            model_name=model_name,
            settings=settings,
        )
    if provider == "cloudflare":
        return llm_mod._build_cloudflare(
            api_key=settings.cloudflare_api_key,
            account_id=settings.cloudflare_account_id,
            model_name=model_name,
            settings=settings,
        )
    return None


def _probe_provider(provider: str, settings: Any, timeout: float) -> dict[str, Any]:
    """Probe a single provider.

    Returns a dict with keys: provider, status, latency_ms, detail.
    Status is one of: ACTIVE, MISSING_KEY, FAILING, SKIPPED.
    """
    result: dict[str, Any] = {
        "provider": provider,
        "status": "UNKNOWN",
        "latency_ms": None,
        "detail": "",
    }

    api_key = _get_api_key(settings, provider)
    if not api_key:
        result["status"] = "MISSING_KEY"
        result["detail"] = f"no {provider}_api_key configured"
        return result

    try:
        model = _build_probe_model(provider, settings)
    except Exception as exc:
        result["status"] = "FAILING"
        result["detail"] = f"build error: {str(exc)[:120]}"
        return result

    if model is None:
        result["status"] = "FAILING"
        result["detail"] = "model builder returned None"
        return result

    # Invoke with the minimal probe prompt.
    from langchain_core.messages import HumanMessage, SystemMessage

    start = time.monotonic()
    try:
        # Use a thread to enforce a hard timeout — LangChain clients
        # honour ``timeout`` only loosely across providers.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                model.invoke,
                [
                    SystemMessage(content="Reply with exactly: OK"),
                    HumanMessage(content=_PROBE_PROMPT),
                ],
            )
            response = future.result(timeout=timeout)

        latency_ms = int((time.monotonic() - start) * 1000)
        result["latency_ms"] = latency_ms

        # Extract the text content from the response.
        content = getattr(response, "content", "")
        if not isinstance(content, str):
            content = str(content)
        content_lower = content.strip().lower()

        # Accept any response that contains "ok" — some models prepend
        # boilerplate ("Sure! OK") or wrap in quotes.
        if "ok" in content_lower:
            result["status"] = "ACTIVE"
            result["detail"] = f"responded: {content.strip()[:40]!r}"
        else:
            result["status"] = "FAILING"
            result["detail"] = f"unexpected response: {content.strip()[:80]!r}"
    except concurrent.futures.TimeoutError:
        result["status"] = "FAILING"
        result["detail"] = f"timeout after {timeout:.0f}s"
    except Exception as exc:
        result["status"] = "FAILING"
        # Truncate the error so the table stays readable.
        msg = str(exc)
        # Strip newlines / collapse whitespace.
        msg = " ".join(msg.split())[:140]
        result["detail"] = f"error: {msg}"

    return result


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------
def _format_knowledge_section(knowledge: dict[str, Any] | None) -> list[str]:
    """Format the advisory knowledge-pack readiness block (R-06)."""
    lines: list[str] = []
    lines.append("")
    lines.append("Knowledge pack (RAG) readiness — advisory, never authoritative:")
    if not isinstance(knowledge, dict) or not knowledge:
        lines.append("  - unknown (knowledge check unavailable)")
        return lines
    ready = bool(knowledge.get("knowledge_ready"))
    lines.append(f"  - knowledge_ready: {ready}")
    status = str(knowledge.get("status") or "")
    if status:
        lines.append(f"  - status: {status}")
    if "store_populated" in knowledge:
        lines.append(f"  - store_populated: {bool(knowledge.get('store_populated'))}")
    if "pack_sources" in knowledge:
        lines.append(f"  - pack_sources: {knowledge.get('pack_sources')}")
    missing = knowledge.get("missing_files")
    if isinstance(missing, list) and missing:
        lines.append(f"  - missing_files: {', '.join(str(m) for m in missing[:5])}")
    return lines


def _format_table(
    results: list[dict[str, Any]],
    dead_providers: dict[str, float],
    knowledge: dict[str, Any] | None = None,
) -> str:
    """Format results as a human-readable table."""
    lines: list[str] = []
    lines.append("")
    lines.append("=" * 78)
    lines.append("WEBPENT LLM DOCTOR — Provider Health Check")
    lines.append("=" * 78)

    # Column widths
    header = f"{'Provider':<14} {'Status':<14} {'Latency':<10} {'Detail':<38}"
    lines.append(header)
    lines.append("-" * 78)

    for r in results:
        latency_str = f"{r['latency_ms']}ms" if r["latency_ms"] is not None else "-"
        # Truncate detail to fit
        detail = r["detail"][:38]
        lines.append(f"{r['provider']:<14} {r['status']:<14} {latency_str:<10} {detail:<38}")

    lines.append("-" * 78)

    # Summary
    active = sum(1 for r in results if r["status"] == "ACTIVE")
    missing = sum(1 for r in results if r["status"] == "MISSING_KEY")
    failing = sum(1 for r in results if r["status"] == "FAILING")
    lines.append(
        f"Summary: {active} active, {missing} missing key, {failing} failing "
        f"out of {len(results)} providers."
    )

    # Circuit-breaker state
    if dead_providers:
        lines.append("")
        lines.append("Circuit-breaker (dead providers):")
        now = time.monotonic()
        # We don't have direct access to the TTL constant here without
        # importing; pull it from the llm module.
        try:
            from webpent.shared.llm import _DEAD_PROVIDER_TTL_SECONDS

            ttl = int(_DEAD_PROVIDER_TTL_SECONDS)
        except Exception:
            ttl = 600
        for name, ts in sorted(dead_providers.items()):
            elapsed = int(now - ts)
            remaining = max(0, ttl - elapsed)
            lines.append(f"  - {name}: dead for {elapsed}s, TTL recovery in {remaining}s")
    else:
        lines.append("")
        lines.append("Circuit-breaker: no dead providers (all clear).")

    lines.append("=" * 78)
    # R-06: advisory knowledge-pack readiness, printed after the provider
    # table so operators see RAG posture in the same preflight pass.
    lines.extend(_format_knowledge_section(knowledge))
    return "\n".join(lines)


def _format_json(
    results: list[dict[str, Any]],
    dead_providers: dict[str, float],
    knowledge: dict[str, Any] | None = None,
) -> str:
    """Format results as JSON."""
    return json.dumps(
        {
            "results": results,
            "dead_providers": {
                name: {"dead_for_seconds": time.monotonic() - ts}
                for name, ts in dead_providers.items()
            },
            "knowledge": knowledge or {},
            "summary": {
                "active": sum(1 for r in results if r["status"] == "ACTIVE"),
                "missing_key": sum(1 for r in results if r["status"] == "MISSING_KEY"),
                "failing": sum(1 for r in results if r["status"] == "FAILING"),
                "total": len(results),
            },
        },
        indent=2,
    )


def _knowledge_readiness() -> dict[str, Any] | None:
    """R-06: reuse the preflight knowledge_ready check verbatim (no drift)."""
    try:
        from webpent.shared.preflight import _check_knowledge_ready

        result = _check_knowledge_ready()
        return result if isinstance(result, dict) else {"knowledge_ready": False}
    except Exception as exc:  # non-blocking by design — RAG is advisory-only
        log.debug("knowledge readiness check failed: %s", exc)
        return {"knowledge_ready": False, "status": f"unavailable ({type(exc).__name__})"}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="V6 DX-Final — Preflight LLM provider health check."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a table.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Per-provider probe timeout in seconds (default: 15).",
    )
    parser.add_argument(
        "--provider",
        action="append",
        help="Only probe the named provider (may be passed multiple times).",
    )
    args = parser.parse_args()

    # Load framework settings.
    try:
        from webpent.config.settings import get_settings
        from webpent.shared.llm import get_dead_providers

        settings = get_settings()
    except Exception as exc:
        log.error("Failed to load framework settings: %s", exc)
        print(f"DOCTOR ERROR: could not load settings: {exc}", file=sys.stderr)
        return 2

    # Deterministic/offline mode is an intentional supported state. Do not
    # perform network probes when the operator disabled AI assistance.
    # R-06: knowledge readiness is independent of LLM posture — compute it
    # once and surface it in every output path (advisory only).
    knowledge = _knowledge_readiness()
    all_providers = list(_PROBE_MODELS.keys())
    if not getattr(settings, "llm_enabled", True):
        results = [
            {
                "provider": provider,
                "status": "SKIPPED",
                "latency_ms": None,
                "detail": "LLM disabled; deterministic fallback is active",
            }
            for provider in all_providers
        ]
        try:
            dead_providers = get_dead_providers()
        except Exception:
            dead_providers = {}
        if args.json:
            print(_format_json(results, dead_providers, knowledge))
        else:
            print(_format_table(results, dead_providers, knowledge))
        # R-06: keep --json stdout machine-readable — human verdicts go to stderr.
        print("\nVERDICT: LLM disabled — deterministic fallback mode is active.",
              file=sys.stderr)
        return 0
    providers_to_probe = (
        [p for p in all_providers if p in args.provider] if args.provider else all_providers
    )

    # Probe each provider sequentially. (Parallel probing would race
    # on the circuit-breaker state and produce confusing output.)
    results: list[dict[str, Any]] = []
    for provider in providers_to_probe:
        sys.stderr.write(f"Probing {provider}... ")
        sys.stderr.flush()
        result = _probe_provider(provider, settings, args.timeout)
        sys.stderr.write(f"{result['status']}\n")
        results.append(result)

    # Snapshot the circuit-breaker state.
    try:
        dead_providers = get_dead_providers()
    except Exception:
        dead_providers = {}

    # Output.
    if args.json:
        print(_format_json(results, dead_providers, knowledge))
    else:
        print(_format_table(results, dead_providers, knowledge))

    # Exit code: 0 if at least one provider is ACTIVE, 1 otherwise.
    active_count = sum(1 for r in results if r["status"] == "ACTIVE")
    if active_count == 0:
        print(
            "\nVERDICT: No active LLM providers — scans will fail at the "
            "first LLM call. Set at least one *_API_KEY env var.",
            file=sys.stderr,
        )
        return 1
    if args.json:
        print(f"VERDICT: {active_count} provider(s) active — ready to scan.",
              file=sys.stderr)
    else:
        print(f"\nVERDICT: {active_count} provider(s) active — ready to scan.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

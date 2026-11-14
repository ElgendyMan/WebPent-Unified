"""GOED v1.8.4 — A.3: REAL API Provider Gate Verification
Tests real provider connectivity, captures required metadata (NO secrets stored).
Produces: reports/goed_v1_8_4/provider_gate_v184.json
"""
import hashlib
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)

from webpent.llm_researcher.providers import get_provider_from_env

REPORTS = os.path.join(_ROOT, "reports", "goed_v1_8_4")
os.makedirs(REPORTS, exist_ok=True)

def run_provider_gate():
    print("=" * 60)
    print("GOED v1.8.4 — A.3: REAL API Provider Gate")
    print("=" * 60)

    result = {"phase": "A3_provider_gate", "timestamp": time.time()}

    # Check env vars
    llm_provider = os.environ.get("LLM_PROVIDER", "not_set")
    llm_api_key_set = bool(os.environ.get("LLM_API_KEY", ""))
    llm_base_url = os.environ.get("LLM_BASE_URL", "not_set")
    llm_model = os.environ.get("LLM_MODEL", "not_set")

    result["env_check"] = {
        "LLM_PROVIDER": llm_provider,
        "LLM_API_KEY_set": llm_api_key_set,
        "LLM_BASE_URL": llm_base_url,
        "LLM_MODEL": llm_model,
    }

    if not llm_api_key_set or llm_provider != "openai_compatible":
        result["provider_status"] = "REAL_API_UNAVAILABLE"
        result["reason"] = f"LLM_PROVIDER={llm_provider}, LLM_API_KEY_set={llm_api_key_set}"
        out_path = os.path.join(REPORTS, "provider_gate_v184.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"REAL_API_UNAVAILABLE — {result['reason']}")
        return

    # Get real provider
    try:
        provider = get_provider_from_env("provider_gate_v184")
    except RuntimeError as e:
        result["provider_status"] = "REAL_API_UNAVAILABLE"
        result["reason"] = str(e)[:200]
        out_path = os.path.join(REPORTS, "provider_gate_v184.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"REAL_API_UNAVAILABLE — {result['reason']}")
        return

    # Check it's real, not mock
    meta = provider.get_provider_metadata()
    is_mock = meta.get("mock_provider", True)
    result["is_mock"] = is_mock

    if is_mock:
        result["provider_status"] = "REAL_API_UNAVAILABLE"
        result["reason"] = "Provider reports as mock"
        out_path = os.path.join(REPORTS, "provider_gate_v184.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print("REAL_API_UNAVAILABLE — provider is mock")
        return

    # Make real test calls
    test_prompts = [
        "Security observation analysis: baseline=200/granted_full/owner=alice, candidate=200/granted_full/owner=bob, control=403/denied. What is the likely hypothesis?",
        "Return only the word READINESS_OK in uppercase.",
    ]

    call_results = []
    total_tokens = 0
    total_latency = 0

    for i, prompt in enumerate(test_prompts):
        t0 = time.time()
        response = provider.generate(prompt, max_tokens=100)
        latency = time.time() - t0

        call_result = {
            "call_index": i,
            "success": response.error is None,
            "error": response.error,
            "latency_seconds": round(latency, 3),
            "tokens_used": response.tokens_used,
            "finish_reason": response.finish_reason,
            "model": response.model,
            "response_preview": response.content[:80] if response.content else "",
        }
        call_results.append(call_result)
        total_tokens += response.tokens_used or 0
        total_latency += latency
        print(f"  Call {i+1}: {'✅' if response.error is None else '❌'} "
              f"latency={latency*1000:.0f}ms tokens={response.tokens_used}")

    # Get policy hash from researcher interface
    try:
        from webpent.llm_researcher.interface import LLMResearcher
        rsch = LLMResearcher(llm_client=provider)
        policy_hash = rsch.get_policy_hash()
    except Exception as e:
        policy_hash = f"unavailable: {str(e)[:80]}"

    # Compute config hash
    config_str = f"{llm_base_url}|{llm_model}|{meta.get('config_hash', '')}"
    config_hash = hashlib.sha256(config_str.encode()).hexdigest()

    # Get redacted telemetry
    telemetry = provider.get_redacted_telemetry()
    usage_stats = provider.get_usage_stats()

    result.update({
        "provider_status": "REAL_API",
        "provider_metadata": {
            "provider_type": meta.get("provider_type"),
            "provider_class": meta.get("provider_class"),
            "model": meta.get("model"),
            "base_url": meta.get("base_url"),
            "api_key_env_var": meta.get("api_key_env_var"),
            "api_key_configured": meta.get("api_key_configured"),
            "api_key_prefix": meta.get("api_key_prefix"),  # First 4 chars only, safe
            "config_hash": config_hash,
            "prompt_version_hash": meta.get("prompt_version_hash"),
            "policy_hash": policy_hash,
        },
        "call_count": len(call_results),
        "successful_calls": sum(1 for c in call_results if c["success"]),
        "total_tokens_used": total_tokens,
        "total_latency_seconds": round(total_latency, 3),
        "avg_latency_seconds": round(total_latency / max(len(call_results), 1), 3),
        "call_results": call_results,
        "usage_stats": usage_stats,
        "redacted_telemetry": telemetry,  # No prompt/response content
        "first_success_evidence": meta.get("first_successful_response_evidence"),
    })

    result["gate_pass"] = (
        result["provider_status"] == "REAL_API" and
        result["successful_calls"] > 0 and
        not is_mock
    )

    out_path = os.path.join(REPORTS, "provider_gate_v184.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"\nProvider status: {result['provider_status']}")
    print(f"Model: {meta.get('model')}")
    print(f"Successful calls: {result['successful_calls']}/{len(call_results)}")
    print(f"Total tokens: {total_tokens}")
    print(f"Gate: {'✅ PASS' if result['gate_pass'] else '❌ FAIL'}")
    print(f"Report: {out_path}")

if __name__ == "__main__":
    run_provider_gate()

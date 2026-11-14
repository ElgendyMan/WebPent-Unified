"""GOED v1.8.4 — Preflight Environment Check
Verifies runtime, repository integrity, manifests, provider configuration, network.
Produces: goed_v1_8_4/preflight.json
"""
import hashlib
import json
import os
import platform
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
def file_hash(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()
def check_file_exists(p):
    full = os.path.join(_ROOT, p) if not p.startswith("/") else p
    return os.path.exists(full)
def run_preflight():
    result = {"phase": "0_preflight", "timestamp": __import__("datetime").datetime.now().isoformat()}

    # 1. Python/runtime versions
    result["runtime"] = {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "executable": sys.executable,
    }

    # 2. Repository integrity (key paths exist)
    repo_checks = {}
    for p in [
        "src/webpent/cqa_v2/causal_guard.py",
        "src/webpent/llm_researcher/interface.py",
        "src/webpent/llm_researcher/causal_feedback_bridge.py",
        "src/webpent/llm_researcher/providers/base.py",
        "src/webpent/llm_researcher/providers/openai_compatible.py",
        "src/webpent/models/proof_bundle.py",
        "benchmarks/blind_v3/manifest.json",
        "benchmarks/differential_v2/differential_target_v2.py",
        "docs/archive/goed-v1.8.3/freeze_manifest.json",
        "docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_MANIFEST.json",
    ]:
        repo_checks[p] = check_file_exists(p)
    result["repository_integrity"] = {
        "all_paths_exist": all(repo_checks.values()),
        "checks": repo_checks,
    }

    # 3. v1.8.3 freeze manifest
    v183_path = os.path.join(_ROOT, "docs/archive/goed-v1.8.3/freeze_manifest.json")
    if os.path.exists(v183_path):
        with open(v183_path) as f:
            v183 = json.load(f)
        result["v183_freeze_manifest"] = {
            "exists": True,
            "self_hash": file_hash(v183_path),
            "freeze_policy": v183.get("freeze_policy", ""),
            "total_artifacts": sum(len(v) for v in v183.get("artifacts", {}).values()),
        }
    else:
        result["v183_freeze_manifest"] = {"exists": False}

    # 4. v1.8.4 freeze manifest
    v184_path = os.path.join(_ROOT, "docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_MANIFEST.json")
    if os.path.exists(v184_path):
        with open(v184_path) as f:
            v184 = json.load(f)
        result["v184_freeze_manifest"] = {
            "exists": True,
            "self_hash": file_hash(v184_path),
            "supersedes_count": v184.get("supersedes", 0),
            "artifacts_count": sum(len(v) for v in v184.get("artifacts", {}).values()),
        }
    else:
        result["v184_freeze_manifest"] = {"exists": False}

    # 5. Freeze provenance & diff
    provenance_path = os.path.join(_ROOT, "docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_PROVENANCE.json")
    diff_path = os.path.join(_ROOT, "docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_DIFF.md")
    result["freeze_provenance_exists"] = os.path.exists(provenance_path)
    result["freeze_diff_exists"] = os.path.exists(diff_path)

    # 6. Provider configuration from environment
    llm_provider = os.environ.get("LLM_PROVIDER", "not_set")
    llm_api_key_set = bool(os.environ.get("LLM_API_KEY", ""))
    llm_base_url = os.environ.get("LLM_BASE_URL", "not_set")
    llm_model = os.environ.get("LLM_MODEL", "not_set")
    llm_api_key_2_set = bool(os.environ.get("LLM_API_KEY_2", ""))

    result["provider_configuration"] = {
        "LLM_PROVIDER": llm_provider,
        "LLM_API_KEY_set": llm_api_key_set,
        "LLM_BASE_URL": llm_base_url,
        "LLM_MODEL": llm_model,
        "LLM_API_KEY_2_set": llm_api_key_2_set,
        "available_provider_slots": 1 + (1 if llm_api_key_2_set else 0),
    }

    # 7. Network reachability & provider test
    network_status = {}
    provider_status = "UNTESTED"

    if llm_api_key_set and llm_provider == "openai_compatible":
        try:
            import httpx
            headers = {"Authorization": f"Bearer {os.environ.get('LLM_API_KEY')}"}
            r = httpx.get(f"{llm_base_url}/models", headers=headers, timeout=10)
            network_status["groq_api_reachable"] = (r.status_code == 200)
            network_status["groq_api_status_code"] = r.status_code
            if r.status_code == 200:
                models = r.json().get("data", [])
                network_status["available_models_count"] = len(models)
                network_status["requested_model_available"] = any(
                    m.get("id") == llm_model for m in models
                )
                provider_status = "REAL_API"

                # Quick test completion
                payload = {
                    "model": llm_model,
                    "messages": [{"role": "user", "content": "Echo: API_READINESS_CHECK"}],
                    "max_tokens": 10
                }
                r2 = httpx.post(f"{llm_base_url}/chat/completions",
                               headers={**headers, "Content-Type": "application/json"},
                               json=payload, timeout=15)
                network_status["test_completion_status"] = r2.status_code
                if r2.status_code == 200:
                    d = r2.json()
                    network_status["test_completion_success"] = True
                    usage = d.get("usage", {})
                    result["provider_metadata"] = {
                        "provider_type": "REAL_API",
                        "provider": "groq_openai_compatible",
                        "model": llm_model,
                        "base_url": llm_base_url,
                        "config_hash": hashlib.sha256(f"{llm_base_url}|{llm_model}".encode()).hexdigest()[:16],
                        "test_tokens_used": usage.get("total_tokens", 0),
                    }
                else:
                    network_status["test_completion_success"] = False
                    network_status["test_completion_error"] = r2.text[:200]
            else:
                network_status["groq_api_error"] = r.text[:200]
                provider_status = "REAL_API_UNAVAILABLE"
        except Exception as e:
            network_status["error"] = str(e)[:200]
            provider_status = "REAL_API_UNAVAILABLE"
    elif not llm_api_key_set:
        provider_status = "REAL_API_UNAVAILABLE"
        network_status["reason"] = "LLM_API_KEY not set"
    else:
        provider_status = "REAL_API_UNAVAILABLE"
        network_status["reason"] = f"LLM_PROVIDER={llm_provider} not recognized as openai_compatible"

    result["network_reachability"] = network_status
    result["provider_status"] = provider_status

    # 8. No credentials in repository check
    import re
    secret_patterns = [
        re.compile(r'sk-[A-Za-z0-9]{20,}'),
        re.compile(r'gsk_[A-Za-z0-9]{20,}'),
        re.compile(r'AIzaSy[A-Za-z0-9_-]{20,}'),
        re.compile(r'ghp_[A-Za-z0-9]{20,}'),
    ]
    secrets_found = []
    scan_dirs = ["src", "goed_v1_8_4", "docs", "benchmarks"]
    for scan_dir in scan_dirs:
        full_dir = os.path.join(_ROOT, scan_dir)
        for root, dirs, files in os.walk(full_dir):
            # Skip pycache
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for fname in files:
                if fname.endswith(('.pyc', '.zip', '.json')):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, errors='ignore') as f:
                        content = f.read()
                    for pat in secret_patterns:
                        matches = pat.findall(content)
                        for m in matches:
                            # Filter out known placeholders/test strings
                            if 'PLACEHOLDER' in m.upper() or 'EXAMPLE' in m.upper() or len(m) < 25:
                                continue
                            rel = os.path.relpath(fpath, _ROOT)
                            secrets_found.append({"file": rel, "pattern": pat.pattern[:30]})
                except Exception:
                    pass

    result["credential_scan"] = {
        "files_scanned_dirs": scan_dirs,
        "secrets_found_count": len(secrets_found),
        "secrets_found": secrets_found[:10],  # First 10 only
        "no_credentials_in_repo": len(secrets_found) == 0,
    }

    # 9. Overall status
    result["overall_status"] = "OK" if (
        result["repository_integrity"]["all_paths_exist"] and
        provider_status == "REAL_API" and
        result["credential_scan"]["no_credentials_in_repo"]
    ) else ("PARTIAL" if provider_status == "REAL_API" else "REAL_API_UNAVAILABLE")

    return result

if __name__ == "__main__":
    result = run_preflight()
    out_path = os.path.join(_ROOT, "reports", "goed_v1_8_4", "preflight.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"Preflight written to: {out_path}")
    print(f"Provider status: {result['provider_status']}")
    print(f"Overall: {result['overall_status']}")
    if result.get("provider_metadata"):
        pm = result["provider_metadata"]
        print(f"Model: {pm['model']}, config_hash: {pm['config_hash']}")

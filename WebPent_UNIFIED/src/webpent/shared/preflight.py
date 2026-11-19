"""webpent.shared.preflight

V10 P0-1 (RCA follow-up): startup capability preflight.

Audits across multiple review rounds flagged that worker boot silently
normalised "Alembic missing" + "WebSocket SSRF unmitigated" + "embeddings
network hang" + "insecure CELERY_PAYLOAD_KEY" as quiet success without
operator-visible capability status. This module provides a single
:func:`run_preflight` function that the API and worker call at startup.
Capability checks may report an explicit degraded state where the selected
profile permits it, but unsafe staging/production posture and unexpected
preflight errors fail closed before the service accepts work.

The report covers:
  1. Alembic — is the migration tooling importable + alembic.ini present?
  2. Playwright WebSocket SSRF guard — does the installed Playwright
     version support ``route_web_socket()`` (>=1.48)? If not, the WS
     SSRF bypass is UNMITIGATED and the operator must know.
  3. Embeddings — is the RAG embedding model loadable offline, or is
     EMBEDDINGS_OFFLINE/DISABLE_RAG set (see webpent.memory.embeddings)?
  4. CELERY_PAYLOAD_KEY — is the broker credential-encryption key a
     strong custom value, or the insecure dev default?

Usage (API/worker startup):
    from webpent.shared.preflight import run_preflight
    run_preflight()
"""

from __future__ import annotations

import importlib.metadata
import logging
import os
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _check_alembic() -> dict[str, object]:
    """Check whether Alembic migration tooling is available."""
    try:
        from pathlib import Path

        import alembic

        # alembic.ini lives at the project root (next to pyproject.toml).
        # The path is relative to this file: ../../../../alembic.ini
        # (src/webpent/shared/preflight.py -> src/webpent/shared ->
        #  src/webpent -> src -> project root).
        ini_path = Path(__file__).resolve().parents[4] / "alembic.ini"
        ini_present = ini_path.exists()
        return {
            "available": True,
            "version": getattr(alembic, "__version__", "unknown"),
            "ini_present": ini_present,
            "status": "ok" if ini_present else "degraded (alembic.ini missing)",
        }
    except ImportError as exc:
        return {
            "available": False,
            "status": f"degraded (alembic not importable: {exc})",
        }


def _check_playwright_ws_guard() -> dict[str, object]:
    """Check whether Playwright supports route_web_socket() (>=1.48).

    The pyproject.toml pins playwright>=1.40.0,<1.41, which does NOT
    support route_web_socket() (added in 1.48). The HTTP SSRF guard
    works on all versions, but the WebSocket SSRF guard is unavailable
    on <1.48 — a malicious page could open a WebSocket to an internal
    host and bypass the HTTP guard entirely.

    This check does NOT block startup — it makes the residual risk
    visible so the operator knows the WS bypass is unmitigated.
    """
    try:
        import playwright

        version = getattr(playwright, "__version__", None)
        if not version:
            try:
                version = importlib.metadata.version("playwright")
            except importlib.metadata.PackageNotFoundError:
                version = "unknown"
        # route_web_socket was added in Playwright 1.48. Parse the
        # major.minor to determine availability.
        try:
            parts = version.split(".")
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            supports_ws_guard = (major > 1) or (major == 1 and minor >= 48)
        except (ValueError, IndexError):
            supports_ws_guard = False
        return {
            "version": version,
            "ws_guard_available": supports_ws_guard,
            "status": (
                "ok (WebSocket SSRF guard active)"
                if supports_ws_guard
                else "DEGRADED — WebSocket SSRF bypass UNMITIGATED "
                "(upgrade Playwright to >=1.48 to enable)"
            ),
        }
    except ImportError:
        return {
            "version": None,
            "ws_guard_available": False,
            "status": "degraded (playwright not installed — browser exploitation unavailable)",
        }


def _check_embeddings() -> dict[str, object]:
    """Check whether the RAG embedding model is loadable offline."""
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        # V10 P0-2: EMBEDDINGS_OFFLINE / DISABLE_RAG switches.
        if getattr(settings, "disable_rag", False):
            return {
                "mode": "disabled (DISABLE_RAG=true)",
                "status": "ok — RAG explicitly disabled, no HF network access",
            }
        if getattr(settings, "embeddings_offline", False):
            return {
                "mode": "offline (EMBEDDINGS_OFFLINE=true)",
                "status": "ok — embeddings will use cache only; first-run download skipped",
            }
        # Check whether the model is already cached locally.
        from pathlib import Path

        cache_dir = Path.home() / ".cache" / "huggingface"
        cache_present = cache_dir.exists() and any(cache_dir.iterdir())
        return {
            "mode": "online (first-run may download ~80MB from huggingface.co)",
            "cache_present": cache_present,
            "status": (
                "ok — model cached locally, no network needed"
                if cache_present
                else "degraded — model NOT cached; first RAG query will "
                "hit huggingface.co (set EMBEDDINGS_OFFLINE=true to "
                "skip, or pre-populate the cache)"
            ),
        }
    except Exception as exc:
        return {
            "mode": "unknown",
            "status": f"degraded (preflight check failed: {exc})",
        }


def _check_knowledge_ready() -> dict[str, object]:
    """TEAM-1 Phase 7: expose ``knowledge_ready`` operational posture.

    Reports whether the shipped offline knowledge pack is complete and
    whether retrieval is actually operational (store populated). This is
    an ADVISORY check: knowledge/RAG is guidance-only and never
    authoritative, so a not-ready result degrades candidate quality — it
    must not block startup or scans.
    """
    report: dict[str, object] = {}
    try:
        from pathlib import Path

        import yaml

        # R-06 (TEAM-2 residual fix): the pack root must be the PROJECT root,
        # not ``src/``. The original ``parents[2]`` anchor resolved to
        # ``<repo>/src/knowledge_pack`` in the canonical src layout, so the
        # manifest was never found and knowledge_ready was permanently a
        # false "degraded — manifest missing". Walk upward from this file
        # instead so the check works for the src layout, editable installs,
        # and wheel layouts alike.
        project_root: Path | None = None
        here = Path(__file__).resolve()
        for candidate in here.parents:
            if (candidate / "knowledge_pack" / "manifest.yaml").is_file():
                project_root = candidate
                break
        if project_root is None:
            return {
                "knowledge_ready": False,
                "status": "degraded — knowledge_pack/manifest.yaml missing",
            }
        manifest_path = project_root / "knowledge_pack" / "manifest.yaml"
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        sources = manifest.get("sources") or []
        missing = []
        for source in sources:
            if not isinstance(source, dict):
                continue
            rel = str(source.get("path") or "").strip()
            if not rel:
                continue
            if not (project_root / "knowledge_pack" / rel).is_file():
                missing.append(rel)
        report["pack_sources"] = len(sources)
        if missing:
            report["knowledge_ready"] = False
            report["missing_files"] = missing[:10]
            report["status"] = "degraded — shipped knowledge pack incomplete"
            return report

        # Probe retrieval only when a vector store can actually answer.
        # TC-4 C1(b) F841 fix: the local ``manager`` binding was assigned
        # but never used — ``retrieve_knowledge_context`` resolves the
        # vector-store manager internally (knowledge_retrieval.py), so the
        # redundant local initialization (and its now-dead import) is
        # removed.  Behavior is unchanged: the probe remains fail-closed.
        from webpent.shared.knowledge_retrieval import retrieve_knowledge_context
        probe = retrieve_knowledge_context(
            "authorized lab web application testing methodology",
            doc_types=("methodology", "scenario"),
            per_type_k=1,
            max_chars=400,
        )
        populated = bool(probe.strip())
        report["store_populated"] = populated
        report["knowledge_ready"] = populated
        report["status"] = (
            "ok — knowledge pack present and retrieval operational"
            if populated
            else (
                "not_ingested — pack shipped but vector store empty; run "
                "PYTHONPATH=src python scripts/ingest_payloads.py "
                "--manifest knowledge_pack/manifest.yaml"
            )
        )
        return report
    except Exception as exc:
        # Non-blocking by design: RAG is advisory-only, never authoritative.
        return {
            "knowledge_ready": False,
            "status": f"degraded (knowledge check failed: {type(exc).__name__})",
        }


def _check_celery_payload_key() -> dict[str, object]:
    """Check whether the Celery broker credential-encryption key is strong."""
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        key = settings.celery_payload_key
        is_default = key in getattr(settings, "_INSECURE_CELERY_PAYLOAD_DEFAULTS", set())
        is_short = len(key) < 32
        if settings.auth_enabled and is_default:
            return {
                "posture": "INSECURE (prod with default key — Settings() should have raised)",
                "status": "FAIL — auth_enabled=True with default CELERY_PAYLOAD_KEY",
            }
        if is_default:
            return {
                "posture": "dev default (acceptable for local lab)",
                "status": "ok for dev — set CELERY_PAYLOAD_KEY for any non-local deployment",
            }
        if is_short:
            return {
                "posture": f"too short ({len(key)} chars, need >=32)",
                "status": "FAIL — CELERY_PAYLOAD_KEY too short",
            }
        return {
            "posture": "strong custom key",
            "status": "ok — broker credentials encrypted with strong key",
        }
    except Exception as exc:
        return {
            "posture": "unknown",
            "status": f"degraded (preflight check failed: {exc})",
        }


def _check_llm_providers() -> dict[str, object]:
    """Report configured LLM providers and usable fallback chains without API calls."""
    try:
        from webpent.config.settings import get_settings
        from webpent.shared.llm import (
            _OPENAI_COMPATIBLE_BASE_URLS,
            _TASK_PREFERENCE_ORDER,
            TaskType,
            _api_key_for_provider,
            _resolve_model_name,
            get_dead_providers,
            is_llm_enabled,
        )

        settings = get_settings()
        configured: dict[str, bool] = {}
        for chain in _TASK_PREFERENCE_ORDER.values():
            for provider, _model in chain:
                configured[provider] = bool(_api_key_for_provider(provider, settings))
        available = sorted(name for name, ready in configured.items() if ready)
        chains: dict[str, list[str]] = {}
        endpoints: dict[str, str] = {}
        for task in TaskType:
            chains[task.value] = [
                f"{provider}:{_resolve_model_name(provider, model, settings)}"
                for provider, model in _TASK_PREFERENCE_ORDER[task]
                if configured.get(provider, False)
            ]
        for provider in available:
            if provider == "openai":
                endpoints[provider] = settings.openai_base_url
            elif provider == "local":
                endpoints[provider] = settings.local_llm_url
            else:
                endpoints[provider] = _OPENAI_COMPATIBLE_BASE_URLS.get(
                    provider, "provider-sdk-managed"
                )
        enabled = is_llm_enabled(settings)
        dead = sorted(get_dead_providers())
        return {
            "enabled": enabled,
            "configured_providers": available,
            "configured_count": len(available),
            "dead_providers": dead,
            "fallback_chains": chains,
            "effective_endpoints": endpoints,
            "status": (
                "disabled — deterministic fallbacks active"
                if not enabled
                else "ok — at least one configured provider"
                if available
                else "degraded — no configured provider; deterministic fallbacks only"
            ),
        }
    except Exception as exc:
        return {
            "enabled": False,
            "configured_providers": [],
            "configured_count": 0,
            "dead_providers": [],
            "fallback_chains": {},
            "effective_endpoints": {},
            "status": f"degraded (LLM diagnostics failed: {type(exc).__name__})",
        }


def _is_nonlocal_bind(host: str | None) -> bool:
    """True when the bind host reaches beyond this machine
    (R4-01 classifier).

    Empty/unknown inputs stay LOCAL (the startup boundary passes the
    bind host only when it is actually known), loopback stays local
    (127.0.0.0/8 and ::1), and every wildcard, private-range,
    public or hostname bind is non-local: a LAN peer is a third
    party for the purposes of the strict key guard.

    UNIFIED MERGE (2026-11-02, Phase 2): restored with the R4-01
    posture contract (tests/test_r4_production_hardening.py).
    """
    normalized = (host or "").strip().lower()
    if not normalized:
        return False
    if normalized in {"localhost", "lo", "local"}:
        return False
    if normalized in {"::1", "[::1]"}:
        return False
    if normalized in {"::", "0:0:0:0:0:0:0:0"}:
        return True
    if ":" in normalized:
        # other IPv6 literals: not the loopback pair, so non-local
        return True
    import re as _re

    m = _re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$",
                  normalized)
    if m:
        octets = [int(group) for group in m.groups()]
        if any(octet > 255 for octet in octets):
            return True
        if octets[0] == 127:
            return False
        return True
    return True


def _truthy_env(name: str) -> bool:
    """Return whether an environment switch is explicitly enabled."""
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _redis_posture(url: str, *, name: str) -> dict[str, object]:
    """Describe Redis transport and whether the URL has an ACL identity."""
    if not url:
        return {"configured": False, "status": "not configured"}
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    secure = scheme == "rediss"
    has_password = bool(parsed.password)
    has_username = bool(parsed.username)
    return {
        "configured": True,
        "scheme": scheme,
        "tls": secure,
        "acl_identity_present": has_username or has_password,
        "status": (
            "ok — TLS transport enabled"
            if secure
            else f"DEGRADED — {name} uses plaintext Redis transport"
        ),
    }


def _check_redis_security() -> dict[str, object]:
    """Check broker and rate-limit Redis URLs without making a network call."""
    broker_url = os.getenv("WEBPENT_REDIS_URL", "redis://localhost:6379/0")
    rate_url = os.getenv("WEBPENT_RATE_LIMIT_REDIS_URL", "")
    broker = _redis_posture(broker_url, name="Celery broker")
    rate_limit = _redis_posture(rate_url, name="rate limiter")
    insecure = any(item.get("configured") and not item.get("tls") for item in (broker, rate_limit))
    return {
        "status": (
            "DEGRADED — plaintext Redis transport detected"
            if insecure
            else "ok — Redis transport posture is acceptable"
        ),
        "broker": broker,
        "rate_limit": rate_limit,
    }


def _enforce_redis_security(report: dict[str, dict[str, object]]) -> None:
    """Require TLS for Redis whenever authentication or strict profile is enabled."""
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        auth_enabled = settings.auth_enabled
        profile = getattr(getattr(settings, "environment_profile", None), "value", "lab")
    except Exception as exc:
        raise SystemExit("Preflight blocked startup: Redis security posture is unknown") from exc
    strict_profile = profile in {"staging", "production"}
    if not auth_enabled and not strict_profile:
        return
    if _truthy_env("WEBPENT_ALLOW_PLAINTEXT_REDIS") and not strict_profile:
        return
    broker = report["redis_security"]["broker"]
    rate_limit = report["redis_security"]["rate_limit"]
    insecure = any(item.get("configured") and not item.get("tls") for item in (broker, rate_limit))
    if insecure:
        raise SystemExit(
            "Preflight blocked startup: authenticated/staging/production deployments "
            "require rediss:// for Redis broker and rate limiter "
            "(plaintext is lab-only)"
        )


def _enforce_api_security_posture(
    *,
    host: str | None,
    report: dict[str, dict[str, object]],
) -> None:
    """Fail closed for unsafe non-local bind configurations (R4-01).

    ``run_preflight()`` is also used by unit tests and local library imports,
    so the bind host is deliberately an explicit input. API/worker startup
    passes ``WEBPENT_API_HOST`` when the process bind address is known.

    Posture, in order:
      1. staging/production profiles require authentication — even on
         loopback (the profile is the operator's own declaration);
      2. loopback/unknown binds keep working in dev (no gate);
      3. any non-local bind with auth disabled refuses boot, unless the
         documented ``I_UNDERSTAND_THIS_IS_INSECURE`` override is set
         (recorded loudly in the report and the log);
      4. any non-local bind with authentication on but insecure default
         secrets (JWT/audit/celery keys shorter than 32 chars) refuses
         boot and names the offending variables;
      5. non-local bind with operator keys and auth on passes cleanly.

    UNIFIED MERGE (2026-11-02, Phase 2): strict-key semantics restored
    per tests/test_r4_production_hardening.py (TestStrictKeyGuard).
    """
    normalized_host = (host or "").strip().lower()
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        profile = getattr(
            getattr(settings, "environment_profile", None), "value", "lab"
        )
        strict_profile = profile in {"staging", "production"}
        if strict_profile and not getattr(settings, "auth_enabled", False):
            raise SystemExit(
                "Preflight blocked startup: staging/production requires authentication"
            )
    except SystemExit:
        raise
    except Exception as exc:
        # A failed settings read must not turn this gate into an
        # accidental bypass on any bind that reaches beyond this
        # machine.
        if _is_nonlocal_bind(normalized_host):
            raise SystemExit(
                "Preflight blocked startup: security settings could not be evaluated "
                "for a non-local bind"
            ) from exc
        return

    if not _is_nonlocal_bind(normalized_host):
        return

    auth_enabled = bool(getattr(settings, "auth_enabled", False))
    if not auth_enabled:
        if _truthy_env("I_UNDERSTAND_THIS_IS_INSECURE"):
            report["api_security_posture"] = {
                "host": normalized_host,
                "status": "OVERRIDDEN — insecure non-local bind explicitly acknowledged",
            }
            logger.critical(
                "[preflight] INSECURE OVERRIDE: non-local bind with auth "
                "disabled; the operator explicitly acknowledged the risk."
            )
            return
        raise SystemExit(
            f"Preflight blocked startup: unsafe {normalized_host} bind — "
            "non-local bind with auth disabled; loopback-only development "
            "binds stay available"
        )

    insecure_keys = []
    for attr, label in (
        ("jwt_secret_key", "JWT_SECRET_KEY"),
        ("audit_secret_key", "AUDIT_SECRET_KEY"),
        ("celery_payload_key", "CELERY_PAYLOAD_KEY"),
    ):
        value = getattr(settings, attr, "") or ""
        if len(str(value)) < 32:
            insecure_keys.append(label)
    if insecure_keys:
        raise SystemExit(
            "Preflight blocked startup: insecure default secret(s) on a "
            f"non-local bind: {', '.join(insecure_keys)} — set operator "
            "keys (32+ chars) before exposing the service beyond loopback"
        )

def _profile_security_posture() -> dict[str, object]:
    """Describe and enforce deployment-profile security invariants."""
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        profile = getattr(getattr(settings, "environment_profile", None), "value", "lab")
        if profile not in {"qualification", "staging", "production"}:
            return {
                "profile": profile,
                "status": "ok — local security defaults preserved",
                "fail_closed": True,
            }

        failures: list[str] = []
        if not getattr(settings, "auth_enabled", False):
            failures.append("authentication is disabled")
        cors_origins = list(getattr(settings, "cors_origins", []) or [])
        if not cors_origins or "*" in cors_origins:
            failures.append("CORS origins must be explicit")
        if not getattr(settings, "rate_limit_enabled", False):
            failures.append("rate limiting is disabled")
        if failures:
            return {
                "profile": profile,
                "status": "FAIL — " + "; ".join(failures),
                "failures": failures,
                "fail_closed": True,
            }
        return {
            "profile": profile,
            "status": "ok — strict security defaults satisfied",
            "fail_closed": True,
        }
    except Exception as exc:
        return {
            "profile": "unknown",
            "status": "unknown — security profile could not be evaluated",
            "reason": type(exc).__name__,
            "fail_closed": True,
        }


def _enforce_profile_security(report: dict[str, dict[str, object]]) -> None:
    """Stop startup when strict deployment security invariants are not met."""
    posture = report["profile_security"]
    status = str(posture.get("status", "unknown"))
    if status.startswith("FAIL") or status.startswith("unknown"):
        raise SystemExit(f"Preflight blocked startup: {status}")


def _posture_state(report: dict[str, dict[str, object]], profile: str) -> dict[str, object]:
    """Project individual checks into a fail-closed startup posture."""
    statuses = [str(info.get("status", "unknown")).lower() for info in report.values()]
    if any("unknown" in status for status in statuses):
        state = "UNKNOWN"
    elif any(
        status.startswith("fail")
        or "unmitigated" in status
        or "blocked startup" in status
        for status in statuses
    ):
        state = "BLOCKED"
    elif any(
        token in status
        for status in statuses
        for token in ("degraded", "disabled", "not configured")
    ):
        state = (
            "DEGRADED"
            if profile in {"qualification", "staging", "production"}
            else "READY_WITH_WARNING"
        )
    else:
        state = "PASS"
    return {
        "profile": profile,
        "state": state,
        "status": state,
        "allowed_to_start": state in {"PASS", "READY_WITH_WARNING", "DEGRADED"},
        "fail_closed": True,
    }


def _check_construction_escape() -> dict[str, object]:
    """Sprint I-1, item 1.3: WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_
    TEST_ONLY (see webpent.production.modern_spine._TEST_ESCAPE_ENV) lets
    test code construct ModernOrchestrator directly, bypassing
    resolve_production_spine(). It must never be honored in a
    qualification/staging/production deployment. Modeled on
    _profile_security_posture()'s fail-closed idiom above.
    """
    escape_var = "WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY"
    escape_set = os.environ.get(escape_var) == "1"
    # Read environment_profile's env-var aliases directly instead of going
    # through get_settings(). This check must stay effective even when
    # OTHER, unrelated Settings hard-stops (auth_enabled/cors_origins/
    # rate_limit_enabled/TLS) would raise before Settings() returns —
    # catching that and falling back to "unknown" (-> not strict) would
    # fail OPEN on exactly the strict deployments this gate protects.
    # Fail-closed by design: if ANY of the three aliases indicates a
    # strict posture, this reports strict, regardless of which one
    # pydantic-settings itself would treat as authoritative.
    strict_values = {"qualification", "staging", "production"}
    seen_values = [
        os.environ[var].strip().lower()
        for var in ("WEBPENT_ENVIRONMENT_PROFILE", "ENVIRONMENT_PROFILE", "environment_profile")
        if os.environ.get(var)
    ]
    strict = any(v in strict_values for v in seen_values)
    profile = seen_values[0] if seen_values else "lab"
    if escape_set and strict:
        return {
            "escape_var": escape_var,
            "profile": profile,
            "status": (
                f"FAIL — {escape_var}=1 is not permitted when "
                f"environment_profile={profile!r}"
            ),
            "fail_closed": True,
        }
    if escape_set:
        # Escape is honored (non-strict profile) — audit-trailed, not
        # silent. A dedicated per-engagement audit chain (Sprint I-1,
        # Part 3.2) does not exist yet; this logs via the same channel
        # every other preflight capability line uses below, prefixed
        # AUDIT so it is grep-able independently of routine [preflight]
        # capability lines.
        logger.warning(
            "AUDIT: construction_escape_honored env_var=%s environment_profile=%s",
            escape_var, profile,
        )
        return {
            "escape_var": escape_var,
            "profile": profile,
            "status": f"ok — escape honored in non-strict profile {profile!r} (audit-logged)",
            "fail_closed": True,
        }
    return {
        "escape_var": escape_var,
        "profile": profile,
        "status": "ok — escape not set",
        "fail_closed": True,
    }


def _enforce_construction_escape(report: dict[str, dict[str, object]]) -> None:
    """Stop startup when the test-only construction escape is honored in a
    strict (qualification/staging/production) deployment posture."""
    status = str(report["construction_escape"].get("status", "unknown"))
    if status.startswith("FAIL"):
        raise SystemExit(f"Preflight blocked startup: {status}")


def enforce_construction_escape_gate() -> dict[str, object]:
    """Sprint I-1, item 1.3: standalone, narrow-scope startup gate for
    entrypoints that must NOT pull in the full run_preflight() suite.

    webpent.cli.commands.main() and webpent.production.campaign_worker.main()
    call this directly: routing them through the full run_preflight() would
    additionally force Alembic/Playwright-WS/embeddings/Celery/Redis checks
    that are unrelated to this gate and are not safe or meaningful to
    enforce on every CLI invocation or every campaign_worker subprocess
    cycle (out of scope for Sprint I-1 item 1.3; would be a drive-by
    behavior change to those two entrypoints).

    The API and Celery-worker entrypoints do not need a separate call —
    they already call run_startup_preflight() at process startup (api/app.py,
    workers/pentest_worker.py), and run_preflight() below calls this same
    check as part of that existing report.
    """
    check = _check_construction_escape()
    _enforce_construction_escape({"construction_escape": check})
    return check


def run_preflight(host: str | None = None) -> dict[str, dict[str, object]]:
    """Emit the capability report and enforce public-bind security posture.

    ``host`` is explicit so importing the module or running local unit tests
    does not guess a network bind address. Production API/worker entrypoints
    pass ``WEBPENT_API_HOST``. When that value is ``0.0.0.0``, the unsafe
    quartet (auth disabled + wildcard CORS + rate limiting disabled) raises
    ``SystemExit`` unless the operator explicitly sets
    ``I_UNDERSTAND_THIS_IS_INSECURE=true``.
    """
    report = {
        "alembic": _check_alembic(),
        "playwright_ws_guard": _check_playwright_ws_guard(),
        "embeddings": _check_embeddings(),
        "knowledge_ready": _check_knowledge_ready(),
        "celery_payload_key": _check_celery_payload_key(),
        "redis_security": _check_redis_security(),
        "llm": _check_llm_providers(),
        "profile_security": _profile_security_posture(),
        "construction_escape": _check_construction_escape(),
    }
    try:
        from webpent.shared.capability_manifest import build_capability_manifest

        manifest = build_capability_manifest()
        manifest["status"] = "degraded" if manifest.get("blockers") else "ok"
        report["capability_manifest"] = manifest
    except Exception as exc:
        # Capability reporting must never become an accidental authorization
        # bypass. A malformed or unavailable manifest is an explicit blocker.
        report["capability_manifest"] = {
            "status": "degraded",
            "profile": "unknown",
            "capabilities": {},
            "blockers": [{"capability": "manifest", "reason": type(exc).__name__}],
            "fail_closed": True,
        }
    try:
        from webpent.config.settings import get_settings

        profile = getattr(get_settings().environment_profile, "value", "unknown")
    except Exception:
        profile = "unknown"
    report["posture"] = _posture_state(report, profile)
    _enforce_profile_security(report)
    _enforce_redis_security(report)
    _enforce_api_security_posture(host=host, report=report)
    _enforce_construction_escape(report)
    # Emit one INFO line per capability so the operator sees the full
    # posture at boot. Each line is prefixed with "[preflight]" for
    # easy grep.
    for name, info in report.items():
        status = info.get("status", "unknown")
        logger.info("[preflight] %s: %s", name, status)
    return report


def run_startup_preflight(*, host: str | None = None) -> dict[str, dict[str, object]]:
    """Run the startup gate and fail closed on unexpected evaluation errors.

    Explicit posture failures already raise ``SystemExit`` from
    :func:`run_preflight`. This wrapper handles only unexpected exceptions so
    every production entrypoint applies the same policy and log message.
    """
    try:
        return run_preflight(host=host)
    except Exception as exc:
        logger.critical(
            "preflight failed unexpectedly at startup; refusing to continue: %s",
            exc,
        )
        raise

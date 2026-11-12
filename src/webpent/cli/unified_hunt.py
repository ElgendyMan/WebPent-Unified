# src/webpent/cli/unified_hunt.py
"""The unified hunt engine — one command, three modes.

Ultimate plan 2026-10-27, proposal 1 (Engine Unification) + 12 (output
clarity):

``webpent hunt --url <target> --mode quick|standard|deep --authorization <ref>``

This is the single recommended entry point. It runs the production
LangGraph engine (the deep, mature pipeline — 80+ nodes) with:

* mode presets (``state/unified_state.py``) mapping quick/standard/deep
  to documented time/request/cost/hypothesis ceilings,
* the closed learning loop active by default (lessons consulted after
  planning, extracted at reflection — proposal 3),
* the dynamic step budget (surface sized after crawling, governor
  reserves scale proportionally — proposal 2),
* a live progress view + instant CONFIRMED-finding lines (proposal 12),
* the retired legacy aliases (``scan``, ``hunt-auto``, the planner-shaped
  old ``hunt``) were REMOVED in the v0.32.0 window (declared 2026-11-01,
  item ج.2 of the 0.30.0 CHANGELOG) — this command is the one CLI entry
  point. The bounded hunter itself lives on as the ``webpent.autonomous``
  library API.

Implementation notes:

* The engine re-uses the production graph-construction path
  (``build_graph`` + ``build_initial_state``) — no second engine, no
  forked wiring. The unification is at the ENTRY POINT and the BUDGET
  layer, which is where the fragmentation actually lived.
* ``--authorization`` is REQUIRED (non-empty string). The unified
  command refuses to start without it — same posture the hunter family
  already enforced.
* The recursion limit is set ABOVE the governor's budget ceiling
  (hard limit > soft budget by construction), so convergence is always
  the governor's completion cutoff, never a raw GraphRecursionError.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from webpent.state.unified_state import resolve_hunt_mode

try:
    # R2-graph-04: the checkpointer's real home is webpent.graph.checkpoints.
    # The old shared-layer path never existed, so the ImportError was
    # swallowed and every HITL run silently lost its checkpointer,
    # truncating after the first interrupt.
    from webpent.graph.checkpoints import get_checkpointer
except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
    get_checkpointer = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

__all__ = [
    "run_unified_hunt",
    "validate_authorization",
    "recursion_limit_for_mode",
]

#: Hard-limit headroom above the soft budget: enough for the
#: completion-reserve tail (>= 19 documented) plus margin, so the
#: governor's cutoff — not LangGraph's recursion guard — ends the run.
_RECURSION_HEADROOM = 60


def _validate_authorization_manifest(
    target_url: str, manifest_path: str | None, authorization_ref: str
) -> dict[str, Any] | None:
    """M2-A: the structured, tamper-evident authorization gate.

    When ``--authorization-manifest`` is supplied the run may only start
    under a verified manifest: digest re-verified, validity window
    checked, target origin covered, and the free-text ``--authorization``
    pointer must EQUAL the manifest's ``authorization_reference``. Every
    refusal raises before any state is built or any request is planned.
    """
    if not manifest_path:
        return None
    from webpent.models.authorization import require_authorization_manifest

    manifest, decision = require_authorization_manifest(
        target_url,
        manifest_path,
        authorization_reference=authorization_ref,
    )
    return {
        "manifest_sha256": decision.manifest_sha256,
        "engagement_id": manifest.engagement_id,
        "client_id": manifest.client_id,
        "operator": manifest.operator,
        "authorized_origins": list(manifest.authorized_origins),
        "excluded_hosts": list(manifest.excluded_hosts),
        "expires_at": manifest.expires_at.isoformat() if manifest.expires_at else None,
    }


def _resolve_scope_file(
    target_url: str, scope_file_path: str | None
) -> dict[str, Any] | None:
    """M2-A: parse the optional scope file and fail-closed check the target.

    Reuses the worker path's exact parser (:mod:`webpent.shared.scope_file`)
    so the CLI and the API worker enforce the SAME grammar: the target URL
    must be covered by an allow entry, not excluded, and not under an
    excluded path — otherwise the run refuses with the precise error code.
    """
    if not scope_file_path:
        return None
    from pathlib import Path as _Path

    from webpent.shared.scope_file import parse_scope_file, target_scope_error

    path = _Path(scope_file_path)
    if not path.is_file():
        raise ValueError(f"scope file not found: {path}")
    try:
        spec = parse_scope_file(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"scope file unreadable: {path} ({exc})") from exc
    error_code = target_scope_error(spec, target_url)
    if error_code is not None:
        raise ValueError(
            f"target is outside the supplied scope file: {error_code} "
            f"(scope fingerprint {spec.fingerprint[:12]})"
        )
    return spec.as_dict()


def validate_authorization(authorization: str | None) -> str:
    """The unified command's mandatory authorization contract."""
    value = (authorization or "").strip()
    if not value:
        raise ValueError(
            "--authorization مطلوب لأمر hunt الموحد: مرّر مرجع التصريح "
            "الكتابي باختبار هذا الهدف (مثال: --authorization 'bug-bounty-2026-NNN'). "
            "WebPent يعمل فقط على أهداف مصرَّح لك باختبارها."
        )
    return value


def recursion_limit_for_mode(mode: str | None) -> int:
    """LangGraph recursion_limit per mode (hard limit > soft budget).

    * quick   — flat ceiling + headroom (the cost clamp keeps the soft
      budget at the flat 50 for quick passes).
    * standard — 200 + headroom (soft budget lands at ~200 for a
      mid-size surface: 50 + 150 surface units).
    * deep    — dynamic_step_budget_cap (400) + headroom; the sizing
      node derives the soft budget, the governor converges the run.
    """
    preset = resolve_hunt_mode(mode)
    soft = {
        "quick": 50,
        "standard": 200,
        "deep": 400,
    }[preset["mode"]]
    try:
        from webpent.config.settings import get_settings

        cap = int(get_settings().dynamic_step_budget_cap)
        if preset["mode"] == "deep":
            soft = cap
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        pass
    return soft + _RECURSION_HEADROOM


def _resolve_checkpointer_for_run(auto_approve: bool, get_checkpointer_fn):
    """Resolve the checkpointer for one run (R2-graph-04, fail-loud).

    HITL mode (auto_approve=False) compiles the graph with
    ``interrupt_before`` and is useless — and silently truncating —
    without a checkpointer: the run stops at the first interrupt and can
    never resume, so a missing checkpointer must stop the run here,
    loudly, instead of after ``payload_generator``.
    """
    checkpointer_ctx = get_checkpointer_fn() if get_checkpointer_fn else None
    if checkpointer_ctx is None and not auto_approve:
        raise RuntimeError(
            "HITL mode (auto_approve=False) requires a LangGraph checkpointer; "
            "install langgraph + langgraph-checkpoint-sqlite or run with "
            "--auto-approve"
        )
    return checkpointer_ctx


def run_unified_hunt(
    *,
    url: str,
    mode: str | None,
    authorization: str,
    client_id: str | None = None,
    engagement_id: str | None = None,
    thread_id: str | None = None,
    auto_approve: bool = False,
    no_llm: bool = False,
    creds: str | None = None,
    cookies: str | None = None,
    report_format: str | None = None,
    progress: bool = True,
    run_graph: bool = True,
    authorization_manifest: str | None = None,
    scope_file: str | None = None,
    max_tokens: int | None = None,
) -> dict[str, Any]:
    """Execute one unified hunt campaign. Returns a summary dict.

    This function is the programmatic core behind the ``webpent hunt``
    CLI command — separated from the CLI layer so tests and the API can
    drive the unified engine without a Typer context. When
    ``run_graph=False`` the function performs every validation and
    preset-resolution step and returns the would-be invocation summary
    WITHOUT invoking the graph (used by ``webpent init``'s command
    preview and by unit tests).

    M2 gates (both fail-closed BEFORE the early return, so even the
    preview refuses an unauthorized or out-of-scope invocation):

    * ``authorization_manifest`` — structured, tamper-evident manifest
      (``models/authorization.py``); the free-text ``--authorization``
      value must equal the manifest's ``authorization_reference``.
    * ``scope_file`` — the worker-path scope grammar; the target must be
      covered by an allow entry and not excluded.
    """
    authorization_ref = validate_authorization(authorization)
    preset = resolve_hunt_mode(mode)
    preset["authorization"] = authorization_ref

    manifest_projection = _validate_authorization_manifest(
        url, authorization_manifest, authorization_ref
    )
    scope_declaration = _resolve_scope_file(url, scope_file)

    summary: dict[str, Any] = {
        "url": url,
        "mode": preset["mode"],
        "authorization": authorization_ref,
        "time_budget_s": preset["time_budget_s"],
        "request_budget": preset["request_budget"],
        "llm_budget_usd": preset["llm_budget_usd"],
        "max_hypotheses": preset["max_hypotheses"],
        "recursion_limit": recursion_limit_for_mode(mode),
        "engine": "unified_hunt",
        "graph_invoked": False,
    }
    if manifest_projection is not None:
        summary["authorization_manifest"] = manifest_projection
    if scope_declaration is not None:
        summary["scope"] = {
            "source": "scope_file",
            "allow_entry_count": len(scope_declaration.get("allow_entries") or ()),
            "fingerprint": scope_declaration.get("fingerprint"),
        }
    if not run_graph:
        return summary

    # Heavy imports stay local so `webpent init`'s preview path (and
    # tests) never pay the graph-construction import cost.
    from uuid import uuid4

    from webpent.cli.commands import _parse_cookies, _parse_credentials
    from webpent.config.settings import get_settings
    from webpent.graph.builder import build_graph
    from webpent.graph.progress_display import HuntProgressRenderer
    from webpent.shared.finding_announcer import FindingAnnouncer

    settings = get_settings()
    resolved_thread_id = thread_id or str(uuid4())
    resolved_engagement_id = engagement_id or f"unified-{preset['mode']}-{uuid4().hex[:12]}"

    credentials = _parse_credentials(creds) if creds else {}
    if credentials and "password" in credentials:
        # Same posture as scan: never persist the password in state.
        credentials = dict(credentials)
        credentials["password"] = ""
    session_cookies = _parse_cookies(cookies) if cookies else {}

    from webpent.models.targets import Target

    target = Target(url=url)
    run_started = time.monotonic()

    renderer = (
        HuntProgressRenderer(
            total_steps=summary["recursion_limit"],
            target_url=url,
            time_budget_s=preset["time_budget_s"],
            cost_ceiling_usd=preset["llm_budget_usd"],
        )
        if progress and settings.enable_unified_hunt_progress
        else None
    )
    announcer = (
        FindingAnnouncer()
        if progress and settings.enable_unified_hunt_progress
        else None
    )

    final_state: dict[str, Any] = {}
    # UM-DR-35.5: the CLI campaign enforces the HARD total-token ceiling
    # for the whole managed run (explicit ``max_tokens`` override, else the
    # settings default). The selected ceiling is recorded in the summary —
    # a CLI option that is displayed but not enforced is prohibited.
    from webpent.shared.llm import get_llm_budget_summary, llm_usage_scope

    effective_max_tokens = int(max_tokens) if max_tokens is not None else int(
        getattr(settings, "llm_max_total_tokens_per_run", 0) or 0)
    graph_error: BaseException | None = None
    budget_summary: dict[str, object] = {"active": False}
    checkpointer_ctx = _resolve_checkpointer_for_run(auto_approve, get_checkpointer)
    try:
        with llm_usage_scope(settings, max_total_tokens=effective_max_tokens):
            if checkpointer_ctx is not None:
                with checkpointer_ctx as checkpointer:
                    graph = build_graph(checkpointer=checkpointer, auto_approve=auto_approve)
                    final_state = _invoke_with_progress(
                        graph, target, preset, resolved_thread_id,
                        resolved_engagement_id, credentials,
                        session_cookies, settings, no_llm, report_format,
                        renderer, announcer,
                        manifest_origins=(
                            (manifest_projection or {}).get("authorized_origins")
                            or []),
                        scope_declaration=scope_declaration,
                    )
            else:
                graph = build_graph(auto_approve=auto_approve)
                final_state = _invoke_with_progress(
                    graph, target, preset, resolved_thread_id,
                    resolved_engagement_id, credentials,
                    session_cookies, settings, no_llm, report_format,
                    renderer, announcer,
                    manifest_origins=(
                        (manifest_projection or {}).get("authorized_origins")
                        or []),
                    scope_declaration=scope_declaration,
                )
            # Capture INSIDE the scope — the budget ContextVar resets on
            # exit and the summary must reflect THIS campaign's accounting.
            try:
                budget_summary = get_llm_budget_summary()
            except (AttributeError, ImportError, RuntimeError, TypeError, ValueError):
                budget_summary = {"active": True, "capture_error": True}
    except BaseException as exc:  # noqa: BLE001 - recorded for status honesty
        graph_error = exc
        raise
    finally:
        if renderer is not None:
            renderer.finish()

    findings = list(final_state.get("findings") or [])
    # R2-graph-06: Finding carries confidence ("confirmed") /
    # confidence_level ("Tool-Confirmed"), not a validation_status
    # attribute — the old getattr always returned "" and the summary
    # permanently reported 0 confirmed findings.
    from webpent.state.reducers import _finding_strength

    confirmed = [
        f for f in findings
        if _finding_strength(f) >= 3
    ]
    # RESIDUAL CLOSURE 2026-10-29 (Track 9.1): real elapsed wall time and
    # the LLM token tally for this run (cost stays honestly "unpriced" —
    # the runtime never invents a USD figure; see shared/llm.py).
    summary["elapsed_s"] = round(time.monotonic() - run_started, 1)
    try:
        from webpent.shared.llm import get_llm_usage_trace

        usage = get_llm_usage_trace()
        summary["llm_calls"] = len(usage)
        summary["llm_tokens_used"] = sum(
            int(entry.get("total_tokens") or 0) for entry in usage if isinstance(entry, dict)
        )
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        summary["llm_calls"] = 0
        summary["llm_tokens_used"] = 0
    # UM-DR-35.5: campaign budget record — the selected ceiling, the split
    # accounting (input/output/total, reservations, unknown-usage calls),
    # and the honest terminal budget status. ``budget_summary`` was
    # captured INSIDE the campaign scope. Unresolved hypotheses are never
    # silently marked negative on a budget stop.
    summary["llm_budget"] = {
        "max_total_tokens": effective_max_tokens,
        "input_tokens": int(budget_summary.get("input_tokens") or 0),
        "output_tokens": int(budget_summary.get("output_tokens") or 0),
        "total_tokens": int(budget_summary.get("total_tokens") or 0),
        "reserved_tokens": int(budget_summary.get("reserved_tokens") or 0),
        "unknown_usage_calls": int(budget_summary.get("unknown_usage_calls") or 0),
        "tokens_exhausted": bool(budget_summary.get("tokens_exhausted")),
        "calls": int(budget_summary.get("calls") or 0),
        "max_calls": (int(budget_summary["max_calls"])
                      if budget_summary.get("max_calls") is not None else None),
        "blocked": bool(budget_summary.get("blocked")),
    }
    if graph_error is not None:
        budget_status = "INTERRUPTED"
    elif budget_summary.get("tokens_exhausted"):
        budget_status = "BUDGET_EXHAUSTED"
    elif budget_summary.get("blocked"):
        budget_status = "BUDGET_EXHAUSTED"
    elif bool(final_state.get("budget_pressure_active")):
        budget_status = "PARTIAL"
    else:
        budget_status = "COMPLETED"
    summary["budget_status"] = budget_status
    summary["unresolved_hypotheses_note"] = (
        "Budget exhaustion never marks unresolved hypotheses as negative; "
        "they remain untested."
        if budget_status == "BUDGET_EXHAUSTED" else "")
    summary.update(
        {
            "graph_invoked": True,
            "thread_id": resolved_thread_id,
            "engagement_id": resolved_engagement_id,
            "findings_total": len(findings),
            "findings_confirmed": len(confirmed),
            "surface_metrics": final_state.get("surface_metrics") or {},
            "dynamic_step_budget": final_state.get("dynamic_step_budget"),
            "consulted_lessons": bool(final_state.get("consulted_lessons")),
            "extracted_lessons": final_state.get("extracted_lessons") or [],
            "detector_results": len(final_state.get("detector_results") or []),
            # UM-DR-36.2/36.3: the Application Semantic Model summary and
            # the Discovery Funnel produced by the campaign itself (real
            # runtime state — persisted channels, included in the final
            # report payload).
            "application_model": {
                k: v for k, v in (final_state.get("application_model") or {}).items()
                if k != "projection"
            } or {"materialized": False},
            "discovery_funnel": final_state.get("discovery_funnel") or {},
        }
    )
    return summary


def _invoke_with_progress(
    graph: Any,
    target: Any,
    preset: dict[str, Any],
    thread_id: str,
    engagement_id: str,
    credentials: dict[str, Any],
    session_cookies: dict[str, Any],
    settings: Any,
    no_llm: bool,
    report_format: str | None,
    renderer: Any,
    announcer: Any,
    manifest_origins: list[str] | None = None,
    scope_declaration: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Invoke the graph via stream() so the progress view stays live.

    M2 additions: ``manifest_origins`` (the verified manifest's authorized
    origins) and ``scope_declaration`` (a parsed scope file) extend the
    declared engagement hosts and seed the scope state channels exactly
    like the worker path — operator-declared identities only.
    """
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )
    from webpent.state.initial_state import build_initial_state

    initial_state = build_initial_state(
        target,
        thread_id=thread_id,
        client_id="",
        engagement_id=engagement_id,
        credentials=credentials,
        session_cookies=session_cookies,
        identity_profiles={},
        llm_override=False if no_llm else None,
        report_formats=[report_format] if report_format else None,
        skip_recon=False,
    )
    # M2-A: a supplied scope file feeds the same state channels the worker
    # path feeds (raw entries are policy input; the projection is
    # redaction-safe) so the in-graph scope enforcement — wildcard_scope_node,
    # scope_enforcer path rules — sees the operator's declaration, not just
    # the inferred-from-URL default.
    if scope_declaration is not None:
        initial_state["raw_scope_entries"] = list(
            scope_declaration.get("allow_entries") or ()
        )
        initial_state["scope_source"] = "scope_file"
        initial_state["scope_declaration"] = dict(scope_declaration)
    # The mode preset's budget ceilings (schema-declared fields — see
    # state.py's unified-hunt bookkeeping block).
    initial_state["llm_budget_usd"] = float(preset["llm_budget_usd"])
    initial_state["max_llm_calls"] = int(preset["max_llm_calls"])
    initial_state["max_hypotheses"] = int(preset["max_hypotheses"])

    config = {
        "recursion_limit": recursion_limit_for_mode(preset["mode"]),
        "configurable": {"thread_id": thread_id},
    }

    from webpent.shared.llm import llm_enabled_override

    # M1-A (L-3): declare the engagement's target hosts for THIS thread
    # before any node runs — without it every SSRF-guarded recon tool on
    # the CLI path (katana/subfinder/dalfox seed gates, the pinned
    # transport's engagement-allowlist exemption) fails closed and the
    # external recon phase is silently lost (the worker path at
    # pentest_worker.py:692 has always set this; the CLI path never
    # did).  Cleared in ``finally`` so a thread reused for a DIFFERENT
    # engagement never inherits this target.
    engagement_token = set_engagement_target_hosts(
        getattr(target, "url", None),
        *(str(origin) for origin in (manifest_origins or []) if origin),
    )

    last_state: dict[str, Any] = {}
    try:
        with llm_enabled_override(False if no_llm else None):
            for chunk in graph.stream(
                initial_state,
                config=config,
                stream_mode="updates",
            ):
                # stream_mode="updates" yields {node_name: partial_state}
                # per superstep — exactly what the renderer/announcer need.
                if not isinstance(chunk, dict):
                    continue
                for node_name, update in chunk.items():
                    if not isinstance(update, dict):
                        continue
                    trace = update.get("node_step_trace")
                    if renderer is not None and isinstance(trace, list) and trace:
                        renderer.observe_trace(trace[-1])
                    findings = update.get("findings")
                    if findings is not None:
                        if announcer is not None:
                            announcer.observe_findings(findings)
                        if renderer is not None:
                            renderer.observe_findings(findings)
                    # Keep the freshest full-state projection we can get
                    # from the update stream (nodes return partial dicts;
                    # the findings/trace keys above are the ones we need).
                    for key in (
                        "surface_metrics", "dynamic_step_budget",
                        "consulted_lessons", "extracted_lessons",
                        "detector_results",
                    ):
                        if key in update:
                            last_state[key] = update[key]
        # The update stream does not carry the accumulated findings list —
        # read the final full state from the graph's own state handle.
        try:
            final = graph.get_state(config)
            if final is not None and getattr(final, "values", None):
                merged = dict(final.values)
                for key, value in last_state.items():
                    merged.setdefault(key, value)
                return merged
        except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError):
            pass
        return last_state
    finally:
        # M1-A (L-3): never leak this engagement's target hosts into a
        # thread reused for a different engagement (worker pattern).
        clear_engagement_target_hosts(engagement_token)

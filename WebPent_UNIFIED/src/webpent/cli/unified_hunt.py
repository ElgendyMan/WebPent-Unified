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
    identity_profiles: dict[str, Any] | None = None,
    report_format: str | None = None,
    progress: bool = True,
    run_graph: bool = True,
    authorization_manifest: str | None = None,
    scope_file: str | None = None,
    enable_umdr48_lanes: bool = False,
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
    checkpointer_ctx = _resolve_checkpointer_for_run(auto_approve, get_checkpointer)
    try:
        if checkpointer_ctx is not None:
            with checkpointer_ctx as checkpointer:
                graph = build_graph(checkpointer=checkpointer, auto_approve=auto_approve)
                final_state = _invoke_with_progress(
                    graph, target, preset, resolved_thread_id,
                    resolved_engagement_id, credentials,
                    session_cookies, settings, no_llm, report_format,
                    renderer, announcer,
                    manifest_origins=(manifest_projection or {}).get("authorized_origins") or [],
                    scope_declaration=scope_declaration,
                    identity_profiles=identity_profiles,
                    enable_umdr48_lanes=enable_umdr48_lanes,
                    auto_approve=auto_approve,
                )
        else:
            # UM-DR-37 root cause RC-3a (secondary): the no-checkpointer
            # branch silently dropped operator-supplied identity_profiles,
            # so secondary principals (e.g. a foreign user for BAC
            # differentials) never reached the graph in environments
            # without langgraph-checkpoint-sqlite. Both branches now
            # forward the same kwargs.
            graph = build_graph(auto_approve=auto_approve)
            final_state = _invoke_with_progress(
                graph, target, preset, resolved_thread_id,
                resolved_engagement_id, credentials,
                session_cookies, settings, no_llm, report_format,
                renderer, announcer,
                manifest_origins=(manifest_projection or {}).get("authorized_origins") or [],
                scope_declaration=scope_declaration,
                identity_profiles=identity_profiles,
            )
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
        }
    )
    # UM-DR-36.1 §5.3: expose the ACTUAL returned artifacts so a
    # programmatic campaign reads real finding identities (never a
    # re-derived hash) — compact per-finding records plus the raw
    # hypothesis dumps for the production promotion dispatch.
    def _artifact(v: Any, key: str, default: Any = None) -> Any:
        # UM-DR-37: findings may carry evidence_bundle as a model_dump
        # DICT (access_control seals verification.proof_bundle.
        # model_dump) — getattr on a dict always returned the default,
        # so every confirmed finding reported evidence_bundle_id == ""
        # even with a sealed bundle attached.
        if isinstance(v, dict):
            return v.get(key, default)
        return getattr(v, key, default)
    summary["findings_detail"] = [
        {
            "id": str(_artifact(f, "id", "") or ""),
            "title": str(_artifact(f, "title", "") or ""),
            "vuln_class": str(_artifact(f, "vuln_class", "") or ""),
            # UM-DR-51 P5: severity is part of the professional finding
            # identity — the raw battery attribution and the 19-field
            # report contract both start at this record; it was dropped
            # here (recorded null downstream)
            "severity": str(_artifact(f, "severity", "") or ""),
            "confidence": str(_artifact(f, "confidence", "") or ""),
            "confidence_level": str(_artifact(f, "confidence_level", "") or ""),
            "url": str(_artifact(f, "url", "") or ""),
            "tool_name": str(_artifact(f, "tool_name", "") or ""),
            "evidence_bundle_id": str(
                _artifact(_artifact(f, "evidence_bundle", None), "bundle_id", "")
                or ""),
            "evidence_keys": sorted(
                (f.get("evidence") or {}).keys()
                if isinstance(f, dict) else
                (getattr(f, "evidence", None) or {}).keys()),
        }
        for f in findings
    ]
    summary["hypotheses_dump"] = [
        h.model_dump(mode="json") if hasattr(h, "model_dump") else dict(h)
        for h in (final_state.get("hypotheses") or [])
    ]
    # UM-DR-47 W6/W7: record the safe-stop honestly and persist the
    # cross-campaign research memory (flag-gated, privacy-scrubbed).
    brain_stop = final_state.get("_brain_safe_stop")
    if isinstance(brain_stop, dict):
        summary["safe_stopped"] = True
        summary["safe_stop_reason"] = str(brain_stop.get("reason") or "")
        summary["safe_stop_snapshot"] = str(brain_stop.get("snapshot_path") or "")
    try:
        from webpent.production.brain_engine import brain_engine_enabled
        _w6_on = brain_engine_enabled()
    except Exception:  # noqa: BLE001 — fail-closed
        _w6_on = False
    if _w6_on:
        try:
            from webpent.production.research_memory_store import (
                save_research_memory,
            )

            _lessons = [
                str(x) for x in (final_state.get("research_lessons") or [])
            ][:16] + [
                str(x) for x in (final_state.get("extracted_lessons") or [])
            ][:16]
            _demotion: set[str] = set()
            for h in (final_state.get("hypotheses") or []):
                _status = str(
                    (h.get("status") if isinstance(h, dict)
                     else getattr(h, "status", "")) or ""
                ).lower()
                if _status in {"resolved_false", "abandoned", "refuted"}:
                    _cls = str(
                        (h.get("vuln_class") if isinstance(h, dict)
                         else getattr(h, "vuln_class", "")) or ""
                    ).lower()
                    if _cls:
                        _demotion.add(_cls)
            _fp_causes = [
                x for x in _lessons if "false_positive" in str(x).lower()
            ][:16]
            _mem_path = save_research_memory(
                url,
                demotion_classes=sorted(_demotion),
                fp_causes=_fp_causes,
                lesson_summaries=_lessons,
            )
            if _mem_path:
                summary["research_memory_saved"] = _mem_path
        except Exception as exc:  # noqa: BLE001 — memory is best-effort
            logger.warning("W6 research-memory save failed: %s", exc)
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
    identity_profiles: dict[str, Any] | None = None,
    enable_umdr48_lanes: bool = False,
    auto_approve: bool = False,
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
        identity_profiles=identity_profiles or {},
        llm_override=False if no_llm else None,
        report_formats=[report_format] if report_format else None,
        skip_recon=False,
        # UM-DR-48: the auto-approve decision must reach the STATE (the
        # BAC state-changing gate and the D-lanes read it) — before
        # this fix it only chose the graph's compile shape, so
        # auto_approve campaigns ran with state["auto_approve"]=False
        auto_approve=auto_approve,
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
    # UM-DR-48 Phase D: the detection-lanes flag reaches the graph's
    # state (the lanes read it via lanes_enabled — flag-gated merge)
    if enable_umdr48_lanes:
        initial_state["enable_umdr48_lanes"] = True
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
    # UM-DR-47 W7: the live QC watchdog on the update stream (flag-
    # gated; OFF keeps the stream loop byte-comparable). Scope hosts =
    # the same declared set the engagement-allowlist uses below.
    watchdog = None
    try:
        from webpent.production.brain_engine import brain_engine_enabled
        _brain_on = brain_engine_enabled()
    except Exception:  # noqa: BLE001 — fail-closed
        _brain_on = False
    if _brain_on:
        from webpent.production.brain_watchdog import BrainWatchdog

        _hosts: set[str] = set()
        try:
            _target_url = getattr(target, "url", None) or ""
            if _target_url:
                from urllib.parse import urlsplit as _urlsplit
                _h = _urlsplit(str(_target_url)).hostname
                if _h:
                    _hosts.add(str(_h).lower())
            for _origin in manifest_origins or []:
                try:
                    _h = _urlsplit(str(_origin)).hostname
                except ValueError:
                    _h = ""
                if _h:
                    _hosts.add(str(_h).lower())
        except Exception:  # noqa: BLE001 — advisory scoping
            _hosts = set()
        watchdog = BrainWatchdog(
            scope_hosts=frozenset(_hosts),
            engagement_id=engagement_id,
        )
    brain_stop: dict[str, Any] | None = None
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
                    if watchdog is not None:
                        watchdog.observe_update(node_name, update)
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
                if watchdog is not None:
                    stop, reason = watchdog.should_stop()
                    if stop:
                        stop_exc = watchdog.safe_stop(
                            reason,
                            last_state=last_state,
                            node=str(node_name) if node_name else None,
                        )
                        brain_stop = {
                            "reason": stop_exc.reason,
                            "snapshot_path": stop_exc.snapshot_path,
                            "details": stop_exc.details,
                        }
                        break
            if brain_stop is not None:
                last_state["_brain_safe_stop"] = brain_stop
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

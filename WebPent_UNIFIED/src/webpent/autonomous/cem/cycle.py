"""CEM — the pure engagement cycle (v83, T4b).

``run_cem_cycle`` is the whole of "continuous": one idempotent, pure
function the operator (or cron) calls in a loop with an injected ``now``.
There is no daemon, thread, sleep or socket here; every observation
arrives through injected ``fetch_*`` doubles, and every permission flows
through the polite scheduler.

Per cycle, per target: observe (injected) -> snapshot -> diff against the
previous snapshot -> guard (scope drift, scheduler) -> propose advisory
actions through an optional reactor hook. The cycle re-ranks and
annotates; it never promotes evidence, never touches out-of-scope hosts,
and never spends anything the scheduler refused.

Failure of any single unit degrades that unit's contribution to empty and
never breaks the cycle.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from typing import Any

from webpent.autonomous.cem.diff_engine import diff_snapshots, is_actionable, is_wake_up
from webpent.autonomous.cem.scope_drift import evaluate as evaluate_scope_drift
from webpent.autonomous.cem.snapshot import MAX_TARGETS, SnapshotStore, build_snapshot
from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

MAX_TARGETS_HARD = min(MAX_TARGETS, 16)
DEFAULT_REQUESTS_PER_OBSERVATION = 20

#: Fetcher keys consumed by build_snapshot; each is an injected callable
#: returning a plain list/dict for that section. A missing fetcher means
#: that section is empty for the cycle, never a network call.
FETCHER_KEYS = (
    "fetch_subdomains",
    "fetch_endpoints",
    "fetch_headers",
    "fetch_cert_expiry",
    "fetch_js_hashes",
    "fetch_tech_stack",
    "fetch_response_shapes",
)


def new_cem_state(*, targets: Any = None) -> dict[str, Any]:
    """Fresh bounded CEM state; garbage targets are dropped, not kept."""
    enabled: dict[str, dict[str, Any]] = {}
    if isinstance(targets, (list, tuple, set)):
        for target in list(targets)[:MAX_TARGETS_HARD]:
            target_id = redact(str(target or ""))[:120]
            if target_id:
                enabled[target_id] = {"enabled": True, "paused": False}
    return {
        "version": 1,
        "targets": enabled,
        "cycle_count": 0,
        "last_cycle_ts": None,
    }


def load_cem_state(path: Any) -> dict[str, Any]:
    """Read persisted state; corrupt/missing -> fresh empty state."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError, AttributeError):
        return new_cem_state()
    if not isinstance(raw, dict):
        return new_cem_state()
    state = new_cem_state(targets=list(raw.get("targets") or {}))
    for target_id, meta in list(raw.get("targets", {}).items()):
        if isinstance(meta, dict):
            state["targets"][str(target_id)[:120]] = {
                "enabled": bool(meta.get("enabled", True)),
                "paused": bool(meta.get("paused", False)),
            }
    raw_count = raw.get("cycle_count")
    state["cycle_count"] = int(raw_count or 0) if isinstance(raw_count, int) else 0
    state["last_cycle_ts"] = raw.get("last_cycle_ts")
    return state


def save_cem_state(state: dict[str, Any], path: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, indent=2, ensure_ascii=False)
            os.replace(tmp_name, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise
    except (OSError, AttributeError) as exc:
        _LOG.warning("CEM state save failed (memory stays in-process): %s", exc)


def _safe_fetch(fetcher: Any) -> Any:
    if not callable(fetcher):
        return None
    try:
        return fetcher()
    except Exception as exc:
        _LOG.warning("injected fetcher failed; section empty this cycle: %s", exc)
        return None


def run_cem_cycle(
    state: dict[str, Any],
    *,
    now: float,
    snapshot_store: SnapshotStore | None,
    scheduler: Any,
    fetchers: dict[str, Any] | None = None,
    scope_entries: Any = None,
    config: dict[str, Any] | None = None,
    reactor: Any | None = None,
    requests_per_observation: int = DEFAULT_REQUESTS_PER_OBSERVATION,
) -> dict[str, Any]:
    """Run exactly one bounded, pure CEM cycle at the injected ``now``.

    The report is advisory end to end: decisions, classifications,
    proposed actions and alerts. Any unit failing contributes empty and
    the cycle continues. Identical inputs and state produce an identical
    report, which is what makes calling it in a loop from cron safe.
    """
    state = state if isinstance(state, dict) else new_cem_state()
    fetchers = fetchers if isinstance(fetchers, dict) else {}
    now = float(now)

    active_targets = [
        target_id
        for target_id, meta in list(state.get("targets", {}).items())[:MAX_TARGETS_HARD]
        if isinstance(meta, dict) and meta.get("enabled", True) and not meta.get("paused")
    ]
    requested = max(1, int(requests_per_observation)) * len(active_targets)
    permission = scheduler.allows(now, requested=requested) if scheduler is not None else {
        "allowed": False,
        "granted": 0,
        "reason": "no_scheduler",
        "detail": "cycle requires a scheduler",
    }
    report: dict[str, Any] = {
        "ts": now,
        "cycle_index": int(state.get("cycle_count") or 0),
        "permission": permission,
        "observed": [],
        "alerts": [],
        "proposals": [],
        "skipped_budget": [],
        "spend": 0,
        "skipped": not permission.get("allowed"),
        "advisory": True,
    }
    if report["skipped"]:
        return report

    remaining = int(permission.get("granted") or 0)
    use_per_target = max(1, int(requests_per_observation))
    for target_id in active_targets:
        if remaining < use_per_target:
            report["skipped_budget"].append(target_id)
            continue
        decision = _observe_target(
            target_id,
            now=now,
            snapshot_store=snapshot_store,
            fetchers=fetchers,
            scope_entries=scope_entries,
            config=config,
            reactor=reactor,
        )
        report["observed"].append(decision)
        report["alerts"].extend(decision.get("alerts", []))
        report["proposals"].extend(decision.get("proposals", []))
        remaining -= use_per_target
        report["spend"] += use_per_target

    scheduler.record_spend(now, report["spend"])
    state["cycle_count"] = report["cycle_index"] + 1
    state["last_cycle_ts"] = now
    if snapshot_store is not None and hasattr(snapshot_store, "save"):
        snapshot_store.save()
    return report


def _observe_target(
    target_id: str,
    *,
    now: float,
    snapshot_store: Any,
    fetchers: dict[str, Any],
    scope_entries: Any,
    config: dict[str, Any] | None,
    reactor: Any | None,
) -> dict[str, Any]:
    decision: dict[str, Any] = {"target_id": target_id, "alerts": [], "proposals": [], "diff": None}
    try:
        previous = snapshot_store.latest(target_id) if snapshot_store is not None else None
        snapshot = build_snapshot(
            target_id,
            now=now,
            subdomains=_safe_fetch(fetchers.get("fetch_subdomains")),
            endpoints=_safe_fetch(fetchers.get("fetch_endpoints")),
            headers=_safe_fetch(fetchers.get("fetch_headers")),
            cert_expiry=_safe_fetch(fetchers.get("fetch_cert_expiry")),
            js_hashes=_safe_fetch(fetchers.get("fetch_js_hashes")),
            tech_stack=_safe_fetch(fetchers.get("fetch_tech_stack")),
            response_shapes=_safe_fetch(fetchers.get("fetch_response_shapes")),
        )
        if snapshot_store is not None:
            snapshot_store.append(snapshot)
        diff = diff_snapshots(
            previous,
            snapshot,
            config=config,
            history_endpoints=(
                snapshot_store.history_endpoints(target_id) if snapshot_store is not None else None
            ),
        )
        decision["diff"] = diff
        decision["snapshot_hash"] = snapshot["hash"]
        decision["first_observation"] = previous is None

        drift = evaluate_scope_drift(
            scope_entries=scope_entries,
            observed_subdomains=snapshot.get("subdomains"),
        )
        decision["alerts"].extend(drift.get("drifts", []))

        if previous is not None and is_actionable(diff):
            decision["proposals"].append(
                {
                    "kind": "wake_up" if is_wake_up(diff) else "mini_campaign",
                    "target_id": target_id,
                    "reason": diff.get("top_signal"),
                    "change_count": diff.get("change_count", 0),
                    "advisory": True,
                }
            )
        if reactor is not None:
            proposals = getattr(reactor, "propose", None)
            if callable(proposals):
                try:
                    extra = proposals(diff, now=now) or []
                    if isinstance(extra, list):
                        decision["proposals"].extend(
                            p for p in extra if isinstance(p, dict)
                        )
                except Exception as exc:
                    _LOG.warning("reactor hook failed; proposals empty: %s", exc)
    except Exception as exc:
        _LOG.warning("observation of %s degraded to empty: %s", target_id, exc)
        decision["error"] = redact(str(exc))[:200]
    return decision


__all__ = [
    "DEFAULT_REQUESTS_PER_OBSERVATION",
    "FETCHER_KEYS",
    "MAX_TARGETS_HARD",
    "load_cem_state",
    "new_cem_state",
    "run_cem_cycle",
    "save_cem_state",
]

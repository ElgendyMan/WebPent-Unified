"""UM-DR-47 Phase W7 — the live-campaign QC watchdog with safe-stop.

The 46 QC node inspected the hypothesis pool at graph-node time. This
module watches the LIVE campaign stream (the ``run_unified_hunt``
update stream) and enforces three invariants DURING execution:

* repetition — the same (url, method) request signature repeated more
  than ``max_repeats`` times with no new finding is waste (the
  mission's criterion 4: "choosing new experiments instead of
  repeating tests");
* scope — a finding whose host is outside the engagement's declared
  hosts is a scope violation (criterion 8: safe-stop at the
  authorization boundary);
* request budget — the campaign's ``request_budget`` ceiling.

On violation the watchdog raises :class:`BrainSafeStop` AFTER writing
a durable snapshot: the interrupted state values (findings so far,
last node, reason, counts) plus the campaign-lifecycle interrupted
mark when its flag is on. ``run_unified_hunt`` catches the stop,
finalizes the partial summary honestly (``safe_stopped=True`` + the
reason), and the campaign can be resumed from the snapshot —
"لقطة/استعادة عند الخلل".

Deterministic: counters and thresholds only, no clock, no network.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

__all__ = ["BrainSafeStop", "BrainWatchdog", "WATCHDOG_SNAPSHOT_ENV"]

WATCHDOG_SNAPSHOT_ENV = "WEBPENT_BRAIN_WATCHDOG_SNAPSHOT_DIR"
_DEFAULT_MAX_REPEATS = 4


class BrainSafeStop(Exception):
    """Raised by the watchdog after snapshotting; never mid-write."""

    def __init__(self, reason: str, snapshot_path: str | None,
                 details: dict[str, Any] | None = None) -> None:
        super().__init__(f"brain safe-stop: {reason}")
        self.reason = reason
        self.snapshot_path = snapshot_path
        self.details = details or {}


class BrainWatchdog:
    """Observes graph update chunks; decides + executes the safe-stop."""

    def __init__(
        self,
        *,
        scope_hosts: frozenset[str] | set[str] | None = None,
        max_repeats: int = _DEFAULT_MAX_REPEATS,
        request_budget: int | None = None,
        engagement_id: str = "",
        snapshot_dir: str | None = None,
    ) -> None:
        self.scope_hosts = frozenset(
            str(h).lower() for h in (scope_hosts or ()) if h
        )
        self.max_repeats = max(1, int(max_repeats))
        self.request_budget = (
            int(request_budget) if request_budget and int(request_budget) > 0 else None
        )
        self.engagement_id = str(engagement_id or "")
        self.snapshot_dir = snapshot_dir
        self.request_signatures: dict[tuple[str, str], int] = {}
        self.request_count = 0
        self.observed_nodes: list[str] = []
        self.violations: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # observation
    # ------------------------------------------------------------------
    def observe_update(self, node_name: str, update: dict[str, Any]) -> None:
        """One graph update chunk: count requests, check invariants."""
        if not isinstance(update, dict):
            return
        self.observed_nodes.append(str(node_name))
        for finding in update.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            self._observe_finding(node_name, finding)

    def _observe_finding(self, node_name: str, finding: dict[str, Any]) -> None:
        url = str(finding.get("url") or "")
        method = str(finding.get("request_method") or "GET").upper()
        self.request_count += 1
        if url:
            key = (url, method)
            self.request_signatures[key] = self.request_signatures.get(key, 0) + 1
        if self.scope_hosts:
            host = ""
            try:
                host = (urlsplit(url).hostname or "").lower()
            except ValueError:
                host = ""
            if host and host not in self.scope_hosts:
                self.violations.append({
                    "kind": "scope_violation",
                    "node": str(node_name),
                    "host": host,
                })

    # ------------------------------------------------------------------
    # decision
    # ------------------------------------------------------------------
    def should_stop(self) -> tuple[bool, str]:
        """(stop, reason) — deterministic threshold evaluation."""
        if any(v["kind"] == "scope_violation" for v in self.violations):
            host = next(
                v["host"] for v in self.violations if v["kind"] == "scope_violation"
            )
            return True, f"scope_violation:{host}"
        if self.request_budget is not None and self.request_count > self.request_budget:
            return True, f"request_budget_exceeded:{self.request_count}"
        for (url, method), count in sorted(self.request_signatures.items()):
            if count > self.max_repeats:
                return (
                    True,
                    f"repetition_without_new_information:{method}:{url}:{count}",
                )
        return False, ""

    # ------------------------------------------------------------------
    # execution (snapshot + raise)
    # ------------------------------------------------------------------
    def safe_stop(
        self,
        reason: str,
        *,
        last_state: dict[str, Any] | None = None,
        node: str | None = None,
    ) -> BrainSafeStop:
        """Write the durable snapshot, then return the stop exception."""
        snapshot_path = self._write_snapshot(reason, last_state, node)
        self._mark_interrupted(reason, node, last_state)
        return BrainSafeStop(reason, snapshot_path, {
            "request_count": self.request_count,
            "observed_nodes": len(self.observed_nodes),
            "violations": self.violations[:8],
        })

    def _snapshot_dir(self) -> str:
        if self.snapshot_dir:
            return self.snapshot_dir
        env_dir = os.environ.get(WATCHDOG_SNAPSHOT_ENV, "").strip()
        if env_dir:
            return env_dir
        return os.path.join(os.getcwd(), ".webpent-campaign-snapshots")

    def _write_snapshot(
        self,
        reason: str,
        last_state: dict[str, Any] | None,
        node: str | None,
    ) -> str | None:
        try:
            from webpent.production.research_memory_store import scrub_for_memory

            directory = self._snapshot_dir()
            os.makedirs(directory, exist_ok=True)
            name = f"safe-stop-{self.engagement_id or 'campaign'}.json"
            path = os.path.join(directory, name)
            payload = {
                "schema": "umdr47-w7-safe-stop-v1",
                "engagement_id": self.engagement_id,
                "reason": reason,
                "node": node,
                "request_count": self.request_count,
                "request_signatures": {
                    f"{m} {u}": c for (u, m), c in
                    sorted(self.request_signatures.items())
                },
                "violations": self.violations[:8],
                "observed_node_count": len(self.observed_nodes),
                "last_state_keys": sorted((last_state or {}).keys()),
                "findings_snapshot": [
                    {
                        "title": str(f.get("title") or "")[:200],
                        "url": str(f.get("url") or "")[:300],
                        "vuln_class": str(f.get("vuln_class") or ""),
                    }
                    for f in (last_state or {}).get("findings", [])[:64]
                    if isinstance(f, dict)
                ],
                "resume_contract": (
                    "operator-restart contract preserved: the snapshot is a "
                    "record, not an authority; resumption goes through the "
                    "checkpointer/campaign-lifecycle path"
                ),
            }
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(scrub_for_memory(payload), fh, indent=1, sort_keys=True)
            return path
        except Exception as exc:  # noqa: BLE001 — snapshot best-effort
            logger.warning("watchdog snapshot failed: %s", exc)
            return None

    def _mark_interrupted(
        self,
        reason: str,
        node: str | None,
        last_state: dict[str, Any] | None,
    ) -> None:
        """Best-effort campaign-lifecycle interrupted mark (flag-gated)."""
        try:
            from webpent.production.campaign_lifecycle import (
                mark_campaign_interrupted,
            )
            mark_campaign_interrupted(
                engagement_id=self.engagement_id,
                reason=f"w7-watchdog:{reason}",
                node=node,
                state_values=last_state,
            )
        except Exception:  # noqa: BLE001 — advisory mark, never fatal
            pass

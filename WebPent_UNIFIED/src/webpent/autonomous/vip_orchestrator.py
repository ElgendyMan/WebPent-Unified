"""VIP Orchestrator — the autonomous campaign leader.

The strongest missing piece after the Project Zero wiring pass: every
capability already exists as a library-tier module — AttackMemory and
AdaptiveStrategyOptimizer remember and prioritize, PostmortemManager
aggregates misses, tech-stack correlation discovers N-days from an
operator feed, the influence graph finds second-order parameter
candidates, surface drift flags newly-appeared attackable surface,
and red-vs-blue self-checks the detectors. But nothing drives them as
ONE self-directed loop: each module is invoked by a separate LangGraph
node on a fixed path, so a "campaign" is only as adaptive as the
static graph that wires it.

This module is that leader. One cycle runs:

  perceive  — build the influence graph (shared parameters = chained
              candidates), fingerprint the tech stack and correlate
              it against the operator CVE feed (N-day candidates),
              and diff surface against the baseline snapshot
              (drift = replan trigger).
  plan      — rank candidate scenarios with AdaptiveStrategyOptimizer,
              drop what AttackMemory says to skip (same
              scenario+endpoint+reason failing >= threshold), queue
              second-order parameters and KEV-flagged correlations,
              and emit prioritized CampaignActions.
  act       — hand each action to a CALLER-PROVIDED executor callable.
              The orchestrator itself never opens a socket, sends a
              request, or touches the filesystem beyond its ledger.
  verify    — run AdversarialReviewer against any claimed finding
              (only downgrades), record outcomes back into AttackMemory
              and the optimizer (failures lose priority; a success
              spawns deeper variants next cycle), and optionally
              self-check the hardened SSRF detector with red-vs-blue,
              feeding escapes to the postmortem store.
  replan    — the next cycle's input arrives from the caller; drift
              results and failure categories shape what gets
              prioritized and what gets skipped.

Safety posture (same as the Project Zero wiring):

  * Default-off: nothing in the production graph calls this module;
    a caller must construct and run it explicitly.
  * Advisory-only: it never writes findings, never promotes
    confirmations (the reviewer only downgrades), and every CVE
    correlation it queues carries the source modules' own
    ``advisory_only`` / ``does_not_confirm`` markers.
  * Fail-soft: any single component error degrades that step to an
    empty/neutral result and the loop continues — a broken drift
    diff never aborts a campaign.
  * Bounded: max_cycles caps the loop; the graph builders keep their
    own endpoint/edge caps; the ledger caps line size.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from webpent.autonomous.campaign_ledger import CampaignLedger
from webpent.learning.attack_memory import (
    AdaptiveStrategyOptimizer,
    AdversarialReviewer,
    AttackMemory,
)
from webpent.shared.detector_hardening import extract_ssrf_indicators_hardened
from webpent.shared.red_vs_blue import RedVsBlueReport, run_red_vs_blue
from webpent.shared.surface_drift import detect_surface_drift
from webpent.shared.surface_evidence_graph import build_surface_evidence_graph
from webpent.shared.surface_influence_graph import build_surface_influence_graph
from webpent.shared.tech_stack_cve import correlate_cves, fingerprint_tech_stack

# A no-op executor: the default "act" step. It never performs anything;
# it marks the action as handed-off-but-not-executed so a dry-run
# campaign (plan + ledger only) is expressible without any hooks.
def _noop_executor(action: Mapping[str, Any]) -> dict[str, Any]:
    return {"outcome": "not_executed", "reason": "no executor configured", "action": dict(action)}


@dataclass
class VipOrchestratorConfig:
    """All knobs in one place. Conservative defaults; everything is
    an in-process behavior knob — no settings file, no env var, so
    wiring an operator campaign never touches the frozen settings
    module."""

    max_cycles: int = 5
    skip_threshold: int = 3
    enable_tech_stack_cve: bool = True
    enable_drift_replan: bool = True
    enable_selfcheck: bool = True
    # Red-vs-blue self-check inputs (labels only in the ledger; the
    # seed payload is a benign SSRF probe marker, never stored raw).
    selfcheck_seed_payload: str = "GET http://169.254.169.254/latest/meta-data/"
    selfcheck_seed_label: str = "ssrf_metadata_probe"
    # Optional postmortem manager; when provided, escaped techniques
    # from the self-check are recorded (durable detection-gap rollup).
    postmortem_manager: Any | None = None
    campaign_id: str = "vip-campaign"
    thread_id: str | None = None


@dataclass
class CampaignInput:
    """One cycle's observations, supplied by the caller (usually the
    latest crawl). Same ``crawled_data`` shape the surface graph
    builders consume."""

    crawled_data: Mapping[str, Any] = field(default_factory=dict)
    scenarios: list[str] = field(default_factory=list)
    # Canonical target endpoint for memory bookkeeping (skip keys are
    # scenario+endpoint+reason — plan and verify must agree on it).
    target: str = ""
    # Optional explicit fingerprint evidence; when absent the orchestrator
    # extracts response headers from ``crawled_data["surface_records"]``.
    headers: Mapping[str, str] | None = None
    set_cookie_headers: Sequence[str] | None = None
    body: str = ""
    # Operator CVE feed entries (CveFeedEntry-shaped dicts). When None,
    # the shared operator-catalog loader resolves the settings path.
    cve_feed: Sequence[Mapping[str, Any]] | None = None
    # Baseline SurfaceEvidenceGraph for drift diffing (cycle 0 of an
    # engagement typically passes the engagement-start snapshot).
    baseline_graph: Any | None = None


@dataclass
class CampaignAction:
    """One prioritized unit of work the leader hands to the executor."""

    kind: str  # scenario | second_order_param | kev_correlation | drift_followup
    target: str
    scenario_id: str
    priority: float
    rationale: str
    endpoint: str = ""
    advisory_only: bool = True
    does_not_confirm: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "scenario_id": self.scenario_id,
            "priority": round(self.priority, 4),
            "rationale": self.rationale,
            "endpoint": self.endpoint,
            "advisory_only": self.advisory_only,
            "does_not_confirm": self.does_not_confirm,
        }


def _headers_from_surface_records(crawled_data: Mapping[str, Any]) -> tuple[dict[str, str], list[str]]:
    """Extract response headers from surface records (fail-soft).

    Mirrors the crawler's PZ evidence extraction: top-level header
    keys first, then per-record ``response_headers`` (Mapping or
    list-of-Mapping shapes).
    """
    headers: dict[str, str] = {}
    cookies: list[str] = []
    for key in ("headers", "response_headers"):
        value = crawled_data.get(key)
        if isinstance(value, Mapping):
            headers.update({str(k): str(v) for k, v in value.items()})
    records = crawled_data.get("surface_records")
    if isinstance(records, list):
        for record in records:
            if not isinstance(record, Mapping):
                continue
            rh = record.get("response_headers")
            if isinstance(rh, Mapping):
                headers.update({str(k): str(v) for k, v in rh.items()})
            elif isinstance(rh, list):
                for item in rh:
                    if isinstance(item, Mapping):
                        headers.update({str(k): str(v) for k, v in item.items()})
            set_cookie = record.get("set_cookie") or record.get("set_cookie_headers")
            if isinstance(set_cookie, str):
                cookies.append(set_cookie)
            elif isinstance(set_cookie, list):
                cookies.extend(str(c) for c in set_cookie if isinstance(c, str))
    return headers, cookies


def _resolve_cve_feed(explicit: Sequence[Mapping[str, Any]] | None) -> list[Mapping[str, Any]]:
    if explicit is not None:
        return [e for e in explicit if isinstance(e, Mapping)]
    try:
        from webpent.shared.operator_catalogs import load_cve_feed_catalog

        return load_cve_feed_catalog(None)
    except Exception:  # noqa: BLE001 — feed resolution is advisory, fail-soft
        return []


class VipOrchestrator:
    """The campaign leader. Construct with a config and (optionally) a
    ledger path, then call :meth:`run_cycle` per cycle or
    :meth:`run_vip_campaign` for the full loop."""

    def __init__(
        self,
        config: VipOrchestratorConfig | None = None,
        *,
        ledger: CampaignLedger | None = None,
        attack_memory: AttackMemory | None = None,
        optimizer: AdaptiveStrategyOptimizer | None = None,
        reviewer: AdversarialReviewer | None = None,
    ) -> None:
        self.config = config or VipOrchestratorConfig()
        self.ledger = ledger  # None → ledger disabled (still fail-soft)
        self.attack_memory = attack_memory or AttackMemory()
        self.optimizer = optimizer or AdaptiveStrategyOptimizer()
        self.reviewer = reviewer or AdversarialReviewer()
        self.last_drift: Any | None = None

    # -- ledger helper -----------------------------------------------------
    def _log(self, step: str, cycle: int, **fields: Any) -> None:
        if self.ledger is not None:
            self.ledger.record(step, cycle, campaign_id=self.config.campaign_id, **fields)

    # -- perceive ----------------------------------------------------------
    def perceive(self, cycle_input: CampaignInput) -> dict[str, Any]:
        """Build this cycle's world model. Every sub-step fail-soft."""
        crawled = cycle_input.crawled_data or {}
        perception: dict[str, Any] = {
            "shared_parameters": [],
            "cve_correlations": [],
            "drift_high_priority": 0,
            "has_drift": False,
        }
        try:
            graph = build_surface_influence_graph(crawled)
            perception["shared_parameters"] = [
                {"name": p.name, "endpoint_count": p.endpoint_count}
                for p in graph.shared_parameters
            ]
        except Exception as exc:  # noqa: BLE001
            perception["influence_graph_error"] = str(exc)[:200]

        if self.config.enable_tech_stack_cve:
            try:
                headers, cookies = (
                    (dict(cycle_input.headers), list(cycle_input.set_cookie_headers or []))
                    if cycle_input.headers is not None or cycle_input.set_cookie_headers
                    else _headers_from_surface_records(crawled)
                )
                components = fingerprint_tech_stack(
                    headers=headers or None,
                    set_cookie_headers=cookies or None,
                    body=cycle_input.body or "",
                )
                feed = _resolve_cve_feed(cycle_input.cve_feed)
                correlations = correlate_cves(components, feed) if components else []
                perception["cve_correlations"] = [c.as_dict() for c in correlations]
            except Exception as exc:  # noqa: BLE001
                perception["cve_correlation_error"] = str(exc)[:200]

        if self.config.enable_drift_replan and cycle_input.baseline_graph is not None:
            try:
                current = build_surface_evidence_graph(crawled)
                drift = detect_surface_drift(cycle_input.baseline_graph, current)
                self.last_drift = drift
                perception["has_drift"] = drift.has_drift
                perception["drift_high_priority"] = len(drift.high_priority_nodes)
            except Exception as exc:  # noqa: BLE001
                perception["drift_error"] = str(exc)[:200]
        self._log("perceive", 0, **{k: v for k, v in perception.items()})
        return perception

    # -- plan --------------------------------------------------------------
    def _memory_skip(self, scenario_id: str, endpoint: str) -> bool:
        """AttackMemory skip check, reason-aware: skip keys are
        scenario+endpoint+reason, so the planner consults every reason
        the scenario has actually failed with, plus the generic
        pattern-generalization check in ``should_skip`` itself."""
        threshold = self.config.skip_threshold
        memory = self.attack_memory
        try:
            if memory.should_skip(
                scenario_id=scenario_id, endpoint=endpoint, threshold=threshold,
            ):
                return True
            for reason in memory.failed_reasons(scenario_id):
                if memory.should_skip(
                    scenario_id=scenario_id, endpoint=endpoint,
                    reason=reason, threshold=threshold,
                ):
                    return True
        except Exception:  # noqa: BLE001 — memory failure never blocks planning
            return False
        return False

    def plan(self, cycle_input: CampaignInput, perception: dict[str, Any]) -> list[CampaignAction]:
        """Emit prioritized, memory-filtered actions for this cycle."""
        actions: list[CampaignAction] = []
        for sid in cycle_input.scenarios:
            if self._memory_skip(sid, cycle_input.target):
                self._log("plan_skip", 0, scenario_id=sid,
                          reason="attack_memory_skip_threshold")
                continue
            priority = self.optimizer.priority(sid)
            rationale = "optimizer_priority"
            if self.optimizer.spawn_deeper(sid):
                priority = min(1.0, priority + 0.2)
                rationale = "optimizer_deeper_spawn"
            actions.append(CampaignAction(
                kind="scenario", target=sid, scenario_id=sid,
                priority=priority, rationale=rationale,
                endpoint=cycle_input.target,
            ))
        for param in perception.get("shared_parameters", []):
            actions.append(CampaignAction(
                kind="second_order_param", target=str(param.get("name", "")),
                scenario_id=f"second-order::{param.get('name', '')}",
                priority=0.8,
                rationale=f"shared across {param.get('endpoint_count', 0)} endpoints",
            ))
        for corr in perception.get("cve_correlations", []):
            kev = bool(corr.get("kev"))
            actions.append(CampaignAction(
                kind="kev_correlation" if kev else "tech_stack_cve",
                target=str(corr.get("cve_id", "")),
                scenario_id=f"n-day::{corr.get('cve_id', '')}",
                priority=0.9 if kev else 0.6,
                rationale=f"tech-stack {corr.get('product', '')} "
                          f"version_match={corr.get('version_match', '')}",
            ))
        if perception.get("drift_high_priority"):
            actions.append(CampaignAction(
                kind="drift_followup", target="surface",
                scenario_id="drift::high-priority-nodes",
                priority=0.95,
                rationale=f"{perception['drift_high_priority']} newly-appeared "
                          "attackable surface nodes",
            ))
        actions.sort(key=lambda a: a.priority, reverse=True)
        self._log("plan", 0, action_count=len(actions),
                  kinds=sorted({a.kind for a in actions}))
        return actions

    # -- act + verify ------------------------------------------------------
    def act(
        self,
        cycle: int,
        actions: Sequence[CampaignAction],
        executor: Callable[[Mapping[str, Any]], dict[str, Any]] | None,
    ) -> list[dict[str, Any]]:
        """Hand actions to the caller-provided executor. The
        orchestrator itself performs nothing."""
        run_executor = executor or _noop_executor
        results: list[dict[str, Any]] = []
        for action in actions:
            try:
                outcome = run_executor(action.as_dict())
            except Exception as exc:  # noqa: BLE001 — executor crash is one action's failure
                outcome = {"outcome": "failed", "reason": f"executor_error: {exc}"[:200]}
            if not isinstance(outcome, dict):
                outcome = {"outcome": "failed", "reason": "executor returned non-dict"}
            outcome.setdefault("outcome", "failed")
            results.append({"action": action.as_dict(), **outcome})
            self._log("act", cycle, kind=action.kind, target=action.target,
                      outcome=outcome.get("outcome", ""))
        return results

    def verify(self, cycle: int, results: Sequence[dict[str, Any]]) -> dict[str, Any]:
        """Reviewer check + memory/optimizer feedback + optional
        detector self-check. Review only DOWNGRADES; outcomes are
        recorded either way."""
        verification: dict[str, Any] = {"reviewed": 0, "downgraded": 0, "recorded": 0}
        for result in results:
            outcome = str(result.get("outcome", ""))
            action = result.get("action", {})
            sid = str(action.get("scenario_id", ""))
            target = str(action.get("target", ""))
            if outcome == "confirmed":
                self.optimizer.record_success(sid)
                evidence = result.get("evidence")
                # An EMPTY evidence mapping is reviewed too — a claimed
                # confirmation with nothing in it is the classic
                # downgrade case, not a skip case.
                if isinstance(evidence, Mapping):
                    verification["reviewed"] += 1
                    try:
                        stands, surviving = self.reviewer.review(
                            result, dict(evidence),
                            vuln_class=str(result.get("vuln_class", "")),
                        )
                        if not stands:
                            verification["downgraded"] += 1
                            result["review_downgraded"] = True
                            result["review_surviving_explanations"] = surviving
                            result["outcome"] = "needs_review"
                            outcome = "needs_review"
                    except Exception:  # noqa: BLE001 — reviewer failure never upgrades
                        pass
            elif outcome == "failed":
                self.optimizer.record_failure(sid)
            if outcome in ("confirmed", "failed", "needs_review"):
                try:
                    self.attack_memory.record(
                        scenario_id=sid,
                        endpoint=str(action.get("endpoint", "") or target),
                        outcome=outcome,
                        reason=str(result.get("reason", "")),
                    )
                    verification["recorded"] += 1
                except Exception:  # noqa: BLE001
                    pass
        self._log("verify", cycle, **verification)
        return verification

    def selfcheck(self, cycle: int) -> dict[str, Any]:
        """Red-vs-blue self-check of the HARDENED SSRF detector, with
        escapes fed to the postmortem store when one is configured.
        This is the loop proving its own detector still closes the
        tracked homoglyph escape."""
        if not self.config.enable_selfcheck:
            return {"selfcheck": "disabled"}
        try:
            report: RedVsBlueReport = run_red_vs_blue(
                seed_payload=self.config.selfcheck_seed_payload,
                seed_payload_label=self.config.selfcheck_seed_label,
                detector=extract_ssrf_indicators_hardened,
            )
        except Exception as exc:  # noqa: BLE001
            return {"selfcheck": "error", "error": str(exc)[:200]}
        escaped = [a.technique for a in report.escaped_techniques]
        if escaped and self.config.postmortem_manager is not None:
            try:
                from webpent.shared.red_vs_blue import feed_escapes_to_postmortem

                feed_escapes_to_postmortem(
                    report,
                    vuln_class="ssrf",
                    detector_name="extract_ssrf_indicators_hardened",
                    thread_id=self.config.thread_id,
                    postmortem_manager=self.config.postmortem_manager,
                )
            except Exception:  # noqa: BLE001 — postmortem is best-effort
                pass
        payload = {
            "selfcheck": "ran",
            "escape_rate": report.escape_rate,
            "escaped_techniques": escaped,
            "detector": "extract_ssrf_indicators_hardened",
        }
        self._log("selfcheck", cycle, **payload)
        return payload

    # -- the loop ----------------------------------------------------------
    def run_cycle(
        self,
        cycle: int,
        cycle_input: CampaignInput,
        executor: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """One full perceive → plan → act → verify (+selfcheck) cycle."""
        perception = self.perceive(cycle_input)
        actions = self.plan(cycle_input, perception)
        results = self.act(cycle, actions, executor)
        verification = self.verify(cycle, results)
        check = self.selfcheck(cycle)
        summary = {
            "cycle": cycle,
            "actions": [a.as_dict() for a in actions],
            "results": results,
            "verification": verification,
            "selfcheck": check,
            "perception": perception,
        }
        self._log("cycle_summary", cycle,
                  action_count=len(actions),
                  drift=perception.get("drift_high_priority", 0))
        return summary


def run_vip_campaign(
    inputs: Sequence[CampaignInput],
    *,
    config: VipOrchestratorConfig | None = None,
    ledger_path: str | None = None,
    executor: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run the full campaign loop: one :class:`CampaignInput` per
    cycle, capped at ``config.max_cycles``. Returns the campaign
    rollup; every step is also in the ledger when a path was given."""
    cfg = config or VipOrchestratorConfig()
    ledger = CampaignLedger(ledger_path) if ledger_path else None
    orch = VipOrchestrator(cfg, ledger=ledger)
    cycles_run: list[dict[str, Any]] = []
    for cycle, cycle_input in enumerate(inputs[: max(1, cfg.max_cycles)]):
        cycles_run.append(orch.run_cycle(cycle, cycle_input, executor))
    rollup = {
        "campaign_id": cfg.campaign_id,
        "cycles_run": len(cycles_run),
        "total_actions": sum(len(c["actions"]) for c in cycles_run),
        "downgraded": sum(c["verification"]["downgraded"] for c in cycles_run),
        "selfcheck_escape_rate": max(
            (c["selfcheck"].get("escape_rate", 0.0) for c in cycles_run),
            default=0.0,
        ),
        "cycles": cycles_run,
    }
    if ledger is not None:
        ledger.record("campaign_rollup", len(cycles_run), **{
            k: rollup[k] for k in ("total_actions", "downgraded", "selfcheck_escape_rate")
        })
    return rollup


__all__ = [
    "CampaignAction",
    "CampaignInput",
    "VipOrchestrator",
    "VipOrchestratorConfig",
    "run_vip_campaign",
]

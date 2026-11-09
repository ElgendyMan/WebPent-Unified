# src/webpent/graph/progress_display.py
"""Live phase-based progress rendering for unified hunt runs.

Ultimate plan 2026-10-27, proposal 12 (output clarity):

A campaign can run for hours; the legacy CLI printed a raw stream of
technical log lines, so the operator could not tell "where are we now"
without opening separate logs. This module renders a compact, honest
progress view FROM DATA THE RUN ALREADY PRODUCES (``node_step_trace``,
the findings channel, the facade's cost bookkeeping) — it invents no
numbers and adds no graph behavior.

Rendering contract:

* ``HuntProgressRenderer`` is a callable sink the unified hunt CLI
  installs around the graph stream. Each graph superstep produces one
  trace entry; the renderer maps the node name to its phase, counts
  confirmed findings, and re-renders a single terminal line (\\r) with
  the bar, the current phase, live finding/cost counts.
* It is display-only: no state mutation, no routing influence, no
  authority. When the terminal is not a TTY (CI, logs), it degrades to
  one compact line per PHASE CHANGE (not per step) so logs stay
  readable.
* The phase map is derived from the documented edge map in
  graph/builder.py — the eight phases the plan's sketch named.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Mapping
from typing import IO, Any

__all__ = ["HuntProgressRenderer", "phase_of_node", "PHASE_ORDER"]

#: The eight user-facing phases (plan, proposal 12 sketch). Node names
#: map through PHASE_OF_NODE below; unknown nodes keep the previous
#: phase (honest "still in <phase>" instead of a wrong guess).
PHASE_ORDER: tuple[str, ...] = (
    "التفويض والهدف",
    "التخطيط ودروس الحملات السابقة",
    "الاستطلاع والمصادقة",
    "الزحف وفهم الهدف",
    "قياس السطح وحماية WAF",
    "توليد الفرضيات",
    "التحقق بالأدلة",
    "المراجعة والتقرير",
)

_PHASE_OF_NODE: dict[str, int] = {
    "target_package_preflight": 0,
    "wildcard_scope": 0,
    "planner": 1,
    "lesson_consultation": 1,
    "auth": 2,
    "identity_provisioning": 2,
    "identity_provisioning_pre_auth": 2,
    "recon": 2,
    "research_campaign": 2,
    "recon_fanout": 2,
    "recon_join": 2,
    "subdomain_takeover": 3,
    "cloud_storage": 3,
    "crawler": 3,
    "javascript_intelligence": 3,
    "target_understanding": 3,
    "scope_enforcer": 4,
    "scope_review": 4,
    "waf_detector": 4,
    "surface_sizing": 4,
    "hypothesis": 5,
    "strategist": 5,
    "payload_optimizer": 5,
    "access_control": 5,
    "api_testing": 5,
    "business_logic_fuzzer": 5,
    "request_smuggling": 5,
    "graphql_testing": 5,
    "cache_poisoning": 5,
    "prototype_pollution": 5,
    "oauth_misconfig": 5,
    "disclosed_report_intel": 5,
    "payload_generator": 6,
    "execution_sandbox": 6,
    "validator": 6,
    "devils_advocate": 6,
    "exploit_chainer": 6,
    "post_exploitation": 6,
    "rabbit_hole": 6,
    "attack_graph": 6,
    "smart_campaigns": 6,
    "smart_campaigns_execution": 6,
    "autonomous_controller": 6,
    "cvss_engine": 7,
    "business_impact": 7,
    "cross_reasoning": 7,
    "executive_summary": 7,
    "reporter": 7,
    "reflection": 7,
    "lesson_extraction": 7,
    "recovery": 6,
    "knowledge_gap": 6,
    "next_best_action": 6,
    "research_session": 6,
    "active_research": 6,
    "causal_research": 6,
    "vip_orchestrator": 6,
}


def phase_of_node(node: str) -> int:
    """Map a graph node name to its 0-based phase index (best effort)."""
    return _PHASE_OF_NODE.get(node, -1)


class HuntProgressRenderer:
    """Display-only progress sink for a running unified hunt.

    Parameters
    ----------
    stream:
        Output stream (default ``sys.stderr`` so stdout stays
        machine-parseable).
    is_tty:
        When false (default auto-detect), render one line per phase
        change instead of a re-drawn live bar — CI/log friendly.
    """

    def __init__(
        self,
        *,
        stream: IO[str] | None = None,
        is_tty: bool | None = None,
        total_steps: int | None = None,
        target_url: str = "",
        time_budget_s: float | None = None,
        cost_ceiling_usd: float | None = None,
    ) -> None:
        self._stream = stream if stream is not None else sys.stderr
        if is_tty is None:
            try:
                is_tty = bool(self._stream.isatty())
            except (AttributeError, ValueError):
                is_tty = False
        self._tty = is_tty
        self._total = max(1, int(total_steps or 1))
        self._target = target_url[:60]
        # RESIDUAL CLOSURE 2026-10-29 (Track 9.1): elapsed time + the
        # DECLARED budget ceilings. Both are real: elapsed is measured,
        # ceilings are the mode preset the operator chose. Live LLM cost
        # is deliberately NOT invented — the runtime records
        # ``pricing_status: unpriced`` (shared/llm.py), so the ceiling is
        # shown as context and the end summary reports token usage.
        self._time_budget_s = time_budget_s
        self._cost_ceiling_usd = cost_ceiling_usd
        self._started = time.monotonic()
        self._steps = 0
        self._phase = -1
        self._findings_confirmed = 0
        self._findings_total = 0
        self._last_line_len = 0

    # -- data ingestion --------------------------------------------------
    def observe_trace(self, entry: Mapping[str, Any]) -> None:
        """Consume one node_step_trace entry (called per superstep)."""
        self._steps += 1
        phase = phase_of_node(str(entry.get("node", "")))
        if phase >= 0 and phase != self._phase:
            self._phase = phase
            self._render(force=True)
        elif self._tty:
            self._render(force=False)

    def observe_findings(self, findings: list[Any] | tuple[Any, ...]) -> None:
        """Count confirmed vs total findings (from the findings channel)."""
        # R2-graph-06: Finding has no validation_status attribute — the
        # confirmation lives in confidence ("confirmed") / confidence_level
        # ("Tool-Confirmed"), matching reducers._finding_strength. The old
        # lookup returned None for every finding, so the bar always showed
        # 0 confirmed.
        from webpent.state.reducers import _finding_strength, model_get

        confirmed = 0
        for finding in findings or ():
            confidence = str(model_get(finding, "confidence") or "").lower()
            level = str(
                model_get(finding, "confidence_level") or ""
            ).lower()
            is_confirmed = (
                confidence == "confirmed" or "tool-confirmed" in level
                or _finding_strength(finding) >= 3
            )
            confirmed += 1 if is_confirmed else 0
        self._findings_total = len(findings or ())
        self._findings_confirmed = confirmed
        if self._tty:
            self._render(force=False)

    # -- rendering --------------------------------------------------------
    @staticmethod
    def _fmt_elapsed(seconds: float) -> str:
        minutes, secs = divmod(max(0, int(seconds)), 60)
        return f"{minutes:02d}:{secs:02d}"

    def _render(self, *, force: bool) -> None:
        if not force and not self._tty:
            return
        filled = max(0, min(8, round(8 * self._steps / self._total)))
        bar = "█" * filled + "░" * (8 - filled)
        phase_label = (
            PHASE_ORDER[self._phase] if 0 <= self._phase < len(PHASE_ORDER)
            else "البداية"
        )
        elapsed = self._fmt_elapsed(time.monotonic() - self._started)
        time_part = f"{elapsed}"
        if self._time_budget_s:
            time_part += f"/{int(self._time_budget_s)}s"
        line = (
            f"[{bar}] المرحلة {max(1, self._phase + 1)}/8: {phase_label}"
            f" | ثغرات مؤكدة: {self._findings_confirmed}/{self._findings_total}"
            f" | خطوة {self._steps}"
            f" | الوقت {time_part}"
        )
        if self._cost_ceiling_usd is not None:
            line += f" | سقف تكلفة LLM: ${self._cost_ceiling_usd:g} (unpriced)"
        if self._target:
            line = f"{self._target} {line}"
        if self._tty:
            pad = max(0, self._last_line_len - len(line))
            self._stream.write("\r" + line + " " * pad)
            self._stream.flush()
            self._last_line_len = len(line)
        else:
            self._stream.write(line + "\n")
            self._stream.flush()

    def finish(self) -> None:
        """Print the final newline so the prompt returns cleanly."""
        if self._tty and self._last_line_len:
            self._stream.write("\n")
            self._stream.flush()

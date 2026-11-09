"""Judgment Council — U-JC-12: the Council Dashboard.

The operator's single view of the council's health, assembled from the
other JC modules — all local, all advisory (JC-L-1, JC-L-2: nothing is
fetched, nothing is executed, nothing mutates a live system):

    * recent sessions and their verdicts (from the council memory log)
    * dissent register health: recorded minorities, accuracy, persistent
    * calibration report (Brier score, drift, min-sample guard)
    * bias findings from the detector
    * override log stats (modes, operator accuracy)
    * alerts (empty on a clean state)

Everything is deterministic for identical inputs (JC-L-2/L-3) and every
record carries the transparency envelope (L-4). The CLI in
``webpent/cli/jc.py`` renders this as markdown or JSON and appends every
invocation to the capped, redacted audit log.
"""

from __future__ import annotations

import contextlib
import json
import logging
from pathlib import Path
from typing import Any

from webpent.jc.bias_detector import BiasDetector
from webpent.jc.calibration import ConfidenceCalibrator
from webpent.jc.dissent import DissentRegister
from webpent.jc.memory import CouncilMemory
from webpent.jc.override import OverrideProtocol

_LOG = logging.getLogger(__name__)

RECENT_SESSIONS = 10


class CouncilDashboard:
    """Assembles one advisory health snapshot from the JC state files."""

    def __init__(
        self,
        *,
        memory_path: Any,
        dissent_path: Any,
        calibration_path: Any,
        sessions_path: Any,
        override_path: Any | None = None,
        bias_history_path: Any | None = None,
    ) -> None:
        self.memory = CouncilMemory(memory_path)
        self.dissent = DissentRegister(dissent_path)
        self.calibrator = ConfidenceCalibrator(calibration_path)
        self.bias = BiasDetector(sessions_path, dissent_path,
                                 history_path=bias_history_path)
        self.overrides = (
            None if override_path is None else OverrideProtocol(override_path)
        )

    # ------------------------------------------------------------ build
    def build(self, *, window_days: int = 30, now_ts: float | None = None
              ) -> dict[str, Any]:
        """One dashboard snapshot (advisory only, L-4 envelope)."""
        entries = self.memory.all_entries()
        resolved = self._resolve_sessions(entries)
        recent = list(reversed(resolved))[:RECENT_SESSIONS]

        dissent_rows = list(self.dissent._resolve().values())
        persistent = self.dissent.get_persistent_minority()
        calibration = self.calibrator.report(window_days, now_ts=now_ts)
        bias_findings = self.bias.detect(window_days, now_ts=now_ts)

        override_stats: dict[str, Any] = {"n_overrides": 0, "modes": {},
                                          "operator_accuracy": None}
        if self.overrides is not None:
            rows = self.overrides.entries()
            modes: dict[str, int] = {}
            for row in rows:
                modes[row["mode"]] = modes.get(row["mode"], 0) + 1
            override_stats = {
                "n_overrides": len(rows),
                "modes": dict(sorted(modes.items())),
                "operator_accuracy": self.overrides.operator_accuracy(),
            }

        alerts = self._alerts(calibration, bias_findings, override_stats)
        return {
            "advisory": True,
            "n_sessions": len(resolved),
            "recent_sessions": recent,
            "dissent": {
                "n_dissent_records": len(dissent_rows),
                "persistent_minority": persistent,
            },
            "calibration": calibration.as_dict(),
            "bias_findings": [f.as_dict() for f in bias_findings],
            "overrides": override_stats,
            "alerts": alerts,
        }

    # ----------------------------------------------------------- helpers
    @staticmethod
    def _resolve_sessions(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Latest state per session_id, oldest first."""
        state: dict[str, dict[str, Any]] = {}
        for row in entries:
            sid = str(row.get("session_id") or "")
            if not sid:
                continue
            verdict = row.get("verdict") or {}
            state[sid] = {
                "session_id": sid,
                "question": row.get("question", ""),
                "action": verdict.get("action"),
                "confidence": verdict.get("confidence"),
                "confidence_tier": verdict.get("confidence_tier"),
                "escalate": verdict.get("escalate"),
                "n_dissent": len(verdict.get("dissent") or []),
                "outcome": row.get("outcome"),
                "ts": row.get("ts"),
            }
        return sorted(state.values(), key=lambda r: (r.get("ts") or 0.0, r["session_id"]))

    @staticmethod
    def _alerts(calibration: Any, bias_findings: list,
                override_stats: dict) -> list[str]:
        alerts = []
        if calibration.drift_detected:
            alerts.append(
                "confidence drift detected: recalibrate (mean predicted "
                f"{calibration.mean_predicted:.2f} vs mean actual "
                f"{calibration.mean_actual:.2f})"
            )
        for f in bias_findings:
            alerts.append(
                f"bias pattern {f.bias_type} (severity {f.severity:.2f}): "
                f"{f.recommendation}"
            )
        if override_stats.get("operator_accuracy") is not None:
            acc = override_stats["operator_accuracy"]
            if acc < 0.5:
                alerts.append(
                    f"operator override accuracy is {acc:.2f}; review the "
                    "override reasons before trusting manual calls"
                )
        return alerts

    # ---------------------------------------------------------- markdown
    def to_markdown(self, snapshot: dict[str, Any]) -> str:
        """Markdown rendering of the snapshot (structurally inert cells)."""
        def cell(text: Any) -> str:
            return " ".join(str(text if text is not None else "").splitlines()
                            ).replace("|", "\u00a6")

        lines = ["# Judgment Council dashboard", ""]
        lines.append(f"Sessions on record: {snapshot['n_sessions']}")
        lines.append("")
        lines.append("## Recent sessions")
        lines.append("")
        lines.append("| session | action | conf | tier | dissent | escalated |")
        lines.append("|---|---|---|---|---|---|")
        for s in snapshot["recent_sessions"]:
            lines.append(
                f"| {cell(s['session_id'][:12])} | {cell(s['action'])} | "
                f"{cell(s['confidence'])} | {cell(s['confidence_tier'])} | "
                f"{cell(s['n_dissent'])} | "
                f"{cell('yes' if s['escalate'] else 'no')} |"
            )
        cal = snapshot["calibration"]
        lines.append("")
        drift_txt = "yes" if cal["drift_detected"] else "no"
        lines.append(
            f"## Calibration\n\nBrier {cal['brier_score']:.4f} over "
            f"{cal['n_samples']} samples (drift: {drift_txt})\n\n"
            f"{cal['recommendation']}"
        )
        dissent = snapshot["dissent"]
        lines.append("")
        minority = ", ".join(dissent["persistent_minority"]) or "none"
        lines.append(
            f"## Dissent\n\n{dissent['n_dissent_records']} minority records; "
            f"persistent minority: {minority}"
        )
        lines.append("")
        lines.append("## Bias findings")
        if snapshot["bias_findings"]:
            for f in snapshot["bias_findings"]:
                lines.append(
                    f"- {f['bias_type']} (severity {f['severity']:.2f}): "
                    f"{f['recommendation']}"
                )
        else:
            lines.append("none detected")
        ov = snapshot["overrides"]
        lines.append("")
        modes = ", ".join(f"{m}={n}" for m, n in ov["modes"].items()) or "none"
        acc = ("n/a" if ov["operator_accuracy"] is None
               else f"{ov['operator_accuracy']:.2f}")
        lines.append(
            f"## Overrides\n\n{ov['n_overrides']} recorded; modes {modes}; "
            f"operator accuracy {acc}"
        )
        if snapshot["alerts"]:
            lines.append("")
            lines.append("## Alerts")
            for a in snapshot["alerts"]:
                lines.append(f"- {cell(a)}")
        lines.append("")
        lines.append("_Advisory only (JC-L-1): this dashboard decides nothing._")
        return "\n".join(lines)


def load_jsonl(path: Any) -> list[dict[str, Any]]:
    """Best-effort JSONL reader used by the CLI for raw state dumps."""
    rows = []
    try:
        lines = Path(str(path)).read_text(encoding="utf-8").splitlines()
    except OSError:
        return rows
    for line in lines:
        row = None
        with contextlib.suppress(ValueError):
            row = json.loads(line)
        if isinstance(row, dict):
            rows.append(row)
    return rows


__all__ = ["CouncilDashboard", "load_jsonl"]

"""Judgment Council operator commands (U-JC-12).

``webpent jc`` is the operator console for the council: every command
reads local state (council memory, dissent register, calibration log,
session log, override log), runs a deterministic advisory module, and
prints JSON (or markdown for the dashboard/digest). Nothing is fetched
(JC-L-2), nothing is executed (JC-L-1), and every invocation is appended
to the capped, redacted audit log at ``<state-dir>/audit.jsonl``.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Annotated

import typer

from webpent.autonomous.hunt_contracts import redact
from webpent.jc.dashboard import CouncilDashboard, load_jsonl

jc_app = typer.Typer(
    name="jc",
    help="The Judgment Council: meta-cognition console (advisory only, local data).",
    no_args_is_help=True,
)

AUDIT_LIMIT = 1000
MAX_TEXT = 200


def _state_dir() -> Path:
    env = os.environ.get("WEBPENT_JC_DIR")
    return Path(env) if env else Path("download/jc")


def _path_of(name: str, explicit: Path | None) -> Path:
    if explicit is not None:
        return Path(explicit)
    env = os.environ.get(f"WEBPENT_JC_{name.upper()}")
    return Path(env) if env else _state_dir() / name


def _audit(*, command: str, **fields: object) -> None:
    """Append one redacted JSON line, then cap the log (every command audited)."""
    entry = {
        "ts": round(time.time(), 3),
        "command": redact(command)[:40],
        **{
            key: redact("" if value is None else str(value))[:MAX_TEXT]
            for key, value in fields.items()
        },
    }
    path = _state_dir() / "audit.jsonl"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        lines = [line for line in lines if line.strip()]
        lines.append(json.dumps(entry, ensure_ascii=False))
        keep = lines[-AUDIT_LIMIT:]
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("\n".join(keep) + "\n")
            os.replace(tmp_name, path)
        except BaseException:
            with suppress(OSError):
                os.unlink(tmp_name)
            raise
    except OSError:
        pass  # audit is best-effort; the command's answer matters more


def _emit(payload: object) -> None:
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _dashboard(explicit: Path | None) -> CouncilDashboard:
    return CouncilDashboard(
        memory_path=_path_of("memory.jsonl", None),
        dissent_path=_path_of("dissent.jsonl", None),
        calibration_path=_path_of("calibration.jsonl", None),
        sessions_path=_path_of("sessions.jsonl", None),
        override_path=_path_of("overrides.jsonl", None),
        bias_history_path=_state_dir() / "bias_history.jsonl",
    )


# ---------------------------------------------------------------- sessions
@jc_app.command("sessions")
def sessions(
    limit: Annotated[int, typer.Option("--limit", help="How many recent sessions.")] = 10,
) -> None:
    """List recorded council sessions, most recent first (advisory)."""
    _audit(command="jc sessions", limit=limit)
    rows = load_jsonl(_path_of("sessions.jsonl", None))
    keep = list(reversed(rows))[: max(0, int(limit))]
    _emit({"count": len(keep), "sessions": keep, "advisory": True})


# ---------------------------------------------------------------- verdicts
@jc_app.command("verdicts")
def verdicts(
    limit: Annotated[int, typer.Option("--limit", help="How many recent verdicts.")] = 10,
) -> None:
    """Show recent verdicts with their reasoning envelope (advisory)."""
    _audit(command="jc verdicts", limit=limit)
    rows = load_jsonl(_path_of("memory.jsonl", None))
    verdict_rows = [r for r in reversed(rows) if isinstance(r.get("verdict"), dict)]
    keep = [r.get("verdict") for r in verdict_rows[: max(0, int(limit))]]
    _emit({"count": len(keep), "verdicts": keep, "advisory": True})


# ------------------------------------------------------------- calibration
@jc_app.command("calibration")
def calibration(
    window_days: Annotated[int, typer.Option("--window-days", help="Window size.")] = 30,
) -> None:
    """Brier score, buckets and drift for recorded confidence (advisory)."""
    _audit(command="jc calibration", window=window_days)
    from webpent.jc.calibration import ConfidenceCalibrator

    report = ConfidenceCalibrator(_path_of("calibration.jsonl", None)).report(
        window_days
    )
    _emit(report.as_dict())


# -------------------------------------------------------------------- bias
@jc_app.command("bias")
def bias(
    window_days: Annotated[int, typer.Option("--window-days", help="Window size.")] = 30,
) -> None:
    """Run the five documented bias-pattern checks over the window (advisory)."""
    _audit(command="jc bias", window=window_days)
    from webpent.jc.bias_detector import BiasDetector

    detector = BiasDetector(
        _path_of("sessions.jsonl", None),
        _path_of("dissent.jsonl", None),
        history_path=_state_dir() / "bias_history.jsonl",
    )
    findings = detector.detect(window_days)
    _emit({"count": len(findings), "findings": [f.as_dict() for f in findings],
           "advisory": True})


# ---------------------------------------------------------------- override
@jc_app.command("override")
def override(
    session_id: Annotated[str, typer.Argument(..., help="Session id to override.")],
    mode: Annotated[str, typer.Option("--mode", help="full / partial / advisory.")] = "advisory",
    reason: Annotated[str, typer.Option("--reason", help="Why (required by policy).")] = "",
    final_action: Annotated[str | None, typer.Option(
        "--final-action", help="The operator's final action for full overrides."
    )] = None,
) -> None:
    """Record an operator override of one council verdict (JC-L-7)."""
    _audit(command="jc override", session=session_id, mode=mode)
    from datetime import datetime, timezone

    from webpent.jc.contracts import Verdict
    from webpent.jc.override import OverrideProtocol

    def _ts(value: object) -> datetime:
        with suppress(TypeError, ValueError):
            parsed = datetime.fromisoformat(str(value))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        return datetime(1970, 1, 1, tzinfo=timezone.utc)

    verdict_row = None
    for row in load_jsonl(_path_of("memory.jsonl", None)):
        if str(row.get("session_id") or "") == session_id:
            verdict_row = row.get("verdict")
    if not isinstance(verdict_row, dict):
        _emit({"recorded": False, "error": f"no verdict recorded for {session_id}",
               "advisory": True})
        return
    verdict = Verdict(
        action=verdict_row.get("action", "none"),
        reasoning=verdict_row.get("reasoning", ""),
        confidence=verdict_row.get("confidence", 0.0),
        confidence_tier=verdict_row.get("confidence_tier", "low"),
        dissent=[],
        escalate=bool(verdict_row.get("escalate")),
        escalation_reason=verdict_row.get("escalation_reason"),
        advocates_summary=verdict_row.get("advocates_summary", {}),
        session_id=session_id,
        timestamp=_ts(verdict_row.get("timestamp")),
    )
    try:
        entry = OverrideProtocol(_path_of("overrides.jsonl", None)).apply(
            verdict, mode, reason, final_action=final_action
        )
    except ValueError as exc:
        _emit({"recorded": False, "error": str(exc), "advisory": True})
        return
    _emit({"recorded": True, "entry": entry})


# --------------------------------------------------------------- dashboard
@jc_app.command("dashboard")
def dashboard(
    window_days: Annotated[int, typer.Option("--window-days", help="Window size.")] = 30,
    as_markdown: Annotated[bool, typer.Option(
        "--markdown", help="Render as markdown instead of JSON."
    )] = False,
) -> None:
    """The single council health view (advisory)."""
    _audit(command="jc dashboard", window=window_days)
    snap = _dashboard(None).build(window_days=window_days)
    if as_markdown:
        typer.echo(_dashboard(None).to_markdown(snap))
        return
    _emit(snap)


# ------------------------------------------------------------------ digest
@jc_app.command("digest")
def digest(
    window_days: Annotated[int, typer.Option("--window-days", help="Window size.")] = 30,
) -> None:
    """Short markdown daily digest of the council's state (advisory)."""
    _audit(command="jc digest", window=window_days)
    board = _dashboard(None)
    snap = board.build(window_days=window_days)
    cal = snap["calibration"]
    dissent = snap["dissent"]
    ov = snap["overrides"]
    lines = [
        "# Judgment Council digest",
        "",
        f"- sessions on record: {snap['n_sessions']}",
        f"- calibration: Brier {cal['brier_score']:.4f} over {cal['n_samples']} samples",
        f"- minority records: {dissent['n_dissent_records']}; persistent minority: "
        + (", ".join(dissent["persistent_minority"]) or "none"),
        f"- bias findings: {len(snap['bias_findings'])}",
        f"- overrides: {ov['n_overrides']} recorded",
    ]
    for alert in snap["alerts"][:5]:
        lines.append(f"- ALERT: {alert}")
    lines.append("")
    lines.append("_Advisory only (JC-L-1)._")
    typer.echo("\n".join(lines))


__all__ = ["jc_app"]

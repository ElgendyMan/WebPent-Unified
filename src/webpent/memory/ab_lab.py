"""Lesson A/B lab — weekly control-vs-treatment windows (Track 6.5, v0.27.0).

Closes the residual declared in ``docs/learning_source_of_truth.md``
(Track 6.5 had only the schema ``integration/learning_ab_contract.py``
and the observational ``memory/improvement_tracker.py``): this module
is the REAL control-vs-treatment lab runner plus the DECLARED numeric
thresholds for its verdict (plan: ``docs/PRODUCTION_FIX_PLAN_0270.md``,
items C-9 and C-10).

C-9 — the weekly dual-window scheduler
--------------------------------------
Every ISO week, per ``(client_id, target_url)`` registered with
:meth:`LessonABLab.open_week`, the lab opens exactly ONE pair of real
windows on the SAME target, in the SAME mode, run SEQUENTIALLY
(never in parallel — one target must not be hit by two arms at once):

1. ``control``   — the real campaign with the lesson loop OFF
                   (``ENABLE_LESSON_CONSULTATION=false``);
2. ``treatment`` — the real campaign with the lesson loop ON (the
                   governed default, ``enable_lesson_consultation=true``).

The scheduler itself never executes a campaign: it owns WINDOWS and
EVIDENCE. Execution goes through an injected ``runner`` callable
(``runner(spec) -> {"ok": bool, "error": str|None, "metrics": dict|None}``).
The shipped production runner is :func:`make_hunt_subprocess_runner`
(a real ``webpent hunt`` subprocess with the per-arm env flag so the
toggle is isolated at process level). Tests inject fakes.

Metrics honesty (declared, not hidden): the lab accepts metrics from
three sources, in order — (1) the runner's own ``metrics`` digest,
(2) an injected ``metrics_lookup`` (the service architecture:
``MultiCampaignService.complete`` → ``persist_campaign_learning`` →
``ImprovementTracker.record_campaign`` records metrics with the
campaign id, so ``metrics_lookup`` is a one-liner over that store),
(3) an explicit :meth:`LessonABLab.record_run_metrics` post. When none
produces metrics the arm is marked ``metrics_missing`` and the week
evaluates to ``inconclusive`` with that declared reason — the lab
NEVER invents numbers.

C-10 — the declared numeric thresholds
--------------------------------------
``AB_THRESHOLDS`` below is the single declared constant set; the plan
file ``docs/PRODUCTION_FIX_PLAN_0270.md`` copies these values verbatim.
:func:`evaluate_ab_pair` is the ONLY place a verdict is computed — a
pure, deterministic function whose output vocabulary matches the
frozen ``ABEvidence`` contract exactly
(``learning_proven`` | ``inconclusive`` | ``learning_not_observed``).

Additive posture: a standalone SQLite store, default-off usage, no
campaign behavior change, no security outcome touched — same posture
as ``ImprovementTracker`` (fail-open measurement).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path
from typing import Any

__all__ = [
    "AB_THRESHOLDS",
    "ABThresholds",
    "ABRunSpec",
    "LessonABLab",
    "evaluate_ab_pair",
    "make_hunt_subprocess_runner",
    "make_tracker_metrics_lookup",
]

#: Verdict vocabulary — must stay aligned with the frozen
#: ``integration/learning_ab_contract.ABEvidence.verdict`` values.
VERDICT_PROVEN = "learning_proven"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_NOT_OBSERVED = "learning_not_observed"

_ARM_CONTROL = "control"
_ARM_TREATMENT = "treatment"
#: Declared execution order — control first, treatment second,
#: strictly sequential (one target, no overlap).
ARM_ORDER = (_ARM_CONTROL, _ARM_TREATMENT)


@dataclass(frozen=True)
class ABThresholds:
    """C-10 — the declared numeric decision thresholds.

    These are the ONLY numbers the verdict may consult. Frozen at
    module level as ``AB_THRESHOLDS``; the evaluation function takes
    them as a parameter so tests can exercise the boundaries without
    mutating module state.
    """

    #: Arms below this many TESTED hypotheses are too small to judge
    #: — the week is inconclusive with reason ``sample_too_small``.
    min_hypotheses_tested_per_arm: int = 10
    #: Treatment must cut tested-hypotheses-per-confirmed-finding by at
    #: least this ratio versus control to be declared ``learning_proven``.
    promotion_reduction_ratio: float = 0.10
    #: Treatment WORSE than control by at least this ratio (efficiency
    #: gain <= -tolerance) is declared ``learning_not_observed``.
    regression_tolerance_ratio: float = 0.20
    #: Any confirmed-finding LOSS in treatment versus control caps the
    #: verdict at ``learning_not_observed`` regardless of efficiency —
    #: learning that costs findings is not learning (safety first).
    require_no_confirmed_loss: bool = True
    #: After this many consecutive inconclusive weeks the lab status
    #: raises a ``paused_advisory`` flag (an operator recommendation,
    #: never an automatic block).
    max_inconclusive_weeks: int = 4

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


#: The declared thresholds (docs/PRODUCTION_FIX_PLAN_0270.md, C-10).
AB_THRESHOLDS = ABThresholds()


def evaluate_ab_pair(
    *,
    control: dict[str, Any] | None,
    treatment: dict[str, Any] | None,
    thresholds: ABThresholds = AB_THRESHOLDS,
) -> dict[str, Any]:
    """C-10 — the pure, deterministic verdict function.

    ``control``/``treatment`` are metric dicts with the declared schema
    ``{"hypotheses_tested": int>=0, "findings_promoted": int>=0}``
    (``None`` = arm has no metrics). Returns
    ``{"verdict": str, "reasons": list[str], "effect": dict|None}``.

    Strict evaluation order (the declared rule):

    1. any arm missing metrics, or below
       ``min_hypotheses_tested_per_arm`` -> ``inconclusive``
       (reasons: ``metrics_missing`` / ``sample_too_small``);
    2. ``require_no_confirmed_loss`` and treatment confirmed findings
       dropped versus control -> ``learning_not_observed``
       (reason: ``confirmed_findings_lost``);
    3. efficiency gain
       ``1 - (t_tested/t_conf) / (c_tested/c_conf)`` —
       ``>= promotion_reduction_ratio`` -> ``learning_proven``;
       ``<= -regression_tolerance_ratio`` -> ``learning_not_observed``;
       otherwise ``inconclusive`` (reason: ``within_noise_band``).
    """
    reasons: list[str] = []
    if control is None or treatment is None:
        if control is None:
            reasons.append("control_metrics_missing")
        if treatment is None:
            reasons.append("treatment_metrics_missing")
        return {"verdict": VERDICT_INCONCLUSIVE, "reasons": reasons, "effect": None}

    def _int(mapping: dict[str, Any], key: str) -> int:
        try:
            return max(0, int(mapping.get(key) or 0))
        except (TypeError, ValueError):
            return 0

    c_tested = _int(control, "hypotheses_tested")
    t_tested = _int(treatment, "hypotheses_tested")
    c_conf = _int(control, "findings_promoted")
    t_conf = _int(treatment, "findings_promoted")

    minimum = int(thresholds.min_hypotheses_tested_per_arm)
    if c_tested < minimum or t_tested < minimum:
        if c_tested < minimum:
            reasons.append(f"control_sample_too_small:{c_tested}<{minimum}")
        if t_tested < minimum:
            reasons.append(f"treatment_sample_too_small:{t_tested}<{minimum}")
        return {
            "verdict": VERDICT_INCONCLUSIVE,
            "reasons": reasons,
            "effect": {"control_tested": c_tested, "treatment_tested": t_tested,
                       "control_confirmed": c_conf, "treatment_confirmed": t_conf},
        }

    if thresholds.require_no_confirmed_loss and t_conf < c_conf:
        reasons.append(f"confirmed_findings_lost:{t_conf}<{c_conf}")
        return {
            "verdict": VERDICT_NOT_OBSERVED,
            "reasons": reasons,
            "effect": {"control_tested": c_tested, "treatment_tested": t_tested,
                       "control_confirmed": c_conf, "treatment_confirmed": t_conf},
        }

    # Efficiency = tested hypotheses per confirmed finding (lower is
    # better). Guard: both arms have >=1 confirmed here unless one arm
    # confirmed ZERO findings — then efficiency is undefined and the
    # honest verdict is inconclusive (no confirmed anchor to compare).
    if c_conf == 0 and t_conf == 0:
        reasons.append("no_confirmed_findings_in_both_arms")
        return {
            "verdict": VERDICT_INCONCLUSIVE,
            "reasons": reasons,
            "effect": {"control_tested": c_tested, "treatment_tested": t_tested,
                       "control_confirmed": 0, "treatment_confirmed": 0},
        }
    if c_conf == 0 or t_conf == 0:
        # Exactly one arm produced findings. If treatment is the
        # producer, learning plausibly helped reach them — but a single
        # asymmetric week is not proof; declare inconclusive with the
        # declared reason and the raw counts for the operator.
        reasons.append(
            f"confirmed_findings_asymmetric:control={c_conf},treatment={t_conf}"
        )
        return {
            "verdict": VERDICT_INCONCLUSIVE,
            "reasons": reasons,
            "effect": {"control_tested": c_tested, "treatment_tested": t_tested,
                       "control_confirmed": c_conf, "treatment_confirmed": t_conf},
        }

    c_efficiency = Fraction(int(c_tested), int(c_conf))
    t_efficiency = Fraction(int(t_tested), int(t_conf))
    # Exact rational arithmetic: the declared boundaries (0.10 / 0.20)
    # must hold AT the boundary — float division would make
    # ``1 - 9/10`` land at 0.0999… and flip declared outcomes.
    # ``Fraction(str(x))`` reads each declared decimal literal exactly.
    gain = Fraction(1) - t_efficiency / c_efficiency
    promotion = Fraction(str(float(thresholds.promotion_reduction_ratio)))
    regression = Fraction(str(float(thresholds.regression_tolerance_ratio)))
    gain_float = round(float(gain), 6)
    effect = {
        "control_tested": c_tested,
        "treatment_tested": t_tested,
        "control_confirmed": c_conf,
        "treatment_confirmed": t_conf,
        "control_efficiency": round(float(c_efficiency), 6),
        "treatment_efficiency": round(float(t_efficiency), 6),
        "efficiency_gain": gain_float,
    }
    if gain >= promotion:
        reasons.append(f"efficiency_gain:{gain_float}>=+{thresholds.promotion_reduction_ratio:g}")
        return {"verdict": VERDICT_PROVEN, "reasons": reasons, "effect": effect}
    if gain <= -regression:
        reasons.append(f"efficiency_gain:{gain_float}<=-{thresholds.regression_tolerance_ratio:g}")
        return {"verdict": VERDICT_NOT_OBSERVED, "reasons": reasons, "effect": effect}
    reasons.append("within_noise_band")
    return {"verdict": VERDICT_INCONCLUSIVE, "reasons": reasons, "effect": effect}


@dataclass(frozen=True)
class ABRunSpec:
    """What a runner receives for one arm's window. Pure data."""

    week_key: str
    arm: str
    run_id: str
    campaign_id: str
    client_id: str
    target_url: str
    target_type: str
    mode: str
    authorization_ref: str
    lesson_flag: str  # "false" (control) | "true" (treatment)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


_RUNNER_TYPE = Callable[[ABRunSpec], dict[str, Any]]
_LOOKUP_TYPE = Callable[[str], dict[str, Any] | None]

_WEEK_TERMINAL = frozenset({"evaluated", "failed"})
_RUN_TERMINAL = frozenset({"completed", "failed", "metrics_missing"})

# P1-08 (0.33.0): the runner executes SYNCHRONOUSLY inside tick(), so a
# ``running`` row that outlives this constant is by definition orphaned by
# a crashed process. Such a row is reclaimed to ``failed`` during selection
# instead of head-of-line-blocking every newer week forever (the operator
# reset_stale_run escape hatch stays, but is no longer the ONLY recovery).
RUNNING_RUN_STALE_AFTER_SECONDS = 24 * 3600


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _now_text() -> str:
    return _utcnow().isoformat()


class LessonABLab:
    """C-9 — the weekly dual-window A/B scheduler and evidence store.

    Additive SQLite store (``ab_lab.sqlite3``). Lifecycle per week::

        planned -> control_done -> evaluated      (both arms produced evidence)
        planned -> control_done -> failed         (treatment run failed)
        planned -> failed                         (control run failed)
        any running arm -> metrics_missing run    (week still evaluates,
                                                   verdict inconclusive)

    Idempotency: ``open_week`` is unique per
    ``(week_key, client_id, target_url)``. ``tick`` executes AT MOST
    ONE due run per call (the declared sequential policy) and is safe
    to call repeatedly (a cron/loop calls it hourly; the oldest
    non-terminal week with a due run wins, so windows straddling an
    ISO boundary still complete).
    """

    def __init__(
        self,
        database_path: str | Path = "./memory/global/ab_lab.sqlite3",
        *,
        thresholds: ABThresholds = AB_THRESHOLDS,
        metrics_lookup: _LOOKUP_TYPE | None = None,
    ) -> None:
        self.path = Path(database_path)
        self.thresholds = thresholds
        self._metrics_lookup = metrics_lookup
        self._lock = threading.RLock()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        # One persistent connection (":memory:" stays addressable across
        # calls; file paths get WAL-free single-writer semantics guarded
        # by the RLock — same concurrency posture as ImprovementTracker).
        self._conn = sqlite3.connect(str(self.path), timeout=10.0, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init()

    # -- storage ----------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        return self._conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS ab_weeks (
                week_key TEXT NOT NULL, client_id TEXT NOT NULL,
                target_url TEXT NOT NULL, target_type TEXT NOT NULL,
                mode TEXT NOT NULL, authorization_ref TEXT NOT NULL,
                status TEXT NOT NULL, verdict_json TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                PRIMARY KEY (week_key, client_id, target_url)
            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS ab_runs (
                run_id TEXT PRIMARY KEY, week_key TEXT NOT NULL,
                client_id TEXT NOT NULL, target_url TEXT NOT NULL,
                arm TEXT NOT NULL, campaign_id TEXT NOT NULL,
                status TEXT NOT NULL, lesson_flag TEXT NOT NULL,
                metrics_json TEXT, metrics_source TEXT,
                error TEXT, started_at TEXT, finished_at TEXT,
                UNIQUE (week_key, client_id, target_url, arm)
            )""")

    # -- opening weeks (C-9) ----------------------------------------------

    @staticmethod
    def week_key_for(now: datetime | None = None) -> str:
        stamp = (now or _utcnow()).isocalendar()
        return f"AB-{stamp.year}-W{stamp.week:02d}"

    def open_week(
        self,
        *,
        client_id: str,
        target_url: str,
        mode: str,
        authorization_ref: str,
        target_type: str = "generic_web",
        now: str | None = None,
    ) -> dict[str, Any]:
        """Open this ISO week's control/treatment pair (idempotent).

        Fail-closed: empty ``client_id``/``target_url``/``authorization_ref``
        raise ``ValueError`` — the lab never schedules an unverified
        campaign. Authorization is a REFERENCE (the runner passes it to
        ``webpent hunt --authorization`` which validates it downstream);
        the lab does not verify scope itself (same posture as the
        scheduler: coordination, not authority).
        """
        client_id = str(client_id or "").strip()
        target_url = str(target_url or "").strip()
        authorization_ref = str(authorization_ref or "").strip()
        mode = str(mode or "").strip() or "standard"
        if not client_id:
            raise ValueError("ab_lab_client_id_required")
        if not target_url:
            raise ValueError("ab_lab_target_url_required")
        if not authorization_ref:
            raise ValueError("ab_lab_authorization_required")

        stamp = _utcnow() if not now else datetime.fromisoformat(now.replace("Z", "+00:00"))
        week_key = self.week_key_for(stamp)
        created = _now_text()
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM ab_weeks WHERE week_key=? AND client_id=? AND target_url=?",
                (week_key, client_id, target_url),
            ).fetchone()
            if existing is not None:
                # P1-03 (0.33.0): idempotent re-open must not silently run
                # the week under STALE parameters — a second open_week with
                # a different mode/authorization_ref/target_type used to be
                # accepted and ignored, so the week executed under the OLD
                # authorization reference. Fail closed with the offending
                # fields instead.
                mismatches = [
                    field_name for field_name, wanted, have in (
                        ("mode", mode, existing["mode"]),
                        ("target_type", str(target_type)[:80],
                         existing["target_type"]),
                        ("authorization_ref", authorization_ref,
                         existing["authorization_ref"]),
                    ) if str(have or "") != str(wanted or "")
                ]
                if mismatches:
                    raise ValueError(
                        "ab_lab_week_param_mismatch:" + ",".join(mismatches)
                    )
                return {**dict(existing), "already_open": True}
            conn.execute(
                "INSERT INTO ab_weeks(week_key,client_id,target_url,target_type,mode,"
                "authorization_ref,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (week_key, client_id, target_url, str(target_type)[:80], str(mode)[:32],
                 authorization_ref, "planned", created, created),
            )
            # F-01 (0.33.0): run_id MUST include a target digest — the old
            # "{week_key}-{arm}-{client_id[:24]}" collided the moment the
            # same client registered a SECOND target in the same ISO week
            # (UNIQUE constraint on ab_runs.run_id failed open_week forever).
            target_digest = hashlib.sha256(target_url.encode("utf-8")).hexdigest()[:8]
            for arm in ARM_ORDER:
                run_id = f"{week_key}-{arm}-{client_id[:16]}-{target_digest}"
                conn.execute(
                    "INSERT INTO ab_runs(run_id,week_key,client_id,target_url,arm,campaign_id,"
                    "status,lesson_flag) VALUES(?,?,?,?,?,?,?,?)",
                    (run_id[:160], week_key, client_id, target_url, arm,
                     run_id[:160], "planned",
                     "false" if arm == _ARM_CONTROL else "true"),
                )
        return {"week_key": week_key, "client_id": client_id,
                "target_url": target_url, "status": "planned", "already_open": False}

    # -- ticking (C-9) ------------------------------------------------------

    def tick(
        self,
        *,
        now: str | None = None,
        runner: _RUNNER_TYPE | None = None,
        week_key: str | None = None,
    ) -> dict[str, Any]:
        """Execute at most ONE due run.

        Without ``week_key`` the OLDEST non-terminal week with a due
        run wins (so a week straddling an ISO boundary still completes
        — the declared sequential policy does not strand windows).
        Without a ``runner`` this is a DRY PLAN: returns what WOULD run
        (``action="planned_run"``, no execution) — the honest default.
        With a runner, the due arm executes synchronously; the following
        arm becomes due on the NEXT tick (declared sequential policy).
        """
        del now  # kept for call-site symmetry; week identity drives selection
        due = self._next_due_run(week_key)
        if due is None:
            self._finalize_eligible_weeks(week_key)
            return {"action": "none", "week_key": week_key or "any",
                    "reason": "no_due_run"}
        week_row, run = due
        if runner is None:
            return {"action": "planned_run", "week_key": week_row["week_key"],
                    "run_id": run["run_id"], "arm": run["arm"],
                    "lesson_flag": run["lesson_flag"], "executed": False}
        return self._execute_run(week_row, run, runner)

    def _next_due_run(
        self, week_key: str | None
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """Pick the one due run: lowest arm index whose predecessor arm
        reached a terminal state, in the oldest active week first."""
        with self._lock, self._connect() as conn:
            if week_key is None:
                week = conn.execute(
                    "SELECT * FROM ab_weeks WHERE status NOT IN "
                    f"({','.join('?' for _ in _WEEK_TERMINAL)}) ORDER BY created_at LIMIT 1",
                    tuple(_WEEK_TERMINAL),
                ).fetchone()
            else:
                week = conn.execute(
                    "SELECT * FROM ab_weeks WHERE week_key=? AND status NOT IN "
                    f"({','.join('?' for _ in _WEEK_TERMINAL)}) ORDER BY created_at LIMIT 1",
                    (week_key, *_WEEK_TERMINAL),
                ).fetchone()
            if week is None:
                return None
            runs = conn.execute(
                "SELECT * FROM ab_runs WHERE week_key=? AND client_id=? AND target_url=?",
                (week["week_key"], week["client_id"], week["target_url"]),
            ).fetchall()
            by_arm = {row["arm"]: dict(row) for row in runs}
            for index, arm in enumerate(ARM_ORDER):
                if index > 0:
                    previous = by_arm.get(ARM_ORDER[index - 1])
                    if previous is None or previous["status"] not in _RUN_TERMINAL:
                        return None  # predecessor not terminal — not due
                run = by_arm.get(arm)
                if run is None:
                    return None
                if run["status"] in _RUN_TERMINAL:
                    continue
                if run["status"] == "running":
                    # P1-08 (0.33.0): reclaim a crashed run instead of
                    # blocking all newer weeks forever. A live synchronous
                    # runner can never be selected here (it holds the loop),
                    # so age beyond the constant proves the process died.
                    started_at = run["started_at"]
                    if started_at:
                        try:
                            age = (_utcnow() - datetime.fromisoformat(
                                str(started_at).replace("Z", "+00:00")
                            )).total_seconds()
                        except ValueError:
                            age = -1.0  # unparsable — leave for the operator
                        if age > RUNNING_RUN_STALE_AFTER_SECONDS:
                            conn.execute(
                                "UPDATE ab_runs SET status='failed', "
                                "error='stale_running_reclaimed', finished_at=? "
                                "WHERE run_id=? AND status='running'",
                                (_now_text(), run["run_id"]),
                            )
                            by_arm[arm]["status"] = "failed"
                            continue  # successor arm becomes due
                    return None  # in progress (or unparsable — operator resets)
                return (dict(week), run)
            return None

    def _execute_run(
        self, week_row: dict[str, Any], run: dict[str, Any], runner: _RUNNER_TYPE
    ) -> dict[str, Any]:
        spec = ABRunSpec(
            week_key=week_row["week_key"], arm=run["arm"], run_id=run["run_id"],
            campaign_id=run["campaign_id"], client_id=week_row["client_id"],
            target_url=week_row["target_url"], target_type=week_row["target_type"],
            mode=week_row["mode"], authorization_ref=week_row["authorization_ref"],
            lesson_flag=run["lesson_flag"],
        )
        started = _now_text()
        # P1-02 (0.33.0): atomic claim. The old unconditional update meant
        # two interleaved tick() calls could both pass _next_due_run and
        # execute the SAME window twice — a direct violation of the declared
        # "run SEQUENTIALLY (never in parallel)" policy. Only a 'planned'
        # row can be claimed; the loser returns an honest no-op.
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE ab_runs SET status='running', started_at=? "
                "WHERE run_id=? AND status='planned'",
                (started, run["run_id"]),
            )
        if cursor.rowcount != 1:
            return {"action": "already_claimed", "week_key": week_row["week_key"],
                    "run_id": run["run_id"], "arm": run["arm"],
                    "executed": False,
                    "reason": "another tick claimed this run first"}
        try:
            outcome = runner(spec)
        except Exception as exc:  # noqa: BLE001 — runner is a plugin boundary
            outcome = {"ok": False, "error": f"runner_raised:{type(exc).__name__}:{exc}"}
        if not isinstance(outcome, dict) or not outcome.get("ok"):
            error = str((outcome or {}).get("error") or "runner_failed")[:500]
            self._update_run(run["run_id"], status="failed", error=error,
                             finished_at=_now_text())
            self._touch_week(week_row["week_key"], week_row["client_id"], week_row["target_url"])
            self._finalize_eligible_weeks()
            return {"action": "run_failed", "week_key": week_row["week_key"],
                    "run_id": run["run_id"], "arm": run["arm"], "error": error}

        metrics = outcome.get("metrics")
        metrics_source = "runner"
        if not isinstance(metrics, dict):
            metrics = None
            if self._metrics_lookup is not None:
                try:
                    looked = self._metrics_lookup(run["campaign_id"])
                except Exception:  # noqa: BLE001 — lookup is a plugin boundary
                    looked = None
                if isinstance(looked, dict):
                    metrics = looked
                    metrics_source = "metrics_lookup"
        if isinstance(metrics, dict):
            cleaned = self._validate_metrics(metrics)
            if cleaned is None:
                metrics = None
            else:
                self._update_run(run["run_id"], metrics_json=json.dumps(cleaned, sort_keys=True),
                                 metrics_source=metrics_source)
        if metrics is None:
            self._update_run(run["run_id"], status="metrics_missing",
                             finished_at=_now_text())
        else:
            self._update_run(run["run_id"], status="completed",
                             finished_at=_now_text())
        week_status = "control_done" if run["arm"] == _ARM_CONTROL else week_row["status"]
        self._touch_week(week_row["week_key"], week_row["client_id"],
                         week_row["target_url"], status=week_status)
        self._finalize_eligible_weeks()
        return {"action": "run_executed", "week_key": week_row["week_key"],
                "run_id": run["run_id"], "arm": run["arm"],
                "status": "metrics_missing" if metrics is None else "completed"}

    # -- metrics (C-9 honesty contract) ------------------------------------

    @staticmethod
    def _validate_metrics(metrics: dict[str, Any]) -> dict[str, int] | None:
        """Declared schema or nothing: ``{"hypotheses_tested": int>=0,
        "findings_promoted": int>=0}`` (cost/time optional extras are
        ignored — the verdict consults ONLY the declared pair)."""
        try:
            tested = max(0, int(metrics.get("hypotheses_tested")))
            promoted = max(0, int(metrics.get("findings_promoted")))
        except (TypeError, ValueError):
            return None
        return {"hypotheses_tested": tested, "findings_promoted": promoted}

    def record_run_metrics(self, run_id: str, metrics: dict[str, Any]) -> dict[str, Any]:
        """Explicit metrics post (source ``operator_record``)."""
        cleaned = self._validate_metrics(metrics)
        if cleaned is None:
            raise ValueError("ab_lab_metrics_schema_invalid")
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM ab_runs WHERE run_id=?", (str(run_id),)).fetchone()
            if row is None:
                raise ValueError("ab_lab_run_not_found")
            if row["status"] == "running":
                raise ValueError("ab_lab_run_still_running")
            conn.execute(
                "UPDATE ab_runs SET metrics_json=?, metrics_source='operator_record', "
                "status=CASE WHEN status IN ('planned','running') THEN 'completed' ELSE status END "
                "WHERE run_id=?",
                (json.dumps(cleaned, sort_keys=True), str(run_id)),
            )
        self._finalize_eligible_weeks()
        return {"run_id": str(run_id), "metrics": cleaned}

    # -- evaluation (C-10 wiring) -------------------------------------------

    def _finalize_eligible_weeks(self, week_key: str | None = None) -> None:
        """Evaluate every week whose arms reached terminal states."""
        with self._lock, self._connect() as conn:
            if week_key is None:
                rows = conn.execute(
                    "SELECT * FROM ab_weeks WHERE status NOT IN "
                    f"({','.join('?' for _ in _WEEK_TERMINAL)})",
                    tuple(_WEEK_TERMINAL),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM ab_weeks WHERE week_key=? AND status NOT IN "
                    f"({','.join('?' for _ in _WEEK_TERMINAL)})",
                    (week_key, *_WEEK_TERMINAL),
                ).fetchall()
            for week in rows:
                runs = conn.execute(
                    "SELECT * FROM ab_runs WHERE week_key=? AND client_id=? AND target_url=?",
                    (week["week_key"], week["client_id"], week["target_url"]),
                ).fetchall()
                by_arm = {row["arm"]: dict(row) for row in runs}
                if set(by_arm) != set(ARM_ORDER):
                    continue
                # Rule 1 — any FAILED arm ends the week immediately
                # (declared lifecycle: planned -> failed on control
                # failure; the remaining arm must not run).
                if any(by_arm[arm]["status"] == "failed" for arm in ARM_ORDER):
                    failed = [arm for arm in ARM_ORDER if by_arm[arm]["status"] == "failed"]
                    self._store_verdict(
                        week,
                        {
                            "verdict": "week_failed",
                            "reasons": [f"arm_failed:{','.join(failed)}"],
                            "effect": None,
                        },
                        week_status="failed",
                    )
                    continue
                # Rule 2 — BOTH arms must otherwise be terminal before
                # any verdict: a control-only completion must never
                # pre-evaluate the week (treatment still planned/running).
                if any(by_arm[arm]["status"] not in _RUN_TERMINAL for arm in ARM_ORDER):
                    continue
                control_metrics = self._metrics_of(by_arm[_ARM_CONTROL])
                treatment_metrics = self._metrics_of(by_arm[_ARM_TREATMENT])
                verdict = evaluate_ab_pair(
                    control=control_metrics, treatment=treatment_metrics,
                    thresholds=self.thresholds,
                )
                self._store_verdict(week, verdict, week_status="evaluated")

    @staticmethod
    def _metrics_of(run: dict[str, Any]) -> dict[str, int] | None:
        raw = run.get("metrics_json")
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def _store_verdict(
        self, week: dict[str, Any], verdict: dict[str, Any], *, week_status: str
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE ab_weeks SET status=?, verdict_json=?, updated_at=? "
                "WHERE week_key=? AND client_id=? AND target_url=?",
                (week_status, json.dumps(verdict, sort_keys=True), _now_text(),
                 week["week_key"], week["client_id"], week["target_url"]),
            )

    def _touch_week(
        self, week_key: str, client_id: str, target_url: str,
        *, status: str | None = None,
    ) -> None:
        with self._lock, self._connect() as conn:
            if status:
                conn.execute(
                    "UPDATE ab_weeks SET status=?, updated_at=? WHERE week_key=? "
                    "AND client_id=? AND target_url=?",
                    (status, _now_text(), week_key, client_id, target_url),
                )
            else:
                conn.execute(
                    "UPDATE ab_weeks SET updated_at=? WHERE week_key=? "
                    "AND client_id=? AND target_url=?",
                    (_now_text(), week_key, client_id, target_url),
                )

    def _update_run(self, run_id: str, **fields: Any) -> None:
        if not fields:
            return
        columns = ", ".join(f"{name}=?" for name in fields)
        values = list(fields.values()) + [str(run_id)]
        with self._lock, self._connect() as conn:
            conn.execute(f"UPDATE ab_runs SET {columns} WHERE run_id=?", values)

    # -- status / operations --------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Full lab state: weeks, runs, verdicts, and the C-10
        ``paused_advisory`` flag over consecutive inconclusive weeks."""
        with self._lock, self._connect() as conn:
            weeks = [dict(row) for row in conn.execute(
                "SELECT * FROM ab_weeks ORDER BY created_at DESC LIMIT 52"
            ).fetchall()]
            runs = [dict(row) for row in conn.execute(
                "SELECT run_id,week_key,arm,status,lesson_flag,metrics_source,error,"
                "started_at,finished_at FROM ab_runs ORDER BY started_at LIMIT 200"
            ).fetchall()]
        for week in weeks:
            if week.get("verdict_json"):
                try:
                    week["verdict"] = json.loads(week.pop("verdict_json"))
                except (TypeError, ValueError):
                    week["verdict"] = None
        consecutive = 0
        for week in weeks:  # newest first
            verdict = week.get("verdict") or {}
            if week.get("status") == "evaluated" and verdict.get("verdict") == VERDICT_INCONCLUSIVE:
                consecutive += 1
            else:
                break
        return {
            "thresholds": self.thresholds.as_dict(),
            "weeks": weeks,
            "runs": runs,
            "consecutive_inconclusive_weeks": consecutive,
            "paused_advisory": consecutive >= int(self.thresholds.max_inconclusive_weeks),
        }

    def reset_stale_run(self, run_id: str) -> dict[str, Any]:
        """Operator recovery: a ``running`` row orphaned by a crashed
        process is marked failed (never silently re-run)."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM ab_runs WHERE run_id=?", (str(run_id),)
            ).fetchone()
            if row is None:
                raise ValueError("ab_lab_run_not_found")
            if row["status"] != "running":
                raise ValueError(f"ab_lab_run_not_running:{row['status']}")
            conn.execute(
                "UPDATE ab_runs SET status='failed', error='reset_by_operator', "
                "finished_at=? WHERE run_id=?", (_now_text(), str(run_id)),
            )
        return {"run_id": str(run_id), "status": "failed"}


# -- production runner + collector references (C-9) ------------------------


def make_hunt_subprocess_runner(
    *,
    hunt_command: tuple[str, ...] = ("webpent", "hunt"),
    timeout_s: float = 4 * 3600,
) -> _RUNNER_TYPE:
    """The shipped production runner: a REAL ``webpent hunt`` subprocess.

    The per-arm lesson toggle is applied as a PROCESS-LEVEL env var
    (``ENABLE_LESSON_CONSULTATION=false|true``) so the two windows are
    isolated at the strongest available boundary — the settings object
    is read once per process by the graph nodes.

    The runner reports ``ok``/``error`` honestly from the exit code and
    does NOT fabricate metrics: unless the deployment's hunt path
    records improvement metrics for the campaign id (service
    architecture) the arm lands as ``metrics_missing`` and the week is
    declared inconclusive — never a guessed number.
    """

    def _run(spec: ABRunSpec) -> dict[str, Any]:
        env = dict(os.environ)
        env["ENABLE_LESSON_CONSULTATION"] = spec.lesson_flag
        argv = [
            *hunt_command,
            "--url", spec.target_url,
            "--mode", spec.mode,
            "--authorization", spec.authorization_ref,
            "--client-id", spec.client_id,
            "--engagement-id", spec.campaign_id,
            "--auto-approve",
            "--no-progress",
        ]
        try:
            completed = subprocess.run(
                argv, env=env, capture_output=True, text=True, timeout=float(timeout_s),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"hunt_timeout:{timeout_s:g}s", "metrics": None}
        except OSError as exc:
            return {"ok": False, "error": f"hunt_spawn_failed:{exc}", "metrics": None}
        if completed.returncode != 0:
            tail = (completed.stderr or completed.stdout or "")[-500:]
            return {
                "ok": False,
                "error": f"hunt_exit_{completed.returncode}:{tail}",
                "metrics": None,
            }
        return {"ok": True, "error": None, "metrics": None}

    return _run


def make_tracker_metrics_lookup(
    database_path: str | Path = "./memory/global/improvement_metrics.sqlite3",
) -> _LOOKUP_TYPE:
    """Default service-architecture metrics lookup: read the campaign's
    recorded row from an ``ImprovementTracker`` database (the path the
    ``MultiCampaignService.complete`` → ``persist_campaign_learning``
    pipeline writes to). Pure read; missing campaign → ``None``."""
    tracker_path = Path(database_path)

    def _lookup(campaign_id: str) -> dict[str, Any] | None:
        if not tracker_path.exists():
            return None
        try:
            import sqlite3 as _sqlite3

            conn = _sqlite3.connect(str(tracker_path), timeout=10.0)
            try:
                row = conn.execute(
                    "SELECT metrics_json FROM campaign_learning_metrics WHERE campaign_id=?",
                    (str(campaign_id)[:160],),
                ).fetchone()
            finally:
                conn.close()
        except _sqlite3.Error:
            return None
        if not row or not row[0]:
            return None
        try:
            parsed = json.loads(row[0])
        except (TypeError, ValueError):
            return None
        if not isinstance(parsed, dict):
            return None
        return {
            "hypotheses_tested": parsed.get("hypotheses_tested"),
            "findings_promoted": parsed.get("findings_promoted"),
        }

    return _lookup

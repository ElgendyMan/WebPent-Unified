"""CEM — Continuous Engagement Mode (v83).

Four layers over the existing hunt pipeline, all advisory, all bounded,
all degraded-safe:

1. **Watchtower**: snapshot engine, diff engine (NOISE / SIGNAL_LOW /
   SIGNAL_HIGH / CRITICAL), scope-drift detector, polite scheduler, and
   the pure engagement cycle ``run_cem_cycle`` (continuity = an external
   scheduler calling one pure function; no daemon).
2. **Reactor**: change reactor (mini-campaigns at 10% of budget),
   regression watch, wake-up call protocol.
3. **Longitudinal memory**: temporal lessons ledger (90-day TTL),
   deployment rhythm detector, dormant hypothesis pool.
4. **Operator interface**: the daily digest and the ``webpent cem`` CLI.

Non-negotiable invariants across every unit: advisory only (re-rank,
annotate, never promote, never suppress fresh evidence); no new
execution authority and no network of its own (fetchers are injected);
injected ``now`` everywhere; ``redact()`` on anything persisted; bounded
sizes; corrupt/missing input degrades to empty instead of raising; and
scope is sacred — out-of-scope is observed but never touched.
"""

from webpent.autonomous.cem.cycle import (
    DEFAULT_REQUESTS_PER_OBSERVATION,
    FETCHER_KEYS,
    MAX_TARGETS_HARD,
    load_cem_state,
    new_cem_state,
    run_cem_cycle,
    save_cem_state,
)
from webpent.autonomous.cem.deployment_rhythm import rhythm_report
from webpent.autonomous.cem.diff_engine import (
    diff_snapshots,
    is_actionable,
    is_wake_up,
    load_signal_config,
)
from webpent.autonomous.cem.digest import build_digest, write_digest
from webpent.autonomous.cem.dormant_pool import DormantPool
from webpent.autonomous.cem.reactor import ChangeReactor
from webpent.autonomous.cem.regression_watch import RegressionWatch
from webpent.autonomous.cem.scheduler import KillSwitch, PoliteScheduler, parse_active_hours
from webpent.autonomous.cem.scope_drift import evaluate as evaluate_scope_drift
from webpent.autonomous.cem.scope_drift import touchable_hosts
from webpent.autonomous.cem.snapshot import MAX_TARGETS, SnapshotStore, build_snapshot
from webpent.autonomous.cem.temporal_lessons import TemporalLessons
from webpent.autonomous.cem.wake_up import WakeUpProtocol

__all__ = [
    "DEFAULT_REQUESTS_PER_OBSERVATION",
    "FETCHER_KEYS",
    "MAX_TARGETS",
    "MAX_TARGETS_HARD",
    "ChangeReactor",
    "DormantPool",
    "KillSwitch",
    "PoliteScheduler",
    "RegressionWatch",
    "SnapshotStore",
    "TemporalLessons",
    "WakeUpProtocol",
    "build_digest",
    "build_snapshot",
    "diff_snapshots",
    "evaluate_scope_drift",
    "is_actionable",
    "is_wake_up",
    "load_cem_state",
    "load_signal_config",
    "new_cem_state",
    "parse_active_hours",
    "rhythm_report",
    "run_cem_cycle",
    "save_cem_state",
    "touchable_hosts",
    "write_digest",
]

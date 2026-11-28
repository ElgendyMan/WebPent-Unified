"""UM-DR-52 W2 — the Adaptive Experimentation engine (advisory layer).

future plan.md Phase 5, window contract §4. Three measured gaps closed
here, on top of the machinery that already exists (``evolution`` for
mutation/decomposition/competing/negative-evidence, ``brain_engine``
for the priority formula, ``experiment_planner`` for the differential
triples) — nothing duplicated:

* **B1 — one legal schema for the lifecycle VIEW.** The window's
  eight-state contract (``open / deferred / abandoned / refuted /
  promoted / blocked / inconclusive / rabbit-hole``) is a *view* over
  the frozen :class:`HypothesisStatus` + the reducer's actions,
  measured on the **final state after the actual reducer** (the RC-6
  lesson: never count a list of updates). The frozen model enum is not
  touched — the view is derived, deterministic, and regression-tested.
* **B2 — learning from failure is mandatory.** An
  :class:`ExperimentLedger` records every experiment with its outcome
  and, on failure, its analyzed cause (required — fail-closed). The
  repeat-guard QC: an experiment signature that FAILED on a coverage
  cell may not repeat on that cell without NEW evidence.
* **B3 — information-gated selection + safe parallelism + measured
  economics.** :func:`select_adaptive` filters through the repeat
  guard and ranks by the W3 priority formula's context (so the W1
  behavioral evidence flows into WHICH experiments get selected — the
  integration is measurable). :func:`partition_safe_parallel` never
  puts two experiments that share a session or principal in the same
  parallel batch, and an unknown session is serial (fail-closed).
  :func:`experiment_economics` computes per-family information vs
  outcome vs cost (the Waste Ledger extension for the adaptive engine
  itself).

Authority isolation (§0.1): this module performs no I/O, grants
nothing, confirms nothing, never bypasses CausalGuard /
ProofBundle / Replay. It ranks, records, and partitions — the
execution path stays the canonical one.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# B1 — the lifecycle view, measured after the reducer
# ---------------------------------------------------------------------------

# The window's closed eight-state set (§4 B1). Closed on purpose:
# adding a state is a code change, not an output.
LIFECYCLE_STATES: tuple[str, ...] = (
    "open", "deferred", "abandoned", "refuted",
    "promoted", "blocked", "inconclusive", "rabbit_hole",
)

# Final-state mapping: the frozen HypothesisStatus values carry the
# terminal truth; the reducer's action carries the live recommendation
# for still-open hypotheses. Terminal status beats a live action.
_STATUS_TO_LIFECYCLE: dict[str, str] = {
    "unexplored": "open",
    "investigating": "open",
    "promoted": "promoted",
    "resolved_true": "promoted",
    "resolved_false": "refuted",
    "abandoned": "abandoned",
    "learned": "open",  # a learned branch reopens as measured knowledge
}

_ACTION_TO_LIFECYCLE: dict[str, str] = {
    "promote": "promoted",
    "defer": "deferred",
    "rabbit_hole": "rabbit_hole",
    "abandon": "abandoned",
    "blocked": "blocked",
    "inconclusive": "inconclusive",
}


def _norm(value: Any) -> str:
    raw = str(getattr(value, "value", value) or "")
    return raw.split(".")[-1].lower()


def lifecycle_of(hyp: Any, action: Any = None) -> str:
    """The eight-state lifecycle of ONE hypothesis, after the reducer.

    Terminal status wins over a live action; a live action refines an
    open hypothesis. Unmapped inputs are a fail-closed error, never a
    silent bucket (an unknown state must surface, not vanish).
    """
    status = _norm(getattr(hyp, "status", ""))
    mapped = _STATUS_TO_LIFECYCLE.get(status)
    if mapped is not None and status not in ("unexplored", "investigating"):
        return mapped
    if action is not None:
        act = _norm(action)
        if act in _ACTION_TO_LIFECYCLE:
            return _ACTION_TO_LIFECYCLE[act]
    if mapped is not None:
        return mapped
    raise ValueError(
        f"unmapped lifecycle input: status={status!r} action={action!r}")


def reduce_final_lifecycle(
    pool: list[Any],
    actions: dict[str, Any] | None = None,
    blocked_ids: set[str] | None = None,
) -> dict[str, int]:
    """Count the pool's FINAL lifecycle state after the actual reducer.

    ``actions`` maps hypothesis id → the reducer's recommended action
    for still-open hypotheses. ``blocked_ids`` are hypotheses the
    validator/budget explicitly denied this cycle. The measurement is
    over the pool objects' terminal ``status`` fields — a list of
    interim updates is never a substitute (RC-6).
    """
    actions = actions or {}
    blocked = blocked_ids or set()
    counts: Counter[str] = Counter({s: 0 for s in LIFECYCLE_STATES})
    for hyp in pool:
        hid = str(getattr(hyp, "id", ""))
        if hid in blocked:
            counts["blocked"] += 1
            continue
        counts[lifecycle_of(hyp, actions.get(hid))] += 1
    return dict(counts)


# ---------------------------------------------------------------------------
# B2 — the experiment ledger: failure is analyzed, not repeated
# ---------------------------------------------------------------------------

@dataclass
class ExperimentRecord:
    """One recorded experiment: what ran, what it cost, what it taught."""

    experiment_sig: str          # stable signature of the experiment design
    cell: str                    # coverage cell (family|resource|endpoint)
    family: str
    outcome: str                 # "discriminated" | "inconclusive" | "fail"
    info_gained: float = 0.0     # the measured information delta, 0 on fail
    requests: int = 0            # measured cost
    failure_cause: str | None = None   # REQUIRED when outcome == "fail"
    evidence_refs: list[str] = field(default_factory=list)
    recorded_at: str = field(default_factory=lambda: datetime.now(
        timezone.utc).isoformat())


class ExperimentLedger:
    """Append-only experiment ledger with the repeat-guard QC.

    The window law (§4 B2): a failed experiment is analyzed and
    recorded; an experiment MATCHING a recorded failure signature may
    not repeat on the same cell without new evidence. Querying is
    deterministic and read-only.
    """

    def __init__(self) -> None:
        self.records: list[ExperimentRecord] = []

    def record(self, rec: ExperimentRecord) -> None:
        if rec.outcome == "fail" and not (rec.failure_cause or "").strip():
            # fail-closed: a failure without an analyzed cause is not a
            # lesson — refuse to store it (the caller must analyze).
            raise ValueError(
                f"failure_cause is required for a failed experiment "
                f"(sig={rec.experiment_sig!r} cell={rec.cell!r})")
        if rec.outcome not in ("discriminated", "inconclusive", "fail"):
            raise ValueError(f"unknown outcome: {rec.outcome!r}")
        self.records.append(rec)

    def failures_on(self, cell: str) -> list[ExperimentRecord]:
        return [r for r in self.records if r.cell == cell and r.outcome == "fail"]

    def repeat_allowed(
        self, experiment_sig: str, cell: str,
        new_evidence: bool = False,
    ) -> bool:
        """The repeat-guard QC: no identical re-run without new evidence.

        True when nothing failed on this cell with this signature
        before, or when genuinely new evidence justifies the retry
        (the caller declares the new evidence; the ledger only refuses
        the silent identical repeat).
        """
        if new_evidence:
            return True
        return not any(
            r.experiment_sig == experiment_sig for r in self.failures_on(cell))

    def lessons(self) -> list[dict[str, Any]]:
        """The failure lessons, one per failed design — B2's output."""
        out: list[dict[str, Any]] = []
        for r in self.records:
            if r.outcome == "fail":
                out.append({
                    "experiment_sig": r.experiment_sig,
                    "cell": r.cell,
                    "family": r.family,
                    "failure_cause": r.failure_cause,
                    "evidence_refs": list(r.evidence_refs),
                    "repeat_blocked_without_new_evidence": True,
                })
        return out


# ---------------------------------------------------------------------------
# B3a — selection gated by information and the repeat guard
# ---------------------------------------------------------------------------

def select_adaptive(
    plans: list[dict[str, Any]],
    ledger: ExperimentLedger,
    score_fn: Any = None,
    k: int = 8,
) -> list[dict[str, Any]]:
    """Rank candidate experiments by information, guard repeats, pick k.

    ``score_fn(plan) -> float`` is the W3 priority formula applied to
    the plan (the brain path passes :func:`brain_priority`-backed
    scoring, so the W1 behavioral evidence flows into WHICH
    experiments are selected — the integration is measurable OFF/ON).
    ``score_fn=None`` falls back to the plan's own declared
    ``info_gain`` (deterministic, no brain). Advisory: returns a
    ranking, executes nothing.
    """
    eligible: list[tuple[float, dict[str, Any]]] = []
    for plan in plans:
        sig = str(plan.get("plan_id") or plan.get("experiment_sig") or "")
        cell = str(plan.get("coverage_cell") or plan.get("cell")
                   or plan.get("plan_id") or "")
        if not ledger.repeat_allowed(sig, cell):
            continue
        score = float(score_fn(plan)) if score_fn is not None else float(
            plan.get("info_gain") or 0.0)
        eligible.append((score, plan))
    eligible.sort(key=lambda t: (-t[0], str(t[1].get("plan_id"))))
    return [p for _, p in eligible[:max(0, k)]]


# ---------------------------------------------------------------------------
# B3b — safe parallelism: no shared session, no shared principal
# ---------------------------------------------------------------------------

def partition_safe_parallel(
    plans: list[dict[str, Any]],
    session_of: Any = None,
) -> list[list[dict[str, Any]]]:
    """Partition plans into parallel-safe batches.

    Two experiments may share a parallel batch ONLY when their session
    identities differ AND their principals differ (§4 B3: no session
    mixing, no evidence mixing, no authorization-boundary mixing).
    A plan whose session is unknown goes to its own SERIAL batch —
    fail-closed, never co-scheduled on an unverified identity.
    """
    session_of = session_of or (lambda p: p.get("session_id"))
    batches: list[list[dict[str, Any]]] = []

    def _conflicts(plan: dict[str, Any], batch: list[dict[str, Any]]) -> bool:
        sid = session_of(plan)
        pid = plan.get("principal_id")
        for other in batch:
            osid = session_of(other)
            # same session, or an unknown session meeting anything, or
            # the same principal twice — all forbidden in parallel.
            if sid is None or osid is None:
                return True
            if sid == osid:
                return True
            if pid is not None and pid == other.get("principal_id"):
                return True
        return False

    for plan in plans:
        placed = False
        for batch in batches:
            if not _conflicts(plan, batch):
                batch.append(plan)
                placed = True
                break
        if not placed:
            batches.append([plan])
    return batches


# ---------------------------------------------------------------------------
# B3c — measured experiment economics (the Waste Ledger extension)
# ---------------------------------------------------------------------------

def experiment_economics(ledger: ExperimentLedger) -> dict[str, Any]:
    """Per-family: information gained vs outcomes vs measured cost.

    Every number traces to recorded experiments — declared measured,
    never estimated. ``info_per_request`` is the family's efficiency
    (the Waste Ledger cell for the adaptive engine itself).
    """
    families: dict[str, dict[str, Any]] = {}
    for r in ledger.records:
        fam = families.setdefault(r.family, {
            "experiments": 0, "discriminated": 0, "inconclusive": 0,
            "failures": 0, "info_gained": 0.0, "requests": 0,
            "failure_causes": [],
        })
        fam["experiments"] += 1
        if r.outcome == "discriminated":
            fam["discriminated"] += 1
        elif r.outcome == "inconclusive":
            fam["inconclusive"] += 1
        else:  # "fail" (record() rejects anything else)
            fam["failures"] += 1
            fam["failure_causes"].append(r.failure_cause)
        fam["info_gained"] = round(fam["info_gained"] + r.info_gained, 6)
        fam["requests"] += int(r.requests)
    for fam in families.values():
        fam["info_per_request"] = round(
            fam["info_gained"] / fam["requests"], 8) if fam["requests"] else None
        fam["failure_causes"] = sorted(
            {str(c) for c in fam["failure_causes"] if c})
    return {
        "schema": "umdr52-experiment-economics/1.0.0",
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "families": families,
    }

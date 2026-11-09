"""Economist — the payout curve database (NC-ECON-1, U-ECON-1).

The MarketKB is the market knowledge base: which programs exist, what
they pay per severity, how fast they respond, how likely a finding is to
be a duplicate. Everything is public data, documented per program, and
stale-dated (every entry carries ``last_updated``; consumers warn past
90 days).

Advisory only (L-1), zero network from this module (L-2): ingestion
reads *local snapshot files* produced by offline operator-run scripts,
refuses any source that is not on the documented trusted list, respects
``dry_run=True`` as the default (no file is touched), and appends one
redacted JSON line per accepted fetch to the ingest log. Corrupt or
missing config degrades to an empty KB; garbage snapshots are refused,
never merged.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

#: Documented, public-data sources only (NC-ECON-1 §U-ECON-1). Anything
#: else is rejected by ingestion — no undocumented source is ever merged.
TRUSTED_SOURCES = frozenset(
    {"hackerone", "hackerone_hacktivity", "bugcrowd", "cvss_public", "program_policy_page"}
)

MAX_PROGRAMS = 256
MAX_LOG_BYTES = 1_000_000
STALE_AFTER_DAYS = 90

SEVERITIES = ("critical", "high", "medium", "low")


@dataclass
class PayoutRange:
    """Min/typical/max payout in USD for one severity."""

    severity: str
    minimum: float
    maximum: float
    typical: float

    def as_dict(self) -> dict[str, float]:
        return {"min": self.minimum, "max": self.maximum, "typical": self.typical}


@dataclass
class ResponseStats:
    """Program response behaviour in days (public data only)."""

    typical_days: float
    p90_days: float


@dataclass
class Program:
    """One bug bounty program, built from public data only."""

    program_id: str
    platform: str
    scope_url: str
    last_updated: str
    payout_curves: dict[str, PayoutRange] = field(default_factory=dict)
    dup_rate: float = 0.5
    bounty_ratio: float = 0.0
    response: ResponseStats = field(default_factory=lambda: ResponseStats(0.0, 0.0))
    vuln_weights: dict[str, float] = field(default_factory=dict)
    notes: str = ""


@dataclass
class Target:
    """A digital asset inside a program (domain/subdomain/app).

    Shared vocabulary for the whole Economist (NC-ECON-1 §1): CEM
    injects the timing signals, the operator configures effort; nothing
    here fetches anything.
    """

    target_id: str
    program_id: str
    last_change_ts: float | None = None
    deploy_rhythm_bonus: float = 1.0
    effort_estimate: float = 1.0
    saturation: float | None = None
    scope_entries: tuple[str, ...] = ()

    def sanitized(self) -> Target:
        """Bounded, redacted copy (garbage in -> sanitized defaults)."""
        rhythm = min(1.5, max(1.0, float(self.deploy_rhythm_bonus or 1.0)))
        effort = min(3.0, max(0.5, float(self.effort_estimate or 1.0)))
        saturation = None
        if self.saturation is not None:
            saturation = min(100.0, max(0.0, float(self.saturation)))
        change = None
        if self.last_change_ts is not None:
            with contextlib.suppress(TypeError, ValueError):
                change = float(self.last_change_ts)
        return Target(
            target_id=redact(str(self.target_id or ""))[:120],
            program_id=str(self.program_id or "")[:120],
            last_change_ts=change,
            deploy_rhythm_bonus=rhythm,
            effort_estimate=effort,
            saturation=saturation,
            scope_entries=tuple(str(s)[:200] for s in list(self.scope_entries)[:256]),
        )


@dataclass
class IngestReport:
    """What one ingestion attempt did (or would have done)."""

    source: str
    dry_run: bool
    status: str  # "ingested" | "would_ingest" | "rejected" | "error"
    programs_seen: int = 0
    programs_accepted: int = 0
    reason: str = ""
    # R2-econ-03: rows skipped as already-stored duplicates (competitive
    # radar re-ingest); default keeps existing callers unaffected.
    rows_ignored: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "dry_run": self.dry_run,
            "status": self.status,
            "programs_seen": self.programs_seen,
            "programs_accepted": self.programs_accepted,
            "reason": self.reason,
            "rows_ignored": self.rows_ignored,
        }


def _parse_payout(severity: str, raw: Any) -> PayoutRange | None:
    if not isinstance(raw, dict):
        return None
    try:
        lo = float(raw.get("min", 0))
        hi = float(raw.get("max", 0))
        typ = float(raw.get("typical", lo))
    except (TypeError, ValueError):
        return None
    lo, hi = min(lo, hi), max(lo, hi)
    typ = min(hi, max(lo, typ))
    return PayoutRange(str(severity)[:20], lo, hi, typ)


def _parse_program(raw: Any) -> Program | None:
    if not isinstance(raw, dict) or not str(raw.get("id") or "").strip():
        return None
    pid = redact(str(raw["id"]).strip())[:120]
    curves: dict[str, PayoutRange] = {}
    for sev in SEVERITIES:
        parsed = _parse_payout(sev, (raw.get("payout_curves") or {}).get(sev))
        if parsed is not None:
            curves[sev] = parsed
    stats = raw.get("stats") if isinstance(raw.get("stats"), dict) else {}
    try:
        dup = min(1.0, max(0.0, float(stats.get("dup_rate", 0.5))))
    except (TypeError, ValueError):
        dup = 0.5
    try:
        bounty = min(1.0, max(0.0, float(stats.get("bounty_ratio", 0.0))))
    except (TypeError, ValueError):
        bounty = 0.0
    rt = stats.get("response_time_days")
    rt = rt if isinstance(rt, dict) else {}
    try:
        response = ResponseStats(float(rt.get("typical", 0) or 0), float(rt.get("p90", 0) or 0))
    except (TypeError, ValueError):
        response = ResponseStats(0.0, 0.0)
    weights = {}
    raw_weights = raw.get("vuln_weights") if isinstance(raw.get("vuln_weights"), dict) else {}
    for cls, weight in list(raw_weights.items())[:64]:
        try:
            weights[str(cls)[:40]] = min(2.0, max(0.0, float(weight)))
        except (TypeError, ValueError):
            continue
    return Program(
        program_id=pid,
        platform=str(raw.get("platform") or "")[:40],
        scope_url=redact(str(raw.get("scope_url") or ""))[:200],
        last_updated=str(raw.get("last_updated") or "")[:20],
        payout_curves=curves,
        dup_rate=dup,
        bounty_ratio=bounty,
        response=response,
        vuln_weights=weights,
        notes=redact(str(raw.get("notes") or ""))[:300],
    )


def _warn_if_stale(program: Program, now: datetime) -> None:
    """Warn when one KB entry's last_updated is older than STALE_AFTER_DAYS.

    R2-econ-11: STALE_AFTER_DAYS used to be dead -- nothing compared
    last_updated against any clock, so a year-old payout curve drove EV
    silently. Fail-soft (charter L-2/L-4): unparseable dates are skipped,
    never raised.
    """
    try:
        updated = datetime.fromisoformat(
            str(program.last_updated).strip().replace("Z", "+00:00")
        )
    except ValueError:
        return
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    if (now - updated).days > STALE_AFTER_DAYS:
        _LOG.warning(
            "program %s KB entry is stale (last_updated %s, older than %d days)",
            program.program_id,
            program.last_updated,
            STALE_AFTER_DAYS,
        )


class MarketKB:
    """Public-data payout curve database. Bounded, fail-soft, offline."""

    def __init__(
        self,
        config_path: Any = None,
        *,
        payout_curves_path: Any = None,
        ingest_log_path: Any = None,
    ) -> None:
        self.config_path = Path(config_path) if config_path is not None else None
        self.payout_curves_path = (
            Path(payout_curves_path) if payout_curves_path is not None else None
        )
        self.ingest_log_path = Path(ingest_log_path) if ingest_log_path is not None else None
        self._programs: dict[str, Program] = {}
        self._global_curves: dict[str, PayoutRange] = {}
        self.load()

    def load(self, *, now: datetime | None = None) -> None:
        """(Re)load config; corrupt/missing -> empty KB, never a raise.

        ``now`` is injectable for deterministic checks (R2-econ-11);
        callers without a clock default to datetime.now(timezone.utc).
        """
        self._programs = {}
        self._global_curves = {}
        self._load_global_curves()
        if self.config_path is None:
            return
        try:
            import yaml

            raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except Exception as exc:
            _LOG.warning("programs config unreadable; empty KB: %s", exc)
            return
        rows = raw.get("programs") if isinstance(raw, dict) else raw
        if not isinstance(rows, list):
            return
        clock = now or datetime.now(timezone.utc)
        if clock.tzinfo is None:
            clock = clock.replace(tzinfo=timezone.utc)
        for row in rows[:MAX_PROGRAMS]:
            program = _parse_program(row)
            if program is not None:
                self._programs[program.program_id] = program
                _warn_if_stale(program, clock)

    def _load_global_curves(self) -> None:
        if self.payout_curves_path is None:
            return
        try:
            import yaml

            raw = yaml.safe_load(self.payout_curves_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except Exception as exc:
            _LOG.warning("global payout curves unreadable; skipping: %s", exc)
            return
        curves = raw.get("curves") if isinstance(raw, dict) else raw
        if not isinstance(curves, dict):
            return
        for sev in SEVERITIES:
            parsed = _parse_payout(sev, curves.get(sev))
            if parsed is not None:
                self._global_curves[sev] = parsed

    # -- lookups ---------------------------------------------------------

    def load_program(self, program_id: str) -> Program:
        pid = str(program_id or "").strip()
        program = self._programs.get(pid)
        if program is None:
            raise KeyError(
                f"unknown program {pid!r}: not in the market knowledge base "
                f"(loaded={len(self._programs)}); add it to config/econ/programs.yaml "
                "from documented public data only"
            )
        return program

    def has_program(self, program_id: str) -> bool:
        return str(program_id or "").strip() in self._programs

    def get_payout_range(self, program_id: str, severity: str) -> PayoutRange:
        sev = str(severity or "").strip().lower()
        program = self._programs.get(str(program_id or "").strip())
        curve = (program.payout_curves if program else {}).get(sev) or self._global_curves.get(sev)
        if curve is None:
            return PayoutRange(sev[:20], 0.0, 0.0, 0.0)
        return curve

    def get_dup_rate(self, program_id: str) -> float:
        program = self._programs.get(str(program_id or "").strip())
        return program.dup_rate if program else 0.5

    def get_response_time(self, program_id: str) -> ResponseStats:
        program = self._programs.get(str(program_id or "").strip())
        return program.response if program else ResponseStats(0.0, 0.0)

    def list_programs(self, platform: str | None = None) -> list[Program]:
        programs = list(self._programs.values())
        if platform:
            wanted = str(platform).strip().lower()
            programs = [p for p in programs if p.platform.lower() == wanted]
        return sorted(programs, key=lambda p: p.program_id)

    # -- ingestion (offline snapshots only) -------------------------------

    def ingest_snapshot(self, source_path: Any, dry_run: bool = True) -> IngestReport:
        """Ingest one *local* snapshot of public program data.

        The snapshot is a JSON file ``{"source": <trusted-name>,
        "programs": [...]}`` produced by an offline, operator-run
        script. Untrusted source names are refused outright.
        ``dry_run=True`` (the default) touches no file at all.
        """
        source = ""
        rows: list[Any] = []
        try:
            payload = json.loads(Path(source_path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return IngestReport("", bool(dry_run), "error", 0, 0, "snapshot file not found")
        except (OSError, ValueError) as exc:
            return IngestReport("", bool(dry_run), "error", 0, 0, f"unreadable snapshot: {exc}")
        if not isinstance(payload, dict):
            return IngestReport("", bool(dry_run), "rejected", 0, 0, "snapshot is not an object")
        source = redact(str(payload.get("source") or ""))[:60]
        if source not in TRUSTED_SOURCES:
            return IngestReport(
                source,
                bool(dry_run),
                "rejected",
                0,
                0,
                f"untrusted source {source!r}: documented public sources only",
            )
        rows = payload.get("programs") if isinstance(payload.get("programs"), list) else []
        parsed: list[Program] = []
        for row in rows[:MAX_PROGRAMS]:
            program = _parse_program(row)
            if program is not None:
                parsed.append(program)
        if dry_run:
            return IngestReport(source, True, "would_ingest", len(rows), len(parsed))
        self._append_ingest_log(source, len(parsed))
        for program in parsed:
            self._programs[program.program_id] = program
        return IngestReport(source, False, "ingested", len(rows), len(parsed))

    def _append_ingest_log(self, source: str, accepted: int) -> None:
        if self.ingest_log_path is None:
            return
        entry = {
            "source": source,
            "accepted": int(accepted),
            "note": "local snapshot ingest; fetch performed offline by the operator",
        }
        try:
            self.ingest_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.ingest_log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as exc:
            _LOG.warning("ingest log write failed (ingest still counted): %s", exc)

    # -- helpers ----------------------------------------------------------

    def weighted_typical_payout(self, program: Program) -> float:
        """Vuln-weighted average typical payout across severities (USD).

        Deterministic normalization used by the target scorer: the
        per-class ``vuln_weights`` multiply each severity's weight, so a
        program paying mostly criticals scores higher than one paying
        mostly informational.
        """
        if not program.payout_curves:
            return 0.0
        total_weight = 0.0
        total_usd = 0.0
        for sev, curve in sorted(program.payout_curves.items()):
            # vuln_weights carry per-severity/class multipliers from public
            # program policy; unknown severities weigh 1.0.
            weight = float(program.vuln_weights.get(sev, 1.0))
            total_weight += weight
            total_usd += weight * curve.typical
        if total_weight <= 0:
            return 0.0
        return total_usd / total_weight

    def save(self, path: Any) -> None:
        """Persist the current programs to a YAML-compatible JSON file."""
        payload = {
            "programs": [
                {
                    "id": p.program_id,
                    "platform": p.platform,
                    "scope_url": p.scope_url,
                    "last_updated": p.last_updated,
                    "payout_curves": {
                        sev: c.as_dict() for sev, c in sorted(p.payout_curves.items())
                    },
                    "stats": {
                        "dup_rate": p.dup_rate,
                        "bounty_ratio": p.bounty_ratio,
                        "response_time_days": {
                            "typical": p.response.typical_days,
                            "p90": p.response.p90_days,
                        },
                    },
                    "vuln_weights": dict(sorted(p.vuln_weights.items())),
                    "notes": p.notes,
                }
                for p in sorted(self._programs.values(), key=lambda x: x.program_id)
            ]
        }
        target = Path(path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=str(target.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2, ensure_ascii=False)
                os.replace(tmp_name, target)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except OSError as exc:
            _LOG.warning("market KB save failed (memory stays in-process): %s", exc)


__all__ = [
    "MAX_PROGRAMS",
    "PayoutRange",
    "Program",
    "ResponseStats",
    "SEVERITIES",
    "STALE_AFTER_DAYS",
    "Target",
    "TRUSTED_SOURCES",
    "MarketKB",
]

"""Economist — the public findings radar (NC-ECON-1, U-ECON-7).

Ingests *public* bug-bounty findings from documented sources and keeps
them in a local SQLite database:

    HackerOne Hacktivity   (public feed snapshots)
    Bugcrowd Crowdstream   (public)
    GitHub security advisories
    Medium/Twitter disclosures (documented sources only)

Every stored finding records exactly {program_id, severity, vuln_class,
endpoint_signature, disclosed_at, source} — nothing else. No hunter
names, no usernames, no avatars, no profile links, no free-text notes:
the zero-PII guarantee is enforced by the schema itself (see
``docs/econ/competitive_zero_pii.md``), not by good intentions.

Security rules (identical to MarketKB ingestion, L-2):

    * the core never touches the network — ``ingest`` reads one local
      snapshot file produced by an offline, operator-run script;
    * untrusted source names are refused outright;
    * ``dry_run=True`` (the default) touches no file at all;
    * bounded sizes, redact() on identifiers, fail-soft on garbage.

The database path must be a plain local filesystem path (no scheme);
anything that smells like a URL is refused. An ``Opportunity`` is a
watched vuln class with no public finding on the program inside the
configured window. Advisory only (L-1): nothing here reports anything.
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from webpent.autonomous.hunt_contracts import redact
from webpent.econ.market_kb import IngestReport

_LOG = logging.getLogger(__name__)

#: Documented public sources only (DoD: at least two general sources).
TRUSTED_FINDING_SOURCES = frozenset(
    {
        "hackerone_hacktivity",
        "bugcrowd_crowdstream",
        "github_advisories",
        "medium_disclosure",
        "twitter_disclosure",
    }
)

MAX_FINDINGS = 2048
DEFAULT_DB_PATH = "download/econ/competitive.db"
SEVERITIES = ("critical", "high", "medium", "low")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    program_id         TEXT NOT NULL,
    severity           TEXT NOT NULL,
    vuln_class         TEXT NOT NULL,
    endpoint_signature TEXT NOT NULL,
    disclosed_at       TEXT NOT NULL,
    source             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_program
    ON findings (program_id, disclosed_at);
"""

# R2-econ-03: without a UNIQUE constraint, re-ingesting the same snapshot
# double-counted rows (saturation index 60 -> 100). Severity is
# deliberately not part of the key: the same disclosure re-reported with
# a different severity label is still the same finding.
_UNIQUE_FINDINGS_INDEX = (
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_findings ON findings "
    "(program_id, vuln_class, endpoint_signature, disclosed_at, source)"
)


def load_competition_params(path: Any) -> dict[str, Any]:
    """Load competition_params.yaml; corrupt/missing -> defaults (fail-soft)."""
    config: dict[str, Any] = {
        "opportunity_window_days": 90.0,
        "watched_classes": [
            "IDOR",
            "SSRF",
            "SQLI",
            "XSS",
            "RCE",
            "AUTH_BYPASS",
            "ACCESS_CONTROL",
            "INFO_DISCLOSURE",
        ],
    }
    if path is None:
        return config
    try:
        import yaml

        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return config
    except Exception as exc:
        _LOG.warning("competition params unreadable; using defaults: %s", exc)
        return config
    if not isinstance(raw, dict):
        return config
    with contextlib.suppress(TypeError, ValueError):
        if raw.get("opportunity_window_days") is not None:
            config["opportunity_window_days"] = max(1.0, float(raw["opportunity_window_days"]))
    classes = raw.get("watched_classes")
    if isinstance(classes, list) and classes:
        config["watched_classes"] = [str(c)[:40].upper() for c in classes[:64]]
    return config


@dataclass
class PublicFinding:
    """One public disclosure, stripped to its non-PII core (L-4)."""

    program_id: str
    severity: str
    vuln_class: str
    endpoint_signature: str
    disclosed_at: datetime
    source: str

    def sanitized(self) -> PublicFinding:
        at = self.disclosed_at
        if not isinstance(at, datetime):
            at = datetime(1970, 1, 1, tzinfo=timezone.utc)  # RT-12: deterministic, no clock
        # RT-03: normalize the instant to UTC
        at = (
            at.replace(tzinfo=timezone.utc) if at.tzinfo is None
            else at.astimezone(timezone.utc)
        )
        severity = str(self.severity or "").lower()
        if severity not in SEVERITIES:
            severity = "low"
        return PublicFinding(
            program_id=str(self.program_id or "")[:120],
            severity=severity,
            vuln_class=str(self.vuln_class or "")[:40].upper(),
            endpoint_signature=redact(str(self.endpoint_signature or ""))[:200],
            disclosed_at=at,
            source=str(self.source or "")[:60],
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "program_id": self.program_id,
            "severity": self.severity,
            "vuln_class": self.vuln_class,
            "endpoint_signature": self.endpoint_signature,
            "disclosed_at": self.disclosed_at.isoformat(),
            "source": self.source,
            "advisory": True,
        }


@dataclass
class Opportunity:
    """A watched vuln class the public hunters are not covering."""

    program_id: str
    vuln_class: str
    last_seen: datetime | None
    reasoning: str
    confidence: float = 0.5
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "program_id": self.program_id,
            "vuln_class": self.vuln_class,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "reasoning": self.reasoning,
            "confidence": round(self.confidence, 3),
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


def _parse_finding(row: Any, source: str) -> PublicFinding | None:
    if not isinstance(row, dict):
        return None
    try:
        at = row.get("disclosed_at")
        if isinstance(at, datetime):
            disclosed = at
        elif isinstance(at, str) and at.strip():
            disclosed = datetime.fromisoformat(at.strip().replace("Z", "+00:00"))
        else:
            return None
        if disclosed.tzinfo is None:
            disclosed = disclosed.replace(tzinfo=timezone.utc)
        else:
            disclosed = disclosed.astimezone(timezone.utc)  # RT-03: UTC-normalize
    except (TypeError, ValueError):
        return None
    finding = PublicFinding(
        program_id=str(row.get("program_id") or row.get("program") or ""),
        severity=str(row.get("severity") or ""),
        vuln_class=str(row.get("vuln_class") or ""),
        endpoint_signature=str(row.get("endpoint_signature") or ""),
        disclosed_at=disclosed,
        source=source,  # the validated snapshot source, never the row's claim
    )
    return finding.sanitized() if finding.program_id else None


class CompetitiveRadar:
    """Local SQLite of public findings + gap analysis. Advisory only."""

    def __init__(
        self,
        db_path: Any = DEFAULT_DB_PATH,
        *,
        params_path: Any = None,
    ) -> None:
        self.params = load_competition_params(params_path)
        if "://" in str(db_path) or str(db_path).startswith(("http", "ftp", "s3")):
            raise ValueError("competitive.db must be a local filesystem path, not a URL")
        self.db_path = Path(str(db_path))

    # ---------------------------------------------------------------- ingest
    def ingest(self, source: str, dry_run: bool = True) -> IngestReport:
        """Ingest one *local* snapshot of public findings (L-2).

        ``source`` is the path of a JSON file
        ``{"source": <trusted-name>, "findings": [...]}`` produced by an
        offline, operator-run script. The default ``dry_run=True``
        validates and counts but never writes.
        """
        try:
            payload = json.loads(Path(source).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return IngestReport("", bool(dry_run), "error", 0, 0, "snapshot file not found")
        except (OSError, ValueError) as exc:
            return IngestReport("", bool(dry_run), "error", 0, 0, f"unreadable snapshot: {exc}")
        if not isinstance(payload, dict):
            return IngestReport("", bool(dry_run), "rejected", 0, 0, "snapshot is not an object")
        source_name = redact(str(payload.get("source") or ""))[:60]
        if source_name not in TRUSTED_FINDING_SOURCES:
            return IngestReport(
                source_name,
                bool(dry_run),
                "rejected",
                0,
                0,
                f"untrusted source {source_name!r}: documented public sources only",
            )
        rows = payload.get("findings") if isinstance(payload.get("findings"), list) else []
        parsed = [f for f in (_parse_finding(r, source_name) for r in rows[:MAX_FINDINGS]) if f]
        if dry_run:
            return IngestReport(source_name, True, "would_ingest", len(rows), len(parsed))
        written, ignored = self._store(parsed)
        return IngestReport(
            source_name, False, "ingested", len(rows), written,
            rows_ignored=ignored,
        )

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.executescript(_SCHEMA)
        try:
            conn.execute(_UNIQUE_FINDINGS_INDEX)
        except sqlite3.IntegrityError as exc:
            # R2-econ-03: a legacy DB may already contain duplicate rows,
            # so the unique index cannot be built. Fail soft (charter
            # L-2/L-4): warn and proceed without the dedup index.
            _LOG.warning(
                "findings dedup index not created (legacy duplicates?): %s", exc
            )
        return conn

    def _store(self, findings: list[PublicFinding]) -> tuple[int, int]:
        """Store findings; returns (written, ignored) (R2-econ-03)."""
        try:
            with self._connect() as conn:
                before = conn.total_changes
                conn.executemany(
                    "INSERT OR IGNORE INTO findings VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        (
                            f.program_id,
                            f.severity,
                            f.vuln_class,
                            f.endpoint_signature,
                            f.disclosed_at.isoformat(),
                            f.source,
                        )
                        for f in findings
                    ],
                )
                written = conn.total_changes - before
            return written, max(0, len(findings) - written)
        except sqlite3.Error as exc:
            _LOG.warning("radar store failed (memory stays in-process): %s", exc)
            return 0, 0

    # ----------------------------------------------------------------- query
    def get_findings(self, program_id: str, since: datetime) -> list[PublicFinding]:
        """Public findings for one program disclosed at/after ``since``."""
        program = str(program_id or "")[:120]
        if not isinstance(since, datetime):
            return []
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        else:
            # R2-econ-02: an aware non-UTC since would otherwise be
            # compared lexicographically against UTC-normalized stored
            # strings; normalize the instant to UTC first.
            since = since.astimezone(timezone.utc)
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT program_id, severity, vuln_class, endpoint_signature,"
                    " disclosed_at, source FROM findings"
                    " WHERE program_id = ? AND disclosed_at >= ?"
                    " ORDER BY disclosed_at, vuln_class, endpoint_signature",
                    (program, since.isoformat()),
                ).fetchall()
        except sqlite3.Error as exc:
            _LOG.warning("radar query failed; returning empty: %s", exc)
            return []
        out = []
        for row in rows:
            with contextlib.suppress(ValueError):
                out.append(
                    PublicFinding(
                        row[0], row[1], row[2], row[3],
                        datetime.fromisoformat(row[4]), row[5],
                    )
                )
        return out

    def count_findings(self, program_id: str) -> int:
        """Total public findings stored for one program (any date)."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM findings WHERE program_id = ?",
                    (str(program_id)[:120],),
                ).fetchone()
        except sqlite3.Error as exc:
            _LOG.warning("radar count failed; returning 0: %s", exc)
            return 0
        return int(row[0]) if row else 0

    def last_seen(self, program_id: str, vuln_class: str) -> datetime | None:
        """Most recent public disclosure of one class on one program."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT MAX(disclosed_at) FROM findings"
                    " WHERE program_id = ? AND vuln_class = ?",
                    (str(program_id)[:120], str(vuln_class)[:40].upper()),
                ).fetchone()
        except sqlite3.Error as exc:
            _LOG.warning("radar query failed; returning None: %s", exc)
            return None
        if not row or not row[0]:
            return None
        with contextlib.suppress(ValueError):
            return datetime.fromisoformat(row[0])
        return None

    # --------------------------------------------------------- opportunities
    def find_opportunities(
        self, program_id: str, now: datetime | None = None,
        window_days: float | None = None,
    ) -> list[Opportunity]:
        """Watched classes with no public finding inside the window (L-3).

        ``now`` is injected (defaults to the wall clock) so decisions
        stay reproducible. ``window_days`` overrides the configured
        ``opportunity_window_days`` for this call (RT-07).
        """
        program = str(program_id or "")[:120]
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        raw_window = (
            float(window_days) if window_days is not None
            else float(self.params["opportunity_window_days"])
        )
        window = timedelta(days=max(0.0, raw_window))
        out: list[Opportunity] = []
        for vuln_class in list(self.params["watched_classes"]):
            last = self.last_seen(program, vuln_class)
            if last is not None and now - last <= window:
                continue
            if last is None:
                reasoning = (
                    f"no public {vuln_class} finding on {program} was ever "
                    f"recorded within the last {window.days:.0f} days"
                )
                confidence = 0.4
            else:
                reasoning = (
                    f"last public {vuln_class} finding on {program} was "
                    f"{(now - last).days} days ago, beyond the "
                    f"{window.days:.0f}-day window"
                )
                confidence = 0.6
            out.append(
                Opportunity(
                    program_id=program,
                    vuln_class=vuln_class,
                    last_seen=last,
                    reasoning=reasoning,
                    confidence=confidence,
                )
            )
        return out


__all__ = [
    "DEFAULT_DB_PATH",
    "MAX_FINDINGS",
    "Opportunity",
    "PublicFinding",
    "TRUSTED_FINDING_SOURCES",
    "CompetitiveRadar",
    "load_competition_params",
]

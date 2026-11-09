"""U-FORGE-5 — The Indexer.

SQLite corpus with the spec's schema (6 tables + 6 indices). Storage
is idempotent (a payload id stored twice is stored once), fully local,
and versioned by ingest timestamp (FORGE-L-10). Zero network I/O.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from webpent.forge.schemas import (
    Family,
    NormalizedPayload,
    PayloadAttribution,
    StoredOutcome,
    _row_to_payload,
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS attributions (
    attribution_id TEXT PRIMARY KEY,
    payload_id     TEXT NOT NULL REFERENCES payloads(payload_id),
    original_source TEXT NOT NULL,
    original_url   TEXT,
    original_author TEXT,
    license        TEXT NOT NULL,
    license_url    TEXT,
    ingested_at    TEXT,
    source_trust   REAL,
    verified_by    TEXT
);

CREATE TABLE IF NOT EXISTS payloads (
    payload_id   TEXT PRIMARY KEY,
    family       TEXT NOT NULL,
    subfamily    TEXT,
    raw          TEXT NOT NULL,
    complexity   TEXT,
    source       TEXT,
    quality_score REAL DEFAULT 0.0,
    novelty_score REAL DEFAULT 0.0,
    is_polyglot  INTEGER DEFAULT 0,
    chains_with  TEXT,
    requires     TEXT,
    ingested_at  TEXT
);

CREATE TABLE IF NOT EXISTS payload_target_tech (
    payload_id TEXT NOT NULL REFERENCES payloads(payload_id),
    tech       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payload_target_waf (
    payload_id TEXT NOT NULL REFERENCES payloads(payload_id),
    waf        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payload_target_context (
    payload_id TEXT NOT NULL REFERENCES payloads(payload_id),
    context    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payload_encodings (
    payload_id TEXT NOT NULL REFERENCES payloads(payload_id),
    encoding   TEXT NOT NULL,
    variant    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payload_outcomes (
    outcome_id  TEXT PRIMARY KEY,
    payload_id  TEXT NOT NULL REFERENCES payloads(payload_id),
    target_id   TEXT NOT NULL,
    success     INTEGER NOT NULL,
    evidence    TEXT,
    tested_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_family     ON payloads(family);
CREATE INDEX IF NOT EXISTS idx_complexity ON payloads(complexity);
CREATE INDEX IF NOT EXISTS idx_quality    ON payloads(quality_score);
CREATE INDEX IF NOT EXISTS idx_tech
    ON payload_target_tech(tech);
CREATE INDEX IF NOT EXISTS idx_context
    ON payload_target_context(context);
CREATE INDEX IF NOT EXISTS idx_outcomes_payload
    ON payload_outcomes(payload_id);
"""


class PayloadIndexer:
    """Owns the corpus database (in-memory by default)."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Schema introspection (used by the schema tests and review tooling)
    # ------------------------------------------------------------------

    def table_names(self) -> set[str]:
        rows = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        return {r[0] for r in rows}

    def index_names(self) -> set[str]:
        rows = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND name LIKE 'idx_%'").fetchall()
        return {r[0] for r in rows}

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def store_payload(self, payload: NormalizedPayload) -> bool:
        """Store a payload; False when the id already exists (the row is
        refreshed with the payload's current fields, so curator updates
        such as declared chains land, but the corpus stays idempotent)."""
        existing = self._conn.execute(
            "SELECT 1 FROM payloads WHERE payload_id = ?",
            (payload.payload_id,)).fetchone()
        if existing:
            self._conn.execute(
                "UPDATE payloads SET family=?, subfamily=?, raw=?, "
                "complexity=?, source=?, quality_score=?, novelty_score=?, "
                "is_polyglot=?, chains_with=?, requires=? WHERE payload_id=?",
                (payload.family.value, payload.subfamily, payload.raw,
                 payload.complexity, payload.source, payload.quality_score,
                 payload.novelty_score, 1 if payload.is_polyglot else 0,
                 "\n".join(payload.chains_with), "\n".join(payload.requires),
                 payload.payload_id))
            self._replace_context_rows(payload)
            self._conn.commit()
            return False
        self._conn.execute(
            "INSERT INTO payloads (payload_id, family, subfamily, raw, "
            "complexity, source, quality_score, novelty_score, is_polyglot, "
            "chains_with, requires, ingested_at) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?)",
            (payload.payload_id, payload.family.value, payload.subfamily,
             payload.raw, payload.complexity, payload.source,
             payload.quality_score, payload.novelty_score,
             1 if payload.is_polyglot else 0,
             "\n".join(payload.chains_with), "\n".join(payload.requires),
             datetime.now(timezone.utc).isoformat()))
        self._store_attribution(payload)
        self._replace_context_rows(payload)
        for name, variant in payload.encoded_variants.items():
            self._conn.execute(
                "INSERT INTO payload_encodings (payload_id, encoding, "
                "variant) VALUES (?,?,?)",
                (payload.payload_id, name, variant))
        self._conn.commit()
        return True

    def _replace_context_rows(self, payload: NormalizedPayload) -> None:
        """Rewrite the tech/waf/context rows for a payload (delete then
        insert, so a refresh cannot leave stale target rows behind)."""
        for table, column, values in (
                ("payload_target_tech", "tech", payload.target_tech),
                ("payload_target_waf", "waf", payload.target_waf),
                ("payload_target_context", "context",
                 payload.target_context)):
            self._conn.execute(
                f"DELETE FROM {table} WHERE payload_id = ?",
                (payload.payload_id,))
            for value in values:
                self._conn.execute(
                    f"INSERT INTO {table} (payload_id, {column}) "
                    "VALUES (?,?)", (payload.payload_id, value))

    def get_encodings(self, payload_id: str) -> dict[str, str]:
        """Encoding name -> variant string for one payload."""
        return {
            r["encoding"]: r["variant"]
            for r in self._conn.execute(
                "SELECT encoding, variant FROM payload_encodings "
                "WHERE payload_id = ?", (payload_id,)).fetchall()}

    def _store_attribution(self, payload: NormalizedPayload) -> None:
        attr = payload.attribution
        if attr is None:
            return
        self._conn.execute(
            "INSERT OR REPLACE INTO attributions (attribution_id, "
            "payload_id, original_source, original_url, original_author, "
            "license, license_url, ingested_at, source_trust, verified_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (f"attr-{payload.payload_id}", payload.payload_id,
             attr.original_source, attr.original_url, attr.original_author,
             attr.license, attr.license_url,
             attr.ingested_at.isoformat(), attr.source_trust,
             attr.verified_by))

    def store_outcome(self, *, payload_id: str, target_id: str,
                      success: bool, evidence: str,
                      outcome_id: str | None = None) -> str:
        oid = outcome_id or f"out-{payload_id}-{target_id}-{success!r}"
        self._conn.execute(
            "INSERT OR REPLACE INTO payload_outcomes (outcome_id, "
            "payload_id, target_id, success, evidence, tested_at) "
            "VALUES (?,?,?,?,?,?)",
            (oid, payload_id, target_id, 1 if success else 0, evidence,
             datetime.now(timezone.utc).isoformat()))
        self._conn.commit()
        return oid

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def count_all(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM payloads").fetchone()
        return int(row[0])

    def count_context_rows(self, table: str) -> int:
        if table not in ("payload_target_tech", "payload_target_waf",
                         "payload_target_context", "payload_encodings"):
            raise ValueError(f"unknown context table '{table}'")
        row = self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        return int(row[0])

    def get_payload(self, payload_id: str) -> NormalizedPayload | None:
        row = self._conn.execute(
            "SELECT * FROM payloads WHERE payload_id = ?",
            (payload_id,)).fetchone()
        if row is None:
            return None
        return self._assemble(row)

    def list_by_family(self, family: Family) -> list[NormalizedPayload]:
        rows = self._conn.execute(
            "SELECT * FROM payloads WHERE family = ? ORDER BY payload_id",
            (family.value,)).fetchall()
        return [self._assemble(row) for row in rows]

    def list_all(self) -> list[NormalizedPayload]:
        rows = self._conn.execute(
            "SELECT * FROM payloads ORDER BY payload_id").fetchall()
        return [self._assemble(row) for row in rows]

    def _assemble(self, row) -> NormalizedPayload:
        pid = row["payload_id"]
        encodings = {
            r["encoding"]: r["variant"]
            for r in self._conn.execute(
                "SELECT encoding, variant FROM payload_encodings "
                "WHERE payload_id = ?", (pid,)).fetchall()}
        tech = [r[0] for r in self._conn.execute(
            "SELECT tech FROM payload_target_tech WHERE payload_id = ?",
            (pid,)).fetchall()]
        waf = [r[0] for r in self._conn.execute(
            "SELECT waf FROM payload_target_waf WHERE payload_id = ?",
            (pid,)).fetchall()]
        context = [r[0] for r in self._conn.execute(
            "SELECT context FROM payload_target_context WHERE payload_id = ?",
            (pid,)).fetchall()]
        attr_row = self._conn.execute(
            "SELECT * FROM attributions WHERE payload_id = ?",
            (pid,)).fetchone()
        attribution = None
        if attr_row is not None:
            attribution = PayloadAttribution(
                payload_id=pid,
                original_source=attr_row["original_source"],
                original_url=attr_row["original_url"] or "",
                original_author=attr_row["original_author"],
                license=attr_row["license"],
                license_url=attr_row["license_url"] or "",
                ingested_at=datetime.fromisoformat(
                    attr_row["ingested_at"] or datetime.now(timezone.utc).isoformat()),
                source_trust=attr_row["source_trust"] or 0.0,
                verified_by=attr_row["verified_by"],
            )
        chains = tuple(
            s for s in (row["chains_with"] or "").split("\n") if s)
        requires = tuple(
            s for s in (row["requires"] or "").split("\n") if s)
        payload = _row_to_payload(row, encodings, tech, waf, context,
                                  attribution)
        return NormalizedPayload(
            payload_id=payload.payload_id, family=payload.family,
            subfamily=payload.subfamily, raw=payload.raw,
            encoded_variants=encodings, target_tech=payload.target_tech,
            target_waf=payload.target_waf,
            target_context=payload.target_context,
            complexity=payload.complexity, source=payload.source,
            attribution=attribution, quality_score=payload.quality_score,
            novelty_score=payload.novelty_score,
            is_polyglot=payload.is_polyglot, chains_with=chains,
            requires=requires)

    def get_outcomes(self, payload_id: str) -> list[StoredOutcome]:
        rows = self._conn.execute(
            "SELECT * FROM payload_outcomes WHERE payload_id = ? "
            "ORDER BY outcome_id", (payload_id,)).fetchall()
        return [StoredOutcome(
            outcome_id=r["outcome_id"], payload_id=r["payload_id"],
            target_id=r["target_id"], success=bool(r["success"]),
            evidence=r["evidence"] or "") for r in rows]

    def success_rate(self, payload_id: str) -> float:
        row = self._conn.execute(
            "SELECT COUNT(*), SUM(success) FROM payload_outcomes "
            "WHERE payload_id = ?", (payload_id,)).fetchone()
        total, wins = int(row[0] or 0), int(row[1] or 0)
        if total == 0:
            return 0.0
        return round(wins / total, 4)

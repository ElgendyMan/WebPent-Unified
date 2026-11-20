"""initial schema

Revision ID: 0001_initial
Create Date: 2026-07-14

V10 P0-C FIX: this migration was missing the ``thread_id``, ``vuln_class``,
``strategic_confidence_score``, and ``hypothesis_id`` columns. On a fresh
DB where Alembic succeeds, the findings table was created WITHOUT these
columns, causing ``save_finding`` to raise
``sqlite3.OperationalError: table findings has no column named thread_id``
— silently swallowed by the worker's ``except Exception`` in
``_persist_findings``, producing the "Persisted 0 + API returns []"
variant of the operator's symptom.

The legacy DDL fallback in ``memory/db.py:_init_db_legacy`` has always
had these columns; the Alembic migration and the legacy DDL are now in
sync. A ``CREATE INDEX`` on ``thread_id`` is added so the API's
``WHERE thread_id = ?`` query (``get_findings_by_thread``) doesn't
full-scan on every status poll.
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the findings table with all V10 columns."""
    op.create_table(
        "findings",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("title", sa.String, nullable=False),
        sa.Column("severity", sa.String, nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("tool_name", sa.String, nullable=False),
        sa.Column("payload", sa.Text),
        sa.Column("url", sa.String, nullable=False),
        sa.Column("confidence", sa.String, nullable=False),
        sa.Column("created_at", sa.String, nullable=False),
        sa.Column("evidence", sa.Text),
        sa.Column("references", sa.Text, nullable=False, server_default="[]"),
        sa.Column("cvss_score", sa.Text),
        sa.Column("business_impact", sa.Text),
        sa.Column("confidence_level", sa.Text),
        sa.Column("reasoning", sa.Text),
        sa.Column("oob_token", sa.Text),
        sa.Column("canary_token", sa.Text),
        sa.Column("evidence_bundle", sa.Text),
        sa.Column("compliance_tags", sa.Text, nullable=False, server_default="[]"),
        sa.Column("evidence_hash", sa.Text),
        sa.Column("post_exploitation_data", sa.Text),
        # V10 P0-C: previously missing from Alembic — present in legacy DDL.
        sa.Column("vuln_class", sa.String, server_default="unknown"),
        sa.Column("strategic_confidence_score", sa.Float),
        sa.Column("hypothesis_id", sa.String),
        sa.Column("thread_id", sa.String),
    )
    # V10 P0-C: index on thread_id so get_findings_by_thread doesn't
    # full-scan on every status poll.
    op.create_index(
        "ix_findings_thread_id",
        "findings",
        ["thread_id"],
    )


def downgrade() -> None:
    """Drop the findings table."""
    op.drop_index("ix_findings_thread_id", table_name="findings")
    op.drop_table("findings")

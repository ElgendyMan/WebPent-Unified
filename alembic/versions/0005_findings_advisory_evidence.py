"""Add advisory_evidence column to findings (R3 E-1, Ruling R3-002).

Amendment B: ADDITIVE, OPTIONAL, default-empty, authority-neutral
advisory-evidence storage for the OOB callback path. The column is a JSON
list written ONLY by ``DatabaseManager.append_oob_advisory_evidence`` —
confidence, confidence_level, reasoning, and payload are structurally
unreachable from that write path (C5 fail-closed).

The column exists in the legacy raw-DDL fallback path
(``webpent.memory.db.FINDINGS_DDL`` / ``_init_db_legacy``'s PRAGMA-guarded
ALTER TABLE block) and in this Alembic migration chain, per the
0004 reconciliation precedent.

Revision ID: 0005_findings_advisory_evidence
Revises: 0004_findings_request_columns
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0005_findings_advisory_evidence"
down_revision = "0004_findings_request_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(
            sa.Column(
                "advisory_evidence",
                sa.Text(),
                nullable=False,
                server_default="[]",
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("advisory_evidence")

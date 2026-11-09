"""Add request_method/request_data/target_param columns to findings.

These columns exist in the legacy raw-DDL fallback path
(``webpent.memory.db.FINDINGS_DDL`` / ``_init_db_legacy``'s ALTER TABLE
block, added during the v10/v61 -> GOED v1.8.4 canonical merge era) but
were missing from this Alembic migration chain, so any deployment that
runs Alembic (the primary ``init_db`` path — legacy DDL is only a fallback
for when Alembic itself is unavailable) ended up with a findings table
missing these columns, causing every finding-persistence write to fail
with "no such column: request_method". See RECONCILIATION_REPORT.md.

Revision ID: 0004_findings_request_columns
Revises: 0003_shared_reauth_vault
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0004_findings_request_columns"
down_revision = "0003_shared_reauth_vault"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(
            sa.Column(
                "request_method", sa.String(), nullable=False, server_default="GET"
            )
        )
        batch_op.add_column(sa.Column("request_data", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("target_param", sa.String(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("target_param")
        batch_op.drop_column("request_data")
        batch_op.drop_column("request_method")

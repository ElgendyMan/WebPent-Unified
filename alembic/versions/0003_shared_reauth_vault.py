"""Shared encrypted re-auth vault records.

Revision ID: 0003_shared_reauth_vault
Revises: 0002_auth_token_versions
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0003_shared_reauth_vault"
down_revision = "0002_auth_token_versions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "reauth_vault_records",
        sa.Column("thread_id", sa.String(length=512), nullable=False),
        sa.Column("record_type", sa.String(length=32), nullable=False),
        sa.Column("encrypted_value", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.Column("updated_at", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("thread_id", "record_type"),
    )
    op.create_index(
        "ix_reauth_vault_expires_at",
        "reauth_vault_records",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_reauth_vault_expires_at", table_name="reauth_vault_records")
    op.drop_table("reauth_vault_records")

"""Shared authentication token-version store.

Revision ID: 0002_auth_token_versions
Revises: 0001_initial
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0002_auth_token_versions"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_token_versions",
        sa.Column("username", sa.String(length=256), primary_key=True),
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.String(length=64), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("auth_token_versions")

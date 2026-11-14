# alembic/env.py — Alembic environment for WebPent V6 Ultimate
"""Alembic migration environment.

Reads the database URL from webpent.config.settings to ensure
consistency with the framework's configuration.
"""

from __future__ import annotations

import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool

from alembic import context

# Ensure src/ is on the path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

config = context.config

if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)

# Import settings to get the database URL
from webpent.config.settings import get_settings  # noqa: E402

settings = get_settings()

# Convert the WebPent database_url (sqlite:///...) to a SQLAlchemy URL.
# A DatabaseManager may pass an explicit per-instance URL through Alembic's
# config object (used by tests, isolated engagements, and multi-tenant runs).
# Prefer that override when present; otherwise retain the process-wide setting.
configured_url = config.get_main_option("sqlalchemy.url")
db_url = configured_url or settings.database_url
if db_url == "sqlite://":
    db_url = "sqlite://"
elif db_url.startswith("sqlite:///"):
    # Resolve relative paths to absolute (matching db.py behavior)
    raw_path = db_url[len("sqlite:///") :]
    p = Path(raw_path)
    if not p.is_absolute():
        project_root = Path(__file__).resolve().parents[1]
        p = project_root / p
    db_url = f"sqlite:///{p}"

config.set_main_option("sqlalchemy.url", db_url)

target_metadata = None


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (connect to DB and execute)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

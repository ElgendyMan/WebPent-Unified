# worker.py
"""Root-level script to expose the Celery application for the worker process.

Usage:
    celery -A worker.celery_app worker --loglevel=info

This module re-exports ``celery_app`` from
``webpent.workers.pentest_worker`` so the Celery CLI can discover it
without a long dotted path. The actual Celery configuration and task
definition live in :mod:`webpent.workers.pentest_worker`.
"""

from __future__ import annotations

import os

# R3 E-4 (Ruling R3-002 §3.4, mechanism (b)): this root launcher is an
# EDITABLE orchestration surface and sets the explicit entrypoint label
# the production graph records in its audited trace. Worker processes are
# launched through this module (celery -A worker); the label is truthful
# by construction. setdefault keeps an operator-provided override intact.
os.environ.setdefault("WEBPENT_ENTRYPOINT", "worker")

from webpent.workers.pentest_worker import celery_app

__all__ = ["celery_app"]

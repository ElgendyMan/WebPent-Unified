# src/webpent/scheduler/__init__.py
"""Scheduled campaigns (PROPOSALS_ULTIMATE_V3 §5).

Campaigns the operator schedules ahead of time, stored in a local JSONL
file with per-campaign state, woken by an explicit ``run-due`` CLI
invocation. There is deliberately NO resident daemon: the tool is not a
resident service, so the "scheduler" is a due-check that runs when the
operator (or their cron) calls it.
"""

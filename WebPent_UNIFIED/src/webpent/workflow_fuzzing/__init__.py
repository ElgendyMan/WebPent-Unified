"""2026-10-25 Proposal 9 — workflow-integrity fuzzing package.

Bounded mutation of multi-step workflows (order, skip, replay, price
tampering, race on a step), each mutation carrying its benign control,
with a CONFIRMED-only validator that fails closed. All flag-gated.
"""

# src/webpent/vip/__init__.py
"""webpent.vip — VIP track capabilities (roadmap 2026-10-27, Track 11).

Every module here is governed by the same mandatory constraints as the rest
of the platform: authorized scope only, fail-safe defaults, deterministic
validators over LLM advice, human review before anything leaves the system,
and a full audit trail.

Track 11 modules:

* :mod:`webpent.vip.dedup_gate` — item 5: prior-findings review as a
  gating condition before a finding is nominated to the final report
  (duplicate suppression is always explicit and auditable, never silent).
* :mod:`webpent.vip.retest` — item 7: controlled re-testing of a previous
  finding inside the authorized scope, with a status update and a durable
  comparison record.

Both modules are additive: they annotate and gate, they never delete
state, and both fail safe (indeterminate — never a silent pass).
"""

from __future__ import annotations

__all__ = ["dedup_gate", "retest"]

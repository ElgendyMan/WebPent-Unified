# src/webpent/safety/__init__.py
"""Operational safety container v2 (2026-10-25 Proposal 10).

Four controls over live operations, each flag-gated and default off:

  * ``request_ledger`` — one layer every HTTP request passes through,
    logging (ts, method, url, flags, engagement) to a bounded SQLite
    ledger (Observability: fail-soft, never blocks a request).
  * ``kill_switch`` — a shared state a POST endpoint freezes; every
    governor checks it on acquire, so the freeze lands within seconds.
  * ``spend_governor`` — a per-engagement LLM token counter; at the
    cap the LLM lane fails closed (error response) so every downstream
    fallback takes its deterministic path automatically.
  * ``agency`` — robots.txt compliance is respected by default;
    the exceptional per-engagement override requires two independent
    explicit switches (global flag AND an explicit engagement list).
"""

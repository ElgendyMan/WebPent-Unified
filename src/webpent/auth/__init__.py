# src/webpent/auth/__init__.py
"""webpent.auth — worker-only authentication helpers.

V10 P0-2 Option A: ``reauth_vault`` provides a worker-process-memory
store for the operator-supplied password, sealed at engagement start
and unsealed only inside the validator's mid-scan re-auth path. The
password is NEVER persisted to checkpoint, SQLite, or Redis in
plaintext after login — FIX-10's scrub of ``state["credentials"]``
remains in force, and the vault is the sole source of truth for
re-auth.
"""

from webpent.auth.reauth_vault import (
    clear_reauth_secret,
    seal_reauth_secret,
    sweep_expired,
    unseal_reauth_secret,
    vault_stats,
)

__all__ = [
    "seal_reauth_secret",
    "unseal_reauth_secret",
    "clear_reauth_secret",
    "sweep_expired",
    "vault_stats",
]

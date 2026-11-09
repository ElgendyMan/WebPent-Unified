# tests/lab/idor_lab_target.py
"""Sprint I-2, Part 1 — Minimal IDOR/BOLA lab target (M10 seed).

A small FastAPI application under tests/lab/ (NOT production src/). Matches
the program spec's lab scenario exactly:

  Principals: User_A (foreign), User_B (owner).
  Objects:
    INV-B-204  — owner B; A denied -> 403
    INV-A-101  — owner A; A reads -> 200
    INV-X-000  — known-denied to A -> 403
  Policy: an invoice is readable only by its owner.

Endpoints:
  POST /api/login          { "username": ..., "password": ... } -> { "token": ... }
  GET  /api/invoices/{id}  requires X-User header (or Bearer token) -> 200/403/404

The login endpoint issues per-principal tokens. The invoice endpoint resolves
the caller principal from either the X-User header (the M4 attach binding
mechanism used by the walking skeleton) or a Bearer token issued by /login,
then enforces owner-only read policy.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

# --- Principal / object store (in-memory, lab-only) -------------------------
PRINCIPALS: dict[str, dict[str, str]] = {
    "User_A": {"password": "password_a", "role": "foreign-user"},
    "User_B": {"password": "password_b", "role": "owner"},
}

# invoice_id -> owner
INVOICES: dict[str, str] = {
    "INV-B-204": "User_B",
    "INV-A-101": "User_A",
    "INV-X-000": "User_B",  # exists, but known-denied to A (owner is B)
}

_LAB_TOKEN_SECRET = b"lab_target_token_secret_only_for_tests_not_production"


def _issue_token(username: str) -> str:
    """Per-principal HMAC token (lab-only; not a production auth scheme)."""
    payload = f"{username}:{int(time.time())}"
    sig = hmac.new(_LAB_TOKEN_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{payload}:{sig}"


def _resolve_principal(authorization: str | None, x_user: str | None) -> str | None:
    """Resolve caller principal from Bearer token OR X-User header.

    X-User is advisory-only at the HTTP layer in production; in this lab it
    is accepted because the M4 context authority OVERWRITES it with the
    vault-resolved alias before the request leaves the executor — the lab
    target therefore always sees the vault-bound identity. A raw caller-
    supplied X-User reaching this target would indicate the B11 fix failed.
    """
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
        parts = token.rsplit(":", 1)
        if len(parts) == 2:
            payload, sig = parts
            expected = hmac.new(_LAB_TOKEN_SECRET, payload.encode(),
                                hashlib.sha256).hexdigest()[:16]
            if hmac.compare_digest(sig, expected):
                username = payload.split(":", 1)[0]
                if username in PRINCIPALS:
                    return username
    if x_user and x_user in PRINCIPALS:
        return x_user
    return None


class LoginRequest(BaseModel):
    username: str
    password: str


def build_app(vulnerable: bool = False) -> FastAPI:
    """Build the lab target app.

    vulnerable=False (default): policy enforced — an invoice is readable only
        by its owner. Used for the Part-1 policy tests and the 6.2 REFUTED
        e2e case (candidate denied by the enforced policy).
    vulnerable=True: IDOR/BOLA vulnerability present — the ownership check is
        bypassed, so a foreign principal reads the owner's invoice (200).
        Used for the 6.1 POSITIVE e2e case (CONFIRMED + promoted).
    """
    app = FastAPI(title=f"WebPent Lab IDOR/BOLA Target (vulnerable={vulnerable})",
                  version="0.1.0")

    @app.post("/api/login")
    def login(req: LoginRequest) -> dict[str, Any]:
        principal = PRINCIPALS.get(req.username)
        if not principal or principal["password"] != req.password:
            raise HTTPException(status_code=401, detail="invalid credentials")
        return {"token": _issue_token(req.username), "principal": req.username,
                "role": principal["role"]}

    @app.get("/api/invoices/me")
    def whoami(
        authorization: str | None = Header(default=None),
        x_user: str | None = Header(default=None, alias="X-User"),
    ) -> dict[str, Any]:
        """Identity-discovery surface (RA-1 / U-2b)."""
        principal = _resolve_principal(authorization, x_user)
        if principal is None:
            raise HTTPException(status_code=401, detail="authentication required")
        role = PRINCIPALS.get(principal, {}).get("role", "unknown")
        return {"id": principal, "principal": principal, "role": role}

    @app.get("/api/invoices/{invoice_id}")
    def read_invoice(
        invoice_id: str,
        authorization: str | None = Header(default=None),
        x_user: str | None = Header(default=None, alias="X-User"),
    ) -> dict[str, Any]:
        principal = _resolve_principal(authorization, x_user)
        if principal is None:
            raise HTTPException(status_code=401, detail="authentication required")
        owner = INVOICES.get(invoice_id)
        if owner is None:
            raise HTTPException(status_code=404, detail="invoice not found")
        if not vulnerable and owner != principal:
            # Policy: an invoice is readable only by its owner.
            raise HTTPException(status_code=403, detail="forbidden: not the owner")
        return {"id": invoice_id, "owner": owner, "amount": 1000, "status": "paid",
                "viewer": principal, "vulnerable": vulnerable}

    return app


# Default (patched) app — used by Part-1 policy tests.
app = build_app(vulnerable=False)


def start_lab_server(vulnerable: bool = False) -> tuple[Any, str]:
    """Start the lab target on an ephemeral port; return (server, base_url).

    Mirrors the pattern used by real_target_qualification_v1_1.start_target_server
    so acceptance tests can spin up an isolated real-HTTP target per test module.
    vulnerable=True starts the IDOR-vulnerable variant (6.1 POSITIVE);
    vulnerable=False (default) starts the policy-enforced variant (6.2 REFUTED).
    """
    import threading

    import uvicorn

    app_instance = build_app(vulnerable=vulnerable)
    config = uvicorn.Config(app_instance, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # Wait for the socket to bind.
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("lab target server failed to start")
    port = server.servers[0].sockets[0].getsockname()[1]
    server._lab_thread = thread  # type: ignore[attr-defined]
    server._vulnerable = vulnerable  # type: ignore[attr-defined]
    return server, f"http://127.0.0.1:{port}"

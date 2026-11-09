# tests/lab/chain_lab_target.py
"""TC-3 §2 V-1 — the CHAIN lab lane (info-disclosure + IDOR).

A small FastAPI application whose TWO vulnerabilities compose into the
dispatch's example chain (info-disclosure + IDOR -> cross-account), while
neither standalone finding proves the composition:

  * V1 INFO_DISCLOSURE — GET /api/admin/debug returns the internal service
    registry (config path + credential reference + the HIDDEN document id)
    to ANY authenticated principal.  Patched variant: admin-only (403).
  * V2 IDOR — GET /api/documents/{doc_id} skips the ownership check.
    Patched variant: owner-only (403).

  Documents:
    DOC-A-11      owner User_A (the caller's own document)
    DOC-B-PUB     owner User_B, id listed by the caller-scoped index
    DOC-B-7f3a91c owner User_B, id listed NOWHERE except the debug
                  registry — non-enumerable without the disclosure leg

  The CHAIN's proven claim (and the reason it is more than finding V1 +
  finding V2): exfiltration of a NON-ENUMERABLE object — the hidden
  document is unreachable unless the disclosure leg supplies its id.
  The chain hypothesis's step-2 request parameter is DERIVED from the
  step-1 response; the derivation digest is part of the chain evidence.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

PRINCIPALS: dict[str, dict[str, str]] = {
    "User_A": {"password": "password_a", "role": "foreign-user"},
    "User_B": {"password": "password_b", "role": "owner"},
}

DOCUMENTS: dict[str, dict[str, str]] = {
    "DOC-A-11": {"owner": "User_A", "classification": "personal",
                 "body": "User_A personal note"},
    "DOC-B-PUB": {"owner": "User_B", "classification": "public",
                  "body": "User_B public memo"},
    # HIDDEN: only the debug registry discloses this id.
    "DOC-B-7f3a91c": {"owner": "User_B", "classification": "internal",
                      "body": "User_B internal record"},
}
HIDDEN_DOC_ID = "DOC-B-7f3a91c"

# The internal service registry the debug endpoint leaks (V1).  It carries
# two honest sensitive-indicator classes (internal_path + credential_label)
# AND the hidden document id — the chain's discovery payload.
INTERNAL_REGISTRY: dict[str, Any] = {
    "service": "doc-registry",
    "config_path": "/app/internal/registry.json",
    "credential_ref": "secret:internal-registry-ro",
    "registry": {
        "User_A": {"email": "user-a@lab.internal", "document_ids": ["DOC-A-11"]},
        "User_B": {"email": "user-b@lab.internal",
                   "document_ids": ["DOC-B-PUB", HIDDEN_DOC_ID]},
    },
}

_LAB_TOKEN_SECRET = b"chain_lab_token_secret_only_for_tests_not_production"


def _issue_token(username: str) -> str:
    payload = f"{username}:{int(time.time())}"
    sig = hmac.new(_LAB_TOKEN_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{payload}:{sig}"


def _resolve_principal(authorization: str | None, x_user: str | None) -> str | None:
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
    """vulnerable=True: both V1 (debug leak) and V2 (IDOR) are present.
    vulnerable=False: debug is admin-only AND the ownership check is
    enforced (each standalone finding AND the chain must refute)."""
    app = FastAPI(title=f"WebPent Chain Lab Target (vulnerable={vulnerable})",
                  version="0.1.0")

    @app.post("/api/login")
    def login(req: LoginRequest) -> dict[str, Any]:
        principal = PRINCIPALS.get(req.username)
        if not principal or principal["password"] != req.password:
            raise HTTPException(status_code=401, detail="invalid credentials")
        return {"token": _issue_token(req.username), "principal": req.username,
                "role": principal["role"]}

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok"}

    @app.get("/api/version")
    def version() -> dict[str, Any]:
        return {"version": "1.0.0"}

    @app.get("/api/admin/debug")
    def debug(
        authorization: str | None = Header(default=None),
        x_user: str | None = Header(default=None, alias="X-User"),
    ) -> dict[str, Any]:
        principal = _resolve_principal(authorization, x_user)
        if principal is None:
            raise HTTPException(status_code=401, detail="authentication required")
        if not vulnerable and principal != "User_B":
            # patched: the debug surface is admin/owner-only
            raise HTTPException(status_code=403, detail="forbidden: admin only")
        return dict(INTERNAL_REGISTRY)

    @app.get("/api/documents")
    def my_documents(
        authorization: str | None = Header(default=None),
        x_user: str | None = Header(default=None, alias="X-User"),
    ) -> dict[str, Any]:
        principal = _resolve_principal(authorization, x_user)
        if principal is None:
            raise HTTPException(status_code=401, detail="authentication required")
        ids = [d for d, meta in DOCUMENTS.items() if meta["owner"] == principal
               and meta["classification"] != "internal"]
        return {"documents": ids}

    @app.get("/api/documents/{doc_id}")
    def read_document(
        doc_id: str,
        authorization: str | None = Header(default=None),
        x_user: str | None = Header(default=None, alias="X-User"),
    ) -> dict[str, Any]:
        principal = _resolve_principal(authorization, x_user)
        if principal is None:
            raise HTTPException(status_code=401, detail="authentication required")
        meta = DOCUMENTS.get(doc_id)
        if meta is None:
            raise HTTPException(status_code=404, detail="document not found")
        if not vulnerable and meta["owner"] != principal:
            raise HTTPException(status_code=403, detail="forbidden: not the owner")
        return {"id": doc_id, "owner": meta["owner"],
                "classification": meta["classification"], "body": meta["body"],
                "viewer": principal, "vulnerable": vulnerable}

    return app


app = build_app(vulnerable=False)


def start_chain_lab_server(vulnerable: bool = False) -> tuple[Any, str]:
    """Start the chain lane on an ephemeral port (mirrors the IDOR lab's
    start pattern)."""
    import threading

    import uvicorn

    app_instance = build_app(vulnerable=vulnerable)
    config = uvicorn.Config(app_instance, host="127.0.0.1", port=0,
                            log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("chain lab server failed to start")
    port = server.servers[0].sockets[0].getsockname()[1]
    server._lab_thread = thread  # type: ignore[attr-defined]
    server._vulnerable = vulnerable  # type: ignore[attr-defined]
    return server, f"http://127.0.0.1:{port}"

"""Disposable realistic local HTTP target harness for RTA v1.

The harness uses a real FastAPI application and a real SQLite database, but
all identities, sessions, and records are synthetic.  Every exposed route is
read-only and intended for loopback-only assessment.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from .contracts import SyntheticAuthContext


@dataclass(frozen=True)
class LocalTargetConfig:
    target_id: str
    version: str
    source_digest: str
    vulnerable_classes: frozenset[str]

    def validate(self) -> None:
        if not self.target_id or not self.version or not self.source_digest:
            raise ValueError("local target requires immutable identity")
        if any(value.startswith("external:") for value in self.vulnerable_classes):
            raise ValueError("target semantics must remain local")


_SESSIONS: dict[str, SyntheticAuthContext] = {
    "synthetic:user-a": SyntheticAuthContext(
        "user-a", "viewer", "tenant-a", "synthetic:user-a", ("document:read", "order:read")
    ),
    "synthetic:user-b": SyntheticAuthContext(
        "user-b", "editor", "tenant-a", "synthetic:user-b", ("document:read", "document:write")
    ),
    "synthetic:admin": SyntheticAuthContext(
        "admin", "admin", "tenant-a", "synthetic:admin", ("document:read", "admin:read")
    ),
    "synthetic:tenant-b": SyntheticAuthContext(
        "tenant-b-user",
        "viewer",
        "tenant-b",
        "synthetic:tenant-b",
        ("document:read", "order:read"),
    ),
    "synthetic:viewer-b": SyntheticAuthContext(
        "user-b",
        "viewer",
        "tenant-a",
        "synthetic:viewer-b",
        ("document:read", "order:read"),
    ),
}


_SEED_ROWS = (
    ("doc-a-1", "tenant-a", "user-a", "public summary a"),
    ("doc-a-2", "tenant-a", "user-b", "private summary a2"),
    ("doc-b-1", "tenant-b", "tenant-b-user", "private summary b1"),
)


_ORDER_ROWS = (
    ("order-a-1", "tenant-a", "user-a", 100, 10),
    ("order-a-2", "tenant-a", "user-b", 100, 50),
    ("order-b-1", "tenant-b", "tenant-b-user", 100, 10),
)


def _runtime_digest(config: LocalTargetConfig) -> str:
    payload = json.dumps(
        {
            "target_id": config.target_id,
            "version": config.version,
            "source_digest": config.source_digest,
            "routes": [
                "/",
                "/api/me",
                "/api/documents/{document_id}",
                "/api/admin/reports",
                "/api/tenant/{tenant_id}/documents/{document_id}",
                "/api/workflows/{workflow_id}/preview",
                "/api/orders/{order_id}/summary",
                "/api/admin/privilege-preview",
                "/api/tenant/{tenant_id}/billing-summary",
            ],
        },
        sort_keys=True,
    ).encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def create_target_app(config: LocalTargetConfig, db_path: str = ":memory:") -> FastAPI:
    """Create one disposable target app with a real SQLite-backed read model."""

    config.validate()
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS documents (
            document_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            summary TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS orders (
            order_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            amount INTEGER NOT NULL,
            discount INTEGER NOT NULL
        );
        """
    )
    conn.executemany("INSERT OR REPLACE INTO documents VALUES (?, ?, ?, ?)", _SEED_ROWS)
    conn.executemany("INSERT OR REPLACE INTO orders VALUES (?, ?, ?, ?, ?)", _ORDER_ROWS)
    conn.commit()

    app = FastAPI(title=f"RTA Local Target {config.target_id}", version=config.version)
    app.state.rta_config = config
    app.state.rta_runtime_digest = _runtime_digest(config)
    app.state.rta_db = conn

    def auth_context(session: str | None) -> SyntheticAuthContext:
        if session is None or session not in _SESSIONS:
            raise HTTPException(status_code=401, detail="synthetic session required")
        return _SESSIONS[session]

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return """<html><body><h1>RTA Local Application</h1>
        <nav><a href='/api/me'>me</a><a href='/api/documents/doc-a-1'>document</a>
        <a href='/api/admin/reports'>reports</a><a href='/api/workflows/wf-a-1/preview'>workflow</a>
        <a href='/api/orders/order-a-1/summary'>order</a></nav></body></html>"""

    @app.get("/api/openapi-lite")
    def openapi_lite() -> dict[str, Any]:
        return {
            "target_id": config.target_id,
            "version": config.version,
            "runtime_digest": app.state.rta_runtime_digest,
            "routes": [
                {"method": "GET", "path": "/api/me", "auth_required": True},
                {"method": "GET", "path": "/api/documents/{document_id}", "auth_required": True},
                {"method": "GET", "path": "/api/admin/reports", "auth_required": True},
                {
                    "method": "GET",
                    "path": "/api/tenant/{tenant_id}/documents/{document_id}",
                    "auth_required": True,
                },
                {
                    "method": "GET",
                    "path": "/api/workflows/{workflow_id}/preview",
                    "auth_required": True,
                },
                {"method": "GET", "path": "/api/orders/{order_id}/summary", "auth_required": True},
                {"method": "GET", "path": "/api/admin/privilege-preview", "auth_required": True},
                {
                    "method": "GET",
                    "path": "/api/tenant/{tenant_id}/billing-summary",
                    "auth_required": True,
                },
            ],
        }

    @app.get("/api/me")
    def me(x_synthetic_session: str | None = Header(default=None)) -> dict[str, Any]:
        context = auth_context(x_synthetic_session)
        return {
            "identity_id": context.identity_id,
            "role": context.role,
            "tenant_id": context.tenant_id,
        }

    @app.get("/api/documents/{document_id}")
    def document(
        document_id: str, x_synthetic_session: str | None = Header(default=None)
    ) -> JSONResponse:
        context = auth_context(x_synthetic_session)
        row = conn.execute(
            "SELECT * FROM documents WHERE document_id = ?", (document_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="document not found")
        allowed = row["owner_id"] == context.identity_id or context.role in {"editor", "admin"}
        if "idor" in config.vulnerable_classes:
            allowed = True
        if not allowed:
            raise HTTPException(status_code=403, detail="document forbidden")
        return JSONResponse(dict(row))

    @app.get("/api/admin/reports")
    def admin_reports(x_synthetic_session: str | None = Header(default=None)) -> dict[str, Any]:
        context = auth_context(x_synthetic_session)
        allowed = context.role == "admin"
        if "bfla" in config.vulnerable_classes:
            allowed = True
        if not allowed:
            raise HTTPException(status_code=403, detail="admin role required")
        return {"report_count": 3, "tenant_id": context.tenant_id}

    @app.get("/api/tenant/{tenant_id}/documents/{document_id}")
    def tenant_document(
        tenant_id: str,
        document_id: str,
        x_synthetic_session: str | None = Header(default=None),
    ) -> JSONResponse:
        context = auth_context(x_synthetic_session)
        row = conn.execute(
            "SELECT * FROM documents WHERE document_id = ? AND tenant_id = ?",
            (document_id, tenant_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="document not found")
        allowed = row["tenant_id"] == context.tenant_id
        if "tenant_isolation" in config.vulnerable_classes:
            allowed = True
        if not allowed:
            raise HTTPException(status_code=403, detail="tenant boundary")
        return JSONResponse(dict(row))

    @app.get("/api/workflows/{workflow_id}/preview")
    def workflow_preview(
        workflow_id: str, x_synthetic_session: str | None = Header(default=None)
    ) -> dict[str, Any]:
        context = auth_context(x_synthetic_session)
        allowed = context.role in {"editor", "admin"}
        if "workflow_authorization" in config.vulnerable_classes:
            allowed = True
        if not allowed:
            raise HTTPException(status_code=403, detail="workflow role required")
        return {
            "workflow_id": workflow_id,
            "stage": "approved-preview",
            "tenant_id": context.tenant_id,
        }

    @app.get("/api/tenant/{tenant_id}/billing-summary")
    def billing_summary(
        tenant_id: str, x_synthetic_session: str | None = Header(default=None)
    ) -> dict[str, Any]:
        context = auth_context(x_synthetic_session)
        full_access = context.tenant_id == tenant_id
        if "tenant_partial_access" in config.vulnerable_classes:
            full_access = True
        if full_access:
            return {
                "tenant_id": tenant_id,
                "access_level": "full",
                "invoice_count": 2,
                "total_due": 110,
            }
        return {
            "tenant_id": tenant_id,
            "access_level": "limited",
            "invoice_count": 0,
            "total_due": None,
        }

    @app.get("/api/admin/privilege-preview")
    def privilege_preview(x_synthetic_session: str | None = Header(default=None)) -> dict[str, Any]:
        context = auth_context(x_synthetic_session)
        allowed = context.role == "admin"
        if "privilege_escalation" in config.vulnerable_classes:
            allowed = context.role in {"editor", "admin"}
        if not allowed:
            raise HTTPException(status_code=403, detail="admin privilege required")
        return {"scope": "admin-preview", "role": context.role, "tenant_id": context.tenant_id}

    @app.get("/api/orders/{order_id}/summary")
    def order_summary(
        order_id: str, x_synthetic_session: str | None = Header(default=None)
    ) -> dict[str, Any]:
        context = auth_context(x_synthetic_session)
        row = conn.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="order not found")
        if row["owner_id"] != context.identity_id and context.role != "admin":
            raise HTTPException(status_code=403, detail="order owner required")
        discount = row["discount"]
        if "business_logic" in config.vulnerable_classes and context.role == "viewer":
            discount = 90
        return {
            "order_id": order_id,
            "amount": row["amount"],
            "discount": discount,
            "total": row["amount"] - discount,
        }

    return app


def default_target_configs() -> tuple[LocalTargetConfig, ...]:
    """Return three intentionally different, immutable local benchmark profiles."""

    return (
        LocalTargetConfig(
            "rta-http-a",
            "1.0.0",
            "sha256:rta-http-source-a",
            frozenset(
                {
                    "idor",
                    "bfla",
                    "tenant_isolation",
                    "workflow_authorization",
                    "business_logic",
                    "privilege_escalation",
                    "tenant_partial_access",
                }
            ),
        ),
        LocalTargetConfig(
            "rta-http-b",
            "1.1.0",
            "sha256:rta-http-source-b",
            frozenset(
                {
                    "idor",
                    "tenant_isolation",
                    "business_logic",
                    "privilege_escalation",
                    "tenant_partial_access",
                }
            ),
        ),
        LocalTargetConfig(
            "rta-http-c",
            "2.0.0",
            "sha256:rta-http-source-c",
            frozenset(
                {"bfla", "workflow_authorization", "privilege_escalation", "tenant_partial_access"}
            ),
        ),
    )

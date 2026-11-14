"""Root-level launcher for the WebPent FastAPI server.

The launcher defaults to a loopback bind for local use. Container or reverse-
proxy deployments must set ``WEBPENT_API_HOST=0.0.0.0`` explicitly; startup
preflight evaluates that bind together with the configured authentication,
CORS, rate-limit, and Redis posture before opening the socket.
"""

from __future__ import annotations

import os

# R3 E-4 (Ruling R3-002 §3.4, mechanism (b)): this root launcher is an
# EDITABLE orchestration surface and sets the explicit entrypoint label
# the production graph records in its audited trace. API processes are
# launched through this module (uvicorn webpent.api.app:app); the label
# is truthful by construction. setdefault keeps an operator-provided
# override intact.
os.environ.setdefault("WEBPENT_ENTRYPOINT", "api")

import uvicorn

from webpent.shared.preflight import run_preflight


def main() -> None:
    """Run the FastAPI application after security preflight."""
    host = os.environ.get("WEBPENT_API_HOST", "127.0.0.1").strip() or "127.0.0.1"
    reload_enabled = os.environ.get("WEBPENT_DEV_RELOAD", "").lower() in {
        "1",
        "true",
        "yes",
    }
    run_preflight(host=host)
    uvicorn.run(
        "webpent.api.app:app",
        host=host,
        port=int(os.environ.get("WEBPENT_API_PORT", "8000")),
        reload=reload_enabled,
    )


if __name__ == "__main__":
    main()

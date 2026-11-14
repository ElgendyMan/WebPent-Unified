"""Temporary loopback HTTP server for RTA integration tests."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import uvicorn


@contextmanager
def serve_loopback(app: Any) -> Iterator[str]:
    """Serve an ASGI app on an ephemeral loopback port and clean it up."""

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        log_level="error",
        access_log=False,
        lifespan="on",
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="rta-loopback", daemon=True)
    thread.start()
    deadline = time.monotonic() + 5.0
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started or not server.servers or not server.servers[0].sockets:
        server.should_exit = True
        thread.join(timeout=2.0)
        raise RuntimeError("loopback RTA server did not start")

    port = server.servers[0].sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    try:
        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
        if thread.is_alive():
            raise RuntimeError("loopback RTA server did not stop cleanly")

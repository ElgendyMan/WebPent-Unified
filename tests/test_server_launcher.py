from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_server_module():
    path = Path(__file__).resolve().parents[1] / "server.py"
    spec = importlib.util.spec_from_file_location("webpent_root_server", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_server_launcher_runs_preflight_before_uvicorn(monkeypatch) -> None:
    server = _load_server_module()
    calls: list[tuple[str, object]] = []

    monkeypatch.delenv("WEBPENT_API_HOST", raising=False)
    monkeypatch.setenv("WEBPENT_API_PORT", "8123")
    monkeypatch.delenv("WEBPENT_DEV_RELOAD", raising=False)
    monkeypatch.setattr(
        server,
        "run_preflight",
        lambda *, host: calls.append(("preflight", host)),
    )
    monkeypatch.setattr(
        server.uvicorn,
        "run",
        lambda application, **kwargs: calls.append(("uvicorn", kwargs)),
    )

    server.main()

    assert calls[0] == ("preflight", "127.0.0.1")
    assert calls[1] == (
        "uvicorn",
        {
            "host": "127.0.0.1",
            "port": 8123,
            "reload": False,
        },
    )


def test_server_launcher_allows_explicit_container_bind(monkeypatch) -> None:
    server = _load_server_module()
    calls: list[tuple[str, object]] = []

    monkeypatch.setenv("WEBPENT_API_HOST", "0.0.0.0")
    monkeypatch.setenv("WEBPENT_API_PORT", "9000")
    monkeypatch.setenv("WEBPENT_DEV_RELOAD", "true")
    monkeypatch.setattr(
        server,
        "run_preflight",
        lambda *, host: calls.append(("preflight", host)),
    )
    monkeypatch.setattr(
        server.uvicorn,
        "run",
        lambda application, **kwargs: calls.append(("uvicorn", kwargs)),
    )

    server.main()

    assert calls[0] == ("preflight", "0.0.0.0")
    assert calls[1][1]["host"] == "0.0.0.0"
    assert calls[1][1]["port"] == 9000
    assert calls[1][1]["reload"] is True

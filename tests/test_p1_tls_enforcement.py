from __future__ import annotations

from pathlib import Path

import pytest

from webpent.shared.http import make_safe_httpx_async_client, make_safe_httpx_client

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_sync_http_factory_rejects_disabled_tls_verification() -> None:
    with pytest.raises(ValueError, match="TLS certificate verification"):
        make_safe_httpx_client(verify=False)


def test_async_http_factory_rejects_disabled_tls_verification() -> None:
    with pytest.raises(ValueError, match="TLS certificate verification"):
        make_safe_httpx_async_client(verify=False)


def test_source_contains_no_literal_tls_downgrade() -> None:
    source_root = PROJECT_ROOT / "src"
    offenders: list[str] = []
    for path in source_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "verify=False" in text or "verify = False" in text:
            offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert offenders == []


def test_safe_http_factory_enforces_verify_true_by_default() -> None:
    client = make_safe_httpx_client()
    try:
        assert client._transport is not None  # noqa: SLF001
    finally:
        client.close()


@pytest.mark.asyncio
async def test_safe_async_http_factory_enforces_verify_true_by_default() -> None:
    client = make_safe_httpx_async_client()
    try:
        assert client._transport is not None  # noqa: SLF001
    finally:
        await client.aclose()

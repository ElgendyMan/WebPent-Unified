from __future__ import annotations

import logging
import re
from types import SimpleNamespace

import pytest


def test_ffuf_is_registered_lazily():
    from webpent.tools.registry import get_tool

    entry = get_tool("ffuf")
    assert entry is not None
    assert entry.category == "recon"


def test_ffuf_parser_accepts_object_and_jsonl():
    from webpent.tools.recon.ffuf import _parse_ffuf_output

    object_records = _parse_ffuf_output(
        '{"results": [{"url": "https://target.test/admin", "status": 200}]}'
    )
    jsonl_records = _parse_ffuf_output(
        '{"url": "https://target.test/login", "status": 302}\nnot-json\n'
    )
    assert object_records[0]["status"] == 200
    assert jsonl_records[0]["url"].endswith("/login")


def test_ffuf_refuses_out_of_scope_before_subprocess(monkeypatch, tmp_path):
    import webpent.tools.recon.ffuf as ffuf

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run out of scope")

    monkeypatch.setattr(ffuf, "run_command", fail_if_called)
    monkeypatch.setattr(ffuf, "is_engagement_target_host", lambda host: False)
    assert ffuf.run_ffuf("https://out-of-scope.test", str(wordlist)) == []
    assert called is False


def test_ffuf_projects_only_safe_result_metadata(monkeypatch, tmp_path):
    import webpent.tools.recon.ffuf as ffuf

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr(ffuf, "is_engagement_target_host", lambda host: True)
    monkeypatch.setattr(
        ffuf,
        "get_settings",
        lambda: SimpleNamespace(ffuf_path="ffuf", ffuf_timeout=5),
    )
    monkeypatch.setattr(
        ffuf,
        "run_command",
        lambda cmd, timeout: (
            '{"results": [{"url": "https://target.test/admin", "status": 200, "length": 12, '
            '"body": "must-not-be-kept"}]}'
        ),
    )

    records = ffuf.run_ffuf("https://target.test", str(wordlist))
    assert records == [
        {
            "url": "https://target.test/admin",
            "status": 200,
            "length": 12,
            "words": None,
            "lines": None,
            "redirectlocation": None,
            "input": None,
        }
    ]
    assert "body" not in records[0]


def test_preflight_blocks_explicit_public_insecure_posture(monkeypatch):
    import webpent.shared.preflight as preflight

    monkeypatch.delenv("I_UNDERSTAND_THIS_IS_INSECURE", raising=False)
    monkeypatch.setattr(preflight, "_check_alembic", lambda: {"status": "ok"})
    monkeypatch.setattr(preflight, "_check_playwright_ws_guard", lambda: {"status": "ok"})
    monkeypatch.setattr(preflight, "_check_embeddings", lambda: {"status": "ok"})
    monkeypatch.setattr(preflight, "_check_celery_payload_key", lambda: {"status": "ok"})
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(
            auth_enabled=False,
            cors_origins=["*"],
            rate_limit_enabled=False,
        ),
    )

    with pytest.raises(SystemExit, match=re.escape("unsafe 0.0.0.0")):
        preflight.run_preflight(host="0.0.0.0")


def test_preflight_override_is_explicit_and_visible(monkeypatch, caplog):
    import webpent.shared.preflight as preflight

    monkeypatch.setenv("I_UNDERSTAND_THIS_IS_INSECURE", "true")
    monkeypatch.setattr(preflight, "_check_alembic", lambda: {"status": "ok"})
    monkeypatch.setattr(preflight, "_check_playwright_ws_guard", lambda: {"status": "ok"})
    monkeypatch.setattr(preflight, "_check_embeddings", lambda: {"status": "ok"})
    monkeypatch.setattr(preflight, "_check_celery_payload_key", lambda: {"status": "ok"})
    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(
            auth_enabled=False,
            cors_origins=["*"],
            rate_limit_enabled=False,
        ),
    )

    with caplog.at_level(logging.CRITICAL):
        report = preflight.run_preflight(host="0.0.0.0")
    assert report["api_security_posture"]["status"].startswith("OVERRIDDEN")
    assert "INSECURE OVERRIDE" in caplog.text


def test_recon_ffuf_is_disabled_by_default(monkeypatch):
    from webpent.agents.recon import agent

    monkeypatch.setattr(
        "webpent.config.settings.get_settings",
        lambda: SimpleNamespace(ffuf_enabled=False, ffuf_wordlist_path=""),
    )
    target = SimpleNamespace(url="https://target.test", domain="target.test")
    assert agent._run_ffuf_discovery(target) == []

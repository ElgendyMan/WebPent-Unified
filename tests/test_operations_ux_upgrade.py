"""Regression tests for the additive operations/UX upgrade."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from webpent.cli.loaders import load_cookie_file, load_creds_file, load_payload_file
from webpent.models.targets import Target
from webpent.reporter.export import export_all_formats
from webpent.shared import stealth
from webpent.shared.preflight import _check_llm_providers
from webpent.state.initial_state import build_initial_state


def test_loaders_accept_bounded_profiles_cookies_and_deduplicated_payloads(tmp_path: Path) -> None:
    creds_path = tmp_path / "creds.json"
    creds_path.write_text(
        json.dumps(
            {
                "admin": {"username": "admin", "password": "secret"},
                "auditor": {"username": "auditor", "password": "secret-2"},
            }
        ),
        encoding="utf-8",
    )
    cookie_path = tmp_path / "cookies.txt"
    cookie_path.write_text(
        "# Netscape HTTP Cookie File\n"
        ".example.test\tTRUE\t/\tFALSE\t0\tSESSION\tabc\n",
        encoding="utf-8",
    )
    payload_path = tmp_path / "payloads.txt"
    payload_path.write_text("<x>\n\n# comment\n<x>\n{{7*7}}\n", encoding="utf-8")

    assert set(load_creds_file(creds_path)) == {"admin", "auditor"}
    assert load_cookie_file(cookie_path) == {"SESSION": "abc"}
    assert load_payload_file(payload_path) == ["<x>", "{{7*7}}"]


def test_loaders_fail_closed_on_invalid_shapes(tmp_path: Path) -> None:
    bad_creds = tmp_path / "bad-creds.json"
    bad_creds.write_text('{"admin": {"username": "only"}}', encoding="utf-8")
    bad_cookies = tmp_path / "bad-cookies.txt"
    bad_cookies.write_text("not-a-netscape-row", encoding="utf-8")

    with pytest.raises(ValueError):
        load_creds_file(bad_creds)
    with pytest.raises(ValueError):
        load_cookie_file(bad_cookies)


def test_initial_state_carries_per_run_ux_contract() -> None:
    state = build_initial_state(
        Target(url="https://example.test"),
        thread_id="thread-1",
        engagement_id="engagement-1",
        llm_override=False,
        custom_payloads=[" one ", "", "two"],
        report_formats=["md", "json"],
    )

    assert state["llm_enabled_override"] is False
    assert state["custom_payloads"] == ["one", "two"]
    assert state["payloads_to_test"] == {"custom": ["one", "two"]}
    assert state["report_formats"] == ["md", "json"]


def test_report_selection_exports_only_requested_format(tmp_path: Path) -> None:
    paths = export_all_formats(
        target_url="https://example.test",
        findings=[],
        output_dir=tmp_path,
        formats=["md"],
    )

    assert set(paths) == {"md"}
    assert (tmp_path / "report.md").is_file()
    assert not (tmp_path / "report.json").exists()
    assert not (tmp_path / "report.html").exists()


def test_report_format_parser_removed_with_retired_aliases() -> None:
    """v0.32.0: the parser helper died with the removed ``scan`` command.

    ``_parse_report_formats`` had exactly one production caller (the
    retired ``scan`` CLI alias removed by the declared v0.32.0 window).
    The unified ``hunt`` takes a single ``--report-format`` value, so the
    comma-normalizing parser has no remaining production surface. This
    test pins the REMOVAL contract instead of the parser itself.
    """
    import webpent.cli as cli_pkg

    assert not hasattr(cli_pkg, "_parse_report_formats"), (
        "_parse_report_formats was removed by the v0.32.0 window; "
        "re-adding it requires a new declared window"
    )


def test_stealth_telemetry_is_redaction_safe_and_resettable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stealth.reset_stealth_telemetry()
    monkeypatch.setattr(stealth, "_draw_jitter_seconds", lambda: 0.25)
    monkeypatch.setattr(stealth.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        stealth,
        "get_settings",
        lambda: SimpleNamespace(stealth_min_request_interval=0.0),
    )

    stealth.apply_jitter(True, label="test")
    stealth.enforce_min_interval(True, "example.test")
    summary = stealth.get_stealth_summary()

    assert summary["jitter_calls"] == 1
    assert summary["rate_limit_calls"] == 1
    assert summary["jitter_sleep_seconds"] == 0.25
    assert summary["total_sleep_seconds"] == 0.25

    stealth.reset_stealth_telemetry()
    assert stealth.get_stealth_summary()["total_sleep_seconds"] == 0.0


def test_llm_preflight_is_read_only_and_reports_fallback_shape() -> None:
    report = _check_llm_providers()

    assert "status" in report
    assert isinstance(report["configured_providers"], list)
    assert isinstance(report["fallback_chains"], dict)
    assert "analysis" in report["fallback_chains"]

# tests/test_notifications.py
"""PROPOSALS_ULTIMATE_V3 §4 (2026-11-01) test suite: notifications.

Covers the three pure per-platform formatters (correct native payload
shapes from one fixture Finding), the severity gate (threshold pass/
drop, unknown severities fail closed), the flag gate (off = no
endpoint resolution, no formatting, no ledger row, no send), fail-soft
per-channel dispatch with an attempt log, ledger pass-through for
every send event (endpoint secret never in the ledger row verbatim),
the daily-digest buffer/builder/render (below-threshold accumulation,
counts, top-k) and one real send against a local HTTP server fixture
(loopback). All channel sends except the loopback fixture are fakes —
no network leaves the process.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from webpent.integrations.notifications.dispatch import (
    DispatchEntry,
    DispatchReport,
    NotificationError,
    SEVERITY_ORDER,
    _default_send,
    dispatch,
    notifications_refusal,
    severity_gate,
    severity_rank,
)
from webpent.integrations.notifications.daily_digest import (
    DailyDigestBuffer,
    build_digest,
    render_text,
)
from webpent.models.findings import Finding


def _finding(severity: str = "high", title: str = "SQL injection in search") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        description="Union-based SQLi confirmed via response differential.",
        tool_name="sqli_agent",
        payload="' OR 1=1 --",
        url="https://target.example.com/search?q=x",
        confidence="confirmed",
    )


def _activated(**extra):
    from webpent.config.settings import Settings, activate_settings

    return activate_settings(Settings(enable_notifications=True, **extra))


class FakeLedger:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.rows: list[tuple[str, str, str]] = []

    def record(self, method, url, *, engagement_id="", flags=""):
        if not self.ok:
            return False
        self.rows.append((method, url, flags))
        return True


# ---------------------------------------------------------------------------
# Pure formatters.
# ---------------------------------------------------------------------------


class TestFormatters:
    def test_slack_payload_shape(self):
        from webpent.integrations.notifications.formatters.slack import format_slack

        payload = format_slack(_finding())
        assert payload["text"].startswith("[HIGH]")
        attachment = payload["attachments"][0]
        assert attachment["color"] == "#ff9800"
        fields = {f["title"]: f["value"] for f in attachment["fields"]}
        assert fields["Severity"] == "high"
        assert "target.example.com" in fields["URL"]
        assert "' OR 1=1" in fields["Payload"]

    def test_slack_truncates_long_description(self):
        from webpent.integrations.notifications.formatters.slack import format_slack

        finding = _finding()
        finding = finding.model_copy(update={"description": "x" * 5000})
        payload = format_slack(finding)
        assert len(payload["attachments"][0]["text"]) <= 700

    def test_discord_payload_shape(self):
        from webpent.integrations.notifications.formatters.discord import format_discord

        payload = format_discord(_finding(severity="critical"))
        assert payload["content"].startswith("🔔 **[CRITICAL]**")
        embed = payload["embeds"][0]
        assert embed["color"] == 0xF44336
        assert embed["url"] == "https://target.example.com/search?q=x"
        names = [f["name"] for f in embed["fields"]]
        assert "Severity" in names and "Payload" in names

    def test_telegram_payload_shape_and_html_escaping(self):
        from webpent.integrations.notifications.formatters.telegram import (
            format_telegram,
            escape_html,
        )

        finding = _finding()
        finding = finding.model_copy(update={"payload": "<script>alert(1)</script>"})
        payload = format_telegram(finding, chat_id="-100123")
        assert payload["parse_mode"] == "HTML"
        assert payload["chat_id"] == "-100123"
        assert "<script>" not in payload["text"]
        assert escape_html("<script>") == "&lt;script&gt;"
        assert "<code>&lt;script&gt;" in payload["text"]

    def test_formatters_are_pure_data(self):
        from webpent.integrations.notifications.formatters.discord import format_discord
        from webpent.integrations.notifications.formatters.slack import format_slack
        from webpent.integrations.notifications.formatters.telegram import format_telegram

        f = _finding()
        for payload in (format_slack(f), format_discord(f), format_telegram(f)):
            json.dumps(payload)  # must be JSON-serializable data


# ---------------------------------------------------------------------------
# Severity gate and threshold.
# ---------------------------------------------------------------------------


class TestSeverityGate:
    def test_documented_order(self):
        assert SEVERITY_ORDER == ("info", "low", "medium", "high", "critical")

    def test_threshold_default_high_in_plan(self):
        from webpent.config.settings import Settings

        assert Settings().notify_min_severity == "high"

    def test_gate_pass_and_drop(self):
        assert severity_gate(_finding("critical"), "high") is True
        assert severity_gate(_finding("high"), "high") is True
        assert severity_gate(_finding("medium"), "high") is False
        assert severity_gate(_finding("info"), "high") is False

    def test_unknown_severity_fails_closed(self):
        with pytest.raises(NotificationError, match="notifications_unknown_severity"):
            severity_rank("apocalyptic")
        with pytest.raises(NotificationError, match="notifications_unknown_severity"):
            severity_gate(_finding(), "banana")


# ---------------------------------------------------------------------------
# Flag gate and mandatory ledger.
# ---------------------------------------------------------------------------


class TestGate:
    def test_flag_off_refuses(self):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_notifications=False)):
            assert notifications_refusal() == "notifications_flag_off"

    def test_flag_off_zero_touches(self):
        from webpent.config.settings import Settings, activate_settings

        ledger = FakeLedger()
        calls: list[str] = []

        def send(endpoint, payload):
            calls.append(endpoint)
            return True

        with activate_settings(Settings(enable_notifications=False)):
            with pytest.raises(NotificationError, match="notifications_flag_off"):
                dispatch([_finding()], ledger=ledger, send_fn=send)
        assert calls == []
        assert ledger.rows == []

    def test_ledger_required_fail_closed(self):
        with _activated(notify_channels=["slack"]):
            with pytest.raises(NotificationError, match="notifications_ledger_required"):
                dispatch([_finding()], ledger=None, send_fn=lambda e, p: True)

    def test_default_off(self):
        from webpent.config.settings import Settings

        assert Settings().enable_notifications is False
        assert Settings().notify_channels == []


# ---------------------------------------------------------------------------
# Dispatch: fail-soft channels, ledger pass-through, privacy.
# ---------------------------------------------------------------------------


class TestDispatch:
    def test_send_via_fake_channel(self):
        import os

        with _activated(notify_channels=["slack"]):
            os.environ["SLACK_WEBHOOK_URL"] = "https://hooks.example.com/services/T/B/X"
            try:
                sent: list[tuple[str, dict]] = []

                def send(endpoint, payload):
                    sent.append((endpoint, payload))
                    return True

                report = dispatch([_finding()], ledger=FakeLedger(), send_fn=send)
                assert report.sent == 1
                assert sent[0][0] == "https://hooks.example.com/services/T/B/X"
                assert sent[0][1]["attachments"][0]["title"] == "SQL injection in search"
            finally:
                os.environ.pop("SLACK_WEBHOOK_URL", None)

    def test_below_threshold_not_sent_and_buffered(self):
        import tempfile
        from pathlib import Path

        with _activated(notify_channels=["slack"]):
            ledger = FakeLedger()
            with tempfile.TemporaryDirectory() as td:
                buffer = DailyDigestBuffer(Path(td) / "digest.jsonl")
                report = dispatch(
                    [_finding("low")], ledger=ledger, send_fn=lambda e, p: True,
                    digest_buffer=buffer,
                )
                assert report.sent == 0
                assert report.suppressed_below_threshold == 1
                assert ledger.rows == []
                assert len(buffer.entries()) == 1
                assert buffer.entries()[0].severity == "low"

    def test_fail_soft_one_platform_failing_does_not_break_others(self):
        import os

        with _activated(notify_channels=["slack", "discord"]):
            os.environ["SLACK_WEBHOOK_URL"] = "https://hooks.example.com/slack"
            os.environ["DISCORD_WEBHOOK_URL"] = "https://hooks.example.com/discord"
            try:
                ledger = FakeLedger()

                def send_fail_all_but(endpoint, payload):
                    if payload.get("embeds"):
                        raise RuntimeError("discord down")
                    return True

                report = dispatch(
                    [_finding()], ledger=ledger, send_fn=send_fail_all_but
                )
                assert report.sent == 1  # slack got through
                statuses = [e.status for e in report.entries]
                assert "failed" in statuses and "sent" in statuses
            finally:
                os.environ.pop("SLACK_WEBHOOK_URL", None)
                os.environ.pop("DISCORD_WEBHOOK_URL", None)

    def test_every_send_event_ledgered_secret_never_verbatim(self):
        import os

        with _activated(notify_channels=["slack"]):
            os.environ["SLACK_WEBHOOK_URL"] = "https://hooks.example.com/services/SECRET/PATH"
            try:
                ledger = FakeLedger()
                dispatch([_finding()], ledger=ledger, send_fn=lambda e, p: True)
                assert len(ledger.rows) == 1
                method, url, flags = ledger.rows[0]
                assert method == "POST" and flags == "notify"
                assert url.startswith("notify://slack#")
                assert "SECRET" not in url and "PATH" not in url
            finally:
                os.environ.pop("SLACK_WEBHOOK_URL", None)

    def test_missing_secret_skipped_fail_soft(self):
        with _activated(notify_channels=["slack"]):
            import os

            os.environ.pop("SLACK_WEBHOOK_URL", None)
            report = dispatch([_finding()], ledger=FakeLedger(), send_fn=lambda e, p: True)
            assert report.entries[0].status == "skipped_no_secret"
            assert report.sent == 0

    def test_ledger_refusal_means_not_sent(self):
        with _activated(notify_channels=["slack"]):
            import os

            os.environ["SLACK_WEBHOOK_URL"] = "https://hooks.example.com/x"
            try:
                sent: list[str] = []
                report = dispatch(
                    [_finding()],
                    ledger=FakeLedger(ok=False),
                    send_fn=lambda e, p: sent.append(e) or True,
                )
                assert report.entries[0].status == "ledger_refused"
                assert sent == []
            finally:
                os.environ.pop("SLACK_WEBHOOK_URL", None)

    def test_unknown_platform_refused_not_sent(self):
        with _activated(notify_channels=["carrier_pigeon"]):
            report = dispatch([_finding()], ledger=FakeLedger(), send_fn=lambda e, p: True)
            assert report.entries[0].status == "unknown_platform"
            assert report.sent == 0

    def test_no_channels_no_sends_even_with_flag_on(self):
        with _activated(notify_channels=[]):
            report = dispatch([_finding()], ledger=FakeLedger(), send_fn=lambda e, p: True)
            assert report.entries == []
            assert report.sent == 0


# ---------------------------------------------------------------------------
# Daily digest.
# ---------------------------------------------------------------------------


class TestDigest:
    def test_buffer_roundtrip_and_fail_closed_load(self, tmp_path):
        buffer = DailyDigestBuffer(tmp_path / "digest.jsonl")
        buffer.add_entry(
            __import__(
                "webpent.integrations.notifications.daily_digest",
                fromlist=["DigestEntry"],
            ).DigestEntry(
                finding_id="f-1", title="t", severity="medium",
                vuln_class="xss", created_at="2026-11-01T00:00:00Z",
            )
        )
        assert len(buffer.entries()) == 1
        # bad line refuses the whole file
        with buffer.path.open("a", encoding="utf-8") as fh:
            fh.write('{"finding_id": "f-2"}\n')
        with pytest.raises(ValueError, match="digest_buffer_bad_line"):
            buffer.entries()

    def test_entry_from_dict_fail_closed(self):
        from webpent.integrations.notifications.daily_digest import DigestEntry

        with pytest.raises(ValueError, match="digest_entry_unknown_fields"):
            DigestEntry.from_dict({"finding_id": "f", "title": "t", "severity": "low",
                                   "vuln_class": "xss", "created_at": "x", "bounty": "1"})
        with pytest.raises(ValueError, match="digest_entry_missing_fields"):
            DigestEntry.from_dict({"finding_id": "f"})
        with pytest.raises(ValueError, match="digest_entry_unknown_severity"):
            DigestEntry.from_dict({"finding_id": "f", "title": "t", "severity": "huge",
                                   "vuln_class": "xss", "created_at": "x"})

    def test_build_digest_counts_and_top_k(self):
        from webpent.integrations.notifications.daily_digest import DigestEntry

        def entry(sev, at, vid):
            return DigestEntry(finding_id=vid, title=f"t-{vid}", severity=sev,
                               vuln_class="sqli", created_at=at)

        entries = [
            entry("low", "2026-11-01T01:00:00Z", "1"),
            entry("medium", "2026-11-01T02:00:00Z", "2"),
            entry("info", "2026-11-01T03:00:00Z", "3"),
            entry("medium", "2026-11-01T04:00:00Z", "4"),
        ]
        digest = build_digest(entries, top_k=2)
        assert digest["total"] == 4
        assert digest["counts_by_severity"]["medium"] == 2
        assert digest["counts_by_severity"]["low"] == 1
        assert digest["counts_by_vuln_class"] == {"sqli": 4}
        top_ids = [e["finding_id"] for e in digest["top_findings"]]
        assert top_ids == ["4", "2"]  # highest severity first, then recency

    def test_render_text_mentions_counts_and_top(self):
        from webpent.integrations.notifications.daily_digest import DigestEntry

        digest = build_digest([
            DigestEntry(finding_id="f-1", title="XSS in profile", severity="medium",
                        vuln_class="xss", created_at="2026-11-01T00:00:00Z"),
        ])
        text = render_text(digest)
        assert "1 finding(s)" in text
        assert "medium: 1" in text
        assert "XSS in profile" in text


# ---------------------------------------------------------------------------
# Default transport: real send against a local HTTP server (loopback).
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    status = 200

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(self.status)
        self.end_headers()

    def log_message(self, *args):  # silence
        pass


class TestDefaultSend:
    def test_real_loopback_send_success_and_failure(self):
        server = HTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            assert _default_send(f"http://127.0.0.1:{port}/hook", {"a": 1}) is True
            _Handler.status = 500
            assert _default_send(f"http://127.0.0.1:{port}/hook", {"a": 1}) is False
            _Handler.status = 200
        finally:
            server.shutdown()
            server.server_close()

    def test_plain_http_refused_off_loopback(self):
        assert _default_send("http://evil.example.com/hook", {"a": 1}) is False
        assert _default_send("ftp://127.0.0.1/hook", {"a": 1}) is False

# tests/vip/test_notifications.py
"""Track 11 item 8 — confirmation notifications.

Covers: redaction-first payloads, disabled-by-default posture, file
channel dispatch, idempotency, severity threshold, bounded-queue drop
policy, transition semantics, and the DB-layer hook (save_finding).
No real network is ever touched.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.vip.notifications import (
    ConfirmationNotifier,
    build_notification_payload,
    notify_confirmation_transition,
)


def _finding(
    *,
    severity: Severity = Severity.HIGH,
    confidence_level: str = "Tool-Confirmed",
    payload_text: str = "<script>canary</script>",
) -> Finding:
    return Finding(
        id=uuid4(),
        title="Reflected XSS in search",
        severity=severity,
        description="deterministic test finding",
        tool_name="validator",
        url="https://app.example.com/search?q=1",
        confidence=Confidence.CONFIRMED,
        vuln_class=VulnClass.XSS,
        confidence_level=confidence_level,
        payload=payload_text,
        reasoning="evidence matched canary marker",
        thread_id="t1",
        # M1-B (E-1): model-level proof requirement — confirmed fixtures
        # must name their confirming gate.
        evidence={"tool_confirmed_by": "test.fixture"},
    )


class TestRedactionFirstPayload:
    def test_default_payload_has_no_sensitive_details(self):
        finding = _finding()
        body = build_notification_payload(finding)
        assert body["event"] == "finding_confirmed"
        assert body["finding_id"] == str(finding.id)
        assert body["severity"] == "high"
        assert body["url"] == finding.url
        assert "payload" not in body
        assert "reasoning" not in body
        assert "evidence_bundle" not in body
        assert "evidence" not in body

    def test_details_only_with_explicit_opt_in(self):
        finding = _finding()
        body = build_notification_payload(finding, include_details=True)
        assert body["payload"] == finding.payload
        assert body["reasoning"] == finding.reasoning

    def test_payload_is_json_serializable(self):
        body = build_notification_payload(_finding())
        assert json.loads(json.dumps(body))["finding_id"]


class TestNotifierGates:
    def test_disabled_by_default_is_noop(self):
        notifier = ConfirmationNotifier()  # no channels
        assert notifier.enabled is False
        assert notifier.notify_finding_confirmed(_finding()) is False
        assert notifier.stats["enqueued"] == 0

    def test_file_channel_dispatch_and_redaction(self, tmp_path):
        inbox = tmp_path / "notifications.jsonl"
        notifier = ConfirmationNotifier(file_path=inbox)
        assert notifier.notify_finding_confirmed(_finding()) is True
        notifier.drain_for_tests()
        rows = [json.loads(line) for line in inbox.read_text().splitlines()]
        assert len(rows) == 1
        assert rows[0]["severity"] == "high"
        assert "payload" not in rows[0]
        assert "reasoning" not in rows[0]

    def test_idempotent_no_renotify_same_finding(self, tmp_path):
        inbox = tmp_path / "notifications.jsonl"
        notifier = ConfirmationNotifier(file_path=inbox)
        finding = _finding()
        assert notifier.notify_finding_confirmed(finding) is True
        assert notifier.notify_finding_confirmed(finding) is False
        notifier.drain_for_tests()
        assert len(inbox.read_text().splitlines()) == 1
        assert notifier.stats["suppressed"] == 1

    def test_min_severity_threshold(self, tmp_path):
        notifier = ConfirmationNotifier(file_path=tmp_path / "n.jsonl", min_severity="critical")
        assert notifier.notify_finding_confirmed(_finding(severity=Severity.MEDIUM)) is False
        assert notifier.stats["suppressed"] == 1

    def test_queue_overflow_drops_without_raising(self, tmp_path, monkeypatch):
        # Deterministic overflow: no worker at all (monkeypatched), so the
        # queue (maxsize=1) fills and further events must DROP.
        notifier = ConfirmationNotifier(
            webhook_url="https://hooks.example.test/x",
            webhook_enabled=True,
            queue_maxsize=1,
        )
        monkeypatch.setattr(notifier, "_ensure_worker", lambda: None)
        results = [notifier.notify_finding_confirmed(_finding()) for _ in range(5)]
        assert sum(1 for r in results if r is True) == 1  # one enqueued
        assert notifier.stats["dropped"] >= 1
        notifier.close()

    def test_webhook_channel_dispatch_signed_and_redacted(self, tmp_path, monkeypatch):
        captured: dict = {}

        class _FakeResponse:
            status_code = 204

        class _FakeClient:
            def __init__(self):
                self.headers = {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def post(self, url, content=None, headers=None):
                captured["url"] = url
                captured["body"] = content
                captured["headers"] = headers
                return _FakeResponse()

        def _fake_factory(**kwargs):
            return _FakeClient()

        monkeypatch.setattr(
            "webpent.shared.http.make_safe_httpx_async_client", _fake_factory
        )
        notifier = ConfirmationNotifier(
            webhook_url="https://hooks.example.test/x",
            webhook_enabled=True,
            webhook_secret="s3cret",
        )
        assert notifier.notify_finding_confirmed(_finding()) is True
        notifier.drain_for_tests()
        assert captured["url"] == "https://hooks.example.test/x"
        body = json.loads(captured["body"])
        assert "payload" not in body
        assert captured["headers"]["X-WebPent-Signature"].startswith("sha256=")

    def test_webhook_failure_never_raises(self, tmp_path, monkeypatch):
        class _Boom:
            def __init__(self, **kwargs):
                pass

            async def __aenter__(self):
                raise RuntimeError("network down")

            async def __aexit__(self, *exc):
                return False

        monkeypatch.setattr(
            "webpent.shared.http.make_safe_httpx_async_client", lambda **kw: _Boom(**kw)
        )
        notifier = ConfirmationNotifier(
            webhook_url="https://hooks.example.test/x", webhook_enabled=True
        )
        assert notifier.notify_finding_confirmed(_finding()) is True
        notifier.drain_for_tests()  # dispatch swallowed the failure
        assert notifier.stats["failed"] >= 1


class TestTransitionSemantics:
    def test_only_transition_into_confirmed_notifies(self):
        finding = _finding()
        # With all channels disabled the hook is a safe no-op.
        assert notify_confirmation_transition(
            new_status="CONFIRMED", old_status="UNCONFIRMED", finding=finding
        ) is False

    def test_hook_guard_rejects_non_confirmed_and_noop_transitions(self, monkeypatch):
        calls: list[tuple] = []

        def _fake_notify(finding):
            calls.append(str(finding.id))
            return True

        monkeypatch.setattr(
            "webpent.vip.notifications.notify_finding_confirmed", _fake_notify
        )
        # bypass singleton by calling the hook's guard path via monkeypatched module fn
        from webpent.vip import notifications as mod

        monkeypatch.setattr(
            mod, "notify_finding_confirmed", _fake_notify
        )
        finding = _finding()
        # REFUTED transition → never notifies
        assert mod.notify_confirmation_transition(
            new_status="REFUTED", old_status="UNCONFIRMED", finding=finding
        ) is False
        # already-confirmed → no-op transition, never notifies
        assert mod.notify_confirmation_transition(
            new_status="CONFIRMED", old_status="CONFIRMED", finding=finding
        ) is False
        # genuine transition → notifies
        assert mod.notify_confirmation_transition(
            new_status="CONFIRMED", old_status="UNCONFIRMED", finding=finding
        ) is True
        assert len(calls) == 1


class TestDbHook:
    def test_save_finding_fires_notification_on_confirmation(self, tmp_path, monkeypatch):
        from webpent.memory.db import DatabaseManager

        events: list[dict] = []

        def _fake_transition(**kwargs):
            events.append(kwargs)
            return True

        monkeypatch.setattr(
            "webpent.vip.notifications.notify_confirmation_transition",
            _fake_transition,
        )
        db_path = tmp_path / "hook_test.db"
        manager = DatabaseManager(database_url=f"sqlite:///{db_path}")
        finding = _finding(confidence_level="Pending")
        manager.save_finding(finding)  # Pending → UNCONFIRMED (no notification)
        assert events == []
        promoted = finding.model_copy(
            update={
                "confidence_level": "Tool-Confirmed",
                # M1-B (E-1): model-level proof requirement.
                "evidence": {"tool_confirmed_by": "test.fixture"},
            }
        )
        manager.save_finding(promoted)  # UNCONFIRMED → CONFIRMED (notify!)
        assert len(events) == 1
        assert events[0]["new_status"] == "CONFIRMED"
        assert str(events[0]["finding"].id) == str(finding.id)
        # Re-save the same confirmed finding → no NEW transition, no notify
        manager.save_finding(promoted)
        assert len(events) == 1


@pytest.mark.parametrize("severity", ["info", "low", "medium", "high", "critical"])
def test_severity_rank_covers_all_buckets(severity):
    from webpent.vip.notifications import _SEVERITY_RANK

    assert severity in _SEVERITY_RANK

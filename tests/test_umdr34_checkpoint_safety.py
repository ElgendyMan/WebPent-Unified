"""UM-DR-34 Phase 7 — checkpoint observability and safe failure.

Covers: serialization failure → explicit degraded marker (never a
silent ``{}``), degraded marker persists visibly, resume refuses to
rebuild a blank runtime from a degraded descriptor (no false-success),
secret restore stays fail-closed, and no secret values in logs.
"""

from __future__ import annotations

import logging
from collections import namedtuple

import pytest

from webpent.graph import checkpoints as cp


def _make_runtime_context():
    from webpent.shared.runtime import RuntimeFactory

    return RuntimeFactory.create(
        engagement_id="umdr34-eng",
        campaign_id="umdr34-camp",
        target_origin="http://10.10.0.5:8080/app",
        use_default_ledger=False,
    )


CheckpointTuple = namedtuple("CheckpointTuple", "config checkpoint pending_writes")


def _checkpoint_tuple(channels: dict) -> CheckpointTuple:
    return CheckpointTuple(
        config={"configurable": {"thread_id": "t-umdr34"}},
        checkpoint={"channel_values": dict(channels), "thread_id": "t-umdr34"},
        pending_writes=[],
    )


class TestRuntimeContextRedactionFailure:
    def test_descriptor_failure_produces_degraded_marker(self, monkeypatch) -> None:
        # Force RuntimeFactory.descriptor to raise — the historic branch
        # swallowed this and persisted "{}" silently.
        import webpent.shared.runtime as runtime_mod

        def _explode(value):
            raise RuntimeError("descriptor serialization exploded")

        monkeypatch.setattr(runtime_mod.RuntimeFactory, "descriptor", staticmethod(_explode))
        marker = cp._redact_channel("runtime_context", _make_runtime_context())
        assert isinstance(marker, dict)
        assert marker.get("runtime_context_status") == "degraded"
        assert marker.get("degraded_reason") == "RuntimeError"

    def test_degraded_marker_is_logged_not_silent(self, caplog) -> None:
        import webpent.shared.runtime as runtime_mod

        original = runtime_mod.RuntimeFactory.descriptor
        try:
            def _explode(value):
                raise RuntimeError("boom")

            runtime_mod.RuntimeFactory.descriptor = staticmethod(_explode)
            with caplog.at_level(logging.ERROR, logger="webpent.graph.checkpoints"):
                marker = cp._redact_channel("runtime_context", _make_runtime_context())
        finally:
            runtime_mod.RuntimeFactory.descriptor = original
        assert marker["runtime_context_status"] == "degraded"
        assert any("DEGRADED" in record.message or "degraded" in record.message for record in caplog.records)

    def test_log_carries_no_secret_values(self, caplog) -> None:
        import webpent.shared.runtime as runtime_mod

        # Built by concatenation so the repo's secret scanner never sees
        # a literal secret-shaped assignment (it is a fake marker that
        # exists ONLY to prove the failure log does not carry it).
        secret = "super-secret-" "cookie-value-" "987654321"
        original = runtime_mod.RuntimeFactory.descriptor
        try:
            def _explode(value):
                raise RuntimeError(f"context contains {secret}")

            runtime_mod.RuntimeFactory.descriptor = staticmethod(_explode)
            with caplog.at_level(logging.ERROR, logger="webpent.graph.checkpoints"):
                marker = cp._redact_channel("runtime_context", _make_runtime_context())
        finally:
            runtime_mod.RuntimeFactory.descriptor = original
        assert marker["runtime_context_status"] == "degraded"
        for record in caplog.records:
            assert secret not in record.getMessage()

    def test_valid_runtime_context_still_descriptors(self) -> None:
        from webpent.shared.runtime import RuntimeFactory

        context = _make_runtime_context()
        descriptor = cp._redact_channel("runtime_context", context)
        assert descriptor == RuntimeFactory.descriptor(context)
        assert descriptor.get("runtime_context_status") != "degraded"

    def test_secret_channels_still_emptied(self) -> None:
        assert cp._redact_channel("session_cookies", {"a": "b"}) == {}
        assert cp._redact_channel("session_headers", {"a": "b"}) == {}
        assert cp._redact_channel("credentials", {"password": "hunter2"}).get("password") == ""


class TestDegradedResume:
    def test_degraded_descriptor_does_not_rebuild_blank_runtime(self, caplog) -> None:
        # The resume path must refuse to rebuild a RuntimeContext from a
        # degraded marker — the historic from_descriptor({}) produced a
        # BLANK runtime (budget/kill-switch reset), a false-success.
        degraded_descriptor = {
            "runtime_context_status": "degraded",
            "degraded_reason": "RuntimeError",
        }
        channels = {"runtime_context": degraded_descriptor, "thread_id": "t-umdr34"}
        with caplog.at_level(logging.ERROR, logger="webpent.graph.checkpoints"):
            result = cp._restore_runtime_secrets(_checkpoint_tuple(channels))
        restored = result.checkpoint["channel_values"]
        # The channel must be dropped (no silent blank-runtime rebuild).
        assert "runtime_context" not in restored
        assert any("DEGRADED" in record.message for record in caplog.records)

    def test_normal_descriptor_still_restores(self) -> None:
        from webpent.shared.runtime import RuntimeContext, RuntimeFactory

        context = _make_runtime_context()
        descriptor = RuntimeFactory.descriptor(context)
        channels = {"runtime_context": descriptor, "thread_id": "t-umdr34"}
        result = cp._restore_runtime_secrets(_checkpoint_tuple(channels))
        restored = result.checkpoint["channel_values"]
        assert isinstance(restored.get("runtime_context"), RuntimeContext)

"""UM-DR-33 — evidence-chain and safety-hardening regressions (Phase 2).

Pins two production fixes found by the Phase 2 source-to-sink/typing audit:

1. ``cqa_v2.proof_bundle_builder.build_complete_proof_bundle`` used to pass
   ``bundle_id=None`` unconditionally, overriding the dataclass
   ``default_factory`` — every production CQA v2 bundle carried
   ``bundle_id=None`` (empirically verified before the fix). The factory
   now fires when the caller omits the id; an explicit id is still honored.

2. ``safety.kill_switch._publish`` used to call
   ``redis.Redis.from_url(None)`` when the subscriber was started but no
   REDIS_URL/CELERY_BROKER_URL was configured — a TypeError swallowed by
   the opportunistic-fanout except on every publish. It now returns
   cleanly (local switch still holds, by documented contract).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from webpent.cqa_v2.proof_bundle_builder import (  # noqa: E402
    CompleteProofBundle,
    build_complete_proof_bundle,
)
from webpent.cqa_v2.causal_guard import GuardedCausalResult, Verdict  # noqa: E402


def _causal_result() -> GuardedCausalResult:
    return GuardedCausalResult(
        verdict=Verdict.CONFIRMED,
        causal_signal="differential",
        confidence=0.9,
        block_reason="",
    )


def _build(**overrides):
    kwargs = dict(
        target_identity="t-identity",
        case_identity="c-identity",
        baseline={"status": 200, "body": "owner-view"},
        candidate={"status": 200, "body": "owner-view"},
        negative_control={"status": 403, "body": "denied"},
        causal_result=_causal_result(),
        semantic_evidence={"invariant": "owner-only read"},
        source_provenance={"run": "umdr33-regression"},
        runtime_provenance={"python": "3.12"},
    )
    kwargs.update(overrides)
    return build_complete_proof_bundle(**kwargs)


class TestProofBundleIdentity:
    def test_default_bundle_id_is_generated_not_none(self) -> None:
        """THE regression: production bundles must never carry None ids."""
        bundle = _build()
        assert bundle.bundle_id is not None
        assert bundle.bundle_id.startswith("cqa2_pb_")
        assert len(bundle.bundle_id) > len("cqa2_pb_")

    def test_explicit_bundle_id_is_honored(self) -> None:
        bundle = _build(bundle_id="cqa2_pb_explicit_123")
        assert bundle.bundle_id == "cqa2_pb_explicit_123"

    def test_two_default_builds_get_distinct_ids(self) -> None:
        a, b = _build(), _build()
        assert a.bundle_id != b.bundle_id

    def test_bundle_still_seals_and_validates(self) -> None:
        bundle = _build()
        assert bundle.is_sealed is True
        assert bundle.evidence_digests.get("baseline_sha256")
        native = bundle.to_native_proof_bundle()
        assert native is not None

    def test_direct_construction_and_builder_agree_on_factory_behavior(self) -> None:
        """Builder path and direct path must behave identically for the
        omitted-id case (the defect made them diverge)."""
        direct = CompleteProofBundle(
            target_identity="t", case_identity="c",
            baseline_observation={}, candidate_observation={},
            negative_control={}, causal_result={},
            semantic_evidence={}, source_provenance={},
            runtime_provenance={},
        )
        built = _build()
        assert direct.bundle_id is not None
        assert built.bundle_id is not None
        assert direct.bundle_id.startswith(built.bundle_id[: len("cqa2_pb_")])


class TestKillSwitchFanoutHardening:
    def test_publish_without_url_returns_cleanly(self, monkeypatch) -> None:
        """Subscriber started + no REDIS_URL/CELERY_BROKER_URL → clean
        no-op, no redis import attempted, no exception."""
        from webpent.safety import kill_switch as ks

        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
        ks._subscriber_started.set()

        import builtins

        real_import = builtins.__import__

        def _no_redis(name, *a, **k):
            if name == "redis":
                raise AssertionError("redis must not be imported without a URL")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", _no_redis)
        # must not raise
        ks._publish({"event": "engage", "reason": "regression"})

    def test_publish_with_url_attempts_redis(self, monkeypatch) -> None:
        from webpent.safety import kill_switch as ks

        monkeypatch.setenv("REDIS_URL", "redis://localhost:6399/0")
        calls = {}

        class _FakeRedis:
            def __init__(self, *a, **k):
                pass

            @classmethod
            def from_url(cls, url, *a, **k):
                assert url == "redis://localhost:6399/0"
                return cls()

            def publish(self, channel, payload):
                calls["channel"] = channel
                calls["payload"] = payload

        fake_module = type(sys)("redis")
        fake_module.Redis = _FakeRedis
        monkeypatch.setitem(sys.modules, "redis", fake_module)
        ks._publish({"event": "engage"})
        assert calls["channel"] == ks._CHANNEL

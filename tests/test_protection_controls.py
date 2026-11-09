# tests/test_protection_controls.py
"""Track 12 item 6 — protection-control handling policy.

The contract: detect block/rate-limit/challenge → STOP the attempt or
request review; polite bounded backoff for rate limits; NO evasion is
ever built or enabled.
"""

from __future__ import annotations

from webpent.production.protection_controls import (
    FORBIDDEN_EVASIONS,
    ProtectionAction,
    ProtectionSignalKind,
    append_protection_log,
    detect_protection_signal,
    evaluate_protection_policy,
)


class TestDetection:
    def test_429_is_rate_limit_with_retry_after(self):
        signal = detect_protection_signal(429, {"Retry-After": "30"})
        assert signal.kind is ProtectionSignalKind.RATE_LIMIT
        assert signal.retry_after_seconds == 30.0

    def test_cf_mitigated_challenge_header(self):
        signal = detect_protection_signal(403, {"cf-mitigated": "challenge"})
        assert signal.kind is ProtectionSignalKind.CHALLENGE

    def test_cf_mitigated_block_header(self):
        signal = detect_protection_signal(403, {"cf-mitigated": "block"})
        assert signal.kind is ProtectionSignalKind.WAF_BLOCK

    def test_403_with_waf_marker_is_block(self):
        signal = detect_protection_signal(403, {"server": "cloudflare"})
        assert signal.kind is ProtectionSignalKind.WAF_BLOCK

    def test_403_without_marker_is_still_block(self):
        # A bare 403 is a block verdict — stop and ask, don't push through.
        signal = detect_protection_signal(403)
        assert signal.kind is ProtectionSignalKind.WAF_BLOCK

    def test_challenge_body_marker(self):
        signal = detect_protection_signal(200, body_excerpt="Just a moment...")
        assert signal.kind is ProtectionSignalKind.CHALLENGE

    def test_quota_language_on_503_is_rate_limit(self):
        signal = detect_protection_signal(503, body_excerpt="quota exceeded for key")
        assert signal.kind is ProtectionSignalKind.RATE_LIMIT

    def test_503_plain_is_backend_throttle(self):
        signal = detect_protection_signal(503)
        assert signal.kind is ProtectionSignalKind.BACKEND_THROTTLE

    def test_normal_response_is_none(self):
        signal = detect_protection_signal(200, body_excerpt="welcome")
        assert signal.kind is ProtectionSignalKind.NONE

    def test_malformed_retry_after_is_not_fatal(self):
        signal = detect_protection_signal(429, {"Retry-After": "soon"})
        assert signal.kind is ProtectionSignalKind.RATE_LIMIT
        assert signal.retry_after_seconds is None


class TestPolicy:
    def test_block_halts_and_requests_review(self):
        signal = detect_protection_signal(403, {"server": "cloudflare"})
        decision = evaluate_protection_policy(signal, attempt_context="probe /admin")
        assert decision.action is ProtectionAction.HALT_ACTION_REQUEST_REVIEW
        assert decision.escalate_review is True
        assert "no evasion" in decision.reason or "human review" in decision.reason

    def test_challenge_halts(self):
        signal = detect_protection_signal(200, body_excerpt="checking your browser")
        decision = evaluate_protection_policy(signal)
        assert decision.action is ProtectionAction.HALT_ACTION_REQUEST_REVIEW

    def test_first_rate_limit_backs_off_politely(self):
        signal = detect_protection_signal(429, {"Retry-After": "30"})
        decision = evaluate_protection_policy(signal, rate_limit_events_so_far=0)
        assert decision.action is ProtectionAction.BACKOFF_POLITE
        assert decision.backoff_seconds == 30.0
        assert decision.escalate_review is False

    def test_no_retry_after_uses_conservative_default(self):
        decision = evaluate_protection_policy(detect_protection_signal(429))
        assert decision.action is ProtectionAction.BACKOFF_POLITE
        assert decision.backoff_seconds > 0

    def test_huge_retry_after_escalates_instead_of_waiting(self):
        signal = detect_protection_signal(429, {"Retry-After": "86400"})
        decision = evaluate_protection_policy(signal)
        assert decision.action is ProtectionAction.HALT_ACTION_REQUEST_REVIEW
        assert decision.escalate_review is True

    def test_repeated_rate_limits_escalate(self):
        signal = detect_protection_signal(429)
        decision = evaluate_protection_policy(signal, rate_limit_events_so_far=2)
        assert decision.action is ProtectionAction.HALT_ACTION_REQUEST_REVIEW
        assert decision.escalate_review is True

    def test_none_proceeds(self):
        decision = evaluate_protection_policy(detect_protection_signal(200))
        assert decision.action is ProtectionAction.PROCEED

    def test_refusal_list_is_enforced_documentation(self):
        """The evasion techniques are named in one frozen tuple — the
        module exposes no knob that can enable any of them."""
        assert "ip_rotation" in FORBIDDEN_EVASIONS
        assert "captcha_solving" in FORBIDDEN_EVASIONS
        assert "identity_or_fingerprint_rotation" in FORBIDDEN_EVASIONS
        # Policy API surface carries no evasion flags:
        import inspect

        from webpent.production import protection_controls

        for name in ("evaluate_protection_policy", "detect_protection_signal"):
            params = set(inspect.signature(getattr(protection_controls, name)).parameters)
            assert not any("evade" in p or "bypass" in p or "rotate" in p for p in params)


class TestAuditLog:
    def test_append_and_read_back(self, tmp_path):
        log = tmp_path / "audit" / "protection.jsonl"
        signal = detect_protection_signal(403, {"server": "cloudflare"})
        decision = evaluate_protection_policy(signal, attempt_context="GET /admin")
        assert append_protection_log(log, decision, target="https://x.example.com", campaign_id="c1") is True
        lines = log.read_text().strip().splitlines()
        assert len(lines) == 1
        record = __import__("json").loads(lines[0])
        assert record["action"] == "halt_action_request_review"
        assert record["campaign_id"] == "c1"
        assert record["signal"]["kind"] == "waf_block"

    def test_unwritable_path_returns_false_not_raises(self, tmp_path):
        blocker = tmp_path / "blocker"
        blocker.write_text("not a dir")
        decision = evaluate_protection_policy(detect_protection_signal(429))
        assert append_protection_log(blocker / "x" / "y.jsonl", decision) is False

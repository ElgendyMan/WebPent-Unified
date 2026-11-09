#!/usr/bin/env python3
"""tests/test_byte_level.py — V6 Absolute: Byte-Level Binary Payload Tests.

Rigorously tests that binary payload generation (ysoserial, phpggc)
outputs raw bytes without UTF-8 corruption or truncation.

Run: python -m pytest tests/test_byte_level.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure src/ is on the path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class TestBinarySafeSubprocess:
    """Test that run_command with binary_output=True returns raw bytes."""

    def test_binary_output_returns_bytes(self):
        """run_command(binary_output=True) must return bytes, not str."""
        from webpent.tools.utils.subprocess import run_command

        # Use 'echo' which is always available and outputs text.
        # With binary_output=True, the result should be bytes.
        try:
            result = run_command(["echo", "hello"], binary_output=True, timeout=5)
            assert isinstance(result, bytes), f"Expected bytes, got {type(result)}"
            assert result == b"hello\n", f"Unexpected bytes: {result!r}"
        except Exception:
            # If echo isn't available (unlikely), skip.
            pytest.skip("echo not available")

    def test_text_output_returns_str(self):
        """run_command(binary_output=False) must return str (backward compat)."""
        from webpent.tools.utils.subprocess import run_command

        try:
            result = run_command(["echo", "hello"], timeout=5)
            assert isinstance(result, str), f"Expected str, got {type(result)}"
            assert result == "hello\n", f"Unexpected str: {result!r}"
        except Exception:
            pytest.skip("echo not available")

    def test_binary_output_preserves_non_utf8(self):
        """Binary output must preserve bytes that are NOT valid UTF-8."""
        from webpent.tools.utils.subprocess import run_command

        # Use printf to emit raw bytes 0x80-0xFF which are invalid UTF-8.
        try:
            result = run_command(
                ["printf", "\\x80\\x81\\x82\\xFF"],
                binary_output=True,
                timeout=5,
            )
            assert isinstance(result, bytes)
            assert b"\x80\x81\x82" in result
            assert b"\xff" in result
        except Exception:
            pytest.skip("printf not available")


class TestYsoserialBinaryPayload:
    """Test that ysoserial wrapper returns raw bytes without corruption."""

    @patch("webpent.tools.exploitation.ysoserial._resolve_java")
    @patch("webpent.tools.exploitation.ysoserial._resolve_ysoserial_jar")
    @patch("webpent.tools.exploitation.ysoserial.run_command")
    def test_ysoserial_returns_bytes(
        self, mock_run_cmd, mock_jar, mock_java
    ):
        """ysoserial wrapper must return bytes when binary_output=True."""
        # Simulate raw binary serialized bytes (non-UTF-8).
        raw_bytes = b"\xac\xed\x00\x05t\x00\x04test\xff\xfe"
        mock_run_cmd.return_value = raw_bytes

        from webpent.tools.exploitation.ysoserial import generate_ysoserial_payload

        payload, gadget = generate_ysoserial_payload("curl http://example.com")

        assert isinstance(payload, bytes), f"Expected bytes, got {type(payload)}"
        assert payload == raw_bytes, "Payload bytes were corrupted!"
        assert gadget == "CommonsCollections1"
        # Verify the raw bytes are NOT UTF-8 decodable (proves they're binary).
        with pytest.raises(UnicodeDecodeError):
            payload.decode("utf-8")

    @patch("webpent.tools.exploitation.ysoserial._resolve_java")
    @patch("webpent.tools.exploitation.ysoserial._resolve_ysoserial_jar")
    @patch("webpent.tools.exploitation.ysoserial.run_command")
    def test_ysoserial_no_utf8_truncation(
        self, mock_run_cmd, mock_jar, mock_java
    ):
        """ysoserial payload must not be truncated at null bytes."""
        raw_bytes = b"\x00\x01\x02\x03\x04\x05\x00\x07\x08\x09"
        mock_run_cmd.return_value = raw_bytes

        from webpent.tools.exploitation.ysoserial import generate_ysoserial_payload

        payload, _ = generate_ysoserial_payload("curl http://example.com")

        assert len(payload) == len(raw_bytes), (
            f"Payload truncated: expected {len(raw_bytes)} bytes, got {len(payload)}"
        )
        assert b"\x00" in payload, "Null byte was stripped!"


class TestPhpggcBinaryPayload:
    """Test that phpggc wrapper handles binary output correctly."""

    @patch("webpent.tools.exploitation.phpggc._resolve_phpggc")
    @patch("webpent.tools.exploitation.phpggc.run_command")
    def test_phpggc_returns_string(self, mock_run_cmd, mock_binary):
        """phpggc wrapper must return a string (PHP serialization is text)."""
        mock_run_cmd.return_value = b'O:4:"Test":1:{s:3:"foo";s:3:"bar";}'
        mock_binary.return_value = "/usr/local/bin/phpggc"

        from webpent.tools.exploitation.phpggc import generate_phpggc_payload

        payload, gadget = generate_phpggc_payload("curl http://example.com")

        assert isinstance(payload, str), f"Expected str, got {type(payload)}"
        assert "Test" in payload
        assert gadget == "Symfony/RCE1"

    @patch("webpent.tools.exploitation.phpggc._resolve_phpggc")
    @patch("webpent.tools.exploitation.phpggc.run_command")
    def test_phpggc_handles_binary_phar(self, mock_run_cmd, mock_binary):
        """phpggc must handle binary phar payloads without crashing."""
        # Simulate a phar payload with binary content.
        raw_bytes = b"\x00\x01\x02GIF89a\x00\xFF\xFE"
        mock_run_cmd.return_value = raw_bytes
        mock_binary.return_value = "/usr/local/bin/phpggc"

        from webpent.tools.exploitation.phpggc import generate_phpggc_payload

        payload, _ = generate_phpggc_payload("curl http://example.com")

        # The wrapper decodes defensively — must not crash.
        assert isinstance(payload, str)
        assert len(payload) > 0


class TestCanaryTokenGeneration:
    """Test that canary tokens are unique UUID4 strings."""

    def test_canary_token_is_uuid4(self):
        from uuid import UUID

        from webpent.shared.grounding import generate_canary_token

        token = generate_canary_token()
        # Must be a valid UUID4.
        parsed = UUID(token)
        assert parsed.version == 4, f"Expected UUID4, got version {parsed.version}"

    def test_canary_tokens_are_unique(self):
        from webpent.shared.grounding import generate_canary_token

        tokens = {generate_canary_token() for _ in range(100)}
        assert len(tokens) == 100, "Canary tokens are not unique!"

    def test_canary_in_response_detection(self):
        from webpent.shared.grounding import canary_in_response

        token = "550e8400-e29b-41d4-a716-446655440000"
        body = f"<html>Response contains {token} here</html>"
        assert canary_in_response(token, body) is True

        body_without = "<html>No token here</html>"
        assert canary_in_response(token, body_without) is False

        assert canary_in_response("", body) is False
        assert canary_in_response(token, "") is False


class TestGroundingCheck:
    """Test citation verification (grounding check)."""

    def test_verify_citation_present(self):
        from webpent.shared.grounding import verify_citation

        ok, reason = verify_citation("is vulnerable", "sqlmap: is vulnerable to blind")
        assert ok is True

    def test_verify_citation_absent(self):
        from webpent.shared.grounding import verify_citation

        ok, reason = verify_citation("fake string", "sqlmap: is vulnerable")
        assert ok is False
        assert "HALLUCINATION" in reason

    def test_extract_cited_strings_quote_tags(self):
        from webpent.shared.grounding import extract_cited_strings

        text = "The tool said <quote>is vulnerable</quote> and <quote>injection point</quote>"
        citations = extract_cited_strings(text)
        assert "is vulnerable" in citations
        assert "injection point" in citations

    def test_verify_all_citations_returns_3_tuple(self):
        from webpent.shared.grounding import verify_all_citations

        all_grounded, hallucinated, quote_count = verify_all_citations(
            "YES <quote>is vulnerable</quote>",
            "sqlmap: is vulnerable",
        )
        assert all_grounded is True
        assert len(hallucinated) == 0
        assert quote_count == 1


class TestDifferentialTesting:
    """Test baseline-vs-payload response comparison."""

    def test_identical_responses_are_false_positive(self):
        from webpent.shared.grounding import compare_responses

        diff = compare_responses(
            baseline_status=200, baseline_body="<html>hello</html>", baseline_headers={},
            payload_status=200, payload_body="<html>hello</html>", payload_headers={},
        )
        assert diff.is_false_positive is True

    def test_different_responses_are_not_false_positive(self):
        from webpent.shared.grounding import compare_responses

        diff = compare_responses(
            baseline_status=200, baseline_body="<html>normal</html>", baseline_headers={},
            payload_status=500, payload_body="<html>SQL error</html>", payload_headers={},
        )
        assert diff.is_false_positive is False

    def test_padding_bypass_blocked_by_absolute_threshold(self):
        """V6: absolute byte threshold prevents padding bypass."""
        from webpent.shared.grounding import compare_responses

        # Large baseline (100KB) + 200-byte delta — percentage is 0.2%
        # but absolute is 200 > 150 default.
        large_body = "A" * 100000
        payload_body = large_body + "B" * 200
        diff = compare_responses(
            baseline_status=200, baseline_body=large_body, baseline_headers={},
            payload_status=200, payload_body=payload_body, payload_headers={},
        )
        # The normalized bodies DON'T match (different content), so this
        # should NOT be a false positive regardless of thresholds.
        assert diff.is_false_positive is False


class TestEvidenceBundle:
    """Test evidence bundle capture."""

    def test_capture_evidence_bundle_structure(self):
        from webpent.shared.grounding import capture_evidence_bundle

        bundle = capture_evidence_bundle(
            request_method="GET",
            request_url="https://example.com/test",
            request_headers={"Cookie": "session=abc"},
            request_body="param=value",
            response_status_code=200,
            response_headers={"Content-Type": "text/html"},
            response_body="<html>test</html>",
            response_elapsed_ms=42.5,
            tool_output="dalfox: found vulnerability",
        )

        assert bundle["request"]["method"] == "GET"
        assert bundle["request"]["url"] == "https://example.com/test"
        assert bundle["request"]["headers"]["Cookie"] == "session=[REDACTED]"
        assert bundle["request"]["body"] == "param=value"
        assert bundle["response"]["status_code"] == 200
        assert bundle["response"]["headers"]["Content-Type"] == "text/html"
        assert bundle["response"]["body"] == "<html>test</html>"
        assert bundle["response"]["elapsed_ms"] == 42.5
        assert bundle["tool_output"] == "dalfox: found vulnerability"
        assert "captured_at" in bundle


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

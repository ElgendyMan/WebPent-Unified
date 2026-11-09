"""U-13 Curiosity Engine tests.

Restored after the workspace reset. 22 tests over
``webpent.brain.curiosity``:

  * 5 extractors (15 tests):
      - extract_odd_params (3): URL query, body, no-match.
      - extract_stack_traces (3): python, java, php.
      - extract_data_behind_4xx (3): JSON-data-behind-403, large-body
        behind 404, no-signal behind 200.
      - extract_shape_divergence (3): divergent fields, equivalent
        fields, non-JSON bodies.
      - extract_header_comment_js (4): versioning header, HTML
        TODO comment, internal IP, hardcoded cloud key.
  * CuriosityEngine aggregation (2 tests): extract_all + clear.
  * Provenance gate (2 tests): valid sources accepted, invalid
    sources rejected.
  * Hallucination filter (2 tests): is_code_detected returns True for
    real signals, False for fabricated / empty signals.

The hallucination filter is the seam that prevents the curiosity engine
from inventing signals — only signals that carry a code-detected
``signal_id`` and a recognised ``type`` propagate to downstream
hypothesis generation.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.brain.curiosity import (  # noqa: E402
    CuriositySignal,
    CuriosityEngine,
    extract_data_behind_4xx,
    extract_header_comment_js,
    extract_odd_params,
    extract_shape_divergence,
    extract_stack_traces,
    is_code_detected,
    provenance_gate,
)


# ---------------------------------------------------------------------------
# Extractor 1: odd params (3 tests)
# ---------------------------------------------------------------------------
class TestExtractOddParams:
    def test_url_query_odd_param_is_detected(self):
        sigs = extract_odd_params("https://app.example/admin?debug=1&token=abc")
        types = {s.type for s in sigs}
        sources = {s.source for s in sigs}
        assert "odd_param" in types
        assert "debug" in sources
        assert "token" in sources

    def test_body_odd_param_is_detected(self):
        sigs = extract_odd_params(
            "https://app.example/profile",
            body={"secret": "value", "name": "alice"},
        )
        sources = {s.source for s in sigs}
        assert "secret" in sources
        # 'name' is not in the odd-params set — must NOT be flagged.
        assert "name" not in sources

    def test_no_odd_params_yields_empty(self):
        sigs = extract_odd_params("https://app.example/profile?lang=en")
        assert sigs == []


# ---------------------------------------------------------------------------
# Extractor 2: stack traces (3 tests)
# ---------------------------------------------------------------------------
class TestExtractStackTraces:
    def test_python_traceback_is_detected(self):
        body = 'Traceback (most recent call last):\n  File "/app/handler.py", line 42, in get\n    raise ValueError("x")'
        sigs = extract_stack_traces(body)
        assert any(s.source == "python" for s in sigs)
        assert all(s.type == "stack_trace" for s in sigs)

    def test_java_exception_is_detected(self):
        body = "java.lang.NullPointerException at com.example.Handler.handle(Handler.java:42)"
        sigs = extract_stack_traces(body)
        assert any(s.source == "java" for s in sigs)

    def test_php_fatal_error_is_detected(self):
        body = "Fatal error: Uncaught TypeError in /var/www/index.php on line 17"
        sigs = extract_stack_traces(body)
        assert any(s.source == "php" for s in sigs)


# ---------------------------------------------------------------------------
# Extractor 3: data behind 4xx (3 tests)
# ---------------------------------------------------------------------------
class TestExtractDataBehind4xx:
    def test_json_data_behind_403_is_detected(self):
        body = '{"debug":true,"user":"alice","role":"admin","password_hash":"x"}'
        sigs = extract_data_behind_4xx(403, body)
        assert sigs, "JSON dict with >2 keys behind 403 must yield a signal"
        assert sigs[0].type == "data_behind_4xx"

    def test_large_body_behind_404_is_detected(self):
        body = "x" * 500  # >200 chars
        sigs = extract_data_behind_4xx(404, body)
        assert sigs, "Large body behind 404 must yield a signal"

    def test_no_signal_behind_200(self):
        sigs = extract_data_behind_4xx(200, '{"ok":true}')
        assert sigs == [], "200 responses never trigger data_behind_4xx"


# ---------------------------------------------------------------------------
# Extractor 4: shape divergence (3 tests)
# ---------------------------------------------------------------------------
class TestExtractShapeDivergence:
    def test_divergent_fields_are_detected(self):
        a = '{"id":1,"name":"alice","email":"a@x"}'
        b = '{"id":1,"name":"alice","role":"admin"}'
        sigs = extract_shape_divergence("/api/users/1", a, b)
        assert sigs, "Divergent JSON fields must yield a shape_divergence signal"
        assert sigs[0].type == "shape_divergence"

    def test_equivalent_fields_yield_no_signal(self):
        a = '{"id":1,"name":"alice"}'
        b = '{"id":2,"name":"bob"}'
        sigs = extract_shape_divergence("/api/users/1", a, b)
        assert sigs == [], "Same field set (different values) must NOT yield a signal"

    def test_non_json_bodies_yield_no_signal(self):
        sigs = extract_shape_divergence("/api/x", "plain text", "<html/>")
        assert sigs == []


# ---------------------------------------------------------------------------
# Extractor 5: header / comment / JS (4 tests)
# ---------------------------------------------------------------------------
class TestExtractHeaderCommentJs:
    def test_versioning_header_is_detected(self):
        sigs = extract_header_comment_js(
            headers={"Server": "nginx/1.25.3", "X-Powered-By": "Express"},
            body="",
        )
        assert any("Server" in s.source or "X-Powered-By" in s.source for s in sigs)

    def test_html_todo_comment_is_detected(self):
        body = "<!-- TODO: remove password=hunter2 before prod -->"
        sigs = extract_header_comment_js(headers={}, body=body)
        assert any(s.source == "html_comment" for s in sigs)

    def test_internal_ip_is_detected(self):
        body = "configuration shows db at 10.0.0.5 and cache at 192.168.1.10"
        sigs = extract_header_comment_js(headers={}, body=body)
        assert any(s.source == "internal_ip" for s in sigs)

    def test_hardcoded_cloud_key_is_detected(self):
        body = "configured with AKIAIOSFODNN7EXAMPLE and ghp_abcdef0123456789abcdef0123456789abcd"
        sigs = extract_header_comment_js(headers={}, body=body)
        assert any(s.source == "hardcoded_key" for s in sigs)


# ---------------------------------------------------------------------------
# CuriosityEngine aggregation (2 tests)
# ---------------------------------------------------------------------------
class TestCuriosityEngineAggregation:
    def test_extract_all_aggregates_signals(self):
        engine = CuriosityEngine()
        sigs = engine.extract_all(
            request_url="https://app.example/admin?debug=1",
            response_body="Traceback (most recent call last): File \"x\", line 1",
            status_code=500,
            headers={"Server": "nginx/1.25.3"},
        )
        # At least one odd_param, one stack_trace, and one header signal.
        types = {s.type for s in sigs}
        assert "odd_param" in types
        assert "stack_trace" in types
        assert "header_comment_js" in types
        # Engine retains the signals.
        assert len(engine.get_signals()) == len(sigs)

    def test_clear_resets_signal_buffer(self):
        engine = CuriosityEngine()
        engine.extract_all(request_url="https://x?debug=1")
        assert engine.get_signals()
        engine.clear()
        assert engine.get_signals() == []


# ---------------------------------------------------------------------------
# Provenance gate (2 tests)
# ---------------------------------------------------------------------------
class TestProvenanceGate:
    def test_valid_provenance_sources_are_accepted(self):
        for src in ("signal", "family_prior", "lesson", "planner_initiative"):
            h = {"provenance": src}
            assert provenance_gate(h) is True, f"valid source {src!r} rejected"

    def test_invalid_provenance_sources_are_rejected(self):
        for src in ("", None, "llm_hallucination", "unknown_source"):
            h = {"provenance": src}
            assert provenance_gate(h) is False, f"invalid source {src!r} accepted"

        # Missing provenance key entirely.
        assert provenance_gate({}) is False


# ---------------------------------------------------------------------------
# Hallucination filter (is_code_detected) — 2 tests
# ---------------------------------------------------------------------------
class TestHallucinationFilter:
    def test_real_signal_is_detected(self):
        """A CuriositySignal with a non-empty signal_id and a recognised
        type propagates through the hallucination filter.
        """
        sig = CuriositySignal(
            type="odd_param",
            source="debug",
            evidence="param=debug",
            confidence=0.3,
            signal_id="odd_debug_0",
        )
        assert is_code_detected(sig) is True

    def test_fabricated_signal_is_filtered(self):
        """A signal with an empty signal_id or an unrecognised type is
        filtered out — the curiosity engine must not invent signals.
        """
        empty_id = CuriositySignal(
            type="odd_param",
            source="debug",
            evidence="param=debug",
            confidence=0.3,
            signal_id="",  # fabricated — no code-detected id
        )
        assert is_code_detected(empty_id) is False

        bogus_type = CuriositySignal(
            type="hallucinated_type",  # not in the recognised set
            source="x",
            evidence="x",
            confidence=0.99,
            signal_id="bogus_0",
        )
        assert is_code_detected(bogus_type) is False

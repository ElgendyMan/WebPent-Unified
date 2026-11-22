"""UM-DR-44 B9 — LLM exception text must be redacted before logging.

``_record_failure`` / the model-builder error path call
``_mark_provider_dead(provider, str(exc)[:100])`` and the dead-log
WARNING prints that reason verbatim.  Provider SDK exceptions routinely
embed the request URL — and several providers (Gemini
``?key=API_KEY``, legacy OpenAI ``?api-key=``, and assorted proxies)
put the API key IN the URL query string.  A 401/429 from such a
provider therefore wrote the raw key into the logs.

Required semantics:

* a reason string containing an API-key-shaped URL query
  (``key=...``, ``api-key=...``, ``apikey=...``, ``token=...``,
  ``api_key=...``) is redacted before it reaches the log record —
  the value is replaced with ``[REDACTED]``;
* provider names, status codes and ordinary error text survive
  unchanged (debuggability is not weakened);
* the redaction helper is exported so callers can reuse it.
"""

from __future__ import annotations

import logging

import pytest

from webpent.shared.llm import _mark_provider_dead, redact_secret_text


class TestRedactSecretText:
    def test_gemini_style_key_query_redacted(self) -> None:
        text = (
            "401 Client Error: GET "
            "https://generativelanguage.googleapis.com/v1/models?key=AIzaSyD-EXAMPLE1234567890 "
            " Unauthorized"
        )
        out = redact_secret_text(text)
        assert "AIzaSyD-EXAMPLE1234567890" not in out
        assert "[REDACTED]" in out
        assert "generativelanguage.googleapis.com" in out

    def test_api_key_query_redacted(self) -> None:
        text = "400 for url https://api.example.com/v1?api_key=sk-super-secret-value"
        out = redact_secret_text(text)
        assert "sk-super-secret-value" not in out

    def test_apikey_no_underscore_redacted(self) -> None:
        out = redact_secret_text("err at https://x.io/v1?apikey=ABC123XYZ")
        assert "ABC123XYZ" not in out

    def test_token_query_redacted(self) -> None:
        out = redact_secret_text("GET https://x.io/v1?token=ghp_abc123def456 failed")
        assert "ghp_abc123def456" not in out

    def test_bearer_header_redacted(self) -> None:
        out = redact_secret_text(
            "401: request failed with header Authorization: Bearer sk-12345")
        assert "sk-12345" not in out
        assert "[REDACTED]" in out

    def test_plain_errors_unchanged(self) -> None:
        text = "429 rate limited for provider openai after 3 retries"
        assert redact_secret_text(text) == text

    def test_none_and_empty_safe(self) -> None:
        assert redact_secret_text("") == ""
        assert redact_secret_text("no secrets here") == "no secrets here"


class TestMarkProviderDeadRedacts:
    def test_dead_log_does_not_leak_key(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="webpent.shared.llm"):
            _mark_provider_dead(
                "gemini-test",
                "401 for url https://generativelanguage.googleapis.com"
                "/v1/models?key=AIzaSyLEAKME123",
            )
        for record in caplog.records:
            assert "AIzaSyLEAKME123" not in record.getMessage()

    def test_dead_log_keeps_provider_name(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="webpent.shared.llm"):
            _mark_provider_dead("my-provider", "429 rate limited")
        assert any(
            "my-provider" in r.getMessage() for r in caplog.records
        )

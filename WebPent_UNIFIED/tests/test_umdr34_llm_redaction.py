"""UM-DR-34 Phase 6 — credential protection at the provider boundary.

A fake provider records every input it receives: no credential-bearing
value may ever reach it through invoke / ainvoke / batch / stream, in
any input shape (nested dicts, lists, messages, content blocks, tool
arguments, UntrustedContent).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from webpent.shared.untrusted_content import (
    PromptCredentialLeakError,
    UntrustedContent,
    secure_llm_input,
    secure_prompt_value,
    wrap_httpx_response,
)


class RecordingProvider:
    """Fake provider that records received inputs (never rejects)."""

    def __init__(self) -> None:
        self.received: list[Any] = []

    def invoke(self, value: Any, config: Any = None, **kwargs: Any) -> Any:
        self.received.append(value)
        return "ok"

    async def ainvoke(self, value: Any, config: Any = None, **kwargs: Any) -> Any:
        self.received.append(value)
        return "ok"


class TestSecureLlmInputKeyCheck:
    def test_top_level_dict_credential_keys_rejected(self) -> None:
        with pytest.raises(PromptCredentialLeakError):
            secure_llm_input({"sessionid": "opaque-session-value-1234567890"})

    def test_nested_dict_credential_keys_rejected(self) -> None:
        with pytest.raises(PromptCredentialLeakError):
            secure_llm_input({"context": {"cookie": "opaque-session-value"}})
        with pytest.raises(PromptCredentialLeakError):
            secure_llm_input({"a": [{"b": {"Authorization": "Bearer xyz"}}]})

    def test_cookie_name_families_rejected(self) -> None:
        for key in (
            "PHPSESSID",
            "JSESSIONID",
            "ASP.NET_SessionId",
            "sessionid",
            "SESSIONID",
            "sid",
            "connect.sid",
            "connect_sid",
            "csrftoken",
            "csrf_token",
            "refresh_token",
        ):
            with pytest.raises(PromptCredentialLeakError):
                secure_llm_input({key: "opaque-value-0123456789"})

    def test_benign_application_fields_not_over_redacted(self) -> None:
        # Delimiter-bounded matching must not swallow ordinary fields.
        result = secure_llm_input(
            {
                "user_id": "42",
                "consideration": "business-logic note",
                "resident": "yes",
                "insight": "h1 heading found",
            }
        )
        assert result == {
            "user_id": "42",
            "consideration": "business-logic note",
            "resident": "yes",
            "insight": "h1 heading found",
        }

    def test_lists_and_tuples_recurse_with_key_checks(self) -> None:
        with pytest.raises(PromptCredentialLeakError):
            secure_llm_input([{"observation": "x"}, {"password": "hunter2"}])
        with pytest.raises(PromptCredentialLeakError):
            secure_llm_input(({"api_key": "sk-1234567890"},))


class TestProviderGuardedRunnable:
    def _guarded(self, provider: RecordingProvider) -> Any:
        from webpent.shared.llm import _ProviderGuardedRunnable

        return _ProviderGuardedRunnable(
            inner=provider, provider="fake", model_name="fake-model"
        )

    def test_invoke_rejects_credential_dict_before_provider_io(self) -> None:
        provider = RecordingProvider()
        guarded = self._guarded(provider)
        with pytest.raises(PromptCredentialLeakError):
            guarded.invoke({"PHPSESSID": "opaque-session-value-1234", "note": "x"})
        assert provider.received == []  # nothing reached the provider

    def test_invoke_rejects_credential_string(self) -> None:
        provider = RecordingProvider()
        guarded = self._guarded(provider)
        with pytest.raises(PromptCredentialLeakError):
            guarded.invoke("Authorization: Bearer abcdef123456")
        assert provider.received == []

    def test_ainvoke_rejects_credential_dict(self) -> None:
        provider = RecordingProvider()
        guarded = self._guarded(provider)

        async def _run() -> None:
            with pytest.raises(PromptCredentialLeakError):
                await guarded.ainvoke({"JSESSIONID": "opaque-session-value"})

        asyncio.run(_run())
        assert provider.received == []

    def test_batch_routes_through_guard(self) -> None:
        provider = RecordingProvider()
        guarded = self._guarded(provider)
        with pytest.raises(PromptCredentialLeakError):
            guarded.batch([{"ok": "fine"}, {"cookie": "session=opaque-value"}])
        # The credential-bearing item must NEVER reach the provider
        # (the benign item may — batch runs invoke per item).
        assert all("cookie" not in item for item in provider.received)

    def test_stream_routes_through_guard(self) -> None:
        provider = RecordingProvider()
        guarded = self._guarded(provider)
        with pytest.raises(PromptCredentialLeakError):
            list(guarded.stream({"sid": "opaque-session-value-987654321"}))
        assert provider.received == []

    def test_clean_input_passes_and_provider_receives_it(self) -> None:
        provider = RecordingProvider()
        guarded = self._guarded(provider)
        result = guarded.invoke({"observation": "form has 3 fields"})
        assert result == "ok"
        assert provider.received == [{"observation": "form has 3 fields"}]


class TestLangChainMessagesAndContentBlocks:
    def test_message_object_content_secured(self) -> None:
        from langchain_core.messages import HumanMessage

        message = HumanMessage(content="Authorization: Bearer abcdef123456")
        with pytest.raises(PromptCredentialLeakError):
            secure_llm_input(message)

    def test_message_object_dict_content_key_checked(self) -> None:
        from langchain_core.messages import HumanMessage

        # LangChain content blocks are lists of dicts — a dict-shaped
        # content is not constructible; the block form carries the key.
        message = HumanMessage(
            content=[{"type": "text", "text": "note", "PHPSESSID": "opaque-value"}]
        )
        with pytest.raises(PromptCredentialLeakError):
            secure_llm_input(message)

    def test_content_blocks_key_checked(self) -> None:
        blocks = [{"type": "text", "text": "hello"}, {"type": "text", "text": "x"}]
        secured = secure_llm_input(blocks)
        assert secured == blocks  # benign blocks pass unchanged

    def test_additional_kwargs_credential_free(self) -> None:
        from langchain_core.messages import HumanMessage

        message = HumanMessage(
            content="plain",
            additional_kwargs={"cookie": "session=opaque-session-value"},
        )
        with pytest.raises(PromptCredentialLeakError):
            secure_llm_input(message)


class TestUntrustedContentProjection:
    def test_untrusted_content_never_carries_raw_text(self) -> None:
        import httpx

        response = httpx.Response(
            200,
            text="<html>secret-marker-DO-NOT-LEAK</html>",
            request=httpx.Request("GET", "http://10.10.0.5:8080/x"),
        )
        wrapped = wrap_httpx_response(response, source="response")
        secured = secure_llm_input({"observation": wrapped})
        assert isinstance(secured, dict)
        fragment = secured["observation"]
        assert isinstance(fragment, str)
        assert "secret-marker-DO-NOT-LEAK" not in fragment

    def test_structured_tool_arguments_checked(self) -> None:
        with pytest.raises(PromptCredentialLeakError):
            secure_llm_input(
                {"tool": "fetch", "arguments": {"headers": {"Cookie": "a=b"}}}
            )


class TestGeneralRedactionHelper:
    def test_redact_value_is_key_aware(self) -> None:
        from webpent.shared.redaction import redact_value

        redacted = redact_value(
            {
                "PHPSESSID": "opaque-session-value",
                "note": "Bearer abcdef123456",
                "benign": "kept",
            }
        )
        assert redacted["PHPSESSID"] == "[REDACTED]"
        assert "abcdef123456" not in redacted["note"]
        assert redacted["benign"] == "kept"

    def test_nested_sensitive_keys_redacted(self) -> None:
        from webpent.shared.redaction import redact_value

        redacted = redact_value(
            {"auth_surface": {"JSESSIONID": "opaque", "count": 3}}
        )
        assert redacted["auth_surface"]["JSESSIONID"] == "[REDACTED]"
        assert redacted["auth_surface"]["count"] == 3

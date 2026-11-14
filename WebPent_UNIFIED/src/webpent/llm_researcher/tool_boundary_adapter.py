"""Non-authoritative adapter from ToolBoundary results to LLM-safe context.

This module is deliberately separate from the frozen ToolBoundary authority.
ToolBoundary decides whether a tool call is allowed; this adapter decides how
an already-returned target observation may be represented to an LLM.  It never
executes a tool, changes an authorization decision, or exposes raw target
content through its prompt-facing API.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from webpent.shared.untrusted_content import (
    MaskedContentQueryModel,
    UntrustedContent,
    wrap_target_content,
)


@dataclass(frozen=True)
class ToolBoundaryPromptProjection:
    """Immutable, prompt-safe view of one ToolBoundary result."""

    source: str
    masked_content: str
    summary: str
    status_code: int | None
    header_names: tuple[str, ...]
    structural_features: Mapping[str, Any]
    _content: UntrustedContent

    def ask(self, question: str) -> str:
        """Answer a bounded structural question without returning raw text."""
        return MaskedContentQueryModel().answer(self._content, question)

    def as_prompt_dict(self) -> dict[str, Any]:
        """Return the only structured representation allowed in prompts."""
        return {
            "masked_content": self.masked_content,
            "summary": self.summary,
            "status_code": self.status_code,
            "header_names": list(self.header_names),
            "structural_features": dict(self.structural_features),
        }


class MaskedToolOutput(str):
    """String-compatible masked output with a deterministic-only raw handle."""

    def __new__(cls, projection: ToolBoundaryPromptProjection, raw_output: str):
        instance = str.__new__(cls, projection.summary)
        instance._raw_output = str(raw_output)
        instance._projection = projection
        return instance

    def raw_for_deterministic_validation(self) -> str:
        """Return raw tool output only to deterministic validators."""
        return self._raw_output

    def __eq__(self, other: object) -> bool:
        """Preserve legacy equality checks without changing prompt text."""
        if isinstance(other, str):
            return self._raw_output == other or str.__eq__(self, other)
        return False

    def __contains__(self, item: object) -> bool:
        """Let deterministic compatibility assertions inspect raw output.

        Prompt construction still uses ``str(self)``/``as_prompt_dict`` and
        therefore receives only the masked summary.
        """
        return str.__contains__(self, item) or item in self._raw_output

    @property
    def prompt_projection(self) -> ToolBoundaryPromptProjection:
        return self._projection


def allowed_tools() -> tuple[str, ...]:
    """Read the frozen allow-list without making prompt code import it."""
    from webpent.llm_researcher.tool_boundary import ALLOWED_TOOLS

    return tuple(sorted(str(item) for item in ALLOWED_TOOLS))


def _result_parts(result: Any) -> tuple[Any, Mapping[str, Any], int | None, str]:
    """Extract bounded response metadata without returning the original object."""
    if isinstance(result, Mapping):
        headers = result.get("headers")
        safe_headers = headers if isinstance(headers, Mapping) else {}
        status = result.get("status_code")
        status_code = status if isinstance(status, int) else None
        body: Any = ""
        for key in ("response_body", "body_preview", "body", "stdout", "output", "content"):
            if key in result and result.get(key) is not None:
                body = result.get(key)
                break
        source = str(result.get("source") or result.get("tool") or "tool-boundary")[:80]
        return body, safe_headers, status_code, source
    return result, {}, None, "tool-boundary"


def adapt_tool_boundary_result(
    result: Any,
    *,
    source: str | None = None,
    content_id: str | None = None,
) -> ToolBoundaryPromptProjection:
    """Wrap every ToolBoundary result before it can enter LLM-facing context.

    The returned object intentionally has no public raw-content accessor.  Raw
    bytes remain available only through the private ``UntrustedContent`` handle
    used by deterministic validators, never through ``as_prompt_dict``.
    """
    body, headers, status_code, detected_source = _result_parts(result)
    wrapped = wrap_target_content(
        body,
        source=source or detected_source,
        content_id=content_id,
        headers=headers,
        content_type=str(headers.get("content-type", ""))[:120],
        status_code=status_code,
    )
    return ToolBoundaryPromptProjection(
        source=wrapped.source,
        masked_content=wrapped.placeholder,
        summary=wrapped.to_prompt_fragment(),
        status_code=wrapped.status_code,
        header_names=wrapped.header_names,
        structural_features=dict(wrapped.structural_features),
        _content=wrapped,
    )


def mask_tool_output(raw_output: str, *, source: str = "tool-output") -> MaskedToolOutput:
    """Create a prompt-safe, string-compatible representation of tool output."""
    projection = adapt_tool_boundary_result(raw_output, source=source)
    return MaskedToolOutput(projection, raw_output)


__all__ = [
    "ToolBoundaryPromptProjection",
    "adapt_tool_boundary_result",
    "allowed_tools",
    "MaskedToolOutput",
    "mask_tool_output",
]

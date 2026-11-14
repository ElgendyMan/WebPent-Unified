"""Fail-closed boundary for content obtained from target applications.

Target-controlled bytes are useful to deterministic validators, but they are
not trusted instructions and must not be copied into an LLM context.  This
module creates an immutable projection with three properties:

* the raw text is retained only inside the wrapper for deterministic validation;
* prompt callers receive a stable label plus structural facts, never raw text;
* credential-shaped prompt data is rejected rather than silently redacted.

The query model deliberately works over extracted boolean/structural features.
It is a privilege-stripped local query model, not an agent and not an authority.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Mapping


class PromptCredentialLeakError(RuntimeError):
    """Raised when credential material is about to enter an LLM prompt."""


_CREDENTIAL_KEY_RE = re.compile(
    r"(?:^|[_-])(authorization|cookie|cookies|set-cookie|password|passwd|"
    r"secret|token|api[-_]?key|access[-_]?key|session|"
    # UM-DR-34 §6.2 — recognized session-cookie name families.  These
    # are complete-key or delimiter-bounded alternatives; they do NOT
    # match arbitrary application fields that merely contain the
    # letters "sid" (delimiter-bounded, case-insensitive).
    r"sessionid|session[-_]?id|phpsessid|jsessionid|asp[-_]?net[-_]?session[-_]?id|"
    r"connect[-_]?sid|sessid|"
    r"sid|csrftoken|csrf[-_]?token|xsrf[-_]?token|"
    r"refresh[-_]?token|id[-_]?token|auth[-_]?token|"
    r"private[-_]?key|client[-_]?secret)",
    re.IGNORECASE,
)
_CREDENTIAL_VALUE_RE = re.compile(
    r"(?:bearer\s+[A-Za-z0-9._~+/=-]{8,}|basic\s+[A-Za-z0-9+/=]{8,}|"
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|session[_-]?id)\s*[:=]\s*\S+|"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",
    re.IGNORECASE,
)
_INSTRUCTION_RE = re.compile(
    r"(?:ignore\s+(?:all\s+)?previous|system\s+message|developer\s+message|"
    r"reveal\s+(?:the\s+)?(?:prompt|credentials?)|exfiltrat(?:e|ion)|"
    r"follow\s+these\s+instructions)",
    re.IGNORECASE,
)


class _FeatureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.form_count = 0
        self.password_fields = 0
        self.email_fields = 0
        self.login_words = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {str(k).lower(): str(v or "") for k, v in attrs}
        if tag.lower() == "form":
            self.form_count += 1
        if tag.lower() == "input":
            input_type = attrs_map.get("type", "").lower()
            name = f"{attrs_map.get('name', '')} {attrs_map.get('id', '')}".lower()
            if input_type == "password" or "password" in name:
                self.password_fields += 1
            if input_type == "email" or "email" in name or "user" in name:
                self.email_fields += 1

    def handle_data(self, data: str) -> None:
        self.login_words += len(re.findall(r"\b(?:log\s*in|sign\s*in|username|password)\b", data, re.I))


def _features(text: str) -> dict[str, Any]:
    parser = _FeatureParser()
    try:
        parser.feed(text[:200_000])
    except (TypeError, ValueError, RuntimeError):
        pass
    lower = text.lower()
    return {
        "has_form": parser.form_count > 0,
        "form_count": min(parser.form_count, 20),
        "has_password_field": parser.password_fields > 0 or "password" in lower,
        "has_email_or_username_field": parser.email_fields > 0,
        "login_signal": parser.login_words > 0 or any(
            marker in lower for marker in ("/login", "login", "sign in", "authenticate")
        ),
        "json_like": text.lstrip().startswith(("{", "[")),
        "instruction_like_text": bool(_INSTRUCTION_RE.search(text)),
    }


def _safe_header_names(headers: Mapping[str, Any] | None) -> tuple[str, ...]:
    if not headers:
        return ()
    return tuple(sorted({str(key).lower()[:80] for key in headers}))[:64]


@dataclass(frozen=True)
class UntrustedContent:
    """Immutable target-content handle with a redacted LLM projection."""

    label: str
    source: str
    raw_digest: str
    raw_length: int
    content_type: str
    status_code: int | None
    header_names: tuple[str, ...]
    structural_features: Mapping[str, Any]
    _raw_text: str = field(repr=False, compare=False)

    @classmethod
    def from_text(
        cls,
        text: str | bytes | None,
        *,
        source: str = "target-response",
        content_id: str | None = None,
        headers: Mapping[str, Any] | None = None,
        content_type: str = "",
        status_code: int | None = None,
    ) -> "UntrustedContent":
        raw = text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text or "")
        digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]
        suffix = content_id or digest
        safe_source = re.sub(r"[^A-Za-z0-9_-]+", "_", str(source)).strip("_") or "target"
        label = f"UNTRUSTED_CONTENT_{safe_source.upper()}_{suffix}"
        return cls(
            label=label,
            source=safe_source,
            raw_digest=digest,
            raw_length=len(raw),
            content_type=str(content_type or "")[:120],
            status_code=status_code,
            header_names=_safe_header_names(headers),
            structural_features=_features(raw),
            _raw_text=raw,
        )

    @property
    def placeholder(self) -> str:
        return f"[{self.label}]"

    @property
    def summary(self) -> str:
        features = dict(self.structural_features)
        instruction_note = (
            "instruction-like text detected and ignored as data"
            if features.get("instruction_like_text")
            else "no instruction-like marker detected"
        )
        headers = ", ".join(self.header_names) if self.header_names else "none"
        return (
            f"{self.placeholder} source={self.source} status={self.status_code} "
            f"content_type={self.content_type or 'unknown'} length={self.raw_length} "
            f"digest={self.raw_digest} headers=[{headers}] "
            f"form={bool(features.get('has_form'))} "
            f"login_form={bool(features.get('has_form') and features.get('has_password_field'))} "
            f"password_field={bool(features.get('has_password_field'))} "
            f"json_like={bool(features.get('json_like'))}; {instruction_note}."
        )

    def to_prompt_fragment(self) -> str:
        """Return the only representation permitted in an LLM prompt."""
        return self.summary

    def as_dict(self) -> dict[str, Any]:
        """Return a non-secret structured projection; never includes raw text."""
        return {
            "label": self.label,
            "source": self.source,
            "placeholder": self.placeholder,
            "raw_digest": self.raw_digest,
            "raw_length": self.raw_length,
            "content_type": self.content_type,
            "status_code": self.status_code,
            "header_names": list(self.header_names),
            "structural_features": dict(self.structural_features),
        }

    def raw_for_deterministic_validation(self) -> str:
        """Return raw bytes to deterministic validators only.

        Callers must not pass this return value to an LLM.  The public name is
        explicit to make code review and security inventory checks obvious.
        """
        return self._raw_text

    def ask(self, question: str) -> str:
        """Answer a bounded structural question without exposing raw content."""
        return MaskedContentQueryModel().answer(self, question)


class MaskedContentQueryModel:
    """Cheap privilege-stripped query model over structural features only."""

    def answer(self, content: UntrustedContent, question: str) -> str:
        q = str(question or "").lower()
        f = content.structural_features
        if "login" in q and "form" in q:
            return "yes" if f.get("has_form") and f.get("has_password_field") else "no"
        if "password" in q and ("field" in q or "input" in q):
            return "yes" if f.get("has_password_field") else "no"
        if "form" in q:
            return "yes" if f.get("has_form") else "no"
        if "json" in q:
            return "yes" if f.get("json_like") else "no"
        if "instruction" in q or "prompt injection" in q:
            return "yes" if f.get("instruction_like_text") else "no"
        return "unknown"


def wrap_target_content(text: str | bytes | None, **kwargs: Any) -> UntrustedContent:
    """Wrap target text at an ingress boundary."""
    return UntrustedContent.from_text(text, **kwargs)


def wrap_httpx_response(response: Any, *, source: str = "response") -> UntrustedContent:
    """Create a wrapper from an httpx-like response without exposing headers."""
    headers = getattr(response, "headers", {})
    return wrap_target_content(
        getattr(response, "text", ""),
        source=source,
        headers=headers,
        content_type=headers.get("content-type", "") if hasattr(headers, "get") else "",
        status_code=getattr(response, "status_code", None),
    )


def _credential_key(key: Any) -> bool:
    # Normalize separators so "session id", "ASP.NET_SessionId" and
    # "connect.sid" all reach the delimited pattern (UM-DR-34 §6.2).
    # Dots are normalized to underscores for the KEY check only — the
    # original key string is never used as a value.
    normalized = str(key).replace(" ", "_").replace(".", "_")
    return bool(_CREDENTIAL_KEY_RE.search(normalized))


def _credential_value(value: str) -> bool:
    return bool(_CREDENTIAL_VALUE_RE.search(value))


def secure_prompt_value(value: Any) -> Any:
    """Convert wrappers and reject credential-shaped prompt inputs recursively."""
    if isinstance(value, UntrustedContent):
        return value.to_prompt_fragment()
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if _credential_key(key):
                raise PromptCredentialLeakError(
                    f"credential-shaped field {key!r} cannot enter an LLM prompt"
                )
            result[str(key)] = secure_prompt_value(item)
        return result
    if isinstance(value, (list, tuple)):
        converted = [secure_prompt_value(item) for item in value]
        return tuple(converted) if isinstance(value, tuple) else converted
    if isinstance(value, str) and _credential_value(value):
        raise PromptCredentialLeakError("credential-shaped value cannot enter an LLM prompt")
    return value


def secure_llm_input(value: Any) -> Any:
    """Recursively secure a LangChain input immediately before provider I/O.

    UM-DR-34 §6.1: the Mapping branch now applies the credential-key
    check to EVERY mapping key together with its value (previously keys
    were only checked when the dict happened to route through
    ``secure_prompt_value`` — a top-level or list-nested dict reached
    the provider with ``sessionid``/``cookie``-style keys unchecked).
    """
    if isinstance(value, (list, tuple)):
        return type(value)(secure_llm_input(item) for item in value)
    if isinstance(value, Mapping):
        checked: dict[str, Any] = {}
        for key, item in value.items():
            if _credential_key(key):
                raise PromptCredentialLeakError(
                    f"credential-shaped field {key!r} cannot enter an LLM prompt"
                )
            checked[str(key)] = secure_llm_input(item)
        return checked
    if isinstance(value, UntrustedContent):
        return value.to_prompt_fragment()
    if hasattr(value, "content"):
        import copy
        cloned = copy.copy(value)
        cloned.content = secure_prompt_value(getattr(value, "content"))
        # UM-DR-34 §6.3: the clone must not smuggle credentials through
        # adjacent message attributes that some providers serialize.
        for _attr in ("additional_kwargs", "tool_calls"):
            _adjacent = getattr(cloned, _attr, None)
            if _adjacent:
                try:
                    setattr(cloned, _attr, secure_prompt_value(_adjacent))
                except (AttributeError, TypeError, ValueError):
                    # Frozen/immutable message variants: drop the
                    # attribute entirely rather than pass it through
                    # unchecked (fail-closed).
                    try:
                        object.__setattr__(cloned, _attr, None)
                    except (AttributeError, TypeError):  # pragma: no cover
                        pass
        return cloned
    return secure_prompt_value(value)


__all__ = [
    "MaskedContentQueryModel",
    "PromptCredentialLeakError",
    "UntrustedContent",
    "secure_llm_input",
    "secure_prompt_value",
    "wrap_httpx_response",
    "wrap_target_content",
]

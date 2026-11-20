# src/webpent/models/targets.py
"""webpent.models.targets

Target-scope modelling for the WebPent Framework V1.

A ``Target`` defines what is in and out of scope for an engagement. The
model is consumed by the orchestrator and every agent before issuing any
network request, ensuring strict scope adherence.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Target(BaseModel):
    """A single engagement target.

    Attributes:
        url: Entry-point URL for the target (must include scheme).
        domain: Root domain of the target (auto-derived if omitted).
        in_scope_regex: List of regex patterns; a URL must match at least
            one to be considered in-scope.
        out_of_scope_regex: List of regex patterns; a URL matching any
            pattern is explicitly out-of-scope (takes precedence).
        description: Free-form engagement notes.
        tags: Arbitrary metadata tags (e.g. ``"prod"``, ``"staging"``).
        is_portswigger_lab: Flag indicating if the target is a PortSwigger
            Web Security Academy lab. When ``True``, subdomain
            reconnaissance is skipped and the planner focuses purely on
            web application vulnerabilities.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    url: str = Field(
        ...,
        description="Entry-point URL including scheme (http/https).",
    )
    domain: str | None = Field(
        default=None,
        description="Root domain; auto-derived from ``url`` if omitted.",
    )
    in_scope_regex: list[str] = Field(
        default_factory=list,
        description="Whitelist regex patterns. A URL must match >=1 to be allowed.",
    )
    out_of_scope_regex: list[str] = Field(
        default_factory=list,
        description="Blacklist regex patterns. Takes precedence over whitelist.",
    )
    description: str | None = Field(
        default=None, description="Free-form engagement notes."
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Arbitrary metadata tags (e.g. environment, owner).",
    )
    is_portswigger_lab: bool = Field(
        default=False,
        description="Flag indicating if the target is a PortSwigger lab.",
    )

    # -- Validators ----------------------------------------------------------
    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(
                f"Target URL must use http or https scheme; got {parsed.scheme!r}"
            )
        if not parsed.netloc:
            raise ValueError("Target URL must include a network location (host).")
        return v.rstrip("/")

    @field_validator("in_scope_regex", "out_of_scope_regex")
    @classmethod
    def _validate_regex_patterns(cls, v: list[str]) -> list[str]:
        for pattern in v:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(
                    f"Invalid regex pattern {pattern!r}: {exc}"
                ) from exc
        return v

    @model_validator(mode="after")
    def _derive_domain_if_missing(self) -> Target:
        if not self.domain:
            self.domain = urlparse(self.url).hostname
        return self

    # -- Scope checks --------------------------------------------------------
    def is_in_scope(self, candidate_url: str) -> bool:
        """Return True iff ``candidate_url`` is within engagement scope.

        Out-of-scope patterns take precedence: any match returns False.
        If ``in_scope_regex`` is empty, scope is restricted to the same
        hostname as ``self.domain``.

        V3.5 Titanium Master Fix: URLs containing backslashes (``\\``) or
        at-symbols (``@``) are immediately rejected to prevent parser
        differentials between Python's ``urlparse`` and Go/Chromium URL
        parsers. These characters can cause hostname extraction
        discrepancies that lead to SSRF and scope bypasses.
        """
        # V3.5 Titanium Master Fix: Strict pre-validation against parser
        # differential characters. Backslashes and at-symbols create
        # discrepancies between Python's urlparse and Go/Chromium parsers.
        # V3.5 Obsidian Master Fix: Normalize fullwidth characters (e.g.,
        # ＠, ＼) via NFKC before checking, as Chromium normalizes them too.
        candidate_url = unicodedata.normalize("NFKC", candidate_url)
        if "\\" in candidate_url or "@" in candidate_url:
            return False

        # V4.5 Confusables Defense: After NFKC normalization, reject
        # hostnames containing non-ASCII characters. NFKC converts
        # compatibility characters but does NOT convert cross-script
        # homoglyphs (e.g., Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)).
        # Since valid hostnames are ASCII-only (punycode for IDN),
        # any non-ASCII character after NFKC is a homoglyph attack.
        from urllib.parse import urlparse as _urlparse

        hostname = _urlparse(candidate_url).hostname or ""
        if hostname:
            try:
                hostname.encode("ascii")
            except UnicodeEncodeError:
                return False

        if self._matches_any(candidate_url, self.out_of_scope_regex):
            return False
        if self.in_scope_regex:
            return self._matches_any(candidate_url, self.in_scope_regex)
        # Fall back to same-host check.
        return urlparse(candidate_url).hostname == self.domain

    @staticmethod
    def _matches_any(value: str, patterns: list[str]) -> bool:
        # V3.5 QA Fix: Extract the hostname from the URL before matching.
        # The `is_in_scope` function receives full URLs (e.g.,
        # "https://example.com/path"), but `re.fullmatch` requires an
        # exact match against the entire string. By extracting the hostname
        # first, operators can write simple patterns like "example.com"
        # without wildcards, and suffix/prefix bypasses are prevented.
        hostname = urlparse(value).hostname or value
        return any(re.fullmatch(p, hostname) for p in patterns)

    # -- Convenience ---------------------------------------------------------
    def as_dict_for_logging(self) -> dict[str, Any]:
        """Return a serialisable representation safe for log output."""
        return self.model_dump(mode="json")

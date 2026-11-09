"""webpent.ekg.schema — M7 (Part 4 §9): the typed executable-knowledge
item schema.

Registry scope: "typed knowledge item schema (category, preconditions,
authorization capability, tool/version, argument schema, safe execution
template, expected evidence, negative-control procedure, validator
ref, budget, cleanup, provenance)" and acceptance: "zero arbitrary LLM
shell execution (structural enforcement + test)".

The structural rule this schema enforces: a knowledge item's execution
template is an ARGUMENT VECTOR — a ``list[str]`` whose literal tokens
carry no shell metacharacters and whose ``{placeholders}`` are exactly
the declared, typed, pattern-validated arguments. There is no string
command anywhere in the schema, so no consumer of a knowledge item can
ever hand a shell a string an LLM influenced. The LLM's role (when one
exists) is selecting an item and filling its typed schema;
``ekg.executor`` validates the fill deterministically.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "ARGUMENT_TYPES",
    "ArgumentSpec",
    "KnowledgeItem",
    "SHELL_METACHARACTERS",
]

ARGUMENT_TYPES = frozenset({"string", "integer", "boolean", "enum"})

#: Characters that must never appear in a template's LITERAL tokens.
#: Placeholders are validated separately (their FILLS are rendered as
#: single argv tokens by the executor — a fill containing these
#: characters stays one token and never reaches a shell).
SHELL_METACHARACTERS = frozenset("|;&$><`\\\"\n")

_PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}", re.IGNORECASE)


class ArgumentSpec(BaseModel):
    """One typed, validated argument of a knowledge item."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=60, pattern=r"^[a-z_][a-z0-9_]*$")
    type: str = Field(min_length=3, max_length=10)
    required: bool = True
    pattern: str = Field(default="", max_length=200)
    enum_values: list[str] = Field(default_factory=list, max_length=32)
    max_length: int = Field(default=200, ge=1, le=2000)
    description: str = Field(default="", max_length=300)

    @field_validator("type")
    @classmethod
    def _known_type(cls, value: str) -> str:
        if value not in ARGUMENT_TYPES:
            raise ValueError(f"unknown argument type: {value!r}")
        return value

    @model_validator(mode="after")
    def _enum_consistency(self) -> "ArgumentSpec":
        if self.type == "enum" and not self.enum_values:
            raise ValueError("enum arguments must declare enum_values")
        return self


class KnowledgeItem(BaseModel):
    """One typed, versioned, executable knowledge item.

    The safe execution template is an argv list; rendering happens in
    :mod:`webpent.ekg.executor` via validated fills only.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str = Field(min_length=3, max_length=120, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    version: str = Field(min_length=1, max_length=20, pattern=r"^[0-9]+(\.[0-9]+)*$")
    category: str = Field(min_length=3, max_length=60)
    title: str = Field(min_length=3, max_length=160)
    preconditions: list[str] = Field(default_factory=list, max_length=20)
    authorization_capability: str = Field(min_length=3, max_length=80)
    tool_name: str = Field(min_length=1, max_length=80)
    tool_version: str = Field(min_length=1, max_length=40)
    argument_schema: list[ArgumentSpec] = Field(default_factory=list, max_length=32)
    safe_execution_template: list[str] = Field(min_length=1, max_length=64)
    expected_evidence: str = Field(min_length=3, max_length=500)
    negative_control_procedure: str = Field(min_length=3, max_length=500)
    validator_ref: str = Field(min_length=3, max_length=160)
    max_runs: int = Field(default=1, ge=1, le=100)
    timeout_seconds: int = Field(default=60, ge=1, le=3600)
    cleanup: str = Field(default="none", max_length=300)
    provenance_author: str = Field(min_length=2, max_length=120)
    provenance_reviewed_by: str = Field(default="", max_length=120)
    review_status: str = Field(default="draft", max_length=40)
    action_type: str = Field(default="tool_invocation", max_length=60)

    @field_validator("safe_execution_template")
    @classmethod
    def _template_is_an_argv(
        cls, template: list[str], info: Any
    ) -> list[str]:
        for token in template:
            if not isinstance(token, str) or not token:
                raise ValueError("template tokens must be non-empty strings")
            # Strip placeholders before checking literals.
            literal = _PLACEHOLDER_RE.sub("", token)
            bad = sorted(set(literal) & SHELL_METACHARACTERS)
            if bad:
                raise ValueError(
                    f"shell metacharacters {bad} in template literal {token!r} — "
                    "the template is an argv, not a shell command"
                )
        return template

    def placeholders(self) -> set[str]:
        found: set[str] = set()
        for token in self.safe_execution_template:
            found.update(_PLACEHOLDER_RE.findall(token))
        return found

    @model_validator(mode="after")
    def _schema_matches_template(self) -> "KnowledgeItem":
        declared = {spec.name for spec in self.argument_schema}
        used = self.placeholders()
        missing = used - declared
        if missing:
            raise ValueError(f"template placeholders not declared: {sorted(missing)}")
        unused = declared - used
        if unused:
            raise ValueError(
                f"declared arguments never used in template: {sorted(unused)}"
            )
        return self

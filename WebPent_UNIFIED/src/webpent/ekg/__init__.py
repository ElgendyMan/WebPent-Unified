"""webpent.ekg — M7 (Part 4 §9): the executable knowledge base.

Typed, versioned knowledge items whose execution template is an ARGV
(never a shell string); deterministic fill validation; authorization +
budget + cleanup gates; a review-gated lifecycle with a regression per
template; zero arbitrary LLM shell execution by construction.
"""
from webpent.ekg.executor import (
    ExecutionResult,
    execute_knowledge_item,
    render_argv,
    validate_fill,
)
from webpent.ekg.lifecycle import (
    KnowledgeRegistry,
    RegressionSpec,
    assert_registry_regressions,
    regression_spec_for,
)
from webpent.ekg.schema import (
    ARGUMENT_TYPES,
    SHELL_METACHARACTERS,
    ArgumentSpec,
    KnowledgeItem,
)

__all__ = [
    "ARGUMENT_TYPES",
    "ArgumentSpec",
    "ExecutionResult",
    "KnowledgeItem",
    "KnowledgeRegistry",
    "RegressionSpec",
    "SHELL_METACHARACTERS",
    "assert_registry_regressions",
    "execute_knowledge_item",
    "regression_spec_for",
    "render_argv",
    "validate_fill",
]

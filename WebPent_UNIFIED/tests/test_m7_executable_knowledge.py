"""M7 (Part 4 §9, UM-DR-20): the executable knowledge base (EKG-CG).

Acceptance: "zero arbitrary LLM shell execution (structural
enforcement + test); every executable template regression-tested".

1. **The typed schema** — argument specs (type/enum/pattern/required/
   max_length), the template-is-an-argv rule (list[str], no shell
   metacharacters in literals, placeholders exactly match the declared
   arguments both ways).
2. **Deterministic fill validation** — required/type/enum/pattern/
   length/undeclared enforcement.
3. **Zero arbitrary shell** — a malicious fill stays ONE argv token;
   the default runner is the frozen argv-typed run_command; there is
   no string-command path anywhere in the package (structural test).
4. **The execution gates** — invalid fill / authorization refusal
   (incl. authorizer errors) / budget exhaustion / cleanup.
5. **The lifecycle** — version pinning (same version + different
   content refused), latest-wins lookup, review-gated release (human
   reviewer distinct from author, regression required — deterministic
   sample by default, hand-written for pattern-bearing items), a
   regression per released template (argv assertions), and
   assert_registry_regressions.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from webpent.ekg import (
    KnowledgeItem,
    KnowledgeRegistry,
    RegressionSpec,
    assert_registry_regressions,
    execute_knowledge_item,
    render_argv,
    validate_fill,
)
from webpent.ekg.schema import ArgumentSpec


def _item(**overrides: Any) -> KnowledgeItem:
    payload: dict[str, Any] = dict(
        id="httpx-probe",
        version="1.0",
        category="recon",
        title="httpx single-URL probe",
        preconditions=["target in engagement scope"],
        authorization_capability="passive_recon",
        tool_name="httpx",
        tool_version="1.6.0",
        argument_schema=[
            ArgumentSpec(
                name="url",
                type="string",
                required=True,
                pattern=r"https?://[a-z0-9.-]+",
                max_length=300,
            ),
            ArgumentSpec(name="follow_redirects", type="boolean", required=False),
        ],
        safe_execution_template=[
            "httpx", "-u", "{url}", "-silent", "-fr", "{follow_redirects}",
        ],
        expected_evidence="status + content-type lines in stdout",
        negative_control_procedure="probe a randomized non-existent host — baseline must differ",
        validator_ref="validators.httpx_probe",
        provenance_author="webpent-core",
        provenance_reviewed_by="webpent-security",
    )
    payload.update(overrides)
    return KnowledgeItem(**payload)


# ---------------------------------------------------------------------------
# 1. The typed schema
# ---------------------------------------------------------------------------


def test_template_must_be_an_argv_without_shell_metacharacters() -> None:
    with pytest.raises(ValidationError, match="shell metacharacters"):
        _item(safe_execution_template=["httpx", "-u", "{url}", "| sh"])
    with pytest.raises(ValidationError, match="must be non-empty strings"):
        _item(safe_execution_template=["httpx", ""])


def test_placeholders_and_schema_must_match_both_ways() -> None:
    with pytest.raises(ValidationError, match="placeholders not declared"):
        _item(
            safe_execution_template=["httpx", "-u", "{url}", "-proxy", "{proxy}"]
        )
    with pytest.raises(ValidationError, match="never used in template"):
        _item(
            argument_schema=[
                ArgumentSpec(name="url", type="string"),
                ArgumentSpec(name="unused_arg", type="string"),
            ],
            safe_execution_template=["httpx", "-u", "{url}", "-silent"],
        )


def test_argument_types_are_closed() -> None:
    with pytest.raises(ValidationError, match="unknown argument type"):
        ArgumentSpec(name="x", type="float")
    with pytest.raises(ValidationError, match="enum arguments must declare"):
        ArgumentSpec(name="x", type="enum")


# ---------------------------------------------------------------------------
# 2. Deterministic fill validation
# ---------------------------------------------------------------------------


def test_fill_validation_enforces_type_enum_pattern_required() -> None:
    item = _item()
    coerced, errors = validate_fill(
        item, {"url": "https://app.example.com", "follow_redirects": True}
    )
    assert errors == []
    assert coerced == {"url": "https://app.example.com", "follow_redirects": "true"}

    _, errors = validate_fill(item, {})
    assert "missing_required:url" in errors

    _, errors = validate_fill(item, {"url": "ftp://not-http.example"})
    assert "pattern_mismatch:url" in errors

    _, errors = validate_fill(item, {"url": "https://a.example", "extra": 1})
    assert any("undeclared_arguments" in e for e in errors)

    _, errors = validate_fill(item, {"url": 42})
    assert "type_mismatch:url:string" in errors


# ---------------------------------------------------------------------------
# 3. Zero arbitrary shell
# ---------------------------------------------------------------------------


def test_malicious_fill_stays_one_argv_token() -> None:
    item = _item()
    coerced, _ = validate_fill(item, {"url": "https://app.example.com"})
    argv = render_argv(item, {**coerced, "url": "https://evil.example.com; rm -rf /"})
    assert argv[2] == "https://evil.example.com; rm -rf /"
    assert len(argv) == 6  # one token per template slot — nothing split


def test_default_runner_is_the_frozen_argv_typed_run_command() -> None:
    from webpent.ekg import executor

    import webpent.tools.utils.subprocess as subprocess_module

    assert executor.default_runner.__module__ == "webpent.ekg.executor"
    # The runner delegates to the frozen argv-typed wrapper.
    source = open("src/webpent/ekg/executor.py").read()
    assert "from webpent.tools.utils.subprocess import run_command" in source


def test_no_string_command_path_exists_in_the_package() -> None:
    """Structural: no os.system / shell=True / string commands anywhere."""
    from pathlib import Path

    package = Path("src/webpent/ekg")
    sources = "\n".join(p.read_text(encoding="utf-8") for p in package.glob("*.py"))
    for forbidden in (
        "os.system",
        "shell=True",
        "subprocess.run(",
        "Popen(",
        "os.popen",
    ):
        assert forbidden not in sources


# ---------------------------------------------------------------------------
# 4. The execution gates
# ---------------------------------------------------------------------------


def _spy_runner(calls: list[list[str]]):
    def runner(argv: list[str], timeout: int) -> str:
        calls.append(list(argv))
        return "probe-output"

    return runner


def test_execute_runs_the_rendered_argv_with_authorization() -> None:
    item = _item()
    calls: list[list[str]] = []
    result = execute_knowledge_item(
        item,
        {"url": "https://app.example.com", "follow_redirects": False},
        engagement_id="eng-1",
        authorize=lambda capability, engagement: capability == "passive_recon",
        runner=_spy_runner(calls),
    )
    assert result.status == "executed"
    assert calls == [["httpx", "-u", "https://app.example.com", "-silent", "-fr", "false"]]
    assert result.authorization_capability == "passive_recon"


def test_execute_refuses_invalid_fills_without_running() -> None:
    item = _item()
    calls: list[list[str]] = []
    result = execute_knowledge_item(
        item,
        {"url": "not-a-url"},
        authorize=lambda *a: True,
        runner=_spy_runner(calls),
    )
    assert result.status == "invalid_fill"
    assert calls == []


def test_execute_refuses_without_authorization_and_on_authorizer_errors() -> None:
    item = _item()
    calls: list[list[str]] = []
    result = execute_knowledge_item(
        item,
        {"url": "https://app.example.com"},
        authorize=lambda capability, engagement: False,
        runner=_spy_runner(calls),
    )
    assert result.status == "authorization_refused"
    assert "capability_not_granted:passive_recon" in result.errors

    def broken(capability: str, engagement: str) -> bool:
        raise RuntimeError("authz backend down")

    result = execute_knowledge_item(
        item,
        {"url": "https://app.example.com"},
        authorize=broken,
        runner=_spy_runner(calls),
    )
    assert result.status == "authorization_refused"
    assert any("authorizer_error" in e for e in result.errors)
    assert calls == []


def test_execute_enforces_the_run_budget() -> None:
    item = _item(max_runs=1)
    calls: list[list[str]] = []
    fill = {"url": "https://app.example.com"}
    first = execute_knowledge_item(
        item, fill, engagement_id="eng-budget",
        authorize=lambda *a: True, runner=_spy_runner(calls),
    )
    assert first.status == "executed" and first.budget_remaining == 0
    second = execute_knowledge_item(
        item, fill, engagement_id="eng-budget",
        authorize=lambda *a: True, runner=_spy_runner(calls),
    )
    assert second.status == "budget_exhausted"
    assert len(calls) == 1


def test_cleanup_is_invoked_best_effort() -> None:
    item = _item(cleanup="remove temp files")
    cleanups: list[str] = []
    result = execute_knowledge_item(
        item,
        {"url": "https://app.example.com"},
        authorize=lambda *a: True,
        runner=_spy_runner([]),
        cleanup=cleanups.append,
    )
    assert result.status == "executed"
    assert result.cleanup_invoked is True
    assert cleanups == ["remove temp files"]


# ---------------------------------------------------------------------------
# 5. The lifecycle
# ---------------------------------------------------------------------------


def test_registry_version_pinning_and_latest_wins() -> None:
    registry = KnowledgeRegistry()
    v1 = _item(version="1.0")
    v2 = _item(version="2.0")
    registry.register(v1)
    registry.register(v2)
    assert registry.get("httpx-probe") is not None
    assert registry.get("httpx-probe").version == "2.0"
    assert registry.get("httpx-probe", "1.0").version == "1.0"

    with pytest.raises(ValueError, match="version collision"):
        registry.register(_item(version="1.0", title="different content"))


def test_release_requires_human_reviewer_distinct_from_author() -> None:
    registry = KnowledgeRegistry()
    item = _item(version="1.0", provenance_reviewed_by="")  # no human review recorded
    registry.register(item)
    reasons = registry.release(item, reviewer="someone")
    assert "item_records_no_human_review" in reasons

    # Self-reviewed (reviewer == author) at a DIFFERENT version — the
    # registry's version pinning would refuse same-version content drift.
    self_reviewed = _item(version="1.1", provenance_reviewed_by="webpent-core")
    registry.register(self_reviewed)
    reasons = registry.release(self_reviewed, reviewer="webpent-core")
    assert "reviewer_must_differ_from_author" in reasons


def test_release_requires_a_passing_regression() -> None:
    registry = KnowledgeRegistry()
    # Pattern-bearing item: the deterministic sample cannot match the
    # url pattern — release must refuse without a hand-written spec.
    item = _item()
    registry.register(item)
    reasons = registry.release(item, reviewer="webpent-security")
    assert any("regression_unbuildable" in r for r in reasons)

    hand_written = RegressionSpec(
        item_id="httpx-probe",
        item_version="1.0",
        sample_fill={"url": "https://sample.example", "follow_redirects": True},
        expected_argv=["httpx", "-u", "https://sample.example", "-silent", "-fr", "true"],
    )
    reasons = registry.release(
        item, reviewer="webpent-security", regression=hand_written
    )
    assert reasons == []
    assert registry.get("httpx-probe", "1.0").review_status == "released"
    # Every released template carries its regression.
    assert len(registry.regression_specs()) == 1
    assert assert_registry_regressions(registry) == []


def test_regressions_catch_template_drift() -> None:
    registry = KnowledgeRegistry()
    item = _item()
    registry.register(item)
    hand_written = RegressionSpec(
        item_id="httpx-probe",
        item_version="1.0",
        sample_fill={"url": "https://sample.example", "follow_redirects": True},
        expected_argv=["httpx", "-u", "https://sample.example", "-silent", "-fr", "true"],
    )
    registry.release(item, reviewer="webpent-security", regression=hand_written)
    # The stored template drifts in place (an edit that bypassed the
    # version discipline — exactly what regressions exist to catch).
    drifted = _item(safe_execution_template=["httpx", "-extra", "-u", "{url}", "-silent", "-fr", "{follow_redirects}"])
    registry._items[KnowledgeRegistry._key("httpx-probe", "1.0")] = drifted
    failures = assert_registry_regressions(registry)
    assert any("argv_drift" in error for _, errors in failures for error in errors)


def test_regression_spec_rejects_item_mismatch() -> None:
    registry = KnowledgeRegistry()
    item = _item()
    registry.register(item)
    wrong = RegressionSpec(
        item_id="other-item",
        item_version="9.9",
        sample_fill={},
        expected_argv=["x"],
    )
    reasons = registry.release(item, reviewer="webpent-security", regression=wrong)
    assert "regression_spec_item_mismatch" in reasons

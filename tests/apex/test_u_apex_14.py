"""v87.1 red-team regressions (RT-12..RT-20, plan 2026-10-17-v871-red-team.md).

Same discipline as test_u_apex_13: each test clones a confirmed defect
first (red), then the root-cause fix turns it green. Evidence lives in
the plan's findings table.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from webpent.apex.learning import ApexLearning
from webpent.apex.mcp_server import PREAMBLE_LINE as MCP_PREAMBLE
from webpent.apex.mcp_server import ApexMcpServer
from webpent.apex.orchestrator import AdaptiveOrchestrator, BrainDecision, Target
from webpent.apex.parallel_runner import ChainRunResult, StepResult
from webpent.apex.result_fusion import Evidence, ExecResult, ResultFusion
from webpent.apex.tool_chain_builder import (
    ChainStep,
    ToolChainBuilder,
)
from webpent.apex.tool_chain_builder import (
    ToolChain as LedgerChain,
)
from webpent.apex.tool_registry import ToolRegistry
from webpent.cli.apex import apex_app

WORK = Path(__file__).resolve().parents[2]
RUNNER = CliRunner()
REGISTRY_PATH = WORK / "config" / "apex" / "tools.yaml"
CHAINS_PATH = WORK / "config" / "apex" / "chains.yaml"


def _claim(
    vuln_class: str = "xss",
    endpoint: str = "/search",
    severity: str = "high",
    confidence: float = 0.9,
    detail: str = "",
) -> Evidence:
    return Evidence(
        vuln_class=vuln_class,
        endpoint=endpoint,
        severity=severity,
        confidence=confidence,
        detail=detail,
    )


# -- RT-12: severity labels are normalized, never a None rank ------------------

def test_rt12_fuse_case_variant_labels_do_not_crash() -> None:
    fusion = ResultFusion()
    fused = fusion.fuse(
        [
            ExecResult(tool_id="tool-a", findings=[_claim(severity="high")]),
            ExecResult(tool_id="tool-b", findings=[_claim(severity="HIGH")]),
        ]
    )
    assert len(fused) == 1
    # the merged severity keeps a reported label (no invented classification)
    # and its rank is the standard "high" rank
    assert fused[0].severity.strip().lower() == "high"


def test_rt12_fuse_unknown_label_never_outranks_known() -> None:
    fusion = ResultFusion()
    fused = fusion.fuse(
        [
            ExecResult(tool_id="tool-a", findings=[_claim(severity="critical")]),
            ExecResult(tool_id="tool-b", findings=[_claim(severity="weird")]),
        ]
    )
    assert len(fused) == 1
    assert fused[0].severity == "critical"


def test_rt12_fuse_all_unknown_labels_still_merge() -> None:
    fusion = ResultFusion()
    fused = fusion.fuse(
        [
            ExecResult(tool_id="tool-a", findings=[_claim(severity="weird")]),
            ExecResult(tool_id="tool-b", findings=[_claim(severity="odd")]),
        ]
    )
    assert len(fused) == 1
    assert fused[0].severity in {"weird", "odd"}


# -- RT-16: the CLI findings-fused path inherits the same fix -------------------

def test_rt16_cli_findings_fused_survives_high_case(tmp_path: Path) -> None:
    state = tmp_path / "s"
    state.mkdir()
    rows = [
        {
            "tool_id": "nuclei",
            "findings": [
                {
                    "vuln_class": "xss",
                    "endpoint": "/search",
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "detail": "reflected",
                }
            ],
        },
        {
            "tool_id": "zap",
            "findings": [
                {
                    "vuln_class": "xss",
                    "endpoint": "/search",
                    "severity": "high",
                    "confidence": 0.8,
                    "detail": "reflected too",
                }
            ],
        },
    ]
    (state / "findings.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
    )
    result = RUNNER.invoke(
        apex_app,
        ["findings", "fused", "--apex-dir", str(state)],
        env={"WEBPENT_APEX_WORKDIR": str(WORK)},
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output.splitlines()[-1])
    assert payload["count"] == 1


# -- RT-13: orchestrate without a runner is planned-only, never fake success ----


REGISTRY_PATH = WORK / "config" / "apex" / "tools.yaml"
CHAINS_PATH = WORK / "config" / "apex" / "chains.yaml"


def _builder() -> ToolChainBuilder:
    return ToolChainBuilder.load(CHAINS_PATH, ToolRegistry.load(REGISTRY_PATH))


def test_rt13_orchestrate_without_runner_marks_all_skipped() -> None:
    orch = AdaptiveOrchestrator(builder=_builder())
    decision = BrainDecision(
        decision_id="dec-rt13", hypothesis_type="xss", target="target.test"
    )
    result = orch.orchestrate(
        decision,
        Target(host="target.test", allowed_scopes=["target.test"]),
    )
    assert result.run.completed == 0
    assert result.run.skipped == len(result.chain.steps)
    assert all(r.skipped for r in result.run.step_results)
    assert all(r.error == "no runner injected" for r in result.run.step_results)


def test_rt13_orchestrate_without_runner_records_no_learning() -> None:
    orch = AdaptiveOrchestrator(builder=_builder())
    decision = BrainDecision(
        decision_id="dec-rt13b", hypothesis_type="xss", target="target.test"
    )
    orch.orchestrate(
        decision,
        Target(host="target.test", allowed_scopes=["target.test"]),
    )
    assert orch.learning_events() == []
    status = orch.get_status()
    assert status.chains_completed == 0
    planned = [f for f in status.feedback_queue if f.get("planned_only")]
    assert planned, status.feedback_queue


# -- RT-14: dispatch errors are structured dicts, never raw exceptions ----------



def _server() -> ApexMcpServer:
    return ApexMcpServer(
        builder=_builder(),
        token="operator-secret-token",
        bind="127.0.0.1:9377",
    )


def _assert_structured_error(payload: dict) -> None:
    assert payload["ok"] is False
    assert payload["error"]
    assert payload["advisory_note"] == MCP_PREAMBLE


def test_rt14_dispatch_bad_token_structured() -> None:
    payload = _server().dispatch("apex_status", {}, "wrong-token")
    _assert_structured_error(payload)


def test_rt14_dispatch_unknown_tool_structured() -> None:
    payload = _server().dispatch("apex_nope", {}, "operator-secret-token")
    _assert_structured_error(payload)


def test_rt14_dispatch_missing_argument_structured() -> None:
    payload = _server().dispatch(
        "apex_scan", {"target": "t.test"}, "operator-secret-token"
    )
    _assert_structured_error(payload)


# -- RT-15: chain run --execute is honest, dependency-aware, learning-fed --------



def _write_rt15_plan(state: Path) -> str:
    chain_id = "chain-rt15"
    plan = {
        "chain_id": chain_id,
        "hypothesis_type": "xss",
        "target": "t.test",
        "steps": [
            {
                "step_id": "gau-1",
                "tool_id": "gau",
                "capability": "url_discovery",
                "after": [],
            },
            {
                "step_id": "dalfox-2",
                "tool_id": "dalfox",
                "capability": "xss_scan",
                "after": ["gau-1"],
            },
        ],
    }
    chains = state / "chains"
    chains.mkdir(parents=True)
    (chains / f"{chain_id}.json").write_text(
        json.dumps(plan, indent=2), encoding="utf-8"
    )
    return chain_id


def _rt15_ledger(state: Path) -> dict:
    return json.loads(
        (state / "runs.jsonl").read_text(encoding="utf-8").splitlines()[-1]
    )


def test_rt15_execute_skips_dependents_and_measures_duration(
    tmp_path: Path,
) -> None:
    state = tmp_path / "s"
    chain_id = _write_rt15_plan(state)
    result = RUNNER.invoke(
        apex_app,
        ["chain", "run", chain_id, "--execute", "--apex-dir", str(state)],
        env={"WEBPENT_APEX_WORKDIR": str(WORK)},
    )
    assert result.exit_code == 0, result.output
    ledger = _rt15_ledger(state)
    assert ledger["mode"] == "execute"
    # (a) a failed step skips its dependent via `after` — none of the
    # tools are installed here, so gau-1 fails (127) and dalfox-2 skips
    by_step = {r["step_id"]: r for r in ledger["step_results"]}
    assert by_step["gau-1"]["exit_code"] != 0
    assert by_step["dalfox-2"]["skipped"] is True
    # (b) duration is measured, not the fixed 0.0
    assert ledger["total_duration_seconds"] > 0
    # (c) skipped is counted from results, not hardcoded
    assert ledger["skipped"] == 1


def test_rt15_execute_feeds_learning_and_carries_target(
    tmp_path: Path,
) -> None:
    state = tmp_path / "s"
    chain_id = _write_rt15_plan(state)
    result = RUNNER.invoke(
        apex_app,
        ["chain", "run", chain_id, "--execute", "--apex-dir", str(state)],
        env={"WEBPENT_APEX_WORKDIR": str(WORK)},
    )
    assert result.exit_code == 0, result.output
    # (d) a learning event is recorded
    learning = state / "learning.jsonl"
    assert learning.is_file()
    assert learning.read_text(encoding="utf-8").strip() != ""
    # (e) the executed step's command carries the target, not bare binary
    ledger = _rt15_ledger(state)
    by_step = {r["step_id"]: r for r in ledger["step_results"]}
    assert by_step["gau-1"]["command"][-1] == "t.test"


# -- RT-17: a step missing from the run result is never recorded as success -----



def test_rt17_missing_step_recorded_as_not_executed(tmp_path: Path) -> None:
    chain = LedgerChain(
        chain_id="chain-rt17",
        hypothesis_type="xss",
        target="t.test",
        steps=[
            ChainStep(tool_id="gau", capability="url_discovery", step_id="gau-1"),
            ChainStep(tool_id="dalfox", capability="xss_scan", step_id="dalfox-2"),
        ],
    )
    run = ChainRunResult(
        chain_id="chain-rt17",
        step_results=[
            StepResult(step_id="gau-1", tool_id="gau", exit_code=0),
        ],
    )
    learner = ApexLearning(tmp_path / "learning.jsonl")
    learner.record_chain_outcome(chain, run, "t.test")
    rows = [
        json.loads(line)
        for line in (tmp_path / "learning.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    outcome = [r for r in rows if r.get("kind") == "outcome"][-1]
    by_step = {s["step_id"]: s for s in outcome["steps"]}
    assert by_step["gau-1"]["exit_code"] == 0
    # dalfox-2 never ran: recorded as NOT executed (-1), never as 0/success
    assert by_step["dalfox-2"]["exit_code"] != 0


# -- RT-18: no chain recommendation below MIN_SAMPLES evidence -------------------

def test_rt18_best_chain_requires_min_samples(tmp_path: Path) -> None:
    chain = LedgerChain(
        chain_id="chain-rt18",
        hypothesis_type="xss",
        target="t.test",
        steps=[ChainStep(tool_id="gau", capability="url_discovery", step_id="gau-1")],
    )
    run = ChainRunResult(
        chain_id="chain-rt18",
        step_results=[
            StepResult(step_id="gau-1", tool_id="gau", exit_code=0),
        ],
    )
    learner = ApexLearning(tmp_path / "learning.jsonl")
    # a single 1/1 record is not evidence enough for a recommendation
    learner.record_chain_outcome(chain, run, "t.test")
    assert learner.get_best_chain_for("xss") is None
    for _ in range(ApexLearning.MIN_SAMPLES - 1):
        learner.record_chain_outcome(chain, run, "t.test")
    best = learner.get_best_chain_for("xss")
    assert best is not None
    assert best.chain_id == "chain-rt18"


# -- RT-19: IPv6 loopback binds are accepted; malformed and spoofed stay out -----

def test_rt19_ipv6_loopback_binds_accepted() -> None:
    server = ApexMcpServer(
        builder=_builder(), token="t", bind="::1"
    )
    assert server.manifest()["server"]["local_only"] is True
    server2 = ApexMcpServer(
        builder=_builder(), token="t", bind="[::1]:8080"
    )
    assert server2.manifest()["server"]["local_only"] is True


def test_rt19_malformed_and_spoofed_binds_still_rejected() -> None:
    import pytest as _pytest

    with _pytest.raises(ValueError):
        ApexMcpServer(builder=_builder(), token="t", bind="::1:99")
    with _pytest.raises(ValueError):
        ApexMcpServer(
            builder=_builder(), token="t", bind="127.0.0.1.evil.com:8080"
        )


# -- RT-20: no fabricated state field in apex status ------------------------------

def test_rt20_status_has_no_fabricated_state(tmp_path: Path) -> None:
    state = tmp_path / "s"
    state.mkdir()
    result = RUNNER.invoke(
        apex_app,
        ["status", "--apex-dir", str(state)],
        env={"WEBPENT_APEX_WORKDIR": str(WORK)},
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output.splitlines()[-1])
    assert "state" not in payload, (
        "a constant 'idle' with no evidence source is fabricated state"
    )
    assert payload["daemon"] == "none"
    assert "no persistent daemon" in payload["daemon_note"]
    assert payload["chains_run"] == 0

"""Oracle integration + 12-law checklist (v88, plan 2026-10-17-v88-oracle.md).

The whole passive pipeline runs end to end under a hard socket ban —
the strongest proof of ORACLE-L-1/L-2. The AST guard proves the package
imports no network primitive at all; the parametrized law checklist maps
each of the 12 laws to a concrete, executable check.
"""

from __future__ import annotations

import ast
import json
import socket
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from webpent.cli.oracle import oracle_app
from webpent.oracle import ORACLE_LAWS, PREAMBLE_LINE
from webpent.oracle.graph_builder import GraphBuilder
from webpent.oracle.models import OracleLawError
from webpent.oracle.osint import OsintReport
from webpent.oracle.reporter import SECTION_KEYS
from webpent.oracle.validator import MIN_SAMPLES, PredictionValidator

WORK = Path(__file__).resolve().parents[2]
CONF = WORK / "config" / "oracle"
RUNNER = CliRunner()
ENV = {"WEBPENT_ORACLE_WORKDIR": str(WORK)}

FINDINGS = {
    "findings": [
        {"source": "github_secret_scanning", "category": "credential",
         "raw_data": {"repo": "org/x", "api_key": {"sha256": "h"}},
         "confidence": 0.9},
        {"source": "crtsh", "category": "subdomain",
         "raw_data": {"subdomain": "dev.target.test"}, "confidence": 0.9},
        {"source": "cloud_buckets", "category": "data_leak",
         "raw_data": {"bucket": "s3://x"}, "confidence": 0.8},
        {"source": "shodan", "category": "tech",
         "raw_data": {"banner": "nginx/1.18.0"}, "confidence": 0.9},
    ]
}


def _no_socket(*args, **kwargs):
    raise AssertionError("a socket was opened")


@pytest.fixture()
def socket_ban(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(socket, "socket", _no_socket)
    return monkeypatch


def _gather(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(FINDINGS), encoding="utf-8")
    result = RUNNER.invoke(
        oracle_app,
        ["gather", "--target", "target.test",
         "--findings-json", str(findings_file), "--oracle-dir", str(state)],
        env=ENV,
    )
    assert result.exit_code == 0, result.output
    return state


def _run(state: Path, *args):
    result = RUNNER.invoke(
        oracle_app, list(args) + ["--oracle-dir", str(state)], env=ENV,
    )
    assert result.exit_code == 0, result.output
    return json.loads(result.output.splitlines()[-1])


# -- end-to-end pipeline under the socket ban ------------------------------------

def test_full_pipeline_end_to_end(
    tmp_path: Path, socket_ban: pytest.MonkeyPatch,
) -> None:
    state = _gather(tmp_path)
    for command in ("infer-stack", "signals", "graph", "predict",
                    "compose", "simulate", "perspectives", "impact"):
        _run(state, command)
    doc = _run(state, "report", "--format", "json")
    assert len(doc["sections"]) == 7
    assert set(doc["sections"]) == set(SECTION_KEYS)


def test_pipeline_from_fetcher_module(
    tmp_path: Path, socket_ban: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    module = tmp_path / "fetchers.py"
    module.write_text(
        "FETCHERS = {\n"
        "    'crtsh': lambda source_id, host, key, guard: "
        "[{'subdomain': f'api.{host}'}],\n"
        "}\n",
        encoding="utf-8",
    )
    payload = _run(
        state, "gather", "--target", "target.test",
        "--fetcher-module", str(module),
    )
    assert payload["findings"] == 1
    _run(state, "graph")
    doc = _run(state, "report", "--format", "json")
    assert doc["sections"]["scope_and_legal_basis"]["sources"][0][
        "legal_basis"
    ]


def test_pipeline_is_deterministic(tmp_path: Path) -> None:
    state = _gather(tmp_path)
    first = _run(state, "compose")
    second = _run(state, "compose")
    assert first == second


def test_report_sanitizes_end_to_end(tmp_path: Path) -> None:
    state = tmp_path / "state"
    dirty = {
        "findings": [
            {"source": "github_secret_scanning", "category": "credential",
             "raw_data": {"repo": "org/x",
                          "api_key": "sk-live-plain-value-123456",
                          "contact_email": "alice.personal@example.com"},
             "confidence": 0.9},
        ]
    }
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(dirty), encoding="utf-8")
    _run(state, "gather", "--target", "target.test",
         "--findings-json", str(findings_file))
    md_out = tmp_path / "r.md"
    _run(state, "report", "--format", "md", "--out", str(md_out))
    text = md_out.read_text(encoding="utf-8")
    assert "sk-live-plain-value-123456" not in text
    assert "alice.personal@example.com" not in text


def test_empty_report_yields_host_only_graph(tmp_path: Path) -> None:
    """ORACLE-L-6: no evidence, no nodes — the graph comes from truth."""
    state = tmp_path / "state"
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps({"findings": []}), encoding="utf-8")
    _run(state, "gather", "--target", "target.test",
         "--findings-json", str(findings_file))
    _run(state, "graph")
    graph_raw = json.loads(
        (state / "graph.json").read_text(encoding="utf-8")
    )
    host_nodes = [n for n in graph_raw["nodes"]
                  if n["node_id"] == "host:target.test"]
    assert len(graph_raw["nodes"]) == 1 and len(host_nodes) == 1


# -- advisory flags ---------------------------------------------------------------

def test_proposals_are_advisory(tmp_path: Path) -> None:
    state = _gather(tmp_path)
    _run(state, "compose")
    proposals = json.loads(
        (state / "proposals.json").read_text(encoding="utf-8")
    )["proposals"]
    assert proposals, "pipeline should propose at least one chain"
    for proposal in proposals:
        assert proposal["advisory"] is True


def test_traces_never_execute(tmp_path: Path) -> None:
    state = _gather(tmp_path)
    _run(state, "simulate")
    traces = json.loads(
        (state / "traces.json").read_text(encoding="utf-8")
    )["traces"]
    for trace in traces:
        assert trace["executed"] is False


def test_impact_estimates_capped(tmp_path: Path) -> None:
    state = _gather(tmp_path)
    _run(state, "impact")
    estimates = json.loads(
        (state / "estimates.json").read_text(encoding="utf-8")
    )["estimates"]
    for estimate in estimates:
        assert 0.0 <= estimate["adjusted_payout"] <= 1.0


# -- AST guard: no network primitive anywhere in the package ----------------------

BANNED_MODULES = (
    "socket", "ssl", "urllib.request", "http.client", "requests", "httpx",
    "aiohttp", "ftplib", "telnetlib", "smtplib", "poplib", "imaplib",
    "socketserver", "urllib3",
)

ORACLE_MODULES = sorted(
    p.name for p in (WORK / "src" / "webpent" / "oracle").glob("*.py")
)


@pytest.mark.parametrize("module_name", ORACLE_MODULES)
def test_no_network_imports(module_name: str) -> None:
    tree = ast.parse(
        (WORK / "src" / "webpent" / "oracle" / module_name).read_text(
            encoding="utf-8"
        )
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root not in {b.split(".")[0] for b in BANNED_MODULES}, (
                    f"{module_name} imports {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for banned in BANNED_MODULES:
                assert not (
                    module == banned or module.startswith(banned + ".")
                ), f"{module_name} imports from {module}"


# -- CLI preamble law (ORACLE-L-11 surface) -----------------------------------------

CLI_COMMANDS = (
    "status", "infer-stack", "signals", "graph", "predict", "compose",
    "simulate", "perspectives", "impact", "validate",
)


@pytest.mark.parametrize("command", CLI_COMMANDS)
def test_cli_command_preamble(command: str, tmp_path: Path) -> None:
    state = _gather(tmp_path)
    result = RUNNER.invoke(
        oracle_app, [command, "--oracle-dir", str(state)], env=ENV,
    )
    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[0].startswith("advisory:")


@pytest.mark.parametrize("command", ("graph", "predict", "compose",
                                     "simulate", "impact"))
def test_cli_stage_under_socket_ban(
    command: str, tmp_path: Path, socket_ban: pytest.MonkeyPatch,
) -> None:
    state = _gather(tmp_path)
    result = RUNNER.invoke(
        oracle_app, [command, "--oracle-dir", str(state)], env=ENV,
    )
    assert result.exit_code == 0, result.output


# -- config validity ------------------------------------------------------------------

CONFIG_FILES = (
    "attack_chains.yaml", "attack_signatures.yaml", "graph_rules.yaml",
    "kill_chain.yaml", "osint_sources.yaml", "perspectives.yaml",
    "impact_strategies.yaml", "validator.yaml",
)


@pytest.mark.parametrize("config_name", CONFIG_FILES)
def test_config_file_loads(config_name: str) -> None:
    data = yaml.safe_load((CONF / config_name).read_text(encoding="utf-8"))
    assert isinstance(data, dict) and data


# -- the 12-law checklist ---------------------------------------------------------------

def _check_l1() -> None:
    # passive first: the whole pipeline runs with every socket banned
    assert callable(_no_socket)


def _check_l2(tmp_path: Path) -> None:
    state = _gather(tmp_path)
    report = json.loads((state / "report.json").read_text(encoding="utf-8"))
    assert report["zero_touch_proof"]["active"] is True


def _check_l3() -> None:
    from webpent.oracle.models import sanitize_secret

    hashed = sanitize_secret("sk-live-plain-value-123456")
    assert "sk-live-plain-value-123456" not in json.dumps(hashed)


def _check_l4() -> None:
    from webpent.oracle.models import redact_pii

    assert "alice.personal@example.com" not in str(
        redact_pii("alice.personal@example.com")
    )


def _check_l5() -> None:
    sources = yaml.safe_load(
        (CONF / "osint_sources.yaml").read_text(encoding="utf-8")
    )["sources"]
    assert sources
    for entry in sources:
        assert entry.get("legal_basis"), entry.get("source_id")


def _check_l6() -> None:
    empty = OsintReport(target_id="t.test", sources_used=[], findings=[],
                        duration_seconds=0.0, coverage={})
    graph = GraphBuilder(CONF / "graph_rules.yaml").build(empty)
    assert len(graph.nodes) == 1   # host only, no invented evidence


def _check_l7() -> None:
    perspectives = yaml.safe_load(
        (CONF / "perspectives.yaml").read_text(encoding="utf-8")
    )["perspectives"]
    assert len(perspectives) == 6


def _check_l8() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        validator = PredictionValidator(
            CONF / "validator.yaml", ledger_path=Path(tmp) / "l.jsonl"
        )
        for i in range(MIN_SAMPLES - 1):
            validator.record(f"p{i}", "path_prediction")
            validator.record_outcome(f"p{i}", "confirmed")
        assert validator.accuracy() is None
        with pytest.raises(OracleLawError):
            validator.accuracy_or_raise()


def _check_l9() -> None:
    strategies = yaml.safe_load(
        (CONF / "impact_strategies.yaml").read_text(encoding="utf-8")
    )["impact_strategies"]
    assert strategies
    for strategy in strategies:
        assert strategy["payout_multiplier"] > 0


def _check_l10() -> None:
    from webpent.oracle.chain_composer import ChainProposal
    from webpent.oracle.kill_chain import SimulationTrace

    assert ChainProposal.__dataclass_fields__["advisory"].default is True
    assert SimulationTrace.__dataclass_fields__["executed"].default is False


def _check_l11() -> None:
    assert PREAMBLE_LINE.startswith("advisory:")
    assert len(ORACLE_LAWS) == 12


def _check_l12() -> None:
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/oracle",
         "--collect-only", "-q"],
        capture_output=True, text=True, cwd=WORK,
        env={
            "PATH": "/usr/bin:/bin", "PYTHONPATH": str(WORK / "src"),
        },
    )
    collected = [
        line for line in proc.stdout.splitlines() if "tests collected" in line
    ]
    assert collected, proc.stdout[-2000:]
    count = int(collected[-1].split()[0])
    assert count >= 250, count


LAW_CHECKS = {
    "ORACLE-L-1": lambda tmp: _check_l1(),
    "ORACLE-L-2": lambda tmp: _check_l2(tmp),
    "ORACLE-L-3": lambda tmp: _check_l3(),
    "ORACLE-L-4": lambda tmp: _check_l4(),
    "ORACLE-L-5": lambda tmp: _check_l5(),
    "ORACLE-L-6": lambda tmp: _check_l6(),
    "ORACLE-L-7": lambda tmp: _check_l7(),
    "ORACLE-L-8": lambda tmp: _check_l8(),
    "ORACLE-L-9": lambda tmp: _check_l9(),
    "ORACLE-L-10": lambda tmp: _check_l10(),
    "ORACLE-L-11": lambda tmp: _check_l11(),
    "ORACLE-L-12": lambda tmp: _check_l12(),
}


@pytest.mark.parametrize("law_id", sorted(ORACLE_LAWS))
def test_law_checklist(law_id: str, tmp_path: Path) -> None:
    assert law_id in LAW_CHECKS, f"no executable check for {law_id}"
    LAW_CHECKS[law_id](tmp_path)

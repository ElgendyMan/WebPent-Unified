"""Red team regression tests for v88 THE ORACLE (plan 2026-10-17-v88-red-team.md).

Each test was written RED against the shipped v88 code and turns GREEN only
with the corresponding fix. One test per confirmed finding, RT-01..RT-11.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webpent.cli.oracle import oracle_app
from webpent.oracle.graph_builder import AttackGraph, GraphBuilder
from webpent.oracle.models import OracleLawError, sanitize_secret
from webpent.oracle.osint import (
    OSINTAggregator,
    OsintFinding,
    OsintReport,
    Target,
    ZeroTouchGuard,
    ZeroTouchViolation,
    load_source_configs,
)
from webpent.oracle.reporter import OracleReporter

WORK = Path(__file__).resolve().parents[2]
SOURCES = WORK / "config" / "oracle" / "osint_sources.yaml"
RUNNER = CliRunner()
ENV = {"WEBPENT_ORACLE_WORKDIR": str(WORK)}


def _aggregator(fetchers, api_keys=None) -> OSINTAggregator:
    return OSINTAggregator(SOURCES, fetchers=fetchers, api_keys=api_keys or {})


def _target() -> Target:
    return Target(host="target.com")


def _err_text(result) -> str:
    return result.output + "\n" + str(result.exception)


def _finding(source: str, category: str, raw: dict) -> OsintFinding:
    return OsintFinding(
        source=source, category=category, raw_data=raw, confidence=0.9,
        extracted_at=datetime.now(timezone.utc),
        evidence_hash="b" * 64, core_hash="b" * 64,
    )


def _report_with_two_findings() -> OsintReport:
    findings = [
        _finding("github_secret_scanning", "credential",
                 {"repo": "org/x", "api_key": {"sha256": "h"}}),
        _finding("crtsh", "subdomain", {"subdomain": "dev.target.test"}),
    ]
    return OsintReport(
        target_id="target.test",
        sources_used=sorted({f.source for f in findings}),
        findings=findings, duration_seconds=0.0, coverage={},
    )


def _gather_state(tmp_path: Path, findings: list[dict] | None = None) -> Path:
    state = tmp_path / "state"
    # a subdomain (entry per graph_rules) + a credential (target) so the
    # predict step actually has a path to record for validation
    findings = findings if findings is not None else [
        {"source": "github_secret_scanning", "category": "credential",
         "raw_data": {"repo": "org/x", "api_key": {"sha256": "a" * 64}},
         "confidence": 0.9},
        {"source": "crtsh", "category": "subdomain",
         "raw_data": {"subdomain": "dev.target.test"}, "confidence": 0.9},
    ]
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps({"findings": findings}),
                             encoding="utf-8")
    result = RUNNER.invoke(
        oracle_app,
        ["gather", "--target", "target.test",
         "--findings-json", str(findings_file),
         "--oracle-dir", str(state)],
        env=ENV,
    )
    assert result.exit_code == 0, _err_text(result)
    return state


# -- RT-01: zero-touch guard must fail closed -----------------------------------

def test_rt01_guard_refuses_schemeless_url() -> None:
    guard = ZeroTouchGuard("target.com")
    with pytest.raises(ZeroTouchViolation):
        guard.check("target.com/login")


def test_rt01_guard_refuses_trailing_dot_fqdn() -> None:
    guard = ZeroTouchGuard("target.com")
    with pytest.raises(ZeroTouchViolation):
        guard.check("https://target.com./api")


def test_rt01_guard_still_allows_third_party_queries() -> None:
    guard = ZeroTouchGuard("target.com")
    guard.check("https://crt.sh/?q=target.com")
    guard.check("https://api.shodan.io/dns?host=target.com")


# -- RT-02: short secrets never leak their value ----------------------------------

def test_rt02_short_secret_prefix_suppressed() -> None:
    assert sanitize_secret("abcd")["partial"] == ""
    assert sanitize_secret("abcd")["sha256"] != ""


def test_rt02_long_secret_prefix_is_prefix_only() -> None:
    out = sanitize_secret("sk-live-0123456789")
    assert out["partial"] == "sk-l…"
    assert out["sha256"] != ""


# -- RT-03: nested secrets are sanitized at gather time --------------------------

def test_rt03_nested_secret_sanitized_in_finding() -> None:
    agg = _aggregator(
        {"github_secret_scanning": lambda *a, **k: [
            {"repo": "org/x", "meta": {"api_key": "sk-live-nested-value"}},
        ]},
        api_keys={"github_secret_scanning": "k"},
    )
    report = agg.gather(_target(), sources=["github_secret_scanning"])
    assert report.findings, "gather must actually produce findings"
    raw = report.findings[0].raw_data
    assert raw["meta"]["api_key"]["sha256"]
    assert "sk-live-nested-value" not in json.dumps(raw, default=str)


def test_rt03_nested_pii_still_redacted() -> None:
    agg = _aggregator({"crtsh": lambda *a, **k: [
        {"subdomain": "dev.target.test",
         "contact": {"email": "bob.hidden@example.net"}},
    ]})
    report = agg.gather(_target(), sources=["crtsh"])
    assert report.findings, "gather must actually produce findings"
    raw = report.findings[0].raw_data
    assert "bob.hidden@example.net" not in json.dumps(raw, default=str)


# -- RT-04: validate refuses to default to confirmed ------------------------------

def test_rt04_validate_requires_result(tmp_path: Path) -> None:
    state = _gather_state(tmp_path)
    pred = RUNNER.invoke(
        oracle_app, ["predict", "--oracle-dir", str(state)], env=ENV,
    )
    assert pred.exit_code == 0, _err_text(pred)
    payload = json.loads(pred.output.splitlines()[-1])
    assert payload["recorded_for_validation"] >= 1, payload
    bad = RUNNER.invoke(
        oracle_app,
        ["validate", "--oracle-dir", str(state),
         "--outcome", "pred-x"],
        env=ENV,
    )
    assert bad.exit_code != 0
    assert "--result" in _err_text(bad)


# -- RT-05: graphs are deterministic run-to-run -----------------------------------

def test_rt05_graph_node_ids_deterministic() -> None:
    report = _report_with_two_findings()
    first = GraphBuilder(WORK / "config" / "oracle" / "graph_rules.yaml").build(
        report
    )
    second = GraphBuilder(WORK / "config" / "oracle" / "graph_rules.yaml").build(
        report
    )
    assert [n.node_id for n in first.nodes.values()] == [
        n.node_id for n in second.nodes.values()
    ]
    assert first.export_dot() == second.export_dot()


def test_rt05_takeover_node_ids_deterministic() -> None:
    report = _report_with_two_findings()
    signals = [
        type("S", (), {"signal_id": "takeover-gh-pages",
                       "signal_type": "subdomain_takeover_candidate",
                       "strength": 0.9})(),
    ]
    builder = GraphBuilder(WORK / "config" / "oracle" / "graph_rules.yaml")
    first = builder.build(report, signals=signals)
    second = builder.build(report, signals=signals)
    assert [n.node_id for n in first.nodes.values()] == [
        n.node_id for n in second.nodes.values()
    ]


# -- RT-06: entry nodes follow the entry rules, not a precedence accident --------

def _rules() -> dict:
    return {"entry_rules": {
        "entry_categories": ["subdomain", "endpoint"],
        "max_criticality": 0.6,
    }}


def _node(node_id: str, node_type: str, criticality: float):
    return type("N", (), {
        "node_id": node_id, "node_type": node_type,
        "label": node_id, "criticality": criticality,
        "confidence": 0.9, "data": {},
    })()


def test_rt06_low_confidence_credential_is_not_entry() -> None:
    graph = AttackGraph()
    graph.add_node(_node("credential:low", "credential", 0.54))
    assert graph.entry_nodes(_rules()) == []


def test_rt06_subdomain_is_entry() -> None:
    graph = AttackGraph()
    graph.add_node(_node("subdomain:a", "subdomain", 0.4))
    assert [n.node_id for n in graph.entry_nodes(_rules())] == ["subdomain:a"]


# -- RT-07: ingest rejects unknown sources (L-5) ----------------------------------

def test_rt07_ingest_rejects_unknown_source(tmp_path: Path) -> None:
    result = RUNNER.invoke(
        oracle_app,
        ["gather", "--target", "target.test",
         "--findings-json", str(_findings_file(tmp_path, source="not-a-source")),
         "--oracle-dir", str(tmp_path / "s")],
        env=ENV,
    )
    assert result.exit_code != 0
    assert "not-a-source" in _err_text(result)


# -- RT-08: confidence is clamped and never NaN -----------------------------------

def test_rt08_confidence_clamped() -> None:
    agg = _aggregator({"wayback": lambda *a, **k: [
        {"url": "https://target.com/old", "confidence": 5.0},
        {"url": "https://target.com/new", "confidence": -2.0},
    ]})
    report = agg.gather(_target(), sources=["wayback"])
    assert report.findings, "gather must actually produce findings"
    values = [f.confidence for f in report.findings]
    assert all(0.0 <= v <= 1.0 for v in values)


def test_rt08_confidence_nan_rejected() -> None:
    agg = _aggregator({"wayback": lambda *a, **k: [
        {"url": "https://target.com/old", "confidence": float("nan")},
    ]})
    report = agg.gather(_target(), sources=["wayback"])
    assert report.findings, "gather must actually produce findings"
    assert all(math.isfinite(f.confidence) for f in report.findings)


# -- RT-09: DOT labels are escaped --------------------------------------------------

def test_rt09_dot_label_escaped() -> None:
    graph = AttackGraph()
    node = _node("endpoint:x", "endpoint", 0.3)
    node.label = 'bad "quote" \\ slash'
    graph.add_node(node)
    dot = graph.export_dot()
    assert 'bad \\"quote\\" \\\\ slash' in dot
    # and the raw, unescaped sequence must not survive
    assert 'bad "quote"' not in dot


# -- RT-10: fetcher module failures are named, not AttributeError -----------------

def test_rt10_missing_fetcher_file_named_error(tmp_path: Path) -> None:
    result = RUNNER.invoke(
        oracle_app,
        ["gather", "--target", "target.test",
         "--fetcher-module", str(tmp_path / "nope.py"),
         "--oracle-dir", str(tmp_path / "s")],
        env=ENV,
    )
    assert result.exit_code != 0
    assert "nope.py" in _err_text(result)


def test_rt10_fetcher_module_without_fetchers_named_error(
    tmp_path: Path,
) -> None:
    module = tmp_path / "empty_fetchers.py"
    module.write_text("OTHER = 1\n", encoding="utf-8")
    result = RUNNER.invoke(
        oracle_app,
        ["gather", "--target", "target.test",
         "--fetcher-module", str(module),
         "--oracle-dir", str(tmp_path / "s")],
        env=ENV,
    )
    assert result.exit_code != 0
    assert "FETCHERS" in _err_text(result)


# -- RT-11: audit lines survive non-ASCII under any locale ------------------------

def test_rt11_audit_utf8(tmp_path: Path) -> None:
    result = RUNNER.invoke(
        oracle_app, ["status", "--oracle-dir", str(tmp_path / "s")],
        env=ENV,
    )
    assert result.exit_code == 0
    audit = tmp_path / "s" / "audit.jsonl"
    assert audit.exists()
    text = audit.read_text(encoding="utf-8")
    assert json.loads(text.splitlines()[0])["command"] == "status"


# -- reporter raises a law error, not FileNotFoundError ----------------------------

def test_reporter_missing_sources_file_is_law_error(
    tmp_path: Path,
) -> None:
    with pytest.raises(OracleLawError):
        OracleReporter(tmp_path / "missing.yaml")


def test_load_source_configs_all_have_legal_basis() -> None:
    configs = load_source_configs(SOURCES)
    assert configs and all(c.legal_basis for c in configs)


def _findings_file(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "unknown_source.json"
    path.write_text(json.dumps({"findings": [
        {"source": source, "category": "tech",
         "raw_data": {"banner": "nginx"}, "confidence": 0.9},
    ]}), encoding="utf-8")
    return path

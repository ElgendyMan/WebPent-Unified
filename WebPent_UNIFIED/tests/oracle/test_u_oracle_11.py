"""U-ORACLE-11 — the Oracle Reporter (v88, plan 2026-10-17-v88-oracle.md)."""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from webpent.oracle.chain_composer import ChainComposer
from webpent.oracle.graph_builder import GraphBuilder
from webpent.oracle.kill_chain import KillChainSimulator
from webpent.oracle.models import OracleLawError
from webpent.oracle.osint import OsintFinding, OsintReport
from webpent.oracle.reporter import SECTION_KEYS, OracleReporter
from webpent.oracle.stack_inferrer import Component, TechStackProfile

WORK = Path(__file__).resolve().parents[2]
SOURCES = WORK / "config" / "oracle" / "osint_sources.yaml"
RULES = WORK / "config" / "oracle" / "graph_rules.yaml"
CHAINS = WORK / "config" / "oracle" / "attack_chains.yaml"
KILL = WORK / "config" / "oracle" / "kill_chain.yaml"


def _finding(source: str, category: str, raw: dict, conf: float = 0.9):
    return OsintFinding(
        source=source, category=category, raw_data=raw, confidence=conf,
        extracted_at=datetime.now(timezone.utc),
        evidence_hash="a" * 64, core_hash="a" * 64,
    )


def _report(findings: list) -> OsintReport:
    return OsintReport(
        target_id="target.test",
        sources_used=sorted({f.source for f in findings}),
        findings=findings, duration_seconds=0.0, coverage={},
    )


def _stack() -> TechStackProfile:
    profile = TechStackProfile(target_id="target.test")
    profile.components = [Component(name="nginx", version="1.18.0",
                                    confidence=0.9)]
    return profile


def _report_doc(tmp_path: Path):
    """A full pipeline report: findings -> graph -> proposals -> traces."""
    findings = [
        _finding("github_secret_scanning", "credential",
                 {"repo": "org/x", "api_key": {"sha256": "h"}}),
        _finding("crtsh", "subdomain", {"subdomain": "dev.target.test"}),
        _finding("cloud_buckets", "data_leak", {"bucket": "s3://x"}),
        _finding("shodan", "tech", {"banner": "nginx/1.18.0"}),
    ]
    report = _report(findings)
    graph = GraphBuilder(RULES).build(report, stack_profile=_stack())
    proposals = ChainComposer(CHAINS).compose(graph)
    simulator = KillChainSimulator(KILL)
    traces = [simulator.simulate(graph, p) for p in proposals[:3]]
    doc = OracleReporter(SOURCES).build(
        report, graph, stack_profile=_stack(), proposals=proposals,
        traces=traces,
    )
    return doc


# -- spec test 1: seven sections --------------------------------------------------

def test_seven_sections_present(tmp_path: Path) -> None:
    doc = _report_doc(tmp_path)
    assert set(doc.sections) == set(SECTION_KEYS)
    assert len(doc.sections) == 7


# -- spec test 2: markdown renders every section -------------------------------------

def test_markdown_contains_all_sections(tmp_path: Path) -> None:
    markdown = OracleReporter(SOURCES).to_markdown(_report_doc(tmp_path))
    for title in (
        "1. Executive Summary", "2. Scope and Legal Basis",
        "3. Evidence Inventory", "4. Technology Stack",
        "5. Attack Graph", "6. Predicted Chains and Simulations",
        "7. Perspectives, Impact and Validation",
    ):
        assert title in markdown
    assert "digraph oracle_attack_graph" in markdown


# -- spec test 3: JSON round trip ---------------------------------------------------------

def test_json_round_trip(tmp_path: Path) -> None:
    doc = _report_doc(tmp_path)
    payload = json.loads(OracleReporter(SOURCES).to_json(doc))
    assert payload["target_id"] == "target.test"
    assert set(payload["sections"]) == set(SECTION_KEYS)
    assert payload["sections"]["evidence_inventory"]["by_category"][
        "credential"
    ] == 1


# -- spec test 4: PDF written ------------------------------------------------------------------

def test_pdf_written(tmp_path: Path) -> None:
    doc = _report_doc(tmp_path)
    pdf_path = OracleReporter(SOURCES).to_pdf(
        doc, tmp_path / "oracle_report.pdf"
    )
    assert pdf_path.exists()
    content = pdf_path.read_bytes()
    assert content.startswith(b"%PDF")
    assert len(content) > 1000


# -- spec test 5: legal basis named for every source used ----------------------------------------

def test_legal_basis_for_every_source(tmp_path: Path) -> None:
    doc = _report_doc(tmp_path)
    scope = doc.sections["scope_and_legal_basis"]
    used = doc.sections["executive_summary"]["sources_used"]
    listed = {s["source_id"] for s in scope["sources"]}
    assert set(used) <= listed
    for entry in scope["sources"]:
        assert entry["legal_basis"]


# -- sanitization: no raw secret and no PII survive into the report

def test_secrets_and_pii_sanitized(tmp_path: Path) -> None:
    findings = [
        _finding("github_secret_scanning", "credential", {
            "repo": "org/x",
            "api_key": "sk-live-plain-value-123456",
            "contact_email": "alice.personal@example.com",
            "phone": "+20123456789",
        }),
    ]
    report = _report(findings)
    graph = GraphBuilder(RULES).build(report)
    doc = OracleReporter(SOURCES).build(report, graph)
    markdown = OracleReporter(SOURCES).to_markdown(doc)
    assert "sk-live-plain-value-123456" not in markdown
    assert "alice.personal@example.com" not in markdown
    assert "+20123456789" not in markdown
    assert "sha256" in markdown   # the hashed form is present instead


# -- guards --------------------------------------------------------------------------------------

def test_passive_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def _no_socket(*args, **kwargs):
        raise AssertionError("reporter opened a socket")

    monkeypatch.setattr(socket, "socket", _no_socket)
    _report_doc(tmp_path)


def test_missing_sources_section_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "sources.yaml"
    bad.write_text("other: []\n", encoding="utf-8")
    with pytest.raises(OracleLawError):
        OracleReporter(bad)

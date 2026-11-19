"""U-FORGE-16 — The Payload CLI (red tests).

Full terminal control of THE FORGE, exactly the spec's command
surface: ingest / find / adapt / mutate / synthesize / waf-bypass /
corpus status+stats+export / attribution / license-report. Each
command is argv in, structured result out — no real terminal, zero
network.
"""
from __future__ import annotations

import json

import pytest

from webpent.forge.payload_cli import PayloadCLI
from webpent.forge.schemas import Family, NormalizedPayload
from webpent.forge.indexer import PayloadIndexer


def _seed(indexer: PayloadIndexer) -> None:
    indexer.store_payload(NormalizedPayload(
        payload_id="sqli-php-1", family=Family.SQLI, subfamily="",
        raw="' OR 1=1-- -", target_tech=("php",),
        target_waf=("cloudflare",), target_context=("json",),
        quality_score=0.8,
        attribution=None))
    indexer.store_payload(NormalizedPayload(
        payload_id="sqli-node-1", family=Family.SQLI, subfamily="",
        raw="1; DROP TABLE users--", target_tech=("node",),
        target_waf=("aws",), target_context=("json",),
        quality_score=0.6,
        attribution=None))
    indexer.store_payload(NormalizedPayload(
        payload_id="xss-php-1", family=Family.XSS, subfamily="",
        raw='<script>alert(1)</script>', target_tech=("php",),
        target_waf=(), target_context=("html",),
        quality_score=0.7,
        attribution=None))


@pytest.fixture
def cli():
    indexer = PayloadIndexer()
    _seed(indexer)
    return PayloadCLI(indexer)


def test_find_with_tech_waf_limit_filters(cli):
    result = cli.run(["find", "SQLI", "--tech", "php",
                      "--waf", "cloudflare", "--limit", "20"])
    assert result.ok
    ids = [p.payload_id for p in result.data["payloads"]]
    assert ids == ["sqli-php-1"]
    limited = cli.run(["find", "SQLI", "--limit", "1"])
    assert len(limited.data["payloads"]) == 1


def test_find_by_context_and_endpoint(cli):
    result = cli.run(["find", "--context", "json",
                      "--endpoint", "/api/users"])
    assert result.ok
    ids = [p.payload_id for p in result.data["payloads"]]
    assert "sqli-php-1" in ids and "sqli-node-1" in ids
    assert "xss-php-1" not in ids


def test_adapt_targets_tech_waf_context(cli):
    result = cli.run(["adapt", "sqli-php-1", "--for-tech", "node",
                      "--for-waf", "aws", "--for-context", "json"])
    assert result.ok
    assert result.data["payload_id"] == "sqli-php-1"
    assert result.data["adapted_for"] == {
        "tech": "node", "waf": "aws", "context": "json"}
    assert result.data["raw"]


def test_mutate_and_synthesize(cli):
    mutated = cli.run(["mutate", "sqli-php-1", "--max-variants", "3"])
    assert mutated.ok
    assert 0 < len(mutated.data["variants"]) <= 3
    synth = cli.run(["synthesize", "--family", "sqli",
                     "--grammar", "standard"])
    assert synth.ok
    assert synth.data["payloads"]
    assert all(p.family == Family.SQLI
               for p in synth.data["payloads"])
    bypass = cli.run(["waf-bypass", "sqli-php-1",
                      "--target-waf", "cloudflare"])
    assert bypass.ok
    assert bypass.data["target_waf"] == "cloudflare"
    assert bypass.data["variants"]


def test_corpus_status_stats_export(cli):
    status = cli.run(["corpus", "status"])
    assert status.ok
    assert status.data["payloads"] == 3
    stats = cli.run(["corpus", "stats"])
    assert stats.ok
    assert stats.data["by_family"]["SQLI"] == 2
    export = cli.run(["corpus", "export", "--format", "jsonl"])
    assert export.ok
    lines = export.data["jsonl"].strip().splitlines()
    assert len(lines) == 3
    assert all(json.loads(line)["payload_id"] for line in lines)


def test_attribution_license_report_and_unknown(cli):
    att = cli.run(["attribution", "sqli-php-1"])
    assert att.ok
    assert "license" in att.data
    report = cli.run(["license-report"])
    assert report.ok
    assert len(report.data["entries"]) == 3
    bad = cli.run(["definitely-not-a-command"])
    assert not bad.ok
    assert bad.data["message"]
    help_text = cli.run(["--help"])
    assert help_text.ok
    for command in ("ingest", "find", "adapt", "mutate",
                    "synthesize", "waf-bypass", "corpus",
                    "attribution", "license-report"):
        assert command in help_text.data["text"]

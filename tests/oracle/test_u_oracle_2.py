"""U-ORACLE-2 — the Stack Inferrer (v88, plan 2026-10-17-v88-oracle.md)."""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.oracle.models import OracleLawError
from webpent.oracle.osint import OSINTAggregator, OsintFinding, OsintReport
from webpent.oracle.stack_inferrer import StackInferrer

WORK = Path(__file__).resolve().parents[2]
SIGS = WORK / "config" / "oracle" / "attack_signatures.yaml"
SOURCES = WORK / "config" / "oracle" / "osint_sources.yaml"


def _report(target_id: str = "target.test") -> OsintReport:
    return OsintReport(
        target_id=target_id,
        sources_used=[],
        findings=[],
        duration_seconds=0.0,
        coverage={},
    )


def _finding(
    source: str, category: str, raw: dict, confidence: float = 0.9
) -> OsintFinding:
    from datetime import datetime, timezone

    return OsintFinding(
        source=source,
        category=category,
        raw_data=raw,
        confidence=confidence,
        extracted_at=datetime.now(timezone.utc),
        evidence_hash="0" * 64,
        core_hash="0" * 64,
    )


# -- spec test 1: inference from banners -----------------------------------------

def test_infer_from_banners() -> None:
    report = _report()
    report.findings = [
        _finding("shodan", "tech", {"banner": "nginx/1.18.0", "port": 443})
    ]
    profile = StackInferrer(SIGS).infer(report)
    nginx = [c for c in profile.components if c.name == "nginx"]
    assert nginx and nginx[0].version == "1.18.0"


# -- spec test 2: inference from job postings ----------------------------------------

def test_infer_from_job_postings() -> None:
    report = _report()
    report.findings = [
        _finding(
            "job_postings", "tech",
            {"title": "DevOps lead", "body": "we run kubernetes and django"},
        )
    ]
    profile = StackInferrer(SIGS).infer(report)
    names = {c.name for c in profile.components}
    assert {"kubernetes", "django"} <= names


# -- spec test 3: inference from code search -------------------------------------------

def test_infer_from_code_search() -> None:
    report = _report()
    report.findings = [
        _finding(
            "code_search", "endpoint",
            {"snippet": "requirements.txt: django==4.2"},
        )
    ]
    profile = StackInferrer(SIGS).infer(report)
    django = [c for c in profile.components if c.name == "django"]
    assert django and django[0].version == "4.2"


# -- spec test 4: confidence scores ----------------------------------------------------

def test_confidence_scores_corroboration() -> None:
    report = _report()
    report.findings = [
        _finding("job_postings", "tech", {"body": "django experience"}),
        _finding("code_search", "endpoint", {"snippet": "django==4.2"}),
    ]
    profile = StackInferrer(SIGS).infer(report)
    django = [c for c in profile.components if c.name == "django"][0]
    single = StackInferrer(SIGS).infer(
        _report()
    )
    single_report = _report()
    single_report.findings = [
        _finding("job_postings", "tech", {"body": "django experience"})
    ]
    single = StackInferrer(SIGS).infer(single_report)
    alone = [c for c in single.components if c.name == "django"][0]
    assert django.confidence > alone.confidence
    assert django.confidence <= 0.95


# -- spec test 5: five distinct inference sources -----------------------------------------

def test_inference_from_five_sources() -> None:
    report = _report()
    report.findings = [
        _finding("shodan", "tech", {"banner": "nginx/1.18.0"}),
        _finding("job_postings", "tech", {"body": "kubernetes + aws"}),
        _finding("code_search", "endpoint", {"snippet": "requirements.txt"}),
        _finding("crtsh", "subdomain", {"subdomain": "cdn.target.test"}),
        _finding("cloud_buckets", "data_leak", {"bucket": "s3://x"}),
    ]
    profile = StackInferrer(SIGS).infer(report)
    assert len(set(profile.inference_sources)) >= 5
    assert profile.components, "each source must contribute evidence"


# -- spec test 6: CVE enrichment ------------------------------------------------------------

def test_cve_enrichment_static_map() -> None:
    report = _report()
    report.findings = [
        _finding("shodan", "tech", {"banner": "nginx/1.18.0"})
    ]
    inferrer = StackInferrer(SIGS)
    profile = inferrer.enrich_with_cves(inferrer.infer(report))
    assert profile.cves["nginx"][0].cve == "CVE-2021-23017"
    # unknown component → no invented CVEs
    bare = _report()
    bare.findings = [_finding("shodan", "tech", {"banner": "obscureware/9"})]
    empty = inferrer.enrich_with_cves(inferrer.infer(bare))
    assert not empty.cves


# -- spec test 7: attack vectors ---------------------------------------------------------------

def test_attack_vectors_per_component() -> None:
    report = _report()
    report.findings = [
        _finding("job_postings", "tech", {"body": "wordpress developer"})
    ]
    profile = StackInferrer(SIGS).infer(report)
    vectors = StackInferrer(SIGS).cross_reference(profile)
    wp = [v for v in vectors if v.component == "wordpress"]
    assert wp and all(v.vector for v in wp)


# -- guards + parametrized config law ------------------------------------------------------------

def test_missing_signature_section_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "sig.yaml"
    bad.write_text("inference_rules: []\n", encoding="utf-8")
    with pytest.raises(OracleLawError):
        StackInferrer(bad)


def test_full_pipeline_osint_to_vectors() -> None:
    def shodan(source_id, host, key, guard):
        guard.check("https://api.shodan.io/x")
        return [{"banner": "nginx/1.18.0", "confidence": 0.9}]

    agg = OSINTAggregator(
        SOURCES, fetchers={"shodan": shodan}, api_keys={"shodan": "k"}
    )
    from webpent.oracle.models import Target

    report = agg.gather(Target(host="target.test"))
    inferrer = StackInferrer(SIGS)
    profile = inferrer.enrich_with_cves(inferrer.infer(report))
    vectors = inferrer.cross_reference(profile)
    assert vectors and vectors[0].component == "nginx"


@pytest.mark.parametrize(
    "rule", _load := __import__("yaml").safe_load(
        (Path(__file__).resolve().parents[2]
         / "config" / "oracle" / "attack_signatures.yaml").read_text()
    )["inference_rules"],
    ids=lambda r: r["rule_id"],
)
def test_every_rule_well_formed(rule) -> None:
    assert rule["rule_id"] and rule["category"] and rule["keywords"]
    assert rule["infers"]
    assert 0.0 < float(rule["confidence"]) <= 1.0

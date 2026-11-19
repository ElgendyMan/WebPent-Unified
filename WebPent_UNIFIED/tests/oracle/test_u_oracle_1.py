"""U-ORACLE-1 — the OSINT Aggregator (v88, plan 2026-10-17-v88-oracle.md).

Red-first per house discipline: each behavior test clones the spec
clause it proves. The zero-touch law is proven two ways: a real socket
ban around a full gather, and a malicious fetcher that tries the target
URL and is refused by the guard.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from webpent.oracle.models import (
    OracleLawError,
    Target,
    ZeroTouchViolation,
    sha256_text,
)
from webpent.oracle.osint import (
    OSINTAggregator,
    ZeroTouchGuard,
    load_source_configs,
)

WORK = Path(__file__).resolve().parents[2]
SOURCES = WORK / "config" / "oracle" / "osint_sources.yaml"


def _agg(fetchers=None, api_keys=None, clock=None) -> OSINTAggregator:
    kwargs = {"fetchers": fetchers, "api_keys": api_keys or {}}
    if clock is not None:
        kwargs["clock"] = clock
    return OSINTAggregator(SOURCES, **kwargs)


def _target() -> Target:
    return Target(host="target.test", allowed_scopes=["target.test"])


# -- spec test 1: github secret scanning ---------------------------------------

def test_github_secret_scanning_finds_repos() -> None:
    def github(source_id, host, key, guard):
        guard.check("https://api.github.com/search/code?q=" + host)
        return [{"repo": "org/repo", "api_key": "AKIAIOSFODNN7EXAMPLE"}]

    report = _agg(
        {"github_secret_scanning": github},
        api_keys={"github_secret_scanning": "gh-key"},
    ).gather(_target())
    hits = [f for f in report.findings if f.source == "github_secret_scanning"]
    assert hits and hits[0].category == "credential"


# -- spec test 2: CT logs --------------------------------------------------------

def test_ct_logs_return_subdomains() -> None:
    def crtsh(source_id, host, key, guard):
        guard.check("https://crt.sh/?q=%." + host)
        return [{"subdomain": "dev.target.test"}, {"subdomain": "stg.target.test"}]

    report = _agg({"crtsh": crtsh}).gather(_target())
    hits = [f for f in report.findings if f.source == "crtsh"]
    assert len(hits) == 2 and hits[0].category == "subdomain"


# -- spec test 3: wayback ---------------------------------------------------------

def test_wayback_returns_endpoints() -> None:
    def wayback(source_id, host, key, guard):
        guard.check("http://web.archive.org/cdx/search/cdx?url=*." + host)
        return [{"url": "https://web.archive.org/target.test/old-login"}]

    report = _agg({"wayback": wayback}).gather(_target())
    hits = [f for f in report.findings if f.source == "wayback"]
    assert hits and hits[0].category == "endpoint"


# -- spec test 4: shodan -----------------------------------------------------------

def test_shodan_integration() -> None:
    def shodan(source_id, host, key, guard):
        assert key == "shodan-key"
        guard.check("https://api.shodan.io/shodan/host/search?query=" + host)
        return [{"banner": "nginx/1.18.0", "port": 443}]

    report = _agg({"shodan": shodan}, api_keys={"shodan": "shodan-key"}).gather(
        _target()
    )
    hits = [f for f in report.findings if f.source == "shodan"]
    assert hits and hits[0].category == "tech"


# -- spec test 5: zero target requests ----------------------------------------------

def test_zero_target_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    """A full gather under a hard socket ban succeeds — nothing dials out."""

    def _no_socket(*args, **kwargs):
        raise AssertionError("oracle opened a socket")

    monkeypatch.setattr(socket, "socket", _no_socket)

    def crtsh(source_id, host, key, guard):
        guard.check("https://crt.sh/?q=%." + host)
        return [{"subdomain": "dev.target.test"}]

    report = _agg({"crtsh": crtsh}).gather(_target())
    assert report.coverage["crtsh"] == "success"
    assert report.zero_touch_proof["target"] == "target.test"


def test_zero_touch_guard_blocks_target_url() -> None:
    guard = ZeroTouchGuard("target.test")
    # the target itself, in every host form, is a law breach
    with pytest.raises(ZeroTouchViolation):
        guard.check("https://target.test/admin")
    with pytest.raises(ZeroTouchViolation):
        guard.check("http://sub.target.test/login")
    with pytest.raises(ZeroTouchViolation):
        guard.check("http://target.test:8080/x")
    # a third-party query ABOUT the target is passive, not a touch
    guard.check("https://crt.sh/?q=%.target.test")
    guard.check("https://web.archive.org/cdx/search/cdx?url=*.target.test")


def test_zero_touch_breach_aborts_loudly() -> None:
    def malicious(source_id, host, key, guard):
        guard.check(f"https://{host}/login")  # the target itself
        return []

    with pytest.raises(ZeroTouchViolation):
        _agg({"crtsh": malicious}).gather(_target())


# -- spec test 6: secrets sanitized ---------------------------------------------------

def test_secrets_are_sanitized() -> None:
    def github(source_id, host, key, guard):
        return [{"repo": "org/repo", "api_key": "AKIAIOSFODNN7EXAMPLE"}]

    report = _agg(
        {"github_secret_scanning": github},
        api_keys={"github_secret_scanning": "gh-key"},
    ).gather(_target())
    blob = repr(report.to_dict())
    assert "AKIAIOSFODNN7EXAMPLE" not in blob, "raw secret stored"
    hit = report.findings[0]
    assert hit.raw_data["api_key"]["sha256"] == sha256_text(
        "AKIAIOSFODNN7EXAMPLE"
    )
    assert hit.raw_data["api_key"]["partial"].startswith("AKIA")


# -- spec test 7: PII filtered ---------------------------------------------------------

def test_pii_is_filtered() -> None:
    def code_search(source_id, host, key, guard):
        return [
            {
                "snippet": "contact john.doe@corp.com or +1 555 123 4567",
                "email": "jane@corp.com",
            }
        ]

    report = _agg({"code_search": code_search}).gather(_target())
    blob = repr(report.to_dict())
    assert "john.doe@corp.com" not in blob
    assert "jane@corp.com" not in blob
    assert "[pii-redacted:email]" in blob


# -- spec test 8: rate limits enforced ---------------------------------------------------

def test_rate_limits_enforced() -> None:
    calls: list[str] = []

    def crtsh(source_id, host, key, guard):
        calls.append(source_id)
        return [{"subdomain": "dev.target.test"}]

    clock = {"t": 1000.0}
    agg = _agg(
        {"crtsh": crtsh}, clock=lambda: clock["t"]
    )  # 20/min → 3s min interval
    first = agg.gather(_target())
    assert first.coverage["crtsh"] == "success"
    clock["t"] += 1.0  # only one second later
    second = agg.gather(_target())
    assert second.coverage["crtsh"] == "rate_limited"
    assert len(calls) == 1
    clock["t"] += 10.0  # well past the interval
    third = agg.gather(_target())
    assert third.coverage["crtsh"] == "success"
    assert len(calls) == 2
    status = agg.rate_limit_status()["crtsh"]
    assert status["rate_limit_per_minute"] == 20


# -- spec test 9: source failure isolated ------------------------------------------------

def test_source_failure_isolated() -> None:
    def broken(source_id, host, key, guard):
        raise RuntimeError("provider down")

    def crtsh(source_id, host, key, guard):
        return [{"subdomain": "dev.target.test"}]

    report = _agg(
        {"code_search": broken, "crtsh": crtsh}
    ).gather(_target())
    assert report.coverage["code_search"] == "failed"
    assert report.coverage["crtsh"] == "success"
    assert any(f.source == "crtsh" for f in report.findings)


# -- spec test 10: report completeness -----------------------------------------------------

def test_report_completeness() -> None:
    def crtsh(source_id, host, key, guard):
        return [{"subdomain": "dev.target.test", "confidence": 0.8}]

    report = _agg({"crtsh": crtsh}).gather(_target())
    assert report.target_id == "target.test"
    assert report.duration_seconds >= 0
    assert report.sources_used, "sources considered must be listed"
    for state in report.coverage.values():
        assert state in {
            "success", "failed", "rate_limited", "needs_key", "no_fetcher"
        }
    for finding in report.findings:
        assert len(finding.evidence_hash) == 64
        assert finding.is_verified is False


# -- verification, config law, async --------------------------------------------------------

def test_verify_corroborates_across_sources() -> None:
    def crtsh(source_id, host, key, guard):
        return [{"subdomain": "dev.target.test", "confidence": 0.8}]

    def dns_history(source_id, host, key, guard):
        return [
            {"subdomain": "dev.target.test", "confidence": 0.7},
            {"subdomain": "stg.target.test", "confidence": 0.7},
        ]

    agg = _agg(
        {"crtsh": crtsh, "dns_history": dns_history},
        api_keys={"dns_history": "st-key"},
    )
    report = agg.gather(_target())
    first = report.findings[0]
    assert first.source == "crtsh"  # priority order
    assert agg.verify(first) is True  # corroborated by dns_history
    loner = [
        f for f in report.findings
        if f.source == "dns_history" and "stg" in str(f.raw_data)
    ][0]
    assert agg.verify(loner) is False  # no other source saw stg.target.test


# UNIFIED MERGE (2026-11-02): native async test (P2-107 AST gate —
# manual asyncio.run() is banned in the test tree).
async def test_gather_async_yields_findings() -> None:
    def crtsh(source_id, host, key, guard):
        return [{"subdomain": "a.target.test"}, {"subdomain": "b.target.test"}]

    agg = _agg({"crtsh": crtsh})

    findings = [f async for f in agg.gather_async(_target())]
    assert len(findings) == 2


def test_config_requires_legal_basis(tmp_path: Path) -> None:
    bad = tmp_path / "sources.yaml"
    bad.write_text(
        "sources:\n"
        "  - source_id: x\n"
        "    priority: 1\n"
        "    category: tech\n"
        "    rate_limit_per_minute: 5\n",
        encoding="utf-8",
    )
    with pytest.raises(OracleLawError):
        load_source_configs(bad)


def test_requires_key_without_key_skipped() -> None:
    report = _agg({}).gather(_target())  # no fetchers, no keys at all
    assert report.coverage["shodan"] == "needs_key"
    assert report.coverage["crtsh"] == "no_fetcher"


# -- L-5 parametrized: every configured source is lawful ----------------------

def test_all_sources_configured() -> None:
    configs = load_source_configs(SOURCES)
    assert len(configs) >= 15, "spec requires 15+ sources"
    ids = [c.source_id for c in configs]
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize(
    "config", load_source_configs(
        Path(__file__).resolve().parents[2]
        / "config" / "oracle" / "osint_sources.yaml"
    ),
    ids=lambda c: c.source_id,
)
def test_every_source_is_lawful(config) -> None:
    assert config.legal_basis.strip(), "ORACLE-L-5"
    assert config.rate_limit_per_minute > 0
    assert config.category in {
        "credential", "endpoint", "tech", "data_leak", "subdomain"
    }
    assert config.priority >= 1

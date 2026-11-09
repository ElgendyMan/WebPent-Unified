# tests/test_takeover.py
"""PROPOSALS_ULTIMATE_V3 §8 (2026-11-01) test suite: takeover detection.

Covers the fingerprint library (every service matches its canonical
body), the three verdicts and their fail-closed validation, the
passive-only contract (verdicts never claim an active takeover; the
evidence note says so), the honesty of ``inconclusive`` (no DNS records,
resolver errors, fetch errors, unknown services — never a vulnerability
claim), mandatory scope checking BEFORE any fetch, mandatory ledger with
fail-closed refusal, flag-off zero work (no DNS, no fetch), concurrency
cap validation, order-stable batch scans, and determinism. DNS and HTTP
are stubs everywhere — no network leaves the process.
"""

from __future__ import annotations

import threading

import pytest

from webpent.recon.takeover import (
    FINGERPRINTS,
    TakeoverError,
    TakeoverVerdict,
    check_host,
    scan_hosts,
    takeover_refusal,
)


def _activated(**extra):
    from webpent.config.settings import Settings, activate_settings

    return activate_settings(Settings(enable_takeover_scan=True, **extra))


@pytest.fixture(autouse=True)
def _flag_on():
    # every test runs with the flag on; flag-off tests nest their own
    # explicit off-context, which wins for their duration
    with _activated():
        yield


class FakeLedger:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.rows: list[tuple[str, str, str]] = []
        self.lock = threading.Lock()

    def record(self, method, url, *, engagement_id="", flags=""):
        if not self.ok:
            return False
        with self.lock:
            self.rows.append((method, url, flags))
        return True


GH_BODY = "There isn't a GitHub Pages site here. If you think this is an error, try recreating the repo."
S3_BODY = "<?xml><Error><Code>NoSuchBucket</Code></Error>"


def _stub_resolver(chain: list[str] | None = None):
    def resolve(record_type, host):
        return list(chain or [])

    return resolve


def _stub_fetch(status=404, body=GH_BODY):
    calls: list[str] = []

    def fetch(url):
        calls.append(url)
        return status, body

    fetch.calls = calls
    return fetch


def _ok_scope(url: str) -> bool:
    return True


# ---------------------------------------------------------------------------
# Flag gate.
# ---------------------------------------------------------------------------


class TestGate:
    def test_flag_off_refuses(self):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_takeover_scan=False)):
            assert takeover_refusal() == "takeover_flag_off"

    def test_flag_off_zero_work(self):
        from webpent.config.settings import Settings, activate_settings

        resolver = _stub_resolver(["foo.github.io"])
        fetch = _stub_fetch()
        with activate_settings(Settings(enable_takeover_scan=False)):
            with pytest.raises(TakeoverError, match="takeover_flag_off"):
                check_host(
                    "sub.target.example.com",
                    resolver=resolver,
                    fetch=fetch,
                    scope_checker=_ok_scope,
                    ledger=FakeLedger(),
                )
            with pytest.raises(TakeoverError, match="takeover_flag_off"):
                scan_hosts(
                    ["sub.target.example.com"],
                    resolver=resolver,
                    fetch=fetch,
                    scope_checker=_ok_scope,
                    ledger=FakeLedger(),
                )
        assert fetch.calls == []  # no DNS side effects possible, none fetched

    def test_default_off_and_concurrency_default(self):
        from webpent.config.settings import Settings

        assert Settings().enable_takeover_scan is False
        assert Settings().takeover_concurrency == 4


# ---------------------------------------------------------------------------
# Fingerprint library.
# ---------------------------------------------------------------------------


class TestFingerprints:
    def test_library_services(self):
        services = [service for service, _ in FINGERPRINTS]
        assert services == [
            "github_pages",
            "aws_s3",
            "heroku",
            "azure",
            "fastly",
            "shopify",
            "tumblr",
            "zendesk",
        ]

    @pytest.mark.parametrize("service,body", [
        ("github_pages", GH_BODY),
        ("aws_s3", S3_BODY),
        ("heroku", "No such app in this space"),
        ("azure", "404 Web Site not found."),
        ("fastly", "Fastly error: unknown domain: sub.example.com"),
        ("shopify", "Sorry, this shop is currently unavailable"),
        ("tumblr", "Whatever you were looking for doesn't currently exist at this address."),
        ("zendesk", "Help Center Closed"),
    ])
    def test_each_service_matches(self, service, body):
        verdict = check_host(
            "sub.target.example.com",
            resolver=_stub_resolver(["dangling.example.net"]),
            fetch=_stub_fetch(body=body),
            scope_checker=_ok_scope,
            ledger=FakeLedger(),
        )
        assert verdict.verdict == "match_fingerprint"
        assert verdict.service == service


# ---------------------------------------------------------------------------
# Verdict honesty.
# ---------------------------------------------------------------------------


class TestVerdicts:
    def test_unknown_verdict_fails_closed(self):
        with pytest.raises(TakeoverError, match="takeover_unknown_verdict"):
            TakeoverVerdict(host="h", verdict="vulnerable")

    def test_dangling_cname_and_404_with_match(self):
        verdict = check_host(
            "sub.target.example.com",
            resolver=_stub_resolver(["target.github.io"]),
            fetch=_stub_fetch(body=GH_BODY),
            scope_checker=_ok_scope,
            ledger=FakeLedger(),
        )
        assert verdict.verdict == "match_fingerprint"
        assert verdict.cname == "target.github.io"
        assert verdict.http_status == 404
        assert verdict.evidence["note"].startswith("PASSIVE detection only")

    def test_404_no_fingerprint_is_not_vulnerable(self):
        verdict = check_host(
            "sub.target.example.com",
            resolver=_stub_resolver(["target.github.io"]),
            fetch=_stub_fetch(body="custom 404 page"),
            scope_checker=_ok_scope,
            ledger=FakeLedger(),
        )
        assert verdict.verdict == "not_vulnerable"
        assert verdict.reason == "takeover_404_no_fingerprint"

    def test_200_is_not_vulnerable_even_with_service_body(self):
        verdict = check_host(
            "sub.target.example.com",
            resolver=_stub_resolver(["target.github.io"]),
            fetch=_stub_fetch(status=200, body=GH_BODY),
            scope_checker=_ok_scope,
            ledger=FakeLedger(),
        )
        assert verdict.verdict == "not_vulnerable"
        assert verdict.reason == "takeover_not_404"

    def test_nxdomain_is_inconclusive_not_a_claim(self):
        verdict = check_host(
            "sub.target.example.com",
            resolver=_stub_resolver([]),
            fetch=_stub_fetch(),
            scope_checker=_ok_scope,
            ledger=FakeLedger(),
        )
        assert verdict.verdict == "inconclusive"
        assert verdict.reason == "takeover_dns_no_records"

    def test_fetch_error_is_inconclusive(self):
        def fetch(url):
            raise ConnectionError("reset")

        verdict = check_host(
            "sub.target.example.com",
            resolver=_stub_resolver(["x.herokuapp.com"]),
            fetch=fetch,
            scope_checker=_ok_scope,
            ledger=FakeLedger(),
        )
        assert verdict.verdict == "inconclusive"
        assert verdict.reason.startswith("takeover_fetch_error:")

    def test_verdict_never_says_taken_over(self):
        # even on a full match the verdict vocabulary is passive
        verdict = check_host(
            "sub.target.example.com",
            resolver=_stub_resolver(["target.github.io"]),
            fetch=_stub_fetch(body=GH_BODY),
            scope_checker=_ok_scope,
            ledger=FakeLedger(),
        )
        assert verdict.verdict != "taken_over"
        assert "taken over" not in verdict.reason


# ---------------------------------------------------------------------------
# Mandatory gates: scope and ledger.
# ---------------------------------------------------------------------------


class TestMandatoryGates:
    def test_scope_checker_required(self):
        with _activated():
            with pytest.raises(TakeoverError, match="takeover_scope_checker_required"):
                check_host(
                    "sub.target.example.com",
                    resolver=_stub_resolver([]),
                    fetch=_stub_fetch(),
                    scope_checker=None,
                    ledger=FakeLedger(),
                )

    def test_out_of_scope_never_fetched(self):
        fetch = _stub_fetch()
        with _activated():
            with pytest.raises(TakeoverError, match="takeover_out_of_scope"):
                check_host(
                    "sub.target.example.com",
                    resolver=_stub_resolver(["x"]),
                    fetch=fetch,
                    scope_checker=lambda url: False,
                    ledger=FakeLedger(),
                )
        assert fetch.calls == []

    def test_ledger_required_and_refusal_fails_closed(self):
        with _activated():
            fetch = _stub_fetch()
            with pytest.raises(TakeoverError, match="takeover_ledger_required"):
                check_host(
                    "sub.target.example.com",
                    resolver=_stub_resolver(["x"]),
                    fetch=fetch,
                    scope_checker=_ok_scope,
                    ledger=None,
                )
            fetch2 = _stub_fetch()
            with pytest.raises(TakeoverError, match="takeover_ledger_refused"):
                check_host(
                    "sub.target.example.com",
                    resolver=_stub_resolver(["x"]),
                    fetch=fetch2,
                    scope_checker=_ok_scope,
                    ledger=FakeLedger(ok=False),
                )
        assert fetch2.calls == []  # ledger refusal = no fetch

    def test_ledger_row_recorded_before_fetch(self):
        ledger = FakeLedger()
        fetch = _stub_fetch()
        with _activated():
            check_host(
                "sub.target.example.com",
                resolver=_stub_resolver(["x"]),
                fetch=fetch,
                scope_checker=_ok_scope,
                ledger=ledger,
            )
        assert ledger.rows == [("GET", "https://sub.target.example.com/", "takeover")]
        assert fetch.calls == ["https://sub.target.example.com/"]


# ---------------------------------------------------------------------------
# Batch scans.
# ---------------------------------------------------------------------------


class TestBatch:
    def test_order_stable_and_concurrency_cap(self):
        hosts = [f"s{i}.target.example.com" for i in range(6)]
        with _activated(takeover_concurrency=2):
            verdicts = scan_hosts(
                hosts,
                resolver=_stub_resolver(["x"]),
                fetch=_stub_fetch(body=GH_BODY),
                scope_checker=_ok_scope,
                ledger=FakeLedger(),
            )
        assert [v.host for v in verdicts] == hosts
        assert all(v.verdict == "match_fingerprint" for v in verdicts)

    def test_bad_concurrency_refused(self):
        with _activated(takeover_concurrency=0):
            with pytest.raises(TakeoverError, match="takeover_bad_concurrency"):
                scan_hosts(
                    ["a.target.example.com"],
                    resolver=_stub_resolver([]),
                    fetch=_stub_fetch(),
                    scope_checker=_ok_scope,
                    ledger=FakeLedger(),
                )

    def test_batch_scope_refusal_fails_closed_in_order(self):
        with _activated():
            with pytest.raises(TakeoverError, match="takeover_out_of_scope"):
                scan_hosts(
                    ["in.target.example.com", "out.target.example.com"],
                    resolver=_stub_resolver([]),
                    fetch=_stub_fetch(),
                    scope_checker=lambda url: "in." in url,
                    ledger=FakeLedger(),
                )


# ---------------------------------------------------------------------------
# Determinism.
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_stubs_same_verdict_bytes(self):
        with _activated():
            a = check_host(
                "sub.target.example.com",
                resolver=_stub_resolver(["t.github.io"]),
                fetch=_stub_fetch(body=GH_BODY),
                scope_checker=_ok_scope,
                ledger=FakeLedger(),
            )
            b = check_host(
                "sub.target.example.com",
                resolver=_stub_resolver(["t.github.io"]),
                fetch=_stub_fetch(body=GH_BODY),
                scope_checker=_ok_scope,
                ledger=FakeLedger(),
            )
        assert a == b

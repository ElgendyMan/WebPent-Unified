"""v83 T3 / U-CEM-3: the scope drift detector."""

from __future__ import annotations

from webpent.autonomous.cem.scope_drift import evaluate, touchable_hosts


def test_in_scope_subdomains_produce_no_drift() -> None:
    report = evaluate(
        scope_entries=["example.com"],
        observed_subdomains=["a.example.com", "b.a.example.com", "example.com"],
    )
    assert report["drifts"] == []
    assert report["out_of_scope_count"] == 0
    assert report["in_scope_count"] == 3
    assert report["highest_severity"] == "none"


def test_out_of_scope_subdomain_is_observed_never_touched() -> None:
    report = evaluate(
        scope_entries=["example.com"],
        observed_subdomains=["safe.example.com", "evil.other.net"],
    )
    drift = report["drifts"][0]
    assert drift["kind"] == "scope_drift"
    assert drift["host"] == "evil.other.net"
    assert drift["touchable"] is False
    assert "out-of-scope" in drift["note"]
    assert touchable_hosts(report) == ["example.com"]


def test_ip_ownership_change_inside_scope_is_high_alert() -> None:
    report = evaluate(
        scope_entries=["example.com"],
        old_dns={"app.example.com": "1.2.3.4"},
        new_dns={"app.example.com": "5.6.7.8"},
    )
    drift = report["drifts"][0]
    assert drift["kind"] == "ip_ownership_change"
    assert drift["severity"] == "high"
    assert drift["from"] == ["1.2.3.4"]
    assert drift["to"] == ["5.6.7.8"]


def test_ip_ownership_outside_scope_is_not_tracked() -> None:
    report = evaluate(
        scope_entries=["example.com"],
        observed_subdomains=["evil.other.net"],
        old_dns={"evil.other.net": "1.1.1.1"},
        new_dns={"evil.other.net": "2.2.2.2"},
    )
    kinds = {d["kind"] for d in report["drifts"]}
    assert kinds == {"scope_drift"}


def test_cert_issuer_change_is_low_alert() -> None:
    report = evaluate(
        scope_entries=["example.com"],
        old_cert_issuer="Let's Encrypt",
        new_cert_issuer="DigiCert",
    )
    drift = report["drifts"][0]
    assert drift["kind"] == "cert_issuer_change"
    assert drift["severity"] == "low"
    assert report["highest_severity"] == "low"


def test_same_issuer_and_stable_dns_are_quiet() -> None:
    report = evaluate(
        scope_entries=["example.com"],
        old_dns={"app.example.com": "1.2.3.4"},
        new_dns={"app.example.com": ["1.2.3.4"]},
        old_cert_issuer="Let's Encrypt",
        new_cert_issuer="Let's Encrypt",
    )
    assert report["drifts"] == []


def test_garbage_inputs_degrade_to_empty_report() -> None:
    for kwargs in (
        {},
        {"scope_entries": None},
        {"scope_entries": 42, "observed_subdomains": "junk", "old_dns": "junk"},
        {
            "scope_entries": ["example.com"],
            "old_dns": {"a.example.com": None},
            "new_dns": {"a.example.com": None},
        },
    ):
        report = evaluate(**kwargs)
        assert isinstance(report, dict)
        assert report["advisory"] is True


def test_bounds_are_enforced() -> None:
    report = evaluate(
        scope_entries=["example.com"],
        observed_subdomains=[f"s{i}.evil.net" for i in range(200)],
    )
    assert report["drift_count"] <= 64
    assert report["out_of_scope_count"] <= 64
    blob_hosts = {d["host"] for d in report["drifts"]}
    assert all("example.com" not in h or h.endswith("example.com") for h in blob_hosts)


def test_scope_matching_is_case_and_dot_safe() -> None:
    report = evaluate(
        scope_entries=["EXAMPLE.com."],
        observed_subdomains=["APP.Example.COM"],
    )
    assert report["drifts"] == []


def test_bare_tld_scope_entry_is_rejected(tmp_path):
    """RT83-4: a scope entry without a dot authorizes nothing (a TLD is never a scope)."""
    report = evaluate(scope_entries=["com"], observed_subdomains=["evil.foo.com"])
    assert report["in_scope_count"] == 0
    assert report["out_of_scope_count"] == 1
    assert touchable_hosts(report) == []


def test_normal_dotted_scope_still_works():
    report = evaluate(scope_entries=["example.com"], observed_subdomains=["app.example.com"])
    assert report["in_scope_count"] == 1
    assert report["out_of_scope_count"] == 0

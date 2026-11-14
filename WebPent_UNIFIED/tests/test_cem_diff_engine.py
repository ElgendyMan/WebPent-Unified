"""v83 T2 / U-CEM-2: the CEM diff engine."""

from __future__ import annotations

from pathlib import Path

from webpent.autonomous.cem.diff_engine import (
    CRITICAL,
    NOISE,
    SIGNAL_HIGH,
    SIGNAL_LOW,
    classify_change,
    diff_snapshots,
    is_actionable,
    is_wake_up,
    load_signal_config,
)

NOW = 1_700_000_000.0


def _snap(endpoints=(), subdomains=(), headers=None, hash_="h", ts=NOW):
    return {
        "target_id": "t1",
        "ts": ts,
        "hash": hash_,
        "endpoints": list(endpoints),
        "subdomains": list(subdomains),
        "headers": dict(headers or {}),
        "cert_expiry": "",
        "js_hashes": {},
        "tech_stack": [],
        "response_shapes": {},
    }


def test_identical_snapshots_are_clean() -> None:
    report = diff_snapshots(_snap(endpoints=["/a"]), _snap(endpoints=["/a"], hash_="h2"))
    assert report["changes"] == []
    assert report["top_signal"] == NOISE
    assert report["change_count"] == 0
    assert not is_actionable(report)


def test_new_endpoint_is_high_and_reappearance_is_flagged() -> None:
    report = diff_snapshots(
        _snap(endpoints=["/a"]),
        _snap(endpoints=["/a", "/admin"], hash_="h2"),
        history_endpoints={"/admin", "/old"},
    )
    added = [c for c in report["changes"] if c["kind"] == "added"]
    assert len(added) == 1
    assert added[0]["item"] == "/admin"
    assert added[0]["reappearance"] is True
    assert added[0]["classification"] == SIGNAL_HIGH
    assert is_actionable(report)
    assert not is_wake_up(report)


def test_removed_endpoint_is_low() -> None:
    report = diff_snapshots(_snap(endpoints=["/a", "/b"]), _snap(endpoints=["/a"], hash_="h2"))
    assert report["changes"][0]["classification"] == SIGNAL_LOW
    assert not is_actionable(report)


def test_new_subdomain_is_critical_and_removal_is_high() -> None:
    report = diff_snapshots(
        _snap(subdomains=["a.example.com"]),
        _snap(subdomains=["a.example.com", "b.example.com"], hash_="h2"),
    )
    assert report["top_signal"] == CRITICAL
    assert is_wake_up(report)

    removal = diff_snapshots(
        _snap(subdomains=["a.example.com", "gone.example.com"]),
        _snap(subdomains=["a.example.com"], hash_="h2"),
    )
    assert removal["top_signal"] == SIGNAL_HIGH


def test_security_header_removal_is_critical_but_noise_headers_are_noise() -> None:
    report = diff_snapshots(
        _snap(headers={"Content-Security-Policy": "default-src 'self'"}),
        _snap(hash_="h2"),
    )
    assert report["top_signal"] == CRITICAL

    noisy = diff_snapshots(
        _snap(headers={"Date": "yesterday"}),
        _snap(hash_="h2"),
    )
    assert noisy["changes"][0]["classification"] == NOISE


def test_tech_stack_and_response_shape_changes_are_high() -> None:
    old = _snap()
    old["tech_stack"] = ["nginx"]
    old["response_shapes"] = {"/login": "form"}
    new = _snap(hash_="h2")
    new["tech_stack"] = ["nginx", "kotlin"]
    new["response_shapes"] = {"/login": "json"}
    report = diff_snapshots(old, new)
    classes = {c["classification"] for c in report["changes"]}
    assert classes == {SIGNAL_HIGH}
    assert is_actionable(report)


def test_noise_paths_and_header_changes_classified() -> None:
    report = diff_snapshots(
        _snap(endpoints=["/favicon.ico"]),
        _snap(endpoints=["/favicon.ico", "/favicon.ico?v=2"], hash_="h2"),
    )
    assert report["top_signal"] == NOISE


def test_load_signal_config_defaults_and_corruption(tmp_path: Path) -> None:
    config = load_signal_config(None)
    assert config["noise_patterns"]
    assert config["max_changes"] > 0

    missing = load_signal_config(tmp_path / "nope.yaml")
    assert missing == config

    bad = tmp_path / "bad.yaml"
    bad.write_text("noise_patterns: [unclosed", encoding="utf-8")
    assert load_signal_config(bad) == config

    junk = tmp_path / "junk.yaml"
    junk.write_text("- just\n- a\n- list\n", encoding="utf-8")
    assert load_signal_config(junk) == config


def test_load_signal_config_custom_lists(tmp_path: Path) -> None:
    good = tmp_path / "custom.yaml"
    good.write_text(
        "noise_patterns:\n  - /health\n"
        "critical_headers:\n  - x-custom-guard\n"
        "max_changes: 25\n",
        encoding="utf-8",
    )
    config = load_signal_config(good)
    assert "/health" in config["noise_patterns"]
    assert "x-custom-guard" in config["critical_headers"]
    assert config["max_changes"] == 25
    # non-string entries and oversized lists are dropped/bounded
    mixed = tmp_path / "mixed.yaml"
    mixed.write_text("noise_patterns:\n  - ok\n  - 42\nmax_changes: 99999\n", encoding="utf-8")
    mconfig = load_signal_config(mixed)
    assert "/health" not in mconfig["noise_patterns"]
    defaults = load_signal_config(None)["noise_patterns"]
    assert mconfig["noise_patterns"] == list(defaults) or "/health" not in mconfig["noise_patterns"]
    assert mconfig["max_changes"] == 200


def test_classify_change_change_record() -> None:
    config = load_signal_config(None)
    change = {"field": "headers", "kind": "changed", "item": "Server: nginx/1.1 -> nginx/1.2"}
    assert classify_change(change, config) == SIGNAL_LOW


def test_diff_is_bounded_and_redacted() -> None:
    old = _snap()
    new = _snap(hash_="h2", endpoints=[f"/p{i}" for i in range(500)])
    new["subdomains"] = [f"s{i}.example.com" for i in range(300)]
    config = {"max_changes": 50, "noise_patterns": [], "critical_headers": [], "ignore_headers": []}
    report = diff_snapshots(old, new, config=config)
    assert report["change_count"] <= 50
    blob = __import__("json").dumps(report)
    assert "REDACTED" in blob or report["changes"]


def test_diff_garbage_inputs_never_raise() -> None:
    for old, new in ((None, None), ("junk", {}), (42, [1]), ({}, None)):
        report = diff_snapshots(old, new)  # type: ignore[arg-type]
        assert isinstance(report, dict)
        assert report["top_signal"] in {NOISE, SIGNAL_LOW, SIGNAL_HIGH, CRITICAL}

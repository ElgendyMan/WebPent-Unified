"""v82 Task 5: CT log mining (crt.sh shape, injected fetch)."""

from __future__ import annotations

import json

from webpent.autonomous.amplifiers.ct_mining import mine_ct_logs

DOC = [
    {"name_value": "dev.lab.example\ntest.lab.example", "common_name": "dev.lab.example"},
    {"name_value": "lab.example"},  # apex: not a subdomain candidate
    {"name_value": "evil.other.example"},  # out of scope
    {"name_value": "dev.lab.example"},  # duplicate
]


def test_mines_unique_in_scope_subdomains() -> None:
    report = mine_ct_logs(
        "https://lab.example/", fetch_text=lambda url: json.dumps(DOC)
    )
    names = [item["subdomain"] for item in report["candidates"]]
    assert sorted(names) == ["dev.lab.example", "test.lab.example"]
    assert all(item["advisory"] is True for item in report["candidates"])


def test_out_of_scope_and_apex_are_excluded() -> None:
    report = mine_ct_logs(
        "https://lab.example/", fetch_text=lambda url: json.dumps(DOC)
    )
    names = [item["subdomain"] for item in report["candidates"]]
    assert "lab.example" not in names
    assert "evil.other.example" not in names


def test_fetch_failure_and_bad_json_degrade() -> None:
    def boom(url: str) -> str:
        raise OSError("offline")

    failed = mine_ct_logs("https://lab.example/", fetch_text=boom)
    assert failed["reason"].startswith("fetch_failed")
    assert mine_ct_logs(
        "https://lab.example/", fetch_text=lambda url: "{not json"
    )["reason"] == "bad_json"


def test_bad_target_yields_nothing() -> None:
    assert mine_ct_logs("not a url", fetch_text=lambda url: "[]")["reason"] == "bad_target"

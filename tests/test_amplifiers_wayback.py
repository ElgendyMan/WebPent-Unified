"""v82 Task 3: historical endpoint tracker (CDX parsing, injected fetch)."""

from __future__ import annotations

from webpent.autonomous.amplifiers.wayback import historical_endpoints, parse_cdx

CDX = """http://lab.example/admin/legacy 200 20200101
http://lab.example/api/v0/users?secret=zzz 200 20200201
http://lab.example/ok
https://other.example/not-ours 200 20200301
not-a-url
http://lab.example/admin/legacy 200 20210101
"""


def test_parses_unique_in_origin_paths_and_strips_queries() -> None:
    paths = parse_cdx(CDX, target_origin="http://lab.example/")
    assert paths.count("/admin/legacy") == 1  # deduped
    assert "/api/v0/users" in paths
    assert "/ok" in paths
    assert all(not p.startswith("http") for p in paths)
    assert all("secret" not in p for p in paths)  # no query values
    assert all(not p.startswith("/not-ours") for p in paths)


def test_empty_target_origin_yields_nothing() -> None:
    assert parse_cdx(CDX, target_origin="not a url") == []


def test_fetch_failure_degrades_gracefully() -> None:
    def boom(url: str) -> str:
        raise OSError("offline")

    report = historical_endpoints("http://lab.example/", fetch_text=boom)
    assert report["candidates"] == []
    assert report["reason"].startswith("fetch_failed")


def test_candidates_are_marked_advisory() -> None:
    report = historical_endpoints(
        "http://lab.example/", fetch_text=lambda url: CDX
    )
    assert report["advisory"] is True
    assert all(item["source"] == "wayback" for item in report["candidates"])
    assert report["count"] == len(report["candidates"]) >= 2

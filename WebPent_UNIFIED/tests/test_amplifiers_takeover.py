"""v82 Task 1: subdomain takeover scanner (advisory, injected fetchers)."""

from __future__ import annotations

from typing import Any

from webpent.autonomous.amplifiers.takeover import (
    SERVICE_FINGERPRINTS,
    scan_takeover,
)


def _dns_map(mapping: dict[str, list[str]], fail: set[str] = frozenset()) -> Any:
    def fetch(host: str) -> list[str]:
        if host in fail:
            raise OSError("resolver down")
        return mapping.get(host, [])

    return fetch


def test_dangling_github_pages_is_reported() -> None:
    dns = _dns_map({"lost.example": ["lost.example.github.io"]})
    body = {"lost.example.github.io": "There isn't a GitHub Pages site here."}

    def resp(name: str) -> list[str]:
        return [body.get(name, "")]

    report = scan_takeover(["lost.example"], fetch_dns=dns, fetch_response=resp)
    assert report["scanned"] == 1
    assert len(report["candidates"]) == 1
    item = report["candidates"][0]
    assert item["service"] == "github-pages"
    assert item["verdict"] == "dangling_fingerprint"
    assert item["advisory"] is True


def test_pointed_but_alive_is_not_dangling() -> None:
    dns = _dns_map({"app.example": ["app.example.herokuapp.com"]})

    def resp(name: str) -> list[str]:
        return ["Welcome to a healthy app"]

    report = scan_takeover(["app.example"], fetch_dns=dns, fetch_response=resp)
    assert report["candidates"] == []


def test_resolver_failure_degrades_to_error_not_exception() -> None:
    dns = _dns_map({}, fail={"broken.example"})
    report = scan_takeover(["broken.example"], fetch_dns=dns)
    assert report["errors"] == 1
    assert report["candidates"] == []


def test_no_cname_and_bounds_are_honest() -> None:
    dns = _dns_map({})
    report = scan_takeover(
        [f"host{i}.example" for i in range(200)], fetch_dns=dns
    )
    assert report["candidates"] == []
    assert report["scanned"] == 128  # MAX_HOSTS bound


def test_no_network_by_default_and_no_secrets_leak() -> None:
    # The module never opens a socket: with doubles only, the scan is pure.
    dns = _dns_map({"s.example": ["s.example.s3.amazonaws.com"]})
    body = {"s.example.s3.amazonaws.com": "The specified bucket does not exist"}

    def resp(name: str) -> list[str]:
        return [body.get(name, "x?token=supersecret")]

    report = scan_takeover(["s.example"], fetch_dns=dns, fetch_response=resp)
    assert report["candidates"][0]["service"] == "s3"
    assert "supersecret" not in str(report)
    assert len(SERVICE_FINGERPRINTS) >= 10

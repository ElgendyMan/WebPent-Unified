"""v82 Task 2: cloud storage permutation + classification (pure)."""

from __future__ import annotations

from webpent.autonomous.amplifiers.cloud_storage import (
    MAX_PERMUTATIONS,
    bucket_permutations,
    bucket_urls,
    classify_bucket,
    scan_buckets,
)


def test_permutations_are_bounded_and_clean() -> None:
    labels = bucket_permutations("Acme Corp", extra_words=["secret"])
    assert labels and len(labels) <= MAX_PERMUTATIONS
    assert "acmecorp-secret" in labels
    assert all(" " not in label for label in labels)


def test_empty_or_odd_company_yields_nothing() -> None:
    assert bucket_permutations("") == []
    assert bucket_permutations("!!!") == []


def test_classify_open_s3_list() -> None:
    result = classify_bucket(
        "https://acme-backup.s3.amazonaws.com/",
        lambda url: "<ListBucketResult><Name>acme-backup</Name>",
    )
    assert result["verdict"] == "open_list"
    assert result["advisory"] is True


def test_classify_protected_and_missing() -> None:
    protected = classify_bucket(
        "https://acme-dev.s3.amazonaws.com/", lambda url: "<Error><Code>AccessDenied</Code>"
    )
    missing = classify_bucket(
        "https://nope-bucket.s3.amazonaws.com/", lambda url: "<Code>NoSuchBucket</Code>"
    )
    assert protected["verdict"] == "protected"
    assert missing["verdict"] == "missing"


def test_fetch_failure_degrades_to_unknown() -> None:
    def boom(url: str) -> str:
        raise OSError("offline")

    result = classify_bucket("https://x.s3.amazonaws.com/", boom)
    assert result["verdict"] == "unknown"
    assert result["reason"].startswith("fetch_failed")


def test_scan_buckets_report_shape_and_no_promotion() -> None:
    bodies = {
        "https://acme-assets.s3.amazonaws.com": "<ListBucketResult>",
        "https://acme-logs.s3.amazonaws.com": "<Code>AccessDenied</Code>",
    }
    report = scan_buckets(
        bucket_urls(["acme-assets", "acme-logs"]),
        fetch_body=lambda u: bodies.get(u, "<Code>NoSuchBucket</Code>"),
    )
    assert report["advisory"] is True
    assert report["verdicts"].get("open_list", 0) >= 1
    assert all(item["advisory"] is True for item in report["open_candidates"])


def test_bucket_urls_cover_all_providers() -> None:
    urls = bucket_urls(["acme-prod"])
    assert "https://acme-prod.s3.amazonaws.com" in urls
    assert "https://storage.googleapis.com/acme-prod/" in urls
    assert "https://blob.core.windows.net/acme-prod/" in urls

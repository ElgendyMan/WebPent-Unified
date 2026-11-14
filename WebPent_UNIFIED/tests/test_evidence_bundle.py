# tests/test_evidence_bundle.py
"""PROPOSALS_ULTIMATE_V2 §7 (2026-10-29) test suite: evidence bundles.

Covers the HAR reconstruction (valid 1.2 shape, honest incompleteness
metadata, chronological order), the secret-free poc.sh renderer, the
honest cvss.json (v3.1 kept, v4 absence documented), deterministic
byte-identical ZIP rebuilds with a per-entry sha256 manifest, the size
budget fail-closed, dedupe merging same-root/same-class chains, and the
external-submission gate refusing on every missing precondition.
"""

from __future__ import annotations

import json
import shlex
import zipfile
from datetime import datetime, timezone

import pytest

from webpent.reporter.evidence_bundle import (
    EvidenceBundleError,
    SubmissionRefused,
    build_cvss_json,
    build_evidence_bundle,
    build_poc_sh,
    build_requests_har,
    dedupe_findings,
    maybe_build_evidence_bundle,
    platform_submission_payload,
    root_endpoint_of,
    submit_bundle,
)
from webpent.config.settings import Settings

WHEN = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)


def _ledger_rows() -> list[dict[str, object]]:
    return [
        {"ts": 1_100.0, "method": "post", "url": "https://t/api/login"},
        {"ts": 1_000.0, "method": "GET", "url": "https://t/"},
    ]


def _finding() -> dict[str, object]:
    return {
        "finding_id": "F-1",
        "vuln_class": "sql_injection",
        "url": "https://t/api/login",
        "cvss_score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N | 9.8",
    }


def _chains() -> list[list[dict[str, object]]]:
    return [
        [{"url": "https://t/api/login", "method": "POST"}],
        [{"url": "https://t/api/login", "method": "POST"},
         {"url": "https://t/api/admin", "method": "GET"}],
    ]


class TestHar:
    def test_valid_har_shape_chronological(self) -> None:
        har = build_requests_har(_ledger_rows(), engagement_id="E-9")
        log = har["log"]
        assert log["version"] == "1.2"
        entries = log["entries"]
        assert [e["request"]["method"] for e in entries] == ["GET", "POST"]
        assert entries[0]["request"]["url"] == "https://t/"
        assert entries[0]["startedDateTime"].startswith("1970-01-01T00:16:40")

    def test_incompleteness_is_explicit(self) -> None:
        har = build_requests_har(_ledger_rows())
        meta = har["log"]["_meta"]["ledger_completeness"]
        assert meta["fields_recorded"] == ["ts", "method", "url"]
        assert "response body" in meta["fields_missing"]
        assert meta["warning"]
        assert har["log"]["entries"][0]["response"]["status"] == 0

    def test_invalid_rows_skipped(self) -> None:
        har = build_requests_har([{"ts": 1.0, "method": "", "url": ""}])
        assert har["log"]["entries"] == []


class TestPoc:
    def test_steps_rendered_secret_free(self) -> None:
        script = build_poc_sh(
            [
                {"number": 1, "method": "POST", "url": "https://t/api?id=1'",
                 "description": "inject probe"},
                {"number": 2, "method": "GET", "url": "https://t/api/admin"},
            ]
        )
        assert script.startswith("#!/bin/sh\nset -eu\n")
        assert "curl -sS -o /dev/null" in script
        assert shlex.quote("https://t/api?id=1'") in script
        assert "inject probe" in script

    def test_no_steps_neutral_script(self) -> None:
        script = build_poc_sh([])
        assert "no reproduction steps" in script


class TestCvss:
    def test_v31_kept_and_v4_absence_documented(self) -> None:
        doc = build_cvss_json(_finding())
        assert doc["cvss_version"] == "3.1"
        assert doc["vector"].startswith("CVSS:3.1/")
        assert doc["base_score"] == "9.8"
        assert "not produced" in doc["note"]

    def test_missing_vector_warns(self) -> None:
        doc = build_cvss_json({"vuln_class": "xss"})
        assert doc["vector"] is None
        assert "no CVSS vector" in doc["warning"]


class TestRootAndDedupe:
    def test_root_is_first_inbound_endpoint(self) -> None:
        assert root_endpoint_of(_finding(), _chains()) == "https://t/api/login"
        assert root_endpoint_of({"url": "https://t/fallback"}) == "https://t/fallback"

    def test_same_class_same_root_merges(self) -> None:
        groups = dedupe_findings(
            [
                {**_finding(), "finding_id": "F-1", "chains": _chains()},
                {**_finding(), "finding_id": "F-2", "chains": _chains()},
                {
                    "finding_id": "F-3",
                    "vuln_class": "sql_injection",
                    "url": "https://t/other",
                    "chains": [[{"url": "https://t/other"}]],
                },
            ]
        )
        assert len(groups) == 2
        merged = groups[0]
        assert merged["finding_ids"] == ["F-1", "F-2"]
        assert merged["root_endpoint"] == "https://t/api/login"
        assert groups[1]["root_endpoint"] == "https://t/other"

    def test_different_class_same_root_stays_split(self) -> None:
        groups = dedupe_findings(
            [
                _finding(),
                {**_finding(), "vuln_class": "idOR"},
            ]
        )
        assert len(groups) == 2


class TestBundle:
    def test_zip_entries_and_manifest_digests(self) -> None:
        result = build_evidence_bundle(
            _finding(),
            ledger_entries=_ledger_rows(),
            browser_observations=[{"screenshot_digest": "sha256:aa", "replayable": True}],
            reproduction_steps=[{"number": 1, "method": "POST", "url": "https://t/api"}],
            chains=_chains(),
            engagement_id="E-9",
            generated_at=WHEN,
        )
        with zipfile.ZipFile(io_bytes(result.zip_bytes)) as archive:
            names = archive.namelist()
            assert names == [
                "bundle.json",
                "requests.har",
                "screenshots/browser_proof.json",
                "poc.sh",
                "cvss.json",
            ]
            manifest = json.loads(archive.read("bundle.json"))
            for entry in manifest["entries"]:
                payload = archive.read(entry["path"])
                assert len(payload) == entry["size"]
                import hashlib

                assert hashlib.sha256(payload).hexdigest() == entry["sha256"]
        assert result.root_endpoint == "https://t/api/login"
        assert manifest["finding_id"] == "F-1"

    def test_rebuild_is_byte_identical(self) -> None:
        kwargs = dict(
            ledger_entries=_ledger_rows(),
            browser_observations=[{"screenshot_digest": "sha256:aa"}],
            reproduction_steps=[{"number": 1, "method": "GET", "url": "https://t/"}],
            chains=_chains(),
            engagement_id="E-9",
            generated_at=WHEN,
        )
        first = build_evidence_bundle(_finding(), **kwargs)
        second = build_evidence_bundle(_finding(), **kwargs)
        assert first.zip_bytes == second.zip_bytes

    def test_budget_fail_closed(self) -> None:
        with pytest.raises(EvidenceBundleError):
            build_evidence_bundle(_finding(), ledger_entries=_ledger_rows(), max_bytes=100)

    def test_warnings_surface_honestly(self) -> None:
        result = build_evidence_bundle(
            {"finding_id": "F-2", "vuln_class": "xss", "url": "https://t/"},
            generated_at=WHEN,
        )
        assert any("zero entries" in w for w in result.warnings)
        assert any("no observations" in w for w in result.warnings)
        assert any("no reproduction steps" in w for w in result.warnings)
        assert any("no CVSS vector" in w for w in result.warnings)


def io_bytes(payload: bytes):  # noqa: ANN001 - test helper
    import io

    return io.BytesIO(payload)


class TestSubmissionGate:
    def _report(self) -> object:
        from webpent.reporter.bounty_report import BountyReport

        return BountyReport(
            report_id="R-1",
            finding_id="F-1",
            campaign_id="C-1",
            title="t",
            severity="critical",
            cvss_score=9.8,
            cvss_justification="j",
            description="d",
            steps_to_reproduce=[],
            evidence={},
            impact="i",
            remediation="r",
            supporting_material={},
            generated_at=WHEN.isoformat(),
        )

    def test_flag_off_refused(self) -> None:
        with pytest.raises(SubmissionRefused):
            submit_bundle(
                self._report(), enable_external_submission=False,
                approval_recorded=True, engagement_id="E-9",
            )

    def test_no_approval_refused_even_with_flag(self) -> None:
        with pytest.raises(SubmissionRefused):
            submit_bundle(
                self._report(), enable_external_submission=True,
                approval_recorded=False, engagement_id="E-9",
            )

    def test_no_engagement_refused(self) -> None:
        with pytest.raises(SubmissionRefused):
            submit_bundle(
                self._report(), enable_external_submission=True,
                approval_recorded=True, engagement_id="",
            )

    def test_approval_and_flag_pass_with_payload(self) -> None:
        payload = submit_bundle(
            self._report(), enable_external_submission=True,
            approval_recorded=True, engagement_id="E-9",
        )
        assert payload["report_id"] == "R-1"

    def test_payload_requires_report_id(self) -> None:
        with pytest.raises(EvidenceBundleError):
            platform_submission_payload({"title": "t"})


class TestFlagGate:
    def test_flag_off_returns_none(self) -> None:
        settings = Settings()
        assert settings.enable_evidence_bundle is False
        assert settings.enable_external_submission is False
        assert maybe_build_evidence_bundle(_finding(), settings=settings) is None

    def test_flag_on_builds_with_settings_budget(self) -> None:
        settings = Settings(
            enable_evidence_bundle=True,
            evidence_bundle_max_bytes=1_000_000,
        )
        result = maybe_build_evidence_bundle(
            _finding(), settings=settings, ledger_entries=_ledger_rows(),
            generated_at=WHEN,
        )
        assert result is not None
        assert result.zip_bytes

    def test_zero_budget_refused(self) -> None:
        settings = Settings(enable_evidence_bundle=True, evidence_bundle_max_bytes=1_000)
        fat_ledger = [
            {"ts": float(i), "method": "GET", "url": f"https://t/path/{i}/?q=abcdefghij"}
            for i in range(200)
        ]
        with pytest.raises(EvidenceBundleError):
            maybe_build_evidence_bundle(
                _finding(), settings=settings, ledger_entries=fat_ledger
            )

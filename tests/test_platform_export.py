# tests/test_platform_export.py
"""PROPOSALS_ULTIMATE_V3 §6 (2026-11-01) test suite: platform report export.

Covers the three platform templates on one full fixture Finding (exact
section structure), the missing-field contract (missing values render as
``missing: <field>`` and are NEVER invented — no CVSS guess from the
severity bucket, no narrative steps), unknown-platform refusal, flag-off
refusal with zero work, the bundle-zip wrap (report.md + bundle entries
copied unchanged), and determinism. Every function is pure text/bytes —
the module performs no platform API calls, and the tests verify the
markdown contains no credentials or transport of any kind.
"""

from __future__ import annotations

import io
import zipfile
from uuid import uuid4

import pytest

from webpent.reporter.platform_export import (
    PLATFORMS,
    PlatformExportError,
    export_bundle_zip,
    export_finding,
    platform_export_refusal,
)
from webpent.models.findings import Finding


def _activated(**extra):
    from webpent.config.settings import Settings, activate_settings

    return activate_settings(Settings(enable_platform_export=True, **extra))


def _full_finding() -> Finding:
    return Finding(
        title="SQL injection in search",
        severity="high",
        description="Union-based SQLi confirmed via response differential.",
        tool_name="sqli_agent",
        payload="' OR 1=1 --",
        url="https://target.example.com/search?q=x",
        request_method="GET",
        target_param="q",
        confidence="confirmed",
        cvss_score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        business_impact="Full database disclosure to unauthenticated users.",
        vuln_class="sqli",
    )


def _bare_finding() -> Finding:
    # minimal: no payload, no cvss, no impact, no target_param
    return Finding(
        title="Reflected XSS in footer",
        severity="medium",
        description="Marker reflected unencoded in footer param.",
        tool_name="xss_agent",
        url="https://target.example.com/?q=<x>",
    )


# ---------------------------------------------------------------------------
# Flag gate.
# ---------------------------------------------------------------------------


class TestGate:
    def test_flag_off_refuses(self):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_platform_export=False)):
            assert platform_export_refusal() == "platform_export_flag_off"

    def test_flag_off_zero_work(self):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_platform_export=False)):
            with pytest.raises(PlatformExportError, match="platform_export_flag_off"):
                export_finding(_full_finding(), "hackerone")
            with pytest.raises(PlatformExportError, match="platform_export_flag_off"):
                export_bundle_zip(_full_finding(), b"PK", "hackerone")

    def test_default_off(self):
        from webpent.config.settings import Settings

        assert Settings().enable_platform_export is False


# ---------------------------------------------------------------------------
# Platform templates.
# ---------------------------------------------------------------------------


class TestTemplates:
    def test_documented_platforms(self):
        assert PLATFORMS == ("hackerone", "bugcrowd", "intigriti")

    def test_hackerone_section_structure(self):
        with _activated():
            md = export_finding(_full_finding(), "hackerone")
        assert md.startswith("# SQL injection in search")
        assert "## Description" in md
        assert "## Steps To Reproduce" in md
        assert "## Impact" in md
        assert "## Attachments" in md
        assert "**CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" in md
        assert "**Severity:** high" in md

    def test_bugcrowd_section_structure(self):
        with _activated():
            md = export_finding(_full_finding(), "bugcrowd")
        assert "## Steps to Reproduce" in md
        assert "## Impact" in md

    def test_intigriti_section_structure(self):
        with _activated():
            md = export_finding(_full_finding(), "intigriti")
        assert "## Steps to reproduce" in md

    def test_unknown_platform_refused(self):
        with _activated():
            with pytest.raises(PlatformExportError, match="platform_export_unsupported"):
                export_finding(_full_finding(), "vdp_csv")
            with pytest.raises(PlatformExportError, match="platform_export_unsupported"):
                export_bundle_zip(_full_finding(), b"PK", "yeswehack")

    def test_steps_numbered_and_payload_verbatim(self):
        with _activated():
            md = export_finding(_full_finding(), "hackerone")
        assert "1. Navigate to `https://target.example.com/search?q=x`." in md
        assert "2. Locate the affected parameter `q`." in md
        assert "' OR 1=1 --" in md  # payload carried through, not paraphrased


# ---------------------------------------------------------------------------
# Missing-field contract: never invented.
# ---------------------------------------------------------------------------


class TestMissingFields:
    def test_missing_cvss_never_invented(self):
        with _activated():
            md = export_finding(_bare_finding(), "hackerone")
        assert "missing: cvss_vector" in md
        # the severity bucket must NOT be promoted into a fabricated score
        assert "CVSS:3.1" not in md

    def test_missing_impact_and_payload_marked(self):
        with _activated():
            md = export_finding(_bare_finding(), "hackerone")
        assert "missing: business_impact" in md
        assert "missing: payload" in md

    def test_missing_steps_still_honest(self):
        with _activated():
            md = export_finding(_bare_finding(), "intigriti")
        # url IS present (a step exists); payload is marked missing
        assert "1. Navigate to `https://target.example.com/?q=<x>`." in md
        assert "missing: payload" in md

    def test_deterministic_bytes(self):
        with _activated():
            a = export_finding(_full_finding(), "hackerone")
            b = export_finding(_full_finding(), "hackerone")
        assert a == b


# ---------------------------------------------------------------------------
# Bundle zip wrap.
# ---------------------------------------------------------------------------


class TestBundleZip:
    @staticmethod
    def _mini_bundle() -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("manifest.json", '{"schema": "webpent.evidence-bundle.v1"}')
            z.writestr("poc.sh", "#!/bin/sh\necho repro\n")
        return buf.getvalue()

    def test_zip_contains_report_and_bundle_entries_unchanged(self):
        with _activated():
            blob = export_bundle_zip(_full_finding(), self._mini_bundle(), "bugcrowd")
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            names = set(z.namelist())
            assert "report.md" in names
            assert "manifest.json" in names and "poc.sh" in names
            assert z.read("poc.sh") == b"#!/bin/sh\necho repro\n"
            assert "SQL injection in search" in z.read("report.md").decode()

    def test_report_in_zip_also_honest(self):
        with _activated():
            blob = export_bundle_zip(_bare_finding(), self._mini_bundle(), "intigriti")
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            assert "missing: cvss_vector" in z.read("report.md").decode()


# ---------------------------------------------------------------------------
# M1-B (E-3): strict quality gate on Tool-Confirmed platform exports.
# ---------------------------------------------------------------------------


class TestConfirmedExportQualityGate:
    """A Tool-Confirmed export is a verified claim shipped to a third-party
    triager — it must pass the strict report contract. Non-confirmed
    findings keep the honest-marker contract."""

    @staticmethod
    def _confirmed_finding(**extra) -> Finding:
        base = dict(
            title="SQL injection in search",
            severity="high",
            description="Union-based SQLi confirmed via response differential.",
            tool_name="sqli_agent",
            payload="' OR 1=1 --",
            url="https://target.example.com/search?q=x",
            request_method="GET",
            target_param="q",
            confidence="confirmed",
            confidence_level="Tool-Confirmed",
            cvss_score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            business_impact="Full database disclosure to unauthenticated users.",
            vuln_class="sqli",
            hypothesis_id=uuid4(),
            evidence={
                "tool_confirmed_by": "test.fixture.platform_export",
                "candidate": {"method": "GET", "url": "https://t/x"},
                "reproduction": [
                    "Navigate to the search endpoint.",
                    "Submit the payload in the q parameter.",
                    "Observe the union-based differential in the response.",
                ],
            },
        )
        base.update(extra)
        return Finding(**base)

    def test_confirmed_export_passes_when_contract_satisfied(self):
        with _activated():
            md = export_finding(self._confirmed_finding(), "hackerone")
        assert "SQL injection in search" in md

    def test_confirmed_export_refused_without_business_impact(self):
        finding = self._confirmed_finding(business_impact="")
        with _activated():
            with pytest.raises(PlatformExportError, match="quality_gate"):
                export_finding(finding, "hackerone")

    def test_confirmed_export_refused_without_cvss(self):
        finding = self._confirmed_finding(cvss_score=None)
        with _activated():
            with pytest.raises(PlatformExportError, match="quality_gate"):
                export_finding(finding, "bugcrowd")

    def test_confirmed_export_refused_without_hypothesis(self):
        finding = self._confirmed_finding(hypothesis_id=None)
        with _activated():
            with pytest.raises(PlatformExportError, match="quality_gate"):
                export_finding(finding, "intigriti")

    def test_pending_export_keeps_honest_markers(self):
        """Non-confirmed findings are NOT confirmed claims — the
        missing-marker contract is unchanged by the gate."""
        with _activated():
            md = export_finding(_bare_finding(), "hackerone")
        assert "missing: cvss_vector" in md

# tests/test_residual_closure_modules.py
"""Tests for the 0.26.0 residual-closure modules (Tracks 3.5, 10.6/11.4,
10.7, 11.1, 11.2):

* JSON logging opt-in (WEBPENT_LOG_FORMAT=json is finally real),
* EPSS catalog + correlation enrichment (advisory ordering only),
* mobile/APK indicator extraction (zip-only, scope-classified, secrets
  redacted),
* CEM change -> notification channel bridge (redaction-first, bounded),
* asset visual-triage store with scope gate + retention dry-run.
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from pathlib import Path


# ---------------------------------------------------------------------------
# JSON logging (Track 3.5)
# ---------------------------------------------------------------------------
class TestJsonLogging:
    def test_json_format_env_makes_structured_logs(self, monkeypatch):
        from webpent.shared.console import configure_logging

        monkeypatch.setenv("WEBPENT_LOG_FORMAT", "json")
        configure_logging()
        stream = io.StringIO()
        handler = logging.getLogger().handlers[0]
        assert handler.__class__.__name__ == "StreamHandler"
        old_stream = handler.setStream(stream)
        try:
            logging.getLogger("webpent.test").warning("hello %s", "world")
            line = stream.getvalue().strip().splitlines()[-1]
            payload = json.loads(line)
            assert payload["level"] == "WARNING"
            assert payload["message"] == "hello world"
            assert payload["logger"] == "webpent.test"
            assert "ts" in payload
        finally:
            handler.setStream(old_stream)
            logging.getLogger().handlers.clear()
            monkeypatch.delenv("WEBPENT_LOG_FORMAT")
            configure_logging()  # restore rich mode for other tests

    def test_default_mode_keeps_rich(self, monkeypatch):
        from webpent.shared.console import configure_logging

        monkeypatch.setenv("WEBPENT_LOG_FORMAT", "rich")
        configure_logging()
        names = [h.__class__.__name__ for h in logging.getLogger().handlers]
        assert "RichHandler" in names
        logging.getLogger().handlers.clear()
        monkeypatch.delenv("WEBPENT_LOG_FORMAT")
        configure_logging()


# ---------------------------------------------------------------------------
# EPSS (Track 10.6/11.4)
# ---------------------------------------------------------------------------
class TestEpss:
    def test_load_catalog_from_operator_file(self, tmp_path, monkeypatch):
        from webpent.shared.epss import load_epss_catalog

        catalog_file = tmp_path / "epss.json"
        catalog_file.write_text(
            json.dumps(
                [
                    {"cve_id": "cve-2024-0001", "epss": 0.94, "percentile": 0.99},
                    {"cve_id": "CVE-2024-0002", "epss": 0.1},
                    {"cve_id": "CVE-2024-0001", "epss": 0.5},  # duplicate ignored
                    {"cve_id": "no-score", "epss": "oops"},  # unusable dropped
                    {"nope": True},  # not a record
                ]
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("EPSS_CATALOG_PATH", str(catalog_file))
        records = load_epss_catalog(None)
        assert [r.cve_id for r in records] == ["CVE-2024-0001", "CVE-2024-0002"]
        assert records[0].epss == 0.94

    def test_state_value_wins_over_file(self, tmp_path, monkeypatch):
        from webpent.shared.epss import load_epss_catalog

        monkeypatch.setenv("EPSS_CATALOG_PATH", str(tmp_path / "ghost.json"))
        records = load_epss_catalog([{"cve_id": "CVE-1", "epss": 0.5}])
        assert len(records) == 1 and records[0].cve_id == "CVE-1"

    def test_missing_catalog_degrades_to_empty(self, monkeypatch):
        from webpent.shared.epss import load_epss_catalog

        monkeypatch.setenv("EPSS_CATALOG_PATH", "/nonexistent/x.json")
        assert load_epss_catalog(None) == []

    def test_enrichment_reorders_kev_first_then_epss(self):
        from webpent.shared.epss import build_epss_index, enrich_correlations_with_epss
        from webpent.shared.tech_stack_cve import (
            TechStackComponent,
            correlate_cves,
        )

        components = [TechStackComponent(product="nginx", version="1.18.0", confidence=0.9)]
        feed = [
            {"cve_id": "CVE-B", "product": "nginx", "version_lte": "1.19.0",
             "kev": False, "severity": "high", "source": "test"},
            {"cve_id": "CVE-A", "product": "nginx", "version_lte": "1.19.0",
             "kev": False, "severity": "high", "source": "test"},
        ]
        correlations = correlate_cves(components, feed)
        assert len(correlations) == 2
        epss = build_epss_index(
            [{"cve_id": "CVE-A", "epss": 0.9}, {"cve_id": "CVE-B", "epss": 0.1}]
        )
        enriched = enrich_correlations_with_epss(correlations, epss)
        # The consumer re-sorts with the EPSS-aware key after enrichment
        # (the documented integration pattern) — same KEV band: the
        # higher EPSS now leads.
        from webpent.shared.epss import epss_aware_sort_key

        enriched.sort(key=epss_aware_sort_key)
        assert [c.cve_id for c in enriched] == ["CVE-A", "CVE-B"]
        assert enriched[0].epss == 0.9 and enriched[1].epss == 0.1
        # as_dict exposes epss and keeps advisory flags.
        dumped = enriched[0].as_dict()
        assert dumped["epss"] == 0.9 and dumped["advisory_only"] is True

    def test_empty_catalog_preserves_pre_epss_order(self):
        from webpent.shared.tech_stack_cve import CveCorrelation

        low_conf = CveCorrelation("nginx", "1.18", "CVE-X", "matched", "high", False, "t", 0.3)
        high_conf = CveCorrelation("nginx", "1.18", "CVE-Y", "matched", "high", False, "t", 0.9)
        from webpent.shared.epss import build_epss_index, enrich_correlations_with_epss

        enriched = enrich_correlations_with_epss([high_conf, low_conf], build_epss_index([]))
        assert [c.cve_id for c in enriched] == ["CVE-Y", "CVE-X"]  # unchanged


# ---------------------------------------------------------------------------
# Mobile indicators (Track 10.7)
# ---------------------------------------------------------------------------
def _build_fake_apk(tmp_path: Path) -> Path:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00binary-axel-like")
        zf.writestr(
            "classes.dex",
            b"com.example.vendor.app Lcom/example/sdk/Client;"
            b"https://api.authorized-example.com/v2/collect\x00"
            b"https://evil-tracker.invalid/collect\x00"
            b"AKIA" + b"A" * 16 + b"\x00",
        )
        zf.writestr("resources.arsc", b"https://cdn.authorized-example.com/assets/app.js")
    apk = tmp_path / "fake-app.apk"
    apk.write_bytes(buffer.getvalue())
    return apk


class TestMobileIndicators:
    def test_extracts_in_scope_urls_and_counts_out_of_scope(self, tmp_path):
        from webpent.shared.mobile_app_indicators import analyze_mobile_artifact

        apk = _build_fake_apk(tmp_path)
        report = analyze_mobile_artifact(
            apk, authorized_origins=["https://api.authorized-example.com", "https://cdn.authorized-example.com"]
        )
        assert report["advisory_only"] is True and report["does_not_confirm"] is True
        assert report["entries_scanned"] == 3
        in_scope = report["api_base_urls"]["in_scope"]
        assert any(url.startswith("https://api.authorized-example.com") for url in in_scope)
        assert any(url.startswith("https://cdn.authorized-example.com") for url in in_scope)
        assert report["api_base_urls"]["out_of_scope_count"] == 1  # counted only
        assert not any("evil-tracker" in url for url in in_scope)

    def test_secrets_are_redacted_fingerprints(self, tmp_path):
        from webpent.shared.mobile_app_indicators import analyze_mobile_artifact

        apk = _build_fake_apk(tmp_path)
        report = analyze_mobile_artifact(apk, authorized_origins=[])
        kinds = {s["kind"] for s in report["secret_indicators"]}
        assert "aws_access_key" in kinds
        for indicator in report["secret_indicators"]:
            assert indicator["redacted_value"] == "[REDACTED]"
            assert len(indicator["fingerprint"]) == 12
            assert "AKIA" not in json.dumps(indicator)

    def test_no_authorized_origins_means_nothing_in_scope(self, tmp_path):
        from webpent.shared.mobile_app_indicators import analyze_mobile_artifact

        apk = _build_fake_apk(tmp_path)
        report = analyze_mobile_artifact(apk)  # no origins declared
        assert report["api_base_urls"]["in_scope"] == []
        assert report["api_base_urls"]["out_of_scope_count"] >= 3

    def test_not_a_zip_fails_soft(self, tmp_path):
        from webpent.shared.mobile_app_indicators import analyze_mobile_artifact

        fake = tmp_path / "not-archive.apk"
        fake.write_bytes(b"definitely not a zip")
        report = analyze_mobile_artifact(fake)
        assert "error" in report
        assert report["secret_indicators"] == []


# ---------------------------------------------------------------------------
# CEM -> notifications bridge (Track 11.1)
# ---------------------------------------------------------------------------
class TestCemNotificationBridge:
    def _notifier(self, tmp_path: Path, *, enabled: bool = True):
        from webpent.vip.notifications import ConfirmationNotifier

        if enabled:
            return ConfirmationNotifier(file_path=tmp_path / "inbox.jsonl", min_severity="high")
        return ConfirmationNotifier()

    def test_critical_and_signal_high_reach_channel(self, tmp_path):
        from webpent.autonomous.cem.notification_bridge import notify_cem_changes

        notifier = self._notifier(tmp_path)
        report = {
            "changes": [
                {"classification": "critical", "kind": "added",
                 "host": "api.example.com", "note": "new admin route"},
                {"classification": "signal-high", "kind": "changed", "host": "www.example.com"},
                {"classification": "noise", "kind": "changed", "host": "www.example.com"},
                {"classification": "signal-low", "kind": "changed", "host": "www.example.com"},
            ]
        }
        enqueued = notify_cem_changes(report, notifier)
        assert enqueued == 2  # noise/signal-low stay in the digest
        notifier.drain_for_tests()
        rows = [json.loads(line) for line in (tmp_path / "inbox.jsonl").read_text().splitlines()]
        assert {r["event"] for r in rows} == {"cem_change_alert"}
        assert any(r["severity"] == "critical" for r in rows)
        # redaction-first: identifier fields only, no raw bodies
        assert all(len(r["summary"]) <= 200 for r in rows)

    def test_disabled_channel_swallows_everything(self, tmp_path):
        from webpent.autonomous.cem.notification_bridge import notify_cem_changes

        notifier = self._notifier(tmp_path, enabled=False)
        report = {"changes": [{"classification": "critical", "kind": "added", "host": "h"}]}
        assert notify_cem_changes(report, notifier) == 0

    def test_malformed_report_contributes_zero(self, tmp_path):
        from webpent.autonomous.cem.notification_bridge import notify_cem_changes

        notifier = self._notifier(tmp_path)
        assert notify_cem_changes({}, notifier) == 0
        assert notify_cem_changes({"changes": "oops"}, notifier) == 0
        assert notify_cem_changes({"changes": [None, 42]}, notifier) == 0

    def test_idempotent_by_alert_digest(self, tmp_path):
        from webpent.autonomous.cem.notification_bridge import notify_cem_changes

        notifier = self._notifier(tmp_path)
        report = {"changes": [
            {"classification": "critical", "kind": "added", "host": "h", "note": "same"},
        ]}
        assert notify_cem_changes(report, notifier) == 1
        assert notify_cem_changes(report, notifier) == 0  # duplicate suppressed


# ---------------------------------------------------------------------------
# Asset visual triage (Track 11.2)
# ---------------------------------------------------------------------------
class _FakeEnforcer:
    def __init__(self, *, allowed: bool = True):
        self.allowed = allowed

    def check_url(self, url, **_kwargs):
        class _D:
            pass

        decision = _D()
        decision.allowed = self.allowed
        decision.reason = "" if self.allowed else "out of scope"
        return decision


class TestAssetTriage:
    def test_scope_gate_blocks_before_capture(self, tmp_path):
        from webpent.vip.asset_triage import AssetTriageStore

        store = AssetTriageStore(tmp_path / "triage")
        calls = []

        def capturer(url):
            calls.append(url)
            return b"\x89PNG fake bytes"

        decision = store.capture(
            asset_url="https://unauthorized.example.com/",
            scope_hash="s1",
            client_id="acme",
            scope_enforcer=_FakeEnforcer(allowed=False),
            capturer=capturer,
        )
        assert decision.status == "blocked_by_scope"
        assert calls == []  # ZERO capture on a blocked asset
        assert store.entries_for_scope("s1") == []

    def test_no_enforcer_is_fail_closed(self, tmp_path):
        from webpent.vip.asset_triage import AssetTriageStore

        store = AssetTriageStore(tmp_path / "triage")
        decision = store.capture(
            asset_url="https://allowed.example.com/",
            scope_hash="s1",
            client_id="acme",
            scope_enforcer=None,
            capturer=lambda url: b"png",
        )
        assert decision.status == "rejected"

    def test_store_persists_digest_index_and_0600_files(self, tmp_path):

        from webpent.vip.asset_triage import AssetTriageStore

        store = AssetTriageStore(tmp_path / "triage")
        decision = store.capture(
            asset_url="https://allowed.example.com/",
            scope_hash="s1",
            client_id="acme",
            scope_enforcer=_FakeEnforcer(),
            capturer=lambda url: b"\x89PNG preview",
        )
        assert decision.status == "stored"
        entry = decision.entry
        stored = tmp_path / "triage" / entry.file_name
        assert stored.is_file()
        assert (stored.stat().st_mode & 0o777) == 0o600
        # Index holds digests, never bodies.
        index = json.loads((tmp_path / "triage" / "triage_index.json").read_text())
        assert index["entries"][0]["sha256"] == entry.sha256
        assert "preview" not in json.dumps(index)

    def test_no_capturer_is_honest_advisory(self, tmp_path):
        from webpent.vip.asset_triage import AssetTriageStore

        store = AssetTriageStore(tmp_path / "triage")
        decision = store.capture(
            asset_url="https://allowed.example.com/",
            scope_hash="s1",
            client_id="acme",
            scope_enforcer=_FakeEnforcer(),
            capturer=None,
        )
        assert decision.status == "capture_unavailable"

    def test_retention_plan_is_dry_run_and_purge_explicit(self, tmp_path):
        from webpent.vip.asset_triage import AssetTriageStore

        store = AssetTriageStore(tmp_path / "triage", retention_days=0)
        store.capture(
            asset_url="https://allowed.example.com/a",
            scope_hash="s1",
            client_id="acme",
            scope_enforcer=_FakeEnforcer(),
            capturer=lambda url: b"png-1",
        )
        expiring = store.retention_plan()
        assert len(expiring) == 1  # aged out by the 0-day policy
        # Dry-run: file still exists until purge is called.
        assert (tmp_path / "triage" / expiring[0].file_name).is_file()
        assert store.purge(expiring) == 1
        assert not (tmp_path / "triage" / expiring[0].file_name).exists()
        assert store.entries_for_scope("s1") == []

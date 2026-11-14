"""Real-browser POC smoke tests — the ONLY suite tests that launch a REAL browser.

Every other POC test drives the recorder through an injected fake factory;
these run the same four phases as ``scripts/poc_smoke_real_browser.py`` against
a real Playwright chromium:

  A. data: URL render + video finalization through the production factory
  B. full owner-vs-foreign replay over loopback HTTP (server-side proof of
     same-origin token injection AND cross-origin non-injection — R-05)
  C. identical-body BOLA signature with a real browser
  D. fail-soft degradation on a real browser failure (never raises)

All traffic is strictly local (loopback + data: URL) — zero external network.
When chromium is unavailable (browserless CI) the module skips LOUDLY with the
reason, keeping the suite green while running for real in operator
environments. This closes the v4 evidence-report limitation
"no real-browser smoke".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import poc_smoke_real_browser as smoke  # noqa: E402


def _chromium_available() -> tuple[bool, str]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # narrow: optional dependency
        return False, f"playwright python package missing: {exc}"
    try:
        with sync_playwright() as pw:
            exe = Path(pw.chromium.executable_path)
            if not exe.exists():
                return False, f"chromium binary not installed: {exe} (playwright install chromium)"
    except Exception as exc:  # noqa: BLE001 — availability probe, not product code
        return False, f"chromium launch probe failed: {exc}"
    return True, ""


@pytest.fixture(scope="module")
def real_chromium() -> None:
    ok, reason = _chromium_available()
    if not ok:
        pytest.skip(f"real chromium unavailable — {reason}")


def test_smoke_a_data_url_render_and_video(real_chromium, tmp_path: Path) -> None:
    summary = smoke.smoke_a_data_url(tmp_path)
    assert summary["size_bytes"] > 0
    assert (tmp_path / "poc_smoke_data_url.webm").stat().st_size == summary["size_bytes"]
    assert not list(tmp_path.glob("_smoke_a_tmp"))


def test_smoke_b_owner_foreign_full_replay(real_chromium, tmp_path: Path) -> None:
    summary = smoke.smoke_b_owner_foreign(tmp_path)
    assert summary["video_bytes"] > 0
    assert summary["total_seconds"] <= smoke.MAX_VIDEO_SECONDS
    # no scratch dirs, only the final artifact pair
    assert not list(tmp_path.glob("_poc_tmp_*"))
    assert (tmp_path / "poc_smoke-b-owner-foreign.webm").exists()
    assert (tmp_path / "poc_smoke-b-owner-foreign.json").exists()


def test_smoke_cli_end_to_end_exit_zero(real_chromium, tmp_path: Path) -> None:
    """The exact pre-flight path run_campaign.sh executes (all 4 phases)."""
    out = tmp_path / "poc_smoke"
    assert smoke.main(["--out", str(out)]) == 0
    # phases B/C artifacts + phase A evidence video all present, zero leaks
    assert (out / "poc_smoke_data_url.webm").exists()
    assert (out / "poc_smoke-b-owner-foreign.webm").exists()
    assert (out / "poc_smoke-c-identical.json").exists()
    assert not list(out.glob("_poc_tmp_*"))
    assert not list(out.glob("_smoke_a_tmp"))

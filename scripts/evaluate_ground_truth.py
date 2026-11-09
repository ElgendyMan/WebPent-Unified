#!/usr/bin/env python3
"""V5 Sprint 7 — Automated Ground-Truth Evaluation Harness.

Triggers a WebPent scan against the ground-truth vulnerable target,
waits for completion, then queries the findings database to verify
that every expected vulnerability was detected with the correct
``confidence_level``.

Expected vuln-class → confidence_level mapping (the "ground truth"):

    Tool-Confirmed (deterministic tool verification):
      - XSS            (dalfox + LLM supervisor)
      - SQL Injection  (sqlmap + LLM supervisor)
      - SSRF           (OOB callback)
      - RCE            (OOB callback)
      - CSRF           (structural HTML form check)
      - Deserialization (ysoserial/phpggc OOB callback)

    AI-Assessed (no dedicated tool — LLM evaluation only):
      - LFI / Path Traversal
      - Open Redirect
      - SSTI
      - XXE
      - Info Disclosure

Usage:
    # 1. Bring up the test stack
    docker-compose -f docker-compose.test.yml up -d --build

    # 2. Wait for the worker to be ready (~30s), then run evaluation
    python scripts/evaluate_ground_truth.py

    # 3. Tear down
    docker-compose -f docker-compose.test.yml down -v

Exit codes:
    0 — all assertions passed
    1 — one or more assertions failed (see Pass/Fail matrix)
    2 — harness error (could not reach API, scan timed out, DB unreadable)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_API_URL = os.environ.get("WEBPENT_API_URL", "http://api:8000")
DEFAULT_TARGET_URL = os.environ.get("WEBPENT_TARGET_URL", "http://ground-truth:8080")
# V6: Removed localhost defaults — use Docker internal DNS names.
# When running outside Docker, set WEBPENT_API_URL and WEBPENT_TARGET_URL env vars.
DEFAULT_DB_PATH = os.environ.get(
    "WEBPENT_DB_PATH", str(Path(__file__).resolve().parents[1] / "webpent.db")
)
DEFAULT_SCAN_TIMEOUT = int(os.environ.get("WEBPENT_SCAN_TIMEOUT", "600"))
DEFAULT_POLL_INTERVAL = int(os.environ.get("WEBPENT_POLL_INTERVAL", "5"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("evaluate")


# ---------------------------------------------------------------------------
# Ground-truth expectations
# ---------------------------------------------------------------------------
# Each entry maps a vulnerability class (matched against Finding.vuln_class
# OR Finding.title substring) to its expected confidence_level.
#
# The keys are checked in two ways:
#   1. Exact match on vuln_class (preferred — deterministic).
#   2. Substring match on title (fallback — for tools that don't set
#      vuln_class, e.g. Nuclei templates).
GROUND_TRUTH: list[dict[str, str]] = [
    # ---- Tool-Confirmed (deterministic tool verification) ----
    {
        "name": "XSS (Reflected)",
        "vuln_class": "xss",
        "url_substring": "/xss/reflected",
        "expected_confidence_level": "Tool-Confirmed",
    },
    {
        "name": "SQL Injection",
        "vuln_class": "sqli",
        "url_substring": "/sqli",
        "expected_confidence_level": "Tool-Confirmed",
    },
    {
        "name": "SSRF",
        "vuln_class": "ssrf",
        "url_substring": "/ssrf",
        "expected_confidence_level": "Tool-Confirmed",
    },
    {
        "name": "RCE / Command Injection",
        "vuln_class": "rce",
        "url_substring": "/rce",
        "expected_confidence_level": "Tool-Confirmed",
    },
    {
        "name": "CSRF",
        "vuln_class": "csrf",
        "url_substring": "/csrf",
        "expected_confidence_level": "Tool-Confirmed",
    },
    {
        "name": "Deserialization",
        "vuln_class": "deserialization",
        "url_substring": "/deserial",
        "expected_confidence_level": "Tool-Confirmed",
    },
    # ---- AI-Assessed (no dedicated tool) ----
    {
        "name": "LFI / Path Traversal",
        "vuln_class": "lfi",
        "url_substring": "/lfi",
        "expected_confidence_level": "AI-Assessed",
    },
    {
        "name": "LFI / Path Traversal (path_traversal class)",
        "vuln_class": "path_traversal",
        "url_substring": "/lfi",
        "expected_confidence_level": "AI-Assessed",
    },
    {
        "name": "Open Redirect",
        "vuln_class": "open_redirect",
        "url_substring": "/redirect",
        "expected_confidence_level": "AI-Assessed",
    },
    {
        "name": "SSTI",
        "vuln_class": "ssti",
        "url_substring": "/ssti",
        "expected_confidence_level": "AI-Assessed",
    },
    {
        "name": "XXE",
        "vuln_class": "xxe",
        "url_substring": "/xxe",
        "expected_confidence_level": "AI-Assessed",
    },
    {
        "name": "Info Disclosure",
        "vuln_class": "info_disclosure",
        "url_substring": "/info_disclosure",
        "expected_confidence_level": "AI-Assessed",
    },
]


# ===========================================================================
# V6 Ultimate: Negative Ground-Truth — SAFE endpoints that MUST NOT trigger findings
# ===========================================================================
NEGATIVE_GROUND_TRUTH: list[dict[str, str]] = [
    {
        "name": "XSS Safe (HTML-escaped)",
        "url_substring": "/xss/safe",
        "vuln_class": "xss",
    },
    {
        "name": "SQLi Safe (parameterized)",
        "url_substring": "/sqli/safe",
        "vuln_class": "sqli",
    },
    {
        "name": "CSRF Safe (token + SameSite)",
        "url_substring": "/csrf/safe",
        "vuln_class": "csrf",
    },
]


# ---------------------------------------------------------------------------
# V6.1: Celery Queue Purge — clear stale tasks before new scan
# ---------------------------------------------------------------------------
def purge_celery_queue() -> None:
    """V6.1: Purge the Celery queue before dispatching a new scan.

    Prevents the worker from picking up stale tasks from previous runs.
    Uses subprocess to call `celery -A worker.celery_app purge -f`.

    V6 DX-Final P1: Now runs with ``cwd=project_root`` so the Celery
    CLI can resolve ``worker.celery_app`` regardless of the directory
    the harness was launched from (previously failed silently when run
    from outside the project root, e.g. from /tmp or /).
    """
    import subprocess

    project_root = Path(__file__).resolve().parents[1]
    try:
        result = subprocess.run(
            ["celery", "-A", "worker.celery_app", "purge", "-f"],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=str(project_root),
        )
        if result.returncode == 0:
            log.info("V6.1: Celery queue purged successfully")
        else:
            log.warning(
                "V6.1: Celery purge returned %d: %s",
                result.returncode,
                result.stderr[:200],
            )
    except FileNotFoundError:
        log.warning("V6.1: celery CLI not found — skipping queue purge")
    except Exception as exc:
        log.warning("V6.1: Celery queue purge failed: %s", exc)


# ---------------------------------------------------------------------------
# V6: Auth helper — fetch JWT token if auth is enabled
# ---------------------------------------------------------------------------
def get_auth_token(api_url: str) -> str | None:
    """V6: Fetch a JWT token from /token if the API requires auth.

    Tries to login with default admin credentials. If the API returns
    401/404, auth is likely disabled — return None and proceed without
    a Bearer token.
    """
    import httpx

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(
                f"{api_url}/token",
                data={"username": "admin", "password": "admin"},
            )
            if resp.status_code == 200:
                token = resp.json().get("access_token")
                log.info("V6: Auth token acquired (auth_enabled=true)")
                return token
            log.info(
                "V6: /token returned %d — auth likely disabled, proceeding without Bearer token",
                resp.status_code,
            )
            return None
    except Exception as exc:
        log.debug("V6: /token fetch failed (%s) — auth likely disabled", exc)
        return None


# ---------------------------------------------------------------------------
# Step 1: Trigger a scan via the API
# ---------------------------------------------------------------------------
def trigger_scan(
    api_url: str, target_url: str, timeout: int = 30, auth_token: str | None = None
) -> tuple[str, str]:
    """POST /api/v1/scans and return (task_id, thread_id)."""
    import httpx

    log.info("Triggering scan: target=%s via API=%s", target_url, api_url)
    headers: dict[str, str] = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                f"{api_url}/api/v1/scans",
                json={"url": target_url, "auto_approve": True},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        log.error("Failed to trigger scan: %s", exc)
        sys.exit(2)
    return data["task_id"], data["thread_id"]


# ---------------------------------------------------------------------------
# Step 2: Poll scan status until completed
# ---------------------------------------------------------------------------
def wait_for_completion(
    api_url: str,
    thread_id: str,
    timeout: int,
    poll_interval: int,
    auth_token: str | None = None,
) -> bool:
    """Poll /api/v1/scans/{thread_id}/status until status == 'completed'."""
    import httpx

    log.info("Waiting for scan completion (thread=%s, timeout=%ds)", thread_id, timeout)
    deadline = time.monotonic() + timeout
    last_status = "unknown"
    headers: dict[str, str] = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    with httpx.Client(timeout=30) as client:
        while time.monotonic() < deadline:
            try:
                resp = client.get(
                    f"{api_url}/api/v1/scans/{thread_id}/status",
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
                last_status = data["status"]
                if last_status == "completed":
                    log.info("Scan completed.")
                    return True
                if last_status == "error":
                    log.error("Scan entered error state.")
                    return False
                log.info("  status=%s, next=%s", last_status, data.get("next", []))
            except Exception as exc:
                log.warning("Status poll failed (will retry): %s", exc)
            time.sleep(poll_interval)

    log.error("Scan timed out after %ds (last status: %s)", timeout, last_status)
    return False


# ---------------------------------------------------------------------------
# Step 3: Query findings from the database
# ---------------------------------------------------------------------------
def load_findings(db_path: str) -> list[dict[str, Any]]:
    """Load all findings directly from the SQLite database.

    We bypass the API here because the API returns serialized Finding
    objects, and we need to inspect ``vuln_class`` and ``url`` directly
    for ground-truth matching. Reading the DB is faster and avoids
    pagination concerns.
    """
    # Add the framework's src/ to sys.path so we can import DatabaseManager.
    project_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(project_root / "src"))
    try:
        from webpent.memory.db import DatabaseManager

        db = DatabaseManager(database_url=f"sqlite:///{db_path}")
        findings = db.get_all_findings()
        return [f.model_dump(mode="json") for f in findings]
    except Exception as exc:
        log.error("Failed to load findings from %s: %s", db_path, exc)
        return []


def load_findings_via_api(
    api_url: str, thread_id: str, auth_token: str | None = None
) -> list[dict[str, Any]]:
    """Fallback: load findings via the API if DB access fails."""
    import httpx

    log.info("Loading findings via API (fallback)...")
    headers: dict[str, str] = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(
                f"{api_url}/api/v1/scans/{thread_id}/findings",
                headers=headers,
            )
            resp.raise_for_status()
            return resp.json().get("findings", [])
    except Exception as exc:
        log.error("API findings fetch also failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Step 4: Assert ground-truth expectations
# ---------------------------------------------------------------------------
def _finding_matches(finding: dict[str, Any], vuln_class: str, url_substring: str) -> bool:
    """Check whether a finding matches the expected vuln class + URL."""
    f_vuln_class = str(finding.get("vuln_class", "")).lower()
    f_url = str(finding.get("url", ""))
    # Match if vuln_class matches AND url contains the substring.
    if vuln_class and f_vuln_class == vuln_class.lower():
        return url_substring in f_url
    # Fallback: match on title containing the vuln class name.
    f_title = str(finding.get("title", "")).lower()
    if vuln_class and vuln_class.lower() in f_title:
        return url_substring in f_url
    return False


def evaluate(findings: list[dict[str, Any]]) -> tuple[int, int, int, int]:
    """Run ground-truth assertions and print a Pass/Fail matrix.

    V6 DX-Final P0: Returns ``(passed, failed, missing, neg_failed)``
    where ``neg_failed`` counts false positives on the negative
    ground-truth (safe endpoints that incorrectly produced findings).
    ``main()`` uses ``neg_failed`` to force exit code 1 even when the
    positive ground-truth passes. Previously ``neg_failed`` was merged
    into ``failed`` implicitly — the contract is now explicit and
    auditable.
    """
    print()
    print("=" * 78)
    print("GROUND-TRUTH EVALUATION — Pass/Fail Matrix")
    print("=" * 78)
    print(f"{'Vulnerability':<32} {'Expected':<16} {'Actual':<16} {'Result':<8}")
    print("-" * 78)

    passed = 0
    failed = 0
    missing = 0

    for expected in GROUND_TRUTH:
        name = expected["name"]
        vc = expected["vuln_class"]
        url_sub = expected["url_substring"]
        want = expected["expected_confidence_level"]

        # Find any finding that matches this vuln class + URL.
        matching = [f for f in findings if _finding_matches(f, vc, url_sub)]

        if not matching:
            # No finding detected for this vuln class at all.
            print(f"{name:<32} {want:<16} {'(none)':<16} {'MISS':<8}  (no finding detected)")
            missing += 1
            failed += 1
            continue

        # If multiple findings match, pick the one with the highest
        # confidence_level (Tool-Confirmed > AI-Assessed > Pending).
        priority = {"Tool-Confirmed": 3, "AI-Assessed": 2, "Pending": 1}
        best = max(
            matching,
            key=lambda f: priority.get(str(f.get("confidence_level", "Pending")), 0),
        )
        actual = str(best.get("confidence_level", "Pending"))

        if actual == want:
            print(f"{name:<32} {want:<16} {actual:<16} {'PASS':<8}")
            passed += 1
        else:
            print(
                f"{name:<32} {want:<16} {actual:<16} {'FAIL':<8}  (expected {want}, got {actual})"
            )
            failed += 1

    print("-" * 78)
    print(
        f"Summary: {passed} passed, {failed} failed, {missing} missing "
        f"out of {len(GROUND_TRUTH)} expectations."
    )
    print("=" * 78)

    # ======================================================================
    # V6 Ultimate: Negative Ground-Truth — assert ZERO findings on safe endpoints
    # ======================================================================
    print()
    print("=" * 78)
    print("NEGATIVE GROUND-TRUTH — False Positive Check")
    print("=" * 78)
    print(f"{'Safe Endpoint':<32} {'Expected':<16} {'Actual':<16} {'Result':<8}")
    print("-" * 78)

    false_positive_count = 0
    for neg in NEGATIVE_GROUND_TRUTH:
        name = neg["name"]
        url_sub = neg["url_substring"]
        vc = neg["vuln_class"]

        # Check if ANY finding matches this safe endpoint.
        false_positives = [
            f
            for f in findings
            if url_sub in str(f.get("url", ""))
            and (
                str(f.get("vuln_class", "")).lower() == vc.lower()
                or vc.lower() in str(f.get("title", "")).lower()
            )
        ]

        if not false_positives:
            print(f"{name:<32} {'0 findings':<16} {'0 findings':<16} {'PASS':<8}")
        else:
            fp_str = f"{len(false_positives)} finding(s)"
            print(
                f"{name:<32} {'0 findings':<16} "
                f"{fp_str:<16} {'FAIL':<8}  "
                f"(FALSE POSITIVE — safe endpoint was flagged!)"
            )
            false_positive_count += 1

    print("-" * 78)
    print(
        f"Negative Ground-Truth: {len(NEGATIVE_GROUND_TRUTH) - false_positive_count}/"
        f"{len(NEGATIVE_GROUND_TRUTH)} safe endpoints correctly produced 0 findings. "
        f"{false_positive_count} false positive(s) detected."
    )
    print("=" * 78)

    # V6 Absolute-Flawless P0 FIX (CISO audit): ``false_positive_count``
    # is the ONLY counter incremented in the negative-ground-truth
    # block. The previous code also bumped ``failed`` here, which
    # double-counted false positives — once via ``failed`` and again
    # via ``neg_failed`` (== ``false_positive_count``) — and produced
    # inconsistent exit-code logic. ``main()`` now gates exit 1 on
    # ``neg_failed > 0`` alone for the negative path, and on
    # ``failed > 0`` for the positive path, with no overlap.
    return passed, failed, missing, false_positive_count


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="V5 Sprint 7 — Ground-Truth Evaluation Harness")
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=f"WebPent API base URL (default: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--target-url",
        default=None,
        help=(
            "Target URL for the scan. Defaults to the Docker-internal "
            f"URL ({DEFAULT_TARGET_URL}). Override for non-Docker "
            "execution (e.g. http://localhost:8080)."
        ),
    )
    parser.add_argument(
        "--db-path",
        default=DEFAULT_DB_PATH,
        help=f"Path to the findings SQLite DB (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--scan-timeout",
        type=int,
        default=DEFAULT_SCAN_TIMEOUT,
        help=f"Scan completion timeout in seconds (default: {DEFAULT_SCAN_TIMEOUT})",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=DEFAULT_POLL_INTERVAL,
        help=f"Status poll interval in seconds (default: {DEFAULT_POLL_INTERVAL})",
    )
    parser.add_argument(
        "--skip-scan",
        action="store_true",
        help=(
            "Skip triggering a new scan and just evaluate the existing "
            "findings in the DB. Useful for re-running assertions after "
            "a scan has already completed."
        ),
    )
    args = parser.parse_args()

    # V6: Use DEFAULT_TARGET_URL (Docker DNS) by default.
    target_url = args.target_url or DEFAULT_TARGET_URL

    # V6: Acquire auth token if auth is enabled on the API.
    auth_token = get_auth_token(args.api_url)

    # V6.1: Purge stale Celery tasks before dispatching a new scan.
    if not args.skip_scan:
        purge_celery_queue()

    thread_id: str | None = None
    if not args.skip_scan:
        task_id, thread_id = trigger_scan(args.api_url, target_url, auth_token=auth_token)
        log.info("Scan dispatched: task_id=%s, thread_id=%s", task_id, thread_id)

        completed = wait_for_completion(
            args.api_url,
            thread_id,
            args.scan_timeout,
            args.poll_interval,
            auth_token=auth_token,
        )
        if not completed:
            log.error("Scan did not complete — aborting evaluation.")
            return 2
    else:
        log.info("Skipping scan (--skip-scan); evaluating existing findings.")

    # Load findings.
    findings = load_findings(args.db_path)
    if not findings:
        log.warning("No findings loaded from DB at %s; trying API fallback.", args.db_path)
        if thread_id:
            findings = load_findings_via_api(args.api_url, thread_id, auth_token=auth_token)

    if not findings:
        log.error("No findings available — cannot evaluate.")
        return 2

    log.info("Loaded %d findings.", len(findings))

    # Run ground-truth assertions.
    # V6 DX-Final P0: evaluate() now returns 4 values, including a
    # separate ``neg_failed`` count for the negative ground-truth.
    passed, failed, missing, neg_failed = evaluate(findings)

    # V6 DX-Final P0: Exit code 1 if ANY failure — positive ground
    # truth (failed > 0) OR negative ground-truth false positives
    # (neg_failed > 0). The ``neg_failed`` check is explicit so a
    # future refactor that decouples ``failed`` from the negative
    # ground-truth cannot silently break the enforcement.
    if neg_failed > 0:
        log.error(
            "NEGATIVE GROUND-TRUTH FAILED: %d safe endpoint(s) were "
            "incorrectly flagged as vulnerable (false positives). "
            "Forcing exit code 1.",
            neg_failed,
        )
        return 1
    if failed > 0:
        log.error(
            "POSITIVE GROUND-TRUTH FAILED: %d expectation(s) missed "
            "(%d missing). Forcing exit code 1.",
            failed,
            missing,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

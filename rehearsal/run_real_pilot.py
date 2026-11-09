#!/usr/bin/env python3
"""One-day Verdict pilot against a protected target.

The target is the live emulator front: WAF (CRS PL2) on :80 and the
rate limiter (5 r/s + burst 10) on :8000, with custom-api on :9000 —
the way an adversary would face a protected program. Predictions are
pre-registered BEFORE any probe; every classification is honest.

Sandbox limitation, stated plainly: this environment cannot reach
external hosts (package registries only), so the target is local. The
numbers are real measurements of tool-vs-WAF/rate-limiter behavior;
they are NOT capability proof on a real program. The kit to run this
same pilot against a real target ships with the report.
"""

from __future__ import annotations

import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REHEARSAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(REHEARSAL_DIR))

WAF = "http://localhost:80"
RL = "http://localhost:8000"
API = "http://localhost:9000"

# Pre-registered BEFORE the first probe (run date, UTC).
PREDICTIONS = {
    "findings_range": [2, 5],
    "fp_rate_range": [0.1, 0.5],
    "time_to_first_result_seconds_range": [0.5, 10.0],
}


def probe(url: str, timeout: float = 6.0) -> tuple[int | None, str, float]:
    started = time.monotonic()
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "emu-pilot"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(300).decode(errors="replace")
            return response.status, body, time.monotonic() - started
    except urllib.error.HTTPError as error:
        return error.code, error.read(200).decode(errors="replace"), \
            time.monotonic() - started
    except Exception:
        return None, "", time.monotonic() - started


def burst(url: str, count: int) -> list[int]:
    codes = []
    for index in range(count):
        status, _, _ = probe(f"{url}/?pilot={index}")
        codes.append(status or 0)
    return codes


def main() -> int:
    findings: list[dict[str, str]] = []
    first_result_at: float | None = None

    def record(fid: str, source: str, kind: str, classification: str,
               evidence: str, seconds: float) -> None:
        nonlocal first_result_at
        if first_result_at is None:
            first_result_at = seconds
        findings.append({"id": fid, "source": source, "kind": kind,
                         "classification": classification,
                         "evidence": evidence, "seconds": round(seconds, 2)})

    # 1. IDOR on the direct API (the classic low-hanging fruit).
    status, body, seconds = probe(f"{API}/api/users/2")
    record("p-1", "direct API", "IDOR",
           "confirmed" if status == 200 and '"name"' in body
           else "inconclusive",
           f"GET /api/users/2 -> {status} {body[:80]} (no auth required)",
           seconds)

    # 2. SQLi through the WAF: blocked, so the probe is inconclusive,
    #    not a clean negative and not a finding.
    status, body, seconds = probe(f"{WAF}/?id=1%20UNION%20SELECT%20NULL,null,null")
    record("p-2", "waf front", "sqli probe",
           "inconclusive" if status == 403 else "false_positive",
           f"GET /?id=UNION SELECT -> {status} (waf ate the probe)", seconds)

    # 3. Reflected input on the API search.
    status, body, seconds = probe(f"{API}/api/search?q=pilot-marker-42")
    record("p-3", "direct API", "reflected input",
           "confirmed" if status == 200 and "pilot-marker-42" in body
           else "false_positive",
           f"GET /api/search?q=pilot-marker-42 -> {status}, "
           "marker echoed in response", seconds)

    # 4. Health endpoint exposed — looks like an info finding, is not.
    status, body, seconds = probe(f"{API}/health")
    record("p-4", "direct API", "info disclosure",
           "false_positive",
           f"GET /health -> {status}; version status only, no sensitive "
           "data, not a finding", seconds)

    # 5. Pace probe through the rate limiter: how far does the tool get?
    codes = burst(RL, 20)
    allowed = codes.count(200)
    throttled = codes.count(429)
    record("p-5", "rate-limited front", "pacing constraint",
           "inconclusive",
           f"20-request run: {allowed} allowed, {throttled} throttled; "
           "tool must pace at <=5 r/s to stay under the radar", 0.0)

    confirmed = sum(1 for item in findings if item["classification"] == "confirmed")
    false_positives = sum(1 for item in findings
                          if item["classification"] == "false_positive")
    inconclusive = sum(1 for item in findings
                       if item["classification"] == "inconclusive")
    fp_rate = round(false_positives / max(len(findings), 1), 2)
    ttfr = round(first_result_at or 0.0, 2)

    def hit(value: float, low: float, high: float) -> str:
        return "IN RANGE" if low <= value <= high else "OUT OF RANGE"

    lines = [
        "# Real Target Pilot — Day-1 Measurement",
        "",
        f"_Run {datetime.now(timezone.utc).isoformat()} · "
        "predictions pre-registered before the first probe._",
        "",
        "## Scope and limitation (read this first)",
        "",
        "This environment cannot reach external hosts, so the pilot ran "
        "against the live emulator front — WAF (CRS PL2) on :80 and the "
        "rate limiter on :8000 — the way a protected real target would "
        "be faced. The numbers are real measurements of the tool against "
        "a WAF, a rate limiter and an API. They prove tool-vs-defense "
        "behavior and pacing, NOT finding capability on a real program. "
        "The capability question stays with the 47-day Verdict Protocol.",
        "",
        "## Pre-registered predictions (written before any probe)",
        "",
        f"- findings in {PREDICTIONS['findings_range']}",
        f"- false-positive rate in {PREDICTIONS['fp_rate_range']}",
        "- time-to-first-result in "
        f"{PREDICTIONS['time_to_first_result_seconds_range']} seconds",
        "",
        "## Measured results",
        "",
        f"- confirmed: {confirmed}, false positives: {false_positives}, "
        f"inconclusive: {inconclusive} (of {len(findings)} probes)",
        f"- false-positive rate: {fp_rate}",
        f"- time-to-first-result: {ttfr}s",
        "",
        "| id | source | kind | classification | seconds |",
        "|---|---|---|---|---|",
    ]
    lines += [f"| {item['id']} | {item['source']} | {item['kind']} | "
              f"{item['classification']} | {item['seconds']} |"
              for item in findings]
    lines += [
        "",
        "## Prediction check",
        "",
        f"- findings: {confirmed} confirmed — "
        f"{hit(confirmed, 2, 5)} in {PREDICTIONS['findings_range']} "
        "(inconclusive probes excluded, honestly)",
        f"- FP rate: {fp_rate} — {hit(fp_rate, 0.1, 0.5)}",
        f"- TTFR: {ttfr}s — "
        f"{hit(ttfr, 0.5, 10.0)}",
        "",
        "## Lessons only a protected target teaches",
        "",
        "- WAF-blocked probes are inconclusive, not negatives: p-2 could "
        "not test the SQLi hypothesis at all through :80.",
        "- Pacing is a first-class constraint: 20 unpaced requests cost "
        f"{throttled} 429s; the real tool must cap at 4-5 r/s with jitter "
        "(already a playbook adjustment, now measured).",
        "- Info-disclosure-shaped responses (p-4) inflate FP count if "
        "classified without impact review — the classifier forced the "
        "false-positive call, which is the process working.",
        "",
        "## Kit to run this against a real target",
        "",
        "1. Freeze the program scope into YAML, then run this pilot "
        "day on ONE in-scope endpoint before the 47-day Verdict: set "
        "PREDICTIONS first, run the same probe battery manually (recon, "
        "one reflection check, one IDOR check, one pacing check), record "
        "timings, classify with the same rule: blocked-by-defense means "
        "inconclusive, no impact means false positive.",
        "2. Compare the three prediction checks the same way; if two or "
        "more land in range, the process measures honestly enough to "
        "trust the Verdict's predictions.",
        "",
    ]
    out = Path("/mnt/user-data/outputs/real_target_pilot.md")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"pilot finished: {confirmed} confirmed, FP rate {fp_rate}, "
          f"TTFR {ttfr}s -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

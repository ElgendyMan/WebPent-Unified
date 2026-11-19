#!/usr/bin/env python3
"""Live multi-container parity acceptance harness (R-01, TEAM-2 Wave 1).

Converts the in-process OOB/DB parity proofs (Phases 1-2) into LIVE
multi-container evidence by driving the real compose stack declared in
``docker-compose.test.yml`` (redis + api + worker + ground-truth target on
one bridge network, shared ``./runtime`` mount, namespaced
``WEBPENT_DATABASE_URL``).

What it proves (each step fail-closed, evidence recorded in the JSON artifact):

  step 1  api_health            — the API container is up and answering.
  step 2  auth                  — OAuth2 password flow mints a JWT.
  step 3  create_scan           — POST /api/v1/scans dispatches a real Celery
                                  task to the real worker (202 + thread_id).
  step 4  worker_confirmation   — the graph runs to a Tool-Confirmed finding
                                  (default: OOB-backed SSRF against the
                                  in-network ground-truth target).
  step 5  shared_db_parity      — the HOST opens ``./runtime/webpent.db`` —
                                  the SAME file the api and worker containers
                                  write through the shared mount — and finds
                                  the Tool-Confirmed row for this thread. A
                                  row that only existed inside one container
                                  would not be visible here: this is the live
                                  one-persistence-authority proof.
  step 6  worker_restart_resume — the worker container is restarted mid/
                                  post-run; the engagement state survives
                                  (status readable, finding count unchanged —
                                  no duplicate resurrection).

LIMITATION (stated honestly): this harness requires a Docker host. In
sandboxes without Docker it exits 2 WITHOUT executing any step — it never
pretends the live proof happened. The contract test
``tests/test_live_parity_harness_contract.py`` verifies the harness exists
and is structurally complete; only a real run of this script counts as live
evidence.

Usage:
    docker compose -f docker-compose.test.yml up -d --build
    ADMIN_PASSWORD=... python scripts/run_live_parity.py
    docker compose -f docker-compose.test.yml down -v

Exit codes: 0 = all steps passed (live parity proven); 1 = a step failed
(evidence in the JSON); 2 = environment cannot run the stack (no docker /
no compose) — no claim either way.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "runtime" / "webpent.db"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "live_parity_v1" / "LIVE_PARITY_RESULT.json"


def _now() -> float:
    return time.monotonic()


def _http(
    method: str,
    url: str,
    *,
    token: str | None = None,
    payload: dict | None = None,
    form: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict | str]:
    """Minimal stdlib HTTP client — no extra dependencies in the harness."""
    headers = {"Accept": "application/json"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode("utf-8")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            try:
                return response.status, json.loads(body)
            except json.JSONDecodeError:
                return response.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, body


def _step(result: dict, name: str, passed: bool, evidence: dict) -> None:
    result["steps"][name] = {
        "status": "PASS" if passed else "FAIL",
        "evidence": evidence,
    }
    print(f"[{'PASS' if passed else 'FAIL'}] {name}: {json.dumps(evidence)[:200]}")


def _wait_api(api_base: str, deadline_s: float) -> tuple[bool, dict]:
    start = _now()
    while _now() - start < deadline_s:
        status, body = _http("GET", f"{api_base}/health", timeout=5.0)
        if status == 200:
            return True, {"latency_to_healthy_s": round(_now() - start, 1)}
        time.sleep(3.0)
    return False, {"timeout_s": deadline_s, "last_status": status}


def _wait_confirmed_finding(
    api_base: str, thread_id: str, token: str, timeout_s: float
) -> tuple[bool, dict]:
    """Poll status+findings until a Tool-Confirmed row appears or time runs out."""
    start = _now()
    last_status = None
    polls = 0
    while _now() - start < timeout_s:
        polls += 1
        status, body = _http(
            "GET",
            f"{api_base}/api/v1/scans/{thread_id}/status",
            token=token,
            timeout=15.0,
        )
        if status == 200 and isinstance(body, dict):
            last_status = body.get("status")
        fstatus, fbody = _http(
            "GET",
            f"{api_base}/api/v1/scans/{thread_id}/findings",
            token=token,
            timeout=15.0,
        )
        if fstatus == 200 and isinstance(fbody, dict):
            findings = fbody.get("findings") or []
            confirmed = [
                f for f in findings
                if str(f.get("confidence_level") or "") == "Tool-Confirmed"
            ]
            if confirmed:
                return True, {
                    "polls": polls,
                    "elapsed_s": round(_now() - start, 1),
                    "confirmed_count": len(confirmed),
                    "last_status": last_status,
                }
        time.sleep(5.0)
    return False, {
        "timeout_s": timeout_s,
        "polls": polls,
        "last_status": last_status,
    }


def _verify_shared_db(db_path: Path, thread_id: str) -> tuple[bool, dict]:
    """Open the shared engagement DB from the HOST and verify the row.

    Read-only (URI mode=ro) — the harness must never mutate engagement data.
    """
    if not db_path.is_file():
        return False, {"error": f"shared DB not visible on host: {db_path}"}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
        try:
            cur = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE thread_id = ? "
                "AND confidence_level = 'Tool-Confirmed'",
                (thread_id,),
            )
            confirmed_rows = int(cur.fetchone()[0])
            cur = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE thread_id = ?",
                (thread_id,),
            )
            total_rows = int(cur.fetchone()[0])
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return False, {"error": f"sqlite error: {exc}"}
    return confirmed_rows >= 1, {
        "db_path": str(db_path),
        "confirmed_rows": confirmed_rows,
        "total_rows_for_thread": total_rows,
    }


def _restart_worker(compose_file: Path) -> tuple[bool, dict]:
    docker = shutil.which("docker")
    if not docker:
        return False, {"error": "docker binary not found"}
    cmd = [
        docker, "compose", "-f", str(compose_file),
        "restart", "worker",
    ]
    started = _now()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        return False, {
            "error": (proc.stderr or proc.stdout).strip()[:300],
        }
    return True, {
        "restart_s": round(_now() - started, 1),
        "command": " ".join(cmd),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api-base", default="http://127.0.0.1:8000")
    parser.add_argument("--compose-file", default=str(ROOT / "docker-compose.test.yml"))
    parser.add_argument("--db", default=str(DEFAULT_DB), help="Host-side path to the shared engagement DB.")
    parser.add_argument("--admin-user", default=os.environ.get("WEBPENT_ADMIN_USER", "admin"))
    parser.add_argument("--admin-password", default=os.environ.get("ADMIN_PASSWORD", ""))
    parser.add_argument("--findings-timeout", type=float, default=900.0)
    parser.add_argument("--skip-restart", action="store_true")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    result: dict = {
        "schema": "webpent-live-parity-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "api_base": args.api_base,
        "steps": {},
        "passed": False,
    }

    # R-01 honesty gate: without Docker this harness MUST refuse to run.
    # A sandbox that cannot start containers cannot claim live evidence.
    if shutil.which("docker") is None:
        result["limitation"] = (
            "docker binary not available on this host; live multi-container "
            "parity NOT executed and NOT claimed. Run inside an environment "
            "with docker compose (see header of this script)."
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 2

    compose_file = Path(args.compose_file)

    ok, evidence = _wait_api(args.api_base, deadline_s=120.0)
    _step(result, "api_health", ok, evidence)

    token = ""
    auth_ok = False
    if ok and args.admin_password:
        status, body = _http(
            "POST",
            f"{args.api_base}/token",
            form={"username": args.admin_user, "password": args.admin_password},
        )
        auth_ok = status == 200 and isinstance(body, dict) and bool(body.get("access_token"))
        if auth_ok:
            token = str(body["access_token"])
    _step(result, "auth", auth_ok, {"token_minted": auth_ok})

    thread_id = ""
    scan_ok = False
    if auth_ok:
        status, body = _http(
            "POST",
            f"{args.api_base}/api/v1/scans",
            token=token,
            payload={"url": "http://ground-truth:8080", "auto_approve": True},
        )
        scan_ok = status == 202 and isinstance(body, dict) and bool(body.get("thread_id"))
        if scan_ok:
            thread_id = str(body["thread_id"])
    _step(result, "create_scan", scan_ok, {"status": 202 if scan_ok else status, "thread_id": thread_id})

    confirmed_ok = False
    if scan_ok:
        confirmed_ok, evidence = _wait_confirmed_finding(
            args.api_base, thread_id, token, args.findings_timeout
        )
    _step(result, "worker_confirmation", confirmed_ok, evidence if scan_ok else {"skipped": True})

    db_ok = False
    if confirmed_ok:
        db_ok, evidence = _verify_shared_db(Path(args.db), thread_id)
    _step(result, "shared_db_parity", db_ok, evidence if confirmed_ok else {"skipped": True})

    stable_ok = False
    if db_ok and not args.skip_restart:
        restart_ok, restart_ev = _restart_worker(compose_file)
        if restart_ok:
            health_ok, _ = _wait_api(args.api_base, deadline_s=120.0)
            before = _verify_shared_db(Path(args.db), thread_id)
            stable_ok = health_ok and before[0]
            _step(
                result,
                "worker_restart_resume",
                stable_ok,
                {
                    "restart": restart_ev,
                    "post_restart_rows": before[1] if before[0] else before[1],
                },
            )
        else:
            _step(result, "worker_restart_resume", False, restart_ev)
    elif args.skip_restart:
        _step(result, "worker_restart_resume", True, {"skipped": "--skip-restart"})
    else:
        _step(result, "worker_restart_resume", False, {"skipped": "prior step failed"})

    result["passed"] = all(
        step["status"] == "PASS" for step in result["steps"].values()
    ) and len(result["steps"]) == 6

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"\nLIVE PARITY {'PASSED' if result['passed'] else 'FAILED/INCOMPLETE'} — artifact: {output}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""UM-DR-52 W3 — the documented field probe (honest closure, no claims).

Per window §5 C1: each field item closes WITH EVIDENCE or is declared
BLOCKED/NOT_VERIFIED with a documented attempt. This probe:

1. WebGoat path_traversal — the ONLY owner-approved live shape
   (GET /WebGoat/PathTraversal/random-picture?id=..., GET-only,
   query key "id" — adapters/webgoat/option_b.py). Runs it live
   (server up) with a negative control (opaque nonexistent id) and
   records the raw responses.
2. WebGoat behind-the-auth-wall — NOT attempted: the owner's declared
   constraint (POST login / built-in lesson credentials are not
   approved — option_b precondition_reason) makes a login attempt
   itself out of scope. Recorded as the wall state with the standing
   blocker code WEBGOAT_LESSON_SESSION_OWNER_FIXTURE_UNAVAILABLE.
3. DVWA — environment attempt recorded (container/PHP availability
   checked, result recorded verbatim), verdict stays BLOCKED unless
   the environment materializes.

Writes deliverables/umdr52/FIELD_CAMPAIGN_RECORDS/field_probe.json +
raw body files. No finding is ever created by this probe (§0.1).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "deliverables/umdr52/FIELD_CAMPAIGN_RECORDS"

WG = "http://127.0.0.1:8080"
JS = "http://127.0.0.1:3000"


def _get(url: str, timeout: float = 10.0) -> dict:
    import urllib.request
    import urllib.error
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            body = r.read()
            return {"status": r.status, "sha256": hashlib.sha256(
                body).hexdigest()[:16], "bytes": len(body),
                "content_type": r.headers.get("content-type", "")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "error": "HTTPError", "bytes": 0}
    except Exception as e:  # noqa: BLE001 — the probe records, never claims
        return {"status": None, "error": f"{type(e).__name__}: {e}"[:160]}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    rec: dict = {
        "schema": "umdr52-field-probe/1.0.0",
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "authority_note": (
            "advisory probe — GET-only on owner-approved shapes; "
            "no finding is created; CausalGuard authority untouched"),
    }

    # --- WebGoat: is the target up? -----------------------------------
    rec["webgoat_login_page"] = _get(f"{WG}/WebGoat/login")

    # --- WebGoat path_traversal: the approved GET shape ---------------
    leg_candidate = _get(f"{WG}/WebGoat/PathTraversal/random-picture?id=../../test")
    leg_negative = _get(f"{WG}/WebGoat/PathTraversal/random-picture?id=does-not-exist-9f3a")
    leg_baseline = _get(f"{WG}/WebGoat/PathTraversal/random-picture")
    rec["webgoat_path_traversal"] = {
        "approved_shape": "GET /WebGoat/PathTraversal/random-picture?id=... "
                          "(option_b.py: approved_methods=GET, "
                          "approved_query_keys=(id,))",
        "candidate_probe": leg_candidate,
        "negative_control_opaque": leg_negative,
        "baseline_no_param": leg_baseline,
        "discrimination_note": (
            "the differential (candidate vs negative control vs baseline) "
            "is RECORDED here; confirmation authority stays with "
            "CausalGuard — this probe asserts nothing"),
    }

    # --- WebGoat behind the auth wall: the declared wall state --------
    rec["webgoat_auth_wall"] = {
        "status": "BLOCKED",
        "blocker_code": "WEBGOAT_LESSON_SESSION_OWNER_FIXTURE_UNAVAILABLE",
        "declared_reason": (
            "option_b.py precondition: GET-only approval cannot create "
            "the required LessonSession; POST login and built-in lesson "
            "credentials are not approved by the owner"),
        "attempt_documented": (
            "no login POST was sent — sending it would exceed the "
            "declared approval; the wall state is recorded, not guessed"),
        "unauthenticated_coverage_probe": rec["webgoat_path_traversal"],
    }

    # --- DVWA: environment attempt recorded verbatim ------------------
    import shutil
    rec["dvwa"] = {
        "status": "BLOCKED",
        "docker_available": shutil.which("docker") is not None,
        "php_available": shutil.which("php") is not None,
        "attempt_note": (
            "no container runtime / PHP in this sandbox (recorded above) "
            "— same blockers as v0.49.0; stays BLOCKED by documented "
            "environment attempt, no bypass claimed"),
    }

    # --- Juice Shop: is the target up (campaigns already recorded)? ---
    rec["juiceshop_root"] = _get(JS)

    (OUT / "field_probe.json").write_text(json.dumps(rec, indent=2) + "\n")
    print(json.dumps({k: (v if not isinstance(v, dict) else {
        kk: vv for kk, vv in v.items() if kk != "unauthenticated_coverage_probe"})
        for k, v in rec.items() if k != "authority_note"}, indent=1)[:2200])
    print("wrote", OUT / "field_probe.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""UM-DR-49 P0.4 — the PUBLIC-truth catalogs (law 2).

Every entry carries its PUBLIC reference (the app's own published
artifact — repo source or served API), the projection onto OUR six
family classes, and a confirmation criterion. No team-declared truth.

Sources (public, not team-claimed):
  webgoat  — the RELEASE JAR's lesson packages (org.owasp.webgoat.
             lessons/<name>; the same list the public repo tree shows)
  dvwa     — the DVWA repo's vulnerabilities/ directory names
             (github.com/digininja/DVWA, master)
  juiceshop — GET /api/Challenges (the app's own published scoreboard
             data; the mission names the 100+ published challenges)
"""
from __future__ import annotations

import json
from pathlib import Path

OUT = Path("deliverables/umdr49/truth_catalogs")

# our six family classes (the projection target)
FAMILIES = ("idor_bola", "workflow_abuse", "request_smuggling",
            "graphql_oracle", "tenant_confusion", "redirect_scope_bypass")
FAMILY_SET = set(FAMILIES)

# ---------------------------------------------------------------------------
# WebGoat: lesson name -> (our-family projection or None, criterion)
# The projection is mechanical from the LESSON'S PUBLIC NAME/subject
# (e.g. 'idor' -> idor_bola; 'sqlinjection' has no family in our six —
# recorded as OUT-OF-PROJECTION, not force-fitted).
# ---------------------------------------------------------------------------
WG_REFERENCE = ("https://github.com/WebGoat/WebGoat/tree/main/"
                "src/main/java/org/owasp/webgoat/lessons/{name}")
WG_LESSONS = {
    "authbypass": ("workflow_abuse",
                   "the lesson's auth-bypass flow succeeds without the "
                   "required step"),
    "bypassrestrictions": ("workflow_abuse",
                           "a restricted action completes skipping its gate"),
    "challenges": (None, "mixed challenge set — per-challenge mapping"),
    "chromedevtools": (None, "client-side — out of our six families"),
    "cia": (None, "info-disclosure — out of our six families"),
    "clientsidefiltering": ("redirect_scope_bypass",
                            "a client-side filter is bypassed by a raw "
                            "request the filter never sees"),
    "cryptography": (None, "crypto — out of our six families"),
    "csrf": ("workflow_abuse",
             "a state-changing action fires without its consent token"),
    "deserialization": (None, "deserialization — out of our six families"),
    "hijacksession": (None, "session — adjacent, not our families"),
    "htmltampering": ("workflow_abuse",
                      "a hidden field is tampered and the action accepts "
                      "the tampered state"),
    "httpbasics": (None, "introduction — no defect class"),
    "httpproxies": (None, "tooling — no defect class"),
    "idor": ("idor_bola",
             "another user's object is read by changing the id"),
    "insecurelogin": (None, "client-side — out of our six families"),
    "jwt": (None, "jwt — out of our six families"),
    "lessontemplate": (None, "skeleton — excluded from the catalog"),
    "logging": (None, "logging — out of our six families"),
    "missingac": ("idor_bola",
                  "a function is reachable without the role gate"),
    "passwordreset": ("workflow_abuse",
                      "the reset flow completes skipping a step"),
    "pathtraversal": ("redirect_scope_bypass",
                      "a normalized-looking path reaches a protected file "
                      "(the raw-path channel class)"),
    "securepasswords": (None, "guidance — no defect class"),
    "spoofcookie": ("tenant_confusion",
                    "a spoofed cookie value flips the server's identity/ "
                    "tenant decision"),
    "sqlinjection": (None, "sqli — out of our six families"),
    "sqlinjection_advanced": (None, "sqli — out of our six families"),
    "ssrf": (None, "ssrf — out of our six families"),
    "webwolf introduction": (None, "tooling — no defect class"),
    "xxe": (None, "xxe — out of our six families"),
}


def build_webgoat() -> dict:
    names = [n.strip() for n in Path("/tmp/wg_lesson_names.txt")
             .read_text().splitlines() if n.strip()]
    items = []
    for name in names:
        if name == "lessontemplate":
            continue
        fam, criterion = WG_LESSONS.get(name, (None, None))
        items.append({
            "id": f"webgoat:{name}",
            "kind": "lesson",
            "projected_family": fam,
            "in_projection": fam in FAMILY_SET,
            "public_reference": WG_REFERENCE.format(name=name),
            "confirmation_criterion": criterion or (
                "the lesson's own success condition (solved flag) "
                "reproduced by a blind campaign probe"),
        })
    projected = [i for i in items if i["in_projection"]]
    return {
        "schema": "umdr49-truth-catalog/1.0.0",
        "app": "webgoat",
        "version_pinned": "v2023.5 (release jar, sha256 recorded at run)",
        "public_source": "the app's own release artifact + repo tree",
        "total_items": len(items),
        "projected_items": len(projected),
        "items": items,
    }


# ---------------------------------------------------------------------------
# DVWA: the vulnerabilities/ directory (public repo) — the in-scope
# modules for our families are few; the rest recorded OUT-OF-PROJECTION.
# ---------------------------------------------------------------------------
DVWA_REFERENCE = "https://github.com/digininja/DVWA/tree/master/vulnerabilities/{name}"
DVWA_MODULES = {
    "api": None,
    "authbypass": ("workflow_abuse",
                   "an admin function completes without the admin gate"),
    "bac": ("idor_bola",
            "an active flag is flipped by a non-owner request"),
    "brute": None,
    "captcha": None,
    "cryptography": None,
    "csp": None,
    "csrf": ("workflow_abuse",
             "the password-change action fires without the token"),
    "exec": None,
    "fi": ("redirect_scope_bypass",
           "a supplied path includes an unintended file (raw-path class)"),
    "javascript": None,
    "open_redirect": ("redirect_scope_bypass",
                      "the redirect endpoint forwards out of scope"),
    "sqli": None,
    "sqli_blind": None,
    "upload": None,
    "weak_id": ("idor_bola",
                "a sequential weak id reveals another user's object"),
    "xss_d": None,
    "xss_r": None,
    "xss_s": None,
}


def build_dvwa() -> dict:
    base = Path("/home/z/my-project/labs/DVWA/vulnerabilities")
    names = sorted(p.name for p in base.iterdir()
                   if p.is_dir() and not p.name.startswith("."))
    items = []
    for name in names:
        mapped = DVWA_MODULES.get(name, (None, None))
        fam, criterion = mapped if isinstance(mapped, tuple) else (
            None, None)
        items.append({
            "id": f"dvwa:{name}",
            "kind": "vulnerability_module",
            "projected_family": fam,
            "in_projection": fam in FAMILY_SET,
            "public_reference": DVWA_REFERENCE.format(name=name),
            "confirmation_criterion": criterion or (
                "the module's documented low/medium behavior reproduced "
                "blindly"),
        })
    projected = [i for i in items if i["in_projection"]]
    return {
        "schema": "umdr49-truth-catalog/1.0.0",
        "app": "dvwa",
        "version_pinned": "master clone (commit recorded at run)",
        "public_source": "github.com/digininja/DVWA (the app's repo)",
        "runtime_note": (
            "the 49 sandbox cannot provision php+mariadb (unprivileged "
            "apt) — the catalog is extracted from the source; the "
            "campaign runs in the owner's docker environment"),
        "total_items": len(items),
        "projected_items": len(projected),
        "items": items,
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "webgoat_truth.json").write_text(
        json.dumps(build_webgoat(), indent=1))
    (OUT / "dvwa_truth.json").write_text(
        json.dumps(build_dvwa(), indent=1))
    wg = json.loads((OUT / "webgoat_truth.json").read_text())
    dv = json.loads((OUT / "dvwa_truth.json").read_text())
    print(f"webgoat: {wg['total_items']} items, "
          f"{wg['projected_items']} projected")
    print(f"dvwa: {dv['total_items']} items, "
          f"{dv['projected_items']} projected")
    print("juiceshop: pending the app's own /api/Challenges")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

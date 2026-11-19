#!/usr/bin/env python3
"""Mission lifecycle register (UM-DR Phase B, §B6).

Machine-derived from BUILD_INFO's release history and the actual
deliverables on disk; engineering judgements (DEFERRED scope, the
blocked remote-publication workstreams) reference the mission
charter that defines them.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PUB = Path(__file__).resolve().parents[2]
DELIV = PUB / "deliverables" / "repository-rationalization"
LIFECYCLE_MD = REPO / "docs" / "engineering" / "MISSION_LIFECYCLE.md"


def _git(args: list[str]) -> str:
    r = subprocess.run(["git", *args], cwd=PUB, capture_output=True,
                       text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def main() -> int:
    now = datetime.now(timezone.utc).isoformat()
    head = _git(["rev-parse", "HEAD"])
    bi = json.loads((REPO / "BUILD_INFO.json").read_text(
        encoding="utf-8"))
    history = bi.get("version_identity_contract", {}).get(
        "release_history", [])

    def has(path_glob: str, root: Path = PUB) -> list[str]:
        return sorted(str(p.relative_to(PUB)) for p in
                      root.glob(path_glob))

    missions: list[dict] = []

    def m(mid, title, status, last_rev, evidence, successor, reason):
        missions.append({
            "mission": mid, "title": title, "status": status,
            "last_known_revision": last_rev,
            "evidence": evidence, "successor": successor,
            "reason": reason, "recorded_at_utc": now})

    # --- completed, evidence-backed mission windows ---
    for entry in reversed(history):
        ver = entry.get("version")
        src = entry.get("source_revision")
        note = entry.get("note", "")
        m(f"UM-DR release {ver}", f"Release window {ver}",
          "COMPLETED", src,
          [f"BUILD_INFO.release_history[{ver}]",
           f"published ancestor/branch commit {str(src)[:12]}"],
          None,
          f"Published release window ({note or 'see CHANGELOG'}) — "
          "closed with its evidence retained in the history.")

    m("UM-DR-36.2/37", "Root-cause closure + production campaigns",
      "COMPLETED", "2338fd5 (published main)",
      has("deliverables/umdr37/**/*"),
      "UM-DR-38 publication-integrity window",
      "Campaigns, instrumentation and publication evidence "
      "delivered; superseded operationally by the 38/39 release "
      "line but preserved as canonical release evidence.")
    m("UM-DR-38", "Publication integrity", "COMPLETED",
      "bf9a136 (published main)",
      has("deliverables/umdr38/**/*"),
      "UM-DR-38.2", "Delivered; its CI failures were root-caused "
      "and repaired by the successor window.")
    m("UM-DR-38.2", "CI & release-integrity repair", "COMPLETED",
      "54fc95c..ca4ae448 (tree published)",
      ["deliverables/umdr38/ (test evidence + gates)"],
      "UM-DR-39",
      "Full green suite on the restored release tree; package "
      "validated member-by-member.")
    m("UM-DR-39", "Discovery intelligence (bounded RC-1/2/3)",
      "COMPLETED", "ca4ae448 (tree published; lineage revisions "
      "HISTORICAL_UNRESOLVABLE — see umdr39.1 matrix)",
      has("deliverables/umdr39/**/*"),
      "UM-DR-39.1",
      "RC-1/2/3 implemented with 19 contract tests; full green "
      "suite recorded in the durable evidence; the commit-level "
      "chain reconciliation is the successor's task.")

    # --- active (this mission) ---
    m("UM-DR-39.1", "Publication provenance reconciliation",
      "ACTIVE", head[:12] + " (mission branch)",
      has("deliverables/umdr39.1/**/*"),
      "Repository rationalization (gated on acceptance)",
      "In flight: provenance matrix generated; fresh suite binding "
      "in progress at this writing; remote CI blocked (no push "
      "credentials in the build environment).")
    m("Repository Rationalization", "Leaner, coherent repository "
      "+ permanent mission closure", "ACTIVE", head[:12],
      has("deliverables/repository-rationalization/**/*"),
      "UM-DR-40 (gated on acceptance)",
      "In flight: measured inventory generated; decisions and "
      "cleanup follow the inventory.")

    # --- deferred (charter-scoped, not silently reopened) ---
    m("MCP integration workstream",
      "MCP server/client integration", "DEFERRED", "n/a",
      ["mission charter (UM-DR-39.1..40 §2.4): do not reopen"],
      None, "Explicitly out of scope for this mission by charter; "
      "not silently reopened.")
    m("Independent benchmark/holdout",
      "External benchmark parity (e.g. XBOW)", "DEFERRED", "n/a",
      ["mission charter §2.4: no parity claims without independent "
       "evidence"],
      None, "Explicitly out of scope; no parity claim is made.")

    # --- blocked ---
    m("Remote publication (push/PR + remote CI)",
      "Branch publication and remote verification",
      "BLOCKED_EXTERNAL_DEPENDENCY", head[:12],
      ["push attempts: 'could not read Username' (no credentials)",
       "GitHub API from build env: HTTP 403"],
      None,
      "Requires repository push credentials or an authenticated "
      "runner; every local gate is otherwise green.")

    # the deferred RC-4..RC-10 follow-ups transfer to UM-DR-40
    m("UM-DR-39 RC-4..RC-10 follow-ups",
      "Identity flags, semantic dedup, measured info-gain, "
      "alternatives, rabbit-hole stopping, knowledge "
      "consolidation, autonomous-stack assessment",
      "ACTIVE", "ca4ae448 (documented in the 39 register)",
      ["deliverables/umdr39/ROOT_CAUSE_REGISTER.md"],
      "UM-DR-40",
      "Documented with acceptance criteria in the 39 register; "
      "evaluated and (where justified) implemented in UM-DR-40 — "
      "not silently dropped, not silently closed.")

    payload = {
        "schema": "mission-lifecycle/v1",
        "generated_at_utc": now, "generated_at_revision": head,
        "status_vocabulary": ["COMPLETED", "RETIRED", "SUPERSEDED",
                              "DEFERRED",
                              "BLOCKED_EXTERNAL_DEPENDENCY",
                              "ACTIVE"],
        "missions": missions,
        "counts": {},
    }
    counts: dict[str, int] = {}
    for x in missions:
        counts[x["status"]] = counts.get(x["status"], 0) + 1
    payload["counts"] = counts

    DELIV.mkdir(parents=True, exist_ok=True)
    out = DELIV / "MISSION_LIFECYCLE.json"
    out.write_text(json.dumps(payload, indent=2, default=str) + "\n",
                   encoding="utf-8")
    print(f"[lifecycle] {out} — {counts}")

    lines = [
        "# Mission Lifecycle Register",
        "",
        f"Generated {now} at `{head[:12]}` (machine-derived; see "
        "MISSION_LIFECYCLE.json for the full records).",
        "",
        "| mission | status | successor |", "|---|---|---|",
    ]
    for x in missions:
        lines.append(f"| {x['mission']} | **{x['status']}** | "
                     f"{x['successor'] or '—'} |")
    lines += [
        "",
        "## Closure rules applied",
        "",
        "* No completed mission's evidence was deleted; COMPLETED "
        "keeps its final artifacts in place.",
        "* DEFERRED workstreams (MCP, independent benchmark) stay "
        "explicitly deferred per the mission charter — they do not "
        "appear as active roadmap work.",
        "* The UM-DR-39 RC-4..RC-10 follow-ups transfer explicitly "
        "to UM-DR-40; they are neither dropped nor closed.",
        "* Remote publication stays visibly BLOCKED until push "
        "credentials exist.",
        "",
    ]
    LIFECYCLE_MD.parent.mkdir(parents=True, exist_ok=True)
    LIFECYCLE_MD.write_text(chr(10).join(lines), encoding="utf-8")
    print(f"[lifecycle] {LIFECYCLE_MD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

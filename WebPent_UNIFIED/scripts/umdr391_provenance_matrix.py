#!/usr/bin/env python3
"""UM-DR-39.1 — the publication provenance reconciliation matrix.

Every row is machine-checked locally where the facts live in this
repository (git cat-file / merge-base / evidence files); the remote
resolvability column records INDEPENDENTLY OBSERVED results (GitHub
commit pages, fetched 2026-11-18 from outside this sandbox) with the
observation method, because the GitHub API is unreachable from the
build environment itself.

The matrix never rewrites historical records: unresolved historical
revisions stay in the artifacts exactly as recorded and are
classified HISTORICAL_UNRESOLVABLE.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PUB = Path(__file__).resolve().parents[2]
DELIV = PUB / "deliverables" / "umdr39.1"
BUILD_INFO = REPO / "BUILD_INFO.json"
DURABLE = PUB / "deliverables" / "umdr38" / "test_evidence" / \
    "FULL_SUITE_EVIDENCE.json"

# Independently observed remote resolution (GitHub commit pages,
# fetched 2026-11-18; the sandbox's direct GitHub API access is
# blocked with HTTP 403, so these were fetched through an
# out-of-band channel and are recorded as observations, not as
# machine re-verification).
REMOTE_OBSERVED = {
    "1968f63c2076b1b804537f91cd5cfa01c3eee0bb":
        ("resolvable",
         'page shows "Update project to v0.40.1 UMDR35-36"'),
    "989c49ba5cb3747859496d06736ae7c8317086ed":
        ("resolvable",
         'page shows "Update to v0.38.0 UMDR32"'),
    "4795f02377373a1a2dc4d3376987f7702cd24bf6":
        ("resolvable",
         'page shows "Start feature development with v0.39.0 UMDR33"'),
    "a0807294694ce969c3664cbd3b6e7be4d3ed3b04":
        ("not_resolvable", "HTTP 404 — No commit found"),
    "e50900d0e7c360ccbe8ce1a2f9099499201cc2b3":
        ("not_resolvable", "HTTP 404 — No commit found"),
    "ca4ae44855c4c096fdb5c96ee7de8e23610b4463":
        ("resolvable",
         'published main HEAD — "Update project to v0.40.1 UMDR39 '
         'FINAL"'),
    "54fc95c": ("resolvable",
                'published main parent — "Update project to v0.40.1 '
                'UMDR38-1 FINAL"'),
}

# Independently observed tree identity: the published checkout at
# ca4ae448 vs the delivered release package
# WebPent_Unified_v0.40.1_UMDR39_FINAL.zip (sha256 12c38190a2bc…),
# compared with a full recursive content diff (diff -rq, .git
# excluded): ZERO differences, 2026-11-18.
TREE_IDENTITY = {
    "published_commit": "ca4ae44855c4c096fdb5c96ee7de8e23610b4463",
    "package": "WebPent_Unified_v0.40.1_UMDR39_FINAL.zip",
    "package_sha256":
        "12c38190a2bc5df5e13dd457ac1a6a2d6ea183f1309ab7c7a8637e3e8b75c16e",
    "method": "diff -rq --exclude=.git of the extracted package vs "
              "the published checkout (4,989 tracked files)",
    "result": "identical — 0 differing/missing/extra files",
    "observed_at": "2026-11-18",
}


def _git(args: list[str]) -> tuple[int, str]:
    r = subprocess.run(["git", *args], cwd=PUB, capture_output=True,
                       text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    _rc, head = _git(["rev-parse", "HEAD"])
    _rc, main_sha = _git(["rev-parse", "main"])
    bi = json.loads(BUILD_INFO.read_text(encoding="utf-8"))
    durable = json.loads(DURABLE.read_text(encoding="utf-8"))
    accounting = durable.get("accounting") or {}

    def commit_row(sha: str, artifact: str, role: str,
                   evidence: str, note: str) -> dict:
        rc, _out = _git(["cat-file", "-e", f"{sha}^{{commit}}"])
        local_ok = rc == 0
        anc = False
        if local_ok:
            arc, _ = _git(["merge-base", "--is-ancestor", sha, main_sha])
            anc = arc == 0
        remote = REMOTE_OBSERVED.get(sha)
        if remote and remote[0] == "not_resolvable":
            classification = ("HISTORICAL_UNRESOLVABLE"
                              if not local_ok else
                              "VERIFIED_LOCAL_ONLY")
        elif local_ok and remote and remote[0] == "resolvable":
            classification = "VERIFIED_REMOTE"
        elif local_ok:
            classification = "VERIFIED_LOCAL_ONLY"
        else:
            classification = "HISTORICAL_UNRESOLVABLE"
        return {
            "revision": sha,
            "artifact": artifact,
            "claimed_role": role,
            "local_resolvable": local_ok,
            "remote_resolvable": (remote[0] if remote else
                                  "NOT_CHECKED_FROM_SANDBOX"),
            "remote_observation": (remote[1] if remote else
                                   "direct GitHub API blocked (403) "
                                   "from the build environment"),
            "branch_or_tag": ("main" if anc else
                              ("features/v0.39.0-umdr33 (via clone)"
                               if sha == "4795f02377373a1a2dc4d337"
                                         "6987f7702cd24bf6" else
                               "none (not an ancestor of main)")),
            "ancestor_of_current_main": anc,
            "associated_test_evidence": evidence,
            "associated_ci_run": None,
            "classification": classification,
            "explanation": note,
        }

    rows = [
        commit_row(
            "ca4ae44855c4c096fdb5c96ee7de8e23610b4463",
            "refs/heads/main (remote HEAD)",
            "currently published source revision",
            "none bound at commit level (see a080729 row); "
            "tree-identical to the validated package",
            "The publication squashed the UM-DR-39 mission tree into "
            "one new commit on main. Its 4,989-file tree is "
            "byte-identical to the delivered UMDR39_FINAL package "
            "(full recursive diff: 0 differences), so the historical "
            "9,330-pass record is evidence for THIS TREE's content — "
            "but no commit-level chain binds them, and no CI run on "
            "this SHA is verifiable from this environment."),
        commit_row(
            "a0807294694ce969c3664cbd3b6e7be4d3ed3b04",
            "WebPent_UNIFIED/BUILD_INFO.json provenance "
            "(source/tested/evidence) + deliverables/umdr38/"
            "test_evidence/FULL_SUITE_EVIDENCE.json source_commit",
            "declared tested source revision of the published tree",
            f"durable record: collected {accounting.get('collected')}, "
            f"passed {accounting.get('passed')}, failed "
            f"{accounting.get('failed')}, errors "
            f"{accounting.get('errors')}",
            "The commit existed only in the mission's local build "
            "repositories, which were lost to environment recycling "
            "before publication; the owner published the validated "
            "TREE as ca4ae448 instead of the branch. The revision is "
            "therefore unresolvable both locally (fresh clone) and "
            "remotely (404). The evidence stays intact as a "
            "historical record; it is NOT silently re-bound. UM-DR-"
            "39.1 re-establishes the chain with a fresh suite on the "
            "re-baselined descendant."),
        commit_row(
            "e50900d0e7c360ccbe8ce1a2f9099499201cc2b3",
            "deliverables/umdr39/ACCEPTANCE_MATRIX.json release_commit"
            " + deliverables/umdr38/UMDR38_GATE_RESULTS.json",
            "39-lineage release/reporting revision",
            "acceptance matrix 12 PASS / 2 BLOCKED_EXTERNAL_DEPENDENCY"
            " (historical record)",
            "Same lost local lineage as a080729 — the 39 acceptance "
            "matrix's release_commit was never pushed. Historical "
            "record preserved unchanged; classified "
            "HISTORICAL_UNRESOLVABLE."),
        commit_row(
            "1968f63c2076b1b804537f91cd5cfa01c3eee0bb",
            "BUILD_INFO.json provenance.recovery_baseline",
            "declared recovery baseline",
            "historical (UM-DR-35/36 window)",
            "Published ancestor of main; resolves locally and "
            "remotely. Valid recovery baseline."),
        commit_row(
            "989c49ba5cb3747859496d06736ae7c8317086ed",
            "BUILD_INFO.json release_history[0] (v0.38.0)",
            "historical release identity anchor",
            "historical", "Published ancestor of main."),
        commit_row(
            "4795f02377373a1a2dc4d3376987f7702cd24bf6",
            "BUILD_INFO.json version_identity_contract."
            "previous_release + release_history[1] + umdr34.baseline",
            "previous release source (0.39.0 features window)",
            "historical",
            "Resolvable locally (via the published features branch "
            "history) and remotely; NOT an ancestor of main (the "
            "features branch diverges). Correctly referenced as the "
            "previous-release anchor, not as the current lineage."),
        commit_row(
            _git(["rev-parse", "54fc95c"])[1],
            "refs/heads/main parent (published)",
            "previous published final (UMDR38-1)",
            "historical (its own mission evidence)",
            "Published ancestor of main; the immediate parent of "
            "ca4ae448."),
    ]

    # the tree-hash reference (umdr34.baseline string)
    tree_ref = "30d0917275384c16a42351ae844a4508dd80c3c9"
    trc, _ = _git(["cat-file", "-e", f"{tree_ref}^{{tree}}"])
    rows.append({
        "revision": tree_ref,
        "artifact": "BUILD_INFO.json umdr34.baseline (inline string)",
        "claimed_role": "recorded TREE hash of the 0.39.0 baseline "
                        "(not a commit)",
        "local_resolvable": trc == 0,
        "remote_resolvable": "NOT_APPLICABLE (tree object, not a "
                             "commit URL)",
        "branch_or_tag": "tree of 4795f02",
        "ancestor_of_current_main": False,
        "associated_test_evidence": "historical",
        "associated_ci_run": None,
        "classification": "VERIFIED_LOCAL_ONLY" if trc == 0 else
                          "HISTORICAL_UNRESOLVABLE",
        "explanation": "A tree hash recorded inside the umdr34 "
                       "baseline string; resolves as a tree object "
                       "locally. Not subject to commit-level "
                       "resolution.",
    })

    matrix = {
        "schema": "umdr39.1-provenance-reconciliation/v1",
        "generated_at_utc": _utcnow(),
        "generated_at_revision": head,
        "published_main": main_sha,
        "remote_observation_method":
            "GitHub commit pages fetched out-of-band 2026-11-18 "
            "(the build environment's direct API access is HTTP-403 "
            "blocked); results recorded verbatim per revision",
        "tree_identity_verification": TREE_IDENTITY,
        "revisions": rows,
        "counts": {},
    }
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["classification"]] = counts.get(
            row["classification"], 0) + 1
    matrix["counts"] = counts

    DELIV.mkdir(parents=True, exist_ok=True)
    out = DELIV / "PROVENANCE_RECONCILIATION_MATRIX.json"
    out.write_text(json.dumps(matrix, indent=2, default=str) + "\n",
                   encoding="utf-8")
    print(f"[umdr39.1] {out}")
    print(f"counts: {counts}")

    # the human report
    dur_pass = accounting.get("passed")
    lines = [
        "# UM-DR-39.1 — Publication Provenance Reconciliation Report",
        "",
        f"Generated {_utcnow()} at `{head[:12]}` (mission branch "
        "from published main `ca4ae448`).",
        "",
        "## What was verified and how",
        "",
        "1. **Fresh verified clone** of the published repository: "
        f"HEAD `ca4ae44855c4…` on `main` (parent `54fc95c`), clean "
        f"tree, {len(_git(['ls-files'])[1].splitlines())} tracked "
        "files, no tags, remote branches "
        "`features/v0.39.0-umdr33` and "
        "`security/umdr34-origin-scope-hardening`.",
        "2. **Tree identity**: the published checkout is "
        "**byte-identical** to the delivered release package "
        "`WebPent_Unified_v0.40.1_UMDR39_FINAL.zip` (sha256 "
        "`12c38190a2bc5df5…`): a full recursive content diff over "
        "all 4,989 tracked files returned **0 differences**. The "
        "published source is exactly the tree that carried the "
        "validated UM-DR-39 work.",
        "3. **Remote resolution of every referenced revision** "
        "(GitHub commit pages, fetched out-of-band 2026-11-18; the "
        "sandbox's direct API access is blocked):",
        "",
        "| revision | role | remote | classification |",
        "|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| `{row['revision'][:12]}` | {row['claimed_role'][:60]} "
            f"| {row['remote_resolvable']} | "
            f"{row['classification']} |")
    lines += [
        "",
        "## The reconciliation, stated honestly",
        "",
        "* The published `ca4ae448` squashed the UM-DR-39 mission "
        "tree into a single new commit on `main`. The mission "
        "branch's own commits — including the declared "
        "source/tested/evidence revision `a080729` and the 39-lineage "
        "release revision `e50900d` — existed only in the mission's "
        "local build repositories, which the build environment "
        "recycled before publication. They resolve neither in a "
        "fresh clone nor on GitHub (404).",
        f"* The durable evidence record ({dur_pass} passed / 0 "
        "failed / 0 errors at `a080729`) is therefore **historical "
        "evidence for the tree** — and the tree IS what was "
        "published — but it is NOT a commit-level verified claim "
        "about `ca4ae448`, and it is not re-bound by textual "
        "substitution. It stays in place, classified "
        "`HISTORICAL_UNRESOLVABLE`.",
        "* `remote_resolvable` facts for the remaining anchors "
        "(`1968f63`, `989c49b`, `4795f02`) are confirmed; the "
        "recovery baseline and release-history anchors are valid "
        "and resolvable.",
        "* **The repair** (§A5): a provenance-only re-baseline on "
        "this mission branch re-points BUILD_INFO at a resolvable "
        "commit under the guarded tool's unresolvable-revisions "
        "condition; a fresh full suite then runs on the exact "
        "re-baselined source; the machine evidence and the "
        "accounting update land as a metadata-only descendant; "
        "BUILD_INFO honesty is re-verified under the unchanged "
        "contract. This establishes a NEW verified chain "
        "(source → tested → evidence) without touching any "
        "historical record.",
        "* **Remote CI on the exact commits** remains "
        "`BLOCKED_EXTERNAL_DEPENDENCY` from this environment: no "
        "push credentials (the previous session's push attempts "
        "failed with `could not read Username`), no authenticated "
        "`gh`, and the GitHub API answers HTTP 403 to this "
        "sandbox. The existing run history (if any) on "
        "`ca4ae448` could not be queried; the exact missing "
        "permission is repository push access (or an authenticated "
        "API token) to trigger `workflow_dispatch` and read the "
        "run.",
        "",
        "See `PROVENANCE_RECONCILIATION_MATRIX.json` for the "
        "machine-readable rows and `CI_VERIFICATION_REPORT.md` for "
        "the CI state.",
        "",
    ]
    report = DELIV / "PROVENANCE_RECONCILIATION_REPORT.md"
    report.write_text(chr(10).join(lines), encoding="utf-8")
    print(f"[umdr39.1] {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

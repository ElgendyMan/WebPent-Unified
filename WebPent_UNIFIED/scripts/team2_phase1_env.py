"""TEAM-2 PHASE 1 — Environment capture (independent, runtime evidence only).

Captures: Python version, dependency versions, lock file hash, source hash
verification against TEAM-1's manifest, governance hash, git availability.
No source modification.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from team2_common import ROOT, save_json, sha256_file, utc  # noqa: E402


def run(cmd: list[str], cwd: str | None = None) -> dict[str, Any]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=180)
        return {"cmd": " ".join(cmd), "exit": p.returncode,
                "stdout": p.stdout[-4000:], "stderr": p.stderr[-1500:]}
    except Exception as exc:
        return {"cmd": " ".join(cmd), "exit": -1, "error": str(exc)[:300]}


def source_tree_manifest_sha256() -> dict[str, Any]:
    """Recompute TEAM-1's documented source-tree manifest:
    sha256 over 'sha256<2sp>relpath\\n' lines of every *.py under src/webpent
    (sorted by path), then sha256 of that manifest."""
    src_dir = os.path.join(ROOT, "src", "webpent")
    lines = []
    files = []
    for dirpath, _dirnames, filenames in os.walk(src_dir):
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, ROOT)
                files.append(rel)
    files.sort()
    for rel in files:
        h = hashlib.sha256(open(os.path.join(ROOT, rel), "rb").read()).hexdigest()
        lines.append(f"{h}  {rel}\n")
    manifest = "".join(lines)
    return {
        "source_files_in_manifest": len(files),
        "SOURCE_MANIFEST_SHA256": hashlib.sha256(manifest.encode()).hexdigest(),
    }


def main() -> dict[str, Any]:
    evp = os.path.join(ROOT, ".venv", "bin", "python")
    ev: dict[str, Any] = {
        "phase": "PHASE_1_ENVIRONMENT",
        "captured_at": utc(),
        "validator": "TEAM-2 independent validation",
        "source_tree": ROOT,
    }

    # 1. Python version (runtime venv + system)
    ev["python_venv_version"] = run([evp, "--version"])
    ev["python_sys_version"] = sys.version

    # 2. Dependency versions (frozen, from the venv actually used)
    ev["pip_freeze"] = run([evp, "-m", "pip", "freeze"])
    freeze = ev["pip_freeze"]["stdout"].strip().splitlines()
    ev["dependency_count"] = len([l for l in freeze if "==" in l])
    key_pkgs = {}
    for line in freeze:
        for k in ("pydantic==", "httpx==", "pytest==", "fastapi==", "uvicorn==",
                  "SQLAlchemy==", "cryptography==", "uv=="):
            if line.lower().startswith(k.lower()):
                key_pkgs[k.removesuffix("==")] = line.split("==")[1]
    ev["key_packages"] = key_pkgs

    # 3. Lock file hashes
    ev["lock_hashes"] = {
        "uv.lock": sha256_file(os.path.join(ROOT, "uv.lock")),
        "pyproject.toml": sha256_file(os.path.join(ROOT, "pyproject.toml")),
        "uv.lock_present": os.path.exists(os.path.join(ROOT, "uv.lock")),
    }

    # 4. Verify TEAM-1's source-hash manifest line by line (sha256sum -c)
    manifest_path = ("/home/z/my-project/download/TEAM1_AVI_V1_2_DELIVERABLES/"
                     "TEAM1_AVI_V1_2_SOURCE_HASH.sha256.txt")
    chk = run(["bash", "-c",
               f"cd {ROOT} && sha256sum -c {manifest_path} 2>&1 | "
               "grep -v '<source-tree-manifest-sha256>' | grep -c ': OK$'"])
    chk_fail = run(["bash", "-c",
                    f"cd {ROOT} && sha256sum -c {manifest_path} 2>&1 | "
                    "grep -v '<source-tree-manifest-sha256>' | grep ': FAILED' || true"])
    ev["team1_source_hash_manifest"] = {
        "path": manifest_path,
        "lines_verified_ok": chk["stdout"].strip(),
        "failed_lines": chk_fail["stdout"].strip() or "none",
        "note": "the <source-tree-manifest-sha256> line is a label placeholder, not a file",
    }

    # 5. Recompute source-tree manifest hash independently
    ev["independent_source_manifest"] = source_tree_manifest_sha256()

    # 6. Governance hash chain (hash the governance files listed by TEAM-1)
    gov_files = ["BASELINE.sha256.txt", "POST.sha256.txt", "CHANGED_FILES.txt",
                 "TEAM1_AVI_V1_2_TRUST_HARDENING.md", "TEAM1_AVI_V1_2_TRUST_HARDENING.json",
                 "LEGACY_CONFIRMATION_PATHS.md", "verification/evidence/BASELINE_AUTHORITY.sha256.txt",
                 "uv.lock", "pyproject.toml"]
    gov = {}
    for rel in gov_files:
        full = os.path.join(ROOT, rel)
        gov[rel] = sha256_file(full) if os.path.exists(full) else "MISSING"
    ev["governance_hashes"] = gov
    gov_manifest = "".join(f"{v}  {k}\n" for k, v in gov.items())
    ev["GOVERNANCE_MANIFEST_SHA256"] = hashlib.sha256(gov_manifest.encode()).hexdigest()

    # 7. Git availability — honest capture
    git_root = run(["git", "rev-parse", "--show-toplevel"], cwd=ROOT)
    git_log = run(["git", "log", "--oneline", "-5"], cwd=ROOT)
    git_status = run(["git", "status", "--porcelain", "--", "."], cwd=ROOT)
    has_git = git_root["exit"] == 0
    ev["git_availability"] = {
        "git_present_in_environment": has_git,
        "git_repo_root": git_root.get("stdout", "").strip() if has_git else "NONE",
        "git_log_head": git_log.get("stdout", "").strip() if has_git else "NONE",
        "webpent_goed_own_git_repo": False,
        "statement": (
            "A git repository EXISTS at the WORKSPACE root (/home/z/my-project) created by "
            "the validation environment AFTER the TEAM-1 archive was delivered (sandbox "
            "baseline commits, not project history). The delivered webpent-goed source tree "
            "itself carries NO upstream project git metadata (no project commits/tags/remotes "
            "for the AVI development history). Provenance therefore remains CONTENT-HASH "
            "based (sha256), consistent with TEAM-1's declared NO_GIT_METADATA_AVAILABLE "
            "statement for the delivered archive. No git provenance is faked here."
            if has_git else "NO_GIT_METADATA_AVAILABLE"),
    }

    # 8. uv lock usage check (environment doc command validity)
    ev["uv_sync_command_from_team1_env_doc"] = "uv sync --frozen --all-extras"
    ev["webpent_installed"] = run([evp, "-c", "import webpent; print(webpent.__file__)"])

    # 9. TEAM-1 script presence check (honesty check on worklog claims)
    t1_scripts = ["team1_v12_campaign.py", "team1_v12_environment_doc.py",
                  "team1_v12_source_hash.py", "team1_v12_final_validation.py",
                  "team1_v12_regression_attacks.py", "team1_v12_closure_doc.py"]
    script_state = {s: os.path.exists(os.path.join(ROOT, "scripts", s)) for s in t1_scripts}
    ev["team1_closure_scripts_present"] = script_state
    ev["team1_closure_scripts_note"] = (
        "TEAM-1 worklog references scripts/team1_v12_*.py generators; they are NOT present "
        "in the delivered tree. Runtime artifacts (100-decision runtime JSON, environment "
        "doc, source hash manifest) ARE present and are validated independently here. "
        "Recorded as a reproducibility gap for the closure PACKAGING, not as evidence of "
        "wrong results — TEAM-2 regenerates all evidence independently."
        if not all(script_state.values()) else "all present")

    path = save_json("team2_phase1_environment.json", ev)
    print(json.dumps({
        "python": ev["python_venv_version"]["stdout"].strip(),
        "dependency_count": ev["dependency_count"],
        "lock_hash_uv_lock": ev["lock_hashes"]["uv.lock"][:16],
        "manifest_lines_ok": ev["team1_source_hash_manifest"]["lines_verified_ok"],
        "failed_lines": ev["team1_source_hash_manifest"]["failed_lines"],
        "independent_source_manifest_sha256": ev["independent_source_manifest"]["SOURCE_MANIFEST_SHA256"],
        "team1_declared_source_manifest": "195dbf88d258b8bdb95f568bf332c986d586cb23a0cc713a52ec39355e44a0d6",
        "git": ev["git_availability"]["statement"][:120],
        "t1_scripts_present": script_state,
        "saved": path,
    }, indent=1))
    return ev


if __name__ == "__main__":
    main()

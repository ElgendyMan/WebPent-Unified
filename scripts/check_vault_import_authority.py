#!/usr/bin/env python3
"""Sprint I-1, item 3.1 — vault import authority static CI gate (M4 v2.1
OQ-3 / §3.3.3, "Layer 2 — Static CI Gate").

Model: scripts/check_orchestrator_construction_authority.py, per M4's own
instruction ("A NEW static analysis gate ... modeled on the existing
check_orchestrator_construction_authority.py literal-substring pattern").
This gate uses AST-based detection instead of literal-substring matching
— stricter than the model script, and necessary here: a literal-substring
search for "reauth_vault" would false-positive on the several files that
mention it only in comments/docstrings (state/state.py:551,
utils/task_crypto.py:20-21,62 — found and verified during this sprint;
see the sprint changelog). AST-based detection also directly satisfies
M4's explicit requirement to "cover direct, multiline, aliased, and
re-exported imports" — ast.ImportFrom naturally normalizes all of those
forms regardless of source formatting.

Contract enforced (OQ-3, ratified):
  Any module outside the allowlist that imports webpent.auth.reauth_vault
  directly, OR imports any of its ten re-exported public symbols
  (seal_reauth_secret, unseal_reauth_secret, seal_session_cookies,
  unseal_session_cookies, seal_identity_profiles, unseal_identity_profiles,
  identity_vault_key, clear_reauth_secret, sweep_expired, vault_stats)
  via `from webpent.auth import ...` OR `from webpent.auth.reauth_vault
  import ...`, fails the build.

  Allowlist = exactly the M4 Table 2-2 caller-inventory files, plus the
  future context-authority module (not yet built — see KNOWN GAP below),
  plus the four test files that legitimately exercise the vault directly.

KNOWN GAP (documented, not silently skipped): M4 additionally requires
"the gate MUST ALSO fail if any comparative-flow module imports the
vault at all" (OQ-3). M4 does not anywhere enumerate a concrete file
list of "comparative-flow modules" — Part 3.5's two-principal
comparative flow is planned/future design, and its implementing code
(including the context-authority module itself) is not part of this
sprint. This gate therefore does not (and cannot yet) enforce that
second bar. Re-visit once the comparative flow's actual module set
exists.

Usage:
  python scripts/check_vault_import_authority.py            # human-readable report
  python scripts/check_vault_import_authority.py --quiet    # CI: exit 1 on violation
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELF_FILE = Path(__file__).resolve()

VAULT_MODULE = "webpent.auth.reauth_vault"
REEXPORT_MODULE = "webpent.auth"

# All ten public vault symbols, per M4 OQ-3 (ratified) — every one is
# watched, matching both the direct-from-reauth_vault path and the
# re-exported-from-auth path (auth/__init__.py currently re-exports five
# of the ten; the other five are imported directly from reauth_vault by
# consumers — Table 2-2). This gate watches all ten via BOTH paths
# regardless of which five auth/__init__.py currently re-exports, so a
# future change to auth/__init__.py's re-export list can't silently
# widen what's allowed.
WATCHED_SYMBOLS = frozenset({
    "seal_reauth_secret", "unseal_reauth_secret",
    "seal_session_cookies", "unseal_session_cookies",
    "seal_identity_profiles", "unseal_identity_profiles",
    "identity_vault_key", "clear_reauth_secret",
    "sweep_expired", "vault_stats",
})

# M4 Table 2-2 — the v1 audit's complete caller inventory (reproduced
# verbatim by file; this sprint verified the file SET against the real
# current tree via a direct grep sweep, since M4's own line numbers may
# have drifted — the files below matched exactly, with zero real drift
# and two comment-only false positives excluded, see sprint changelog).
TABLE_2_2_ALLOWLIST: frozenset[Path] = frozenset(
    ROOT / "src" / "webpent" / rel for rel in (
        "workers/pentest_worker.py",
        "cli/commands.py",
        "agents/authentication/agent.py",
        "agents/validator/agent.py",
        "agents/access_control/agent.py",
        "shared/session_liveness.py",
        "graph/checkpoints.py",
        "shared/identity_provisioning.py",
        # UM-DR-24 (2026-11-06): genuinely new legacy call site, added
        # after deliberate review per this script's own documented route.
        # auth/worker_session_factory.py is the M3 UM-DR-17 ق7 identity
        # runner's DESIGNATED vault-bridging seam: it unseals the sealed
        # identity profiles the worker sealed (unseal_identity_profiles)
        # and mirrors run_pentest_task's sealing key shape
        # (identity_vault_key) so the per-identity session factory reads
        # exactly what the worker sealed. The UM-DR-17 review caught and
        # fixed the first draft's cross-role fallback-scan leak; STRICT
        # own-role matching is pinned by tests/test_m3_identity_orchestrator_runner.py
        # (12 tests). Routing through production/context_authority.py was
        # evaluated and REJECTED: that module intentionally wraps only the
        # reauth-secret seal/unseal surface (seal_reauth_secret /
        # unseal_reauth_secret) — re-exposing identity-profile unsealing
        # through it would create a NEW vault re-export surface, the exact
        # expansion this authority rule exists to prevent.
        "auth/worker_session_factory.py",
    )
)

# The vault module and its re-export point are themselves not violations
# of their own rule.
SELF_DEFINING_MODULES: frozenset[Path] = frozenset({
    ROOT / "src" / "webpent" / "auth" / "reauth_vault.py",
    ROOT / "src" / "webpent" / "auth" / "__init__.py",
})

# The context-authority module (M4 OQ-3: "a separate module ... the vault
# import is internal to this module and is NEVER re-exported") is built in
# Sprint I-2 at src/webpent/production/context_authority.py (per the sprint
# spec, Part 2.1). The earlier sprint allowlisted a shared/ path as "future";
# both paths are allowlisted here so a relocation between shared/ and
# production/ does not silently break the gate. The production path is the
# ratified location.
FUTURE_CONTEXT_AUTHORITY_MODULE = ROOT / "src" / "webpent" / "shared" / "context_authority.py"
CONTEXT_AUTHORITY_MODULE = ROOT / "src" / "webpent" / "production" / "context_authority.py"

# Test files that legitimately exercise the vault directly — verified via
# a direct grep sweep of tests/ (not assumed from M4, which doesn't
# enumerate test files at all).
TEST_ALLOWLIST: frozenset[Path] = frozenset(
    ROOT / "tests" / name for name in (
        "test_checkpoint_redaction.py",
        "test_v10_p0_reauth_vault_and_emergency_persist.py",
        "test_vip_audit_gap_closure.py",
        "test_vip_shared_reauth_vault.py",
    )
) | {
    # This gate's own regression test — reviewed alongside this script.
    ROOT / "tests" / "test_check_vault_import_authority.py",
}

ALLOWLIST: frozenset[Path] = (
    TABLE_2_2_ALLOWLIST | SELF_DEFINING_MODULES | TEST_ALLOWLIST
    | {FUTURE_CONTEXT_AUTHORITY_MODULE, CONTEXT_AUTHORITY_MODULE}
)

EXCLUDED_DIR_NAMES = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".mypy_cache", ".pytest_cache", "build", "dist",
}


def _violating_names(node: ast.ImportFrom) -> list[str]:
    """Return which imported names from this ImportFrom node are vault
    symbols, given the module it imports from."""
    if node.module == VAULT_MODULE:
        # ANY import from reauth_vault directly is a violation — not
        # just the ten watched symbols (the module also exposes private
        # helpers; importing anything from it outside the allowlist is
        # already the thing being denied).
        return [alias.name for alias in node.names]
    if node.module == REEXPORT_MODULE:
        return [alias.name for alias in node.names if alias.name in WATCHED_SYMBOLS]
    return []


def find_violations() -> list[tuple[Path, int, str]]:
    violations: list[tuple[Path, int, str]] = []
    for path in (ROOT / "src").rglob("*.py"):
        if any(part in EXCLUDED_DIR_NAMES for part in path.parts):
            continue
        if path in ALLOWLIST:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "reauth_vault" not in text and "webpent.auth" not in text:
            continue
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names = _violating_names(node)
                if names:
                    violations.append((
                        path, node.lineno,
                        f"from {node.module} import {', '.join(names)}",
                    ))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == VAULT_MODULE:
                        violations.append((
                            path, node.lineno, f"import {alias.name}"
                            + (f" as {alias.asname}" if alias.asname else ""),
                        ))
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="CI mode: no output on success, exit 1 on violation")
    args = parser.parse_args()

    violations = find_violations()

    if not violations:
        if not args.quiet:
            print(
                "OK: webpent.auth.reauth_vault (and its 10 re-exported symbols) "
                f"are imported only by the {len(TABLE_2_2_ALLOWLIST)} Table 2-2 "
                f"caller sites, the vault/re-export modules themselves, and the "
                f"{len(TEST_ALLOWLIST)} approved test files. NOTE: this gate does "
                "NOT yet enforce the comparative-flow-module bar (OQ-3) — no "
                "concrete comparative-flow module list exists yet this sprint; "
                "see this script's own docstring."
            )
        return 0

    print(f"FAIL: {len(violations)} unauthorized vault import site(s) found:", file=sys.stderr)
    for path, lineno, detail in violations:
        print(f"  {path.relative_to(ROOT)}:{lineno}: {detail}", file=sys.stderr)
    print(
        "\nRoute callers through the context authority module once it exists "
        "(M4 OQ-3), or add a genuinely new legacy call site to "
        "TABLE_2_2_ALLOWLIST in this script after deliberate review — do not "
        "weaken this check silently.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

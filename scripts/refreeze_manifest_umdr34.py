#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the UM-DR-34 window (2026-11-10)
per the DR-009 / refreeze protocol.

Documented scope of this refreeze — exactly FOURTEEN frozen files, all
thawed under the UM-DR-34 charter (scope authority, safe egress &
execution governance):

  1.  src/webpent/scope/__init__.py — export the canonical authority
      surface (EngagementScopeAuthority, ControlPlaneEgressPolicy,
      authority_from_policy, authority_for_target_only, ...).
  2.  src/webpent/scope/models.py — ScopeDecision extended with the
      canonical audit fields (§2.2); backward-compatible construction.
  3.  src/webpent/scope/enforcer.py — fnmatch host matching REPLACED by
      the ONE strict compiler (scope/authority.compile_host_matcher);
      explicit None port handling (port 0 never a default-port alias);
      canonical audit fields on in-scope decisions.
  4.  src/webpent/scope/parser.py — boolean ``out_of_scope`` markers in
      HackerOne/Bugcrowd-style exports no longer crash the parser
      (fail-closed deny rule instead) — §2.4.
  5.  src/webpent/shared/engagement_scope.py — atomic EngagementContext
      (one ContextVar, structured tokens, nested restore); ENGAGEMENT vs
      CONTROL_PLANE egress separation; fail-closed admission (§3.1/3.2);
      bare-host declarations bind default HTTP(S) ports only (§3.3).
  6.  src/webpent/shared/http.py — method-aware canonical redirect guard
      (§4.3); async transport rate ceiling + loopback-trusted parity
      (§4.2/§5.2, including the latent async-response-hook crash fix);
      default-on engagement ceiling, fail-closed on governor failure
      (§5.1/§5.4).
  7.  src/webpent/shared/global_rate_governor.py — Redis cross-process
      coordination injection, honest coordination_scope reporting,
      fail-closed ``require_coordination`` posture (§5.3).
  8.  src/webpent/config/settings.py — global_rate_governor_redis_url /
      _require_coordination fields; rate_limit_enabled documented as the
      non-engagement switch only.
  9.  src/webpent/shared/untrusted_content.py — secure_llm_input Mapping
      key check (§6.1); cookie-name families (§6.2);
      additional_kwargs/tool_calls sanitization (§6.3).
  10. src/webpent/shared/redaction.py — key-aware structured redaction
      (§6.4); checkpoint-specific redaction in graph/checkpoints.py
      untouched.
  11. src/webpent/graph/checkpoints.py — runtime_context degraded-marker
      contract (§7): no silent "{}", no blank-runtime false-success
      resume; secret-free structured logging.
  12. src/webpent/agents/hunter_runner.py — acquire()/release() permits
      around real execution (§4.6/§5.2); omitted scope_policy builds an
      explicit bounded target-only authority reported as target_only.
  13. src/webpent/families/execution_node.py — full safe factory (redirect
      hook + untrusted-content mask) instead of a bare pinning transport
      (§4.8).

Regression coverage verified BEFORE this re-pin (tests/test_umdr34_*.py,
170 tests):
  test_umdr34_canonical_scope_authority.py  — wildcard/path/origin/method
      adversarial matrix, parser unification, determinism, deny precedence
  test_umdr34_engagement_lifecycle.py       — fail-closed admission,
      nested restore, exception paths, thread/async isolation,
      control-plane separation, bare-host port binding
  test_umdr34_boundary_enforcement.py       — sync/async/redirect
      denials with ZERO network attempts, rate parity, fail-closed
  test_umdr34_llm_redaction.py              — key checks, cookie families,
      guarded runnable invoke/ainvoke/batch/stream with a recording
      fake provider
  test_umdr34_checkpoint_safety.py          — degraded marker, logged,
      no secrets in logs, no blank-runtime resume
Plus every pre-existing suite touching these modules (scope, SSRF,
rate ceiling, checkpoint redaction, browser hunter, untrusted content)
re-run green before the manifest write.

The pre-unfreeze baseline manifest is untouched. Self-verifying: the
result is re-hashed from disk before write.

Usage: python3 scripts/refreeze_manifest_umdr34.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

UMDR34_REPINNED_FILES = (
    "src/webpent/__init__.py",  # 0.39.0 -> 0.40.0 version bump (UM-DR-33 precedent)
    "src/webpent/scope/__init__.py",
    "src/webpent/scope/models.py",
    "src/webpent/scope/enforcer.py",
    "src/webpent/scope/parser.py",
    "src/webpent/shared/engagement_scope.py",
    "src/webpent/shared/http.py",
    "src/webpent/shared/global_rate_governor.py",
    "src/webpent/config/settings.py",
    "src/webpent/shared/untrusted_content.py",
    "src/webpent/shared/redaction.py",
    "src/webpent/graph/checkpoints.py",
    "src/webpent/agents/hunter_runner.py",
    "src/webpent/families/execution_node.py",
)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    pins: dict[str, str] = {}
    order: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        digest, _, relpath = line.partition("  ")
        pins[relpath] = digest
        order.append(relpath)

    missing = [f for f in UMDR34_REPINNED_FILES if f not in pins]
    if missing:
        print(f"FATAL: files not in manifest: {missing}", file=sys.stderr)
        return 2

    print("Old pins (recorded for the audit trail):")
    new_pins: dict[str, str] = {}
    for relpath in UMDR34_REPINNED_FILES:
        old = pins[relpath]
        target = REPO / relpath
        if not target.is_file():
            print(f"FATAL: thawed file missing on disk: {relpath}", file=sys.stderr)
            return 2
        new = sha256_of(target)
        new_pins[relpath] = new
        marker = " (unchanged)" if old == new else ""
        print(f"  {old[:16]}… -> {new[:16]}…  {relpath}{marker}")

    rewritten = [
        f"{new_pins.get(relpath, pins[relpath])}  {relpath}" for relpath in order
    ]

    # Self-verify: re-hash from disk before writing.
    for relpath in UMDR34_REPINNED_FILES:
        assert sha256_of(REPO / relpath) == new_pins[relpath]

    MANIFEST.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
    print(
        f"\nRe-froze {len(UMDR34_REPINNED_FILES)} file(s); manifest entries: "
        f"{len(order)} (unchanged count)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

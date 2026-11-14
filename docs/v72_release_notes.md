# WebPent v72 Release Notes

## Scope

This release applies the Sprint 0–4 hardening and Smart Autonomous Bug Hunter work on the existing WebPent codebase. It does not modify WAPTLab or Juice Shop, and it does not claim live WAPTLab findings from the local quality gate.

## Implemented changes

The release includes versioned PBKDF2-HMAC-SHA256 envelopes with legacy read-back and key rotation support, canonical engagement-scope matching for IDNA/IPv6/scheme/port/path boundaries, Smart scan profiles, convergent autonomous stop rules, centralized GoalTree helpers, and ProofBundle promotion guards.

Confirmation paths now require behavior-based evidence. The relevant validators enforce causal evidence, a completed negative control, and a sealed ProofBundle before a finding can become Tool-Confirmed. Swagger SSRF, JWT, BAC/IDOR, XSS replay, OOB callbacks, cloud-storage markers, subdomain fingerprints, structural heuristics, and generic validator paths are covered by fail-closed guards. Heuristic-only paths remain Needs Human Review.

The dependency set was upgraded to the resolved LangGraph/LangChain 1.x generation. The legacy `langchain` text-splitter fallback was removed in favor of `langchain_text_splitters`, and the unused internal `search_disclosed_reports` helper was removed while the runtime disclosed-report ingestion and advisory path remains intact.

The quality gate now resolves `ruff`, `bandit`, and `pip-audit` from the executable directory beside the active Python interpreter before falling back to `PATH`. Nuclei now distinguishes a successful empty result (`no_match`) from a panic, fatal error, or non-zero exit (`TOOL_INFRA_FAILURE`). BAC also supports a bounded optional initial cooldown and preserves the existing fail-closed confirmation guards; a `429` is never treated as a negative control.

The quality gate writes a provisional report before building the release manifest, writes the final report with the manifest check, and refreshes the manifest afterward so release hashes do not intentionally describe a stale gate report. Production startup is now fail-closed for unexpected preflight errors through one shared API/worker helper. The production compose validates configuration before startup, waits for `/health`, requires explicit production CORS/rate limiting/Redis TLS settings, and enables bind-mount ownership fail-fast. Docker builds accept an immutable `BASE_IMAGE` and release tag.

## Verification

| Gate | Result |
|---|---|
| Compileall | Passed |
| Ruff, project source/tests/scripts | Passed with 0 errors |
| Pytest | 1108 passed, 0 failed in the latest documented baseline |
| Bandit high severity | Passed |
| pip-audit strict | Passed; no known vulnerabilities in the lock-derived requirements |
| CycloneDX SBOM generation | Passed |
| Release manifest | Generated with SHA-256 file hashes; signature remains operator-controlled |
| WAPTLab safety artifact | Passed as a non-contacting/local safety contract artifact |

The quality artifact records `hard_checks_passed: true` and `passed: false`. The overall release flag is intentionally false because staging Docker/worker evidence, live qualification, and operational backup/restore evidence remain unclosed. This is deliberate and preserves the project's honest classification as a **production-hardened release candidate**, not production-qualified or VIP-qualified.

## Live qualification boundary

The latest documented WAPTLab qualification produced 13 findings and 0 Tool-Confirmed findings. BAC recorded owner `429`, foreign `200`, and anonymous `302`, but no sealed `evidence_bundle` was produced. The result is therefore inconclusive for IDOR and is not promoted. SSTI paths also remained non-confirmed because the replay encountered the lab's defensive filters or incomplete OTP/2FA state. No bypass was added and no WAPTLab source or deployment was modified.

## Reproducibility

Run the final gate from the project root with the project virtual environment active:

```bash
export PYTHONPATH="$PWD/src"
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python scripts/run_vip_quality_gate.py
```

The machine-readable result is written to `docs/vip_quality_gate.json`. The gate may return exit code `1` while known qualification blockers remain, even when every hard check passes.

## Safety boundary

No WAPTLab or Juice Shop source, deployment, database, or live target was modified by this release. No unverified finding is promoted to confirmed status, and no live count of WAPTLab vulnerabilities is asserted by the release artifacts.

## Release posture

**Hard checks green; production hardening implemented; staging qualification blockers explicit; production-qualified/VIP status not claimed.** See [`docs/production_readiness_20260821.md`](production_readiness_20260821.md), [`docs/v72_release_handoff.md`](v72_release_handoff.md), and [`docs/v72_plan_compliance_audit.md`](v72_plan_compliance_audit.md) for the current handoff and residual register.

**Author:** Manus AI

# M2_PHASE_REPORT.md — M2 (Authorization, Scope & Execution Security)

**Phase:** M2 of the CANONICAL_PHASE_REGISTRY (Part 4 §4 — release blocker).
**Date closed:** 2026-11-05 (UTC).
**Window:** DRIFT_REGISTER UM-DR-15.
**Baseline:** post-M1b tree (UM-DR-14); frozen authority manifest (13 files) byte-verified before and after.
**Refreeze:** `scripts/refreeze_manifest_m2_authorization_scope.py` — exactly 3 declared frozen changes (cli/commands.py, cli/unified_hunt.py, shared/direct_io_inventory.py), tests-before-refreeze discipline, post-write self-check passed.

---

## 1. What was delivered

### M2-A — Structured, tamper-evident Authorization Manifest

The Part-4 §4 objective — replace the free-text `--authorization` pointer with a structured manifest — is implemented in `models/authorization.py` (new file, outside the frozen gate):

- `AuthorizationManifest` (`webpent-authorization-manifest-v1`, pydantic `extra="forbid"`): `client_id` + `engagement_id` both REQUIRED (the same isolation root `EngagementContract` enforces), operator, `authorization_reference`, `authorized_origins` (normalized origins), `excluded_hosts`, include/exclude path rules, `not_before`/`expires_at`.
- **Tamper evidence:** `manifest_sha256` = sha256 over the canonical JSON of every other field. `verify_integrity()` recomputes and refuses on ANY divergence — a flipped origin, a silently extended expiry, or a swapped reference cannot pass. `sign_manifest_document()` gives operators the canonical signed form (signing and verification share one canonicalization; the digest is never hand-computed).
- **Fail-closed decisions:** `authorize_target()`/`require_authorization_manifest()` refuse — with exact, operator-readable reasons — on: missing file, bad JSON, wrong schema_version, missing fields, placeholder reference (the H-2 CHANGE-ME contract, enforced at SIGN time too), digest mismatch, expired/not-yet-valid window, out-of-scope origin, subdomain of an authorized origin, excluded host, and reference mismatch.
- **CLI wiring:** `webpent hunt --authorization-manifest PATH` — the free-text `--authorization` value must EQUAL the manifest's `authorization_reference`, making the pointer verifiable instead of self-asserted while keeping the command surface backward-compatible. Verified manifest origins join the declared engagement hosts. Both new gates run BEFORE the `run_graph=False` preview return — `webpent init`'s preview refuses unauthorized invocations too.
- **CLI scope gate:** `webpent hunt --scope-file PATH` closes the worker/CLI asymmetry — the SAME parser (`shared/scope_file.py`) and the SAME fail-closed codes (`scope_file_target_url_not_in_scope/_excluded/_path_excluded`) now guard the CLI entry, and the declaration feeds `raw_scope_entries`/`scope_source`/`scope_declaration` exactly like the worker path.

### M2-B — Adversarial scope corpus (26 tests)

Against the REAL enforcement seams, per the registry's named corpus:

| Attack class | Seam attacked | Outcome pinned |
|---|---|---|
| Cloud metadata (169.254.169.254, fe80::, IPv4-mapped) | blocklist + pinned transport | refused without DNS, end-to-end |
| Encoded hosts (hex/octal/decimal/shortened) | `_is_blocked_host` DNS fallthrough | resolved and caught |
| DNS rebinding TOCTOU | `SSRFPinningTransport` | poisoned second lookup never reaches a socket |
| Multi-record (public+private) DNS | blocklist-every-IP | fail-closed |
| DNS failure | `_resolve_first_ip`/`_is_blocked_host` | fail-closed |
| Cross-origin redirect (public, undeclared) | `_redirect_guard` OriginPolicy | refused |
| Redirect to metadata | `_redirect_guard` + transport | refused (defence in depth) |
| Own-origin redirect | OriginPolicy | followed |
| Engagement carve-out | `is_engagement_target_host` | host-EXACT (a second private host stays blocked) |
| Link-local declaration/admission | `set_engagement_target_hosts` + `admission_target_check` | refused unconditionally |
| Poison argv (`--os-shell`, metadata URLs, `file://`) | ScopeLaw FV-1 | hard deny regardless of scope verdict |
| Unregistered tools | ScopeLaw | refused |

### M2-C — Execution security guards (11 tests)

- `run_command` argv contract: shell-strings and non-str argv refused (TypeError); unregistered executables refused (typed).
- `WEBPENT_ALLOWED_EXECUTABLES` env gate behavior.
- **AST scan: zero real `shell=True` call sites** in the production tree (string examples in remediation templates don't count — the scan walks `ast.Call` keywords).
- **Every AST-verified spawn site must be in the documented inventory** — this detector found the M2 window's one real defect (below).
- `ActionAuthority` default-deny: active action without approval denied; `smart_auto_approve` CANNOT rescue an out-of-scope target (the L-2 contract pinned against the authority gate itself); destructive actions never autonomous.
- `--auto-approve` changes ONLY the interrupt list — the scope/authority gates are graph NODES and run in both builds.
- Container posture: the documented gosu non-root drop verified (or a static USER directive).

## 2. Defects found and closed this window

1. **Undocumented subprocess spawn sites (M2-C detector):** `production/verdict_bridge.py`, `memory/ab_lab.py`, `apex/sandbox.py` spawn processes via `subprocess.run` without an entry in the approved map. Verified bounded argv-typed calls (cwd-pinned/timeout/`noqa: S603`); documented in `shared/direct_io_inventory.py` with reasons (refrozen declared change).
2. **Stale g02 artifact + unapproved pin (pre-existing, closed deliberately):** the artifact was last regenerated at UNIFIED-MERGE phase-1/2 (2026-11-02); the M0 fixes, the M1-A M-4/M-5 safe-transport migration and M1-C windows never refreshed it. `scripts/regen_direct_io_inventory_m2_authorization_scope.py` regenerated with fail-closed gates (removals == exactly the 5 physically-removed M-4/M-5 identities; additions only from the declared file set). The unapproved pin was adjudicated 47→36 records / 41→30 identities: 6 subprocess identities approved by documentation, 5 removed by the M-4/M-5 migration — **zero new unapproved sites**.
3. **`scope_template.yaml` usage-line drift:** advertised a nonexistent `webpent hunt --scope` flag; now points at the real `--url/--scope-file` (line grammar) and `webpent scope check` (typed YAML). The `run_campaign.sh` retired-flag problem is REGISTERED (deferred to the 0.34.2 cleanup window with an owning decision — rewrite or archive), not silently patched.

## 3. Gate evidence at closure

- Frozen authority manifest (13 files): byte-verified OK (untouched).
- Frozen-module gate: 661 green post-refreeze (baseline-disagreement set extended with the declared M2 thaw paths: commands.py, direct_io_inventory.py; unified_hunt.py re-pinned but absent from the pre-unfreeze baseline by age).
- Combined M2 + M1 + g02 + frozen run: **861 passed** (single run): the three M2 suites (25+26+11), the M1b matrix/ownership/contracts suites, the M1-A guard suites, the g02 inventory tests, scope/ScopeLaw/SSRF/HITL contract tests, and the frozen gate.
- Test-count gate: **8,317 ≥ floor 8,115** (0 collection errors).
- Coverage ratchet: **4.26% ≥ 4.07%** (enforcement mode, pinned scope).
- Environment limits (unchanged, documented): no Docker; no external targets ever contacted (all adversarial DNS/transport tests run on monkeypatched resolvers + mock transports); ruff/bandit not run in this sandbox (CI holds them).

## 4. Deferred (registered, owning phases)

| Item | Owning phase | Reason |
|---|---|---|
| API-side manifest intake + manifest→state-channel mirror | M9 | approval binding needs the manifest identity in state; the library entry point (`require_authorization_manifest`) is ready for the worker/API to call |
| `run_campaign.sh` retired-flag rewrite or archive | 0.34.2 cleanup | script predates the v0.32.0 alias removal; needs an operator-surface decision |
| Proxy-chain egress policy (beyond the pinned-transport proxy semantics) | M12 deployment hardening | needs the deployment egress-control contract |

## 5. Registry update

`docs/engineering/CANONICAL_PHASE_REGISTRY.md` M2 entry: **COMPLETE (2026-11-05)** — this report is the evidence record; UM-DR-15 is the window record. The acceptance criterion "adversarial scope + fail-closed suites pass (incl. all H/M regression tests from the M0 register)" is evidenced by the 861-test combined run.

— End of M2_PHASE_REPORT.md —

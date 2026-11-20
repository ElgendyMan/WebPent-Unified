# UMDR41 Security Review
## Effective API route authorization matrix (20 routes, decorator AND effective behavior)
| Route | Method | Auth dependency | Effective behavior under default (lab, auth off, loopback) |
|---|---|---|---|
| /api/v1/scope/load | POST | require_role(admin,service) | stub admin satisfies → anonymous-equivalent on loopback; STRICT profiles hard-stop at settings |
| /api/v1/scope | GET | require_role(admin,service) | same as above |
| /api/v1/scope/check | GET | require_role(admin,service) | same (directive's clarification verified: role dep EXISTS; issue is only the default bypass) |
| /api/v1/scope/{id} | DELETE | require_role(admin,service) | same |
| /health | GET | none | intentional (liveness) |
| /token | POST | OAuth2 form | 404 while auth disabled (never mints bypass tokens) |
| /api/v1/me | GET | get_current_user | stub admin |
| /api/v1/recon | POST | require_role(admin,service) | stub admin |
| /api/v1/scans | POST | require_role(admin,service) | stub admin; credentials encrypted via celery_payload_key |
| /api/v1/campaigns/{id}/halt,resume | POST | require_role(admin,service) | stub admin |
| /api/v1/campaigns/{id}/estimate,dashboard,reports | GET | get_current_user | stub admin |
| /api/v1/scans/{id}/status,findings,risk-summary | GET | get_current_user | stub admin |
| /api/v1/scans/{id}/approve | POST | require_role(admin) | stub admin |
| /api/oob/{finding_id}/{secret} | GET,POST | secret constant-time | advisory-only, never seals |
| /api/oob/{thread}/{finding}/{secret} | GET,POST | secret constant-time | advisory-only |

Enforcement verified beyond decorators: settings hard-stops (production/qualification/staging: auth on, secrets real ≥32 chars, rediss://, no wildcard CORS, TLS verify on), preflight non-local-bind block with I_UNDERSTAND_THIS_IS_INSECURE escape hatch (logged CRITICAL), scan ownership checks, OOB route disable flag.
Residual: default lab+loopback unauthenticated stub admin is the documented dev boundary — acceptable per §6.1.9 only because non-local exposure fails closed; kept, matrix documented.
## Scope authority (§6.3 — FIXED)
Pre-fix: in-process dict only. Post-fix: SqliteScopeStore (versioned append-only, tamper-detecting via recomputed fingerprint, fail-closed ScopeStoreUnavailable), registry store-mode makes store the read authority; API opt-in via WEBPENT_SCOPE_STORE_PATH; FATAL on init failure when requested (no silent downgrade). Alternative single-process restriction documented for operators who do not opt in.
## Dangerous-pattern audit (§6.4-6.6)
- shell=True/eval/exec/pickle/os.system: ZERO real sites (all 5+5+2 textual hits are string examples inside remediation knowledge bases).
- SQL: 6 f-string execute sites analyzed — PRAGMA busy_timeout (int constant), ALTER TABLE ADD COLUMN (internal column map), table names from internal allowlists, UPDATE column lists from fixed field maps with parameterized VALUES. No attacker-controlled identifier found; parameterization preserved.
- SSRF/transport: shared/http.py DNS pinning + rebinding resistance present (regression-tested by existing suites); controlled_target adapter admits loopback-only by contract; OAuth plan construction now scheme-validating (F-003 fix).
- Secrets: 30 hits all fixtures; git history clean of .env deletions with credentials.
- Subprocess governance: tools/utils/subprocess.py boundary wrapper with argv arrays; executable discovery PATH-shadowing acknowledged in SECURITY.md — upgrade path documented (absolute-path + version verification) but not implemented (owner decision on tool manifest).
## Container security (§6.10)
gosu privilege-drop entrypoint PRESERVED (directive: do not break it). Read-only fs/capdrops/seccomp/PID limits: NOT validated in this sandbox (no Docker daemon); recommended compose hardening block included in REMEDIATION_PLAN. Dockerfile.base: 3 unpinned @latest Go tools (F-010).

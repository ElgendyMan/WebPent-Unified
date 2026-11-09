# bbscout Integration and Local Runtime Runbook

## Scope and security boundary

WebPent consumes bbscout only as an **advisory Target Package v2 source**. The bridge is implemented in `src/webpent/shared/bbscout_bridge.py`; it does not perform HTTP requests, browser navigation, account creation, login, bounty-platform submission, or target scanning. Every executable action remains behind WebPent `ActionAuthority` and `ActionExecutor`.

The supplied bbscout archive is kept outside the WebPent source tree because it has no explicit LICENSE file in the reviewed archive; vendoring is therefore not claimed. Reviewed archive SHA-256: `1890f9fd4cc9d9bdf5aa0e127cb61bd38199e965cc387474b38b7e765d4a1c8b`. The integration therefore uses a thin contract boundary rather than copying source code. The package admission path recalculates the canonical digest, enforces package identity and scope, and rejects unsigned packages for live handoff.

> A provider-discovery result, browser observation, heuristic, or LLM suggestion is not authorization and cannot become a confirmed finding without target-backed causal evidence, an independent negative control, and a sealed/replayable ProofBundle.

## Supported modes

| Mode | Purpose | Network/action posture | Requirement |
|---|---|---|---|
| `offline` | Local package review and contract tests | No target contact; no browser; no provider submission | Default |
| `live` | Future owner-authorized package handoff | Still subject to scope, authority, capability, and proof gates | Verified detached signature, trusted key, explicit operator confirmation, and approved environment |

The current implementation intentionally does **not** implement autonomous signup or login. Gmail passwords, cookies, OTPs, session exports, and provider credentials must never be placed in `.env`, source, checkpoints, prompts, logs, reports, or ZIP archives. If an authenticated browser session is later required, the operator must provide a human-approved session handoff through an approved secret/session manager, and the browser adapter must remain read-only unless a separately reviewed action contract exists.

## Configuration

The following settings are typed in `webpent.config.settings.Settings` and are disabled or fail-closed by default:

```dotenv
BBSCOUT_ENABLED=false
BBSCOUT_PACKAGE_HOST_PATH=./config/bbscout
BBSCOUT_PACKAGE_PATH=/run/webpent/bbscout/target-package.json
BBSCOUT_MODE=offline
BBSCOUT_REQUIRE_VERIFIED_SIGNATURE=true
BBSCOUT_ALLOWED_PROVIDER_IDS=
BBSCOUT_ALLOWED_PROGRAM_IDS=
BBSCOUT_BROWSER_ENABLED=false
BBSCOUT_BROWSER_READ_ONLY=true
BBSCOUT_SIGNUP_ENABLED=false
BBSCOUT_PROVIDER_SUBMISSION_ENABLED=false
BBSCOUT_CREDENTIALS_REF=

# Quality-gate-only external source path; do not commit or mount credentials.
# BBSCOUT_SOURCE_ROOT=/absolute/path/to/reviewed/bbscout/src
```

`BBSCOUT_CREDENTIALS_REF` is only an opaque reference to an operator-controlled secret manager. It is not a place to put a password, API key, cookie, or token. Settings reject unsupported modes, live mode without verified signatures, signup, provider submission, and a non-read-only browser handoff.

LLM configuration remains provider-neutral and advisory. Keep `LLM_ENABLED=false` and `WEBPENT_LLM_ENABLED=false` for deterministic local runs. When an operator enables an LLM, keys and base URLs must come from the process environment or a secret manager, with bounded timeout, budget, redaction, and fallback. LLM output cannot authorize actions, widen scope, confirm findings, or write raw credentials to state.

## Local Docker stack

The repository already contains the local development stack in `docker-compose.dev.yml`:

- `redis:7-alpine` is an internal service with a healthcheck.
- `api` runs the FastAPI application and waits for Redis health.
- `worker` runs `celery -A worker.celery_app worker` with concurrency one.
- Playwright/Chromium are supplied by the pinned `webpent-base` image when that image is built from `Dockerfile.base`.

For the development compose, put an operator-reviewed package at the host-only path `BBSCOUT_PACKAGE_HOST_PATH`; it is mounted into both API and worker containers as read-only. The production compose uses the same container path and passes the same 11 safe policy/reference variables to API and worker, while keeping the feature default-off. The package directory is ignored by Git and must not contain credentials, cookies, or provider session exports.

Build the base image and application from a Docker-capable, owner-controlled machine:

```bash
make build-base
docker compose -f docker-compose.dev.yml up -d --build
docker compose -f docker-compose.dev.yml ps
docker compose -f docker-compose.dev.yml logs -f api worker
```

Run a local authorized lab only after reviewing the target package and scope:

```bash
python main.py preflight
python main.py scan --url http://127.0.0.1:4280 --profile smart-observe
```

Stop the stack and remove containers when finished:

```bash
docker compose -f docker-compose.dev.yml down
```

This development stack is not a production deployment. The production `docker-compose.yml` intentionally expects externally managed TLS Redis (`rediss://`) and strong secrets, and it fails closed if authentication, CORS, rate limiting, or secret requirements are not satisfied. Its bbscout package mount is read-only and the API/worker configuration is parity-tested, but that is a configuration contract—not proof of a live container startup. Production Docker, HA, backup/restore, and distributed worker qualification require a persistent Docker-capable staging environment and were not proven in the sandbox.

## Package handoff workflow

1. Produce or receive a Target Package v2 from a reviewed bbscout source outside the WebPent tree.
2. Validate its provenance and detached signature independently.
3. Load it transiently through the bridge; do not copy raw provider responses or credential material into state.
4. Require explicit operator confirmation and a one-time engagement lease.
5. Run package preflight, scope compilation, capability preflight, and `ActionAuthority` checks.
6. Execute only the action classes granted by the engagement and preserve idempotency, budget, stop, and lease constraints.
7. Promote a result only after causal signal, neutral negative control, and sealed/replayable ProofBundle validation.
8. Export only redacted reports and continuity metadata.

## What remains blocked

The following are intentionally not claimed as complete by this integration:

- Autonomous account creation, Gmail login, OTP handling, or acceptance of bounty-platform terms.
- Automatic HackerOne, Bugcrowd, Intigriti, or YesWeHack submission.
- Broad public-program crawling followed by scanning without an explicit owner-approved allowlist and scope package.
- Live WAPTLab/Juice Shop qualification runs from this sandbox.
- Production or HA qualification of Docker/Redis/Celery workers.
- VIP qualification based only on offline fixtures, static audits, candidate findings, or LLM output.

These controls keep discovery useful while preventing a browser or provider adapter from becoming an unbounded autonomous account or scanning agent.

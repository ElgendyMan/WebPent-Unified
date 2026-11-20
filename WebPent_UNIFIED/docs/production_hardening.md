# Production Hardening Profile

WebPent has two supported operating profiles. **Deterministic offline mode** is intended for local development, CI, and air-gapped labs. **Online production mode** is intended for an explicitly authorized deployment with authentication, strong secrets, restricted CORS, rate limiting, and at least one configured LLM provider when LLM-assisted nodes are enabled.

## Deterministic local profile

Use the following environment contract for a local run that does not require provider calls:

```dotenv
WEBPENT_LLM_ENABLED=false
WEBPENT_AUTH_ENABLED=false
WEBPENT_RATE_LIMIT_ENABLED=false
WEBPENT_ALLOW_INSECURE_TLS=false
WEBPENT_DISABLE_RAG=true
```

Run `python scripts/doctor.py --json` after loading this profile. The expected verdict is that deterministic fallback mode is active and no provider network probes are performed.

## Online production profile

A production deployment must set `WEBPENT_AUTH_ENABLED=true`, provide random values of at least 32 characters for `JWT_SECRET_KEY`, `AUDIT_SECRET_KEY`, and `CELERY_PAYLOAD_KEY`, set explicit `WEBPENT_CORS_ORIGINS` values instead of `*`, and enable distributed rate limiting when more than one API instance can exist. Redis should use `rediss://` with certificate validation configured at the infrastructure layer.

The LLM router remains the only provider boundary. Configure only the providers approved for the engagement. Provider failures must remain visible as degraded routing rather than being represented as successful evidence.

## TLS exception

`WEBPENT_ALLOW_INSECURE_TLS` defaults to `false`. When it is `true`, access-control probes may disable certificate verification for an explicitly authorized lab target. The probe emits an audit warning. This setting must not be enabled for public or production targets because it removes server-certificate authenticity checks.

## Verification policy

The delivery archive must not contain `.env` files, cookies, databases, runtime logs, bytecode, nested archives, or raw secret candidates. Before release, run compilation, the full test suite, Ruff, and the doctor command under the intended profile. If optional provider, browser, RAG, or external-scanner dependencies are unavailable, report those capabilities as unavailable instead of silently treating them as passed.

# UMDR41 Dependency Audit
## Single source of truth drift
- pyproject (exact pins): torch 2.14.1, langgraph 1.2.10 + lg-checkpoint-sqlite 3.1.1 + langchain-core 1.6.7 (documented tested pair), langchain-community 0.4.2, cloudflare 0.4.0, openai 1.6.7, mistralai 1.1.6, google-genai 4.4.0, cohere 0.6.0, anthropic 1.7.5, chroma 1.1.0, sentence-transformers 6.1.0, pypdf 6.21.4 (the previously-reported pypdf disagreement is RESOLVED in this revision — runtime requirements file matches), playwright 1.57.0 (floor documented 1.48 for route_web_socket), alembic 1.20.0, docker 7.2.0, fastapi 0.142.2, uvicorn 0.54.0, celery 5.6.3, redis 5.3.1, jinja2 3.1.6, rich 15.0.0, typer 0.23.1, multipart 0.0.32, bcrypt 5.0.0, PyJWT 2.15.1, structlog 26.1.0.
- uv.lock present; requires-python >=3.11 (documented rationale: dnspython CVE fix has no 3.10 wheel).
- Extras: dev (esprima, jsbeautifier, dnspython>=2.9.2, reportlab, pytest stack, ruff, mypy, bandit, pip-audit, langchain-huggingface), recon-extra (arjun, gated off by default).
## Toolchain reproducibility (Dockerfile.base)
PINNED: nuclei v3.11.0, dalfox v2.12.0. UNPINNED (@latest): subfinder, httpx, katana — F-010, owner decision required (exact versions + manifest + image-build verification step). interactsh-client commented out.
## Optional-dependency architecture (§7.1) — NOT implemented this window
torch/chromadb/sentence-transformers are CORE deps. Moving them to an ml extra requires the six-point proof (imports work without, no silent default dependency, explicit unavailable-capability, no heavyweight import when disabled, verification on enable, both-install tests) — queued in REMEDIATION_PLAN P2.8.
## Installation tests (§7.4) — sandbox-constrained
Minimal/standard/full/offline installs and wheel build NOT runnable here (no network budget for multi-GB torch). What WAS verified: exact langgraph pair + core deps import cleanly in a fresh venv subset (langgraph 1.2.10, langgraph-checkpoint-sqlite 3.1.1, langchain-core 1.6.7, bcrypt 5.0.0) and all affected suites pass against them.

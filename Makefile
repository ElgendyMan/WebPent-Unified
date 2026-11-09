# =============================================================================
# WebPent V6 Ultimate — Makefile
# =============================================================================
# Usage:
#   make build-base    # Build the heavy base image (~15 min, cached forever)
#   make build-app     # Build the app image on top of base (~5 sec)
#   make build         # Build both base + app
#   make dev-init      # Create local memory/ output/ webpent.db (first clone)
#   make dev-up        # Start dev compose stack
#   make dev-down      # Stop dev compose stack
#   make dev-logs      # Tail dev logs
#   make dev-reinstall # Re-run `pip install -e .` inside the api container
#   make doctor        # Preflight: test all configured LLM API keys
#   make test          # Run V6 unified verification + ground-truth harness
#   make clean         # Remove containers + volumes
# =============================================================================

.PHONY: build-base build-app build dev-init dev-up dev-down close dev-reset dev-logs dev-reinstall doctor test test-count test-unit coverage lint security ci clean

# Docker image names
BASE_IMAGE := webpent-base:latest
APP_IMAGE := webpent-v6:latest

# Compose files
DEV_COMPOSE := docker-compose.dev.yml
PROD_COMPOSE := docker-compose.yml

# M1-C (UM-DR-12): the coverage floor's pinned scope, read once from the
# floor file so the Makefile can never drift from it.
FLOOR_SCOPE := $(shell python3 -c "import json;print(json.load(open('scripts/coverage_floor.json'))['scope'])")

# =============================================================================
# Build targets
# =============================================================================
build-base:
	@echo "Building base image (this takes ~15 min on first run)..."
	docker build -t $(BASE_IMAGE) -f Dockerfile.base .
	@echo "Base image built: $(BASE_IMAGE)"

build-app:
	@echo "Building app image (fast — base already cached)..."
	docker build -t $(APP_IMAGE) -f Dockerfile .
	@echo "App image built: $(APP_IMAGE)"

build: build-base build-app
	@echo "All images built successfully."

# =============================================================================
# Development targets
# =============================================================================

# V6 DX-Final: dev-init — prepare the host-side bind-mount targets so
# Docker doesn't create them as root (the classic "permission denied"
# footgun on fresh clones). Also pre-creates webpent.db so the SQLite
# WAL/SHM sidecar files don't end up root-owned.
#
# V8 FIX: webpent.db ownership hand-off. On the FIRST `make dev-up`,
# entrypoint.sh (running as root inside the container) chowns the
# bind-mounted db files to the container's webpent UID. On SUBSEQUENT
# `make dev-up` runs, those files are owned by the container UID, not
# the host user — so an unconditional `touch` (which updates the
# timestamp) fails with "Permission denied". Fix: only touch/chmod
# each db file IF it does not already exist. If it exists (regardless
# of owner), leave it alone — the container already owns it and will
# read/write it fine. Do NOT add sudo; do NOT change entrypoint.sh.
dev-init:
	@echo "Initializing dev workspace (memory/ output/ webpent.db)..."
	@mkdir -p memory memory/global output
	@# V8 FIX: touch + chmod ONLY if the file does not already exist.
	@# After the first container start, entrypoint.sh chowns these to
	@# the container's webpent UID — a host-side touch on an
	@# existing file owned by another UID fails with Permission denied.
	@[ -f webpent.db ] || { touch webpent.db && chmod 644 webpent.db; }
	@[ -f webpent.db-wal ] || { touch webpent.db-wal && chmod 644 webpent.db-wal; }
	@[ -f webpent.db-shm ] || { touch webpent.db-shm && chmod 644 webpent.db-shm; }
	@echo "Done. You can now run 'make dev-up'."

dev-up:
	@echo "Ensuring dev workspace exists..."
	@mkdir -p memory memory/global output
	@# V8 FIX: same ownership hand-off logic as dev-init — only
	@# touch/chmod if the file does NOT already exist. This prevents
	@# "Permission denied" on the second `make dev-up` after
	@# entrypoint.sh has chowned the db files to the container UID.
	@[ -f webpent.db ] || { touch webpent.db && chmod 644 webpent.db; }
	@[ -f webpent.db-wal ] || { touch webpent.db-wal && chmod 644 webpent.db-wal; }
	@[ -f webpent.db-shm ] || { touch webpent.db-shm && chmod 644 webpent.db-shm; }
	@# V7 Phase 2 FIX: bring down any existing stack for this exact
	@# compose file (including orphans) so leftover containers/networks
	@# from a previous invocation never linger and cause "name already
	@# taken" conflicts. container_name is intentionally hardcoded in
	@# docker-compose.dev.yml (other targets rely on the fixed names:
	@# `make doctor` greps `webpent-dev-api`, the worker healthcheck
	@# comment references it, operators run `docker logs webpent-dev-api`).
	@# The lifecycle discipline belongs here, not in dropping the names.
	@docker-compose -f $(DEV_COMPOSE) down --remove-orphans >/dev/null 2>&1 || true
	docker-compose -f $(DEV_COMPOSE) up -d --build
	@# V7 Phase 3 FIX: poll /health before reporting success. docker-proxy
	@# accepts and resets connections during the window between "container
	@# running" and "uvicorn bound to port 8000", which previously surfaced
	@# as a confusing "Connection reset by peer" against a healthy stack.
	@# Curl -sf retries every 1s, capped at 30 attempts; on timeout, point
	@# the operator at `docker logs webpent-dev-api` instead of falsely
	@# reporting success. The container's own HEALTHCHECK (start-period=10s,
	@# retries=3) tracks the same transition in parallel for `docker ps`.
	@echo "Waiting for API to become healthy (up to 30s)..."
	@attempts=0; max=30; \
	while [ $$attempts -lt $$max ]; do \
                if curl -sf http://localhost:8000/health >/dev/null 2>&1; then \
                        echo "API healthy after $$attempts s."; \
                        break; \
                fi; \
                attempts=$$((attempts + 1)); \
                sleep 1; \
	done; \
	if [ $$attempts -ge $$max ]; then \
                echo ""; \
                echo "WARNING: API did not become healthy within $$max seconds."; \
                echo "Check 'docker logs webpent-dev-api' for the actual startup error."; \
                echo "Common causes: DB migration pending, port 8000 already bound on host,"; \
                echo "or (on Kali) ufw interfering with Docker's iptables DOCKER-USER chain."; \
	else \
                echo "Dev stack started. API: http://localhost:8000"; \
	fi

dev-down:
	docker-compose -f $(DEV_COMPOSE) down

# V7 Ready-For-Kali: simple, memorable alias for dev-down.
close: dev-down
	@echo "Dev stack stopped."

# V7 Phase 2 FIX: dev-reset — force-remove all webpent-dev-* containers
# and the webpent-dev-net network unconditionally. Use this when a
# previous run left the stack in a state that dev-up's `down
# --remove-orphans` can't untangle (e.g. orphaned containers from a
# renamed/duplicated project folder — see Phase 0 of the v7 fix plan).
# This is intentionally more aggressive than dev-down: it ignores
# Compose's project-name tracking and removes the named resources
# directly. Safe because the names are hardcoded and bounded.
dev-reset:
	@echo "Force-removing all webpent-dev-* containers and network..."
	@-docker rm -f webpent-dev-api webpent-dev-worker webpent-dev-redis webpent-dev-tunnel 2>/dev/null || true
	@-docker network rm webpent-dev-net 2>/dev/null || true
	@echo "Done. Run 'make dev-up' to start fresh."

dev-logs:
	docker-compose -f $(DEV_COMPOSE) logs -f api worker

# V6 DX-Final: dev-reinstall — re-run `pip install -e .` inside the
# running api container. Use this after adding a new dependency to
# pyproject.toml to pick it up without rebuilding the image.
dev-reinstall:
	@echo "Reinstalling framework deps inside api container..."
	docker-compose -f $(DEV_COMPOSE) exec api pip install -e .
	@echo "Done. Restart the worker to pick up new deps:"
	@echo "  docker-compose -f $(DEV_COMPOSE) restart worker"

# V7 Phase 0/1: Knowledge ingestion
# V8 P0 B2: Added ingest-knowledge-verify target — pre-flight pin check
# that runs WITHOUT touching ChromaDB or the embedding API. Use this
# to confirm knowledge_sources.yaml is reachable BEFORE running the
# full ingestion (which spends embedding API quota).
ingest-knowledge-verify:
	@echo "V8 P0 B2: Verifying knowledge source pins (no ChromaDB write)..."
	python scripts/ingest_payloads.py --verify-pins

ingest-knowledge:
	@echo "V7: Ingesting knowledge corpus..."
	python scripts/ingest_payloads.py

ingest-file:
	@if [ -z "$(file)" ]; then echo "Usage: make ingest-file file=path/to/report.pdf"; exit 1; fi
	@echo "V7: Ingesting $(file)..."
	python scripts/ingest_payloads.py --ingest-file "$(file)" --doc-type $(or $(doctype),methodology)

# =============================================================================
# Preflight doctor
# =============================================================================
# V6 DX-Final: doctor — test all configured LLM API keys with a minimal
# prompt ("Reply with OK") and print a table showing which providers
# are active, missing keys, or failing. Run this before starting a
# scan to catch misconfigurations early.
doctor:
	@echo "Running preflight LLM doctor..."
	@if docker ps --format '{{.Names}}' | grep -q webpent-dev-api; then \
                echo "Running inside webpent-dev-api container..."; \
                docker exec -it webpent-dev-api python scripts/doctor.py; \
	else \
                echo "Dev container not running \u2014 running on host..."; \
                python scripts/doctor.py; \
	fi

# =============================================================================
# Production targets
# =============================================================================
prod-up:
	@# V7 Phase 2 FIX: same lifecycle discipline as dev-up — bring down
	@# any existing prod stack (including orphans) before up, so leftover
	@# containers/networks from a previous run don't cause "name already
	@# taken" conflicts. container_name is intentionally hardcoded in
	@# docker-compose.yml for the same reasons as the dev compose file.
	@docker-compose -f $(PROD_COMPOSE) down --remove-orphans >/dev/null 2>&1 || true
	docker-compose -f $(PROD_COMPOSE) up -d --build

prod-down:
	docker-compose -f $(PROD_COMPOSE) down

# =============================================================================
# Testing and quality gates
# =============================================================================

test-count:
	@PYTHONPATH=src python3 scripts/verify_test_count.py

test-unit:
	@PYTHONPATH=src python3 -m pytest

coverage:
	@PYTHONPATH=src python3 -m pytest --cov=webpent --cov-report=term-missing --cov-report=xml:coverage.xml --cov-fail-under=35

# M1-C (UM-DR-12): the honest-coverage ratchet as a first-class target.
# Enforcement mode: measures the pinned scope and fails if coverage drops
# below the floor in scripts/coverage_floor.json (the floor only moves up;
# a downward update requires scripts/coverage_ratchet.py --allow-lower).
coverage-ratchet:
	@PYTHONPATH=src python3 scripts/coverage_ratchet.py --scope "$(FLOOR_SCOPE)"

lint:
	@ruff check src/webpent/config/settings.py src/webpent/integrations/webhook.py src/webpent/shared/preflight.py src/webpent/tools/recon/ffuf.py src/webpent/tools/registry.py src/webpent/agents/validator/active_checks.py scripts/verify_test_count.py tests/test_p0_ffuf_preflight.py tests/test_p0_p1_active_validators.py tests/test_p0_secondary_identity_entrypoint.py tests/test_p0_websocket_webhook.py tests/test_p1_task_crypto_fail_closed.py --select E,F,I,RUF --ignore BLE001 --output-format concise

security:
	@echo "Running Bandit high-severity security gate..."
	@bandit -q -r src/webpent -x tests -lll

tool-boundary-gate:
	@PYTHONPATH=src python3 scripts/check_tool_boundary_prompt_boundary.py

ci: test-count coverage lint security tool-boundary-gate coverage-ratchet

# =============================================================================
# Legacy verification target (kept for backwards compatibility)
# =============================================================================
# V6 DX-Final: unified verification — runs verify_all.py (merged from
# verify_v6_ultimate.py + verify_v6_foundation.py) and the ground-truth
# evaluation harness. The harness exits 1 if either the positive OR
# negative ground-truth fails, so `make test` propagates the failure.
test:
	@echo "Running V6 unified verification (verify_all.py)..."
	python verify_all.py
	@echo "Running V6 ground-truth evaluation harness..."
	python scripts/evaluate_ground_truth.py

# =============================================================================
# Cleanup
# =============================================================================
clean:
	docker-compose -f $(DEV_COMPOSE) down -v 2>/dev/null || true
	docker-compose -f $(PROD_COMPOSE) down -v 2>/dev/null || true
	docker rmi $(APP_IMAGE) 2>/dev/null || true
	@echo "Cleaned up containers, volumes, and images."

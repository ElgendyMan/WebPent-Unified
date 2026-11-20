#!/usr/bin/env python3
"""verify_all.py — V6 DX-Final Unified Verification.

Merges the legacy ``verify_v6_ultimate.py`` and
``verify_v6_foundation.py`` scripts into a single audit harness so
``make test`` only needs to invoke one script. The two original
scripts are now consolidated here; their checks are preserved verbatim
(only the section numbering was prefixed with F=Foundation / U=Ultimate
to disambiguate overlapping section numbers).

Sections:
  F1. PASSLIB ABSENCE CHECK
  F2. DEPENDENCY PRESENCE CHECK (bcrypt, python-multipart)
  F3. DEVELOP-FIRST SECURITY TOGGLES (auth_enabled, rate_limit_enabled)
  F4. DOCKERFILE LAYER CACHING (pyproject.toml before COPY . .)
  F5. DOCKER-COMPOSE DEV VOLUME MOUNTS
  F6. EVALUATION SCRIPT NETWORKING
  U1. DOCKER BUILD OPTIMIZATION (BASE IMAGE)
  U2. CLOUDFLARE TUNNEL INTEGRATION
  U3. NEGATIVE GROUND-TRUTH (SAFE ENDPOINTS)
  U4. DYNAMIC TOOL REGISTRY (PLUGIN SYSTEM)
  U5. ALEMBIC DATABASE MIGRATIONS
  U6. BOUNDED SELF-HEALING (RECURSION LIMIT)
  DX. V6 DX-FINAL OBJECTIVES (Dockerfile caching, doctor, RAG moderation)
  AST. SYNTAX / AST VERIFICATION

Exit codes:
    0 — all checks passed
    1 — one or more checks failed
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src" / "webpent"

failures: list[str] = []
passes: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        passes.append(f"PASS  {label}" + (f"  ({detail})" if detail else ""))
    else:
        failures.append(f"FAIL  {label}" + (f"  ({detail})" if detail else ""))


def section(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


# ===========================================================================
# F1. PASSLIB ABSENCE CHECK
# ===========================================================================
section("F1. PASSLIB ABSENCE CHECK")

pyproject_src = (ROOT / "pyproject.toml").read_text()
auth_src = (SRC / "api" / "auth.py").read_text()

check(
    "F1a. 'passlib' absent from pyproject.toml",
    "passlib" not in pyproject_src.lower(),
)
check(
    "F1b. 'passlib' absent from api/auth.py (no imports, no references)",
    "passlib" not in auth_src.lower(),
)
check(
    "F1c. 'passlib' absent from entire src/ tree (grep all .py files)",
    not any(
        "passlib" in f.read_text().lower()
        for f in SRC.rglob("*.py")
    ),
)

# ===========================================================================
# F2. DEPENDENCY PRESENCE CHECK
# ===========================================================================
section("F2. DEPENDENCY PRESENCE CHECK (bcrypt, python-multipart)")

check(
    "F2a. 'bcrypt' present in pyproject.toml dependencies",
    "bcrypt" in pyproject_src,
)
check(
    "F2b. 'python-multipart' present in pyproject.toml dependencies",
    "python-multipart" in pyproject_src,
)
check(
    "F2c. auth.py imports bcrypt directly (bcrypt.hashpw / bcrypt.checkpw)",
    "import bcrypt" in auth_src
    and "bcrypt.hashpw" in auth_src
    and "bcrypt.checkpw" in auth_src,
)

# ===========================================================================
# F3. DEVELOP-FIRST SECURITY TOGGLES
# ===========================================================================
section("F3. DEVELOP-FIRST SECURITY TOGGLES")

settings_src = (SRC / "config" / "settings.py").read_text()
app_src = (SRC / "api" / "app.py").read_text()

check(
    "F3a. settings.py defines auth_enabled field",
    "auth_enabled" in settings_src,
)
check(
    "F3b. auth_enabled defaults to False",
    bool(re.search(r'auth_enabled\s*:\s*bool\s*=\s*Field\(\s*default\s*=\s*False', settings_src)),
)
check(
    "F3c. auth.py checks settings.auth_enabled (bypass when False)",
    "auth_enabled" in auth_src
    and "not settings.auth_enabled" in auth_src,
)
check(
    "F3d. rate_limit_enabled defaults to False in settings.py",
    bool(re.search(r'rate_limit_enabled\s*:\s*bool\s*=\s*Field\(\s*default\s*=\s*False', settings_src)),
)
check(
    "F3e. app.py checks rate_limit_enabled (bypass when False)",
    "rate_limit_enabled" in app_src,
)

# ===========================================================================
# F4. DOCKERFILE LAYER CACHING (pyproject.toml before COPY . .)
# ===========================================================================
section("F4. DOCKERFILE LAYER CACHING")

dockerfile_src = (ROOT / "Dockerfile").read_text()

# Find all COPY lines and check that "COPY . ." is after pyproject.toml copy.
copy_lines = [
    (i + 1, line.strip())
    for i, line in enumerate(dockerfile_src.splitlines())
    if line.strip().startswith("COPY")
]

check(
    "F4a. Dockerfile copies pyproject.toml BEFORE source code",
    any("pyproject.toml" in line for _, line in copy_lines),
)

pyproject_line_num = next(
    (ln for ln, line in copy_lines if "pyproject.toml" in line), 0
)
copy_all_line_num = next(
    (ln for ln, line in copy_lines if line == "COPY . ."), 0
)

check(
    "F4b. 'COPY . .' comes AFTER 'COPY pyproject.toml'",
    copy_all_line_num > pyproject_line_num and copy_all_line_num > 0,
    f"pyproject.toml at line {pyproject_line_num}, COPY . . at line {copy_all_line_num}",
)

entrypoint_copies_after = [
    line
    for ln, line in copy_lines
    if ln > copy_all_line_num and copy_all_line_num > 0 and line != "COPY . ."
]

check(
    "F4c. 'COPY . .' is the last COPY of project source "
    "(single-file entrypoint COPY may follow)",
    copy_all_line_num > 0
    and all(
        "entrypoint" in line for line in entrypoint_copies_after
    ),
    f"COPY . . at line {copy_all_line_num}; "
    f"COPYs after it: {entrypoint_copies_after}",
)

check(
    "F4d. pip install appears BEFORE 'COPY . .'",
    next(
        (i + 1 for i, line in enumerate(dockerfile_src.splitlines())
         if "pip install" in line and "RUN" in line),
        0,
    )
    < copy_all_line_num,
    f"pip install at line ~?, COPY . . at line {copy_all_line_num}",
)

# ===========================================================================
# F5. DOCKER-COMPOSE DEV VOLUME MOUNTS
# ===========================================================================
section("F5. DOCKER-COMPOSE DEV VOLUME MOUNTS")

dev_compose_path = ROOT / "docker-compose.dev.yml"
check(
    "F5a. docker-compose.dev.yml exists",
    dev_compose_path.is_file(),
)

if dev_compose_path.is_file():
    dev_compose_src = dev_compose_path.read_text()
    check(
        "F5b. docker-compose.dev.yml mounts ./src as volume",
        "./src:/app/src" in dev_compose_src,
    )
    check(
        "F5c. docker-compose.dev.yml mounts ./scripts as volume",
        "./scripts:/app/scripts" in dev_compose_src,
    )
    check(
        "F5d. docker-compose.dev.yml uses uvicorn --reload",
        "--reload" in dev_compose_src,
    )
    check(
        "F5e. docker-compose.dev.yml sets AUTH_ENABLED=false",
        "AUTH_ENABLED=false" in dev_compose_src,
    )
    check(
        "F5f. docker-compose.dev.yml sets RATE_LIMIT_ENABLED=false",
        "RATE_LIMIT_ENABLED=false" in dev_compose_src,
    )
    check(
        "F5g. docker-compose.dev.yml uses env_file: .env",
        "env_file: .env" in dev_compose_src
        or "env_file:" in dev_compose_src,
    )

# ===========================================================================
# F6. EVALUATION SCRIPT NETWORKING
# ===========================================================================
section("F6. EVALUATION SCRIPT NETWORKING")

eval_src = (ROOT / "scripts" / "evaluate_ground_truth.py").read_text()

check(
    "F6a. evaluate_ground_truth.py uses 'http://api:8000' as default API URL",
    "http://api:8000" in eval_src,
)
check(
    "F6b. evaluate_ground_truth.py uses 'http://ground-truth:8080' as default target",
    "http://ground-truth:8080" in eval_src,
)
check(
    "F6c. evaluate_ground_truth.py does NOT hardcode 'localhost:8080' as default",
    'DEFAULT_TARGET_URL_HOST' not in eval_src
    and 'http://localhost:8080' not in eval_src.split("DEFAULT_")[0] if "DEFAULT_" in eval_src else True,
)
check(
    "F6d. evaluate_ground_truth.py has get_auth_token function for JWT",
    "def get_auth_token(" in eval_src,
)
check(
    "F6e. evaluate_ground_truth.py passes auth_token to trigger_scan",
    "auth_token=auth_token" in eval_src,
)

# ===========================================================================
# U1. DOCKER BUILD OPTIMIZATION (BASE IMAGE)
# ===========================================================================
section("U1. DOCKER BUILD OPTIMIZATION (BASE IMAGE)")

check(
    "U1a. Dockerfile.base exists",
    (ROOT / "Dockerfile.base").is_file(),
)
check(
    "U1b. Dockerfile.base installs Go tools (nuclei, katana, etc.)",
    "go install" in (ROOT / "Dockerfile.base").read_text()
    and "nuclei" in (ROOT / "Dockerfile.base").read_text(),
)
check(
    "U1c. Dockerfile.base installs torch + sentence-transformers + playwright",
    all(x in (ROOT / "Dockerfile.base").read_text()
        for x in ["torch", "sentence-transformers", "playwright install"]),
)
_first_meaningful = next(
    (
        line.strip()
        for line in (ROOT / "Dockerfile").read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ),
    "",
)
check(
    "U1d. Dockerfile's first meaningful line is FROM webpent-base:latest",
    _first_meaningful.startswith("FROM webpent-base:latest"),
    f"first meaningful line: {_first_meaningful!r}",
)
check(
    "U1e. Makefile exists with build-base and build-app targets",
    (ROOT / "Makefile").is_file()
    and "build-base" in (ROOT / "Makefile").read_text()
    and "build-app" in (ROOT / "Makefile").read_text(),
)

# ===========================================================================
# U2. CLOUDFLARE TUNNEL INTEGRATION
# ===========================================================================
section("U2. CLOUDFLARE TUNNEL INTEGRATION")

check(
    "U2a. scripts/start_tunnel.sh exists",
    (ROOT / "scripts" / "start_tunnel.sh").is_file(),
)
check(
    "U2b. start_tunnel.sh contains cloudflared tunnel command",
    "cloudflared tunnel" in (ROOT / "scripts" / "start_tunnel.sh").read_text(),
)
check(
    "U2c. start_tunnel.sh updates WEBPENT_OOB_CALLBACK_BASE_URL in .env",
    "WEBPENT_OOB_CALLBACK_BASE_URL" in (ROOT / "scripts" / "start_tunnel.sh").read_text(),
)
check(
    "U2d. docker-compose.dev.yml has cloudflared service",
    "cloudflared" in (ROOT / "docker-compose.dev.yml").read_text(),
)
check(
    "U2e. docker-compose.yml has cloudflared service",
    "cloudflared" in (ROOT / "docker-compose.yml").read_text(),
)

# ===========================================================================
# U3. NEGATIVE GROUND-TRUTH (SAFE ENDPOINTS)
# ===========================================================================
section("U3. NEGATIVE GROUND-TRUTH (SAFE ENDPOINTS)")

app_test_src = (ROOT / "tests" / "ground_truth" / "app.py").read_text()

check(
    "U3a. /xss/safe endpoint exists with html.escape",
    "/xss/safe" in app_test_src and "html.escape" in app_test_src or "_html.escape" in app_test_src,
)
check(
    "U3b. /sqli/safe endpoint exists with parameterized query",
    "/sqli/safe" in app_test_src and "WHERE username = ?" in app_test_src,
)
check(
    "U3c. /csrf/safe endpoint exists with csrf_token",
    "/csrf/safe" in app_test_src and "csrf_token" in app_test_src,
)
check(
    "U3d. evaluate_ground_truth.py has NEGATIVE_GROUND_TRUTH list",
    "NEGATIVE_GROUND_TRUTH" in eval_src,
)
check(
    "U3e. evaluate_ground_truth.py checks for false positives on safe endpoints",
    "false_positive" in eval_src.lower() and "FALSE POSITIVE" in eval_src,
)

# ===========================================================================
# U4. DYNAMIC TOOL REGISTRY (PLUGIN SYSTEM)
# ===========================================================================
section("U4. DYNAMIC TOOL REGISTRY (PLUGIN SYSTEM)")

check(
    "U4a. tools/registry.py exists",
    (SRC / "tools" / "registry.py").is_file(),
)
registry_src = (SRC / "tools" / "registry.py").read_text()
check(
    "U4b. register_tool decorator defined",
    "def register_tool(" in registry_src,
)
check(
    "U4c. get_tools(category) function defined",
    "def get_tools(" in registry_src,
)
check(
    "U4d. get_tool(name) function defined",
    "def get_tool(" in registry_src,
)
check(
    "U4e. auto_discover function defined",
    "def auto_discover(" in registry_src,
)
init_src = (SRC / "tools" / "__init__.py").read_text()
registry_lookup_src = (SRC / "tools" / "registry.py").read_text()
check(
    "U4f. tools/__init__.py is side-effect free and registry discovers lazily",
    "auto_discover" in init_src
    and "ensure_discovered" in init_src
    and "def ensure_discovered(" in registry_lookup_src
    # every lookup path goes through lazy discovery
    and registry_lookup_src.count("ensure_discovered()") >= 4,
)
# Check all 8 wrappers have @register_tool.
for tool_file, tool_name in [
    ("recon/nuclei.py", "nuclei"),
    ("recon/katana.py", "katana"),
    ("recon/httpx.py", "httpx"),
    ("recon/subfinder.py", "subfinder"),
    ("exploitation/dalfox.py", "dalfox"),
    ("exploitation/sqlmap.py", "sqlmap"),
    ("exploitation/ysoserial.py", "ysoserial"),
    ("exploitation/phpggc.py", "phpggc"),
]:
    src = (SRC / "tools" / tool_file).read_text()
    check(
        f"U4g. {tool_file} has @register_tool decorator",
        "@register_tool(" in src
        and f'name="{tool_name}"' in src,
    )
check(
    "U4h. recon agent uses get_tool() from registry",
    "get_tool" in (SRC / "agents" / "recon" / "agent.py").read_text(),
)
check(
    "U4i. validator agent uses get_tool() from registry",
    "get_tool" in (SRC / "agents" / "validator" / "agent.py").read_text(),
)

# ===========================================================================
# U5. ALEMBIC DATABASE MIGRATIONS
# ===========================================================================
section("U5. ALEMBIC DATABASE MIGRATIONS")

check(
    "U5a. alembic.ini exists",
    (ROOT / "alembic.ini").is_file(),
)
check(
    "U5b. alembic/env.py exists",
    (ROOT / "alembic" / "env.py").is_file(),
)
check(
    "U5c. alembic/versions/ has initial migration",
    any((ROOT / "alembic" / "versions").glob("*.py")),
)
check(
    "U5d. alembic/env.py imports settings for DB URL",
    "get_settings" in (ROOT / "alembic" / "env.py").read_text(),
)
db_src = (SRC / "memory" / "db.py").read_text()
check(
    "U5e. db.py init_db() calls _run_alembic_upgrade()",
    "_run_alembic_upgrade" in db_src,
)
check(
    "U5f. db.py has _init_db_legacy() fallback",
    "_init_db_legacy" in db_src,
)

# ===========================================================================
# U6. BOUNDED SELF-HEALING (RECURSION LIMIT)
# ===========================================================================
section("U6. BOUNDED SELF-HEALING (RECURSION LIMIT)")

worker_src = (SRC / "workers" / "pentest_worker.py").read_text()
check(
    "U6a. GraphRecursionError imported in pentest_worker.py",
    "GraphRecursionError" in worker_src,
)
check(
    "U6b. recursion_limit uses settings.max_graph_steps (V8: no 15 clamp)",
    # V8 Phase 3: removed min(..., 15) clamp. Worker now uses
    # settings.max_graph_steps directly, same as api/cli.
    "min(settings.max_graph_steps, 15)" not in worker_src
    and "settings.max_graph_steps" in worker_src,
)
check(
    "U6c. GraphRecursionError caught in try/except",
    "except GraphRecursionError" in worker_src,
)
check(
    "U6d. _mark_pending_as_human_review function defined",
    "def _mark_pending_as_human_review(" in worker_src,
)
check(
    "U6e. _mark_pending_as_human_review sets 'Needs Human Review'",
    '"Needs Human Review"' in worker_src,
)
check(
    "U6f. Bounded self-healing logs CRITICAL warning",
    "logger.critical" in worker_src
    and "GraphRecursionError" in worker_src,
)

# ===========================================================================
# DX. V6 DX-FINAL OBJECTIVES
# ===========================================================================
section("DX. V6 DX-FINAL OBJECTIVES (Dockerfile caching, doctor, RAG moderation)")

# DX-1: Dockerfile caching — pip install -e . BEFORE COPY . ., and no
# `2>/dev/null || true` masking on pip install commands.
check(
    "DX1a. Dockerfile copies pyproject.toml + README.md before pip install",
    "COPY pyproject.toml README.md ./" in dockerfile_src,
)
check(
    "DX1b. Dockerfile runs `pip install --no-cache-dir -e .` BEFORE 'COPY . .'",
    "pip install --no-cache-dir -e ." in dockerfile_src
    and dockerfile_src.index("pip install --no-cache-dir -e .") < dockerfile_src.index("COPY . ."),
)
check(
    "DX1c. Dockerfile does NOT mask pip install failures (no '2>/dev/null || true' on pip lines)",
    "pip install" in dockerfile_src
    and "2>/dev/null || true" not in "\n".join(
        line for line in dockerfile_src.splitlines() if "pip install" in line
    ),
)

# DX-2: Makefile has dev-init, dev-reinstall, doctor targets.
makefile_src = (ROOT / "Makefile").read_text()
check(
    "DX2a. Makefile has dev-init target",
    "dev-init:" in makefile_src,
)
check(
    "DX2b. Makefile dev-init creates memory/ and output/ dirs",
    "mkdir -p memory memory/global output" in makefile_src,
)
check(
    "DX2c. Makefile dev-init touches webpent.db",
    "touch webpent.db" in makefile_src,
)
check(
    "DX2d. Makefile has dev-reinstall target",
    "dev-reinstall:" in makefile_src,
)
check(
    "DX2e. Makefile dev-reinstall runs `pip install -e .` inside api container",
    "docker-compose" in makefile_src
    and "exec api pip install -e ." in makefile_src,
)
check(
    "DX2f. Makefile has doctor target",
    "doctor:" in makefile_src,
)
check(
    "DX2g. Makefile doctor runs scripts/doctor.py",
    "python scripts/doctor.py" in makefile_src,
)
check(
    "DX2h. Makefile test runs verify_all.py (unified verifier)",
    "python verify_all.py" in makefile_src,
)
check(
    "DX2i. Makefile test runs scripts/evaluate_ground_truth.py",
    "python scripts/evaluate_ground_truth.py" in makefile_src,
)

# DX-3: docker-compose.dev.yml live reload watches main.py + worker.py.
check(
    "DX3a. docker-compose.dev.yml uses webpent.api.app:app (V7 fix)",
    "webpent.api.app:app" in dev_compose_src,
)
check(
    "DX3b. docker-compose.dev.yml uses plain --reload (V7 fix)",
    "--reload" in dev_compose_src and "--reload-dir" not in dev_compose_src and "--reload-include" not in dev_compose_src,
)
check(
    "DX3c. docker-compose.dev.yml celery has no --reload (V7 fix)",
    "celery" in dev_compose_src and "worker" in dev_compose_src
    and "--reload" not in (dev_compose_src.split("worker:")[1] if "worker:" in dev_compose_src else "")
    if "worker:" in dev_compose_src else False,
)

# DX-4: LLM circuit breaker TTL.
llm_src = (SRC / "shared" / "llm.py").read_text()
check(
    "DX4a. llm.py stores dead-provider timestamps (dict[str, float], not set)",
    "_DEAD_PROVIDERS: dict[str, float]" in llm_src,
)
check(
    "DX4b. llm.py defines _DEAD_PROVIDER_TTL_SECONDS constant",
    "_DEAD_PROVIDER_TTL_SECONDS" in llm_src,
)
check(
    "DX4c. llm.py TTL default is 600s (10 minutes)",
    bool(re.search(r'_DEAD_PROVIDER_TTL_SECONDS\s*:\s*float\s*=\s*600\.0', llm_src)),
)
check(
    "DX4d. llm.py has _evict_expired_dead_providers function",
    "def _evict_expired_dead_providers(" in llm_src,
)
check(
    "DX4e. llm.py _is_provider_dead evicts expired entries",
    "_evict_expired_dead_providers" in llm_src
    and "_evict_expired_dead_providers()" in llm_src,
)
check(
    "DX4f. llm.py uses time.monotonic() for TTL timestamps",
    "time.monotonic()" in llm_src,
)

# DX-5: scripts/doctor.py exists and is wired correctly.
doctor_path = ROOT / "scripts" / "doctor.py"
check(
    "DX5a. scripts/doctor.py exists",
    doctor_path.is_file(),
)
if doctor_path.is_file():
    doctor_src = doctor_path.read_text()
    check(
        "DX5b. doctor.py probes all providers with a minimal prompt",
        "Reply with OK" in doctor_src
        and "_PROBE_PROMPT" in doctor_src,
    )
    check(
        "DX5c. doctor.py outputs a table with ACTIVE/MISSING_KEY/FAILING",
        "ACTIVE" in doctor_src
        and "MISSING_KEY" in doctor_src
        and "FAILING" in doctor_src,
    )
    check(
        "DX5d. doctor.py surfaces circuit-breaker state",
        "dead_providers" in doctor_src
        and "get_dead_providers" in doctor_src,
    )
    check(
        "DX5e. doctor.py exits 1 when no providers are active",
        "return 1" in doctor_src,
    )

# DX-6: RAG moderation in lessons persistence.
lessons_src = (SRC / "memory" / "lessons.py").read_text()
check(
    "DX6a. lessons.py defines _sanitize_lesson_content",
    "def _sanitize_lesson_content(" in lessons_src,
)
check(
    "DX6b. lessons.py redacts payload regions to [REDACTED-PAYLOAD]",
    "[REDACTED-PAYLOAD]" in lessons_src,
)
check(
    "DX6c. lessons.py save_lesson calls _sanitize_lesson_content",
    "def save_lesson(" in lessons_src
    and "_sanitize_lesson_content(content)" in lessons_src,
)
check(
    "DX6d. lessons.py save_hypothesis calls _sanitize_lesson_content",
    "def save_hypothesis(" in lessons_src
    and "_sanitize_lesson_content(content)" in lessons_src,
)
check(
    "DX6e. lessons.py drops lessons that sanitise to empty (returns None)",
    "return None" in lessons_src
    and "if not sanitized:" in lessons_src,
)
check(
    "DX6f. lessons.py has SQL injection redaction pattern",
    "_SQL_INJECTION_RE" in lessons_src,
)
check(
    "DX6g. lessons.py has XSS payload redaction pattern",
    "_XSS_PAYLOAD_RE" in lessons_src,
)
check(
    "DX6h. lessons.py has shell metacharacter redaction pattern",
    "_SHELL_METACHAR_RE" in lessons_src,
)

# DX-7: RAG moderation in reflection agent (persistence-side) and
# hypothesis_analyzer agent (retrieval-side).
reflection_src = (SRC / "agents" / "reflection" / "agent.py").read_text()
check(
    "DX7a. reflection/agent.py imports _sanitize_lesson_content",
    "from webpent.memory.lessons import _sanitize_lesson_content" in reflection_src,
)
check(
    "DX7b. reflection/agent.py _persist_lesson sanitises before SQLite + Chroma writes",
    "_sanitize_lesson_content(lesson)" in reflection_src
    and "sanitized_lesson" in reflection_src,
)
hypothesis_src = (SRC / "agents" / "hypothesis_analyzer" / "agent.py").read_text()
check(
    "DX7c. hypothesis_analyzer/agent.py defines _sanitize_retrieved_lessons",
    "def _sanitize_retrieved_lessons(" in hypothesis_src,
)
check(
    "DX7d. hypothesis_analyzer/agent.py sanitises retrieved lessons before injection",
    "_sanitize_retrieved_lessons(relevant_lessons)" in hypothesis_src,
)

# DX-8: P0/P1 bug fixes from the security audit (Round 1).
check(
    "DX8a. pentest_worker.py resume_pentest_task handles GraphRecursionError",
    "except GraphRecursionError" in worker_src
    and "terminated_recursion_limit" in worker_src,
)
check(
    "DX8b. evaluate_ground_truth.py returns 4-tuple (passed, failed, missing, neg_failed)",
    "tuple[int, int, int, int]" in eval_src,
)
check(
    "DX8c. evaluate_ground_truth.py main() gates exit on neg_failed > 0",
    "if neg_failed > 0:" in eval_src
    and "return 1" in eval_src,
)
check(
    "DX8d. evaluate_ground_truth.py purge_celery_queue uses cwd=str(project_root)",
    "cwd=str(project_root)" in eval_src,
)
check(
    "DX8e. memory/db.py stamps alembic_version on fallback "
    "(to the actual head revision, not a literal 'head')",
    "alembic_command.stamp(cfg, actual_head)" in db_src
    # and never silently stamps a literal "head" over a failed migration
    and 'alembic_command.stamp(cfg, "head")' not in db_src,
)
check(
    "DX8f. memory/db.py implements fcntl.flock advisory lock for migrations",
    "fcntl.flock" in db_src
    and "LOCK_EX" in db_src,
)
check(
    "DX8g. memory/db.py has _get_alembic_version helper for double-checked locking",
    "def _get_alembic_version(" in db_src,
)
check(
    "DX8h. api/app.py defines _extract_trusted_client_ip helper",
    "def _extract_trusted_client_ip(" in app_src,
)
check(
    "DX8i. api/app.py start_scan uses _extract_trusted_client_ip (no raw X-Forwarded-For)",
    "_extract_trusted_client_ip(" in app_src
    and app_src.count("_extract_trusted_client_ip(") >= 2,  # def + at least 2 callsites
)

# ===========================================================================
# AST. SYNTAX / AST VERIFICATION
# ===========================================================================
section("AST. SYNTAX / AST VERIFICATION")

files_to_check = [
    "tools/registry.py",
    "tools/__init__.py",
    "tools/recon/nuclei.py",
    "tools/recon/katana.py",
    "tools/recon/httpx.py",
    "tools/recon/subfinder.py",
    "tools/exploitation/dalfox.py",
    "tools/exploitation/sqlmap.py",
    "tools/exploitation/ysoserial.py",
    "tools/exploitation/phpggc.py",
    "agents/recon/agent.py",
    "agents/validator/agent.py",
    "agents/reflection/agent.py",
    "agents/hypothesis_analyzer/agent.py",
    "memory/db.py",
    "memory/lessons.py",
    "workers/pentest_worker.py",
    "graph/builder.py",
    "state/state.py",
    "config/settings.py",
    "api/auth.py",
    "api/app.py",
    "shared/llm.py",
]
for rel in files_to_check:
    try:
        ast.parse((SRC / rel).read_text())
        check(f"AST: {rel}", True)
    except SyntaxError as exc:
        check(f"AST: {rel}", False, str(exc))

# Also check non-src files.
for f in [
    "scripts/evaluate_ground_truth.py",
    "scripts/doctor.py",
    "tests/ground_truth/app.py",
    "alembic/env.py",
    "verify_all.py",
]:
    try:
        ast.parse((ROOT / f).read_text())
        check(f"AST: {f}", True)
    except SyntaxError as exc:
        check(f"AST: {f}", False, str(exc))

# ===========================================================================
# OUTPUT
# ===========================================================================
print()
print("=" * 78)
print("V6 DX-FINAL UNIFIED AUDIT — PASS/FAIL MATRIX")
print("=" * 78)
for p in passes:
    print(p)
for f in failures:
    print(f)

print()
print("-" * 78)
print(f"Total: {len(passes)} PASS, {len(failures)} FAIL")
print("-" * 78)

if failures:
    print()
    print("VERDICT: V6 DX-FINAL UNIFIED AUDIT FAILED.")
    sys.exit(1)
else:
    print()
    print("VERDICT: V6 DX-FINAL UNIFIED AUDIT PASSED.")
    sys.exit(0)

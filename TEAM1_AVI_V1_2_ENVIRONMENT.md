# TEAM1_AVI_V1_2_ENVIRONMENT

**Date:** 2026-09-19
**Purpose:** Reproducible environment for AVI V1.2 release-closure validation (TEAM-4 BLOCKER 3).
**Rule honored:** the existing lock file (`uv.lock`) is used; no random versions are installed.

---

## 1. Toolchain

| Component | Exact version |
|---|---|
| Python (runtime venv `.venv`) | 3.12.14 |
| Python requirement (pyproject.toml) | `>=3.10` (3.12 used and validated) |
| uv (installer/sync tool) | 0.12.15 |
| OS / arch | Linux 5.10.134-013.15.kangaroo.al8.x86_64 x86_64 |

## 2. Dependency management — lock file is authoritative

The repository ships `uv.lock` (229 pinned packages resolved from `pyproject.toml`).
The environment is created **strictly from the lock file** with `--frozen`
(no resolution, no silent upgrades):

```bash
cd webpent-goed
uv sync --frozen --all-extras
```

`--all-extras` installs the `dev` extras (pytest, pytest-asyncio, pytest-cov, ruff)
plus optional runtime extras, all at lock-file versions.

Lock file integrity (sha256, recorded at closure time):

```
uv.lock       sha256:fcd0e8d544c40f033d90590aedb19ca4167116f7be3a9bf024942ea409078375
pyproject.toml sha256:0840839bfb709f24c45beb18141f54f3d848cbe5b5eeca9c403a3d40e8a71a5c
```

## 3. Installation command (exact, from clean checkout)

```bash
# 1. Install uv >= 0.12 (one-time):  pip install uv  (or curl -LsSf https://astral.sh/uv/install.sh | sh)
# 2. From the repository root:
uv sync --frozen --all-extras
# 3. Verify:
.venv/bin/python --version          # -> 3.12.14
.venv/bin/python -m pytest --version
```

The project itself is installed **editable** into the venv by `uv sync`
(`webpent==0.3.0`, source at `src/webpent`).

## 4. Key package versions (as installed from `uv.lock`)

| Package | Version |
|---|---|
| pydantic | 2.13.4 |
| httpx | 0.28.1 |
| pytest / pytest-asyncio / pytest-cov | 9.1.1 / 1.4.0 / 7.1.0 |
| fastapi | 0.141.1 |
| uvicorn | 0.52.3 |
| langgraph | 0.6.11 |
| langchain | 0.3.30 |
| SQLAlchemy | 2.0.52 |
| alembic | 1.19.1 |
| torch | 2.13.0 |
| numpy | 2.5.2 |
| cryptography | 50.0.0 |

The complete frozen list of all 229 installed packages is in section 7.

## 5. Runtime configuration required by tests / campaign

| Variable | Value used | Why |
|---|---|---|
| `WEBPENT_AUDIT_SECRET_KEY` | `test_key_32_chars_minimum_required_1234567890` | HMAC authenticity tag for sealed ProofBundles. **Test/lab value only** — production must inject a real secret via the config boundary. The acceptance tests set this themselves via `os.environ.setdefault`. |

Network: the real-target harness binds ephemeral HTTP servers on `127.0.0.1`
(localhost only, authorized by `AuthorizedLabProfile` + `ScopeLaw`). No external
network access is required by the validation suites.

## 6. Test commands (exact)

```bash
cd webpent-goed
export WEBPENT_AUDIT_SECRET_KEY="test_key_32_chars_minimum_required_1234567890"

# V1.2 acceptance set (V1 production release + V1.1 real-target + V1.2 semantic integrity)
.venv/bin/python -m pytest tests/team1_acceptance/test_avi_v1_production_release.py \
    tests/team1_acceptance/test_avi_v1_1_real_target_qualification.py \
    tests/team1_acceptance/test_c_proof_semantic_integrity.py -q

# TEAM-3 regression attacks (hostile-fix test files)
.venv/bin/python -m pytest tests/test_e2e_chain_promotion_locks.py \
    tests/team1_acceptance/test_hmac_proof_authority.py \
    tests/team1_acceptance/test_teamt2_hostile_fixes.py \
    tests/test_v10_hostile_fixes.py tests/test_v9_hostile_audit_fixes.py \
    tests/test_fv1_scopelaw_poison_deny.py -q

# 100-decision campaign (writes TEAM1_AVI_V1_2_100_DECISION_RUNTIME.json, runs twice for determinism)
/home/z/.venv/bin/python /home/z/my-project/scripts/team1_v12_campaign.py

# TEAM-3 attack-table runner (documented attack scenarios, per-attack evidence)
/home/z/.venv/bin/python /home/z/my-project/scripts/team1_v12_regression_attacks.py
```

Expected results are recorded in `TEAM1_AVI_V1_2_RELEASE_CLOSURE.md` /
`TEAM1_AVI_V1_2_RELEASE_CLOSURE.json`.

## 7. Complete frozen dependency list (229 packages)

```text
CacheControl==0.14.4
Jinja2==3.1.6
Mako==1.4.1
MarkupSafe==3.0.3
PyJWT==2.13.0
PyPika==0.51.1
PyYAML==6.0.3
Pygments==2.21.0
SQLAlchemy==2.0.52
aiohappyeyeballs==2.7.1
aiohttp==3.14.3
aiosignal==1.4.0
aiosqlite==0.22.1
alembic==1.19.1
amqp==5.3.1
annotated-doc==0.0.5
annotated-types==0.8.0
anthropic==0.122.0
anyio==4.14.2
asgiref==3.12.1
ast_serialize==0.8.0
attrs==26.1.0
backoff==2.2.1
bandit==1.9.4
bcrypt==5.0.0
beautifulsoup4==4.15.0
billiard==4.2.4
boolean.py==5.0
build==1.5.0
celery==5.6.3
certifi==2026.7.22
cffi==2.1.1
charset-normalizer==3.5.1
chroma-hnswlib==0.7.6
chromadb==0.6.3
click-didyoumean==0.3.1
click-plugins==1.1.1.2
click-repl==0.3.0
click==8.4.2
cohere==5.21.1
coverage==7.15.4
cryptography==50.0.0
cuda-bindings==13.3.1
cuda-pathfinder==1.6.0
cuda-toolkit==13.0.3.0
cyclonedx-python-lib==11.12.0
dataclasses-json==0.6.7
defusedxml==0.7.1
distro==1.9.0
docker==7.2.0
docstring_parser==0.18.0
durationpy==0.10
fastapi==0.141.1
fastavro==1.12.2
filelock==3.32.3
filetype==1.2.0
flatbuffers==25.12.19
frozenlist==1.8.0
fsspec==2026.7.0
google-ai-generativelanguage==0.12.0
google-api-core==2.34.0
google-auth==2.56.3
googleapis-common-protos==1.75.1
greenlet==3.1.1
grpcio-status==1.83.0
grpcio==1.83.0
h11==0.16.0
hf-xet==1.6.0
httpcore==1.0.9
httptools==0.8.0
httpx-sse==0.4.3
httpx==0.28.1
huggingface_hub==1.27.0
idna==3.18
importlib_resources==7.1.0
iniconfig==2.3.0
jiter==0.16.0
joblib==1.5.3
jsonpatch==1.33
jsonpointer==3.1.1
kombu==5.6.2
kubernetes==36.0.3
langchain-anthropic==0.3.22
langchain-chroma==0.2.3
langchain-cloudflare==0.3.6
langchain-cohere==0.4.6
langchain-community==0.3.31
langchain-core==0.3.86
langchain-google-genai==2.1.12
langchain-mistralai==0.2.12
langchain-openai==0.3.35
langchain-text-splitters==0.3.11
langchain==0.3.30
langgraph-checkpoint-sqlite==2.0.11
langgraph-checkpoint==2.1.2
langgraph-prebuilt==0.6.5
langgraph-sdk==0.2.15
langgraph==0.6.11
langsmith==0.11.0
librt==0.15.0
license-expression==30.4.4
markdown-it-py==4.2.0
marshmallow==3.26.2
mdurl==0.1.2
mmh3==5.2.1
mpmath==1.3.0
msgpack==1.2.1
multidict==6.7.1
mypy==2.3.1
mypy_extensions==1.1.0
narwhals==2.24.0
networkx==3.6.1
numpy==2.5.2
nvidia-cublas==13.1.1.3
nvidia-cuda-cupti==13.0.85
nvidia-cuda-nvrtc==13.0.88
nvidia-cuda-runtime==13.0.96
nvidia-cudnn-cu13==9.20.0.48
nvidia-cufft==12.0.0.61
nvidia-cufile==1.15.1.6
nvidia-curand==10.4.0.35
nvidia-cusolver==12.0.4.66
nvidia-cusparse==12.6.3.3
nvidia-cusparselt-cu13==0.8.1
nvidia-nccl-cu13==2.29.7
nvidia-nvjitlink==13.3.33
nvidia-nvshmem-cu13==3.4.5
nvidia-nvtx==13.0.85
oauthlib==3.3.1
onnxruntime==1.28.0
openai==2.54.0
opentelemetry-api==1.44.0
opentelemetry-exporter-otlp-proto-common==1.44.0
opentelemetry-exporter-otlp-proto-grpc==1.44.0
opentelemetry-instrumentation-asgi==0.65b0
opentelemetry-instrumentation-fastapi==0.65b0
opentelemetry-instrumentation==0.65b0
opentelemetry-proto==1.44.0
opentelemetry-sdk==1.44.0
opentelemetry-semantic-conventions==0.65b0
opentelemetry-util-http==0.65b0
orjson==3.12.0
ormsgpack==1.12.2
overrides==7.7.0
packageurl-python==0.17.6
packaging==25.0
pathspec==1.1.1
pip-api==0.0.34
pip-requirements-parser==32.0.1
pip_audit==2.10.1
platformdirs==4.11.3
playwright==1.48.0
pluggy==1.6.0
posthog==7.39.1
prompt_toolkit==3.0.53
propcache==0.5.2
proto-plus==1.28.3
protobuf==7.35.1
py-serializable==2.1.0
pyasn1==0.6.4
pyasn1_modules==0.4.2
pycparser==3.0
pydantic-settings==2.15.0
pydantic==2.13.4
pydantic_core==2.46.4
pyee==12.0.0
pyparsing==3.3.2
pypdf==6.16.1
pyproject_hooks==1.2.0
pytest-asyncio==1.4.0
pytest-cov==7.1.0
pytest==9.1.1
python-dateutil==2.9.0.post0
python-dotenv==1.2.3
python-multipart==0.0.32
redis==5.3.1
regex==2026.7.19
requests-oauthlib==2.0.0
requests-toolbelt==1.0.0
requests==2.34.2
rich==15.0.0
ruff==0.16.3
safetensors==0.8.0
scikit-learn==1.9.0
scipy==1.18.0
sentence-transformers==5.7.0
setuptools==84.0.0
shellingham==1.5.4
six==1.17.0
sniffio==1.3.1
sortedcontainers==2.4.0
soupsieve==2.9.2
sqlalchemy-cloudflare-d1==0.3.11
sqlite-vec==0.1.9
starlette==1.6.0
stevedore==5.9.0
structlog==26.1.0
sympy==1.14.0
tenacity==9.1.4
threadpoolctl==3.6.0
tiktoken==0.13.0
tokenizers==0.22.2
tomli==2.4.1
tomli_w==1.2.0
torch==2.13.0
tqdm==4.70.0
transformers==5.15.0
triton==3.7.1
typer==0.27.1
types-PyYAML==6.0.12.20260815
types-requests==2.33.0.20260712
typing-inspect==0.9.0
typing-inspection==0.4.4
typing_extensions==4.16.0
tzdata==2026.3
tzlocal==5.4.4
urllib3==2.7.0
uuid_utils==0.17.0
uvicorn==0.52.3
uvloop==0.22.1
vine==5.1.0
watchfiles==1.2.0
wcwidth==0.8.2
websocket-client==1.9.0
websockets==17.0.1
wrapt==2.3.0
xxhash==4.0.1
yarl==1.24.5
zstandard==0.25.0
```

## 8. Known environment notes

- `pip freeze` reports the project as an editable install of the local source tree;
  version `0.3.0` comes from `pyproject.toml`.
- The shared safe-HTTP client (SSRF guard) blocks direct requests to
  `127.0.0.1`; the authorized-loopback fallback in `ModernOrchestrator.execute_real_request`
  performs the real request to the authorized lab target. This is expected log
  noise (`SSRF transport: blocked direct request ...`) and the observations are
  real HTTP responses — evidence origin remains `target_runtime`.
- No database migrations are required for the validation suites (tests are
  self-contained; `webpent.db` in the repo is not touched by them).

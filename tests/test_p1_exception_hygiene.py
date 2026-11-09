from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRITICAL_FILES = (
    "src/webpent/production/autonomous_validation_v1.py",
    "src/webpent/production/validators.py",
    "src/webpent/shared/http.py",
    "src/webpent/production/modern_spine.py",
    "src/webpent/production/context_authority.py",
    "src/webpent/shared/fixture_registry.py",
    "src/webpent/shared/untrusted_content.py",
    "src/webpent/graph/builder.py",
    "src/webpent/agents/validator/agent.py",
)
FROZEN_TOOL_BOUNDARY_SHA256 = "c46608c3add66d66898ede7b9e89345c3ddaa7cc14bf624ae1ccac57cf2a0cd0"
# DR-006 adjudicated hash (TC-2) — see DRIFT_REGISTER.md DR-006.
DR006_TOOL_BOUNDARY_SHA256 = "01dafce37a6eea81b1c6a6dee46f2836f8e8850ef7fb6d4a2d8f21a86a11e616"


def test_named_critical_modules_have_no_broad_exception_handlers():
    violations = []
    for relative in CRITICAL_FILES:
        tree = ast.parse((ROOT / relative).read_text(), filename=relative)
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Name) and node.type.id == "Exception":
                violations.append(f"{relative}:{node.lineno}")
    assert violations == []


def test_frozen_tool_boundary_is_byte_identical():
    # DR-006 (TC-2): the resurrection modified tool_boundary.py after this
    # pin was captured (v9 hash c46608c3… -> adjudicated 01dafce3…).  The
    # delta was adjudicated as an ADDITIVE, default-off authority extension
    # (S-3): __init__ gains allowed_hosts=() (empty tuple changes nothing
    # for existing callers) and a NEW fail-closed is_allowed() second-layer
    # check; the authorize() path is byte-unchanged in semantics.  Adopted
    # and re-pinned here; full adjudication record in DRIFT_REGISTER.md
    # DR-006.  Any FURTHER drift from the adjudicated hash still fails.
    path = ROOT / "src/webpent/llm_researcher/tool_boundary.py"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == DR006_TOOL_BOUNDARY_SHA256

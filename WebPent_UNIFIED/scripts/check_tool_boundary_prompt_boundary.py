"""Static gate for the ToolBoundary -> LLM consumption boundary."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "webpent"
ADAPTER = SRC / "llm_researcher" / "tool_boundary_adapter.py"
PROMPT_PATHS = (
    SRC / "llm_researcher" / "interface.py",
    SRC / "llm_researcher" / "research_loop.py",
    SRC / "llm_researcher" / "causal_feedback_bridge.py",
    SRC / "shared" / "llm.py",
)


def _direct_boundary_imports(path: Path) -> list[str]:
    if not path.exists():
        return []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "webpent.llm_researcher.tool_boundary":
            hits.append(f"{path}:{node.lineno}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "webpent.llm_researcher.tool_boundary":
                    hits.append(f"{path}:{node.lineno}")
    return hits


def main() -> int:
    errors: list[str] = []
    if not ADAPTER.exists():
        errors.append("missing_tool_boundary_adapter")
    interface = (SRC / "llm_researcher" / "interface.py").read_text(encoding="utf-8")
    if "adapt_tool_boundary_result" not in interface:
        errors.append("interface_missing_adapter_projection")
    if "wrap_target_content" in interface:
        errors.append("interface_bypasses_adapter")
    for path in PROMPT_PATHS:
        errors.extend(_direct_boundary_imports(path))
    adapter = ADAPTER.read_text(encoding="utf-8") if ADAPTER.exists() else ""
    if "adapt_tool_boundary_result" not in adapter or "wrap_target_content" not in adapter:
        errors.append("adapter_missing_untrusted_projection")
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PASS: ToolBoundary prompt-consumption boundary is adapter-enforced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

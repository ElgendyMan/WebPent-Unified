from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
OUT_MATRIX = ROOT / "combined_plan_traceability_matrix.json"
OUT_GRAPH = ROOT / "source_runtime_callgraph.md"


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def python_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def symbol_index() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for path in python_files():
        text = read_text(path)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                result.setdefault(node.name, []).append(str(path.relative_to(ROOT)))
    return result


def graph_facts() -> dict[str, object]:
    builder = ROOT / "src/webpent/graph/builder.py"
    text = read_text(builder)
    nodes = sorted(set(re.findall(r"graph\.add_node\((NODE_[A-Z0-9_]+)", text)))
    edges = re.findall(
        r"graph\.add_edge\((NODE_[A-Z0-9_]+|START|END),\s*(NODE_[A-Z0-9_]+|START|END)\)", text
    )
    conditionals = re.findall(
        r"graph\.add_conditional_edges\(\s*(NODE_[A-Z0-9_]+),\s*([a-zA-Z_][a-zA-Z0-9_]*)", text
    )
    interrupt = "interrupt_before" in text
    return {
        "builder": str(builder.relative_to(ROOT)),
        "nodes": nodes,
        "edges": [list(edge) for edge in edges],
        "conditional_edges": [list(edge) for edge in conditionals],
        "interrupt_before_present": interrupt,
    }


def callers(names: list[str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {name: [] for name in names}
    for path in python_files():
        if path.name in {"llm.py", "self_critique.py"}:
            continue
        text = read_text(path)
        for name in names:
            if name in text:
                result[name].append(str(path.relative_to(ROOT)))
    return result


def status_for(required_symbols: list[str], required_files: list[str]) -> dict[str, object]:
    idx = symbol_index()
    missing_symbols = [name for name in required_symbols if name not in idx]
    missing_files = [name for name in required_files if not (ROOT / name).exists()]
    return {
        "implemented_symbols": {
            name: idx.get(name, []) for name in required_symbols if name in idx
        },
        "missing_symbols": missing_symbols,
        "missing_files": missing_files,
        "status": "implemented"
        if not missing_symbols and not missing_files
        else "partial_or_absent",
    }


def main() -> None:
    matrix = {
        "baseline": {
            "archive": "/home/ubuntu/upload/webpent_v60_final_reviewed.zip",
            "pytest": "700 passed, 110 warnings",
            "ruff": "104 errors under configured E/F/I/N/W/UP/B/C4/SIM rules",
            "compileall": (
                "not reached in first baseline command because Ruff failed; rerun separately"
            ),
        },
        "graph": graph_facts(),
        "p0_traceability": {
            "same_client_lesson_retrieval": status_for(
                ["search_lessons"], ["src/webpent/memory/lessons.py"]
            ),
            "cached_llm": {
                **status_for(["get_cached_llm"], ["src/webpent/shared/llm.py"]),
                "callers": callers(["get_cached_llm"])["get_cached_llm"],
            },
            "deterministic_confidence": status_for(
                ["compute_confidence_score"], ["src/webpent/shared/confidence.py"]
            ),
            "self_critique": {
                **status_for(
                    ["recommend_self_critique_action", "should_fire_before_promotion"],
                    ["src/webpent/shared/self_critique.py"],
                ),
                "callers": callers(
                    ["recommend_self_critique_action", "should_fire_before_promotion"]
                ),
            },
            "smart_campaigns": status_for(
                ["smart_campaigns_node", "smart_campaigns_execution_node"],
                ["src/webpent/agents/smart_campaigns/agent.py"],
            ),
        },
        "planned_components": {
            "KnowledgeGapEngine": status_for(["KnowledgeGapEngine"], []),
            "ResearchSession": status_for(["ResearchSession"], []),
            "ActionExecutor": status_for(["ActionExecutor"], []),
            "ProofBundle": status_for(["ProofBundle"], []),
            "NegativeEvidenceLedger": status_for(["NegativeEvidenceLedger"], []),
            "CoverageIntelligence": status_for(["CoverageIntelligence"], []),
        },
    }
    OUT_MATRIX.write_text(json.dumps(matrix, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    graph = matrix["graph"]
    lines = [
        "# Source-to-runtime callgraph (Phase 0)",
        "",
        f"Generated from `{graph['builder']}` by a static AST/regex audit.",
        "This artifact is source evidence, not proof that every edge completed in a live scan.",
        "",
        "## Registered nodes",
        "",
    ]
    lines.extend(f"- `{node}`" for node in graph["nodes"])
    lines.extend(["", "## Direct edges", ""])
    lines.extend(f"- `{left}` -> `{right}`" for left, right in graph["edges"])
    lines.extend(["", "## Conditional routers", ""])
    lines.extend(f"- `{node}` uses `{router}()`" for node, router in graph["conditional_edges"])
    lines.extend(
        [
            "",
            "## Approval boundary",
            "",
            f"- `interrupt_before` present in builder: `{graph['interrupt_before_present']}`",
        ]
    )
    OUT_GRAPH.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

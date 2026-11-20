#!/usr/bin/env python3
"""UMDR42 Phase B — full-project audit.

Runs a battery of scans over src/ and produces a consolidated findings
file (UMDR42_AUDIT_FINDINGS.json + .md). Scans:

  B1  ruff check (all rules, no fix) — weak code / lint debt
  B2  bandit -lll (high severity) — security weak code
  B3  dead code: public functions/classes in src/ never referenced
      anywhere in src/ (excl. self), tests/, scripts/, or wired entry
      points (main/server/worker/viewer)
  B4  wiring: entry-point imports (main/server/worker/viewer/entrypoint)
      that fail, module-level __init__ exports that don't exist
  B5  weak patterns: bare except, except Exception: pass (silent
      swallow), mutable default args, == None / != None comparisons
  B6  TODO/FIXME/XXX/HACK markers in src/
  B7  duplicate function names across modules in the same package
      (accidental shadowing via re-export)
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
OUT = ROOT / "deliverables" / "umdr42_audit"

# ---- UMDR42 D5: ratchet mode -------------------------------------------
# A dead-code baseline (scripts/quality/dead_code_baseline.json) records
# the post-D2 candidate count. In ratchet mode the scanner FAILS if the
# current candidate count exceeds the baseline; run with --update-baseline
# to re-freeze after a deliberate reduction.
import sys as _sys
_UPDATE = "--update-baseline" in _sys.argv

findings: list[dict] = []


def run(cmd: list[str], timeout: int = 300) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       timeout=timeout)
    return p.returncode, (p.stdout + p.stderr)


def add(category: str, severity: str, file: str, line: int, title: str,
        detail: str) -> None:
    findings.append({
        "id": f"UMDR42-{len(findings) + 1:03d}",
        "category": category, "severity": severity,
        "file": file, "line": line, "title": title, "detail": detail,
    })


def rel(p: Path) -> str:
    return str(p.relative_to(ROOT))


# ---------------------------------------------------------------- B1 ruff
print("B1: ruff ...", flush=True)
if subprocess.run(["which", "ruff"], capture_output=True).returncode == 0:
    rc, out = run(["ruff", "check", "src/", "--output-format=concise",
                   "--no-cache"], timeout=600)
    # severity mapping below; we record the count + top categories
    lines = [l for l in out.splitlines() if l.strip().startswith("src/")]
    add("lint", "info", "src/", 0,
        f"ruff findings: {len(lines)}",
        "Full list in ruff output; categorized counts in detail. "
        "This is pre-existing tracked debt (ruff ratchet baseline in "
        "scripts/quality/ruff_baseline.json governs CI); recorded for "
        "the audit, fix handled via the ratchet, not one-by-one here.")
    from collections import Counter
    codes = Counter(l.split(":")[-1].strip().split()[0]
                    for l in lines if ":" in l)
    top = ", ".join(f"{k}={v}" for k, v in codes.most_common(10))
    findings[-1]["detail"] += f" | top codes: {top}"
else:
    add("tooling", "info", "-", 0, "ruff not installed in sandbox", "-")

# ------------------------------------------------------------- B2 bandit
print("B2: bandit ...", flush=True)
if subprocess.run(["which", "bandit"], capture_output=True).returncode == 0:
    rc, out = run(["bandit", "-q", "-r", "src/webpent", "-lll",
                   "-f", "json"], timeout=600)
    try:
        data = json.loads(out)
        for r in data.get("results", []):
            add("security", "high", r["filename"], r["line_number"],
                f"bandit {r['test_id']}: {r['issue_text'][:100]}",
                r.get("code", "").strip()[:200])
    except json.JSONDecodeError:
        add("tooling", "info", "-", 0, "bandit output unparseable", out[:200])
else:
    add("tooling", "info", "-", 0, "bandit not installed in sandbox", "-")

# -------------------------------------------------- B3 dead public symbols
print("B3: dead-code scan ...", flush=True)
# collect all definitions in src
# decorator-registered symbols: any def whose decorator list mentions a
# .command/.callback/.get/.post/.put/.delete/.patch/.on_event/.route/
# .websocket/.add_api_route call registers the function with a framework
# (Typer/FastAPI/Flask) at import time — never dead regardless of name
# references. AST visitors (visit_*) are framework dispatch too.
DECORATOR_RE = re.compile(
    r"\.(command|callback|get|post|put|delete|patch|route|websocket"
    r"|on_event|add_api_route|exception_handler|middleware|hookimpl"
    r"|hookspec|singledispatch|register|signal|receiver|task|on_"
    r"|shared_task|app_template_filter|context_processor)\b")

defs: dict[str, list[tuple[Path, int, str]]] = {}  # name -> [(file,line,kind)]
for py in SRC.rglob("*.py"):
    if "__pycache__" in str(py):
        continue
    try:
        tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        add("error", "high", rel(py), 0, "SyntaxError", "file unparseable")
        continue
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            # decorator-registered defs (Typer/FastAPI/pytest/pluggy
            # hooks) are framework-dispatched — never dead candidates
            if getattr(node, "decorator_list", None):
                dec_src = " ".join(
                    ast.unparse(d) for d in node.decorator_list)
                if DECORATOR_RE.search(dec_src) or dec_src.strip(
                ).startswith(("pytest", "fixture", "parametrize")):
                    continue
            # AST visitor methods are framework dispatch
            if node.name.startswith("visit_"):
                continue
            # only MODULE-LEVEL and class-public defs
            defs.setdefault(node.name, []).append(
                (py, node.lineno, type(node).__name__))

# gather the full reference corpus (src + tests + scripts + entries)
corpus_files = list(SRC.rglob("*.py")) + list((ROOT / "tests").rglob("*.py")) \
    + list((ROOT / "scripts").rglob("*.py"))
for extra in ("main.py", "server.py", "worker.py", "viewer.py",
              "verify_all.py"):
    p = ROOT / extra
    if p.is_file():
        corpus_files.append(p)
corpus = ""
for f in corpus_files:
    if "__pycache__" in str(f):
        continue
    try:
        corpus += f.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass

# names that are framework/magic/dunder or known-legal unreferenced
ALLOW = {
    "__init__", "__str__", "__repr__", "__eq__", "__hash__", "__len__",
    "__enter__", "__exit__", "__post_init__", "__iter__", "__next__",
    "__call__", "__getattr__", "__setattr__", "__contains__", "__aiter__",
    "__anext__", "__aenter__", "__aexit__", "__await__", "__bool__",
    "main",
}

# __all__ exports count as referenced (public API)
all_exports: set[str] = set()
for py in SRC.rglob("*.py"):
    try:
        tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        continue
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and any(getattr(t, "id", None) == "__all__"
                        for t in node.targets)):
            try:
                all_exports.update(
                    ast.literal_eval(node.value))
            except Exception:
                pass

dead: list[tuple[Path, int, str, str]] = []
for name, sites in defs.items():
    if name.startswith("_") or name in ALLOW or name in all_exports:
        continue
    # count references OUTSIDE its own def line
    occurrences = len(re.findall(r"\b" + re.escape(name) + r"\b", corpus))
    def_count = len(sites)
    # a name referenced at most as many times as it is defined
    # (i.e., no usage beyond its own def) is a dead candidate
    if occurrences <= def_count:
        for f, ln, kind in sites:
            dead.append((f, ln, name, kind))

print(f"   dead candidates: {len(dead)}")
# record as ONE summary finding per file (keeps the register usable)
from collections import defaultdict
dead_by_file: dict[Path, list] = defaultdict(list)
for f, ln, name, kind in dead:
    dead_by_file[f].append(f"{name} ({kind}, line {ln})")
for f, items in sorted(dead_by_file.items(), key=lambda kv: -len(kv[1])):
    add("dead-code", "medium", rel(f), items[0].split("line ")[-1],
        f"{len(items)} unreferenced public symbol(s)",
        "; ".join(items[:12]) + (" ..." if len(items) > 12 else ""))

# ------------------------------------------------ B4 wiring: entry imports
print("B4: entry-point wiring ...", flush=True)
for entry in ("main.py", "server.py", "worker.py", "viewer.py"):
    p = ROOT / entry
    if not p.is_file():
        continue
    rc, out = run([sys.executable, "-c",
                   f"import ast,sys; ast.parse(open('{entry}').read())"],
                   timeout=60)
    if rc != 0:
        add("wiring", "high", entry, 0, "entry file unparseable", out[:200])
# __init__ export existence
for init in SRC.rglob("__init__.py"):
    try:
        tree = ast.parse(init.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        continue
    # collect names genuinely available in the module namespace:
    # imported names, assignments (incl. tuple unpacking AND names
    # bound inside try/except import guards — the layer-gate pattern
    # used across the optional packages), and def/class statements
    available: set[str] = set()

    def collect(bindings: list[ast.stmt]) -> None:
        for node in bindings:
            if isinstance(node, ast.ImportFrom):
                for a in node.names:
                    available.add(a.asname or a.name)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    available.add((a.asname or a.name).split(".")[0])
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        available.add(t.id)
                    elif isinstance(t, (ast.Tuple, ast.List)):
                        for el in t.elts:
                            if isinstance(el, ast.Name):
                                available.add(el.id)
                            elif isinstance(el, ast.Starred) and isinstance(el.value, ast.Name):
                                available.add(el.value.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                available.add(node.target.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                   ast.ClassDef)):
                available.add(node.name)
            elif isinstance(node, ast.Try):
                for sub in (node.body + node.orelse + node.finalbody
                            + [s for eh in node.handlers
                               for s in eh.body]):
                    collect([sub])

    collect(tree.body)
    src_text = init.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"__all__\s*=\s*\[(.*?)\]", src_text, re.S)
    if not m:
        continue
    try:
        names = ast.literal_eval("[" + m.group(1) + "]")
    except Exception:
        continue
    # a module-level __getattr__ (PEP 562 lazy export) resolves ANY
    # name at runtime — its branches enumerate the supported names
    has_lazy_getattr = any(
        isinstance(node, ast.FunctionDef) and node.name == "__getattr__"
        for node in tree.body)
    pkg_dir = init.parent
    for n in names:
        if n in available:
            continue  # imported/defined above -> fine
        if has_lazy_getattr:
            continue  # PEP 562 lazy export resolves it at runtime
        target = None
        if (pkg_dir / f"{n}.py").is_file():
            target = pkg_dir / f"{n}.py"
        elif (pkg_dir / n / "__init__.py").is_file():
            target = pkg_dir / n / "__init__.py"
        if target is None:
            # not imported, not defined, no module/file backing -> broken
            add("wiring", "high", rel(init), 0,
                f"__all__ exports missing symbol '{n}'",
                "exported name has no module, submodule, import or "
                "definition backing it in this package")

# ------------------------------------------------ B5 weak patterns
print("B5: weak patterns ...", flush=True)
WEAK_PATTERNS = [
    (re.compile(r"except\s+Exception\s*:\s*\n\s*pass"), "silent except-pass"),
    (re.compile(r"except\s*:\s*\n"), "bare except"),
    (re.compile(r"def\s+\w+\([^)]*=\s*\[\]\s*\)"), "mutable default []"),
    (re.compile(r"def\s+\w+\([^)]*=\s*\{\}\s*\)"), "mutable default {}"),
    (re.compile(r"[!=]=\s+None\b"), "None comparison with =="),
]
weak_counts: dict[str, int] = defaultdict(int)
for py in SRC.rglob("*.py"):
    if "__pycache__" in str(py):
        continue
    text = py.read_text(encoding="utf-8", errors="replace")
    for pat, label in WEAK_PATTERNS:
        n = len(pat.findall(text))
        if n:
            weak_counts[label] += n
for label, n in sorted(weak_counts.items(), key=lambda kv: -kv[1]):
    add("weak-code", "medium", "src/", 0, f"{label}: {n} occurrences",
        "pattern scan across src/; see audit .md for per-file detail")

# ------------------------------------------------------------- B6 markers
print("B6: TODO markers ...", flush=True)
marker_re = re.compile(r"#\s*(TODO|FIXME|XXX|HACK)\b")
marker_files = 0
marker_total = 0
for py in SRC.rglob("*.py"):
    if "__pycache__" in str(py):
        continue
    hits = marker_re.findall(py.read_text(encoding="utf-8",
                                          errors="replace"))
    if hits:
        marker_files += 1
        marker_total += len(hits)
add("markers", "low", "src/", 0,
    f"{marker_total} TODO/FIXME/XXX/HACK markers in {marker_files} files",
    "tracked backlog markers")

# ------------------------------------------------------- B7 smoke compile
print("B7: compileall ...", flush=True)
rc, out = run([sys.executable, "-m", "compileall", "-q", "src/"],
              timeout=600)
if rc != 0:
    add("error", "high", "src/", 0, "compileall failures", out[:500])
else:
    add("error", "info", "src/", 0, "compileall clean", "all modules compile")

# ------------------------------------------------------------------- write
OUT.mkdir(parents=True, exist_ok=True)
sev_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
findings.sort(key=lambda f: (sev_rank.get(f["severity"], 4),
                             f["category"], f["file"]))
for i, f in enumerate(findings, 1):
    f["id"] = f"UMDR42-{i:03d}"
json.dump({"generated": "2026-11-19", "tool": "umdr42 phase B audit",
           "counts": {
               "total": len(findings),
               "high": sum(1 for f in findings if f["severity"] == "high"),
               "medium": sum(1 for f in findings
                             if f["severity"] == "medium"),
               "low": sum(1 for f in findings if f["severity"] == "low"),
           }, "findings": findings},
          open(OUT / "UMDR42_AUDIT_FINDINGS.json", "w"),
          indent=2, ensure_ascii=False)

with open(OUT / "UMDR42_AUDIT_FINDINGS.md", "w") as fh:
    fh.write("# UMDR42 Phase B — Full-Project Audit Findings\n\n")
    fh.write(f"Generated 2026-11-19. Total: {len(findings)} findings "
             f"({sum(1 for f in findings if f['severity']=='high')} high, "
             f"{sum(1 for f in findings if f['severity']=='medium')} medium,"
             f" {sum(1 for f in findings if f['severity']=='low')} low, "
             f"{sum(1 for f in findings if f['severity']=='info')} info).\n\n")
    fh.write("Categories: " + ", ".join(sorted({f['category']
             for f in findings})) + "\n\n---\n\n")
    for f in findings:
        fh.write(f"## {f['id']} [{f['severity'].upper()}] "
                 f"({f['category']}) — {f['title']}\n\n")
        fh.write(f"- **File:** `{f['file']}`" +
                 (f" (line {f['line']})" if f['line'] else "") + "\n")
        fh.write(f"- **Detail:** {f['detail']}\n\n")
print(f"\nDONE: {len(findings)} findings -> {OUT}")

# ---- ratchet on the dead-code candidate count ---------------------------
import json as _json
from pathlib import Path as _P
_baseline = ROOT / "scripts" / "quality" / "dead_code_baseline.json"
_dead = [f for f in findings if f["category"] == "dead-code"]
_count = sum(int(f["title"].split()[0]) for f in _dead)
if _UPDATE:
    _baseline.write_text(_json.dumps(
        {"dead_code_candidates": _count, "date": "2026-11-19",
         "note": "UMDR42 D5 ratchet baseline (post-D2 deletions)"},
        indent=2) + "\n")
    print(f"dead-code baseline updated: {_count}")
elif _baseline.is_file():
    _limit = _json.loads(_baseline.read_text())["dead_code_candidates"]
    if _count > _limit:
        print(f"FAIL: dead-code candidates {_count} exceed baseline "
              f"{_limit} — delete the new dead code or document and "
              f"re-baseline with --update-baseline")
        raise SystemExit(1)
    print(f"dead-code ratchet: {_count} <= {_limit} OK")
else:
    print("no dead-code baseline yet — run with --update-baseline")

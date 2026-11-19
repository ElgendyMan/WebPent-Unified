#!/usr/bin/env python3
"""check_triple_consistency.py — NF-P0R-01 standing check."""
from __future__ import annotations
import argparse, re, sys
from pathlib import Path
try: import tomllib
except ModuleNotFoundError: import tomli as tomllib
try: from importlib.metadata import version as installed_version, PackageNotFoundError
except ModuleNotFoundError: from importlib_metadata import version as installed_version, PackageNotFoundError
def parse_closure(p):
    r = {}
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        m = re.match(r"^([a-zA-Z0-9_.-]+)==([a-zA-Z0-9_+.-]+)$", line)
        if m: r[m.group(1).lower()] = m.group(2)
    return r
def parse_pyproject_pins(p):
    data = tomllib.loads(p.read_text())
    deps = data.get("project",{}).get("dependencies",[])
    r = {}
    for dep in deps:
        dep = dep.strip().strip(",").strip('"').strip()
        m = re.match(r'^"?([a-zA-Z0-9_.-]+)(?:\[[^\]]*\])?==([a-zA-Z0-9_+.-]+)"?$', dep)
        if m: r[m.group(1).lower()] = m.group(2)
    return r
def parse_uv_lock(p):
    r = {}
    cur = None
    for line in p.read_text().splitlines():
        m = re.match(r'^name\s*=\s*"([^"]+)"\s*$', line.strip())
        if m: cur = m.group(1).lower(); continue
        m = re.match(r'^version\s*=\s*"([^"]+)"\s*$', line.strip())
        if m and cur: r[cur] = m.group(1); cur = None
    return r
def get_installed(pkgs):
    r = {}
    for n in pkgs:
        try: r[n] = installed_version(n)
        except PackageNotFoundError: r[n] = None
    return r
def check(root, verbose=False):
    closure = parse_closure(root/"deliverables"/"requirements_closure.txt")
    pypins = parse_pyproject_pins(root/"pyproject.toml")
    lock = parse_uv_lock(root/"uv.lock")
    inst = get_installed(set(pypins.keys()))
    errors = []
    for pkg, pv in sorted(pypins.items()):
        cv = closure.get(pkg, "<not-in-closure>")
        lv = lock.get(pkg, "<not-in-lock>")
        iv = inst.get(pkg)
        if cv != pv: errors.append(f"DIVERGENCE {pkg}: pyproject={pv} closure={cv}")
        if lv != pv: errors.append(f"DIVERGENCE {pkg}: pyproject={pv} uv.lock={lv}")
        if iv is None: errors.append(f"NOT-INSTALLED {pkg}: pyproject={pv}")
        elif iv != pv: errors.append(f"DIVERGENCE {pkg}: pyproject={pv} installed={iv}")
    return (1 if errors else 0, errors)
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parent.parent)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--negative-control", action="store_true")
    args = ap.parse_args()
    if args.negative_control:
        print("NEGATIVE CONTROL: injecting fake langgraph divergence")
        pypins = parse_pyproject_pins(args.project_root/"pyproject.toml")
        pypins["langgraph"] = "0.0.0-fake"
        lock = parse_uv_lock(args.project_root/"uv.lock")
        inst = get_installed(set(pypins.keys()))
        errors = []
        for pkg, pv in sorted(pypins.items()):
            lv = lock.get(pkg,"<not-in-lock>")
            iv = inst.get(pkg)
            if lv != pv: errors.append(f"DIVERGENCE {pkg}: pyproject={pv} uv.lock={lv}")
            if iv and iv != pv: errors.append(f"DIVERGENCE {pkg}: pyproject={pv} installed={iv}")
        if errors:
            print(f"NEGATIVE CONTROL TRIPPED: {len(errors)} divergence(s)")
            for e in errors[:5]: print(f"  {e}")
            return 1
        print("NEGATIVE CONTROL FAILED"); return 2
    print(f"TRIPLE-CONSISTENCY CHECK — {args.project_root}")
    rc, errors = check(args.project_root, args.verbose)
    if rc == 0: print("TRIPLE-CONSISTENCY: PASS (all sources agree)"); return 0
    print(f"TRIPLE-CONSISTENCY: FAIL ({len(errors)} divergence(s))")
    for e in errors: print(f"  {e}")
    return 1
if __name__ == "__main__": sys.exit(main())

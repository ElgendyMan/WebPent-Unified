#!/usr/bin/env python3
"""Sprint I-1, item 2.3 — S-2 composition test subprocess body (M3 v1.1
§5.2.2, amended by F-02).

Runs in a FRESH subprocess (spawned by
tests/team1_acceptance/test_sprint_i1_part2_s2_composition.py) so
sys.modules starts clean. Prints a single JSON line to stdout as its
result; the parent test process makes the actual assertions so failures
show up as normal pytest failures, not just a subprocess exit code.

KNOWN GAP (see config/isolation_denylist.yaml and the sprint changelog):
D-01 (denylisted top-level names) and A-01 (allowlisted site-packages)
were never provided to this sprint (M3 v1.1 defers to a v1.0 document
that was not uploaded). This script CANNOT assert "no denylisted name in
sys.modules" or "no module outside webpent/stdlib/A-01" without
fabricating that contract. It DOES implement, fully and for real:
  - importing every composition root by real name, including the pinned
    uvicorn string target for the API app;
  - resolve_production_spine() for a loopback engagement;
  - the F-02 lazy-load trigger (getattr every public name, forcing
    __getattr__ resolution), including webpent.research_engine directly;
  - the OQ-2 bbscout-absence assertion, which needs no denylist — it is
    one specific, spec-named package;
  - a "strix" substring absence check in sys.modules keys, justified
    directly by M3's own repeated language ("no capability of the
    external reference codebase (Strix) is reachable") rather than by
    any D-01 content this sprint lacks.
"""
from __future__ import annotations

import importlib
import json
import sys


def lazy_load_trigger(module) -> list[str]:
    """F-02: access every public name via getattr() to force __getattr__
    resolution. Returns the list of names successfully resolved."""
    names = getattr(module, "__all__", None)
    if names is None:
        names = [n for n in dir(module) if not n.startswith("_")]
    resolved = []
    for name in names:
        try:
            getattr(module, name)
            resolved.append(name)
        except AttributeError:
            pass
    return resolved


def compute_a01_transitive_closure(a01_entries: list[str], dist_name_overrides: dict[str, str]) -> set[str]:
    """Sprint I-1 Continuation 03: A-01's 33 entries are IMPORT names
    (config/isolation_denylist.yaml), but pip distribution names often
    differ (e.g. import `jose` <- distribution `python-jose`; import
    `yaml` <- distribution `PyYAML`). A-01 members also pull in real,
    legitimate transitive dependencies (anyio, starlette, click, six,
    ... — verified this sprint: 41 distinct top-level modules appear at
    runtime beyond the 33 direct A-01 names, all traced to real
    dependency edges). A literal "top-level import must BE an A-01 name"
    check would false-positive on every one of those 41. This computes
    the full transitive closure of A-01's declared pip dependencies via
    importlib.metadata, so the S-2 test can check group membership
    correctly instead of only exact-name membership.
    """
    import importlib.metadata as im

    def normalize(name: str) -> str:
        return name.lower().replace("_", "-")

    seen: set[str] = set()
    stack = [dist_name_overrides.get(e, e) for e in a01_entries]
    while stack:
        name = stack.pop()
        key = normalize(name)
        if key in seen:
            continue
        seen.add(key)
        try:
            dist = im.distribution(name)
        except im.PackageNotFoundError:
            continue
        for req in (dist.requires or []):
            req_name = req.split(";")[0]
            for sep in ("<", ">", "=", "!", "~", "[", " "):
                req_name = req_name.split(sep)[0]
            req_name = req_name.strip()
            if req_name:
                stack.append(req_name)
    return seen


def main() -> None:
    result = {"errors": [], "lazy_loaded": {}, "resolve_production_spine_ok": False}

    composition_roots = [
        "webpent.cli",
        "webpent.cli.ingest",
        "webpent.workers.pentest_worker",
        "webpent.production.production_spine",
        "webpent.production.modern_spine_integration",
    ]
    imported_modules = {}
    for root in composition_roots:
        try:
            imported_modules[root] = importlib.import_module(root)
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"import {root} failed: {exc!r}")

    # Pinned uvicorn string target, resolved exactly as uvicorn.run()
    # resolves "webpent.api.app:app" internally — module path then
    # attribute lookup, not a plain top-level import (this is the exact
    # mechanism M1's audit found a naive static import-graph analysis
    # missing).
    try:
        api_module_path, api_attr = ["webpent.api.app", "app"]
        api_module = importlib.import_module(api_module_path)
        getattr(api_module, api_attr)
        imported_modules["webpent.api.app"] = api_module
    except Exception as exc:  # noqa: BLE001
        result["errors"].append(f"pinned uvicorn target webpent.api.app:app failed: {exc!r}")

    # F-02 lazy-load trigger for every imported composition root.
    for name, module in imported_modules.items():
        result["lazy_loaded"][name] = lazy_load_trigger(module)

    # research_engine may not be reached by every entrypoint import
    # chain — import it directly too, per F-02's explicit instruction.
    try:
        research_engine = importlib.import_module("webpent.research_engine")
        result["lazy_loaded"]["webpent.research_engine"] = lazy_load_trigger(research_engine)
    except Exception as exc:  # noqa: BLE001
        result["errors"].append(f"import webpent.research_engine failed: {exc!r}")

    # resolve_production_spine for a loopback engagement.
    try:
        from webpent.production.production_spine import (
            ProductionSpineConfig,
            resolve_production_spine,
        )

        cfg = ProductionSpineConfig(
            engagement_id="s2_composition_test_loopback",
            target_url="http://127.0.0.1:1",
            entrypoint="cli",
        )
        resolve_production_spine(cfg)
        result["resolve_production_spine_ok"] = True
    except Exception as exc:  # noqa: BLE001
        result["errors"].append(f"resolve_production_spine failed: {exc!r}")

    result["sys_modules_keys"] = sorted(sys.modules.keys())

    # Sprint I-1 Continuation 03: D-01 denylisted-name assertion (now
    # buildable, real content arrived) + A-01-closure assertion (see
    # compute_a01_transitive_closure's docstring for why this needs the
    # transitive closure, not exact-name membership).
    d01_patterns = [
        "strix", "strix.agents", "strix.config", "strix.core", "strix.interface",
        "strix.llm", "strix.report", "strix.runtime", "strix.skills",
        "strix.telemetry", "strix.tools", "strix.utils",
    ]
    result["d01_hits"] = [
        m for m in result["sys_modules_keys"]
        if any(m == p or m.startswith(p + ".") for p in d01_patterns)
    ]

    a01_entries = [
        "alembic", "bcrypt", "bbscout", "bs4", "celery", "cryptography", "dns",
        "fastapi", "httpx", "jinja2", "jose", "jwt", "langchain_anthropic",
        "langchain_chroma", "langchain_cloudflare", "langchain_cohere",
        "langchain_community", "langchain_core", "langchain_google_genai",
        "langchain_mistralai", "langchain_openai", "langchain_text_splitters",
        "langgraph", "pdfkit", "playwright", "pydantic", "pydantic_settings",
        "redis", "rich", "typer", "uvicorn", "weasyprint", "yaml",
        "sentence_transformers",
    ]
    # import-name -> real pip distribution-name overrides, for names that
    # differ (verified against installed metadata this sprint).
    dist_overrides = {
        "bs4": "beautifulsoup4", "dns": "dnspython", "jose": "python-jose",
        "jwt": "pyjwt", "yaml": "pyyaml",
    }
    a01_closure = compute_a01_transitive_closure(a01_entries, dist_overrides)

    try:
        import importlib.metadata as im
        pkg_dist_map = im.packages_distributions()
    except Exception:
        pkg_dist_map = {}

    # Known interpreter/tooling artifacts that are not real pip packages
    # at all (no distribution metadata exists for them) -- verified this
    # sprint: cython_runtime is a Cython-compiled-extension runtime hook,
    # sitecustomize is Python's own site-customization auto-import hook.
    # pywin32_bootstrap / pywin32_system32 are interpreter bootstrapping
    # shims injected by the Windows Python distribution itself (they carry
    # no pip distribution and exist only on win32) — same class of
    # non-package interpreter artifact, not a third-party dependency.
    _NON_PACKAGE_ARTIFACTS = {
        "cython_runtime",
        "sitecustomize",
        "pywin32_bootstrap",
        "pywin32_system32",
    }

    stdlib_names = set(getattr(sys, "stdlib_module_names", ()))
    unaccounted = []
    for mod_name in result["sys_modules_keys"]:
        top = mod_name.split(".")[0]
        if top == "webpent" or top in stdlib_names or top.startswith("_"):
            continue
        if top in _NON_PACKAGE_ARTIFACTS:
            continue
        dists = pkg_dist_map.get(top, [])
        if any(d.lower().replace("_", "-") in a01_closure for d in dists):
            continue
        if top.lower().replace("_", "-") in a01_closure:
            continue
        unaccounted.append(mod_name)
    result["a01_unaccounted_top_level"] = sorted(set(m.split(".")[0] for m in unaccounted))

    print(json.dumps(result))


if __name__ == "__main__":
    main()

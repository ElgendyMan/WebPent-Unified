# UM-DR-38 — Repository Structure Report

Generated: 2026-11-17T12:41:00.640709+00:00.

## The decision (§5.1)

The project stays under `WebPent_UNIFIED/` as the canonical project root — no bulk move of thousands of files. The repository root instead gains a real entrypoint.

## Repository root now contains

```
.github
AS_BUILT_ARCHITECTURE.md
DISCOVERY_LOSS_MAP.md
README.md
ROOT_CAUSE_REGISTER.md
WebPent_UNIFIED
WebPent_Unified_umdr38.bundle
deliverables
```

* `README.md` — what WebPent is, that the project lives under `WebPent_UNIFIED/`, clean-checkout clone + install (Python 3.12, `uv sync --locked --extra dev`), quick-start commands, the MANDATORY authorization requirements, documentation entrypoints, security policy, current release version 0.40.1, and the CI summary.
* `.github/workflows/` (canonical, root-level): ci.yml, nightly.yml, weekly-benchmarks.yml.

## Workflow migration (§5.2/§5.3)

GitHub discovers workflows ONLY at the repository root; the historical nested copies never ran on push. The migration is mechanical (scripts/umdr38_migrate_workflows.py semantics):

* every gate step carried over UNCHANGED — the gate-to-finding map in the ci.yml header is preserved verbatim;
* each job executes from the actual project root via `defaults.run.working-directory: WebPent_UNIFIED`;
* artifact upload paths re-rooted to the workspace layout;
* `ci.yml` gained `workflow_dispatch` and the §6.2 evidence steps (ignored `.webpent-evidence/` directory, uploaded as a workflow artifact);
* the coverage-ratchet step now runs `uv run make coverage-ratchet` — the plain `make` invocation could never pass on a stock runner (the Makefile target calls `python3` directly, resolving outside the project venv);
* nested copies RETIRED: `WebPent_UNIFIED/.github/workflows/` exists = **False** (removed; exactly one canonical copy of each workflow remains);
* the deployment-contract and M12 workflow tests now resolve the canonical root workflow (nested fallback preserved for standalone project checkouts).

## Remote CI discovery (§5.4) — honest status

BLOCKED_EXTERNAL_DEPENDENCY: the build environment has no GitHub push credentials, so no run of the root workflow can be triggered on the release commit from here. The workflow file exists at the only location GitHub discovers; the exact push + PR commands are provided in the CI verification report. No GitHub run is claimed.

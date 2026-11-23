# Governance index — WebPent-Unified

One page that maps every standing gate, register and authority to its
enforcement point. Nothing here is new: each line links an existing,
tested mechanism. Last verified: UM-DR-45 window (2026-11-23).

## The five authorities

| Authority | Enforced by | Fail posture |
| --- | --- | --- |
| Scope of engagement | `shared/engagement_scope.py` + `scope/registry.py` (durable store opt-in, UM-DR-41 §6.3) + `api/app.py` 503 fail-closed | fail-closed |
| Tool/transport boundary (G-02) | `shared/http.py` safe client + `shared/direct_io_inventory.py` approvals + `tests/test_g02_direct_io_inventory.py` | fail-closed |
| Finding confirmation (G-08 causal) | CausalGuard + ProofBundle + replay; `state/reducers.py` `_finding_strength` (Tool-Confirmed requires provenance) | fail-closed |
| Hypothesis lifecycle | `production/hypothesis_identity.py` (§5.3 merge policy) + `state/reducers.py::merge_hypotheses` | append-only, never silent-merge |
| Rate/egress ceiling | `shared/http.py` transport gate + `GlobalRateGovernor` (Redis cross-process, memory single-process — honestly reported) | fail-closed in engagement |

## The standing registers

| Register | Location | Refresh |
| --- | --- | --- |
| Frozen-module manifest | `frozen_modules.sha256` + `tests/test_frozen_module_gate.py` | declared thaw windows, re-pinned by `scripts/refreeze_manifest_*.py` |
| Direct-I/O approvals (G-08/G-02) | `shared/direct_io_inventory.py` + `docs/direct_io_inventory.json` | deliberate regen scripts; per-record expiry (all current records expire 2027-02-17) |
| CVE allowlist (single source for SBOM + deps gate) | `scripts/quality/cve_allowlist.json` | on every new advisory; version-pinned rationale |
| Agent decision register (D5) | `deliverables/umdr45/agent_decision_register.json` | per window inventory |
| Dependency single source of truth | `pyproject.toml` (set) + `uv.lock` (graph) | `uv lock --check` in CI; derived requirements files are views |
| Test accounting | `accounting_v3` (`scripts/pytest_accounting_plugin.py`) | every CI run; old reports superseded, never edited |

## Release discipline

1. Delivery branch CI green 3 consecutive runs on ONE SHA (R1 gate).
2. Fast-forward `main` only (no merge commits, no force).
3. Tag releases; BUILD_INFO provenance must resolve at the tag.
4. Parallel branches are archived as `archive/<branch>-<sha>` tags — never deleted without the owner signature.
5. No bulk approval renewal; every G-08/G-02 record reviewed individually.

## Honest vocabulary (KB §9)

PASS / FAIL / SKIPPED / BLOCKED / NOT_RUN / NOT_VERIFIED / PARTIAL — used
verbatim in every report, including this window's closeout.

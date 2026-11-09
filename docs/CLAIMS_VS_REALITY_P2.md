# Claims vs Reality — prototype pollution & cache poisoning (P2-301/P2-302)

**Decision date:** 2026-11-01 · **Decision owner:** Phase-2 remediation (P2-301/302)

## What the Phase-1 audit found (F-12a/F-12b)

"Prototype pollution detection" and "cache-poisoning detection" existed in the
delivery only as **surface-signal strings** (`shared/surface_security.py:517`
prototype-mutation JS review; `models/surface_security.py`
`PROTOTYPE_POLLUTION = "prototype_pollution"`) — no detector module, no
payload logic, no probe construction anywhere in `agents/`.

## What was implemented in P2 (library stage — real and tested)

| Capability | Location | Tests |
|---|---|---|
| Deep-key payload set (`__proto__`, `constructor[prototype]`, double-nesting), canary-namespaced for unambiguous attribution | `src/webpent/agents/prototype_pollution/agent.py` | `tests/test_prototype_pollution_agent.py` (7) |
| Probe construction with per-probe negative controls (research-loop candidate shape) | same | same |
| Canary reflection analysis — fail-closed (requires canary in candidate, absent from baseline control, responses differing); sink hints reported advisory-only; promotion guard `blocked_missing_negative_control_and_proof_bundle` | same | same |
| Cache-key confusion probe families (`X-Forwarded-Host/Proto/Port`, `X-Original-URL`, `X-Rewrite-URL`, 4 param-encoding variants), each with a clean control request | `src/webpent/agents/cache_poisoning/agent.py` | `tests/test_cache_poisoning_agent.py` (4) |
| Two-request differential confirmation — fail-closed (attack-reflected ∧ victim-served ∧ control-clean ∧ shape-equivalent; anything else is `inconclusive`, never confirmed) | same | same |

Acceptance evidence: `uv run pytest -q tests/test_prototype_pollution_agent.py
tests/test_cache_poisoning_agent.py` → **10 passed**; `grep -rl "__proto__"
src/webpent/agents/` → ≥ 1; full suite green.

## What is deliberately DEFERRED, and why (the frozen-law constraint)

Wiring these detectors into production execution — `Finding` emission, the
triage/agent registry, the hunter graph — requires editing files that are
**byte-frozen** by `frozen_modules.sha256` (719/719, enforced by
`tests/test_frozen_module_gate.py`): `workers/pentest_worker.py`,
`agents/validator/registry.py`, `agents/validator/agent.py`,
`agents/hunter_graph.py`, `shared/research_contracts.py`,
`shared/surface_security.py`, and `models/findings.py` (VulnClass members).
The frozen law "predates and supersedes ruff/remediation entirely" (pyproject
FROZEN-LINT-EXCLUDE note). Every sibling integration (e.g.
`request_smuggling`) lives inside those same frozen files.

**Therefore the detectors ship as library-stage modules** (pure data +
analysis, zero network; execution belongs to the governed transport) and the
wiring is a documented re-freeze-window deliverable, exactly like the
unfreeze-and-merge note in `docs/CLI_DECISION_MATRIX.md`.

> **UPDATE — R4 re-freeze window executed (2026-11-02, DR-020):** the window
> authorized by the operator executed the § Revisit trigger verbatim —
> `VulnClass.PROTOTYPE_POLLUTION` / `VulnClass.CACHE_POISONING` added,
> both agents registered next to `request_smuggling`, deterministic
> validators (`postp0_checks.validate_prototype_pollution` /
> `validate_cache_poisoning`), and two scope-gated graph nodes in the
> deep-probing chain. The product's honest claim is now:
> **"prototype-pollution / cache-poisoning wired — detector nodes live in the
> hunter chain, deterministic fail-closed validators registered, findings
> emit with the promotion guard and require validator re-confirmation"**.
> Re-freeze record: `scripts/refreeze_r4_20261102.py` (8 files, in place,
> 719 entries); transport-inventory regen:
> `scripts/regen_direct_io_inventory_r4_20261102.py` (661 → 672 records,
> 0 removals); new tests: `tests/test_r4_production_hardening.py`.
> The historical section below is preserved as the pre-window record.

## Revisit trigger — EXECUTED in the R4 window (2026-11-02)

The authorized re-freeze window executed this trigger verbatim (per the
`DRIFT_REGISTER.md` process, TC-4 in-place refreeze precedent): added
`VulnClass.PROTOTYPE_POLLUTION` / `VulnClass.CACHE_POISONING`, registered both
agents next to `request_smuggling`, and flipped this doc's claim line (§ above).

## Re-freeze queue additions — final critique round (2026-11-01) — CLOSED R4 (2026-11-02)

Two production-readiness gaps were surfaced by the third-round critique
(`PRODUCTION_READY_CRITIQUE_PLAN.md`) whose fixes require frozen bytes, so they joined the
same re-freeze-window queue as the detector wiring above. **Both were executed in the
operator-authorized R4 window (2026-11-02, DR-020)** alongside the detector wiring and the
strict production key guard (`shared/preflight.py`: any non-loopback bind with auth disabled
or an insecure default secret now refuses boot — the escalation the third-round critique
queued as §3.4):

1. **`--version` / `--build-info` CLI flag** — DONE in R4: eager Typer options on the app
   callback (package version + `webpent.__version__` / `BUILD_INFO.json` provenance table).
2. **Security-headers middleware** — DONE in R4: `security_headers_middleware` on the API
   (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy:
   no-referrer`, conservative `Content-Security-Policy`; `Strict-Transport-Security` only
   when the request actually arrived over TLS).

Both were one-window-sized edits; neither changed runtime behavior for the local-only
governed path.

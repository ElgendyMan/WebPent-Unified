# Plan: v77 — Smart Remediation Editor + Security Patterns Guide
(الاقتراح المركزي الثاني)

Date: 2026-10-14. Input: the pasted suggestion-2 plan (4 phases / 12
deliverables). Directive: execute in full, under the standing governance
invariants.

## Governance mapping (read before any task)

The pasted plan describes developer-facing advisory tooling. Mapped onto
WebPent's invariants it becomes:

1. ADVISORY-ONLY. Every module is a pure function over findings that already
   exist. Nothing executes, nothing re-tests live, nothing promotes, nothing
   mints a request or a target. The verification steps are text for a human;
   the framework never runs them itself.
2. No invention. Guidance is keyed by `VulnClass` (the enum), never by title
   string matching. A finding whose class has no pattern entry produces an
   honest "no guidance" result, never fabricated CWE or fix text.
3. Findings without a usable `vuln_class` (e.g. the minimal proof-bundle-
   linked findings the orchestrator stores) are counted as
   `skipped_unclassified`, never guessed into a class.
4. Redaction-safe. Locators keep origin, path, method, and parameter NAMES
   only; query values, payloads, credentials, and raw bodies never enter the
   output. Exploit narratives are class-level, not target-specific.
5. Machine-derived. Report counts come from the findings list; nothing is
   asserted that was not computed.
6. Structure: the plan's 12 deliverables land as 12 modules in one cohesive
   package `src/webpent/remediation/` (the codebase convention is one
   package per concern; `reports/` already exists as `reporter/`). Names are
   preserved: `patterns_db`, `root_cause_mapper`, `context_guide`,
   `locator`, `exploit_scenario`, `impact_explainer`, `fix_templates`,
   `action_plan`, `verification_steps`, `developer_report`,
   `executive_summary`, `priority_dashboard`.

## Task 1 — Pattern database (`remediation/patterns_db.py`)

`SecurityPattern` dataclass: `vuln_class: VulnClass`, `cwe_id: str | None`,
`cwe_name`, `simplified_name` (plain language), `description`,
`default_severity: Severity`, `bad_example`, `good_example`, `references`,
`root_causes: tuple[RootCause, ...]`. `PATTERNS` covers every `VulnClass`
member except `UNKNOWN`, whose entry is `cwe_id=None` (honest absence).
API: `get_pattern(vuln_class) -> SecurityPattern | None`,
`pattern_for_finding(finding) -> SecurityPattern | None`,
`coverage() -> dict` (mapped / unmapped class counts).
Tests: every non-unknown member resolves; unknown resolves to None;
bad/good examples non-empty and distinct; no class silently missing.

## Task 2 — Root-cause mapper (`remediation/root_cause_mapper.py`)

`RootCause` enum: `missing_validation`, `input_trust`, `execution_order`,
`state_management`. `classify(vuln_class) -> RootCause | None` for every
class; `explain(cause) -> str`; `classes_for_cause(cause) -> list[VulnClass]`.
Tests: total over the enum, None only for unknown, explain text non-empty.

## Task 3 — Context guide (`remediation/context_guide.py`)

Per class: `acceptable` / `warning` / `dangerous` context tiers (when the
same weakness is tolerable vs exploitable), plus `note`. Static curated
text; unknown returns a tier structure with honest empty lists.
Tests: every mapped class has non-empty dangerous tier; unknown handled.

## Task 4 — Locator (`remediation/locator.py`)

`locate(finding) -> dict`: origin, path, method, param name(s) parsed from
the finding's own url/fields; query VALUES dropped (redaction); nothing
invented for missing fields (`None`, not a guess).
Tests: values stripped, names kept, missing fields stay None.

## Task 5 — Exploit scenario (`remediation/exploit_scenario.py`)

`scenario_steps(vuln_class) -> list[dict]` — class-level generic narrative
(what an attacker chain looks like), derived from the pattern DB, no target
data. Tests: non-empty for mapped classes, empty + reason for unknown.

## Task 6 — Impact explainer (`remediation/impact_explainer.py`)

`business_impact(vuln_class) -> dict` with impact narrative and
`interim_mitigations` (WAF/rule/disable/rotate style containment a human can
apply today). Tests: mapped classes carry >=1 mitigation; unknown honest.

## Task 7 — Fix templates (`remediation/fix_templates.py`)

`FixTemplate`: `concept`, `bad_code`, `good_code`,
`framework_variants: dict[str, tuple[str, str]]` (flask / django / express /
spring where meaningful). Tests: every mapped class resolves; bad != good;
variants keyed and paired.

## Task 8 — Action plan (`remediation/action_plan.py`)

`build_action_plan(findings) -> dict`: three tiers — `urgent`
(critical/high confirmed), `proactive` (the rest), `preventive`
(root-cause hardening deduped by class) — each item with `effort` (S/M/L),
`priority`, `finding_ids`, `vuln_class`. Plus
`skipped_unclassified` count. Machine-derived only.
Tests: tier assignment, dedup of preventive items, unclassified skipping.

## Task 9 — Verification steps (`remediation/verification_steps.py`)

`checklist(vuln_class) -> list[dict]`: post-fix human checklist (retest with
the class canary, confirm the negative control stays clean, add a regression
test). Tests: mapped classes non-empty; unknown returns [].

## Task 10 — Developer report (`remediation/developer_report.py`)

`build_developer_report(findings) -> dict`: per finding a Jira-ready card
composed from Tasks 1-9 (locator, root cause, scenario, impact, fix,
verification, priority) + machine-derived counts and
`skipped_unclassified`. Explicit non-claim in the module docstring: advisory
text attached to existing findings; nothing re-runs.
Tests: card fields complete for a classified finding; unknown/unclassified
surfaced honestly.

## Task 11 — Executive summary (`remediation/executive_summary.py`)

`build_executive_summary(findings) -> dict`: counts by severity and class,
top urgent actions (first 3 of the urgent tier), exposure statement derived
from counts. Tests: counts match input; exposure wording tracks counts.

## Task 12 — Priority dashboard (`remediation/priority_dashboard.py`)

`build_priority_dashboard(findings) -> list[dict]`:
`priority = severity_weight x exploitability x spread / fix_effort`, with
named constants for every weight, clamped, sorted descending. Tests:
weights applied as documented, ordering correct, unclassified skipped.

## Task 13 — Report wiring (`autonomous/hunt_state.py`)

`to_report_json` gains a `remediation` section (executive summary +
dashboard) computed from `state.findings` only when at least one finding is
classified; empty otherwise. No new execution authority.
Tests: report section present/absent per findings content.

## Task 14 — Verification and release gates

1. Full regression: 0 failures, exact count reported.
2. Ruff clean on all new/touched files.
3. Traceability row + plan verification record appended.
4. Direct-IO inventory: deliberately regenerate only if the scan shows drift.
5. Deliverable: `webpent_v77_autonomous_bug_hunter.zip`.

## Task 14 — Verification and release gates (DONE)

Executed 2026-10-14:

1. Full regression: 2281 passed, 0 failures (119.48s,
   `PLAYWRIGHT_BROWSERS_PATH=/home/thaura/pw-browsers`).
   Baseline 2245 + 36 new remediation tests = 2281, exact.
2. Ruff clean on all 13 touched files after fixes: import sorting in
   `remediation/__init__.py` and `tests/test_remediation_editor.py`,
   unused `pytest` import removed, set comprehension in
   `patterns_db.coverage()` rewritten as `set(VulnClass)`.
3. Traceability row appended; this record appended.
4. Direct-IO inventory: no drift — `test_g02_direct_io_inventory.py`
   4/4 pass against the recorded artifact, no regeneration needed (the
   remediation package performs no transport IO).
5. Deliverable: `webpent_v77_autonomous_bug_hunter.zip` built and
   presented.

Implementation notes kept for the record:

- Bug found and fixed during testing: `action_plan._item()` raised
  KeyError on `VulnClass.UNKNOWN` because `_EFFORT` covers only the 33
  real classes; `_vuln_class_of()` now returns None for UNKNOWN so it is
  counted in `skipped_unclassified` like garbage, never guessed into a
  tier.
- `root_cause_mapper` initially omitted `VulnClass.JAVASCRIPT` from
  `_CLASS_CAUSE`; added (`input_trust`) so the cause partition covers
  every mapped class.
- `hunt_state.to_report_json()` emits `remediation` only when at least
  one finding is classified; all-zero findings return no section at all.

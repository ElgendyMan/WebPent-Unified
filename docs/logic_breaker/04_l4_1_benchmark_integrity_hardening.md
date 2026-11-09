# L4.1 — Logic Breaker benchmark-integrity hardening

Mission: four integrity fixes to the EGAIE Logic Breaker (http-v3) benchmark,
each with red-first regression tests, followed by full re-validation
(advisory-only; the only target is the isolated loopback benchmark target).
All work is on the production repo at HEAD `6c49403` (deliverables doc commit
recorded below). The pre-existing working-tree overlay
`download/econ/portfolio_transitions.jsonl` (repository-owner change, present
before L0) is preserved and was never staged.

## 1. Root causes and fixes

### Fix 1 — resume verification was tautological (`http_runner.py`)

Root cause: `_resume_correct` asserted only
`requests_made >= requests_before_resume`, which any resumed run satisfies by
construction; it could not detect a lost confirmation, a re-confirmation of an
already-executed experiment, or a duplicate mutation.

Fix: new `_resume_invariants(first, resumed, target, tokens_before_resume,
identities_before_resume)` asserts real state: (a) no confirmed finding lost;
(b) per-experiment proof-record counts never increase after resume (no
re-confirmation); (c) every pre-resume `(family, resource, token)` mutation
identity still applied and applied exactly once; (d) a NEW identity reusing a
pre-resume idempotency token is flagged as a re-applied mutation, while a new
identity with a fresh token is a legitimate investigation request. Request
counts are never used as a substitute. Supporting read-only introspection
`ControlledInvestigationTarget.applied_mutation_identities()` added to
`http_target.py` (no change to the mutation loop).

### Fix 2 — proofs were bound to cases by list length (`http_runner.py`)

Root cause: the report compared the number of replay-valid proof records with
`confirmed_count`. Any unrelated replay-valid bundle masked a confirmed case
that had no proof at all.

Fix: `_proof_association_metrics(state)` builds the confirmed-case set from
trusted case/task identity and binds each verified proof record one-to-one via
two trusted identities (the record's `experiment_id` and the case prefix of its
proof signature). First record per experiment wins; duplicates, mismatched
identities and unbound replay-valid records are counted separately as
`confirmed_without_proof`, `duplicate_proof_records`,
`mismatched_identity_records`, `unrelated_replay_valid`. Seal and replay
verification are untouched. The same association object feeds both
`_thresholds_pass` (any anomaly fails) and `HTTPReport.thresholds`.

### Fix 3 — implicit V1/V2 fallback in the Logic Breaker port (`logic_port.py`)

Root cause: `LogicExperimentPort._case_from_id` fell back to the V1/V2
registries, so a V1 or V2 case id silently executed real probes through the
http-v3 Logic Breaker path — cross-version contamination of a versioned
benchmark.

Fix: the port now resolves exclusively through `HTTP_CASE_V3_INDEX`; an
unknown or other-version id raises `ValueError("unknown http-v3 case id: …")`
BEFORE any HTTP request. The read-only `HTTPExperimentPort` keeps its broader
legacy resolution for unrelated callers. Verified: V1/V2 ids through the V3
port make zero HTTP requests and zero production actions.

### Fix 4 — zero-confirmation runs reported positive success ratios (`http_runner.py`)

Root cause: `requests_per_confirmed` was computed unconditionally as
`port.requests_made`, so a run that executed 17 requests and confirmed nothing
reported 17.0 — a positive per-confirmation success metric for a failed run.

Fix: with zero confirmations, `requests_per_confirmed` and `recall` are
reported as `None` (undefined, never a positive ratio). `_thresholds_pass` now
requires `confirmed_count >= 1` and a defined positive
`requests_per_confirmed`, while a baseline with zero confirmations remains a
legitimate comparison outcome (`confirmed_count > baseline`). No division by
zero anywhere.

## 2. Regression tests (red-first)

`tests/egaie/test_logic_benchmark_integrity.py` — 22 tests:
resume pass/lost-confirmation/re-confirmation/duplicate-mutation/legitimate-new
(5), proof association one-to-one/swapped/duplicate/unrelated/missing/masking
(6), V3-only fail-closed incl. V1/V2/unknown ids with zero requests (6, two
parametrized), thresholds zero-confirmation/zero-requests/positive-requests/
normal/baseline-zero/undefined-metrics end-to-end (5).

Red proof against pre-mission code (temp worktree at `ad0367a`):

- `PYTHONPATH=src python3 -m pytest tests/egaie/test_logic_benchmark_integrity.py`
  → collection ImportError: the integrity helpers
  (`_proof_association_metrics` et al.) do not exist in the old code.
- `python3 /tmp/demo_old_defects.py` against the old worktree:
  `OLD zero-confirm requests_per_confirmed = 17.0` and
  `OLD replay_valid_confirmed = 1 == confirmed_count = 1` with an unrelated
  bundle masking a proofless confirmed case.
- `python3 /tmp/demo_fix3.py` against the old worktree:
  `V1 id ACCEPTED, requests_made = 3`, `V2 id ACCEPTED, requests_made = 6`.

After the fix (same scripts, HEAD `6c49403`):
`zero-confirm requests_per_confirmed = None`;
`V1 id REJECTED … requests_made = 0`,
`V2 id REJECTED … requests_made = 0`.

## 3. Benchmark before/after (http-v3, real loopback target)

Detection results are unchanged by the hardening (these fixes verify state,
they do not change probing). Full command:
`run_http_comparison(target, cases=HTTP_GROUND_TRUTH_V3)`.

| Metric | Before (L4 audit run) | After (this mission) |
|---|---|---|
| adaptive TP / FP / FN | 2 / 0 / 0 | 2 / 0 / 0 |
| adaptive precision / recall / F1 | 1.0 / 1.0 / 1.0 | 1.0 / 1.0 / 1.0 |
| baseline TP / FP | 1 / 0 | 1 / 0 |
| baseline precision / recall / F1 | 1.0 / 0.5 / 0.667 | 1.0 / 0.5 / 0.667 |
| adaptive / baseline requests | 18 / 12 | 18 / 12 |
| requests_per_confirmed | 9.0 | 9.0 (None on zero-confirm runs) |
| proof-to-case associations | length-equality only | one-to-one: 2 bound, 0 missing, 0 duplicate, 0 mismatched, 0 unrelated |
| duplicate mutations | unmeasurable | 0 (resume invariants assert it) |
| thresholds_pass / reproducible / resume_correct | true / true / true (tautological) | true / true / true (real invariants) |
| V1/V2 ids through V3 port | executed, 3/6 requests | rejected pre-HTTP, 0 requests |

`HTTPReport.thresholds` now records `"min_confirmations": 1` and the
one-to-one replay-valid association rule, so the acceptance criteria are
declared in the report itself.

## 4. Changed files and commits

| Commit | Content |
|---|---|
| `6c49403` | the four fixes + 22 regression tests + canonically regenerated direct-I/O inventory |
| `d094530` | this deliverables record |

sha256 at HEAD `6c49403`:

```
b8ed1113e38a499958e5fea0e3ec6828e877005886f18c2534b035b7bcc2b292  src/webpent/egaie/http_target.py
2082bdee9def0fbdd79fa450c3e91d884c8620521bb98776cd05ee911500b491  src/webpent/egaie/benchmark/http_runner.py
7717340bd611592535d428cb1da38a666e016a6f05424b8d636a298991a7b63a  src/webpent/egaie/logic_port.py
2a02825f64aa6e719ceea8e1ca76342efc6d77b100ff50f77e6937cc09a35539  tests/egaie/test_logic_benchmark_integrity.py
617d580e3a684765dc8434dd84c93ef673a14e2c0d92038d93fad90d5e51da7f  docs/direct_io_inventory.json
3cbf4602bd59b1095bf175757af42597a347fb3f5810c7bca65897002eeae501  docs/DIRECT_IO_INVENTORY.md
```

## 5. Validation gates

- Full suite: `PYTHONPATH=src python3 -m pytest -q` → **4422 passed** (EGAIE
  suite alone: 85 passed, was 63 + 22 new). The only mid-mission failure was
  the G-02 direct-I/O drift gate, caused by the two shifted line numbers of
  approved boundary sites in `http_target.py`; resolved by the canonical
  regeneration script (`scripts/regenerate_direct_io_inventory.py`), reviewable
  diff: 2 line numbers + timestamp only, 659 records unchanged, unapproved-site
  pin (24 records / 21 identities) untouched, `test_g02_direct_io_inventory.py`
  4/4 passed after.
- Construction authority: OK (26-file allowlist). Frozen manifest: OK (13
  files). Vault import authority: OK (8 caller sites).
- Ruff on changed files (`E,F,I,RUF,B`): only the 3 pre-existing RUF100 notes
  in untouched lines of `http_target.py` / `logic_port.py` (present at the
  review baseline; left as-is).
- Scope/authorization/idempotency paths untouched; no gate weakened or
  relabelled; no new dependency.

## 6. Remaining limitations

- The Logic Breaker still covers only http-v3 PRICE_INTEGRITY (2 positive, 2
  negative cases); cross-family coverage is future work.
- `_proof_association_metrics` binds via `experiment_id` and the signature
  case prefix; a forged bundle carrying BOTH trusted identities of another
  case is indistinguishable from the real one at the metric layer (seal +
  oracle replay remain the cryptographic check).
- Resume invariants run inside the benchmark harness; a production resume path
  outside the harness should adopt the same `_resume_invariants` check.
- The three pre-existing RUF100 lint notes and the pre-existing `make lint`
  failures in `scripts/verify_test_count.py`, `config/settings.py`,
  `shared/preflight.py` are outside this mission's scope.

## 7. Delivery artifact

Release workflow requires the ZIP + SHA-256 (as in L0–L4): tracked tree at
HEAD `6c49403` plus the preserved working-tree overlay
`download/econ/portfolio_transitions.jsonl`.

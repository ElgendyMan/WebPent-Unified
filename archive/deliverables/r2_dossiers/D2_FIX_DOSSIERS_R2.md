# D2 — PER-FIX DOSSIERS (Sprint R2, Dispatch #002)

Every dossier below is an **UNAPPLIED patch dossier per constraint C2**: the fix target is a
frozen file (`frozen_modules.sha256`, 695/695 on the v5 baseline). Proposed diffs are written
against the v5 tree exactly as read (line numbers verified in D1). **Nothing in this directory
has been applied to `src/`.** Each dossier contains the unfreeze request the Orchestrator needs:
files, hunks, test impact, and the rollback story.

Joint unfreeze-request properties (apply to all dossiers):
- Direction: every diff REMOVES an authority pathway or tightens a check — C4 fail-closed-only.
- No Trust Spine component internals (C3 list) are modified by any proposed diff; the C3-adjacent
  files touched are caller/wiring surfaces only.
- After each lands, the matching strict-xfail marker in `tests/test_r2_spine_authority_contracts.py`
  MUST be removed in the same change (each xfail test will xpass — strictly failing the suite —
  until its marker is removed; this is the designed tripwire).
- Rollback per change = `git revert` of the single unfreeze commit + re-run of the frozen gate
  and the matching contract test; no data migration anywhere (C8-compatible).

---

## D2/R2-01 — BYP-01 residual: truthful entrypoint provenance (P0 lineage)

**Status:** BYP-01 core is ABSENT on v5 (factory routing landed pre-v5; see D1 §2.1). This dossier
covers the residual: `state["entrypoint"]` has no setter; every graph run resolves as
`"direct_invoke"`, which cannot distinguish cli / worker / campaign_worker as R2-01(ii) requires.

**Files:** `src/webpent/production/modern_spine_integration.py` (FROZEN) + editable call-site
wiring afterwards (out of scope until the frozen read-side exists).

**Proposed diff (unapplied):**

```diff
--- a/src/webpent/production/modern_spine_integration.py
+++ b/src/webpent/production/modern_spine_integration.py
@@ -97,10 +97,19 @@
     tool_boundary = state.get("_tool_boundary")
     advisory_memory = state.get("_advisory_memory")
-    # No prior convention establishes which top-level channel (cli/api/worker)
-    # invoked this graph node (state carried no "entrypoint" key anywhere in
-    # this codebase before this fix); "direct_invoke" is the KNOWN_ENTRYPOINTS
-    # value for exactly this case, while still honoring an explicit value if
-    # a caller sets one in state.
-    entrypoint = str(state.get("entrypoint") or "direct_invoke")
+    # Entrypoint provenance (Sprint R2, R2-01(ii)): resolution order is
+    # explicit state value (set by an editable call site after unfreeze)
+    # > WEBPENT_ENTRYPOINT environment variable (set by editable
+    # orchestration surfaces: entrypoint.sh / docker-compose / Makefile) >
+    # "direct_invoke" (the KNOWN_ENTRYPOINTS value for the unknown-channel
+    # case). Strict-bool-style vocabulary: an env value that is not in
+    # KNOWN_ENTRYPOINTS fails closed rather than falling back silently.
+    entrypoint = str(state.get("entrypoint") or "").strip()
+    if not entrypoint:
+        entrypoint = os.environ.get("WEBPENT_ENTRYPOINT", "").strip()
+    if not entrypoint:
+        entrypoint = "direct_invoke"
     spine_config = ProductionSpineConfig(
```

*(the factory already rejects unknown vocabulary at `ProductionSpineConfig.__post_init__`, so an
operator typo in `WEBPENT_ENTRYPOINT` fails closed with `ProductionSpineError` — enforcement is
existing frozen factory behavior, not new code.)*

**Post-land wiring (editable surfaces, second commit of the same unfreeze):**
- `entrypoint.sh`: `export WEBPENT_ENTRYPOINT="${WEBPENT_ENTRYPOINT:-cli}"`
- `docker-compose.yml` worker service: `WEBPENT_ENTRYPOINT: worker`
- `Makefile` campaign targets: `WEBPENT_ENTRYPOINT=campaign_worker`

**Test impact:** remove `xfail` + `strict` note on none (this residual currently has the REAL pin
`test_t03b_entrypoint_has_no_production_setter` which must be updated in the same commit — its
failure message instructs exactly that); extend `test_t03` to parametrize over the new resolution
order. **Rollback:** revert commit; `test_t03b` reverts to pinning "no setter".

---

## D2/R2-02 — BYP-02: OOB pathway demoted to advisory-evidence-only (P0)

**Files:** `src/webpent/api/app.py` (FROZEN), `src/webpent/memory/db.py` (FROZEN).
**Ratified directive:** valid correlation token → append ADVISORY evidence record attached to the
finding; NEVER construct/seal a ProofBundle; NEVER flip confidence; PromotionPipeline stays the
sole promotion authority. Receiver authentication (v) unchanged.

**Proposed diff part 1 — `app.py` receiver (unapplied):**

```diff
--- a/src/webpent/api/app.py
+++ b/src/webpent/api/app.py
@@ -1852,7 +1852,7 @@
 def _oob_db_lookup_and_confirm(
     finding_id: UUID,
     reasoning_appendix: str,
     callback_context: dict[str, Any] | None = None,
 ) -> Finding | None:
-    """Thread-safe DB lookup + confirm — callable from asyncio.to_thread.
+    """Thread-safe DB lookup + ADVISORY evidence append — asyncio.to_thread.
@@
-    from webpent.models.proof_bundle import build_proof_bundle
-
     context = dict(callback_context or {})
-    causal_observation = {
-        "evidence_refs": [ ... ], "causal_signal": True, ...
-    }
-    proof_bundle = build_proof_bundle(...).seal(actor="api.oob_callback_receiver")
+    # Sprint R2 (BYP-02): this pathway is ADVISORY-EVIDENCE-ONLY. Token
+    # correlation is not causal proof; PromotionPipeline remains the sole
+    # promotion authority (SDD §1). No ProofBundle is constructed or sealed
+    # here, and confidence is never changed by this path.
+    advisory_record = {
+        "kind": "oob_callback_advisory",
+        "source": "api.oob_callback_receiver",
+        "observed_at": context.get("callback_ts"),
+        "transport": {"method": context.get("method"),
+                       "client_host": context.get("client_host"),
+                       "body_digest": context.get("body_digest")},
+        "correlation": "per_finding_token",
+    }
@@
-    return db.mark_oob_confirmed(
+    return db.append_oob_advisory_evidence(
         finding_id,
         reasoning_appendix=reasoning_appendix,
-        payload_marker=_OOB_CONFIRMED_MARKER,
-        causal_observation=causal_observation,
-        proof_bundle=proof_bundle,
+        advisory_record=advisory_record,
     )
```

**Proposed diff part 2 — `db.py` new targeted-write method + demoted caller shim:**

```diff
--- a/src/webpent/memory/db.py
+++ b/src/webpent/memory/db.py
@@ (after mark_oob_confirmed)
+    def append_oob_advisory_evidence(
+        self,
+        finding_id: UUID | str,
+        *,
+        reasoning_appendix: str,
+        advisory_record: Mapping[str, Any],
+    ) -> Finding | None:
+        """Sprint R2 (BYP-02): append OOB callback evidence as ADVISORY-only.
+        Never touches confidence_level/confidence; never writes a
+        confirmation marker. Same BEGIN IMMEDIATE serialisation as
+        mark_oob_confirmed."""
+        ...  # targeted UPDATE of reasoning (+ advisory JSON), no confidence columns
```

and the handler-side flip check in `app.py` (`:2189-2205`) becomes an advisory-acknowledgement
check ("evidence recorded — pending validation" semantics; 204 response retained so target-side
behavior is unchanged), with `_OOB_CONFIRMED_MARKER` deleted.

**Semantics preserved:** invalid token → 403 before ANY write (unchanged, `:2111-2114`); master
switch `oob_confirm_route_enabled` stays first gate (unchanged, `:2232/:2286`); per-finding token
constant-time validation unchanged.
**Test impact:** remove xfail markers on `test_t04_oob_callback_is_advisory_only` and
`test_t05_sole_confirmation_authority_inventory` (they then pass; strict tripwire enforces same-
commit removal); existing OOB parity/DB tests that assert the flip are updated per C6 with
justifications logged in D3 (they assert the now-corrected violating behavior — exactly the C6
clause). **Rollback:** revert; confidence flips resume being impossible to miss via T-04/T-05.

---

## D2/R2-03 — BYP-05: graph path rejects UNSUPPORTED_LEGACY_ONLY (P2)

**Files:** `src/webpent/graph/builder.py` (FROZEN).
**Violation (v5):** the node-level raise (`modern_spine_integration.py:61-79`) is dead code on the
production path — `_combined_recon_node` guards the call with `if MODERN_SPINE_ENABLED:` and the
disabled case runs legacy alone (D1 §2.3).

**Proposed diff (unapplied):**

```diff
--- a/src/webpent/graph/builder.py
+++ b/src/webpent/graph/builder.py
@@ -1338,6 +1338,17 @@
     def _combined_recon_node(state):
         if engagement_id and not state.get("engagement_id"):
             state["engagement_id"] = engagement_id
         if MODERN_SPINE_ENABLED:
             modern_state = modern_spine_recon_node(dict(state))
             ...
             state["legacy_recon_advisory_only"] = True
+        else:
+            # Sprint R2 (BYP-05): the invariant is "never re-route, only
+            # reject." Skipping the modern node and running legacy alone is
+            # the silent re-route; reject the engagement loudly instead. The
+            # node-level raise (modern_spine_integration.py) remains as the
+            # direct-invocation guard; this is the graph-path enforcement.
+            from webpent.shared.exceptions import UnsupportedLegacyOnlyModeError
+            raise UnsupportedLegacyOnlyModeError(
+                "WEBPENT_MODERN_SPINE_MODE=UNSUPPORTED_LEGACY_ONLY refuses to "
+                "run (graph recon path). Unset WEBPENT_MODERN_SPINE_MODE, or "
+                "use COMPATIBILITY_LEGACY for the fail-closed-for-authority "
+                "legacy-advisory mode. Flag-based rollback per SDD §8 remains "
+                "the only supported rollback."
+            )
         # Legacy recon runs SECOND — compatibility/advisory only.
```

Notes: uses the existing engagement-level failure pattern (an exception already defined and in
use one level down — no new error channel, per R2-03 requirements). `WEBPENT_MODERN_SPINE=0`
alone still downgrades to `COMPATIBILITY_LEGACY` (modern node runs, legacy advisory) — unchanged,
matching the node's own documented semantics. SDD §8 rollback definition (exploration/source
flags at the spine) remains valid and is what the error message points to (C8).
**Test impact:** remove xfail on `test_t06_builder_rejects_unsupported_legacy_only`; add a
behavioral graph-path test (env-patched `build_graph` invocation asserting the raise). Existing
tests that assert legacy-alone under the disable env: swept — `tests/team1_acceptance/
test_sprint_i1b_part2_byp05.py` only pins node-level behavior (no change needed); if any test
asserts the graph-path legacy-alone behavior it is updated per C6 with justification in D3.
**Rollback:** revert commit; T-06 reverts to documenting the gap.

---

## D2/R2-04 — B-06 residual: `entrypoint="campaign_worker"` (P3)

**Files:** `src/webpent/production/production_spine.py` (FROZEN — one-word vocabulary change),
`src/webpent/production/campaign_worker.py` (FROZEN — one-word literal change).

**Proposed diff (unapplied):**

```diff
--- a/src/webpent/production/production_spine.py
+++ b/src/webpent/production/production_spine.py
@@ -31,7 +31,7 @@
 # Entrypoints that MUST resolve through this factory.
-KNOWN_ENTRYPOINTS: Final[frozenset[str]] = frozenset({"cli", "api", "worker", "direct_invoke"})
+KNOWN_ENTRYPOINTS: Final[frozenset[str]] = frozenset({"cli", "api", "worker", "campaign_worker", "direct_invoke"})
--- a/src/webpent/production/campaign_worker.py
+++ b/src/webpent/production/campaign_worker.py
@@ -64,7 +64,7 @@
     spine_config = ProductionSpineConfig(
         engagement_id=state.engagement_id,
         target_url=state.target_url,
-        entrypoint="worker",
+        entrypoint="campaign_worker",
     )
```

Rationale: R2-01(ii) requires the entrypoint to distinguish campaign_worker from worker; today the
subprocess masquerades as the Celery worker in `ProductionTrace.entrypoint` and the config-digest
drift registry cannot detect a worker-vs-campaign_worker divergence for the same engagement.
Config digests change for campaign-worker runs (entrypoint is digest-input) — acceptable: the
drift registry's per-engagement digest comparison is entrypoint-sensitive by design, and
campaign subprocesses run one engagement per process (verified: `campaign_worker.main` loads a
single state file).
**Test impact:** remove xfail on `test_t07b_campaign_worker_entrypoint_is_campaign_worker`;
`tests/team1_acceptance/test_durable_research_state.py` updated in the same commit only if it
asserts the literal "worker" (checked: it asserts durable-state behavior, not the literal — no
change needed, recorded here as the R2-04 test disposition). **Rollback:** revert; T-07b reverts
to documenting the residual.

---

## D2/R2-05 — BYP-03 lane provenance (P1, CONDITIONAL — condition resolved: NOT LANDABLE)

Per the ratified record: labeling only "if at least one finding-persistence call site is
editable". v5 verdict (D1 §2.5): **all persistence sites are frozen** — `cli/commands.py:944`,
`workers/pentest_worker.py:224-259` (`db.save_finding` at :250). The additive provenance marker
would have to be written by exactly these sites. → **Boundary note in D5 §4.3 + this escalation
dossier. Not forced.**

Escalation content: the minimal landable design post-unfreeze is a single additive
`lane_provenance: "spine_attested" | "parallel_lane"` column written at the two `save_finding`
sites (no existing fields removed; report renders it as-is), plus a source-inventory test
sibling to T-05. No diff is proposed because its form depends on the R2-02 outcome at
`db.py` (shared write surface).

## D2/R2-06 — BYP-04 Phase-1 smart-profile block (P1, CONDITIONAL — condition resolved: NO EDITABLE SEAM)

v5 verdict (D1 §2.6): every file on the smart execution path is frozen (settings, initial_state,
smart agent, ActionAuthority, runtime, campaign_executor). → **Operator procedure (D5 §4.2) +
this escalation dossier. Not forced.**

Escalation content: the natural enforcement home post-unfreeze is the frozen factory's existing
SDD §8-conformant flag machinery (`ProductionSpineConfig.__post_init__` strict-bool + trace
`flag_resolution` stage): add `phase1_smart_profile_block: bool | None = None` resolved via
`_resolve_strict_bool_flag` (env `WEBPENT_PHASE1_SMART_PROFILE_BLOCK`, default True = block) and
raise `ProductionSpineError` when a non-legacy scan_mode engagement reaches a spine resolution.
Engagement+fingerprint binding comes free via the existing `flag_resolution` trace stage. The
operator procedure (D5 §4.2) is the interim control and is fail-safe: the default profile IS
legacy, so a Phase 1 engagement only reaches the smart lane by an explicit operator action that
the procedure forbids.

## D2/R2-07 — Hygiene (P3, CONDITIONAL — condition resolved: NOTHING TO DO)

ruff F811/F401 clean on both cited files (D1 §2.7). No diff proposed; recorded in D7.

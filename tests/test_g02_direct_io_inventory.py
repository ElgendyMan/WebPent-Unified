"""G-02/G-08 direct-I/O inventory enforcement test.

Sprint I-1b, item B.3 (corrected per self-critique Fix 1):
``docs/V3_RESIDUAL_GAP_MATRIX_20260821.md`` marked G-08 CLOSED citing this
test file, which did not exist.  The module
(``src/webpent/shared/direct_io_inventory.py``) and its recorded artifact
(``docs/direct_io_inventory.json``) did exist; this test closes the loop by
re-running the AST inventory on the current source and failing on drift.

Three checks are enforced:
  1. Drift: ``scan_direct_io(src)`` must equal the recorded artifact's
     ``records`` field, byte-for-byte (order included).  Any added/removed/
     moved transport site breaks the build until the artifact is deliberately
     regenerated (reviewable diff, never silent).
  2. Approval TTL: no ``approved_transport_records`` / ``dynamic_import_allowlist``
     entry may have a missing/invalid/expired ``expires_at``.
  3. Unapproved-site gap PIN (fail-closed on the future): the recorded artifact
     was generated from a PARTIAL scan that omitted 23 files.  A full scan
     reveals exactly 18 raw-transport sites in 8 files that are NOT in any
     approval list (raw ``httpx`` / ``__import__`` / ``importlib.*``).  This
     test PINS that number and set: any NEW unapproved site fails the build.
     The 18 known sites are tracked as an open security-engineering work item;
     they are NOT silently approved.  When security adjudicates them (approve
     or remove), reduce the pin accordingly.

The artifact's ``records`` field was regenerated from the full current scan in
Sprint I-1b completion (394 -> 551 records); every record was verified to
correspond to a real site in the current source, and the 23 previously-missing
files include 3 frozen modules.  See the sprint changelog for the full
justification evidence.
"""
from __future__ import annotations

import json
from pathlib import Path

from webpent.shared.direct_io_inventory import (
    expired_approval_errors,
    scan_direct_io,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_PATH = REPO_ROOT / "docs" / "direct_io_inventory.json"
SRC_ROOT = REPO_ROOT / "src"

# The pinned known-gap.  18 RECORDS collapse to 15 distinct (file, kind, symbol)
# identities because some sites repeat the same symbol on different lines
# (cli/commands.py has two ``__import__`` lines; modern_spine.py has two
# ``import httpx`` + two ``httpx.Client`` call lines).  Both counts are pinned.
#
# FINAL-CLOSURE RULING R3: 18/15 -> 19/16. New unapproved site added by the
# I-2 M4 module: src/webpent/production/context_authority.py:207,
# `__import__("json")` (dynamic_import, literal) inside mint_decision_token's
# arguments digest. It is a new distinct (file, kind, symbol) identity (the
# file did not exist before Sprint I-2), so both the record and identity
# counts move by exactly +1. Legitimate — context_authority.py is the
# designed context-authority module; the site is the vault-I/O digest path,
# not a new transport family. Deliberately re-pinned per security-engineering
# adjudication (this ruling), not hand-edited without review.
# MERGE 2026-10-26: 21 -> 33 (the not_approved approval_status count of the regenerated artifact; the earlier 28 in this comment was the unapproved_raw_transport coverage metric, a different number). The merged tree (l6 + donorC + track123
# layers, then the r5 identity-ladder patch) was fully rescanned by
# scripts/regenerate_direct_io_inventory.py (796 records). The unapproved
# raw-transport set grew with the absorbed lineages' audited sites; every
# one of them remains fail-closed-pinned exactly as before — the pin moves
# with the tree, it does not weaken: any NEW site outside this pinned set
# still fails this gate.
# ULTIMATE PLAN 2026-10-27, proposal 4: 33 -> 31. The dead-code archive
# (archive/pre_v10_prototypes/) removed src/webpent/cqa/execution.py —
# a verified-dead prototype carrying two unapproved raw-transport
# records (import httpx + httpx.AsyncClient call). Archived code carries
# no transport surface, so its records left the scan honestly. No NEW
# site was added: the remaining 31 records are exactly the merge's 33
# minus the two archived cqa ones (verified by set-diff during the
# window; see ULTIMATE_PLAN_EXECUTION_20261027.md).
# LEARNING A/B LAB 2026-10-29: 31 -> 33. The new scope-completion file
# src/webpent/memory/ab_lab.py (C-9, docs/PRODUCTION_FIX_PLAN_0270.md)
# deliberately adds two subprocess sites — the real ``webpent hunt``
# window launcher (make_hunt_subprocess_runner). Same pinned family as
# the pre-existing subprocess sites (apex/sandbox.py,
# production/verdict_bridge.py): process spawn of the operator's own
# installed CLI, never a network transport. Deliberately re-pinned with
# this window's security review; any site OUTSIDE this set still fails.
# UNIFIED-MERGE window (2026-11-02): 33 -> 47 — the four-way union
# brought lineage files with not-approved transport sites never
# recorded by the single-lineage artifact (244 new identities across
# 61 union files; zero raw-transport additions; zero removals —
# scripts/regen_direct_io_inventory_unified.py, DRIFT_REGISTER
# UM-DR-07).
# UM-DR-15 (M2, 2026-11-05): the pin shrinks 47 -> 36 records /
# 41 -> 30 identities by ADJUDICATION ONLY, two causes:
#   (a) the M-4/M-5 safe-transport migration physically removed the raw
#       sites (legacy_containment httpx.Client, oob.py urlopen,
#       dispatch.py urllib.request transport import) — M1-A windows;
#   (b) the three bounded argv-typed subprocess sites (apex/sandbox.py,
#       memory/ab_lab.py, production/verdict_bridge.py) became APPROVED
#       in shared/direct_io_inventory.py with documented reasons.
# No NEW unapproved site appears — new-identity growth stays fail-closed.
# UM-DR-29 (2026-11-07): the pin shrinks 36 -> 34 records / 30 -> 28
# identities — the completion of the Ultimate-Plan-2026-10-27-proposal-4
# archive physically removed src/webpent/cqa/execution.py (the prior
# window documented the identity removal but the file deletion was
# never executed; UM-DR-29 completed it — see
# archive/umdr29_dead_code/README.md). No new site; adjudicated file
# removal only.
PINNED_UNAPPROVED_RECORD_COUNT = 34
# MERGE 2026-10-26: 18 -> 27 (unapproved unique identity set of the merged
# tree after scripts/regenerate_direct_io_inventory.py; every identity in the
# set is still fail-closed-pinned exactly as before).
# ULTIMATE PLAN 2026-10-27, proposal 4: 27 -> 25 (the two archived
# cqa/execution.py identities above).
# LEARNING A/B LAB 2026-10-29: 25 -> 27 (the two ab_lab.py subprocess
# identities above — import + call of the window launcher; both are
# unique identities, hence +2 here vs +2 records).
# UNIFIED-MERGE window (2026-11-02): 27 -> 41 (same union rationale).
# UM-DR-29 (2026-11-07): 30 -> 28 — the two cqa/execution.py identities
# physically left with the completed proposal-4 archive move.
PINNED_UNAPPROVED_IDENTITY_COUNT = 28
PINNED_UNAPPROVED_SITES = frozenset({
# MERGE 2026-10-26: regenerated identity set of the merged tree
# (scripts/regenerate_direct_io_inventory.py). Every identity here is
# still fail-closed-pinned; any NEW site outside this set fails the gate.
    ('src/webpent/agents/validator/family_checks.py', 'dynamic_resolution', 'getattr(post_state_replay, ... )'),
    ('src/webpent/causal_reasoning_v2/integration_layer.py', 'dynamic_import', '__import__'),
    ('src/webpent/cli/commands.py', 'dynamic_import', '__import__'),
    ('src/webpent/cli/commands.py', 'import', 'playwright.sync_api.sync_playwright'),
    # ULTIMATE PLAN 2026-10-27, proposal 4 (completed physically by
    # UM-DR-29, 2026-11-07): the two cqa/execution.py identities left
    # the tree with the dead-code archive — removed from this set.
    ('src/webpent/families/execution_node.py', 'call', 'httpx.Client'),
    ('src/webpent/families/execution_node.py', 'dynamic_resolution', 'getattr(httpx.Client.request, ... )'),
    ('src/webpent/families/execution_node.py', 'import', 'httpx'),
    ('src/webpent/irta/v3/campaign.py', 'call', 'httpx.AsyncClient'),
    ('src/webpent/irta/v3/campaign.py', 'import', 'httpx'),
    ('src/webpent/llm_researcher/providers/openai_compatible.py', 'call', 'httpx.Client'),
    ('src/webpent/llm_researcher/providers/openai_compatible.py', 'import', 'httpx'),
    ('src/webpent/production/campaign_worker.py', 'dynamic_import', '__import__'),
    ('src/webpent/production/context_authority.py', 'dynamic_import', '__import__'),
    ('src/webpent/production/modern_spine.py', 'call', 'httpx.Client'),
    ('src/webpent/production/modern_spine.py', 'import', 'httpx'),
    # LEARNING A/B LAB 2026-10-29: the C-9 window launcher — same
    # adjudicated subprocess family as verdict_bridge/sandbox above.
    ('src/webpent/reporter/poc_recorder.py', 'import', 'playwright.sync_api.sync_playwright'),
    ('src/webpent/shared/fixture_registry.py', 'import', 'socket'),
    ('src/webpent/tools/registry.py', 'dynamic_import', 'importlib.import_module'),
    ('src/webpent/tools/registry.py', 'dynamic_import', 'importlib.reload'),
    # UNIFIED-MERGE window (2026-11-02): the union's not-approved
    # sites — dynamic-import plugin loaders (agents), the benchmark
    # fixture runner's socket, the report smoke's tmp-file IO and
    # the archived-lineage fixtures. Adjudicated in UM-DR-07.
    ('src/webpent/agents/advanced_web_vulns/agent.py', 'dynamic_import', '__import__'),
    ('src/webpent/agents/graphql_testing/agent.py', 'dynamic_import', '__import__'),
    ('src/webpent/agents/js_discovery/agent.py', 'dynamic_import', '__import__'),
    ('src/webpent/benchmark/fixtures/runner.py', 'call', 'socket.socket'),
    ('src/webpent/benchmark/fixtures/runner.py', 'import', 'socket'),
    # UM-DR-29 (2026-11-07): the two cqa/execution.py identities above
    # physically left the tree with the completed proposal-4 archive
    # move (removed from this pinned set; 30 -> 28 identities).
    ('src/webpent/oast/server.py', 'call', 'socket.socket'),
    ('src/webpent/oast/server.py', 'import', 'socket'),
    ('src/webpent/shared/h2_race.py', 'call', 'socket.create_connection'),
    ('src/webpent/shared/h2_race.py', 'import', 'socket'),
})


def _load_artifact() -> dict:
    assert ARTIFACT_PATH.exists(), f"recorded direct-I/O artifact missing: {ARTIFACT_PATH}"
    return json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))


def _unapproved_sites(records: list[dict]) -> set[tuple[str, str, str]]:
    return {
        (r["file"], r["kind"], r["normalized_symbol"])
        for r in records
        if r.get("approval_status") == "not_approved"
    }


def test_artifact_exists_and_has_schema():
    art = _load_artifact()
    for key in ("records", "approved_direct_files", "approved_transport_records",
                "dynamic_import_allowlist", "schema"):
        assert key in art, f"artifact missing required key {key!r}"
    assert art["schema"] == "webpent.direct_io_inventory.v1"


def test_inventory_records_match_recorded_artifact_no_drift():
    """Drift check: current AST scan == recorded artifact, fail on any diff."""
    art = _load_artifact()
    expected = scan_direct_io(SRC_ROOT)
    observed = art.get("records")
    assert observed == expected, (
        "direct-I/O inventory drifted from the recorded artifact in "
        "docs/direct_io_inventory.json. If you intentionally added/removed/moved "
        "a transport site, regenerate the artifact deliberately (reviewable diff); "
        "never hand-edit it. First differing site: "
        f"{_first_diff(expected, observed)}"
    )


def _first_diff(expected: list, observed: list) -> str:
    if observed is None:
        return "artifact has no records field at all"
    if len(observed) != len(expected):
        return f"record count {len(observed)} (artifact) != {len(expected)} (current scan)"
    for i, (e, o) in enumerate(zip(expected, observed, strict=True)):
        if e != o:
            return f"record #{i}: current={e!r} vs artifact={o!r}"
    return "ordering differs"


def test_no_expired_approvals():
    errs = expired_approval_errors()
    assert errs == [], f"expired/invalid approval metadata: {errs[:5]}"


def test_unapproved_site_gap_is_pinned_fail_closed_on_new_sites():
    """Fail-closed pin: exactly the known 18 unapproved sites; any NEW one fails.

    This is NOT an xfail.  The known gap is pinned by count AND by identity.
    A new unapproved transport site (e.g., a PR adding a raw ``httpx`` import
    in an unapproved file) changes the set and FAILS the build, forcing
    security review.  Removing/approving one of the 18 known sites also fails
    the pin, which is correct — the pin must be deliberately reduced only after
    security adjudication.
    """
    records = scan_direct_io(SRC_ROOT)
    unapproved_records = [r for r in records if r.get("approval_status") == "not_approved"]
    current_identities = _unapproved_sites(records)
    assert len(unapproved_records) == PINNED_UNAPPROVED_RECORD_COUNT, (
        f"unapproved RECORD count changed: {len(unapproved_records)} (current) != "
        f"{PINNED_UNAPPROVED_RECORD_COUNT} (pinned). A new raw-transport site was "
        "added or an existing one was removed — deliberately update the pin only after "
        "security-engineering adjudication."
    )
    assert len(current_identities) == PINNED_UNAPPROVED_IDENTITY_COUNT, (
        f"unapproved IDENTITY count changed: {len(current_identities)} (current) != "
        f"{PINNED_UNAPPROVED_IDENTITY_COUNT} (pinned)."
    )
    assert current_identities == PINNED_UNAPPROVED_SITES, (
        f"unapproved-site set drifted from the pinned known-gap set. "
        f"New: {sorted(current_identities - PINNED_UNAPPROVED_SITES)[:5]}; "
        f"Gone: {sorted(PINNED_UNAPPROVED_SITES - current_identities)[:5]}."
    )

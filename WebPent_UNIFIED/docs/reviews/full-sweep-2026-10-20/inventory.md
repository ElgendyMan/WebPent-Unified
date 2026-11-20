# Inventory — FULL SWEEP (TOTAL ADVERSARIAL REVIEW PROTOCOL v2)

_Date: 2026-10-20. Scope: the whole tree + the last two proposals
(DEEP FAMILIES, FORGE). Working copy: `/home/thaura/webpent_review`
(ZIP `webpent_v89_prism_campaign_w1w5.zip`, sha256 fa8ed70e…, is the
last verified deliverable; this tree matches it).

## 1. The tree by the numbers

- `src/webpent/` packages: **80** top-level package dirs, **896**
  Python files. `tests/`: **415** test files across 14 sub-dirs
  (apex, bridge, campaign, deep, dojo, econ, forge, ground_truth, jc,
  lab, oracle, prism, scenario_lab, team1_acceptance) plus ~300 root
  test modules.
- Largest packages by LOC: shared 48k, agents 32k, autonomous 8.5k,
  production 7.9k, models 6.3k, cli 5.4k, memory 5.3k.
- The last two proposals as shipped: **forge/** 20 modules / 2,919
  LOC (schemas, sources, normalizer, quality_gate, indexer, ingester,
  query_engine, encoding_engine, evolution, adversarial, chaining,
  contextualizer, cross_target, mutation, outcome_tracker,
  synthesizer, payload_cli, payload_dashboard, integration,
  bridge) and **deep/** 16 modules / 3,008 LOC (15 detectors + bridge).
- The campaign layer: **campaign/** 2,853 LOC, 15 units
  (U-CAMPAIGN-1..15) across strategist/executor/storage/storyteller/
  historian/warroom + the spine-side `production/campaign_bridge.py`.
- The three isolated packages (verdict/, emulator/, rehearsal/):
  untouched since their wargames rounds (suites re-run each round).

## 2. Seals (verified this sweep, sha256)

- `src/webpent/production/modern_spine.py`:
  `d10783ec422bf1cfbba8daeb75f574fb6908b48ab793e54b8fde8c05e8fc9e3e`
  (moved deliberately at Wave 3, documented in
  `docs/reviews/round7_campaign_wave3_seal_update.md`).
- `src/webpent/live_hunter/profile.py`:
  `30fd86c61156e7a5883205b9ce4b2f6c3f856f78e1561676345ad988d9c5b663`
  (never moved).

## 3. Cross-layer surface map (who talks to whom)

- deep → campaign + prism: `deep/bridge.py` (DEEP_FAMILY_TO_CAMPAIGN
  map, finding→hypothesis/evidence/finding converters).
- forge → apex/campaign surfaces: `forge/integration.py`
  (get_payloads_for_phase, get_tool_chain_for_payloads, oracle
  enrichment, prism outcome feed, DOJO scenario payloads).
- campaign → spine: only through `production/campaign_bridge.py`
  (Wave 3 wiring, 2 touch points in `run_autonomous_validation_campaign`,
  BRIDGE_GUARD typed blockers).
- Family enums exist in THREE shapes: `campaign/schemas.py` Family
  (str Enum, 8 members, lowercase values), `forge/schemas.py` Family
  (Enum, 10 members, uppercase names), and the DEEP detectors' free
  string families (e.g. "MASS_ASSIGNMENT") mapped by
  `deep/bridge.py`.
- Dashboards: 8 (oracle, prism, econ, forge/payload, remediation,
  campaign/warroom, apex, jc). CLI surfaces: forge/payload_cli,
  campaign/warroom/cli, and `cli/`.

## 4. Governing constraints in force during this sweep

- No new features; findings get fixes, not expansions.
- Zero-touch on `modern_spine.py` / `profile.py` and the three
  isolated packages; escalation only, documented.
- No fix without a red test; tests are never modified to pass.
- Advisory only; zero live network from the core; zero
  auto-exploitation.
- Direct-I/O policy: `getattr` is the counted dynamic-resolution
  site (`src/webpent/shared/direct_io_inventory.py` AST scanner);
  new packages carry zero.

## 5. Evidence collected in discovery (before the 12 axes)

- getattr audit of the four recent packages (campaign, forge, prism,
  deep): campaign 0, forge 0, deep 0, prism 5 (prism is an older
  layer; pre-dates the zero-getattr rule). **hasattr** (same
  duck-typing class, NOT counted by the scanner): 1 site —
  `forge/integration.py:93`.
- Broad `except Exception`: 1 site — `forge/encoding_engine.py:77`
  (`generate_variants` silently skips any encoder that raises).
- forge/schemas.py:15 docstring claims forge Family is "a superset of
  the campaign layer's families" — mechanically false: campaign has
  BOLA, IDOR, AUTH_BYPASS, INFO_DISCLOSURE with no forge counterpart.
- deep/bridge.py imports only the three Tier-1 finding types
  (mass_assignment, host_header, cache_deception); the other 12
  detectors (race_condition, business_logic, smuggling, saml,
  deserialization, dom_clobbering, jwt_advanced, nosql_injection,
  prototype_pollution, rate_limit_bypass, client_path_traversal,
  + deep/bridge gap) have no path into the campaign/prism bridge.
- Suite ground truth: full-suite run executed during the sweep (see
  sweep_04_claims.md). verify_all + construction gate re-run in
  Phase 5.

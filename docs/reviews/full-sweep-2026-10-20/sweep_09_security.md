# Axis 9/12 — SECURITY (can anything here be turned into a weapon or a leak?)

Depths: (a) network surface, (b) injection/storage surface, (c)
policy-bypass surface.

## Shallow (network surface)

forge + deep: the only network-capable import is urllib.parse (pure
string encoding); detectors take `send` injected; the ingester takes
pre-fetched strings. campaign: zero I/O beyond JSON files. No live
network from any recent package.

## Medium (injection/storage)

- SQLite access in forge/indexer.py and forge/outcome_tracker.py uses
  parameterized queries (`INSERT ... VALUES (?,?,...)` with bound
  rows — verified in outcome_tracker.py:79). No f-string SQL found.
- JSON stores: CampaignStore/CampaignMemory write with fixed
  filenames derived from campaign/memory ids. A campaign id
  containing "/" or ".." would escape the records directory
  (path traversal in the local store). Assessed: ids are generated
  internally (operator-chosen ids reach the CLI only as lookup
  keys, and get_brief/get never write). Residual: a future caller
  that records an attacker-influenced campaign_id could write
  outside the store. Recorded as **F-08 LOW** (hardening note for
  the roadmap; the current write path is fed by generated ids only).

## Deep (policy-bypass)

- Approval sovereignty: campaign_bridge holds no approval code path
  (AST-source-locked); the CLI's approve is the operator's explicit
  act on a stored brief. Nothing in forge/deep can mark a campaign
  approved.
- Auto-exploitation: no send/execute anywhere in forge or deep;
  chains are advisory ChainSteps.
- Scanner blind spot: `hasattr` duck-typing is not counted by the
  direct-I/O scanner while `getattr` is — the same dynamic-resolution
  class, one site live in forge/integration.py:93 (**F-03**). The
  fix is in the package (replace with a direct read); changing the
  scanner itself is core work and is escalated as a roadmap item,
  not done mid-review.

## Verdict for this axis

F-03 MEDIUM (fixed), F-08 LOW (documented). No exploit path, no leak
path, no policy bypass found.

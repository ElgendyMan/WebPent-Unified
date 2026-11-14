# M9_PHASE_REPORT.md — M9 (Human-in-the-Loop Approval Gates)

**Phase:** M9 of the CANONICAL_PHASE_REGISTRY (Part 4 §11 — P0 for high-impact actions).
**Date closed:** 2026-11-06 (UTC).
**Window:** DRIFT_REGISTER UM-DR-21.
**Baseline entering:** post-M7 tree (UM-DR-20); frozen authority manifest untouched; frozen-module gate 661 green.
**Refreeze:** NONE REQUIRED — the entire phase is a NEW package (`src/webpent/approvals/`) outside the frozen gate, built ON the existing (frozen, untouched) ActionAuthority + HITL interrupts. Zero frozen-file changes.

---

## 1. What was delivered

The registry's entering note: "interrupts exist and work (scope_review + execution_sandbox), ActionAuthority tiers exist; classification documentation + channel binding + voiding-on-change are the work". All three gaps closed:

### 1.1 — Tier 0–3 classification by ACTUAL behavior (`approvals/classification.py`)

`classify_action` consumes the action's OBSERVED behavior (method, family, capability, identity-material booleans, budget, authorization flags) — never its self-description. T0 read-only (no approval; authorization alone governs) → T1 active → T2 destructive/upload/OOB/above-band budget → T3 export/foreign-identity/cross-tenant/authorization-flagged. Every verdict carries its signal reasons.

### 1.2 — The binding tuple + voiding (`approvals/binding.py`)

`ApprovalBinding` — immutable, bound to the FULL Part 4 §11 tuple: engagement, manifest digest, action (method/path/family/capability), identity, tier, preview, budget, approver, approved-at, expiry, channel, status. `fingerprint_action` is the canonical sha256 over the action side — any component change alters it, which IS the material-change detector. `consume` refuses on: not granted / already consumed (a stale pre-consumption copy cannot double-spend — the gate resolves the CURRENT registry state, a defect the window caught and fixed) / expired / material change (voids terminally) / emergency stop.

### 1.3 — Channels, lifecycle, audit (`approvals/binding.py`)

CLI-prompt-first (`cli_prompt_channel`; empty/refused = deny); **notification channels can NEVER grant** (`ChannelOutcome.notification_only` short-circuits to a non-granted status — structurally, a webhook cannot approve). Timeout / deny / cancel / emergency-stop paths; TIER_0 never prompts. `ApprovalLedger` — append-only JSONL audit trail: every event (requested/granted/denied/timeout/cancelled/voided/consumed/refused/emergency_stop) with timestamps and per-binding retrieval.

### 1.4 — Approvals complete authorization, never replace it

Test-pinned against the REAL frozen `ActionAuthority`: a `human_approved=True` request on an out-of-scope target is STILL policy-denied. The gate's output is a consumable approval the authorization layer may consult; a policy denial always wins.

## 2. Acceptance vs the registry

| Registry acceptance (Part 4 §11) | Status |
|---|---|
| approval classification + binding completing authorization (never replacing) | **delivered + test-pinned vs the real authority** (§1.1, §1.4) |
| Tier 0–3 risk classification by ACTUAL action behavior | **delivered** (§1.1) |
| approval bound to the full 10-element tuple; material change voids | **delivered + tested component-by-component** (§1.2) |
| channels: CLI prompt first; notification ≠ approval | **delivered** (§1.3 — notification cannot grant, structurally) |
| timeout / deny / cancel / emergency-stop | **delivered** (§1.3) |
| approval audit trail complete | **delivered** (§1.3 — JSONL, ordered, per-binding) |

Deferred with owners: authenticated notification integrations (Slack/SMTP transports) → operator-demand window (the channel protocol exists; transports are configuration); graph-node wiring of the gate into the frozen interrupt points → the next builder thaw (the existing scope_review/execution_sandbox interrupts remain the graph's pause points; the gate is the approval bookkeeping they consult).

## 3. Gate evidence at closure

- **Tests:** `tests/test_m9_approval_gates.py` — 19 passed (classification behaviors; the full tuple; the 8-component material-change matrix; deny/timeout/cancel/expiry/one-time-consume/emergency-stop; tier-0-never-prompts; notification-cannot-grant; the real-Authority policy-denial test; the ordered persisted audit trail).
- **Frozen-module gate:** 661 passed (no frozen changes).
- **Test-count gate:** 8,488 ≥ floor 8,115.
- **Authority manifest:** untouched (13 files).

— End of M9_PHASE_REPORT.md —

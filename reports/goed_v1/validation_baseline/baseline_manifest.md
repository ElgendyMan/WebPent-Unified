# GOED v1 — Validation Baseline
**Created:** 2026-09-03T06:21:02.050699+00:00
**Purpose:** Immutable snapshot of GOED v1 state before validation execution.

## Source Files Hashed

| File | SHA-256 |
|------|---------|
| `src/webpent/goed_v1/__init__.py` | `1c67229be93cdadf...` |
| `src/webpent/goed_v1/__pycache__/__init__.cpython-312.pyc` | `99815c46730e6a82...` |
| `src/webpent/goed_v1/__pycache__/contracts.cpython-312.pyc` | `eedf71c2e2eead7d...` |
| `src/webpent/goed_v1/__pycache__/exploration_loop.cpython-312.pyc` | `753815ad2f61af31...` |
| `src/webpent/goed_v1/__pycache__/hypothesis_engine.cpython-312.pyc` | `dda9c4912791942c...` |
| `src/webpent/goed_v1/__pycache__/open_world_mode.cpython-312.pyc` | `9350954e1b324dc0...` |
| `src/webpent/goed_v1/contracts.py` | `5b691cdb439c5fea...` |
| `src/webpent/goed_v1/exploration_loop.py` | `9c18b58c29c32400...` |
| `src/webpent/goed_v1/hypothesis_engine.py` | `93cd704047f4aecf...` |
| `src/webpent/goed_v1/open_world_mode.py` | `800e520f27ab7b69...` |

## Governance State

| Key | Value |
|-----|-------|
| `vip_qualified` | `false` |
| `qualification_state` | `CONDITIONAL` |
| `official_isolated_p10_runs_authorized` | `false` |
| `P10` | `CLOSED` |
| `P9` | `CLOSED` |
| `VIP` | `NOT_QUALIFIED` |
| `Bug Bounty` | `BLOCKED` |

## Smoke Tests

| Test | Result |
|------|--------|
| Import smoke | **PASS** |
| Preservation verified | `True` |
| GRO creation | **PASS** (4 hypotheses) |
| Security hypotheses | 2 |
| Alternative hypotheses | 3 |
| Leakage detection | **PASS** (5 patterns detected) |
| Safe context | **PASS** |

## Core Metrics (Frozen)

- CQA v2 Gate 5: TP=25 TN=25 FP=0 FN=0 P=1.0 R=1.0 F1=1.0
- Qualification v10: TP=10 FP=0 FN=0 P=1.0 R=1.0 F1=1.0
- Discovery inventory: 128 items classified across 4 categories

## Rule 0 Compliance

This baseline is IMMUTABLE. All validation work is ADDITIVE.
No existing modules, tests, artifacts, metrics, or governance gates will be modified.

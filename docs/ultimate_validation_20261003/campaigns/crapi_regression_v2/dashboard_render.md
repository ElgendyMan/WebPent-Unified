# Agent Evolution Dashboard — `regression-crapi-live-v2-20261003`

- Target: `http://127.0.0.1:8888`
- Persona: **All hunter personas**
- Duration: **507.245 seconds**
- Routes crawled: **29**; curiosity flags: **28**
- Graph events: **81**
- LLM calls: **32**; actual cost: **$0.12665525**

## Validator outcomes

| Outcome | Count |
|---|---:|
| blocked | 1 |
| confirmed | 0 |
| inconclusive | 12 |
| refuted | 0 |

## Agent-call distribution

| Node | Calls |
|---|---:|
| exploiter_node | 13 |
| planner_node | 1 |
| replan_node | 9 |
| validator_node | 9 |

## Family attempts

| Family | Attempts |
|---|---:|
| IDOR | 1 |
| INFO_DISCLOSURE | 4 |
| XSS | 4 |

## Chaining Engine

- Chains discovered: **0**
- Chains confirmed: **0**
- Combined severity upgrades: **0**
- Chain authority: existing M4/AVI/ProofBundle/Replay/PromotionPipeline only.

- Audit chain verified: **True** (`42b5710b30d7f5a4`)
- Notes: `hunt_notes.md`
- Promotion authority: existing AVI/ProofBundle/replay/PromotionPipeline only.

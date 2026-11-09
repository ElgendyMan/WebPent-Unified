# Agent Evolution Dashboard — `generalization-phase5-fixed-juice_shop`

- Target: `http://127.0.0.1:3000`
- Persona: **Stok / API Breaker**
- Duration: **348.187 seconds**
- Routes crawled: **25**; curiosity flags: **22**
- Graph events: **52**
- LLM calls: **20**; actual cost: **$0.08900575**

## Validator outcomes

| Outcome | Count |
|---|---:|
| confirmed | 0 |
| inconclusive | 9 |
| refuted | 1 |

## Agent-call distribution

| Node | Calls |
|---|---:|
| exploiter_node | 10 |
| planner_node | 1 |
| validator_node | 9 |

## Family attempts

| Family | Attempts |
|---|---:|
| INFO_DISCLOSURE | 5 |
| OPEN_REDIRECT | 1 |
| SSRF | 4 |

- Audit chain verified: **True** (`8da08608c0b519ab`)
- Notes: `hunt_notes.md`
- Promotion authority: existing AVI/ProofBundle/replay/PromotionPipeline only.

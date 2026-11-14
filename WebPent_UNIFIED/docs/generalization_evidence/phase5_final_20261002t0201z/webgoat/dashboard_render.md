# Agent Evolution Dashboard — `generalization-20261002t0201z-webgoat`

- Target: `http://127.0.0.1:8082/WebGoat`
- Persona: **Stok / API Breaker**
- Duration: **198.382 seconds**
- Routes crawled: **3**; curiosity flags: **0**
- Graph events: **35**
- LLM calls: **12**; actual cost: **$0.04859225**

## Validator outcomes

| Outcome | Count |
|---|---:|
| confirmed | 0 |
| inconclusive | 7 |
| refuted | 0 |

## Agent-call distribution

| Node | Calls |
|---|---:|
| exploiter_node | 6 |
| planner_node | 1 |
| validator_node | 5 |

## Family attempts

| Family | Attempts |
|---|---:|
| XSS | 5 |

- Audit chain verified: **True** (`13b395ac7a1a7d2b`)
- Notes: `hunt_notes.md`
- Promotion authority: existing AVI/ProofBundle/replay/PromotionPipeline only.

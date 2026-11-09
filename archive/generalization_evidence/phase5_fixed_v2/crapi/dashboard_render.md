# Agent Evolution Dashboard — `generalization-phase5-fixed-crapi`

- Target: `http://127.0.0.1:8888`
- Persona: **Stok / API Breaker**
- Duration: **343.529 seconds**
- Routes crawled: **20**; curiosity flags: **23**
- Graph events: **52**
- LLM calls: **20**; actual cost: **$0.08911275**

## Validator outcomes

| Outcome | Count |
|---|---:|
| confirmed | 0 |
| inconclusive | 8 |
| refuted | 2 |

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
| SSRF | 1 |
| XSS | 3 |

- Audit chain verified: **True** (`3ec05e27cc548b0b`)
- Notes: `hunt_notes.md`
- Promotion authority: existing AVI/ProofBundle/replay/PromotionPipeline only.

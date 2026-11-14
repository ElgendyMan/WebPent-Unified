# Component Ownership Review

The audit found multiple related implementations and 49 same-basename candidate groups. These are not declared duplicates solely from naming. Canonical ownership is assigned by authority and execution role.

| Capability | Canonical owner | Supporting/legacy implementations | Ownership rule |
|---|---|---|---|
| Target discovery and HTTP mapping | `src/webpent/rta/discovery.py` | target adapters and historical discovery helpers | RTA discovery owns realistic local HTTP surface mapping |
| Causal validation | `src/webpent/rta/validation.py` and DCVU engine | legacy validators | Only approved causal boundaries can support scoring |
| Generic research intelligence | `src/webpent/research/` plus shared research modules | IRTA research facade | IRTA does not replace the existing core |
| Planning | Existing campaign/research planners | `src/webpent/irta/research/loop.py` | Existing planner remains canonical for legacy execution; IRTA loop is bounded planning |
| Evidence and ProofBundle | Existing proof/evidence modules | negative-intelligence contracts | IRTA may classify evidence but cannot mint authoritative proof without observations |
| Policy and execution | `ActionAuthority`/`ActionExecutor` in shared campaign execution | adapters | All future actions must pass the existing policy boundary |
| Memory | Existing reasoning/security memory layers | IRTA learning measurement | No second authoritative memory layer is introduced |
| Business logic fixture | `src/webpent/irta/business/workflows.py` for IRTA disposable cases | target-specific fixtures | Pure workflow fixture is additive and not a live target adapter |

No duplicate was merged or deleted during the audit. Any future consolidation requires dependency analysis, behavior comparison, regression, and a separate reviewed commit.

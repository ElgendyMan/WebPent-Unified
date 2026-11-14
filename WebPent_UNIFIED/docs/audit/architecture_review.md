# Architecture Integrity Review

## Generic-core contamination

The audit scanner checked the configured generic directories for known target identifiers, fixture names, route shortcuts, and vulnerability-specific markers. It found **zero candidate marker hits** in those directories. This is evidence that the current scan did not find contamination; it is not a proof against every possible semantic coupling. Target-specific behavior remains expected in RTA adapters, profiles, and fixtures.

## Duplicate review

The repository contains 49 same-basename candidate groups. A same-basename match is not treated as a duplicate implementation without dependency and behavior analysis. Historical components were not deleted or merged. The groups are retained for manual ownership review.

| Capability | Canonical implementation | Other related layers | Decision |
|---|---|---|---|
| Causal validation | `src/webpent/rta/validation.py` and DCVU validation contracts | legacy validators and adapters | Reuse canonical RTA/DCVU boundaries; do not merge blindly |
| Research hypotheses | `src/webpent/research/` and `src/webpent/shared/research_intelligence.py` | IRTA bounded facade | IRTA is additive orchestration, not a replacement |
| Planning | Existing research/campaign planners | `src/webpent/irta/research/loop.py` | Existing planners remain canonical for legacy flows; IRTA facade is bounded |
| Evidence/proof | Existing ProofBundle/seal/replay contracts | IRTA negative scoring | Preserve existing proof authority; IRTA does not mint proof |
| Memory | Existing security/reasoning memory components | IRTA learning measurement | Measurement only; no second authoritative memory layer |
| Decision/policy | Existing ActionAuthority/ActionExecutor paths | IRTA stop conditions | Existing policy boundary remains canonical |

## Review conclusion

No deletion, validator modification, ground-truth modification, metric manipulation, or default safety-gate opening was observed in this audit change. The IRTA additions remain isolated and target-neutral by construction.

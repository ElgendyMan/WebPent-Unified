# Post-IRTA Feature Traceability Matrix

This matrix distinguishes implementation from capability proof. A feature is **VERIFIED** only when source, test, artifact, and reproduction evidence align. A design or contract without live causal proof is **PARTIAL** or **UNVERIFIED**.

| Feature | Planned | Implemented | Location | Test | Evidence | Status |
|---|---:|---:|---|---|---|---|
| Causal Detection Foundation | Yes | Yes | `src/webpent/dcvu/`, `src/webpent/rta/validation.py` | Yes | DCVU/RTA reports and regression | VERIFIED within local bounded scope |
| ProofBundle sealing/replay | Yes | Yes | `src/webpent/**proof*`, RTA/DCVU evidence paths | Yes | Historical artifacts and tests | PARTIAL; case-specific independent replay is incomplete |
| Target Knowledge Model | Yes | Yes | `src/webpent/research/`, `src/webpent/shared/` | Yes | Research-core evaluations | PARTIAL; target-independent live quality is not proven |
| Attack Graph | Yes | Yes | `src/webpent/**attack_graph*` | Yes | Graph tests and artifacts | PARTIAL; graph existence is not causal detection |
| ASROS | Yes | Yes | `src/webpent/**asros*` | Yes | Existing regression | PARTIAL; bounded capability is shown, VIP quality is not |
| AREX | Yes | Yes | `src/webpent/**arex*` | Yes | Existing regression | PARTIAL; execution remains policy-gated |
| DCVU | Yes | Yes | `src/webpent/dcvu/` | Yes | Controlled benchmark report | VERIFIED as a validation harness, not real-world proof |
| RTA | Yes | Yes | `src/webpent/rta/` | Yes | RTA v1 report and live local targets | VERIFIED for local lifecycle portability; quality portability remains unproven |
| IRTA v2 generator/mutations | Yes | Yes | `src/webpent/irta/generator/` | Yes, 13 focused tests | IRTA report and metrics | VERIFIED as contracts; live detector quality is not proven |
| IRTA v2 research loop | Yes | Yes | `src/webpent/irta/research/loop.py` | Yes | Focused tests | PARTIAL; bounded facade, not autonomous unrestricted execution |
| Negative intelligence | Yes | Yes | `src/webpent/irta/negative/` | Yes | Focused tests | VERIFIED as fail-closed suppression contracts |
| Business Logic v2 | Yes | Yes | `src/webpent/irta/business/` | Yes | Workflow tests | PARTIAL; pure disposable fixture, not live target proof |
| Memory learning improvement | Yes | Measurement primitive | `src/webpent/irta/metrics/benchmark.py` | Yes | Recall-delta contract only | UNVERIFIED for actual future detection improvement |

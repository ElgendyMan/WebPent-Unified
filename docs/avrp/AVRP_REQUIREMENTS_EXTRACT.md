# AVRP v1 Requirements Extract

Source: `/home/ubuntu/upload/pasted_content_11.txt`

## Scope and safety

AVRP is an additive, bounded advisory layer over the existing WebPent/ASROS/AVDE contracts. It must not weaken gates, bypass capability checks, modify historical evidence, convert blocked cases into confirmed findings, inflate metrics, claim VIP/P10 qualification, open P10, or use external targets.

Execution remains in-process and deterministic. No new daemon, scheduler, persistent service, external target, credentials, privileged access, destructive action, or parallel authority/transport layer may be introduced.

## Required capabilities

1. Continuous research state: active/completed investigations, rejected paths, unknown areas, high-value assets, security assumptions, confidence; every update requires evidence reference, timestamp, confidence, and reason; deterministic snapshot/restore, version compatibility, and target isolation.
2. Evidence correlation: correlate multiple observations into an evidence relationship graph; every relation needs source observations, reasoning, confidence, and validation requirement.
3. Vulnerability pattern generalization: reusable patterns for authorization failures, ownership violations, privilege boundaries, workflow abuse, and data exposure; each pattern needs prerequisites, security assumption, typical evidence, validation strategy, and common false positives.
4. Autonomous research loop v2: Observe -> update world model -> correlate evidence -> generate hypotheses -> rank paths -> validate -> learn -> adjust strategy; it must continue after failed hypotheses, change direction, avoid repeated paths, and focus on valuable areas.
5. Coverage intelligence: explored/unexplored areas, confidence, missing evidence, and potential blind spots; answer what remains poorly understood.
6. Advanced attack-chain reasoning: weakness + supporting condition + privilege boundary + business impact; chains remain hypotheses, with no exploitation claim without proof and no promotion without oracle.
7. Multi-class benchmark: minimum IDOR, privilege escalation, business-logic authorization failure, information disclosure, and authentication-boundary issue; each requires target model, campaign, hypotheses, validation attempts, causal oracle, ProofBundle, and replay. Metrics must describe research quality, not invent detection results.
8. Self-improvement: analyze successful/failed paths, low-value actions, high-value evidence, and update prioritization weights; no cross-target leakage, no hidden state, explainable updates.
9. Quality review: check clear security boundary, causal evidence, eliminated alternatives, demonstrated impact, and reproducibility; reviewer cannot create findings, override oracle, or bypass evidence requirements.
10. Evaluation/delivery: pytest, ruff, compileall, generic neutrality, secret scan, G-02, release provenance, and tests for state persistence, correlation, pattern generalization, adaptive loop, coverage, chains, learning isolation, and quality review.

## Delivery requirements

Create `AVRP-v1-Completion-Report` with implemented components, architecture changes, benchmark results, metrics, limitations, blockers, and governance status.

Create `WebPent-AVRP-v1-Delivery-YYYYMMDD.zip` containing `src/`, `tests/`, `benchmarks/`, `reports/`, `docs/`, `artifacts/`, release manifest, provenance, and `SHA256SUMS.txt`.

## Success boundary

The milestone may claim only the demonstrated engineering capability: continuous adaptive investigation. It must not claim VIP qualification, open P10, or use external targets.

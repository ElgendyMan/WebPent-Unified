# TEAM1_DEEP_RECON_V1.md — Implementation Report

## Mission: Deep Recon & Schema-to-Hypothesis V1
Moves WebPent from 'surface discovery produces a few structural hints' to 'hunter builds reusable target knowledge model from real recon and uses it to generate/rank/discriminate hypotheses.'

## Pipeline
REAL TARGET OBSERVATION → DEEP RECON → NORMALIZED TARGET SCHEMA → PRINCIPALS → RESOURCES/OBJECTS → ACTIONS → PARAMETERS → RELATIONSHIPS → AUTHORIZATION/TRUST BOUNDARIES → ATTACK SURFACES → HYPOTHESES → UNRESOLVED QUESTIONS → DISCRIMINATING EXPERIMENTS → EXISTING AUTONOMOUS RESEARCH LOOP

## Phase 1: Recon contract — Principal/Resource/Action/Parameter with evidence refs, confidence, provenance, normalized identifier. Role NOT assumed from string alone. Parameter NOT classified security-sensitive from name alone.
## Phase 2: Surface discovery — generic HTTP routes/methods/params/JSON structures/auth observations. Path shape normalized (numeric IDs → {id}). 401/403 → anonymous principal.
## Phase 3: Schema ingestion — OpenAPI/Swagger/GraphQL → World Model entities. Marked SCHEMA_DERIVED. 'GET /users/{id}' does NOT imply IDOR — only attack-relevant surface/hypothesis candidate.
## Phase 4: Relationship inference — OBSERVED (direct evidence) / INFERRED (requires reason+supporting_observations+confidence>0+uncertainty) / UNKNOWN (creates unresolved question, NOT fact).
## Phase 5: Trust boundary extraction — anonymous→authenticated, user→admin, user→privileged, client→server. Each boundary becomes an UNRESOLVED QUESTION — NEVER a confirmed authorization vulnerability.

## Integration: DeepReconEngine is a PRODUCER for World Model + ResearchControlLoop. NOT a second planner. ResearchControlLoop remains the ONE authoritative decision path.

## Regression: compileall PASS, state contract PASS, 22/22 tests PASS, NEW_FAILURES=0. All authority hashes match baseline.

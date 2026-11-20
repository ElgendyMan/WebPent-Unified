# Single Case Trace: target-alpha-case-01

- replay_verified: True
- scoring_category: FP

## Stage: discovery

- status: ok
- source: cqa_v1_campaign_observations
- has_baseline: True
- has_candidate: True
- has_control: True

## Stage: hypothesis

- status: ok
- case_id: target-alpha-case-01
- target_id: target-alpha
- hypothesis: candidate_observation_differs_from_baseline_in_a_way_that_indicates_vulnerability

## Stage: candidate

- status: ok
- observation_present: True
- status_code: 200

## Stage: baseline

- status: ok
- observation_present: True
- status_code: 200

## Stage: control

- status: ok
- observation_present: True
- status_code: 404

## Stage: causal_comparison

- verdict: CONFIRMED
- causal_signal: True
- confidence: 0.9
- block_reason: None

## Stage: verdict

- verdict: CONFIRMED

## Stage: proof_creation

- bundle_created: True
- bundle_id: None
- native_proof_bundle_valid: None

## Stage: seal

- seal: 97301204c23be110a182535f8802c52d5e8b0b890e64e49943c6b222c65cc3fb
- seal_length: 64
- is_sealed: True
- seal_self_verifies: True

## Stage: replay

- verdict_match: True
- seal_valid: True
- seal_match: True
- digest_match: True

## Stage: scoring

- scored: True
- category: FP
- tp: 0
- tn: 0
- fp: 1
- fn: 0

## Replay Result Details

- verdict_match: True
- seal_valid: True
- seal_match: True
- digest_match: True

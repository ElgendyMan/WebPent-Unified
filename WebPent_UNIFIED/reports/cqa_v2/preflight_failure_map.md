# CQA v2 — Preflight Failure Map

## Pipeline Stage Statistics

- baseline_available: 50/50
- candidate_available: 50/50
- control_available: 50/50
- safe_precondition: 50/50
- causal_inputs_complete: 50/50
- causal_result_present: 50/50
- proof_inputs_complete: 50/50
- proof_bundle_present: 0/50
- seal_present: 0/50
- replay_present: 50/50

## Per-Case Diagnosis

For each case, the FIRST contract boundary that fails is identified.
Every case names a specific boundary; generic failure descriptions are not used.

### Case: target-alpha-case-01

- case_id: target-alpha-case-01
- target_id: target-alpha
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-alpha-case-02

- case_id: target-alpha-case-02
- target_id: target-alpha
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-alpha-case-03

- case_id: target-alpha-case-03
- target_id: target-alpha
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-alpha-case-04

- case_id: target-alpha-case-04
- target_id: target-alpha
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-alpha-case-05

- case_id: target-alpha-case-05
- target_id: target-alpha
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-alpha-case-06

- case_id: target-alpha-case-06
- target_id: target-alpha
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-alpha-case-07

- case_id: target-alpha-case-07
- target_id: target-alpha
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-alpha-case-08

- case_id: target-alpha-case-08
- target_id: target-alpha
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-alpha-case-09

- case_id: target-alpha-case-09
- target_id: target-alpha
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-alpha-case-10

- case_id: target-alpha-case-10
- target_id: target-alpha
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-beta-case-01

- case_id: target-beta-case-01
- target_id: target-beta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-beta-case-02

- case_id: target-beta-case-02
- target_id: target-beta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-beta-case-03

- case_id: target-beta-case-03
- target_id: target-beta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-beta-case-04

- case_id: target-beta-case-04
- target_id: target-beta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-beta-case-05

- case_id: target-beta-case-05
- target_id: target-beta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-beta-case-06

- case_id: target-beta-case-06
- target_id: target-beta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-beta-case-07

- case_id: target-beta-case-07
- target_id: target-beta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-beta-case-08

- case_id: target-beta-case-08
- target_id: target-beta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-beta-case-09

- case_id: target-beta-case-09
- target_id: target-beta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-beta-case-10

- case_id: target-beta-case-10
- target_id: target-beta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-gamma-case-01

- case_id: target-gamma-case-01
- target_id: target-gamma
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-gamma-case-02

- case_id: target-gamma-case-02
- target_id: target-gamma
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-gamma-case-03

- case_id: target-gamma-case-03
- target_id: target-gamma
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-gamma-case-04

- case_id: target-gamma-case-04
- target_id: target-gamma
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-gamma-case-05

- case_id: target-gamma-case-05
- target_id: target-gamma
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-gamma-case-06

- case_id: target-gamma-case-06
- target_id: target-gamma
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-gamma-case-07

- case_id: target-gamma-case-07
- target_id: target-gamma
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-gamma-case-08

- case_id: target-gamma-case-08
- target_id: target-gamma
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-gamma-case-09

- case_id: target-gamma-case-09
- target_id: target-gamma
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-gamma-case-10

- case_id: target-gamma-case-10
- target_id: target-gamma
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-delta-case-01

- case_id: target-delta-case-01
- target_id: target-delta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-delta-case-02

- case_id: target-delta-case-02
- target_id: target-delta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-delta-case-03

- case_id: target-delta-case-03
- target_id: target-delta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-delta-case-04

- case_id: target-delta-case-04
- target_id: target-delta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-delta-case-05

- case_id: target-delta-case-05
- target_id: target-delta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-delta-case-06

- case_id: target-delta-case-06
- target_id: target-delta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-delta-case-07

- case_id: target-delta-case-07
- target_id: target-delta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-delta-case-08

- case_id: target-delta-case-08
- target_id: target-delta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-delta-case-09

- case_id: target-delta-case-09
- target_id: target-delta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-delta-case-10

- case_id: target-delta-case-10
- target_id: target-delta
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-epsilon-case-01

- case_id: target-epsilon-case-01
- target_id: target-epsilon
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-epsilon-case-02

- case_id: target-epsilon-case-02
- target_id: target-epsilon
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-epsilon-case-03

- case_id: target-epsilon-case-03
- target_id: target-epsilon
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-epsilon-case-04

- case_id: target-epsilon-case-04
- target_id: target-epsilon
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-epsilon-case-05

- case_id: target-epsilon-case-05
- target_id: target-epsilon
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-epsilon-case-06

- case_id: target-epsilon-case-06
- target_id: target-epsilon
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-epsilon-case-07

- case_id: target-epsilon-case-07
- target_id: target-epsilon
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-epsilon-case-08

- case_id: target-epsilon-case-08
- target_id: target-epsilon
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-epsilon-case-09

- case_id: target-epsilon-case-09
- target_id: target-epsilon
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

### Case: target-epsilon-case-10

- case_id: target-epsilon-case-10
- target_id: target-epsilon
- baseline_available: True
- candidate_available: True
- control_available: True
- causal_input_missing: False
- proof_input_missing: False
- seal_missing: True
- replay_missing: False
- exact_block_reason: proof_bundle_never_constructed
- owning_component: proof_bundle_store.builder
- required_fix: call_proof_bundle_builder_with_complete_inputs

## Block Reason Aggregation

- proof_bundle_never_constructed: 50 cases

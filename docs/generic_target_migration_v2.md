# Generic Target Migration Note v2

## Purpose

This note records the migration from target-specific campaign inventory embedded in shared orchestration to explicit target-local profile providers. It is an architecture and migration document; it is not a live benchmark result and does not change frozen P10 governance artifacts.

## Dependency direction

The dependency direction is intentionally one-way:

```text
shared contracts / safety / proof / planner
                    ^
                    |
target adapter registration -> target-local campaign profile provider
```

The generic core owns the contracts and validation rules. A target adapter may register an optional `CampaignProfileSpec` containing a stable profile identifier and declarative campaign, execution-contract, and validator builders. Runtime builders remain in the registration object and are never serialized into checkpoints, descriptors, or evidence bundles. Shared code does not import benchmark profiles or adapter modules.

A non-generic profile is activated only when all of the following are true: the caller requests it explicitly; the requested profile is attached to the selected registered adapter; the provider validates successfully; and the resulting ledger/contracts match the provider identity. Missing, malformed, or mismatched providers fail closed. `auto` is deliberately generic and never guesses a target from a URL, route, host name, or inventory label.

## WAPTLab migration

The WAPTLab campaign matrix, proof contracts, validator registry wrapper, and execution-contract declarations now live in `src/webpent/benchmark/waptlab_campaign_profile.py`. The WAPTLab adapter is the only runtime registration point that may expose this profile. Reporting scripts and compatibility tests import the profile from that target-local module. The shared campaign and validator builders accept generic injected data and retain no WAPTLab constants or compatibility exports.

This preserves legacy benchmark behavior through an explicit provider while preventing the shared planner, bootstrap, smart-campaign refresh, and validator layer from silently selecting WAPTLab semantics.

## Generic web adapter boundary

`src/webpent/adapters/generic_web/adapter.py` implements the target-neutral adapter. It uses the central safe HTTP client boundary and an injected transport in offline tests. Its read-only discovery and lifecycle stages are bounded by timeout, request-rate, depth, page, and body limits; it follows only same-origin URLs; it rejects state-changing or cross-origin discovery paths; and it emits categorical, redacted observations rather than raw response bodies, cookies, headers, DOM, screenshots, or automatic findings. Generic cases remain observation-only or `needs_profile` unless an explicitly registered target-local provider supplies a valid semantic oracle and negative control.

The adapter can classify a surface as `html`, `spa`, `api`, `hybrid`, or `unknown`, and can report capabilities and lifecycle classifications such as `observation_only`, `unsupported`, `needs_profile`, and `needs_human_review`. A route existing or returning HTTP 200 is not itself a finding.

## Workflow and case contracts

The versioned generic workflow contract introduces the canonical concepts `browser_dom_observation`, `authorized_api_read`, and `same_origin_resource_observation`, while preserving explicit aliases for the older identifiers. `CaseDefinition` records required capabilities, authorization and mutation requirements, negative-control requirements, and bounded execution metadata. `CaseResult` is fail-closed: `confirmed` or `probable` requires a proof reference, and blocked/unsupported/inconclusive/profile-review states are not promoted to findings. The versioned optional `CaseLifecycleAdapter` companion contract now defines `describe_target`, `capabilities`, `prepare`, `baseline`, `execute_safe_action`, `observe`, `execute_negative_control`, and `cleanup`. `GenericCaseRunner` resolves that contract through the target registration, validates authorization/origin/capabilities/mutation policy, and exposes execution through `RuntimeContext.execute_registered_case`; legacy registrations remain compatible but fail closed when lifecycle execution is requested without a provider.

## Validation performed

The implementation was verified offline with fake transports and two distinct generic target shapes, registry target swap tests through the formal lifecycle runner, redaction/proof/replay tests, RuntimeContext integration, the full test suite, Ruff, compilation, neutrality scanning, direct-I/O inventory, G-02 runtime and precommit checks, secret scanning, and `git diff --check`. No public target, OAST endpoint, external network target, login flow, or destructive action was used.

## Open qualification gate

No official target qualification is claimed. A bounded, synthetic, loopback-only controlled lab is now available and has produced three isolated local runs with redacted target-backed observations, sealed/replayable ProofBundles, and independently recomputed local metrics. This evidence exercises the transport and proof pipeline only; it is not Juice Shop evidence and does not replace independent approval of the oracle, results, hashes, or frozen ground truth. Consequently official P10, P9, and VIP remain `NOT_QUALIFIED` even though the offline engineering and controlled-lab gates pass.

## Review checklist

| Review item | Expected decision |
|---|---|
| Shared core imports a target profile | Must fail neutrality checks |
| `auto` infers a target from URL or route | Forbidden; generic only |
| Non-generic profile without registered provider | Blocked/fail-closed |
| Runtime callback stored in state or bundle | Forbidden |
| Cross-origin or mutating discovery | Rejected |
| Raw body, cookie, header, DOM, or screenshot in proof | Redacted/rejected |
| HTTP 200 treated as a vulnerability | Forbidden |
| Live P10/VIP claim without governance and sealed runs | Forbidden |

## Source references

- [`shared/target_adapters.py`](../src/webpent/shared/target_adapters.py)
- [`shared/campaign_planner.py`](../src/webpent/shared/campaign_planner.py)
- [`benchmark/waptlab_campaign_profile.py`](../src/webpent/benchmark/waptlab_campaign_profile.py)
- [`adapters/generic_web/adapter.py`](../src/webpent/adapters/generic_web/adapter.py)
- [`shared/generic_web_contracts.py`](../src/webpent/shared/generic_web_contracts.py)
- [`shared/generic_case_runner.py`](../src/webpent/shared/generic_case_runner.py)
- [`shared/runtime.py`](../src/webpent/shared/runtime.py)
- [`scripts/check_generic_target_neutrality.py`](../scripts/check_generic_target_neutrality.py)
- [`audit/p10_gap_matrix_v1.md`](../audit/p10_gap_matrix_v1.md)
- [`audit/controlled_local_lab_oracle_review_packet_v1.json`](../audit/controlled_local_lab_oracle_review_packet_v1.json)
- [`audit/controlled_local_lab_review_manifest_v1.json`](../audit/controlled_local_lab_review_manifest_v1.json)
- [`scripts/run_controlled_local_lab_p10.py`](../scripts/run_controlled_local_lab_p10.py)
- [`scripts/replay_controlled_local_lab_p10.py`](../scripts/replay_controlled_local_lab_p10.py)
- [`scripts/verify_controlled_local_lab_metrics.py`](../scripts/verify_controlled_local_lab_metrics.py)

> The product architecture is generic; target-specific knowledge is an explicit plugin/profile concern.


# CQA v1 Detection Stress Summary

The required stress dimensions are represented by the additive IRTA v3 stress contracts: same HTTP status, misleading response, partial authorization, tenant confusion, privilege ambiguity, and workflow ordering.

The stress evaluator is fail-closed. An ambiguous response is not a vulnerability claim and cannot enter scoring without candidate/control observations, a causal predicate, a sealed ProofBundle, and verified replay.

The local stress regression gate passed. No external target, credential, mutation, or historical validator was used.

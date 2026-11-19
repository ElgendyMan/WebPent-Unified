"""webpent.deception — M6 (Part 4 §8): target-deception resistance and
evidence quality.

The deception fixture corpus (8 classes × 3 variants, ground truth:
never vulnerable), the deception-resistant causal verifier (three-
response protocol: baseline/candidate/control + repeatability; one-way
verdicts — nothing ever upgrades), the declared per-vuln-class evidence
contracts (required evidence, negative controls, limitations, replay),
the sqlmap internal differential extraction (the M0-documented
deferral: candidate-only markers over the baseline pair), and the
ATOBench-inspired benchmark with ground truth + blind set and sample
sizes.
"""
from webpent.deception.benchmark import (
    DeceptionBenchmarkReport,
    run_deception_benchmark,
)
from webpent.deception.fixtures import (
    DECEPTION_CLASSES,
    DeceptionFixture,
    build_fixture_corpus,
)
from webpent.deception.sqlmap_differential import (
    SqlmapDifferential,
    extract_sqlmap_differential,
)
from webpent.deception.validator_contracts import (
    CONTRACT_VERSION,
    EVIDENCE_CONTRACTS,
    EvidenceContract,
    validate_evidence_bundle,
)
from webpent.deception.verifier import VerificationOutcome, verify_responses

__all__ = [
    "CONTRACT_VERSION",
    "DECEPTION_CLASSES",
    "DeceptionBenchmarkReport",
    "DeceptionFixture",
    "EVIDENCE_CONTRACTS",
    "EvidenceContract",
    "SqlmapDifferential",
    "VerificationOutcome",
    "build_fixture_corpus",
    "extract_sqlmap_differential",
    "run_deception_benchmark",
    "validate_evidence_bundle",
    "verify_responses",
]

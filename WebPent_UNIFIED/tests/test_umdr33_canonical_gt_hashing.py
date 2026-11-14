"""UM-DR-33 §3.6 — canonical ground-truth identity hashing.

Regression coverage for the single canonical JSON serialization contract
(``webpent.shared.canonical_json``):

1. The contract is deterministic and its bytes are the documented compact
   form (sorted keys, no whitespace, ASCII-escaped, UTF-8).
2. Every mutation of the ground-truth manifest — vulnerability entry,
   control, out-of-scope rule, principal — changes the digest.
3. The two historical serialization paths (benchmark fixture vs provenance
   script) now produce the IDENTICAL canonical digest (the pre-UM-DR-33
   divergence that produced two hashes for one manifest can never
   silently return).
4. Non-ASCII content round-trips through the same bytes regardless of the
   process's ambient encoding.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from webpent.shared.canonical_json import (  # noqa: E402
    CANONICAL_JSON_CONTRACT_ID,
    canonical_json_bytes,
    canonical_json_sha256,
)


def _load_target():
    spec = importlib.util.spec_from_file_location(
        "campaign_identity_target_umdr33",
        ROOT / "benchmarks" / "campaign_identity_target.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


target = _load_target()


class TestCanonicalContract:
    def test_contract_id_is_stable_and_documented(self) -> None:
        assert CANONICAL_JSON_CONTRACT_ID == (
            "canonical-json/v1 (sort_keys, compact, ensure_ascii, utf-8)"
        )

    def test_bytes_are_compact_sorted_and_ascii(self) -> None:
        obj = {"b": 1, "a": {"d": [3, 2], "c": "x"}, "u": "é"}
        blob = canonical_json_bytes(obj)
        assert blob == b'{"a":{"c":"x","d":[3,2]},"b":1,"u":"\\u00e9"}'

    def test_determinism(self) -> None:
        for _ in range(3):
            assert canonical_json_sha256(target.GROUND_TRUTH_MANIFEST) == (
                canonical_json_sha256(target.GROUND_TRUTH_MANIFEST)
            )

    def test_canonical_digest_is_the_umdr33_declared_identity(self) -> None:
        """The canonical identity equals the historical compact-form hash
        (58684262…); the historical spaced form (b78ad5c6…) is retired."""
        assert canonical_json_sha256(target.GROUND_TRUTH_MANIFEST) == (
            "58684262356fa0c39fe7bde74cecec97f56746c2c019288249af120d72f87374"
        )
        assert canonical_json_sha256(target.GROUND_TRUTH_MANIFEST) != (
            "b78ad5c66f82108b759098cd7b31145a4b59b21cfc7223b9df9ce163956a583f"
        )


class TestMutationChangesDigest:
    """§3.6: 'mutation tests proving that changing a vulnerability,
    control, or fixture manifest changes the digest'."""

    def _assert_mutation_changes_digest(self, mutate) -> None:
        baseline = canonical_json_sha256(target.GROUND_TRUTH_MANIFEST)
        mutated = copy.deepcopy(target.GROUND_TRUTH_MANIFEST)
        mutate(mutated)
        assert canonical_json_sha256(mutated) != baseline

    def test_changing_a_vulnerability_entry(self) -> None:
        def mutate(m):
            m["vulnerabilities"]["V-IDOR-601"]["expected"] = "changed"
        self._assert_mutation_changes_digest(mutate)

    def test_removing_a_vulnerability(self) -> None:
        def mutate(m):
            del m["vulnerabilities"]["V-XTENANT-501"]
        self._assert_mutation_changes_digest(mutate)

    def test_changing_a_safe_control(self) -> None:
        def mutate(m):
            m["safe_controls"] = ["/api/tampered/control"]
        self._assert_mutation_changes_digest(mutate)

    def test_changing_a_never_merge_rule(self) -> None:
        def mutate(m):
            m["never_merge"][0] = ("/a", "/b", "tampered")
        self._assert_mutation_changes_digest(mutate)

    def test_changing_an_alias_pair(self) -> None:
        def mutate(m):
            m["alias_same_object"][0] = ("/x", "/y")
        self._assert_mutation_changes_digest(mutate)

    def test_changing_an_abstain_rule(self) -> None:
        def mutate(m):
            m["abstain"] = [("/api/products/tampered", "/api/products/78")]
        self._assert_mutation_changes_digest(mutate)

    def test_changing_out_of_scope_rules(self) -> None:
        def mutate(m):
            m["out_of_scope"] = ["/everything/*"]
        self._assert_mutation_changes_digest(mutate)

    def test_changing_any_vulnerability_attribute(self) -> None:
        def mutate(m):
            m["vulnerabilities"]["V-IDOR-601"]["kind"] = "tampered"
        self._assert_mutation_changes_digest(mutate)

    def test_deep_nested_change(self) -> None:
        def mutate(m):
            m.setdefault("nested", {}).setdefault("deep", {})["leaf"] = 1
        self._assert_mutation_changes_digest(mutate)


class TestCrossPathAgreement:
    """The two pre-UM-DR-33 divergent paths now agree exactly."""

    def test_fixture_hash_equals_canonical(self) -> None:
        assert target._gt_manifest_hash() == canonical_json_sha256(
            target.GROUND_TRUTH_MANIFEST
        )

    def test_provenance_identity_equals_canonical(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from experiment_provenance import capture_artifact_provenance  # noqa: E402

        record = capture_artifact_provenance(
            generator_script=Path(__file__),
            repo=ROOT,
            ground_truth_manifest=target.GROUND_TRUTH_MANIFEST,
            allow_dirty=True,
        )
        gt = record["ground_truth_manifest"]
        assert gt["identity"] == canonical_json_sha256(
            target.GROUND_TRUTH_MANIFEST
        )
        assert gt["contract"] == CANONICAL_JSON_CONTRACT_ID
        assert gt["identity"] == target._gt_manifest_hash()

    def test_benchmark_artifact_fields_agree(self) -> None:
        """The shipped benchmark artifact carries ONE manifest identity in
        both places (report field + provenance block)."""
        artifact = ROOT / "reports" / "qualification" / "umdr32_benchmark.json"
        if not artifact.exists():  # pragma: no cover - always present in repo
            pytest.skip("benchmark artifact not built in this checkout")
        import json

        data = json.loads(artifact.read_text())
        report_hash = data["ground_truth"]["manifest_sha256"]
        provenance_hash = data["provenance"]["ground_truth_manifest"]["identity"]
        assert report_hash == provenance_hash == (
            "58684262356fa0c39fe7bde74cecec97f56746c2c019288249af120d72f87374"
        )


class TestUnicodeStability:
    def test_non_ascii_serialization_is_ambient_independent(self) -> None:
        obj = {"name": "ténant-ünicode", "payload": "مرحبا"}
        assert canonical_json_bytes(obj) == canonical_json_bytes(
            json.loads(canonical_json_bytes(obj).decode("utf-8"))
        )

    def test_no_raw_non_ascii_bytes(self) -> None:
        blob = canonical_json_bytes({"k": "éمرحبا"})
        blob.decode("ascii")  # must not raise — ensure_ascii contract


import json  # noqa: E402  (used by TestUnicodeStability)

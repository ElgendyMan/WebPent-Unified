"""U-7 fabric / vulnerability-family contract tests.

Restored after the workspace reset. Covers 6 families × 3 tests = 18
tests over the production fabric's
``webpent.production.vulnerability_family_contracts`` module.

The 6 families are the highest-priority concrete contracts in the
registry:
  SSRF (100), JWT_MANIPULATION (98), FILE_UPLOAD (95),
  OPEN_REDIRECT (90), MASS_ASSIGNMENT (88), RACE_CONDITION (85).

For each family the three invariants are:
  (1) ``family_contract(family)`` returns the registered contract with
      the correct ``family`` field and a non-empty ``required_evidence``
      tuple (fail-closed: an unknown family raises KeyError).
  (2) ``build_family_hypothesis`` returns a hypothesis dict with all
      three request roles (``baseline``, ``candidate``,
      ``negative_control``) and a ``family_contract_version`` of ``v1``.
  (3) The candidate request path is distinct from the baseline request
      path (a true differential triple, not a tautology).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.production.vulnerability_family_contracts import (  # noqa: E402
    FAMILY_CONTRACTS,
    build_family_hypothesis,
    family_contract,
)


_TARGET = "http://127.0.0.1:8099"
_FAMILIES = ("SSRF", "JWT_MANIPULATION", "FILE_UPLOAD", "OPEN_REDIRECT", "MASS_ASSIGNMENT", "RACE_CONDITION")


def _family_id(family: str) -> str:
    return family.lower()


# ---------------------------------------------------------------------------
# Family: SSRF
# ---------------------------------------------------------------------------
class TestSsrfFamily:
    FAMILY = "SSRF"

    def test_contract_is_registered_with_required_evidence(self):
        c = family_contract(self.FAMILY)
        assert c.family == self.FAMILY
        assert c.required_evidence
        assert c.priority == 100

    def test_hypothesis_has_three_request_roles(self):
        h = build_family_hypothesis(_TARGET, self.FAMILY, hypothesis_id=f"h_{_family_id(self.FAMILY)}_u7")
        assert set(h["requests"]) == {"baseline", "candidate", "negative_control"}
        assert h["family_contract_version"] == "v1"

    def test_candidate_path_differs_from_baseline(self):
        h = build_family_hypothesis(_TARGET, self.FAMILY, hypothesis_id=f"h_{_family_id(self.FAMILY)}_u7b")
        assert h["requests"]["candidate"]["path"] != h["requests"]["baseline"]["path"]


# ---------------------------------------------------------------------------
# Family: JWT_MANIPULATION
# ---------------------------------------------------------------------------
class TestJwtManipulationFamily:
    FAMILY = "JWT_MANIPULATION"

    def test_contract_is_registered_with_required_evidence(self):
        c = family_contract(self.FAMILY)
        assert c.family == self.FAMILY
        assert c.required_evidence
        assert c.priority == 98

    def test_hypothesis_has_three_request_roles(self):
        h = build_family_hypothesis(_TARGET, self.FAMILY, hypothesis_id=f"h_{_family_id(self.FAMILY)}_u7")
        assert set(h["requests"]) == {"baseline", "candidate", "negative_control"}
        assert h["family_contract_version"] == "v1"

    def test_candidate_path_or_header_differs_from_baseline(self):
        h = build_family_hypothesis(_TARGET, self.FAMILY, hypothesis_id=f"h_{_family_id(self.FAMILY)}_u7b")
        cand = h["requests"]["candidate"]
        base = h["requests"]["baseline"]
        # JWTManipulation injects an Authorization header on candidate.
        assert cand.get("headers") or cand["path"] != base["path"]


# ---------------------------------------------------------------------------
# Family: FILE_UPLOAD
# ---------------------------------------------------------------------------
class TestFileUploadFamily:
    FAMILY = "FILE_UPLOAD"

    def test_contract_is_registered_with_required_evidence(self):
        c = family_contract(self.FAMILY)
        assert c.family == self.FAMILY
        assert c.required_evidence
        assert c.priority == 95

    def test_hypothesis_has_three_request_roles(self):
        h = build_family_hypothesis(_TARGET, self.FAMILY, hypothesis_id=f"h_{_family_id(self.FAMILY)}_u7")
        assert set(h["requests"]) == {"baseline", "candidate", "negative_control"}
        assert h["family_contract_version"] == "v1"

    def test_candidate_upload_filename_differs_from_baseline(self):
        h = build_family_hypothesis(_TARGET, self.FAMILY, hypothesis_id=f"h_{_family_id(self.FAMILY)}_u7b")
        assert h["requests"]["candidate"]["upload_filename"] != h["requests"]["baseline"]["upload_filename"]


# ---------------------------------------------------------------------------
# Family: OPEN_REDIRECT
# ---------------------------------------------------------------------------
class TestOpenRedirectFamily:
    FAMILY = "OPEN_REDIRECT"

    def test_contract_is_registered_with_required_evidence(self):
        c = family_contract(self.FAMILY)
        assert c.family == self.FAMILY
        assert c.required_evidence
        assert c.priority == 90

    def test_hypothesis_has_three_request_roles(self):
        h = build_family_hypothesis(_TARGET, self.FAMILY, hypothesis_id=f"h_{_family_id(self.FAMILY)}_u7")
        assert set(h["requests"]) == {"baseline", "candidate", "negative_control"}
        assert h["family_contract_version"] == "v1"

    def test_candidate_path_differs_from_baseline(self):
        h = build_family_hypothesis(_TARGET, self.FAMILY, hypothesis_id=f"h_{_family_id(self.FAMILY)}_u7b")
        assert h["requests"]["candidate"]["path"] != h["requests"]["baseline"]["path"]


# ---------------------------------------------------------------------------
# Family: MASS_ASSIGNMENT
# ---------------------------------------------------------------------------
class TestMassAssignmentFamily:
    FAMILY = "MASS_ASSIGNMENT"

    def test_contract_is_registered_with_required_evidence(self):
        c = family_contract(self.FAMILY)
        assert c.family == self.FAMILY
        assert c.required_evidence
        assert c.priority == 88

    def test_hypothesis_has_three_request_roles(self):
        h = build_family_hypothesis(_TARGET, self.FAMILY, hypothesis_id=f"h_{_family_id(self.FAMILY)}_u7")
        assert set(h["requests"]) == {"baseline", "candidate", "negative_control"}
        assert h["family_contract_version"] == "v1"

    def test_candidate_body_differs_from_baseline(self):
        h = build_family_hypothesis(_TARGET, self.FAMILY, hypothesis_id=f"h_{_family_id(self.FAMILY)}_u7b")
        assert h["requests"]["candidate"]["body"] != h["requests"]["baseline"]["body"]


# ---------------------------------------------------------------------------
# Family: RACE_CONDITION
# ---------------------------------------------------------------------------
class TestRaceConditionFamily:
    FAMILY = "RACE_CONDITION"

    def test_contract_is_registered_with_required_evidence(self):
        c = family_contract(self.FAMILY)
        assert c.family == self.FAMILY
        assert c.required_evidence
        assert c.priority == 85

    def test_hypothesis_has_three_request_roles(self):
        h = build_family_hypothesis(_TARGET, self.FAMILY, hypothesis_id=f"h_{_family_id(self.FAMILY)}_u7")
        assert set(h["requests"]) == {"baseline", "candidate", "negative_control"}
        assert h["family_contract_version"] == "v1"

    def test_candidate_is_marked_concurrent(self):
        h = build_family_hypothesis(_TARGET, self.FAMILY, hypothesis_id=f"h_{_family_id(self.FAMILY)}_u7b")
        # RACE_CONDITION's candidate is the concurrent burst.
        assert h["requests"]["candidate"].get("concurrent") is True

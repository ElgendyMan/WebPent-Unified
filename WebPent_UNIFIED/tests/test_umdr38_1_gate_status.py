"""UM-DR-38.1 Phase 4 — canonical gate-status regression tests.

The UM-DR-38 acceptance matrix carried G38-07 with a computed
``exit_code = 1`` alongside a HARDCODED ``status = PASS`` — an
acceptance report contradicting its own execution evidence. These
tests pin the fixed contract:

    exit 0    -> PASS
    exit != 0 -> FAIL
    not run   -> NOT_RUN
    blocked   -> BLOCKED_EXTERNAL_DEPENDENCY

and that the aggregates (G38-07 over all mandatory gates, G38-12 over
the security set) follow their members: ANY member failure makes the
aggregate FAIL — a failing ruff-ratchet can never yield a PASS.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import umdr38_closure  # noqa: E402


def test_exit_zero_is_pass() -> None:
    assert umdr38_closure._canonical_status(0) == "PASS"


def test_exit_one_and_two_are_fail() -> None:
    assert umdr38_closure._canonical_status(1) == "FAIL"
    assert umdr38_closure._canonical_status(2) == "FAIL"


def test_none_is_not_run() -> None:
    assert umdr38_closure._canonical_status(None) == "NOT_RUN"


def test_blocked_is_blocked() -> None:
    assert umdr38_closure._canonical_status(
        None, blocked=True) == "BLOCKED_EXTERNAL_DEPENDENCY"
    assert umdr38_closure._canonical_status(
        0, blocked=True) == "BLOCKED_EXTERNAL_DEPENDENCY"


def _member(name: str, exit_code: int | None) -> dict:
    return {"gate": name, "exit_code": exit_code}


def test_g38_07_cannot_be_pass_when_ruff_exit_is_one() -> None:
    members = [_member(n, 0) for n in (
        "state-contract", "orchestrator-construction-authority",
        "isolation-denylist", "vault-import-authority",
        "test-count-floor", "build-info-honesty", "direct-io-inventory",
        "deps-cve-gate", "secret-scan", "bandit-high",
        "coverage-ratchet", "vip-audit-gap")]
    members.append(_member("ruff-ratchet", 1))
    exit_code, status = umdr38_closure._aggregate_status(members)
    assert exit_code == 1
    assert status == "FAIL", (
        "G38-07 MUST be FAIL when any mandatory gate (ruff-ratchet) "
        "exits 1 — the UM-DR-38 matrix carried exit_code=1 with a "
        "hardcoded PASS")


def test_g38_07_passes_only_when_every_member_exits_zero() -> None:
    members = [_member(n, 0) for n in (
        "state-contract", "orchestrator-construction-authority",
        "isolation-denylist", "vault-import-authority",
        "test-count-floor", "build-info-honesty", "direct-io-inventory",
        "ruff-ratchet", "deps-cve-gate", "secret-scan", "bandit-high",
        "coverage-ratchet", "vip-audit-gap")]
    exit_code, status = umdr38_closure._aggregate_status(members)
    assert exit_code == 0 and status == "PASS"


def test_g38_07_is_not_run_when_no_member_ran() -> None:
    exit_code, status = umdr38_closure._aggregate_status([])
    assert exit_code is None and status == "NOT_RUN"


def test_g38_12_follows_the_security_gates() -> None:
    ok = [_member(n, 0) for n in ("ruff-ratchet", "deps-cve-gate",
                                  "secret-scan", "bandit-high")]
    exit_code, status = umdr38_closure._aggregate_status(ok)
    assert status == "PASS"
    ok[1]["exit_code"] = 2
    exit_code, status = umdr38_closure._aggregate_status(ok)
    assert exit_code == 1 and status == "FAIL"


def test_matrix_counts_derived_from_elements() -> None:
    matrix = [{"status": "PASS"}, {"status": "PASS"},
              {"status": "FAIL"}, {"status": "NOT_RUN"},
              {"status": "BLOCKED_EXTERNAL_DEPENDENCY"}]
    counts = umdr38_closure._matrix_counts(matrix)
    assert counts == {"PASS": 2, "FAIL": 1, "NOT_RUN": 1,
                      "BLOCKED_EXTERNAL_DEPENDENCY": 1}


def test_final_decision_rules() -> None:
    def m(statuses: list[str]) -> list[dict]:
        return [{"status": s} for s in statuses]

    assert umdr38_closure._final_decision(
        m(["FAIL"]), remote_verified=False) == "PARTIALLY_VERIFIED"
    assert umdr38_closure._final_decision(
        m(["NOT_RUN"]), remote_verified=False) == "PARTIALLY_VERIFIED"
    blocked_only = m(["BLOCKED_EXTERNAL_DEPENDENCY"] * 2
                     + ["PASS"] * 28)
    assert umdr38_closure._final_decision(
        blocked_only, remote_verified=False) == (
        "COMPLETE_LOCAL_REMOTE_PUBLICATION_BLOCKED")
    all_pass = m(["PASS"] * 30)
    assert umdr38_closure._final_decision(
        all_pass, remote_verified=True) == "COMPLETE_VERIFIED"
    assert umdr38_closure._final_decision(
        all_pass, remote_verified=False) == "PARTIALLY_VERIFIED", (
        "COMPLETE_VERIFIED requires the ACTUAL remote verification — "
        "never chosen because the work took long")

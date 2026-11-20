"""GOED v1.8.4 — Phase 5: Replay Integrity Verification
Tests the STRICT replay protocol (v1.8.4):
  CONFIRMED → CONFIRMED: PASS only when ALL of:
    verdict_match AND evidence_match AND seal_valid AND seal_match AND replay_executed
  CONFIRMED → INCONCLUSIVE: MUST FAIL replay validation
  Seal equality ALONE: MUST NOT make replay valid

Produces: reports/goed_v1_8_4/replay_integrity_v184.json
"""

import hashlib
import json
import os
import signal
import subprocess
import sys
import time

import httpx

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from webpent.cqa_v2 import guarded_causal_evaluate
from webpent.cqa_v2.proof_bundle_builder import (
    CompleteProofBundle,
    build_complete_proof_bundle,
)
from webpent.cqa_v2.replay_verifier import verify_replay

REPORTS = os.path.join(_ROOT, "reports", "goed_v1_8_4")
os.makedirs(REPORTS, exist_ok=True)


def _sd(t):
    return hashlib.sha256(t.encode()).hexdigest()


def make_obs(r, p):
    return {
        "status_code": r.status_code,
        "body_length": len(r.text),
        "semantic_digest": _sd(r.text),
        "response_shape": "json" if r.text.strip().startswith("{") else "text",
        "request": {"method": "GET", "path": p.split("?")[0], "header_names": ["X-Actor"]},
        "headers": {k.lower(): v for k, v in r.headers.items()},
        "body_preview": r.text[:200],
    }


def start_target(port=9210, timeout=15):
    script = os.path.join(_ROOT, "benchmarks", "differential_v2", "differential_target_v2.py")
    proc = subprocess.Popen(
        [sys.executable, script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=os.environ.copy(),
        preexec_fn=os.setsid,
    )
    for _ in range(int(timeout * 10)):
        try:
            httpx.get(f"http://127.0.0.1:{port}/", timeout=0.2)
            return proc, port
        except Exception:
            time.sleep(0.1)
    return proc, port


def stop_target(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def build_confirmed_bundle(client, base_url):
    """Build a CompleteProofBundle for a genuinely CONFIRMED case."""
    # Use differential_v2 paths that produce CONFIRMED
    rb = client.get("/dv2/easy/own_1", headers={"X-Actor": "attacker"})
    rc = client.get("/dv2/easy/target_1", headers={"X-Actor": "attacker"})
    rctrl = client.get("/dv2/easy/ctrl_1", headers={"X-Actor": "attacker"})

    b = make_obs(rb, "/dv2/easy/own_1")
    c = make_obs(rc, "/dv2/easy/target_1")
    ctrl = make_obs(rctrl, "/dv2/easy/ctrl_1")

    causal_result = guarded_causal_evaluate(b, c, ctrl)
    assert causal_result.verdict.value == "CONFIRMED", "Expected CONFIRMED case"

    bundle = build_complete_proof_bundle(
        target_identity="dv2_easy_localhost_9210",
        case_identity="dv2_replay_test_001",
        baseline=b,
        candidate=c,
        negative_control=ctrl,
        causal_result=causal_result,
        semantic_evidence={
            "precondition": "read_only_no_state_mutation",
            "vulnerability_class": "ownership_boundary_violation",
        },
        source_provenance={"benchmark": "differential_v2", "family": "easy"},
        runtime_provenance={"engine": "cqa_v2_strict", "actor": "replay_test_harness"},
    )
    return bundle, causal_result


def test_confirmed_to_confirmed(client, base_url):
    """Test 1: CONFIRMED → CONFIRMED must pass strict replay."""
    bundle, _ = build_confirmed_bundle(client, base_url)
    result = verify_replay(bundle)

    checks = {
        "verdict_match": result.verdict_match,
        "evidence_match": result.evidence_match,
        "seal_valid": result.seal_valid,
        "seal_match": result.seal_match,
        "replay_executed": result.replay_executed,
        "replay_valid_strict": result.replay_valid,
        "original_verdict": result.original_verdict,
        "replay_verdict": result.replay_verdict,
    }
    passed = all(
        [
            result.verdict_match,
            result.evidence_match,
            result.seal_valid,
            result.seal_match,
            result.replay_executed,
            result.replay_valid,
        ]
    )
    return passed, checks


def test_confirmed_to_inconclusive(client, base_url):
    """Test 2: CONFIRMED → INCONCLUSIVE must FAIL replay validation.
    We simulate this by tampering with the candidate observation so that
    replayed causal evaluation gives a different verdict.
    """
    bundle, _ = build_confirmed_bundle(client, base_url)

    # Tamper: modify candidate observation to look like baseline (same semantics)
    tampered = CompleteProofBundle.from_json(bundle.to_json())
    # Make candidate identical to baseline — causal guard will say CLEAN, not CONFIRMED
    tampered.candidate_observation = dict(tampered.baseline_observation)
    tampered.candidate_observation["request"] = {"path": "/dv2/easy/target_1", "method": "GET"}
    # Recompute digests and seal to make seal_valid=True but verdict different
    tampered.evidence_digests = {}
    tampered.deterministic_seal = ""
    tampered.__post_init__()

    # Now verify replay — seal will be valid (matches tampered content),
    # but verdict will differ from original CONFIRMED
    result = verify_replay(tampered)

    # The original verdict was CONFIRMED, replay should give CLEAN/INCONCLUSIVE
    verdict_changed = result.original_verdict != result.replay_verdict
    replay_valid_is_false = not result.replay_valid

    checks = {
        "original_verdict": result.original_verdict,
        "replay_verdict": result.replay_verdict,
        "verdict_changed": verdict_changed,
        "seal_valid_still": result.seal_valid,  # Seal valid for tampered content
        "seal_match": result.seal_match,  # Seal matches tampered content
        "replay_valid_FALSE": replay_valid_is_false,
        "replay_valid_value": result.replay_valid,
    }
    passed = verdict_changed and replay_valid_is_false and result.seal_valid
    return passed, checks


def test_seal_alone_not_sufficient(client, base_url):
    """Test 3: Seal equality ALONE must NOT make replay valid.
    Create a bundle where seal matches and is valid, but verdict differs.
    """
    bundle, _ = build_confirmed_bundle(client, base_url)

    # Force a verdict change without breaking the seal:
    # Build a new bundle with different content but we manually set the seal
    # to match the original. This simulates an attacker who copies a seal.
    tampered = CompleteProofBundle.from_json(bundle.to_json())
    # Change candidate to baseline-like
    tampered.candidate_observation = dict(tampered.baseline_observation)
    tampered.candidate_observation["request"] = {"path": "/dv2/easy/target_1", "method": "GET"}
    # Recompute digests
    tampered.evidence_digests = {}
    # But KEEP the original seal (don't recompute it)
    original_seal = bundle.deterministic_seal

    # Now verify_seal() will recompute from tampered content → won't match original
    seal_valid_after_tamper = tampered.verify_seal()

    # Manually force the seal to match original (simulating seal forgery claim)
    tampered.deterministic_seal = original_seal
    # verify_seal() recomputes — still won't match because content changed
    seal_verify_result = tampered.verify_seal()

    # Now run full replay
    result = verify_replay(tampered)

    checks = {
        "original_seal": original_seal[:16] + "...",
        "seal_valid_after_content_tamper": seal_valid_after_tamper,
        "manual_seal_override_verify": seal_verify_result,
        "replay_verdict": result.replay_verdict,
        "verdict_match": result.verdict_match,
        "seal_match": result.seal_match,  # We forced seal to match
        "seal_valid": result.seal_valid,  # verify_seal() recomputes → False
        "replay_valid": result.replay_valid,
        "seal_match_but_replay_valid_false": (result.seal_match and not result.replay_valid),
    }

    # Key assertion: even if we claim seal matches, verify_seal() catches it
    # and replay_valid is False
    passed = (not seal_valid_after_tamper) and (not result.replay_valid)
    return passed, checks


def run_replay_tests():
    print("=" * 60)
    print("GOED v1.8.4 — Phase 5: Replay Integrity Verification")
    print("=" * 60)

    proc, port = start_target()
    time.sleep(0.3)
    base_url = f"http://127.0.0.1:{port}"
    client = httpx.Client(timeout=10, base_url=base_url)

    results = {}

    try:
        print("\n[Test 1] CONFIRMED → CONFIRMED (strict replay)...")
        t1_passed, t1_checks = test_confirmed_to_confirmed(client, base_url)
        results["test_1_confirmed_to_confirmed"] = {
            "passed": t1_passed,
            "checks": t1_checks,
            "description": "CONFIRMED case replays to CONFIRMED — all 5 conditions must pass",
        }
        print(f"  {'✅ PASS' if t1_passed else '❌ FAIL'}")
        for k, v in t1_checks.items():
            print(f"    {k}: {v}")

        print("\n[Test 2] CONFIRMED → INCONCLUSIVE (must FAIL replay)...")
        t2_passed, t2_checks = test_confirmed_to_inconclusive(client, base_url)
        results["test_2_confirmed_to_inconclusive"] = {
            "passed": t2_passed,
            "checks": t2_checks,
            "description": "Tampered content changes verdict — replay_valid MUST be False",
        }
        print(f"  {'✅ PASS' if t2_passed else '❌ FAIL'}")
        for k, v in t2_checks.items():
            print(f"    {k}: {v}")

        print("\n[Test 3] Seal equality ALONE is NOT sufficient...")
        t3_passed, t3_checks = test_seal_alone_not_sufficient(client, base_url)
        results["test_3_seal_alone_insufficient"] = {
            "passed": t3_passed,
            "checks": t3_checks,
            "description": "Tampered content + matching seal claim → verify_seal catches it, replay_valid=False",
        }
        print(f"  {'✅ PASS' if t3_passed else '❌ FAIL'}")
        for k, v in t3_checks.items():
            print(f"    {k}: {v}")

        overall = all(r["passed"] for r in results.values())
        results["overall_pass"] = overall
        results["phase"] = "5_replay_integrity"
        results["protocol_version"] = "v1.8.4_STRICT"
        results["strict_rule"] = (
            "replay_valid = verdict_match AND evidence_match AND seal_valid AND seal_match AND replay_executed"
        )

        out_path = os.path.join(REPORTS, "replay_integrity_v184.json")
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\n{'=' * 60}")
        print(f"Overall: {'✅ ALL TESTS PASS' if overall else '⚠️ SOME TESTS FAILED'}")
        print(f"Report: {out_path}")

    finally:
        client.close()
        stop_target(proc)


if __name__ == "__main__":
    run_replay_tests()

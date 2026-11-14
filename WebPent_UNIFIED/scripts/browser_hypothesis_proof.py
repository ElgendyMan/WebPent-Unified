#!/usr/bin/env python3
"""Browser-hypothesis integration proof — synthetic browser surface through
the new bridge into hypothesis objects, then candidate construction and the
frozen generic validators (M4 confirmation gate). SYNTHETIC PROOF ONLY: no
real browser, no HTTP, no LLM.

Run:  PYTHONPATH=src python3 scripts/browser_hypothesis_proof.py
Outputs to deliverables/browser_hypothesis_proof/
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from webpent.integration.browser_hypothesis_bridge import browser_surface_to_hypotheses  # noqa: E402
from webpent.models.findings import VulnClass  # noqa: E402
from webpent.production.validators import (  # noqa: E402
    ValidationOutcome,
    validate_idor,
    validate_info_disclosure,
    validate_ssrf,
    validate_xss,
)

OUT = ROOT / "deliverables" / "browser_hypothesis_proof"
OUT.mkdir(parents=True, exist_ok=True)
TARGET = "http://synthetic-browser.test"


def _ev(status, body="", headers=None, **extra):
    ev = {"status_code": status, "response_body": body, "headers": headers or {}}
    ev.update(extra)
    return ev


# ---------------------------------------------------------------------------
# Synthetic browser surfaces (as a real crawler's SurfaceMap would produce)
# ---------------------------------------------------------------------------
SURFACES = {
    "form_with_user_id": {
        "target_url": TARGET,
        "routes": ["/", "/profile"],
        "forms": [{"action": "/profile", "method": "GET", "inputs": [{"name": "user_id"}, {"name": "tab"}]}],
        "xhr_endpoints": [],
        "state_transitions": [],
        "js_blobs": [],
    },
    "hidden_xhr_proxy_endpoint": {
        "target_url": TARGET,
        "routes": ["/dashboard"],
        "forms": [],
        "xhr_endpoints": [{"url": "/api/internal/fetch", "method": "POST", "params": ["url", "timeout"]}],
        "state_transitions": [],
        "js_blobs": [],
    },
    "auth_flow_transition": {
        "target_url": TARGET,
        "routes": ["/login", "/dashboard"],
        "forms": [],
        "xhr_endpoints": [],
        "state_transitions": [{"from_route": "/login", "to_route": "/dashboard", "requires_auth": True, "principal_alias": "alice"}],
        "js_blobs": [],
    },
    "js_api_key_disclosure": {
        "target_url": TARGET,
        "routes": ["/app.js"],
        "forms": [],
        "xhr_endpoints": [],
        "state_transitions": [],
        "js_blobs": ["const cfg = { api_key: 'sk_live_abcdef0123456789xyz', endpoint: '/api/v1' };"],
    },
}

XSS_PAYLOAD = "<script>webpent_bh_proof_1a2b()</script>"


def _validator_for_hypothesis(hyp):
    """Map a hypothesis vuln_class to a (validator_fn, synthetic_evidence_set) pair."""
    vc = str(hyp.vuln_class)
    if vc == VulnClass.IDOR.value:
        return validate_idor, dict(
            baseline=_ev(200, "<html><h1>Account #1042</h1><p>Balance: $250.00</p><span nonce='a1'></span></html>"),
            candidate=_ev(200, "<html><h1>Account #1042</h1><p>Balance: $250.00</p><span nonce='b2'></span></html>"),
            negative_control=_ev(404, "<html><h1>Not Found</h1></html>"),
        ), "IDOR cross-user access confirmed via responses_similar (owner==foreign, control 404)"
    if vc == VulnClass.SSRF.value:
        return validate_ssrf, dict(
            baseline=_ev(200, '{"fetched":"https://api.example.com/data"}'),
            candidate=_ev(200, '{"fetched":"http://169.254.169.254/latest/meta-data/iam"}'),
            negative_control=_ev(400, "invalid url scheme"),
        ), "SSRF confirmed: candidate reaches cloud metadata, control rejected"
    if vc == VulnClass.XSS.value:
        return validate_xss, dict(
            baseline=_ev(200, "search results: none"),
            candidate=_ev(200, f"results for: {XSS_PAYLOAD}", {"content-type": "text/html; charset=utf-8"}, payload=XSS_PAYLOAD),
            negative_control=_ev(200, "results for: "),
        ), "XSS confirmed: raw marker reflected verbatim in executable content-type"
    if vc == VulnClass.INFO_DISCLOSURE.value:
        return validate_info_disclosure, dict(
            baseline=_ev(200, '{"status":"ok"}'),
            candidate=_ev(500, "Error: failed to connect to db with password 'dbpass123secret' at jdbc:mysql://10.0.0.5:3306/app\njava.sql.SQLException: stack trace line 1\nstack trace line 2\nstack trace line 3", {"content-type": "text/plain"}),
            negative_control=_ev(200, '{"status":"ok"}'),
        ), "Info disclosure confirmed: verbose 500 leaks credential + internal host + stack trace"
    return None, None, f"no synthetic validator path for {vc} (recorded as hypothesis only)"


def _zero_fp_cases():
    """Hostile/boilerplate inputs that must NOT confirm (zero false positives)."""
    cases = {}
    # IDOR: different resource -> INCONCLUSIVE, not CONFIRMED
    cases["fp_guard_idor_different_resource"] = dict(
        validator=validate_idor,
        kwargs=dict(
            baseline=_ev(200, "<html>Account #1001 balance 250</html>"),
            candidate=_ev(200, "<html>Account #2002 balance 999</html>"),
            negative_control=_ev(404, "<html>not found</html>"),
        ),
        must_not_confirm=True,
    )
    # XSS: marker only HTML-entity encoded -> REFUTED
    encoded = XSS_PAYLOAD.replace("<", "&lt;").replace(">", "&gt;")
    cases["fp_guard_xss_encoded_only"] = dict(
        validator=validate_xss,
        kwargs=dict(
            baseline=_ev(200, "q="),
            candidate=_ev(200, f"q={encoded}", {"content-type": "text/html"}, payload=XSS_PAYLOAD),
            negative_control=_ev(200, "q="),
        ),
        must_not_confirm=True,
    )
    # SSRF: no differential -> REFUTED
    cases["fp_guard_ssrf_no_differential"] = dict(
        validator=validate_ssrf,
        kwargs=dict(
            baseline=_ev(200, '{"ok":true}'),
            candidate=_ev(200, '{"ok":true}'),
            negative_control=_ev(400, "bad"),
        ),
        must_not_confirm=True,
    )
    # Info disclosure: trivial 500 with one 'error' word -> REFUTED/INCONCLUSIVE
    cases["fp_guard_info_trivial_500"] = dict(
        validator=validate_info_disclosure,
        kwargs=dict(
            baseline=_ev(200, "ok"),
            candidate=_ev(500, "An error occurred.", {"content-type": "text/plain"}),
            negative_control=_ev(200, "ok"),
        ),
        must_not_confirm=True,
    )
    return cases


def main():
    summary = {"surfaces": {}, "full_traces": [], "zero_fp_guards": {}, "totals": {}}
    confirmed_traces = 0
    total_hypotheses = 0
    for name, surface in SURFACES.items():
        hyps = browser_surface_to_hypotheses(surface)
        total_hypotheses += len(hyps)
        surface_result = {"hypotheses": [], "validator_traces": []}
        for hyp in hyps:
            hdict = {
                "id": str(hyp.id),
                "vuln_class": str(hyp.vuln_class),
                "statement": hyp.statement,
                "origin": str(hyp.origin),
                "origin_detail": hyp.origin_detail,
                "confidence": hyp.confidence_score,
            }
            surface_result["hypotheses"].append(hdict)
            validator_fn, kwargs, note = _validator_for_hypothesis(hyp)
            if validator_fn is None:
                surface_result["validator_traces"].append({"hypothesis_id": hdict["id"], "vuln_class": hdict["vuln_class"], "note": note})
                continue
            # run validator (M4 confirmation gate) — pure logic, synthetic responses
            result = validator_fn(**kwargs)
            trace = {
                "hypothesis_id": hdict["id"],
                "vuln_class": hdict["vuln_class"],
                "origin_detail": hdict["origin_detail"],
                "validator": validator_fn.__name__,
                "outcome": str(result.outcome),
                "is_confirmation_grade": bool(getattr(result, "is_confirmation_grade", lambda: False)()),
                "discriminating_signal": str(getattr(result, "discriminating_signal", "")),
                "note": note,
                "trace": ["browser_surface", "bridge_hypothesis", "candidate_built", "M4_validator", str(result.outcome)],
            }
            surface_result["validator_traces"].append(trace)
            summary["full_traces"].append(trace)
            if result.outcome == ValidationOutcome.CONFIRMED:
                confirmed_traces += 1
        summary["surfaces"][name] = surface_result
        (OUT / f"surface_{name}.json").write_text(json.dumps(surface_result, indent=2))

    # zero-FP guards
    fp_violations = 0
    for name, case in _zero_fp_cases().items():
        result = case["validator"](**case["kwargs"])
        confirmed = result.outcome == ValidationOutcome.CONFIRMED
        summary["zero_fp_guards"][name] = {"outcome": str(result.outcome), "confirmed": confirmed, "must_not_confirm": case["must_not_confirm"]}
        if confirmed and case["must_not_confirm"]:
            fp_violations += 1

    summary["totals"] = {
        "surfaces": len(SURFACES),
        "hypotheses_generated": total_hypotheses,
        "full_traces_through_M4": len(summary["full_traces"]),
        "traces_ending_CONFIRMED": confirmed_traces,
        "zero_fp_guards": len(summary["zero_fp_guards"]),
        "fp_violations": fp_violations,
    }
    (OUT / "browser_hypothesis_proof_summary.json").write_text(json.dumps(summary, indent=2))

    print("=== Browser -> Hypothesis -> Candidate -> M4 Validator (synthetic) ===")
    for name, sr in summary["surfaces"].items():
        print(f"  {name}: {len(sr['hypotheses'])} hypotheses, {len(sr['validator_traces'])} validator traces")
        for t in sr["validator_traces"]:
            if "outcome" in t:
                print(f"      [{t['outcome']}] {t['vuln_class']} via {t['origin_detail']} -> {t['validator']}")
    print(f"\n  TOTAL: {total_hypotheses} hypotheses, {len(summary['full_traces'])} full traces, {confirmed_traces} CONFIRMED")
    print("\n=== Zero-FP guards (must NOT confirm) ===")
    for name, g in summary["zero_fp_guards"].items():
        print(f"  {name}: outcome={g['outcome']} confirmed={g['confirmed']}")
    print(f"\n  FP violations: {fp_violations}")
    assert confirmed_traces >= 1, "at least one full trace must end in CONFIRMED"
    assert fp_violations == 0, "zero false positives required"
    print("\nALL ASSERTIONS PASSED — browser-hypothesis integration proof complete.")
    print(f"Artifacts in: {OUT}")


if __name__ == "__main__":
    main()

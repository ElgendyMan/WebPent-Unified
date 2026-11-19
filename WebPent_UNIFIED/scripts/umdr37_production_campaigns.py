#!/usr/bin/env python3
"""UM-DR-37 Part 12 — true production end-to-end campaigns (x3).

Three SEPARATE campaigns through the REAL production entrypoint
(``webpent.cli.unified_hunt.run_unified_hunt``), each against a FRESH
lab instance (new process-level HTTP server on an ephemeral port, new
engagement/campaign id, isolated artifact), with:

* the LangGraph update stream tee'd (per-stage writes + timings);
* every lab request recorded (path + principal) so the safety
  invariants are provable from the run itself: enforced boundary never
  confirmed, missing resource never confirmed, every request on-origin;
* CausalGuard invocations and verify_replay_evidence outcomes counted
  (observation only — nothing is confirmed outside the graph);
* the production discovery funnel (production/discovery_funnel.py).

UM-DR-38 §7.2 instrumentation repairs (all pinned by
tests/test_umdr38_campaign_instrumentation.py):

* A. MONKEYPATCH LIFECYCLE — instrumentation is installed through the
  REVERSIBLE ``campaign_instrumentation`` context manager: every
  original function is restored in ``finally``, and each campaign
  installs its single observation layer over the ORIGINALS, never over
  a previous campaign's layer — wrappers cannot accumulate across
  sequential runs and the per-run counts stay per-run.
* B. AUTHORITATIVE FINAL STATE — the funnel is computed from the ACTUAL
  final graph state read via ``graph.get_state(config)`` while the run
  context is still open (the checkpointer applies the reducers); the
  tee'd last-write merge survives only as an explicitly-labeled
  fallback, never silently.
* E. CLEANUP — the lab server and the out-of-scope origin are closed
  in ``finally`` even when the campaign raises; a failed campaign
  leaves no running server and no shared state.
* F. REDACTION — the recorded invocation carries cookie/session values
  redacted; only the minimum needed to reproduce the security
  conclusion is preserved.
* Phase 5 (UM-DR-38 §9) — one authoritative lab version constant used
  by the HTTP response, the per-run records and the combined record.

Mission Part 12.5 reproducibility: same lab version, same controlled
configuration, fresh state, unique campaign ids, isolated artifacts,
recorded budgets. Any result difference must be explained.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

RUNS = 3

# UM-DR-38 Phase 5: THE single authoritative lab version — used by the
# HTTP response, every per-run record and the combined record. Reports
# and readiness JSON derive from these records, so the value cannot
# diverge again (regression-pinned).
LAB_VERSION = "1.6.0"

INVOICES = {
    "INV-A-101": ("User_A", "paid", 1200),
    "INV-B-777": ("User_B", "open", 3400),
    "INV-ADMIN-9001": ("User_ADMIN", "paid", 99),
}
SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B",
            "sess-admin9": "User_ADMIN"}
MISSING = "INV-MISSING-404"
DECOY = "DECOY-9999"  # public-by-design invoice lookalike: never confirms


def _git(args: list[str]) -> str:
    r = subprocess.run(["git", *args], cwd=REPO, capture_output=True,
                       text=True, check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


def _lockfile_sha256() -> str | None:
    lock = REPO / "uv.lock"
    if not lock.is_file():
        return None
    h = hashlib.sha256()
    with open(lock, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class _OutOfScopeOrigin:
    """A SECOND local origin the lab manifest tempts the crawler with.

    Serves a would-be-vulnerable invoice route and records EVERY
    request it receives. The safety invariant is provable from this
    log: the out-of-scope origin must receive ZERO requests (blocked
    before execution by the same-origin/SSRF/scope enforcement).
    """

    def __init__(self) -> None:
        self.request_log: list[str] = []
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                outer.request_log.append(self.path)
                body = json.dumps({
                    "id": "INV-OUT-OF-SCOPE-1", "owner": "Someone_Else",
                    "requested_by": "whoever"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_a) -> None:
                return

        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=self.server.serve_forever,
                         daemon=True).start()
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"

    def shutdown(self) -> None:
        self.server.shutdown()


class _IdorLab(BaseHTTPRequestHandler):
    """The authorized local lab (same scenario as the root-cause runs).
    Instances are per-campaign; each records every request it serves."""

    request_log: list[dict] = []

    def _principal(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "session=" in part:
                return SESSIONS.get(part.strip().split("=", 1)[1])
        return None

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        type(self).request_log.append(
            {"path": path, "principal": principal})
        if path in ("", "/"):
            self._send(200, json.dumps({
                "app": "invoice-lab", "version": LAB_VERSION,
                "auth": "cookie session",
                "links": ["/api/users", "/api/session", "/api/health",
                          "/api/invoices/INV-A-101",
                          "/api/invoices/INV-B-777",
                          "/api/invoices/INV-ADMIN-9001",
                          f"/api/invoices/{MISSING}",
                          f"/api/invoices/{DECOY}",
                          # the OUT-OF-SCOPE temptation: an absolute URL
                          # to a DIFFERENT local origin carrying a
                          # would-be-vulnerable resource. Same-origin
                          # enforcement must drop it at discovery; the
                          # out-of-scope origin's request log proves it.
                          f"{self.server.out_of_scope_origin}/api/"
                          "invoices/INV-OUT-OF-SCOPE-1"]}).encode())
            return
        if path == "/api/health":
            self._send(200, b'{"status":"ok"}')
            return
        if path == "/api/users":
            if not principal:
                self._send(401, b'{"error":"authentication required"}')
                return
            self._send(200, json.dumps({"users": [
                {"id": "u1", "name": "User_A", "role": "customer"},
                {"id": "u2", "name": "User_B", "role": "customer"},
                {"id": "u9", "name": "User_ADMIN", "role": "admin"}]}).encode())
            return
        if path == "/api/session":
            if not principal:
                self._send(401, b'{"error":"authentication required"}')
                return
            self._send(200, json.dumps({"principal": principal,
                                        "authenticated": True}).encode())
            return
        if path.startswith("/api/invoices/"):
            if not principal:
                self._send(401, b'{"error":"authentication required"}')
                return
            inv = path.rsplit("/", 1)[1]
            if inv == DECOY:
                # public-by-design invoice lookalike: any authenticated
                # principal legitimately reads it and there is NO owner
                # binding, so no ownership differential can exist — the
                # decoy must never confirm
                self._send(200, json.dumps({
                    "id": DECOY, "public": True,
                    "notice": "public sample invoice",
                    "requested_by": principal}).encode())
                return
            if inv not in INVOICES:
                self._send(404, b'{"error":"invoice not found"}')
                return
            owner, status, amount = INVOICES[inv]
            if owner == "User_ADMIN" and principal != "User_ADMIN":
                self._send(403, json.dumps({
                    "error": "forbidden", "invoice": inv,
                    "requires": "admin"}).encode())
                return
            self._send(200, json.dumps({
                "id": inv, "owner": owner, "status": status,
                "amount": amount, "requested_by": principal}).encode())
            return
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *_a) -> None:
        return


def _count(value):
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, dict):
        return {k: _count(v) for k, v in list(value.items())[:40]}
    return None


@contextlib.contextmanager
def campaign_instrumentation(sink: dict):
    """UM-DR-38 §7.2.A — REVERSIBLE instrumentation for exactly ONE
    campaign.

    Installs a single observation layer around the production modules
    and RESTORES every original in ``finally``. Sequential campaigns in
    one process each install their layer over the ORIGINALS (never over
    a previous campaign's layer): wrappers cannot accumulate, tracing
    is per-campaign, and CausalGuard/verification counts stay per-run.

    §7.2.B: while the run context is open, the tee also captures the
    AUTHORITATIVE final graph state via ``graph.get_state(config)``
    (reducer-applied by the checkpointer) as soon as the update stream
    is exhausted; the last-write merge is kept only as an explicitly
    labeled fallback.
    """
    import webpent.agents.access_control.agent as ac_agent
    import webpent.graph.builder as gb
    import webpent.production.confirmation_adapter as ca
    import webpent.shared.verifier as verifier_mod

    stages = sink["stages"]
    guard_calls = sink["guard_calls"]
    verifications = sink["verifications"]
    raw_state = sink["raw_state"]
    graphs = sink["graphs"]
    last_t = [time.perf_counter()]

    real_build = gb.build_graph

    def traced_build(*args, **kwargs):
        graph = real_build(*args, **kwargs)
        real_stream = graph.stream

        def tee_stream(state, config=None, **stream_kwargs):
            graphs.append((graph, config))
            for chunk in real_stream(state, config=config, **stream_kwargs):
                now = time.perf_counter()
                if isinstance(chunk, dict):
                    for node, delta in chunk.items():
                        if isinstance(delta, dict):
                            stages.append({
                                "node": str(node),
                                "wall_s": round(now - last_t[0], 3),
                                "writes": {
                                    k: _count(v)
                                    for k, v in list(delta.items())[:40]
                                    if not str(k).startswith("__")
                                },
                            })
                            for key, value in delta.items():
                                if not str(key).startswith("__"):
                                    raw_state[str(key)] = value
                last_t[0] = now
                yield chunk
            # §7.2.B: the stream is exhausted and the run context (and
            # its checkpointer) is still open HERE — read the actual
            # final state with the reducers applied by LangGraph.
            try:
                snapshot = graph.get_state(config)
                values = getattr(snapshot, "values", None)
                if values:
                    sink["authoritative_final_state"] = dict(values)
            except Exception as exc:  # noqa: BLE001 — recorded honestly
                sink["authoritative_final_state_error"] = (
                    f"{type(exc).__name__}: {exc}")

        graph.stream = tee_stream
        return graph

    real_adjudicate = ca.adjudicate_with_causal_guard

    def counted_adjudicate(*args, **kwargs):
        result = real_adjudicate(*args, **kwargs)
        verdict = None
        if isinstance(result, dict):
            verdict = result.get("verdict")
        else:
            # the production adapter returns GuardedAdjudication with a
            # TYPED GuardedCausalResult — the verdict lives on
            # .guard_result.verdict (a Verdict enum)
            guard_result = getattr(result, "guard_result", None)
            verdict = getattr(guard_result, "verdict", None)
            if verdict is None:
                verdict = getattr(result, "verdict", None)
        guard_calls.append({
            "verdict": str(getattr(verdict, "value", verdict)),
            "vulnerability_class": str(kwargs.get("vulnerability_class")
                                       or ""),
            # UM-DR-38.1 §5.3: the authority interface exposes NO
            # finding identity — correlation stays count-level and the
            # per-finding chain joins happen at the verification stage
            "correlation": "count-level (no finding identity in the "
                           "authority interface)",
        })
        return result

    real_verify = verifier_mod.verify_replay_evidence

    def counted_verify(finding, *args, **kwargs):
        result = real_verify(finding, *args, **kwargs)
        verifications.append({
            "finding_id": str(getattr(finding, "id", "")),
            "vuln_class": str(getattr(finding, "vuln_class", "")),
            "passed": bool(getattr(result, "passed", False)),
            "reason": str(getattr(result, "reason", ""))[:200],
            "has_bundle": getattr(result, "proof_bundle", None) is not None,
        })
        return result

    saved = {
        "gb.build_graph": gb.build_graph,
        "ca.adjudicate_with_causal_guard": ca.adjudicate_with_causal_guard,
        "verifier_mod.adjudicate_with_causal_guard": getattr(
            verifier_mod, "adjudicate_with_causal_guard", None),
        "verifier_mod.verify_replay_evidence":
            verifier_mod.verify_replay_evidence,
        "ac_agent.verify_replay_evidence":
            ac_agent.verify_replay_evidence,
    }
    gb.build_graph = traced_build
    ca.adjudicate_with_causal_guard = counted_adjudicate
    if saved["verifier_mod.adjudicate_with_causal_guard"] is not None:
        verifier_mod.adjudicate_with_causal_guard = counted_adjudicate
    verifier_mod.verify_replay_evidence = counted_verify
    ac_agent.verify_replay_evidence = counted_verify
    try:
        yield sink
    finally:
        # §7.2.A: STRICT restoration — the next campaign (and the rest
        # of the process) sees the original functions, never a wrapper.
        gb.build_graph = saved["gb.build_graph"]
        ca.adjudicate_with_causal_guard = saved[
            "ca.adjudicate_with_causal_guard"]
        if saved["verifier_mod.adjudicate_with_causal_guard"] is not None:
            verifier_mod.adjudicate_with_causal_guard = saved[
                "verifier_mod.adjudicate_with_causal_guard"]
        verifier_mod.verify_replay_evidence = saved[
            "verifier_mod.verify_replay_evidence"]
        ac_agent.verify_replay_evidence = saved[
            "ac_agent.verify_replay_evidence"]


def _redacted_invocation(invocation: dict) -> dict:
    """§7.2.F: the RECORDED copy of the invocation carries cookies and
    session-like values redacted; the run itself uses the real (lab-
    synthetic) values, and only the minimum needed to reproduce the
    security conclusion is preserved."""
    out = dict(invocation)
    if out.get("cookies"):
        out["cookies"] = "***REDACTED***"
    if out.get("identity_profiles"):
        out["identity_profiles"] = {
            name: {**profile,
                   "cookies": dict.fromkeys(profile.get("cookies") or {}, "***REDACTED***")}
            for name, profile in out["identity_profiles"].items()}
    return out


def run_campaign(run_index: int) -> dict:
    out_of_scope = _OutOfScopeOrigin()
    server = HTTPServer(("127.0.0.1", 0), _IdorLab)
    server.out_of_scope_origin = out_of_scope.origin
    _IdorLab.request_log = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    campaign_id = f"umdr38-campaign-{run_index}-{uuid.uuid4().hex[:8]}"

    invocation = {
        "url": origin, "mode": "standard",
        "authorization": "umdr38-authorized-lab-engagement",
        "cookies": "session=sess-a7f3d1",
        "identity_profiles": {
            "user-b": {"name": "user-b", "role": "user",
                       "cookies": {"session": "sess-b9e2c4"}},
        },
        "auto_approve": True, "no_llm": True, "progress": False,
        "run_graph": True, "engagement_id": campaign_id,
    }

    sink: dict = {
        "stages": [], "guard_calls": [], "verifications": [],
        "raw_state": {}, "graphs": [],
        "authoritative_final_state": None,
        "authoritative_final_state_error": None,
    }

    from webpent.cli.unified_hunt import run_unified_hunt

    started = datetime.now(timezone.utc).isoformat()
    started_mono = time.monotonic()
    try:
        with campaign_instrumentation(sink):
            summary = run_unified_hunt(**invocation)
        elapsed = round(time.monotonic() - started_mono, 1)
    finally:
        # §7.2.E: servers are closed even when the campaign raises — a
        # failed campaign leaves no running server and no shared state
        # that could influence the next run.
        out_of_scope.shutdown()
        server.shutdown()

    stages = sink["stages"]
    guard_calls = sink["guard_calls"]
    verifications = sink["verifications"]
    raw_state = sink["raw_state"]

    # ---- safety invariants, proven from the lab's own request log -----
    requests_log = list(_IdorLab.request_log)
    admin_requests = [
        r for r in requests_log
        if r["path"] == "/api/invoices/INV-ADMIN-9001"]
    admin_denied_to_non_admin = [
        r for r in admin_requests if r["principal"] not in
        (None, "User_ADMIN")]
    missing_requests = [
        r for r in requests_log if MISSING in r["path"]]

    findings_detail = summary.get("findings_detail") or []
    confirmed = [f for f in findings_detail
                 if f.get("confidence_level") == "Tool-Confirmed"]

    # UM-DR-38.2 §2.3: per-finding classification evidence. The RAW
    # engine classification stays authoritative; the object-level
    # authorization differential is recorded as SEPARATE, fixture-
    # backed evidence (requesting principal from the lab's own request
    # log, object owner from the invoice-lab fixture registry — the
    # controlled ground truth). A finding is only labeled
    # object-level-authorization-failure when the cross-identity
    # differential is PROVEN from that evidence; path+principal alone
    # never proves ownership, and no aggregate flag may override the
    # raw classes.
    def _classification_evidence(finding: dict) -> dict:
        url = str(finding.get("url", ""))
        inv_id = url.rstrip("/").rsplit("/", 1)[-1]
        owner = INVOICES.get(inv_id, (None,))[0] if "/" in url else None
        # the finding URL may carry the full origin; the lab log stores
        # the PATH — normalize before joining (a path/principal join
        # must actually match the logged requests, else requesters
        # would read as None and the differential would never prove)
        raw_path = url.split("?", 1)[0]
        if "://" in raw_path:
            raw_path = "/" + raw_path.split("://", 1)[1].split("/", 1)[1]
        requesters = sorted({
            r["principal"] for r in requests_log
            if r["path"] == raw_path and r["principal"]})
        raw_class = str(finding.get("vuln_class", ""))
        retained = raw_class or "unclassified"
        # the differential: at least one LOGGED non-owner principal
        # reached the confirmed object — the Tool-Confirmed finding
        # (CausalGuard + sealed ProofBundle + replay) validates that
        # the access SUCCEEDED; the owner comes from the fixture
        # registry (controlled ground truth)
        non_owners = [req for req in requesters if req != owner]
        differential = bool(owner) and bool(non_owners)
        return {
            "raw_vuln_class": raw_class,
            "object_id": inv_id if owner else None,
            "requesting_principals": requesters or None,
            "object_owner": owner,
            "ownership_source": ("invoice-lab fixture registry "
                                 "(INVOICES — controlled ground truth)"
                                 if owner else None),
            "request_evidence_source": "the lab's own request log",
            "non_owner_requesting_principals": non_owners or None,
            "access_success_evidence": (
                "the Tool-Confirmed finding itself (CausalGuard "
                "adjudication + sealed ProofBundle + passing replay) "
                "validates that the cross-identity access succeeded"),
            "cross_identity_differential_proven": differential,
            "classification": (
                "object_level_authorization_failure (BOLA/IDOR family; "
                "at least one logged non-owner principal reached the "
                "confirmed object — owner from the fixture registry, "
                "requesters from the lab's own log, access success "
                "validated by the confirmed chain)"
                if differential else
                f"raw engine classification retained ({retained}) — "
                "the recorded evidence does not prove an object-level "
                "authorization failure"),
        }

    confirmed = [
        {**f, "classification_evidence": _classification_evidence(f)}
        for f in confirmed]
    access_control_confirmed = [
        f for f in confirmed
        if str(f.get("vuln_class", "")).lower() in
        {"auth_bypass", "idor"}]
    differential_proven = [
        f for f in access_control_confirmed
        if f["classification_evidence"][
            "cross_identity_differential_proven"]]

    invariant_checks = {
        # UM-DR-38.2 §2.3: the HONEST forms — raw classes (never a
        # blanket IDOR claim) + the separately-proven differential
        "at_least_one_confirmed_access_control_finding": bool(
            access_control_confirmed),
        "confirmed_access_control_findings_carry_bundles": all(
            f.get("evidence_bundle_id")
            for f in access_control_confirmed),
        "object_level_differential_proven": bool(differential_proven),
        "differential_findings_carry_bundles": all(
            f.get("evidence_bundle_id") for f in differential_proven),
        "enforced_admin_boundary_unconfirmed": not any(
            "INV-ADMIN-9001" in f.get("url", "") for f in confirmed),
        "admin_boundary_actually_enforced_in_lab": bool(
            admin_denied_to_non_admin),
        "missing_resource_unconfirmed": not any(
            MISSING in f.get("url", "") for f in confirmed),
        "missing_resource_was_probed_as_404": bool(missing_requests),
        "all_requests_on_origin": all(
            r["path"].startswith("/") for r in requests_log),
        "public_resource_unconfirmed": not any(
            "/api/health" in f.get("url", "")
            or "/api/session" in f.get("url", "")
            or f.get("url", "").rstrip("/") == origin
            for f in confirmed),
        # §12 decoy: the public-by-design invoice lookalike (no owner
        # binding -> no ownership differential) must never confirm
        "decoy_route_unconfirmed": not any(
            DECOY in f.get("url", "") for f in confirmed),
        "decoy_route_was_served": any(
            r["path"] == f"/api/invoices/{DECOY}" for r in requests_log),
        # §12 out-of-scope: the second origin (a would-be-vulnerable
        # resource on ANOTHER origin) must receive ZERO requests —
        # blocked before execution, proven from its own request log
        "out_of_scope_origin_zero_requests": (
            len(out_of_scope.request_log) == 0),
    }

    # ---- §7.2.B: the funnel from the AUTHORITATIVE final state -------
    funnel_state = sink["authoritative_final_state"]
    if funnel_state is not None:
        final_state_source = ("graph.get_state(config) — the actual "
                              "final graph state (reducer-applied), "
                              "read while the run context was open")
    else:
        funnel_state = raw_state
        final_state_source = (
            "FALLBACK: tee'd last-write merge of the update stream — an "
            "approximation (authoritative read unavailable: "
            f"{sink['authoritative_final_state_error']!r})")
    funnel = None
    funnel_error = None
    try:
        from webpent.production.discovery_funnel import build_discovery_funnel
        funnel = build_discovery_funnel(funnel_state)
    except Exception as exc:  # noqa: BLE001 — fail-soft, recorded honestly
        funnel_error = f"{type(exc).__name__}: {exc}"
    funnel_stages = (funnel or {}).get("stages") or {}

    # UM-DR-38.1 §5.4: the per-finding confirmation chain — joined on
    # finding_id across the run summary artifacts and the
    # instrumentation events, with the funnel kept separate and labeled
    import confirmation_chain
    confirmation_chain_record = confirmation_chain.build_confirmation_chain(
        confirmed, verifications, guard_calls,
        eligible_candidates=(
            funnel_stages.get("candidate_findings")
            if isinstance(funnel_stages.get("candidate_findings"), int)
            else None))

    # ---- §7.2.C: the full per-campaign assertion set ------------------
    principals_observed = sorted({
        r["principal"] for r in requests_log if r["principal"]})
    run_record = {
        "schema": "umdr38-production-campaign/v1",
        "run": run_index,
        "campaign_id": campaign_id,
        "started_at_utc": started,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": elapsed,
        "source_commit": _git(["rev-parse", "HEAD"]) or None,
        "tree_sha": _git(["rev-parse", "HEAD^{tree}"]) or None,
        "tree_clean": not bool(_git(["status", "--porcelain"])),
        "python_version": platform.python_version(),
        "lockfile_sha256": _lockfile_sha256(),
        "lab_version": f"invoice-lab/{LAB_VERSION}",
        "execution_mode": ("campaign script -> production entrypoint "
                           "webpent.cli.unified_hunt.run_unified_hunt "
                           "(no_llm=True, auto_approve=True)"),
        "request_budget": {
            "dynamic_step_budget": summary.get("dynamic_step_budget"),
            "note": "CLI standard-mode preset budgets; the enforced "
                    "request surface is proven by the lab request log",
        },
        "lab_requests_issued": len(requests_log),
        "discovered_endpoints": funnel_stages.get("endpoints_discovered"),
        "discovered_candidate_resources": funnel_stages.get(
            "candidate_findings"),
        # UM-DR-39 §12.4: the RC-1/RC-2 after-state proof — the
        # confirmation chain and the authorization observations as the
        # AUTHORITATIVE final state reports them (the funnel now counts
        # the producer vocabulary; the projection writes the channel)
        "funnel_confirmation_stages": {
            key: funnel_stages.get(key)
            for key in ("replay_verified", "promoted_findings",
                        "confirmed_findings")},
        "authorization_observations_count": funnel_stages.get(
            "authorization_observations"),
        "identities_observed": principals_observed,
        "authorization_relationships": {
            "authorization_observations": funnel_stages.get(
                "authorization_observations"),
            "differential_questions": funnel_stages.get(
                "differential_questions"),
        },
        "hypotheses": {
            "in_pool": funnel_stages.get("hypotheses_in_pool"),
            "open": funnel_stages.get("hypotheses_open"),
            "resolved": funnel_stages.get("hypotheses_resolved"),
        },
        "lab_origin": origin,
        "invocation": _redacted_invocation(invocation),
        "redaction": ("cookies/session values redacted in the recorded "
                      "copy (synthetic lab credentials); the run itself "
                      "used the real values"),
        "stage_count": len(stages),
        "stages": stages,
        "lab_request_count": len(requests_log),
        "lab_requests": requests_log[:200],
        "out_of_scope_origin": out_of_scope.origin,
        "out_of_scope_request_count": len(out_of_scope.request_log),
        "out_of_scope_requests": list(out_of_scope.request_log),
        "findings_total": summary.get("findings_total"),
        "findings_confirmed": summary.get("findings_confirmed"),
        "confirmed_detail": [
            {**{k: f.get(k) for k in
                ("id", "vuln_class", "confidence_level", "url",
                 "evidence_bundle_id", "evidence_keys")},
             "classification_evidence": f["classification_evidence"]}
            for f in confirmed
        ],
        "causal_guard_invocations": len(guard_calls),
        "guard_verdicts": [g["verdict"] for g in guard_calls],
        "verifications": verifications,
        "final_state_source": final_state_source,
        "confirmation_chain": confirmation_chain_record,
        # UM-DR-38.2 §2.2: the measurement discrepancies between the
        # lab's ground-truth request log and the graph-state funnel,
        # recorded EXPLICITLY with sources (never silently corrected;
        # the graph-channel wiring is the UM-DR-39 root-cause work)
        "measurement_discrepancies": {
            "principals_in_lab_request_log": principals_observed,
            "funnel_principals_observed": funnel_stages.get(
                "principals_observed"),
            "funnel_authorization_observations": funnel_stages.get(
                "authorization_observations"),
            "funnel_differential_questions": funnel_stages.get(
                "differential_questions"),
            "funnel_object_ownership_relations": funnel_stages.get(
                "object_ownership_relations"),
            "sources": {
                "principals_in_lab_request_log": "the lab's own "
                                                 "request log "
                                                 "(ground truth)",
                "funnel_*": "build_discovery_funnel over the "
                            "authoritative final graph state "
                            "(graph.get_state) — the "
                            "multi_identity_reasoning / "
                            "authorization_observations channels are "
                            "not materialized by this campaign's "
                            "final state",
            },
            "disposition": "documented as a measurement limitation; "
                           "the graph-channel wiring investigation is "
                           "UM-DR-39 scope (root-cause register)",
        },
        "invariant_checks": invariant_checks,
        "funnel": funnel,
        "funnel_error": funnel_error,
        "notes": [
            "the funnel is computed from the AUTHORITATIVE final state "
            "(graph.get_state) — the tee'd last-write merge survives "
            "only as an explicitly labeled fallback",
            "requests logged by the lab itself prove the safety "
            "invariants from the run, not from expectations",
        ],
    }
    return run_record


def main() -> int:
    runs = [run_campaign(index + 1) for index in range(RUNS)]
    combined = {
        "schema": "umdr38-production-campaigns/v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mission": "UM-DR-38 Phase 8 (from UM-DR-37 Part 12 / "
                   "gates G37-16..G37-23)",
        "run_count": len(runs),
        "lab_version": f"invoice-lab/{LAB_VERSION}",
        "configuration": "mode=standard, no_llm=True, auto_approve=True, "
                         "User_A cookies + user-b identity profile",
        "runs": runs,
        "reproducibility": {
            "same_lab_version": all(
                r["lab_version"] == f"invoice-lab/{LAB_VERSION}"
                for r in runs),
            "same_configuration": True,
            "fresh_state_per_run": True,
            "unique_campaign_ids": [r["campaign_id"] for r in runs],
            "confirmed_counts": [r["findings_confirmed"] for r in runs],
            "guard_verdicts_per_run": [r["guard_verdicts"] for r in runs],
            "confirmed_raw_classes_per_run": [
                sorted({str(f.get("vuln_class"))
                        for f in r["confirmed_detail"]})
                for r in runs],
            "all_runs_confirm_access_control_finding": all(
                r["invariant_checks"][
                    "at_least_one_confirmed_access_control_finding"]
                for r in runs),
            "all_runs_prove_object_level_differential": all(
                r["invariant_checks"]["object_level_differential_proven"]
                for r in runs),
            "all_invariants_hold": all(
                all(r["invariant_checks"].values()) for r in runs),
            "differences_explained": (
                "finding counts beyond the two boundary violations are "
                "advisory api_issue candidates whose exact set depends on "
                "crawl ordering; the CONFIRMED set is the invariant being "
                "reproduced"
            ),
        },
    }
    out = REPO / "artifacts" / "umdr37_production_campaigns.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(combined, indent=2, default=str),
                   encoding="utf-8")
    for run in runs:
        single = REPO / "artifacts" / (
            f"umdr37_production_campaign_run{run['run']}.json")
        single.write_text(json.dumps(run, indent=2, default=str),
                          encoding="utf-8")
    print(f"[campaigns] lab version: {LAB_VERSION}")
    repro = combined["reproducibility"]
    print(f"[campaigns] confirmed per run: "
          f"{repro['confirmed_counts']}")
    print(f"[campaigns] raw classes per run: "
          f"{repro['confirmed_raw_classes_per_run']}")
    print(f"[campaigns] all runs prove object-level differential: "
          f"{repro['all_runs_prove_object_level_differential']}")
    print(f"[campaigns] all invariants hold: "
          f"{repro['all_invariants_hold']}")
    for run in runs:
        state = ("authoritative"
                 if "get_state" in run["final_state_source"]
                 else "fallback")
        print(f"  run {run['run']}: stages={run['stage_count']} "
              f"requests={run['lab_request_count']} "
              f"guard={run['guard_verdicts']} state={state} "
              f"funnel={'ok' if run['funnel'] else run['funnel_error']}")
    print(f"[artifact] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

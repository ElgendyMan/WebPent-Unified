"""TEAM-2 common wiring for AVI V1.2 post-closure independent validation.

RULES HONORED:
  * NO source modification, NO test modification, NO validator/pipeline change.
  * This module only COMPOSES existing production components at runtime.
  * All evidence produced here is fresh runtime evidence, independent of TEAM-1.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

ROOT = "/home/z/my-project/avi_v12/webpent-goed"
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

# Test/lab HMAC secret (from TEAM1_AVI_V1_2_ENVIRONMENT.md section 5).
os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")

EVIDENCE_DIR = "/home/z/my-project/download/TEAM2_AVI_V1_2_VALIDATION"
os.makedirs(EVIDENCE_DIR, exist_ok=True)


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_json(name: str, obj: Any) -> str:
    path = os.path.join(EVIDENCE_DIR, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, default=str)
    return path


def sha256_file(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Production component imports (authorities are imported, never re-implemented)
# ---------------------------------------------------------------------------
from webpent.live_hunter.profile import AuthorizedLabProfile  # noqa: E402
from webpent.live_hunter.tool_scope import ScopeLaw  # noqa: E402
from webpent.production.experiment_fabric import normalize_observation  # noqa: E402
from webpent.production.modern_spine import ModernOrchestrator  # noqa: E402
from webpent.production.real_target_qualification_v1_1 import (  # noqa: E402
    _GraphQLApp,
    _RESTApp,
    start_target_server,
)
from webpent.production.validators import run_validator  # noqa: E402


def make_orchestrator(engagement_id: str) -> ModernOrchestrator:
    """Bind a production ModernOrchestrator with AuthorizedLabProfile+ScopeLaw.

    Loopback-only authorization. This is the SAME wiring the acceptance tests
    use (tests/team1_acceptance/test_hmac_proof_authority.py).
    """
    profile = AuthorizedLabProfile(
        authorized_targets=("127.0.0.1",),
        engagement_id=engagement_id,
        operator_approval_at=utc(),
        knowledge_ready=True,
    )
    scope_law = ScopeLaw(profile=profile, engagement_id=engagement_id)
    return ModernOrchestrator(engagement_id=engagement_id, scope_law=scope_law)


# ===========================================================================
# TEAM-2 INDEPENDENT target mixes (NOT copied from TEAM-1's campaign config).
# All 6 families appear as ground truth across the 4 targets; REST + GraphQL.
# ===========================================================================
T2_TARGETS: list[dict[str, Any]] = [
    {"target_id": "rest_alpha",   "api_type": "rest",    "app": "rest",
     "vulnerable": {"IDOR", "SSRF"}},
    {"target_id": "rest_bravo",   "api_type": "rest",    "app": "rest",
     "vulnerable": {"AUTH_BYPASS", "OPEN_REDIRECT"}},
    {"target_id": "gql_charlie",  "api_type": "graphql", "app": "graphql",
     "vulnerable": {"OPEN_REDIRECT", "INFO_DISCLOSURE"}},
    {"target_id": "gql_delta",    "api_type": "graphql", "app": "graphql",
     "vulnerable": {"INFO_DISCLOSURE", "MASS_ASSIGNMENT"}},
]

# Pre-registered binding-compatibility expectations (TEAM-2's OWN analysis,
# derived from the production identity-binding logic — validated at runtime):
# REST uses real HTTP statuses (403/404/302/401) so all 6 families can bind.
# GraphQL returns HTTP 200 with structured errors, so only body/header-based
# binding families (OPEN_REDIRECT 302, INFO_DISCLOSURE, MASS_ASSIGNMENT) can
# bind; IDOR/SSRF/AUTH_BYPASS on GraphQL are expected NOT to promote.
BINDING_COMPAT: dict[str, set[str]] = {
    "rest": {"IDOR", "OPEN_REDIRECT", "SSRF", "MASS_ASSIGNMENT",
             "INFO_DISCLOSURE", "AUTH_BYPASS"},
    "graphql": {"OPEN_REDIRECT", "INFO_DISCLOSURE", "MASS_ASSIGNMENT"},
}

ACTORS = ["bob", "mallory", "eve", "trudy"]


def _hyp(hid: str, fam: str, api_type: str, idx: int, requests: dict,
         resource_owner: str, auth_ctx: str) -> dict[str, Any]:
    return {
        "id": hid,
        "vulnerability_class": fam,
        "api_type": api_type,
        "information_value": 0.5 + 0.01 * idx,
        "resource_owner": resource_owner,
        "authorization_context": auth_ctx,
        "requests": requests,
        "t2_expected_promotable": fam in BINDING_COMPAT[api_type],
    }


def build_t2_hypotheses(base_url: str, api_type: str, target_id: str) -> list[dict[str, Any]]:
    """TEAM-2's own hypothesis variant builder: 6 families x 4 actor/endpoint
    variants (+1 extra) = 25 unique hypotheses per target. Every hypothesis
    carries explicit REAL request specs (baseline/candidate/negative_control),
    multiple actors, and ownership boundaries."""
    hyps: list[dict[str, Any]] = []
    idx = 0

    def g(q: str, headers: dict | None = None) -> dict[str, Any]:
        from urllib.parse import quote
        h = {"X-User": "anonymous"}
        if headers:
            h.update(headers)
        return {"method": "GET", "path": f"/graphql?query={quote(q, safe='')}",
                "headers": h}

    for v, actor in enumerate(ACTORS):
        xff = ["127.0.0.1", "127.0.0.1", "10.0.0.5", "192.168.1.1"][v]
        if api_type == "rest":
            # IDOR: candidate actor (not owner) reads alice's order; owner reads own.
            hyps.append(_hyp(
                f"t2_{target_id}_idor_v{v+1}", "IDOR", api_type, idx,
                {"baseline": {"method": "GET", "path": "/api/orders/1", "headers": {"X-User": "alice"}},
                 "candidate": {"method": "GET", "path": "/api/orders/1", "headers": {"X-User": actor}},
                 "negative_control": {"method": "GET", "path": "/api/orders/99999", "headers": {"X-User": actor}}},
                "alice", "owner=alice resource=/api/orders/1"))
            idx += 1
            # OPEN_REDIRECT variants
            redir_cand = ["https://evil.com/steal", "https://attacker.net/phish",
                          "http://evil.io/session", "https://evil.example.net/collect"][v]
            hyps.append(_hyp(
                f"t2_{target_id}_openredirect_v{v+1}", "OPEN_REDIRECT", api_type, idx,
                {"baseline": {"method": "GET", "path": "/api/redirect?url=https://trusted.com/home"},
                 "candidate": {"method": "GET", "path": f"/api/redirect?url={redir_cand}"},
                 "negative_control": {"method": "GET", "path": "/api/redirect?url="}},
                "system", "redirect_allowlist=trusted.com"))
            idx += 1
            # SSRF variants
            ssrf_cand = ["http://169.254.169.254/latest/meta-data/",
                         "http://localhost:9200/_cluster/health",
                         "http://169.254.170.2/v2/iam/security-credentials/",
                         "http://127.0.0.1:8500/v1/kv/?token=secret"][v]
            hyps.append(_hyp(
                f"t2_{target_id}_ssrf_v{v+1}", "SSRF", api_type, idx,
                {"baseline": {"method": "GET", "path": "/api/fetch?url=https://api.example.com/data"},
                 "candidate": {"method": "GET", "path": f"/api/fetch?url={ssrf_cand}"},
                 "negative_control": {"method": "GET", "path": "/api/fetch?url=ftp://invalid"}},
                "system", "egress_allowlist=api.example.com"))
            idx += 1
            # MASS_ASSIGNMENT variants
            hyps.append(_hyp(
                f"t2_{target_id}_massassign_v{v+1}", "MASS_ASSIGNMENT", api_type, idx,
                {"baseline": {"method": "PUT", "path": "/api/profile/alice",
                              "headers": {"X-User": "alice", "Content-Type": "application/json"},
                              "body": json.dumps({"name": "alice"})},
                 "candidate": {"method": "PUT", "path": "/api/profile/alice",
                               "headers": {"X-User": "alice", "Content-Type": "application/json"},
                               "body": json.dumps({"name": "alice", "role": "admin"})},
                 "negative_control": {"method": "PUT", "path": "/api/profile/alice",
                                      "headers": {"X-User": "alice", "Content-Type": "application/json"},
                                      "body": json.dumps({"name": f"alice{v}"})}},
                "alice", "role_assignment=admin_only"))
            idx += 1
            # INFO_DISCLOSURE variants
            hyps.append(_hyp(
                f"t2_{target_id}_infodisc_v{v+1}", "INFO_DISCLOSURE", api_type, idx,
                {"baseline": {"method": "GET", "path": "/api/public"},
                 "candidate": {"method": "GET", "path": "/api/debug"},
                 "negative_control": {"method": "GET", "path": "/api/health"}},
                "system", "debug_endpoint=internal_only"))
            idx += 1
            # AUTH_BYPASS variants
            hyps.append(_hyp(
                f"t2_{target_id}_authbypass_v{v+1}", "AUTH_BYPASS", api_type, idx,
                {"baseline": {"method": "GET", "path": "/api/admin"},
                 "candidate": {"method": "GET", "path": "/api/admin",
                               "headers": {"X-Forwarded-For": xff}},
                 "negative_control": {"method": "GET", "path": "/api/admin",
                                      "headers": {"X-Forwarded-For": "192.168.1.99"}}},
                "admin", "admin_access=trusted_proxy_only"))
            idx += 1
        else:
            # GraphQL variants (explicit real requests through /graphql)
            hyps.append(_hyp(
                f"t2_{target_id}_idor_v{v+1}", "IDOR", api_type, idx,
                {"baseline": g('query{order(id:1){item}}', {"X-User": "alice"}),
                 "candidate": g('query{order(id:1){item}}', {"X-User": actor}),
                 "negative_control": g('query{order(id:99999){item}}', {"X-User": actor})},
                "alice", "owner=alice resource=order(id:1)"))
            idx += 1
            redir_cand = ['query{redirect(url:"https://evil.com/steal")}',
                          'query{redirect(url:"https://evil.com/phish")}',
                          'query{redirect(url:"https://evil.io/session")}',
                          'query{redirect(url:"https://trusted.com/home")}'][v]
            hyps.append(_hyp(
                f"t2_{target_id}_openredirect_v{v+1}", "OPEN_REDIRECT", api_type, idx,
                {"baseline": g('query{redirect(url:"https://trusted.com")}'),
                 "candidate": g(redir_cand),
                 "negative_control": g('query{redirect(url:"")}')}
                if v < 3 else
                {"baseline": g('query{redirect(url:"https://trusted.com")}'),
                 "candidate": g('query{redirect(url:"https://trusted.com/home")}'),
                 "negative_control": g('query{redirect(url:"")}')},
                "system", "redirect_allowlist=trusted.com"))
            idx += 1
            hyps.append(_hyp(
                f"t2_{target_id}_ssrf_v{v+1}", "SSRF", api_type, idx,
                {"baseline": g('query{fetch(url:"https://api.example.com")}'),
                 "candidate": g('query{fetch(url:"http://169.254.169.254/metadata")}'),
                 "negative_control": g('query{fetch(url:"ftp://invalid")}')}
                if v < 3 else
                {"baseline": g('query{fetch(url:"https://api.example.com")}'),
                 "candidate": g('query{fetch(url:"https://api.example.com/data")}'),
                 "negative_control": g('query{fetch(url:"ftp://invalid")}')},
                "system", "egress_allowlist=api.example.com"))
            idx += 1
            hyps.append(_hyp(
                f"t2_{target_id}_massassign_v{v+1}", "MASS_ASSIGNMENT", api_type, idx,
                {"baseline": g('mutation{updateProfile(name:"alice"){name role}}', {"X-User": "alice"}),
                 "candidate": g('mutation{updateProfile(name:"alice",role:admin){name role}}', {"X-User": "alice"}),
                 "negative_control": g('mutation{updateProfile(name:"alice2"){name role}}', {"X-User": "alice"})},
                "alice", "role_assignment=admin_only"))
            idx += 1
            hyps.append(_hyp(
                f"t2_{target_id}_infodisc_v{v+1}", "INFO_DISCLOSURE", api_type, idx,
                {"baseline": g('query{__typename}'),
                 "candidate": g('query{debugInfo}'),
                 "negative_control": g('query{__schema{types{name}}}')},
                "system", "debug_endpoint=internal_only"))
            idx += 1
            hyps.append(_hyp(
                f"t2_{target_id}_authbypass_v{v+1}", "AUTH_BYPASS", api_type, idx,
                {"baseline": g('query{admin{users}}'),
                 "candidate": g('query{admin{users}}', {"X-Forwarded-For": xff}),
                 "negative_control": g('query{admin{users}}', {"X-Forwarded-For": "192.168.1.99"})},
                "admin", "admin_access=trusted_proxy_only"))
            idx += 1

    # +1 extra variant so each target carries exactly 25 unique hypotheses.
    extra_actor = "oscar"
    if api_type == "rest":
        hyps.append(_hyp(
            f"t2_{target_id}_idor_v5", "IDOR", api_type, idx,
            {"baseline": {"method": "GET", "path": "/api/orders/2", "headers": {"X-User": "bob"}},
             "candidate": {"method": "GET", "path": "/api/orders/2", "headers": {"X-User": extra_actor}},
             "negative_control": {"method": "GET", "path": "/api/orders/99999", "headers": {"X-User": extra_actor}}},
            "bob", "owner=bob resource=/api/orders/2"))
    else:
        hyps.append(_hyp(
            f"t2_{target_id}_idor_v5", "IDOR", api_type, idx,
            {"baseline": g('query{order(id:2){item}}', {"X-User": "bob"}),
             "candidate": g('query{order(id:2){item}}', {"X-User": extra_actor}),
             "negative_control": g('query{order(id:99999){item}}', {"X-User": extra_actor})},
            "bob", "owner=bob resource=order(id:2)"))
    return hyps


def start_t2_target(spec: dict[str, Any]):
    """Start one real HTTP target from the production harness fixtures."""
    if spec["app"] == "rest":
        app = _RESTApp(vulnerable=set(spec["vulnerable"]), target_id=spec["target_id"])
    else:
        app = _GraphQLApp(vulnerable=set(spec["vulnerable"]), target_id=spec["target_id"])
    srv, url = start_target_server(app)
    return srv, url


def run_t2_target_campaign(spec: dict[str, Any], *, run_tag: str,
                           max_decisions: int = 25) -> dict[str, Any]:
    """Run the production dispatch campaign against ONE real target.

    Production path: ModernOrchestrator.run_autonomous_validation_campaign
    -> AutonomousValidationIntelligence.run_campaign (full 11-stage pipeline).
    """
    engagement = f"t2_val_{spec['target_id']}_{run_tag}"
    srv, url = start_t2_target(spec)
    try:
        orch = make_orchestrator(engagement)
        hyps = build_t2_hypotheses(url, spec["api_type"], spec["target_id"])
        result = orch.run_autonomous_validation_campaign(
            target_url=url, hypotheses=hyps, max_decisions=max_decisions)
        decisions = []
        for d in result.get("decisions", []):
            rec = dict(d)
            rec["target_id"] = spec["target_id"]
            rec["api_type"] = spec["api_type"]
            hid = rec.get("hypothesis_id")
            hyp = next((h for h in hyps if h["id"] == hid), {})
            rec["t2_ground_truth"] = {
                "vulnerable_family": spec["vulnerable"],
                "family_in_target_vulnerable_set": rec.get("vulnerability_class") in spec["vulnerable"],
                "t2_expected_promotable": hyp.get("t2_expected_promotable"),
            }
            decisions.append(rec)
        return {
            "target_id": spec["target_id"],
            "api_type": spec["api_type"],
            "vulnerable_families_ground_truth": sorted(spec["vulnerable"]),
            "target_url_digest": result.get("target_url_digest"),
            "engagement_id": engagement,
            "decisions_executed": result.get("decisions_executed"),
            "promoted_count": result.get("promoted_count"),
            "rejected_count": result.get("rejected_count"),
            "trace": result.get("trace"),
            "security_report": result.get("security_report"),
            "decisions": decisions,
        }
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass


def execute_real_triple(orch: ModernOrchestrator, *, base_url: str,
                        requests: dict[str, Any], hypothesis_id: str) -> dict[str, Any]:
    """Execute baseline/candidate/negative_control as REAL authorized HTTP via
    the orchestrator's execute_real_request (same path the pipeline uses)."""
    raw: dict[str, Any] = {}
    for role in ("baseline", "candidate", "negative_control"):
        spec = requests[role]
        obs = orch.execute_real_request(
            method=str(spec.get("method", "GET")),
            target_url=base_url + str(spec.get("path", "/")),
            headers=spec.get("headers"),
            body=spec.get("body"),
            hypothesis_id=hypothesis_id,
        )
        raw[role] = {
            "status_code": obs.get("status_code", 0),
            "response_body": str(obs.get("response_body", "")),
            "headers": obs.get("headers", {}) or {},
            "real_http": bool(obs.get("real_http", False)),
            "authorized": bool(obs.get("authorized", False)),
            "evidence_origin": "target_runtime",
        }
    return raw


def normalize_and_validate(orch: ModernOrchestrator, *, vuln_class: str,
                           raw_triple: dict[str, Any],
                           hypothesis: dict[str, Any],
                           experiment_id: str):
    """Normalize observations + run the canonical validator (production path)."""
    b = normalize_observation(experiment_id, "baseline", raw_triple["baseline"])
    c = normalize_observation(experiment_id, "candidate", raw_triple["candidate"])
    nc = normalize_observation(experiment_id, "negative_control", raw_triple["negative_control"])

    def _vi(role: str) -> dict[str, Any]:
        raw = raw_triple[role]
        return {"status_code": raw["status_code"],
                "response_body": str(raw["response_body"])[:2000],
                "headers": dict(raw.get("headers", {}) or {})}

    vr = run_validator(vuln_class, baseline=_vi("baseline"),
                       candidate=_vi("candidate"), negative_control=_vi("negative_control"))
    return b, c, nc, vr

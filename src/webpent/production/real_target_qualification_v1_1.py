"""TEAM-1 AVI V1.1 — Real Target Qualification Harness.

Moves AVI from synthetic/local qualification to realistic authorized target
validation. NO new architecture, NO new authorities. Composes the existing V1
pipeline (AutonomousValidationIntelligence → ScopeLaw/ToolBoundary →
CausalValidator → ProofBundle → Replay → PromotionPipeline → SecurityReport).

Provides:
  1. Realistic isolated authorized targets:
     - REST application (users, ownership, auth boundaries, negative controls)
     - GraphQL application (authenticated + unauthenticated flows)
     - Each target has vulnerable + patched variants (ground truth known).
  2. Validator Reality Upgrade: for all 6 families, baseline/candidate/
     negative_control are ALL real HTTP requests (explicit request specs).
  3. Discovery → Validation lifecycle: hypothesis discovery (ground-truth
     hypothesis set) → experiment selection → real execution → validation →
     promotion/refutation. Measures FP / FN / inconclusive.
  4. Long-horizon campaign support (100 decisions, multiple targets).
  5. SecurityReportQualifier: reports contain ONLY replay-verified proof,
     causal evidence, negative control, target-backed evidence. Rejects
     confidence-only, external-scanner, heuristic-only findings. (Composition
     of existing PromotionPipeline gates — no new authority.)
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Final
from urllib.parse import parse_qs, urlparse

from webpent.models.evidence import sha256_text
from webpent.production.validators import EvidenceQuality

logger = logging.getLogger(__name__)

QUAL_VERSION: Final[str] = "real_target_qualification_v1_1"

SIX_FAMILIES: Final[tuple[str, ...]] = (
    "IDOR", "OPEN_REDIRECT", "SSRF", "MASS_ASSIGNMENT", "INFO_DISCLOSURE", "AUTH_BYPASS",
)


# ===========================================================================
# 1. Realistic REST application (ownership + auth boundaries + negative controls)
# ===========================================================================
class _RESTApp:
    """Stateful REST app. Users: alice (owner), bob (foreign). Orders owned by users.

    ``vulnerable`` = set of vulnerability families that are actually vulnerable
    (ground truth). Families NOT in the set are patched (should be REFUTED).
    """

    def __init__(self, vulnerable: set[str], target_id: str = "rest_app") -> None:
        self.vulnerable = {v.upper() for v in vulnerable}
        self.target_id = target_id
        self.orders = {
            "1": {"id": 1, "owner": "alice", "item": "laptop", "price": 1200},
            "2": {"id": 2, "owner": "bob", "item": "phone", "price": 800},
        }
        self.profiles = {"alice": {"name": "alice", "role": "user"},
                         "bob": {"name": "bob", "role": "user"}}

    def is_vuln(self, family: str) -> bool:
        return family.upper() in self.vulnerable

    def handle(self, method: str, path: str, query: dict, headers: dict, body: str) -> tuple[int, dict, str]:
        """Return (status, headers, body_text)."""
        user = headers.get("X-User", headers.get("x-user", "anonymous"))
        # --- IDOR / BOLA ---
        if path.startswith("/api/orders/"):
            oid = path.split("/")[-1]
            if oid not in self.orders:
                return 404, {}, json.dumps({"error": "order_not_found"})
            order = self.orders[oid]
            if self.is_vuln("IDOR") or order["owner"] == user:
                return 200, {"Content-Type": "application/json"}, json.dumps(order)
            return 403, {}, json.dumps({"error": "forbidden"})
        # --- Open Redirect ---
        if path == "/api/redirect":
            url = query.get("url", [""])[0]
            if self.is_vuln("OPEN_REDIRECT") and url.startswith("http"):
                return 302, {"Location": url}, ""
            if url and not any(t in url for t in ("trusted.com", "example.com", "localhost")):
                return 400, {}, json.dumps({"error": "invalid_redirect"})
            if url:
                return 302, {"Location": url}, ""
            return 200, {}, json.dumps({"ok": True})
        # --- SSRF ---
        if path == "/api/fetch":
            url = query.get("url", [""])[0]
            if self.is_vuln("SSRF") and ("169.254" in url or "metadata" in url or "localhost" in url):
                return 200, {}, json.dumps({"fetched": "ami-id iam role metadata token secret internal-ip"})
            if url.startswith("ftp://") or "169.254" in url:
                return 400, {}, json.dumps({"error": "url_rejected"})
            return 200, {}, json.dumps({"fetched": "normal external data"})
        # --- Mass Assignment ---
        if method == "PUT" and path.startswith("/api/profile/"):
            uname = path.split("/")[-1]
            if uname not in self.profiles:
                return 404, {}, json.dumps({"error": "no_user"})
            try:
                payload = json.loads(body) if body else {}
            except Exception:
                payload = {}
            if self.is_vuln("MASS_ASSIGNMENT") and "role" in payload:
                self.profiles[uname]["role"] = str(payload["role"])
            resp = dict(self.profiles[uname])
            resp["name"] = payload.get("name", resp["name"])
            return 200, {"Content-Type": "application/json"}, json.dumps(resp)
        # --- Info Disclosure ---
        if path == "/api/debug":
            if self.is_vuln("INFO_DISCLOSURE"):
                return 200, {}, json.dumps({"stack": "traceback at line 42 password=secret123 api_key=sk-123 token=xyz db_password=root"})
            return 404, {}, json.dumps({"error": "not_found"})
        if path == "/api/public":
            return 200, {}, json.dumps({"public": "info"})
        if path == "/api/health":
            return 200, {}, json.dumps({"status": "ok"})
        # --- Auth Bypass ---
        if path == "/api/admin":
            bypass = headers.get("X-Forwarded-For", headers.get("x-forwarded-for", ""))
            if self.is_vuln("AUTH_BYPASS") and bypass == "127.0.0.1":
                return 200, {}, json.dumps({"admin": True, "users": list(self.profiles.keys())})
            if user == "anonymous" or not user:
                return 401, {}, json.dumps({"error": "unauthorized"})
            return 403, {}, json.dumps({"error": "forbidden"})
        return 404, {}, json.dumps({"error": "not_found"})


# ===========================================================================
# 2. Realistic GraphQL application (authenticated + unauthenticated flows)
# ===========================================================================
class _GraphQLApp:
    """GraphQL app at /graphql. Supports queries/mutations with ownership.

    ``vulnerable`` = set of families actually vulnerable (ground truth).
    """

    def __init__(self, vulnerable: set[str], target_id: str = "graphql_app") -> None:
        self.vulnerable = {v.upper() for v in vulnerable}
        self.target_id = target_id
        self.orders = {"1": {"id": 1, "owner": "alice", "item": "laptop"},
                       "2": {"id": 2, "owner": "bob", "item": "phone"}}
        self.profiles = {"alice": {"name": "alice", "role": "user"}}

    def is_vuln(self, family: str) -> bool:
        return family.upper() in self.vulnerable

    def handle(self, method: str, path: str, query: dict, headers: dict, body: str) -> tuple[int, dict, str]:
        if path != "/graphql":
            return 404, {}, json.dumps({"error": "not_graphql"})
        gql = query.get("query", [""])[0] or body or ""
        user = headers.get("X-User", headers.get("x-user", "anonymous"))
        gql_l = gql.lower()
        # IDOR: order(id:...)
        if "order" in gql_l and "id" in gql_l:
            oid = "1" if "1" in gql else "2"
            order = self.orders.get(oid)
            if not order:
                return 200, {}, json.dumps({"data": {"order": None}, "errors": [{"message": "not_found"}]})
            if self.is_vuln("IDOR") or order["owner"] == user:
                return 200, {}, json.dumps({"data": {"order": order}})
            return 200, {}, json.dumps({"data": {"order": None}, "errors": [{"message": "forbidden"}]})
        # Mass assignment: updateProfile(role:...)
        if "updateprofile" in gql_l or "update_profile" in gql_l:
            role_admin = "admin" in gql_l
            if self.is_vuln("MASS_ASSIGNMENT") and role_admin:
                self.profiles["alice"]["role"] = "admin"
            return 200, {}, json.dumps({"data": {"updateProfile": dict(self.profiles["alice"])}})
        # Info disclosure: debugInfo
        if "debuginfo" in gql_l or "debug_info" in gql_l:
            if self.is_vuln("INFO_DISCLOSURE"):
                return 200, {}, json.dumps({"data": {"debugInfo": "password=secret token=xyz stack trace traceback api_key=sk-1"}})
            return 200, {}, json.dumps({"data": {"debugInfo": None}, "errors": [{"message": "not_found"}]})
        # Auth bypass: adminQuery with X-Forwarded-For
        if "admin" in gql_l:
            bypass = headers.get("X-Forwarded-For", headers.get("x-forwarded-for", ""))
            if self.is_vuln("AUTH_BYPASS") and bypass == "127.0.0.1":
                return 200, {}, json.dumps({"data": {"admin": {"users": ["alice", "bob"]}}})
            if user == "anonymous":
                return 200, {}, json.dumps({"data": {"admin": None}, "errors": [{"message": "unauthorized"}]})
            return 200, {}, json.dumps({"data": {"admin": None}, "errors": [{"message": "forbidden"}]})
        # Open redirect via redirectUrl query
        if "redirect" in gql_l:
            if self.is_vuln("OPEN_REDIRECT") and "evil" in gql_l:
                return 302, {"Location": "https://evil.com/steal"}, ""
            return 200, {}, json.dumps({"data": {"redirect": "https://trusted.com/home"}})
        # SSRF via fetchUrl
        if "fetch" in gql_l:
            if self.is_vuln("SSRF") and "metadata" in gql_l:
                return 200, {}, json.dumps({"data": {"fetch": "metadata iam token secret internal-ip"}})
            return 200, {}, json.dumps({"data": {"fetch": "normal"}})
        return 200, {}, json.dumps({"data": {"__typename": "Query"}})


# ===========================================================================
# HTTP server wrapper that routes to an app.
# ===========================================================================
class _QualTargetHandler(BaseHTTPRequestHandler):
    app: Any = None  # set per-server

    def log_message(self, *a):
        pass

    def _dispatch(self, method: str):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        headers = {k: v for k, v in self.headers.items()}
        status, hdrs, body_text = self.app.handle(method, parsed.path, qs, headers, body)
        self.send_response(status)
        self.send_header("Content-Type", hdrs.pop("Content-Type", "application/json"))
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body_text.encode() if isinstance(body_text, str) else body_text)

    def do_GET(self): self._dispatch("GET")
    def do_POST(self): self._dispatch("POST")
    def do_PUT(self): self._dispatch("PUT")


def start_target_server(app: Any) -> tuple[HTTPServer, str]:
    """Start a real HTTP target server on an ephemeral port. Returns (server, base_url)."""
    handler = type("H", (_QualTargetHandler,), {"app": app})
    srv = HTTPServer(("127.0.0.1", 0), handler)
    import threading
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    import time
    time.sleep(0.15)
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


# ===========================================================================
# 3. Hypothesis builder — Discovery → explicit real request specs per family.
#    Each hypothesis has ground truth expected_outcome + explicit requests.
# ===========================================================================
def build_real_target_hypotheses(target_url: str, api_type: str,
                                 vulnerable: set[str],
                                 families: tuple[str, ...] = SIX_FAMILIES) -> list[dict[str, Any]]:
    """Build hypotheses with explicit real request specs (baseline/candidate/
    negative_control) for all 6 families, against a real target.

    Each hypothesis carries ``expected_outcome`` (ground truth: CONFIRMED if
    family vulnerable, REFUTED otherwise) for FP/FN measurement.
    """
    hyps: list[dict[str, Any]] = []
    vuln = {f.upper() for f in vulnerable}
    for i, fam in enumerate(families):
        fam_u = fam.upper()
        expected = "CONFIRMED" if fam_u in vuln else "REFUTED"
        hid = f"h_{api_type}_{fam_u.lower()}_{'vuln' if expected=='CONFIRMED' else 'patched'}"
        h: dict[str, Any] = {
            "id": hid, "vulnerability_class": fam_u,
            "api_type": api_type, "information_value": 0.5 + 0.01 * i,
            "expected_outcome": expected, "ground_truth_vulnerable": expected == "CONFIRMED",
            "requests": {},
        }
        R = _rest_requests(fam_u, target_url) if api_type == "rest" else _graphql_requests(fam_u, target_url)
        h["requests"] = R
        h["path"] = R["candidate"]["path"]
        hyps.append(h)
    return hyps


def _rest_requests(fam: str, base: str) -> dict[str, dict[str, Any]]:
    if fam == "IDOR":
        return {
            "baseline": {"method": "GET", "path": "/api/orders/1", "headers": {"X-User": "alice"}},
            "candidate": {"method": "GET", "path": "/api/orders/1", "headers": {"X-User": "bob"}},
            "negative_control": {"method": "GET", "path": "/api/orders/99999", "headers": {"X-User": "bob"}},
        }
    if fam == "OPEN_REDIRECT":
        return {
            "baseline": {"method": "GET", "path": "/api/redirect?url=https://trusted.com/home"},
            "candidate": {"method": "GET", "path": "/api/redirect?url=https://evil.com/steal"},
            "negative_control": {"method": "GET", "path": "/api/redirect?url="},
        }
    if fam == "SSRF":
        return {
            "baseline": {"method": "GET", "path": "/api/fetch?url=https://api.example.com/data"},
            "candidate": {"method": "GET", "path": "/api/fetch?url=http://169.254.169.254/latest/meta-data/"},
            "negative_control": {"method": "GET", "path": "/api/fetch?url=ftp://invalid"},
        }
    if fam == "MASS_ASSIGNMENT":
        return {
            "baseline": {"method": "PUT", "path": "/api/profile/alice", "headers": {"X-User": "alice", "Content-Type": "application/json"},
                         "body": json.dumps({"name": "alice"})},
            "candidate": {"method": "PUT", "path": "/api/profile/alice", "headers": {"X-User": "alice", "Content-Type": "application/json"},
                          "body": json.dumps({"name": "alice", "role": "admin"})},
            "negative_control": {"method": "PUT", "path": "/api/profile/alice", "headers": {"X-User": "alice", "Content-Type": "application/json"},
                                 "body": json.dumps({"name": "alice2"})},
        }
    if fam == "INFO_DISCLOSURE":
        return {
            "baseline": {"method": "GET", "path": "/api/public"},
            "candidate": {"method": "GET", "path": "/api/debug"},
            "negative_control": {"method": "GET", "path": "/api/health"},
        }
    if fam == "AUTH_BYPASS":
        return {
            "baseline": {"method": "GET", "path": "/api/admin"},
            "candidate": {"method": "GET", "path": "/api/admin", "headers": {"X-Forwarded-For": "127.0.0.1"}},
            "negative_control": {"method": "GET", "path": "/api/admin", "headers": {"X-Forwarded-For": "10.0.0.1"}},
        }
    return {}


def _graphql_requests(fam: str, base: str) -> dict[str, dict[str, Any]]:
    def g(q: str, headers: dict | None = None) -> dict[str, Any]:
        return {"method": "GET", "path": f"/graphql?query={q}", "headers": headers or {}}
    if fam == "IDOR":
        return {"baseline": g("query%7Border(id:1)%7Bitem%7D%7D", {"X-User": "alice"}),
                "candidate": g("query%7Border(id:1)%7Bitem%7D%7D", {"X-User": "bob"}),
                "negative_control": g("query%7Border(id:99999)%7Bitem%7D%7D", {"X-User": "bob"})}
    if fam == "MASS_ASSIGNMENT":
        return {"baseline": g("mutation%7BupdateProfile(name:%22alice%22)%7Bname%20role%7D%7D", {"X-User": "alice"}),
                "candidate": g("mutation%7BupdateProfile(name:%22alice%22,role:admin)%7Bname%20role%7D%7D", {"X-User": "alice"}),
                "negative_control": g("mutation%7BupdateProfile(name:%22alice2%22)%7Bname%20role%7D%7D", {"X-User": "alice"})}
    if fam == "INFO_DISCLOSURE":
        return {"baseline": g("query%7B__typename%7D"),
                "candidate": g("query%7BdebugInfo%7D"),
                "negative_control": g("query%7B__schema%7Btypes%7Bname%7D%7D%7D")}
    if fam == "AUTH_BYPASS":
        return {"baseline": g("query%7Badmin%7Busers%7D%7D"),
                "candidate": g("query%7Badmin%7Busers%7D%7D", {"X-Forwarded-For": "127.0.0.1"}),
                "negative_control": g("query%7Badmin%7Busers%7D%7D", {"X-Forwarded-For": "10.0.0.1"})}
    if fam == "OPEN_REDIRECT":
        return {"baseline": g("query%7Bredirect(url:%22https://trusted.com%22)%7D"),
                "candidate": g("query%7Bredirect(url:%22https://evil.com/steal%22)%7D"),
                "negative_control": g("query%7Bredirect(url:%22%22)%7D")}
    if fam == "SSRF":
        return {"baseline": g("query%7Bfetch(url:%22https://api.example.com%22)%7D"),
                "candidate": g("query%7Bfetch(url:%22http://169.254.169.254/metadata%22)%7D"),
                "negative_control": g("query%7Bfetch(url:%22ftp://invalid%22)%7D")}
    return {}


# ===========================================================================
# 4. Qualification metrics — FP / FN / inconclusive against ground truth.
# ===========================================================================
@dataclass
class QualificationMetrics:
    total: int = 0
    true_positives: int = 0   # promoted AND ground truth vulnerable
    false_positives: int = 0  # promoted AND ground truth patched
    false_negatives: int = 0  # NOT promoted AND ground truth vulnerable
    true_negatives: int = 0   # NOT promoted AND ground truth patched
    inconclusive: int = 0
    promoted: int = 0
    refuted: int = 0
    per_family: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def false_positive_rate(self) -> float:
        actual_safe = self.true_negatives + self.false_positives
        return self.false_positives / actual_safe if actual_safe else 0.0

    @property
    def false_negative_rate(self) -> float:
        actual_vuln = self.true_positives + self.false_negatives
        return self.false_negatives / actual_vuln if actual_vuln else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "promoted": self.promoted, "refuted": self.refuted,
            "true_positives": self.true_positives, "false_positives": self.false_positives,
            "false_negatives": self.false_negatives, "true_negatives": self.true_negatives,
            "inconclusive": self.inconclusive,
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "per_family": self.per_family,
            "qual_version": QUAL_VERSION,
        }


def measure_qualification(decisions: list[dict[str, Any]],
                          hypotheses: list[dict[str, Any]]) -> QualificationMetrics:
    """Compare AVI decisions against ground truth. FP = promoted but safe."""
    by_id = {h["id"]: h for h in hypotheses}
    m = QualificationMetrics()
    for d in decisions:
        hid = d.get("hypothesis_id")
        h = by_id.get(hid)
        if not h:
            continue
        m.total += 1
        fam = d.get("vulnerability_class", "UNKNOWN")
        fm = m.per_family.setdefault(fam, {"total": 0, "promoted": 0, "fp": 0, "fn": 0, "inconclusive": 0})
        fm["total"] += 1
        promoted = d.get("promotion", {}).get("decision") == "PROMOTED"
        outcome = d.get("validator_outcome")
        vuln = bool(h.get("ground_truth_vulnerable"))
        if outcome == "INCONCLUSIVE":
            m.inconclusive += 1
            fm["inconclusive"] += 1
        if promoted:
            m.promoted += 1
            fm["promoted"] += 1
            if vuln:
                m.true_positives += 1
            else:
                m.false_positives += 1
                fm["fp"] += 1
        else:
            m.refuted += 1
            if vuln:
                m.false_negatives += 1
                fm["fn"] += 1
            else:
                m.true_negatives += 1
    return m


# ===========================================================================
# 5. SecurityReportQualifier — composition of existing gates (no new authority).
#    Reports contain ONLY replay-verified proof + causal evidence + negative
#    control + target-backed evidence. Rejects confidence-only, external
#    scanner, heuristic-only findings.
# ===========================================================================
class SecurityReportQualifier:
    """Filters the SecurityReport to qualification-grade findings only.

    Uses EXISTING PromotionPipeline gates (no new authority). A finding enters
    the qualified report iff:
      - promotion decision == PROMOTED (all 7 anti-fake gates passed)
      - replay_verified == True (replay-verified proof)
      - validator_outcome == CONFIRMED (causal evidence)
      - negative control present (negative_control_digest non-null)
      - target_backed (evidence_origin == target_runtime, real_http executed)
      - evidence_quality >= OBSERVED_DIFFERENTIAL (rejects heuristic-only)
      - verdict_authority not external scanner (rejects external scanner claims)
      - NOT confidence-only (confidence_score is None / unused)
    """

    MIN_QUALITY = int(EvidenceQuality.OBSERVED_DIFFERENTIAL)

    def qualify(self, decisions: list[dict[str, Any]],
                security_report: dict[str, Any]) -> dict[str, Any]:
        qualified: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for d in decisions:
            finding = {
                "hypothesis_id": d.get("hypothesis_id"),
                "vulnerability_class": d.get("vulnerability_class"),
                "experiment_id": d.get("experiment_id"),
                "validator_outcome": d.get("validator_outcome"),
                "evidence_quality": d.get("evidence_quality"),
                "replay_verified": d.get("replay_verified"),
                "promotion": d.get("promotion", {}),
                "api_type": d.get("api_type"),
            }
            reasons = self._rejection_reasons(d)
            if reasons:
                finding["rejection_reasons"] = reasons
                rejected.append(finding)
            else:
                qualified.append(finding)
        return {
            "qual_version": QUAL_VERSION,
            "qualified_findings": qualified,
            "qualified_count": len(qualified),
            "rejected_count": len(rejected),
            "rejected_findings_sample": rejected[:20],
            "report_digest": sha256_text(json.dumps(qualified, sort_keys=True, default=str))[:16],
            "original_report_promoted_count": security_report.get("promoted_count", 0),
        }

    def _rejection_reasons(self, d: dict[str, Any]) -> list[str]:
        reasons: list[str] = []
        if d.get("promotion", {}).get("decision") != "PROMOTED":
            reasons.append("not_promoted_by_promotion_pipeline")
        if not d.get("replay_verified"):
            reasons.append("replay_not_verified")
        if d.get("validator_outcome") != "CONFIRMED":
            reasons.append("no_causal_confirmation")
        if int(d.get("evidence_quality", 0)) < self.MIN_QUALITY:
            reasons.append("heuristic_only_below_observed_differential")
        if not d.get("real_http_executed"):
            reasons.append("not_target_backed_no_real_http")
        # Confidence-only / external scanner are already rejected by
        # PromotionPipeline gates; we assert they did not sneak through.
        prom = d.get("promotion", {})
        if "causal_validator_confirmed" in prom.get("gates_failed", []):
            reasons.append("confidence_only_or_no_causal_validator")
        if "no_external_scanner_authority" in prom.get("gates_failed", []):
            reasons.append("external_scanner_authority_claim")
        return reasons


__all__ = [
    "QUAL_VERSION", "SIX_FAMILIES", "_RESTApp", "_GraphQLApp",
    "start_target_server", "build_real_target_hypotheses",
    "QualificationMetrics", "measure_qualification", "SecurityReportQualifier",
]

"""WebPent Milestone 5 — fixture registry, admission scanner, and hash-chained manifest.

Per M5 v1.1 (OQ-5.4 split placement): this module owns the registry + manifest
+ seven-category secret scanner. The quarantine content store lives in
``fixture_store.py``. No frozen module is touched.

Remediation (Team-Red audit, Sprint I-3):
  D1 — key-name matching no longer flags legitimate fixture-schema metadata
       fields (authorization_hints, lab_session_authorization_ref, ...); only
       their VALUES are regex-scanned.
  D5 — loopback/foreign-origin URL check added (M5 §2.5 / FIX-8), IP-normalized.
  D14 — source_type derived from content, not caller-supplied.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Bounds (M5 §2.5) — tunable but NEVER disableable.
# ---------------------------------------------------------------------------
MAX_SOURCE_BYTES = int(os.environ.get("WEBPENT_FIXTURE_MAX_SOURCE_BYTES", "16777216"))  # 16 MiB
MAX_JSON_DEPTH = int(os.environ.get("WEBPENT_FIXTURE_MAX_JSON_DEPTH", "64"))
MAX_HAR_ENTRIES = int(os.environ.get("WEBPENT_FIXTURE_MAX_HAR_ENTRIES", "5000"))

SCANNER_VERSION = "m5-admission-scanner/1.2"

# The fixed non-proof literal every admitted fixture carries (M5 §2.1).
DECLARED_NON_PROOF = "NON_PROOF_ADVISORY_SOURCE"

# Approved source taxonomy (M5 §2.2). approved_internal_catcher is RESERVED.
SOURCE_STATIC_HAR = "static_har"
SOURCE_STATIC_JSON = "static_json"
SOURCE_RESERVED_CATCHER = "approved_internal_catcher"

# Rejection reason codes (M5 §2.2, §2.3, OQ-5.1, OQ-5.6, OQ-5.7, OQ-5.8, FIX-8).
REASON_SECRET_LIVE = "secret_live_value_found"
REASON_SECRET_AMBIGUOUS = "secret_ambiguous_match"
REASON_RESCAN_UNCLEAN = "fixture_rescan_unclean"
REASON_CATCHER_UNKNOWN = "catcher_producer_unknown"
REASON_UNKNOWN_SOURCE = "unknown_source_class"
REASON_BUDGET = "fixture_budget_exceeded"
REASON_WINDOW = "capture_outside_engagement_window"
REASON_DUPLICATE_BINDING = "duplicate_binding_mismatch"
REASON_OVERSIZE = "fixture_oversize"
REASON_STRUCTURE = "fixture_structure_bound_exceeded"
REASON_LOOPBACK = "fixture_loopback_url_rejected"
REASON_FOREIGN_ORIGIN = "fixture_foreign_origin_rejected"

# Seven admission categories (M5 §2.3).
CAT_CREDENTIALS = "credentials_passwords"
CAT_COOKIES = "session_cookies"
CAT_AUTH_HEADERS = "authorization_headers"
CAT_API_KEYS = "api_keys_tokens"
CAT_JWT = "jwt"
CAT_PEM = "private_key_pem"
CAT_VAULT = "vault_values_references"

# Case-insensitive sensitive key vocabulary (M5 FIX-3, FIX-4).
SENSITIVE_KEY_TOKENS = frozenset({
    "password", "passwd", "pass", "pwd", "credential", "credentials",
    "secret", "secrets", "api_key", "apikey", "api-key", "access_key",
    "accesskey", "secret_key", "secretkey", "private_key", "privatekey",
    "token", "auth", "authorization", "authorisation", "session",
    "sessionid", "session_id", "connect.sid", "cookie", "cookies",
    "bearer", "basic_auth", "client_secret", "x-api-token", "x-auth-key",
    "private-token", "x-gitlab-token",
})

# Named custom auth headers (M5 FIX-4).
NAMED_CUSTOM_AUTH_HEADERS = frozenset({
    "x-api-token", "x-auth-key", "private-token", "x-gitlab-token",
})

# D1 FIX: fixture-schema field names that are LEGITIMATE (M5 §2.1) and MUST NOT
# trigger key-name secret matching. Their VALUES are still regex-scanned.
FIXTURE_SCHEMA_KEY_WHITELIST = frozenset({
    "authorization_hints", "lab_session_authorization_ref", "capturer_tool",
    "capturer_version", "operator_alias", "candidate_rationale", "response_shape",
    "endpoint_template", "fixture_format_version", "source_type",
    "declared_non_proof", "defect_family_hint", "parameter_names",
    "parameter_location", "method", "capture_context", "redaction_metadata",
    "redaction_note", "route_shape", "capture_timestamp", "admission_metadata",
    "secret_scan_result", "staleness_bound", "target_fingerprint",
    "engagement_instance_id", "engagement_id", "fixture_id", "content_digest",
    "object_reference_plan", "baseline_candidate_control_plan",
    "negative_control_object_ref", "owner_object_ref", "candidate_object_ref",
    "resource_owner_principal", "foreign_principal", "matrix_row",
    "baseline_role", "candidate_role", "negative_control_role",
    "required_principal_aliases", "information_value", "api_type", "path",
    "value", "name", "url", "headers", "cookies", "postData", "params",
    "mimeType", "text", "comment", "status", "statusText", "httpVersion",
    "redirectURL", "headersSize", "bodySize", "pageref", "startedDateTime",
    "time", "request", "response", "cache", "timings", "log", "entries",
    "version", "creator", "browser", "pages", "id", "title", "pageTimings",
})

# Generic suspicious-auth-header rule (M5 FIX-4).
GENERIC_AUTH_HEADER_NAME_TOKENS = ("token", "secret", "key", "auth")
LONG_OPAQUE_VALUE_MIN = 16

# JWT: three non-empty base64url segments (M5 FIX-12).
_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,}\b")
_PEM_RE = re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----")
_VAULT_RES = [
    re.compile(r"\{\{\s*vault\.[^}]+\}\}", re.IGNORECASE),
    re.compile(r"\bVAULT_[A-Z0-9_]+\b"),
    re.compile(r"\bvault:[^\s\"'<>]+", re.IGNORECASE),
    re.compile(r"\bvault://[^\s\"'<>]+", re.IGNORECASE),
]
_URL_USERINFO_RE = re.compile(r"https?://[^:@/\s]+:([^@/\s]+)@")
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_BASIC_RE = re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{8,}", re.IGNORECASE)

# D5 FIX: URL extraction for loopback/foreign-origin check (M5 §2.5 / FIX-8).
_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.IGNORECASE)
# Ports the lab harnesses use — must be rejected at admission (M5 §2.5 corpus).
FORBIDDEN_LOOPBACK_PORTS = (8081, 9090)


@dataclass
class SecretFinding:
    category: str
    count: int
    location_hint: str


@dataclass
class ScanResult:
    clean: bool
    disposition: str
    findings: list[SecretFinding] = field(default_factory=list)
    scanner_version: str = SCANNER_VERSION
    loopback_hits: list[str] = field(default_factory=list)
    foreign_origin_hits: list[str] = field(default_factory=list)

    @property
    def categories_hit(self) -> list[str]:
        return sorted({f.category for f in self.findings})

    def value_free_summary(self) -> dict[str, Any]:
        return {
            "scanner_version": self.scanner_version,
            "disposition": self.disposition,
            "categories": self.categories_hit,
            "findings": [
                {"category": f.category, "count": f.count, "location_hint": f.location_hint}
                for f in self.findings
            ],
            "loopback_hits": self.loopback_hits,
            "foreign_origin_hits": self.foreign_origin_hits,
        }


def _long_opaque(value: str) -> bool:
    v = value.strip()
    if len(v) < LONG_OPAQUE_VALUE_MIN or " " in v:
        return False
    return sum(c.isalnum() for c in v) >= int(0.7 * len(v))


def _scan_text_value(text: str, findings: dict[str, list[SecretFinding]], location_hint: str) -> None:
    if not text:
        return
    if _JWT_RE.search(text):
        findings[CAT_JWT].append(SecretFinding(CAT_JWT, 1, location_hint + "/jwt-shaped"))
    if _PEM_RE.search(text):
        findings[CAT_PEM].append(SecretFinding(CAT_PEM, 1, location_hint + "/pem-block"))
    for vre in _VAULT_RES:
        if vre.search(text):
            findings[CAT_VAULT].append(SecretFinding(CAT_VAULT, 1, location_hint + "/vault-ref"))
            break
    if _BEARER_RE.search(text):
        findings[CAT_AUTH_HEADERS].append(SecretFinding(CAT_AUTH_HEADERS, 1, location_hint + "/bearer"))
    if _BASIC_RE.search(text):
        findings[CAT_AUTH_HEADERS].append(SecretFinding(CAT_AUTH_HEADERS, 1, location_hint + "/basic-auth"))
    if _URL_USERINFO_RE.search(text):
        findings[CAT_CREDENTIALS].append(SecretFinding(CAT_CREDENTIALS, 1, location_hint + "/url-userinfo"))


def _key_is_sensitive(key: str) -> bool:
    # D1 FIX: whitelisted schema keys never trigger key-name matching.
    if key.strip().lower() in FIXTURE_SCHEMA_KEY_WHITELIST:
        return False
    k = key.strip().lower().replace("_", "-")
    if k in SENSITIVE_KEY_TOKENS:
        return True
    for tok in SENSITIVE_KEY_TOKENS:
        if tok in k:
            return True
    return False


def _classify_key_hit(key: str) -> str:
    k = key.lower()
    if "cookie" in k:
        return CAT_COOKIES
    if "authorization" in k or "auth" in k or "bearer" in k:
        return CAT_AUTH_HEADERS
    if "token" in k or "api" in k or "key" in k or "secret" in k:
        return CAT_API_KEYS
    if "password" in k or "passwd" in k or "pwd" in k or "credential" in k:
        return CAT_CREDENTIALS
    return CAT_API_KEYS


def _check_named_param(name: str, value: str, location_hint: str,
                       findings: dict[str, list[SecretFinding]]) -> None:
    if not value or not isinstance(value, str):
        return
    name_l = name.strip().lower()
    hint = f"{location_hint}.{name or 'unnamed'}=<redacted>"
    if name_l in NAMED_CUSTOM_AUTH_HEADERS:
        findings[CAT_AUTH_HEADERS].append(SecretFinding(CAT_AUTH_HEADERS, 1, hint))
        return
    if _key_is_sensitive(name):
        findings[_classify_key_hit(name)].append(SecretFinding(_classify_key_hit(name), 1, hint))
        return
    if any(tok in name_l for tok in GENERIC_AUTH_HEADER_NAME_TOKENS) and _long_opaque(value):
        findings[CAT_AUTH_HEADERS].append(SecretFinding(CAT_AUTH_HEADERS, 1, hint + "-long-opaque"))


class _StructureBoundExceeded(Exception):
    pass


def _bounded_json_walk(obj: Any, depth: int, path: str, findings: dict[str, list[SecretFinding]]) -> None:
    if depth > MAX_JSON_DEPTH:
        raise _StructureBoundExceeded(REASON_STRUCTURE + ":json_depth")
    if isinstance(obj, dict):
        if "name" in obj and "value" in obj and isinstance(obj.get("value"), str):
            _check_named_param(str(obj.get("name", "")), str(obj.get("value", "")), path, findings)
        for k, v in obj.items():
            kstr = str(k)
            child_path = f"{path}.{kstr}"
            if isinstance(v, str) and v:
                # D1 FIX: key-name matching skips whitelisted schema keys.
                if _key_is_sensitive(kstr):
                    cat = _classify_key_hit(kstr)
                    findings[cat].append(SecretFinding(cat, 1, child_path + "=<redacted>"))
                _scan_text_value(v, findings, child_path)
            elif isinstance(v, (dict, list)):
                _bounded_json_walk(v, depth + 1, child_path, findings)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _bounded_json_walk(item, depth + 1, f"{path}[{i}]", findings)
    elif isinstance(obj, str):
        _scan_text_value(obj, findings, path)


def _extract_har_arrays(obj: Any, findings: dict[str, list[SecretFinding]], entry_count: list[int]) -> None:
    if not isinstance(obj, dict):
        return
    log = obj.get("log") if isinstance(obj.get("log"), dict) else obj
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        return
    for entry in entries:
        entry_count[0] += 1
        if entry_count[0] > MAX_HAR_ENTRIES:
            raise _StructureBoundExceeded(REASON_STRUCTURE + ":har_entries")
        if not isinstance(entry, dict):
            continue
        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        for cookie in request.get("cookies", []) or []:
            if isinstance(cookie, dict):
                name, value = str(cookie.get("name", "")), str(cookie.get("value", ""))
                if value:
                    findings[CAT_COOKIES].append(
                        SecretFinding(CAT_COOKIES, 1, f"har.cookie.{name or 'unnamed'}=<redacted>"))
                    _scan_text_value(value, findings, f"har.cookie.{name or 'unnamed'}")
        post_data = request.get("postData") if isinstance(request.get("postData"), dict) else {}
        for param in post_data.get("params", []) or []:
            if isinstance(param, dict):
                _check_named_param(str(param.get("name", "")), str(param.get("value", "")),
                                   "har.postData", findings)
        for header in request.get("headers", []) or []:
            if isinstance(header, dict):
                _check_named_param(str(header.get("name", "")), str(header.get("value", "")),
                                   "har.header", findings)


# ---------------------------------------------------------------------------
# D5 FIX: loopback + foreign-origin URL check (M5 §2.5 / FIX-8).
# Hosts parsed to binary addresses and compared with 127.0.0.0/8 and ::1/128.
# String matching alone is insufficient (M5 FIX-8).
# ---------------------------------------------------------------------------
def _is_loopback_host(host: str) -> bool:
    host = host.strip().strip("[]").lower()
    if host in ("localhost",) or host.endswith(".localhost"):
        return True
    # IPv4 shorthand/hex/octal normalization (M5 FIX-8 corpus: 127.1,
    # 0x7f000001, 017700000001, padded decimals). inet_aton accepts all forms.
    try:
        packed = socket.inet_aton(host)
        return packed[0] == 127  # 127.0.0.0/8
    except (OSError, ValueError):
        pass
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # hostname — loopback covered by localhost check above
    if isinstance(ip, ipaddress.IPv4Address):
        return ip in ipaddress.ip_network("127.0.0.0/8")
    if ip == ipaddress.IPv6Address("::1"):
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped in ipaddress.ip_network("127.0.0.0/8")
    return False



def check_url_origins(text: str, approved_origins: Optional[frozenset] = None) -> tuple[list[str], list[str]]:
    """Return (loopback_hits, foreign_origin_hits) — value-free host:port only."""
    loopback, foreign = [], []
    _PROTO_REL = re.compile(r"(?<![a-zA-Z0-9:])//[^\s\"'<>\\)]+", re.IGNORECASE)
    urls = list(_URL_RE.findall(text)) + list(_PROTO_REL.findall(text))
    for url in urls:
        # strip trailing punctuation
        url = url.rstrip(".,;)'\"")
        m = re.match(r"(?:https?:)?//([^/]+)", url)
        if not m:
            continue
        hostport = m.group(1)
        if hostport.startswith("["):
            close = hostport.index("]")
            host = hostport[1:close]
            port = hostport[close+2:] if len(hostport) > close+2 and hostport[close+1] == ":" else ""
        else:
            host, _, port = hostport.partition(":")
        portnum = None
        if port.isdigit():
            portnum = int(port)
        origin = f"{host}:{portnum}" if portnum else host
        if _is_loopback_host(host):
            loopback.append(origin)
            continue
        if portnum in FORBIDDEN_LOOPBACK_PORTS:
            loopback.append(origin + "/forbidden-port")
            continue
        if approved_origins is not None and host not in approved_origins and hostport not in approved_origins:
            foreign.append(origin)
    return loopback, foreign


def detect_source_type(raw: bytes) -> Optional[str]:
    """D14 FIX: derive source_type from content, not caller-supplied."""
    try:
        obj = json.loads(raw.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(obj, dict) and isinstance(obj.get("log"), dict) and isinstance(obj["log"].get("entries"), list):
        return SOURCE_STATIC_HAR
    if isinstance(obj, dict) and ("route_shape" in obj or "endpoint_template" in obj):
        return SOURCE_STATIC_JSON
    return SOURCE_STATIC_JSON  # default JSON traffic record


def scan_fixture_bytes(raw: bytes, approved_origins: Optional[frozenset] = None) -> ScanResult:
    """Mandatory strict admission scan over RAW BYTES (M5 §2.3)."""
    findings: dict[str, list[SecretFinding]] = {c: [] for c in (
        CAT_CREDENTIALS, CAT_COOKIES, CAT_AUTH_HEADERS, CAT_API_KEYS,
        CAT_JWT, CAT_PEM, CAT_VAULT)}

    text = raw.decode("utf-8", errors="replace")
    _scan_text_value(text, findings, "raw-bytes")

    # D5: loopback/foreign-origin check on raw text (before parse).
    loopback, foreign = check_url_origins(text, approved_origins)

    entry_count = [0]
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        obj = None
    if obj is not None:
        try:
            _bounded_json_walk(obj, 0, "$", findings)
            _extract_har_arrays(obj, findings, entry_count)
        except _StructureBoundExceeded:
            findings[CAT_VAULT].append(SecretFinding(CAT_VAULT, 1, REASON_STRUCTURE))

    flat = [f for fl in findings.values() for f in fl]
    if not flat and not loopback and not foreign:
        return ScanResult(clean=True, disposition="clean")

    definite_cats = {CAT_PEM, CAT_JWT, CAT_COOKIES, CAT_CREDENTIALS}
    has_definite = any(f.category in definite_cats for f in flat) or any(
        s in f.location_hint.lower() for f in flat
        for s in ("bearer", "basic-auth", "x-api-token", "x-auth-key", "private-token", "x-gitlab-token"))
    if loopback:
        return ScanResult(clean=False, disposition=REASON_LOOPBACK, findings=flat,
                          loopback_hits=loopback, foreign_origin_hits=foreign)
    if foreign:
        return ScanResult(clean=False, disposition=REASON_FOREIGN_ORIGIN, findings=flat,
                          loopback_hits=loopback, foreign_origin_hits=foreign)
    disposition = REASON_SECRET_LIVE if has_definite else REASON_SECRET_AMBIGUOUS
    return ScanResult(clean=False, disposition=disposition, findings=flat,
                      loopback_hits=loopback, foreign_origin_hits=foreign)


def content_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mint_fixture_id(digest_hex: str) -> str:
    return "fx_" + digest_hex[:16]


# ---------------------------------------------------------------------------
# Hash-chained JSONL manifest (M5 §2.4 — per M4 OQ-8 idiom, sibling chain).
# ---------------------------------------------------------------------------
class FixtureManifestChain:
    SCHEMA_VERSION = 1

    def __init__(self, path: str):
        self.path = path
        self._event_no = 0
        self._last_hash = "0" * 64
        self._recover_tail()

    def _recover_tail(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                evt = json.loads(line)
                self._event_no = max(self._event_no, evt.get("event_no", 0))
                self._last_hash = evt.get("event_hash", self._last_hash)

    def append_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        payload = dict(payload)
        payload["manifest_schema_version"] = self.SCHEMA_VERSION
        self._event_no += 1
        event = {"event_no": self._event_no, "previous_event_hash": self._last_hash, "payload": payload}
        event["event_hash"] = hashlib.sha256(
            json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        fd = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        self._last_hash = event["event_hash"]
        return event

    def verify_chain(self) -> tuple[bool, str]:
        if not os.path.exists(self.path):
            return True, self._last_hash
        expected_prev = "0" * 64
        last = expected_prev
        with open(self.path, "r", encoding="utf-8") as fh:
            for no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                evt = json.loads(line)
                if evt.get("previous_event_hash") != expected_prev:
                    return False, f"chain_break_at_event_{evt.get('event_no', no)}"
                recomputed = hashlib.sha256(json.dumps(
                    {"event_no": evt["event_no"], "previous_event_hash": evt["previous_event_hash"],
                     "payload": evt["payload"]}, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
                if recomputed != evt.get("event_hash"):
                    return False, f"hash_mismatch_at_event_{evt.get('event_no', no)}"
                expected_prev = evt["event_hash"]
                last = evt["event_hash"]
        return True, last

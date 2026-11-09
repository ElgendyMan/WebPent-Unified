"""U-DEEP-18 — Web Cache Deception.

Family: CACHE_DECEPTION. Detection principle: the deception exists
only when the SAME crafted static-looking path serves the victim's
sensitive body to an unauthenticated attacker — body equality between
the cookie-bearing and the cookie-less request, plus a documented
sensitivity check on the shared body. Anything less is not a finding.

Zero live network: the transport is the injected ``send(path,
cookies)`` callable; findings are advisory evidence only
(DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

from dataclasses import dataclass

# Spec corpus, verbatim (U-DEEP-18).
CACHE_DECEPTION_PATHS: list[str] = ["/profile", "/api/user", "/account"]
STATIC_EXTS: list[str] = [
    ".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff"]
CACHE_DECEPTION_HEADERS: list[str] = [
    "X-Original-URL: /profile",
    "X-Rewrite-URL: /profile",
]

# Sensitivity markers for the documented is_sensitive check: a body is
# treated as sensitive when it carries personal-state content, not
# generic HTML.
SENSITIVE_MARKERS: tuple[str, ...] = (
    "balance", "email", "username", "token", "password", "api_key",
    "session", "ssn", "phone", "address", "order", "invoice",
)

_MARKER_SENTINEL = "static"


@dataclass(frozen=True)
class CacheDeceptionFinding:
    crafted_path: str
    endpoint: str
    static_ext: str
    evidence: tuple[str, ...]
    family: str = "CACHE_DECEPTION"
    confidence: float = 0.9
    statement: str = ""
    success_indicator: str = ""


def is_sensitive(body: str) -> bool:
    """Documented sensitivity check: lowercased marker scan."""
    lowered = body.lower()
    return any(marker in lowered for marker in SENSITIVE_MARKERS)


class CacheDeceptionDetector:
    """Crafts static-looking paths under sensitive endpoints and
    compares the victim's and the attacker's views of the same URL."""

    def __init__(self, send, victim_cookies: dict | None = None) -> None:
        self._send = send
        self._victim_cookies = victim_cookies or {}

    def crafted_paths(self) -> list[str]:
        return [f"{endpoint}/static{ext}"
                for endpoint in CACHE_DECEPTION_PATHS
                for ext in STATIC_EXTS]

    def scan(self) -> list[CacheDeceptionFinding]:
        findings: list[CacheDeceptionFinding] = []
        for endpoint in CACHE_DECEPTION_PATHS:
            for ext in STATIC_EXTS:
                finding = self._probe(endpoint, ext)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _probe(self, endpoint: str, ext: str) -> CacheDeceptionFinding | None:
        crafted = f"{endpoint}/static{ext}"
        victim = self._send(crafted, cookies=self._victim_cookies)
        attacker = self._send(crafted, cookies=None)
        victim_body = victim.body
        attacker_body = attacker.body
        if victim_body != attacker_body:
            return None
        if not is_sensitive(victim_body):
            return None
        evidence = (
            f"crafted_path: {crafted}",
            f"endpoint: {endpoint} static_ext: {ext}",
            f"victim view (authenticated cookies) == attacker view "
            f"(no cookies): {len(victim_body)} bytes, identical bodies",
            f"shared body carries sensitive markers: "
            f"{is_sensitive(victim_body)}",
            "cache deception: the unauthenticated attacker receives the "
            "victim's cached sensitive response",
        )
        return CacheDeceptionFinding(
            crafted_path=crafted,
            endpoint=endpoint,
            static_ext=ext,
            evidence=evidence,
            statement=(
                f"Web cache deception on {crafted}: the same static-"
                "looking path serves the victim's sensitive body to an "
                "unauthenticated attacker — advisory; verify against an "
                "authorized target."),
            success_indicator=(
                f"identical, sensitive bodies for {crafted} with and "
                "without cookies"),
        )

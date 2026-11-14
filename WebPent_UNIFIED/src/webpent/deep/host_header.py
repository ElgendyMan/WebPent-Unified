"""U-DEEP-5 — Host Header Injection.

Family: HOST_HEADER_INJECTION. Detection principle: CONTEXT OVER
CONTENT — what matters is what the application DOES with the Host
(reset links, redirects, cache keys, internal routing), never whether
a header merely echoes. Every sub-family compares a probe against a
clean baseline: identical behavior is never a finding.

Zero live network: the transport is the injected
``send(method, path, headers)`` callable; findings are advisory
evidence only (DEEP-L-8 ADVISORY_ONLY).

Sub-family severities (spec): password reset poisoning CRITICAL (ATO),
cache poisoning HIGH, internal routing HIGH, open redirect MEDIUM.
"""
from __future__ import annotations

from dataclasses import dataclass

# Spec payload corpus, verbatim structure (U-DEEP-5).
HOST_HEADER_PAYLOADS: dict[str, list[str]] = {
    "host_override": [
        "Host: evil.com",
        "Host: target.com.evil.com",
        "Host: target.com:evil",
        "Host: evil.com#target.com",
    ],
    "x_forwarded": [
        "X-Forwarded-Host: evil.com",
        "X-Forwarded-Server: evil.com",
        "X-HTTP-Host-Override: evil.com",
        "Forwarded: host=evil.com",
    ],
    "cache_poison": [
        "Host: target.com", "X-Forwarded-Host: evil.com",
    ],
    "route_based": [
        "Host: internal.target.com",
        "Host: 127.0.0.1",
        "Host: admin.target.com",
    ],
}

SEVERITY_BY_SUBFAMILY = {
    "password_reset_poisoning": "critical",
    "cache_poisoning": "high",
    "internal_routing_bypass": "high",
    "open_redirect_via_host": "medium",
}

_CLEAN_HEADERS = {"Host": "target.com"}
_INJECTED_HOST = "evil.com"


@dataclass(frozen=True)
class HostHeaderFinding:
    subfamily: str
    severity: str
    evidence: tuple[str, ...]
    request_header: str
    family: str = "HOST_HEADER_INJECTION"
    confidence: float = 0.9
    statement: str = ""
    success_indicator: str = ""


def _parse_header_line(line: str) -> tuple[str, str]:
    name, _, value = line.partition(":")
    return name.strip(), value.strip()


class HostHeaderDetector:
    """Probes the four Host-abuse surfaces against a clean baseline."""

    def __init__(self, send) -> None:
        self._send = send

    def run_all(self) -> list[HostHeaderFinding]:
        baseline = self._send("GET", "/", dict(_CLEAN_HEADERS))
        findings: list[HostHeaderFinding] = []
        findings.extend(self._password_reset(baseline))
        findings.extend(self._open_redirect(baseline))
        findings.extend(self._cache_poison(baseline))
        findings.extend(self._internal_routing(baseline))
        return findings

    # ------------------------------------------------------------------
    # 1. Password reset poisoning (critical)
    # ------------------------------------------------------------------

    def _password_reset(self, baseline) -> list[HostHeaderFinding]:
        findings: list[HostHeaderFinding] = []
        for line in HOST_HEADER_PAYLOADS["host_override"]:
            name, value = _parse_header_line(line)
            probe = self._send("POST", "/reset", {name: value})
            body = probe.body
            if _INJECTED_HOST not in body:
                continue
            if _INJECTED_HOST in baseline.body:
                continue
            findings.append(HostHeaderFinding(
                subfamily="password_reset_poisoning",
                severity=SEVERITY_BY_SUBFAMILY["password_reset_poisoning"],
                evidence=(
                    f"request_header: {line}",
                    f"baseline body: {baseline.body!r}",
                    f"probe body contains attacker host: {body!r}",
                ),
                request_header=line,
                statement=(
                    "Password-reset flow builds its link from the "
                    "attacker-supplied Host — account takeover vector "
                    "(advisory; verify against an authorized target)."),
                success_indicator=(
                    f"reset response embeds {_INJECTED_HOST} in a link "
                    "the baseline never contains"),
            ))
            break
        return findings

    # ------------------------------------------------------------------
    # 2. Open redirect via Host (medium)
    # ------------------------------------------------------------------

    def _open_redirect(self, baseline) -> list[HostHeaderFinding]:
        findings: list[HostHeaderFinding] = []
        for line in HOST_HEADER_PAYLOADS["x_forwarded"]:
            name, value = _parse_header_line(line)
            probe = self._send("GET", "/", {name: value})
            headers = probe.headers or {}
            location = headers.get("Location", "")
            if not location.startswith("http"):
                continue
            if _INJECTED_HOST not in location:
                continue
            if _INJECTED_HOST in (baseline.headers or {}).get("Location", ""):
                continue
            findings.append(HostHeaderFinding(
                subfamily="open_redirect_via_host",
                severity=SEVERITY_BY_SUBFAMILY["open_redirect_via_host"],
                evidence=(
                    f"request_header: {line}",
                    f"probe Location: {location!r}",
                    f"baseline status: {baseline.status_code}",
                ),
                request_header=line,
                statement=(
                    "Redirect target is derived from the injected "
                    f"forwarded host ({name}) — advisory; verify against "
                    "an authorized target."),
                success_indicator=(
                    f"Location header points at {_INJECTED_HOST} only "
                    "for the injected header"),
            ))
            break
        return findings

    # ------------------------------------------------------------------
    # 3. Cache poisoning via forwarded Host (high)
    # ------------------------------------------------------------------

    def _cache_poison(self, baseline) -> list[HostHeaderFinding]:
        clean = baseline.body
        probe = self._send("GET", "/", {"X-Forwarded-Host": _INJECTED_HOST})
        # A later, clean request must now serve attacker-influenced
        # content for a cache key to have been poisoned.
        follow_up = self._send("GET", "/", dict(_CLEAN_HEADERS))
        follow_body = follow_up.body
        if _INJECTED_HOST in follow_body and follow_body != clean:
            return [HostHeaderFinding(
                subfamily="cache_poisoning",
                severity=SEVERITY_BY_SUBFAMILY["cache_poisoning"],
                evidence=(
                    f"request_header: X-Forwarded-Host: {_INJECTED_HOST}",
                    f"baseline body: {clean!r}",
                    f"follow-up (clean headers) body: {follow_body!r}",
                ),
                request_header=f"X-Forwarded-Host: {_INJECTED_HOST}",
                statement=(
                    "Cache key includes the forwarded Host: an injected "
                    "value poisons content served to later clean "
                    "requests (advisory; verify against an authorized "
                    "target)."),
                success_indicator=(
                    "a clean follow-up request returns content carrying "
                    f"the injected host {_INJECTED_HOST}"),
            )]
        return []

    # ------------------------------------------------------------------
    # 4. Internal routing bypass (high)
    # ------------------------------------------------------------------

    def _internal_routing(self, baseline) -> list[HostHeaderFinding]:
        findings: list[HostHeaderFinding] = []
        baseline_status = baseline.status_code
        for line in HOST_HEADER_PAYLOADS["route_based"]:
            name, value = _parse_header_line(line)
            probe = self._send("GET", "/admin", {name: value})
            probe_status = probe.status_code
            # Access granted (2xx) where the clean request was refused
            # (4xx) — the Host switched the routing/auth decision.
            if baseline_status is not None and baseline_status >= 400 \
                    and probe_status is not None and probe_status < 300:
                findings.append(HostHeaderFinding(
                    subfamily="internal_routing_bypass",
                    severity=SEVERITY_BY_SUBFAMILY[
                        "internal_routing_bypass"],
                    evidence=(
                        f"request_header: {line}",
                        f"baseline status: {baseline_status}",
                        f"probe status: {probe_status}",
                        f"probe body: {probe.body!r}",
                    ),
                    request_header=line,
                    statement=(
                        f"Host {value!r} routes the request past "
                        "authentication — internal interface reachable "
                        "from outside (advisory; verify against an "
                        "authorized target)."),
                    success_indicator=(
                        f"status {baseline_status} on the clean request "
                        f"vs {probe_status} with the internal Host"),
                ))
                break
        return findings

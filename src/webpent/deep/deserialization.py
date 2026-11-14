"""U-DEEP-15 — Deserialization.

Family: DESERIALIZATION. Six language signatures with their magic
bytes (spec verbatim); identification by decoded magic bytes, base64
prefix or raw marker, then canary-only probing — no gadget chains,
no ysoserial/PHPGGC payloads, ever. Detection principle: EFFECT OVER
ECHO — a canary is only a finding when the target actually
deserializes it (an executed side-effect marker that was never
echoed, a serializer-error timing profile, or a response diff against
the clean baseline), never when the input is merely reflected.

Zero live network: the transport is the injected
``send(endpoint, body)`` callable; findings are advisory evidence only
(DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass

CANARY_MARKER = "webpent-deser-canary"

TIMING_THRESHOLD_MS = 500

# Spec corpus, verbatim structure (U-DEEP-15): six languages.
DESERIALIZATION_SIGNATURES: dict[str, dict] = {
    "java": {"tool": "ysoserial", "magic_bytes": b"\xac\xed\x00\x05"},
    "php": {"tool": "PHPGGC", "raw_prefixes": ("O:", "a:")},
    "python": {"tool": "pickle", "magic_bytes": b"\x80\x04\x95"},
    "dotnet": {"tool": "ysoserial.net", "base64_magic": "AAEAAAD/"},
    "ruby": {"tool": "Marshal", "magic_bytes": b"\x04\x08"},
    "nodejs": {"tool": "node-serialize",
               "raw_magic": "_$$ND_FUNC$$_"},
}

SEVERITY_BY_SUBFAMILY = {
    "rce_side_effect": "critical",
    "error_timing": "high",
    "response_diff": "medium",
}


@dataclass(frozen=True)
class DeserializationFinding:
    subfamily: str
    severity: str
    evidence: tuple[str, ...]
    language: str
    family: str = "DESERIALIZATION"
    confidence: float = 0.85
    statement: str = ""
    success_indicator: str = ""


class DeserializationDetector:
    """Identifies serialized input by magic bytes and probes each
    language with an inert canary, reading only effect channels."""

    _ENDPOINT = "/api/import"

    def __init__(self, send) -> None:
        self._send = send

    # ------------------------------------------------------------------

    def identify(self, value: str) -> list[str]:
        """Languages whose magic this value matches, corpus order."""
        matches: list[str] = []
        decoded = None
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4))
        except Exception:
            decoded = None
        for language in ("java", "php", "python", "dotnet", "ruby",
                         "nodejs"):
            sig = DESERIALIZATION_SIGNATURES[language]
            if "magic_bytes" in sig and decoded is not None \
                    and decoded.startswith(sig["magic_bytes"]):
                matches.append(language)
            elif "base64_magic" in sig \
                    and value.startswith(sig["base64_magic"]):
                matches.append(language)
            elif "raw_prefixes" in sig and value.lstrip().startswith(
                    sig["raw_prefixes"]):
                matches.append(language)
            elif "raw_magic" in sig and sig["raw_magic"] in value:
                matches.append(language)
        return matches

    def canary(self, language: str) -> str:
        """An inert canary carrying this language's magic — never a
        gadget chain (no ysoserial, no PHPGGC, no code to run)."""
        sig = DESERIALIZATION_SIGNATURES[language]
        if "magic_bytes" in sig:
            head = base64.b64encode(sig["magic_bytes"]).decode().rstrip("=")
            return head + CANARY_MARKER
        if "base64_magic" in sig:
            return sig["base64_magic"] + CANARY_MARKER
        if "raw_prefixes" in sig:
            return sig["raw_prefixes"][0] + CANARY_MARKER
        return sig["raw_magic"] + "/*" + CANARY_MARKER + "*/"

    def scan(self) -> list[DeserializationFinding]:
        baseline = self._send(self._ENDPOINT, {})
        baseline_body = self._body(baseline)
        baseline_line = f"baseline: {json.dumps(baseline_body, sort_keys=True)}"
        findings: list[DeserializationFinding] = []
        for language in ("java", "php", "python", "dotnet", "ruby",
                         "nodejs"):
            payload = self.canary(language)
            probe = self._send(self._ENDPOINT, {"data": payload})
            subfamily, evidence_extra = self._effect(
                language, payload, baseline, baseline_body, probe)
            if subfamily is None:
                continue
            findings.append(self._finding(
                language, subfamily, payload, baseline_line, probe,
                evidence_extra))
        return findings

    # ------------------------------------------------------------------

    def _effect(self, language: str, payload: str, baseline,
                baseline_body, probe) -> tuple[str | None, list[str]]:
        if probe.status_code >= 400:
            elapsed = probe.elapsed_ms - baseline.elapsed_ms
            if elapsed >= TIMING_THRESHOLD_MS:
                return "error_timing", [
                    f"elapsed delta: {elapsed}ms "
                    f"(threshold {TIMING_THRESHOLD_MS}ms)"]
            if self._body(probe) != baseline_body:
                return "response_diff", [
                    "response differs from the clean baseline "
                    "(serializer error shape)"]
            return None, []
        body = json.dumps(self._body(probe))
        executed = f"{CANARY_MARKER}-executed"
        if CANARY_MARKER in body and executed in body:
            return "rce_side_effect", [
                f"side-effect marker in response: {executed}"]
        # a verbatim echo is not an effect: the canary was only
        # reflected, never deserialized
        return None, []

    @staticmethod
    def _body(response):
        try:
            return response.json()
        except Exception:
            return {}

    def _finding(self, language: str, subfamily: str, payload: str,
                 baseline_line: str, probe,
                 evidence_extra: list[str]) -> DeserializationFinding:
        tool = DESERIALIZATION_SIGNATURES[language]["tool"]
        statements = {
            "rce_side_effect": (
                f"{tool} canary produced an executed side-effect marker "
                "in the response — deserialization leading to code "
                "execution (advisory; verify against an authorized "
                "target)."),
            "error_timing": (
                f"{tool} canary produced a slow serializer-error "
                "response — deserialization attempted (advisory; "
                "verify against an authorized target)."),
            "response_diff": (
                f"{tool} canary produced a response that differs from "
                "the clean baseline — deserialization attempted "
                "(advisory; verify against an authorized target)."),
        }
        indicators = {
            "rce_side_effect": "executed canary marker in the response",
            "error_timing": (f"elapsed delta at or above "
                             f"{TIMING_THRESHOLD_MS}ms on error"),
            "response_diff": ("error-shaped response where the baseline "
                              "was clean"),
        }
        evidence = [
            baseline_line,
            f"probe: {json.dumps(self._body(probe), sort_keys=True)}",
            *evidence_extra,
        ]
        return DeserializationFinding(
            subfamily=subfamily,
            severity=SEVERITY_BY_SUBFAMILY[subfamily],
            evidence=tuple(evidence),
            language=language,
            statement=statements[subfamily],
            success_indicator=indicators[subfamily],
        )

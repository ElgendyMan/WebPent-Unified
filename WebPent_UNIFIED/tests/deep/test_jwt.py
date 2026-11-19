"""U-DEEP-10 — JWT Advanced (red tests).

Detection principle: ACCEPTANCE OVER STRUCTURE — a modified token is
only a finding when the server actually accepts it where the original
does (or where the original's acceptance can't explain the modified
one). Zero network: send(method, path, headers) is injected.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

from webpent.deep.jwt_advanced import (
    JWT_ADVANCED_ATTACKS,
    SEVERITY_BY_SUBFAMILY,
    JwtAdvancedDetector,
)

PUBLIC_KEY = b"-----BEGIN PUBLIC KEY-----test-material-----"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _header_of(token: str) -> dict:
    head = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))


def _token(alg="HS256", kid=None, extra=None):
    header = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    if extra:
        header.update(extra)
    payload = {"sub": "victim", "role": "user"}
    signing_input = f"{_b64url(json.dumps(header).encode())}." \
                    f"{_b64url(json.dumps(payload).encode())}"
    sig = hmac.new(PUBLIC_KEY, signing_input.encode(),
                   hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(sig)}"


class _Response:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.body = body


def _vulnerable_send(method, path, headers):
    auth = headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ")
    try:
        header = _header_of(token)
    except Exception:
        return _Response(401, "bad token")
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        return _Response(200, "authenticated as victim")
    # key-source takeover: a server that trusts client-supplied key
    # sources (jku/x5u/jwk) accepts the token on their presence, before
    # any local signature verification — that trust is the flaw.
    for key in ("jku", "x5u", "jwk"):
        if key in header:
            return _Response(200, "authenticated as victim")
    if alg == "hs256" and "kid" not in header:
        # signature must be the HMAC under the (public) key material
        sig = token.rsplit(".", 1)[1]
        expected = _b64url(hmac.new(
            PUBLIC_KEY, token.rsplit(".", 1)[0].encode(),
            hashlib.sha256).digest())
        if sig == expected:
            return _Response(200, "authenticated as victim")
        return _Response(401, "bad signature")
    kid = str(header.get("kid", ""))
    if "dev/null" in kid or "|" in kid or "OR" in kid:
        return _Response(200, "authenticated as victim")
    if "\n" in kid:
        return _Response(200, "authenticated as victim")
    return _Response(401, "denied")


def _hardened_send(method, path, headers):
    return _Response(401, "denied")


@pytest.fixture
def detector():
    return JwtAdvancedDetector(_vulnerable_send, token=_token(),
                               public_key=PUBLIC_KEY)


def test_corpus_documented_and_total():
    assert set(JWT_ADVANCED_ATTACKS) == {
        "alg_none", "alg_confusion", "kid_injection",
        "jku_manipulation", "x5u_manipulation", "jwk_injection",
        "header_injection"}


def test_alg_none_has_four_variants():
    assert len(JWT_ADVANCED_ATTACKS["alg_none"]) == 4


def test_alg_none_detected(detector):
    findings = detector.run_all()
    assert any(f.subfamily == "alg_none" for f in findings)


def test_alg_none_token_structure(detector):
    findings = detector.run_all()
    none_finding = next(f for f in findings
                        if f.subfamily == "alg_none")
    token = none_finding.token_probed
    assert token.endswith(".")
    assert str(_header_of(token).get("alg", "")).lower() == "none"


def test_alg_confusion_signature_is_real_hmac(detector):
    findings = detector.run_all()
    confusion = next(f for f in findings
                     if f.subfamily == "alg_confusion")
    sig = confusion.token_probed.rsplit(".", 1)[1]
    expected = _b64url(hmac.new(
        PUBLIC_KEY, confusion.token_probed.rsplit(".", 1)[0].encode(),
        hashlib.sha256).digest())
    assert sig == expected


def test_kid_injection_detected(detector):
    findings = detector.run_all()
    assert any(f.subfamily == "kid_injection" for f in findings)


def test_jku_manipulation_detected(detector):
    findings = detector.run_all()
    assert any(f.subfamily == "jku_manipulation" for f in findings)


def test_header_injection_detected(detector):
    findings = detector.run_all()
    assert any(f.subfamily == "header_injection" for f in findings)


def test_hardened_server_no_findings():
    detector = JwtAdvancedDetector(_hardened_send, token=_token(),
                                   public_key=PUBLIC_KEY)
    assert detector.run_all() == []


def test_baseline_recorded_in_evidence(detector):
    findings = detector.run_all()
    assert findings
    assert any("baseline" in line for f in findings
               for line in f.evidence)


def test_severity_deterministic(detector):
    findings = detector.run_all()
    by_sub = {f.subfamily: f for f in findings}
    assert by_sub["alg_none"].severity == "critical"
    assert by_sub["header_injection"].severity == \
        SEVERITY_BY_SUBFAMILY["header_injection"]
    assert set(SEVERITY_BY_SUBFAMILY) == set(JWT_ADVANCED_ATTACKS)


def test_statement_advisory_and_deterministic(detector):
    a = detector.run_all()
    b = JwtAdvancedDetector(_vulnerable_send, token=_token(),
                            public_key=PUBLIC_KEY).run_all()
    assert [(f.subfamily, f.token_probed) for f in a] == \
        [(f.subfamily, f.token_probed) for f in b]
    assert all("advisory" in f.statement.lower() for f in a)

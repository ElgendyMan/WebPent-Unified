# src/webpent/secrets_scanner/scanner.py
"""Leaked-secrets scanner core (PROPOSALS_ULTIMATE_V3 §7, 2026-11-01).

Honesty and privacy contracts, stated up front:
- MASKING IS ABSOLUTE. Every SecretHit carries only a masked rendering
  of the matched text (first 4 + last 4 characters, or full masking for
  short matches). The full value is NEVER stored on the hit, never
  logged, never rendered into a finding, never printed. The only way a
  full value leaves this module is through the injected ``secret_sink``
  callable (one call per hit, intended for the encrypted evidence
  bundle); with no sink the full value is dropped entirely.
- CONFIRMED vs SUSPECTED is a strict split: ``confirmed`` requires a
  match against the fixed library of OFFICIAL token prefixes (AWS
  access keys, Stripe live keys, GitHub tokens, Slack bot tokens,
  Google API keys, JWTs, PEM private keys). Anything else that merely
  looks random in a secret-ish assignment context is ``suspected`` at
  best, and only when its Shannon entropy clears
  ``secrets_min_entropy`` (default 3.5). Low-entropy candidates are
  silently not reported.
- NO NETWORK in ``scan_text``. The one network-touching path,
  ``scan_backup_paths``, fetches nothing itself: the fetcher is
  injected, and EVERY candidate URL passes a mandatory scope check
  first — a refused URL is never fetched, and the scan point fails
  closed with ``secrets_out_of_scope``.
- Flag-gated via ``enable_secrets_scanner`` (default False); every
  entry point refuses with ``secrets_scanner_flag_off`` when it is off.
- All candidate fixture values in the tests are FAKE.

Deterministic: same text + same settings → identical hit list.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Sequence

__all__ = [
    "PATTERN_LIBRARY",
    "SecretHit",
    "SecretsScannerError",
    "backup_candidates",
    "finding_payload",
    "mask_secret",
    "scan_backup_paths",
    "scan_text",
    "secrets_refusal",
    "shannon_entropy",
]

# Confidence buckets (closed set; unknown values fail closed).
CONFIDENCES = ("confirmed", "suspected")

# Fixed, documented library of OFFICIAL token prefixes. Each entry:
# (kind, compiled regex, confidence). Kinds name the provider's own
# documented format; a match here means the string has the vendor's
# canonical shape, hence ``confirmed``.
_PATTERN_SPEC: tuple[tuple[str, str], ...] = (
    ("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b"),
    ("stripe_live_key", r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    ("github_token", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("slack_bot_token", r"\bxoxb-[0-9A-Za-z-]{10,}\b"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    ("pem_private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
PATTERN_LIBRARY: tuple[tuple[str, "re.Pattern[str]", str], ...] = tuple(
    (kind, re.compile(pattern), "confirmed") for kind, pattern in _PATTERN_SPEC
)

# Assignment-context keys that mark a value as secret-ish. Used ONLY
# for the entropy path — a match here never upgrades to confirmed.
_CONTEXT_KEYS = re.compile(
    r"\b(api[_-]?key|apikey|auth[_-]?token|access[_-]?token|secret|"
    r"client[_-]?secret|private[_-]?key|passwd|password|token)\b",
    re.IGNORECASE,
)
_ASSIGNMENT = re.compile(r"[\"']?([A-Za-z0-9_.-]+)[\"']?\s*[:=]\s*[\"']([^\"']{8,256})[\"']")
# Value charset accepted for the entropy path (prints, no whitespace).
_VALUE_CHARS = re.compile(r"^[A-Za-z0-9+/=_\-.~]+$")

# Common backup/secret-leak paths probed by scan_backup_paths. Fixed
# and small: every URL is checked against scope BEFORE fetching.
_BACKUP_PATHS: tuple[str, ...] = (
    "/.env",
    "/.git/config",
    "/config.json.bak",
    "/backup.zip",
    "/database.yml",
    "/.svn/entries",
    "/dump.sql",
    "/web.config.bak",
)

_MAX_TEXT_BYTES = 2_000_000
_MIN_ENTROPY_LENGTH = 12


class SecretsScannerError(ValueError):
    """Raised when a scan cannot proceed within its contracts."""


@dataclass(frozen=True)
class SecretHit:
    """One masked hit. Carries NO full value — see module contracts."""

    kind: str
    confidence: str
    span: tuple[int, int]
    source: str
    masked_value: str

    def __post_init__(self) -> None:
        if self.confidence not in CONFIDENCES:
            raise SecretsScannerError("secrets_unknown_confidence")


def secrets_refusal() -> str | None:
    """Refusal code when the operator's flag is off, else None."""
    from webpent.config.settings import get_settings

    if not get_settings().enable_secrets_scanner:
        return "secrets_scanner_flag_off"
    return None


def _require_flag() -> None:
    if secrets_refusal() is not None:
        raise SecretsScannerError("secrets_scanner_flag_off")


def mask_secret(value: str) -> str:
    """Mask to first-4 + last-4; fully mask anything shorter than 8."""
    if len(value) < 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * 8}{value[-4:]}"


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character over the string's charset."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _min_entropy() -> float:
    from webpent.config.settings import get_settings

    threshold = float(get_settings().secrets_min_entropy)
    if threshold < 0:
        raise SecretsScannerError("secrets_bad_entropy_threshold")
    return threshold


def scan_text(
    text: str,
    source_hint: str,
    *,
    secret_sink: Callable[[str, str], None] | None = None,
) -> list[SecretHit]:
    """Scan text for leaked secrets; hits are masked, sink gets originals.

    ``secret_sink(kind, full_value)`` is called at most once per hit,
    BEFORE the full value is discarded. With ``secret_sink=None`` the
    full value is dropped entirely.
    """
    _require_flag()
    if len(text.encode("utf-8", errors="replace")) > _MAX_TEXT_BYTES:
        raise SecretsScannerError("secrets_text_too_large")

    hits: list[SecretHit] = []
    for kind, pattern, confidence in PATTERN_LIBRARY:
        for match in pattern.finditer(text):
            value = match.group(0)
            if secret_sink is not None:
                secret_sink(kind, value)
            hits.append(
                SecretHit(
                    kind=kind,
                    confidence=confidence,
                    span=(match.start(), match.end()),
                    source=source_hint,
                    masked_value=mask_secret(value),
                )
            )

    threshold = _min_entropy()
    for match in _ASSIGNMENT.finditer(text):
        key, value = match.group(1), match.group(2)
        if not _CONTEXT_KEYS.search(key):
            continue
        if not _VALUE_CHARS.match(value) or len(value) < _MIN_ENTROPY_LENGTH:
            continue
        if shannon_entropy(value) < threshold:
            continue
        span = (match.start(2), match.end(2))
        if any(span[0] < h.span[1] and h.span[0] < span[1] for h in hits):
            continue  # already confirmed by a library pattern
        if secret_sink is not None:
            secret_sink("suspected_high_entropy", value)
        hits.append(
            SecretHit(
                kind="suspected_high_entropy",
                confidence="suspected",
                span=span,
                source=source_hint,
                masked_value=mask_secret(value),
            )
        )

    hits.sort(key=lambda h: (h.span[0], h.span[1]))
    return hits


def backup_candidates(base_url: str) -> list[str]:
    """The fixed backup-path candidate URLs for one base URL."""
    if not base_url.rstrip("/"):
        raise SecretsScannerError("secrets_bad_base_url")
    return [base_url.rstrip("/") + path for path in _BACKUP_PATHS]


def scan_backup_paths(
    base_url: str,
    fetch: Callable[[str], str],
    *,
    scope_checker: Callable[[str], bool] | None,
    secret_sink: Callable[[str, str], None] | None = None,
) -> list[SecretHit]:
    """Probe fixed backup paths; scope check is MANDATORY before fetch.

    ``fetch(url) -> body text`` is injected (tests pass fakes).
    ``scope_checker`` is mandatory: without one the scan refuses
    (``secrets_scope_checker_required``). Every candidate URL passes
    the check BEFORE any fetch; refused URLs are never fetched. If
    EVERY candidate is refused the scan refuses outright with
    ``secrets_out_of_scope`` rather than silently scanning nothing.
    """
    _require_flag()
    if scope_checker is None:
        raise SecretsScannerError("secrets_scope_checker_required")
    urls = backup_candidates(base_url)
    allowed: list[str] = []
    for url in urls:
        if not scope_checker(url):
            continue  # never fetched
        allowed.append(url)
    if not allowed:
        raise SecretsScannerError("secrets_out_of_scope")
    hits: list[SecretHit] = []
    for url in allowed:
        body = fetch(url)
        if not body:
            continue
        hits.extend(scan_text(body, url, secret_sink=secret_sink))
    return hits


def finding_payload(
    hits: Sequence[SecretHit], *, target_url: str = ""
) -> list[dict]:
    """Map hits to Finding-constructor dicts (masked values only).

    Severity follows the confidence split: confirmed → high,
    suspected → medium. Class is info_disclosure (exposed-secret
    routing); nothing here invents evidence — the description names the
    kind and the masked rendering only.
    """
    payloads: list[dict] = []
    for hit in hits:
        if hit.confidence == "confirmed":
            severity = "high"
        elif hit.confidence == "suspected":
            severity = "medium"
        else:
            raise SecretsScannerError("secrets_unknown_confidence")
        payloads.append(
            {
                "title": f"Exposed secret ({hit.kind}) in {hit.source or target_url}",
                "severity": severity,
                "description": (
                    f"A value matching the {hit.kind} format was found in "
                    f"{hit.source or target_url}. Masked rendering: "
                    f"{hit.masked_value}. Full value is withheld from this "
                    "report by contract and lives only in the encrypted "
                    "evidence bundle."
                ),
                "tool_name": "secrets_scanner",
                "url": hit.source or target_url,
                "vuln_class": "info_disclosure",
                "confidence": hit.confidence,
            }
        )
    return payloads

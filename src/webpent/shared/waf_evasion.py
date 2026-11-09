"""webpent.shared.waf_evasion — bounded payload encoding-mutation variants.

Team 2 review, item 8.3 ("Adaptive WAF Evasion"): once a WAF vendor is
deterministically detected (see ``shared.waf_fingerprints``), this
module generates a bounded set of RE-ENCODED variants of an existing
payload string — never a new payload class, never new attack logic.
Each function here is a pure string transform: case mutation, HTML
entity / URL double-encoding, Unicode confusable substitution, and
inline-comment insertion for SQL — all well-documented, widely-known
WAF-bypass TECHNIQUES, not new or untested exploit primitives.

This does not itself decide which payload to generate (that remains
the validator's/payload_generator's job, see e.g.
``validator.agent._SSTI_OOB_PAYLOAD_TEMPLATES`` and
``payload_generator.agent._generate_payloads_for_finding``) — it takes
an EXISTING payload string those already produce and returns variants
of it. Bounded to a small, fixed number of variants per call
(``_MAX_VARIANTS``) regardless of vendor, consistent with this
codebase's general stance on bounded search (see
``exploit_chainer``'s ``_MAX_PAIRS_EXAMINED`` for the same philosophy
applied elsewhere) — this is about giving the validator a FEW more
reasonable attempts when a WAF is already confirmed present, not an
unbounded brute-force mutation engine.
"""

from __future__ import annotations

import random
import re
import urllib.parse

_MAX_VARIANTS = 5


def _case_mutate(payload: str) -> str:
    """Randomize letter case — defeats naive case-sensitive keyword
    filters (e.g. a rule matching literal 'SELECT' but not 'SeLeCt')."""
    return "".join(
        char.upper() if random.random() < 0.5 else char.lower() for char in payload  # noqa: S311
    )


def _double_url_encode(payload: str) -> str:
    """Double URL-encode — defeats WAFs that decode a request body/query
    exactly once before matching signatures, missing a payload hidden
    behind a second layer of percent-encoding."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def _html_entity_encode(payload: str) -> str:
    """Encode a bounded subset of characters as HTML numeric entities —
    defeats signature matching on literal angle brackets/quotes for
    reflected-HTML-context payloads (XSS), while the browser itself
    still decodes the entities before rendering."""
    out = []
    for char in payload:
        if char in "<>\"'&":
            out.append(f"&#{ord(char)};")
        else:
            out.append(char)
    return "".join(out)


def _sql_inline_comment_split(payload: str) -> str:
    """Insert MySQL/MariaDB inline-comment tokens between SQL keywords —
    a well-documented WAF-bypass technique (e.g. ``SEL/**/ECT`` or
    ``UNION/**/SELECT``) that defeats whole-keyword signature matching
    while the database's own comment-stripping still parses it as the
    original keyword. Only touches a small, fixed set of SQL keywords;
    leaves everything else in the payload untouched.

    Matches on WORD BOUNDARIES only (``\\b``), not bare substring
    replacement — a naive ``payload.replace("or", "o/**/r")`` corrupts
    any unrelated word that merely CONTAINS "or" as a substring (for
    example splitting the target column name "password" into
    "passw/**/ord", silently breaking the exfiltration target the
    payload was trying to read). Reproduced and confirmed with exactly
    this example before this word-boundary fix.
    """
    keywords = ("SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "OR", "AND")
    result = payload
    for kw in keywords:
        mid = len(kw) // 2
        head, tail = re.escape(kw[:mid]), re.escape(kw[mid:])
        pattern = re.compile(r"\b(" + head + r")(" + tail + r")\b", re.I)
        result = pattern.sub(r"\1/**/\2", result)
    return result


def _unicode_homoglyph_substitute(payload: str) -> str:
    """Substitute a small set of ASCII characters commonly filtered by
    naive WAF rules with visually-similar Unicode fullwidth forms —
    defeats byte-exact signature matching on specific punctuation
    (parentheses, angle brackets) when the downstream interpreter
    (browser, template engine) normalizes fullwidth forms back to
    their ASCII equivalents before evaluation."""
    table = {
        "(": "\uff08", ")": "\uff09", "<": "\uff1c", ">": "\uff1e",
        "'": "\u2019", '"': "\u201d",
    }
    return "".join(table.get(char, char) for char in payload)


# vendor -> ordered list of transform functions most likely to matter
# for that vendor's KNOWN filtering behavior. Vendors not listed fall
# back to _DEFAULT_ORDER. This ordering is a reasonable, documented
# starting point, not a guarantee specific to any one vendor's current
# ruleset — vendors update their rules continuously.
_VENDOR_TRANSFORM_ORDER: dict[str, tuple] = {
    "cloudflare": (_case_mutate, _double_url_encode, _unicode_homoglyph_substitute),
    "akamai": (_double_url_encode, _case_mutate, _sql_inline_comment_split),
    "aws_waf_cloudfront": (_case_mutate, _html_entity_encode, _double_url_encode),
    "imperva_incapsula": (_sql_inline_comment_split, _case_mutate, _double_url_encode),
    "sucuri": (_html_entity_encode, _case_mutate, _double_url_encode),
    "f5_big_ip_asm": (_double_url_encode, _sql_inline_comment_split, _case_mutate),
}
_DEFAULT_ORDER = (_case_mutate, _double_url_encode, _html_entity_encode, _sql_inline_comment_split)


def generate_evasion_variants(
    payload: str, *, vendor: str | None = None, max_variants: int = _MAX_VARIANTS
) -> list[str]:
    """Return up to ``max_variants`` re-encoded variants of ``payload``.

    Each variant is produced by a SINGLE named transform (never a
    compound chain of several transforms at once — compounding grows
    the output space combinatorially for little added value and makes
    it much harder for a human reviewer to see what changed and why).
    Transform order is chosen by ``vendor`` when it is a recognized
    key in ``_VENDOR_TRANSFORM_ORDER``, falling back to a fixed default
    order otherwise (including when ``vendor`` is ``None`` — i.e. no
    WAF was detected at all, so these still provide reasonable
    general-purpose bypass attempts, just without vendor-specific
    prioritization). Deduplicates variants that happen to be identical
    to the original payload or to each other (e.g. a payload with no
    SQL keywords leaves ``_sql_inline_comment_split`` a no-op).
    """
    if not payload:
        return []
    order = _VENDOR_TRANSFORM_ORDER.get(str(vendor or "").lower(), _DEFAULT_ORDER)
    seen = {payload}
    variants: list[str] = []
    for transform in order:
        if len(variants) >= max_variants:
            break
        try:
            candidate = transform(payload)
        except Exception:
            continue
        if candidate not in seen:
            seen.add(candidate)
            variants.append(candidate)
    return variants[:max_variants]

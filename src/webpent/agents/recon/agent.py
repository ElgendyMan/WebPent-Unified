# src/webpent/agents/recon/agent.py
"""webpent.agents.recon.agent

LangGraph node that performs the recon phase of an engagement.

The recon node chains three ProjectDiscovery tools:

  1. ``subfinder`` — passive subdomain enumeration for the target root
     domain.
  2. ``httpx`` — live-host probing of every discovered subdomain.
  3. ``nuclei`` — template-based vulnerability scanning of the primary
     target URL.

The node is intentionally resilient: a failure in subfinder or httpx
does not abort nuclei, and a failure in nuclei does not discard the
subdomains already discovered. All usable observations are converted
into :class:`Finding` instances and returned to the graph.

PortSwigger lab mode:
    When ``target.is_portswigger_lab`` is ``True``, subdomain enumeration
    is skipped entirely (lab environments are single-tenant with no
    meaningful subdomain surface). ``httpx`` is invoked directly against
    the lab host so that live-host probing / tech-fingerprint data is
    still collected. The summary message reflects the active mode so
    logs and reports stay accurate.

Record-conversion resilience:
    Nuclei records are converted to ``Finding`` models with per-item
    error isolation. A single malformed record (e.g. a non-absolute
    ``matched-at`` URL that fails Pydantic validation) is logged and
    skipped rather than aborting the entire scan's findings. The
    ``url`` field is also sanitised inside ``_nuclei_record_to_finding``
    as defense-in-depth: any value that does not start with ``http://``
    or ``https://`` falls back to the engagement's primary target URL.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from langchain_core.messages import AIMessage

from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.models.targets import Target
from webpent.shared.exceptions import ToolExecutionError, ToolNotFoundError
from webpent.state.state import PentestState

# V6 Ultimate: Use the dynamic tool registry instead of hardcoded imports.
# The registry auto-discovers all tool wrappers at import time.
from webpent.tools.registry import get_tool


def _get_run_nuclei():
    entry = get_tool("nuclei")
    return entry.func if entry else None

def _get_run_httpx():
    entry = get_tool("httpx")
    return entry.func if entry else None

def _get_run_subfinder():
    entry = get_tool("subfinder")
    return entry.func if entry else None


def _get_run_ffuf():
    entry = get_tool("ffuf")
    return entry.func if entry else None

logger = logging.getLogger(__name__)

# Fallback values used when a Nuclei record is missing a field. Keeping
# them in one place makes future tuning trivial and avoids magic strings
# scattered through the mapping logic.
_FALLBACK_TITLE = "Unnamed Nuclei Finding"
_FALLBACK_DESCRIPTION = "No description was provided by the template."
_FALLBACK_SEVERITY = Severity.INFO
_FALLBACK_TOOL_NAME = "nuclei"

# Nuclei severity strings -> framework :class:`Severity` enum. Nuclei
# occasionally emits unknown/custom severities; anything unmapped falls
# back to ``INFO`` so the finding is never silently dropped.
_NUCLEI_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

# Human-readable recon-method labels used in the summary message.
# Centralised so the planner/recon/reporter nodes stay in sync.
_METHOD_SUBFINDER_HTTPX = "subfinder+httpx"
_METHOD_HTTPX_LAB = "httpx (lab mode)"
_METHOD_HTTPX_IP_LITERAL = "httpx (ip-literal)"
_METHOD_HTTPX_LOCAL_HOST = "httpx (local-hostname)"
_METHOD_NONE = "none"


def _is_ip_literal(host: str | None) -> bool:
    """Return True iff ``host`` is a bare IP literal (v4 or v6).

    subfinder does passive DNS enumeration against a *domain* — it has
    no meaningful work to do against a raw IP (there are no DNS records
    to enumerate). Detecting this lets us skip straight to httpx against
    the host itself instead of pointlessly invoking subfinder and
    collecting ``TOOL_INFRA_FAILURE`` warnings on every local-IP scan.

    Uses :func:`ipaddress.ip_address`, which accepts both IPv4 and IPv6
    literals and rejects hostnames / partial strings via ``ValueError``.
    """
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_non_public_hostname(host: str | None) -> bool:
    """Return True for names that cannot be treated as public DNS roots.

    Scanner containers commonly reach an isolated lab through a single-label
    Docker service name (for example ``app``). Reserved local suffixes are
    likewise not public DNS targets. Sending these names to passive
    subdomain-enumeration providers is both useless and an avoidable scope
    escape. Fully-qualified names containing a dot remain eligible for the
    normal subfinder pipeline.
    """
    if not host or _is_ip_literal(host):
        return False
    normalised = host.rstrip(".").lower()
    reserved_suffixes = (
        ".localhost",
        ".local",
        ".internal",
        ".test",
        ".invalid",
        ".example",
    )
    return "." not in normalised or normalised.endswith(reserved_suffixes)


def _is_private_ip(host: str | None) -> bool:
    """Return True iff ``host`` is an IP literal in a private/reserved range.

    Extends :func:`_is_ip_literal` with the ``is_private`` check from
    :mod:`ipaddress`, which covers RFC1918 (10/8, 172.16/12, 192.168/16),
    loopback (127/8, ::1), link-local (169.254/16, fe80::/10), and other
    reserved ranges. Used only for log-message clarity — both private and
    public IP literals skip subfinder for the same reason (subfinder
    needs a domain), but the log line tells the operator which case
    applied so they can sanity-check the routing decision.
    """
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _coerce_severity(raw: Any) -> Severity:
    """Map a Nuclei severity string to a :class:`Severity` value."""
    if not isinstance(raw, str):
        return _FALLBACK_SEVERITY
    return _NUCLEI_SEVERITY_MAP.get(raw.strip().lower(), _FALLBACK_SEVERITY)


def _extract_template_id(record: dict[str, Any]) -> str | None:
    """Best-effort extraction of a template identifier for the payload."""
    return (
        record.get("template-id")
        or record.get("template_id")
        or record.get("template")
        or record.get("id")
    )


# V3.5: Map Nuclei template tags to VulnClass values for deterministic routing.
# Nuclei templates include a ``tags`` field (list of strings) in the ``info``
# object. This mapping enables automatic vuln_class assignment without
# fragile keyword matching on titles.
#
# V8 P0 A1: Added INFO_DISCLOSURE entries. Nuclei tags like "exposure",
# "disclosure", "exposed", "files", "backup", "config", "git", "svn",
# "tokens", "secrets", "cloud" now route to VulnClass.INFO_DISCLOSURE
# instead of falling through to UNKNOWN — this is the deterministic
# classifier the A1 plan calls for, distinguishing artifact disclosures
# from useless fingerprint noise (which stays UNKNOWN).
_NUCLEI_TAG_TO_VULN_CLASS: dict[str, str] = {
    "xss": VulnClass.XSS.value,
    "cross-site scripting": VulnClass.XSS.value,
    "sqli": VulnClass.SQLI.value,
    "sql-injection": VulnClass.SQLI.value,
    "sql injection": VulnClass.SQLI.value,
    "ssrf": VulnClass.SSRF.value,
    "server-side-request-forgery": VulnClass.SSRF.value,
    "lfi": VulnClass.LFI.value,
    "local-file-inclusion": VulnClass.LFI.value,
    "rfi": VulnClass.RFI.value,
    "remote-file-inclusion": VulnClass.RFI.value,
    "rce": VulnClass.RCE.value,
    "remote-code-execution": VulnClass.RCE.value,
    "command-injection": VulnClass.COMMAND_INJECTION.value,
    "command injection": VulnClass.COMMAND_INJECTION.value,
    "ssti": VulnClass.SSTI.value,
    "template-injection": VulnClass.SSTI.value,
    "open-redirect": VulnClass.OPEN_REDIRECT.value,
    "redirect": VulnClass.OPEN_REDIRECT.value,
    "xxe": VulnClass.XXE.value,
    "csrf": VulnClass.CSRF.value,
    "deserialization": VulnClass.DESERIALIZATION.value,
    "path-traversal": VulnClass.PATH_TRAVERSAL.value,
    "traversal": VulnClass.PATH_TRAVERSAL.value,
    "directory-traversal": VulnClass.PATH_TRAVERSAL.value,
    # --- V8 P0 A1: artifact / info-disclosure tags -----------------------
    "exposure": VulnClass.INFO_DISCLOSURE.value,
    "exposed": VulnClass.INFO_DISCLOSURE.value,
    "disclosure": VulnClass.INFO_DISCLOSURE.value,
    "files": VulnClass.INFO_DISCLOSURE.value,
    "file": VulnClass.INFO_DISCLOSURE.value,
    "backup": VulnClass.INFO_DISCLOSURE.value,
    "config": VulnClass.INFO_DISCLOSURE.value,
    "git": VulnClass.INFO_DISCLOSURE.value,
    "svn": VulnClass.INFO_DISCLOSURE.value,
    "hg": VulnClass.INFO_DISCLOSURE.value,
    "tokens": VulnClass.INFO_DISCLOSURE.value,
    "token": VulnClass.INFO_DISCLOSURE.value,
    "secrets": VulnClass.INFO_DISCLOSURE.value,
    "secret": VulnClass.INFO_DISCLOSURE.value,
    "cloud": VulnClass.INFO_DISCLOSURE.value,
    "metadata": VulnClass.INFO_DISCLOSURE.value,
    "listing": VulnClass.INFO_DISCLOSURE.value,
    "directory-listing": VulnClass.INFO_DISCLOSURE.value,
    "source": VulnClass.INFO_DISCLOSURE.value,
    "source-code": VulnClass.INFO_DISCLOSURE.value,
    "leak": VulnClass.INFO_DISCLOSURE.value,
    "leaked": VulnClass.INFO_DISCLOSURE.value,
    "download": VulnClass.INFO_DISCLOSURE.value,
}


def _infer_vuln_class(record: dict[str, Any]) -> str:
    """Infer the :class:`VulnClass` from a Nuclei record's tags and name.

    V3.5: Replaces keyword matching on titles with deterministic tag-based
    classification. Falls back to :attr:`VulnClass.UNKNOWN` if no match.
    """
    info: dict[str, Any] = record.get("info") or {}

    # Check tags (list of strings in info.tags)
    tags = info.get("tags") or record.get("tags")
    if isinstance(tags, list):
        for tag in tags:
            tag_lower = str(tag).strip().lower()
            if tag_lower in _NUCLEI_TAG_TO_VULN_CLASS:
                return _NUCLEI_TAG_TO_VULN_CLASS[tag_lower]
    elif isinstance(tags, str):
        tag_lower = tags.strip().lower()
        if tag_lower in _NUCLEI_TAG_TO_VULN_CLASS:
            return _NUCLEI_TAG_TO_VULN_CLASS[tag_lower]

    # Fallback: check the template name
    name = str(info.get("name", "")).lower()
    for keyword, vc in _NUCLEI_TAG_TO_VULN_CLASS.items():
        if keyword in name:
            return vc

    return VulnClass.UNKNOWN.value


def _extract_artifacts_from_nuclei(
    records: list[dict[str, Any]],
    target_url: str,
) -> list[dict[str, str]]:
    """Deterministic artifact-disclosure extractor for nuclei records.

    V8 P0 A1: scans every nuclei record's ``matched-at`` URL (and the
    resulting Finding's ``url``) through
    :func:`webpent.models.mental_model.classify_artifact_type`. Returns
    a list of ``{"type": art_type, "url": url}`` dicts ready to feed
    into :func:`extract_mental_model_updates` as the ``artifacts=``
    kwarg.

    Pure regex — NO LLM. Distinguishes artifact disclosures (.git,
    Dockerfile, backups, configs, SQL dumps, source-code disclosure)
    from useless fingerprint noise (nuclei tech-detection / fingerprint
    templates that don't match an artifact pattern are silently
    dropped here, because they have no Mental-Model representation).

    The return value is deduplicated by URL — multiple nuclei templates
    may match the same ``/.git/config`` URL; we only want one ARTIFACT
    node per unique URL.
    """
    if not records:
        return []
    # Local import to avoid module-load cycle
    # (mental_model imports from shared/cognitive_components).
    try:
        from webpent.models.mental_model import classify_artifact_type
    except Exception:
        return []

    seen_urls: set[str] = set()
    artifacts: list[dict[str, str]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        # Try every plausible URL-bearing field in a nuclei record.
        candidate_urls: list[str] = []
        for key in ("matched-at", "matched_at", "host", "url"):
            val = record.get(key)
            if isinstance(val, str) and val:
                candidate_urls.append(val)
        # Also include the engagement target_url as a fallback so a
        # record that matched against the target itself (e.g. a
        # Dockerfile served at the root) is still considered.
        if target_url:
            candidate_urls.append(target_url)
        for raw_url in candidate_urls:
            # Normalise: must be absolute http(s):// for the Mental Model
            # URL normaliser, OR a path-only string that we can still
            # pattern-match against (classify_artifact_type works on
            # any string — it doesn't require an absolute URL).
            url_str = raw_url.strip()
            if not url_str:
                continue
            art_type = classify_artifact_type(url_str)
            if not art_type:
                continue
            # Dedup by the (art_type, url) pair so the same URL found
            # by multiple templates only creates one ARTIFACT node.
            key = f"{art_type}::{url_str}"
            if key in seen_urls:
                continue
            seen_urls.add(key)
            artifacts.append({"type": art_type, "url": url_str})
    return artifacts


def _nuclei_record_to_finding(record: dict[str, Any], target_url: str) -> Finding:
    """Convert a single Nuclei JSONL record into a :class:`Finding`.

    The mapping intentionally degrades gracefully: any missing field is
    replaced with a sensible fallback so that a malformed template
    description never raises during recon.

    URL sanitisation (defense-in-depth):
        Nuclei templates occasionally emit ``matched-at`` values that
        are relative paths (``/api/users``) or scheme-less hosts
        (``example.com/admin``). The :class:`Finding` model rejects
        such values via its URL validator. To avoid a single quirky
        template invalidating an otherwise-good record, any URL that
        does not start with ``http://`` or ``https://`` is replaced
        with the engagement's primary ``target_url``.

    Args:
        record: A parsed Nuclei JSONL record.
        target_url: The target URL the scan was issued against. Used as
            the finding's ``url`` when the record does not include one
            (or includes an invalid one).

    Returns:
        A populated :class:`Finding` instance.

    Raises:
        pydantic.ValidationError: Only if multiple fields are malformed
            simultaneously (rare in practice). Callers should wrap this
            call in ``try/except`` and skip the record on failure — see
            :func:`recon_node`.
    """
    info: dict[str, Any] = record.get("info") or {}

    title = info.get("name") or record.get("matched-at") or _FALLBACK_TITLE
    description = info.get("description") or _FALLBACK_DESCRIPTION
    severity = _coerce_severity(info.get("severity"))

    # Prefer the per-match URL when Nuclei provides one; otherwise fall
    # back to the engagement's primary target URL. Sanitise to ensure
    # the value satisfies Finding's absolute-URL validator — Nuclei
    # templates occasionally emit relative paths or scheme-less hosts
    # in the ``matched-at`` field.
    raw_url = record.get("matched-at") or record.get("host") or target_url
    if isinstance(raw_url, str) and raw_url.startswith(("http://", "https://")):
        url = raw_url
    else:
        url = target_url

    payload = _extract_template_id(record)

    references: list[str] = []
    raw_refs = info.get("reference") or record.get("reference")
    if isinstance(raw_refs, list):
        references = [str(r) for r in raw_refs if r]
    elif isinstance(raw_refs, str):
        references = [raw_refs]

    return Finding(
        title=str(title)[:120],  # enforce model max_length defensively
        severity=severity,
        description=str(description),
        tool_name=_FALLBACK_TOOL_NAME,
        payload=payload,
        url=url,
        confidence=Confidence.FIRM,
        # V10 P0-5 (RCA follow-up): explicit evidence-class signal.
        # Recon nuclei hits are NOT tool-confirmed — they are
        # template-match candidates that require a downstream
        # validator (sqlmap/dalfox/structural check) to confirm.
        # Previously confidence_level defaulted to "Pending" (implicit),
        # which the executive_summary risk scorer (P0-4) now correctly
        # excludes from confirmed_count. Setting it explicitly here
        # makes the provenance clear: this is a recon_record / candidate,
        # not a tool_confirmed finding.
        confidence_level="Pending",
        references=references,
        vuln_class=_infer_vuln_class(record),
    )


def _run_subdomain_recon(
    target: Target,
    session_cookies: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """Execute the subfinder -> httpx pipeline.

    POST-P0 Phase 3: optional ``session_cookies`` are forwarded to the
    httpx liveness probe so authenticated surfaces answer honestly
    (values are never logged).

    Returns a tuple of ``(httpx_results, method_label)``. ``method_label``
    is a human-readable description of the recon method used (e.g.
    ``"subfinder+httpx"``, ``"httpx (lab mode)"``, or
    ``"httpx (ip-literal)"``), suitable for inclusion in the summary
    message.

    On any tool-level failure the function logs the error and returns
    an empty list — the caller (``recon_node``) treats this as non-fatal
    so that Nuclei can still run against the primary target.

    PortSwigger lab mode:
        When ``target.is_portswigger_lab`` is ``True``, subfinder is
        skipped (lab environments have no meaningful subdomain surface).
        ``httpx`` is invoked directly against the lab host so live-host
        probing / tech-fingerprint data is still collected.

    IP-literal targets (V7 Phase 5):
        When the target host is a bare IP address (private OR public),
        subfinder is skipped — subfinder does passive DNS enumeration
        against a *domain* and has no meaningful work to do against a
        raw IP (there are no DNS records to enumerate). ``httpx`` is
        invoked directly against the IP so live-host probing / tech-
        fingerprint data is still collected. Nuclei continues to run
        against the primary target URL afterwards, exactly as in lab
        mode, so the operator still gets real vulnerability scanning
        coverage. The log line distinguishes private vs. public IPs so
        the operator can sanity-check the routing decision.
    """
    # PortSwigger lab optimisation: skip subdomain enumeration entirely.
    if target.is_portswigger_lab:
        logger.info(
            "PortSwigger lab mode active — skipping subfinder for %s",
            target.url,
        )
        # Probe the lab host directly so we still get httpx fingerprints.
        # Preserve the declared scheme and port; a bare domain loses the
        # target port (for example, 127.0.0.1:8000) and httpx may emit no
        # result for the resulting host-only input.
        probe_target = target.url
        try:
            run_httpx = _get_run_httpx()
            if run_httpx:
                return run_httpx([probe_target]), _METHOD_HTTPX_LAB
        except (ToolNotFoundError, ToolExecutionError) as exc:
            logger.warning(
                "httpx failed for PortSwigger lab target %s: %s",
                probe_target,
                exc,
            )
            return [], _METHOD_HTTPX_LAB

    # V7 Phase 5: IP-literal optimisation — skip subfinder for bare IP
    # targets (subfinder is structurally incapable of finding anything
    # for a raw IP). This mirrors the PortSwigger lab branch above and
    # keeps nuclei + httpx running so vulnerability coverage is
    # preserved. Applies to both private (RFC1918/loopback) and public
    # IPs — the distinction is logged but does not change the routing.
    # Domain targets still go through the full subfinder -> httpx
    # pipeline below, since real domains legitimately benefit from
    # subdomain enumeration.
    if _is_ip_literal(target.domain):
        ip_kind = "private" if _is_private_ip(target.domain) else "public"
        logger.info(
            "Target host %s is a %s IP literal — skipping subfinder "
            "(passive DNS enumeration requires a domain); probing host "
            "directly with httpx. Nuclei will still run against %s.",
            target.domain,
            ip_kind,
            target.url,
        )
        # Preserve the declared scheme and port; a bare domain loses the
        # target port (for example, 127.0.0.1:8000) and httpx may emit no
        # result for the resulting host-only input.
        probe_target = target.url
        try:
            run_httpx = _get_run_httpx()
            if run_httpx:
                return run_httpx([probe_target]), _METHOD_HTTPX_IP_LITERAL
        except (ToolNotFoundError, ToolExecutionError) as exc:
            logger.warning(
                "httpx failed for IP-literal target %s: %s",
                probe_target,
                exc,
            )
            return [], _METHOD_HTTPX_IP_LITERAL

    if not target.domain:
        logger.warning("Target has no domain; skipping subdomain enumeration.")
        return [], _METHOD_SUBFINDER_HTTPX
    # Docker/service aliases and reserved local names are not public DNS roots.
    # Probe the declared URL directly, preserving the explicit port and path,
    # and never send the alias to an external passive-DNS enumerator.
    if _is_non_public_hostname(target.domain):
        logger.info(
            "Target host %s is a local/reserved hostname — skipping subfinder "
            "and probing the declared URL directly. Nuclei will still run "
            "against %s.",
            target.domain,
            target.url,
        )
        try:
            run_httpx = _get_run_httpx()
            if run_httpx:
                return run_httpx([target.url]), _METHOD_HTTPX_LOCAL_HOST
        except (ToolNotFoundError, ToolExecutionError) as exc:
            logger.warning("httpx failed for local hostname %s: %s", target.domain, exc)
        return [], _METHOD_HTTPX_LOCAL_HOST
    try:
        run_subfinder = _get_run_subfinder()
        if not run_subfinder:
            logger.warning("subfinder tool not in registry — skipping subdomain enumeration")
            return [], _METHOD_NONE
        subdomains = run_subfinder(target.domain)
    except (ToolNotFoundError, ToolExecutionError) as exc:
        logger.warning("subfinder failed for %s: %s", target.domain, exc)
        return [], _METHOD_SUBFINDER_HTTPX

    if not subdomains:
        logger.info("subfinder returned no subdomains for %s", target.domain)
        return [], _METHOD_SUBFINDER_HTTPX

    # Always include the root domain in the httpx input so that the
    # primary host is probed even when subfinder finds nothing.
    unique_hosts: list[str] = []
    seen: set[str] = set()
    for host in [target.domain, *subdomains]:
        if host and host not in seen:
            seen.add(host)
            unique_hosts.append(host)

    try:
        run_httpx = _get_run_httpx()
        if not run_httpx:
            return [], _METHOD_SUBFINDER_HTTPX
        return run_httpx(unique_hosts, cookies=session_cookies), _METHOD_SUBFINDER_HTTPX
    except (ToolNotFoundError, ToolExecutionError) as exc:
        logger.warning("httpx failed for %d hosts: %s", len(unique_hosts), exc)
        return [], _METHOD_SUBFINDER_HTTPX


def _run_nuclei_scan(
    target: Target,
    session_cookies: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Execute the Nuclei scan via the tool registry."""
    try:
        run_nuclei = _get_run_nuclei()
        if not run_nuclei:
            logger.warning("nuclei tool not in registry — skipping scan")
            return []
        return run_nuclei(
            target.url,
            session_cookies=session_cookies,
            extra_headers=extra_headers,
        )
    except (ToolNotFoundError, ToolExecutionError) as exc:
        logger.warning("nuclei failed for %s: %s", target.url, exc)
        return []


def _run_ffuf_discovery(
    target: Target,
    session_cookies: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Run opt-in ffuf content discovery with an explicit local wordlist."""
    from webpent.config.settings import get_settings

    settings = get_settings()
    if not settings.ffuf_enabled or not settings.ffuf_wordlist_path:
        return []
    run_ffuf = _get_run_ffuf()
    if not run_ffuf:
        logger.warning("ffuf tool not in registry — skipping content discovery")
        return []
    try:
        return run_ffuf(
            target.url,
            settings.ffuf_wordlist_path,
            session_cookies=session_cookies,
            extra_headers=extra_headers,
        )
    except (ToolNotFoundError, ToolExecutionError, ValueError) as exc:
        logger.warning("ffuf content discovery failed for %s: %s", target.url, exc)
        return []


def _convert_nuclei_records(
    records: list[dict[str, Any]],
    target_url: str,
) -> list[Finding]:
    """Convert Nuclei JSONL records into validated ``Finding`` models.

    Per-item error isolation ensures that a single malformed record
    (e.g. one whose ``info.name`` exceeds the model's ``max_length``
    even after truncation, or one that triggers a Pydantic
    ``ValidationError`` for some other reason) cannot discard the rest
    of the scan's findings. Malformed records are logged and skipped.

    Args:
        records: Parsed Nuclei JSONL records.
        target_url: Fallback URL used when a record lacks a valid one.

    Returns:
        A list of successfully-converted :class:`Finding` instances.
    """
    findings: list[Finding] = []
    failures = 0

    for record in records:
        if not isinstance(record, dict):
            continue
        try:
            finding = _nuclei_record_to_finding(record, target_url)
        except Exception:  # noqa: BLE001 — log and skip, don't abort
            failures += 1
            logger.warning(
                "Skipping malformed Nuclei record (id=%r): ",
                record.get("id") or record.get("template-id"),
                exc_info=True,
            )
            continue
        findings.append(finding)

    if failures:
        logger.warning(
            "Nuclei record conversion: %d succeeded, %d skipped due to errors",
            len(findings),
            failures,
        )

    return findings


def _discover_hidden_parameters(
    target: Target,
    existing_endpoints: list[str] | None = None,
    session_cookies: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """V7 Sprint 3.1a: Discover hidden parameters via Arjun-style param mining.

    Probes the target URL with a curated list of common parameter names
    (sourced from the SecLists wordlist ingested in Sprint 1, or a
    built-in fallback list if the RAG store has no payloads yet). For
    each parameter, sends a GET request with the parameter set to a
    canary value. If the response differs from the baseline (no-param)
    response by more than a threshold, the parameter is considered
    "discovered" — it influences the server's behavior, indicating it's
    a hidden or undocumented parameter that may be exploitable.

    Uses ``make_safe_httpx_client`` for all probes (SSRF guard, which
    allows the engagement's own declared target through even when it
    is a private IP — see ``shared/engagement_scope.py``). Returns a
    list of dicts: ``{"param": str, "url": str, "evidence": str}``.
    """
    # Built-in fallback parameter wordlist (used when the RAG store
    # has no ingested SecLists content). Curated from Arjun's default
    # wordlist — covers the most common hidden parameters.
    _fallback_param_wordlist: list[str] = [
        "id", "debug", "test", "admin", "user", "username", "password",
        "token", "key", "secret", "api", "cmd", "exec", "command",
        "file", "path", "page", "redirect", "url", "next", "return",
        "callback", "action", "method", "type", "format", "output",
        "query", "search", "filter", "sort", "order", "limit", "offset",
        "page", "size", "count", "total", "start", "end", "from", "to",
        "date", "time", "year", "month", "day", "name", "email",
        "phone", "address", "city", "state", "zip", "country",
        "role", "group", "level", "access", "permission", "privilege",
        "is_admin", "is_active", "enabled", "disabled", "deleted",
        "status", "state", "mode", "verbose", "log", "trace",
        "source", "target", "destination", "host", "port", "scheme",
        "protocol", "version", "lang", "locale", "currency",
    ]

    try:
        from webpent.shared.http import make_safe_httpx_client
    except ImportError:
        logger.debug("make_safe_httpx_client not importable — skipping param discovery")
        return []

    # Determine which endpoints to probe. Use existing_endpoints if
    # provided (from the crawler), otherwise just probe the target URL.
    endpoints = existing_endpoints or [target.url]
    if not endpoints:
        return []

    # Cap the number of endpoints to bound engagement time.
    endpoints = endpoints[:5]
    # Cap the wordlist to the first 40 params (bounds network traffic).
    param_list = _fallback_param_wordlist[:40]

    discoveries: list[dict[str, Any]] = []

    for endpoint in endpoints:
        try:
            # 1. Fetch baseline response (no params). POST-P0 Phase 3:
            # probes carry the operator's session so authenticated-only
            # endpoints participate in the differential.
            with make_safe_httpx_client(
                timeout=10.0, follow_redirects=False, verify=True,
                cookies=session_cookies or None,
            ) as client:
                baseline_resp = client.get(endpoint)
            baseline_len = len(baseline_resp.content)
            baseline_status = baseline_resp.status_code
            baseline_body = baseline_resp.text[:2000]

            # 2. Probe each parameter.
            for param in param_list:
                try:
                    with make_safe_httpx_client(
                        timeout=10.0, follow_redirects=False, verify=True,
                        cookies=session_cookies or None,
                    ) as client:
                        probe_resp = client.get(
                            endpoint, params={param: "webpent_canary_12345"}
                        )
                    probe_len = len(probe_resp.content)
                    probe_status = probe_resp.status_code

                    # Detect a "discovered" parameter:
                    # - Status code changed (e.g., 200 → 500 = param caused an error)
                    # - Body length changed by > 50 bytes (param influenced the output)
                    # - Body CONTENT changed even when length/status didn't
                    #   (V7 Ready-For-Kali FIX — caught by pyflakes flagging
                    #   `baseline_body` as computed-but-never-used: a param
                    #   that flips a same-length value, e.g. "false"->"true "
                    #   in a reflected field, was previously invisible to
                    #   this detector since length and status both stay
                    #   unchanged. Compares the first 2000 chars only, same
                    #   bound as baseline_body itself, to keep this cheap.)
                    probe_body = probe_resp.text[:2000]
                    if probe_status != baseline_status:
                        discoveries.append({
                            "param": param,
                            "url": endpoint,
                            "evidence": f"Status changed: {baseline_status} → {probe_status}",
                        })
                    elif abs(probe_len - baseline_len) > 50:
                        discoveries.append({
                            "param": param,
                            "url": endpoint,
                            "evidence": (
                                f"Length changed: {baseline_len} → {probe_len} "
                                f"(delta={probe_len - baseline_len})"
                            ),
                        })
                    elif probe_body != baseline_body:
                        discoveries.append({
                            "param": param,
                            "url": endpoint,
                            "evidence": "Body content changed with no length/status delta "
                                        "(e.g. a same-length value was reflected/altered)",
                        })
                except Exception as exc:
                    # V10 P3-5 FIX: previously a bare `except Exception:
                    # continue` with no logging — silent failure meant
                    # transient network errors / single-param issues
                    # were invisible. Log a WARNING per-param so the
                    # operator can see which params were skipped.
                    logger.warning(
                        "Hidden param discovery failed for %s: %s",
                        param, exc,
                    )
                    continue  # per-param resilience
        except Exception as exc:
            logger.debug("Param discovery baseline failed for %s: %s", endpoint, exc)
            continue

    if discoveries:
        logger.info(
            "Hidden parameter discovery: found %d params across %d endpoints",
            len(discoveries), len(endpoints),
        )
    return discoveries


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def recon_node(state: PentestState) -> dict:
    """LangGraph node implementing the recon phase.

    Args:
        state: Current graph state. Must contain a ``target`` key with a
            :class:`Target` instance.

    Returns:
        A partial state update with two keys:
          * ``findings`` — list of :class:`Finding` instances produced
            by Nuclei. Appended to existing findings via the
            ``merge_findings`` reducer.
          * ``messages`` — a single :class:`AIMessage` summarising the
            phase outcome, including the active recon method so the
            transcript accurately reflects lab vs. standard mode.
            Appended to existing messages via the ``add_messages``
            reducer.
    """
    target: Target = state["target"]

    logger.info("Recon phase starting for target=%s", target.url)

    # 1. Subdomain enumeration + live-host probing (best-effort).
    httpx_results, recon_method = _run_subdomain_recon(
        target, session_cookies=state.get("session_cookies")
    )
    logger.info(
        "Recon (%s) yielded %d live host(s) for %s",
        recon_method,
        len(httpx_results),
        target.domain or target.url,
    )

    # 2. Nuclei vulnerability scan against the primary target URL.
    nuclei_records = _run_nuclei_scan(
        target,
        session_cookies=state.get("session_cookies"),
        extra_headers=state.get("session_headers"),
    )
    logger.info(
        "Nuclei produced %d raw record(s) for %s",
        len(nuclei_records),
        target.url,
    )

    # 3. Convert Nuclei records into validated Finding models.
    #    Per-item error isolation ensures one malformed record cannot
    #    discard the rest of the scan's findings.
    new_findings = _convert_nuclei_records(nuclei_records, target.url)
    # V10 P1-4: observability — log the promoted_count so the operator
    # sees the full funnel: raw_lines (logged in run_nuclei) →
    # parsed_records → promoted_to_findings. If nuclei_records is empty
    # due to TOOL_INFRA_FAILURE (P0-3 quarantine), promoted_count=0.
    logger.info(
        "nuclei observability: parsed_records=%d, promoted_to_findings=%d",
        len(nuclei_records), len(new_findings),
    )

    # V7 Sprint 3.1a: Hidden-parameter discovery (Arjun-style).
    # Probes the target with common parameter names to find undocumented
    # params that influence server behavior. Results are stored in
    # crawled_data so downstream agents (hypothesis, payload_generator)
    # can use them.
    crawled_data: dict[str, Any] = dict(state.get("crawled_data") or {})
    try:
        existing_endpoints = crawled_data.get("endpoints") or crawled_data.get("urls") or []
        if not existing_endpoints:
            existing_endpoints = [target.url]
        hidden_params = _discover_hidden_parameters(
            target,
            existing_endpoints,
            session_cookies=state.get("session_cookies"),
        )
        if hidden_params:
            crawled_data["hidden_parameters"] = hidden_params
            logger.info("Hidden parameter discovery: %d params found", len(hidden_params))
    except Exception as exc:
        logger.debug("Hidden parameter discovery failed: %s", exc)

    # P0-2: opt-in content/directory discovery. The wrapper enforces
    # engagement scope; recon stores only metadata and does not promote
    # discovered paths to vulnerability Findings without validation.
    try:
        ffuf_results = _run_ffuf_discovery(
            target,
            session_cookies=state.get("session_cookies"),
            extra_headers=state.get("session_headers"),
        )
        if ffuf_results:
            crawled_data["content_discovery"] = ffuf_results
            logger.info("ffuf content discovery: %d path(s) found", len(ffuf_results))
    except Exception as exc:
        logger.debug("ffuf content discovery failed: %s", exc)

    # V7 Cognitive Upgrade — Phase 2: extract Mental Model updates from
    # recon's discoveries (httpx live hosts + any technologies detected
    # in httpx output). Pure additive — does not change any existing
    # recon logic. The extraction is deterministic regex/heuristic,
    # NO LLM. See webpent.models.mental_model.extract_mental_model_updates.
    #
    # V8 P0 A1: also extract ARTIFACT nodes from nuclei `matched-at`
    # URLs. The classifier (classify_artifact_type) is pure regex and
    # distinguishes artifact disclosures (.git/config, Dockerfile,
    # backup.zip, docker-compose.yml, .env, .htaccess, id_rsa, .DS_Store,
    # source-code disclosures, .svn, .hg) from useless fingerprint noise
    # (nuclei tech-detection / fingerprint templates that don't match
    # any artifact pattern). The artifacts are fed into the Mental Model
    # in the SAME run that discovers them — Phase A1 DoD — so the
    # Rabbit Hole and Strategist agents can see them immediately.
    mental_model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    try:
        from webpent.models.mental_model import extract_mental_model_updates
        # httpx results are dicts that typically carry "host", "url",
        # "tech" (a list of detected technologies), and "title".
        # V7 Phase 2 FIX (audit): only pass hostnames/IPs to the hosts
        # parameter — passing full URLs (result.get("url")) created
        # malformed host nodes with identity_key="http://localhost/admin"
        # because _normalise_host() just lowercases; it doesn't parse
        # the hostname out of a URL. URLs discovered by httpx are
        # endpoints, not hosts — the extractor's endpoints parameter
        # handles those separately.
        recon_hosts: list[str] = []
        recon_endpoints: list[str] = []
        recon_technologies: list[str] = []
        for result in (httpx_results or []):
            if not isinstance(result, dict):
                continue
            host = result.get("host") or result.get("input") or ""
            if host:
                recon_hosts.append(host)
            url = result.get("url") or ""
            if url:
                recon_endpoints.append(url)
            tech = result.get("tech") or result.get("technologies") or []
            if isinstance(tech, list):
                recon_technologies.extend(str(t) for t in tech if t)
            elif isinstance(tech, str) and tech:
                recon_technologies.append(tech)
        # Always include the target's primary host so the Mental Model
        # has at least one host to anchor edges to.
        if target.domain:
            recon_hosts.append(target.domain)
        # V8 P0 A1: extract artifact disclosures from nuclei records.
        # This is the deterministic classifier — no LLM. Nuclei records
        # whose `matched-at` URL matches an artifact pattern (e.g.
        # `/.git/config`, `/Dockerfile`, `/backup.zip`) become ARTIFACT
        # nodes; nuclei tech-detection / fingerprint noise does NOT
        # match any pattern and is silently dropped here (it remains a
        # Finding, but does not pollute the Mental Model).
        recon_artifacts: list[dict[str, str]] = _extract_artifacts_from_nuclei(
            nuclei_records, target.url,
        )
        if recon_artifacts:
            logger.info(
                "Recon artifact intelligence: %d artifact disclosure(s) "
                "extracted from nuclei records (types=%s). These will "
                "become ARTIFACT nodes in the Mental Model.",
                len(recon_artifacts),
                sorted({a["type"] for a in recon_artifacts}),
            )
        mental_model_update = extract_mental_model_updates(
            discovery_source="recon_node",
            hosts=recon_hosts,
            endpoints=recon_endpoints,
            technologies=recon_technologies,
            artifacts=recon_artifacts,
            target_url=target.url,
        )
    except Exception as exc:
        logger.debug("Mental Model extraction (recon) failed: %s", exc)

    # 4. Compose the LangGraph partial-state update.
    #    The summary includes the active recon method so the transcript
    #    stays accurate in both standard and PortSwigger lab modes.
    summary = (
        f"Recon phase completed for {target.url}. "
        f"Discovered {len(httpx_results)} live host(s) via {recon_method}; "
        f"Nuclei produced {len(new_findings)} finding(s)."
    )
    if crawled_data.get("hidden_parameters"):
        summary += (
            f" Hidden-param discovery found "
            f"{len(crawled_data['hidden_parameters'])} parameter(s)."
        )
    if crawled_data.get("content_discovery"):
        summary += f" ffuf found {len(crawled_data['content_discovery'])} in-scope path(s)."
    if mental_model_update.get("nodes"):
        summary += (
            f" Mental Model: added {len(mental_model_update['nodes'])} node(s) "
            f"+ {len(mental_model_update.get('edges') or [])} edge(s)."
        )

    return {
        "findings": new_findings,
        "crawled_data": crawled_data,
        "mental_model": mental_model_update,
        "messages": [AIMessage(content=summary)],
        "current_phase": "enumeration",
    }

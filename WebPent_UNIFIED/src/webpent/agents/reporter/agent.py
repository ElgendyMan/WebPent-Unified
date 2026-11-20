# src/webpent/agents/reporter/agent.py
"""webpent.agents.reporter.agent

LangGraph node that aggregates all findings into a professional report
and persists it to disk.

V3 Phase 5 upgrades the reporter to generate both Markdown and HTML
reports. The HTML report is rendered from a Jinja2 template.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from webpent.api.scan_registry import get_thread_ids_by_engagement_id
from webpent.config.settings import get_settings, profile_requires_proof_bundle
from webpent.memory.db import get_db_manager
from webpent.models.findings import Finding, Severity
from webpent.shared.bac_identity_tester import target_fingerprint
from webpent.shared.coverage_ledger import project_coverage_ledger
from webpent.shared.ensemble import apply_ensemble_review
from webpent.shared.finding_aggregation import aggregate_findings
from webpent.shared.kev import enrich_finding_with_kev
from webpent.shared.llm import (
    TaskType,
    get_safety_system_instruction,
    safe_prompt_format,
    try_get_llm,
)
from webpent.shared.persistent_finding_ledger import PersistentFindingLedger
from webpent.shared.report_quality import evaluate_report_quality
from webpent.state.reducers import model_get
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)


def _proof_required_for_state(state: PentestState, settings: Any) -> bool:
    """Resolve proof policy from settings plus the profile carried by state."""
    governance = state.get("smart_governance") or {}
    profile = (
        state.get("profile")
        or governance.get("public_profile")
        or governance.get("profile")
    )
    return bool(
        getattr(settings, "smart_require_proof_bundle", False)
        or governance.get("require_proof_bundle", False)
        or profile_requires_proof_bundle(profile)
    )


_REPORT_MD_FILENAME = "report.md"
_REPORT_HTML_FILENAME = "report.html"
_TEMPLATE_PATH = Path(__file__).parent.parent.parent / "templates" / "reports" / "html.j2"

_SYSTEM_PROMPT = (
    "You are a Senior Security Consultant writing an executive summary "
    "for a penetration test engagement. Use clear, professional language "
    "suitable for both technical and executive audiences. Output Markdown "
    "only — no preamble, no code fences."
)

_HUMAN_TEMPLATE_WITH_FINDINGS = (
    "Target: {target}\n"
    "Total findings: {count}\n\n"
    "Findings table (Markdown):\n\n{table}\n\n"
    "Write a concise executive summary (3-5 paragraphs) covering:\n"
    "1. Overall security posture.\n"
    "2. Most critical risks and their business impact.\n"
    "3. Recommended remediation priorities.\n"
)

_HUMAN_TEMPLATE_NO_FINDINGS = (
    "Target: {target}\n"
    "Total findings: 0\n\n"
    "Write a brief executive summary (2-3 paragraphs) noting that no "
    "vulnerabilities were identified during the engagement and "
    "recommending continued monitoring."
)

_FALLBACK_SUMMARY = (
    "An automated executive summary could not be generated because all "
    "configured LLM providers were unavailable. Refer to the structured "
    "findings table below for the raw results of the engagement. "
    "Manual review and narrative composition are recommended."
)

# V7 Sprint 3.3: Bug-bounty report format.
# Most bug bounty platforms (HackerOne, Bugcrowd) expect a specific
# report structure: Summary, Steps to Reproduce, Impact, Suggested
# Fix, and Supporting Material. This is distinct from the enterprise
# report format (which includes compliance mapping, CVSS vectors,
# and executive summaries). The bug-bounty format is more concise
# and action-oriented — it's written for the triage team, not for
# executives.
_BUG_BOUNTY_SYSTEM_PROMPT = (
    "You are a Bug Bounty Report Writer. For each vulnerability, "
    "produce a structured bug-bounty report with the following "
    "sections: Summary, Steps to Reproduce, Impact, Suggested Fix, "
    "and Supporting Material. Use clear, concise language suitable "
    "for a bug bounty triage team. Output Markdown only — no preamble, "
    "no code fences. Each finding should be a separate section "
    "starting with '## [Severity] Finding Title'."
)

_BUG_BOUNTY_HUMAN_TEMPLATE = (
    "Target: {target}\n"
    "Total findings: {count}\n\n"
    "Findings (Markdown table):\n\n{table}\n\n"
    "For EACH finding, write a bug-bounty report section with:\n"
    "1. **Summary** — 1-2 sentence description of the vulnerability.\n"
    "2. **Steps to Reproduce** — numbered steps to trigger the vuln.\n"
    "3. **Impact** — what an attacker can achieve.\n"
    "4. **Suggested Fix** — concrete remediation advice.\n"
    "5. **Supporting Material** — evidence (request/response snippets, "
    "screenshots references, CVSS scores).\n"
)

_REPORT_BUG_BOUNTY_MD_FILENAME = "bug_bounty_report.md"


def _findings_with_proof_bundles(
    findings: Iterable[Any],
    proof_bundles: Iterable[Any] | None,
    *,
    engagement_id: str = "",
    target_url: str = "",
) -> list[Any]:
    """Attach only current, finding-bound proof bundles to report views.

    A bundle is not portable evidence: it must belong to the current engagement
    and the current target fingerprint. Historical or cross-target bundles are
    deliberately ignored, preserving the strict fail-closed report gate.
    """
    current_target_fingerprint = target_fingerprint(target_url) if target_url else ""
    bundle_by_ref: dict[str, dict[str, Any]] = {}
    for raw_bundle in proof_bundles or ():
        if not isinstance(raw_bundle, Mapping):
            continue
        bundle_ref = str(raw_bundle.get("finding_id") or "").strip()
        if not bundle_ref:
            continue
        bundle_engagement = str(raw_bundle.get("engagement_id") or "").strip()
        bundle_target = str(raw_bundle.get("target_fingerprint") or "").strip()
        if engagement_id and bundle_engagement != engagement_id:
            continue
        if current_target_fingerprint and bundle_target != current_target_fingerprint:
            continue
        bundle_by_ref[bundle_ref] = dict(raw_bundle)
    views: list[Any] = []
    for finding in findings:
        finding_id = str(model_get(finding, "id", "") or "").strip()
        hypothesis_id = str(model_get(finding, "hypothesis_id", "") or "").strip()
        embedded = model_get(finding, "evidence_bundle")
        bundle = None
        if isinstance(embedded, Mapping):
            embedded_ref = str(embedded.get("finding_id") or "").strip()
            embedded_engagement = str(embedded.get("engagement_id") or "").strip()
            embedded_target = str(embedded.get("target_fingerprint") or "").strip()
            if (
                embedded_ref in {finding_id, hypothesis_id}
                and (not engagement_id or embedded_engagement == engagement_id)
                and (
                    not current_target_fingerprint
                    or embedded_target == current_target_fingerprint
                )
            ):
                bundle = dict(embedded)
        bundle = bundle or bundle_by_ref.get(finding_id) or bundle_by_ref.get(hypothesis_id)
        if bundle is None:
            views.append(finding)
            continue
        if isinstance(finding, Mapping):
            view = dict(finding)
        elif hasattr(finding, "model_dump"):
            view = finding.model_dump(mode="json")
        else:
            views.append(finding)
            continue
        view["proof_bundle"] = bundle
        evidence = view.get("evidence")
        if isinstance(evidence, Mapping) and evidence.get("proof_bundle") is None:
            view["evidence"] = {**evidence, "proof_bundle": bundle}
        views.append(view)
    return views


def _compose_bug_bounty_markdown(
    target_url: str,
    findings: list[Finding],
    llm_generated_sections: str,
    crawled_data: dict[str, Any] | None = None,
) -> str:
    """V7 Sprint 3.3: Compose a bug-bounty-ready Markdown report.

    Structure (per HackerOne/Bugcrowd conventions):
      * Header: target, date, total findings
      * Per-finding sections with: Summary, Steps to Reproduce,
        Impact, Suggested Fix, Supporting Material
      * Appendix: JS secrets discovered (if any)
    """
    lines: list[str] = [
        "# Bug Bounty Report", "",
        f"**Target:** {target_url}",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Total Findings:** {len(findings)}",
        "",
    ]

    # If the LLM generated per-finding sections, include them.
    if llm_generated_sections.strip():
        lines.extend(["## Findings", "", llm_generated_sections.strip(), ""])
    else:
        # Fallback: render a structured table if the LLM call failed.
        lines.extend(["## Findings", "", _render_findings_table(findings), ""])

    # Appendix: JS secrets discovered during crawling.
    if crawled_data and crawled_data.get("js_secrets"):
        secrets = crawled_data["js_secrets"]
        lines.extend([
            "## Appendix: Exposed Secrets in JavaScript", "",
            "The following secrets were discovered in the target's "
            "client-side JavaScript files during the crawl phase:", "",
            "| Type | Value (truncated) | Source |",
            "|------|-------------------|--------|",
        ])
        for s in secrets:
            lines.append(
                f"| {s.get('type', 'Unknown')} | "
                f"{s.get('value', '—')} | "
                f"{s.get('source', '—')} |"
            )
        lines.append("")

    # Appendix: Hidden parameters discovered.
    if crawled_data and crawled_data.get("hidden_parameters"):
        params = crawled_data["hidden_parameters"]
        lines.extend([
            "## Appendix: Hidden Parameters Discovered", "",
            "The following undocumented parameters were discovered via "
            "parameter mining (Arjun-style probing):", "",
            "| Parameter | URL | Evidence |",
            "|-----------|-----|----------|",
        ])
        for p in params:
            lines.append(
                f"| {p.get('param', '—')} | "
                f"{p.get('url', '—')} | "
                f"{p.get('evidence', '—')} |"
            )
        lines.append("")

    return "\n".join(lines)


def _sanitize_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _render_findings_table(findings: Iterable[Finding]) -> str:
    header = (
        "| # | Title | Severity | CVSS | Confidence | Business Impact | Reasoning | URL |\n"
        "|---|-------|----------|------|------------|-----------------|-----------|-----|\n"
    )
    rows: list[str] = []
    for idx, finding in enumerate(findings, start=1):
        title = _sanitize_cell(str(model_get(finding, "title", "") or ""))
        # R-07 (TEAM-2 residual): terminal refutations are struck through so a
        # retracted confirmation is never mistaken for an active claim.
        if str(model_get(finding, "confidence_level", "") or "") == "Refuted":
            title = f"~~{title}~~"
        severity = _sanitize_cell(str(model_get(finding, "severity", "") or ""))
        cvss = _sanitize_cell(str(model_get(finding, "cvss_score") or "—"))
        conf_level = _sanitize_cell(
            str(model_get(finding, "confidence_level", "Pending") or "Pending")
        )
        impact = _sanitize_cell(str(model_get(finding, "business_impact") or "—"))
        # V5 Sprint 5: Expose the audit-trail reasoning in the report.
        # Truncate long justifications so the Markdown table stays readable.
        reasoning_raw = str(model_get(finding, "reasoning", "") or "")
        reasoning = _sanitize_cell(reasoning_raw[:300]) if reasoning_raw else "—"
        url = _sanitize_cell(str(model_get(finding, "url", "") or ""))
        rows.append(
            f"| {idx} | {title} | {severity} | {cvss} | {conf_level} | "
            f"{impact} | {reasoning} | {url} |"
        )
    return header + "\n".join(rows)


def _build_human_prompt(target_url: str, findings: list[Finding]) -> str:
    if not findings:
        return safe_prompt_format(
            _HUMAN_TEMPLATE_NO_FINDINGS, target=target_url
        )
    return safe_prompt_format(
        _HUMAN_TEMPLATE_WITH_FINDINGS,
        target=target_url, count=len(findings),
        table=_render_findings_table(findings),
    )


def _scenario_scope_source_row(state: Mapping[str, Any]) -> tuple[str, str]:
    """Resolve the redaction-safe ``(source_label, detail)`` scope pair.

    SCENARIO CONTRACT: the report must surface WHERE the engagement
    boundaries came from. ``scope_file`` boundaries are contractual;
    ``inferred_from_url`` boundaries are cautious estimates and the
    report says so explicitly. Never carries secret material — scope
    declarations are host/path policy only by grammar.
    """
    declaration = dict(state.get("scope_declaration") or {})
    source = str(state.get("scope_source") or declaration.get("source") or "").strip()
    if source == "scope_file":
        detail = "operator-supplied contract (boundaries are contractual)"
        fingerprint = str(declaration.get("fingerprint") or "")
        if fingerprint:
            detail += f", fingerprint {fingerprint}"
        return "scope_file", detail
    if source == "inferred_from_url":
        return "inferred_from_url", (
            "cautious default derived from the target URL alone (same exact "
            "host only, no automatic subdomain expansion) — boundaries are "
            "ESTIMATES, not contractual; provide a scope file for "
            "contract-grade coverage claims"
        )
    if source:
        return source, "declared scope source"
    return "not_declared", "no scope source recorded this run"


def _scenario_auth_row(state: Mapping[str, Any]) -> str:
    """One-line honest authentication outcome (never carries secrets)."""
    status = str(state.get("authentication_status") or "").strip() or "unknown"
    liveness = dict(state.get("session_liveness") or {})
    principals = len([
        k for k, v in dict(state.get("identity_records") or {}).items()
        if isinstance(v, dict)
    ])
    parts = [status]
    if principals:
        parts.append(f"{principals} principal record(s)")
    if liveness:
        parts.append(
            f"liveness={str(liveness.get('status') or 'unknown')}"
            f", reauth={int(liveness.get('reauth_attempts') or 0)}"
            f"/{int(liveness.get('max_reauth_attempts') or 0)}"
        )
        if liveness.get("downgrade_requested"):
            parts.append("dead-session downgrade requested (affected findings "
                         "landed in Needs Human Review)")
    return "; ".join(parts)


def _compose_scenario_sections(
    state: Mapping[str, Any],
    findings: list[Finding],
) -> list[str]:
    """Build the scenario declaration + coverage matrix report sections.

    SCENARIO CONTRACT (report phase): the final report must contain —
      * scope source (file vs inferred) with its honesty caveat,
      * authentication outcome incl. principals exercised and session
        liveness (redaction-safe: statuses/counters only, NEVER cookie
        or credential values),
      * a coverage matrix across AuthZ / Input / Misconfig / Logic with
        the evidence basis actually present in state,
      * declared engagement limitations (single-account honesty,
        CAPTCHA/MFA blockers, dead-session downgrades).
    Everything here is derived from deterministic state fields; no LLM
    output is involved, so the section cannot overstate coverage.
    """
    lines: list[str] = []
    scope_source, scope_detail = _scenario_scope_source_row(state)
    declaration = dict(state.get("scope_declaration") or {})
    allow_entries = len(declaration.get("allow_entries") or [])
    excluded_hosts = len(declaration.get("excluded_hosts") or [])
    include_paths = len(declaration.get("include_paths") or [])
    exclude_paths = len(declaration.get("exclude_paths") or [])

    # --- Section 1: scope & session declaration (after the header) ---
    lines.extend([
        "## Scope & Session Declaration", "",
        "| Item | Value |",
        "|---|---|",
        f"| Scope source | `{scope_source}` — {scope_detail} |",
        f"| Allow entries | {allow_entries} |",
        f"| Excluded hosts | {excluded_hosts} |",
        f"| Path rules | include: {include_paths}, exclude: {exclude_paths} |",
        f"| Authentication | {_scenario_auth_row(state)} |",
    ])
    diff = dict((state.get("auth_surface_diff") or {}).get("counts") or {})
    if diff:
        lines.append(
            f"| Auth surface diff | both: {int(diff.get('both') or 0)}, "
            f"auth_only: {int(diff.get('auth_only') or 0)} "
            "(BAC/IDOR priority fuel), anonymous_only: "
            f"{int(diff.get('anonymous_only') or 0)} |"
        )
    lines.append("")
    if scope_source == "inferred_from_url":
        lines.extend([
            "> **Inferred-scope caveat:** no scope file was supplied for this "
            "engagement. Coverage claims are limited to the URL-derived "
            "default boundary; out-of-domain discoveries were recorded as "
            "observations only and never tested.",
            "",
        ])

    # --- Section 2: coverage matrix (deterministic, state-derived) ---
    tool_backed: dict[str, set[str]] = {}
    for finding in findings:
        if str(model_get(finding, "confidence_level", "") or "") != "Tool-Confirmed":
            continue
        tool = str(model_get(finding, "tool_name", "") or "unknown")
        category = str(model_get(finding, "category", "") or "general").lower()
        tool_backed.setdefault(category, set()).add(tool)
    bac_gaps = len(list(state.get("bac_coverage_gaps") or []))
    hypotheses = list(state.get("hypotheses") or [])
    limitations = list(state.get("engagement_limitations") or [])

    def _principal_note() -> str:
        records = dict(state.get("identity_records") or {})
        named = [str(k) for k, v in records.items() if isinstance(v, dict)]
        if not named:
            return "anonymous"
        return ", ".join(sorted(named))

    matrix_rows: list[tuple[str, str, str, str]] = [
        (
            "Access control (BAC/IDOR)",
            _principal_note(),
            "cross-principal differential probes; auth-only surface diff",
            f"{bac_gaps} open gap(s)" if bac_gaps else "no open gaps recorded",
        ),
        (
            "Input validation (SQLi/XSS/...)",
            _scenario_auth_row(state).split(";")[0],
            "tool-backed: " + (
                ", ".join(sorted({t for s in tool_backed.values() for t in s}))
                or "none confirmed this run"
            ),
            f"{len(tool_backed)} category(ies) with Tool-Confirmed evidence",
        ),
        (
            "Misconfiguration & exposure",
            "anonymous + authenticated",
            "recon/nuclei template matches in state",
            "see findings table",
        ),
        (
            "Business logic",
            _scenario_auth_row(state).split(";")[0],
            "bounded flow fuzz probes (skip-step/repeat/replay)",
            "no oracle => Needs Human Review when unconfirmed",
        ),
    ]
    lines.extend([
        "## Coverage Matrix", "",
        "Deterministic, state-derived coverage statement: which area was "
        "exercised with which principal and on what evidence basis. This "
        "table cannot be inflated by narrative — every cell is read from "
        "the engagement record.",
        "",
        "| Coverage area | Principals | Evidence basis | Gaps / notes |",
        "|---|---|---|---|",
    ])
    for area, principals, basis, gaps in matrix_rows:
        esc_principals = principals.replace("|", "\\|")
        esc_basis = basis.replace("|", "\\|")
        esc_gaps = gaps.replace("|", "\\|")
        lines.append(f"| {area} | {esc_principals} | {esc_basis} | {esc_gaps} |")
    lines.append("")
    lines.append(f"- Hypotheses recorded: {len(hypotheses)}")
    if limitations:
        lines.append(
            f"- Declared limitations: {len(limitations)} (single-account "
            "honesty, blocked auth paths, and dead-session downgrades are "
            "listed in the decision/limitations records)"
        )
    lines.append("")
    return lines


def _compose_markdown(
    target_url: str,
    findings: list[Finding],
    executive_summary: str,
    decision_log: list[dict[str, Any]] | None = None,
    scenario_sections: list[str] | None = None,
) -> str:
    """Compose the legacy Markdown report.

    V8 P0 A3: now appends a ``## Decision Log`` appendix when
    ``decision_log`` is non-empty, so the legacy Markdown path also
    surfaces promotion / abandon / risk-gate decisions. Mirrors the
    HTML template's Decision Log section.

    SCENARIO CONTRACT: when ``scenario_sections`` is provided (built by
    :func:`_compose_scenario_sections` from deterministic state fields)
    the Scope & Session Declaration is surfaced directly under the
    header and the Coverage Matrix is appended before the Decision Log.
    """
    header: list[str] = [
        "# WebPent Engagement Report", "",
        f"**Target:** {target_url}",
        f"**Total findings:** {len(findings)}",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
    ]
    if scenario_sections:
        # Declaration (first block) reads best directly under the header
        # — before any narrative — while the coverage matrix (second
        # block) stays with the appendices.
        declaration: list[str] = []
        matrix: list[str] = []
        cursor = declaration
        for line in scenario_sections:
            if line.startswith("## Coverage Matrix"):
                cursor = matrix
            cursor.append(line)
        header.extend(declaration)
        scenario_matrix = matrix
    else:
        scenario_matrix = []
    lines: list[str] = [
        *header,
        "", "## Executive Summary", "", executive_summary.strip(), "",
    ]
    if findings:
        lines.extend(["## Findings", "", _render_findings_table(findings), ""])
    # R-07 (TEAM-2 residual): explicit terminal-refutation section. 'Refuted'
    # is only ever produced by the deterministic refutation path (sealed
    # negative-control bundle + causal observation), so this summary is
    # audit-transparency output — it never lets LLM text retract anything.
    refuted = [
        f for f in findings
        if str(model_get(f, "confidence_level", "") or "") == "Refuted"
    ]
    if refuted:
        lines.extend([
            f"## Refuted Findings ({len(refuted)})", "",
            "Retracted by the deterministic refutation path (verified "
            "contradictory evidence + sealed negative-control proof bundle). "
            "Refuted is terminal: later callbacks or state saves cannot "
            "resurrect the original confirmation.",
            "",
        ])
        for f in refuted:
            title = str(model_get(f, "title", "") or "")
            url = str(model_get(f, "url", "") or "")
            reason = str(model_get(f, "reasoning", "") or "")
            lines.append(
                f"- ~~{title}~~ — `{url}`"
                + (f" — retraction basis: {reason[:240]}" if reason else "")
            )
        lines.append("")
    # SCENARIO CONTRACT: state-derived coverage matrix appendix.
    if scenario_matrix:
        lines.extend(scenario_matrix)
    # V8 P0 A3: Decision Log appendix.
    if decision_log:
        lines.extend([
            "## Decision Log", "",
            "Every promotion, abandonment, scope check, and risk-gate "
            "decision the framework made during this engagement, in "
            "chronological order. `Rule Fired` is the deterministic "
            "rule that triggered the decision (never LLM free text).",
            "",
            "| # | Timestamp (UTC) | Type | Rule Fired | Outcome | Branch ID |",
            "|---|-----------------|------|------------|---------|-----------|",
        ])
        for i, entry in enumerate(decision_log, 1):
            ts = (entry.get("timestamp") or "")[:19] or "—"
            dtype = entry.get("decision_type") or "—"
            rule = (entry.get("rule_fired") or "—").replace("|", "\\|")
            outcome = (entry.get("outcome") or "—").replace("|", "\\|")
            branch = entry.get("branch_id") or "—"
            lines.append(
                f"| {i} | `{ts}` | `{dtype}` | {rule} | {outcome} | `{branch}` |"
            )
        lines.append("")
    return "\n".join(lines)


def _save_report(content: str, output_dir: Path, filename: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(content, encoding="utf-8")
    return path


def _compute_stats(findings: list[Finding]) -> dict[str, int]:
    tool_confirmed = sum(
        1 for f in findings
        if model_get(f, "confidence_level", "") == "Tool-Confirmed"
    )
    # R-07 (TEAM-2 residual): count terminal refutations alongside
    # confirmations so reports can state both honestly.
    refuted = sum(
        1 for f in findings
        if model_get(f, "confidence_level", "") == "Refuted"
    )
    critical = sum(
        1 for f in findings
        if str(model_get(f, "severity", "")).lower() == Severity.CRITICAL.value
    )
    high = sum(
        1 for f in findings
        if str(model_get(f, "severity", "")).lower() == Severity.HIGH.value
    )
    return {
        "confirmed_count": tool_confirmed,
        "refuted_count": refuted,
        "critical_count": critical,
        "high_count": high,
    }


def _findings_to_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for f in findings:
        result.append({
            "title": str(model_get(f, "title", "") or ""),
            "severity": str(model_get(f, "severity", "") or ""),
            "confidence": str(model_get(f, "confidence", "") or ""),
            "confidence_level": model_get(f, "confidence_level", "Pending") or "Pending",
            "cvss_score": model_get(f, "cvss_score") or "",
            "business_impact": model_get(f, "business_impact") or "",
            # V5 Sprint 5: Expose reasoning for the audit trail section
            # in the HTML template. Empty string keeps the template
            # truthiness checks simple.
            "reasoning": model_get(f, "reasoning", "") or "",
            "url": str(model_get(f, "url", "") or ""),
        })
    return result


def _render_html_report(
    target_url: str, findings: list[Finding],
    executive_summary: str, hypotheses: list[str],
) -> str | None:
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError:
        logger.warning("Jinja2 is not installed — HTML report will not be generated.")
        return None

    template_dir = _TEMPLATE_PATH.parent
    template_name = _TEMPLATE_PATH.name

    if not _TEMPLATE_PATH.exists():
        logger.warning("HTML template not found at %s — skipping HTML report.", _TEMPLATE_PATH)
        return None

    try:
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template(template_name)
        stats = _compute_stats(findings)
        # R-07 (TEAM-2 residual): surface terminal refutations in the legacy
        # HTML render path as well (export_to_html gets them via
        # build_report_data).
        refuted_findings = [
            d for d in _findings_to_dicts(findings)
            if d.get("confidence_level") == "Refuted"
        ]
        html = template.render(
            target_url=target_url, total_findings=len(findings),
            confirmed_count=stats["confirmed_count"],
            refuted_count=stats["refuted_count"],
            refuted_findings=refuted_findings,
            critical_count=stats["critical_count"],
            high_count=stats["high_count"],
            executive_summary=executive_summary,
            findings=_findings_to_dicts(findings),
            hypotheses=hypotheses,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )
        logger.info("HTML report rendered successfully")
        return html
    except Exception as exc:
        logger.warning("Failed to render HTML report: %s. Only Markdown will be saved.", exc)
        return None


def reporter_node(state: PentestState) -> dict:
    """LangGraph node implementing the reporting phase.

    V5 Sprint 11: Now reads ``executive_summary`` and ``risk_score``
    from graph state (populated by the executive_summary_node) and
    delegates multi-format export to ``webpent.reporter.export``.
    Falls back to the legacy LLM-generated summary if the
    executive_summary_node did not populate the field.
    """
    target = state["target"]
    findings: list[Finding] = list(state.get("findings") or [])
    # Reports are cumulative within one explicit engagement scope. The current
    # run may not be persisted until the worker returns, so merge historical
    # DB findings first and keep the current state as the authoritative input
    # for this run. Any registry/DB failure falls back to the current state.
    engagement_id = str(state.get("engagement_id") or "")
    client_id = str(state.get("client_id") or "")
    owner_username = str(state.get("owner_username") or "")
    if engagement_id:
        try:
            sibling_threads = get_thread_ids_by_engagement_id(
                engagement_id,
                owner_username=owner_username,
                client_id=client_id,
            )
            historical = get_db_manager().get_findings_by_threads(sibling_threads)
            findings = aggregate_findings([*historical, *findings])
            ledger_findings = PersistentFindingLedger(
                get_settings().findings_ledger_path
            ).get(
                engagement_id,
                owner_username=owner_username,
                client_id=client_id,
            )
            findings = aggregate_findings([*ledger_findings, *findings])
        except Exception as exc:
            logger.warning(
                "Cumulative report projection unavailable for engagement %s: %s",
                engagement_id,
                exc,
            )
    # Phase 5.3: independently review only High/Critical findings before
    # report rendering. This adds an evidence signal and never changes
    # categorical confirmation semantics.
    primary_provider = state.get("llm_primary_provider")
    findings = apply_ensemble_review(
        findings,
        primary_provider=str(primary_provider) if primary_provider else None,
    )
    # 2026-10-24 fix: kev_catalog is declared on the state schema but had
    # no producer node, so the raw state read was always empty. The loader
    # resolves state first, then the operator's local JSON file
    # (kev_catalog_path), fail-soft to [] — the pre-wiring default.
    from webpent.shared.operator_catalogs import load_kev_catalog

    kev_catalog = load_kev_catalog(state.get("kev_catalog"))
    if isinstance(kev_catalog, list) and kev_catalog:
        findings = [enrich_finding_with_kev(finding, kev_catalog) for finding in findings]

    # Track 11 item 5 (2026-10-28) — dedup-before-nomination: split prior
    # duplicates out of the nomination set (gate annotation from
    # webpent.vip.dedup_gate). Fail-open: any annotation/shape error keeps
    # ALL findings nominated. Duplicates are never silently dropped — they
    # are rendered in the explicit appendix below.
    dedup_duplicates: list[Finding] = []
    try:
        from webpent.vip.dedup_gate import split_duplicate_findings

        _nominated, dedup_duplicates = split_duplicate_findings(findings)
        if dedup_duplicates:
            logger.info(
                "Reporter: %d finding(s) not renominated (prior duplicates, "
                "dedup gate Track 11.5) — listed in the report appendix",
                len(dedup_duplicates),
            )
            findings = _nominated
    except Exception:  # noqa: BLE001 — nomination gate must never block reporting
        logger.debug("dedup split unavailable — all findings stay nominated", exc_info=True)

    # V7 Cognitive Upgrade — Phase 1: state["hypotheses"] is now
    # list[Hypothesis] (atomic type migration). The reporter / export
    # pipeline / Jinja2 templates all expect list[str], so extract
    # .statement from each Hypothesis for the legacy rendering path.
    # The full Hypothesis objects remain in state for Dynamic
    # Prioritization / Decision Log / Rabbit Hole consumers.
    raw_hypotheses = list(state.get("hypotheses") or [])
    # V9 P0 B2 defense-in-depth: dedupe by hypothesis id (the
    # merge_hypotheses reducer already does this in state, but we
    # guard here too so a future regression in the reducer cannot
    # produce duplicate hypothesis text in the report).
    seen_hyp_ids: set = set()
    hypotheses: list[str] = []
    for h in raw_hypotheses:
        if isinstance(h, str):
            # Backward compat: legacy callers still passing strings.
            # Dedupe by the string itself.
            if h not in hypotheses:
                hypotheses.append(h)
        elif hasattr(h, "statement") or isinstance(h, dict):
            # V7 Hypothesis object or checkpoint-shaped dictionary — dedupe
            # by id and preserve its statement on resumed engagements.
            hid = model_get(h, "id")
            if hid is not None:
                if hid in seen_hyp_ids:
                    continue
                seen_hyp_ids.add(hid)
            statement = model_get(h, "statement", "")
            hypotheses.append(str(statement) if statement else str(h))
        else:
            s = str(h)
            if s not in hypotheses:
                hypotheses.append(s)

    # V5 Sprint 11: read the AI executive summary + risk score from
    # state (populated by executive_summary_node). Fall back to the
    # legacy LLM call if not present.
    executive_summary: str = state.get("executive_summary", "") or ""
    risk_score: str = state.get("risk_score", "Low") or "Low"

    target_url = str(model_get(target, "url", "") or "")
    settings = get_settings()
    proof_required = _proof_required_for_state(state, settings)
    report_findings = _findings_with_proof_bundles(
        findings,
        state.get("proof_bundles") or [],
        engagement_id=engagement_id,
        target_url=target_url,
    )
    quality_result = evaluate_report_quality(
        report_findings,
        require_proof_bundle=proof_required,
    )
    quality_dump = quality_result.model_dump(mode="json")

    logger.info(
        "Reporter phase starting for target=%s with %d finding(s) "
        "(risk=%s, summary_from_state=%s)",
        target_url, len(findings), risk_score, bool(executive_summary),
    )

    # Strict mode is opt-in. It fails closed before any LLM narrative is
    # generated, and returns only field names/statuses in the state audit.
    if (
        getattr(settings, "enable_report_quality_gate", False) or proof_required
    ) and not quality_result.ready:
        return {
            "messages": [AIMessage(content=(
                "Report quality gate blocked export: one or more findings "
                "lack required evidence contract fields. Review the "
                "report_quality_gate audit before retrying."
            ))],
            "report_quality_gate": quality_dump,
            "current_phase": "reporting",
        }

    # If the executive_summary_node did not populate the field, fall
    # back to the legacy LLM call.
    if not executive_summary:
        llm = try_get_llm(TaskType.ANALYSIS)
        human_prompt = _build_human_prompt(target_url, findings)
        try:
            response = llm.invoke(
                [
                    SystemMessage(content=get_safety_system_instruction()),
                    SystemMessage(content=_SYSTEM_PROMPT),
                    HumanMessage(content=human_prompt),
                ]
            )
            executive_summary = (
                response.content if isinstance(response.content, str)
                else str(response.content)
            )
        except Exception as exc:
            logger.error(
                "All LLM providers failed for reporter: %s. Using fallback summary.",
                exc,
            )
            executive_summary = _FALLBACK_SUMMARY

    decision_log: list[dict[str, Any]] = list(state.get("decision_log") or [])

    # V9 P0 [round-2 wiring audit]: resolve output_dir first and
    # guarded. export_all_formats() below needs this same output_dir
    # independently of whether the legacy Markdown path (next block)
    # succeeds, so this is split out rather than guarded together with
    # markdown composition — a Markdown-only failure must not also
    # block the JSON/HTML/PDF export from being attempted.
    try:
        output_dir = get_settings().ensure_output_dir()
    except Exception as exc:
        # Previously unguarded: a permissions/disk-full error here
        # used to crash reporter_node (the graph's LAST node)
        # uncaught. No report file (Markdown, JSON, HTML, or PDF) can
        # be written without a usable output directory, so this is
        # the one sub-case where returning early is correct rather
        # than attempting the multi-format export below.
        logger.error(
            "Could not create/access the report output directory "
            "(%s). No report file can be written this run. Findings "
            "remain persisted in the database (incremental "
            "persistence) and are retrievable via the API/DB once "
            "the output path issue is resolved.",
            exc,
        )
        return {
            "messages": [AIMessage(content=(
                f"Report generation failed: output directory "
                f"unavailable ({exc}). Findings remain persisted in "
                "the database."
            ))],
            "current_phase": "reporting",
        }

    # Legacy Markdown report (preserved for backward compat).
    # V8 P0 A3: pass the Decision Log so the legacy Markdown path also
    # surfaces promotion / abandon / risk-gate decisions. (The HTML
    # template gets it via export_all_formats below.)
    # V10 P3-3 FIX (a): initialise md_path=None before the try block so
    # the except handler below never sees an undefined name (the
    # previous code only assigned md_path inside the try, so a
    # _compose_markdown failure followed by a _render_html_report
    # fallback failure logged md_path as an unbound local).
    selected_formats = state.get("report_formats")
    # DEFECT SC-1 (scenario campaign, 2026-09-15): initial_state normalizes
    # an absent report_formats into an EMPTY list, so the historical
    # ``is None`` check never fired for default engagements — the legacy
    # Markdown report (the canonical human-readable artifact) was silently
    # skipped while JSON/HTML/PDF export still wrote (export_all_formats
    # defaults its own formats param). An empty selection now means
    # "operator default" here too, matching export semantics.
    markdown_requested = (
        selected_formats is None
        or not selected_formats
        or "all" in selected_formats
        or "md" in selected_formats
    )
    md_path: str | None = None
    markdown_failed = False
    try:
        if markdown_requested:
            # SCENARIO CONTRACT: derive the scope/session declaration +
            # coverage matrix from deterministic state fields. A failure
            # here must never take down the report's last node — degrade
            # to a report without the scenario sections instead.
            try:
                _scenario_sections = _compose_scenario_sections(state, findings)
            except Exception as scenario_exc:
                logger.warning(
                    "Scenario declaration composition failed (%s) — "
                    "report will omit the scenario sections.",
                    type(scenario_exc).__name__,
                )
                _scenario_sections = []
            markdown = _compose_markdown(
                target_url, findings, executive_summary,
                decision_log=decision_log,
                scenario_sections=_scenario_sections,
            )
            md_path = _save_report(markdown, output_dir, _REPORT_MD_FILENAME)
            # Track 11 item 5: make duplicate suppression visible in the
            # canonical Markdown artifact (explicit appendix, reversible
            # by human review). A failure here never blocks the report.
            if dedup_duplicates:
                try:
                    from webpent.vip.dedup_gate import render_duplicates_appendix

                    appendix = render_duplicates_appendix(dedup_duplicates)
                    if appendix:
                        with open(md_path, "a", encoding="utf-8") as handle:
                            handle.write(appendix)
                except Exception:  # noqa: BLE001
                    logger.debug("dedup appendix render failed", exc_info=True)
            logger.info("Markdown report written to %s", md_path)
    except Exception as exc:
        markdown_failed = True
        # V9 P0 [round-2 wiring audit]: previously unguarded — a
        # formatting error triggered by one malformed finding (e.g. an
        # unexpected None/type in a field _compose_markdown doesn't
        # defensively handle) used to crash the entire reporter_node
        # uncaught, sacrificing the JSON/HTML/PDF export below too
        # even though that export does not depend on the Markdown
        # path succeeding. Log and continue instead.
        logger.error(
            "Legacy Markdown report generation failed (%s) — "
            "continuing to JSON/HTML/PDF export, which does not "
            "depend on the Markdown path. Findings remain persisted "
            "in the database regardless.",
            exc,
        )

    html_requested = (
        selected_formats is None
        or "all" in selected_formats
        or "html" in selected_formats
    )

    # V5 Sprint 11: Multi-format export (JSON + HTML + PDF) with
    # cryptographic audit trail + compliance tags.
    # V7 Cognitive Upgrade — Phase 6: pass the Decision Log from state
    # so it's surfaced in the report's explainability appendix.
    # V10 P3-3 FIX (b): track export_ok so the final return message
    # can be downgraded to a WARNING when both Markdown composition
    # AND the multi-format export (incl. legacy HTML fallback) fail.
    export_ok = False
    try:
        from webpent.reporter.export import export_all_formats

        campaign_ledger = dict(state.get("campaign_ledger") or {})
        campaign_plan = state.get("campaign_plan")
        if isinstance(campaign_plan, dict):
            # Preserve the declarative planner output separately from the
            # projection-only smart coverage ledger.
            campaign_ledger["campaign_plan"] = campaign_plan
        campaign_ledger["coverage_projection"] = project_coverage_ledger(state)
        campaign_ledger["llm_budget_trace"] = list(state.get("llm_budget_trace") or [])
        campaign_ledger["llm_usage_trace"] = list(state.get("llm_usage_trace") or [])
        campaign_ledger["task_outcome_count"] = len(state.get("campaign_task_outcomes") or [])
        campaign_ledger["http_observation_count"] = len(state.get("smart_http_observations") or [])
        package_projection = state.get("target_package")
        if not isinstance(package_projection, dict):
            package_projection = {}
        target_package = {
            "package_id": state.get("target_package_id") or package_projection.get("package_id"),
            "package_sha256": (
                state.get("target_package_sha256")
                or package_projection.get("package_sha256")
            ),
            "schema_version": (
                package_projection.get("schema_version") or "target-package.schema.v2"
            ),
            "scope_digest": (
                state.get("target_package_scope_digest")
                or package_projection.get("scope_digest")
            ),
            "policy_digest": (
                state.get("target_package_policy_digest")
                or package_projection.get("policy_digest")
            ),
            "capability_digest": (
                state.get("target_package_capability_digest")
                or package_projection.get("capability_digest")
            ),
            "scope_status": (
                package_projection.get("scope_status")
                or state.get("target_package_status")
            ),
            "signature_state": package_projection.get("signature_state"),
            "status": package_projection.get("status") or state.get("target_package_status"),
            "revocation_state": (
                (state.get("target_package_authorization") or {}).get("revocation_state")
                if isinstance(state.get("target_package_authorization"), dict)
                else None
            ),
        }
        if not target_package["package_id"]:
            target_package = None
        execution_observations = list(state.get("execution_observations") or [])
        logger.info(
            "Reporter export input: execution_observations=%d, findings=%d",
            len(execution_observations),
            len(report_findings),
        )
        paths = export_all_formats(
            target_url=target_url,
            findings=report_findings,
            output_dir=output_dir,
            executive_summary=executive_summary,
            risk_score=risk_score,
            hypotheses=hypotheses,
            decision_log=decision_log,
            bac_observations=list(state.get("bac_observations") or []),
            bac_coverage_gaps=list(state.get("bac_coverage_gaps") or []),
            relational_evidence=list(state.get("relational_evidence") or []),
            subdomain_takeover_observations=list(
                state.get("subdomain_takeover_observations") or []
            ),
            subdomain_takeover_coverage_gaps=list(
                state.get("subdomain_takeover_coverage_gaps") or []
            ),
            cloud_storage_observations=list(state.get("cloud_storage_observations") or []),
            cloud_storage_coverage_gaps=list(state.get("cloud_storage_coverage_gaps") or []),
            jwt_deep_observations=list(state.get("jwt_deep_observations") or []),
            jwt_deep_coverage_gaps=list(state.get("jwt_deep_coverage_gaps") or []),
            disclosed_report_advisories=list(state.get("disclosed_report_advisories") or []),
            advisory_coverage_gaps=list(state.get("advisory_coverage_gaps") or []),
            strict_quality_gate=bool(getattr(settings, "enable_report_quality_gate", False)),
            require_proof_bundle=proof_required,
            coverage_ledger=dict(state.get("coverage_ledger") or {}),
            campaign_ledger=campaign_ledger,
            proof_observability=dict(state.get("proof_observability") or {}),
            authorization_matrix=dict(state.get("authorization_matrix") or {}),
            llm_usage_trace=list(state.get("llm_usage_trace") or []),
            runtime_capability_gaps=list(state.get("runtime_capability_gaps") or []),
            execution_observations=execution_observations,
            target_package=target_package,
            formats=list(selected_formats) if selected_formats else None,
        )
        export_ok = True
        rendered = ", ".join(
            f"{name}={path}" for name, path in paths.items() if path is not None
        ) or "none"
        logger.info("V5 Sprint 11 multi-format export complete: %s", rendered)
    except Exception as exc:
        logger.warning(
            "V5 Sprint 11 multi-format export failed (%s) — falling "
            "back to legacy HTML render.", exc,
        )
        # V9 P0 B10: guard the fallback path too — a bad UUID/datetime/None
        # in _render_html_report must NOT wipe the engagement's Markdown
        # report (already written above) or crash the graph. Respect an
        # explicit format selection: JSON-only/MD-only runs must not create
        # an unrequested HTML artifact.
        if html_requested:
            try:
                html = _render_html_report(target_url, findings, executive_summary, hypotheses)
                if html is not None:
                    html_path = _save_report(html, output_dir, _REPORT_HTML_FILENAME)
                    export_ok = True
                    logger.info("HTML report written to %s (legacy)", html_path)
            except Exception as fallback_exc:
                logger.error(
                    "Legacy HTML render also failed (%s) — Markdown report "
                    "at %s is the canonical output. Engagement findings are "
                    "still persisted in the DB; only the HTML rendering is lost.",
                    fallback_exc, md_path,
                )
        else:
            logger.error(
                "Selected report formats failed and no HTML fallback was requested; "
                "engagement findings remain persisted in the DB."
            )

    # V10 P3-3 FIX (b): previously this returned "Report generated
    # successfully." unconditionally — even when BOTH Markdown
    # composition and the multi-format export (incl. legacy HTML
    # fallback) raised exceptions. Downgrade to a WARNING in that case
    # so the operator is alerted that no report artifact was produced
    # (findings remain persisted in the DB regardless).
    if markdown_failed and not export_ok:
        return {
            "messages": [AIMessage(content=(
                "WARNING: report generation failed — both Markdown "
                "composition and the multi-format export raised "
                "exceptions. Findings remain persisted in the database "
                "but no report artifact was written. Check the logs "
                "for details."
            ))],
            "current_phase": "reporting",
        }

    return {
        "messages": [AIMessage(content=(
            "Report generated successfully."
            + (
                f" {len(dedup_duplicates)} finding(s) matched previously reported "
                "results and were listed in the duplicates appendix instead of "
                "the nomination table (dedup gate)."
                if dedup_duplicates else ""
            )
        ))],
        "report_quality_gate": quality_dump,
        "current_phase": "reporting",
    }


def reporter_node_bug_bounty(state: PentestState) -> dict:
    """V7 Sprint 3.3: Generate a bug-bounty-ready report.

    Produces a Markdown report with the HackerOne/Bugcrowd structure:
    Summary, Steps to Reproduce, Impact, Suggested Fix, Supporting
    Material. Also includes appendices for JS secrets and hidden
    parameters discovered during recon.

    This node reads the same state as the enterprise ``reporter_node``
    but produces a differently-structured output. It can be used as a
    drop-in replacement for ``reporter_node`` when the operator wants
    a bug-bounty-format report instead of an enterprise report.

    Usage (in graph/builder.py)::

        # To use bug-bounty format, replace reporter_node with
        # reporter_node_bug_bounty in the graph:
        graph.add_node(NODE_REPORTER, reporter_node_bug_bounty)
    """
    target = state["target"]
    findings: list[Finding] = list(state.get("findings") or [])
    crawled_data: dict[str, Any] = state.get("crawled_data") or {}
    target_url = str(model_get(target, "url", "") or "")
    engagement_id = str(state.get("engagement_id") or "")
    settings = get_settings()

    # Track 11 item 5 (2026-10-28) — dedup-before-nomination (bug-bounty
    # path). Same fail-open split as the main reporter: prior duplicates
    # leave the nomination set and are rendered in an explicit appendix.
    dedup_duplicates: list[Finding] = []
    try:
        from webpent.vip.dedup_gate import split_duplicate_findings

        _nominated, dedup_duplicates = split_duplicate_findings(findings)
        if dedup_duplicates:
            logger.info(
                "Bug-bounty reporter: %d finding(s) not renominated (prior "
                "duplicates, dedup gate Track 11.5)",
                len(dedup_duplicates),
            )
            findings = _nominated
    except Exception:  # noqa: BLE001
        logger.debug("dedup split unavailable — all findings stay nominated", exc_info=True)

    proof_required = _proof_required_for_state(state, settings)
    report_findings = _findings_with_proof_bundles(
        findings,
        state.get("proof_bundles") or [],
        engagement_id=engagement_id,
        target_url=target_url,
    )
    quality_result = evaluate_report_quality(
        report_findings,
        require_proof_bundle=proof_required,
    )
    quality_dump = quality_result.model_dump(mode="json")

    logger.info(
        "Bug-bounty reporter starting for target=%s with %d finding(s)",
        target_url, len(findings),
    )

    if (
        getattr(settings, "enable_report_quality_gate", False) or proof_required
    ) and not quality_result.ready:
        return {
            "messages": [AIMessage(content=(
                "Bug-bounty report blocked by the evidence quality gate. "
                "Review report_quality_gate and complete the missing "
                "contract fields before export."
            ))],
            "report_quality_gate": quality_dump,
            "current_phase": "reporting",
        }

    # Generate per-finding bug-bounty sections via the LLM.
    llm_generated_sections = ""
    if findings:
        llm = try_get_llm(TaskType.ANALYSIS)
        human_prompt = safe_prompt_format(
            _BUG_BOUNTY_HUMAN_TEMPLATE,
            target=target_url,
            count=len(findings),
            table=_render_findings_table(findings),
        )
        try:
            response = llm.invoke(
                [
                    SystemMessage(content=get_safety_system_instruction()),
                    SystemMessage(content=_BUG_BOUNTY_SYSTEM_PROMPT),
                    HumanMessage(content=human_prompt),
                ]
            )
            llm_generated_sections = (
                response.content if isinstance(response.content, str)
                else str(response.content)
            )
        except Exception as exc:
            logger.error(
                "LLM failed for bug-bounty report: %s. Using fallback table format.",
                exc,
            )
            llm_generated_sections = ""

    # Compose the bug-bounty Markdown report.
    markdown = _compose_bug_bounty_markdown(
        target_url, findings, llm_generated_sections, crawled_data,
    )

    output_dir = get_settings().ensure_output_dir()
    md_path = _save_report(markdown, output_dir, _REPORT_BUG_BOUNTY_MD_FILENAME)
    # Track 11 item 5: explicit duplicates appendix in the bug-bounty
    # Markdown artifact (visible, reversible — never a silent drop).
    if dedup_duplicates:
        try:
            from webpent.vip.dedup_gate import render_duplicates_appendix

            appendix = render_duplicates_appendix(dedup_duplicates)
            if appendix:
                with open(md_path, "a", encoding="utf-8") as handle:
                    handle.write(appendix)
        except Exception:  # noqa: BLE001
            logger.debug("dedup appendix render failed", exc_info=True)
    logger.info("Bug-bounty Markdown report written to %s", md_path)

    return {
        "messages": [AIMessage(
            content=(
                f"Bug-bounty report generated successfully at {md_path}."
                + (
                    f" {len(dedup_duplicates)} prior duplicate(s) listed in the "
                    "appendix (not renominated)."
                    if dedup_duplicates else ""
                )
            )
        )],
        "report_quality_gate": quality_dump,
        "current_phase": "reporting",
    }

"""Bug-bounty evidence export — turns a promoted finding into a submission.

Produces, per finding (no frozen file is touched; read-only over the ledger):

* ``<finding_id>_bugbounty.md`` — human-readable submission:
  title, severity, CVSS vector+score, affected URL, numbered steps to
  reproduce, cURL command pairs (owner vs foreign, token placeholders —
  never literal tokens), impact, remediation, ProofBundle reference,
  video-POC attachment links.
* ``<finding_id>_evidence.json`` — machine-readable sidecar with the same
  fields for platform APIs (HackerOne/Bugcrowd importers).

Remediation text is a static mapping from the deterministic ``vuln_class``
routing category — there is deliberately no target-specific code here.
"""

from __future__ import annotations

import json
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from webpent.models.evidence import redact_sensitive
from webpent.reporter.poc_recorder import (
    _as_mapping,
    finding_is_promoted,
    safe_artifact_stem,
)

# vuln_class -> remediation guidance (static, target-independent)
REMEDIATIONS: dict[str, str] = {
    "IDOR": (
        "Enforce object-level authorization on every request: resolve the "
        "object's owner server-side from the authenticated session (never "
        "from client-supplied IDs alone) and return 403/404 on cross-tenant "
        "access. Add regression tests for horizontal privilege boundaries."
    ),
    "BOLA": (
        "Enforce object-level authorization on the API layer: bind every "
        "object reference to the owning principal server-side and reject "
        "cross-account access with 403/404. See OWASP API1 (BOLA)."
    ),
    "XSS": (
        "Apply context-aware output encoding, adopt a strict Content Security "
        "Policy, and sanitize user-supplied HTML with a vetted allow-list "
        "library before rendering."
    ),
    "SSRF": (
        "Validate and allow-list outbound request destinations, block link-"
        "local/metadata/private IP ranges at the network layer, and never "
        "fetch raw user-supplied URLs from server-side code."
    ),
    "MISSING_CSRF": (
        "Require per-session anti-CSRF tokens on all state-changing "
        "endpoints and validate SameSite cookie attributes."
    ),
    "INFO_DISCLOSURE": (
        "Remove sensitive data from public responses, disable verbose error "
        "reporting in production, and review data classifications for every "
        "exposed endpoint."
    ),
    "AUTH_BYPASS": (
        "Re-verify authorization on every route server-side, fail closed on "
        "missing/invalid session state, and add negative-path tests for "
        "unauthenticated access to protected resources."
    ),
    "UNKNOWN": (
        "Review the affected endpoint's authorization and input-handling "
        "logic; apply least-privilege and defense-in-depth controls."
    ),
}


def _redact(value: Any, *, key_hint: str = "") -> Any:
    """Redact secret-shaped values before they enter Markdown or JSON output."""
    clean, _ = redact_sensitive(value, key_hint=key_hint)
    return clean


def _safe_text(value: Any, *, default: str = "") -> str:
    text = str(value or "").strip()
    if not text:
        return default
    return str(_redact(text)).strip()


def _safe_header_name(value: Any) -> str:
    """Accept only a header name; never allow a header value into a command."""
    candidate = _safe_text(value, default="Authorization")
    return candidate if re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", candidate) else "Authorization"


def _shell_env_header(header_name: str, variable: str) -> str:
    """Quote static header text while leaving the token variable expandable."""
    return f"{shlex.quote(header_name + ': ')}\"${variable}\""


def _cvss_parts(finding: Mapping[str, Any]) -> tuple[str, str]:
    """Score + vector extraction (v4, R-13).

    Prefer an explicit ``cvss_vector`` field; only tokens that actually start
    with ``CVSS:`` are treated as vectors (v3 classified any token containing
    ``/`` as a vector, so a score written ``7.5/10`` became a bogus vector).
    """
    explicit_vector = str(finding.get("cvss_vector") or "").strip()
    raw = str(finding.get("cvss_score") or "").strip()
    if not raw and not explicit_vector:
        return str(finding.get("severity") or "UNKNOWN"), ""
    vector_match = explicit_vector or None
    score_match = None
    for token in raw.replace("\n", " ").split():
        if token.startswith(("CVSS:3", "CVSS:4")):
            vector_match = vector_match or token
        elif "/" not in token:
            try:
                score_match = f"{float(token):.1f}"
            except ValueError:
                continue
    return (score_match or str(finding.get("severity") or "UNKNOWN")), (vector_match or "")


def _proof_bundle_ref(evidence: Mapping[str, Any]) -> dict[str, str]:
    """Extract ProofBundle identity from finding evidence (read-only)."""
    bundle = evidence.get("proof_bundle") if isinstance(evidence, Mapping) else None
    if not isinstance(bundle, Mapping):
        promotion = evidence.get("promotion") if isinstance(evidence, Mapping) else None
        bundle = (promotion.get("proof_bundle") if isinstance(promotion, Mapping) else None) or {}
    return {
        "bundle_id": str(bundle.get("bundle_id") or bundle.get("id") or ""),
        "seal_hash": str(bundle.get("seal_hash") or bundle.get("hash") or ""),
        "replay_verified": str(bundle.get("replay_verified") or ""),
    }


def build_curl_commands(
    finding: Mapping[str, Any], *, token_header: str = "Authorization"
) -> list[str]:
    """Two cURL repro commands using env-var token placeholders.

    Literal tokens are NEVER embedded in exports; operators substitute
    ``$OWNER_TOKEN`` / ``$FOREIGN_TOKEN`` at submission time.
    v4 (R-04): every variable fragment (URL, header, body) is passed through
    ``shlex.quote`` — the v3 single-quote template broke out of quoting on
    any target-controlled ``'``/``$(...)``/``&`` and produced executable
    junk (or worse) when a triager copy-pasted the submission command.
    """
    url = _safe_text(finding.get("url"), default="TARGET_URL")
    method = str(finding.get("request_method") or "GET").upper()
    if not re.fullmatch(r"[A-Z]{1,10}", method):
        method = "GET"
    data = finding.get("request_data") or {}
    body = ""
    if isinstance(data, Mapping) and data:
        body = json.dumps(_redact(data, key_hint="request_data"), separators=(",", ":"))
    header_name = _safe_header_name(token_header)
    lines = []
    for label, token_var in (("owner", "OWNER_TOKEN"), ("foreign", "FOREIGN_TOKEN")):
        parts = [f"curl -sk -X {method}", f"-H {_shell_env_header(header_name, token_var)}"]
        if body:
            parts += ["-H 'Content-Type: application/json'", f"-d {shlex.quote(body)}"]
        parts.append(shlex.quote(url))
        lines.append(f"# {label} session — expect identical privileged data if vulnerable\n" + " \\\n  ".join(parts))
    return lines


def steps_to_reproduce(finding: Mapping[str, Any]) -> list[str]:
    url = _safe_text(finding.get("url"), default="TARGET_URL (replace with the sealed target URL)")
    method = str(finding.get("request_method") or "GET").upper()
    param = _safe_text(finding.get("target_param"), default="the affected object identifier")
    payload = _safe_text(finding.get("payload"))
    steps = [
        f"Authenticate as the resource OWNER and note the identifier referenced by {param} in `{method} {url}`.",
        "Authenticate as a second, unrelated account (the FOREIGN principal) in a separate session.",
        f"Replay `{method} {url}` from the FOREIGN session (same request, foreign token).",
        "Observe that the foreign session receives the owner's protected data (or the privileged effect) without any ownership check.",
        "Compare the two responses — identical privileged payloads across sessions demonstrate the broken object-level authorization.",
    ]
    if payload:
        steps.insert(3, f"Use the captured payload where applicable: `{payload[:200]}`.")
    return steps


def export_finding_evidence(
    finding: Mapping[str, Any],
    *,
    output_dir: Path | str,
    poc_dir: Path | str | None = None,
    token_header: str = "Authorization",
) -> dict[str, Any]:
    """Write the markdown submission + JSON sidecar for one finding."""
    finding = _as_mapping(finding)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    fid = _safe_text(finding.get("id"), default="unknown")
    # v4 (R-14): the ledger id is kept verbatim in CONTENT; only FILE names
    # use the sanitized stem (hostile ids must not traverse paths).
    stem = safe_artifact_stem(fid)
    evidence = finding.get("evidence") or {}
    evidence = evidence if isinstance(evidence, Mapping) else {}
    score, vector = _cvss_parts(finding)
    bundle = _proof_bundle_ref(evidence)
    vuln_class = _safe_text(finding.get("vuln_class"), default="UNKNOWN")
    remediation = REMEDIATIONS.get(vuln_class, REMEDIATIONS["UNKNOWN"])

    poc_note = ""
    if poc_dir is not None:
        poc = Path(poc_dir)
        video = poc / f"poc_{stem}.webm"
        meta = poc / f"poc_{stem}.json"
        if video.exists():
            poc_note = (
                f"\n## Video POC\n\n- Recording: `poc_{stem}.webm` "
                f"({video.stat().st_size} bytes)\n- Metadata: "
                f"`poc_{stem}.json`\n"
            )

    curl_cmds = build_curl_commands(finding, token_header=token_header)
    steps = steps_to_reproduce(finding)
    md = [
        f"# {_safe_text(finding.get('title'), default='Security finding')}",
        "",
        f"- **Severity:** {finding.get('severity', 'UNKNOWN')}  ",
        f"- **CVSS:** {score}" + (f"  ({vector})" if vector else ""),
        f"- **Vulnerability class:** {vuln_class}",
        f"- **Affected URL:** `{_safe_text(finding.get('url'), default='TARGET_URL (not supplied)')}`",
        f"- **Reported:** {datetime.now(timezone.utc).date().isoformat()}",
        "",
        "## Summary",
        "",
        _safe_text(finding.get("description"), default="Description was not provided in the source finding; see the executed steps below."),
        "",
        "## Steps to reproduce",
        "",
        *[f"{i}. {step}" for i, step in enumerate(steps, 1)],
        "",
        "## Reproduction commands",
        "",
        "```bash",
        *curl_cmds,
        "```",
        "",
        "## Impact",
        "",
        _safe_text(
            finding.get("business_impact") or finding.get("description"),
            default="Business impact was not provided in the source finding.",
        ),
        poc_note,
        "## Remediation",
        "",
        remediation,
        "",
        "## Supporting evidence",
        "",
        f"- ProofBundle: `{bundle['bundle_id'] or 'n/a'}` "
        f"(seal: `{bundle['seal_hash'] or 'n/a'}`, replay: "
        f"`{bundle['replay_verified'] or 'n/a'}`)",
        f"- Tool: {_safe_text(finding.get('tool_name'), default='webpent')}",
        f"- References: {', '.join(_safe_text(ref) for ref in (finding.get('references') or [])) or 'n/a'}",
        "",
    ]
    md_path = out / f"{stem}_bugbounty.md"
    md_path.write_text("\n".join(md), encoding="utf-8")

    sidecar = {
        "finding_id": fid,
        "title": _safe_text(finding.get("title"), default="Security finding"),
        "severity": _safe_text(finding.get("severity"), default="UNKNOWN"),
        "cvss_score": score,
        "cvss_vector": vector,
        "vuln_class": vuln_class,
        "url": _safe_text(finding.get("url"), default="TARGET_URL (not supplied)"),
        "method": _safe_text(finding.get("request_method"), default="GET"),
        "steps_to_reproduce": steps,
        "curl_commands": curl_cmds,
        "impact": _safe_text(
            finding.get("business_impact") or finding.get("description"),
            default="Business impact was not provided in the source finding.",
        ),
        "remediation": remediation,
        "proof_bundle": bundle,
        "references": [_safe_text(ref) for ref in (finding.get("references") or [])],
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }
    json_path = out / f"{stem}_evidence.json"
    json_path.write_text(json.dumps(sidecar, indent=2) + "\n", encoding="utf-8")
    return {"markdown": str(md_path), "json": str(json_path), "finding_id": fid}


def export_all_promoted(
    findings: list[Mapping[str, Any]],
    *,
    output_dir: Path | str,
    poc_dir: Path | str | None = None,
    token_header: str = "Authorization",
) -> dict[str, Any]:
    """Export every promoted finding; returns an honest summary."""
    exported, skipped = [], []
    for finding in findings:
        finding = _as_mapping(finding)
        fid = str(finding.get("id") or "")
        if not finding_is_promoted(finding):
            skipped.append({"finding_id": fid, "reason": "not_promoted"})
            continue
        try:
            result = export_finding_evidence(
                finding, output_dir=output_dir, poc_dir=poc_dir, token_header=token_header
            )
            exported.append(result)
        except (TypeError, ValueError, KeyError, OSError) as exc:
            skipped.append({"finding_id": fid, "reason": f"{type(exc).__name__}: {exc}"})
    return {"exported": exported, "skipped": skipped, "count": len(exported)}

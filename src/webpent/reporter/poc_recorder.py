"""Video POC recorder — turns a promoted finding into a step-by-step video.

Design constraints (FINAL PREPARATION SPRINT, 2026-10-05):

* The trust chain (PromotionPipeline, ProofBundle, ReplayVerifier) is FROZEN
  and is NOT modified by this module. POC recording is a strictly optional
  ENHANCEMENT that runs after a finding has already been promoted.
* ``maybe_record_poc`` is the integration entry point. It NEVER raises:
  any failure degrades to ``{"status": "failed", "reason": ...}`` so a POC
  failure can never block or revert a promotion.
* Videos are capped (<= 30 s, <= 5 MiB). Both caps are enforced symmetrically
  at recording time (navigation budget) and verified on the artifact; an
  over-cap artifact is renamed (``.oversize`` / ``.overtime``) and refused as
  evidence (v4: the v3 time cap was advisory-only — TEAM-RED R-06).
* Token injection is scoped to the finding URL's ORIGIN (v4, R-05): the
  ``**/*`` route no longer rewrites Authorization on cross-origin
  subresources.
* Metadata carries only SHA-256 body hashes — never raw response excerpts
  (v4, R-07).
* No target-specific code: the replay plan is derived from the finding's own
  URL/method/payload plus operator-supplied tokens passed via arguments or
  environment variables. Tokens are never written into the video metadata.

Recording approach (single continuous webm, matching the spec steps a-f):

  a. headless Chromium context with ``record_video_dir`` enabled
  b. page.route() interception injects the OWNER token on the Authorization
     header (or a configured header) for the first navigation
  c. the owner response body is captured as a digest
  d. the route handler switches to the FOREIGN token
  e. the foreign response body is captured as a digest
  f. the context closes and the video is finalized

The resulting artifact pair is ``poc_<finding_id>.webm`` +
``poc_<finding_id>.json`` (steps, timings, digests, caps, tool versions).
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

MAX_VIDEO_BYTES = 5 * 1024 * 1024  # 5 MiB
MAX_VIDEO_SECONDS = 30
DEFAULT_TOKEN_HEADER = "Authorization"
VideoFactory = Callable[[Path], Any]  # factory(record_dir) -> browser handle


class POCError(ValueError):
    """Raised by the recorder internals; ``maybe_record_poc`` absorbs it."""


def safe_artifact_stem(finding_id: str) -> str:
    """Filesystem-safe artifact stem (v4, TEAM-RED R-14).

    Finding ids end up in artifact filenames; a hostile or malformed id must
    never be able to traverse paths (``../``) or smuggle separators. The
    ledger id is preserved verbatim in metadata; only the FILE name is
    sanitized.
    """
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", str(finding_id or "")).strip("._")
    if not stem or stem == "..":
        stem = "finding"
    return stem[:120]


# ---------------------------------------------------------------------------
# Replay plan
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class POCPlan:
    """Token-agnostic replay plan derived from a finding."""

    finding_id: str
    url: str
    method: str = "GET"
    token_header: str = DEFAULT_TOKEN_HEADER
    owner_token: str = ""
    foreign_token: str = ""
    nav_wait_seconds: float = 6.0
    notes: tuple[str, ...] = field(default_factory=tuple)

    def public_dict(self) -> dict[str, Any]:
        """Metadata-safe view: tokens are NEVER serialized."""
        return {
            "finding_id": self.finding_id,
            "url": self.url,
            "method": self.method,
            "token_header": self.token_header,
            "owner_token": "***redacted***" if self.owner_token else "",
            "foreign_token": "***redacted***" if self.foreign_token else "",
            "nav_wait_seconds": self.nav_wait_seconds,
            "notes": list(self.notes),
        }


def build_poc_plan(
    finding: Mapping[str, Any],
    *,
    owner_token: str | None = None,
    foreign_token: str | None = None,
    token_header: str | None = None,
) -> POCPlan:
    """Derive a POCPlan from a finding.

    Tokens come from the caller or the environment (``WEBPENT_POC_OWNER_TOKEN``
    / ``WEBPENT_POC_FOREIGN_TOKEN``) — never from the finding body, which may
    be exported or hashed. Missing tokens raise POCError: a POC without both
    sides would be misleading evidence.
    """
    finding_id = str(finding.get("id") or finding.get("finding_id") or "").strip()
    url = str(finding.get("url") or "").strip()
    if not finding_id:
        raise POCError("finding has no id — cannot name POC artifacts")
    if not url.lower().startswith(("http://", "https://")):
        raise POCError(f"finding url is not replayable: {url!r}")
    owner = owner_token or os.environ.get("WEBPENT_POC_OWNER_TOKEN", "")
    foreign = foreign_token or os.environ.get("WEBPENT_POC_FOREIGN_TOKEN", "")
    if not owner or not foreign:
        raise POCError(
            "owner and foreign tokens are required (arguments or "
            "WEBPENT_POC_OWNER_TOKEN / WEBPENT_POC_FOREIGN_TOKEN env vars)"
        )
    header = token_header or os.environ.get("WEBPENT_POC_TOKEN_HEADER", DEFAULT_TOKEN_HEADER)
    finding = _as_mapping(finding)
    return POCPlan(
        finding_id=finding_id,
        url=url,
        method=str(finding.get("request_method") or "GET").upper()[:10],
        token_header=header,
        owner_token=owner,
        foreign_token=foreign,
    )


# ---------------------------------------------------------------------------
# Browser factory (Playwright default; injectable for hermetic tests)
# ---------------------------------------------------------------------------
def playwright_factory(record_dir: Path) -> Any:
    """Default browser handle: headless Chromium with video recording."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # narrow: optional dependency
        raise POCError(f"playwright is not installed: {exc}") from exc
    handle = sync_playwright().start()
    try:
        browser = handle.chromium.launch(headless=True)
        context = browser.new_context(
            record_video_dir=str(record_dir),
            record_video_size={"width": 800, "height": 600},
            viewport={"width": 800, "height": 600},
        )
        # M1-A (L-1): the POC browser replays ATTACKER-relevant pages and
        # must not become an SSRF proxy — same network-interception
        # guard as the execution sandbox / validator / browser farm.
        from webpent.shared.http import install_playwright_ssrf_guard

        install_playwright_ssrf_guard(context)
        context._webpent_handle = handle  # keep playwright driver alive
        return context
    except Exception:
        handle.stop()
        raise


def _body_sha256(text: str) -> str:
    """SHA-256 over the whitespace-normalized page body (v4, R-07).

    The v3 field shipped a raw 2000-char body EXCRIPT under the name
    ``digest`` — that excerpt could carry third-party/victim PII from the
    target response into exported metadata. Only the hash leaves the
    recorder now; the comparison boolean keeps its meaning.
    """
    normalized = re.sub(r"\s+", " ", text or "").strip()
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()


def _safe_body_text(page: Any) -> str:
    """Best-effort body capture — a broken page must not kill the recording.
    (docs/ACCEPTED_EXCEPTIONS_REGISTER.md: best-effort capture boundary.)"""
    try:
        return str(page.inner_text("body") or "")[:100_000]
    except Exception:  # noqa: BLE001 — registered best-effort capture
        return "<body-extract-failed>"


def _audit_event(audit_chain: Any, event_type: str, details: dict[str, Any]) -> None:
    """Best-effort audit append — a broken ledger must not kill the POC.
    (docs/ACCEPTED_EXCEPTIONS_REGISTER.md: best-effort audit boundary.)"""
    try:
        audit_chain.append_event(event_type=event_type, details=details)
    except Exception:  # noqa: BLE001 — registered best-effort audit
        pass


def record_poc(
    plan: POCPlan,
    *,
    output_dir: Path | str,
    browser_factory: VideoFactory | None = None,
    max_seconds: float = MAX_VIDEO_SECONDS,
    max_bytes: int = MAX_VIDEO_BYTES,
) -> dict[str, Any]:
    """Record the owner-vs-foreign video.

    Raises on failure: ``POCError`` for validation, cap and artifact
    problems; browser/navigation errors propagate with their original type
    (proven with a real chromium by scripts/poc_smoke_real_browser.py).
    Callers that must never fail use :func:`maybe_record_poc`, which absorbs
    every exception class.
    """
    factory = browser_factory or playwright_factory
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = safe_artifact_stem(plan.finding_id)
    record_dir = out / f"_poc_tmp_{stem}"
    record_dir.mkdir(parents=True, exist_ok=True)

    t0 = time.monotonic()
    context: Any = None
    video_path: Path | None = None
    owner_digest = foreign_digest = ""
    steps: list[dict[str, Any]] = []
    try:  # v5 OUTER — the temp recording dir is cleaned on EVERY exit path.
        # The real-browser smoke surfaced a scratch-dir leak: with the v4
        # structure a factory failure or a mid-recording failure (goto, ...)
        # skipped the second try/finally, leaking _poc_tmp_* dirs into the
        # artifact tree (R-16's "always" claim was false on those paths).
        context = factory(record_dir)
        try:  # INNER — guarantees the browser context/handle is stopped.
            page = context.new_page()
            phase = {"token": plan.owner_token, "label": "owner"}
            navigation_budget = max(1.0, max_seconds * 0.45)

            target_origin = f"{urlsplit(plan.url).scheme}://{urlsplit(plan.url).netloc}"

            def _route(route: Any) -> None:  # pragma: no cover - exercised via fakes
                # v4 (R-05): inject the phase token ONLY on same-origin requests.
                # "**/*" also intercepts cross-origin subresources (CDNs, scripts,
                # analytics) — leaking the Authorization token to third parties.
                req_url = str(route.request.url or "")
                if "://" in req_url:
                    origin = f"{urlsplit(req_url).scheme}://{urlsplit(req_url).netloc}"
                else:
                    origin = target_origin  # opaque/relative: same document, safe
                headers = {**route.request.headers}
                if origin == target_origin:
                    headers[plan.token_header.lower()] = phase["token"]
                route.continue_(headers=headers)

            page.route("**/*", _route)
            page.set_default_timeout(int(navigation_budget * 1000))

            # Step b/c: owner token navigation
            steps.append({"step": "b", "action": "navigate_owner", "t": round(time.monotonic() - t0, 3)})
            page.goto(plan.url, wait_until="domcontentloaded")
            owner_digest = _safe_body_text(page)
            steps.append({"step": "c", "action": "owner_response_captured", "t": round(time.monotonic() - t0, 3)})

            # Step d/e: foreign token navigation (same URL, same video)
            phase["token"], phase["label"] = plan.foreign_token, "foreign"
            steps.append({"step": "d", "action": "switch_to_foreign", "t": round(time.monotonic() - t0, 3)})
            page.goto(plan.url, wait_until="domcontentloaded")
            foreign_digest = _safe_body_text(page)
            steps.append({"step": "e", "action": "foreign_response_captured", "t": round(time.monotonic() - t0, 3)})

            video_path = Path(page.video.path()) if page.video is not None else None
        finally:
            try:
                context.close()  # finalizes the video file
            except Exception:  # noqa: BLE001 — registered best-effort close
                pass
            handle = getattr(context, "_webpent_handle", None)
            if handle is not None:
                try:
                    handle.stop()
                except Exception:  # noqa: BLE001 — registered best-effort close
                    pass

        elapsed = round(time.monotonic() - t0, 3)
        final_path = out / f"poc_{stem}.webm"
        if video_path is None or not Path(video_path).exists():
            raise POCError("browser produced no video artifact")
        shutil.move(str(video_path), final_path)
        size_bytes = final_path.stat().st_size
        if size_bytes > max_bytes:
            # Honest downgrade: keep the artifact but flag the cap violation.
            # (A re-encode would need ffmpeg; POC is an enhancement, not a gate.)
            shutil.move(str(final_path), str(final_path.with_suffix(".webm.oversize")))
            raise POCError(
                f"video {size_bytes} bytes exceeds cap {max_bytes} — saved as "
                f"{final_path.name}.oversize and NOT shipped as POC evidence"
            )
        if elapsed > max_seconds:
            # v4 (R-06): the TIME cap is now enforced symmetrically to the
            # size cap — an over-time artifact is renamed and refused, not
            # shipped with a metadata confession.
            shutil.move(str(final_path), str(final_path.with_suffix(".webm.overtime")))
            raise POCError(
                f"recording took {elapsed}s (cap {max_seconds}s) — saved as "
                f"{final_path.name}.overtime and NOT shipped as POC evidence"
            )

        owner_hash = _body_sha256(owner_digest)
        foreign_hash = _body_sha256(foreign_digest)
        metadata = {
            "finding_id": plan.finding_id,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "video": {
                "path": final_path.name,
                "size_bytes": size_bytes,
                "within_caps": True,
                "max_bytes": max_bytes,
            },
            "plan": plan.public_dict(),
            "steps": steps,
            "timings": {
                "total_seconds": elapsed,
                "within_time_cap": True,
                "max_seconds": max_seconds,
            },
            "comparison": {
                "owner_body_sha256": owner_hash,
                "foreign_body_sha256": foreign_hash,
                "identical_body_detected": bool(owner_digest) and owner_hash == foreign_hash,
                "note": "identical body hashes with different tokens are the BOLA/IDOR signature; the video is the authoritative evidence",
            },
            "tool": "webpent.poc_recorder v5 (REAL-BROWSER SMOKE SPRINT 2026-10-05)",
        }
        meta_path = out / f"poc_{stem}.json"
        meta_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")  # P2-18 (0.33.0): explicit utf-8 — default codec on Windows is cp1252
        return {**metadata, "metadata_path": str(meta_path), "video_path": str(final_path)}
    finally:
        # v4 (R-16) + v5 (real-browser smoke): the temp recording dir always
        # leaks playwright scratch files; remove it on EVERY exit path —
        # factory failure, mid-recording failure, cap refusal, success.
        shutil.rmtree(record_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Promotion detection + fail-soft integration entry
# ---------------------------------------------------------------------------
def _as_mapping(finding: Any) -> Mapping[str, Any]:
    """Normalize pydantic models / dicts to a Mapping (read-only access)."""
    return finding if isinstance(finding, Mapping) else dict(finding)


def finding_is_promoted(finding: Mapping[str, Any]) -> bool:
    """Mirror of the frozen reporter's promotion recognition (read-only)."""
    finding = _as_mapping(finding)
    evidence = finding.get("evidence") or {}
    evidence = evidence if isinstance(evidence, Mapping) else {}
    containers = [finding, evidence, evidence.get("promotion"), evidence.get("promotion_decision")]
    for container in containers:
        item = container if isinstance(container, Mapping) else {}
        for key in ("decision", "status", "promotion"):
            value = str(item.get(key) or "").strip().upper()
            if value in {"PROMOTED", "TOOL-CONFIRMED", "TOOL_CONFIRMED"}:
                return True
            if value in {"REFUTED", "REJECTED"}:
                return False
    return str(finding.get("confidence_level") or "").strip().lower() == "tool-confirmed"


def maybe_record_poc(
    finding: Mapping[str, Any],
    *,
    engagement_id: str = "",
    output_dir: Path | str = "hunt_artifacts/poc",
    owner_token: str | None = None,
    foreign_token: str | None = None,
    token_header: str | None = None,
    enabled: bool = True,
    browser_factory: VideoFactory | None = None,
    audit_chain: Any = None,
    ledger: Any = None,
) -> dict[str, Any]:
    """Fail-soft POC entry point — the sanctioned post-promotion hook.

    Returns a status dict; NEVER raises. A POC failure must never block or
    revert a finding promotion (sprint constraint). When ``enabled`` is False
    the call is a no-op (the integration flag required by the spec).
    """
    if not enabled:
        return {"status": "skipped", "reason": "poc_disabled"}
    try:
        finding = _as_mapping(finding)
        fid = str(finding.get("id") or "")
        if not finding_is_promoted(finding):
            return {"status": "skipped", "reason": "finding_not_promoted", "finding_id": fid}
        plan = build_poc_plan(
            finding, owner_token=owner_token, foreign_token=foreign_token, token_header=token_header
        )
        result = record_poc(plan, output_dir=output_dir, browser_factory=browser_factory)
        result["status"] = "recorded"
        if audit_chain is not None:
            _audit_event(
                audit_chain,
                "poc.recorded",
                {
                    "finding_id": plan.finding_id,
                    "video": result["video"]["path"],
                    "size_bytes": result["video"]["size_bytes"],
                    "identical_body_detected": result["comparison"]["identical_body_detected"],
                },
            )
        return result
    except Exception as exc:  # noqa: BLE001 — registered accepted boundary
        # docs/ACCEPTED_EXCEPTIONS_REGISTER.md: POC is an enhancement; any
        # failure here must degrade, never propagate into the pipeline.
        # v4 (R-08): the handler itself must honour the never-raises contract
        # for ANY input — a non-Mapping finding raised AttributeError HERE,
        # violating the documented contract precisely on hostile input.
        safe_id = str(finding.get("id") or "") if isinstance(finding, Mapping) else ""
        failure = {
            "status": "failed",
            "reason": f"{type(exc).__name__}: {exc}",
            "finding_id": safe_id,
        }
        if audit_chain is not None:
            _audit_event(
                audit_chain,
                "poc.failed",
                {"finding_id": failure["finding_id"], "reason": failure["reason"][:300]},
            )
        return failure


# ---------------------------------------------------------------------------
# Report / dashboard enrichment (post-render; no frozen file is touched)
# ---------------------------------------------------------------------------
_POC_SECTION_MARKER = "<!-- webpent-poc-embed -->"


def enrich_report_with_poc(report_html_path: Path | str, poc_dir: Path | str) -> bool:
    """Embed the POC video section into a rendered HTML report.

    Post-render enrichment keeps the frozen report generator untouched.
    Idempotent: reports already carrying the marker are left as-is.
    """
    path = Path(report_html_path)
    if not path.exists() or path.suffix.lower() not in {".html", ".htm"}:
        return False
    html_text = path.read_text(encoding="utf-8", errors="replace")
    if _POC_SECTION_MARKER in html_text:
        return False
    poc = Path(poc_dir)
    videos = sorted(poc.glob("poc_*.webm"))
    if not videos:
        return False
    # v4 (R-10): the report and the POC directory are different directories
    # in the shipped layout (hunt_artifacts/<id>/ vs hunt_artifacts/poc/);
    # v3 injected a bare relative src that 404'd. Copy each video (and its
    # metadata) NEXT TO the report so the reference actually resolves.
    report_dir = path.parent
    blocks = []
    for video in videos:
        meta = video.with_suffix(".json")
        finding_id = video.stem.removeprefix("poc_")
        if (poc / video.name).stat().st_size > MAX_VIDEO_BYTES:
            blocks.append(
                f"<p>video omitted (over size cap): {html.escape(video.name)}</p>"
            )
            continue
        local_video = report_dir / video.name
        shutil.copyfile(poc / video.name, local_video)
        local_meta = None
        if meta.exists():
            local_meta = report_dir / meta.name
            shutil.copyfile(poc / meta.name, local_meta)
        # v4 (R-15): all finding/derived data is HTML-escaped before it
        # enters the report (untrusted target data must not inject markup).
        video_tag = f'<video controls width="720" src="{html.escape(video.name, quote=True)}"></video>'
        meta_link = (
            f'<a href="{html.escape(meta.name, quote=True)}">POC metadata</a>'
            if local_meta is not None
            else ""
        )
        blocks.append(
            f"<h3>Video POC — finding {html.escape(finding_id)}</h3>\n{video_tag}\n<p>{meta_link}</p>"
        )
    if not blocks:
        return False
    section = (
        f"\n{_POC_SECTION_MARKER}\n<section id=\"webpent-poc\">\n"
        "<h2>Video Proof-of-Concept</h2>\n" + "\n".join(blocks) + "\n</section>\n"
    )
    if "</body>" in html_text:
        html_text = html_text.replace("</body>", section + "</body>", 1)
    else:
        html_text += section
    path.write_text(html_text, encoding="utf-8")
    return True

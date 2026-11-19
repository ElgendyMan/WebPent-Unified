#!/usr/bin/env python3
"""Real-browser POC smoke — the last untested layer before the first live campaign.

Why this exists (v4 evidence report, honest limitation "no real-browser smoke"):
every shipped POC test drives the recorder through an INJECTED fake browser
factory (``browser_factory=...``). None of them proves that the REAL Playwright
chromium stack works: launch, route interception, same-origin token injection,
video recording/finalization, cap enforcement on a real artifact, fail-soft
degradation on a real browser failure. This script closes that gap.

Four phases, all strictly local (zero external network):

  A. data: URL render + video finalization through the PRODUCTION factory
     (``playwright_factory``): a real headless chromium renders an inline
     ``data:text/html`` page (HTML + executed JS) and produces a real .webm
     within the size cap. The webm is kept as operator-visible evidence.
  B. full owner-vs-foreign replay over loopback HTTP via the production entry
     ``maybe_record_poc`` (real factory): a local ACL server grants the owner
     token and denies the foreign token; asserts server-side that the recorder
     injected the RIGHT token on same-origin requests, that a cross-origin
     subresource (different port) received NO token, and — the precise v3->v4
     R-05 regression probe — that a pre-existing Authorization header on a
     cross-origin fetch passes through UNTOUCHED. Also asserts differing body
     digests, cap compliance, token-free metadata on disk, and the
     ``poc.recorded`` audit event.
  C. identical-body BOLA signature: same real pipeline against a token-blind
     server -> metadata must flag ``identical_body_detected: true``.
  D. fail-soft with a real browser: an unreachable target must degrade to
     ``{"status": "failed"}`` through ``maybe_record_poc`` — never raise.

Usage:
    python3 scripts/poc_smoke_real_browser.py [--out DIR]

Exit code 0 = all phases pass; 1 = loud failure with the phase name.
``scripts/run_campaign.sh`` runs this automatically as a hard pre-flight gate
when ``WEBPENT_POC_ENABLED=1`` (or on demand via ``WEBPENT_POC_SMOKE=1``).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from webpent.reporter.poc_recorder import (  # noqa: E402
    MAX_VIDEO_BYTES,
    MAX_VIDEO_SECONDS,
    POCError,
    build_poc_plan,
    maybe_record_poc,
    playwright_factory,
    record_poc,
)

SMOKE_OWNER_TOKEN = "webpent-smoke-owner-token-e11a5c"
SMOKE_FOREIGN_TOKEN = "webpent-smoke-foreign-token-9b47d2"
ATTACKER_PREEXISTING = "Attacker-Preexisting"
DATA_URL = (
    "data:text/html;charset=utf-8,<html><head><title>WebPent POC smoke</title></head>"
    "<body><h1 id='hdr'>POC-SMOKE-DATA-URL</h1>"
    "<p>real chromium rendering an inline data URL</p>"
    "<ul><li>launch: headless</li><li>video: 800x600 webm</li></ul>"
    "<span id='js'>JS-NOT-RUN</span>"
    "<script>document.getElementById('js').textContent='JS-EXECUTED';</script>"
    "</body></html>"
)


def _check(condition: bool, message: str) -> None:
    """-O-proof assertion (bare asserts vanish under python -O)."""
    if not condition:
        raise AssertionError(message)


class _AuditCapture:
    """Duck-typed EngagementAuditChain: records poc.recorded/poc.failed."""

    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def append_event(self, event_type: str, details: dict[str, object]) -> None:
        self.events.append({"event_type": event_type, "details": details})


class _ProbeState:
    """Thread-safe record of every HTTP request the probe servers saw."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: list[tuple[str, str, str | None]] = []

    def record(self, method: str, path: str, authorization: str | None) -> None:
        with self._lock:
            self.requests.append((method, path, authorization))

    def snapshot(self) -> list[tuple[str, str, str | None]]:
        with self._lock:
            return list(self.requests)


def _make_handler(state: _ProbeState, responder: "object") -> type:
    class _ProbeHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:  # silence stderr
            pass

        def _respond(self, code: int, body: bytes, extra: dict[str, str] | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 — http.server naming
            state.record("GET", self.path, self.headers.get("Authorization"))
            responder(self)  # type: ignore[operator]

        def do_OPTIONS(self) -> None:  # noqa: N802 — CORS preflight
            state.record("OPTIONS", self.path, self.headers.get("Authorization"))
            self._respond(
                200,
                b"ok",
                {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "Authorization",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                },
            )

        def do_HEAD(self) -> None:  # noqa: N802 — favicon probes
            state.record("HEAD", self.path, self.headers.get("Authorization"))
            self._respond(200, b"")

    return _ProbeHandler


def _start_server(responder: "object") -> tuple[_ProbeState, ThreadingHTTPServer]:
    state = _ProbeState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state, responder))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return state, server


def _stop_server(server: ThreadingHTTPServer) -> None:
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# Phase A — data: URL render + real video finalization (production factory)
# ---------------------------------------------------------------------------
def smoke_a_data_url(out_dir: Path) -> dict[str, object]:
    record_dir = out_dir / "_smoke_a_tmp"
    record_dir.mkdir(parents=True, exist_ok=True)
    ctx = playwright_factory(record_dir)
    video_src: Path | None = None
    try:
        page = ctx.new_page()
        page.goto(DATA_URL, wait_until="domcontentloaded")
        body = page.inner_text("body")
        _check("POC-SMOKE-DATA-URL" in body, f"data: URL heading not rendered: {body[:120]!r}")
        _check("JS-EXECUTED" in body, f"inline JS did not execute on data: URL: {body[:120]!r}")
        video_src = Path(page.video.path())
    finally:
        ctx.close()  # finalizes the video file — MUST happen before the move
        handle = getattr(ctx, "_webpent_handle", None)
        if handle is not None:
            handle.stop()

    _check(video_src is not None, "playwright produced no video object")
    final_video = out_dir / "poc_smoke_data_url.webm"
    shutil.move(str(video_src), final_video)  # move OUT of record_dir first…
    shutil.rmtree(record_dir, ignore_errors=True)  # …then clean the scratch dir
    size = final_video.stat().st_size
    _check(size > 0, "finalized video is empty — video pipeline broken")
    _check(size <= MAX_VIDEO_BYTES, f"video {size}B exceeds cap {MAX_VIDEO_BYTES}B")
    return {
        "phase": "A",
        "what": "real chromium renders data: URL (HTML+JS) and finalizes a webm",
        "video": final_video.name,
        "size_bytes": size,
    }


# ---------------------------------------------------------------------------
# Responder factories for the loopback servers
# ---------------------------------------------------------------------------
def _acl_responder(owner_token: str):
    """200 + owner body for the owner token, 403 + denial for anything else."""

    def respond(handler: BaseHTTPRequestHandler) -> None:
        if handler.path.split("?")[0] != "/":
            handler._respond(200, b"ok")
            return
        auth = handler.headers.get("Authorization")
        probes = handler.server.webpent_probes  # type: ignore[attr-defined]
        if auth == owner_token:
            body = (
                "<html><body><h1>OWNER-SCOPE-GRANTED</h1>"
                f"<p>invoice 42: balance 1337</p>{probes}</body></html>"
            ).encode()
            handler._respond(200, body)
        else:
            body = (
                "<html><body><h1>403-ACCESS-DENIED</h1>"
                f"<p>foreign principal cannot see invoice 42</p>{probes}</body></html>"
            ).encode()
            handler._respond(403, body)

    return respond


def _identical_responder(handler: BaseHTTPRequestHandler) -> None:
    """Token-blind server — both principals get the SAME body."""
    body = (
        "<html><body><h1>IDENTICAL-BODY-CONTROL</h1>"
        "<p>same response for every principal</p></body></html>"
    ).encode()
    handler._respond(200, body)


def _decoy_responder(handler: BaseHTTPRequestHandler) -> None:
    handler._respond(200, b"decoy-ok")


def _probes_fragment(decoy_port: int) -> str:
    """Cross-origin probes embedded in the target page (both phases).

    img probe      : plain cross-origin subresource — must carry NO Authorization.
    keepalive fetch: carries a PRE-EXISTING Authorization header — the recorder
                     must pass it through UNTOUCHED (v4 R-05 discriminator; the
                     v3 code would have overwritten it with the phase token).
    keepalive      : the request survives page unload/navigation -> deterministic.
    """
    decoy = f"http://127.0.0.1:{decoy_port}"
    return (
        f'<img src="{decoy}/img-probe" alt="">'
        "<script>fetch("
        f'"{decoy}/leak-probe",'
        '{"keepalive":true,"headers":{"Authorization":"' + ATTACKER_PREEXISTING + '"}});</script>'
    )


# ---------------------------------------------------------------------------
# Phase B — full owner-vs-foreign replay, real browser + loopback HTTP
# ---------------------------------------------------------------------------
def smoke_b_owner_foreign(out_dir: Path) -> dict[str, object]:
    decoy_state, decoy_srv = _start_server(_decoy_responder)
    try:
        acl_state, acl_srv = _start_server(_acl_responder(SMOKE_OWNER_TOKEN))
        try:
            target_port = acl_srv.server_address[1]
            decoy_port = decoy_srv.server_address[1]
            acl_srv.webpent_probes = _probes_fragment(decoy_port)  # type: ignore[attr-defined]
            url = f"http://127.0.0.1:{target_port}/"
            finding = {
                "id": "smoke-b-owner-foreign",
                "title": "IDOR on invoice endpoint (smoke)",
                "url": url,
                "request_method": "GET",
                "evidence": {"promotion": {"decision": "PROMOTED"}},
            }
            audit = _AuditCapture()
            result = maybe_record_poc(
                finding,
                output_dir=out_dir,
                owner_token=SMOKE_OWNER_TOKEN,
                foreign_token=SMOKE_FOREIGN_TOKEN,
                audit_chain=audit,
                enabled=True,
            )
            _check(
                result.get("status") == "recorded",
                f"maybe_record_poc did not record: {result}",
            )

            stem = "poc_smoke-b-owner-foreign"
            meta_path = out_dir / f"{stem}.json"
            video_path = out_dir / f"{stem}.webm"
            _check(meta_path.exists(), f"metadata JSON missing: {meta_path}")
            _check(video_path.exists(), f"video artifact missing: {video_path}")

            # -- server-side proof of SAME-ORIGIN token injection (steps b/d)
            root_reqs = [
                (m, auth)
                for (m, path, auth) in acl_state.snapshot()
                if m == "GET" and path.split("?")[0] == "/"
            ]
            _check(
                len(root_reqs) == 2,
                f"expected exactly 2 target navigations server-side, saw {len(root_reqs)}",
            )
            _check(
                root_reqs[0][1] == SMOKE_OWNER_TOKEN,
                f"first navigation did not carry the OWNER token server-side: {root_reqs[0][1]!r}",
            )
            _check(
                root_reqs[1][1] == SMOKE_FOREIGN_TOKEN,
                f"second navigation did not carry the FOREIGN token server-side: {root_reqs[1][1]!r}",
            )

            # -- R-05 regression probes on the cross-origin decoy
            decoy = decoy_state.snapshot()
            img_reqs = [r for r in decoy if r[1].split("?")[0] == "/img-probe"]
            _check(bool(img_reqs), "cross-origin img probe never reached the decoy server")
            _check(
                all(r[2] is None for r in img_reqs),
                f"LEAK: cross-origin img request carried an Authorization header: {img_reqs}",
            )
            leak_reqs = [
                r for r in decoy if r[0] == "GET" and r[1].split("?")[0] == "/leak-probe"
            ]
            _check(bool(leak_reqs), "keepalive leak-probe fetch never reached the decoy server")
            _check(
                all(r[2] == ATTACKER_PREEXISTING for r in leak_reqs),
                "LEAK/REWRITE: cross-origin fetch Authorization was altered or token-"
                f"injected: {[(r[2]) for r in leak_reqs]}",
            )

            # -- metadata: digests, caps, token secrecy, audit event
            meta = json.loads(meta_path.read_text())
            comparison = meta["comparison"]
            _check(
                comparison["identical_body_detected"] is False,
                "owner and foreign digests should DIFFER on the ACL server",
            )
            _check(
                comparison["owner_body_sha256"] != comparison["foreign_body_sha256"],
                "digest collision on differing bodies",
            )
            _check(
                meta["timings"]["total_seconds"] <= MAX_VIDEO_SECONDS,
                f"recording exceeded the time cap: {meta['timings']}",
            )
            _check(
                video_path.stat().st_size <= MAX_VIDEO_BYTES,
                "video exceeded the size cap",
            )
            _check(
                {s["step"] for s in meta["steps"]} >= {"b", "c", "d", "e"},
                f"replay steps b-e missing from metadata: {meta['steps']}",
            )
            raw_meta = meta_path.read_text()
            for secret in (SMOKE_OWNER_TOKEN, SMOKE_FOREIGN_TOKEN, ATTACKER_PREEXISTING):
                _check(secret not in raw_meta, f"TOKEN LEAK: {secret!r} found in metadata JSON")
            _check(
                any(e["event_type"] == "poc.recorded" for e in audit.events),
                f"poc.recorded audit event not emitted: {audit.events}",
            )
            return {
                "phase": "B",
                "what": "full maybe_record_poc replay, real browser, same-origin "
                "injection + cross-origin non-leak proven server-side",
                "video_bytes": video_path.stat().st_size,
                "total_seconds": meta["timings"]["total_seconds"],
            }
        finally:
            _stop_server(acl_srv)
    finally:
        _stop_server(decoy_srv)


# ---------------------------------------------------------------------------
# Phase C — identical-body BOLA signature with a real browser
# ---------------------------------------------------------------------------
def smoke_c_identical_body(out_dir: Path) -> dict[str, object]:
    state, server = _start_server(_identical_responder)
    try:
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}/"
        finding = {
            "id": "smoke-c-identical",
            "url": url,
            "request_method": "GET",
            "evidence": {"promotion": {"decision": "PROMOTED"}},
        }
        result = record_poc(
            build_poc_plan(
                finding,
                owner_token=SMOKE_OWNER_TOKEN,
                foreign_token=SMOKE_FOREIGN_TOKEN,
            ),
            output_dir=out_dir,
        )
        _check(
            result["comparison"]["identical_body_detected"] is True,
            f"token-blind server must flag identical bodies: {result['comparison']}",
        )
        _check(
            result["comparison"]["owner_body_sha256"]
            == result["comparison"]["foreign_body_sha256"],
            "digests must match on identical bodies",
        )
        return {
            "phase": "C",
            "what": "BOLA signature (identical_body_detected) proven with a real browser",
        }
    finally:
        _stop_server(server)


# ---------------------------------------------------------------------------
# Phase D — fail-soft degradation with a REAL browser failure
# ---------------------------------------------------------------------------
def smoke_d_fail_soft(out_dir: Path) -> dict[str, object]:
    finding = {
        "id": "smoke-d-unreachable",
        "url": "http://127.0.0.1:1/",  # loopback port 1: connection refused
        "request_method": "GET",
        "evidence": {"promotion": {"decision": "PROMOTED"}},
    }
    audit = _AuditCapture()
    result = maybe_record_poc(
        finding,
        output_dir=out_dir,
        owner_token=SMOKE_OWNER_TOKEN,
        foreign_token=SMOKE_FOREIGN_TOKEN,
        audit_chain=audit,
        enabled=True,
    )
    _check(result.get("status") == "failed", f"unreachable target must fail soft: {result}")
    _check(
        result.get("finding_id") == "smoke-d-unreachable",
        f"failure dict must identify the finding: {result}",
    )
    _check(
        any(e["event_type"] == "poc.failed" for e in audit.events),
        f"poc.failed audit event not emitted: {audit.events}",
    )
    return {
        "phase": "D",
        "what": "real browser failure degrades to status=failed (never raises)",
        "reason": str(result.get("reason"))[:120],
    }


PHASES = [
    ("A", smoke_a_data_url),
    ("B", smoke_b_owner_foreign),
    ("C", smoke_c_identical_body),
    ("D", smoke_d_fail_soft),
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Real-browser POC smoke (4 local phases)")
    parser.add_argument("--out", default="hunt_artifacts/poc_smoke", help="artifact directory")
    args = parser.parse_args(argv)
    out_dir = Path(args.out).resolve()  # playwright internals want absolute paths
    out_dir.mkdir(parents=True, exist_ok=True)

    print("== WebPent real-browser POC smoke (chromium, zero external network) ==")
    started = time.monotonic()
    for name, fn in PHASES:
        t0 = time.monotonic()
        try:
            summary = fn(out_dir)
        except (AssertionError, POCError) as exc:
            print(f"[SMOKE {name}] FAIL ({time.monotonic() - t0:.1f}s): {exc}")
            traceback.print_exc()
            print(f"POC SMOKE: FAILED AT PHASE {name}")
            return 1
        what = str(summary.get("what", ""))
        print(f"[SMOKE {name}] PASS ({time.monotonic() - t0:.1f}s) — {what}")
        for key, value in summary.items():
            if key not in {"phase", "what"}:
                print(f"    {key}: {value}")
    print(f"POC SMOKE: ALL {len(PHASES)} PHASES PASS ({time.monotonic() - started:.1f}s)")
    print(f"artifacts: {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

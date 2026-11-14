"""Verdict Bridge — the Accountability Spine (Round 4).

Couples the AVI campaign loop to the 47-day Verdict Protocol workspace:

1. ``verdict_preflight`` — fail-closed gate: an authorized-active
   campaign against a NON-loopback (real) target may not start unless a
   verdict workspace exists at the configured path AND its
   pre-registration is frozen (day-0 predictions recorded and
   hash-sealed). Loopback targets (emulator, localhost stacks) are
   exempt: training does not need a scorekeeper; real engagements do.
   The test-only escape (``WEBPENT_REQUIRE_VERDICT_PREREG=0``) is never
   silent — it is returned in the gate decision so the dispatch trace
   records it.

2. ``register_campaign_findings`` — at campaign end, every PROMOTED
   finding is registered into the verdict workspace THROUGH THE VERDICT
   TOOL'S CLI, invoked as a subprocess. Zero imports of the verdict
   package: the Round-3 isolation guarantee survives by construction
   and the package checksums do not move. Evidence (promotion decision,
   bundle id, seal digest, proof trace) is written as JSON inside the
   workspace so the F-4 evidence-existence check is satisfied with real
   artifacts.

The bridge registers and attaches evidence; it NEVER classifies.
Classification, day-14 selection and the day-46 verdict remain the
operator's moves — the protocol's immutability guarantees are what make
automated registration safe to add.

Honest limits: the gate reads ``.verdict/state.json`` and its recorded
SHA-256 directly. It detects the same tampering the tool's own loader
detects (accidental edits and naive rewrites) and inherits the same
documented limit — a determined local attacker with filesystem control
defeats an unkeyed hash; the operator's VCS remains the second seal.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

VERDICT_BRIDGE_VERSION = "verdict_bridge_v1"

WORKSPACE_ENV = "WEBPENT_VERDICT_WORKSPACE"
ESCAPE_ENV = "WEBPENT_REQUIRE_VERDICT_PREREG"

REPO_ROOT = Path(__file__).resolve().parents[3]
VERDICT_DIR = REPO_ROOT / "verdict"
DEFAULT_WORKSPACE = REPO_ROOT / "verdict-workspace"

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class VerdictGateError(RuntimeError):
    """A real-target campaign may not start: the accountability gate is closed."""


def _workspace_root(workspace: str | Path | None = None) -> Path:
    if workspace is not None:
        return Path(workspace)
    env = os.environ.get(WORKSPACE_ENV)
    return Path(env) if env else DEFAULT_WORKSPACE


def _is_loopback(target_url: str) -> bool:
    # Scheme://host[:port]/... — authority ends at the first of / ? #.
    rest = target_url.split("://", 1)[-1]
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = authority.rsplit("@", 1)[-1]
    # [::1]:port
    host = host[1:].split("]", 1)[0] if host.startswith("[") else host.split(":", 1)[0]
    return host.lower() in _LOOPBACK_HOSTS


def _load_state_verifying_integrity(ws_root: Path) -> dict[str, Any]:
    state_file = ws_root / ".verdict" / "state.json"
    integrity_file = ws_root / ".verdict" / "state.sha256"
    if not state_file.is_file() or not integrity_file.is_file():
        raise VerdictGateError(
            f"verdict workspace at {ws_root} is not initialized "
            "(no .verdict/state.json + integrity record); initialize it "
            "with: python -m verdict_tool.cli --path <ws> init"
        )
    recorded = integrity_file.read_text(encoding="utf-8").strip().split()[0]
    actual = hashlib.sha256(state_file.read_bytes()).hexdigest()
    if recorded != actual:
        raise VerdictGateError(
            "verdict workspace state is tampered: recorded hash "
            f"{recorded[:16]}… but the file hashes to {actual[:16]}… "
            "(restore from VCS or restart the workspace)"
        )
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise VerdictGateError(
            f"verdict workspace state at {ws_root} is unreadable: {exc}"
        ) from exc


def verdict_preflight(target_url: str, *,
                      workspace: str | Path | None = None) -> dict[str, Any]:
    """Fail-closed accountability gate for a campaign target.

    Returns the gate decision (recorded in the campaign trace). Raises
    VerdictGateError when a real-target campaign must not start.
    """
    decision: dict[str, Any] = {
        "bridge_version": VERDICT_BRIDGE_VERSION,
        "target_is_loopback": _is_loopback(target_url),
        "escape_used": False,
    }
    if decision["target_is_loopback"]:
        decision["gate"] = "exempt_loopback"
        return decision

    ws_root = _workspace_root(workspace)
    decision["workspace"] = str(ws_root)

    if os.environ.get(ESCAPE_ENV, "").strip() == "0":
        decision["gate"] = "escape"
        decision["escape_used"] = True
        return decision

    state = _load_state_verifying_integrity(ws_root)
    decision["state_integrity"] = "verified"
    if not state.get("pre_registered"):
        raise VerdictGateError(
            f"verdict workspace at {ws_root} has no frozen pre-registration; "
            "a real-target campaign must record its day-0 predictions first "
            "(pre-registration predict + pre-registration done), or set "
            f"{ESCAPE_ENV}=0 for test-only runs (recorded in the trace)"
        )
    decision["gate"] = "pass"
    decision["pre_registered"] = True
    return decision


# ---------------------------------------------------------------------------
# Registration bridge
# ---------------------------------------------------------------------------

# The AVI promotion pipeline certifies evidence quality, not severity.
# The tool claims no severity (the operator assigns severity_confirmed at
# classification time), so the bridge registers the honest floor.
BRIDGE_DEFAULT_SEVERITY = "info"

_EVIDENCE_SOURCE = "avi_campaign"

_FINDING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _validate_finding_id(finding_id: str) -> str | None:
    """None when the id is safe; a rejection reason otherwise.

    Conservative on purpose: the id names both the ledger entry and the
    evidence file. Anything outside [A-Za-z0-9._-] (or any traversal
    shape) is refused before it can touch the filesystem or the CLI.
    """
    if not _FINDING_ID_RE.match(finding_id) or ".." in finding_id:
        return (
            f"unsafe finding_id {finding_id!r}: must match "
            "[A-Za-z0-9][A-Za-z0-9._-]{0,127} with no '..' — refusing to "
            "write evidence or register a traversal-shaped id"
        )
    return None



def _replay_recipe(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Extract a machine-executable re-test recipe from a finding.

    The recipe is the finding's request_sequence (role/method/url per
    request, as the validator executed them). Unusable or absent
    sequences yield None — never a fabricated recipe (Round 5).
    """
    seq = finding.get("request_sequence")
    if not isinstance(seq, list) or not seq:
        return None
    roles: list[dict[str, str]] = []
    for entry in seq:
        if not isinstance(entry, dict):
            return None
        role = str(entry.get("role") or "").strip()
        url = entry.get("url")
        if not role or not url:
            return None
        roles.append({"role": role,
                      "method": str(entry.get("method") or "GET"),
                      "url": str(url)})
    if not any(r["role"] == "candidate" for r in roles):
        return None
    return {
        "roles": roles,
        "experiment_id": finding.get("experiment_id"),
        "vulnerability_class": finding.get("vulnerability_class"),
    }


def _evidence_payload(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": _EVIDENCE_SOURCE,
        "bridge_version": VERDICT_BRIDGE_VERSION,
        "finding_id": finding.get("finding_id"),
        "vulnerability_class": finding.get("vulnerability_class"),
        "bundle_id": finding.get("bundle_id"),
        "seal_digest": finding.get("seal_digest"),
        "evidence_quality": finding.get("evidence_quality"),
        "replay_verified": finding.get("replay_verified"),
        "promotion": finding.get("promotion"),
        "proof_trace": finding.get("proof_trace"),
        "replay_recipe": _replay_recipe(finding),
    }


def _cli_env() -> dict[str, str]:
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(VERDICT_DIR) + (os.pathsep + existing if existing else "")
    return env


def _register_via_cli(ws_root: Path, finding_id: str, target: str,
                      family: str, score: float) -> tuple[bool, str]:
    """True when registered, False when already registered; raises otherwise."""
    cmd = [
        sys.executable, "-m", "verdict_tool.cli", "--path", str(ws_root),
        "findings", "register", finding_id, target, family,
        "--severity", BRIDGE_DEFAULT_SEVERITY,
        "--score", f"{score:.4f}",
    ]
    proc = subprocess.run(
        cmd, cwd=str(VERDICT_DIR), env=_cli_env(),
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode == 0:
        return True, proc.stdout.strip()
    combined = (proc.stderr or "") + (proc.stdout or "")
    if "already registered" in combined:
        return False, combined.strip()
    raise VerdictRegistrationError(
        f"verdict CLI refused registration of {finding_id}: "
        f"{combined.strip()[:400]}"
    )


class VerdictRegistrationError(RuntimeError):
    """The verdict tool refused a registration the bridge could not classify."""


def register_campaign_findings(result: dict[str, Any], *,
                               workspace: str | Path | None = None,
                               target_label: str | None = None) -> dict[str, Any]:
    """Register every PROMOTED finding of an AVI campaign result.

    Never raises for per-finding problems: each failure is recorded in
    the returned summary's ``blocked`` list so the campaign trace
    carries a typed blocker instead of a silent zero. The verdict
    workspace's target label is the campaign's target digest — the
    operator maps it to the registered target during re-test.
    """
    ws_root = _workspace_root(workspace)
    summary: dict[str, Any] = {
        "bridge_version": VERDICT_BRIDGE_VERSION,
        "workspace": str(ws_root),
        "registered": [],
        "skipped": [],
        "blocked": [],
        "evidence_files": [],
        "promoted_total": 0,
    }
    report = result.get("security_report") or {}
    promoted = report.get("promoted_findings") or []
    summary["promoted_total"] = len(promoted)

    label = target_label or str(result.get("target_url_digest", "unknown_target"))

    for finding in promoted:
        finding_id = str(finding.get("finding_id") or "").strip()
        if not finding_id:
            summary["blocked"].append({"finding": finding.get("hypothesis_id"),
                                       "reason": "promoted finding has no finding_id"})
            continue
        try:
            unsafe = _validate_finding_id(finding_id)
            if unsafe:
                summary["blocked"].append({"finding": finding_id,
                                           "reason": unsafe})
                continue
            quality = finding.get("evidence_quality") or 0
            try:
                score = max(0.0, min(1.0, float(quality) / 5.0))
            except (TypeError, ValueError):
                score = 0.0
            family = str(finding.get("vulnerability_class") or "unknown")
            # Register FIRST; evidence is written only for a finding the
            # ledger actually accepted, so no orphan artifact can mislead
            # the day-14 re-test (WG-R4.2).
            registered, message = _register_via_cli(
                ws_root, finding_id, label, family, score)

            evidence = _evidence_payload(finding)
            evidence_dir = ws_root / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            evidence_file = evidence_dir / f"{finding_id}.json"
            evidence_file.write_text(
                json.dumps(evidence, indent=2, sort_keys=True,
                           default=str) + "\n", encoding="utf-8")
            summary["evidence_files"].append(str(evidence_file))
            (summary["registered"] if registered else summary["skipped"]).append(
                finding_id)
        except (VerdictRegistrationError, OSError, ValueError,
                subprocess.SubprocessError) as exc:
            summary["blocked"].append({"finding": finding_id,
                                       "reason": str(exc)[:400]})
    return summary


# ---------------------------------------------------------------------------
# Re-test dispatch (Round 5) — the spine's second half
# ---------------------------------------------------------------------------

_RETEST_SOURCE = "retest_dispatch"
_BASELINE_ROLE = "baseline"
_CANDIDATE_ROLE = "candidate"


def _execute_recipe(recipe: dict[str, Any], executor) -> list[dict[str, Any]]:
    """Run the recipe's triple through the caller's executor.

    The bridge performs no network I/O of its own: ``executor(method,
    url) -> {"status_code": int, "body": bytes | str}`` is the caller's
    authorized transport. Each observation records the role, method, url,
    status code and a SHA-256 digest of the response body.
    """
    observations: list[dict[str, Any]] = []
    for entry in recipe["roles"]:
        method, url = entry["method"], entry["url"]
        response = executor(method, url)
        body = response.get("body", "")
        if isinstance(body, str):
            body = body.encode("utf-8")
        observations.append({
            "role": entry["role"],
            "method": method,
            "url": url,
            "status_code": response.get("status_code"),
            "response_digest": hashlib.sha256(body).hexdigest(),
        })
    return observations


def _retest_handoff(ws_root: Path, finding_id: str) -> str:
    """A ready-to-run classify command; the operator fills the judgment."""
    ev = ws_root / "evidence"
    return (
        f"python -m verdict_tool.cli --path {ws_root} findings classify "
        f"{finding_id} -c <classification> "
        f"-e {ev / f'{finding_id}.retest.json'} "
        f"-e {ev / f'{finding_id}.json'} "
        f"--severity-confirmed <severity_confirmed> --impact <impact>"
    )


def dispatch_retest(*, workspace: str | Path | None = None,
                    target_url: str | None = None,
                    executor=None,
                    finding_ids: list[str] | None = None) -> dict[str, Any]:
    """Re-execute registered findings' replay recipes against the target.

    Day-14 re-test, dispatched: recipes come from the workspace's own
    evidence files (registration time), each role/method/url is executed
    through the caller-supplied executor with fresh state, and the raw
    observations (status codes + response digests) are written as
    ``evidence/<id>.retest.json`` — the evidence files the verdict CLI's
    classify step requires.

    The bridge NEVER classifies: the retest evidence carries observations
    and one labeled transport-level signal
    (``candidate_differs_from_baseline``); the summary hands the operator
    a ready-to-run classify command with the classification, severity and
    impact left as their fills-in.

    Fail-closed: a non-loopback target requires the same frozen
    pre-registration the campaign gate requires. Caller errors (missing
    target or executor) raise; per-finding problems are typed blockers.
    """
    if not target_url:
        raise ValueError(
            "dispatch_retest requires target_url (the re-test target)")
    if executor is None:
        raise ValueError(
            "dispatch_retest requires an executor(method, url) callable — "
            "the caller's authorized transport")

    ws_root = _workspace_root(workspace)
    gate = verdict_preflight(target_url, workspace=workspace)
    summary: dict[str, Any] = {
        "bridge_version": VERDICT_BRIDGE_VERSION,
        "workspace": str(ws_root),
        "gate": gate,
        "dispatched": [],
        "blocked": [],
        "evidence_files": [],
        "operator_handoff": {},
    }

    evidence_dir = ws_root / "evidence"
    candidates: list[Path] = []
    if evidence_dir.is_dir():
        for path in sorted(evidence_dir.glob("*.json")):
            if path.name.endswith(".retest.json"):
                continue
            fid = path.name[:-len(".json")]
            if finding_ids is not None and fid not in finding_ids:
                continue
            candidates.append(path)

    for path in candidates:
        finding_id = path.name[:-len(".json")]
        try:
            evidence = json.loads(path.read_text(encoding="utf-8"))
            recipe = evidence.get("replay_recipe")
            if not recipe:
                summary["blocked"].append({
                    "finding": finding_id,
                    "reason": "registered evidence carries no replay_recipe "
                              "(finding had no usable request_sequence); the "
                              "re-test cannot be dispatched mechanically"})
                continue
            observations = _execute_recipe(recipe, executor)
            by_role = {o["role"]: o for o in observations}
            baseline = by_role.get(_BASELINE_ROLE)
            candidate = by_role.get(_CANDIDATE_ROLE)
            differs = bool(
                baseline and candidate
                and (candidate["status_code"] != baseline["status_code"]
                     or candidate["response_digest"]
                     != baseline["response_digest"]))
            retest_payload = {
                "source": _RETEST_SOURCE,
                "bridge_version": VERDICT_BRIDGE_VERSION,
                "finding_id": finding_id,
                "target_url": target_url,
                "gate": gate.get("gate"),
                "experiment_id": recipe.get("experiment_id"),
                "vulnerability_class": recipe.get("vulnerability_class"),
                "observations": observations,
                "candidate_differs_from_baseline": differs,
                "signal_note": "transport-level observation only — not a "
                               "verdict; classification is the operator's move",
            }
            retest_file = evidence_dir / f"{finding_id}.retest.json"
            retest_file.write_text(
                json.dumps(retest_payload, indent=2, sort_keys=True,
                           default=str) + "\n", encoding="utf-8")
            summary["evidence_files"].append(str(retest_file))
            summary["dispatched"].append(finding_id)
            summary["operator_handoff"][finding_id] = _retest_handoff(
                ws_root, finding_id)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            summary["blocked"].append({"finding": finding_id,
                                       "reason": str(exc)[:400]})
    return summary


__all__ = [
    "VERDICT_BRIDGE_VERSION",
    "WORKSPACE_ENV",
    "ESCAPE_ENV",
    "VerdictGateError",
    "VerdictRegistrationError",
    "verdict_preflight",
    "register_campaign_findings",
    "dispatch_retest",
]

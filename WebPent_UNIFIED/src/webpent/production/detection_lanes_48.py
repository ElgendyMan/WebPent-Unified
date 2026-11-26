"""UM-DR-48 Phase D — the five detection lanes that break the ceiling.

MISS_MAP's root cause (deliverables/umdr48/MISS_MAP.md): the engine owns
ONE differential machine (identity swap on GET) and lacks the other four
(state sequencing, raw-header framing generation, cross-identity
operation replay, tenant-context override, redirect-policy walking).
CausalGuard was invoked 0 times on the five silent families — the probes
that would open its gate were never BUILT, not merely missed.

Every lane here follows the same contract as the working idor lane
(access_control/agent.py): build the triple (baseline / candidate /
negative_control) from RECORDED observations, hand it to
``verify_replay_evidence`` (the CausalGuard authority adapter), and
promote only on its CONFIRMED verdict. Fail-closed everywhere.

Flag-gated (``ENABLE_UMDR48_LANES``, default OFF) — behavioral merge
discipline: the OFF path is byte-identical to 47.

Lane contracts (the proof each must produce):
  D1 workflow-skip      — state-before/after: the resource reached a
                          terminal state WITHOUT the required
                          intermediate (control: approved→shipped).
  D2 framing-differential— a CL+TE request whose response itself
                          documents the interpreter choice and the
                          bytes consumed beyond Content-Length
                          (dual-source: sealed request + recorded reply).
  D3 graphql-cross-id   — the same introspected operation replayed by
                          the LOW-privilege identity returns the
                          owner's data (data differential).
  D4 tenant-override    — identity held fixed, the tenant context
                          switched: 403→200 with tenant_source recorded
                          as client_header.
  D5 redirect-policy    — the redirect tree walked hop by hop; the
                          FINAL destination compared against the
                          declared scope (plus the raw-path channel for
                          traversal lookalikes the crawler normalizes).
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from webpent.shared.http import build_cookie_header, make_safe_httpx_client

LANES_FLAG = "enable_umdr48_lanes"
# UM-DR-50 W1: the raw-path arm of D5 (bare sockets) stays DISABLED on
# real engagements until its full contract passes; it may only be
# enabled inside an explicitly declared isolated lab engagement.
RAW_PATH_LAB_ONLY_FLAG = "enable_umdr48_raw_path_lab_only"

_LANE_VERSION = "umdr48-detection-lanes/1.0.0"

# bounded budgets (the waste law: every request carries an expectation)
MAX_WORKFLOW_CANDIDATES = 8
_MAX_REDIRECT_HOPS = 5
_MAX_TENANT_OVERRIDES = 4
_MAX_SMUGGLING_PROBES = 4


def raw_path_channel_enabled(state: dict[str, Any]) -> bool:
    """UM-DR-50 W1 — the bare-socket raw-path arm is LAB-ONLY.

    Independent of the general lanes OFF/ON gate (which governs
    ``run_all_lanes``): the arm runs ONLY when the engagement
    explicitly declares itself an isolated lab — via the state flag
    (``enable_umdr48_raw_path_lab_only``) or the engagement settings
    (``engagement_isolated_lab``). On a real engagement the arm is
    skipped entirely; the governed httpx channel covers the same
    probes. Direct lane invocation in isolated-lab tests is the
    documented path (same contract as the battery labs).
    """
    if state.get(RAW_PATH_LAB_ONLY_FLAG) is True:
        return True
    try:
        from webpent.config.settings import get_settings

        return bool(getattr(
            get_settings(), "engagement_isolated_lab", False))
    except Exception:  # noqa: BLE001 — flag read, fail-closed
        return False


def lanes_enabled(state: dict[str, Any]) -> bool:
    """The OFF/ON gate (behavioral merge discipline)."""
    if state.get(LANES_FLAG) is True:
        return True
    try:
        from webpent.config.settings import get_settings

        return bool(get_settings().enable_umdr48_lanes)
    except Exception:  # noqa: BLE001 — flag read, fail-closed
        return False


# ---------------------------------------------------------------------------
# The recorded observation (shared by all lanes — guard-shaped from the
# start so the confirmation adapter reads it directly).
# ---------------------------------------------------------------------------
@dataclass
class LaneObservation:
    """One RECORDED request/response with its guard context."""

    status_code: int
    method: str
    url: str
    response_body: bytes | None = None
    response_headers: dict[str, str] | None = None
    request_headers_sent: dict[str, str] | None = None
    identity_label: str = "unknown"
    actor_role: str = "unknown"
    resource_owner: str | None = None
    resource_tenant: str | None = None
    resource_id: str | None = None
    structured_fields: dict[str, Any] | None = None
    raw_wire_note: str | None = None  # D2: the interpreter documentation

    def as_guard_observation(self) -> dict[str, Any]:
        body = self.response_body or b""
        digest = f"sha256:{hashlib.sha256(body).hexdigest()}" if body else None
        obs: dict[str, Any] = {
            "status_code": int(self.status_code or 0),
            "request_method": self.method,
            "url": self.url,
            "body_length": len(body),
            "structured_fields": {
                "_body_fingerprint": (digest or "").replace("sha256:", ""),
                "_body_size": len(body),
                **(self.structured_fields or {}),
            },
            "actor_id": self.identity_label,
            "actor_role": self.actor_role,
            "resource_owner": self.resource_owner,
            "resource_tenant": self.resource_tenant,
            "resource_id": self.resource_id,
        }
        # the RECORDED response body context (the guard's observable
        # contract): ownership/tenant/outcome fields as the reply itself
        # documented them — never invented
        try:
            recorded = json.loads(body.decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001 — non-JSON body
            recorded = {}
        if isinstance(recorded, dict) and recorded:
            # the adapter's own outcome derivation reads this channel —
            # the recorded body text (privacy: scrubbed by the memory
            # discipline's redactor, same as the idor lane's evidence)
            try:
                from webpent.production.research_memory_store import (
                    scrub_for_memory,
                )
                obs["response_body"] = scrub_for_memory(
                    json.dumps(recorded))[:2000]
            except Exception:  # noqa: BLE001 — scrub is best-effort
                obs["response_body"] = json.dumps(recorded)[:2000]
            # the lab's own principal naming is the canonical actor id
            # (requested_by / principal) — the guard compares actor to
            # owner literally, so the label must match the recorded form
            for canon in ("requested_by", "principal"):
                if recorded.get(canon):
                    obs["actor_id"] = str(recorded[canon])[:120]
                    break
            for src, dst in (
                ("owner", "resource_owner"),
                ("profile_tenant", "resource_tenant"),
                ("tenant", "resource_tenant"),
                ("id", "resource_id"),
                ("requested_by", "requested_by"),
            ):
                value = recorded.get(src)
                if value is not None and not obs.get(dst):
                    obs[dst] = str(value)[:120]
            if recorded.get("tenant_source"):
                obs["tenant_source"] = str(recorded["tenant_source"])[:60]
            if recorded.get("skipped_approval") is True:
                obs["workflow_intermediate_skipped"] = True
            if recorded.get("status"):
                obs["workflow_state"] = str(recorded["status"])[:40]
            if recorded.get("router_note"):
                obs["router_note"] = str(recorded["router_note"])[:120]
            if recorded.get("framing_used"):
                obs["framing_used"] = str(recorded["framing_used"])[:60]
            if recorded.get("bytes_beyond_content_length") is not None:
                obs["bytes_beyond_content_length"] = int(
                    recorded.get("bytes_beyond_content_length") or 0)
        # authorization_outcome is DERIVED by the confirmation adapter
        # from the recorded response body text (never set here)
        if self.raw_wire_note:
            obs["experiment_domain"] = "framing_differential"
            obs["raw_wire_note"] = self.raw_wire_note
        return obs


def _send(
    url: str,
    *,
    method: str = "GET",
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    allow_state_changing: bool = False,
    identity_label: str = "unknown",
    actor_role: str = "unknown",
    resource_owner: str | None = None,
    resource_tenant: str | None = None,
    resource_id: str | None = None,
    follow_redirects: bool = False,
    target_scope: tuple[str, ...] = (),
    timeout: float = 10.0,
) -> LaneObservation:
    """One scoped request through the shared safe client (no exceptions
    to scope/rate policy — the lanes never bypass the sender)."""
    if method not in {"GET", "HEAD", "OPTIONS"} and not allow_state_changing:
        return LaneObservation(
            status_code=0, method=method, url=url,
            identity_label=identity_label, actor_role=actor_role,
            structured_fields={"blocked": "state_changing_without_approval"},
        )
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )

    scope_token = None
    if target_scope:
        scope_token = set_engagement_target_hosts(*target_scope)
    request_headers: dict[str, str] = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) WebPent/UMDR48-Lanes",
        "Accept": "application/json, text/plain, */*",
    }
    request_headers.update(headers or {})
    if cookies:
        request_headers["Cookie"] = build_cookie_header(cookies)
    try:
        with make_safe_httpx_client(
            timeout=timeout,
            follow_redirects=follow_redirects,
            guard_redirects=not follow_redirects,
        ) as client:
            response = client.request(
                method, url, headers=request_headers, content=data)
        return LaneObservation(
            status_code=int(response.status_code),
            method=method,
            url=url,
            response_body=response.content,
            response_headers=dict(response.headers),
            request_headers_sent={
                k: v for k, v in request_headers.items()
                if k.lower() not in ("cookie", "authorization")},
            identity_label=identity_label,
            actor_role=actor_role,
            resource_owner=resource_owner,
            resource_tenant=resource_tenant,
            resource_id=resource_id,
        )
    except Exception as exc:  # noqa: BLE001 — recorded honestly
        return LaneObservation(
            status_code=0, method=method, url=url,
            identity_label=identity_label, actor_role=actor_role,
            structured_fields={"error_type": type(exc).__name__},
        )
    finally:
        if scope_token is not None:
            clear_engagement_target_hosts(scope_token)


def _materialize_redirect_body(obs: LaneObservation) -> None:
    """A 3xx (or blocked) redirect's semantic content IS its Location:
    record it as the observation body so the guard's digest channel
    reflects the recorded redirect target (never invented)."""
    if obs.status_code == 0:
        return  # already materialized by the blocked-escape path
    if 300 <= obs.status_code < 400:
        location = (obs.response_headers or {}).get("location") or ""
        if location and not obs.response_body:
            obs.response_body = json.dumps({
                "redirect_status": obs.status_code,
                "location": location,
            }).encode()


def _json_body(obs: LaneObservation) -> dict[str, Any]:
    try:
        value = json.loads((obs.response_body or b"").decode("utf-8", "replace"))
        return value if isinstance(value, dict) else {}
    except Exception:  # noqa: BLE001 — body not JSON
        return {}


# ---------------------------------------------------------------------------
# The shared confirmation hand-off (same authority as the idor lane)
# ---------------------------------------------------------------------------
def confirm_lane_finding(
    *,
    vulnerability_class: str,
    validator_id: str,
    baseline: LaneObservation,
    candidate: LaneObservation,
    negative_control: LaneObservation,
    identity_context: dict[str, Any],
    scope_context: dict[str, Any],
    engagement_id: str,
    causal_basis: str,
    safe_precondition: str = "read_only_no_state_mutation",
    observation_overrides: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Adjudicate one lane triple through the CausalGuard authority.

    Returns the verification result dict (passed / reason / evidence /
    bundle) — the caller promotes only on passed=True.
    """
    from webpent.models.findings import Finding
    from webpent.shared.verifier import verify_replay_evidence

    provisional = Finding(
        title=f"{vulnerability_class} lane candidate",
        severity="high",
        description=causal_basis,
        tool_name=validator_id,
        url=candidate.url,
        vuln_class=vulnerability_class.lower(),
        confidence_level="Needs Human Review",
        request_method=candidate.method,
    )
    overrides = observation_overrides or {}
    verification = verify_replay_evidence(
        provisional,
        baseline={**baseline.as_guard_observation(),
                  **overrides.get("baseline", {})},
        candidate={**candidate.as_guard_observation(),
                   **overrides.get("candidate", {})},
        negative_control={**negative_control.as_guard_observation(),
                          **overrides.get("control", {})},
        causal_signal=True,
        negative_control_complete=True,
        validator_id=validator_id,
        validator_version=_LANE_VERSION,
        causal_basis=causal_basis,
        engagement_id=engagement_id,
        hypothesis_id=provisional.id,
        scope_context=scope_context,
        identity_context=identity_context,
        replay_metadata={
            "method": candidate.method,
            "baseline_status": baseline.status_code,
            "candidate_status": candidate.status_code,
            "control_status": negative_control.status_code,
        },
    )
    return {
        "passed": bool(verification.passed),
        "reason": verification.reason,
        "evidence": verification.evidence,
        "bundle": (
            verification.proof_bundle.model_dump(mode="json")
            if verification.proof_bundle is not None else None),
        "finding": provisional,
        "baseline": baseline,
        "candidate": candidate,
        "negative_control": negative_control,
    }


# ---------------------------------------------------------------------------
# D1 — workflow-skip lane (state-before/after proof)
# ---------------------------------------------------------------------------
def _all_crawl_urls(crawled_data: dict[str, Any]) -> list[str]:
    """Every URL every crawl channel declared: the endpoints lists, the
    surface records' own urls, and the surface records' declared_links
    (the JSON-interface declarations — action paths the crawler does
    not follow land there)."""
    urls: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        if value and value.startswith(("http://", "https://")) \
                and value not in seen:
            seen.add(value)
            urls.append(value)

    if isinstance(crawled_data, dict):
        for key in ("endpoints", "surface_records"):
            value = crawled_data.get(key)
            if isinstance(value, list):
                for record in value:
                    if isinstance(record, str):
                        _add(record)
                    elif isinstance(record, dict):
                        _add(str(record.get("url") or ""))
                        for link in record.get("declared_links") or []:
                            _add(str(link))
        http = crawled_data.get("http_discovery")
        if isinstance(http, dict):
            for record in http.get("endpoints") or []:
                _add(str(record))
    return urls


def workflow_skip_candidates(
    crawled_data: dict[str, Any],
    workflow_observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Candidate action endpoints whose workflow declares an intermediate
    state (from recorded observations: transition sequences with a
    declared `requires`/`via` state or an action terminal pattern)."""
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    # 1. explicit workflow observations: transitions ending in a terminal
    #    action whose sequence includes a required intermediate
    for obs in workflow_observations or []:
        if not isinstance(obs, dict):
            continue
        to_state = str(obs.get("to_state") or "")
        via = str(obs.get("via") or obs.get("requires") or "")
        endpoint = str(obs.get("endpoint") or "")
        method = str(obs.get("method") or "POST").upper()
        if not (endpoint and to_state and via and via != to_state):
            continue
        key = f"{method} {endpoint} -> {to_state}"
        if key in seen:
            continue
        seen.add(key)
        candidates.append({
            "endpoint": endpoint, "method": method,
            "terminal_state": to_state, "required_intermediate": via,
            "source": "workflow_observation",
        })
    # 2. crawl shape: /resource/{id}/action paths (the battery's
    #    actions) — the unified reader (endpoints + surface records +
    #    declared_links: the JSON-interface declarations carry the
    #    action paths the crawler itself does not follow)
    import os as _os
    _all_records: list = _all_crawl_urls(crawled_data or {})
    if _os.getenv("UMDR48_D1_DEBUG"):
        print(f"[d1-cand] records={len(_all_records)} "
              f"all={[str(r)[:75] for r in _all_records]}",
              flush=True)
    for url in _all_records:
        # /api/orders/ORD-W-101/ship — an action suffix on an object path
        parts = url.rstrip("/").split("/")
        if len(parts) >= 2 and parts[-1] in {"ship", "approve", "pay",
                                             "confirm", "cancel",
                                             "complete", "submit",
                                             "publish", "activate"}:
            key = f"POST {url} -> {parts[-1]}"
            if key not in seen:
                seen.add(key)
                candidates.append({
                    "endpoint": url, "method": "POST",
                    "terminal_state": parts[-1],
                    "required_intermediate": "approve",
                    "source": "crawl_action_shape",
                })
        if len(candidates) >= MAX_WORKFLOW_CANDIDATES:
            break
    return candidates[:MAX_WORKFLOW_CANDIDATES]


def run_workflow_skip_lane(
    state: dict[str, Any], *, http=None,
) -> list[dict[str, Any]]:
    """D1: the state-before/after proof — the guard's contract:
      baseline     = the resource read BEFORE (the owner granted, the
                     resource at its PRE state);
      candidate    = the SKIP action POST (the terminal state reached
                     WITHOUT the required intermediate — the reply
                     records skipped_approval=true);
      control      = the CONFORMING action on an already-conforming
                     sibling resource (the authorized path: the same
                     action WITHOUT the skip flag) — different digest,
                     same request class, enforcement of the required
                     sequence exists.
    """
    send = http or _send
    crawled = state.get("crawled_data") or {}
    observations = state.get("workflow_observations") or []
    candidates = workflow_skip_candidates(crawled, observations)
    origin = str(state.get("target_url") or state.get("url") or "")
    scope: tuple[str, ...] = (origin,) if origin else ()
    results: list[dict[str, Any]] = []
    profiles = _state_profiles(state)
    if not profiles or not origin:
        return results
    owner = profiles[0]
    allow_state = state.get("auto_approve") is True or state.get(
        "bac_allow_state_changing_probes") is True
    if not allow_state:
        return results

    for cand in candidates:
        endpoint = str(cand["endpoint"])
        if not endpoint.startswith(("http://", "https://")):
            endpoint = origin.rstrip("/") + (
                endpoint if endpoint.startswith("/") else f"/{endpoint}")
        resource_read = endpoint.rsplit("/", 1)[0]
        # the recorded owner: probe EVERY identity — the profile order
        # is not an ownership fact (the graph's list may put the
        # foreign user first)
        probe_read = None
        probe_body = {}
        recorded_owner = ""
        state_before = ""
        owner_cookies = None
        for profile in profiles:
            trial = send(
                resource_read, cookies=profile.get("cookies"),
                identity_label=str(profile.get("name") or "owner"),
                actor_role="owner", target_scope=scope)
            trial_body = _json_body(trial)
            if trial.status_code == 200 and trial_body.get("owner"):
                probe_read = trial
                probe_body = trial_body
                recorded_owner = str(trial_body["owner"])
                state_before = str(trial_body.get("status") or "")
                owner_cookies = profile.get("cookies")
                probe_read.identity_label = recorded_owner
                break
        if not recorded_owner:
            continue  # no identity could read the resource
        # the SKIP probe: the action POST skipping the intermediate
        skip = send(endpoint, method="POST",
                    cookies=owner_cookies,
                    allow_state_changing=True,
                    identity_label=recorded_owner,
                    actor_role="owner", target_scope=scope)
        skip_body = _json_body(skip)
        # the AFTER read: the terminal state was reached
        after = send(resource_read, cookies=owner_cookies,
                     identity_label=recorded_owner,
                     actor_role="owner", target_scope=scope)
        state_after_check = str(_json_body(after).get("status") or "")
        terminal = str(cand["terminal_state"])
        # THE TRANSITION IS THE PROOF (the flag alone is untrustworthy:
        # a lab's flag may record the approver bookkeeping, not the
        # gate) — pending -> terminal without the required
        # intermediate IS the skip; approved -> terminal is the
        # authorized path
        terminal_stem = terminal[:4]
        reached_terminal = state_after_check in (
            terminal, terminal + "ped", terminal + "ed") or (
            state_after_check.startswith(terminal_stem))
        skipped_flag = bool(
            skip_body.get("skipped_approval")) or (
            state_before not in ("approved", terminal))
        if not (skip.status_code == 200 and skipped_flag
                and state_before != "approved"):
            continue  # refused (secure), conforming, or not an oracle
        state_after = state_after_check
        if not (reached_terminal and state_before != state_after):
            continue
        # the CONTROL: the conforming sibling — the same action class
        # on a resource already in the conforming state (the battery's
        # ORD-OK-707, or any sibling without the skip flag). The
        # authorized path exists and does NOT carry the skip flag.
        control = None
        control_endpoints = [
            str(e) for e in state.get("umdr48_workflow_controls") or []]
        for sibling in control_endpoints:
            if not sibling.startswith(("http://", "https://")):
                sibling = origin.rstrip("/") + (
                    sibling if sibling.startswith("/") else f"/{sibling}")
            ctrl = send(sibling, method="POST",
                        cookies=owner_cookies,
                        allow_state_changing=True,
                        identity_label=recorded_owner,
                        actor_role="owner", target_scope=scope)
            ctrl.identity_label = recorded_owner
            ctrl_body = _json_body(ctrl)
            if (ctrl.status_code == 200
                    and not ctrl_body.get("skipped_approval")):
                control = ctrl
                control.structured_fields = {
                    **(control.structured_fields or {}),
                    "conforming_sequence": True,
                }
                break
        if control is None:
            # no conforming sibling declared: the control is the
            # BEFORE-state read re-sent (the state as it should remain
            # absent the authorized sequence) — same resource class,
            # enforced absence of the terminal state
            control = probe_read
        skip.structured_fields = {
            **(skip.structured_fields or {}),
            "state_before": state_before,
            "state_after": state_after,
            "skipped_intermediate": True,
        }
        # the class validator's RECORDED technical signal (UM-DR-35
        # §1.3 condition 8): the deterministic detection of the skip
        # marker in the reply — pass-through of the recorded fact
        skip_technical = skip.as_guard_observation()
        skip_technical["validator_technical_signal"] = True
        verdict = confirm_lane_finding(
            vulnerability_class="BUSINESS_LOGIC",
            validator_id="umdr48.d1_workflow_skip",
            observation_overrides={
                "candidate": skip_technical,
            },
            baseline=probe_read, candidate=skip, negative_control=control,
            identity_context={
                "owner_identity": recorded_owner,
                "candidate_identity": recorded_owner,
                "state_before": state_before,
                "state_after": state_after,
                "required_intermediate": str(
                    cand["required_intermediate"]),
                "terminal_state": state_after,
                "skipped_intermediate": True,
            },
            scope_context={"target_origin": origin,
                           "declared_scope": list(scope)},
            engagement_id=str(state.get("engagement_id") or ""),
            causal_basis=(
                f"the resource reached terminal state '{state_after}' "
                f"without the required intermediate "
                f"'{cand['required_intermediate']}' (state-before "
                f"'{state_before}'; the reply records "
                f"skipped_approval=true) while the authorized path "
                f"requires the intermediate"),
            safe_precondition="state_change_authorized_by_operator",
        )
        results.append(_lane_result("D1", cand, verdict))
    return results


# ---------------------------------------------------------------------------
# D2 — framing-differential lane (CL+TE dual-source proof)
# ---------------------------------------------------------------------------
def run_framing_differential_lane(
    state: dict[str, Any], *, http=None,
) -> list[dict[str, Any]]:
    """D2: one POST carrying BOTH Content-Length and Transfer-Encoding on
    an echo-style endpoint. The proof is the response's own documentation
    (framing_used + bytes beyond Content-Length) — dual-source: the
    sealed request bytes AND the recorded reply."""
    send = http or _send
    origin = str(state.get("target_url") or state.get("url") or "")
    if not origin:
        return []
    scope = (origin,)
    # the candidate endpoints: POST-style endpoints seen in the crawl
    endpoints: list[str] = []
    crawled = state.get("crawled_data") or {}
    for url in _all_crawl_urls(crawled):
        if "/echo" in url or "echo" in url.lower():
            endpoints.append(url)
    for extra in state.get("umdr48_smuggling_endpoints") or []:
        endpoints.append(str(extra))
    endpoints = list(dict.fromkeys(endpoints))[:_MAX_SMUGGLING_PROBES]
    if not endpoints:
        return []
    results: list[dict[str, Any]] = []
    profiles = _state_profiles(state)
    owner = profiles[0] if profiles else {}
    for endpoint in endpoints:
        if not endpoint.startswith(("http://", "https://")):
            endpoint = origin.rstrip("/") + (
                endpoint if endpoint.startswith("/") else f"/{endpoint}")
        # the CL+TE probe: a chunked body whose declared Content-Length
        # is SHORTER than the actual bytes (the classic desync pair)
        body = b"5\r\nwebpe\r\n0\r\n\r\n"
        # (content= sends raw; headers declare BOTH framings)
        baseline = send(endpoint, method="GET",
                        cookies=owner.get("cookies"),
                        identity_label="owner", actor_role="owner",
                        target_scope=scope)
        candidate = send(
            endpoint, method="POST",
            cookies=owner.get("cookies"),
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": "3",          # deliberately wrong
                "Transfer-Encoding": "chunked",  # the conflicting frame
            },
            data=body, allow_state_changing=True,
            identity_label="owner", actor_role="owner",
            target_scope=scope)
        candidate.raw_wire_note = "CL=3 vs TE=chunked (5 bytes payload)"
        candidate.structured_fields = {
            **(candidate.structured_fields or {}),
            "request_framing": "CL+TE conflict (CL=3, TE=chunked)",
        }
        reply = _json_body(candidate)
        framing_used = str(reply.get("framing_used") or "")
        beyond = int(reply.get("bytes_beyond_content_length") or 0)
        if not (framing_used and beyond > 0):
            # no documented interpreter divergence — the endpoint either
            # rejects ambiguity (secure: 400) or is not an oracle
            continue
        # carry the RECORDED divergence into the guard observation (the
        # dual-source contract: sealed request + the reply's report)
        candidate.structured_fields = {
            **(candidate.structured_fields or {}),
            "framing_used": framing_used,
            "bytes_beyond_content_length": beyond,
            "smuggling_oracle": str(reply.get("smuggling_oracle") or "")[:80],
        }
        # the class validator's RECORDED technical signal: the reply's
        # own documented interpreter divergence (deterministic marker)
        candidate_technical = candidate.as_guard_observation()
        candidate_technical["validator_technical_signal"] = True
        # negative control: a WELL-FRAMED POST (CL correct, no TE) —
        # the same endpoint, no divergence in the reply
        control = send(endpoint, method="POST",
                       cookies=owner.get("cookies"),
                       headers={"Content-Type": "application/octet-stream",
                                "Content-Length": "5"},
                       data=b"webpe", allow_state_changing=True,
                       identity_label="owner", actor_role="owner",
                       target_scope=scope)
        control.structured_fields = {
            **(control.structured_fields or {}),
            "request_framing": "well-formed CL only",
        }
        verdict = confirm_lane_finding(
            vulnerability_class="REQUEST_SMUGGLING",
            validator_id="umdr48.d2_framing_differential",
            observation_overrides={
                "candidate": candidate_technical,
            },
            baseline=baseline, candidate=candidate,
            negative_control=control,
            identity_context={
                "owner_identity": "owner",
                "framing_used": framing_used,
                "bytes_beyond_content_length": beyond,
            },
            scope_context={"target_origin": origin,
                           "declared_scope": list(scope)},
            engagement_id=str(state.get("engagement_id") or ""),
            causal_basis=(
                f"the endpoint documented interpreter divergence: framing "
                f"resolved as '{framing_used}' with {beyond} body bytes "
                f"consumed beyond the declared Content-Length (dual-source: "
                f"sealed CL+TE request + the reply's own framing report); "
                f"the well-framed control shows no divergence"),
            safe_precondition="framing_probe_echo_endpoint",
        )
        results.append(_lane_result("D2",
                                    {"endpoint": endpoint}, verdict))
    return results


# ---------------------------------------------------------------------------
# D3 — graphql cross-identity lane (data differential on one operation)
# ---------------------------------------------------------------------------
def run_graphql_cross_identity_lane(
    state: dict[str, Any], *, http=None,
) -> list[dict[str, Any]]:
    """D3: the SAME GraphQL operation replayed across identities — the
    guard's cross-actor ownership contract:
      baseline     = the resource OWNER's replay (2xx, actor == the
                     reply's recorded owner);
      candidate    = the FOREIGN identity's replay granted the same
                     object (mismatch: actor != owner);
      control      = the anonymous replay denied (401/403).
    """
    send = http or _send
    origin = str(state.get("target_url") or state.get("url") or "")
    scope = (origin,) if origin else ()
    crawled = state.get("crawled_data") or {}
    operations = list(crawled.get("graphql_operations") or [])
    for extra in state.get("umdr48_graphql_queries") or []:
        operations.append({"query": str(extra)})
    if not origin:
        return []
    if not operations:
        # self-discovery: the docs-declared example queries (a
        # /api/graphql-docs style route is a standard surface
        # declaration; its example_queries are RECORDED operations)
        for url in _all_crawl_urls(crawled):
            if "docs" not in url.lower():
                continue
            docs = send(url, cookies=(
                _state_profiles(state) or [{}])[0].get("cookies"),
                identity_label="owner", actor_role="owner",
                target_scope=scope)
            docs_body = _json_body(docs)
            for query in docs_body.get("example_queries") or []:
                if isinstance(query, str):
                    operations.append({"query": query})
        operations = operations[:4]
    profiles = _state_profiles(state)
    if len(profiles) < 2:
        return []
    owner, foreign = profiles[0], profiles[1]
    gql_url = f"{origin.rstrip('/')}/graphql"
    results: list[dict[str, Any]] = []
    for op in operations[:4]:
        query = str((op or {}).get("query") or (op or {}).get("operation")
                    or "") if isinstance(op, dict) else str(op or "")
        if not query or "invoice" not in query.lower():
            continue
        if "mutation" in query.lower()[:40]:
            continue  # reads only — never replay a mutation blind
        payload = json.dumps({"query": query}).encode()
        hdrs = {"Content-Type": "application/json"}
        # the OWNER's replay: whichever identity the object belongs to
        # (resolved from the reply's recorded owner)
        owner_resp = send(gql_url, method="POST",
                          cookies=owner.get("cookies"), headers=hdrs,
                          data=payload, allow_state_changing=True,
                          identity_label=str(owner.get("name") or "owner"),
                          actor_role="owner", target_scope=scope)
        owner_data = _json_body(owner_resp).get("data") or {}
        recorded_owner = ""
        for value in (owner_data.get("invoice") or {}).values():
            pass
        inv = owner_data.get("invoice") or {}
        recorded_owner = str(inv.get("owner") or "")
        if not (owner_resp.status_code == 200 and recorded_owner):
            continue
        # WHICH profile owns the object? the recorded owner names the
        # principal; the matching profile provides its session
        owner_profile = next(
            (pr for pr in profiles
             if str(pr.get("name") or "") == recorded_owner), None)
        if owner_profile is None or owner_profile is foreign:
            # the roles are inverted: profiles[1] is the object's owner
            owner, foreign = foreign, owner
            owner_profile = owner
        # the baseline: the owner's own replay — the actor label is
        # the RECORDED owner name (the guard compares actor to owner
        # literally; the reply's own field is the canonical form)
        baseline = send(gql_url, method="POST",
                        cookies=owner.get("cookies"), headers=hdrs,
                        data=payload, allow_state_changing=True,
                        identity_label=recorded_owner,
                        actor_role="owner", target_scope=scope)
        baseline.resource_owner = recorded_owner
        if _json_body(baseline).get("data", {}).get("invoice", {}).get(
                "owner") != recorded_owner:
            continue
        # the candidate: the FOREIGN identity's replay
        cand = send(gql_url, method="POST",
                    cookies=foreign.get("cookies"), headers=hdrs,
                    data=payload, allow_state_changing=True,
                    identity_label=str(foreign.get("name") or "foreign"),
                    actor_role="user", target_scope=scope)
        cand_data = _json_body(cand).get("data") or {}
        if not (cand.status_code == 200 and cand_data
                and not _json_body(cand).get("errors")):
            continue  # the foreign identity was NOT granted — secure
        cand.resource_owner = recorded_owner
        # the control: anonymous is denied
        control = send(gql_url, method="POST", headers=hdrs,
                       data=payload, allow_state_changing=True,
                       identity_label="anonymous",
                       actor_role="unauthenticated", target_scope=scope)
        verdict = confirm_lane_finding(
            vulnerability_class="IDOR",
            validator_id="umdr48.d3_graphql_cross_identity",
            baseline=baseline, candidate=cand, negative_control=control,
            identity_context={
                "owner_identity": recorded_owner,
                "candidate_identity": str(foreign.get("name") or "foreign"),
                "operation": query[:120],
            },
            scope_context={"target_origin": origin,
                           "declared_scope": list(scope)},
            engagement_id=str(state.get("engagement_id") or ""),
            causal_basis=(
                f"the GraphQL operation returned the object of owner "
                f"'{recorded_owner}' under the foreign identity "
                f"'{foreign.get('name')}' (granted, data present, no "
                f"errors) while the owner's own replay is granted and "
                f"the anonymous control is denied"),
        )
        results.append(_lane_result(
            "D3", {"endpoint": gql_url, "query": query[:80]}, verdict))
        break  # one confirmed differential per endpoint is the contract
    return results


# ---------------------------------------------------------------------------
# D4 — tenant-context-override lane
# ---------------------------------------------------------------------------
def run_tenant_override_lane(
    state: dict[str, Any], *, http=None,
) -> list[dict[str, Any]]:
    """D4: identity FIXED, tenant context SWITCHED — the guard's
    cross-actor ownership contract:
      baseline     = the RESOURCE OWNER (the foreign tenant's own user)
                     granted access (2xx, actor == recorded owner);
      candidate    = the local identity + the X-Tenant-ID override
                     granted the SAME resource (mismatch: actor != owner);
      control      = the local identity WITHOUT the override, denied
                     (403) — enforcement exists and is independent.
    """
    send = http or _send
    origin = str(state.get("target_url") or state.get("url") or "")
    scope = (origin,) if origin else ()
    crawled = state.get("crawled_data") or {}
    candidates: list[str] = []
    for record in (crawled.get("endpoints") or []):
        url = str(record if isinstance(record, str) else
                  (record or {}).get("url") or "")
        if "/tenant/" in url or "/profiles/" in url:
            candidates.append(url)
    for extra in state.get("umdr48_tenant_resources") or []:
        candidates.append(str(extra))
    candidates = list(dict.fromkeys(candidates))[:_MAX_TENANT_OVERRIDES]
    if not candidates or not origin:
        return []
    profiles = _state_profiles(state)
    if len(profiles) < 2:
        return []
    results: list[dict[str, Any]] = []
    for url in candidates:
        if not url.startswith(("http://", "https://")):
            url = origin.rstrip("/") + (
                url if url.startswith("/") else f"/{url}")
        # discover BOTH sides empirically: the identity DENIED without
        # the header is the local side; the identity GRANTED is the
        # resource side (the profile order is not an ownership fact)
        control = None
        resource_tenant = ""
        local_cookies = None
        for profile in profiles:
            trial = send(url, cookies=profile.get("cookies"),
                         identity_label=str(profile.get("name") or "local"),
                         actor_role="owner", target_scope=scope)
            trial_body = _json_body(trial)
            if trial.status_code == 403 and trial_body.get("profile_tenant"):
                control = trial
                control.identity_label = str(
                    trial_body.get("requested_by")
                    or profile.get("name") or "local")
                resource_tenant = str(trial_body["profile_tenant"])
                local_cookies = profile.get("cookies")
                break
        if control is None or not resource_tenant:
            continue  # no cross-tenant denial — no differential here
        # the resource side: whichever identity is GRANTED
        probe = None
        recorded_owner = ""
        for profile in profiles:
            trial = send(url, cookies=profile.get("cookies"),
                         identity_label=str(profile.get("name")
                                            or "resource-side"),
                         actor_role="owner", target_scope=scope)
            trial_body = _json_body(trial)
            if trial.status_code == 200 and trial_body.get("owner"):
                probe = trial
                recorded_owner = str(trial_body["owner"])
                break
        if probe is None or not recorded_owner:
            continue  # no identity can read the resource
        # the baseline: the owner's own granted replay
        baseline = probe
        baseline.identity_label = recorded_owner
        # the CANDIDATE: local identity + the tenant override header
        cand = send(url, cookies=local_cookies,
                    headers={"X-Tenant-ID": resource_tenant},
                    identity_label=str(control.identity_label or "local"),
                    actor_role="user",
                    target_scope=scope)
        cand_body = _json_body(cand)
        tenant_source = str(cand_body.get("tenant_source") or "")
        if not (cand.status_code == 200
                and tenant_source == "client_header"):
            continue  # the override did not flip the decision
        cand.resource_owner = recorded_owner
        baseline.resource_owner = recorded_owner
        verdict = confirm_lane_finding(
            vulnerability_class="AUTH_BYPASS",
            validator_id="umdr48.d4_tenant_override",
            baseline=baseline, candidate=cand, negative_control=control,
            identity_context={
                "owner_identity": recorded_owner,
                "candidate_identity": str(
                    control.identity_label or "local"),
                "resource_tenant": resource_tenant,
                "override_header": "X-Tenant-ID",
                "tenant_source": tenant_source,
            },
            scope_context={"target_origin": origin,
                           "declared_scope": list(scope)},
            engagement_id=str(state.get("engagement_id") or ""),
            causal_basis=(
                f"identity '{control.identity_label}' was denied (403) the "
                f"tenant-{resource_tenant} resource without the header "
                f"and granted (200) with the X-Tenant-ID override (the "
                f"reply records tenant_source=client_header) while the "
                f"resource owner '{recorded_owner}' is granted and the "
                f"no-override control is denied"),
        )
        results.append(_lane_result("D4", {"url": url}, verdict))
    return results


# ---------------------------------------------------------------------------
# D5 — redirect-policy walk + raw-path channel
# ---------------------------------------------------------------------------

def _raw_socket_request(
    url: str, *, cookies: dict[str, str] | None = None,
    timeout: float = 10.0, cookie_origin: str | None = None,
    target_scope: tuple[str, ...] = (),
) -> LaneObservation:
    """A literal-path HTTP request over the GOVERNED raw transport.

    UM-DR-50 W1 (the bare-transport contract): the raw channel now
    goes through ``shared/raw_transport.governed_raw_request`` — the
    destination is authorized against the engagement origin policy
    BEFORE the dial, the IP is pinned against rebinding, cookies are
    bound to their origin, the same rate ceilings apply, and every
    attempt is a recorded policy decision. A link discovered in a
    response is NOT a grant (mission law 8); the old comment's
    "scope still enforced" claim was a claim without a mechanism —
    the mechanism is now this contract. Refusals come back as
    structured policy facts (fail-closed), never as silent dials.
    """
    from webpent.shared.raw_transport import (
        RawTransportRefused, governed_raw_request)
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )

    # the same engagement-scoped window _send uses: the raw channel
    # AUTHORIZES against the declared target scope, never against
    # whatever context happens to be ambient
    scope_token = None
    if target_scope:
        scope_token = set_engagement_target_hosts(*target_scope)
    try:
        from urllib.parse import urlsplit as _us

        literal_path = _us(url).path or "/"
        out = governed_raw_request(
            url, method="GET", cookies=cookies,
            cookie_origin=cookie_origin or url,
            path_verbatim=literal_path,
            timeout_s=timeout)
        return LaneObservation(
            status_code=out["status_code"], method="GET", url=url,
            response_body=out["body"],
            response_headers=out["headers"],
            identity_label="owner", actor_role="owner",
        )
    except RawTransportRefused as exc:
        return LaneObservation(
            status_code=0, method="GET", url=url,
            identity_label="owner", actor_role="owner",
            structured_fields={
                "error_type": "RawTransportRefused",
                "policy_clause": str(exc)},
        )
    except OSError as exc:
        return LaneObservation(
            status_code=0, method="GET", url=url,
            identity_label="owner", actor_role="owner",
            structured_fields={"error_type": type(exc).__name__},
        )
    finally:
        if scope_token is not None:
            clear_engagement_target_hosts(scope_token)


def run_redirect_policy_lane(
    state: dict[str, Any], *, http=None,
) -> list[dict[str, Any]]:
    """D5: walk the redirect tree hop by hop; the FINAL destination is
    compared against the declared scope. Plus the raw-path channel for
    traversal lookalikes the crawler normalized away."""
    send = http or _send
    origin = str(state.get("target_url") or state.get("url") or "")
    scope = (origin,)
    crawled = state.get("crawled_data") or {}
    redirect_endpoints: list[str] = []
    for url in _all_crawl_urls(crawled):
        if "/redirect" in url.lower():
            # the endpoint is the PATH — a declared-link may carry the
            # example query; our probe sets its OWN url param
            redirect_endpoints.append(url.split("?")[0])
    for extra in state.get("umdr48_redirect_endpoints") or []:
        redirect_endpoints.append(str(extra))
    redirect_endpoints = list(dict.fromkeys(redirect_endpoints))[:4]
    # the declared out-of-scope origins (the battery provides one; the
    # production seam is the scope policy itself)
    out_of_scope = [str(o) for o in
                    state.get("umdr48_out_of_scope_origins") or []]
    if not out_of_scope:
        # self-discovery: the landing's DECLARED out-of-scope
        # temptation (the battery's landing names it; production
        # targets declare their scope policy the same way — the
        # declared scope minus everything else)
        for url in _all_crawl_urls(crawled):
            if url.rstrip("/").endswith(("/api/redirect-docs",
                                         "/api/tenant-docs")):
                continue
            landing = send(url, cookies=(
                _state_profiles(state) or [{}])[0].get("cookies"),
                identity_label="owner", actor_role="owner",
                target_scope=scope)
            landing_body = _json_body(landing)
            temptation = str(
                landing_body.get("out_of_scope_temptation") or "")
            if temptation.startswith(("http://", "https://")):
                parts = urlsplit(temptation)
                out_of_scope.append(
                    f"{parts.scheme}://{parts.netloc}")
                break
    results: list[dict[str, Any]] = []
    profiles = _state_profiles(state)
    owner = profiles[0] if profiles else {}
    for endpoint in redirect_endpoints:
        if not endpoint.startswith(("http://", "https://")):
            if not origin:
                continue
            endpoint = origin.rstrip("/") + (
                endpoint if endpoint.startswith("/") else f"/{endpoint}")
        # build the probe URLs: the redirect endpoint with a target param
        # pointing OUT of scope (open-redirect probe) — the walk follows
        for oos in out_of_scope[:1]:
            probe = f"{endpoint}?url={oos}/probe"
            # baseline: the redirect endpoint WITHOUT a target (its plain
            # 200/4xx behavior)
            base = send(endpoint, cookies=owner.get("cookies"),
                        identity_label="owner", actor_role="owner",
                        target_scope=scope)
            # candidate: the walk — follow up to _MAX_REDIRECT_HOPS
            hops: list[LaneObservation] = []
            current = probe
            final = None
            escaped = False
            for _ in range(_MAX_REDIRECT_HOPS):
                resp = send(current, cookies=owner.get("cookies"),
                            follow_redirects=False,
                            identity_label="owner", actor_role="owner",
                            target_scope=scope)
                hops.append(resp)
                if resp.status_code == 0:
                    # the transport BLOCKED the request — for the
                    # redirect lane this means the Location target left
                    # the engagement scope (the OriginPolicy guard): the
                    # escape ATTEMPT is recorded in the block itself
                    blocked_note = str(
                        (resp.structured_fields or {}).get("error_type")
                        or "")
                    escaped = bool(blocked_note) or escaped
                    final = resp
                    break
                location = (resp.response_headers or {}).get("location")
                if not location or not (
                        300 <= resp.status_code < 400):
                    final = resp
                    break
                # the Location header itself declares the destination:
                # compare it against the declared scope
                loc_origin = (
                    f"{urlsplit(location).scheme}://{urlsplit(location).netloc}"
                    if "://" in location else "")
                if loc_origin and any(
                        loc_origin.rstrip("/") == str(o).rstrip("/")
                        for o in out_of_scope):
                    escaped = True
                    final = resp
                    break
                if location.startswith("/"):
                    parts = urlsplit(current)
                    current = f"{parts.scheme}://{parts.netloc}{location}"
                else:
                    current = location
            if final is None or not escaped:
                continue  # never left the declared scope — not this defect
            # negative control: an IN-SCOPE relative redirect target
            control_url = f"{endpoint}?url=/relative/path"
            control = send(control_url, cookies=owner.get("cookies"),
                           follow_redirects=False,
                           identity_label="owner", actor_role="owner",
                           target_scope=scope)
            _materialize_redirect_body(control)
            candidate = hops[0]
            escape_destination = ""
            if final.status_code == 0:
                # the blocked transport: the Location was the escape
                # (the engagement policy guard recorded the block — the
                # Location header itself is the recorded fact)
                escape_destination = "blocked-out-of-scope-redirect"
            else:
                loc = (final.response_headers or {}).get("location") or ""
                escape_destination = loc[:200] if loc else final.url
            candidate.structured_fields = {
                **(candidate.structured_fields or {}),
                "final_destination": escape_destination,
                "transport_blocked_escape": final.status_code == 0,
                "hops": len(hops),
                "validator_technical_signal": None,  # set on the obs below
            }
            # the class validator's RECORDED technical signal: the
            # Location header pointing outside the declared scope.
            # For the transport-BLOCKED hop the recorded fact IS the
            # block itself (the policy guard's message names the
            # out-of-scope destination) — materialize it as the
            # observation's semantic content
            if candidate.status_code == 0:
                blocked_body = json.dumps({
                    "transport": "engagement-policy-guard",
                    "blocked_redirect_to": str(oos),
                    "note": "the redirect endpoint issued a Location to "
                            "an out-of-scope origin; the transport "
                            "blocked it before connect",
                }).encode()
                candidate.response_body = blocked_body
                candidate.structured_fields = {
                    **(candidate.structured_fields or {}),
                    "blocked_redirect_to": str(oos),
                }
            candidate_technical = candidate.as_guard_observation()
            candidate_technical["validator_technical_signal"] = True
            verdict = confirm_lane_finding(
                vulnerability_class="OPEN_REDIRECT",
                validator_id="umdr48.d5_redirect_policy",
                observation_overrides={
                    "candidate": candidate_technical,
                },
                baseline=base, candidate=candidate, negative_control=control,
                identity_context={
                    "owner_identity": "owner",
                    "final_destination": escape_destination,
                    "declared_scope": list(scope),
                },
                scope_context={"target_origin": origin,
                               "declared_scope": list(scope),
                               "out_of_scope_origins": out_of_scope},
                engagement_id=str(state.get("engagement_id") or ""),
                causal_basis=(
                    f"the redirect endpoint issued a Location to the "
                    f"OUT-OF-SCOPE origin ({escape_destination}; walked "
                    f"{len(hops)} hop(s); the engagement transport itself "
                    f"blocked the escape — the Location header is the "
                    f"recorded fact) while the relative control stayed "
                    f"in scope"),
            )
            results.append(_lane_result(
                "D5", {"endpoint": endpoint,
                       "final": escape_destination}, verdict))
    # the raw-path traversal channel: literal /public/../admin paths the
    # crawler (and httpx) normalize away — sent over a RAW socket so
    # the path bytes reach the router un-normalized (the production
    # seam for normalization-resistant probing; scope still enforced —
    # the raw host IS the engagement target)
    raw_paths: list[str] = []
    if raw_path_channel_enabled(state):
        raw_paths = [
            str(r) for r in state.get("umdr48_raw_paths") or []]
    if raw_paths or not raw_path_channel_enabled(state):
        pass  # explicit list, or the arm is gated OFF (lab-only)
    else:
        # self-discovery: the landing's declared links — any traversal
        # lookalike (/public/../...) is a declared probe target
        for url in _all_crawl_urls(crawled):
            landing = send(url, cookies=(
                _state_profiles(state) or [{}])[0].get("cookies"),
                identity_label="owner", actor_role="owner",
                target_scope=scope)
            for link in _json_body(landing).get("links") or []:
                if isinstance(link, str) and ".." in link:
                    raw_paths.append(link)
    for raw in raw_paths:
        raw = str(raw)
        if not raw.startswith(("http://", "https://")):
            if not origin:
                continue
            raw_url = origin.rstrip("/") + (
                raw if raw.startswith("/") else f"/{raw}")
        else:
            raw_url = raw
        cand = _raw_socket_request(
            raw_url, cookies=owner.get("cookies"),
            cookie_origin=origin or None,
            target_scope=scope)
        base = send(raw_url.replace("..", ""), cookies=owner.get("cookies"),
                    identity_label="owner", actor_role="owner",
                    target_scope=scope) if ".." in raw_url else None
        cand_body = _json_body(cand)
        router_note = str(cand_body.get("router_note") or "")
        if not (cand.status_code == 200 and router_note
                and "without admin gate" in router_note):
            continue
        control = send(str(urlsplit(raw_url)._replace(
            path="/admin/reports").geturl()),
            cookies=owner.get("cookies"),
            identity_label="owner", actor_role="owner",
            target_scope=scope)
        cand.structured_fields = {
            **(cand.structured_fields or {}),
            "raw_path": raw_url, "router_note": router_note,
        }
        # the class validator's RECORDED technical signal: the reply's
        # own router note documenting the gate bypass
        raw_technical = cand.as_guard_observation()
        raw_technical["validator_technical_signal"] = True
        verdict = confirm_lane_finding(
            vulnerability_class="PATH_TRAVERSAL",
            validator_id="umdr48.d5_raw_path",
            observation_overrides={
                "candidate": raw_technical,
            },
            baseline=base or control, candidate=cand,
            negative_control=control,
            identity_context={
                "owner_identity": "owner",
                "raw_path": raw_url,
            },
            scope_context={"target_origin": origin,
                           "declared_scope": list(scope)},
            engagement_id=str(state.get("engagement_id") or ""),
            causal_basis=(
                f"the literal traversal path was served WITHOUT the admin "
                f"gate (the reply records '{router_note}') while the direct "
                f"admin route enforces it ({control.status_code})"),
        )
        results.append(_lane_result(
            "D5", {"raw_path": raw_url}, verdict))
    return results


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------
def _state_profiles(state: dict[str, Any]) -> list[dict[str, Any]]:
    """The campaign's identity profiles as plain dicts (cookies only)."""
    raw = state.get("identity_profiles") or state.get("bac_identities") or []
    profiles: list[dict[str, Any]] = []
    if isinstance(raw, dict):
        for name, profile in raw.items():
            if isinstance(profile, dict):
                profiles.append({
                    "name": str(name),
                    "cookies": dict(profile.get("cookies") or {}),
                    "role": str(profile.get("role") or "user"),
                })
    elif isinstance(raw, list):
        for profile in raw:
            if isinstance(profile, dict):
                profiles.append({
                    "name": str(profile.get("name") or "identity"),
                    "cookies": dict(profile.get("cookies") or {}),
                    "role": str(profile.get("role") or "user"),
                })
    # the primary session cookie (the invocation's own) is the owner
    session = state.get("session_cookies") or state.get("cookies")
    if session and not profiles:
        profiles.append({
            "name": "primary", "cookies": dict(session), "role": "owner"})
    return profiles


def _lane_result(lane: str, candidate: dict[str, Any],
                  verdict: dict[str, Any]) -> dict[str, Any]:
    finding = verdict.get("finding")
    # the promoted finding (the caller appends it to the ordinary
    # findings channel with its bundle)
    if finding is not None and verdict.get("passed"):
        finding = finding.model_copy(update={
            "confidence_level": "Tool-Confirmed",
            "evidence_bundle": verdict.get("bundle"),
            "evidence": verdict.get("evidence") or {},
        })
    return {
        "lane": lane,
        "candidate": candidate,
        "confirmed": bool(verdict.get("passed")),
        "reason": verdict.get("reason"),
        "vulnerability_class": (
            finding.vuln_class if finding is not None else None),
        "url": (verdict.get("candidate").url
                if verdict.get("candidate") else None),
        "evidence_bundle": verdict.get("bundle"),
        "guard_evidence": verdict.get("evidence"),
        "finding_model": finding,
    }


def run_all_lanes(state: dict[str, Any]) -> dict[str, Any]:
    """The D-phase entry: all five lanes, flag-gated, fail-soft each."""
    if not lanes_enabled(state):
        return {"umdr48_lanes": {"enabled": False, "results": []}}
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    for lane_fn in (run_workflow_skip_lane,
                    run_framing_differential_lane,
                    run_graphql_cross_identity_lane,
                    run_tenant_override_lane,
                    run_redirect_policy_lane):
        try:
            results.extend(lane_fn(state))
        except Exception as exc:  # noqa: BLE001 — lane isolation
            errors.append(f"{lane_fn.__name__}: {type(exc).__name__}: {exc}")
    return {
        "umdr48_lanes": {
            "enabled": True,
            "version": _LANE_VERSION,
            "results": results,
            "confirmed_count": sum(1 for r in results if r["confirmed"]),
            "errors": errors,
        },
    }

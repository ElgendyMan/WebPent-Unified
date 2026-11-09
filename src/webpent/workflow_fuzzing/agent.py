# src/webpent/workflow_fuzzing/agent.py
"""Workflow-integrity fuzzing executor + validator (Proposal 9).

The executor replays a recorded workflow through the hardened client
(:func:`make_safe_httpx_client`) under the request-rate governor, three
times per mutation: baseline (the original workflow), mutated, and the
benign control twin (the SAME kind of mutation applied to the benign
step). The validator is a PURE, deterministic, fail-closed contract: a
break is CONFIRMED only when

  1. the mutated target step succeeded (2xx) AND its state artifact
     differs from the baseline replay of that step (the mutation was
     accepted AND changed observable state, e.g. a tampered 0.01 price
     produced a real order), AND
  2. the control twin was NOT accepted (rejected on the benign path),
     proving the break is specific to the sensitive path and not a
     property of the mutation itself.

Anything missing, malformed, or ambiguous (no control twin, control
also accepted) is INCONCLUSIVE; a mutation the server rejects or one
that changes no state is REFUTED. The LLM never decides confirmation.

All public orchestration is flag-gated (``enable_workflow_fuzzing``,
default False); the pure helpers stay unflagged for testability.
"""
from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

import re

from webpent.shared.h2_race import (
    H2ResponseTimeout,
    H2Unavailable,
    RaceRequestSpec,
    run_race,
)

logger = logging.getLogger(__name__)

# Keys whose values legitimately rotate on every response (CSRF tokens,
# nonces, timestamps, anti-replay fields): their VALUES are masked out
# before the artifact digest so a rotating token is never mistaken for
# a state change. Key NAMES are preserved, so a genuinely new field is
# still detected. Covers JSON bodies and HTML hidden inputs.
_VOLATILE_KEY = re.compile(
    r'("[^"]*(?:csrf|nonce|timestamp|replay|_token)[^"]*"\s*:\s*)'
    r'("[^"]*"|null)',
    re.IGNORECASE,
)
_VOLATILE_INPUT = re.compile(
    r'(<input[^>]*name="[^"]*(?:csrf|nonce|token)[^"]*"[^>]*value=")[^"]*"',
    re.IGNORECASE,
)


def _mask_volatile(body: str) -> str:
    return _VOLATILE_INPUT.sub(r"\1MASKED\"", _VOLATILE_KEY.sub(r"\1<MASKED>", body))

from webpent.workflow_fuzzing.strategies import (
    MutatedWorkflow,
    WorkflowStep,
    enumerate_mutations,
)

# Hard bound on total mutations replayed per workflow. enumerate_mutations
# yields at most 5 kinds x bounded sensitive steps; this cap keeps the
# request budget explicit and fail-closed.
MAX_MUTATIONS_PER_WORKFLOW = 40

STATUS_CONFIRMED = "confirmed"
STATUS_REFUTED = "refuted"
STATUS_INCONCLUSIVE = "inconclusive"


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------

def _send_step(client: Any, step: WorkflowStep) -> dict[str, Any]:
    """Send one recorded step; never raises (errors degrade to a failed step)."""
    try:
        response = client.request(
            step.method.upper(),
            step.url,
            headers=dict(step.headers) or None,
            json=dict(step.body) or None,
        )
        return {
            "step": step.name,
            "status_code": int(response.status_code),
            "state_artifact": _state_artifact(response),
        }
    except Exception:  # noqa: BLE001 — a failed send is a failed step, not a crash
        return {"step": step.name, "status_code": 0, "state_artifact": None}


def _state_artifact(response: Any) -> str:
    """Deterministic observable-state digest of one response.

    Kept deliberately simple: status + final URL + body length + a short
    body excerpt. Two replays that land in the same state produce the
    same artifact; a state change (order created, balance debited)
    changes at least one component. Volatile per-response values (CSRF
    tokens, nonces, timestamps) are masked BEFORE digesting: the v3.0
    excerpt compared raw bodies, so a rotating token made two identical
    states look different — a false CONFIRMED on every request whose
    server rotates tokens.
    """
    try:
        return _artifact_from_parts(
            str(response.status_code),
            str(getattr(response, "url", "")),
            str(response.text or ""),
        )
    except Exception:  # noqa: BLE001 — artifact failure degrades to empty
        return ""


def _artifact_from_parts(status_code: str, url: str, text: str) -> str:
    """The artifact format shared by the httpx and H2 transports.

    Both paths MUST digest through this one function: the validator
    compares a race step's artifact against its baseline replay, and a
    format divergence between transports would read as a state change
    that never happened (a false CONFIRMED).
    """
    body = _mask_volatile(text)
    return "|".join(
        [
            str(status_code),
            str(url),
            str(len(body)),
            body[:256],
        ]
    )


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlparse

        return urlparse(url).netloc or url
    except Exception:  # noqa: BLE001 — host extraction is best-effort
        return url


def _send_under_governor(
    client: Any, step: WorkflowStep, governor: Any | None
) -> dict[str, Any]:
    if governor is not None:
        with governor.acquire(_host_of(step.url)):
            return _send_step(client, step)
    return _send_step(client, step)


# Hop-by-hop / connection-scoped headers that are illegal or meaningless
# on an H2 stream (:authority replaces Host; framing headers are set by
# the connection itself).
_H2_STRIP_HEADERS = frozenset(
    {"host", "content-length", "transfer-encoding", "connection", "keep-alive"}
)


def _h2_race_enabled() -> bool:
    try:
        from webpent.config.settings import get_settings

        return bool(get_settings().enable_h2_race)
    except Exception:  # noqa: BLE001 — flag error resolves to OFF
        return False


def _h2_race_pair(
    governor: Any | None, step: WorkflowStep, attempts: int = 2
) -> "list[dict[str, Any]] | None":
    """Fire the race step as ONE single-packet H2 burst of ``attempts``.

    Returns the step results on success, or None when the caller must
    fall back to the serialized-thread path. None is returned ONLY for
    pre-send conditions (flag off, h2 library missing, H2 negotiation
    refused, fail-closed refusal): nothing reached the wire, so a
    fallback sends nothing twice. A post-send timeout raises
    H2ResponseTimeout inside run_race; here it is converted to failed
    step results WITHOUT a fallback — the burst is already on the wire
    and re-firing it (serialized or not) would double-send a race.

    The governor is acquired ONCE for the whole burst: the spend cap
    counts the N requests as one batch, mirroring how the frames leave
    as one flush. Note the raw-socket transport bypasses the hardened
    httpx client; it is reached only for already-recorded step URLs
    under an explicit engagement flag, and the step's URL has already
    been replayed through the hardened client in the baseline pass.
    """
    if not _h2_race_enabled():
        return None
    body = (
        json.dumps(dict(step.body), separators=(",", ":")).encode()
        if step.body
        else None
    )
    headers = {
        name: value
        for name, value in dict(step.headers).items()
        if name.lower() not in _H2_STRIP_HEADERS
    }
    spec = RaceRequestSpec(
        method=step.method, url=step.url, headers=headers, body=body
    )
    try:
        if governor is not None:
            with governor.acquire(_host_of(step.url)):
                result = run_race(
                    [spec] * attempts, enable_h2_race=True
                )
        else:
            result = run_race([spec] * attempts, enable_h2_race=True)
    except H2ResponseTimeout:
        logger.warning(
            "h2 race burst for %s was sent but responses timed out; "
            "NOT re-firing — recorded as failed steps",
            step.url,
        )
        return [
            {
                "step": step.name,
                "status_code": 0,
                "state_artifact": None,
                "h2_race": "response_timeout",
            }
        ] * attempts
    except H2Unavailable:
        logger.info(
            "h2 race unavailable for %s (library missing or H2 not "
            "negotiated); falling back to serialized threads",
            step.url,
        )
        return None
    except Exception as exc:  # noqa: BLE001 — pre-send refusal: safe fallback
        logger.info(
            "h2 race refused for %s (%s); falling back to serialized threads",
            step.url,
            exc,
        )
        return None
    results: list[dict[str, Any]] = []
    for resp in result.responses:
        text = (
            resp["body"].decode("utf-8", errors="replace")
            if resp["body"]
            else ""
        )
        results.append(
            {
                "step": step.name,
                "status_code": int(resp["status"]),
                "state_artifact": _artifact_from_parts(
                    str(resp["status"]), step.url, text
                ),
            }
        )
    return results


def _replay(
    client_factory: Callable[[], Any],
    governor: Any | None,
    steps: tuple[WorkflowStep, ...],
    race_step: str | None = None,
) -> list[dict[str, Any]]:
    """Replay a workflow in order through the hardened client.

    Strictly sequential by default. When ``race_step`` names a step, the
    FIRST occurrence of that step is sent as two truly concurrent
    attempts at its position in the workflow and the duplicate
    occurrence later in the sequence is skipped — the race actually
    races. When ``enable_h2_race`` is on AND the target speaks HTTP/2,
    the pair leaves as a single-packet H2 burst (all streams opened,
    one flush) instead of two threads; any pre-send H2 failure falls
    back to the thread pair, and a post-send timeout is recorded as
    failed steps WITHOUT re-firing. The v3.0 behavior was doubly wrong:
    the race mutation appended its duplicate at the END of the workflow
    (never concurrent unless the target was the last step), and plain
    replay mutations were wrongly fired concurrently whenever they
    duplicated a step. Replay is now always sequential; only a race
    mutation is concurrent, and only at the named step.
    """
    client = client_factory()
    results: list[dict[str, Any]] = []
    raced = False
    for step in steps:
        if race_step is not None and step.name == race_step:
            if raced:
                # The duplicated occurrence: the pair already went out
                # concurrently at the original's position.
                continue
            raced = True

            h2_results = _h2_race_pair(governor, step)
            if h2_results is not None:
                results.extend(h2_results)
                continue

            def _one(_attempt: int, s: WorkflowStep = step) -> dict[str, Any]:
                return _send_under_governor(client, s, governor)

            with ThreadPoolExecutor(max_workers=2) as pool:
                results.extend(pool.map(_one, range(2)))
            continue
        results.append(_send_under_governor(client, step, governor))
    return results


def _step_result(
    replay: list[dict[str, Any]], step_name: str | None
) -> dict[str, Any] | None:
    """First result for a step name, or None (fail-closed on missing)."""
    if step_name is None:
        return None
    for r in replay:
        if r.get("step") == step_name:
            return r
    return None


def _accepted(result: dict[str, Any] | None) -> bool:
    """A step was accepted: 2xx response."""
    return bool(result) and 200 <= int(result.get("status_code") or 0) < 300


def _mutated_target(m: MutatedWorkflow) -> str | None:
    """The step whose result decides the mutated verdict, by name.

    reorder: the sensitive step that moved one earlier — it now runs in
      its predecessor's position, so acceptance means the order was not
      enforced. skip: the successor — its success is what proves the
      skipped step was not required. replay/race: the duplicated step
      itself. price_tamper: the tampered step itself.
    """
    if not 0 <= m.target_index < len(m.control_steps):
        return None
    if m.kind == "skip_step":
        if m.target_index + 1 >= len(m.control_steps):
            return None
        return m.control_steps[m.target_index + 1].name
    return m.control_steps[m.target_index].name


def _control_target(m: MutatedWorkflow) -> str | None:
    """The step whose result decides the control twin's verdict."""
    if m.control_mutated is None:
        return None
    j = m.control_index
    if not 0 <= j < len(m.control_steps):
        return None
    if m.kind == "skip_step":
        if j + 1 >= len(m.control_steps):
            return None
        return m.control_steps[j + 1].name
    return m.control_steps[j].name


# ---------------------------------------------------------------------------
# Validator (pure, deterministic, fail-closed)
# ---------------------------------------------------------------------------

def validate_workflow_integrity_break(
    baseline_step: dict[str, Any] | None,
    mutated_step: dict[str, Any] | None,
    control_step: dict[str, Any] | None,
) -> str:
    """One verdict for one mutation. Pure; never raises.

    CONFIRMED     mutated step 2xx with a state artifact different from
                  baseline AND the control twin NOT accepted.
    REFUTED       mutated step rejected (non-2xx) or state-identical.
    INCONCLUSIVE  any input missing/malformed, or the control was also
                  accepted (ambiguous — cannot attribute the break to
                  the sensitive path).
    """
    try:
        if baseline_step is None or mutated_step is None or control_step is None:
            return STATUS_INCONCLUSIVE
        if not _accepted(mutated_step):
            return STATUS_REFUTED
        baseline_artifact = baseline_step.get("state_artifact")
        mutated_artifact = mutated_step.get("state_artifact")
        if mutated_artifact is None or mutated_artifact == baseline_artifact:
            # accepted but produced no state change: no integrity break
            return STATUS_REFUTED
        if _accepted(control_step):
            # the mutation is accepted on the benign path too: ambiguous
            return STATUS_INCONCLUSIVE
        return STATUS_CONFIRMED
    except Exception:  # noqa: BLE001 — the validator fails closed
        return STATUS_INCONCLUSIVE


# ---------------------------------------------------------------------------
# Flag-gated orchestration
# ---------------------------------------------------------------------------

def run_workflow_fuzzing(
    steps: tuple[WorkflowStep, ...],
    *,
    client_factory: Callable[[], Any] | None = None,
    governor: Any | None = None,
    max_mutations: int = MAX_MUTATIONS_PER_WORKFLOW,
) -> dict[str, Any]:
    """Flag-gated entry: fuzz one recorded workflow; report per mutation.

    Returns {"executed": bool, "mutations": [{kind, label, verdict}],
    "confirmed": n}. Flag off (default), workflow out of bounds, or no
    applicable mutations -> executed False with no verdicts; nothing is
    sent over the wire.
    """
    try:
        from webpent.config.settings import get_settings

        flag_on = bool(get_settings().enable_workflow_fuzzing)
    except Exception:  # noqa: BLE001 — flag error resolves to OFF
        flag_on = False
    if not flag_on:
        return {"executed": False, "mutations": [], "confirmed": 0}
    try:
        all_mutations = enumerate_mutations(steps)
    except Exception:  # noqa: BLE001 — out-of-bounds workflow fuzzes nothing
        return {"executed": False, "mutations": [], "confirmed": 0}
    mutations = all_mutations[: max(0, max_mutations)]
    if not mutations:
        return {"executed": False, "mutations": [], "confirmed": 0}

    if client_factory is None:
        from webpent.shared.http import make_safe_httpx_client

        client_factory = make_safe_httpx_client

    report: list[dict[str, Any]] = []
    confirmed = 0
    for m in mutations:
        try:
            verdict = _evaluate_mutation(m, client_factory, governor)
        except Exception:  # noqa: BLE001 — an executor error is inconclusive
            verdict = STATUS_INCONCLUSIVE
        if verdict == STATUS_CONFIRMED:
            confirmed += 1
        report.append({"kind": m.kind, "label": m.label, "verdict": verdict})
    total = len(all_mutations)
    truncated = total > len(mutations)
    if truncated:
        logger.warning(
            "workflow fuzzing truncated: ran %d of %d mutations (cap %d) "
            "for this workflow — the remainder are NOT covered by this run",
            len(mutations), total, max_mutations,
        )
    return {
        "executed": True,
        "mutations": report,
        "confirmed": confirmed,
        "total_mutations": total,
        "truncated": truncated,
    }


def _evaluate_mutation(
    m: MutatedWorkflow,
    client_factory: Callable[[], Any],
    governor: Any | None,
) -> str:
    """Replay baseline + mutated + control twin, then apply the validator.

    The no-control-twin check runs FIRST: v3.0 burned the baseline and
    mutated replays on the wire before discovering no verdict was
    possible. The baseline is deliberately replayed fresh for EVERY
    mutation (not cached across mutations): each mutated run executes
    after the previous mutations' side effects, so a cached baseline
    would compare against pre-fuzz server state and produce false
    verdicts — the replay cost is the price of sound differential
    testing. Only a race mutation is replayed concurrently (at the
    raced step); the control twin races the same way at its own target
    step so an unfixed race has a twin that should NOT confirm.
    """
    if not m.control_mutated:
        # no benign twin the kind can act on: fail closed to inconclusive
        return STATUS_INCONCLUSIVE
    if m.kind == "race_on_step":
        mut_race = _mutated_target(m)
        ctrl_race = _control_target(m) if m.control_mutated else None
    else:
        mut_race = ctrl_race = None
    baseline = _replay(client_factory, governor, m.control_steps)
    mutated = _replay(client_factory, governor, m.steps, race_step=mut_race)
    mut_res = _step_result(mutated, _mutated_target(m))
    mut_base = _step_result(baseline, _mutated_target(m))
    control = _replay(client_factory, governor, m.control_mutated, race_step=ctrl_race)
    ctrl_res = _step_result(control, _control_target(m))
    return validate_workflow_integrity_break(mut_base, mut_res, ctrl_res)

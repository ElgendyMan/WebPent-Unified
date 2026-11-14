"""Explicit, redacted oracle contracts for the Juice Shop P10 inventory.

These contracts define what may be observed and what remains unproven. They are
not approvals and they never turn a candidate observation into a vulnerability
verdict without an independently frozen mapping and strict proof.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class JuiceOracleContract:
    """A bounded oracle specification with separate proof dimensions."""

    oracle_id: str
    observation_proof: str
    vulnerability_proof: str
    negative_control: str
    raw_data_retained: bool = False
    qualification_eligible: bool = True


JUICE_ORACLE_CONTRACTS: Final[dict[str, JuiceOracleContract]] = {
    "http.read_only.resource_existence_and_metadata": JuiceOracleContract(
        oracle_id="http.read_only.resource_existence_and_metadata",
        observation_proof=(
            "Record status, content-type, anonymous-access result, and bounded "
            "length bucket; never retain resource content."
        ),
        vulnerability_proof=(
            "Requires independently approved mapping that the public resource "
            "is the vulnerable challenge surface, not merely a 2xx response."
        ),
        negative_control=(
            "Request an unrelated allowlisted static resource and compare only "
            "the redacted metadata shape."
        ),
    ),
    "http.read_only.log_resource_metadata": JuiceOracleContract(
        oracle_id="http.read_only.log_resource_metadata",
        observation_proof=(
            "Record public existence, content-type family, and bounded length "
            "bucket without retaining log lines."
        ),
        vulnerability_proof=(
            "Requires approved mapping that anonymous exposure of the selected "
            "log resource is the intended challenge condition."
        ),
        negative_control=(
            "Request an unrelated non-log allowlisted resource and compare only "
            "metadata categories."
        ),
    ),
    "http.read_only.signature_resource_metadata": JuiceOracleContract(
        oracle_id="http.read_only.signature_resource_metadata",
        observation_proof=(
            "Record public existence, content-type family, and bounded length "
            "bucket without retaining file content."
        ),
        vulnerability_proof=(
            "Requires approved mapping that the exposed signature/error file is "
            "the intended challenge surface."
        ),
        negative_control=(
            "Request an unrelated allowlisted static resource and compare only "
            "metadata categories."
        ),
    ),
    "http.read_only.metrics_publication": JuiceOracleContract(
        oracle_id="http.read_only.metrics_publication",
        observation_proof=(
            "Record endpoint reachability, content-type family, and bounded "
            "metric-shape counters without retaining metric names or values."
        ),
        vulnerability_proof=(
            "Requires approved definition that unauthenticated publication is "
            "the benchmark condition; endpoint existence alone is insufficient."
        ),
        negative_control=(
            "Request an unrelated allowlisted public endpoint and compare only "
            "redacted status and content-type families."
        ),
    ),
    "http.read_only.policy_resource_metadata": JuiceOracleContract(
        oracle_id="http.read_only.policy_resource_metadata",
        observation_proof=(
            "Record public reachability, content-type family, and bounded size "
            "bucket without retaining policy content."
        ),
        vulnerability_proof=(
            "Requires approved challenge semantics; policy-file existence alone "
            "does not establish a misconfiguration."
        ),
        negative_control=(
            "Request the alternate well-known policy path and compare only "
            "redacted metadata."
        ),
    ),
    "http.read_only.error_disclosure_metadata": JuiceOracleContract(
        oracle_id="http.read_only.error_disclosure_metadata",
        observation_proof=(
            "Record status and redacted error-shape flags only; do not retain "
            "stack traces, paths, headers, or response bodies."
        ),
        vulnerability_proof=(
            "Requires approved definition of the disclosure condition, such as "
            "verbose error metadata, rather than an arbitrary 4xx/5xx."
        ),
        negative_control=(
            "Request a known benign invalid path and compare only redacted error "
            "shape flags."
        ),
    ),
    "http.read_only.public_route_metadata": JuiceOracleContract(
        oracle_id="http.read_only.public_route_metadata",
        observation_proof=(
            "Record route reachability and bounded metadata without retaining "
            "page content."
        ),
        vulnerability_proof=(
            "Requires independent approval that public route exposure is a "
            "challenge condition; route existence is not enough by itself."
        ),
        negative_control=(
            "Request an unrelated public route and compare only redacted route "
            "metadata."
        ),
    ),
    "http.read_only.version_disclosure_metadata": JuiceOracleContract(
        oracle_id="http.read_only.version_disclosure_metadata",
        observation_proof=(
            "Record anonymous reachability and version-shape presence as a "
            "redacted boolean, never the version string."
        ),
        vulnerability_proof=(
            "Requires approved mapping that anonymous version disclosure is the "
            "intended challenge condition."
        ),
        negative_control=(
            "Request an unrelated administrative route and compare only status "
            "and redacted presence flags."
        ),
    ),
    "out_of_scope.external_destination_control": JuiceOracleContract(
        oracle_id="out_of_scope.external_destination_control",
        observation_proof=(
            "Not executed: proving external destination control is outside "
            "the local-only contract."
        ),
        vulnerability_proof="Unavailable under the current safety contract.",
        negative_control="Not applicable.",
        qualification_eligible=False,
    ),
    "dom.safe_search_sink_observation": JuiceOracleContract(
        oracle_id="dom.safe_search_sink_observation",
        observation_proof=(
            "Record only a typed-search DOM state and bounded sink-presence flag; "
            "do not inject executable content or retain page source."
        ),
        vulnerability_proof=(
            "Requires independent approval of the exact DOM/XSS semantics; a "
            "sink-presence observation alone is not a confirmed XSS."
        ),
        negative_control=(
            "Repeat the typed search with a benign control string and compare "
            "only redacted DOM state flags."
        ),
    ),
}


def get_juice_oracle(oracle_id: str) -> JuiceOracleContract:
    """Return one exact oracle contract or fail closed."""
    try:
        return JUICE_ORACLE_CONTRACTS[oracle_id]
    except KeyError as exc:
        raise KeyError(f"unknown_juice_oracle:{oracle_id}") from exc


__all__ = [
    "JuiceOracleContract",
    "JUICE_ORACLE_CONTRACTS",
    "get_juice_oracle",
]

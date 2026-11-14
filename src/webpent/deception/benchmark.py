"""webpent.deception.benchmark — M6 (Part 4 §8): the ATOBench-inspired
internal deception benchmark.

Registry scope: "ATOBench-inspired internal benchmark with ground
truth + blind set" and acceptance: "misleading fixtures rejected ...
deception benchmark reports published with sample sizes".

The benchmark runs the fixture corpus through the deception-resistant
verifier with the three-response causal protocol:

* ``baseline``  — the fixture's response to a benign request;
* ``candidate`` — the fixture's response to the payload request;
* ``control``   — the fixture's response to a randomized control
  request;
* ``repeat``    — the candidate re-issued (repeatability).

Ground truth: every fixture is NOT vulnerable. The verifier that
"confirms" on any fixture is reporting a FALSE POSITIVE — the report
counts them per class and in aggregate, with the sample sizes the
acceptance demands. A blind set is held out from the per-fixture
labels: the report's ``blind_set`` section scores fixtures by id hash
so a verifier cannot be tuned to the visible half.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.deception.fixtures import DECEPTION_CLASSES, DeceptionFixture, build_fixture_corpus
from webpent.deception.verifier import VerificationOutcome, verify_responses

__all__ = [
    "DeceptionBenchmarkReport",
    "run_deception_benchmark",
]

_BENIGN = "product"
_PAYLOAD = "<script>alert(1)</script>' OR 1=1--"
_CONTROL = "zz-randomized-control-token"


def _request(token: str, payload: str = "") -> dict[str, Any]:
    return {"path": "/search", "payload": payload, "token": token}


class DeceptionBenchmarkReport(BaseModel):
    """The published benchmark report with sample sizes."""

    model_config = ConfigDict(extra="forbid")

    benchmark: str = "webpent-deception-benchmark-v1"
    fixtures_total: int = Field(ge=0)
    classes: list[str] = Field(default_factory=list)
    per_class: dict[str, dict[str, int]] = Field(default_factory=dict)
    false_positives: int = Field(ge=0)
    rejected: int = Field(ge=0)
    inconclusive: int = Field(ge=0)
    blind_set: dict[str, Any] = Field(default_factory=dict)
    false_positive_fixture_ids: list[str] = Field(default_factory=list)
    ground_truth: str = "no fixture is vulnerable — any confirmation is a false positive"


def _is_blind(fixture_id: str) -> bool:
    """Deterministic 50% split by fixture-id hash (the blind set)."""
    digest = hashlib.sha256(fixture_id.encode("utf-8")).hexdigest()
    return int(digest[:2], 16) % 2 == 0


def run_deception_benchmark(
    corpus: list[DeceptionFixture] | None = None,
) -> DeceptionBenchmarkReport:
    """Run the corpus through the causal verifier; report with sizes."""
    fixtures = corpus if corpus is not None else build_fixture_corpus()
    per_class: dict[str, dict[str, int]] = {
        deception_class: {
            "fixtures": 0,
            "rejected": 0,
            "inconclusive": 0,
            "false_positives": 0,
        }
        for deception_class in DECEPTION_CLASSES
    }
    false_positive_ids: list[str] = []
    blind_counts = {"fixtures": 0, "rejected": 0, "inconclusive": 0, "false_positives": 0}

    for fixture in fixtures:
        baseline = fixture.respond(_request("baseline", _BENIGN))
        candidate = fixture.respond(_request("candidate", _PAYLOAD))
        control = fixture.respond(_request("control", _CONTROL))
        repeat = fixture.respond(_request("candidate", _PAYLOAD))
        outcome: VerificationOutcome = verify_responses(
            baseline=baseline,
            candidate=candidate,
            control=control,
            candidate_repeat=repeat,
        )
        bucket = per_class[fixture.deception_class]
        bucket["fixtures"] += 1
        if outcome.verdict == "refuted_deceptive":
            bucket["rejected"] += 1
            key = "rejected"
        elif outcome.verdict == "inconclusive":
            bucket["inconclusive"] += 1
            key = "inconclusive"
        else:
            bucket["false_positives"] += 1
            false_positive_ids.append(fixture.fixture_id)
            key = "false_positives"
        if _is_blind(fixture.fixture_id):
            blind_counts["fixtures"] += 1
            blind_counts[key] += 1

    total_rejected = sum(c["rejected"] for c in per_class.values())
    total_inconclusive = sum(c["inconclusive"] for c in per_class.values())
    total_fp = sum(c["false_positives"] for c in per_class.values())

    return DeceptionBenchmarkReport(
        fixtures_total=len(fixtures),
        classes=list(DECEPTION_CLASSES),
        per_class=per_class,
        false_positives=total_fp,
        rejected=total_rejected,
        inconclusive=total_inconclusive,
        blind_set=blind_counts,
        false_positive_fixture_ids=false_positive_ids,
    )


def report_to_json(report: DeceptionBenchmarkReport) -> str:
    """Deterministic JSON serialization for publication."""
    return json.dumps(
        json.loads(report.model_dump_json()), indent=2, sort_keys=True
    )

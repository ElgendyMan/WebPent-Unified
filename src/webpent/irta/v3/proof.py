"""ProofBundle and scoring eligibility primitives for IRTA v3."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ProofBundle:
    target_id: str
    case_id: str
    baseline_digest: str
    candidate_digest: str
    control_digest: str
    causal_signal: str
    replay_token: str
    seal: str = ""

    def _canonical(self) -> str:
        payload = asdict(self)
        payload.pop("seal", None)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def sealed(self) -> ProofBundle:
        return ProofBundle(
            target_id=self.target_id,
            case_id=self.case_id,
            baseline_digest=self.baseline_digest,
            candidate_digest=self.candidate_digest,
            control_digest=self.control_digest,
            causal_signal=self.causal_signal,
            replay_token=self.replay_token,
            seal=hashlib.sha256(self._canonical().encode("utf-8")).hexdigest(),
        )

    def verify_seal(self) -> bool:
        return bool(self.seal) and self.seal == hashlib.sha256(
            self._canonical().encode("utf-8")
        ).hexdigest()

    def replay(self, replay_token: str) -> bool:
        return self.verify_seal() and replay_token == self.replay_token

    def scoring_eligible(self) -> bool:
        required = (
            self.baseline_digest,
            self.candidate_digest,
            self.control_digest,
            self.causal_signal,
            self.replay_token,
        )
        return self.verify_seal() and all(required)

"""L6 smoke: run the generalized discovery engine over blind eval
instances (vulnerable and secured lookalikes) with no fixture reuse."""
import sys

sys.path.insert(0, "src")

from webpent.egaie import discovery_runner as dr
from webpent.egaie.eval_instances import InstanceTarget, generate_instance

SECURED = dict.fromkeys((
    "identity_read", "identity_mutation", "workflow_identity",
    "order", "price", "coupon", "balance"), False)


def run(seed: int, profile: dict[str, bool] | None) -> None:
    spec = generate_instance(seed, blind=True, profile=profile)
    label = "secured" if profile == SECURED else "mixed"
    with InstanceTarget(spec) as target:
        port = dr._build_port(target, seed)
        state = dr._seed_state(target, dr._version_ids(seed)[0])
        state = dr._build_orchestrator(port, "adaptive").run(
            state, max_rounds=64)
    print(f"== seed {seed} ({label}) instance={spec.instance_id}")
    print(f"   read segment: {spec.read_segment!r} "
          f"workflow prefix: {spec.workflow_prefix!r}")
    families: dict[str, int] = {}
    for exp in state.experiments:
        families[exp.family] = families.get(exp.family, 0) + 1
    print(f"   experiments={len(state.experiments)} by family: {families}")
    confirmed = [
        rec for rec in state.hypotheses
        if rec.status.value == "confirmed" and rec.origin.startswith(
            "differential:recon:")
    ]
    for rec in confirmed:
        print(f"     CONFIRMED [{rec.origin}]")
        print(f"       stmt: {rec.statement[:110]}")
    if not confirmed:
        print("     (no confirmed findings)")
    outcomes: dict[str, int] = {}
    for exp in state.experiments:
        outcome = state.experiment_outcome(exp.experiment_id)
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    print(f"   outcomes: {outcomes}")


if __name__ == "__main__":
    run(11, None)
    run(14, None)
    run(17, SECURED)

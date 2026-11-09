"""Quick L6 evaluation pass: run the engine over a seed set and score
each completed state with the ground-truth evaluator."""
import sys

sys.path.insert(0, "src")

from webpent.egaie import discovery_runner as dr
from webpent.egaie.eval_instances import InstanceTarget, generate_instance
from webpent.evalsuite.evaluator import corpus_summary, evaluate_instance

SECURED = dict.fromkeys((
    "identity_read", "identity_mutation", "workflow_identity",
    "order", "price", "coupon", "balance"), False)


def run(seed: int, profile: dict[str, bool] | None) -> dict:
    spec = generate_instance(seed, blind=True, profile=profile)
    with InstanceTarget(spec) as target:
        port = dr._build_port(target, seed)
        state = dr._seed_state(target, dr._version_ids(seed)[0])
        state = dr._build_orchestrator(port, "adaptive").run(
            state, max_rounds=64)
    return evaluate_instance(spec, state)


if __name__ == "__main__":
    results = [run(11, None), run(14, None), run(17, SECURED)]
    for r in results:
        print(f"== {r['instance_id']} seed={r['seed']} "
              f"TP={r['true_positives']} FP={r['false_positives']} "
              f"FN={r['false_negatives']} "
              f"leakage={len(r['leakage_findings'])}")
        for family, s in r["families"].items():
            if s["defective"] or s["confirmed"] or s["false_negatives"]:
                print(f"   {family}: defective={s['defective']} "
                      f"confirmed={len(s['confirmed'])} "
                      f"outcomes={s['outcomes']}")
                for fn in s["false_negatives"]:
                    print(f"     FN causal={fn['causal_failure']}")
                for fp in s["false_positives"]:
                    print(f"     FP causal={fp['causal_failure']}")
    import json
    print(json.dumps(corpus_summary(results), indent=2))

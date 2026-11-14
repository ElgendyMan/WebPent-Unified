"""Public benchmark entrypoint for VABHIC v7 controlled evaluation."""

from webpent.vabhic_v7.benchmark import SCENARIO_CLASSES, VIPControlledBenchmarkV6

__all__ = ["SCENARIO_CLASSES", "VIPControlledBenchmarkV6"]


if __name__ == "__main__":
    import json

    print(json.dumps(VIPControlledBenchmarkV6().evaluate(), indent=2, sort_keys=True))

"""v82 Tasks 13-15: anomaly detector, cross-target memory, hypothesis quality."""

from __future__ import annotations

import json

from webpent.autonomous.amplifiers.intuition import (
    MAX_FINGERPRINTS,
    MAX_HYPOTHESES,
    CrossTargetStore,
    build_baseline,
    detect_anomalies,
    fingerprint_of,
    rank_by_quality,
    score_hypothesis,
)

# -- Task 13: anomaly detector ------------------------------------------------


def _observations() -> list[dict]:
    return [
        {"size": 100, "latency_ms": 50, "status": 200},
        {"size": 110, "latency_ms": 60, "status": 200},
        {"size": 90, "latency_ms": 55, "status": 200},
        {"size": 105, "latency_ms": 58, "status": 200},
        {"size": 95, "latency_ms": 52, "status": 200},
        {"size": 100, "latency_ms": 50, "status": 404},
    ]


def test_baseline_computes_median_and_mad() -> None:
    baseline = build_baseline(_observations())
    assert baseline["samples"] == 6
    assert baseline["size_median"] == 100.0
    assert baseline["latency_ms_median"] == 53.5
    assert baseline["size_mad"] >= 0
    assert baseline["status_counts"]["200"] == 5
    assert baseline["advisory"] is True


def test_baseline_honors_sample_bound() -> None:
    from webpent.autonomous.amplifiers.intuition import MAX_SAMPLES

    obs = [{"size": i} for i in range(MAX_SAMPLES + 20)]
    assert build_baseline(obs)["samples"] == MAX_SAMPLES


def test_deviation_beyond_k_flagged() -> None:
    baseline = build_baseline(_observations())
    report = detect_anomalies({"size": 900, "latency_ms": 55, "status": 200}, baseline)
    kinds = [s["kind"] for s in report["signals"]]
    assert "size_deviation" in kinds
    assert "latency_ms_deviation" not in kinds
    size_signal = next(s for s in report["signals"] if s["kind"] == "size_deviation")
    assert size_signal["z"] > 4.0


def test_normal_observation_is_clean() -> None:
    baseline = build_baseline(_observations())
    report = detect_anomalies({"size": 102, "latency_ms": 57, "status": 200}, baseline)
    assert report["signals"] == []


def test_rare_status_detected_with_enough_samples() -> None:
    baseline = build_baseline(_observations())
    report = detect_anomalies({"status": 503, "size": 100}, baseline)
    assert any(s["kind"] == "rare_status" for s in report["signals"])


def test_rare_status_suppressed_without_baseline_samples() -> None:
    baseline = {"samples": 2, "status_counts": {"200": 2}}
    report = detect_anomalies({"status": 503}, baseline)
    assert report["signals"] == []


def test_anomaly_garbage_inputs_are_honest() -> None:
    assert detect_anomalies("x", "y") == {"signals": [], "advisory": True}
    assert build_baseline("nope") == {"samples": 0, "advisory": True}
    assert build_baseline([{"size": "junk", "status": None}])["samples"] == 1
    assert detect_anomalies({"size": 1}, {})["signals"] == []


# -- Task 14: cross-target pattern recognition --------------------------------


def test_fingerprint_is_stable_and_normalized() -> None:
    a = fingerprint_of(["nginx", "React", " flask "])
    b = fingerprint_of(["flask", "NGINX", "react"])
    assert a == b
    assert a == "flask|nginx|react"


def test_fingerprint_rejects_non_collections() -> None:
    assert fingerprint_of(42) == ""
    assert fingerprint_of(None) == ""


def test_record_and_suggest_ranking(tmp_path) -> None:
    store = CrossTargetStore(tmp_path / "cross.json")
    stack = ["nginx", "php"]
    for _ in range(3):
        store.record_proven(stack, "sqli", "http://a.example")
    store.record_proven(stack, "xss", "http://b.example")
    suggestions = store.suggestions_for(["PHP", "NGINX"])
    assert suggestions[0] == {"vuln_class": "sqli", "hits": 3, "advisory": True}
    assert suggestions[1]["vuln_class"] == "xss"
    assert store.suggestions_for(["unknown", "stack"]) == []


def test_target_keys_are_redacted_origins(tmp_path) -> None:
    store = CrossTargetStore(tmp_path / "cross.json")
    store.record_proven(["nginx"], "xss", "http://user:pass@t.example/page?q=secret")
    entry = store._patterns[fingerprint_of(["nginx"])]
    assert entry["targets"] == ["http://t.example"]


def test_persistence_roundtrip(tmp_path) -> None:
    path = tmp_path / "cross.json"
    store = CrossTargetStore(path)
    store.record_proven(["nginx", "php"], "sqli", "http://a.example")
    store.save()
    reloaded = CrossTargetStore(path)
    assert reloaded.suggestions_for(["php", "nginx"])[0]["vuln_class"] == "sqli"


def test_corrupt_file_starts_empty(tmp_path) -> None:
    path = tmp_path / "cross.json"
    path.write_text("{not json at all", encoding="utf-8")
    store = CrossTargetStore(path)
    assert store.suggestions_for(["nginx"]) == []


def test_nothing_secret_is_persisted(tmp_path) -> None:
    path = tmp_path / "cross.json"
    store = CrossTargetStore(path)
    store.record_proven(["nginx"], "sqli", "http://t.example?token=sk_live_supersecret99")
    store.save()
    blob = path.read_text(encoding="utf-8")
    assert "sk_live" not in blob
    assert json.loads(blob)  # still valid JSON


def test_fingerprint_cap(tmp_path) -> None:
    path = tmp_path / "cross.json"
    store = CrossTargetStore(path)
    for i in range(MAX_FINGERPRINTS + 10):
        store.record_proven([f"stack-{i}"], "xss", f"http://t{i}.example")
    store.save()
    reloaded = CrossTargetStore(path)
    assert len(reloaded._patterns) == MAX_FINGERPRINTS


# -- Task 15: hypothesis quality scoring ---------------------------------------


def test_score_rewards_specificity_evidence_testability() -> None:
    weak = {"target_url": "admin panel somewhere", "evidence": "", "source": ""}
    strong = {
        "target_url": "http://lab.example/search",
        "request_method": "GET",
        "evidence": "reflected at param q (seen in probe #12)",
        "validator": "probe_reflection",
        "estimated_iterations": 1,
    }
    assert score_hypothesis(weak) < 0.5
    assert score_hypothesis(strong) == 1.0


def test_score_is_pure_and_deterministic() -> None:
    h = {"target_url": "http://x.example/a", "evidence": "e", "validator": "v"}
    assert score_hypothesis(h) == score_hypothesis(dict(h))
    original = dict(h)
    score_hypothesis(h)
    assert h == original


def test_score_of_garbage_is_zero() -> None:
    assert score_hypothesis("nope") == 0.0
    assert score_hypothesis({}) >= 0.0


def test_rank_reorders_without_dropping(tmp_path) -> None:
    weak = {"target_url": "guess something", "evidence": ""}
    strong = {
        "target_url": "http://lab.example/id",
        "request_method": "POST",
        "evidence": "bool-based error observed",
        "validator": "probe_bool",
    }
    ranked = rank_by_quality([weak, strong])
    assert [item["quality_score"] for item in ranked] == sorted(
        [item["quality_score"] for item in ranked], reverse=True
    )
    assert len(ranked) == 2  # nothing dropped
    assert all("quality_score" in item for item in ranked)
    # inputs untouched
    assert "quality_score" not in weak


def test_rank_bounds_and_garbage() -> None:
    items = [
        {"target_url": f"http://x.example/{i}", "evidence": "e"}
        for i in range(MAX_HYPOTHESES + 5)
    ]
    ranked = rank_by_quality(items)
    assert len(ranked) == MAX_HYPOTHESES
    assert rank_by_quality("junk") == []
    assert rank_by_quality([None, 5, {"target_url": "http://x/a"}])[0]["target_url"] == "http://x/a"

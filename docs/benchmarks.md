# Live benchmarks (PROPOSALS_ULTIMATE_V2 §8)

Detection-rate benchmarking of the framework against LOCAL lab targets
only. A benchmark run that could touch a production target is a footgun,
so every layer here is fail-closed:

- `enable_live_benchmarks` (default **False**) gates the whole runner
  (`webpent/benchmark/live_runner.py`): with it off, no benchmark
  traffic is ever generated.
- `benchmark_target` must name an explicit LOCAL target, e.g.
  `http://127.0.0.1:3000` for a locally started Juice Shop container.
  The runner refuses any host that is not `localhost` / `127.0.0.1` /
  `::1` (fail-closed), including userinfo tricks
  (`http://127.0.0.1@evil.com`) and subdomain tricks
  (`http://127.0.0.1.evil.com`); only http/https schemes are accepted.
- The runner itself never contacts the target. It gates, times, and
  scores a caller-supplied campaign callable — the single seam where
  the real framework invocation is wired — so the gating and scoring
  are testable offline and every network request is attributable to one
  explicit dependency.

## Ground truth

A ground-truth JSON file declares, per target, the known vulnerabilities
(class + endpoint) the run is expected to find:

```json
{
  "schema_version": 1,
  "target": "juice-shop-local",
  "vulns": [
    {"vuln_class": "xss", "endpoint": "/search", "notes": "reflected in results template"},
    {"vuln_class": "path_traversal", "endpoint": "/ftp"}
  ]
}
```

Loading is fail-closed: unreadable files, invalid JSON, missing
`vuln_class`/`endpoint`, or an unknown `schema_version` are hard
refusals (`webpent/benchmark/ground_truth.py`).

## Scoreboard

`webpent/benchmark/scoreboard.py` scores the run strictly: a finding
counts as a detection only when BOTH its class and endpoint match a
declared vuln exactly; each declared vuln counts once; leftover
findings are listed as false positives. The board
(`benchmark_scoreboard.json`, `schema_version: 1`) records per class:
expected/detected counts, detection rate, and missed endpoints; and
overall: detection rate, false positives, elapsed seconds (solve time),
and token cost. Boards are byte-deterministic so successive versions
diff cleanly, and `compare_scoreboards` flags ANY per-class detection
drop between versions as a regression — attributable to whatever change
produced the newer board.

## Running a benchmark

```bash
# 1. start a local lab (example: Juice Shop)
docker run --rm -p 3000:3000 bkimminich/juice-shop

# 2. run an opted-in benchmark campaign
WEBPENT_ENABLE_LIVE_BENCHMARKS=1 \
WEBPENT_BENCHMARK_TARGET=http://127.0.0.1:3000 \
WEBPENT_BENCHMARK_GROUND_TRUTH=benchmarks/ground_truth/juice-shop-local.json \
  python -m pytest tests/test_live_benchmarks.py -k OptInJuiceShopContainer -s
```

The container test is excluded from the default CI run: it activates
only with `WEBPENT_BENCHMARK_LIVE=1` **and** a `WEBPENT_BENCHMARK_TARGET`
pointing at the locally started container. Everything else in the suite
runs offline (a localhost HTTP fixture server stands in for the lab).

## Scoreboard — detection rate per class

Current measured state. The fixture-harness row is produced by
`tests/test_live_benchmarks.py::TestLiveFixtureServer` (a localhost
HTTP fixture with a reflected-XSS search endpoint and an exposed
directory listing) and is re-measured on every suite run. Juice Shop
rows are pending the first local container run; they are filled by
following the steps above and re-numbering this table after each
subsequent framework improvement (never overwritten silently).

| Target            | Vuln class      | Endpoint | Detection rate | Solve time | Token cost | Measured                      |
|-------------------|-----------------|----------|----------------|------------|------------|-------------------------------|
| bench-fixture     | xss             | /search  | 1.00           | ~ms        | 123/run    | fixture harness, 2026-10-30   |
| bench-fixture     | path_traversal  | /ftp     | 1.00           | ~ms        | 123/run    | fixture harness, 2026-10-30   |
| juice-shop-local  | xss             | /search  | pending        | —          | —          | first container run pending   |
| juice-shop-local  | sqli            | /rest/products/search | pending | —  | —          | first container run pending   |
| juice-shop-local  | path_traversal  | /ftp     | pending        | —          | —          | first container run pending   |

The `juice-shop-local.json` ground truth ships with the campaign and is
extended as classes are measured; a class enters the table only when a
run actually scored it.

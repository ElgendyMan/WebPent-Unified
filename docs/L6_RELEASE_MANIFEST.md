# L6 Release Manifest

Release: **webpent-l6-blind-discovery** (2026-10-24)
HEAD commit: `6522e6f`

ZIP: `webpent_l6.zip`, cut from this exact commit
(the archive cannot contain its own digest; the SHA-256 of the
final zip is published alongside the release)

```
6522e6f docs: regenerate G-02 inventory markdown twin (662 records, matches committed JSON)
84a3955 tests+docs: L6 resume/no-duplicate-mutation and out-of-scope authorization red-first tests; mission deliverables document
e486076 gates: restore make ci gate targets (stale --minimum literal, E501/F841 in gate-listed files)
1fbcf9d docs: regenerate direct-I/O inventory artifact (662 records; 3 new egaie differential/eval sites)
9714fd4 egaie: L6 candidate identities from observed external owners; full eval harness
78decbb tests: L6 red-first blind-discovery regression suite (12 tests)
c2118e4 egaie: L6 oracle routing, mutual-read discriminator, sealed eval corpus
4a7973d egaie: L6 blind-surface generalization — SurfaceBindings-driven tracker, generators, and fail-closed oracle
ff0263b docs: L5 differential discovery deliverables (architecture, benchmark+ablation, hypotheses, limitations)
```

## Key file digests (SHA-256)

| file | sha256 |
|---|---|
| `src/webpent/egaie/differential.py` | `c667f10c69bce5c5c47a1b69d5648b48a1ec24032b37ea78858fe248181f1e79` |
| `src/webpent/egaie/eval_instances.py` | `04a43bb61092ba66c3e9ccf2033b1f128d51a5dc3a9c7719de5ee4ce14d5e7ea` |
| `src/webpent/egaie/discovery_runner.py` | `02580c4b9dec09febb93ad3c610ea334e57617697f8333af47fb59da740fe236` |
| `src/webpent/evalsuite/evaluator.py` | `4ee184df22ea3ad7bddd21bb04f8e7fd741fbaf83d69e3cab9b07211f4a33c6f` |
| `src/webpent/evalsuite/__init__.py` | `7b1a3b30bbeaeadf0215808a45a3c63b17ff48bbc12c6005992bf47790a4ae0e` |
| `tests/egaie/test_blind_discovery.py` | `39156d40b11e99a2d352e1b4b5186b46f2ccc86d536cfca17f43fa8c8d3d3420` |
| `scripts/l6_evaluate.py` | `c97970c43513bcd4f77c1e1714afe87a97e368a15db958e6790eacf439ba8963` |
| `scripts/l6_eval_quick.py` | `2d921c5121e3fdb3c0fc8d0ca3604bb035cbc86770a9d297d1ce38c0d012e6bf` |
| `docs/l6_evaluation.json` | `d1743f985ca964795cb7f6370c24feca992280a22ce9d502953e46d5ae8a096a` |
| `docs/L6_DELIVERABLES.md` | `aedc9c96661eb61a581a20a59759b9a63d98273fd28aa4bed3f68295f8b1be33` |
| `docs/direct_io_inventory.json` | `0480973ab678720c1f580e14f0b9a96cb2ebca235fe3f9fc800a630e8e25945e` |
| `docs/DIRECT_IO_INVENTORY.md` | `619a52b4db191ec013649399b74321c7921f51d4873ed02e5d1f9997ff368cf5` |

## Gates

```json
{
  "pytest": "4453 passed, 0 failed",
  "coverage": "61.70% >= 35% floor (4451 passed run)",
  "lint": "make lint: all checks passed",
  "test_count": "4451 collected >= floor 1940 (pre-new-tests run)",
  "bandit_lll": "exit 0",
  "construction_authority": "OK",
  "vault_import_authority": "OK"
}
```

## Evaluation summary

```json
{
  "heldout": {
    "instances": 9,
    "TP": 37,
    "FP": 0,
    "FN": 0,
    "precision": 1.0,
    "leakage": 0
  },
  "negative": {
    "instances": 2,
    "TP": 0,
    "FP": 0
  },
  "modes_heldout_confirmed": {
    "adaptive": 37,
    "fixed": 37,
    "ablation": 0
  },
  "status": "PRELIMINARY - generated-instance corpus only; not real-world bug-hunting capability"
}
```

Excluded from the release tree: `download/econ/portfolio_transitions.jsonl`
(working file, never staged or committed).

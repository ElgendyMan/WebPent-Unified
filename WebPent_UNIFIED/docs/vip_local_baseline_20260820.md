# VIP local baseline — 2026-08-20

## Scope
This baseline is local-only. No WAPTLab or external target was executed.

## Git

The final commit and clean-tree state are recorded in `docs/vip_local_release_report_20260820.md` after the release commit. This baseline file is intentionally updated before packaging and is not itself evidence of a live target run.

## Runtime
```text
Python 3.12.3
pip 26.2.1 from /tmp/webpent_v72_git_recovered/.venv/lib/python3.12/site-packages/pip (python 3.12)
```

## Inventory counts
```text
python_modules=247
tests=137
scripts=45
docs=106
```

## Dependency metadata
```text
pyproject.toml
requirements-audit-v63.txt
uv.lock
```

## Existing evidence boundary
Historical WAPTLab artifacts are retained as prior evidence only; they are not re-executed in this task.

## Current release-gate result
This pass recorded **1007 pytest passes, 0 failures**, Ruff clean, compileall pass, `verify_all.py` at **145 PASS / 0 FAIL**, `git diff --check` pass, and a local dependency audit with no reported vulnerabilities. The local project package was skipped by pip-audit because it is not published on PyPI. No WAPTLab or other target was executed.

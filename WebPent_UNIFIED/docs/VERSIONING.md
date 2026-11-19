# Versioning — the two version axes (P2-405)

**Date:** 2026-11-01 · **Closes:** Phase-1 version-consistency observation
(package version `0.3.0` vs delivery build label `v15.2`).

## The two axes

| Axis | Example | Authoritative source | Changes when |
|---|---|---|---|
| **Package/API version** | `0.3.0` | `pyproject.toml` `[project].version` (surfaces as `webpent.__version__` / package metadata) | The Python API surface changes (semver: breaking → major, features → minor, fixes → patch) |
| **Delivery build label** | `WebPent v15.2` | `BUILD_INFO.json` `build_name` (+ delivery ZIP name / `DISTRIBUTION_STATUS.md`) | A delivery is cut (the label counts delivery iterations, including doc-only and packaging-only ones) |

They are **different axes by design**: the build label can advance while the
package version stays put (e.g. v15.0→v15.2 delivered mostly evidence,
governance, and packaging changes), and the package version will move on its
own semver schedule when the API actually changes.

## Rules

1. Never "sync" the two mechanically (e.g. by bumping `pyproject` to `15.2`);
   that would fake semver meaning the API does not carry.
2. Every delivery record that cites a build must name BOTH:
   the label (`BUILD_INFO.build_name`) and the package version
   (`pyproject` version at delivery time), e.g. "v15.2 (package 0.3.0)".
3. `BUILD_INFO.json` is provenance (stability-enforced by
   `scripts/check_build_info_honesty.py`); the package version is live
   project state. Only a re-freeze ceremony changes the former.

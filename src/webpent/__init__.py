"""WebPent package metadata.

RESIDUAL CLOSURE 2026-10-29 (Track 0.4 — version identity): this
attribute had stayed at "0.14.0" across eleven pyproject bumps (0.15.0
.. 0.25.0), silently diverging from pyproject.toml/CHANGELOG.md — the
release-packaging gate pinned the stale literal instead of catching the
divergence. The version SSOT is pyproject.toml; this attribute must
move with it at every release.
"""

__version__ = "0.40.1"

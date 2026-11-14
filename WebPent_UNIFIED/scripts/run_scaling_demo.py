"""Backward-compatible entrypoint for the fresh multi-campaign demo.

The previous implementation imported historical campaign artifacts. That was
useful as a fixture, but it was not a real concurrent execution. The canonical
 demo now lives in ``run_fresh_two_target_demo.py`` and starts two controlled
loopback targets, runs both campaigns through the production spine, exercises a
per-campaign action-ledger halt, and generates reports from the fresh sealed
findings.
"""
from __future__ import annotations

from run_fresh_two_target_demo import main


if __name__ == "__main__":
    main()

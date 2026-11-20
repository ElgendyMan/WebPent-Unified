"""Shared fixtures for the DEEP Tier-1 suite.

Every detector takes its transport as an injected function — the tests
drive fakes, and the package itself never opens a socket (zero live
network from core; advisory-only detection).
"""
from __future__ import annotations

import pytest

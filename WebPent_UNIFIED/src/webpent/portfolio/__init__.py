# src/webpent/portfolio/__init__.py
"""webpent.portfolio — ق11 multi-target fleet dashboard (FEATURE_PROPOSALS ق11).

One portfolio = many targets, each with its own priority and budget
caps, run across the worker fleet (production/worker_coordination +
cross_process_leases + scheduler/campaign_scheduler). This package is
the portfolio_manager dashboard layer the proposal asks for; the fleet
primitives themselves are imported, never edited. See ``manager.py``.
"""

from webpent.portfolio.manager import (
    FleetDashboard,
    PortfolioEntry,
    PortfolioManager,
    PortfolioError,
    PlanWave,
)

__all__ = [
    "PortfolioEntry",
    "PortfolioManager",
    "PortfolioError",
    "PlanWave",
    "FleetDashboard",
]

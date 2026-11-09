"""Enable ``python3 -m webpent.cli`` (v4 remediation, TEAM-RED finding R-01).

The v3 campaign scripts (``run_campaign.sh``, ``stop_campaign.sh``,
``verify_campaign.sh``) invoke ``python3 -m webpent.cli ...`` which requires
``webpent/cli/__main__.py``. That file did not exist, so every shipped
campaign script failed with ``No module named webpent.cli.__main__`` — the
hunt never started and the product-side kill-switch path was never reached.

This module is NEW and NOT part of the 695-file frozen trust manifest; it
only re-exports the existing ``main`` entry point (single CLI authority
``webpent.cli:main``, unchanged). The frozen files ``__init__.py`` and
``commands.py`` are untouched.
"""

from webpent.cli import main

if __name__ == "__main__":
    main()

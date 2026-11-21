#!/usr/bin/env python3
"""Exact per-report pytest accounting via plugin hooks (UM-DR-36.2 §3.4).

Loaded with::

    UMDR_ACCOUNTING_OUT=/path/out.json pytest -p pytest_accounting_plugin ...

(the runner scripts/run_tests_with_evidence.py sets both). When the env
var is absent the plugin is inert, so loading it is always safe.

Why a plugin: the UM-DR-36.1 evidence parsed pytest's TERMINAL SUMMARY,
which collapses the categories the mission requires to keep apart. The
recorded anomaly — "collected 9141 vs executed 9142" — was precisely
this: the terminal summary counts one module-level COLLECTION SKIP
(non-item) and SETUP ERRORS inside "errors"/"skipped", so a single
"executed" number conflates item reports with collection-phase reports.
Hook-level counting separates them exactly:

  collected_items     items that entered the session (session.items)
  collection_errors   modules that FAILED collection (non-item reports)
  collection_skips    modules SKIPPED at collection (non-item reports)
  deselected          items removed by deselection
  started_items       items that produced at least one test report
  not_started         collected - started (interrupted runs)
  outcomes            call-phase (or setup-skip) item outcomes:
                      passed / failed / skipped / xfailed / xpassed
  setup_errors        items whose SETUP errored (started, never ran)
  teardown_errors     teardown errors of items that DID get an outcome
  interrupted         exitstatus == 2 (keyboard interrupt)

Invariants (computed, never assumed):

  collected_items == started_items + not_started
  started_items   == sum(outcomes) + setup_errors
  errors_total    == setup_errors + teardown_errors + collection_errors
  and (cross-checkable against the terminal summary):
  terminal skipped == skipped + collection_skips
  terminal errors  == errors_total
"""
from __future__ import annotations

import json
import os


class AccountingPlugin:
    def __init__(self) -> None:
        self.collection_errors = 0
        self.collection_skips = 0
        self.deselected = 0
        self.started: set[str] = set()
        self.setup_errors = 0
        self.teardown_errors = 0
        self.outcomes = {
            "passed": 0, "failed": 0, "skipped": 0,
            "xfailed": 0, "xpassed": 0,
        }
        self.failed_nodeids: list[str] = []

    # -- collection phase --------------------------------------------------

    def pytest_collectreport(self, report) -> None:
        if getattr(report, "failed", False):
            self.collection_errors += 1
        elif getattr(report, "skipped", False):
            self.collection_skips += 1

    def pytest_deselected(self, items) -> None:
        self.deselected += len(list(items))

    # -- per-test reports ---------------------------------------------------

    def pytest_runtest_logreport(self, report) -> None:
        self.started.add(report.nodeid)
        when = getattr(report, "when", "")
        outcome = getattr(report, "outcome", "")
        if when == "setup":
            if outcome == "failed":
                self.setup_errors += 1
            elif outcome == "skipped":
                # skip marker evaluated at setup: an item-level skip
                self.outcomes["skipped"] += 1
            return
        if when == "teardown":
            if outcome == "failed":
                self.teardown_errors += 1
            return
        if when == "call":
            was_xfail = hasattr(report, "wasxfail")
            if outcome == "passed":
                self.outcomes["xpassed" if was_xfail else "passed"] += 1
            elif outcome == "skipped":
                self.outcomes["xfailed" if was_xfail else "skipped"] += 1
            elif outcome == "failed":
                # strict xfail failures surface as failed + wasxfail and
                # pytest counts them as failures in the terminal summary
                self.outcomes["failed"] += 1
                if not hasattr(report, "wasxfail"):
                    self.failed_nodeids.append(report.nodeid)
            return

    # -- session end --------------------------------------------------------

    def pytest_sessionfinish(self, session, exitstatus) -> None:
        out_path = os.environ.get("UMDR_ACCOUNTING_OUT")
        if not out_path:
            return
        # ``session.items`` holds the SELECTED items only (post -k /
        # deselection); the deselected items never enter it.
        selected = len(getattr(session, "items", []) or [])
        collected = selected + self.deselected
        started = len(self.started)
        outcomes_total = sum(self.outcomes.values())
        errors_total = (self.setup_errors + self.teardown_errors
                        + self.collection_errors)
        interrupted = int(exitstatus) == 2  # pytest.ExitCode.INTERRUPTED
        not_started = selected - started
        data = {
            "schema": "pytest-accounting/v1",
            "collected_items": collected,
            "collection_errors": self.collection_errors,
            "collection_skips": self.collection_skips,
            "deselected": self.deselected,
            "started_items": started,
            "not_started": not_started,
            "outcomes": dict(self.outcomes),
            "outcomes_total": outcomes_total,
            "setup_errors": self.setup_errors,
            "teardown_errors": self.teardown_errors,
            "errors_total": errors_total,
            "interrupted": interrupted,
            "exitstatus": int(exitstatus),
            "failed_nodeids": self.failed_nodeids,
            "invariants": {
                "collected_eq_started_plus_not_started_plus_deselected":
                    collected == started + not_started + self.deselected,
                "started_eq_outcomes_plus_setup_errors":
                    started == outcomes_total + self.setup_errors,
                "errors_total_decomposes":
                    errors_total == (self.setup_errors
                                     + self.teardown_errors
                                     + self.collection_errors),
                "not_started_zero_unless_interrupted":
                    not_started == 0 or interrupted,
            },
        }
        data["invariants_all_true"] = all(data["invariants"].values())
        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
                fh.write("\n")
        except OSError:
            # The runner fail-closes on a missing accounting file; a
            # plugin write error must never silently pass.
            raise


def pytest_configure(config) -> None:
    config._umdr_accounting = AccountingPlugin()
    config.pluginmanager.register(config._umdr_accounting,
                                   "umdr_accounting_plugin")

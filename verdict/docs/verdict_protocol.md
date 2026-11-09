# The Verdict Protocol v1.0

A 47-day measurement protocol for answering one question before any
real bug-bounty run: **does this tool actually work?** The protocol is
pre-registered (predictions on day 0, checked on day 46, no
reinterpretation), measured (every claim traces to a state field), and
honest (classifications are immutable once written).

## Structure

The protocol has 47 entries and three phases:

| Days | Phase | What happens |
|---|---|---|
| 0 | setup | freeze targets, write pre-registration + predictions |
| 1 | targets | select and validate the 3 real targets |
| 2 | run | first live run (launch + backup + checkins) |
| 3-4 | run | stop, backup, verify |
| 5-13 | analysis | findings, classification, cross-analysis |
| 14 | selection | select exactly 5 submissions |
| 15 | submission | prepare reports, screenshots, record submissions |
| 16 | watch | open the tracker; submissions go live |
| 17-45 | watch | daily tracker updates (status per finding) |
| 46 | verdict | metrics report + final verdict (GO / GO_CAUTIOUS / IMPROVE / NO-GO) |

Every day is a checklist of filesystem and state predicates — the tool
records what the operator did; it never runs tools or touches targets.

## The Verdict decision table (day 46)

Computed from tracked submission outcomes only:

| Accepted | Under review | Duplicates | Verdict |
|---|---|---|---|
| >= 3 | — | — | GO — tool is validated |
| 2 | — | — | GO_CAUTIOUS |
| 1 | >= 2 | — | IMPROVE — wait for more data |
| 1 | < 2 | — | IMPROVE — core quality |
| 0 | — | >= 3 | IMPROVE — too many duplicates |
| 0 | — | < 3 | NO-GO — core needs redesign |

## Metrics

`verdict metrics` reports: total findings, confirmed count, FP rate,
submitted / accepted / rejected / duplicates, acceptance rate,
time-to-first-finding (hours), time-to-first-accepted (days), and the
pre-registered prediction ranges with an accuracy check per range.

## CLI

```
verdict init|status|day|pre-registration|targets|run|findings|
analysis|select|submit|watch|verdict|export
```

`verdict --help` lists every command; `verdict day --list` walks all
47 days.

## Guarantee

No auto-submission: the submission pipeline writes reports and records
outcomes, and a source-level test (`test_no_auto_submission`) asserts
the module contains no network code and no submit/send/post/upload
methods. The human submits; the tool remembers.

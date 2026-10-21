# Review Results — Subsystem Groups (Option A)

Per-subsystem working files for the alumina-proxy red-team + regression review
(`alox-f`, window `8b0bd5b6..220104c`, 24 commits). Each file combines that
subsystem group's **TRUE POSITIVE** scorecard rows (verbatim from the pruned
`scorecard.md`) with the working descriptions needed to act on them.

## Source references

| Artefact | Path | Role |
|---|---|---|
| Pruned scorecard (76 TP rows) | `~/.ooda/alox-scorecard/scorecard.md` | Verbatim TP rows + evidence |
| Pre-prune backup (111 rows, incl. FP evidence) | `~/.ooda/alox-scorecard/scorecard.md.bak` | FP context only |
| Raw findings (wave-by-wave descriptions) | `~/code/alox-f.md` | Working descriptions |
| Canonical finding IDs | `~/.ooda/alox-scorecard/findings-index.md` | ID registry |

## Group files

| # | Group | TP | File |
|---|---|---|---|
| 1 | DNS parsing/validation | 8 | `01-dns-parsing-validation.md` |
| 2 | DoT/TLS transport | 5 | `02-dot-tls-transport.md` |
| 3 | CONNECT & ClientHello parsing | 5 | `03-connect-clienthello-parsing.md` |
| 4 | Resolver & config data model | 10 | `04-resolver-config-data-model.md` |
| 5 | Scheduler & cache | 5 | `05-scheduler-cache.md` |
| 6 | Failover/degradation state machine | 2 | `06-failover-degradation-state-machine.md` |
| 7 | Zero-allocation invariant | 10 | `07-zero-allocation-invariant.md` |
| 8 | Tooling/CI/scripts | 5 | `08-tooling-ci-scripts.md` |
| 9 | Docs/doc-drift | 9 | `09-docs-doc-drift.md` |
| 10 | Test/coverage gaps | 9 | `10-test-coverage-gaps.md` |
| 11 | Robustness/telemetry | 3 | `11-robustness-telemetry.md` |

## Deduplication note

Five findings were reported twice by independent scans (same root cause, two
IDs). Each group file lists the duplicate row **once** under its canonical ID
and marks the collapsed row with a pointer to the canonical ID:

| Collapsed (duplicate) | Canonical |
|---|---|
| W5-L5a-F2 | W4-L4a-F2 |
| W5-L5a-F3 | W4-L4a-F3 |
| W7-H7b-F1 | W5-H5b-F1 |
| W7-H7b-F2 | W5-H5b-F2 |
| W7-H7b-F3 | W5-H5b-F3 |

71 unique findings across 76 scorecard rows (5 duplicate rows collapsed).

## Row format

Scorecard rows are reproduced verbatim:

`| ID | Severity | Location | TRUE POSITIVE | pass-tally | confidence | evidence |`

Verdict = majority of 5 passes (`TRUE POSITIVE`). Rust findings were scored by
`linus`; tooling/docs/test findings by `general`. Repo was READ-ONLY during
scoring.

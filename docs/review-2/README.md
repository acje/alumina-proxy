# Review 2 Results — Subsystem Groups

Second red-team pass on the alumina-proxy SNI-filtering explicit forward proxy.
Each canonical candidate was voted by **5 independent subagents** (TP / FP /
INDETERMINATE); majority-FP candidates were discarded. This directory holds the
aggregated **KEPT** findings per subsystem group, with the verified facts needed
to act on them.

Repo and spec (`docs/alumina-proxy.md`) were **READ-ONLY** throughout; all
candidate and vote artefacts live under `.ooda/review2/` (gitignored).

## Source references

| Artefact | Path | Role |
|---|---|---|
| Dedup manifests (canonical rows + verified-clean registers) | `.ooda/review2/dedup/g1.md`..`g11.md` | Canonical severity/location/fix-target/summary per candidate |
| Verdict files (raw tally + verified facts + dissenting view) | `.ooda/review2/votes/<candidate>/verdict.md` | Per-candidate 5-voter verdict |
| Voter ballots | `.ooda/review2/votes/<candidate>/voter1.md`..`voter5.md` | Individual TP/FP ballots |
| Immutable spec | `docs/alumina-proxy.md` | Byte-canonical governing specification |
| Prior review (Option A) | `docs/review/` | First-pass TP rows + working descriptions |

## Group files

| # | Group | KEPT | File |
|---|---|---|---|
| 1 | DNS parsing/validation | 3 | `g1.md` |
| 2 | DoT/TLS transport | 3 | `g2.md` |
| 3 | CONNECT & ClientHello parsing | 5 | `g3.md` |
| 4 | Resolver & config data model | 4 | `g4.md` |
| 5 | Scheduler & cache | 5 | `g5.md` |
| 6 | Failover/degradation state machine | 3 | `g6.md` |
| 7 | Zero-allocation invariant | 4 | `g7.md` |
| 8 | Tooling/CI/scripts | 10 | `g8.md` |
| 9 | Docs/doc-drift | 18 | `g9.md` |
| 10 | Test/coverage gaps | 16 | `g10.md` |
| 11 | Robustness/telemetry | 4 | `g11.md` |

**Total KEPT: 75** (of 158 canonical candidates; 83 discarded as majority-FP).

## Severity normalization

Manifest severities were normalized at aggregation: `Low` → `Info`. Final mix:
**High ×1, Medium ×16, Info ×58**.

- **High (1):** G8-C02 (gate runs only `--test foundations|boot`; lib units +
  5 of 7 integration binaries never executed; `docs/verification.md:18` full
  suite unexecuted).
- **Medium (16):** G7-C01, G7-C05, G7-C10; G9-C01, G9-C03, G9-C04, G9-C06,
  G9-C07, G9-C08; G10-C02, G10-C03, G10-C11, G10-C13, G10-C14, G10-C19; G11-C01.
- **Info (58):** all remaining KEPT findings.

## Cross-group merges (at aggregation)

Independent scans reported the same root cause under multiple canonical IDs.
Each family is listed **once** under its primary ID in the group files; the
collapsed rows carry a pointer to the primary ID:

| Collapsed (duplicate) | Primary (family) |
|---|---|
| G2-C09, G6-C01 | G1-C09 — `dp=` downgrade counter misses failback-begin relocation |
| G9-C02, G9-C09 | G5-C10 — refresh-band `30 / 300` stale in derived docs + spec-body facet |
| G9-C14 | G9-C03 — DoT non-goal staleness (architecture §9 / build-plan §7) |
| G9-C12 | G9-C06 — "first NS, port 53" stale rows (architecture / traceability) |
| G8-C22 | G8-C10 — supply-chain-gate reproducibility (observe + enforce) |

68 unique findings across 75 KEPT rows (7 collapsed).

**Kept distinct (deliberately not merged):** G8-C02 vs G8-C12 (coverage gap vs
doc-authority); G8-C13 vs G8-C19; G10-C13 vs G10-C03 (response-header gates
untested — cross-referenced; C13 also flags C14/C15 as sibling `:233`-mandated
gaps).

## Row format

Each group file reproduces the canonical row (severity / location / fix target /
summary) followed by the working description and verified facts from the
5-voter verdict, plus the recommended fix target (`code` | `spec` | `doc` |
`none`) and any spec deviation. Verdict = majority of 5 independent voters
(`TRUE POSITIVE` kept; majority-FP discarded). Repo was READ-ONLY during voting.

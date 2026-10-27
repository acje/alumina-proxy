# Alumina on an e2-micro class VM — workload profiles, baseline and optimizations

> **Honest context.** This page documents the new e2-micro workload surface
> (steady 1 Gbit/s + connection-churn storms at 150/s and 50/s), the baseline
> measured at HEAD `dc54638` (harness commits `117a224`/`b1de21c`/`dc54638`,
> proxy release binary `b441a5ae…`), the R1 optimized result (commit `b3b1ebc`),
> a tried-and-reverted negative result (G8 read-pacing group), the WS-A
> R2–R4 follow-up (tried/blocked, none retained; R5/R6 not executed), and the
> unsafe-cleanup A/B on the legacy 100 Mbps contract (before `867dd43` vs after
> `435eb66`, Option A cipher storage). e2-micro
> equivalence is modeled by **workload parameters only** — never by capping the
> shared harness container's CPU/memory, because the client, backend and DNS
> responder run inside the same container and a cap would confound client
> saturation into a false proxy deficit (see
> [Methodology — honest e2-micro modeling](#methodology--honest-e2-micro-modeling)).
> All per-test gains in this document are **same-session interleaved A/B only**,
> never clean cumulative sums; receipts are cited inline and live under
> `.ooda/benchmarks/`.

## e2-micro workload profiles & invocation

The e2-micro profiles are selected by the optional 3rd positional argument of
`scripts/seam_echo.sh` (harness epic `alumina-eryh`, WS-B). The supervisor
needs a freshly built current-HEAD binary at `.ooda/alumina-head/baseline/
alumina-musl`, pinned by `HEAD_CANDIDATE_SHA` (shipped in `seam_echo.sh`) —
`head` fails closed (`SEAM-BLOCKED`) when the SHA does not match, so an
unverified binary can never be measured:

```sh
sh scripts/seam_echo.sh head <smoke|timed> e2micro1gbps        # steady, 32 conns, 1000 Mbps
sh scripts/seam_echo.sh head <smoke|timed> e2microrstorm150     # 150 HTTP CONNECT+TLS1.3 sessions/s
sh scripts/seam_echo.sh head <smoke|timed> e2microrstorm50      # 50 sessions/s
```

An empty 3rd argument keeps the legacy fixed 100 Mbps contract (backward
compatible). `smoke` uses
2 s warmup / 0 s measure; `timed` uses 5 s warmup / 60 s measure. Receipts are
written to `.ooda/benchmarks/<stamp>-…Z.json` where `<stamp>` is the
`<short-head>-seam-head-<workload>-<kind>-<ISO-time>` prefix.

### New client flags (workload engine, `seam_echo.py`)

The profile selectors forward these client flags:

| Profile | Forwarded flags |
| --- | --- |
| `e2micro1gbps` | `--workload steady --conns 32 --target-mbps 1000 --outstanding-cap 2048` |
| `e2microrstorm150` | `--workload storm --arrival-rate 150 --session-frames-min 4 --session-frames-max 16` |
| `e2microrstorm50` | `--workload storm --arrival-rate 50 --session-frames-min 4 --session-frames-max 16` |

The workload engine adds a `--workload steady|storm` mode switch, an open-loop
`--arrival-rate` (storm sessions/s), an `--outstanding-cap` (steady: 2 048
frames / 8 MiB open-loop ceiling, exhaustion = explicit unsent, never catch-up),
a high persistent-connection count `--conns 32` (vs the legacy 8), a `--target-mbps
1000` rate target, and storm burst bounds `--session-frames-min/max`.

### New storm report fields

The storm receipts add a `storm:` block and a `latency.setup_latency`
histogram, distinct from the legacy steady report:

- `arrivals_planned` vs `arrivals_attempted` vs `connections_established` —
  connections established against planned arrivals (deficit = planned −
  established).
- `setup_failures` (map keyed by failure reason; `{}` = none) and
  `deferred_unstarted` / `unaccounted` — setup timeouts and unaccounted
  sessions.
- `peak_live` / `peak_dialing` — peak concurrent established sessions and
  peak concurrent dialing (live-concurrent peak is guarded at 300, far below
  the fixed 512-tunnel pool).
- `protocol_errors`, `missing_bytes_errors`, `sessions_completed` — byte-exact
  echo integrity.
- `latency.setup_latency` p50 / p99 / max (+ `overflow_count`) histogram for
  CONNECT+TLS1.3 setup, alongside the existing `actual_send_to_echo` echo-latency
  histogram.

## Methodology — honest e2-micro modeling

- **Open-loop client rate control, achieved not claimed.** The client
  schedules every frame on `--interval_s` and caps in-flight with
  `--outstanding-cap`; reported throughput is the measured
  `achieved_client_payload_mbps` in the receipt, not the configured target.
- **e2-micro modeled via workload parameters, not container capping.** 1 Gbit/s
  of open-loop traffic (steady) and connection churn of 150/s and 50/s (storm)
  reproduce the e2-micro class envelope. The shared harness container also runs
  the client, backend and DNS responder, so imposing a cgroup CPU/memory cap on
  the container would throttle the client's own send loop and misattribute a
  client-side saturation as a proxy deficit. The receipt carries this disclosure
  verbatim in `e2micro_model.note`.
- **Host vs target disclosure.** Measurements run on the shared harness host —
  arm64 Apple-VM, 4 CPU / 14 GiB, loopback-only network (`net+PID ns` on
  `flock-vm-root`, loopback global-unicast alias) — against the e2-micro target
  spec of **2 shared vCPU / 1 GB RAM / up to 1 Gbit/s**. Host headroom (4 host
  CPUs) is explicitly not e2-micro-equivalent; see the ROI caveat under
  [R1 optimized result](#r1-optimized--storm150-interleaved-ab).
- **Honest fit-to-1GB.** The proxy's sampled VmRSS is flat at ~209 316–209 324
  KB ≈ 204 MiB across every receipt, of which the fixed
  **512 × 2 × 128 KiB traffic slab = 128 MiB** is structural inventory (the
  binary's startup log reports a named fixed-buffer lower bound consistent with
  observed VmRSS). 204 MiB sits comfortably under the 1 GiB e2-micro budget,
  even before accounting for tuned memory; the 128 MiB slab is a fixed compile
  profile, not a leak (alloc-witness green at each landed commit).

## Baseline at HEAD `dc54638` (proxy binary `b441a5ae…`)

All-baseline sessions are `valid=True / verdict=valid` with 0 protocol errors,
0 missing-byte errors, 0 setup failures and RSS mean = peak (no drift within the
60 s window):

| Workload (kind) | Planned → established | Interval deficit | Setup latency p50 / p99 / max | Echo `actual_send_to_echo` p50 | Proxy CPU mean / peak | Proxy RSS |
| --- | --- | --- | --- | --- | --- | --- |
| storm150 (timed, 60 s) | 9000 → 9000 | 0 (`setup_failures {}`, `missing_bytes_errors 0`, `unaccounted 0`) | 3850 / 4950 / 19009 µs | 40950 µs | 0.0570 / 0.1198 cores | 209 320 KB |
| storm50 (smoke, 2 s) | 100 → 100 | 0 | 6850 / 8850 / 8890 µs | 41350 µs | 0.0300 / 0.0775 cores | 209 316 KB |
| 1gbps (timed, 60 s) | — | ≈ 0 (measure `offered_unsent 1`, `missed_at_end 0`) | — | 1250 µs | 0.3098 / 0.3600 cores | 209 316 KB |

Receipts:

- storm150 timed — `.ooda/benchmarks/dc54638-seam-head-e2microrstorm150-timed-20261018T144707Z.json` (dirty=0). This is the **primary storm anchor**: `achieved` 9000/9000, `peak_live 10`, setup p50/p99/max 3850/4950/19009 µs, echo p50 40950 µs, proxy CPU mean/peak 0.0570/0.1198, RSS 209 320 KB.
- storm50 smoke — `.ooda/benchmarks/dc54638-seam-head-e2microrstorm50-smoke-20261018T144247Z.json`: 100/100. The storm50 timed baseline was not the primary anchor; storm150 is anchor for the storm class.
- 1gbps timed — `.ooda/benchmarks/dc54638-seam-head-e2micro1gbps-timed-20261018T144820Z.json` (dirty=0): `achieved_client_payload_mbps 999.9925` (≈ 1000 Mbps), echo p50 1250 µs, proxy CPU mean 0.3098 cores, RSS 209 316 KB. The 1gbps smoke receipt (`.ooda/benchmarks/dc54638-seam-head-e2micro1gbps-smoke-20261018T144252Z.json`) shows the same echo p50 and ≈ 0.31 cores.

## R1 optimized — storm150 interleaved A/B

**R1** = commit `b3b1ebc` ("worker: O(1) storm admit/occupied/pending counters +
free-slot min-heap", candidates C21+C22+C23), parent `dc54638`, linus
adversarial review **APPROVE** (review-report bead `alumina-psbj`, review
`alumina-zmkb`, `review:tier=adversarial`). The candidate (binary
`fa47cfbc…`) replaces ~9 × O(512) slot scans per connect lifecycle
(admit/note_occupancy/release/drain) with boot-retained O(1) counters and a
fixed free-slot min-heap, preserving the exact lowest-index allocation order.

Same-session interleaved A/B order B1, B2, C1, B3, C2 on storm150 — all
sessions `valid=True`, `workload_fulfilled=True`, 9000/9000 (B2: 9150/9150), 0
protocol errors, 0 deficit, setup p50 3850 µs and echo p50 40950 µs flat, RSS
209 320–209 324 KB flat:

| Session | Binary | Runtime identity | Proxy CPU mean | Receipt |
| --- | --- | --- | --- | --- |
| B1 (baseline) | `b441a5ae…` | head `dc54638`, dirty 0 | 0.0570 | `dc54638-…-e2microrstorm150-timed-20261018T144707Z.json` |
| B2 (baseline) | `b441a5ae…` | head `dc54638`, dirty 2 | 0.0564 | `dc54638-…-e2microrstorm150-timed-20261018T150402Z.json` |
| C1 (candidate) | `fa47cfbc…` | head `dc54638`, dirty 2 | 0.0555 | `dc54638-…-e2microrstorm150-timed-20261018T150536Z.json` |
| B3 (baseline) | `b441a5ae…` | head `dc54638`, dirty 2 | 0.0558 | `dc54638-…-e2microrstorm150-timed-20261018T150645Z.json` |
| C2 (candidate) | `fa47cfbc…` | head `dc54638`, dirty 2 | 0.0550 | `dc54638-…-e2microrstorm150-timed-20261018T150755Z.json` |

(B2/B3/C1/C2 were measured with the uncommitted two-file diff in the working
tree — `dirty 2` — against the pinned binary per row; commit `b3b1ebc`
contains exactly that diff and clean-tree rebuilds to the measured candidate
binary `fa47cfbc37e6…`.)

Result:

- Candidate mean ≈ **−2%** (0.0550–0.0555 vs 0.0558–0.0570); adjacent-pair
  deltas C1 vs B2 ≈ −1.6%, C2 vs B3 ≈ −1.4%. Candidate CPU mean sits below
  every baseline session → **6/6 directional agreement**, zero regression on
  any other metric.
- **ROI caveat.** The absolute magnitude is tiny — the whole storm anchor is
  ~0.055–0.057 of one core on a 4-core host, i.e. huge headroom — so micro-CPU
  options in this class have limited cost/benefit at this host's load. These
  are same-session interleaved A/B comparisons only; absolute cross-session
  swing is large.
- 1gbps secondary read (candidate `fa47cfbc…`, receipt `dc54638-…-e2micro1gbps-timed-20261018T150905Z.json`): achieved 999.9925 Mbps (identical to baseline), echo p50 1250 µs, sustained CPU mean ≈ 0.292 excluding a single first-interval startup spike (raw `cores_peak 6.31` = one `interval[0]` sample) vs baseline 0.3098; RSS 209 324 KB flat.

## G8 read-pacing group — tried and reverted (honest negative result)

Do **not** read this section as shipped. The G8 group (candidate scoring in
evidence bead `alumina-i4od`: `C41 READ_CHUNK 32→64 KiB` + `C8 full-remainder
first read` + `C9 reserve-budget`, all `serving.rs` read/relay pacing) was
implemented on top of `b3b1ebc`, measured at 1gbps, found CPU-neutral with a
leaning-worse tail, then **reverted — tree restored, no commit, no retained
binary**.

Six valid timed 1gbps receipts at `source_head b3b1ebc` (uncommitted diff,
`dirty 2`), interleaved baseline binary `b441a5ae…` vs G8 candidate binary
`fbf47e4c…`:

| Session | Binary | Echo p50 / p99 / max (µs) | Proxy CPU mean | Achieved Mbps | Receipt |
| --- | --- | --- | --- | --- | --- |
| 1 (baseline) | `b441a5ae…` | 1250 / 3950 / 10999 | 0.3105 | 999.9985 | `b3b1ebc-…-e2micro1gbps-timed-20261018T152536Z.json` |
| 2 (candidate) | `fbf47e4c…` | 1250 / 4750 / 47837 | 0.3132 | 999.9931 | `b3b1ebc-…-e2micro1gbps-timed-20261018T152646Z.json` |
| 3 (baseline) | `b441a5ae…` | 1250 / 4650 / 33821 | 0.3128 | 999.9876 | `b3b1ebc-…-e2micro1gbps-timed-20261018T152756Z.json` |
| 4 (candidate) | `fbf47e4c…` | 1250 / 4350 / 13385 | 0.3083 | 999.9821 | `b3b1ebc-…-e2micro1gbps-timed-20261018T152906Z.json` |
| 5 (baseline) | `b441a5ae…` | 1250 / 9150 / 214933 | 0.3080 | 997.9412 | `b3b1ebc-…-e2micro1gbps-timed-20261018T153043Z.json` |
| 6 (candidate) | `fbf47e4c…` | 1250 / 5850 / 47156 | 0.3143 | 999.9980 | `b3b1ebc-…-e2micro1gbps-timed-20261018T153153Z.json` |

Verdict from the receipts:

- **CPU neutral** — baseline mean 0.3104 cores (0.3105/0.3128/0.3080) vs G8
  candidate mean 0.3119 (0.3132/0.3083/0.3143): the read-pacing change made
  per-byte CPU slightly worse, not better, at the 1gbps steady load.
- **Tail leans worse** — echo p99 4350–5850 µs (candidate) vs 3950–9150 µs
  (baseline) is mixed, and the two largest maxima sit on candidate sessions
  (47.8 ms, 47.2 ms). The single 214.9 ms baseline max corresponds to a
  contended interval (`cores_peak` ≈ 5.96 on that session), an aperture
  artifact rather than a stable tail.
- **Throughput maintained** — achieved 999.98–999.998 Mbps in five of six
  (997.94 Mbps in the one contended-baseline session); no regression in
  offered rate.

Because CPU was neutral-to-worse and the tail signal did not improve under the
hoped-for read-size amortization, the group was reverted and no commit exists —
the receipts above are the honest record of a negative result.

## WS-A follow-up (R2–R9): parser/micro-opt seams are gate-insensitive — closed out at proxy-headroom

The WS-A follow-on seams (epic `alumina-eryh`, R2–R9) are results, not shipped
optimizations: every R2–R4 candidate was tried and none retained, and R5/R6 were
never executed. Numbers below are recovered only from the receipt set
`.ooda/benchmarks/c5800c6-seam-head-e2microrstorm150-timed-*.json` (6 timed
receipts at `source_head c5800c6`, each seam an uncommitted diff, `dirty 3`) and
the fleet-opportunity bead `alumina-tpia`. All 6 receipts are `valid=True`,
`workload_fulfilled=True`, 9000/9000 planned→established, 0 protocol errors,
0 missing-byte errors, `setup_failures {}`.

### R2/R3/R4 — tried and reverted / blocked (no seam landed)

| Seam | Verdict | Receipt-cited outcome |
| --- | --- | --- |
| R2 — getpeername removal | TRIED + REVERTED — neutral | storm150 setup p50 pin-locked 3750 µs, p99 4850–5150 µs noise, CPU mean ~0.048 cores flat, RSS +32 KB (209 352 vs 209 320 KB) on the R2 head runs |
| R3 — slot-reset cursor-only (per-reset memset skip) | TRIED + REVERTED — neutral | identical storm150 setup p50/p95 3750/4550 µs, CPU flat; ~1.22 GB memset skipped across the session moved nothing |
| R4 — ClientHello single-copy | BLOCKED — no measured result | true single-copy needs a new dual-parse-site invariant with consumed-math coupling; trial reverted to HEAD (no change landed) |

R5 (allowlist ordinal) and R6 (CONNECT head-parse fold) were **NOT EXECUTED**;
they are halted and deferred to the re-instrumented microbenchmark epic
`alumina-tpia`.

### Empirical finding — the storm150 gate cannot resolve parser/micro-opt seams

Across the head receipt set, storm150 setup latency is pin-dominated: **p50
3750 µs in every receipt**, p95 4550 µs flat, p99 only 4850–5150 µs (±~200 µs
noise) and max 10.3–22.5 ms (±~10 ms) — far larger than any claimed R2–R6 gain.
End-to-end latency gates are **insensitive to instruction-count wins**: parser/
read-path micro-optimizations (cursor math, single-copy, memsets, digit folds)
are invisible to this gate, so future response-time claims need a
machine-instruction-count instrument (`alumina-tpia`).

### Proxy-headroom conclusion

Across R1..R4 the proxy used **~0.057 cores (storm150)** / **~0.31 cores
(1gbps)** of an e2-micro 2-CPU VM — large headroom under the 2-vCPU budget.
Only R1 (`b3b1ebc`, ~2% CPU) was kept; every follow-on parser/micro-opt
candidate (R2/R3/R4) was neutral-or-worse and is being closed out (D1). WS-A
halts at this proxy-headroom conclusion rather than a new optimization.

## Unsafe-cleanup A/B — legacy 100 Mbps contract (Option A)

The unsafe-cleanup roadmap (`docs/alox-unsafe-plan.md`) removed the `unsafe`
surface from two files down to one (`src/alloc.rs`, kept by design). The perf
guard for the Option A cipher-storage change (inc2, `03f70c1`) specifies a
Linux `perf stat -e cycles` A/B arbiter, but the shared `flock-vm` exposes
**no hardware counters** (emulated CPU, empty `perf list hw`; `cycles` and
`instructions` are unsupported even with `--privileged`), so the cycles gate is
unmeasurable in this environment. The recorded proxy is this same-session
interleaved A/B on the **legacy fixed 100 Mbps contract** — 8 conns, 4096 B
frame + 12 B header counted separately, open-loop 100 decimal Mbps client
payload, 5 s warmup / 60 s measure, setup/drain 5 s each (`seam_echo.sh head
timed`, empty workload selector).

Binaries are pinned by sha256 and verified by the harness's fail-closed sha
gate before measurement:

| Side | Source commit | Binary sha256 |
| --- | --- | --- |
| A (before) | `867dd43` (parent of Option A, inc2) | `40c7209207c2…` |
| B (after) | `435eb66` (current HEAD, all five increments) | `b80c39e6fb60…` |

Interleaved order A1, B1, A2, B2, A3, B3, A4, B4 (n = 4 per side). Every
session is `valid=True / verdict=valid` with byte-exact echo
(`echoed == sent == admitted`) and 0 protocol / missing-byte / send-failed /
timeout / connection errors. Receipts are stamped with the harness's
current-HEAD `435eb66` regardless of measured binary; binary identity is
carried in `executed_binary_sha256`:

| Session | Binary | Achieved Mbps | Echo p50 / p95 / p99 / max (µs) | Proxy CPU mean / peak | Receipt |
| --- | --- | --- | --- | --- | --- |
| A1 | `40c72092…` | 99.8048 | 2850 / 3650 / 3950 / 58299 | 0.0620 / 0.1200 | `435eb66-…-140820Z.json` |
| B1 | `b80c39e6…` | 99.9457 | 2850 / 3750 / 4150 / 15076 | 0.0690 / 0.1600 | `435eb66-…-140934Z.json` |
| A2 | `40c72092…` | 99.9987 | 2750 / 3050 / 3250 / 4105 | 0.0365 / 0.0800 | `435eb66-…-141043Z.json` |
| B2 | `b80c39e6…` | 99.8457 | 2850 / 3950 / 4450 / 23808 | 0.1322 / 0.1998 | `435eb66-…-141152Z.json` |
| A3 | `40c72092…` | 99.9020 | 2850 / 3950 / 4450 / 21724 | 0.1348 / 0.2000 | `435eb66-…-141348Z.json` |
| B3 | `b80c39e6…` | 99.8976 | 2850 / 3950 / 4550 / 17321 | 0.1316 / 0.1999 | `435eb66-…-141459Z.json` |
| A4 | `40c72092…` | 99.8064 | 2850 / 3950 / 4550 / 30815 | 0.1328 / 0.2000 | `435eb66-…-141607Z.json` |
| B4 | `b80c39e6…` | 99.9522 | 2850 / 3950 / 4450 / 14047 | 0.1342 / 0.2000 | `435eb66-…-141716Z.json` |

Result (medians, n = 4):

- **Throughput flat** — achieved median 99.8542 (A) vs 99.9216 (B) Mbps; every
  session 99.80–100.00 Mbps. No regression at the 100 Mbps contract.
- **Latency flat** — echo p50 2850 µs on both sides; p99 4200 (A) vs 4450 (B)
  µs, inside the 3250–4550 µs interleaved band.
- **CPU mean is host-contention noise, not a change signal** — median 0.0974
  (A) vs 0.1319 (B) cores, but the before-side lows sit only in the first two
  sessions (A1 0.0620, A2 0.0365) before the shared host busied up; from B2
  onward every session is ~0.13 cores. The co-located pairs are flat (A3 0.1348
  vs B3 0.1316; A4 0.1328 vs B4 0.1342). Absolute magnitude is ≤ 0.13 cores on
  a 4-core host — the same proxy-headroom regime as the R1 / WS-A sections.
- **RSS flat** — 210 556 KB in every session, both trees (no A/B delta; ~1.2
  MiB above the `dc54638` baseline's 209 316–209 324 KB, present in both trees
  and not attributable to the A/B).

Honest notes:

- `workload_fulfilled=False` in every session because the open-loop client
  briefly hit the 4 MiB outstanding cap (`backpressure_unsent` 0–357,
  `offered_unsent` 0–3 in the measure phase). This is client-side open-loop
  backpressure, not a proxy deficit — echo integrity is byte-exact and no
  failure counter is non-zero.
- This A/B is the recorded proxy for the unmeasurable Linux `cycles` gate; it
  does not resolve the memset-cost question (the plan's macOS fallback is
  "smoke only, never a gate"). The noise-free falsifier — memsets survive at
  opt3 as `_bzero` and the JA4 fingerprint is byte-identical before/after — is
  satisfied independently of this benchmark.

## Feature comparison — before/after unsafe-cleanup

| Feature / result | Before (`867dd43`) | After (`435eb66`) |
| --- | --- | --- |
| `unsafe` surface | 2 files: `src/alloc.rs` (9), `src/log.rs` (3) | 1 file: `src/alloc.rs` (7, S2 kept by design) |
| Cipher storage (Option A, inc2) | `MaybeUninit<u16>` + raw-parts helpers | initialized `[u16; MAX_CIPHERS]` + length; helpers deleted |
| Log sink (Option D, inc4) | libc `writev` FFI, raw fd, `set_fd_nonblocking` | std-only `SinkIo::write_vectored`, owned `UnixStream` |
| DoT reuse identity (S7, inc5) | `&*conn.tls as *const _ as usize` | typed `std::ptr::addr_eq` |
| `libc` dependency | runtime `[dependencies]` | `[dev-dependencies]` only |
| **100 Mbps achieved (new result)** | **99.8542 Mbps median** | **99.9216 Mbps median** |
| **100 Mbps echo p50 (new result)** | **2850 µs** | **2850 µs** |
| **100 Mbps proxy CPU mean (new result)** | **0.0974 cores (host-noise band)** | **0.1319 cores (host-noise band)** |
| RSS | 210 556 KB | 210 556 KB |

The pre-roadmap state (parent `598cbf5`) had `unsafe` in four files; inc1 (F5,
`867dd43`) had already removed `src/client_hello.rs`, so the A/B before side
starts at two files.

## Workload & measurement parameters

| Parameter | e2micro1gbps | e2microrstorm150 | e2microrstorm50 |
| --- | --- | --- | --- |
| Workload mode | steady | storm | storm |
| Payload frame | 4096 B payload + 12 B header (counted separately) | 4–16 frames/session | 4–16 frames/session |
| Open-loop rate | 1000 decimal Mbps (`target_mbps 1000`) | arrival 150 sessions/s | arrival 50 sessions/s |
| Persistent / concurrent | 32 conns (`--conns 32`) | live-concurrent peak guarded 300 | live-concurrent peak guarded 300 |
| Outstanding cap (steady) | 2048 frames / 8 388 608 B | — | — |
| Warmup / window / setup+drain | 5 s / 60 s / 5 s (smoke: 2 s / 0 s) | 5 s / 60 s / 5 s (smoke: 2 s / 0 s) | 5 s / 60 s / 5 s (smoke: 2 s / 0 s) |
| Endpoint | Real TLS 1.3 byte-exact framed-echo backend, `example.com` (genuine CA + SAN) | same | same |
| Measurement aperture | explicit start/end boundary ticks; boundary lag and drain remainder disclosed (not exact scheduled-window isolation) | same | same |

## Candidate scope / identity

Shared harness/host: pinned `localhost/alumina-e2e:e2e-20261011`
(harness image `9191d288…`, parent `ad70ceb9…`) on `flock-vm-root`;
`aarch64-unknown-linux-musl` release binaries; uid 65534 via `setpriv`; DNS
over TCP responder with CONNECT allowlist + `[any_illegal] flare_only` memo
(cfg `b00d4c32…`).

| Attribute | Baseline | R1 candidate | G8 candidate (reverted) | Unsafe A (before) | Unsafe B (after) |
| --- | --- | --- | --- | --- | --- |
| Binary | `b441a5ae8947…` (deterministic release build) | `fa47cfbc37e6…` (clean rebuild of `b3b1ebc`) | `fbf47e4c74b5…` (uncommitted G8 diff on `b3b1ebc`) | `40c7209207c2…` (rebuild of `867dd43`) | `b80c39e6fb60…` (rebuild of `435eb66`) |
| Measured receipts | `dc54638-…-timed-20261018T144707Z` (storm150), `…T144247Z` (storm50 smoke), `…T144820Z` (1gbps) | storm150 `…T150536Z` / `…T150755Z`, 1gbps `…T150905Z` | six `b3b1ebc-…-e2micro1gbps-timed-20261018T152…Z` receipts | four `435eb66-…-140820Z` / `…141043Z` / `…141348Z` / `…141607Z` (100 Mbps timed) | four `435eb66-…-140934Z` / `…141152Z` / `…141459Z` / `…141716Z` (100 Mbps timed) |
| Landing commit | — | `b3b1ebc` (perf, linus adversarial APPROVE `alumina-psbj`) | none (reverted, tree restored) | `867dd43` (before Option A) | `435eb66` (HEAD) |
| RSS (all) | 209 316–209 324 KB ≈ 204 MiB | same | same | 210 556 KB | 210 556 KB |

Receipt JSON files live under `.ooda/benchmarks/` (gitignored local evidence);
the numbers above are extracted from the cited receipt fields, not from the
rounded brief.

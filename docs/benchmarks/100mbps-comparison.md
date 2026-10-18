# Alumina ae9bdb4 vs HAProxy 3.2.25 vs Envoy 1.39.4 — 100 Mbps matched comparison

> **Honest context (post-optimization end-state).** The Alumina column now reports the Phase-4 post-optimization end-state at measurement HEAD **ae9bdb4** (perf-mission, 5 adversarial-approved single-parent commits: `1afc90a`, `c4441ed`, `d9679c9`, `54c73db`, `ae9bdb4`), superseding the stale pre-opt 9b9f4de figures. The candidate is a `aarch64-unknown-linux-musl` release binary `b441a5ae…` — byte-identical to a deterministic clean-tree rebuild at ae9bdb4 — supervised by `seam_echo.sh head timed` on `flock-vm-root` (harness `9191d288…`). The Alumina row is the **best-session post-opt result from a same-session interleaved A/B** (G10 candidate-B; receipt `54c73db-seam-head-timed-20261018T134417Z.json`, full A/B table in mission bead `alumina-unqq.1`): interval deficit **36** (vs pre-opt repeat 254), `actual_send_to_echo` max **12.99 ms** (vs 58.13), proxy CPU mean **0.1148** (vs 0.2027/0.2800), latency percentiles flat at ~2.75 / 3.95–4.05 / 4.25–4.45 ms, proxy RSS unchanged **209 316 KB**. Do NOT read this as a single clean cumulative sum: per-group gains were validated by same-session interleaved A/B only, and cross-session absolute swing is large (documented same-tree baselines 92 / 139 / 254 plus a contended 909 window — see mission finding bead `alumina-nfet`). The Phase-4 candidate band is deficit 36–132, `sched_to_echo` max ~12–21 ms, proxy CPU mean ~0.115–0.173. The HAProxy/Envoy columns are unchanged fresh 2026-10-18 runs from the 9b9f4de matched session. Alumina RSS is structural, not a leak: the binary's own startup inventory log reports a named fixed-buffer lower bound of 205 657 890 B (134 217 728 B traffic slab + 71 303 168 B serving workspace + DNS named buffers) plus a 2 MiB log queue, consistent with the observed VmRSS.

> **e2-micro workloads.** The new e2-micro profiles (steady 1 Gbit/s +
> connection churn 150/s and 50/s), how to run them, and their baseline /
> R1-optimized / tried-and-reverted numbers are documented separately in
> [e2micro-workload.md](e2micro-workload.md). This page keeps the legacy fixed
> 100 Mbps comparison.

## Matched results (60 s window)

| Metric | Alumina ae9bdb4 (post-opt, best-session) | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- | --- |
| Route label (client mode) | via-proxy (CONNECT) | direct-proxy (direct TLS/SNI, no CONNECT) | via-proxy (CONNECT-terminate) |
| Verdict | valid | valid | valid |
| Workload fulfilled | no | no | no |
| Achieved client payload | 99.980 Mbps | 99.956 Mbps | 99.974 Mbps |
| Planned frames / admitted | 183 105 / 183 069 | 183 105 / 183 025 | 183 105 / 183 057 |
| Sent / echoed (total) | 183 069 / 183 069 | 183 025 / 183 025 | 183 057 / 183 057 |
| In-window sent / drain-completed sent | 183 069 / 0 | 183 025 / 0 | 183 057 / 0 |
| In-window echoed / drain echoed | 183 061 / 8 | 183 017 / 8 | 183 049 / 8 |
| Interval deficit (planned − in-window sent) | 36 (backpressure 34 + missed_at_end 2) | 80 (backpressure 79 + missed_at_end 1) | 48 (backpressure 47 + missed_at_end 1) |
| Measurement-cohort never-sent slots | 36 (backpressure 34 + missed_at_end 2) | 80 (backpressure 79 + missed_at_end 1) | 48 (backpressure 47 + missed_at_end 1) |
| Errors (timeout / send_failed / conn_errors / protocol) | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| latency `actual_send_to_echo` (in-window cohort) | p50 2.75 ms, p95 3.95 ms, p99 4.45 ms, max 12.99 ms (n=183 061) | p50 2.85 ms, p95 3.95 ms, p99 4.25 ms, max 17.76 ms (n=183 017) | p50 2.85 ms, p95 3.95 ms, p99 4.35 ms, max 12.15 ms (n=183 049) |
| latency `sched_to_echo` | p50 3.15 ms, p95 4.35 ms, p99 4.65 ms, max 13.52 ms | p50 3.25 ms, p95 4.25 ms, p99 4.65 ms, max 17.90 ms | p50 3.25 ms, p95 4.35 ms, p99 4.65 ms, max 12.30 ms |
| `send_lag` (distinct population, n=in-window sent) | p50 0.35 ms, p95 1.45 ms, p99 1.65 ms, max 9.70 ms (n=183 069) | p50 0.35 ms, p95 1.35 ms, p99 1.45 ms, max 14.56 ms (n=183 025) | p50 0.35 ms, p95 1.35 ms, p99 1.45 ms, max 8.53 ms (n=183 057) |
| Proxy CPU (observed aperture) | mean 0.1148 cores, peak 0.1600 (263 core samples) | mean 0.1058 cores, peak 0.1600 (263 periodic core intervals) | mean 0.1377 cores, peak 0.2000 (263 periodic core intervals) |
| Proxy thread count (positive-only task count) | 1 (single-worker) | 1 (`nbthread 1`) | 7 (`--concurrency 1`) |
| Client CPU | mean 0.5110 cores, peak 0.6000 | mean 0.5137 cores, peak 1.4992 | mean 0.4890 cores, peak 1.6650 |
| Backend CPU | mean 0.2672 cores, peak 0.3599 | mean 0.2828 cores, peak 0.3600 | mean 0.2622 cores, peak 0.3600 |
| Proxy RSS (sampled VmRSS) / VmHWM | mean=peak 209 316 KB; VmHWM 209 316 KB | mean 84 180 KB / peak 84 184 KB; VmHWM 84 184 KB | mean 61 823 KB / peak 61 828 KB; VmHWM 61 828 KB |

## Relay optimization progression (Alumina 100 Mbps / 60 s)

| Attribute | Alumina 8dbbec8 (baseline) | Alumina 54a34ce (copy-only removal) | Alumina e3a9ff1 | Alumina ae9bdb4 (post-opt) |
| --- | --- | --- | --- | --- |
| Read / buffer mechanism | 4 KiB stack scratch bounce `CHUNK = 4096` + `append_client_bytes` memcpy into 512 KiB slab | 4 KiB direct-into-slab read `CHUNK = 4096` (copy-only removed) | 32 KiB direct-into-slab read `READ_CHUNK = 32 KiB`, `MIN_BUF_ROOM = 4096`, half-visit read room reservation in `Stage::Relay` | same as e3a9ff1 (`src/serving.rs:123,128`) |
| Poll batch & dispatch mechanism | 64-event `mio::Events`, sequential per-token dispatch | 64-event `mio::Events`, sequential per-token dispatch | 512-event `POLL_EVENTS_CAP` two-pass per-slot coalescing (`CoalescedBatch`), dup-free app reschedule queue | 1024-event `POLL_EVENTS_CAP` (`src/serving.rs:117`) two-pass coalescing, plus perf-mission hot-path opts (G1-G10: C16 next-expiry cache, C50/C15 deadline bitmap + setup snapshot, C1 O(1) first-arrival chain, C14 one-side re-arm, C18 next-due cache) |
| Syscall & visit-budget mechanics (`VISIT_OPS = 16` / `VISIT_BYTES = 64 KiB`) | 4 KiB reads; interleaved client/upstream tokens exhaust `VISIT_OPS` → reschedules; memcpy bounce adds no read size | 4 KiB reads still exhaust `VISIT_OPS` → frequent reschedules; copy removal alone changes nothing | 32 KiB reads amortize `read(2)`; two-pass coalescing amortizes `epoll_wait(2)`/`epoll_ctl(2)` — syscall granularity governs latency | unchanged mechanics (`src/serving.rs:105-106`); Phase-4 gains come from schedule/poll hot paths (C16/C18 caches, C50 bitmap, C14 re-arm), not read granularity |
| Achieved payload / deficit | 99.996 Mbps / deficit 6 (offered_unsent 2 + backpressure 3 + drain 1) | 99.817 Mbps / deficit 335 (backpressure 333 + missed_at_end 2) | 99.999 Mbps / deficit 2 (backpressure 2) | 99.980 Mbps / deficit 36 (backpressure 34 + missed_at_end 2); Phase-4 candidate band 36-132 |
| `actual_send_to_echo` (p50 / p95 / p99 / max) | 23.95 / 40.85 / 42.15 / 82.6 ms | 23.95 / 40.95 / 42.35 / 92.5 ms | 2.95 / 3.35 / 3.55 / 9.05 ms | 2.75 / 3.95 / 4.45 / 12.99 ms (band max 11.6-20.5) |
| `sched_to_echo` (p50 / p95 / p99 / max) | 24.55 / 41.45 / 42.85 / 83.7 ms | 24.55 / 41.55 / 43.05 / 94.5 ms | 3.35 / 3.95 / 4.05 / 9.55 ms | 3.15 / 4.35 / 4.65 / 13.52 ms |
| `send_lag` (p50 / p95 / p99 / max) | 0.55 / 1.25 / 1.35 / 3.78 ms | 0.55 / 1.25 / 1.35 / 40.5 ms | 0.55 / 1.25 / 1.35 / 4.17 ms | 0.35 / 1.45 / 1.65 / 9.70 ms |
| Proxy CPU (mean / peak) | 0.037 / 0.080 | 0.040 / 0.080 | 0.038 / 0.811 | 0.115 / 0.160 (best-session; Phase-4 band 0.115-0.173) |
| Proxy RSS (VmRSS) / VmHWM | 153 532 / 153 532 KB | 153 532 / 153 532 KB | 153 620 / 153 620 KB | 209 316 / 209 316 KB |
| Raw JSON receipt | [results/54a34ce-seam-as-is-timed-20261013T234349Z.json](results/54a34ce-seam-as-is-timed-20261013T234349Z.json) | [results/54a34ce-seam-to-be-timed-20261013T234500Z.json](results/54a34ce-seam-to-be-timed-20261013T234500Z.json) | [results/e3a9ff1-seam-timed-20261015T135816Z.json](results/e3a9ff1-seam-timed-20261015T135816Z.json) | per-commit same-session interleaved A/B (harness receipts `.ooda/benchmarks/54c73db-seam-head-timed-20261018T1341*.json`); A/B tables in mission beads `alumina-nfet`, `alumina-bfdr`, `alumina-wrq6`, `alumina-z0wt`, `alumina-unqq.1` |

## Workload & measurement parameters

| Parameter | Value |
| --- | --- |
| Persistent connections | 8 |
| Payload frame | 4096 B payload + 12 B framing header (counted separately) |
| Aggregate open-loop client payload rate | 100 decimal Mbps = 12 500 000 B/s + echo |
| Warmup / window / setup+drain | 5 s / 60 s / 5 s |
| Planned whole frames | 183 105 scheduled frames = 749 998 080 B + 1 920 B unscheduled floor remainder |
| Outstanding cap | 1024 frames / 4 194 304 B (exhaustion = explicit unsent, never catch-up) |
| Endpoint | Real TLS 1.3 byte-exact framed-echo backend, `example.com` (genuine CA + SAN) |
| E2E latency histogram resolution | `bin_us=100` (100 us bin midpoint resolution) |
| Proxy CPU sample resolution | `core_samples=240` periodic in-window intervals over the 60 s observed aperture |

## Candidate scope / identity

Shared harness/host (all three): `9191d288…` net+PID ns on `flock-vm-root`, loopback alias; arm64 Apple-VM, 4 CPU / 14 GiB.

| Attribute | Alumina ae9bdb4 (post-opt) | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- | --- |
| Route label / client mode | via-proxy (CONNECT) | direct-proxy (direct TLS/SNI, no CONNECT) | via-proxy (CONNECT-terminate) |
| Binary | fresh musl build @ commit ae9bdb4 (binary `b441a5ae…`, deterministic — byte-identical clean-tree rebuild) | official pinned image 3.2.25 | official pinned image v1.39.4 |
| Measurement HEAD | ae9bdb4 (Rust code; interleaved A/B ran pre-commit, receipt `source_head` 54c73db; candidate binary == ae9bdb4 clean rebuild) | 9b9f4de | 9b9f4de |
| Libc / build | `aarch64-unknown-linux-musl` | glibc (libssl/libcrypto/liblua5.4/libpcre2/libz/libzstd) | BoringSSL RELEASE (libc/libm/libdl/librt/libpthread) |
| User (uid) | 65534 | image default (no user flag) | 65534 (`--user 65534:65534`) |
| Config | CONNECT allowlist + `[any_illegal]` `flare_only`; cfg `b00d4c32…` | TCP/SNI passthrough allowlist, `nbthread 1`, no CONNECT; cfg `35cf35df…` | CONNECT-terminate to fixed backend `8.8.8.8:443`, `--concurrency 1`; cfg `e6fb9ef7…` |
| Evidence receipts | G10 interleaved A/B table in mission bead `alumina-unqq.1`; harness receipts `.ooda/benchmarks/54c73db-seam-head-timed-20261018T134156Z.json` (CAND-A) / `T134417Z.json` (CAND-B) | [seam](results/qryg-haproxy-timed-20261018T101253Z-5423.json) · [native](results/qryg-haproxy-timed-20261018T101253Z-5423.native.json) | [seam](results/qryg-envoy-timed-20261018T101411Z-5756.json) · [native](results/qryg-envoy-timed-20261018T101411Z-5756.native.json) |

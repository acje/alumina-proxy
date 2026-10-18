# Alumina 9b9f4de vs HAProxy 3.2.25 vs Envoy 1.39.4 — 100 Mbps matched comparison

> **Honest context (repeat run).** This table records a fresh matched 100 Mbps timed rerun at measurement HEAD **9b9f4de** (2026-10-18). The measured binary is a fresh `aarch64-unknown-linux-musl` release build (sha256 `04ddd305…`) compiled from HEAD Rust source that is byte-identical to the earlier **d3536a5** single trial (only the `seam_echo.sh` supervisor and benchmark docs changed since; neither compiles into the binary) — so this is a deterministic rebuild, byte-identical to the d3536a5 binary. The Alumina run was supervised by `seam_echo.sh head timed` on `flock-vm-root` (harness `9191d288…`); raw receipt [results/9b9f4de-seam-head-timed-20261018T101118Z.json](results/9b9f4de-seam-head-timed-20261018T101118Z.json) (`source_head` 9b9f4de, `valid=true`, `workload_fulfilled=false`). All Alumina values are verbatim from that receipt. Repeat-run variance vs the d3536a5 single trial: interval deficit 139 (all backpressure) → 254 (backpressure 251 + missed_at_end 3), `actual_send_to_echo` p50/p95 unchanged (2.85/3.85 ms) with p99 4.35→4.25 ms, but max 23.19→58.13 ms (`sched_to_echo` max 23.48→67.12 ms, `send_lag` max 19.95→47.10 ms), proxy CPU mean 0.1885→0.2027 / peak 0.2400→0.2800 cores, and proxy RSS unchanged (209 308 KB). The wider repeat-run deficit and latency tails show the earlier single-trial numbers are indicative, not precise. The RSS level is structural, not a leak: the binary's own startup inventory log reports a named fixed-buffer lower bound of 205 657 890 B (134 217 728 B traffic slab + 71 303 168 B serving workspace + DNS named buffers) plus a 2 MiB log queue, consistent with the observed VmRSS. The HAProxy/Envoy columns are now fresh runs too (new 2026-10-18 receipt links), replacing the earlier e3a9ff1-pass values.

## Matched results (60 s window)

| Metric | Alumina 9b9f4de (repeat) | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- | --- |
| Route label (client mode) | via-proxy (CONNECT) | direct-proxy (direct TLS/SNI, no CONNECT) | via-proxy (CONNECT-terminate) |
| Verdict | valid | valid | valid |
| Workload fulfilled | no | no | no |
| Achieved client payload | 99.861 Mbps | 99.956 Mbps | 99.974 Mbps |
| Planned frames / admitted | 183 105 / 182 851 | 183 105 / 183 025 | 183 105 / 183 057 |
| Sent / echoed (total) | 182 851 / 182 851 | 183 025 / 183 025 | 183 057 / 183 057 |
| In-window sent / drain-completed sent | 182 851 / 0 | 183 025 / 0 | 183 057 / 0 |
| In-window echoed / drain echoed | 182 843 / 8 | 183 017 / 8 | 183 049 / 8 |
| Interval deficit (planned − in-window sent) | 254 (backpressure 251 + missed_at_end 3) | 80 (backpressure 79 + missed_at_end 1) | 48 (backpressure 47 + missed_at_end 1) |
| Measurement-cohort never-sent slots | 254 (backpressure 251 + missed_at_end 3) | 80 (backpressure 79 + missed_at_end 1) | 48 (backpressure 47 + missed_at_end 1) |
| Errors (timeout / send_failed / conn_errors / protocol) | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| latency `actual_send_to_echo` (in-window cohort) | p50 2.85 ms, p95 3.85 ms, p99 4.25 ms, max 58.13 ms (n=182 843) | p50 2.85 ms, p95 3.95 ms, p99 4.25 ms, max 17.76 ms (n=183 017) | p50 2.85 ms, p95 3.95 ms, p99 4.35 ms, max 12.15 ms (n=183 049) |
| latency `sched_to_echo` | p50 3.25 ms, p95 4.25 ms, p99 4.55 ms, max 67.12 ms | p50 3.25 ms, p95 4.25 ms, p99 4.65 ms, max 17.90 ms | p50 3.25 ms, p95 4.35 ms, p99 4.65 ms, max 12.30 ms |
| `send_lag` (distinct population, n=in-window sent) | p50 0.35 ms, p95 1.35 ms, p99 1.45 ms, max 47.10 ms (n=182 851) | p50 0.35 ms, p95 1.35 ms, p99 1.45 ms, max 14.56 ms (n=183 025) | p50 0.35 ms, p95 1.35 ms, p99 1.45 ms, max 8.53 ms (n=183 057) |
| Proxy CPU (observed aperture) | mean 0.2027 cores, peak 0.2800 (263 core samples) | mean 0.1058 cores, peak 0.1600 (263 periodic core intervals) | mean 0.1377 cores, peak 0.2000 (263 periodic core intervals) |
| Proxy thread count (positive-only task count) | 1 (single-worker) | 1 (`nbthread 1`) | 7 (`--concurrency 1`) |
| Client CPU | mean 0.5110 cores, peak 0.6000 | mean 0.5137 cores, peak 1.4992 | mean 0.4890 cores, peak 1.6650 |
| Backend CPU | mean 0.2672 cores, peak 0.3599 | mean 0.2828 cores, peak 0.3600 | mean 0.2622 cores, peak 0.3600 |
| Proxy RSS (sampled VmRSS) / VmHWM | mean=peak 209 308 KB; VmHWM 209 308 KB | mean 84 180 KB / peak 84 184 KB; VmHWM 84 184 KB | mean 61 823 KB / peak 61 828 KB; VmHWM 61 828 KB |

## Relay optimization progression (Alumina 100 Mbps / 60 s)

| Attribute | Alumina 8dbbec8 (baseline) | Alumina 54a34ce (copy-only removal) | Alumina e3a9ff1 | Alumina 9b9f4de (repeat) |
| --- | --- | --- | --- | --- |
| Read / buffer mechanism | 4 KiB stack scratch bounce `CHUNK = 4096` + `append_client_bytes` memcpy into 512 KiB slab | 4 KiB direct-into-slab read `CHUNK = 4096` (copy-only removed) | 32 KiB direct-into-slab read `READ_CHUNK = 32 KiB`, `MIN_BUF_ROOM = 4096`, half-visit read room reservation in `Stage::Relay` | same as e3a9ff1 (`src/serving.rs:123,128`) |
| Poll batch & dispatch mechanism | 64-event `mio::Events`, sequential per-token dispatch | 64-event `mio::Events`, sequential per-token dispatch | 512-event `POLL_EVENTS_CAP` two-pass per-slot coalescing (`CoalescedBatch`), dup-free app reschedule queue | 1024-event `POLL_EVENTS_CAP` (`src/serving.rs:117`), same two-pass coalescing |
| Syscall & visit-budget mechanics (`VISIT_OPS = 16` / `VISIT_BYTES = 64 KiB`) | 4 KiB reads; interleaved client/upstream tokens exhaust `VISIT_OPS` → reschedules; memcpy bounce adds no read size | 4 KiB reads still exhaust `VISIT_OPS` → frequent reschedules; copy removal alone changes nothing | 32 KiB reads amortize `read(2)`; two-pass coalescing amortizes `epoll_wait(2)`/`epoll_ctl(2)` — syscall granularity governs latency | unchanged mechanics (`src/serving.rs:105-106`) |
| Achieved payload / deficit | 99.996 Mbps / deficit 6 (offered_unsent 2 + backpressure 3 + drain 1) | 99.817 Mbps / deficit 335 (backpressure 333 + missed_at_end 2) | 99.999 Mbps / deficit 2 (backpressure 2) | 99.861 Mbps / deficit 254 (backpressure 251 + missed_at_end 3) |
| `actual_send_to_echo` (p50 / p95 / p99 / max) | 23.95 / 40.85 / 42.15 / 82.6 ms | 23.95 / 40.95 / 42.35 / 92.5 ms | 2.95 / 3.35 / 3.55 / 9.05 ms | 2.85 / 3.85 / 4.25 / 58.13 ms |
| `sched_to_echo` (p50 / p95 / p99 / max) | 24.55 / 41.45 / 42.85 / 83.7 ms | 24.55 / 41.55 / 43.05 / 94.5 ms | 3.35 / 3.95 / 4.05 / 9.55 ms | 3.25 / 4.25 / 4.55 / 67.12 ms |
| `send_lag` (p50 / p95 / p99 / max) | 0.55 / 1.25 / 1.35 / 3.78 ms | 0.55 / 1.25 / 1.35 / 40.5 ms | 0.55 / 1.25 / 1.35 / 4.17 ms | 0.35 / 1.35 / 1.45 / 47.10 ms |
| Proxy CPU (mean / peak) | 0.037 / 0.080 | 0.040 / 0.080 | 0.038 / 0.811 | 0.203 / 0.280 |
| Proxy RSS (VmRSS) / VmHWM | 153 532 / 153 532 KB | 153 532 / 153 532 KB | 153 620 / 153 620 KB | 209 308 / 209 308 KB |
| Raw JSON receipt | [results/54a34ce-seam-as-is-timed-20261013T234349Z.json](results/54a34ce-seam-as-is-timed-20261013T234349Z.json) | [results/54a34ce-seam-to-be-timed-20261013T234500Z.json](results/54a34ce-seam-to-be-timed-20261013T234500Z.json) | [results/e3a9ff1-seam-timed-20261015T135816Z.json](results/e3a9ff1-seam-timed-20261015T135816Z.json) | [results/9b9f4de-seam-head-timed-20261018T101118Z.json](results/9b9f4de-seam-head-timed-20261018T101118Z.json) |

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

| Attribute | Alumina 9b9f4de | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- | --- |
| Route label / client mode | via-proxy (CONNECT) | direct-proxy (direct TLS/SNI, no CONNECT) | via-proxy (CONNECT-terminate) |
| Binary | fresh musl build @ commit 9b9f4de (binary `04ddd305…`, deterministic — byte-identical to the d3536a5 build) | official pinned image 3.2.25 | official pinned image v1.39.4 |
| Measurement HEAD | 9b9f4de (code d3536a5; receipt `source_head`) | 9b9f4de | 9b9f4de |
| Libc / build | `aarch64-unknown-linux-musl` | glibc (libssl/libcrypto/liblua5.4/libpcre2/libz/libzstd) | BoringSSL RELEASE (libc/libm/libdl/librt/libpthread) |
| User (uid) | 65534 | image default (no user flag) | 65534 (`--user 65534:65534`) |
| Config | CONNECT allowlist + `[any_illegal]` `flare_only`; cfg `b00d4c32…` | TCP/SNI passthrough allowlist, `nbthread 1`, no CONNECT; cfg `35cf35df…` | CONNECT-terminate to fixed backend `8.8.8.8:443`, `--concurrency 1`; cfg `e6fb9ef7…` |
| Evidence receipts | [seam-head](results/9b9f4de-seam-head-timed-20261018T101118Z.json) | [seam](results/qryg-haproxy-timed-20261018T101253Z-5423.json) · [native](results/qryg-haproxy-timed-20261018T101253Z-5423.native.json) | [seam](results/qryg-envoy-timed-20261018T101411Z-5756.json) · [native](results/qryg-envoy-timed-20261018T101411Z-5756.native.json) |

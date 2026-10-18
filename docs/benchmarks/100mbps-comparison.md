# Alumina d3536a5 vs HAProxy 3.2.25 vs Envoy 1.39.4 — 100 Mbps matched comparison

> **Honest context (single trial).** This table records one matched 100 Mbps timed rerun of Alumina at the measured commit **d3536a5** (2026-10-18). The measured binary is a fresh `aarch64-unknown-linux-musl` release build from the d3536a5 Rust source; the only tree change between d3536a5 and the measurement HEAD `8d28d10` is the `seam_echo.sh` supervisor (the fail-closed `head` mode), which is not compiled into the binary. The run was supervised by `seam_echo.sh head timed` on `flock-vm-root` (harness `9191d288…`); raw receipt [results/8d28d10-seam-head-timed-20261018T094907Z.json](results/8d28d10-seam-head-timed-20261018T094907Z.json) (`source_head` 8d28d10, `valid=true`, `workload_fulfilled=false`). All Alumina values are verbatim from that single receipt. Versus e3a9ff1 this trial shows deficit 2→139 (all backpressure), `actual_send_to_echo` p50 2.95→2.85 ms / max 9.05→23.19 ms, and proxy RSS 153 620→209 308 KB; the deficit/latency deltas are a single-trial pair and are indicative pending repeat runs. The RSS rise is structural, not a leak: the binary's own startup inventory log reports a named fixed-buffer lower bound of 205 657 890 B (134 217 728 B traffic slab + 71 303 168 B serving workspace + DNS named buffers) plus a 2 MiB log queue, consistent with the observed VmRSS. HAProxy/Envoy columns are unchanged from the earlier e3a9ff1 comparison pass.

## Matched results (60 s window)

| Metric | Alumina d3536a5 | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- | --- |
| Route label (client mode) | via-proxy (CONNECT) | direct-proxy (direct TLS/SNI, no CONNECT) | via-proxy (CONNECT-terminate) |
| Verdict | valid | valid | valid |
| Workload fulfilled | no | no | no |
| Achieved client payload | 99.924 Mbps | 99.998 Mbps | 99.994 Mbps |
| Planned frames / admitted | 183 105 / 182 966 | 183 105 / 183 102 | 183 105 / 183 095 |
| Sent / echoed (total) | 182 966 / 182 966 | 183 102 / 183 102 | 183 095 / 183 095 |
| In-window sent / drain-completed sent | 182 966 / 0 | 183 102 / 0 | 183 095 / 0 |
| In-window echoed / drain echoed | 182 958 / 8 | 183 094 / 8 | 183 087 / 8 |
| Interval deficit (planned − in-window sent) | 139 (backpressure 139) | 3 | 10 |
| Measurement-cohort never-sent slots | 139 (backpressure 139) | 3 (backpressure 3) | 10 (backpressure 8 + missed_at_end 2) |
| Errors (timeout / send_failed / conn_errors / protocol) | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| latency `actual_send_to_echo` (in-window cohort) | p50 2.85 ms, p95 3.85 ms, p99 4.35 ms, max 23.19 ms (n=182 958) | p50 2.55 ms, p95 4.05 ms, p99 4.25 ms, max 7.38 ms (n=183 094) | p50 2.75 ms, p95 4.05 ms, p99 4.35 ms, max 9.21 ms (n=183 087) |
| latency `sched_to_echo` | p50 3.15 ms, p95 4.25 ms, p99 4.65 ms, max 23.48 ms | p50 3.35 ms, p95 4.25 ms, p99 4.45 ms, max 7.68 ms | p50 3.35 ms, p95 4.35 ms, p99 4.55 ms, max 9.28 ms |
| `send_lag` (distinct population, n=in-window sent) | p50 0.35 ms, p95 1.35 ms, p99 1.55 ms, max 19.95 ms (n=182 966) | p50 0.55 ms, p95 1.45 ms, p99 1.65 ms, max 4.35 ms (n=183 102) | p50 0.45 ms, p95 1.45 ms, p99 1.65 ms, max 4.30 ms (n=183 095) |
| Proxy CPU (observed aperture) | mean 0.1885 cores, peak 0.2400 (240 core samples) | mean 0.0501 cores, peak 0.120 (240 periodic core intervals) | mean 0.0783 cores, peak 0.120 (240 periodic core intervals) |
| Proxy thread count (positive-only task count) | 1 (single-worker) | 1 (`nbthread 1`) | 7 (`--concurrency 1`) |
| Client CPU | mean 0.4888 cores, peak 0.5599 | mean 0.261 cores, peak 0.440 | mean 0.299 cores, peak 0.440 |
| Backend CPU | mean 0.2532 cores, peak 0.3588 | mean 0.181 cores, peak 0.280 | mean 0.186 cores, peak 0.280 |
| Proxy RSS (sampled VmRSS) / VmHWM | mean=peak 209 308 KB; VmHWM 209 308 KB | mean=peak 84 180 KB; VmHWM 84 180 KB | mean 61 834 KB / peak 61 840 KB; VmHWM 61 840 KB |

## Relay optimization progression (Alumina 100 Mbps / 60 s)

| Attribute | Alumina 8dbbec8 (baseline) | Alumina 54a34ce (copy-only removal) | Alumina e3a9ff1 | Alumina d3536a5 |
| --- | --- | --- | --- | --- |
| Read / buffer mechanism | 4 KiB stack scratch bounce `CHUNK = 4096` + `append_client_bytes` memcpy into 512 KiB slab | 4 KiB direct-into-slab read `CHUNK = 4096` (copy-only removal; no stack bounce memcpy) | 32 KiB direct-into-slab read `READ_CHUNK = 32 KiB`, `MIN_BUF_ROOM = 4096`, half-visit read room reservation in `Stage::Relay` | same as e3a9ff1 (`src/serving.rs:123,128`) |
| Poll batch & dispatch mechanism | 64-event `mio::Events`, sequential per-token dispatch | 64-event `mio::Events`, sequential per-token dispatch | 512-event `POLL_EVENTS_CAP` two-pass per-slot readiness coalescing (`CoalescedBatch`), duplicate-free app reschedule queue | 1024-event `POLL_EVENTS_CAP` (`src/serving.rs:117`) two-pass per-slot readiness coalescing (`CoalescedBatch`), duplicate-free app reschedule queue |
| Syscall & visit-budget mechanics (`VISIT_OPS = 16` / `VISIT_BYTES = 64 KiB`) | 4 KiB read syscalls + interleaved client/upstream tokens exhaust the per-visit op budget → reschedules; memcpy bounce adds no read size, latency governed by syscall/visit granularity | 4 KiB read syscalls; per-4 KiB token interleave still exhausts `VISIT_OPS` → frequent reschedules; copy removal alone does not change granularity | 32 KiB reads amortize `read(2)`; two-pass per-slot coalescing amortizes `epoll_wait(2)`/`epoll_ctl(2)` across the visit budget — syscall/visit granularity, not user-space 4 KiB memcpy, governs latency | unchanged mechanics (`src/serving.rs:105-106`) |
| Achieved payload / deficit | 99.996 Mbps / deficit 6 (offered_unsent 2 + backpressure 3 + drain 1) | 99.817 Mbps / deficit 335 (backpressure 333 + missed_at_end 2) | 99.999 Mbps / deficit 2 (backpressure 2) | 99.924 Mbps / deficit 139 (backpressure 139) |
| `actual_send_to_echo` (p50 / p95 / p99 / max) | 23.95 / 40.85 / 42.15 / 82.6 ms | 23.95 / 40.95 / 42.35 / 92.5 ms | 2.95 / 3.35 / 3.55 / 9.05 ms | 2.85 / 3.85 / 4.35 / 23.19 ms |
| `sched_to_echo` (p50 / p95 / p99 / max) | 24.55 / 41.45 / 42.85 / 83.7 ms | 24.55 / 41.55 / 43.05 / 94.5 ms | 3.35 / 3.95 / 4.05 / 9.55 ms | 3.15 / 4.25 / 4.65 / 23.48 ms |
| `send_lag` (p50 / p95 / p99 / max) | 0.55 / 1.25 / 1.35 / 3.78 ms | 0.55 / 1.25 / 1.35 / 40.5 ms | 0.55 / 1.25 / 1.35 / 4.17 ms | 0.35 / 1.35 / 1.55 / 19.95 ms |
| Proxy CPU (mean / peak) | 0.037 / 0.080 | 0.040 / 0.080 | 0.038 / 0.811 | 0.189 / 0.240 |
| Proxy RSS (VmRSS) / VmHWM | 153 532 / 153 532 KB | 153 532 / 153 532 KB | 153 620 / 153 620 KB | 209 308 / 209 308 KB |
| Raw JSON receipt | [results/54a34ce-seam-as-is-timed-20261013T234349Z.json](results/54a34ce-seam-as-is-timed-20261013T234349Z.json) | [results/54a34ce-seam-to-be-timed-20261013T234500Z.json](results/54a34ce-seam-to-be-timed-20261013T234500Z.json) | [results/e3a9ff1-seam-timed-20261015T135816Z.json](results/e3a9ff1-seam-timed-20261015T135816Z.json) | [results/8d28d10-seam-head-timed-20261018T094907Z.json](results/8d28d10-seam-head-timed-20261018T094907Z.json) |

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

| Attribute (shared) | Alumina d3536a5 | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- | --- |
| Workload | Same fixed 100 decimal Mbps workload for all three (8 persistent connections, 4096 B payload frames + 12 B header, aggregate open-loop pacing, 5 s warmup / 60 s window / 5 s setup+drain) — see table above | same | same |
| Harness image / placement | `9191d288…` net+PID ns, `flock-vm-root`, loopback alias | same | same |
| Host | arm64 Apple-VM, 4 CPU / 14 GiB | same | same |

| Attribute (per-candidate) | Alumina d3536a5 | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- | --- |
| Route label / client mode | via-proxy (CONNECT) | direct-proxy (direct TLS/SNI, no CONNECT) | via-proxy (CONNECT-terminate) |
| Binary commit | d3536a5 (fresh musl binary `04ddd305…`) | official pinned image 3.2.25 | official pinned image v1.39.4 |
| Measurement HEAD | 8d28d10 (Rust code d3536a5; receipt `source_head` `8d28d10…`) | 031ee10 | 031ee10 |
| Libc / build | `aarch64-unknown-linux-musl` | glibc (official image; libssl/libcrypto/liblua5.4/libpcre2/libz/libzstd) | BoringSSL RELEASE (libc/libm/libdl/librt/libpthread) |
| User | uid 65534 | image default (no user flag) | uid 65534 (`--user 65534:65534`) |
| Seam tool (`tool_sha256`) | `347a0b8b…` | `347a0b8b…` | `347a0b8b…` |
| Supervisor | `seam_echo.sh` `d05abfcb…` (fail-closed `head` mode) | `qryg_runner.sh` `c6d4aab6…` + `harness_native.sh` `57b4acd0…` | `qryg_runner.sh` `c6d4aab6…` + `harness_native.sh` `57b4acd0…` |
| Config | allowlist + listen + `[any_illegal]` `scope=connection` + `[actions]` `kind=[flare_only]` `scope=[connection]` (`config_sha256` `b00d4c32…`) | `haproxy.cfg` `35cf35df…` (TCP/SNI passthrough: `mode tcp`, `tcp-request content` on ClientHello, `use_backend` on SNI `example.com`, fixed backend `8.8.8.8:443`, `nbthread 1`, no CONNECT method) | `envoy_connect.yaml` `e6fb9ef7…` (CONNECT-terminate: HCM `connect_matcher` route to fixed backend `8.8.8.8:443`, route `timeout: 0s`, `--concurrency 1`, uid 65534) |
| Candidate image / binary | freshly built `04ddd305…` (musl, this measurement; never a retained image) | image `d483b789…` / manifest `3947a542…`, binary `8c8791be…` | image `a084f595…` / manifest `ce82b213…`, binary `6b064069…` |
| Raw + companion evidence | seam report `7f5339d5…` — [results/8d28d10-seam-head-timed-20261018T094907Z.json](results/8d28d10-seam-head-timed-20261018T094907Z.json) | seam `ffa5ee4a…` — [results/qryg-haproxy-timed-20261014T012232Z-66396.json](results/qryg-haproxy-timed-20261014T012232Z-66396.json) + native `96b341de…` — [results/qryg-haproxy-timed-20261014T012232Z-66396.native.json](results/qryg-haproxy-timed-20261014T012232Z-66396.native.json) | seam `770de863…` — [results/qryg-envoy-timed-20261014T012343Z-66851.json](results/qryg-envoy-timed-20261014T012343Z-66851.json) + native `5256d337…` — [results/qryg-envoy-timed-20261014T012343Z-66851.native.json](results/qryg-envoy-timed-20261014T012343Z-66851.native.json) |

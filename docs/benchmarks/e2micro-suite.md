# Alumina — e2-micro benchmark suite (1gbps + connection storms, Envoy/HAProxy comparison)

Benchmark suite for the Alumina egress proxy (CONNECT forward proxy) moduli: the
fresh `bench` suite replaces the deleted legacy suite (SM-1). It measures
Alumina against the two market CONNECT-capable forward proxies — Envoy and
HAProxy — under an e2-micro-shaped workload, with results recorded in §9.

This document is methodology, metrics, and invocation reference. The Results
section (§9) holds the **corrected M-04 results** (2026-10-28).

- Topic: methodology (research-first, per evidence bead `alumina-d59gq`).
- Status: results recorded — corrected M-04 (2026-10-28) in §9. Correction
  package complete.
- Protocol: P2 measurement protocol frozen for the exact candidate `3f587e9`
  (2026-10-29) in §10 — binds E2–E4 before any measurement runs.
- Governing repository spec: `docs/alumina-proxy.md` (this suite measures its
  golden CONNECT path; it does not alter proxy semantics).

---

## 1. System under test & subjects

All three subjects are **HTTP CONNECT forward proxies**: the client issues
`CONNECT example.com:443` to the proxy; the proxy establishes a TCP tunnel to
the origin; TLS runs end-to-end through the tunnel to a byte-exact echo
backend. This is the "CONNECT egress" role Alumina is designed for.

| Subject | Version (as of 2026-10-27) | CONNECT model | Config |
|---|---|---|---|
| alumina | `aarch64-unknown-linux-musl` build of the repo HEAD, sha-pinned at run time | **Direct tunnel**: answers `200 Connection Established` itself, resolves `example.com` via its own resolver (`["127.0.0.1"]`) and opens raw TLS to the origin immediately | generated in-container (`run.sh`); allowlist `example.com:443`, `[any_illegal]` notify actions |
| Envoy | v1.40.2 (latest stable; image binary) | **CONNECT relay**: HCM `allow_connect: true` + `connect_matcher` route + `upgrade_configs CONNECT`, static upstream `8.8.8.8:443`; relays the CONNECT line and forwards the origin's 200 | `scripts/bench/envoy-connect.yaml`, `--concurrency 2` |
| HAProxy | 3.4.7 (latest stable on branch 3.4; image binary) | **CONNECT relay**: `mode http`, forwards the CONNECT line to a static origin `8.8.8.8:443`, tunnels after the origin's 200 (`timeout tunnel`) | `scripts/bench/haproxy-connect.cfg`, `nbthread 2` |

### Relay-vs-direct asymmetry (must-read before interpreting results)

- **Direct tunnel (alumina)**: session setup = client→proxy CONNECT, proxy
  200, then a raw TLS handshake straight through the tunnel to the origin.
- **Relay (Envoy, HAProxy)**: the proxy connects to the origin first and sends
  it the client's CONNECT request line; the origin answers
  `HTTP/1.1 200 Connection Established`, which the proxy forwards; only then
  does TLS begin. Session establishment therefore carries an extra local
  origin round trip and an origin-side 200.
- To make the relay model measurable against the direct model, the suite's
  TLS1.3 echo backend tolerates an optional leading CONNECT preamble: it peeks
  (never consumes; `MSG_PEEK`) the first bytes, answers a relayed CONNECT with
  exactly one `200 Connection Established`, then performs the TLS handshake.
  A plain TLS ClientHello (alumina's path) is never consumed by the probe
  (`scripts/bench_workload.py`, `EchoBackend._serve`; regression gates
  `preamble-conn` / `preamble-noeat` / `preamble-counts` in the selftest).

**What is comparable across subjects** (after 200 + TLS): the frame data path —
per-frame echoed-data latency (`latency.actual_send_to_echo`), steady
throughput (`achieved_client_payload_mbps`), and per-subject CPU/RSS sampling.
The relay cost is a one-time, per-connection setup cost; frames flow only after
TLS is up, so the measured data-path latency and throughput are unaffected by
the model difference.

**What is NOT comparable across subjects** (must be read per-subject, never
head-to-head):

1. **Storm `setup_latency` (linus F8)**: for Envoy/HAProxy, "session
   establishment" includes the relay + origin preamble answer + TLS handshake;
   for alumina it is CONNECT + TLS handshake alone. The receipt's disclosed
   semantics "CONNECT start → handshake complete" therefore mean different
   things per subject. Treat `latency.setup_latency` as a **property of each
   subject's own path**, not as an apples-to-apples comparison.
2. **Peak CPU shape**: `--concurrency 2` / `nbthread 2` (Envoy FAQ: one worker
   per target core; see §7) vs alumina's single boot owner and single serving
   owner (fixed profile, `docs/alumina-proxy.md`). Per-subject CPU mean/peak is
   reported honestly; direct cross-subject CPU-homing comparisons are
   indicative only and are disclosed as such.

---

## 2. e2-micro workload-parameter modeling (honest by construction)

The workload models a Google e2-micro target — **2 shared vCPU / 1 GB memory,
nominal ~1 Gbit/s bandwidth class** (GCP E2 shared-core family: `e2-micro`
0.5 GB per vCPU ratio, 2 shared vCPU, 1 GB; see References). Modeling is by
**workload parameters only**:

- **Rate**: open-loop offered load is set to the 1 Gbps-class profile (1000
  Mbps aggregate), or to connection-arrival rates for the storms (150/s, 50/s).
- **Connection churn**: 32 sustained tunnels (steady) or 4–16 frames per
  session at a fixed arrival rate with a live-concurrent peak guard of 300
  (storm), mirroring the h2load fixed-connection-rate idiom (§7).

The harness **never applies a container cgroup CPU/mem cap**. e2-micro
equivalence is expressed exclusively as workload and target parameters, per the
research-first method: resource modeling belongs to the proxy under test
(worker concurrency, fixed serving-owner profile), while the load generator
stays **open-loop and unthrottled by latency** (Envoy FAQ guidance, §7). This
is a deliberate, documented choice — running the harness inside a cgroup-capped
container would conflate the proxy's cost with the harness's, which is precisely
what the fixed profile must avoid. Receipts record the model verbatim:
`e2micro_model.model = "workload-parameter model (rate + connection churn); no
container cgroup CPU/mem cap applied"`.

### Host-vs-target disclosure

- Host: arm64 Apple VM, 8 CPU / 14 GiB memory, Linux via a rootful podman
  connection, `--network none`, everything on a loopback global-unicast
  alias (`8.8.8.8/32`). All client, backend, DNS responder, and proxy processes
  run inside the single pinned bench container, so CPU sampling is uniform over
  the measured aperture.
- Target modeled: e2-micro (2 shared vCPU, 1 GB), via workload parameters only
  (§ above). The measured host is **not** an e2-micro; results are the proxy's
  cost on this harness and generalize only through the disclosed model.

---

## 3. Topology & harness

```
client (open-loop, validated TLS1.3)
   |  CONNECT example.com:443
   v
CONNECT proxy on 127.0.0.1:8080   (alumina | envoy | haproxy)
   |  tunnel: relay model sends the CONNECT line + 200, then raw TLS;
   |          direct model (alumina) answers 200 itself, raw TLS immediately
   v
TLS1.3 byte-exact framed echo backend on 8.8.8.8:443  (loopback alias)
   ^
DNS responder on 127.0.0.1:53 (UDP + TCP, both transports on one port)
   `-- example.com -> 8.8.8.8
```

- One pinned, reproducible bench image `localhost/alumina-bench:20261027`
  (`id 7c3937c1…`, built from `scripts/bench/Dockerfile` on `debian:trixie-slim`,
  COPY of Envoy 1.40.2 + HAProxy 3.4.7 release binaries; **separate** from the
  pinned e2e image `localhost/alumina-e2e:e2e-20261011`, which is untouched).
  `scripts/bench_run.sh` fails closed unless the live image id equals the
  pinned `BENCH_IMAGE_ID`.
- Genuine CA + SAN=example.com certificate generated in-container; the client
  validates the chain and the SAN.
- Supervision: `scripts/bench/run.sh` (in-container body) stages the alias,
  resolv.conf, certs, then starts DNS responder, backend, one proxy; reaps all
  children (acquisition-before-trap, `B8`); emits `BENCH-OK` (exit 0),
  `BENCH-INVALID` (exit 3), or `BENCH-FAIL` (exit 1). `scripts/bench_run.sh`
  (host) pins image + alumina binary sha, and writes the JSON receipt to
  `gitignored .ooda/benchmarks/`.

---

## 4. Workload profiles & invocation

### Profiles (workload parameters)

| Profile | `--workload` | Parameters (as passed by `bench_run.sh`) |
|---|---|---|
| **1gbps** (steady) | `steady` | `--conns 32 --target-mbps 1000 --outstanding-cap 2048` |
| **storm150** | `storm` | `--arrival-rate 150 --session-frames-min 4 --session-frames-max 16` |
| **storm50** | `storm` | `--arrival-rate 50 --session-frames-min 4 --session-frames-max 16` |

Storm common defaults: live+in-dial peak guard `--peak-conns 300` (well under
the fixed 512-tunnel pool), so storm never exhausts the fixed profile's tunnel
budget. Steady is open-loop with a bounded outstanding cap (2048) keeping
scheduling at the head of the QPS-latency curve rather than at saturation
(Envoy FAQ: never measure at max-load knee).

### Invocation

```sh
# smoke (2 s measure; fast path correctness), storm profiles run at their rate
BENCH_IMAGE_ID=7c3937c1… sh scripts/bench_run.sh <alumina|envoy|haproxy> smoke <1gbps|storm150|storm50>

# timed (60 s measure, 5 s warmup) — the boundary-run profile
HEAD_CANDIDATE_SHA=<sha256 of .ooda/alumina-head/baseline/alumina-musl> \
BENCH_IMAGE_ID=7c3937c1… sh scripts/bench_run.sh <proxy> timed <profile>
```

- `HEAD_CANDIDATE_SHA` is **mandatory and fail-closed for alumina** (binary
  sha-verified before the session; a mismatch blocks the run). The boundary run
  rebuilds alumina from repo HEAD and pins its sha.
- `BENCH_IMAGE_ID` is mandatory fail-closed for every subject (image id
  verified against `localhost/alumina-bench:20261027` before the session).
- `BENCH_PODMAN_CONNECTION` (rootful podman connection; required),
  `BENCH_IMAGE`.

### Selftests (driver self-check)

- Host: `python3 scripts/bench_workload.py --selftest` (80 PASS / 8 SKIP /
  0 FAIL on the LibreSSL host; TLS-1.3-load-bearing checks report SKIP with the
  capability reason).
- In-container (authoritative, OpenSSL 3.5 / TLS 1.3): run the same command
  inside the bench image — 96 PASS / 0 SKIP / 0 FAIL as of SM-2. A SKIP is
  never a PASS and never a FAIL; it is the honest tri-state verdict.

---

## 5. Metrics & receipt schema

Headline metrics (all from the JSON receipt in `.ooda/benchmarks/`):

| Metric | Receipt field | Definition |
|---|---|---|
| Per-frame latency p50/p95/p99 (steady headline) | `latency.sched_to_echo` | sched-to-echo: open-loop schedule→echo completion, includes queueing; reported as `p50_us`/`p95_us`/`p99_us` (µs) with histogram overflow honesty (`overflow`, `max_us`) |
| Data-path latency | `latency.actual_send_to_echo` | echo time once the frame was actually sent — the relay/direct-comparable data path |
| CPU mean / peak per subject | `sampling.<subject>.cores_mean` / `.cores_peak` | procfs CPU-tick sampling over the observed aperture (`boundary_lag_s` disclosed), subject = `client` / `backend` / `proxy`; `unknown` typed when probes fail (never folded into clean) |
| RSS | `sampling.<subject>.rss_current_mean_kb` / `rss_current_peak_kb` / `vmhwm_kb` | current + lifetime-high (VmHWM) |
| **Throughput headline (read FIRST)** | `interval_vs_cohort.achieved_client_payload_mbps` | client-measured goodput over the measurement window (payload Mbps) — **this is the honest headline, see F1 below** |
| Storm sessions | `storm.sessions_completed`, `storm.setup_failures`, `storm.peak_live`, `storm.peak_dialing`, `storm.setup_latency` | per-session connect accounting + establishment-latency histogram (§1 caveats) |
| Validity | `valid`, `reasons`, `workload_fulfilled`, `verdict` | failure-driven: corruption, missing-bytes, protocol disorder, timeouts, partial send, accounting break, or `unknown-cpu` invalidate; `workload_fulfilled` requires clean in-window counters |
| Identity | `identity` | `source_head`, `dirty_count`, `retained_binary_sha256`, `executed_binary_sha256`, `bench image_id`, `config_sha256`, tool sha, python/OpenSSL versions — every receipt is reproducible and attributable |

### F1 — the 1gbps profile is echo-backend-limited (GIL-bound python path): read achieved, not 1000

The 1000 Mbps figure in the steady profile is the **offered-load target**, not
a delivered guarantee. The measured-path ceiling is set by the TLS1.3 echo
backend, not by any proxy: the in-process python `EchoBackend`
(`scripts/bench_workload.py`) is GIL/thread-bound at ~25.3 K frames/s
(≈ 830 Mbps for 4096 B frames). That is why the pre-M-03 runs recorded
**808 (alumina) / 881 (envoy) / 846 (haproxy)** Mbps (SM-2 smoke) and then
**826–830 Mbps** on every subject — a shared harness backend ceiling, never a
per-proxy claim.

The python backend was **replaced on the measured path by a compiled
Rust/rustls static-musl TLS1.3 echo backend** (`scripts/bench/echo-backend/`,
M-03 commit `6c4cc49`; binary `.ooda/echo-backend/echo-backend-musl`,
sha-pinned `efa64083…` via `BENCH_ECHO_SHA` in `bench_run.sh`). The compiled
backend lifted the ceiling to **~999.7–1000 Mbps** (M-04: alumina 999.969,
envoy 999.834, haproxy 999.725 — corrected table, §9). The python
`EchoBackend` is retained as the in-process selftest reference and the
`BENCH_BACKEND=python` one-line fallback.

Consequences, stated up front:

1. Every headline claim about the steady profile must be read at its
   **achieved** rate — `interval_vs_cohort.achieved_client_payload_mbps` — and
   `workload_fulfilled` must be shown alongside (F1).
2. The **relative comparison remains fair**: all three subjects receive the
   same offered load and the same backend, so any residual ceiling applies to
   all; this is a comparison of proxies at equal load, not an absolute-rate
   certification.
3. "≈1000 Mbps" with `workload_fulfilled=false` is **not** a delivered-1000
   guarantee: it is the achieved rate plus a tiny open-loop backpressure/drain
   tail at the target (M-04: `backpressure_unsent` alumina 56 / envoy 303 /
   haproxy 502 of ~1.83 M frames = 0.003–0.03%; `missed_at_end=0` all) — the
   open-loop client's outstanding-cap marker, exactly the F1 class the
   fulfilled flag is designed to surface (caveats, §9).

### In-window vs drain honesty

The report splits `interval_vs_cohort.in_window_*_frames` from
`drain_*_frames`; latency histograms contain in-window echoes only. A run whose
echo completes late (in drain) is reported honestly as such (F4): when reading
fulfillment semantics, prefer the in-window echoed count and interpret
`drain_echoed_frames` explicitly.

---

## 6. Comparison framing (apples-to-apples discipline)

- **Same driver**: one `scripts/bench_workload.py` drives all three subjects —
  same open-loop scheduler, same frame workload, same byte-exact echo, same
  conservation/accounting invariants, same report schema.
- **Same harness**: identical topology, image, DNS, backend, scheduling
  (equal offered load by construction).
- **Same measurement**: latency p50/p95/p99 + CPU max/mean + RSS, reported per
  subject from the same aperture.
- **Version-latest stable**: Envoy **v1.40.2** and HAProxy **3.4.7** (latest
  stable as of 2026-10-27, evidence bead `alumina-d59gq`) pinned in the bench
  image; alumina built from repo HEAD (boundary run) and sha-pinned fail-closed.
- **Target-concurrency match**: Envoy `--concurrency 2`, HAProxy `nbthread 2`
  (Envoy FAQ: one worker per logical core of the modeled 2-vCPU target);
  alumina's single serving owner is its fixed profile and is disclosed as the
  asymmetry it is (§1).
- **Confounded axes disclosed**: relay-vs-direct (setup path, §1), storm
  `setup_latency` cross-subject incomparability (F8, §1), echo-backend ceiling
  (F1, §5 — GIL-bound python path, resolved by the M-03 compiled backend),
  storm p50 delayed-ACK/Nagle first-segment stall (resolved by alumina upstream
  `TCP_NODELAY` M-01 and haproxy `option http-no-delay` M-02; §9 honest
  readings). Nothing is silently averaged across these.

What this suite is NOT: it is not an absolute-throughput certification of any
proxy, not a synthetic-payload-inspection benchmark, and not a max-load knee
search. It is a controlled, equal-load, CONNECT-egress head-to-head with honest
ceiling and asymmetry disclosure.

---

## 7. Why these methods (research-first citations)

Method choices are grounded in primary sources captured by the evidence pass
(`alumina-d59gq`):

- **Open-loop steady generator + expected-measure** — Envoy's performance FAQ
  ("Best practices for benchmarking Envoy"): prefer **open-loop** load
  generators, **never measure latency at max load**, measure below the knee of
  the QPS-latency curve, and keep load-generator connection reuse/timing as a
  first-order documented variable.
  <https://www.envoyproxy.io/docs/envoy/latest/faq/performance/how_to_benchmark_envoy>
- **Fixed connection-creation rate (storm)** — h2load/nghttp2's
  `-r, --rate=<N>`: "the fixed rate at which connections are created", coupled
  with `-c` max connections — the idiomatic connection-storm generator, and
  h2load reports median / p95 / p99 latency.
  <https://nghttp2.org/documentation/h2load.1.html> ·
  <https://nghttp2.org/documentation/h2load-howto.html>
- **Connection/session rate as a server-side metric** — HAProxy's stats page
  exposes current connection rate (clients connecting, not yet full sessions)
  and session rate with CSV export; the idiomatic server-side cross-check to
  the client-side receipt.
  <https://www.haproxy.com/blog/exploring-the-haproxy-stats-page>
- **e2-micro shape** — GCP E2 shared-core family documentation ("E2
  shared-core machine types… micro = 0.5 GB per vCPU") and the e2-micro
  reference (2 shared vCPU / 1 GB): the modeled 2-vCPU/1-GB target.
  <https://cloud.google.com/compute/docs/general-purpose-machines> ·
  <https://gcloud-compute.com/e2-micro.html>
- **Envoy CONNECT config (relay)** — canonical `configs/proxy_connect.yaml`:
  HCM `http2_protocol_options.allow_connect: true`, `connect_matcher {}` route,
  `route.upgrade_configs [{upgrade_type: CONNECT}]` (CONNECT is otherwise 403).
  <https://raw.githubusercontent.com/envoyproxy/envoy/main/configs/proxy_connect.yaml> ·
  <https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/upgrades>
- **HAProxy CONNECT relay model** — `option http_proxy` direct-tunnel forward
  proxying was removed in HAProxy 2.5, and the `do-resolve`+`set-dst`+`set-dst-port`
  dynamic-destination replacement does not route the HTTP-mode connect in
  3.4.7 (verified in-suite: origin never contacted, 503). HAProxy 3.4's
  supported CONNECT mechanism in `mode http` is to forward the CONNECT request
  to a static origin and tunnel after a 2xx — the relay model used here,
  identical in shape to Envoy's. This choice is documented in
  `scripts/bench/haproxy-connect.cfg` and was a measured decision, not a silent
  convenience.
- **Version pinning** — Envoy FAQ: benchmark a **release binary**, latest point
  release. Both subjects are the pinned latest-stable binaries from the bench
  image (`alumina-d59gq`: Envoy v1.40.2 published 2026-10-27; HAProxy 3.4.7 on
  branch 3.4, branch 3.5 still `-dev`).

---

## 8. Suite files (reference)

- `scripts/bench_workload.py` — the driver: open-loop steady/storm engines,
  TLS1.3 byte-exact echo backend (MSG_PEEK CONNECT-preamble tolerance), DNS
  responder (UDP+TCP), report/verdict model, tri-state selftest.
- `scripts/bench_run.sh` — host supervisor: image + alumina-sha fail-closed
  pins (`HEAD_CANDIDATE_SHA`), echo-backend-sha fail-closed pin
  (`BENCH_ECHO_SHA`), `BENCH_BACKEND=compiled` default (`python` fallback to the
  in-process EchoBackend), podman session, receipts to `.ooda/benchmarks/`.
- `scripts/bench/run.sh` — in-container supervisor body: topology staging +
  supervision + `BENCH-OK`/`INVALID`/`FAIL` exits.
- `scripts/bench/Dockerfile` — pinned bench image (trixie-slim + Envoy 1.40.2 +
  HAProxy 3.4.7 binaries).
- `scripts/bench/envoy-connect.yaml` — Envoy CONNECT relay config.
- `scripts/bench/haproxy-connect.cfg` — HAProxy CONNECT relay config (`option
  http-no-delay` set — M-02 storm p50 stall fix).
- `scripts/bench/echo-backend/` — M-03 compiled Rust/rustls static-musl TLS1.3
  echo backend crate (`Cargo.toml`, `src/main.rs`; own empty `[workspace]`, out
  of the alumina closure by design). Built to
  `.ooda/echo-backend/echo-backend-musl` and sha-pinned fail-closed.
- `.ooda/echo-backend/echo-backend-musl` — the compiled echo backend binary
  (sha `efa64083…` on the M-04 path; gitignored build artifact, not committed).

---

## 9. Results (corrected, 2026-10-28)

Corrected M-04 boundary-equivalent results recorded from repo HEAD `85b7769`
(tree clean: `dirty_count=0` for every receipt): alumina binary sha-pinned
fail-closed at `HEAD_CANDIDATE_SHA` = `executed_binary_sha256` `1e173c13…ce82`
(M-01 upstream TCP_NODELAY fix included), compiled Rust echo backend
`efa64083…72cd` (M-03), pinned bench image `7c3937c1…b449c` (Envoy v1.40.2,
HAProxy 3.4.7). All nine timed runs are interleaved **A-E-H** per profile
(alumina → envoy → haproxy), SECONDS 60 / WARMUP 5, every receipt `valid=True`.
The JSON receipts in `.ooda/benchmarks/85b7769-*.json` are the source of truth.
Latency columns report the frame data path (`latency.actual_send_to_echo`,
p50/p95/p99 in µs — the cross-subject comparable measure, §1).

### Corrected timed results (M-04)

| Profile | Subject | achieved Mbps | fulfilled | p50 / p95 / p99 (µs) | CPU mean / peak (cores) | RSS mean (KiB) | missed_at_end | Receipt |
|---|---|---|---|---|---|---|---|---|
| 1gbps steady | alumina | 999.969 | false | 1050 / 1150 / 1150 | 0.409 / 0.440 | 211188 | 0 | `85b7769-bench-alumina-1gbps-timed-20261028T131504Z` |
| 1gbps steady | envoy | 999.834 | false | 150 / 1150 / 1250 | 0.484 / 0.640 | 65949 | 0 | `85b7769-bench-envoy-1gbps-timed-20261028T131621Z` |
| 1gbps steady | haproxy | 999.725 | false | 1150 / 1150 / 1250 | 0.370 / 0.480 | 24948 | 0 | `85b7769-bench-haproxy-1gbps-timed-20261028T131729Z` |
| storm150 | alumina | n/a (storm) | true | 150 / 41950 / 42250 | 0.028 / 0.119 | 210915 | – | `85b7769-bench-alumina-storm150-timed-20261028T131839Z` |
| storm150 | envoy | n/a (storm) | true | 250 / 41750 / 42150 | 0.051 / 0.544 | 65121 | – | `85b7769-bench-envoy-storm150-timed-20261028T131947Z` |
| storm150 | haproxy | n/a (storm) | true | 150 / 41750 / 42150 | 0.031 / 0.080 | 25262 | – | `85b7769-bench-haproxy-storm150-timed-20261028T132055Z` |
| storm50 | alumina | n/a (storm) | true | 250 / 41850 / 42450 | 0.011 / 0.077 | 210832 | – | `85b7769-bench-alumina-storm50-timed-20261028T132204Z` |
| storm50 | envoy | n/a (storm) | true | 250 / 41550 / 42250 | 0.022 / 0.077 | 64867 | – | `85b7769-bench-envoy-storm50-timed-20261028T132313Z` |
| storm50 | haproxy | n/a (storm) | true | 150 / 41450 / 42250 | 0.013 / 0.078 | 25068 | – | `85b7769-bench-haproxy-storm50-timed-20261028T132423Z` |

Corrected per-subject storm establishment latency (µs, `latency.setup_latency`) —
**with the F8 caveat (§1)**: the receipt semantics "CONNECT start → handshake
complete" cover different path lengths per subject (relay+origin answer+TLS for
Envoy/HAProxy vs CONNECT+TLS for alumina), so these are properties of each
subject's own path, never an apples-to-apples comparison.

| Profile | Subject | setup_latency p50 / p95 / p99 (µs) |
|---|---|---|
| storm150 | alumina | 1150 / 1550 / 1850 |
| storm150 | envoy | 1350 / 1850 / 2150 |
| storm150 | haproxy | 1250 / 1750 / 1950 |
| storm50 | alumina | 1350 / 2050 / 2450 |
| storm50 | envoy | 1550 / 1850 / 2050 |
| storm50 | haproxy | 1450 / 1650 / 1850 |

### Honest readings (M-04, corrected)

- **1gbps: ~999.7–999.97 Mbps for all three subjects, all `workload_fulfilled=false`.**
  The M-03 compiled backend lifted the python GIL ceiling (F1, §5) to the
  open-loop target. The fulfilled flag is now a **tiny honest open-loop tail at
  the 1000 Mbps target**, not a proxy deficiency: `missed_at_end=0` for all,
  `sent==echoed` (1.830998M / 1.830751M / 1.830551M frames), with
  `backpressure_unsent` alumina 56 / envoy 303 / haproxy 502 (~0.003–0.03% of
  ~1.83 M) and a 29–33-frame `drain_echoed` just at close — the open-loop
  client's outstanding-cap marker, never a certified-to-1000 (caveats below).
  **Alumina is the closest to target** (999.969 Mbps, 56/1,831,054 = 0.003%
  backpressure) and is the only subject with a `fulfilled=True` 1gbps receipt on
  record (2 s smoke: 0 backpressure / 3 drain).
- **Storms: `workload_fulfilled=true` for all six runs** — storm150 9000/9000
  and storm50 3000/3000 planned sessions established exactly,
  `setup_failures={}` (0), `send_failed=0`, `protocol_errors=0`,
  `frames_echoed==frames_sent` 1:1. `setup_latency` fell ~40–50% (e.g. alumina
  storm150 p50 1950→1150 µs, storm50 2950→1350 µs) — the same drain fix
  benefiting session establishment.
- **Storm p50 attribution (why the ~40 ms is gone)**: the pre-fix
  ~40.65–40.95 ms data-path p50 for alumina and haproxy was the
  **first-segment delayed-ACK/Nagle stall on the proxy→origin path** — fixed by
  alumina upstream `TCP_NODELAY` in dial (M-01, commit `df54c44`) and haproxy
  `option http-no-delay` (M-02, `490aff5`); envoy had no such stall (its p50 was
  0.55–1.05 ms pre-fix). Data-path p50 now ≈ 0.15–0.25 ms for all subjects,
  matching envoy's data path.
- **Uniform ~41–42.5 ms p95/p99 storm tail persists across every subject and
  profile** — harness-scheduler cadence, not proxy latency; the single max
  outlier was one alumina storm150 frame at 83 ms of ~90k (recorded, not
  silent).
- **Identity/fidelity**: `dirty_count=0`, `source_head=85b7769`,
  `executed_binary_sha256=1e173c13…ce82` (alumina) vs pinned image binaries
  (envoy `b9d6d1e0…`, haproxy `d2e03232…`), `image_id=7c3937c1…b449c`,
  `host_cpus=8`, `host_mem_gib=14`, tool sha `c6bd1524`, OpenSSL 3.5.7,
  python 3.13.5. RSS alumina ≈ 211 MiB — unchanged fixed named-buffer pool,
  profile-invariant (§2).

### Caveats (M-04)

- **`fulfilled=false` at ~1000 Mbps is an open-loop cap, not a proxy fail**:
  `missed_at_end=0` and the tiny `backpressure_unsent` / `drain_echoed`-at-close
  (0.003–0.03%) mean the client never certified to 1000; read the achieved rate
  **and** the fulfilled flag together (F1, §5).
- **Uniform ~41–42.5 ms p95/p99 storm tail = harness cadence, cross-subject**:
  identical tails across subjects and profiles are the scheduler's quanta, not
  proxy latency; per-frame p50 is the load-bearing proxy signal.
- **2 s smoke vs 60 s timed are not equivalent**: smoke validates path
  correctness fast and can show `fulfilled=True` where the 60 s timed run shows
  `fulfilled=False` at the same nominal profile (1gbps alumina: smoke True /
  timed False). Timed receipts are the authoritative results.
- **Residual M-04 surprises (recorded, not silent)**: (1) one haproxy storm50
  smoke attempt exited `valid=False reasons=['unknown-cpu']` (missing end
  boundary-tick observation for all three samplers — harness 2 s-sampling
  flake; the storm workload itself was clean 100/100 sessions, 0 setup
  failures); the re-run was `valid=True` and the flake receipt is retained
  (`85b7769-bench-haproxy-storm50-smoke-20261028T131415Z.json`). (2) A spurious
  client `cores_peak` on two 1gbps timed runs (10.3 / 11.7 cores, alumina and
  haproxy) from one boundary-tick sample — same flake family; proxy and backend
  CPU peaks are clean and are the values reported in the table above.

---

## 10. P2 measurement protocol (frozen 2026-10-29) — exact candidate `3f587e9`

Frozen protocol for the P2 measurement package (columns E2–E4,
`alumina-cdwui.15/.16/.17`), adopted before any P2 measurement has run. The
protocol, the receipt fields, and the honesty rules are fixed against the one
exact candidate identity from the P1 integration gate
(`alumina-cdwui.20`, commander-verified); evidence rows may not choose their
own yardstick after seeing numbers. It **extends** this document (§1–§9) and
changes nothing in them; it is not a benchmark framework and creates no files.

### 10.1 Binding rule and non-authorizations

- E2–E4 run **only** the exact commands in §10.5–§10.7 against the exact
  candidate in §10.2, file **only** the receipt fields named there, and judge
  them with the §10.4 verdict alphabet. A fresh executor must not need anything
  outside this section beyond the §-cited invocation/schema tables.
- **No optimization target is preselected**, and **no `fulfilled=true` is
  required** for a receipt to be valid. A lower achieved goodput than a
  baseline is a **finding to disclose**, never a failure and never a veto.
- **No optimization implementation is authorised by this protocol.** This is a
  measurement contract only. `alumina-73t4t` and `alumina-bsiv6` remain
  separate, **unauthorised** change proposals and are not inputs here.
- New receipt fields, new profiling/instrumentation, and new harness seams are
  **out of scope** for E1–E4. A scenario or profile that needs one is recorded
  `BLOCKED`/`Unknown` (§10.4) and routed as a seam decision — never silently
  worked around and never answered with an earlier candidate's number.

### 10.2 Exact candidate identity (P1 gate, `alumina-cdwui.20`)

| Item | Identity (record verbatim) |
|---|---|
| Source SHA | `3f587e947fa8f050954b2f1fa7ec6b47012ac769` (short `3f587e9`; sole parent `ad82b77c…`; 19 commits `c27115e..HEAD`; no push) |
| P1 base / changed set | base `eedec45`; 10 paths: `README.md`, `docs/architecture.md`, `docs/serving-datastructure.html` (deleted), `src/config.rs`, `src/enforcement/policy.rs`, `src/incident_report.rs`, `src/log.rs`, `src/serve.rs`, `src/serving.rs`, `src/serving/tests.rs` |
| Canonical spec digest | `e39dd75d33635d582e981bfcb4f91fa92e3f23f2bf9a408c3d7dcd5079cd4401` (unchanged; CANONICAL-DIGEST-OK) |
| Executed artifact sha256 | `c869192e67032597c4b490de16260cdc33b5b7a811cb7e37308f9b5d25274031` (`target/release/alumina`; production digest identical to the D4 candidate `a19d407`) |
| Builder | podman connections `flock-vm` (rootless) / `flock-vm-root` (rootful); pinned `docker.io/library/rust@sha256:484dce…2779a` |
| Pinned bench image (§3) | `localhost/alumina-bench:20261027`, id `7c3937c1…b449c` = `BENCH_IMAGE_ID` (fail-closed) |
| Compiled echo backend (§5/§8) | `.ooda/echo-backend/echo-backend-musl`, `BENCH_ECHO_SHA` fail-closed; pinned sha `efa64083…72cd` (§9), but **record** the value actually used on each run |
| Podman connection | rootful `BENCH_PODMAN_CONNECTION` (fail-closed unless reachable; `--network none`) |
| Alumina bench binary | `.ooda/alumina-head/baseline/alumina-musl`, `aarch64-unknown-linux-musl`, `HEAD_CANDIDATE_SHA` fail-closed; build + stage recipe in §10.5 "Alumina binary note", expected sha `c869192e…` |

#### 10.2.1 Clean-identity caveat (mandatory on every P2 receipt)

The P1 gate earned **CONDITIONAL-COMPLETE**, not clean-tree qualification: at
gate time `git status --porcelain` was non-empty because of one **foreign,
untracked** file `scripts/verify_alt.sh` (99,890 B; sha256
`85465b4c96daeef4234ac33168b4d831548aed0f7d9b3b7f8df37bb7dda0c8ee`) — another
session's in-progress harness experiment, not authored by the gate, not a build
input, byte-stable across the run, deliberately not deleted/staged/ignored.
(The same external session produced `arch_alt/architecture-review.md`,
`d25b3458…0802f`, mid-run on one aborted attempt; treat any such foreign
untracked path the same way.)

Consequence for P2: **every receipt must state the working-tree identity it
actually ran on (§10.3) and that a clean-tree re-run is required before any
production-qualification claim.** No P2 receipt may be presented as clean-tree
or production qualification.

### 10.3 Working-tree identity record (the checkout is contended)

The harness's `identity.dirty_count` counts only tracked modifications
(`git status --porcelain --untracked-files=no`) and therefore does **not** see
untracked foreign files. Each P2 run MUST additionally capture, into the run
record beside the JSON receipt:

- `git rev-parse HEAD` — must equal §10.2's source SHA;
- a full `git status --porcelain --untracked-files=all` snapshot **before and
  after** the run (identity bracket), with `sha256` + size of any untracked
  file on both snapshots (SOURCE-IDENTITY-STABLE discipline, as in the P1
  gate);
- the `BENCH-ECHO-IDENTITY` / `BENCH-BINARY-IDENTITY` lines emitted by
  `bench_run.sh` (stdout; the fail-closed pins). `BENCH-BINARY-IDENTITY` is
  **alumina-only** (`bench_run.sh` emits it only under `PROXY=alumina`); on
  envoy/haproxy the binary identity is the pinned image id + the receipt's
  `identity.executed_binary_sha256`, so a missing binary-identity line on those
  subjects is not an `Unknown`;
- the rootful `BENCH_PODMAN_CONNECTION` name used.

A run whose bracket does not hold (identity changed mid-run) is `Unknown`
(§10.4), never a measured receipt.

### 10.4 Verdict alphabet (pass / fail / invalid / Unknown)

Receipt level — decided by the JSON receipt alone:

| Verdict | Decided by (existing receipt fields) |
|---|---|
| `valid` | `valid=true`, `reasons=[]`, `verdict="valid"`, identity attrs equal to the §10.2 pins actually used, plus a held §10.3 bracket |
| `invalid` | `valid=false` with non-empty `reasons` (corruption, missing-bytes, protocol disorder, timeout, partial send, accounting break, unknown-cpu) — a **measurement-invalid** determination, **never a proxy finding**; re-run and retain the invalid receipt (M-04 flake precedent, §9 caveats) |
| `Unknown` | harness/operational: `BENCH-FAIL` (in-container body) / `BENCH-HOST-FAIL` (host-side, `exit <n>`), `BENCH-BLOCKED` (podman/image/pin unreachable), a sampler probe typed `sampling.*.unknown=true`/`probe_failures`, an unreadable receipt, or an un-resolvable identity — record with the observed capability; never folded into `valid`, never a clean or negative proxy verdict |

Rules every receipt MUST satisfy (cite §5/§9, do not re-derive):

1. **Offered load is never reported as achieved goodput.** `--target-mbps` /
   `params.target_mbps` is the offer; the headline is
   `interval_vs_cohort.achieved_client_payload_mbps`, read with
   `workload_fulfilled` shown alongside (F1).
2. **`fulfilled=false` with `missed_at_end=0`** (tiny `backpressure_unsent` +
   a `drain_echoed`-at-close open-loop tail) is **disclosed** as an open-loop
   cap and read as such — never as a proxy failure (F1, §9 caveats).
3. **Absent capability ⇒ `BLOCKED`/`Unknown`** with the observed capability
   recorded (§10.6, §10.7) — never a fabricated number and never a substitute
   candidate; `85b7769` or any pre-P1 SHA stays comparison-only (§6).
4. A failed probe is typed `Unknown` (`sampling.*.unknown`), never folded clean.
5. **Ceiling attribution.** `achieved < offered` with a near-saturated
   `sampling.<client|backend>.cores_mean` (shared-harness bottleneck, e.g. the
   GIL-bound echo backend, §9 F1) is a **shared-harness ceiling** and must be
   labelled as such — never the proxy-path cost; only a non-saturated read path
   attributes the delta to the proxy.

E-increment level (the whole E2/E3/E4 row):

| Verdict | Decided by |
|---|---|
| `pass` | every prescribed run completed with a `valid` receipt at the §10.2 candidate + a held §10.3 bracket + honesty rules; a lower goodput than baseline is a disclosed finding, not a failure |
| `fail` | a prescribed run could not be completed as specified (harness `BENCH-FAIL`, `invalid` receipt from an un-diagnosed cause, a missing required field, or identity not pinned to §10.2) |
| `invalid` | the run produced a measurement-invalid receipt (re-run required; unusable as measured) |
| `Unknown`/`BLOCKED` | capability absent (E3), seam not expressible (E3/E4 variants), bracketed identity unstable, or sampler `unknown` — with the observed capability recorded; routed, never substituted |

### 10.5 E2 — reproduce 1-Gbps + connection-storm receipts

**Objective.** Reproduce the §9 profile set on the exact candidate §10.2,
producing new receipts judged by §10.4. The comparison source is the **timed**
receipts only — `.ooda/benchmarks/85b7769-bench-*-timed-*.json` (interleaved
A-E-H; SECONDS 60 / WARMUP 5; `dirty_count=0`); the 2 s smoke receipts
(`…-smoke-…json`) are never comparison inputs (§4). Before any comparison is
claimed, show the baseline pins equal on both sides: bench image id,
executed/retained binary sha, `identity.tool_sha256`, openssl and python
versions. This candidate's numbers come only from its own new runs — §9 numbers
are never restated as this candidate's.

**Commands.** Timed runs interleaved **A-E-H** (alumina → envoy → haproxy),
SECONDS 60 / WARMUP 5; smoke (2 s, WARMUP 0) is an optional fast-path
correctness check only and never authoritative (cite §4 for the parameter
tables and selftests):

```sh
BENCH_IMAGE_ID=7c3937c1df71c3190730efb0975a4b17a9d646d737d76e9ac3075afd831b449c \
BENCH_PODMAN_CONNECTION=<rootful connection> \
HEAD_CANDIDATE_SHA=<§10.5 note below> BENCH_ECHO_SHA=<recorded value> \
sh scripts/bench_run.sh <alumina|envoy|haproxy> timed <1gbps|storm150|storm50>
```

Matrix: 3 subjects × 3 profiles = 9 timed runs (A-E-H per profile), each
receipt to `.ooda/benchmarks/3f587e9-bench-<subject>-<profile>-<kind>-*`
(`STAMP = <short-head>-bench-$PROXY-$WORKLOAD-$KIND-$TS`, `bench_run.sh`).

**Alumina binary note.** `HEAD_CANDIDATE_SHA` must name the sha of a
`aarch64-unknown-linux-musl` build of §10.2 with its builder/toolchain
recorded. Build and stage it exactly as follows (every step below is a pin, not
a suggestion):

```sh
# toolchain 1.99.0 (rust-toolchain.toml) via the pinned builder images
# docker.io/library/rust@sha256:484dce…2779a (§10.2 Builder; verify.sh canary);
# target fixed at aarch64-unknown-linux-musl (bench_run.sh BENCH_RUST_TARGET).
cargo +1.99.0 build --locked --release --target aarch64-unknown-linux-musl --target-dir target
# stage the statically-linked artifact where bench_run.sh mounts it
# (host `.ooda/…` -> container `/ooda/…` -> `/work/alumina`, run.sh):
install -m 0755 target/aarch64-unknown-linux-musl/release/alumina .ooda/alumina-head/baseline/alumina-musl
shasum -a 256 .ooda/alumina-head/baseline/alumina-musl   # expect the §10.2 sha below
```

The P1-gate executed artifact is `c869192e…` (`target/release/alumina` —
statically-linked aarch64 musl ELF, digest asserted equal to D4 candidate
`a19d407`); a §10.2 (`3f587e9`) build is expected to reproduce it. **The file
now staged at `.ooda/alumina-head/baseline/alumina-musl` is the old `85b7769`
build (`1e173c13…ce82`)** — running the candidate `HEAD_CANDIDATE_SHA` against it
fails closed (`BENCH-BLOCKED: alumina binary identity mismatch`,
`bench_run.sh`), which is the intended outcome until the rebuild above lands. A
fresh build that does **not** reproduce `c869192e…` is fail-closed too: record
the delta and the exact build inputs, and retag the run `Unknown` (identity not
pinned to §10.2, §10.4) — never run or number an unpinned binary. If a build
from §10.2 reproduces the sha, cite it; if its sha differs, record the delta and
the build inputs explicitly — the candidate stays §10.2, but the receipt names
exactly what ran.

**Required receipt fields** (all existing, §5). The steady and storm report
schemas differ (verified against the §9 receipts
`85b7769-bench-alumina-1gbps-timed-…json` and
`85b7769-bench-alumina-storm50-timed-…json`): a **storm receipt has no
`phases` block, no `interval_vs_cohort.achieved_client_payload_mbps`, no
`interval_vs_cohort.drain_*`, and its `latency` holds only
`actual_send_to_echo` + `setup_latency`** (no `sched_to_echo`, no `send_lag`).
Requiring a storm-absent field would force every clean storm run to `fail`
(§10.4), so the rows are split by profile.

Steady `1gbps` runs:

| Purpose | Fields |
|---|---|
| Identity | `identity.source_head`, `identity.dirty_count` + §10.3 bracket, `identity.retained_binary_sha256`, `identity.executed_binary_sha256`, `identity.image_id`, `identity.rust_target`, `identity.config_sha256`, `identity.tool_sha256`, `identity.openssl_version`, `identity.python_version`, `identity.workload_label` |
| Model | `e2micro_model.host_cpus`, `host_mem_gib`, `modeled_vcpu`, `modeled_mem_gib` |
| Headline goodput | `interval_vs_cohort.achieved_client_payload_mbps`, `params.target_mbps`, `workload_fulfilled` |
| Fulfilment honesty | `phases.measure.backpressure_unsent`, `phases.measure.missed_at_end`, `interval_vs_cohort.drain_echoed_frames`, `phases.measure.unechoed` |
| Latency | `latency.actual_send_to_echo` / `sched_to_echo` / `send_lag` p50/p95/p99 + `max_us` + `overflow_count` |
| CPU / RSS | `sampling.<client\|backend\|proxy>.cores_mean` / `cores_peak` / `rss_current_mean_kb` / `rss_current_peak_kb` / `vmhwm_kb` / `unknown` / `probe_failures` |
| Validity | `valid`, `reasons`, `verdict`, `kind=timed`, `mode` |

Storm `storm150`/`storm50` runs:

| Purpose | Fields |
|---|---|
| Identity / Model | (same Identity and Model rows as steady above) |
| Storm honesty / progress | `storm.{arrivals_planned, arrivals_attempted, connections_established, sessions_completed, setup_failures, frames_sent, frames_echoed, session_errors, protocol_errors, send_failed_sessions, peak_live, peak_dialing}`, `interval_vs_cohort.{data_echo_observe_window_s, in_window_sent_frames, in_window_echoed_frames}`, `workload_fulfilled`, `params.target_mbps` |
| Storm latency | `latency.actual_send_to_echo` + `latency.setup_latency` (each p50/p95/p99 + `max_us` + `overflow_count`) |
| CPU / RSS | (same CPU / RSS row as steady above) |
| Validity | `valid`, `reasons`, `verdict`, `kind=timed`, `mode` |

Do **not** require `phases.measure.*`, achieved goodput, `drain_*` counters,
`sched_to_echo`, or `send_lag` on storm receipts — those fields do not exist
there. The storm is a connection-churn/progress test, not a goodput reading.

**E2 verdict.** Per §10.4: `pass` = all 9 receipts `valid` at §10.2 with a held
§10.3 bracket and honesty rules — whatever the goodput or `fulfilled` values.
`invalid` receipts are re-run and retained with reasons disclosed; an
un-resolvable identity or harness failure makes the row `Unknown`/`fail`.

### 10.6 E3 — 10-Gbps burst/sustained: capability preflight, then measure-or-BLOCKED

**Capability preflight (explicit; run first; all observable via existing
seams):**

1. **Target architecture.** The alumina subject is the fixed-profile
   `aarch64-unknown-linux-musl`, single-boot/single-serving-owner build (§10.2,
   `docs/alumina-proxy.md`); the modeled target is e2-micro (2 shared vCPU /
   1 GB, §2). Ten Gbps through **one** serving owner is a CPU-homing question
   of the proxy on this host, not a network-cabling fact: record `rust_target`
   + the modeled target, do not assume an egress NIC.
2. **Network ceiling.** The aperture is in-container `--network none` over a
   loopback global-unicast alias `8.8.8.8/32` (§2/§3): the ceiling is the
   loopback path + echo backend + open-loop client at 4096 B frames, not a
   device. Any 10-Gbps claim can only ever be "proxy-on-this-harness" and must
   say so.
3. **Backend / load-generator headroom.** The compiled echo backend must drain
   ≥ the offered rate and the open-loop client must offer it without
   saturating its own cores. Headroom is read from the E2 1gbps timed
   receipts: `e2micro_model.host_cpus` and `sampling.<client|backend>.cores_mean`
   — near-saturated sampler cores at 1 Gbps imply no honest 10× headroom.
   Record the estimate and disclose it as an estimate. Note that
   `e2micro_model.host_cpus` / `host_mem_gib` are **hard-coded literals** in the
   report writer (`bench_workload.py`: 8 CPUs / 14 GiB), not observed values —
   accurate on today's host, false on any other — so the executor must also
   record `nproc` and `/proc/meminfo` beside any receipt that claims headroom.
4. **Expressibility seam.** The documented invocation accepts only the
   `E2MICRO_LABELS` set `1gbps|storm150|storm50`, and `1gbps` pins
   `--target-mbps 1000` (`bench_run.sh`, `E2MICRO_LABELS` in the driver; the
   `e2micro_model` receipt block is only attached for those labels). A 10-Gbps
   steady/burst profile is **not expressible through `sh scripts/bench_run.sh …`
   today** without a harness seam change — which is **out of this docs-only
   protocol's authority** and must be a separate seam decision (new workload
   label / `--target-mbps 10000` wiring) before any 10-Gbps numbers.
   Independently of the label set, `bench_workload.py` rejects
   `--target-mbps > 2000` (`MAX_TARGET_MBPS`, "target-mbps out of range",
   exit 3) and caps the outstanding-cap argument at `MAX_OUTSTANDING_CAP = 8192`
   — a seam decision must lift those constants too, not just wire the label.

**Determination.** If any preflight item cannot establish 10-Gbps capability,
**or** the expressibility seam is not authorized, E3 records
**`BLOCKED`/`Unknown`** with the observed capability values — never a
fabricated 10-Gbps figure, never a substitute candidate.

**Runnable command retained when the capability is absent:** the E2 1gbps
timed alumina run, re-executed at the exact candidate:

```sh
BENCH_IMAGE_ID=7c3937c1df71c3190730efb0975a4b17a9d646d737d76e9ac3075afd831b449c \
BENCH_PODMAN_CONNECTION=<rootful connection> \
HEAD_CANDIDATE_SHA=<§10.5 note> BENCH_ECHO_SHA=<recorded value> \
sh scripts/bench_run.sh alumina timed 1gbps
```

Its receipt's `e2micro_model` + `sampling.*.cores_mean` +
`interval_vs_cohort.achieved_*` become the observed-capability record that E3
files its `BLOCKED`/`Unknown` determination against.

### 10.7 E4 — slow-peer backpressure and full-allowlist DNS/deadline (existing seams only)

No new production metrics and no new instrumentation: every field exists in
§5, and every injection point is an existing driver seam or a measured
constant.

**a) Slow-peer / backpressure — observed base captured; scenario `BLOCKED`.**
The 1 Gbps run does **not** create a slow or stalled consumer: the only client
mechanic is the open-loop admission cap (`--outstanding-cap`), and the §9 M-04
receipt shows 56/1.83 M unsent frames with `missed_at_end=0` — the backend
drained immediately. Nothing in §10.5 stalls the sink, so the E4 requirement
("at least one slow/stalled consumer alongside active bulk tunnels and new
CONNECT admissions; measure progress of unrelated tunnels", `alumina-cdwui.17`)
is **never exercised**. The slow-consumer injection point is the sink-delay seam
— the driver's `--echo-delay-s` backend knob (b) — a harness seam change, **out
of this docs-only protocol's authority**. Until a seam decision authorizes it,
this slice is **`BLOCKED`/`Unknown`** (§10.4); the E2 `1gbps` timed alumina run
is retained only as the **observed base backpressure** record — command = §10.5,
required fields `phases.measure.backpressure_unsent`,
`phases.measure.missed_at_end`, `interval_vs_cohort.drain_*_frames`,
`phases.measure.unechoed`, `latency.send_lag`, `latency.sched_to_echo`
p50/p95/p99, `sampling.backend.cores_mean`. A "valid receipt reporting these
fields" is **never** a pass predicate for a scenario the run never exercised;
zero backpressure with `missed_at_end=0` is reported as such and the slice
stays `BLOCKED`.

**b) Slow-peer sink-drain injection — seam-gated.** The driver already exposes
the per-echo delay knob `--echo-delay-s` (backend role; default 0.0) and the
`BENCH_BACKEND=python` one-line fallback (§5), but `run.sh` does not currently
pass the knob through. Wiring it is a harness seam change — **out of this
docs-only protocol's authority**. Until a seam decision authorizes it, this
variant is `BLOCKED`/`Unknown` with the observed base backpressure (slice a) +
the deadline constants, never fabricated.

**c) Full-allowlist DNS failure/recovery + deadline-progress.** The golden path
stages **one allowlisted name** — `[allowed_fqdn."example.com:443"]` (`run.sh`)
— and a DNS responder answering `example.com → 8.8.8.8`; the driver's
responder answers NXDOMAIN for any name it has no answer for (an existing
seam). E4's required **32-name allowlist** is not staged by the harness today.
A controlled failure-and-recovery phase therefore needs two `run.sh`/staging
seams: (1) expand the staged allowlist to the 32 names, and (2) point the
responder away from `example.com` (or drop its answer) then restore it — both
**out of this docs-only protocol's authority**. Until a seam decision authorizes
them: `BLOCKED`/`Unknown` with the observed capability recorded.

Deadline-**progress under load**, by contrast, is measurable now on the storm
profiles with no seam change: the fixed constants `params.setup_deadline_s`
(5.0), `params.drain_deadline_s` (5.0) and the 5.0 s no-progress STALL_LIMIT
are already in every receipt, and the storm row's `storm.{arrivals_attempted,
connections_established, sessions_completed, setup_failures}` plus
`valid`/`reasons` (incl. `timeout`) show whether the candidate makes progress
within the deadlines at churn. Command = the E2 `storm50`/`storm150` timed
alumina invocations (§10.5). Verdict: §10.4 — `setup_failures={}` and
`valid=true` are measured facts to disclose, not thresholds this protocol sets.

### 10.8 Frozen receipt lifecycle

- New receipts land in `.ooda/benchmarks/3f587e9-bench-<subject>-<profile>-<kind>-<ts>.json`
  (gitignored, §3/§5 pipeline); `.ooda/benchmarks/85b7769-bench-*-timed-*.json`
  remain the comparison source (smoke receipts are never comparison inputs) and
  are untouched.
- A `valid` receipt later found to misstate its §10.3 working tree is
  reclassified `Unknown` and re-run — never amended in place.
- Any E2–E4 row that cannot follow §10.5–§10.7 halts and reports
  `BLOCKED`/`Unknown` with the observed capability and the exact reason —
  never a partial number and never an earlier candidate's receipt.

---

## References

1. Envoy performance FAQ — benchmarking best practices:
   <https://www.envoyproxy.io/docs/envoy/latest/faq/performance/how_to_benchmark_envoy>
2. Envoy CONNECT/upgrades overview (CONNECT off by default; connect_matcher;
   relay vs terminate):
   <https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/upgrades>
3. Envoy canonical CONNECT config:
   <https://raw.githubusercontent.com/envoyproxy/envoy/main/configs/proxy_connect.yaml>
4. h2load manual — `-r/--rate` fixed connection-creation rate; p50/p95/p99
   output: <https://nghttp2.org/documentation/h2load.1.html> and
   <https://nghttp2.org/documentation/h2load-howto.html>
5. HAProxy stats page — connection rate / session rate + CSV:
   <https://www.haproxy.com/blog/exploring-the-haproxy-stats-page>
6. GCP E2 machine types (shared-core, micro = 0.5 GB per vCPU):
   <https://cloud.google.com/compute/docs/general-purpose-machines>
7. e2-micro reference (2 shared vCPU / 1 GB):
   <https://gcloud-compute.com/e2-micro.html>
8. Evidence bead `alumina-d59gq` (bd) — captured primary-source pass for the
   above (2026-10-27).
9. Linus review-report `alumina-152lm` (bd) — APPROVE of SM-2 (commit
   `238e7fa`), findings F1/F8 carried into this document.

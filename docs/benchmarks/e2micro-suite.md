# Alumina — e2-micro benchmark suite (1gbps + connection storms, Envoy/HAProxy comparison)

Benchmark suite for the Alumina egress proxy (CONNECT forward proxy) moduli: the
fresh `bench` suite replaces the deleted legacy suite (SM-1). It measures
Alumina against the two market CONNECT-capable forward proxies — Envoy and
HAProxy — under an e2-micro-shaped workload, with results to be recorded in the
Results section by the boundary run (SM-4).

This document is methodology, metrics, and invocation reference. The Results
section is a **placeholder** until SM-4's boundary run populates it with
receipts. Nothing in a placeholder counts as a measurement.

- Topic: methodology (research-first, per evidence bead `alumina-d59gq`).
- Status: SM-3 (doc + placeholder). Results pending SM-4.
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

- Host: arm64 Apple VM, 4 CPU / 14 GiB memory, Linux via rootful podman
  (`flock-vm-root`), `--network none`, everything on a loopback global-unicast
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

# timed (60 s measure, 5 s warmup) — the boundary-run (SM-4) profile
HEAD_CANDIDATE_SHA=<sha256 of .ooda/alumina-head/baseline/alumina-musl> \
BENCH_IMAGE_ID=7c3937c1… sh scripts/bench_run.sh <proxy> timed <profile>
```

- `HEAD_CANDIDATE_SHA` is **mandatory and fail-closed for alumina** (binary
  sha-verified before the session; a mismatch blocks the run). For the boundary
  run SM-4 rebuilds alumina from repo HEAD and pins its sha.
- `BENCH_IMAGE_ID` is mandatory fail-closed for every subject (image id
  verified against `localhost/alumina-bench:20261027` before the session).
- Optional `BENCH_PODMAN_CONNECTION` (default `flock-vm-root`), `BENCH_IMAGE`.

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

### F1 — the 1gbps profile is client-generator-limited: read achieved, not 1000

The 1000 Mbps figure in the steady profile is the **offered-load target**, not
a delivered guarantee. On this host the open-loop client (single-owner stdlib
selectors loop pacing a 32-tunnel cohort at 2048 outstanding) tops out below
schedule: SM-2 smoke receipts show planned 61,035 frames vs admitted/sent
~49–54k, i.e. **achieved_client_payload_mbps of 808 (alumina) / 881 (envoy) /
846 (haproxy)**, `workload_fulfilled=False`, `valid=True` (shortfall is honest
`backpressure_unsent`; an open-loop cap is not a failure reason by design).

Consequences, stated up front:

1. Every headline claim about the steady profile must be read at its
   **achieved** rate — `interval_vs_cohort.achieved_client_payload_mbps` — and
   `workload_fulfilled` must be shown alongside (F1).
2. The **relative comparison remains fair**: all three subjects receive the
   same offered load and the same scheduling, so the equal ceiling applies to
   all; this is a comparison of proxies at equal load, not an absolute-rate
   certification.
3. The correct reading of a clean SM-2 smoke: "proxy sustained the generator at
   ~810–880 Mbps offered payload on this host with a clean in-window verdict",
   never "1 Gbps delivered".

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
  `setup_latency` cross-subject incomparability (F8, §1), generator ceiling
  (F1, §5). Nothing is silently averaged across these.

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
  pins, podman session, receipts to `.ooda/benchmarks/`.
- `scripts/bench/run.sh` — in-container supervisor body: topology staging +
  supervision + `BENCH-OK`/`INVALID`/`FAIL` exits.
- `scripts/bench/Dockerfile` — pinned bench image (trixie-slim + Envoy 1.40.2 +
  HAProxy 3.4.7 binaries).
- `scripts/bench/envoy-connect.yaml` — Envoy CONNECT relay config.
- `scripts/bench/haproxy-connect.cfg` — HAProxy CONNECT relay config.

---

## 9. Results (placeholder — filled by boundary run, SM-4)

Results are recorded by the SM-4 boundary run, which rebuilds alumina from repo
HEAD (sha-pinned fail-closed), runs the interleaved matrix below on the pinned
bench image, and back-fills this section with receipt-cited numbers (plus the
F1 `achieved_client_payload_mbps` + `workload_fulfilled` columns per run).

| Profile | Subject | achieved_client_payload_mbps | workload_fulfilled | latency p50 / p95 / p99 (µs) | CPU mean / peak | RSS mean / peak (KiB) | Receipt |
|---|---|---|---|---|---|---|---|
| 1gbps steady | alumina | (pending) | (pending) | (pending) | (pending) | (pending) | (pending) |
| 1gbps steady | envoy | (pending) | (pending) | (pending) | (pending) | (pending) | (pending) |
| 1gbps steady | haproxy | (pending) | (pending) | (pending) | (pending) | (pending) | (pending) |
| storm150 | alumina | n/a (storm) | (pending) | (pending) | (pending) | (pending) | (pending) |
| storm150 | envoy | n/a (storm) | (pending) | (pending) | (pending) | (pending) | (pending) |
| storm150 | haproxy | n/a (storm) | (pending) | (pending) | (pending) | (pending) | (pending) |
| storm50 | alumina | n/a (storm) | (pending) | (pending) | (pending) | (pending) | (pending) |
| storm50 | envoy | n/a (storm) | (pending) | (pending) | (pending) | (pending) | (pending) |
| storm50 | haproxy | (pending) | (pending) | (pending) | (pending) | (pending) | (pending) |

Storm `setup_latency` will be reported per subject **with the F8 caveat** (not
cross-subject comparable); storm data-path latency uses `actual_send_to_echo`.
Placeholders deliberately assert no measurement.

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

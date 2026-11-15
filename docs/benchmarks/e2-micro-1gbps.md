# Alumina — e2-micro benchmark method (1 Gbps class, three CONNECT proxies)

The method measures three HTTP CONNECT forward proxies — alumina, Envoy, and HAProxy —
against an `e2-micro` GCP target, on **two headline metrics**: sustained throughput and
response time. It is a method, not a receipt: **Status: method defined; not yet executed
on GCP.** It supersedes the event-trail benchmark suite removed 2026-11-15 (historical
receipt `git:597f730:docs/benchmarks/e2micro-suite.md`). That suite measured a retired
loopback harness on a host VM; what survives is the method below, the interpretation
rules, and its historical readings as a labelled record.

## Non-goals

- **No feature or security equivalence claim** — cost on a shared path says nothing about what either product can enforce.
- **No packets-per-second claim** — GCP publishes no `e2-micro` PPS figure, so none is claimed or implied.
- **No claim about behaviour inside the tunnel** — only the CONNECT exchange, the initial ClientHello, and the frame data path are observed.
- **Not a production-qualification artefact** — the repository is a scoped local QA candidate; this method qualifies nothing.

## GCP target facts

| Fact | Value | Source |
|---|---|---|
| Shape | `e2-micro`: 2 shared vCPUs at a **0.25-vCPU fractional baseline**, 1 GB memory | <https://cloud.google.com/compute/docs/general-purpose-machines>; <https://gcloud-compute.com/e2-micro.html> |
| Max egress bandwidth | **"Up to 1" Gbps** — a tiered platform cap for the shape | <https://cloud.google.com/compute/docs/network-bandwidth> |
| MTU condition | Reached only near the default VPC MTU of **1460** | <https://cloud.google.com/vpc/docs/mtu> |
| Cap semantics | A **ceiling** shared with all instance traffic — **not a guaranteed or committed rate** | <https://cloud.google.com/compute/docs/network-bandwidth> |
| Persistent disk | Writes limited to **60%** of the corresponding read throughput on this disk class | <https://cloud.google.com/compute/docs/disks/performance> |

**Loopback is rejected as a bandwidth measure.** A loopback aperture measures CPU and the
network stack, not egress bandwidth. GCP publishes **no loopback exemption** from the
egress cap, so any loopback-derived bandwidth figure is carried as `[UNCONFIRMED]` —
never reported as an `e2-micro` bandwidth result.

## Topology

```text
client VM  ──CONNECT──▶  alumina on e2-micro  ──TCP──▶  echo origin
(open-loop,              (the measured subject)         (byte-exact TLS 1.3
 unthrottled)                                            framed echo)
```

All three live in one VPC with separate network identities. Client and origin are
load/sink infrastructure, not measured subjects: their cost is disclosed, never attributed.

## Metrics

- **Sustained throughput** — achieved client payload Mbps over the measurement window,
  always reported **with the offered rate**; offered load is never reported as achieved.
- **Response time** — per-frame data-path p50 / p95 / p99 in µs (client send → echo
  received), the cross-subject comparable measure.
- **Supporting series** — CPU mean/peak, RSS, setup latency: disclosed, never headline.

## Method

- **Open-loop client**, never throttled by observed latency (a closed-loop client measures
  its own queueing); **32 sustained tunnels**; **60 s measurement window + 5 s warmup**.
- **Per-subject identity pins** — source revision, executed binary/image digest, config
  digest, tool version; an unpinned run is not a result. **One JSON receipt per run**.
- **Verdict alphabet**: `valid` (receipt self-consistent and identity pinned) · `invalid`
  (measurement invalid, never a finding about a proxy; re-run and retain both) · `Unknown`
  (harness/operational failure or absent capability, never folded into `valid`, never a clean
  verdict) · per-increment `pass`/`fail`.
- **Absent capability is recorded `BLOCKED`/`Unknown`** with the observed capability, never a
  fabricated number. **Repeat: not yet executed on GCP** — no receipt exists in the tree.

## Reading the results

### Relay-vs-direct asymmetry (must-read before interpreting results)

- **Direct tunnel (alumina)**: the client sends `CONNECT example.com:443`; alumina answers
  its own `200 Connection Established`, resolves the authority itself, and opens raw TLS
  to the origin immediately.
- **Relay (Envoy, HAProxy)**: the proxy connects to a configured origin first, forwards the
  client's CONNECT request line and the origin's `200 Connection Established`, and only
  then starts TLS — session establishment carries an extra local origin round trip and an
  origin-side 200.
- The retired loopback harness bridged the two models: its TLS 1.3 echo backend peeked
  (never consumed) the first bytes and answered a relayed CONNECT with exactly one 200
  before the handshake, so a plain ClientHello was never consumed. That property belongs to
  the retired harness; a GCP harness must establish the equivalent deliberately, or measure
  each model against its own origin.

**Comparable after 200 + TLS**: frame data-path latency, steady throughput, and per-subject
CPU/RSS — the relay cost is one-time per connection, and frames flow only after TLS is up.
**Not comparable, never head-to-head**: storm `setup_latency` (relay = relay + origin 200 +
TLS; direct = CONNECT + TLS) and peak-CPU shape (per-worker knobs vs a single serving owner).

### Host-vs-target disclosure

The M-04 receipts were **host measurements**: an 8-CPU / 14 GiB arm64 Apple VM, rootful
container, loopback global-unicast alias, modelling `e2-micro` by workload parameters
only, with **no cgroup CPU/mem cap**. They are **not** `e2-micro` measurements. The method
above is designed for the target itself; until it runs, every number in this document is
host-measured and generalises only through this disclosure.

### Honest readings (M-04, corrected)

The source receipts (`.ooda/benchmarks/85b7769-*.json`) **are absent from the tree**. These
numbers are **historical and not re-derivable** from this repository; they are recorded
because they are the last full three-subject comparison, not because they can be
reproduced. Corrected M-04, 2026-10-28:

| Profile | Subject | achieved Mbps | fulfilled | p50 / p95 / p99 (µs) | CPU mean / peak (cores) | RSS mean (KiB) | missed_at_end |
|---|---|---|---|---|---|---|---|
| 1gbps steady | alumina | 999.969 | false | 1050 / 1150 / 1150 | 0.409 / 0.440 | 211188 | 0 |
| 1gbps steady | envoy | 999.834 | false | 150 / 1150 / 1250 | 0.484 / 0.640 | 65949 | 0 |
| 1gbps steady | haproxy | 999.725 | false | 1150 / 1150 / 1250 | 0.370 / 0.480 | 24948 | 0 |
| storm150 | alumina | n/a (storm) | true | 150 / 41950 / 42250 | 0.028 / 0.119 | 210915 | – |
| storm150 | envoy | n/a (storm) | true | 250 / 41750 / 42150 | 0.051 / 0.544 | 65121 | – |
| storm150 | haproxy | n/a (storm) | true | 150 / 41750 / 42150 | 0.031 / 0.080 | 25262 | – |
| storm50 | alumina | n/a (storm) | true | 250 / 41850 / 42450 | 0.011 / 0.077 | 210832 | – |
| storm50 | envoy | n/a (storm) | true | 250 / 41550 / 42250 | 0.022 / 0.077 | 64867 | – |
| storm50 | haproxy | n/a (storm) | true | 150 / 41450 / 42250 | 0.013 / 0.078 | 25068 | – |

- **1gbps: ~999.7–999.97 Mbps for all three subjects.** `workload_fulfilled=false` is a tiny
  open-loop tail at the 1000 Mbps target (`missed_at_end=0`, `sent==echoed`), not a proxy
  deficiency: read achieved rate **and** the flag together.
- **Storms: all six runs established their planned sessions exactly** — storm150 9000/9000,
  storm50 3000/3000, `setup_failures={}`, `protocol_errors=0`, `frames_echoed==frames_sent` 1:1.
- **Storm p50 attribution**: the pre-fix ~40.65–40.95 ms data-path p50 was a first-segment
  delayed-ACK/Nagle stall on the proxy→origin path, fixed by upstream `TCP_NODELAY`
  (alumina) and `option http-no-delay` (HAProxy); Envoy had no such stall. Data-path p50 is
  now ~0.15–0.25 ms for all subjects.
- **The uniform ~41–42.5 ms p95/p99 storm tail across every subject and profile is
  harness-scheduler cadence, not proxy latency.** Identical tails across subjects are the
  scheduler's quanta; per-frame p50 is the load-bearing proxy signal.
- **Relay `setup_latency` is not comparable across subjects** (relay + origin answer + TLS
  vs CONNECT + TLS); read it per subject, never head-to-head.
- **The 2 s smoke profile is not equivalent to the 60 s timed run** — a smoke run can be
  `fulfilled=true` where the timed run is `false` at the same nominal profile.

## Non-claims

- No published `e2-micro` PPS number is claimed or implied.
- These measurements are not a security-equivalence claim: achieving the bandwidth class
  says nothing about detection coverage or enforcement.
- Detection surfaces are enumerated in `docs/alumina-proxy.md` and compared at capability
  level in the [capability matrix](feature-matrix.md); a future run must add its own
  receipts, and nothing here is authoritative without one.

# Alumina Proxy — Domain filtering TLS proxy

Allowlist TLS egress in your cloud environments.

Alumina is an **HTTPS-on-TCP explicit HTTP CONNECT forward proxy**: each
allowlist entry declares its destination port (e.g. `api.github.com:443`,
`example.com:443`). Per connection it terminates two independent TCP sessions,
validates the TLS 1.3 ClientHello (version offer, SNI against the allowlist,
ECH rejection), and relays end-to-end TLS upstream **without decryption**.
For hard network-level isolation under workload RCE, deploy Alumina on a
separate VPC appliance identity (`listen = '0.0.0.0:<port>'`); a same-pod
multi-container sidecar (`listen = '127.0.0.1:<port>'`) is cooperative only
(see [Reference VPC appliance deployment pattern](#reference-vpc-appliance-deployment-pattern)).

Alumina can be deployed as a light weight explicit forward proxy to protect the egress
for your servers or containers by allowlisting which domains are eligible for
egress traffic. The idiomatic use case is to deploy Alumina Proxy with one container
or workload type in a VPC that limits egress to be exclusively through the
Alumina Proxy. In case of component compromise the attacker will have limited
opportunities for establishing egress; policy violations and early-upstream-data
events trigger configurable tripwire actions (`notify` / `block`) with bounded
stdout monitoring (`src/config.rs:906-907`; `src/enforcement/action.rs:28-31`;
spec §Tripwire actions, monitoring, and pacing → §Action catalog and
attribution). External delivery of `notify` events is a **deployment
responsibility** — see the [stdout collector runbook](#notify-delivery-stdout-collector-reliability-and-drop-alerting-runbook).

## Design philosophy

Alumina is deliberately narrow: it is the **exit gate** of the castle, nothing
more. It does not guard the interior, wall off attackers, or police ingress —
it guards the single exit through which your workload reaches the outside
world, and it guards that exit with a fixed, opinionated design rather than a
surface of configuration choices.

The trust model is not distrust of the system. Your application and you (the
operator) are trusted at rest; you hold full privilege over both application
and proxy configuration. Alumina exists because compromise is inevitable: when
an application is compromised, the proxy's job is to **identify** the
compromise and **protect against further exploitation** purely through egress —
the limit of its visibility and responsibility.

The core promise: **no silent acceptance of adversarial behavior**. In the
idiomatic deployment the only client is your trusted-at-rest application on a
fixed golden path, so a healthy workload produces zero deviations. A tripwire
firing is therefore a **high-value signal**: highly unexpected, and almost
certainly operator misconfiguration or adversarial activity. Every deviation is
detected and acted on; there is no tolerated rate of bad behavior. Tripwires
react on the first sign of deviation and are highly accurate. The action taken
(`notify` or `block`) is your configuration choice; Alumina does not always
panic by blocking all egress. Tarpit is reserved/deferred — it is not accepted
as an operational setting (`src/config.rs:908,1065`; spec §Tripwire actions →
Tarpit (deferred)). The all-scope block bar is operator-configurable
too: by default the first deviation arms all-scope block, and raising the bar
is your deliberate choice to tolerate a bounded burst — never a hidden
tolerated rate.

> "There will be no silent acceptance of adversarial behavior without action
> taken. The action may be `notify` or `block` (tarpitting is reserved/deferred,
> not accepted as an operational setting). We will not always panic by blocking
> all meaningful egress automation — that is an operator configuration choice.
> Alumina promises to deliver highly accurate tripwires. The operator decides
> what the appropriate action will be for their context."

Narrowness is the mechanism, not a compromise: a single purpose, a fixed
resource profile, and fixed security semantics make the proxy's invariants
provable — no post-boot allocation, a single boot and serving owner, bounded
buffers, no runtime-surface expansion. The fixed profile is the inviolable
contract; it never yields to a feature.

## Documents

| Document | Role |
| --- | --- |
| [alumina-proxy.md](docs/alumina-proxy.md) | **Canonical spec** — sole governing requirements |
| [docs/architecture.md](docs/architecture.md) | Conceptual design + as-built single-owner mapping (decisions D1–D7) |
| [docs/benchmarks/e2micro-suite.md](docs/benchmarks/e2micro-suite.md) | e2-micro benchmark suite (1gbps + connection storms) vs Envoy/HAProxy — methodology + corrected M-04 results |
| [docs/qa-package/README.md](docs/qa-package/README.md) | Local testQA run/validation instructions |
| [Notify delivery: stdout collector reliability and drop-alerting runbook](#notify-delivery-stdout-collector-reliability-and-drop-alerting-runbook) | Deployment-owned collector runbook: liveness, drop-alerting, restart semantics, failure drill |
| [docs/verification.md](docs/verification.md) | Verification instructions, command set + offline link checker |

## Runtime surface and fixed inputs

- `./config.toml` (≤ 16384 B, keyed `[allowed_fqdn."<fqdn>:<port>"]` tables per the `alumina-cfgk` amendment, mandatory keys, no defaults) carries the validated
  resolver set (1..=5 entries: bare `IP` on port 53, `IP#fqdn` on port 853, or
  `IP#fqdn#pin-sha256=<b64>` strict-pin on port 853); no `resolv.conf` read, no
  CLI args, no env overrides; one listening socket; **SIGTERM the only handled
  lifecycle signal** (spec §Architecture → Runtime surface).
- Privilege preflight (non-root, empty caps, `no_new_privs`): unmet → EX_CONFIG
  78; unresolved beyond allowance → EX_TEMPFAIL 75.
- Example config: `docs/qa-package/config.example.toml` (≤ 16384 B) shows the
  `resolver` entry plus the mandatory `[any_illegal]` and keyed
  `[allowed_fqdn."<fqdn>:<port>"]` (`early_data` per entry, `alumina-cfgk`
  keyed schema) tripwire tables with `<fqdn>:<port>` allowlist entries — a
  real-world HTTPS target
  (`api.github.com:443`) and illustrative domains (`example.com:443`,
  `www.example.net:443`); illustrative only, executed by no gate.

## Workload & protocol compatibility (zero proxy code changes)

Alumina's wire contract (spec §Protocol contract) is: an explicit
plaintext `HTTP/1.1` `CONNECT <fqdn>:<port>` (the port must exactly
match the allowlisted entry, e.g. `443`); then — after `200
Connection established` — the **client speaks first** with a TLS 1.3
`ClientHello` whose SNI equals `<fqdn>` (Barrier A); and the upstream server
sends **zero bytes before the validated `ClientHello` is flushed upstream**
(Barrier B — `EarlyUpstreamData` closes the tunnel if the server speaks
first). Once the gate opens, encrypted application bytes are relayed opaquely,
with no ALPN or application-protocol inspection (spec §Protocol contract,
Inspection scope).

| Workload | Transport | Compatible? |
| --- | --- | --- |
| HTTPS REST/API (`https://api.github.com:443`, e.g. `reqwest` with `HTTPS_PROXY=http://<proxy>:5353`, TLS 1.3) | TLS 1.3 `ClientHello` (SNI) immediately after `200` | **Yes** — works out of the box |
| NATS Mode 1 — standard NATS (`nats://` / `tls://` server-first StartTLS) | server-speaks-first plaintext `INFO {...}` before any TLS upgrade | **No** — even when the CONNECT port is authorized, the server-first plaintext `INFO` trips Barrier B (`EarlyUpstreamData`) and Barrier A (non-TLS client bytes) |
| NATS Mode 2 — NATS `tls_first` (`handshake_first: true`; `async_nats::ConnectOptions::tls_first()`) | client TLS 1.3 `ClientHello` (SNI) right after `200`; `INFO` inside the encrypted TLS 1.3 stream | **Yes** — wire-compatible, zero `alumina-proxy` changes |
| NATS Mode 3 — NATS over WebSockets (`wss://<nats-fqdn>:443`) | TLS 1.3 `ClientHello` (SNI) right after `200`; HTTP `Upgrade: websocket` + NATS frames inside the encrypted tunnel | **Yes** — wire-compatible, zero `alumina-proxy` changes |

`alumina-proxy` needs **zero code changes** for NATS workloads: the NATS
**client/workload** must (a) establish the TCP tunnel via
`HTTP CONNECT <nats-fqdn>:<allowlisted-port>` to Alumina and (b) match the
allowlisted entry's port and speak a TLS 1.3 `ClientHello` first (`wss://` or
`tls_first`).

## Reference VPC appliance deployment pattern

To enforce positive locking (spec §Deployment boundary → Typical deployment
pattern), the protected workload and Alumina must run under **separate
network-policy and runtime identities** so a compromised workload (RCE) cannot
bypass `HTTPS_PROXY` via direct `connect(2)` syscalls or reset latched
`Block Domain` / `Block All` tripwire state by crashing its own container.

### 1. Topology and VPC firewall confinement

```text
[Protected Serverless / Container Workload (tag: app-workload)]
   │  Direct VPC egress: all-traffic
   │  HTTPS_PROXY = http://<alumina-internal-ip>:5353
   ▼
[VPC Egress Firewall on app-workload]
   ├── ALLOW tcp:5353 -> <alumina-internal-ip>/32 (Alumina listener)
   ├── ALLOW link-local platform metadata if required by platform runtime
   └── DENY  all      -> 0.0.0.0/0 (blocks direct TCP/443, UDP/QUIC, and Private Google Access VIPs)
   │
   ▼
[Dedicated Alumina Appliance VM (tag: alumina-proxy, static internal IP, no public IP)]
   ├── INGRESS: ALLOW tcp:5353 from VPC subnet CIDR only (+ host iptables INPUT rule)
   ├── EGRESS:  ALLOW tcp:53,853 -> TCP-capable recursive resolver (via Cloud NAT or VPC resolver)
   ├── EGRESS:  ALLOW tcp:443  -> 0.0.0.0/0 via Cloud NAT (approved allowlist destinations)
   └── EGRESS:  DENY  all      -> 0.0.0.0/0 (all other ports and protocols denied)
```

- **Why a separate VPC appliance beats a same-pod sidecar under RCE:**
  - In serverless multi-container sidecar platforms (such as Cloud Run
    multi-container services), all containers in a revision share one network
    namespace (`CLONE_NEWNET`), one VPC IP/tag, and one pod lifecycle, and do
    not grant `CAP_NET_ADMIN` for per-UID `iptables` owner matching. Any
    firewall rule permitting the sidecar to reach `0.0.0.0/0:443` also permits
    an RCE payload in the application container to dial `:443` directly, and
    crashing the application container respawns the pod and clears in-memory
    tripwire latches.
  - Standard serverless HTTP ingress proxies (such as GFE / Cloud Run Services)
    terminate HTTP and reject raw `HTTP CONNECT` tunneling, and serverless
    Worker Pools do not accept unsolicited inbound TCP `SYN` connections on
    Direct VPC IPs. Hosting Alumina on a dedicated minimal VM appliance (e.g.
    Container-Optimized OS `e2-micro` with a static internal VPC IP) provides
    raw TCP `CONNECT` ingress and hard VPC firewall separation.

### 2. Minimal `FROM scratch` container image

Matches spec §Deployment boundary → Typical deployment pattern (hrdn4
restatement) — two files in the root filesystem (`/alumina`, `/config.toml`),
zero shell or OS utilities:

```dockerfile
FROM --platform=linux/amd64 rust:1.99.0-alpine AS builder
WORKDIR /build
RUN apk add --no-cache musl-dev && rustup target add x86_64-unknown-linux-musl
COPY Cargo.toml Cargo.lock ./
COPY src ./src
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release --target x86_64-unknown-linux-musl --bin alumina

FROM scratch
WORKDIR /
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/alumina /alumina
COPY config.toml /config.toml
USER 65534:65534
EXPOSE 5353
ENTRYPOINT ["/alumina"]
```

**`config.toml` note:** the `COPY config.toml /config.toml` line above
references the operator-supplied configuration, provided at image build time —
it is **not tracked in this repository**; see
`docs/qa-package/config.example.toml`.

### 3. Appliance runtime invocation and TCP DNS requirement

- **Container-Optimized OS host invocation (`--network host`):** use the
  idiomatic `#cloud-config` (`metadata.user-data`) with a declarative systemd
  unit (`alumina-proxy.service`) instead of imperative shell. The resolver is
  declared in `config.toml` at image build; the unit configures the registry
  credential helper, opens the narrow VPC ingress rule, pins the image by
  digest, and runs the container with the hardened profile:

  ```yaml
  #cloud-config
  write_files:
    - path: /etc/systemd/system/alumina-proxy.service
      permissions: "0644"
      owner: root
      content: |
        [Unit]
        Description=Alumina CONNECT Egress Proxy
        Wants=gcr-online.target docker.service
        After=gcr-online.target docker.service

        [Service]
        Environment="HOME=/var/lib/docker"
        Environment="DOCKER_CONFIG=/var/lib/docker/.docker"
        ExecStartPre=/usr/bin/docker-credential-gcr configure-docker --registries=<registry-host>
        ExecStartPre=/sbin/iptables -w -I INPUT -p tcp -s <vpc-subnet-cidr> --dport 5353 -j ACCEPT
        ExecStartPre=-/usr/bin/docker rm -f alumina-proxy
        ExecStartPre=/usr/bin/docker pull <registry-host>/<project>/<repo>/alumina-proxy@sha256:<digest>
        ExecStart=/usr/bin/docker run --rm --name alumina-proxy --network host --log-driver=gcplogs --workdir / --read-only --tmpfs /tmp:size=64m --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges <registry-host>/<project>/<repo>/alumina-proxy@sha256:<digest>
        ExecStop=-/usr/bin/docker stop -t 8 alumina-proxy
        Restart=always
        RestartSec=2s
        TimeoutStopSec=10s

        [Install]
        WantedBy=multi-user.target
  runcmd:
    - systemctl daemon-reload
    - systemctl enable --now alumina-proxy.service
  ```

  `--user 65534:65534`, `--cap-drop ALL`, and `--security-opt no-new-privileges`
  satisfy `src/preflight.rs` (`UID != 0`, `CapEff == CapPrm == CapAmb == 0`,
  `no_new_privs == 1`); `--network host` binds `0.0.0.0:5353` directly on the
  internal VPC interface without bridge NAT overhead; `--read-only` plus the
  `--tmpfs /tmp:size=64m` scratch mount keep the root filesystem immutable at
  runtime.
- **TCP-capable DNS resolver (via the config `resolver` entry):** Alumina
  performs DNS over TCP exclusively (spec §Configuration & DNS → Transport),
  with per-entry dial port 53 (bare `IP`) or 853 (DoT `IP#fqdn` / strict-pin
  `IP#fqdn#pin-sha256=<b64>` forms). Where a cloud provider's link-local
  metadata DNS (`169.254.169.254:53`) answers UDP only for external records,
  the `resolver` entry in `config.toml` (baked into the image) is set to a
  TCP-capable recursive resolver reachable over a narrow `tcp:53,853` firewall
  rule; no platform resolver file is read.
- **Client TLS 1.3 requirement:** Client HTTPS stacks using `HTTPS_PROXY` must
  offer TLS 1.3 (`0x0304`) as their minimum protocol version so `ClientHello`
  `supported_versions` does not advertise TLS 1.2 (`0x0303`), which Alumina
  rejects by design (spec §Protocol contract → Version offer).

## Notify delivery: stdout collector reliability and drop-alerting runbook

Deployment-owned companion to the `notify` action. The proxy owns detection,
denial, action, and **bounded, best-effort emission** into its single stdout
sink — nothing more ([docs/alumina-proxy.md](docs/alumina-proxy.md) §Log
delivery, §Monitoring). It **never guarantees delivery**. Everything that turns
that byte stream into an operator signal — the collector, its liveness, and
alerting on loss — is a deployment responsibility, in part because the proxy
cannot observe its own unread pipe (writes succeed into a buffer nobody reads).

### Who guarantees what (tested proxy behaviour vs deployment-owned assurance)

**Proxy-owned, tested** — rely on, do not re-verify:

- Nonblocking stdout: fd 1 is made nonblocking once (`src/log.rs:1319`), writes
  are `write_vectored` against a 16-op / 64 KiB per-turn budget
  (`src/log.rs:66-67`), and a stalled or full pipe can never stall serving
  (`src/log.rs:1574-1582`). A `WouldBlock` retains the partial cursor and
  retries (`src/log.rs:2049-2123`); byte conservation is exact.
- Bounded queue: 256 × 2 KiB (`src/log.rs:53-54`); on overflow a whole record is
  dropped and counted (`dropped`), never truncated.
- The monitor family is split into a reserved `kind=monitor` summary whose
  fixed core is admitted even when the queue is full, and best-effort
  `monitor_domain` / `monitor_capture` detail batches
  ([docs/alumina-proxy.md](docs/alumina-proxy.md):340).
- A failed sink latches permanently and the drain quiesces (`src/log.rs:1638`):
  no further records of any kind are emitted until the proxy restarts.

**Deployment-owned** — you must build and assure; no proxy test covers this:

- A **persistent reader** on proxy stdout. Write-succeeds ≠ received (the pipe
  buffers; nobody reading it is not visible to the proxy).
- **Collector liveness** and alerting on its death or a filled pipe (out-of-band;
  the proxy emits no "nobody is reading" record anywhere).
- **Backpressure**: read fast enough that the pipe never stays full long enough
  to overflow the 256 × 2 KiB queue into counted drops.
- **Gap detection and loss alerting** per the counters below, plus the honest
  acceptance that a dropped record and a dropped counter can themselves be lost.

### Capacity guidance (derived from recorded workload receipts, not an invented rate)

Two inputs: the fixed emission geometry (source fact) and the recorded workload
receipts ([docs/benchmarks/e2micro-suite.md](docs/benchmarks/e2micro-suite.md) §2,
§9; `.ooda/benchmarks/85b7769-*.json`, 85b7769 baseline).

**Receipt provenance / host disclosure.** The M-04 receipts are **host
measurements**, not e2-micro: they were recorded on an arm64 Apple VM (8 CPU /
14 GiB, rootful podman, loopback alias) modelling e2-micro by workload
parameters only, with no cgroup CPU/mem cap
([docs/benchmarks/e2micro-suite.md](docs/benchmarks/e2micro-suite.md):97-107).
Read the CPU/RSS numbers below as host-measured indications for a collector
budget, never as e2-micro certifications. The receipts measure **relay
throughput**, not notify stdout volume (the proxy emits essentially nothing on a
clean golden path).

**What the receipts record** (corrected M-04, §9): 1gbps steady alumina achieved
999.969 Mbps at 32 sustained conns with CPU mean/peak 0.409/0.440 cores and RSS
mean 211,188 KiB (`85b7769-bench-alumina-1gbps-timed-20261028T131504Z.json`);
storm150 (150 new conns/s) established 9000/9000 sessions with CPU mean/peak
0.028/0.119 cores and RSS mean 210,915 KiB
(`85b7769-bench-alumina-storm150-timed-20261028T131839Z.json`); storm50
established 3000/3000 at 0.011/0.077 cores RSS 210,832 KiB
(`85b7769-bench-alumina-storm50-timed-20261028T132204Z.json`).

**Guidance.** Size the collector with (1) a **buffer ≥ one full proxy queue
(512 KiB)** so a burst never backpressures the proxy into drops, and (2) a read
rate that stays ahead of your connection-churn class — the receipts bound the
classes at 150 new conns/s (storm150) and 50/s (storm50). Every notify-tripping
connection emits at most bounded per-connection warn/info records (≤ 2 KiB each)
folded into the monitor summary (reserved, ≤ 2048 B fixed core) and detail
batches (≤ 2048 B each, up to 3+3 per dirty second, `src/log.rs:60-63`); the
summary emits at most once per dirty whole-second (`src/enforcement/monitor.rs:351-353`).
Budget collector CPU/RAM in the same order of magnitude as the proxy's recorded
footprint above and never assume the proxy slows down for a slow reader.

### Alerting on proxy-observable loss (exact counters, units, observation point)

Alert thresholds are your configuration; the semantics below are fixed
constants. Every counter is saturating with an overflow flag; treat a nonzero
overflow flag as "count is a floor, not a total".

| Signal | Where | Unit (exact) | Means |
| --- | --- | --- | --- |
| `dropped` | `startup_final` ([src/log.rs](src/log.rs):1853) and `shutdown_final` (:1957) **only** — never in the monitor summary core (:883-909) | 1 per whole record lost, all classes | Whole-record loss over boot/full run. Long-run loss surfaces **only** at these two boundaries; while serving it is not refreshed in-band |
| `report_drops` / `oreport_drops` | every `kind=monitor` summary fixed core ([src/log.rs](src/log.rs):890-894) | 1 per dropped `monitor_domain` **batch** at report time (:1977; `src/enforcement/monitor.rs:320`) — a batch is up to 11 domain blocks, never per block | Queue-full refusal of a domain detail batch |
| `capture_drops` / `ocapture_drops` | every `kind=monitor` summary fixed core ([src/log.rs](src/log.rs):895-899) | **mixed, by design**: 1 per detail at capture time (later-relation suppression [serving.rs](src/serving.rs):2341-2358; 64-detail window eviction [monitor.rs](src/enforcement/monitor.rs):335) **and** 1 per dropped `monitor_capture` batch at report time ([log.rs](src/log.rs):1988) — a batch is up to 22 details | Capture-detail loss in mixed units; a nonzero value means detail loss, never treat "1" as "one detail" |
| `dx=` | `kind=monitor`, square brackets loss bitset, present only when nonzero ([src/log.rs](src/log.rs):984-995) | 1 bit per allowlist ordinal, hex | That ordinal's JA4-change facts overflowed the bounded detail |

**Notification drop path (drain/strand).** Records already in the queue that
cannot drain before a sink failure or at exit are counted under generic
`dropped` (strand/drain path, [src/log.rs](src/log.rs):1668, :2094-2102) — never
as `report_drops`/`capture_drops`. A forced shutdown summary stranded by a dead
sink is counted but **unobservable after exit** (the process is gone).

### Alerting on collector-observable absence + the honest limitation

- The monitor summary is **event-driven**: it is emitted only when the aggregate
  is dirty, at most once per whole second
  (`src/enforcement/monitor.rs:351-353`). On a silent golden path there are
  **no** periodic summaries at all — so "no summary for N s" is not an alarm by
  itself. Alert instead on **silence where emission was expected**: a stream that
  had been delivering `kind=monitor` lines (or an open DNS incident per the
  incident-summary window) going quiet for > N s ⇒ the sink latched failed
  (`src/log.rs:1638`, nothing more is ever emitted until proxy restart) **or**
  the collector died. Distinguish by checking collector liveness out-of-band;
  a latched sink is cleared only by an operator-controlled proxy restart.
- **A dropped record and a dropped counter can themselves be lost.** The summary
  line that would carry `report_drops`/`capture_drops` is itself a record the
  sink can strand; generic `dropped` refreshes only at startup/shutdown; and a
  collector that dies with a full pipe loses what was written-but-unread (those
  bytes are gone, succeeded, never read). Therefore: counters are a **lower
  bound** on true loss. The conservative operator response to any fired tripwire
  is to treat it as confirmed and investigate; the conservative response to a
  suspiciously *silent* stream with a healthy workload is never to conclude "no
  loss" from counter == 0 — verify the reader is actually consuming.
- **Conservative responses, by signal:** `report_drops`/`capture_drops`/`dx`
  growth ⇒ detail is gone (summary aggregates remain authoritative) — do not try
  to reconstruct detail, do not scale the proxy. Generic `dropped` at
  `shutdown_final` ⇒ the run's stdout corpus is incomplete — rebuild context
  from the collector's persisted stream and patch alerting. Silence after a
  latched sink ⇒ rotate: repair or replace the collector, then exercise the
  operator-controlled restart to clear the latch, expecting in-memory state
  reset (§ below).

### Restart semantics (state that is in-memory and does not survive)

- **Proxy restart** clears all in-memory enforcement state: the per-ordinal and
  all-scope block latches ([src/enforcement/state.rs](src/enforcement/state.rs):218,231,302-305)
  and the JA4 first-seen baselines ([src/serving.rs](src/serving.rs):951-953,
  "reset on restart"). A previously blocked or baselined identity is treated as
  first-seen again, and the monitor aggregate (including the drop counters in
  the summary) starts at zero. Treat a proxy restart as a clean-slate for block
  and baseline state; a restarted proxy does not resume prior latches.
- **Collector restart does not replay proxy history.** Proxy stdout is one-way
  and drained; there is no replay buffer. Records the collector missed are gone
  — either dropped and counted (queue overflow / strand) or written to a pipe
  it never read. After a collector restart, the persisted stream simply resumes
  at the proxy's current emission; do not expect past records, and do not
  back-fill from the proxy.

### Failure drill (stall the collector) — status: SPECIFICATION ONLY, not yet executed

Execution is D4's scope (bead `alumina-cdwui.13`) on the exact candidate. Prerequisites for the executor:

1. A running proxy with at least one `notify` action reachable on a fixed golden
   path; a collector process that reads proxy stdout and appends to a durable
   stream it can search; ability to stop and start the collector **without**
   restarting the proxy (separate process/identity); a way to generate one
   controlled notify-tripping event (e.g. the TLS 1.3-only JA4-change procedure
   in [docs/qa-package/README.md](docs/qa-package/README.md) §JA4
   change-signal verification).
2. **Stall** the collector (SIGSTOP or stop the service — not the proxy).
3. **Generate** one controlled notify event, then a second, a few seconds apart.
4. **Restore** the collector; let it drain and persist what remains queued in
   the pipe.
5. **Inspect drop/liveness signals** in the persisted stream: whether a
   `kind=monitor` summary appears and whether `report_drops`/`capture_drops`/`dx`
   are nonzero; whether records emitted during the stall are missing; and, on an
   operator-controlled proxy SIGTERM/start (restart is operator-controlled, a
   preserved constraint), whether `startup_final`/`shutdown_final` `dropped`
   stayed 0.

**Expected observations.** Two branches. (a) **No-loss branch (the honest default
for a small drill):** with a short stall and a handful of notify events, the
records are pipe-buffered — the write succeeds into the pipe, nothing is lost,
and the resumed collector delivers them late; `report_drops`/`capture_drops`/`dx`
and `startup_final`/`shutdown_final` `dropped` all stay 0. The pipe buffer and
the 256-slot in-memory queue absorb the burst. (b) **Loss branch (requires a
sustained burst, not a few events):** `report_drops`/`capture_drops` move only
if the in-memory queue is full **at report time** (a dropped `monitor_domain`
/`monitor_capture` batch, `src/log.rs:1977,1988`), and generic `dropped` moves
only when the queue overflows — both need enough un-drained records to exhaust
the 256 × 2 KiB queue, i.e. well over a hundred retained records with the
collector stopped. With the small burst a small drill generates, do not expect
counters to move; forcing branch (b) deliberately is its own larger drill. The
proxy never stalls serving in either branch (nonblocking sink).

**Pass / Unknown criteria.** PASS if: the proxy never stalled serving; some
subset of the events survived (pipe-buffered) and were drained after restore;
and every counter that moved is exactly explicable by the recorded geometry —
or, on the no-loss branch, all event records for the stall window are present
and all counters stayed 0. **Unknown** (record as Unknown, never PASS) if: the
collector or proxy OOM/thrashed (environment), a latched sink silently quiesced
(no in-band evidence by design), or the stall duration versus pipe capacity was
not measured. No direct-egress fallback is required anywhere in this drill — the
proxy's stdout pipe is the only path exercised.

## Repository layout

`src/main.rs` boot owner → `src/runtime.rs` shared-readiness serving loop;
`src/{serve,boot,config,resolver,preflight,inventory}.rs` boot path;
`src/enforcement/{mod,action,monitor,policy,state}.rs` tripwire/action/monitoring
surface (rp2e amendment); `src/{dns,connect,client_hello,startup_dns,cache,schedule,worker,gate,serving,eligibility,log}.rs`
serving/parser core; `src/serving/{policy,reject,startup,tests}.rs`,
`src/runtime/tests.rs`, `src/startup_dns/tests.rs` serving/startup decomposition
and sibling test modules; `src/{alloc,fault,fuzz}.rs` F1/F2/F4 scaffolds;
`scripts/` verification owners; `tests/` integration corpus.

## License

Dual-licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.

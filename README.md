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
attribution).

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

# Reference VPC appliance deployment pattern

To enforce positive locking (spec §Deployment boundary → Typical deployment
pattern), the protected workload and Alumina must run under **separate
network-policy and runtime identities** so a compromised workload (RCE) cannot
bypass `HTTPS_PROXY` via direct `connect(2)` syscalls or reset latched
`Block Domain` / `Block All` tripwire state by crashing its own container.

## 1. Topology and VPC firewall confinement

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
   ├── INGRESS: ALLOW tcp:5353 from <vpc-subnet-cidr> only — subnet-scoped, unauthenticated; see trust note
   ├── EGRESS:  ALLOW tcp:53,853 -> TCP-capable recursive resolver (via Cloud NAT or VPC resolver)
   ├── EGRESS:  ALLOW tcp:443  -> 0.0.0.0/0 via Cloud NAT (approved allowlist destinations)
   └── EGRESS:  DENY  all      -> 0.0.0.0/0 (all other ports and protocols denied)
```

The Cloud Run worker pool named in spec §Initial test target is the **initial
validation target** for behaviour and performance; the VM appliance in this
document is the **production reference pattern**. They are different roles, not
competing requirements — both must run under a network-policy and runtime
identity separate from the protected workload (spec §Deployment boundary).

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
    terminate HTTP and reject raw `HTTP CONNECT` tunneling. Cloud Run worker
    pools have no load-balanced endpoint, but Direct VPC connectivity for
    worker pools supports ingress as well as egress and documents inbound
    custom TCP to the instance's private VPC IP — the deployment shape the spec
    names as the initial test target. Hosting Alumina on a dedicated minimal VM
    appliance (e.g. Container-Optimized OS `e2-micro` with a static internal VPC
    IP) provides raw TCP `CONNECT` ingress and hard VPC firewall separation for
    the production reference pattern.

- **Ingress trust boundary — subnet-scoped, no client authentication.** The
  ingress rule above and the host `iptables` rule in §3 scope admission to the
  VPC subnet, not to the protected workload's identity. Alumina authenticates no
  client at accept: admission is delegated entirely to the network boundary. Any
  peer in that subnet that can reach the listener inherits the allowlist and the
  bounded capacity limits (512 tunnel slots and their reused buffers). The spec
  requires ingress restricted to the intended workloads (spec §Deployment
  boundary → Typical deployment pattern); subnet scope satisfies that only when
  the subnet contains the protected workload and no other untrusted peers. On a
  shared subnet, narrow the source to the workload's own address range (or to a
  firewall identity the platform can express) and keep the `iptables`
  `-s <vpc-subnet-cidr>` source in step with it.

## 2. Minimal `FROM scratch` container image

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
[the example configuration](qa-package/config.example.toml), whose resolver pins
are placeholders and must be replaced before use. The tracked example also binds
`listen = "127.0.0.1:5353"` for local testing; the appliance in §3 runs with
`--network host` and must bind `0.0.0.0:5353` (or the appliance's own internal
VPC address) so the VPC ingress rule reaches it. Every allowlist entry must
declare its `dns_assurance` trust class explicitly; a missing key fails startup
(exit 78).

## 3. Appliance runtime invocation and TCP DNS requirement

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
  satisfy `src/boot/preflight.rs` (`UID != 0`, `CapEff == CapPrm == CapAmb == 0`,
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

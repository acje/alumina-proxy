# Alumina Proxy

Alumina is an egress control boundary built on **least privilege and least
capability**. A workload may connect only to explicitly approved domains and
ports. The proxy has one responsibility: enforce that boundary, with the minimum
protocol scope and runtime capability needed to do so.

Alumina provides defense in depth against application compromise. It reduces a
compromised workload's opportunities for data exfiltration and command and
control, and detects departures from known-good behavior visible at the egress
boundary. The application is trusted at rest; Alumina limits what an attacker
can do after that trust is broken.

This protection depends on deployment preventing other routes to the network.
Abuse of approved endpoints remains outside Alumina's visibility. It is not a
general-purpose gateway, an ingress defense, or an encrypted-payload inspector.

## Design principles

Alumina follows [AloxStyle](https://github.com/acje/aloxstyle) for Rust code.
The governing requirements are the [specification](docs/alumina-proxy.md). Its
design constraints are narrow authority, bounded execution (fixed capacities,
one boot owner, one serving owner, two reused 128 KiB per-tunnel buffers), the
[allocation contract](docs/alumina-proxy.md#zero-allocation-invariant-scope),
and no silent acceptance of any deviation on the defined CONNECT,
initial-ClientHello and tripwire surfaces: the operator chooses `notify` or
`block`, the proxy owns the semantics.

## Security boundaries

- **TLS 1.3-only, client-first.** Clients establish a plaintext HTTP/1.1 CONNECT
  tunnel, then send a TLS 1.3-only ClientHello. ECH and server-first protocols
  are rejected. See
  [workload compatibility](docs/qa-package/README.md#protocol-compatibility-workloads-dialed-through-alumina).
- **No payload inspection.** The client must verify the upstream certificate
  and hostname. Abuse inside an admitted endpoint's encrypted traffic is outside
  the proxy's visibility.
- **Delegated DNS assurance, not local DNSSEC validation.** DNS uses TCP or
  strict-pinned DNS over TLS. Plain DNS does not authenticate DNS data and
  unpinned DoT fails closed. Strong profiles require the operator's
  root-validating policy declaration; delegated DNSSEC depends on that
  resolver actually validating. An AD bit alone does not prove a root anchor.
- **Deployment enforces confinement.** Separate workload and proxy
  network/runtime identities are required to prevent direct-egress bypass and
  workload-controlled resets of block state. A same-pod sidecar is cooperative
  only.
- **Notifications are best-effort.** The deployment owns stdout collection,
  collector liveness, and loss alerting. Proxy restarts clear in-memory block
  state and JA4 baselines.

## DNS assurance

Each allowlisted `name:port` must declare `dns_assurance`; a missing key fails
startup with exit 78, and `resolver_trusted` must be declared explicitly. The
stronger profiles require strict-pinned resolvers plus an operator-declared
root-validating no-stale policy. Endpoint verification stays client-owned: the
client, not the proxy, checks the upstream certificate and hostname. See the
[governing assurance rules](docs/alumina-proxy.md#hardening-per-entry-dns-assurance-and-qualified-admission)
and [trust-chain design](docs/trust-chain-design.md).

## Getting started

The repository is a **scoped local QA candidate**, not a production-qualified
or externally deployed system. Qualification requirements and validation
prerequisites are documented in the [QA package](docs/qa-package/README.md).

Alumina reads `./config.toml`; there are no CLI arguments or environment
overrides. The [example configuration](docs/qa-package/config.example.toml)
documents the required schema, but its resolver pins are placeholders, not
ready-to-run credentials.

Use the [deployment guide](docs/deployment.md) for the static container build,
privilege requirements, and VPC firewall pattern. Configure clients to use
`HTTPS_PROXY=http://<proxy>:5353` with TLS 1.3-only enabled.

For local build and validation prerequisites, follow the
[QA package](docs/qa-package/README.md) and
[verification commands](docs/verification.md).

## Documentation

- [Specification](docs/alumina-proxy.md): sole governing requirements.
- [Deployment](docs/deployment.md): container, runtime, and network confinement.
- [Monitoring](docs/monitoring.md): stdout collection, loss alerting, and
  restart semantics.
- [Benchmarks](docs/benchmarks/e2micro-suite.md): methodology, results, and
  limitations.
- [Trust-chain design](docs/trust-chain-design.md): current status and
  conditional goal.

## License

Dual-licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.

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

- **Narrow authority.** Admit allowlisted HTTP CONNECT destinations, validate
  the initial TLS 1.3 ClientHello and matching SNI, then relay without
  decryption. Additional protocols and runtime controls are outside the fixed
  scope.
- **Bounded execution.** Fixed capacities, a single boot owner and a single
  serving owner, and two reused 128 KiB directional buffers per tunnel constrain
  resource use and make invariants explicit and verifiable.
- **Allocation discipline.** Serving and DNS-refresh paths reuse storage
  allocated at initialization, with no first-party heap allocation or
  deallocation except the authorized per-connect DoT setup. Bounded dependency
  allocations are outside that invariant's scope; see the
  [allocation contract](docs/alumina-proxy.md#zero-allocation-invariant-scope).
- **No silent acceptance.** Every deviation on the defined CONNECT,
  initial-ClientHello, and tripwire surfaces triggers action. The operator
  chooses `notify` or `block`; Alumina owns the enforcement semantics.

Robustness comes from these constraints, not an expanding feature set. The
lightweight, statically linked single binary is an implementation of that
design.

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

Each allowlisted `name:port` has an immutable minimum: omission defaults to
`resolver_trusted` and preserves legacy bounded stale-serving; operators can
select `resolver_authenticated` or `delegated_dnssec`. Both stronger settings
require every configured resolver to be strict-pinned and the operator to
declare `root_validating_no_stale`. Delegated DNSSEC additionally requires the
resolver's AD verdict. The proxy does not independently validate DNSSEC or
establish the resolver's trust anchors, clock or no-stale behavior; those are
deployment conditions, not consequences of the AD bit.

Startup readiness and every actual upstream connection attempt, including
retries, check the entry's current proof against its minimum. Strong profiles
do not admit expired or absent proof, promote zero-TTL evidence, or silently
fall back to weaker resolution. A and AAAA are observed separately, never
combined into a best-family assurance claim. The proxy attempts bounded
per-entry assurance records at full, degraded or failed startup and on
material changes, including idle expiry. Logging is best-effort: a record
attempt is not a delivery or availability guarantee. See the
[governing assurance rules](docs/alumina-proxy.md#hardening-per-entry-dns-assurance-and-qualified-admission),
[as-built architecture](docs/architecture.html), and
[trust-chain status](docs/trust-chain-design.md).

Endpoint verification stays client-owned: the client — not the proxy —
checks the upstream server certificate and hostname; client certificates apply
only under mutual TLS; SNI matching is already separate policy. Achieved
assurance is not an availability guarantee; monitoring follows the
[monitoring](docs/monitoring.md) model.

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
- [Architecture](docs/architecture.html): source-derived, as-built reference.
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

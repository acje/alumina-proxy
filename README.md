# Alumina Proxy

Alumina is an egress control boundary built on **least privilege and least
capability**. A workload may connect only to explicitly approved domains and
ports. The proxy has one responsibility: enforce that boundary, with the minimum
protocol scope and runtime capability needed to do so.

The application and operator are trusted at rest; the design accounts for
application compromise. Alumina limits the resulting egress opportunities and
surfaces deviations from the workload's known-good behavior. It is not a
general-purpose gateway, an ingress defense, or an encrypted-payload inspector.

## Design principles

- **Narrow authority.** Admit allowlisted HTTP CONNECT destinations, validate
	the initial TLS 1.3 ClientHello and matching SNI, then relay without decryption.
	Additional protocols and runtime controls are outside the fixed scope.
- **Bounded execution.** Fixed capacities, a single boot owner and a single
	serving owner, and two reused 128 KiB directional buffers per tunnel constrain
	resource use and make invariants explicit and verifiable.
- **Allocation discipline.** Serving and DNS-refresh paths reuse storage
	allocated at initialization, with no first-party heap allocation or deallocation
	except the authorized per-connect DoT setup. Bounded dependency allocations
	are outside that invariant's scope; see the
	[allocation contract](docs/alumina-proxy.md#zero-allocation-invariant-scope).
- **No silent acceptance.** Every deviation on the defined CONNECT,
	initial-ClientHello, and tripwire surfaces triggers action. The operator chooses
	`notify` or `block`; Alumina owns the enforcement semantics.

Robustness comes from these constraints, not an expanding feature set. The
lightweight, statically linked single binary is an implementation of that design.

## Security boundaries

- **TLS 1.3-only, client-first.** Clients establish a plaintext HTTP/1.1 CONNECT
	tunnel, then send a TLS 1.3-only ClientHello. ECH and server-first protocols
	are rejected. See [workload compatibility](docs/qa-package/README.md#protocol-compatibility-workloads-dialed-through-alumina).
- **No payload inspection.** The client must verify the upstream certificate
	and hostname. Abuse inside an admitted endpoint's encrypted traffic is outside
	the proxy's visibility.
- **No DNSSEC today.** DNS uses TCP, optionally strict-pinned DNS over TLS.
	Unpinned DoT currently fails closed; plain DNS does not authenticate DNS data.
- **Deployment enforces confinement.** Separate workload and proxy network/runtime
	identities are required to prevent direct-egress bypass and workload-controlled
	resets of block state. A same-pod sidecar is cooperative only.
- **Notifications are best-effort.** The deployment owns stdout collection,
	collector liveness, and loss alerting. Proxy restarts clear in-memory block
	state and JA4 baselines.

## Planned assurance controls

**Not implemented — a strategic goal, not a current guarantee.** Delegated
DNSSEC validation is the selected approach; its governed amendment and
implementation remain future work. A qualified, trusted validating recursive
resolver would supply the DNSSEC verdicts over authenticated, strict-pinned
DNS-over-TLS; see the [trust-chain design](docs/trust-chain-design.md).

- **TODO.** Admission would require a configured minimum DNS assurance level and
	a currently valid achieved proof per new CONNECT `name:port` — bounded
	lifetimes, no stale or expired proofs, no unchecked TTL-zero extension, and
	no fallback to a weaker unauthenticated path.
- **TODO.** Report achieved assurance for every allowlisted `fqdn:port` at the
	startup resolution/readiness decision — successful, degraded, or failed —
	including unresolved and unattempted results, then on meaningful
	validation-level changes. Judge A/AAAA independently; never label the whole
	entry secure from its best family.

Endpoint verification stays client-owned: the client — not the proxy — checks
the upstream server certificate and hostname; client certificates apply only
under mutual TLS; SNI matching is already separate policy. Achieved assurance
is not an availability guarantee; monitoring follows the
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
- [Monitoring](docs/monitoring.md): stdout collection, loss alerting, and restart semantics.
- [Benchmarks](docs/benchmarks/e2micro-suite.md): methodology, results, and limitations.
- [Trust-chain design](docs/trust-chain-design.md): future goal, not a current guarantee.

## License

Dual-licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.

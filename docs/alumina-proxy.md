# Alumina Proxy - Domain-level filtering for HTTPS egress

## Overview

Alumina is a non-terminating forward proxy for HTTPS over TCP, admitting connections to a configured FQDN allowlist. Its priorities are integrity, bounded resources, low latency, least privilege, and a minimal feature set. It supports a single golden-path profile: a simple, known-good, cloud-platform-agnostic configuration, rather than general compatibility or automatic negotiation between proxy operating modes. Environments whose complexity or technical debt prevents adopting this profile should use a more capable alternative, such as GCP Secure Web Proxy. Application-protocol verification is not a goal.

The typical use case is a cloud-hosted server whose outbound integrations call a small set of approved third-party HTTPS services. Alumina is a niche alternative to a managed secure web proxy for this profile, not a feature-equivalent replacement. Clients explicitly use Alumina; deployment-enforced network isolation blocks alternate HTTPS egress even when clients ignore proxy settings. Together, these controls are analogous to positive locking: default-deny egress with explicit destination authorization, enforced independently of application cooperation. The analogy describes confinement, not a guarantee against misuse of approved endpoints. This pattern is independent of cloud provider or compute platform.

## Threat model

Alumina must resist attempts by a compromised application in the same VPC to alter its integrity, control, or destination enforcement. It restricts the egress it provides to reduce opportunities for data exfiltration and command and control (C2), not to provide comprehensive prevention.

DoS resistance is a design goal, but availability cannot be guaranteed within fixed resource limits. In the idiomatic deployment, the assumed availability blast radius is the HTTPS egress path of the VPC containing the compromised application. In typical deployments the unavailability of egress from a compromised VPC will not be the critical issue.

**Accepted limitation:** Alumina restricts CONNECT hostnames and DNS-derived network destinations, and requires matching SNI. It does not authenticate the upstream server or enforce the origin named inside encrypted application requests. An approved endpoint may expose attacker-controlled resources or permit access to other origins through domain fronting or connection coalescing. A compromised application may abuse these capabilities for data exfiltration or command and control, including by supplying its own credentials. These activities are outside Alumina's enforcement scope. Allowlisting a domain therefore accepts the risk of capabilities reachable through its admitted endpoints, not merely the application's intended use of that domain.

## Protocol contract

Alumina supports HTTPS over TCP to limit its protocol surface, not to verify that admitted tunnels carry HTTPS. Clients use explicit proxy configuration and plaintext HTTP/1.1 CONNECT with a configured `<fqdn>:<port>` target — an allowlisted FQDN and its allowed TCP port, 1 through 65535, e.g. `api.github.com:443` — followed by a TLS 1.3-only ClientHello with SNI. TLS 1.2 and earlier profiles, plain HTTP forwarding, HTTP/1.0 CONNECT, HTTP/2 CONNECT to the proxy, UDP/QUIC, and transparent interception are unsupported. HTTP versions inside the encrypted tunnel are opaque to Alumina.

Fail-closed behavior applies to unsupported or invalid input observable in CONNECT and ClientHello, and to internal failures. Once admitted, tunnel contents are relayed without application-protocol verification; Alumina cannot detect unsupported behavior hidden inside the encrypted stream.

```text
Read CONNECT -> Authorize hostname
-> Connect upstream, reading the current cache before each attempt
-> Send 200 -> Read and validate ClientHello
-> Forward buffered bytes -> Relay -> Drain/close
```

The [security invariants](#i-security--authorization-invariants) govern upstream connection establishment and release of buffered tunnel bytes. Before a successful CONNECT response begins, failures may receive an HTTP error response; once it begins, failures close the connection without injecting another HTTP response or a TLS alert. Only completion of a successful response permits ClientHello inspection; buffered tunnel bytes remain gated by authorization.

Open the upstream-to-client forwarding gate in the worker transition that accounts for successful local socket writes of all original wire bytes through the end of the validated ClientHello, before any subsequent upstream read. Write completion does not confirm remote receipt ([send(2)](https://man7.org/linux/man-pages/man2/send.2.html)). Do not infer arrival ordering for activity first observed after the gate opens.

CONNECT headers and ClientHello are parsed incrementally with separate byte limits and an absolute setup deadline. ClientHello may span TCP reads and TLS records; inspection preserves the original bytes for forwarding. Reject malformed framing and duplicate or ambiguous SNI.

### CONNECT request

Alumina's own configuration is strict; client input is accepted where variants have a single meaning and rejected where interpretation could differ.

- **Accept:** any hostname case, compared in lowercase; `Content-Length: 0`. Ignore all other headers, including `Host` and `Proxy-Authorization`.
- **Reject:** a destination port of `0`, a leading-zero or non-numeric port, a port above `65535`, or a `<fqdn>:<port>` pair whose hostname or port does not exactly match one allowlisted entry; nonzero `Content-Length`, any `Transfer-Encoding`, bare LF line endings, and obs-fold.
- **One request per connection:** close after any error response.
- **Errors:** Policy violations, which indicate misconfiguration or compromise, receive an empty body: `400` malformed request, `403` hostname not allowlisted. Runtime conditions receive a fixed plain-text body stating the reason: `502` no resolved addresses or upstream connection failed, `503` no capacity, `504` setup deadline expired. Client input is never echoed.

### TLS ClientHello profile

- **Version offer:** Require the `supported_versions` extension with TLS 1.3 (`0x0304`) as its only non-GREASE version. Reject missing extensions, TLS 1.2 fallback offers, and other non-GREASE versions. TLS 1.3-only is a golden-path profile requirement, not a security control: clients must be configured with TLS 1.3 as their minimum version. Require the TLS 1.3 ClientHello `legacy_version` value `0x0303` and the single null legacy compression method. Accept handshake record legacy versions `0x0301` and `0x0303` for the initial ClientHello; these compatibility fields do not enable a TLS 1.2 parsing path. Reject SSLv2 framing and non-handshake records before the initial ClientHello is complete; bound each plaintext record payload to 16 KiB.
- **Identity and framing:** Require exactly one `server_name` extension containing exactly one hostname entry, matching the approved CONNECT hostname. Validate enclosing lengths, vectors, and extension boundaries; reject duplicate extensions and malformed or ambiguous identity. Well-framed unknown extensions and GREASE values may be skipped by length; do not introduce cipher-suite or ALPN policy.
- **ECH:** Reject the `encrypted_client_hello` extension, including ECH GREASE, regardless of outer SNI. Golden-path clients must not send ECH. Never strip or rewrite extensions.
- **Inspection scope:** Inspect only the initial ClientHello, preserving fragmentation and all buffered bytes. Later handshake messages and encrypted application traffic remain opaque. A second ClientHello following a HelloRetryRequest is not inspected; it adds no capability beyond the accepted domain-fronting limitation. The version check constrains the client's advertised profile; it does not authenticate the upstream server or independently verify the version actually negotiated by the endpoints.

## Configuration & DNS

Configuration is a single TOML document of at most 4 KiB (4096 bytes), including comments and whitespace, with a required `allowlist` array of 1 through 32 exact `<fqdn>:<port>` strings and a required `listen` key. Each entry is a lowercase ASCII DNS hostname (an IP literal-shaped entry — a name whose labels are all-numeric, e.g. `1.2.3.4:443` — is invalid configuration) with a canonical decimal port from 1 through 65535 and no leading zero; a bare FQDN without `:port`, an empty or non-numeric port, port `0`, a port above `65535`, or a leading-zero port is invalid configuration. Both limits apply: 32 maximum-length DNS names need not fit. A compact configuration with 32 entries of 100 ASCII bytes each (including the `:port` suffix) and a listener fits within the document limit. Bound the configuration read and reject oversized input without truncating it. Load and fully validate configuration and local prerequisites before opening listeners or issuing DNS queries. There is no runtime policy update interface; see the [runtime surface](#architecture).

`startup_unresolved_allowance` is required and must be an integer from `0` through `allowlist length - 1`; `0` requires every hostname to be usable at startup. An empty allowlist is invalid configuration. The allowance affects startup availability, never destination authorization. All configuration keys are mandatory; no defaults are supplied.

Missing or unreadable configuration, invalid TOML (including duplicate keys or invalid table redefinitions), missing required fields, unknown keys or tables, incorrect types, out-of-range values, conflicting settings, and unmet local prerequisites cause immediate startup failure with exit status 78 (EX_CONFIG) and a diagnostic identifying the field or source location where available. Reject duplicate allowlist names after normalization. Do not coerce types, discard invalid entries, or supply missing required values from defaults, environment variables, or command-line overrides. After startup resolution, DNS timeouts, negative answers, and other network failures are expected runtime outcomes governed by the cache rules below, not configuration errors.

- **Listener:** `listen` is a required string of the form `address:port`, with a numeric IPv4 or bracketed IPv6 address and a port from 1 through 65535. Wildcard addresses are allowed. A bind failure prevents startup.
- **Names:** Configuration uses lowercase ASCII DNS hostnames, with IDNs supplied in A-label form; CONNECT and SNI hostnames compare case-insensitively. Configuration and CONNECT may normalize a single trailing dot; SNI must satisfy TLS hostname syntax. Compare canonical names and issue absolute DNS queries without search suffixes.
- **Resolver selection:** Read the platform-provided resolver configuration once at startup and select its first declared nameserver address, using port 53. The address must be a numeric unicast IPv4 or IPv6 address without a zone identifier. An unreadable configuration, missing nameserver, or invalid selected address prevents startup; do not skip it in favor of another nameserver. The resolver endpoint is fixed for the process lifetime. Ignore platform search suffixes and resolver tuning options; do not use general OS hostname-resolution APIs, hosts-file lookup, runtime rediscovery, or fallback to another resolver. The platform configuration is a trusted deployment input.
- **Resolution:** Alumina implements a bounded DNS stub, not a recursive resolver or client-facing DNS service. Resolve before opening the listener, then refresh independently of requests; requests use cached results without triggering or waiting for lookups. Local DNSSEC validation and DNS over TLS or HTTPS are outside the initial scope.
- **Startup deadline:** Startup proceeds in fixed order: privilege check, configuration and resolver reads, storage initialization, DNS startup window, then listener opening. After local validation and storage initialization, set an absolute monotonic deadline 90 seconds ahead, before the first DNS connection attempt. It cannot be extended or supplemented by a network-readiness phase. Clip each exchange deadline to it, including TCP establishment and response processing. Check the clock before publication; only results fully validated and published strictly before the deadline count.
- **Startup readiness:** A configured hostname is usable if its current cache has an eligible, non-retired positive binding; all others, including validated negatives and unattempted names, count as unresolved. Open the listener early only when all names are usable, atomically rechecking cache and deadline. Otherwise, at the deadline evaluate the cache once: serve if the unresolved count is at most `startup_unresolved_allowance`, or exit with status 75 (EX_TEMPFAIL) for external restart. On expiry, cancel the outstanding exchange, close its transport, and invalidate obsolete work before background resolution resumes.
- **Degraded serving:** The allowance applies only at startup; subsequent availability follows the normal cache and DNS incident rules. Consistent with the [runtime surface](#architecture), Alumina exposes no readiness endpoint.
- **Startup diagnostics:** During startup, attempt to enqueue one warn notification on the first exchange failure across all names and record types. Continue tracking per-type incidents and latest failure reasons, but suppress their individual first-failure warnings. Emit one final result on success or failure with full/degraded/failure status, allowance, usable/unresolved counts, and unresolved names with latest outcomes or not-attempted reasons. Suppress hourly summaries until serving; preserve unresolved type incidents and initialize traffic-reporting windows at that transition. Do not replay suppressed warnings when serving begins; retained incidents continue normally, and subsequent new incidents receive the normal per-type warning.
- **Transport:** Use plain DNS over TCP only, with one reusable connection and one outstanding query. There is no UDP or alternate-resolver fallback. Validate the response flag, opcode, transaction ID, and question name, type, and class against the outstanding query; draw each transaction ID from the OS CSPRNG (`getrandom`). Close the DNS connection on timeout, malformed or mismatched responses, truncation, or an oversized message; do not publish partial results. TCP is not cryptographic authentication of the resolver or DNS data.
- **Wire parsing:** Require QDCOUNT 1, exact section counts with no trailing bytes, and RDLENGTH equal to the parsed RDATA (4 for A, 16 for AAAA). Follow compression pointers only to strictly earlier offsets, and only in owner names and CNAME/SOA names. Reject reserved label types, labels over 63 octets, and decoded names over 255 octets.
- **DNS control traffic:** DNS sockets may reach only the selected resolver endpoint. This control traffic is separate from tunnel destination authorization and may use a private, loopback, or link-local resolver address; it never makes that address eligible as a CONNECT destination.
- **DNS provenance:** Issue only IN-class A/AAAA queries for the exact approved hostname, with recursion desired, through the selected recursive resolver. Do not perform local recursion, CNAME follow-up queries, or alternate-resolver fallback. Accept direct addresses or a complete CNAME chain rooted at the queried hostname, with at most eight links and no loops. Require one unambiguous target per chain owner; reject conflicting targets and coexistence of CNAME and A/AAAA records at a chain owner. For a positive answer, every candidate must be an IN-class record of the requested type in the answer section, owned by the queried hostname or the terminal name of the rooted chain. All supporting CNAME records must also be in the answer section. Unrelated records and all authority/additional-section addresses must never become candidates. A chain may instead terminate in a validated negative outcome without terminal addresses, as specified below; a chain lacking either terminal addresses or a validated negative outcome is an exchange failure. CNAME targets need not be allowlisted or share a DNS suffix; they locate an approved name's addresses but never authorize additional CONNECT names. CONNECT and SNI remain the original approved hostname. DNAME records in the answer section are unsupported and cause an exchange failure, even if a synthesized CNAME is present; never implement DNAME substitution.
- **Service discovery:** HTTPS/SVCB endpoint substitution is unsupported. These records must not change the CONNECT target, destination port, or transport. Clients must use the origin hostname on its allowlisted entry's port as the CONNECT target and supply matching SNI, rather than substitute an alternative endpoint.
- **Addresses:** As defense-in-depth against resolver or zone misconfiguration, only globally routable unicast destinations are eligible. Compare parsed numeric addresses, never textual forms. IPv4 candidates must not fall within `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, or `240.0.0.0/4`. IPv6 candidates must lie within `2000::/3` and outside `2001::/23`, `2001:db8::/32`, `2002::/16`, and `3fff::/20`. Prefixes that embed or translate IPv4 addresses are ineligible regardless of the embedded address, including IPv4-mapped, IPv4-compatible, NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4, and Teredo; Alumina never extracts an embedded IPv4 address to check it. NAT64/DNS64 deployments are outside the golden path. The table is fixed at build time; changing it requires a design revision. The IPv4 exclusion table is deliberately scoped to private, loopback, link-local, benchmark, documentation, and other non-globally-routable space; public special-use ranges — AS112 anycast `192.31.196.0/24`, AMT `192.52.193.0/24`, and direct-delegation AS112 `192.175.48.0/24` — are intentionally not excluded because they are globally routable and can legitimately host internet services, so their absence is not an omission. Validate every A/AAAA candidate before publication and again before each connection attempt.
- **Cache lifetime:** Each configured name holds one cache entry per record type: its eligible addresses (bindings), one freshness deadline, one retirement deadline, and a generation. The entry TTL is the earliest TTL of any supporting CNAME or address record in the answer (RFC 2181 §5.2), measured from receipt with a monotonic clock; all bindings in an entry share its deadlines. Fresh, stale, and retired are computed from the entry deadlines and the current monotonic time, never stored: only validated DNS outcomes mutate an entry, and timers only drive refresh and notifications. Honor the received TTL without raising it to the minimum refresh interval, except that a TTL of 0 is treated as 1 second, deviating from RFC 1035 so zero-TTL steering services remain usable. A validated positive answer replaces the cached addresses for its record type and establishes new freshness and retirement deadlines. A validated recursive negative answer evicts immediately without stale grace: NXDOMAIN is name-wide for the queried allowlisted hostname, including when its CNAME terminal name is nonexistent; NODATA is specific to the queried record type and must not evict addresses of another type. Apply a validated NXDOMAIN to both record types as though each had received it: evict both entries, update both schedules, and clear both exchange-failure incidents. Neither outcome requires the AA bit. DNS queries and refresh results belong to cache state, not connection generations; obsolete results cannot overwrite newer cache state.
- **Stale retirement:** After TTL expiry, a binding may authorize new upstream connections for a fixed 72-hour (259200-second) stale grace, matching the RFC 8767 maximum stale timer, while background refresh or retries are pending. The entry's absolute retirement deadline is receipt time plus the entry TTL plus 259200 seconds. Exchange failures, including timeouts, SERVFAIL, and malformed responses, retain bindings only within this lifetime; failures, scheduling delays, client requests, and successful TCP connections never extend the deadline. Missing, replaced, evicted, or retired bindings cannot authorize a new upstream connection. Check retirement directly before every upstream connection attempt, even if timer processing is delayed. A positive answer for one record type cannot renew bindings of another type. Retirement does not change the peer or lifecycle of an established tunnel, stop background retries, remove the configured hostname, or terminate the process; a later validated positive answer restores authorization automatically. Stale use and per-type retirement are reported only through DNS incident summaries.
- **Refresh scheduling:** After a positive answer with cacheable bindings, schedule the next normal refresh for its record type at receipt time plus `min(300 seconds, max(30 seconds, entry TTL))`. These fixed lower and upper bounds govern refresh scheduling, not DNS freshness: a 30-second TTL schedules refresh after 30 seconds; a shorter TTL expires before the normal refresh becomes due, and any intervening authorization uses the stale grace. Track due work in a fixed table with one due time per name and record type and no separate query queue; superseding work overwrites the due time, so at most one query per name and record type is pending. Each record type maintains independent due times and retry state; an outcome for one type must not alter the other's state except for name-wide NXDOMAIN. Due entries share the single DNS transport and may wait behind other exchanges. Scan the table in fixed rotating round-robin order so repeated failures cannot monopolize transport access. Start at most one query per name and record type per second. These intervals establish due times, not guaranteed query start times under contention. Client requests cannot accelerate refresh or retries.
- **Negative refresh scheduling:** A validated negative answer with an authority SOA schedules the next normal refresh using `min(300 seconds, max(30 seconds, min(SOA TTL, SOA.MINIMUM)))`, measured from receipt. NXDOMAIN applies this due time to both record types and supersedes older work; NODATA applies it only to the queried type. Negative TTL controls retry scheduling, never positive authorization: its expiry cannot restore evicted bindings. A validated NXDOMAIN without an SOA schedules both record types with the bounded retry backoff instead. These are fixed profile rules, not configuration options.
- **Refresh failures and recovery:** An exchange failure ends the affected resolution attempt; schedule later attempts from completion using 1, 2, 4, 8, 16, then 30-second capped backoff. The 30-second minimum normal refresh interval does not apply to failure retries. Keep retry state distinct for A and AAAA; only a validated positive answer with cacheable bindings for the affected type resets its backoff. Retry missing or retired bindings using bounded backoff; evicted bindings use negative refresh scheduling when an SOA is available, otherwise backoff. Continue background attempts for as long as the process serves traffic. Repeated NXDOMAIN answers without an SOA and positive answers without cacheable bindings advance rather than reset retry backoff. An answer for another type must not reset a failing type's backoff or extend its authorization. A failing name cannot monopolize DNS work.
- **DNS incident notifications:** Track unresolved exchange failures independently for A and AAAA. The first exchange failure for a type starts an incident and emits one warn notification, except during startup, where the startup diagnostics rules govern warning emission. Subsequent failures update its latest reason without logging each retry. A validated positive or negative answer clears that type's exchange-failure incident and emits one info recovery notification with its duration; valid NODATA, including an absent AAAA record for an IPv4-only name, is not a resolution failure. Incident recovery does not imply restoration of eligible addresses or reset the retry backoff for negative answers. Except for NXDOMAIN, an outcome for one type cannot clear an incident for the other. While either type has an incident, emit one error summary per hostname after each 3600-second reporting window. Start the first window when the hostname first enters an incident; do not restart it when the other type fails or recovers. Report an immediate error when a hostname transitions from having eligible bindings to having none, including through retirement or negative-answer eviction. Recovery of eligible bindings emits one info notification. Do not restart the process or change retry scheduling in response to these notifications.
- **DNS incident summaries:** Include hostname, failing record types, incident start and elapsed duration per type, latest failure reason, last positive-resolution time per type, attempts and exchange failures per type during the reporting window, and per type the eligible address count, entry state (fresh, stale, or retired), and remaining freshness and retirement deadlines. Include the number of distinct tunnels with activity, total forwarded bytes, and new tunnels admitted with stale bindings during that window. Activity means at least one tunnel byte successfully forwarded in either direction; CONNECT response bytes, merely open sockets, buffered reads, and readiness events do not count. Count a tunnel once per window even if it predates the incident, remains open across windows, or closes before the summary. Count payload bytes once on successful writes, not on both reads and writes. Count a stale admission once when a new upstream peer is committed using a stale binding; retries and relay activity are not admissions. On full hostname incident recovery, emit a final summary for the partial window at info level with its actual duration.
- **DNS reporting bounds:** Preallocate incident state for both record types of each configured name, reporting counters and window state per name, and one last-counted window identifier per tunnel slot. Reporting windows use a monotonic clock; rotate window accounting before recording events at or after a boundary, so activity belongs to exactly one window. Reused tunnel slots reset their reporting marker; window identifiers cannot be reused while a live tunnel can retain them. Saturate counters on overflow and report an overflow flag rather than wrapping. Include window start, end, and duration in summaries; coalesce delayed notifications without catch-up bursts, identifying skipped windows rather than merging them into a purported one-hour report. Formatting and enqueueing remain allocation-free, bounded, and nonblocking. Notifications are best-effort under the existing log-drop policy; reset window counters at boundaries even if enqueueing fails, and count dropped notifications.
- **Bounds and retries:** Enforce the initial resource profile for DNS messages, record counts, CNAME chain length, and outstanding queries. Reject loops and results exceeding capacity rather than retaining an arbitrary truncated subset. Each DNS exchange has a 2-second deadline. Make at most four sequential upstream connection attempts per tunnel, each with a 2-second deadline within the absolute setup deadline. Before each attempt, read the hostname's current A and AAAA entries and ignore any that are empty, retired, or exhausted. If both families remain, use IPv4 for the first attempt and otherwise the family not used by the previous attempt; if one remains, use it. Within a family, use the address at index n, where n is the number of earlier attempts in that family; the family is exhausted when n reaches the entry's current address count. The tunnel stores only these per-family attempt counts, never addresses or cache references, so a replacement between attempts takes effect at the next attempt. Stop when no family remains. Revalidate address eligibility before each attempt. Commit the peer at the first successful TCP connection; retry only failed connection establishment and never replace a connected peer. Cache updates do not change the peer of an established tunnel.

### DNS response outcomes

Validate the entire response, query binding, framing, record bounds, and any rooted CNAME chain in staging before classification or cache mutation. A malformed or contradictory response is always an exchange failure, regardless of its response code. Classify trusted recursive responses independently of the AA bit; AA is neither required for acceptance nor proof of authenticity.

For negative classification, an authority SOA, when present, must be exactly one IN-class SOA with valid RDATA whose owner is the terminal name or its ancestor at a DNS label boundary. The terminal name is the queried hostname for a direct answer, or the final target of the rooted CNAME chain. A malformed, non-covering, or ambiguous authority SOA is an exchange failure. NXDOMAIN does not require an SOA; Alumina's golden-path NODATA classification does.

| Outcome | Required response | Cache action |
| --- | --- | --- |
| Positive | `NOERROR` with answer-section addresses of the requested type at the queried or CNAME terminal name | Replace the queried type after candidate eligibility and TTL validation; do not preserve old addresses merely because the new answer has no cacheable eligible bindings |
| NXDOMAIN | `NXDOMAIN` with any valid rooted CNAME chain and no contradictory A/AAAA data at its terminal name; SOA optional | Apply to both types of the queried allowlisted hostname: evict immediately, update schedules, clear exchange-failure incidents, and invalidate older work |
| NODATA | `NOERROR` with no answer-section addresses of the requested type at the queried or CNAME terminal name, and a valid covering authority SOA | Immediately evict the queried type only |
| Exchange failure | Timeout, `SERVFAIL`, `REFUSED`, other error codes, referral, unsupported DNAME, incomplete chain, empty `NOERROR` without a covering SOA, or malformed, mismatched, oversized, or contradictory response | Publish nothing; retain previous bindings only within their existing freshness and retirement deadlines |

An empty answer section alone is not NODATA. A referral does not become a negative answer merely because it has no addresses. Valid NXDOMAIN or NODATA after a CNAME chain is a complete negative outcome, not an incomplete positive answer. Neither negative outcome authorizes addresses for the CNAME target as a separate CONNECT hostname. Do not fall back to another transport, resolver, record type, or endpoint-discovery mechanism to reinterpret an unsupported response.

## Deployment boundary

Alumina is responsible for the egress it provides. VPC isolation mechanisms and prevention of alternative egress paths are outside its scope. Deployment supplies raw TCP connectivity and access to the platform-provided DNS resolver.

### Typical deployment pattern

Run the application and Alumina under separate runtime and network-policy identities. The application's integration HTTPS clients explicitly use Alumina's private raw TCP endpoint as their proxy. Only Alumina has the network permissions needed to connect to third-party endpoints.

```text
Cloud-hosted server / integration HTTPS client
-> Private Alumina endpoint: HTTP CONNECT, then end-to-end TLS
-> Approved third-party endpoint: TCP <fqdn>:<port> (the allowlisted entry's port)

Application -> Direct or alternate third-party HTTPS path: denied
Alumina    -> Selected recursive resolver: TCP 53
```

Deployment default-denies application egress except to Alumina and explicitly required platform or internal dependencies. These exceptions must not provide an alternate HTTPS path. Apply confinement across all routes and address families, restrict proxy ingress to the intended workloads, and prevent the application from changing proxy or network controls. Proxy configuration alone is not confinement. Alumina unavailability must not enable direct fallback. Alumina's egress path must not apply NAT64, and its selected resolver must not synthesize DNS64 AAAA records.

The production image is a minimal Linux container holding only the statically linked Alumina binary, its configuration file, and the platform resolver configuration. It has no shell, package manager, or other executables. Run it as a non-root user with no added capabilities, a read-only root filesystem, no writable or secret volumes, and a runtime identity holding no cloud permissions; Alumina requires no credentials. Changing policy requires deploying a new instance with new configuration.

Private endpoint discovery, routing, firewalls, and any NAT or TCP load balancing are operator responsibilities. The pattern requires no particular cloud provider; platforms unable to enforce this separation are outside the golden path.

DNS readiness does not prove reachability. If required, an operator-owned check uses CONNECT through Alumina and completes TLS to representative approved destinations, verifying certificates and hostnames; Alumina performs no reachability probes. Deployment startup and restart timing must allow local initialization plus the DNS startup window.

### DNS deployment assumptions

**DNS trust:** Alumina relies on the platform-provided recursive resolver for correct name-to-address bindings. Deployment must protect the resolver, its configuration, and communication between Alumina and the resolver from modification or impersonation by compromised applications. Resolver responses must still pass all parsing, provenance, cache-lifetime, and destination-address checks.

**Third-party DNS compatibility:** Operators control the deployment but need not control approved third parties' DNS. Allowlisting accepts the DNS-directed infrastructure behind each approved hostname, including CDN and hosting-provider endpoints; CNAME validation does not establish exclusive third-party control or server authenticity. The golden path requires the selected recursive resolver to return complete direct or bounded-CNAME positive/negative answers for the actual allowlist. Qualify those responses before deployment and test vendor DNS changes. An incomplete or unsupported runtime response follows bounded stale retention, retries, and incident notifications; broader discovery requirements require an explicit design revision or a more capable proxy, not automatic compatibility fallback.

**DNS freshness limitation:** Bounded stale authorization trades freshness for availability and accepts the risk of address reassignment during the grace period. The retirement deadline bounds Alumina's own stale retention, not the age of authoritative data: the recursive resolver may itself return stale data as a successful positive answer, renewing Alumina's deadlines. Any end-to-end freshness guarantee requires a deployment-enforced upstream stale-answer bound; Alumina does not independently establish authoritative freshness.

### Initial test target

The following is a provider-specific validation target, not a requirement of the deployment pattern or a dependency of Alumina's design.

The initial GCP test target is a Cloud Run worker pool with Direct VPC connectivity, providing private TCP ingress and continuously allocated CPU, rather than ordinary Cloud Run service HTTP ingress. Platform network limits remain independent of CPU speed: the [Cloud Run Direct VPC documentation](https://docs.cloud.google.com/run/docs/configuring/vpc-direct-vpc#limitations) currently specifies up to 1 Gbps per instance. Testing the 10 Gbps end of the target requires a deployment whose network ceiling permits it.

## Architecture

Alumina uses Rust and a single worker loop in the first iteration, following TigerStyle principles adapted to Rust. Ownership, protocol state transitions, scheduling budgets, timers, and resource bounds are explicit application responsibilities.

- **Compile-Time Bounds:** Max concurrent connections and buffer sizes are statically fixed.
- **Boot-Time Storage:** Application storage is allocated before serving traffic; stack usage is bounded. This does not imply constant total memory use or immunity to resource exhaustion.
- **Single Owner:** The worker owns tunnel state, DNS sockets, timers, and the entire DNS cache. There is no resolver thread, blocking system resolver, shared mutable cache, or cross-thread publication. Additional workers are outside the initial profile; any future worker must own its own connection and DNS state without cross-worker data-path coordination.
- **Cache Publication:** Preallocate one cache entry per configured name and record type, plus staging storage. Validate a complete result in staging, then replace the relevant entry in one worker transition without merging obsolete records. Keep A and AAAA entries distinct; a name-wide negative result applies to both and supersedes older pending work. Each entry's generation advances on every replacement or eviction and rejects obsolete DNS results. Tunnels never hold references into the cache.
- **Scheduling:** Use fair round-robin scheduling with at most 64 KiB of I/O or 16 I/O operations per connection visit, whichever comes first. Recheck timers after at most 256 ready-slot visits or I/O operations, even if more work is pending. Reschedule unfinished work without waiting for a new readiness edge; DNS work receives bounded turns alongside tunnel traffic. Size ready queues and timer storage from fixed slot counts, with no duplicate queue entry per slot.
- **I/O model:** Use `mio` with Linux epoll for nonblocking socket readiness, without an async runtime or `async`/`await`. Advance forwarding gates and forwarded-byte accounting only on successful writes.
- **Failure Handling:** Expected input and I/O failures are handled explicitly. `panic = "abort"` is a fail-stop policy, not proof of panic freedom; `unwrap()` and `expect()` are excluded from production paths.
- **Runtime surface:** The CONNECT listener is the only runtime input interface. There is no control plane, administrative, health, metrics, debug, or reconfiguration interface, and configuration is read once at startup. SIGTERM is the only handled lifecycle signal: it starts shutdown and never reloads configuration or changes policy. Catchable administrative signals cannot reload configuration or change policy, and SIGPIPE is ignored. Logs go to stdout only.
- **Runtime prerequisites:** Production targets a minimal Linux container. At startup, require a non-root UID, empty effective, permitted, and ambient capability sets, and `no_new_privs`; otherwise fail as an unmet local prerequisite. Read configuration and resolver files once during startup and initialize all application storage before DNS resolution begins. Final shutdown closes sockets and exits without deallocating.

## Initial resource profile

These are fixed build-time limits, not optional TOML settings or measured capacity claims. Limit exhaustion rejects work; it never enlarges storage or relaxes validation.

| Resource | Limit |
| --- | --- |
| Configuration document / allowlist entries | 4 KiB / 1 through 32 |
| Worker threads | 1 |
| Concurrent tunnels, including setup / pending setups | 512 / 128 |
| Traffic buffers per tunnel slot | Two 128 KiB buffers, one per direction |
| Total preallocated tunnel traffic storage | 128 MiB |
| Retained serving workspace (per-slot CONNECT head + two 64 KiB ClientHello inspector buffers) | 512 × 136 KiB = 68 MiB |
| CONNECT headers | 8 KiB |
| Buffered TLS bytes before authorization, including record framing | 64 KiB |
| TLS plaintext record payload during inspection | 16 KiB |
| ClientHello distinct extensions tracked (duplicate rejection) | 64 |
| ClientHello offered supported_versions entries retained | 32 |
| DNS response message / total resource records | 16 KiB / 128 |
| Cached address candidates per configured name | 16 IPv4 and 16 IPv6 |
| CNAME chain length | 8 links; loops rejected |
| DNS TCP connections / outstanding queries | 1 / 1 |
| Setup deadline / individual upstream connect deadline | 10 seconds / 2 seconds |
| Upstream connection attempts per tunnel | 4, within the setup deadline |
| DNS exchange deadline | 2 seconds |
| Normal DNS refresh interval, lower / upper | 30 seconds / 300 seconds |
| SOA-based negative DNS refresh interval, lower / upper | 30 seconds / 300 seconds |
| DNS failure retry backoff | 1, 2, 4, 8, 16, then 30 seconds capped |
| Stale DNS authorization grace after TTL expiry | 259200 seconds (72 hours) |
| DNS incident summary interval | 3600 seconds per affected hostname |
| DNS reporting storage | 32 name/window states, 64 record-type incident states, 512 tunnel window markers |
| Preallocated log queue / maximum encoded entry | 256 entries / 8 KiB, including framing |
| Log sink work per scheduling turn | 64 KiB or 16 I/O operations, whichever comes first |
| Startup resolution window | 90 seconds, absolute; includes DNS TCP establishment |
| Relay idle deadline / EOF drain deadline / shutdown grace period | 300 seconds / 5 seconds / 8 seconds |

Preallocate 512 tunnel slots with two 128 KiB directional buffers each: `512 * 2 * 128 KiB = 128 MiB`. Reuse these buffers across CONNECT parsing, ClientHello inspection, and relay without discarding coalesced tunnel bytes. The separate CONNECT and ClientHello limits still apply; larger relay buffers do not permit larger setup messages. DNS storage, the retained serving workspace (512 × 136 KiB = 68 MiB of per-slot CONNECT head plus two 64 KiB ClientHello inspector buffers), connection metadata, stacks, executable memory, and kernel socket buffers are outside this traffic-storage budget and must be accounted for separately when sizing the container.

The first-iteration target is 1-10 Gbps aggregate relayed payload throughput across both directions, subject to CPU speed, workload, and network limits. At these rates, 128 MiB represents approximately 1.07 seconds to 107 milliseconds of aggregate payload, not a throughput guarantee. Storage is partitioned by tunnel and direction and cannot all absorb a burst on one connection; a 128 KiB directional buffer represents approximately 1.05 milliseconds at 1 Gbps or 0.10 milliseconds at 10 Gbps. Use socket backpressure rather than buffer growth. Benchmark sustained relay and bursts separately; application buffer capacity is not a substitute for TCP window sizing or a measured CPU budget.

## Lifecycle

- **Setup:** Start the setup deadline at successful client accept; it ends when the forwarding gate opens and is never reset. Each upstream connect deadline starts when its attempt is initiated, ends on success or failure, and is clipped to the setup deadline.
- **Relay:** Handle partial reads and writes, backpressure, and spurious readiness without losing pending work. Start the idle deadline when the forwarding gate opens; reset it only on successful tunnel-byte writes in either direction, not on reads or readiness.
- **Closure:** On the first orderly EOF during relay, start the drain deadline without subsequent resets. Drain each EOF direction and shut down the peer's write direction; reverse traffic may continue. Close when both directions reach EOF and finish draining, or when an applicable deadline expires. Release connection resources exactly once.
- **Shutdown:** On the first handled SIGTERM, stop accepting connections and start the shutdown grace deadline; subsequent signals cannot extend it. Drain until all tunnels close or the deadline expires, then close remaining sockets and exit.
- **Capacity and logging:** When tunnel or setup capacity is exhausted, reject new connections with a best-effort static `503` and close; never evict established tunnels. Attempt an error entry when tunnel slots, pending setups, or log queue usage first exceeds 80%, and again when usage falls below 70%. Attempt one warn entry per rejected connection with the client address, reason, and requested hostname when valid. Attempt one warn entry per tunnel closed for early upstream activity with the hostname, peer address, and whether data, EOF, or reset was observed.
- **Log delivery:** All logging is best-effort. Format allocation-free structured records with escaped text within the resource-profile bounds. Drop and count new entries when the queue is full or the encoded record exceeds its limit; never truncate a record. Drain through a nonblocking sink under the per-turn work budget, preserving partial-write progress and yielding on backpressure. A stalled sink must not delay rejection, tunnel I/O, DNS, or deadlines.

## Invariants

### I. Security & Authorization Invariants

- **The Destination-Binding Invariant:** An upstream tunnel connection may be opened only for an approved CONNECT hostname that is a valid FQDN, not an IPv4/IPv6 literal, on the allowlist entry's TCP port (1 through 65535). At each connection attempt, the destination address must come from a positive entry in Alumina's current DNS cache for that hostname that no later answer has replaced or evicted, must be strictly before that binding's absolute retirement deadline, and must satisfy the destination-address policy. The selected peer remains fixed for that tunnel.
- **The Authorization-Before-Forwarding Invariant:** No client tunnel bytes, including ClientHello, are forwarded until the complete ClientHello passes validation and its mandatory SNI contains a valid, nonempty FQDN whose normalized value equals the approved CONNECT hostname's normalized value. No upstream bytes are forwarded before the [forwarding gate](#protocol-contract) opens. Upstream data, EOF, or reset observed through actual I/O while it is closed terminates setup without forwarding or logging upstream bytes. A successful CONNECT response alone does not authorize forwarding in either direction.
- **The Fail-Closed Invariant:** Malformed or unsupported input, ambiguous identity, DNS failure, and resource exhaustion cannot skip authorization checks or enable permissive fallback. The only DNS-failure tolerance is continued use of an existing positive binding within its explicitly bounded stale grace; failures cannot renew authorization or revive replaced, evicted, or retired bindings.

### II. Memory & Resource Invariants

- **The Zero-Allocation Invariant:** While serving traffic or refreshing DNS, proxy execution paths, including dependencies, must not allocate or deallocate heap storage. Only boot initialization is exempt; shutdown exits without deallocating.
- **The Resource-Bounds Invariant:** Connections, buffers, queues, DNS requests, timers, and logs have explicit capacity limits. Exhaustion rejects work rather than expanding storage without bound.

### III. Execution & Concurrency Invariants

- **The Ownership Invariant:** Each live connection's mutable state belongs to exactly one worker.
- **The Generation-Isolation Invariant:** Connection-scoped events, timers, and buffered bytes belong to one connection generation. Stale work cannot affect reused connection storage; generation reuse must not make stale work valid again. DNS refresh and other non-connection work have independent lifetimes.
- **The Bounded-Work Invariant:** Each scheduling turn has a finite work budget. Pending work is rescheduled without losing readiness or starving other connections and deadlines.

### IV. Protocol & State Machine Invariants

- **The State-Transition Invariant:** Every I/O outcome has an explicit permitted transition. Invalid protocol transitions close the connection; readiness alone is not evidence that an operation succeeded.
- **The Stream-Parsing Invariant:** For the same byte stream within the specified size and time limits, parsing decisions are independent of TCP read boundaries. Parsing incomplete input never authorizes forwarding.
- **The Non-Decrypting Invariant:** The proxy shall never possess TLS private keys, manage authority certificates, or decrypt payload traffic. It acts strictly as a metadata validator and a transparent bit-pipe.
- **The Byte-Conservation Invariant:** Forwarded tunnel bytes are an ordered, unmodified prefix of the received tunnel stream in each direction, without duplication or replay. Normal completion drains accepted tunnel bytes; failures terminate the stream rather than silently skipping data and continuing. Deadline-forced closure is failure, not normal completion.
- **The Deadline Invariant:** All deadlines use a monotonic clock. At or after expiry, progress cannot renew a timer or complete its expired phase, even if timer handling is delayed. Enforce the earliest applicable deadline.

## Verification requirements

- **Protocol and DNS:** Verify TLS 1.3-only acceptance, TLS 1.2 fallback and ECH rejection, fragmented ClientHello handling, DNS response binding, CNAME provenance, startup resolution failure, bounded stale retention on refresh failure, negative-answer eviction, and obsolete-result isolation. Check refresh scheduling for TTLs of 1, 29, 30, 31, 299, 300, and 301 seconds, TTL 0 treated as 1 second, and the earliest supporting CNAME/address TTL. Verify capped retry backoff, independent A/AAAA recovery, continued retries after retirement, and automatic recovery from a validated positive answer. Check admission immediately before, at, and after retirement, including delayed timer processing and retries between connection attempts. Replace, evict, and retire entries between connection attempts; later attempts must use only current entries, and each family must stop at its current address count. Confirm failures and client activity cannot extend deadlines, negative answers bypass grace, and established tunnels are unaffected. Exercise malformed input and configured bounds with focused tests and parser fuzzing. Verify address eligibility with boundary vectors for every listed IPv4 and IPv6 range (first, last, and adjacent addresses), including `64:ff9b::a9fe:a9fe`, `::ffff:10.0.0.1`, `::10.0.0.1`, `2002:a9fe:a9fe::1`, and a Teredo address encoding a private IPv4 address; all must be rejected, while native global addresses on either side of each boundary must be accepted. Verify independent A/AAAA due times and retry state, except for NXDOMAIN. Exercise simultaneous due entries, a timeout followed by service of another due entry, and repeated failures across the full allowlist. Confirm transport contention does not cause starvation, duplicate pending work, or extension of cache retirement deadlines.
- **TLS forwarding gate:** Deterministically exercise data, EOF, and reset observed before gate opening: after the `200`, between ClientHello fragments, after validation, and during partial upstream writes. Check both forwarding barriers, `WouldBlock`, spurious and combined readable/writable readiness, and gate opening before the next upstream read. Do not reject fast responses first observed after opening as early activity. Verify interoperability with TLS 1.3 endpoints for ordinary handshakes, fragmentation, HelloRetryRequest, and fatal alerts.
- **Lifecycle deadlines:** Check each timer's start, end, and reset events immediately before, at, and after expiry, including delayed timer handling and overlapping deadlines. Exercise connect retries clipped to setup, gate opening at expiry, idle resets by writes in either direction but not reads or readiness, and second EOF/SIGTERM without extension. Verify normal draining and deadline-forced closure with buffered bytes remaining.
- **DNS classification:** Exercise direct and complete CNAME positive answers, cross-suffix targets, eight-link acceptance, nine-link rejection, loops, conflicting CNAME targets, CNAME/address coexistence, and answer-section provenance. Check direct and CNAME-terminal NXDOMAIN/NODATA with AA both clear and set; NXDOMAIN with or without SOA must evict both types, update both schedules, and clear both incidents, while NODATA requires a valid covering SOA and evicts only the queried type. Reject malformed or contradictory negatives, ambiguous or non-covering SOAs, referrals, incomplete chains, empty NOERROR without SOA, and answer-section DNAME including synthesized CNAME responses. Verify SOA TTL/MINIMUM scheduling at the fixed bounds, immediate eviction despite positive stale grace, zero-cacheable-binding replacement, and no revival after negative TTL expiry or obsolete work. No outcome may trigger follow-up queries or endpoint substitution. Test pointer loops, self and forward pointers, reserved label types, label and name length limits, RDLENGTH mismatches, trailing bytes, and QDCOUNT other than 1.
- **DNS observability:** Verify first-failure warnings, hourly per-hostname error summaries, independent A/AAAA incident recovery except NXDOMAIN clearing both, immediate no-eligible-binding notifications, no stale-use or per-type retirement notifications, and final partial-window summaries. Confirm valid NODATA does not start an exchange-failure incident. Exercise tunnels established before an incident, multiple writes and both directions in one window, activity across window boundaries, closed and reused slots, stale admissions, and exact-once forwarded-byte accounting. Verify delayed and skipped reporting windows, counter saturation, log-drop accounting, and continued DNS/deadline progress when the log sink is stalled. Reporting must not extend authorization or alter retry scheduling.
- **Resource profile:** Verify the 4096-byte configuration boundary, the 128 MiB traffic-buffer allocation, bounded queues and timers, allocation-free operation, deadline enforcement, and preservation of buffered bytes across setup and relay. Use allocator instrumentation and dependency checks to verify that startup DNS resolution, serving, background refresh, logging, and shutdown perform no heap allocation or deallocation after boot initialization. Report process and kernel memory separately from the traffic-buffer budget.
- **Logging:** Verify queue and encoded-entry boundaries, escaped text, whole-record drops and accounting, threshold transitions, and one enqueue attempt per rejection. Verify worst-case final startup results for valid configurations fit the encoded-entry limit, including framing. Exercise partial writes, backpressure, and a stalled sink; enforce the sink work budget while tunnel I/O, DNS, and deadlines continue. Formatting and delivery must remain allocation-free.
- **Startup readiness:** Verify a missing allowance fails configuration validation, integer/type/range validation, zero requiring all hostnames to be usable, and every valid allowlist requiring at least one usable hostname. An empty allowlist must fail configuration validation before DNS queries or listener creation. Exercise all-ready early startup, exact-allowance degraded startup at the deadline, allowance-exceeded exit with status 75, configuration failure with status 78, not-yet-attempted names, NXDOMAIN counted against the allowance, eviction before readiness, and independent A/AAAA outcomes. Check responses immediately before, at, and after the 90-second deadline, delayed timer delivery, DNS TCP establishment inside the exchange budget, cancellation and obsolete-work isolation, and no extension from progress or retries. Verify degraded-result diagnostics, serving-mode incident/window handover, `502` for unavailable names, automatic background recovery, and no active reachability probes. Verify that failures across multiple names and record types produce exactly one startup warning enqueue attempt, while preserving independent incident state and latest reasons. Confirm that serving begins without replaying suppressed warnings and that subsequent new incidents receive normal per-type warnings. Runtime loss of a binding must not reapply the startup allowance or enable permissive fallback.
- **Deployment confinement:** Demonstrate successful approved third-party calls through the private proxy endpoint and rejection of unapproved CONNECT hostnames. From the application runtime, verify direct connections to approved and unapproved third-party addresses are denied, including IPv4, IPv6 where available, alternate HTTPS ports, UDP/QUIC, private routes, provider-managed paths, and alternate proxies or relays. Exercise clients that ignore proxy settings, proxy-bypass configuration, and proxy unavailability; none may obtain direct egress. Confirm the workload cannot alter proxy or confinement controls, unauthorized sources cannot reach the listener, and clients retain upstream certificate verification. Repeat these checks when networking, client libraries, or permitted dependencies change; this is deployment verification, not a property Alumina can establish internally.
- **Initial deployment:** Demonstrate TCP DNS resolution and end-to-end CONNECT ingress on the selected Cloud Run worker-pool deployment. Qualify complete direct, CNAME, and negative recursive responses for the intended third-party allowlist against the selected platform resolver, including original CONNECT/SNI preservation. Measure network startup delays against the fixed 90-second DNS budget; verify the chosen allowance and operator-controlled restart policy without automatic timeout extensions. Demonstrate an operator-owned CONNECT plus authenticated TLS check through Alumina for deployment reachability assurance. Compatibility failure requires an explicit deployment or design revision, never automatic protocol or resolver fallback; add bounded follow-up queries only through an explicit revision justified by observed necessary compatibility gaps.
- **Runtime surface and deployment prerequisites:** Verify that startup fails as root, with nonempty effective, permitted, or ambient capability sets, or without `no_new_privs`. Verify that the running process has exactly one listening socket and no other inbound interface. Verify that SIGTERM performs bounded shutdown and that catchable administrative signals cannot reload configuration or change policy. Verify that the image contains only the specified files.
- **Performance:** Measure aggregate forwarded payload bytes once, not once on read and again on write. Benchmark 1-10 Gbps bursts where CPU and network capacity permit, and report burst duration, concurrency, payload sizes, CPU utilization, queueing, and sustained throughput separately. Include slow-peer backpressure and verify DNS and deadline progress under load. These targets and deployment behaviors are unverified until measured.

## Tripwire actions, monitoring, and pacing — user-authorized amendment

**Authority.** This section is a narrow, user-authorized amendment to this specification (`alumina-rp2e`, 2026-10-14). It defines a configuration tripwire/action/monitoring/pacing surface and resolves its semantics. It amends only the surface enumerated here; every other clause of this document — the fixed resource profile, lifecycle deadlines, invariants, logging vocabulary, and core TLS 1.3 + SNI + ECH-reject behavior — is unchanged and remains binding. Specification publication precedes implementation; the status table at the end assigns each surface an honest planned/implemented/deferred status.

### Action catalog and attribution

Each configured allowlist ordinal (1 through 32) carries exactly one Action from `FlareOnly`, `Block`, or `Tarpit`. A per-domain action applies only to failures attributable to that specific validated configured-domain identity, keyed by the fixed allowlist ordinal set. A per-domain action never overrides a mandatory-denial class.

Attribution and precedence rules:

- **AnyIllegal class:** CONNECT parse failure, hostname not allowlisted, missing, malformed, or unsupported SNI, ECH, TLS-profile rejection, and any other recognizable control failure from the enumerated CONNECT-head and ClientHello-profile catalogs are fixed, connection-scoped, terminal mandatory denials, unchanged from the baseline contract. They are attributed to the AnyIllegal class, never to a configured domain. Operational failures (upstream dial failure, unavailable or retired DNS binding, capacity refusal, setup deadline expiry, shutdown-phase activity) and absent internal evidence are never AnyIllegal and never select an Action.
- **AnyIllegal first-slot action:** the first AnyIllegal control failure on a connection selects a configured `Block` action with scope `Connection` or `All` only; a `Domain` scope for the AnyIllegal action is invalid configuration (startup failure, exit 78, EX_CONFIG). An unknown or unattributable identity thus maps through the AnyIllegal channel with its configured Connection/All scope; there is no permissive default and no unconfigured latch.
- **Early upstream data:** upstream Data observed through actual I/O after a matching, validated ClientHello but before the forwarding gate opens is attributed to the validated configured domain (approved CONNECT ordinal plus matching SNI proof). It remains a mandatory baseline denial — terminate setup, forward nothing; in addition the configured per-domain Action (`FlareOnly` or a scoped `Block`) may apply.
- **EOF and reset** observed while the gate is closed are operational Unknown: never policy violations, never domain-attributed, never selecting an Action. They keep their baseline handling.
- Only the configured allowlist ordinal set is ever keyed for per-domain effects; no attacker-controlled hostname or IP table is introduced.

### Block and Flare semantics

- **Block Connection:** terminates the offender connection only; no scope history.
- **Block Domain:** a fixed ordinal table (at most 32 entries) marks the configured domain blocked; it affects current and future flows matching that ordinal until restart.
- **Block All:** synchronously prevents all subsequent application I/O, including pending writes and new admission, before any further I/O, then performs bounded physical closure of at most 512 slots. It persists until restart; there is no runtime unblock interface.
- **FlareOnly:** a notification and aggregation context only. It never authorizes forwarding, never delays baseline denial, and never widens scope. Implicit Flare for an applied Block inherits that Block's scope (reporting scope equals enforcement scope).

### Tarpit (deferred)

Tarpit is `Connection`-scope, post-gate, byte-preserving time-only pacing/backpressure on otherwise-authorized traffic, with a separate per-connection credit counter, a rate given as an integer bytes-per-second plus an explicit `Unlimited` variant, and no simulated packet or byte loss. **No real establishment-allowed predicate exists today**, so Tarpit cannot bind to any current failure without widening a mandatory-denial class; it is therefore **deferred**, not implemented. Configuration that selects `Tarpit` must be rejected with an explicit deferred-status diagnostic — it must never be accepted as an inert runtime setting — until a genuine trigger-catalog decision authorizes a real predicate.

### Configuration surface (implemented; exact schema)

The reserved surface keys each Action to the fixed allowlist ordinal set (1 through 32) positionally, by index-aligned arrays, so no attacker-controlled name table and no second mapping are introduced. The exact schema is:

```
[any_illegal]
scope = "connection" | "all"          # AnyIllegal first-slot Block scope; "domain" is invalid configuration

[actions]
kind  = ["flare_only" | "block", ...]  # one literal per allowlist entry, in allowlist order
scope = ["connection" | "domain" | "all", ...]  # one literal per allowlist entry, in allowlist order
```

- The group is reserved and validated when present: `[any_illegal]` scope must be `connection` or `all` (a `domain` scope is invalid configuration, exit 78); `[actions]` `kind` and `scope` arrays are mandatory and their length must equal the allowlist length (one entry per configured ordinal); `kind = "tarpit"` for any ordinal is rejected with an explicit Tarpit-deferred diagnostic and is never accepted as an implemented runtime action; any other `kind` or `scope` literal is unknown (exit 78). A partial group (one table without the other, or mismatched lengths) is also exit 78.
- An absent group is invalid configuration at enforcement integration (landed this increment): a document without the full `[any_illegal]` + positional `[actions]` group fails startup with exit 78 (EX_CONFIG). There is no absent-group baseline fallback; the pre-existing offender-scoped mandatory-denial semantics are reproduced by configuring `[any_illegal] scope = "connection"` with per-domain `flare_only`/`connection` entries.
- All keys are mandatory with no defaults within the group and no environment or command-line override; unknown keys or tables fail startup with exit 78 (EX_CONFIG) exactly as today. `Block` and `Flare` scopes are configurable (`Connection`, `Domain`, `All`); the `Tarpit` scope is fixed at `Connection`. The `Tarpit` rate is an integer bytes-per-second plus an explicit `Unlimited` variant, with checked representability. Configuration validation timing and procedure are unchanged.
- Capacity: the enforcement group counts toward the existing 4 KiB document bound; no full-schema combination is guaranteed to fit beyond a measured example. Measured with the exact document serializer the parser reads (pinned by parser-real assertions in `src/config.rs`) at 32 allowlist entries of 100 ASCII bytes each (each an `<fqdn>:<port>` spelling, including the `:port` suffix): the compact `block`/`domain` full arrays with `[any_illegal] scope = "all"` total 4061 bytes (including the trailing newline) and fit; the longer `flare_only`/`connection` full arrays with `[any_illegal] scope = "connection"` total 4356 bytes and are rejected by the byte cap (OversizedDocument, exit 78). The `kind`/`scope` length must equal the allowlist length, so a max-count config at the longer spelling exceeds the bound and is rejected at startup. Each total is the exact serialized document length and is serialization- and layout-dependent (whitespace, listen spelling, trailing newline); only the compact form at the measured 32 × 100-byte `<fqdn>:<port>` entries is shown to fit under the preserved 4 KiB cap and 32-entry count. Neither a cap expansion, an alias, a silent compact migration, nor a change to the legal literal set is implied.

### Monitoring

Additional LOG KIND(s) on the existing stdout sink — and only that sink — report per-domain action events and correlated per-ordinal and global aggregates. They follow the existing bounded, best-effort, allocation-free logging contract: whole-record drop and count on overflow, saturating counters with an overflow flag, and fold-before-close/reuse. Correlated connection detail is captured as the first detection relation per connection (actual slot index + generation + fact/effect together; an effect can never appear without its fact); a later detection relation on the same connection folds into the correlated per-ordinal and global aggregates only, never into the bounded detail, and is counted as correlated-detail loss — there is no full history. An accepted monitoring summary enqueue consumes its bounded detail window, so a later summary never repeats the same relations as fresh; a refused summary retains the bounded detail and counts the refusal as honest loss. A forced final summary refused at shutdown is likewise counted as loss but cannot be observed after the process exits, so a shutdown report is never guaranteed lossless. An early-upstream-data outcome with no effect (operational Unknown) is observable only through that bounded correlated detail, never as a permanent exact aggregate total. No new sink, endpoint, control, or metrics interface is added; a Flare for Block or Tarpit events is implicit and coalesced at the existing report cadence, never one record per packet.

### Planned fixed control storage (design estimate, not measured)

All added enforcement and monitoring storage is boot-time allocated from the existing fixed inventory and performs zero heap allocation or deallocation after boot. The bounding design estimate below is derived from the fixed counts (512 tunnel slots, at most 32 ordinals) and a concrete type/sizeof plan to be verified at implementation; it is not a measured or runtime figure.

| Planned structure | Count | Unit size (bound) | Bound total |
| --- | --- | --- | --- |
| Per-ordinal DomainAction table (`FlareOnly`/`Block` + scope) | 32 | 2 B | 64 B |
| Domain-blocked ordinal bitset + All latch | 32 bits + flag | — | 5 B |
| Per-slot latched tripwire fact (phase, class, validated ordinal, generation) | 512 | 8 B | 4096 B |
| Per-ordinal saturated aggregate counters + overflow + window state | 32 | 32 B | 1024 B |
| Per-slot last-counted window marker | 512 | 8 B | 4096 B |

The planned additional control storage totals approximately 9–10 KiB against the existing 128 MiB traffic storage and 2 MiB log queue. Exact sizes are fixed at implementation with `sizeof`-verified types. No pacing credit/burst storage is reserved or preallocated while Tarpit is deferred (no speculative reserved pacing allocation); it is added to this table only if a genuine trigger-catalog decision authorizes Tarpit. Per-turn enforcement work composes with the existing 16-op/64 KiB per-visit budget and at-most-256-visit timer recheck; the per-turn control-step count is a fixed value derived from that native per-visit I/O budget at implementation, not an invented range. Block All's bounded physical closure is the only path that walks the slot table.

### Explicitly unchanged (non-negotiable)

The fixed resource profile (512 tunnels, 128 pending setups, two 128 KiB per-slot buffers, 128 MiB traffic storage, the 256 x 8 KiB log queue, 16-op/64 KiB visits, at-most-256-visit recheck, DNS response/candidate/incident caps, the 90-second startup window, and all deadlines — 10/2/300/5/8 seconds); empty capability sets and `no_new_privs`; byte conservation; non-decrypting; single owner; generation isolation; bounded work; no runtime metrics, control, debug, or endpoint interface; logs to stdout only; core TLS 1.3 + SNI + ECH-reject; packet dropping is never implemented; no new dependency unless its intake precedes execution; no kernel pacing knob.

### Status

| Surface | Status |
| --- | --- |
| This amendment published | Current revision |
| Configuration: exact reserved schema (`[any_illegal]` + positional `[actions]`), AnyIllegal first-slot `Block` `Connection`/`All`, Tarpit deferred rejection, unknown/missing keys exit 78, force-mandatory group, at most 4 KiB | Implemented (this increment) |
| Typed detection-fact capture before erasure; early upstream data validated-domain attribution; EOF/reset operational Unknown | Implemented (this increment) |
| Enforcement: `Block` Connection/Domain/All synchronous latch + bounded closure at the runtime detection sites; `FlareOnly` reporting context (aggregate capture counters, fold on close) | Implemented (this increment) |
| Monitoring: new stdout log kinds + correlated aggregates, drop+count, saturation + overflow, fold | Implemented (this increment) |
| Tarpit pacing | Deferred — no real establishment-allowed predicate; configuration selecting it fails with an explicit deferred-status diagnostic |
| Pacing credit/burst storage | None reserved (no speculative pacing allocation) |

## Security hardening — CONNECT, TLS identity, DNS cache, scheduling, and logging — user-authorized amendment

**Authority.** This section is a narrow, user-authorized amendment to this specification (`alumina-sechd`, 2026-10-17). It pins the exact parser, DNS-cache, scheduling, and logging semantics of the security-review findings whose root cause in spec is a spec weakness or underspecification: L3, L6, L8, L9, L10, L11, L12, L13, L16, L17, and L18. It amends only the surface enumerated here; every other clause of this document — the fixed resource profile, lifecycle deadlines, invariants, logging vocabulary, and core TLS 1.3 + SNI + ECH-reject behavior — is unchanged and remains binding. Specification publication precedes implementation; the status table at the end assigns each surface an honest planned/implemented/deferred status.

### Amended surfaces and status

| Finding | Amended surface | Spec record | Code enforcement |
| --- | --- | --- | --- |
| L3 | CONNECT bare-CR rejection | implemented | planned |
| L6 | Startup positive-by-eligibility classification | implemented | planned |
| L8 | Non-`host_name` `server_name` rejection | implemented | planned |
| L9 | Initial TLS record minimum payload | implemented | already in code; pinned |
| L10 | SNI trailing-dot normalization | implemented | already in code; pinned |
| L11 | Extension/version caps in the resource profile | implemented | already in code; pinned |
| L12 | DNS TTL cap 86400 s (max auth lifetime 345600 s) | implemented | planned |
| L13 | Binding-address deduplication | implemented | planned |
| L16 | Whole-second scheduling granularity | implemented | already in code; pinned |
| L17 | Four parser fuzz targets | implemented | planned |
| L18 | Sink-failure drop accounting | implemented | planned |

All eleven surfaces are recorded by this amendment (spec record: implemented). Code enforcement for the behavioral findings lands in later hardening groups (code status: planned); L9, L10, L11, and L16 document caps and behavior already present in the codebase.

### L3 — CONNECT bare-CR rejection

Add to the CONNECT **Reject** list (spec `:41`): reject a bare CR — an ASCII `0x0d` not immediately followed by `0x0a` — as a header line ending. Only the CRLF pair (`0x0d 0x0a`) is an accepted line ending within the CONNECT head; a `0x0d` observed without an immediately following `0x0a` is rejected as a malformed line ending. This tightens the existing bare-LF rejection to a strict CRLF-only rule. (The code fix arrives in a later hardening group; this amendment records the requirement.)

### L6 — Startup positive classification uses eligible bindings

The startup readiness/usable classification (spec `:65`) and the startup diagnostics state: a positive startup classification requires an eligible, non-retired positive binding for the record type — matching the "usable" predicate at `:65` — not merely a non-empty set of bindings. An entry whose bindings are all ineligible or retired does not count as a startup positive and is treated as unresolved for the allowance computation.

### L8 — Reject non-`host_name` `server_name` entries

Per RFC 6066 §3, the `server_name` extension's name list must contain exactly one entry and that entry's `NameType` must be `host_name` (0). Any entry whose `NameType` is not `host_name` (0) is rejected as malformed or ambiguous identity (spec `:48`) — never silently ignored or skipped by length.

### L9 — Initial TLS record minimum payload

The initial TLS record carrying the ClientHello handshake must have a handshake payload of at least 4 bytes: 1 byte handshake type (`0x01`, ClientHello) plus 3 bytes handshake length. A first record whose handshake payload is fewer than 4 bytes is rejected as malformed framing. This is stricter than the bare maximum payload bound (16 KiB, `:47`/`:48`) and is pinned here because the deployed parser already enforces the minimum.

### L10 — SNI trailing-dot normalization

SNI handling must satisfy RFC 6066 `host_name` and resolve trailing-dot normalization consistently with config/CONNECT normalization at `:61`: a single trailing dot in the SNI `server_name` is normalized (trailing dot removed) before comparison against the approved CONNECT hostname, and the normalized name is compared case-insensitively. An SNI `host_name` that is empty, an IP literal, or otherwise fails TLS hostname syntax is rejected as invalid identity.

### L11 — Extension/version caps promoted into the resource profile

The code-invented hard caps are promoted to spec resource-profile limits, keeping the numbers identical to the code (`src/client_hello.rs:6,9,12,15`; `src/connect.rs:8`):

| Resource | Limit |
| --- | --- |
| CONNECT headers | 8 KiB |
| Buffered TLS bytes before authorization, including record framing | 64 KiB |
| TLS plaintext record payload during inspection | 16 KiB |
| ClientHello distinct extensions tracked (duplicate rejection) | 64 |
| ClientHello offered supported_versions entries retained | 32 |

The first two rows already exist in the Initial resource profile (`:163`/`:164`); the record-payload, extension, and version rows are new to the profile. No existing profile row is loosened or otherwise altered; the caps are pinned exactly as the code enforces them today.

### L12 — DNS TTL cap (deliberate new bound)

Spec `:74` is amended to cap the honored DNS TTL at a fixed maximum of **86400 seconds (24 hours)**. The entry freshness deadline uses `min`(earliest supporting CNAME/address TTL, 86400); a TTL of 0 remains treated as 1 second (RFC 1035 deviation preserved). With the fixed 259200-second stale grace (`:75`), the maximum authorization lifetime is 86400 + 259200 = **345600 seconds**. This is a new deliberate deviation from "honor the received TTL without raising it": the cap only ever lowers honored TTLs, never raises one, so authorization lifetime is bounded. Recorded here as a decision; flagged for user confirmation.

### L13 — Binding-address deduplication

Spec `:73`/`:74` are amended to require deduplicating identical addresses (compared as parsed numeric addresses, never textual forms) at staging/publication: a record type's published eligible bindings contain no duplicate addresses. Deduplication precedes publication so the per-family attempt budget (spec `:82`) is never wasted on duplicate candidates — within a family, address index `n` always selects a distinct address.

### L16 — Whole-second scheduling granularity

The refresh/backoff scheduling clauses (spec `:76`–`:78`) are amended to specify that all due times, the per-second start-rate guard, and backoff-stage comparisons use whole-second resolution from a single monotonic anchor. Due-time and not-before guards compare at whole-second truncation (documenting the existing code at `src/schedule.rs:381-384`); no sub-second due times or fractions influence scheduling, so refresh/backoff spacing is captured to whole seconds only.

### L17 — Four named parser fuzz targets

The Verification requirement at `:226` ("parser fuzzing") is sharpened to name the four parser targets that must be driven by a real fuzz loop before serving qualification: (1) ClientHello inspection (`ChInspector::feed`), (2) CONNECT headers (`ConnectParser`), (3) DNS wire (answer/record parsing), and (4) log-record encoding. Scaffold-only harnesses that do not drive the parsers do not satisfy the requirement.

### L18 — Sink-failure drop accounting

Spec `:197` (Log delivery) — and the DNS reporting/log-drop accounting it shares — is amended to specify that records stranded when the sink fails or stalls (queue-accepted records that cannot be drained before the failure) are counted as dropped under the existing whole-record drop accounting, never silently lost. A stalled or failing sink increments the drop count for stranded records; it must not cause them to be retained indefinitely, nor block rejection, tunnel I/O, DNS, or deadlines.

### Explicitly unchanged (non-negotiable)

The fixed resource profile (512 tunnels, 128 pending setups, two 128 KiB per-slot buffers, 128 MiB traffic storage, the 256 x 8 KiB log queue, 16-op/64 KiB visits, at-most-256-visit recheck, DNS response/candidate/incident caps, the 90-second startup window, and all deadlines — 10/2/300/5/8 seconds); empty capability sets and `no_new_privs`; byte conservation; non-decrypting; single owner; generation isolation; bounded work; no runtime metrics, control, debug, or endpoint interface; logs to stdout only; core TLS 1.3 + SNI + ECH-reject; packet dropping is never implemented; no new dependency unless its intake precedes execution; no kernel pacing knob. Nothing in this amendment loosens any of these items or restates any profile row differently; only L11 adds cap rows that reflect caps already enforced in the code, and L12 adds the new 86400-second TTL cap recorded as a deliberate bound above.

## CONNECT, configuration, and DNS destination-address hardening — user-authorized amendment

**Authority.** This section is a narrow, user-authorized amendment to this specification (`alumina-skhc`, 2026-10-17). It records the user authorization for three spec-body hardening edits applied together in one review-driven increment: (1) the Protocol contract restricts CONNECT to plaintext HTTP/1.1 and declares HTTP/1.0 CONNECT unsupported; (2) Configuration declares an IP literal-shaped allowlist entry — a name whose labels are all-numeric, e.g. `1.2.3.4:443` — invalid configuration; and (3) the Addresses clause clarifies that the AS112 anycast `192.31.196.0/24`, AMT `192.52.193.0/24`, and direct-delegation AS112 `192.175.48.0/24` ranges are deliberately not excluded because they are globally routable and can legitimately host internet services. It amends only the surfaces enumerated here; every other clause of this document — the fixed resource profile, lifecycle deadlines, invariants, logging vocabulary, and core TLS 1.3 + SNI + ECH-reject behavior — is unchanged and remains binding. The amended behavior is already committed in the body clauses above; this section records only their user authorization.

### Status

| Surface | Status |
| --- | --- |
| This amendment published | Current revision |
| Protocol contract: plaintext HTTP/1.1 CONNECT only; HTTP/1.0 CONNECT unsupported | Implemented (this increment) |
| Configuration: IP literal-shaped allowlist entries (all-numeric labels) invalid configuration | Implemented (this increment) |
| Addresses: AS112 anycast / AMT / direct-delegation AS112 ranges deliberately not excluded (globally routable) | Implemented (this increment) |

### Explicitly unchanged (non-negotiable)

The fixed resource profile (512 tunnels, 128 pending setups, two 128 KiB per-slot buffers, 128 MiB traffic storage, the 256 x 8 KiB log queue, 16-op/64 KiB visits, at-most-256-visit recheck, DNS response/candidate/incident caps, the 90-second startup window, and all deadlines — 10/2/300/5/8 seconds); empty capability sets and `no_new_privs`; byte conservation; non-decrypting; single owner; generation isolation; bounded work; no runtime metrics, control, debug, or endpoint interface; logs to stdout only; core TLS 1.3 + SNI + ECH-reject; packet dropping is never implemented; no new dependency unless its intake precedes execution; no kernel pacing knob. Nothing in this amendment loosens any of these items or restates any profile row differently.

## CONNECT Content-Length canonical digits — user-authorized amendment

**Authority.** This section is a narrow, user-authorized amendment to this specification (`alumina-icdl`, 2026-10-17). It records the user authorization for the canonical-digit `Content-Length` rule on the CONNECT Accept/Reject surface: a leading-zero `Content-Length` value is invalid on that surface and is rejected fail-closed, consistent with the canonical-digit rule already applied to the CONNECT target port (`:41`). It applies to the `Content-Length` field of an accepted CONNECT request (`:40`/`:41` region): literal `Content-Length: 0` is the only accepted value (`:40`); nonzero `Content-Length` is rejected (`:41`); and a leading-zero spelling of the accepted literal is itself rejected as malformed rather than accepted. It amends only the surface enumerated here; every other clause of this document — the fixed resource profile, lifecycle deadlines, invariants, logging vocabulary, and core TLS 1.3 + SNI + ECH-reject behavior — is unchanged and remains binding. The amended behavior is already committed in the CONNECT head parser at `src/connect.rs:363-365`; this section records only its user authorization.

### Status

| Surface | Status |
| --- | --- |
| This amendment published | Current revision |
| CONNECT Accept/Reject: canonical-digit `Content-Length`; literal `Content-Length: 0` is the only accepted value | Implemented (this increment) |
| Leading-zero `Content-Length` rejected fail-closed, consistent with the CONNECT target-port canonical-digit rule | Implemented (this increment) |

### Explicitly unchanged (non-negotiable)

The fixed resource profile (512 tunnels, 128 pending setups, two 128 KiB per-slot buffers, 128 MiB traffic storage, the 256 x 8 KiB log queue, 16-op/64 KiB visits, at-most-256-visit recheck, DNS response/candidate/incident caps, the 90-second startup window, and all deadlines — 10/2/300/5/8 seconds); empty capability sets and `no_new_privs`; byte conservation; non-decrypting; single owner; generation isolation; bounded work; no runtime metrics, control, debug, or endpoint interface; logs to stdout only; core TLS 1.3 + SNI + ECH-reject; packet dropping is never implemented; no new dependency unless its intake precedes execution; no kernel pacing knob. Nothing in this amendment loosens any of these items or restates any profile row differently.

## Memory accounting — retained serving workspace — user-authorized amendment

**Authority.** This section is a narrow, user-authorized amendment to this specification (`alumina-mema`, 2026-10-18). It corrects the memory accounting so the documentation is consistent with the structure currently used in code. The Initial resource profile and the traffic-storage budget note (`:161`-`:186`) are amended to record the **retained serving workspace** — a fixed, boot-time allocation that the code has always made but the prior accounting omitted. It amends only the surfaces enumerated here; every other clause of this document — the fixed resource profile limits, lifecycle deadlines, invariants, logging vocabulary, and core TLS 1.3 + SNI + ECH-reject behavior — is unchanged and remains binding.

### Amended surface

The retained serving workspace is a fixed per-slot allocation, made once at boot for the process lifetime and reused across connections, **outside** the 128 MiB tunnel-traffic-storage budget:

| Structure | Count | Unit size | Bound total |
| --- | --- | --- | --- |
| Per-slot CONNECT parser head | 512 | 8 KiB | 4096 KiB |
| Per-slot ClientHello inspector buffers (`buf` + `scratch`) | 512 × 2 | 64 KiB | 65 536 KiB |
| **Retained serving workspace total** | 512 slots | 136 KiB | **68 MiB** |

This is the `SLOT_WORKSPACE_BYTES` / `SERVING_WORKSPACE_BYTES` accounting in `src/inventory.rs:18-21` and the two `[u8; 64 KiB]` buffers (`buf`, `scratch`) in each `ChInspector` at `src/client_hello.rs:251,255`, preallocated for all 512 slots at boot (`src/serving.rs:926-938`). It is included in the boot inventory's named-fixed-buffer lower bound (`BootInventory::named_fixed_buffer_bytes` = 128 MiB traffic + 68 MiB serving workspace + DNS named buffers ≈ 196 MiB), consistent with the observed ~204 MiB VmRSS in `docs/benchmarks/e2micro-workload.md`.

The DNS transport's fixed 512-byte query buffer (`QUERY_BUF_LEN`, `src/startup_dns.rs:37`) is likewise a retained named buffer and is accounted with the DNS named buffers.

This amendment is a **clarification of the existing fixed profile, not a change to any limit**: the serving workspace was already allocated and retained by the code; the prior resource table understated the retained footprint by ~68 MiB. No profile row is loosened or altered.

### Status

| Surface | Status |
| --- | --- |
| This amendment published | Current revision |
| Initial resource profile: retained serving workspace row added (`:162`) | Implemented (this increment) |
| Traffic-storage budget note: serving workspace added to the outside-budget list (`:186`) | Implemented (this increment) |
| DNS 512-byte query buffer accounted with DNS named buffers | Implemented (this increment) |

### Explicitly unchanged (non-negotiable)

The fixed resource profile (512 tunnels, 128 pending setups, two 128 KiB per-slot buffers, 128 MiB traffic storage, the 256 x 8 KiB log queue, 16-op/64 KiB visits, at-most-256-visit recheck, DNS response/candidate/incident caps, the 90-second startup window, and all deadlines — 10/2/300/5/8 seconds); empty capability sets and `no_new_privs`; byte conservation; non-decrypting; single owner; generation isolation; bounded work; no runtime metrics, control, debug, or endpoint interface; logs to stdout only; core TLS 1.3 + SNI + ECH-reject; packet dropping is never implemented; no new dependency unless its intake precedes execution; no kernel pacing knob. Nothing in this amendment loosens any of these items or restates any profile row differently.

## Hardening: DNS wrong-family records, ClientHello handshake bound, CONNECT discriminant split — user-authorized amendment

**Authority.** This section is a narrow, user-authorized amendment to this specification (`alumina-hrdn`, 2026-10-19). It records the user authorization for three hardening increments applied together in one review-driven increment: (1) DNS wrong-family A/AAAA records at a chain owner are truly ignored — discarded without ever marking the owner as carrying address data — so a positive answer can never be satisfied by wrong-family records and a chain yielding only them terminates in a validated negative outcome (`:71`); (2) the ClientHello inspection profile bounds the TLS handshake message length, 4-byte header plus body, to 16 KiB — the same bound already applied to plaintext record payloads during inspection (`:47`/`:48`, resource profile `:165`/`:166`); and (3) the CONNECT parse surface splits the coarse rejection into exact finite discriminants — method not CONNECT, unsupported HTTP version, target not authority-form `host:port`, malformed request line — and removes the coarse `NotHttp` catch-all from both `ConnectError` and `ConnectHeadReason` (`:40`/`:41`). It amends only the surfaces enumerated here; every other clause of this document — the fixed resource profile, lifecycle deadlines, invariants, logging vocabulary, and core TLS 1.3 + SNI + ECH-reject behavior — is unchanged and remains binding. The amended behavior is already implemented in the code cited below; this section records only its user authorization.

### Amended surface

#### Vec 33 — DNS wrong-family records are truly ignored

Spec `:71` (DNS provenance) already rejects coexistence of CNAME and A/AAAA records at a chain owner (`CnameCoexist`). This increment hardens the independent wrong-family path: an answer to an A query containing AAAA records at a chain owner — or an AAAA query containing A records — is discarded as wrong-family without setting the owner's has-address-data flag (`src/dns.rs:824-830`, `:847-853`). Wrong-family records therefore never register as address data, cannot satisfy the positive-answer terminal requirement, and cannot corrupt a same-family CNAME chain into a misleading has-data outcome. A chain whose queries yield only wrong-family records terminates in the validated negative outcome `EmptyNoerrorWithoutSoa` — a clean, consistent NODATA-class result — and an NXDOMAIN carrying a wrong-family record at the terminal owner remains a clean `NxDomain`, never `TerminalWithoutData` (tests `ignored_opposite_family_*_then_cname_*` at `src/dns.rs:1847-1893`; `nxdomain_with_opposite_family_*` at `:1937`-`:1969`). The pre-existing reverse-direction artifact — a wrong-family address arriving before a same-family CNAME counting as address data — is eliminated with it; that path now also yields `EmptyNoerrorWithoutSoa`.

#### Vec 34 — ClientHello handshake-message length bound

Spec `:47` bounds each plaintext record payload to 16 KiB (`:166`). This increment adds the matching bound on the TLS handshake message length at 16 KiB (`MAX_HANDSHAKE_LEN`, 4-byte header plus body, `src/client_hello.rs:12`). A handshake whose declared length exceeds the bound is rejected as `ChError::HandshakeTooLarge { got }` at the scan gate (`src/client_hello.rs:394-395`) instead of being buffered toward the 64 KiB `MAX_CLIENT_HELLO` inspection total (`:165`). This is a content-level classification bound, not a buffer change: the retained serving workspace (`SLOT_WORKSPACE_BYTES`, `src/inventory.rs`, resource profile `:163`) and the two reused 64 KiB inspector buffers are unchanged. The TLS profile fold maps the new cause to the existing `Profile` reject kind (`src/client_hello.rs:198-220`), and a claim exactly at the 16 KiB cap is a complete-at-bound, not a length rejection (`src/client_hello.rs:1115-1128`).

#### Vec 36 — Split CONNECT error discriminants and remove the `NotHttp` catch-all

Spec `:40`/`:41` govern the CONNECT Accept/Reject surface. This increment replaces the coarse parse-failure classification with exact, finite discriminants: a request line that is not exactly three whitespace-separated tokens is `MalformedRequestLine`; a method other than `CONNECT` is `MethodNotConnect`; an HTTP version other than `HTTP/1.1` is `UnsupportedVersion`; and a target that is not authority-form `host:port` — starting with `/`, `*`, or a `scheme://` prefix (e.g. `windows(3)://`), or lacking a colon — is `TargetNotAuthorityForm` (`src/connect.rs:321-341`, `:384-400`). The coarse `NotHttp` variant is removed from both `ConnectError` and `ConnectHeadReason` (`src/connect.rs:42-56`, `:102-116`); `ConnectHeadReason::COUNT` is now 13 (`src/connect.rs:148`) and `AnyIllegalCause::KIND_COUNT` is 18 (`src/enforcement/policy.rs:21`). The monitoring grammar's fixed kind labels follow (`c13`, `a13`; `src/log.rs:1846`, `:1850`, `:1937`). The eliminated `NotHttp` row is deliberately not re-added: every prior `NotHttp` rejection is now attributable to exactly one of the new discriminants, so the coarser catch-all carried no additional information.

### Status

| Surface | Status |
| --- | --- |
| This amendment published | Current revision |
| DNS: wrong-family A/AAAA records truly ignored; no has-address-data flag; clean validated negative (`:71`) | Implemented (this increment) |
| ClientHello: handshake-message length bound 16 KiB; `HandshakeTooLarge` rejection (`:47`/`:48`) | Implemented (this increment) |
| CONNECT: exact finite discriminants (`MethodNotConnect`, `UnsupportedVersion`, `TargetNotAuthorityForm`, `MalformedRequestLine`); `NotHttp` removed (`:40`/`:41`) | Implemented (this increment) |

### Explicitly unchanged (non-negotiable)

The fixed resource profile (512 tunnels, 128 pending setups, two 128 KiB per-slot buffers, 128 MiB traffic storage, the 256 x 8 KiB log queue, 16-op/64 KiB visits, at-most-256-visit recheck, DNS response/candidate/incident caps, the 90-second startup window, and all deadlines — 10/2/300/5/8 seconds); empty capability sets and `no_new_privs`; byte conservation; non-decrypting; single owner; generation isolation; bounded work; no runtime metrics, control, debug, or endpoint interface; logs to stdout only; core TLS 1.3 + SNI + ECH-reject; packet dropping is never implemented; no new dependency unless its intake precedes execution; no kernel pacing knob. Nothing in this amendment loosens any of these items or restates any profile row differently.

## Hardening: CONNECT header-line count bound, passive resolver degraded signaling, widened refresh band — user-authorized amendment

**Authority.** This section is a narrow, user-authorized amendment to this specification (`alumina-hrdn2`, 2026-10-19). It records the user authorization for three hardening increments applied together in one review-driven increment: (1) the CONNECT header-line count is bounded to at most 16 header fields, with a new exact `TooManyHeaderLines` discriminant on the Accept/Reject surface (`:40`/`:41`); (2) the passive resolver gain a consecutive-failure degradation state machine that emits one distinct degraded fact per enter/exit crossing rather than per failure, folded into the `alumina-rp2e` enforcement monitor's fact vocabulary; and (3) the normal DNS refresh band widens from 30/300 seconds to 5/900 seconds with the SOA-based negative refresh keeping its own 30-second floor (`:76`/`:77`, resource profile `:176`/`:177`). It amends only the surfaces enumerated here; every other clause of this document — the fixed resource profile, lifecycle deadlines, invariants, logging vocabulary, and core TLS 1.3 + SNI + ECH-reject behavior — is unchanged and remains binding. The amended behavior is already implemented in the code cited below; this section records only its user authorization.

### Amended surface

#### Vec 35 — CONNECT header-line count bound

Spec `:40`/`:41` govern the CONNECT Accept/Reject surface. This increment bounds the number of header lines a CONNECT request head may carry at 16 header fields (`MAX_HEADER_LINES`, `src/connect.rs:13`). Every line the header loop yields is counted (`src/connect.rs:267-270`), incrementing before the empty-line continue as defense in depth — the head is truncated at the first CRLFCRLF delimiter, so each header field yields exactly one header-loop line and the empty line never appears in a bounded head. A request whose count exceeds 16 is rejected with the new exact discriminant `ConnectError::TooManyHeaderLines`, mapped to `ConnectHeadReason::TooManyHeaderLines` (`src/connect.rs:61`, `:126`, `:149`). `ConnectHeadReason::COUNT` is now 14 (`src/connect.rs:160`), `AnyIllegalCause::KIND_COUNT` is 19 (`src/enforcement/policy.rs:21`), and the monitoring grammar's fixed kind labels follow (`c14`, `a14`; `src/log.rs:1846`, `:1850`, `:1937`). The bound is a parse-classification bound, not a buffer change: the fixed request-head buffer and its size limits are unchanged, and a head of exactly 16 fields is accepted at the boundary.

#### Vec 19 — Passive resolver degraded signaling

The startup-resolution and refresh clauses (`:62`–`:78`) govern the resolver stub. This increment adds a passive degradation state machine: after three consecutive counted exchange failures the resolver relocates into `Degraded` mode (`DEGRADED_AFTER`, `src/startup_dns.rs:550`; the `ResolverDegradation` state at `:536-546` makes the count-degradation boundary structural — `Healthy` can never hold three consecutive failures), and any subsequently successful publication relocates it back to healthy, restarting the consecutive-failure count from zero (`note_success`). A valid negative response counts as a successful exchange. The state machine emits exactly one enter crossing on relocation into degraded and exactly one exit crossing on recovery — never one per individual failure — accumulated as a drainable transition count (`record_resolver_failure`/`record_resolver_success`, `src/startup_dns.rs:1804-1821`; drained via `take_resolver_transitions`). The shared serving owner drains pending crossings each turn and after the startup window (`drain_resolver_transitions`, `src/serve.rs:381`, `:585`) into enforcement via `Enforcement::note_fact_resolver_degraded()` (`src/enforcement/state.rs`), landing in the saturating `FactCounters::resolver_degraded` (`src/enforcement/monitor.rs`). The monitor grammar folds the counter into `facts_total()`, surfaces it as the zero-suppressed `rd=` key, and counts its overflow into `ofacts` (`src/log.rs`). The fact is edge-triggered, so an operator observing `rd=` sees each degraded-mode transition instead of a per-failure flood, at zero new allocations and zero new log surfaces.

#### Vec 14 — Widened refresh band with a split negative floor

Spec `:76` (refresh scheduling) and `:77` (negative refresh scheduling), with the profile rows `:176`/`:177`, are amended. The normal refresh band widens to `min(900 seconds, max(5 seconds, entry TTL))` (`REFRESH_MIN = 5`, `REFRESH_MAX = 900`, `src/schedule.rs:5`, `:8`; `normal_refresh_interval` clamp `:42-44`). The SOA-based negative refresh band becomes `min(900 seconds, max(30 seconds, min(SOA TTL, SOA.MINIMUM)))` with its own 30-second floor (`NEGATIVE_REFRESH_MIN`, `src/schedule.rs:11`; `negative_refresh_interval` clamp `:50-52`), preserving the established 30-second negative floor while the cap rises to 900 with the normal band. The per-second start-rate guard of `:76` is unchanged and is verified to still hold at the 5-second cadence the widened floor makes plausible (test `start_rate_guard_holds_within_a_five_second_refresh_cadence`). The cache-level TTL cap at `src/cache.rs:328` is explicitly unchanged: a received TTL is never raised above its validated value on the way into the cache; the widened scheduling bounds affect only refresh due times.

### Status

| Surface | Status |
| --- | --- |
| This amendment published | Current revision |
| CONNECT: header-line count bound at 16; exact `TooManyHeaderLines` discriminant (`:40`/`:41`) | Implemented (this increment) |
| Resolver: consecutive-failure `Degraded` state machine; one fact per enter/exit crossing; `rd=` monitor key (`:62`–`:78`) | Implemented (this increment) |
| Refresh: normal band 5/900 seconds; SOA-based negative floor 30/900 seconds (`:76`/`:77`, `:176`/`:177`) | Implemented (this increment) |

### Explicitly unchanged (non-negotiable)

The fixed resource profile (512 tunnels, 128 pending setups, two 128 KiB per-slot buffers, 128 MiB traffic storage, the 256 x 8 KiB log queue, 16-op/64 KiB visits, at-most-256-visit recheck, DNS response/candidate/incident caps, the 90-second startup window, and all deadlines — 10/2/300/5/8 seconds); empty capability sets and `no_new_privs`; byte conservation; non-decrypting; single owner; generation isolation; bounded work; no runtime metrics, control, debug, or endpoint interface; logs to stdout only; core TLS 1.3 + SNI + ECH-reject; packet dropping is never implemented; no new dependency unless its intake precedes execution; no kernel pacing knob. Nothing in this amendment loosens any of these items or restates any profile row differently.

## Hardening: CNAME bailiwick enforcement, DNS anomaly fact surface, resolver peer assertion — user-authorized amendment

**Authority.** This section is a narrow, user-authorized amendment to this specification (`alumina-hrdn3`, 2026-10-19). It records the user authorization for four hardening increments applied together in one review-driven increment: (1) a followed CNAME link target must land inside an allowlist bailiwick zone or the exchange fails with the distinct `BailiwickViolation` discriminant (`:71`); (2) an answer carrying a resource-record TTL above 96 hours is detected and counted (`:74`); (3) those two detections plus the resolver-peer assertion surface as a typed, saturating DNS-anomaly fact vocabulary (`bv`/`rpm`/`xttl`) folded into the `alumina-rp2e` enforcement monitor; and (4) a completed connect landing on a peer other than the configured nameserver fails the exchange with the distinct `ResolverPeerMismatch` anomaly (`:68`). It amends only the surfaces enumerated here; every other clause of this document — the fixed resource profile, lifecycle deadlines, invariants, logging vocabulary, and core TLS 1.3 + SNI + ECH-reject behavior — is unchanged and remains binding. The amended behavior is already implemented in the code cited below; this section records only its user authorization.

### Amended surface

#### Vec 11 — CNAME bailiwick enforcement

Spec `:71` governs the response-provenance rules and the CNAME walk. This increment confines every followed CNAME link to the allowlist bailiwick zones: the resolver derives a deduplicated zone set from the allowlist once per resolve (`BailiwickZones::from_allowlist`, `src/dns.rs:787`), a hostname with more than two labels contributing its parent domain and a two-label apex contributing itself (`zone_of`, `src/dns.rs:821`); `covers` then decides membership on label boundaries via `soa_covers` (`src/dns.rs:811`, `:1175`). The check is placed after the existing CNAME-provenance rules in the followed-link walk (`src/dns.rs:1142`), so the ≤8-link bound, loop detection, and no-conflicting-target rules still apply and bailiwick is the final gate on where a link may land. A target outside every zone fails the exchange with the distinct `DnsError::BailiwickViolation` (`src/dns.rs:247`), never silently routing into an attacker zone. `BailiwickZones` uses the fixed `ALLOWLIST_MAX` `DnsName` slots (`src/dns.rs:769`) with no heap allocation, preserving the fixed profile; the wire-parser fuzz target that holds no allowlist carries its own single-zone set (`BailiwickZones::single`, `src/dns.rs:802`).

#### Vec 32 — CNAME-chain pinning to known-good zones

Spec `:71` governs the response-provenance rules and the CNAME walk, and vector 32's "known-good zones" pinning is realized by the same gate as Vec 11: every followed CNAME link is confined to the allowlist bailiwick zones derived above (`BailiwickZones::from_allowlist`, `src/dns.rs:787`; `covers`/`soa_covers`, `:811`/`:1175`), so a chain can never pass through or terminate in an attacker zone. The chain-pinning intent of vector 32 — chaining into attacker zones — is thereby fully covered: a target outside every zone fails the exchange with `DnsError::BailiwickViolation` (`src/dns.rs:247`) rather than being followed. The two vectors differ only in vantage (bailiwick membership vs. pinning to known-good zones) and share one implementation seam; both are promoted out of candidate research together.

#### Vec 21 — DNS anomaly fact surface

The startup-resolution and refresh clauses (`:62`–`:78`) and the `alumina-rp2e` monitoring vocabulary govern the resolver stub and monitor, and vector 21's "detect unexpected TTLs" is realized as one of the anomaly kinds. This increment adds a typed DNS-anomaly surface to the monitor: `DnsAnomalyKind` with the three variants `BailiwickViolation`, `ResolverPeerMismatch`, and `ExtremeTtl` and a structural `COUNT`/`index`/`from_index` (`src/enforcement/monitor.rs:22-47`), carried as `FactCounters::dns_anomaly: [SaturatingCounter; 3]` (`src/enforcement/monitor.rs:14`). The `ExtremeTtl` variant is fed by a per-exchange detection for an answer whose address- or CNAME-carrying resource-record TTL exceeds the threshold `EXTREME_TTL_THRESHOLD = 345_600` (96 h; `src/dns.rs:25`): the flag lives on the reused `ResponseWorkspace` (`extreme_ttl`, `src/dns.rs:712`, `:725`), reset at each parse start (`:857`), set in the answer loop when an A/AAAA/CNAME record's TTL crosses the threshold (`:912`), read back through the `extreme_ttl()` accessor (`:734`), and noted once per affected exchange after a successful publish (`src/startup_dns.rs:1412-1414`). The existing honored-TTL cap at `src/cache.rs:328` is unchanged: a received TTL is never raised on its way into the cache; this increment only observes and counts the extreme value. The transport retains a matching fixed `dns_anomalies: [u32; 3]` (`src/startup_dns.rs:622`), notes each detection saturatingly (`note_dns_anomaly`, `:1022`), and drains it once with `mem::take` so a drain never double-counts (`take_dns_anomalies`, `:1028`). The shared serving owner drains pending anomalies each turn and after the startup window (`drain_dns_anomalies`, `src/serve.rs:383`, `:603`) into enforcement via `Enforcement::note_fact_dns_anomaly()` (`src/enforcement/state.rs`), landing in the saturating monitor counter. The monitor grammar folds the counters into `facts_total()`, counts any overflow into `ofacts` (`src/log.rs:490`), and surfaces them as the zero-suppressed, deterministic-order `bv=`/`rpm=`/`xttl=` keys emitted after the `rd=` block (`src/log.rs:527-541`), at zero new allocations and zero new log surfaces.

#### Vec 22 — Resolver peer assertion

Spec `:68` fixes one resolver per tunnel with a single transport peer. This increment adds a passive assertion at the transport: a completed nonblocking connect whose peer is not the configured nameserver fails the exchange with `FailureReason::Connect` and notes a `ResolverPeerMismatch` anomaly (`peer_matches`, `src/startup_dns.rs:1010`; the peer check in `step_connect`, `:1216-1223`). The assertion runs once per completed connect — a warm reused connection passes without re-asserting — and the configured nameserver address is the only accepted peer. Under test the seam can force a mismatch (`force_peer_mismatch`) so the branch is exercised end to end (vec-22).

### Status

| Surface | Status |
| --- | --- |
| This amendment published | Current revision |
| Bailiwick + known-good-zone pinning: followed CNAME links confined to allowlist zones; outside target fails with `BailiwickViolation` (`:71`) | Implemented (this increment) |
| Anomaly fact surface: typed saturating `bv`/`rpm`/`xttl` counters incl. extreme-TTL (>96 h) detection, folded into the rp2e monitor (`:62`–`:78`, `:74`) | Implemented (this increment) |
| Peer assertion: connected peer ≠ configured nameserver fails connect with `ResolverPeerMismatch` (`:68`) | Implemented (this increment) |

### Explicitly unchanged (non-negotiable)

The fixed resource profile (512 tunnels, 128 pending setups, two 128 KiB per-slot buffers, 128 MiB traffic storage, the 256 x 8 KiB log queue, 16-op/64 KiB visits, at-most-256-visit recheck, DNS response/candidate/incident caps, the 90-second startup window, and all deadlines — 10/2/300/5/8 seconds); empty capability sets and `no_new_privs`; byte conservation; non-decrypting; single owner; generation isolation; bounded work; no runtime metrics, control, debug, or endpoint interface; logs to stdout only; core TLS 1.3 + SNI + ECH-reject; packet dropping is never implemented; no new dependency unless its intake precedes execution; no kernel pacing knob. Nothing in this amendment loosens any of these items or restates any profile row differently.

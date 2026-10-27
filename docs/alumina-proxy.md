# Alumina Proxy - Domain-level filtering for HTTPS egress

## Overview

Alumina is a non-terminating forward proxy for HTTPS over TCP, admitting connections to a configured FQDN allowlist. Its priorities are integrity, bounded resources, low latency, least privilege, and a minimal feature set. It supports a single golden-path profile: a simple, known-good, cloud-platform-agnostic configuration, rather than general compatibility or automatic negotiation between proxy operating modes. Environments whose complexity or technical debt prevents adopting this profile should use a more capable alternative, such as GCP Secure Web Proxy. Application-protocol verification is not a goal.

The typical use case is a cloud-hosted server whose outbound integrations call a small set of approved third-party HTTPS services. Alumina is a niche alternative to a managed secure web proxy for this profile, not a feature-equivalent replacement. Clients explicitly use Alumina; deployment-enforced network isolation blocks alternate HTTPS egress even when clients ignore proxy settings. Together, these controls are analogous to positive locking: default-deny egress with explicit destination authorization, enforced independently of application cooperation. The analogy describes confinement, not a guarantee against misuse of approved endpoints. This pattern is independent of cloud provider or compute platform.

## Design philosophy — the exit gate

Alumina is deliberately narrow: it is the castle's **exit gate**, nothing more.
It does not guard the interior, wall off attackers, or police ingress — it
guards the single exit through which the workload reaches the outside world,
and it guards that exit with a fixed, opinionated design rather than a surface
of configuration choices. This narrowness is a permanent commitment, not
current state: scope never grows to ingress control, payload inspection, or
adjacent capabilities.

The trust model is not distrust of the system. The application and the operator
are trusted at rest; the operator holds full privilege over both application
and proxy configuration. Alumina exists because compromise is inevitable: when
an application is compromised, the proxy's task is to **identify** the
compromise and **protect against further exploitation** purely through egress —
the limit of its visibility and responsibility.

From that task follows the core promise: **no silent acceptance of adversarial
behavior**. Every deviation from the configured golden path is detected and
acted on; there is no tolerated rate of bad behavior. The tripwires are
trigger-happy by design — they react on the first sign of deviation — and
highly accurate. The action taken (flare, block, or tarpit) is the operator's
configuration choice; the proxy does not always panic by blocking all egress.
Alumina's promise is highly accurate tripwires; the operator decides the
appropriate action for their context.

Narrowness is the mechanism, not a compromise: a single purpose, a fixed
resource profile, and fixed security semantics make the proxy's invariants
provable — no post-boot allocation, a single boot and serving owner, bounded
buffers, no runtime-surface expansion. The fixed profile is the inviolable
contract; it never yields to a feature.

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
- **Errors:** Policy violations, which indicate misconfiguration or compromise, receive an empty body: `400` malformed request, `403` hostname not allowlisted. Runtime conditions receive a fixed plain-text body stating the reason: `502` no resolved addresses or upstream connection failed, `503` no capacity, `504` setup deadline expired. Client input is never echoed. The response corpus is an acknowledged allowlist-enumeration and cache-state oracle (alumina-redtm SP-008): the `400`/`403` split discriminates allowlist membership from malformed syntax and the `502`/`503`/`504` split discriminates DNS-cache state per allowlisted name; this is a threat-model acknowledgement only, with no behavior change.

### TLS ClientHello profile

- **Version offer:** Require the `supported_versions` extension with TLS 1.3 (`0x0304`) as its only non-GREASE version. Reject missing extensions, TLS 1.2 fallback offers, and other non-GREASE versions. TLS 1.3-only is a golden-path profile requirement, not a security control: clients must be configured with TLS 1.3 as their minimum version. Require the TLS 1.3 ClientHello `legacy_version` value `0x0303` and the single null legacy compression method. Accept handshake record legacy versions `0x0301` and `0x0303` for the initial ClientHello; these compatibility fields do not enable a TLS 1.2 parsing path. Reject SSLv2 framing and non-handshake records before the initial ClientHello is complete; bound each plaintext record payload to 16 KiB.
- **Identity and framing:** Require exactly one `server_name` extension containing exactly one hostname entry, matching the approved CONNECT hostname. Validate enclosing lengths, vectors, and extension boundaries; reject duplicate extensions and malformed or ambiguous identity. Well-framed unknown extensions and GREASE values may be skipped by length; do not introduce cipher-suite or ALPN policy.
- **ECH:** Reject the `encrypted_client_hello` extension, including ECH GREASE, regardless of outer SNI. Golden-path clients must not send ECH. Never strip or rewrite extensions.
- **Inspection scope:** Inspect only the initial ClientHello, preserving fragmentation and all buffered bytes. Later handshake messages and encrypted application traffic remain opaque. A second ClientHello following a HelloRetryRequest is not inspected; it adds no capability beyond the accepted domain-fronting limitation. The version check constrains the client's advertised profile; it does not authenticate the upstream server or independently verify the version actually negotiated by the endpoints.

## Configuration & DNS

Configuration is a single TOML document of at most 16 KiB (16384 bytes), including comments and whitespace, with a required set of 1 through 32 `[allowed_fqdn."<fqdn>:<port>"]` keyed tables — each carrying exactly one `early_data` inline table with that entry's `action` and `scope` — and a required `listen` key. Each table key is a literal `<fqdn>:<port>` spelling naming a lowercase ASCII DNS hostname (an IP literal-shaped entry — a name whose labels are all-numeric, e.g. `1.2.3.4:443` — is invalid configuration) with a canonical decimal port from 1 through 65535 and no leading zero; a bare FQDN without `:port`, an empty or non-numeric port, port `0`, a port above `65535`, or a leading-zero port is invalid configuration. Table keys are unique after normalization (lowercase FQDN plus canonical port); a duplicate after normalization is invalid configuration. Both limits apply: 32 maximum-length DNS names need not fit. A compact configuration with 32 entries of 100 ASCII bytes each (including the `:port` suffix) and a listener fits within the document limit. Bound the configuration read and reject oversized input without truncating it. Load and fully validate configuration and local prerequisites before opening listeners or issuing DNS queries. There is no runtime policy update interface; see the [runtime surface](#architecture).

`startup_unresolved_allowance` is required and must be an integer from `0` through the number of configured `[allowed_fqdn."..."]` tables minus one; `0` requires every hostname to be usable at startup. An empty table set is invalid configuration. The allowance affects startup availability, never destination authorization. All configuration keys are mandatory; no defaults are supplied.

Missing or unreadable configuration, invalid TOML (including duplicate keys or invalid table redefinitions), missing required fields, unknown keys or tables, incorrect types, out-of-range values, conflicting settings, and unmet local prerequisites cause immediate startup failure with exit status 78 (EX_CONFIG) and a diagnostic identifying the field or source location where available. The conflicting-settings class is enumerated here for auditability (documentation clarification only; no new validation): the mandated-set predicates — a required set of settings that must be present and consistent together, where a member present more than once after normalization is a conflict (duplicate keys, invalid table redefinitions, and duplicate allowlist names after normalization are the enumerated instances) — and the forbidden-pair predicates — two settings that cannot legally coexist under this document's schema, where the schema's enumerated scope values are exclusive (a scope value outside the enumerated set for its surface is invalid configuration rather than a silent override). Reject duplicate allowlist names after normalization. Do not coerce types, discard invalid entries, or supply missing required values from defaults, environment variables, or command-line overrides. After startup resolution, DNS timeouts, negative answers, and other network failures are expected runtime outcomes governed by the cache rules below, not configuration errors.

- **Listener:** `listen` is a required string of the form `address:port`, with a numeric IPv4 or bracketed IPv6 address and a port from 1 through 65535. Wildcard addresses are allowed. A bind failure prevents startup.
- **Names:** Configuration uses lowercase ASCII DNS hostnames, with IDNs supplied in A-label form; CONNECT and SNI hostnames compare case-insensitively. Configuration and CONNECT may normalize a single trailing dot; SNI must satisfy TLS hostname syntax. Compare canonical names and issue absolute DNS queries without search suffixes.
- **Resolver selection:** Read the validated `resolver` array from the configuration document once at startup (see the resolver-set and DoT amendments below); no platform resolver file is read. The array holds 1 through 5 entries, each a numeric unicast IPv4 or IPv6 address without a zone identifier, optionally carrying a validated `#fqdn` identity (and, for strict-pinned DoT, a `#pin-sha256=<b64>` suffix); the dial port is 53 for a bare-IP entry and 853 for an entry carrying an FQDN. Select the first (primary) entry as the initial resolver. The resolver set is fixed for the process lifetime, but the transport relocates across the declared array under per-resolver degradation with bounded failback to the primary (failover/failback), never beyond the declared entries. Ignore platform search suffixes and resolver tuning options; do not use general OS hostname-resolution APIs, hosts-file lookup, runtime rediscovery, or fallback to an undeclared resolver. The validated configuration is a trusted deployment input.
- **Resolution:** Alumina implements a bounded DNS stub, not a recursive resolver or client-facing DNS service. Resolve before opening the listener, then refresh independently of requests; requests use cached results without triggering or waiting for lookups. Local DNSSEC validation and DNS over TLS or HTTPS are outside the initial scope.
- **Startup deadline:** Startup proceeds in fixed order: privilege check, configuration read (allowlist and resolver set), storage initialization, DNS startup window, then listener opening. After local validation and storage initialization, set an absolute monotonic deadline 90 seconds ahead, before the first DNS connection attempt. It cannot be extended or supplemented by a network-readiness phase. Clip each exchange deadline to it, including TCP establishment and response processing. Check the clock before publication; only results fully validated and published strictly before the deadline count.
- **Startup readiness:** A configured hostname is usable if its current cache has an eligible, non-retired positive binding; all others, including validated negatives and unattempted names, count as unresolved. Open the listener early only when all names are usable, atomically rechecking cache and deadline. Otherwise, at the deadline evaluate the cache once: serve if the unresolved count is at most `startup_unresolved_allowance`, or exit with status 75 (EX_TEMPFAIL) for external restart. On expiry, cancel the outstanding exchange, close its transport, and invalidate obsolete work before background resolution resumes.
- **Degraded serving:** The allowance applies only at startup; subsequent availability follows the normal cache and DNS incident rules. Consistent with the [runtime surface](#architecture), Alumina exposes no readiness endpoint.
- **Startup diagnostics:** During startup, attempt to enqueue one warn notification on the first exchange failure across all names and record types. Continue tracking per-type incidents and latest failure reasons, but suppress their individual first-failure warnings. Emit one record per unresolved name carrying the full untruncated name, its latest outcome, and its not-attempted reason, then one final summary result on success or failure with full/degraded/failure status, allowance, usable/unresolved counts, and the number of per-name records that could not be enqueued. Suppress hourly summaries until serving; preserve unresolved type incidents and initialize traffic-reporting windows at that transition. Do not replay suppressed warnings when serving begins; retained incidents continue normally, and subsequent new incidents receive the normal per-type warning.
- **Transport:** Each resolver entry dials its declared form: plain DNS over TCP on port 53 for a bare-IP entry, or DNS over TLS (DoT) on port 853 for an entry carrying an `#fqdn` identity, with one reusable connection and one outstanding query. DoT validates the server identity against the entry's FQDN as SNI/SAN and, for a strict-pinned entry, the server's SPKI digest against its `#pin-sha256=` suffix; an unpinned DoT entry validates against an empty root store and fails closed. There is no UDP or alternate-resolver fallback, and a DoT handshake or identity failure never downgrades to cleartext plain DNS. Validate the response flag, opcode, transaction ID, and question name, type, and class against the outstanding query; draw each transaction ID from the OS CSPRNG (`getrandom`). Close the DNS connection on timeout, malformed or mismatched responses, truncation, or an oversized message; do not publish partial results. Plain DNS over TCP is not cryptographic authentication of the resolver or DNS data.
- **Wire parsing:** Require QDCOUNT 1, exact section counts with no trailing bytes, and RDLENGTH equal to the parsed RDATA (4 for A, 16 for AAAA). Follow compression pointers only to strictly earlier offsets, and only in owner names and CNAME/SOA names. Reject reserved label types, labels over 63 octets, and decoded names over 255 octets.
- **DNS control traffic:** DNS sockets may reach only the selected resolver endpoint. This control traffic is separate from tunnel destination authorization and may use a private, loopback, or link-local resolver address; it never makes that address eligible as a CONNECT destination.
- **DNS provenance:** Issue only IN-class A/AAAA queries for the exact approved hostname, with recursion desired, through the selected recursive resolver. Do not perform local recursion, CNAME follow-up queries, or alternate-resolver fallback. Accept direct addresses or a complete CNAME chain rooted at the queried hostname, with at most eight links and no loops. Require one unambiguous target per chain owner; reject conflicting targets and coexistence of CNAME and A/AAAA records at a chain owner. For a positive answer, every candidate must be an IN-class record of the requested type in the answer section, owned by the queried hostname or the terminal name of the rooted chain. All supporting CNAME records must also be in the answer section. Unrelated records and all authority/additional-section addresses must never become candidates. A chain may instead terminate in a validated negative outcome without terminal addresses, as specified below; a chain lacking either terminal addresses or a validated negative outcome is an exchange failure. CNAME targets need not be allowlisted, but every followed CNAME link must land inside an allowlist bailiwick zone — the per-entry union of the allowlist name's self-default zone (the name and its subdomains) and that entry's declared `cname_bailiwick` suffix union, each matched at label boundaries — or the exchange fails with the distinct `BailiwickViolation` outcome rather than silently routing into an attacker zone; they locate an approved name's addresses but never authorize additional CONNECT names. CONNECT and SNI remain the original approved hostname. DNAME records in the answer section are unsupported and cause an exchange failure, even if a synthesized CNAME is present; never implement DNAME substitution.
- **Service discovery:** HTTPS/SVCB endpoint substitution is unsupported. These records must not change the CONNECT target, destination port, or transport. Clients must use the origin hostname on its allowlisted entry's port as the CONNECT target and supply matching SNI, rather than substitute an alternative endpoint.
- **Addresses:** As defense-in-depth against resolver or zone misconfiguration, only globally routable unicast destinations are eligible. Compare parsed numeric addresses, never textual forms. IPv4 candidates must not fall within `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, or `240.0.0.0/4`. IPv6 candidates must lie within `2000::/3` and outside `2001::/23`, `2001:db8::/32`, `2002::/16`, and `3fff::/20`. Prefixes that embed or translate IPv4 addresses are ineligible regardless of the embedded address, including IPv4-mapped, IPv4-compatible, NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4, and Teredo; Alumina never extracts an embedded IPv4 address to check it. NAT64/DNS64 deployments are outside the golden path. The table is fixed at build time; changing it requires a design revision. The IPv4 exclusion table is deliberately scoped to private, loopback, link-local, benchmark, documentation, and other non-globally-routable space; public special-use ranges — AS112 anycast `192.31.196.0/24`, AMT `192.52.193.0/24`, and direct-delegation AS112 `192.175.48.0/24` — are intentionally not excluded because they are globally routable and can legitimately host internet services, so their absence is not an omission. Validate every A/AAAA candidate before publication and again before each connection attempt.
- **Cache lifetime:** Each configured name holds one cache entry per record type: its eligible addresses (bindings), one freshness deadline, one retirement deadline, and a generation. The entry TTL is the earliest TTL of any supporting CNAME or address record in the answer (RFC 2181 §5.2), measured from receipt with a monotonic clock; all bindings in an entry share its deadlines. Fresh, stale, and retired are computed from the entry deadlines and the current monotonic time, never stored: only validated DNS outcomes mutate an entry, and timers only drive refresh and notifications. Honor the received TTL without raising it to the minimum refresh interval, except that a TTL of 0 is treated as 1 second, deviating from RFC 1035 so zero-TTL steering services remain usable. A validated positive answer replaces the cached addresses for its record type and establishes new freshness and retirement deadlines. A validated recursive negative answer evicts immediately without stale grace: NXDOMAIN is name-wide for the queried allowlisted hostname, including when its CNAME terminal name is nonexistent; NODATA is specific to the queried record type and must not evict addresses of another type. Apply a validated NXDOMAIN to both record types as though each had received it: evict both entries, update both schedules, and clear both exchange-failure incidents. Neither outcome requires the AA bit. DNS queries and refresh results belong to cache state, not connection generations; obsolete results cannot overwrite newer cache state.
- **Stale retirement:** After TTL expiry, a binding is retained for a fixed 72-hour (259200-second) stale-retention lifetime, matching the RFC 8767 maximum stale timer, but it may authorize new upstream connections only within a separate stale-serving window of 3600 seconds (1 hour) after TTL expiry: retention bounds how long a binding is kept, while the stale-serving window bounds how long it may serve new connections, and the two are independent. The entry's absolute retirement deadline is receipt time plus the entry TTL plus 259200 seconds. Exchange failures, including timeouts, SERVFAIL, and malformed responses, retain bindings only within this lifetime; failures, scheduling delays, client requests, and successful TCP connections never extend the deadline. Missing, replaced, evicted, or retired bindings cannot authorize a new upstream connection, and a binding past its stale-serving window cannot authorize one either. Check retirement and the stale-serving window directly before every upstream connection attempt, even if timer processing is delayed. A positive answer for one record type cannot renew bindings of another type. Retirement does not change the peer or lifecycle of an established tunnel, stop background retries, remove the configured hostname, or terminate the process; a later validated positive answer restores authorization automatically. Stale use and per-type retirement are reported only through DNS incident summaries.
- **Refresh scheduling:** After a positive answer with cacheable bindings, schedule the next normal refresh for its record type at receipt time plus `min(900 seconds, max(5 seconds, entry TTL))`. These fixed lower and upper bounds govern refresh scheduling, not DNS freshness: a 30-second TTL schedules refresh after 30 seconds; a shorter TTL expires before the normal refresh becomes due, and any intervening authorization uses the stale-serving window. Track due work in a fixed table with one due time per name and record type and no separate query queue; superseding work overwrites the due time, so at most one query per name and record type is pending. Each record type maintains independent due times and retry state; an outcome for one type must not alter the other's state except for name-wide NXDOMAIN. Due entries share the single DNS transport and may wait behind other exchanges. Scan the table in fixed rotating round-robin order so repeated failures cannot monopolize transport access. Start at most one query per name and record type per second. These intervals establish due times, not guaranteed query start times under contention. Client requests cannot accelerate refresh or retries.
- **Negative refresh scheduling:** A validated negative answer with an authority SOA schedules the next normal refresh using `min(900 seconds, max(30 seconds, min(SOA TTL, SOA.MINIMUM)))`, measured from receipt. NXDOMAIN applies this due time to both record types and supersedes older work; NODATA applies it only to the queried type. Negative TTL controls retry scheduling, never positive authorization: its expiry cannot restore evicted bindings. A validated NXDOMAIN without an SOA schedules both record types with the bounded retry backoff instead. These are fixed profile rules, not configuration options.
- **Refresh failures and recovery:** An exchange failure ends the affected resolution attempt; schedule later attempts from completion using 1, 2, 4, 8, 16, then 30-second capped backoff. The minimum normal refresh interval does not apply to failure retries. Keep retry state distinct for A and AAAA; only a validated positive answer with cacheable bindings for the affected type resets its backoff. Retry missing or retired bindings using bounded backoff; evicted bindings use negative refresh scheduling when an SOA is available, otherwise backoff. Continue background attempts for as long as the process serves traffic. Repeated NXDOMAIN answers without an SOA and positive answers without cacheable bindings advance rather than reset retry backoff. An answer for another type must not reset a failing type's backoff or extend its authorization. A failing name cannot monopolize DNS work.
- **DNS incident notifications:** Track unresolved exchange failures independently for A and AAAA. The first exchange failure for a type starts an incident and emits one warn notification, except during startup, where the startup diagnostics rules govern warning emission. Subsequent failures update its latest reason without logging each retry. A validated positive or negative answer clears that type's exchange-failure incident and emits one info recovery notification with its duration; valid NODATA, including an absent AAAA record for an IPv4-only name, is not a resolution failure. Incident recovery does not imply restoration of eligible addresses or reset the retry backoff for negative answers. Except for NXDOMAIN, an outcome for one type cannot clear an incident for the other. While either type has an incident, emit one error summary per hostname after each 3600-second reporting window. Start the first window when the hostname first enters an incident; do not restart it when the other type fails or recovers. Report an immediate error when a hostname transitions from having eligible bindings to having none, including through retirement or negative-answer eviction. Recovery of eligible bindings emits one info notification. Do not restart the process or change retry scheduling in response to these notifications.
- **DNS incident summaries:** Include hostname, failing record types, incident start and elapsed duration per type, latest failure reason, last positive-resolution time per type, attempts and exchange failures per type during the reporting window, and per type the eligible address count, entry state (fresh, stale, or retired), and remaining freshness and retirement deadlines. Include the number of distinct tunnels with activity, total forwarded bytes, and new tunnels admitted with stale bindings during that window. Activity means at least one tunnel byte successfully forwarded in either direction; CONNECT response bytes, merely open sockets, buffered reads, and readiness events do not count. Count a tunnel once per window even if it predates the incident, remains open across windows, or closes before the summary. Count payload bytes once on successful writes, not on both reads and writes. Count a stale admission once when a new upstream peer is committed using a stale binding; retries and relay activity are not admissions. On full hostname incident recovery, emit a final summary for the partial window at info level with its actual duration.
- **DNS reporting bounds:** Preallocate incident state for both record types of each configured name, reporting counters and window state per name, and one last-counted window identifier per tunnel slot. Reporting windows use a monotonic clock; rotate window accounting before recording events at or after a boundary, so activity belongs to exactly one window. Reused tunnel slots reset their reporting marker; window identifiers cannot be reused while a live tunnel can retain them. Saturate counters on overflow and report an overflow flag rather than wrapping. Include window start, end, and duration in summaries; coalesce delayed notifications without catch-up bursts, identifying skipped windows rather than merging them into a purported one-hour report. Formatting and enqueueing remain allocation-free, bounded, and nonblocking. Notifications are best-effort under the existing log-drop policy; reset window counters at boundaries even if enqueueing fails, and count dropped notifications.
- **Bounds and retries:** Enforce the initial resource profile for DNS messages, record counts, CNAME chain length, and outstanding queries. Reject loops and results exceeding capacity rather than retaining an arbitrary truncated subset. Each DNS exchange has a 5-second deadline. Make at most four sequential upstream connection attempts per tunnel, each with a 2-second deadline within the absolute setup deadline. Before each attempt, read the hostname's current A and AAAA entries and ignore any that are empty, retired, or exhausted. If both families remain, use IPv4 for the first attempt and otherwise the family not used by the previous attempt; if one remains, use it. Within a family, use the address at index n, where n is the number of earlier attempts in that family; the family is exhausted when n reaches the entry's current address count. The tunnel stores only these per-family attempt counts, never addresses or cache references, so a replacement between attempts takes effect at the next attempt. Stop when no family remains. Revalidate address eligibility before each attempt. Commit the peer at the first successful TCP connection; retry only failed connection establishment and never replace a connected peer. Cache updates do not change the peer of an established tunnel.

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

The production image is a minimal Linux container holding only the statically linked Alumina binary and its configuration file. It has no shell, package manager, or other executables. Run it as a non-root user with no added capabilities, a read-only root filesystem, no writable or secret volumes, and a runtime identity holding no cloud permissions; Alumina requires no credentials. Changing policy requires deploying a new instance with new configuration.

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
- **Runtime prerequisites:** Production targets a minimal Linux container. At startup, require a non-root UID, empty effective, permitted, and ambient capability sets, and `no_new_privs`; otherwise fail as an unmet local prerequisite. Read configuration once during startup and initialize all application storage before DNS resolution begins. Final shutdown closes sockets and exits without deallocating.

## Initial resource profile

These are fixed build-time limits, not optional TOML settings or measured capacity claims. Limit exhaustion rejects work; it never enlarges storage or relaxes validation.

| Resource | Limit |
| --- | --- |
| Configuration document / allowlist entries | 16 KiB / 1 through 32 |
| Worker threads | 1 |
| Concurrent tunnels, including setup / pending setups | 512 / 128 |
| Traffic buffers per tunnel slot | Two 128 KiB buffers, one per direction |
| Total preallocated tunnel traffic storage | 128 MiB |
| Retained serving workspace (per-slot CONNECT head + two 64 KiB ClientHello inspector buffers + JA4 ClientHello retention) | 512 × ~152.4 KiB ≈ 76 MiB (design estimate) |
| CONNECT headers | 8 KiB |
| Buffered TLS bytes before authorization, including record framing | 64 KiB |
| TLS plaintext record payload during inspection | 16 KiB |
| ClientHello distinct extensions tracked (duplicate rejection) | 64 |
| ClientHello offered supported_versions entries retained | 32 |
| DNS response message / total resource records | 16 KiB / 128 |
| Cached address candidates per configured name | 16 IPv4 and 16 IPv6 |
| CNAME chain length | 8 links; loops rejected |
| DNS TCP connections / outstanding queries | 1 / 1 |
| Resolver set / per-resolver state | 5 / fixed |
| Setup deadline / individual upstream connect deadline | 10 seconds / 2 seconds |
| Upstream connection attempts per tunnel | 4, within the setup deadline |
| DNS exchange deadline | 5 seconds |
| Normal DNS refresh interval, lower / upper | 5 seconds / 900 seconds |
| SOA-based negative DNS refresh interval, lower / upper | 30 seconds / 900 seconds |
| DNS failure retry backoff | 1, 2, 4, 8, 16, then 30 seconds capped |
| Stale DNS retention after TTL expiry | 259200 seconds (72 hours) |
| Stale-serving window (new upstream authorization after TTL expiry) | 3600 seconds (1 hour) |
| DNS incident summary interval | 3600 seconds per affected hostname |
| DNS reporting storage | 32 name/window states, 64 record-type incident states, 512 tunnel window markers |
| Preallocated log queue / maximum encoded entry | 256 entries / 2 KiB, including framing |
| Log sink work per scheduling turn | 64 KiB or 16 I/O operations, whichever comes first |
| Startup resolution window | 90 seconds, absolute; includes DNS TCP establishment |
| Relay idle deadline / EOF drain deadline / shutdown grace period | 300 seconds / 5 seconds / 8 seconds |

Preallocate 512 tunnel slots with two 128 KiB directional buffers each: `512 * 2 * 128 KiB = 128 MiB`. Reuse these buffers across CONNECT parsing, ClientHello inspection, and relay without discarding coalesced tunnel bytes. The separate CONNECT and ClientHello limits still apply; larger relay buffers do not permit larger setup messages. DNS storage, the retained serving workspace (512 × ~152.4 KiB ≈ 76 MiB of per-slot CONNECT head plus two 64 KiB ClientHello inspector buffers plus the JA4 ClientHello retention, per the JA4 client-fingerprint tripwire amendment), connection metadata, stacks, executable memory, and kernel socket buffers are outside this traffic-storage budget and must be accounted for separately when sizing the container.

The first-iteration target is 1-10 Gbps aggregate relayed payload throughput across both directions, subject to CPU speed, workload, and network limits. At these rates, 128 MiB represents approximately 1.07 seconds to 107 milliseconds of aggregate payload, not a throughput guarantee. Storage is partitioned by tunnel and direction and cannot all absorb a burst on one connection; a 128 KiB directional buffer represents approximately 1.05 milliseconds at 1 Gbps or 0.10 milliseconds at 10 Gbps. Use socket backpressure rather than buffer growth. Benchmark sustained relay and bursts separately; application buffer capacity is not a substitute for TCP window sizing or a measured CPU budget.

**Fixed profile (non-negotiable).** The resource-profile rows above, the lifecycle deadlines, and the invariants are fixed and non-negotiable; no amendment loosens them. The following constraints also hold: packet dropping is never implemented; no new dependency is added unless its intake (source review) precedes execution; and no kernel pacing knob is used.

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
- **The Fail-Closed Invariant:** Malformed or unsupported input, ambiguous identity, DNS failure, and resource exhaustion cannot skip authorization checks or enable permissive fallback. The only DNS-failure tolerance is continued use of an existing positive binding within its explicitly bounded stale-serving window; failures cannot renew authorization or revive replaced, evicted, or retired bindings.

### II. Memory & Resource Invariants

- **The Zero-Allocation Invariant:** While serving traffic or refreshing DNS, first-party proxy execution paths must not allocate or deallocate heap storage. Only boot initialization is exempt; shutdown exits without deallocating. Dependency behavior is a bounded seam outside this invariant's first-party scope (see the `alumina-zai` amendment).
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
- **Resource profile:** Verify the 16384-byte configuration boundary, the 128 MiB traffic-buffer allocation, bounded queues and timers, allocation-free operation, deadline enforcement, and preservation of buffered bytes across setup and relay. Use allocator instrumentation and dependency checks to verify that startup DNS resolution, serving, background refresh, logging, and shutdown perform no heap allocation or deallocation after boot initialization. Report process and kernel memory separately from the traffic-buffer budget.
- **Logging:** Verify queue and encoded-entry boundaries, escaped text, whole-record drops and accounting, threshold transitions, and one enqueue attempt per rejection. Verify that the per-name unresolved-name records and the final startup summary result fit the encoded-entry limit for valid configurations, including framing, with each unresolved name emitted exactly once at its full untruncated length and the summary's dropped-name count accounting for per-name records that could not be enqueued. Exercise partial writes, backpressure, and a stalled sink; enforce the sink work budget while tunnel I/O, DNS, and deadlines continue. Formatting and delivery must remain allocation-free.
- **Startup readiness:** Verify a missing allowance fails configuration validation, integer/type/range validation, zero requiring all hostnames to be usable, and every valid allowlist requiring at least one usable hostname. An empty allowlist must fail configuration validation before DNS queries or listener creation. Exercise all-ready early startup, exact-allowance degraded startup at the deadline, allowance-exceeded exit with status 75, configuration failure with status 78, not-yet-attempted names, NXDOMAIN counted against the allowance, eviction before readiness, and independent A/AAAA outcomes. Check responses immediately before, at, and after the 90-second deadline, delayed timer delivery, DNS TCP establishment inside the exchange budget, cancellation and obsolete-work isolation, and no extension from progress or retries. Verify degraded-result diagnostics, serving-mode incident/window handover, `502` for unavailable names, automatic background recovery, and no active reachability probes. Verify that failures across multiple names and record types produce exactly one startup warning enqueue attempt, while preserving independent incident state and latest reasons. Confirm that serving begins without replaying suppressed warnings and that subsequent new incidents receive normal per-type warnings. Runtime loss of a binding must not reapply the startup allowance or enable permissive fallback.
- **Deployment confinement:** Demonstrate successful approved third-party calls through the private proxy endpoint and rejection of unapproved CONNECT hostnames. From the application runtime, verify direct connections to approved and unapproved third-party addresses are denied, including IPv4, IPv6 where available, alternate HTTPS ports, UDP/QUIC, private routes, provider-managed paths, and alternate proxies or relays. Exercise clients that ignore proxy settings, proxy-bypass configuration, and proxy unavailability; none may obtain direct egress. Confirm the workload cannot alter proxy or confinement controls, unauthorized sources cannot reach the listener, and clients retain upstream certificate verification. Repeat these checks when networking, client libraries, or permitted dependencies change; this is deployment verification, not a property Alumina can establish internally.
- **Initial deployment:** Demonstrate TCP DNS resolution and end-to-end CONNECT ingress on the selected Cloud Run worker-pool deployment. Qualify complete direct, CNAME, and negative recursive responses for the intended third-party allowlist against the selected platform resolver, including original CONNECT/SNI preservation. Measure network startup delays against the fixed 90-second DNS budget; verify the chosen allowance and operator-controlled restart policy without automatic timeout extensions. Demonstrate an operator-owned CONNECT plus authenticated TLS check through Alumina for deployment reachability assurance. Compatibility failure requires an explicit deployment or design revision, never automatic protocol or resolver fallback; add bounded follow-up queries only through an explicit revision justified by observed necessary compatibility gaps.
- **Runtime surface and deployment prerequisites:** Verify that startup fails as root, with nonempty effective, permitted, or ambient capability sets, or without `no_new_privs`. Verify that the running process has exactly one listening socket and no other inbound interface. Verify that SIGTERM performs bounded shutdown and that catchable administrative signals cannot reload configuration or change policy. Verify that the image contains only the specified files.
- **Performance:** Measure aggregate forwarded payload bytes once, not once on read and again on write. Benchmark 1-10 Gbps bursts where CPU and network capacity permit, and report burst duration, concurrency, payload sizes, CPU utilization, queueing, and sustained throughput separately. Include slow-peer backpressure and verify DNS and deadline progress under load. These targets and deployment behaviors are unverified until measured.

## Tripwire actions, monitoring, and pacing


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

Additional LOG KIND(s) on the existing stdout sink — and only that sink — report per-domain action events and correlated per-ordinal and global aggregates. They follow the existing bounded, best-effort, allocation-free logging contract: whole-record drop and count on overflow, saturating counters with an overflow flag, and fold-before-close/reuse. The monitor family is split into an always-emitted, authoritative `kind=monitor` summary and best-effort `monitor_domain` / `monitor_capture` detail batches. The summary carries a fixed core — 13 globals, 10 scalars, 19 `c<i>` counters, 4 `unk<i>` counters, and the `dx=` loss bitset — and is enqueued reserved (commit-point) at every report cadence, so the aggregate readiness outcome is always recorded even when every detail batch is dropped. The detail batches are best-effort: `monitor_domain` packs the 32 domain blocks into 3 batches (~11/11/10 blocks) and `monitor_capture` packs the 64 capture details into 3 batches (~22/22/20 details), each batch ≤ 2048 B with `part=<n>/<total>`, emitted only when the underlying data is nonzero. Detail loss never blocks the summary: `report_drops` counts each dropped `monitor_domain` batch once per batch; `capture_drops` counts capture-detail loss with mixed units — once per detail at capture time (a later detection relation on an already-captured connection is suppressed, or a detail is evicted when the 64-detail window is full) and once per batch when a `monitor_capture` batch is dropped at report time (up to 22 details lost in one counted batch) — the per-batch/per-detail unit mixing is intentional and documented; both are saturating counters with overflow flags in the summary's fixed core. Correlated connection detail is captured as the first detection relation per connection (actual slot index + generation + fact/effect together; an effect can never appear without its fact); a later detection relation on the same connection folds into the correlated per-ordinal and global aggregates only, never into the bounded detail, and is counted as correlated-detail loss — there is no full history. An accepted monitoring summary enqueue consumes its bounded detail window, so a later summary never repeats the same relations as fresh; a refused summary retains the bounded detail and counts the refusal as honest loss. A forced final summary refused at shutdown is likewise counted as loss but cannot be observed after the process exits, so a shutdown report is never guaranteed lossless. An early-upstream-data outcome with no effect (operational Unknown) is observable only through that bounded correlated detail, never as a permanent exact aggregate total. No new sink, endpoint, control, or metrics interface is added; a Flare for Block or Tarpit events is implicit and coalesced at the existing report cadence, never one record per packet.

### Planned fixed control storage (design estimate, not measured)

All added enforcement and monitoring storage is boot-time allocated from the existing fixed inventory and performs zero heap allocation or deallocation after boot. The bounding design estimate below is derived from the fixed counts (512 tunnel slots, at most 32 ordinals) and a concrete type/sizeof plan to be verified at implementation; it is not a measured or runtime figure.

| Planned structure | Count | Unit size (bound) | Bound total |
| --- | --- | --- | --- |
| Per-ordinal DomainAction table (`FlareOnly`/`Block` + scope) | 32 | 2 B | 64 B |
| Domain-blocked ordinal bitset + All latch | 32 bits + flag | — | 5 B |
| Per-slot latched tripwire fact (phase, class, validated ordinal, generation) | 512 | 8 B | 4096 B |
| Per-ordinal saturated aggregate counters + overflow + window state | 32 | 32 B | 1024 B |
| Per-slot last-counted window marker | 512 | 8 B | 4096 B |
| First-seen JA4 baseline table (36-byte JA4 per entry; per-ordinal, no per-IP element) | 512 | 36 B | 18432 B (~18 KiB) |
| ClientHello JA4 retention (`[u16; 8192]` ciphers + `[u8; 255]` ALPN + `[u16; 64]` extensions + `[u16; 64]` sigalgs in per-slot `ChInspector`) | 512 | ~16.5 KiB | ~8.2 MiB |

The planned additional enforcement and monitoring control storage (the five non-JA4 rows above) totals approximately 9–10 KiB against the existing 128 MiB traffic storage and 512 KiB log queue. The two JA4 rows (first-seen baseline ~21 KiB and ClientHello retention ~8.2 MiB) are additional and separately accounted in the JA4 client-fingerprint tripwire amendment section. Exact sizes are fixed at implementation with `sizeof`-verified types. No pacing credit/burst storage is reserved or preallocated while Tarpit is deferred (no speculative reserved pacing allocation); it is added to this table only if a genuine trigger-catalog decision authorizes Tarpit. Per-turn enforcement work composes with the existing 16-op/64 KiB per-visit budget and at-most-256-visit timer recheck; the per-turn control-step count is a fixed value derived from that native per-visit I/O budget at implementation, not an invented range. Block All's bounded physical closure is the only path that walks the slot table.

## Security hardening — CONNECT, TLS identity, DNS cache, scheduling, and logging


### L3 — CONNECT bare-CR rejection

Add to the CONNECT **Reject** list (spec §CONNECT request): reject a bare CR — an ASCII `0x0d` not immediately followed by `0x0a` — as a header line ending. Only the CRLF pair (`0x0d 0x0a`) is an accepted line ending within the CONNECT head; a `0x0d` observed without an immediately following `0x0a` is rejected as a malformed line ending. This tightens the existing bare-LF rejection to a strict CRLF-only rule.

### L6 — Startup positive classification uses eligible bindings

The startup readiness/usable classification (spec §Configuration & DNS) and the startup diagnostics state: a positive startup classification requires an eligible, non-retired positive binding for the record type — matching the "usable" predicate at §Configuration & DNS — not merely a non-empty set of bindings. An entry whose bindings are all ineligible or retired does not count as a startup positive and is treated as unresolved for the allowance computation.

### L8 — Reject non-`host_name` `server_name` entries

Per RFC 6066 §3, the `server_name` extension's name list must contain exactly one entry and that entry's `NameType` must be `host_name` (0). Any entry whose `NameType` is not `host_name` (0) is rejected as malformed or ambiguous identity (spec §TLS ClientHello profile) — never silently ignored or skipped by length.

### L9 — Initial TLS record minimum payload

The initial TLS record carrying the ClientHello handshake must have a handshake payload of at least 4 bytes: 1 byte handshake type (`0x01`, ClientHello) plus 3 bytes handshake length. A first record whose handshake payload is fewer than 4 bytes is rejected as malformed framing. This is stricter than the bare maximum payload bound (16 KiB, §TLS ClientHello profile) and is pinned here because the deployed parser already enforces the minimum.

### L10 — SNI trailing-dot normalization

SNI handling must satisfy RFC 6066 `host_name` and resolve trailing-dot normalization consistently with config/CONNECT normalization at §Configuration & DNS: a single trailing dot in the SNI `server_name` is normalized (trailing dot removed) before comparison against the approved CONNECT hostname, and the normalized name is compared case-insensitively. An SNI `host_name` that is empty, an IP literal, or otherwise fails TLS hostname syntax is rejected as invalid identity.

### L11 — Extension/version caps promoted into the resource profile

The code-invented hard caps are promoted to spec resource-profile limits, keeping the numbers identical to the code (`src/client_hello.rs:6,9,12,15`; `src/connect.rs:8`):

| Resource | Limit |
| --- | --- |
| CONNECT headers | 8 KiB |
| Buffered TLS bytes before authorization, including record framing | 64 KiB |
| TLS plaintext record payload during inspection | 16 KiB |
| ClientHello distinct extensions tracked (duplicate rejection) | 64 |
| ClientHello offered supported_versions entries retained | 32 |

The first two rows already exist in the Initial resource profile (§Initial resource profile); the record-payload, extension, and version rows are new to the profile. No existing profile row is loosened or otherwise altered; the caps are pinned exactly as the code enforces them today.

### L12 — DNS TTL cap (deliberate new bound)

Spec §Configuration & DNS is amended to cap the honored DNS TTL at a fixed maximum of **86400 seconds (24 hours)**. The entry freshness deadline uses `min`(earliest supporting CNAME/address TTL, 86400); a TTL of 0 remains treated as 1 second (RFC 1035 deviation preserved). With the fixed 259200-second stale grace (§Configuration & DNS), the maximum authorization lifetime is 86400 + 259200 = **345600 seconds**. This is a new deliberate deviation from "honor the received TTL without raising it": the cap only ever lowers honored TTLs, never raises one, so authorization lifetime is bounded.

### L13 — Binding-address deduplication

Spec §Configuration & DNS are amended to require deduplicating identical addresses (compared as parsed numeric addresses, never textual forms) at staging/publication: a record type's published eligible bindings contain no duplicate addresses. Deduplication precedes publication so the per-family attempt budget (spec §Configuration & DNS) is never wasted on duplicate candidates — within a family, address index `n` always selects a distinct address.

### L16 — Whole-second scheduling granularity

The refresh/backoff scheduling clauses (spec §Configuration & DNS) are amended to specify that all due times, the per-second start-rate guard, and backoff-stage comparisons use whole-second resolution from a single monotonic anchor. Due-time and not-before guards compare at whole-second truncation (documenting the existing code at `src/schedule.rs:381-384`); no sub-second due times or fractions influence scheduling, so refresh/backoff spacing is captured to whole seconds only.

### L17 — Four named parser fuzz targets

The Verification requirement at §IV. Protocol & State Machine Invariants ("parser fuzzing") is sharpened to name the four parser targets that must be driven by a real fuzz loop before serving qualification: (1) ClientHello inspection (`ChInspector::feed`), (2) CONNECT headers (`ConnectParser`), (3) DNS wire (answer/record parsing), and (4) log-record encoding. Scaffold-only harnesses that do not drive the parsers do not satisfy the requirement.

### L18 — Sink-failure drop accounting

Spec §Lifecycle (Log delivery) — and the DNS reporting/log-drop accounting it shares — is amended to specify that records stranded when the sink fails or stalls (queue-accepted records that cannot be drained before the failure) are counted as dropped under the existing whole-record drop accounting, never silently lost. A stalled or failing sink increments the drop count for stranded records; it must not cause them to be retained indefinitely, nor block rejection, tunnel I/O, DNS, or deadlines.

## CONNECT, configuration, and DNS destination-address hardening

The Protocol contract restricts CONNECT to plaintext HTTP/1.1 and declares HTTP/1.0 CONNECT unsupported. Configuration declares an IP literal-shaped allowlist entry — a name whose labels are all-numeric, e.g. `1.2.3.4:443` — invalid configuration. The Addresses clause clarifies that the AS112 anycast `192.31.196.0/24`, AMT `192.52.193.0/24`, and direct-delegation AS112 `192.175.48.0/24` ranges are deliberately not excluded because they are globally routable and can legitimately host internet services.

## CONNECT Content-Length canonical digits

On the CONNECT Accept/Reject surface, a leading-zero `Content-Length` value is invalid and is rejected fail-closed, consistent with the canonical-digit rule already applied to the CONNECT target port. Literal `Content-Length: 0` is the only accepted value; nonzero `Content-Length` is rejected; and a leading-zero spelling of the accepted literal is itself rejected as malformed rather than accepted.

## Memory accounting — retained serving workspace


### Retained serving workspace

The retained serving workspace is a fixed per-slot allocation, made once at boot for the process lifetime and reused across connections, **outside** the 128 MiB tunnel-traffic-storage budget:

| Structure | Count | Unit size | Bound total |
| --- | --- | --- | --- |
| Per-slot CONNECT parser head | 512 | 8 KiB | 4096 KiB |
| Per-slot ClientHello inspector buffers (`buf` + `scratch`) | 512 × 2 | 64 KiB | 65 536 KiB |
| **Retained serving workspace total** | 512 slots | 136 KiB | **68 MiB** |

This is the `SLOT_WORKSPACE_BYTES` / `SERVING_WORKSPACE_BYTES` accounting in `src/inventory.rs:18-21` and the two `[u8; 64 KiB]` buffers (`buf`, `scratch`) in each `ChInspector` at `src/client_hello.rs:251,255`, preallocated for all 512 slots at boot (`src/serving.rs:926-938`). It is included in the boot inventory's named-fixed-buffer lower bound (`BootInventory::named_fixed_buffer_bytes` = 128 MiB traffic + 68 MiB serving workspace + DNS named buffers ≈ 196 MiB), consistent with the observed ~204 MiB VmRSS in `docs/benchmarks/e2micro-workload.md`.

The DNS transport's fixed 512-byte query buffer (`QUERY_BUF_LEN`, `src/startup_dns.rs:37`) is likewise a retained named buffer and is accounted with the DNS named buffers.

This amendment is a **clarification of the existing fixed profile, not a change to any limit**: the serving workspace was already allocated and retained by the code; the prior resource table understated the retained footprint by ~68 MiB. No profile row is loosened or altered.

## Hardening: DNS wrong-family records, ClientHello handshake bound, CONNECT discriminant split


### Wrong-family DNS records, handshake bound, and CONNECT discriminant split

#### Vec 33 — DNS wrong-family records are truly ignored

Spec §Configuration & DNS (DNS provenance) already rejects coexistence of CNAME and A/AAAA records at a chain owner (`CnameCoexist`). This increment hardens the independent wrong-family path: an answer to an A query containing AAAA records at a chain owner — or an AAAA query containing A records — is discarded as wrong-family without setting the owner's has-address-data flag (`src/dns.rs:824-830`, `:847-853`). Wrong-family records therefore never register as address data, cannot satisfy the positive-answer terminal requirement, and cannot corrupt a same-family CNAME chain into a misleading has-data outcome. A chain whose queries yield only wrong-family records terminates in the validated negative outcome `EmptyNoerrorWithoutSoa` — a clean, consistent NODATA-class result — and an NXDOMAIN carrying a wrong-family record at the terminal owner remains a clean `NxDomain`, never `TerminalWithoutData` (tests `ignored_opposite_family_*_then_cname_*` at `src/dns.rs:1847-1893`; `nxdomain_with_opposite_family_*` at `:1937`-`:1969`). The pre-existing reverse-direction artifact — a wrong-family address arriving before a same-family CNAME counting as address data — is eliminated with it; that path now also yields `EmptyNoerrorWithoutSoa`.

#### Vec 34 — ClientHello handshake-message length bound

Spec §TLS ClientHello profile bounds each plaintext record payload to 16 KiB (§Initial resource profile). This increment adds the matching bound on the TLS handshake message length at 16 KiB (`MAX_HANDSHAKE_LEN`, 4-byte header plus body, `src/client_hello.rs:12`). A handshake whose declared length exceeds the bound is rejected as `ChError::HandshakeTooLarge { got }` at the scan gate (`src/client_hello.rs:394-395`) instead of being buffered toward the 64 KiB `MAX_CLIENT_HELLO` inspection total (§Initial resource profile). This is a content-level classification bound, not a buffer change: the retained serving workspace (`SLOT_WORKSPACE_BYTES`, `src/inventory.rs`, resource profile §Initial resource profile) and the two reused 64 KiB inspector buffers are unchanged. The TLS profile fold maps the new cause to the existing `Profile` reject kind (`src/client_hello.rs:198-220`), and a claim exactly at the 16 KiB cap is a complete-at-bound, not a length rejection (`src/client_hello.rs:1115-1128`).

#### Vec 36 — Split CONNECT error discriminants and remove the `NotHttp` catch-all

Spec §CONNECT request govern the CONNECT Accept/Reject surface. This increment replaces the coarse parse-failure classification with exact, finite discriminants: a request line that is not exactly three whitespace-separated tokens is `MalformedRequestLine`; a method other than `CONNECT` is `MethodNotConnect`; an HTTP version other than `HTTP/1.1` is `UnsupportedVersion`; and a target that is not authority-form `host:port` — starting with `/`, `*`, or a `scheme://` prefix (e.g. `windows(3)://`), or lacking a colon — is `TargetNotAuthorityForm` (`src/connect.rs:321-341`, `:384-400`). The coarse `NotHttp` variant is removed from both `ConnectError` and `ConnectHeadReason` (`src/connect.rs:42-56`, `:102-116`); `ConnectHeadReason::COUNT` is now 13 (`src/connect.rs:148`) and `AnyIllegalCause::KIND_COUNT` is 18 (`src/enforcement/policy.rs:21`). The monitoring grammar's fixed kind labels follow (`c13`, `a13`; `src/log.rs:1846`, `:1850`, `:1937`). The eliminated `NotHttp` row is deliberately not re-added: every prior `NotHttp` rejection is now attributable to exactly one of the new discriminants, so the coarser catch-all carried no additional information.

## Hardening: CONNECT header-line count bound, passive resolver degraded signaling, widened refresh band


### CONNECT header-line bound, resolver degraded signaling, and refresh band

#### Vec 35 — CONNECT header-line count bound

Spec §CONNECT request govern the CONNECT Accept/Reject surface. This increment bounds the number of header lines a CONNECT request head may carry at 16 header fields (`MAX_HEADER_LINES`, `src/connect.rs:13`). Every line the header loop yields is counted (`src/connect.rs:267-270`), incrementing before the empty-line continue as defense in depth — the head is truncated at the first CRLFCRLF delimiter, so each header field yields exactly one header-loop line and the empty line never appears in a bounded head. A request whose count exceeds 16 is rejected with the new exact discriminant `ConnectError::TooManyHeaderLines`, mapped to `ConnectHeadReason::TooManyHeaderLines` (`src/connect.rs:61`, `:126`, `:149`). `ConnectHeadReason::COUNT` is now 14 (`src/connect.rs:160`), `AnyIllegalCause::KIND_COUNT` is 19 (`src/enforcement/policy.rs:21`), and the monitoring grammar's fixed kind labels follow (`c14`, `a14`; `src/log.rs:1846`, `:1850`, `:1937`). The bound is a parse-classification bound, not a buffer change: the fixed request-head buffer and its size limits are unchanged, and a head of exactly 16 fields is accepted at the boundary.

#### Vec 19 — Passive resolver degraded signaling

The startup-resolution and refresh clauses (§Configuration & DNS) govern the resolver stub. This increment adds a passive degradation state machine: after three consecutive counted exchange failures the resolver relocates into `Degraded` mode (`DEGRADED_AFTER`, `src/startup_dns.rs:550`; the `ResolverDegradation` state at `:536-546` makes the count-degradation boundary structural — `Healthy` can never hold three consecutive failures), and any subsequently successful publication relocates it back to healthy, restarting the consecutive-failure count from zero (`note_success`). A valid negative response counts as a successful exchange. The state machine emits exactly one enter crossing on relocation into degraded and exactly one exit crossing on recovery — never one per individual failure — accumulated as a drainable transition count (`record_resolver_failure`/`record_resolver_success`, `src/startup_dns.rs:1804-1821`; drained via `take_resolver_transitions`). The shared serving owner drains pending crossings each turn and after the startup window (`drain_resolver_transitions`, `src/serve.rs:381`, `:585`) into enforcement via `Enforcement::note_fact_resolver_degraded()` (`src/enforcement/state.rs`), landing in the saturating `FactCounters::resolver_degraded` (`src/enforcement/monitor.rs`). The monitor grammar folds the counter into `facts_total()`, surfaces it as the zero-suppressed `rd=` key, and counts its overflow into `ofacts` (`src/log.rs`). The fact is edge-triggered, so an operator observing `rd=` sees each degraded-mode transition instead of a per-failure flood, at zero new allocations and zero new log surfaces.

#### Vec 14 — Widened refresh band with a split negative floor

Spec §Configuration & DNS (refresh scheduling) and §Configuration & DNS (negative refresh scheduling), with the profile rows §Initial resource profile, are amended. The normal refresh band widens to `min(900 seconds, max(5 seconds, entry TTL))` (`REFRESH_MIN = 5`, `REFRESH_MAX = 900`, `src/schedule.rs:5`, `:8`; `normal_refresh_interval` clamp `:42-44`). The SOA-based negative refresh band becomes `min(900 seconds, max(30 seconds, min(SOA TTL, SOA.MINIMUM)))` with its own 30-second floor (`NEGATIVE_REFRESH_MIN`, `src/schedule.rs:11`; `negative_refresh_interval` clamp `:50-52`), preserving the established 30-second negative floor while the cap rises to 900 with the normal band. The per-second start-rate guard of §Configuration & DNS is unchanged and is verified to still hold at the 5-second cadence the widened floor makes plausible (test `start_rate_guard_holds_within_a_five_second_refresh_cadence`). The cache-level TTL cap at `src/cache.rs:328` is explicitly unchanged: a received TTL is never raised above its validated value on the way into the cache; the widened scheduling bounds affect only refresh due times.

## Hardening: CNAME bailiwick enforcement, DNS anomaly fact surface, resolver peer assertion


### CNAME bailiwick, DNS anomaly facts, and resolver peer assertion

#### Vec 11 — CNAME bailiwick enforcement

Spec §Configuration & DNS governs the response-provenance rules and the CNAME walk. This increment confines every followed CNAME link to the allowlist bailiwick zones: the resolver derives a deduplicated zone set from the allowlist once per resolve (`BailiwickZones::from_allowlist`, `src/dns.rs:787`), a hostname with more than two labels contributing its parent domain and a two-label apex contributing itself (`zone_of`, `src/dns.rs:821`); `covers` then decides membership on label boundaries via `soa_covers` (`src/dns.rs:811`, `:1175`). The check is placed after the existing CNAME-provenance rules in the followed-link walk (`src/dns.rs:1142`), so the ≤8-link bound, loop detection, and no-conflicting-target rules still apply and bailiwick is the final gate on where a link may land. A target outside every zone fails the exchange with the distinct `DnsError::BailiwickViolation` (`src/dns.rs:247`), never silently routing into an attacker zone. `BailiwickZones` uses the fixed `ALLOWLIST_MAX` `DnsName` slots (`src/dns.rs:769`) with no heap allocation, preserving the fixed profile; the wire-parser fuzz target that holds no allowlist carries its own single-zone set (`BailiwickZones::single`, `src/dns.rs:802`).

#### Vec 32 — CNAME-chain pinning to known-good zones

Spec §Configuration & DNS governs the response-provenance rules and the CNAME walk, and vector 32's "known-good zones" pinning is realized by the same gate as Vec 11: every followed CNAME link is confined to the allowlist bailiwick zones derived above (`BailiwickZones::from_allowlist`, `src/dns.rs:787`; `covers`/`soa_covers`, `:811`/`:1175`), so a chain can never pass through or terminate in an attacker zone. The chain-pinning intent of vector 32 — chaining into attacker zones — is thereby fully covered: a target outside every zone fails the exchange with `DnsError::BailiwickViolation` (`src/dns.rs:247`) rather than being followed. The two vectors differ only in vantage (bailiwick membership vs. pinning to known-good zones) and share one implementation seam; both are promoted out of candidate research together.

#### Vec 21 — DNS anomaly fact surface

The startup-resolution and refresh clauses (§Configuration & DNS) and the `alumina-rp2e` monitoring vocabulary govern the resolver stub and monitor, and vector 21's "detect unexpected TTLs" is realized as one of the anomaly kinds. This increment adds a typed DNS-anomaly surface to the monitor: `DnsAnomalyKind` with the three variants `BailiwickViolation`, `ResolverPeerMismatch`, and `ExtremeTtl` and a structural `COUNT`/`index`/`from_index` (`src/enforcement/monitor.rs:22-47`), carried as `FactCounters::dns_anomaly: [SaturatingCounter; 3]` (`src/enforcement/monitor.rs:14`). The `ExtremeTtl` variant is fed by a per-exchange detection for an answer whose address- or CNAME-carrying resource-record TTL exceeds the threshold `EXTREME_TTL_THRESHOLD = 345_600` (96 h; `src/dns.rs:25`): the flag lives on the reused `ResponseWorkspace` (`extreme_ttl`, `src/dns.rs:712`, `:725`), reset at each parse start (`:857`), set in the answer loop when an A/AAAA/CNAME record's TTL crosses the threshold (`:912`), read back through the `extreme_ttl()` accessor (`:734`), and noted once per affected exchange after a successful publish (`src/startup_dns.rs:1412-1414`). The existing honored-TTL cap at `src/cache.rs:328` is unchanged: a received TTL is never raised on its way into the cache; this increment only observes and counts the extreme value. The transport retains a matching fixed `dns_anomalies: [u32; 3]` (`src/startup_dns.rs:622`), notes each detection saturatingly (`note_dns_anomaly`, `:1022`), and drains it once with `mem::take` so a drain never double-counts (`take_dns_anomalies`, `:1028`). The shared serving owner drains pending anomalies each turn and after the startup window (`drain_dns_anomalies`, `src/serve.rs:383`, `:603`) into enforcement via `Enforcement::note_fact_dns_anomaly()` (`src/enforcement/state.rs`), landing in the saturating monitor counter. The monitor grammar folds the counters into `facts_total()`, counts any overflow into `ofacts` (`src/log.rs:490`), and surfaces them as the zero-suppressed, deterministic-order `bv=`/`rpm=`/`xttl=` keys emitted after the `rd=` block (`src/log.rs:527-541`), at zero new allocations and zero new log surfaces.

#### Vec 22 — Resolver peer assertion

Spec §Configuration & DNS fixes one resolver per tunnel with a single transport peer. This increment adds a passive assertion at the transport: a completed nonblocking connect whose peer is not the configured nameserver fails the exchange with `FailureReason::Connect` and notes a `ResolverPeerMismatch` anomaly (`peer_matches`, `src/startup_dns.rs:1010`; the peer check in `step_connect`, `:1216-1223`). The assertion runs once per completed connect — a warm reused connection passes without re-asserting — and the configured nameserver address is the only accepted peer. Under test the seam can force a mismatch (`force_peer_mismatch`) so the branch is exercised end to end (vec-22).

## Hardening: resolver set moved into the validated TOML config, resolv.conf reader removed, V18 failover


**Failover/failback (Stage 2).** The transport relocates across the configured resolver array under per-resolver passive degradation, with bounded failback to the primary, while the fixed resource profile (1 DNS TCP connection / 1 outstanding query, §Initial resource profile) and the no-fallback trust boundary are preserved: a degraded resolver never causes a connect to an undeclared or unauthenticated endpoint, because the transport relays only among the addresses the validated `resolver` array declares. The peer assertion surface (§Configuration & DNS) is generalized from "the configured primary" to "the currently active resolver".

### Resolver set, config surface, and failover/failback

#### Resolver source and count bound

Spec §Configuration & DNS govern the configuration document and its mandatory keys, and §Configuration & DNS governs resolver selection. This increment adds a required `resolver` key holding an array of 1 through 5 addresses (`MAX_RESOLVERS = 5`, `src/resolver.rs:6`; re-exported as `config::MAX_RESOLVERS`). Each entry must be a numeric unicast IPv4 or IPv6 address with no zone identifier, served on the fixed port 53 (`resolver::select`, `src/resolver.rs:56-76`; `RESOLVER_PORT`, `src/resolver.rs:4`). The validated set is a fixed `[Nameserver; MAX_RESOLVERS]` array plus a length so empty and over-capacity inputs are unrepresentable at the config boundary (`ResolverSet`, `src/resolver.rs:89-131`; sole constructor `ResolverSet::from_slice` refuses zero or > 5 entries, `:99-110`); `primary()` (index 0) is structural and infallible. The platform resolver file — `read_resolver_config_file`/`parse_resolver_config` and the `Scalar`-style line scanner — no longer exists; no OS resolver file is read. The resolver endpoint remains fixed for the process lifetime; ignore search suffixes and tuning options as before.

#### Config validation surface and error precedence

`resolver` is now a mandatory configuration key: a document with every other key present but no `resolver` fails with `MissingField("resolver")`. Count outside 1..=5 maps to the new `ConfigError::ResolverCountOutOfRange { got }` (`src/config.rs:482`), and an invalid address to the new `ConfigError::InvalidResolver { index, value }` (`:486`, 1-based index in its diagnostic), both exiting 78 (EX_CONFIG) like every other configuration error (§Configuration & DNS). The resolver is built last in `from_table` (`build_resolver_set`, `src/config.rs:699`), after enforcement/allowlist/listen/allowance validation, so every pre-existing invalid-config error keeps its established precedence and no error fixture changes; only previously-valid documents must now carry `resolver`.

#### Boot, image, and read-once surfaces

`run_boot(config_path)` takes a single argument; `BootReport.nameserver` is removed and the primary resolver is read from the validated config (`report.config.resolver_set().primary()`, `src/boot.rs`; `src/main.rs` prints and consumes it from the config, no `RESOLVER_PATH`). The startup order clause §Configuration & DNS ("configuration and resolver reads") is satisfied by one config read carrying both allowlist and resolver set. The image clause §Typical deployment pattern ("its configuration file, and the platform resolver configuration") becomes: the production image holds the statically linked binary and its configuration file (validated allowlist + resolver set) and nothing else. The read-once clause §Architecture is met by reading `config.toml` once; no resolver-specific file read remains.

#### 4 KiB document preflight (measured, not assumed)

The "A compact configuration with 32 entries of 100 ASCII bytes each" bound at §Configuration & DNS was re-measured with the new key using the parser-real assertions in `src/config.rs`. The tightest 32 × 100-byte compact form (`[any_illegal]` + `[actions]`, `full_group_document`) previously measured 4061 B; adding the mandatory one-entry `resolver = ["1.1.1.1"]` (23 B including newline) yields **4084 B**, which fits the 4096 B limit — asserted in `compact_32_hundred_byte_names_measured_total_is_4084` (`src/config.rs:1204-1211`). Honest bounds with the 5-resolver maximum: a 2-entry resolver (4095 B) still fits; a 3-, 4-, or 5-entry resolver (4106/4117/4128 B) with 32 × 100-byte names **exceeds** the documented limit and is not configurable in that tightest form — the max-count 5-entry form needs shorter allowlist names. No cap expansion is made: the 4096 B document limit is unchanged, and the 5-resolver maximum trades full name-length headroom against the new surface — names short enough to leave sufficient headroom can still declare all five resolvers. The 4 KiB fit preflight therefore **passes** for the compact one-entry form this stage ships.

#### Multi-resolver failover and failback (Vec 18)

Spec §Configuration & DNS (peer assertion) and §Initial resource profile (DNS TCP transport resource row) govern this stage's incremental surface; no other clause changes. The transport owns a per-resolver `ResolverDegradation` and an `ActiveResolver` index that travels with the configured set length, so an out-of-range active index is unrepresentable (`ActiveResolver`, `src/startup_dns.rs:588-615`; `degradations: [ResolverDegradation; MAX_RESOLVERS]`, `:669`). The set is installed from the validated config at window begin (`begin_window`, `:805`; `resolve_window`, `:1649`), and the pre-window state is a guarded single-resolver (`resolvers: None`) so boot and loopback injection behave identically to the Stage-1 single-resolver surface.

- **Degradation (V19, `DEGRADED_AFTER = 3`, `src/startup_dns.rs:552`).** Every counted exchange failure advances the *active* resolver's consecutive-failure state; the third consecutive failure relocates it into passive degraded mode and emits one `rd` enter crossing for the monitor. A validated published outcome resets the active resolver to healthy and emits one exit crossing when it was degraded (`on_exchange_succeeded`); a success on a degraded resolver recovers that resolver in place.
- **Failover (`on_exchange_failed`, `src/startup_dns.rs:2012`).** Once the active resolver is degraded, the next counted failure relocates the transport to the next healthy resolver in the set, scanning forward with wrap and skipping degraded candidates (`next_healthy_after_active`), closing and re-pointing the single DNS TCP connection on relocation so the next exchange dials the new active resolver. When every configured resolver is degraded the transport stays on the last active resolver and fails closed; it never dials outside the declared set.
- **Failback (`FAILBACK_AFTER = 900 s`, `src/startup_dns.rs:558`).** Relocation to a non-primary arms a 900-second `now0`-scale grace; the next exchange after it elapses probes the primary again (`maybe_begin_failback`, called at the top of `start_exchange`, `src/startup_dns.rs:1792`). A successful probe settles it: the primary is recovered as the active resolver with its degradation reset, and no probe remains armed. A failed probe increments the primary's consecutive-failure count (the third re-degrades it), re-seats the transport onto the backup it came from, and re-arms the grace — never cascading a probe failure into a second failover candidate search while the primary is being probed. A success on a non-primary leaves the grace armed, so the primary is still probed at the next due exchange.
- **Peer assertion (`peer_matches`, `src/startup_dns.rs:1090`).** The §Configuration & DNS resolver-peer assertion now validates against the active resolver's address only, so a failover/failback re-point never trips the `ResolverPeerMismatch` anomaly on a correctly relocated connect, and a stray connect to a resolver the transport is not currently on still fails closed with `ResolverPeerMismatch`.
- **Transport profile (§Initial resource profile).** The failover/failback machine moves an existing 1-conn/1-query transport between configured addresses; it never opens a second connection, so the "DNS TCP connections / outstanding queries | 1 / 1" row is unchanged. Failover tests are pure state-machine tests (`src/startup_dns/tests.rs`) because `Nameserver` fixes the port at 53, so a loopback failover test would dial a real host; the existing single-resolver loopback suite remains valid and unchanged.

## Hardening: resolver endpoint as IP+FQDN (V37, Package 1 of the DoT chain)


### Resolver FQDN metadata (IP#fqdn)

#### V37 — Resolver FQDN metadata (`IP#fqdn`)

Spec §Configuration & DNS govern the configuration document and resolver selection, and the `alumina-hrdn4` amendment owns the validated `resolver` array. This increment extends each resolver entry with an optional validated name identity without changing the array's shape, its 1..=5 count bound, or its address validation: an entry may be `IP#fqdn` instead of a bare IP, with the IP half validated exactly as before (numeric unicast IPv4/IPv6, no zone identifier, fixed port 53) and the FQDN half validated as a DNS name.

- **FQDN validation (`Fqdn`, `src/resolver.rs:22`).** Each label is 1–63 bytes of lowercase ASCII letters, digits, and hyphens, with no leading or trailing hyphen, and the total is at most `FQDN_MAX_LEN = 253` (`src/resolver.rs:10`). A wildcard `*` anywhere maps to `WildcardFqdn`; non-ASCII/IDN characters map to `IdnFqdn`; uppercase or otherwise non-DNS characters, and leading/trailing/empty labels (a leading or trailing dot), map to `InvalidFqdn` — the three new `ResolverError` discriminants live at `src/resolver.rs:125-127` (Display `:151-163`). Digit-leading labels are allowed (RFC 1123), matching the allowlist `config::Fqdn` label rule at `src/config.rs:35`. The validated name is stored inline as `[u8; FQDN_MAX_LEN]` with a `len: u8`, so `Nameserver` (`src/resolver.rs:88`) and `ResolverSet` remain `Copy` and the fixed zero-alloc profile is preserved.
- **Entry parse (`select`, `src/resolver.rs:180`).** `select()` splits a token once on `#`: the IP half is validated exactly as before, and the FQDN half, when present, is validated as above. A bare IP yields `fqdn: None` (`is_ip_only()`, `src/resolver.rs:113`) and remains fully valid — IP-only is the tolerated degraded-trust form. A trailing `#pin-sha256=`-style suffix is rejected as `InvalidFqdn` through the non-DNS-characters rule.
- **Carriage and accessors.** `Nameserver` and `ResolverSet` stay `Copy`; `build_resolver_set` (`src/config.rs:699`) is structurally unchanged — the `fqdn` field rides the existing validated surface. The additions are `fqdn()` (`src/resolver.rs:104`), `is_ip_only()` (`:113`), and `ResolverSet::iter()` (`src/resolver.rs:291`) for the boot scan. `src/startup_dns.rs` carries the copied set unchanged this package: the §Configuration & DNS resolver-peer assertion remains address-based (the DoT handshake on port 853 is implemented by the DoT transport section below), and both the single-resolver and failover/failback surfaces are otherwise untouched.
- **Startup warning.** Every IP-only resolver entry emits one stdout startup warning — `BootReport::ip_only_resolvers()` (`src/boot.rs:46`) printed from `src/main.rs:51-53` — so a degraded-trust bare-IP deployment is operator-visible immediately.
- **Config diagnostics.** `ConfigError::InvalidResolver`'s diagnostic text now names the `IP#fqdn` form; a malformed FQDN fails the same discriminant with the established exit 78 (EX_CONFIG) and precedence (`build_resolver_set` runs last in `from_table`, so earlier invalid-config errors keep their order).

#### 4 KiB document preflight (re-measured, V37 form)

The 4 KiB document bound at §Configuration & DNS was re-measured for the V37 golden path with parser-real assertions in `src/config.rs`. The golden-path example shape — a 3-entry allowlist and a 5-resolver `IP#fqdn` array — serializes to **437 B**, pinned by `resolver_ip_fqdn_example_fits_4kib` (`src/config.rs:1415`, asserts `len == 437` and `<= 4096` and that it parses). The honest-bounds language of the `alumina-hrdn4` clause still holds in the tightest 32 × 100-byte compact form (`full_group_document`): the bare-IP one-entry form remains 4084 B, and a single realistic `IP#fqdn` entry (18-character `cloudflare-dns.com`) measures **4103 B** — over the limit — pinned by `compact_32_hundred_byte_names_with_ip_fqdn_resolver_measured_total_is_4103` (`src/config.rs:1216`). A one-entry `IP#fqdn` with an FQDN of 11 characters or fewer still fits (e.g. `dns.google`, 10 characters, keeps 4095 B). So, as the hrdn4 clause documented, the max-count/max-name compact form trades name-length headroom against this surface and needs shorter allowlist names (or shorter FQDNs) to hold `IP#fqdn` entries; no cap expansion is made.

## DoT transport (V1) and strict SPKI pinning (V5), Package 2 of the DoT chain


### DoT transport and SPKI pinning

#### Directory — three resolver trust forms, per-entry dial port

Spec §Configuration & DNS and the hrdn4/V37 amendments own the validated `resolver` array. Package 2 gives each 1..=5 entry one of three dial forms selected at startup by entry grammar (never mixed mid-flight, never silently downgraded):

| Resolver entry | Dial | Trust on the handshake |
| --- | --- | --- |
| `IP` | plain DNS, port 53 | none (tolerated degraded trust; one startup warning each) |
| `IP#fqdn` | DoT, port 853 | CA-chain validation (empty root store — see the caveat below) |
| `IP#fqdn#pin-sha256=<b64>` | DoT, port 853 | strict SPKI pin equality **and** FQDN/SAN validation |

`Nameserver::port()` (`src/resolver.rs:202`) returns 853 whenever the entry carries an FQDN and 53 for a bare-IP entry; the per-entry port drives the dial address the transport registers (`src/startup_dns.rs:2446`). A DoT entry that fails its handshake is settled as one counted connect failure — there is **no** silent plain-DNS fallback and a TLS identity failure never downgrades the connection to cleartext. The startup window, retry schedule, failover/failback, and 1-conn/1-query doctrine are unchanged.

#### Pin grammar and carrier (`#pin-sha256=`)

`SpiPin` (`src/resolver.rs:103`) carries the 32 raw digest bytes inline so `Nameserver`/`ResolverSet` stay `Copy` with no heap. The suffix `#pin-sha256=` (`PIN_SHA256_SUFFIX`, `src/resolver.rs:15`) is a sub-suffix of the `#fqdn` rest, so the single `#` IP/rest boundary splits exactly once and the two suffixes compose. `decode_b64_32` (`src/resolver.rs:155`) accepts exactly 43 unpadded base64 characters, or 43 data characters plus one `=` pad, in either the standard or URL-safe alphabet, with non-zero leftover bits rejected; `config.rs` gates a pin on a DoT port-853 entry (`InvalidResolver` diagnostics) and `parse` maps any decode failure to `PinError::Invalid`.

#### Verifier — strict pin + FQDN/SAN, or empty-root CA-chain

`AluminaServerCertVerifier` (`src/startup_dns.rs:702`) implements `ServerCertVerifier` over the ring provider's supported algorithms. The pinned branch: `ParsedCertificate::try_from` the end entity, then `verify_server_name` against the resolver FQDN as SNI/SAN, then ring SHA-256 of `subject_public_key_info()` compared to `SpiPin::as_bytes()` — a mismatch returns `InvalidCertificate(ApplicationVerificationFailure)`, and the pin branch **skips** CA-chain validation (TOFU-grade strictness, V5). The unpinned `IP#fqdn` branch validates the chain with `verify_server_cert_signed_by_trust_anchor` against `RootCertStore::empty()` (`src/startup_dns.rs:728-734`): with no trust anchors configured, chain validation deterministically fails (`UnknownIssuer`) for a self-signed or CA-untethered certificate, so an unpinned DoT entry fails closed and counts a connect failure.

> **Caveat — empty root store.** No webpki-roots (or other) trust-anchor bundle is carried: `IP#fqdn` entries are validated against an **empty** root store and therefore cannot succeed against a publicly-trusted resolver until a trust-anchor intake lands. This is a deliberate chain-transition state, not a bypass: the entry fails closed and is operator-visible. A follow-up crate intake (`rust-dep-intake`) is required before unpinned DoT is operationally useful for public resolvers; strict-pinned entries are usable immediately because they need no CA chain.

#### Transport confinement and lifecycle

TLS state and its heap allocations are confined to the per-connect DoT setup seam `build_tls_connection` (`src/startup_dns.rs:766`, called from `upgrade_to_tls` `src/startup_dns.rs:1546`): the rustls `ClientConnection` lives in a `Box` inside the connected transport (`DnsConn::Tls`), so the fixed `StartupDns` struct and every non-DoT struct stay compact, and the bare-IP path constructs no TLS state at all. Warm reuse of one established TLS connection across the startup window's exchanges is retained; a handshake or identity failure never reuses a poisoned connection and each failed exchange is counted individually. There is no dynamic pin update at runtime — the pin is fixed at startup.

#### Verification

Hermetic loopback tests (`src/startup_dns/dot_tests.rs`) drive a rustls `ServerConnection` responder over 127.0.0.1 with deterministic embedded certificates (self-signed EC P-256, CN/SAN `dot.test`, plus a same-SPKI SAN-mismatch variant) — no real resolver is dialed. They cover: pinned success for both names × A/AAAA over one warm connection; the handshake-before-send-before-receive stage order; wrong-pin rejection; SAN-mismatch rejection; and unpinned-vs-empty-root rejection — each negative path counts 4 failed exchanges, publishes nothing, and leaves zero bindings. `dot_tests` is wired into the native verification gate (`scripts/verify.sh` INTENDED set; `mid`/`boundary phase1` clippy and the full lib test suite).

## Hardening: serving-from-stale observability level bit


### Serving-from-stale level bit

The `alumina-rp2e` monitoring vocabulary governs the enforcement monitor record. This increment adds a single latched level bit: `Monitor::serving_stale` (`src/enforcement/monitor.rs`), set by `note_serving_stale` (set + dirty) and cleared by `note_serving_fresh` (clear, deliberately no dirty to avoid log-volume regression), with the `serving_stale()` accessor. The shared serving owner notes the bit at peer admission (`note_peer_freshness`, `src/serving.rs`) from the cache entry state that granted the peer (Stale → set, Fresh → clear, Empty/Retired → no-op), before the slot borrow. The monitor grammar emits the zero-suppressed `ss=` key after the `rd=` block and before the `bv=` block (`src/log.rs`), only when latched (never `ss=0`), at +5 bytes when set; the all-saturated record with `ss=1` stays inside the 8192-byte slot. The bit is observability-only: serving behavior is byte-identical, with zero new allocations, zero new log surfaces, and no runtime-surface expansion.

## Hardening: failback consecutive-success hysteresis


### Failback consecutive-success settle

The `alumina-hrdn4` failback clause governs the bounded failback probe of the primary resolver. This increment adds a consecutive-success counter: `StartupDns::failback_successes` (`src/startup_dns.rs`), reset to zero when a failback probe begins (`maybe_begin_failback`) and when a probe fails (re-seating onto the backup and re-arming the 900-second grace). A successful probe increments the counter; only the third consecutive successful primary probe settles the failback — clearing the probe source and grace — so a transient primary is not re-adopted on a single success. A success on a non-primary backup leaves the counter and grace untouched. The counter is state-machine-local: zero new allocations, zero new log keys, no runtime-surface expansion, and the fixed 1-conn/1-query transport profile is unchanged.

## DoT transport: serving-lifetime warm reuse


### Serving-lifetime warm reuse

The `alumina-dot-chain-v1-v5` warm-reuse clause (§Transport confinement and lifecycle) retained one established TLS connection across the startup window's exchanges. This increment extends that retention to the serving lifetime: the DoT connection established during the startup window is retained (idle) across serving refreshes and reused for subsequent DNS exchanges — no rebuild, no fresh handshake, and no re-allocation of TLS state on refresh. The prior window-end close is removed: the transport is no longer torn down when the startup window settles.

The retention mechanism is the shared registration's `armed` interest: it clears to `None` while the exchange is idle (`sync_shared`, `src/startup_dns.rs:1345`), so the owner's poll never waits on the retained socket (no spin), while the connection itself stays owned in the transport (`self.conn`). The owner re-aligns the shared registration every serving turn (`sync_dns_shared`, `src/runtime.rs:265`) and once at window end (`src/serving/startup.rs:206`); `start_exchange` (`src/startup_dns.rs`) reuses the retained connection when one is present, and `attach_shared` (`src/startup_dns.rs:1319`) accepts a retained connection (a no-op when the registration is already shared). TLS state and its heap allocations remain confined to the per-connect DoT setup seam `build_tls_connection` (`src/startup_dns.rs:766`) exactly as before.

The close-on-failure, close-on-relocation, and close-on-shutdown lifecycle is unchanged: a handshake or identity failure never reuses a poisoned connection and each failed exchange is counted individually; failover relocation and the failback re-seat close the connection before repointing (`maybe_begin_failback`, `src/startup_dns.rs`); and owner shutdown closes via `cancel_for_shutdown` (`src/startup_dns.rs:1127`), with the retained transport and its heap staying owned until process exit. Only idle retention is added; every close path that existed before remains.

A guard test proves the increment: `serving_refresh_retains_dot_transport_without_rebuild` (`src/startup_dns/dot_tests.rs:574`) drives a serving refresh over the retained DoT connection and asserts no transport rebuild occurs.

## Observability: DoT→plain downgrade counter


### DoT→plain downgrade counter

The `alumina-rp2e` monitoring vocabulary governs the enforcement monitor record. This increment adds a single event counter: `StartupDns::downgrade_to_plain` (`src/startup_dns.rs`), incremented by the state-machine-local `note_downgrade_if_dot_to_plain` helper at both relocation choke points of `on_exchange_failed` — the failover relocation (degraded active → next healthy) and the failback re-seat (failed probe → `failback_source` backup) — exactly when the departed active resolver carried an `IP#fqdn` FQDN (port 853) and the relocated-to resolver is a bare-IP entry (port 53). A relocation that keeps or gains an FQDN is not a downgrade and is not counted. The counter is drained by the serving storage (`drain_downgrade_to_plain`, `src/serve.rs`) into `Enforcement::note_fact_downgrade_to_plain()` and the monitor's saturating `FactCounters::downgrade_to_plain` (`src/enforcement/monitor.rs`), folded into `facts_total()`. The monitor grammar emits the zero-suppressed `dp=` key after the `ss=` block and before the `bv=` block (`src/log.rs`), only when nonzero (never `dp=0`), and counts its overflow into `ofacts`. The counter is observability-only: serving behavior is byte-identical, with zero new allocations, zero new log surfaces, and no runtime-surface expansion.

## Zero-Allocation Invariant: first-party scope, rustls bounded seam


### Zero-Allocation Invariant scope

The Zero-Allocation Invariant (§II. Memory & Resource Invariants) previously read "proxy execution paths, including dependencies, must not allocate or deallocate heap storage." This increment narrows the invariant's binding scope to **first-party proxy execution paths**: first-party serving and DNS-refresh code must not allocate or deallocate heap storage, with boot initialization exempt and shutdown exiting without deallocating. Dependency behavior is a bounded seam outside the invariant's first-party scope.

The pinned rustls 0.23.46 dependency (`Cargo.toml:201`, `=0.23.46`, `default-features=false` with ring/std/tls12/logging) performs bounded per-record heap allocations on the warm DoT path once the handshake completes: inbound, each app-data message is copied into a fresh heap `Vec` (`Payload::into_vec` → `bytes.to_vec()`); outbound, each record is built into a fresh `Vec` (`PrefixedPayload::with_capacity` + `m.encode()`). These allocations are bounded per record at ≤~16-18 KiB, occur only over an established DoT connection, and are confined to the dependency — the documented seam this amendment records, not a first-party allocation. First-party DoT setup allocates only at the documented per-connect setup seam `build_tls_connection` (`alumina-dot-chain-v1-v5`, §Verifier — strict pin + FQDN/SAN, or empty-root CA-chain), which is the authorized first-party allocation point: each fresh DoT dial builds its TLS state there (rustls `Arc`s for the provider, verifier, and config, the SNI `String`, and the `Box`ed `ClientConnection`), confined to that seam. Retained-transport serving refresh allocates nothing — the established connection is reused warm across serving refreshes (`alumina-dotrt`, §DoT transport: serving-lifetime warm reuse), with no rebuild.

## Hardening: post-window per-resolver probe sweep + `resolver_probe` verdict log


### Post-window probe sweep

#### Post-decision timing

The startup deadline clause (§Configuration & DNS) governs the 90-second absolute window and its "cannot be extended or supplemented by a network-readiness phase" rule. This increment adds a **post-decision** probe sweep that runs after the startup decision (`settle_startup`, `src/serve.rs`), whether the listener opened or the process exited 75 (on exit-75 the process terminates, so the sweep is moot there). The sweep is not a readiness phase, never extends or supplements the window, never delays listener opening, and does not change the readiness evaluation at §Configuration & DNS. It is bounded, scheduled work folded into the same cooperative poll pattern as the startup window, subject to the existing round-robin scheduling and at-most-one-query-per-second guard (§Configuration & DNS) so it cannot starve background refresh.

#### Post-window probe record and verdict vocabulary

The startup diagnostics clause (§Configuration & DNS) governs startup warning and final-result records. This increment adds a separate `resolver_probe` record (`Kind::ResolverProbe`, `src/log.rs`), emitted **once** after the sweep completes — separate from `startup_final` because that record is emitted at the readiness decision, before the post-window probe verdicts exist. The record carries one inline segment per resolver: index, address (with FQDN/pin presence), verdict (`ok` / `failed` / `not_probed`), and the failure reason when failed. It is encoded through the same allocation-free, bounded `encode_record_final` path into a fixed 8 KiB slot; on overflow the whole record is dropped and counted, like every other record.

#### Sweep semantics (probe state machine)

The probe sweep probes each unprobed resolver exactly once, relocating the existing single DNS TCP connection sequentially — never opening a second connection, so the "DNS TCP connections / outstanding queries | 1 / 1" row (§Initial resource profile) is unchanged. The probe target is the primary allowlisted name (ordinal 0), A family, an already-approved query target (§Configuration & DNS), with the standard 5-second exchange deadline (§Configuration & DNS).

- **State.** `StartupDns::probe_sweep: Option<ProbeSweep>` (`src/startup_dns.rs`) with `ProbeSweep { remaining: [bool; MAX_RESOLVERS], active_before: ActiveResolver, verdicts: [ProbeVerdict; MAX_RESOLVERS], current: Option<usize> }`; `ProbeVerdict` is `Ok | Failed(FailureReason) | NotProbed`. All fixed-size, no heap.
- **Trigger.** The sweep begins after the startup decision only when `probe_sweep.is_none() && failback_source.is_none() && resolvers.is_some() && set_len() > 1`; a single-resolver set (`set_len() == 1`) short-circuits — nothing to probe. The active resolver is already exercised by the window and is skipped, receiving verdict `not_probed` in the record.
- **Probe.** For each unprobed index: relocate temporarily (`close_connection` + `active_resolver = probe_target` + `repoint_to_active`, `src/startup_dns.rs`), keeping the dial target and `active_resolver` in sync so the §Configuration & DNS resolver-peer assertion is preserved; run one exchange; then settle and restore `active_resolver = active_before` + `repoint_to_active`. A DoT→plain probe relocation records the existing `dp=` downgrade counter (`note_downgrade_if_dot_to_plain`).
- **Probe-mode branches.** While a sweep probe is in flight, `on_exchange_failed` (`src/startup_dns.rs`) advances the **probed** resolver's consecutive-failure degradation (the third consecutive failure emits the existing edge-triggered `rd=` enter fact at `DEGRADED_AFTER = 3`) but **suppresses the relocation branch and failback arming**, restoring `active_before` instead — the active transport is healthy and must not move. `on_exchange_succeeded` resets the probed resolver to healthy and restores `active_before`. Zero new enforcement surface.
- **Mutual exclusion with failback.** The sweep runs only when `failback_source.is_none()`; a sweep probe never arms or consumes the failback grace, and a sweep probe relocating to a non-primary is never hijacked into a failback probe.
- **DoT fail-closed.** An unpinned `IP#fqdn` entry fails its handshake deterministically against the empty root store (`src/startup_dns.rs`); its probe verdict is `failed` with the handshake reason — the honest, operator-visible answer. No silent plain-DNS fallback (V5 doctrine).
- **Shutdown.** The sweep aborts cleanly on shutdown; partial verdicts are dropped (bounded, best-effort, same as all logging).

## DNS exchange deadline raised to 5 seconds


### DNS exchange deadline and profile table

#### DNS exchange deadline

The bounds-and-retries clause (§Configuration & DNS) governs DNS exchange bounds and retries. This amendment changes the single sentence "Each DNS exchange has a 2-second deadline" to "Each DNS exchange has a 5-second deadline". The deadline is the single constant `EXCHANGE_DEADLINE_SECS` (`src/startup_dns.rs`), shared by the startup window exchanges and the serving-time refresh path; raising it to 5 seconds applies uniformly. The startup budget invariant still holds: `MAX_RESOLVERS (5) × DEGRADED_AFTER (3) × EXCHANGE_DEADLINE_SECS (5) = 75 ≤ STARTUP_WINDOW_SECS (90)`, so the 90-second startup window (§Configuration & DNS) is unchanged and never exceeded.

#### Profile table

The resource-profile table row "DNS exchange deadline | 2 seconds" (§Initial resource profile) is amended to "DNS exchange deadline | 5 seconds".

## JA4 client-fingerprint tripwire


### JA4 format clause

The tripwire computes the canonical FoxIO JA4 client fingerprint as the fixed 36-character string:

```
{t/q/d}{ver}{sni d/i}{cipher_count:02}{ext_count:02}{alpn_first_last}_{hash12(ciphers_sorted)}_{hash12(exts_sorted_excl_SNI/ALPN + "_" + sigalgs_unsorted)}
```

- `t/q/d`: transport — `t` TLS, `q` QUIC, `d` DTLS.
- `ver`: the HIGHEST value in the `supported_versions` extension (`0x002b`) if present, ignoring GREASE values; else the Protocol Version. The `legacy_version` (handshake version) is ignored.
- `sni d/i`: `d` if the SNI extension (`0x0000`) is present, `i` if it is absent (presence-based per the canonical rule: a present SNI — even an IP-literal one — yields `d`; only an absent SNI yields `i`). In Alumina's context (§TLS ClientHello profile requires exactly one SNI for accepted connections and the config rejects IP-literal allowlist entries), the common case is present → `d`; rejected or malformed initial ClientHellos with no SNI must yield `i`.
- `cipher_count:02`: two-digit count of offered cipher suites, including SCSV `0x00ff` and `0x5600` and experimental/reserved `0xFE00`-`0xFEFF`, after GREASE filtering.
- `ext_count:02`: two-digit count of extension types, after GREASE filtering.
- `alpn_first_last`: the first and last ASCII alphanumeric characters of the first ALPN value, per the verbatim rule below.
- `hash12(ciphers_sorted)`: the first 12 hex characters of the SHA-256 of the GREASE-filtered, sorted cipher-suite list.
- `hash12(exts_sorted_excl_SNI/ALPN + "_" + sigalgs_unsorted)`: the first 12 hex characters of the SHA-256 of the GREASE-filtered, sorted extension-type list excluding SNI (`0`) and ALPN (`16`), concatenated with `_` and the unsorted signature-algorithms (`13`) list.

**ALPN hex-fallback rule (verbatim from the FoxIO spec, evidence `alumina-jze0p`):**

> "The first and last ASCII alphanumeric characters of the ALPN (Application-Layer Protocol Negotiation) first value."
>
> "If there is no ALPN extension, no ALPN values, or the first ALPN value is empty, then we print "00" as the value in the fingerprint. If the first ALPN value is only a single character, then that character is treated as both the first and last character."
>
> "If the first or last byte of the first ALPN is not an ASCII alphanumeric character (meaning not `0x30-0x39`, `0x41-0x5A`, or `0x61-0x7A`), then we print the first and last characters of the hex representation of the first ALPN instead."

The spec mandates the hex-fallback; the FoxIO reference implementations (`python/ja4.py` and `rust/ja4`) instead keep ASCII bytes as-is and substitute `'9'` for non-ASCII bytes, and do not implement the hex-fallback. **Alumina follows the spec** (user-confirmed 2026-10-22): a first or last ALPN byte outside `0x30-0x39`, `0x41-0x5A`, or `0x61-0x7A` triggers the hex-fallback.

### Reconciliation with the cipher/ALPN policy ban

Spec §TLS ClientHello profile ("do not introduce cipher-suite or ALPN policy") is unchanged. The JA4 tripwire OBSERVES and RETAINS cipher-suite, extension, and ALPN data from the initial ClientHello for fingerprinting only: it introduces NO cipher-suite or ALPN policy, makes no acceptance/rejection decision on them, and exerts no negotiation influence. The retained data is never used to admit, reject, or modify a connection.

### Reconciliation with the inspection scope

Spec §TLS ClientHello profile is unchanged. JA4 computes the fingerprint from the INITIAL ClientHello only, matching the existing inspection-scope clause; later handshake messages (including a second ClientHello following a HelloRetryRequest) and encrypted application traffic remain opaque and are never fingerprinted.

### Fixed storage

#### Control-storage table

The "Planned fixed control storage" table gains two rows:

| Planned structure | Count | Unit size (bound) | Bound total |
| --- | --- | --- | --- |
| First-seen JA4 baseline table (36-char JA4 + 1-char present flag + 4-byte IP) | 512 | ~41 B | ~21 KiB |
| ClientHello JA4 retention (`[u16; 8192]` ciphers + `[u8; 255]` ALPN + `[u16; 64]` extensions + `[u16; 64]` sigalgs in per-slot `ChInspector`) | 512 | ~16.5 KiB | ~8.2 MiB |

The first-seen JA4 baseline table holds 512 fixed entries (32 ordinals × 16 addresses = `MAX_ADDRESSES`), each storing the full 36-character JA4 string plus a 1-character present flag plus the 4-byte IP address: ~41 B/entry × 512 ≈ 21 KiB total (design estimate ~21-27 KiB). The ClientHello JA4 retention is the fixed per-slot storage retained in `ClientHello` inside each `ChInspector` by the parser-retention increment: `[u16; 8192]` (16 KiB) + `[u8; 255]` (255 B) + `[u16; 64]` (128 B) + `[u16; 64]` sigalgs (128 B) = 16,895 B ≈ 16.5 KiB/slot; 512 × 16,895 B ≈ 8.2 MiB. Both figures are design estimates, not measured, consistent with the table header; exact sizes are fixed at implementation with `sizeof`-verified types.

#### Retained serving workspace reconciliation

The retained serving workspace figure is reconciled to account for the new ~16.5 KiB/slot ClientHello JA4 retention (linus review Info I1): 512 × (136 KiB + ~16.5 KiB) ≈ 512 × ~152.5 KiB ≈ 76 MiB (design estimate), replacing the previous 512 × 136 KiB = 68 MiB at §Initial resource profile (the 68 MiB figure recorded in the `alumina-mema` amendment describes that amendment's surface and is superseded for the live profile by this reconciled figure). The added retention is boot-time fixed storage with zero heap allocation or deallocation after boot, consistent with the fixed profile.

## C1 JA4 change-signal value


### JA4 change-signal value

The per-ordinal JA4 change signal (JA4 amendment, the `d<j>j` counter) gains a companion 36-byte value: when a Changed baseline outcome flares the per-ordinal counter, the serving path also stores the full 36-byte JA4 of the changed fingerprint as the latest changed JA4 for that ordinal. The monitor record emits both fields together, zero-suppressed as a unit: `d<j>j=N d<j>v="<36-char-ja4>"` appears only when the ordinal's change counter is nonzero; a no-change ordinal emits neither. The value is retained per ordinal in a fixed `[[u8; 36]; ALLOWLIST_MAX]` table (32 × 36 = 1,152 B), boot-time fixed storage with zero heap allocation or deallocation after boot, consistent with the fixed profile.

## Post-window probe sweep exchange-deadline citation


### Probe sweep exchange-deadline citation

#### Post-window probe sweep exchange deadline

The post-window probe sweep clause (§Sweep semantics (probe state machine)) governs the startup probe sweep. This amendment refreshes the exchange-deadline citation at §Sweep semantics (probe state machine) from the stale 2-second value to the 5-second value, aligning §Sweep semantics (probe state machine) with the alumina-5sx 5-second deadline (single constant `EXCHANGE_DEADLINE_SECS`, `src/startup_dns.rs`); no other text on the line changes.

## Keyed configuration schema


### Keyed allowlist tables

The `allowlist` array and the positional `[actions]` kind/scope arrays are removed. The sole
allowlist mapping is the set of `[allowed_fqdn."<fqdn>:<port>"]` table keys: each configured
domain is defined exactly once, with its action co-located in the same table. This
eliminates the index-alignment error class and the second mapping; no attacker-controlled
name table is introduced. The exact schema is:

```
[any_illegal]
scope = "connection" | "all"          # AnyIllegal first-slot Block scope; "domain" is invalid configuration

[allowed_fqdn."<fqdn>:<port>"]
early_data = { action = "flare_only" | "block", scope = "connection" | "domain" | "all" }  # block scope "domain"/"all" is invalid configuration (exit 78)
```

- The allowlist is the set of `[allowed_fqdn."..."]` table keys, 1 through 32 tables; empty
  or more than 32 is invalid configuration (exit 78). Each key is a literal `<fqdn>:<port>`
  spelling (a bare FQDN key is invalid configuration). Existing FQDN/port validation rules
  carry over unchanged: lowercase ASCII DNS hostname, canonical decimal port 1 through
  65535, no leading zero, IP-literal-shaped entry invalid. Table keys are unique after
  normalization (lowercase FQDN + canonical port); a duplicate-after-normalization is
  invalid configuration (exit 78).
- Ordinals are 0-based: 0 through 31 are assigned to the `[allowed_fqdn."..."]` tables in
  ascending table-key order, not document order (the TOML parser iterates tables in sorted
  key order), and `Config::allowlist_position` returns `Some(0)` for the first table; the
  ordinal numbering carried in logs matches that same 0-based numbering. The allowlist and
  its actions are built from the same table, so enforcement pairing is unaffected by the
  ordering.
- Every `[allowed_fqdn."..."]` table contains the mandatory `early_data` key and an optional
  `cname_bailiwick` key; every other key remains invalid configuration (exit 78). `early_data`
  is an inline table with exactly `action` and `scope`; missing `early_data` or an unknown key
  is invalid configuration (exit 78); no defaults are supplied, consistent with the
  all-keys-mandatory doctrine. The `early_data` key names the existing per-domain control
  (rp2e §Action catalog and attribution early upstream data); it is forward-compatible with a future `ja4` key gated
  on a separate behavior amendment.
- Per-FQDN `action` is `flare_only` or `block`; `tarpit` is a reserved keyword for a future
  action, rejected with an explicit reserved-keyword diagnostic (exit 78), never accepted as
  an implemented runtime action. Per-FQDN `scope` is `connection`, `domain`, or `all` with
  unchanged semantics (rp2e §Block and Flare semantics-§Block and Flare semantics).
- `[any_illegal]` is unchanged and remains mandatory: `scope` must be `connection` or `all`
  (`domain` invalid, exit 78); an absent group is invalid configuration at enforcement
  integration (rp2e §Configuration surface (implemented; exact schema) preserved).
- All keys are mandatory with no defaults and no environment or command-line override;
  unknown keys or tables fail startup with exit 78 (EX_CONFIG) exactly as today.
  Configuration validation timing and procedure are unchanged.

### Document bound

`CONFIG_DOC_LIMIT` is raised from 4096 to 16384 bytes. The configuration clause (§Configuration & DNS) is
amended to state a single TOML document of at most 16 KiB (16384 bytes), including comments
and whitespace, with 1 through 32 `[allowed_fqdn."..."]` tables and a required `listen` key.
Boot-time read only; zero runtime/heap impact; no runtime-surface expansion. The capacity
clause (rp2e §Configuration surface (implemented; exact schema)) is amended to the new bound: the keyed full-schema 32-entry worst case
is re-measured with the exact document serializer the parser reads (pinned by parser-real
assertions in `src/config.rs`) and must fit under 16 KiB. Neither a further cap expansion,
an alias, a silent compact migration, nor a change to the legal literal set is implied.

### Startup-final record shape

The startup result is two record shapes, not one. Unresolved names are never embedded in the
summary record:

```
level=info kind=startup_name secs=<n> ordinal=<0..31> name="<full fqdn>" outcome=<negative|no_eligible|failed|not_attempted>[ reason="<token>"]
level=info kind=startup_final secs=<n> status="<full|degraded|failure|terminated>" allowance=<n> usable=<n> unresolved=<n> exchanges=<n> failed=<n> not_attempted=<n> dropped=<n> names_dropped=<n>
```

- Exactly one `startup_name` record is attempted per unresolved name, in ascending allowlist
  ordinal order, before the summary. `name` is the full validated unresolved FQDN, at most
  253 bytes, and is never truncated or elided; `ordinal` is the same 0-based allowlist
  ordinal carried elsewhere in logs; `reason` appears only for the `failed` and
  `not_attempted` outcomes. Resolved names are never emitted.
- The summary embeds no names, so its field set is fixed and it fits its slot for any counter
  values, including `u64::MAX`. It is attempted last, so the aggregate readiness outcome is
  recorded even when every per-name record was dropped.
- A per-name attempt that cannot be enqueued — full queue or encode overflow — is dropped
  whole and increments the shared whole-record drop counter exactly once. `names_dropped`
  reports how many of those failures were per-name attempts: it is a subset of the summary's
  cumulative `dropped`, and the two are never summed. Counting, never truncation, remains the
  only overflow response.

Recorded worst-case encoded lengths, including the terminal newline framing, for the widest
legal configuration (32 keyed FQDNs at the 253-byte maximum with `u64::MAX` counters) against
the fixed 2048-byte slot:

| Record kind | Worst case | Headroom |
| --- | --- | --- |
| `startup_name` | 380 B | 1668 B |
| `startup_final` | 325 B | 1723 B |
| `startup_warning` | 331 B | 1717 B |
| `reject` | 406 B | 1642 B |
| `early_activity` | 405 B | 1643 B |
| `exchange_failed` | 341 B | 1707 B |
| `fatal` | 360 B | 1688 B |
| `shutdown_final` | 103 B | 1945 B |
| `capacity_high` / `capacity_low` | 127 B / 125 B | 1921 B / 1923 B |
| `queue_high` / `queue_low` | 124 B / 122 B | 1924 B / 1926 B |
| `resolver_probe` | 1857 B | 191 B |
| `monitor_summary` | 763 B | 1285 B |
| `monitor_domain` | 1370 B | 678 B |
| `monitor_capture` | 1237 B | 811 B |

Both startup records fit with wide margins, so the encoded-entry requirement at §Verification requirements is met
by measurement for every valid configuration. `resolver_probe` is now the tightest record in
the vocabulary at 191 B of headroom against the 2048-byte slot; any future addition to any
monitor-family record shape must re-measure against the 2048-byte slot before it is
accepted.

## Red-team remediation: 16 findings


### Remediated findings

#### SP-001 — All-scope AnyIllegal latch arms only after a bounded fact threshold

The first AnyIllegal control failure could select `Block` scope `All` and latch a
process-wide egress outage from a single unauthenticated request, with no pacing or
threshold between Connection and All scope and no unblock path. Resolution: `All` scope arms
only after a bounded fact counter crosses a fixed threshold within a fixed window, using
fixed constants; there is no speculative pacing. The rp2e §Block and Flare semantics property is preserved —
once armed, the latch still performs the synchronous bounded physical closure and persists
until restart — and §Planned fixed control storage (design estimate, not measured) is respected (no speculative pacing allocation; Tarpit remains
deferred). The threshold and window are fixed constants, not configuration. Implementation
folds into a later sub-mission of this package; this amendment records the binding
semantics.

#### SP-002 — Upstream-sourced early data: baseline denial kept; Domain/All block scopes rejected at startup

Early upstream data observed before the forwarding gate opens was attributed to the
validated configured domain, letting an upstream endpoint fire the per-domain latch (and, at
`All` scope, a process-wide latch) — a vantage orthogonal to the enforcement subject. The
earlier K-connection corroboration proposal is superseded (permanently ineligible); the
resolution is now structural. `early_data = { action = "block", scope = "domain" | "all" }`
is invalid configuration, rejected at startup with exit 78 (EX_CONFIG); the only legal
`block` scope for `early_data` is `connection`. The baseline mandatory denial is kept
(terminate setup on early upstream data while the gate is closed, rp2e §Action catalog and attribution); the
K-connection corroboration state and gate are removed from the enforcement path, and the
upstream-sourced signal can no longer select a per-domain or process-wide latch because
those scopes are unreachable from configuration. This amendment records the binding
semantics.

#### SP-003 — Homogeneous-trust resolver arrays; mixed DoT/plain rejected at startup

A resolver array mixing DoT (`IP#fqdn[^pin]`) and plain (`IP`) entries let failover land on
a bare-IP entry, converting sustained DoT blocking into a silent cleartext-DNS downgrade,
with validated negatives masking the degradation. Resolution: resolver arrays are
homogeneous-trust — an array mixing DoT and plain entries is rejected at startup with exit
78 (EX_CONFIG), removing the cross-entry downgrade path structurally. This respects §Vec 19 — Passive resolver degraded signaling (a
valid negative response still counts as a successful exchange within a homogeneous array) and
§Directory — three resolver trust forms, per-entry dial port (tolerated degraded trust is scoped to a homogeneous plain array, not a mixed one).
Implementation folds into a later sub-mission of this package; this amendment records the
binding semantics.

#### SP-004 — Sustained-negative incident class

A validated NXDOMAIN evicts both families immediately and clears exchange-failure incidents,
with only one transition notification and no recurring observable — sustained negatives are
indistinguishable from deliberate name removal. Resolution: a sustained-negative incident
class is added: after N consecutive validated negatives across M windows, a negative-refresh
incident opens that participates in hourly summaries and the `rd`-class monitor facts, giving
an operator a persistent deletion signal rather than a single event. This respects §DNS response outcomes
(validated negatives remain successful outcomes that clear exchange-failure incidents); the
sustained-negative incident is a distinct incident class and does not invert the
negative-clears-incident rule. Implementation folds into a later sub-mission of this package;
this amendment records the binding semantics.

#### SP-005 — Per-ordinal JA4 set baseline

The first-seen per-(ordinal, IP) JA4 baseline conflated multiple clients behind one proxy,
re-seeded on IP churn, and left the 17th-peer overflow behavior unspecified. Resolution: the
baseline becomes a per-ordinal set of up to K=16 distinct observed JA4 strings, reusing the
existing 512-entry table (32 ordinals × 16 slots). At set-capacity overflow, further adds are
suppressed and a count is incremented (the evict-vs-suppress question is resolved as
suppress-with-count, preserving the baseline-never-updated semantics). Baseline-seeding
events are recorded as operator-visible facts so re-seeding churn is distinguishable from
attacker-driven re-seed. This respects §Control-storage table/§C1 JA4 change-signal value (the fixed 512-entry table shape and the
baseline-never-updated doctrine). Implementation folds into a later sub-mission of this
package; this amendment records the binding semantics.

#### SP-006 — Sigalg-list bound and `count:02` overflow rendering

The spec pinned canonical JA4 byte-for-byte fidelity while mandating sigalg retention
`[u16; 64]`, so a ClientHello offering more than 64 signature algorithms silently truncated
the hash input; `count:02` overflow rendering was undefined. Resolution: a ClientHello
offering more than 64 `signature_algorithms` entries is rejected as a ClientHello-profile
violation, classified as **AnyIllegal**. This is a profile-boundary rejection, not a JA4
admit/reject decision, so §Reconciliation with the cipher/ALPN policy ban (JA4 data never used to admit, reject, or modify a
connection) is respected. `count:02` overflow rendering is bounded: the two-digit count
saturates at 99 with no literal overflow marker (`+` would break the fixed 2-character
canonical slot of the 36-byte JA4 string); this applies to `cipher_count`, the only count
that can exceed 99 under the 64-extension cap. Implementation folds into a later sub-mission of
this package; this amendment records the binding semantics.

#### RT-001 — No silent sigalg truncation

The JA4 fingerprint was computed from a deterministically truncated `signature_algorithms`
list, so entries beyond the retained prefix never reached the fingerprint and profile pivots
beyond entry 64 never raised `Changed`. Resolution: the sigalg-list bound of SP-006 removes
the truncation path — a list longer than the retained bound is rejected as a profile
violation rather than lopped, so the fingerprint input is never silently truncated; the ALPN
255-byte cut and `count_token` 99 cap remain bounded retention, not truncation of the JA4
hash input. Implementation folds into a later sub-mission of this package; this amendment
records the binding semantics.

#### SP-007 — Resource-profile rows folded in place

The body table rows §Initial resource profile still read 30/300 while `alumina-hrdn2` (Vec 14) amended
them to 5/900 (normal) and 30/900 (negative), matching the code. Resolution: the rows are
folded in place to the already-authorized Vec 14 values, exactly as the `alumina-5sx` and
`alumina-cfgk` amendments did for their rows: §Initial resource profile becomes 5 seconds / 900 seconds and
§Initial resource profile becomes 30 seconds / 900 seconds. Implemented (this revision).

#### SP-008 — CONNECT response-corpus oracle acknowledged

The CONNECT error-response taxonomy is an allowlist-enumeration and cache-state oracle,
unacknowledged in the threat model. Resolution: threat-model acknowledgement only, at §CONNECT request
(doc-only, no behavior change): the response corpus is an acknowledged
allowlist/cache-state oracle — the `400`/`403` split discriminates allowlist membership from
malformed syntax and the `502`/`503`/`504` split discriminates DNS-cache state per
allowlisted name. No throttling, normalization, or body change is made. Implemented (this
revision).

#### SP-009 — Probe-relocation counter disjoint from `dp=`

The post-window probe sweep's DoT→plain relocations incremented the same `dp=` downgrade
counter, making real failovers indistinguishable from probe noise. Resolution: probe
relocations are counted in a separate bounded fact disjoint from `dp=`, so the downgrade
counter remains a clean signal; the probe record carries its own relocation segment. This
respects §DoT→plain downgrade counter (`dp=` remains the sole serving-downgrade surface) and §Sweep semantics (probe state machine) (probe
relocations no longer fold into `dp=`). The new monitor field is re-measured against the
8192-byte slot headroom (§Startup-final record shape). Implementation folds into a later sub-mission of this
package; this amendment records the binding semantics.

#### SP-010 — Log-queue priority classes

The flat 256-entry FIFO dropped the most consequential records (Block All latch, startup
final, incident summaries) like any best-effort entry under queue pressure. Resolution:
bounded priority classes are added to the log queue: latch/event records (`Block All`,
`startup_final`, `resolver_probe`) are reserved and cannot be dropped by new unrelated
entries; when the queue is full, the newest entry from the lowest class is dropped first.
This respects §Lifecycle (drop-and-count remains, now class-aware; a stalled sink still never
delays rejection, tunnel I/O, DNS, or deadlines) and §Monitoring (the shutdown report remains
not-guaranteed-lossless; reservation is bounded, not lossless). Implementation folds into a
later sub-mission of this package; this amendment records the binding semantics.

#### SP-012 — Conflict predicates enumerated

"Conflicting settings" was an unenumerated catch-all in configuration validation, against
the exact-discriminant precedent the document set for CONNECT. Resolution: the conflict
predicates are enumerated at §Configuration & DNS (documentation clarification only; no new validation): the
mandated-set predicates — a required set of settings that must be present and consistent
together, where a member present more than once after normalization is a conflict (duplicate
keys, invalid table redefinitions, and duplicate allowlist names after normalization are the
enumerated instances) — and the forbidden-pair predicates — two settings that cannot legally
coexist under this document's schema, where the schema's enumerated scope values are
exclusive (a scope value outside the enumerated set for its surface is invalid configuration
rather than a silent override). The exit-78 behavior is unchanged. Implemented (this
revision).

#### SP-013 — Latest-change value keyed per-ordinal with triggering peer source address

The C1 latest-change 36-byte JA4 value is keyed per-ordinal, matching the per-ordinal
first-seen JA4 baseline (SP-005, `Ja4BaselineTable`, `src/serving.rs` — a 36-byte JA4 per
entry, no per-IP element); there is no per-(ordinal, IP) baseline. The reported value alone
could belong to a different peer than the one whose change fired, so the triggering peer's
source address is carried in the flare/monitor record as a fixed tagged IPv4/IPv6 union,
aligning the reported fingerprint with the change that fired. The monitor record grows
accordingly and is re-measured against the 8192-byte slot headroom (§Startup-final record shape). Implementation
folds into sub-mission 6 of this package, fulfilled by the alox7 F-12 increment; this
amendment records the binding semantics.

#### RT-005 — CNAME bailiwick parent-zone note

Bailiwick enforcement grants authority at parent-zone granularity, so a parent-zone
compromise pivots allowlist names anywhere inside that zone; this is a threat-model note, not
a code defect. Resolution: spec-text note only — require nothing more today. The parent-zone
SOA granularity is an accepted threat-model boundary: the anomaly surface
(`BailiwickViolation`) continues to fire only outside the parent SOA, and the residual (a
parent-zone delegation compromise is indistinguishable in-band) is acknowledged without
changing the bailiwick rule. Implemented (this revision). This note is superseded and refined
by SP-014 (alumina-alox10, §SP-013 — Latest-change value keyed per-ordinal with triggering peer source address): the parent-zone granularity residual is narrowed to the
operator-declared suffix union — the operator, not the derivation, now chooses the zone
granularity, and a declared suffix is an explicit trust boundary.

#### RT-006 — Independent stale-serving window

Stale DNS authorization grace (259200 seconds) is shared with retention, so a captured answer
could keep serving up to 72 hours past TTL expiry with no independent cap. Resolution: a
separate stale-SERVING window is introduced, independent of the 259200-second retention
deadline: stale bindings are served only within the new stale-serving window, which is a new
profile deadline in the fixed enumeration (§Initial resource profile). Retention (259200 seconds) is unchanged.
Implementation folds into a later sub-mission of this package; this amendment records the
binding semantics.

#### RT-007 — Pin-branch validity check non-blocking with distinct expired-cert fact

The strict-SPKI pin branch checked SAN and SPKI digest but never evaluated
Not-Before/Not-After, so a pinned key retained trust indefinitely with no expiry forcing.
Resolution: the pin branch gains a Not-Before/Not-After validity check that is non-blocking —
it does not fail the handshake, which remains grounded in the pin match plus signature
verification per §Verifier — strict pin + FQDN/SAN, or empty-root CA-chain (validity-time check only, no chain-build) — and emits a distinct
expired-cert warning fact when serving over an expired pinned certificate, forcing pin
rotation with operator-visible telemetry. Implementation folds into a later sub-mission of
this package; this amendment records the binding semantics.

## Low-risk alox hardening: probe isolation, failover ordinal, and failback reset


#### F-03 — Probe-Isolation Invariant

The post-window probe sweep (`alumina-rbp`, §Sweep semantics (probe state machine)) is an observational increment, but the sweep clauses enumerate resolver-health mutations while remaining silent about name-cache, schedule, generation, retry, and incident mutations — leaving a permitted mutating reading in which a backup resolver probed once could evict or replace working bindings obtained from the active resolver. Resolution: a **Probe-Isolation Invariant** governs every sweep probe: probe responses may determine only the probe verdict and the explicitly enumerated probed-resolver health state (`ProbeVerdict`, `src/startup_dns.rs`); the name outcome is parsed and validated in staging, then discarded. Probes must not mutate any allowlist-name cache entry, generation, freshness/retirement/stale-serving deadline, refresh/retry schedule, name incident, or admission counter. This refines the `alumina-rbp` probe-mode clause (§Sweep semantics (probe state machine)) — which already suppresses relocation and failback arming while a probe is in flight — by barring the name-authorization write path entirely. Opposite-answer tests (active and probed resolvers returning different valid outcomes) assert all name-authorization state remains byte-for-byte unchanged (`probe_exchange_publishes_no_name_authorization_state`, `src/startup_dns/tests.rs`).

#### F-04 — Failover relocates on the third counted failure

The failover clause (§Multi-resolver failover and failback (Vec 18)) states that "once the active resolver is degraded, the next counted failure relocates the transport" — implying four failures per relocation, which with five resolvers yields `4 + 4 + 4 + 4 + 3 = 19` exchanges = 95 seconds, exceeding the absolute 90-second startup window (§Configuration & DNS) and invalidating the `5 × 3 × 5 = 75 ≤ 90` budget proof (§DNS exchange deadline). Resolution: the failover clause is corrected to state that relocation happens on the **same transition** that records the third consecutive failure and marks the active resolver degraded (`on_exchange_failed`, `src/startup_dns.rs`): the degradation advance and the relocation are one call, so each relocation away from a resolver requires three failures, not four. The complete five-resolver worst case is 15 exchanges (`5 × 3`), each bounded by the 5-second exchange deadline, giving `15 × 5 = 75 ≤ 90` — the budget proof at §DNS exchange deadline therefore corresponds to the state machine. The 90-second deadline (§Configuration & DNS) is unchanged. Deterministic tests prove the exact failure ordinal that closes, repoints, and starts against each resolver, and the complete five-resolver startup budget (`five_resolvers_relocate_on_the_third_failure_not_the_fourth`, `five_resolver_startup_budget_fits_the_window`, `src/startup_dns/tests.rs`).

#### F-05 — Failback counter resets at arm and on failure, not on every probe begin

The failback clause (§Failback consecutive-success settle) states the consecutive-success counter resets "when a failback probe begins" — a wording readable as resetting on every probe begin, which would make the `FAILBACK_SUCCESSES = 3` settle unreachable (each success reaches only one, the next probe begin resets it again, and the probe loops on the backup with repeated 900-second relocation cycles). Resolution: the reset points are refined to the two transitions that actually reset the counter (`maybe_begin_failback` / `on_exchange_failed`, `src/startup_dns.rs`): the counter resets to zero when failback is initially **armed** — the backup→primary transition in `maybe_begin_failback` (`:3019`) — and when a probe **fails**, re-seating onto the backup and re-arming the grace (`:3202`). It does not reset on any later probe begin: once armed, `maybe_begin_failback` is a no-op for the rest of the regime (guards `:3004-3006`), so the counter accumulates across probe begins while the transport remains on the primary. Between successful but not-yet-settling probes the transport resides on the primary with the probe armed (`failback_source` set to the backup) and the grace **not** re-armed (`failback_due` stays `None`); the grace is re-armed only by a failed probe. The counter increments on each successful primary probe and settles — clearing the probe source, grace, and counter — only at the third consecutive success (`:3270-3274`). A success on a non-primary backup leaves the counter and grace untouched (`is_primary()` guard, `:3269`). On shutdown the counter is discarded with the transport; the next boot starts unarmed with the counter at zero. The compact transition table below is the state machine; the deterministic regression test `probe_begin_mid_regime_does_not_reset_the_failback_counter` (`src/startup_dns/tests.rs`) drives `maybe_begin_failback` between successes to prove a probe begin mid-regime does not reset the counter.

| Transition | Counter | Transport | Grace (`failback_due`) | Probe source (`failback_source`) |
| --- | --- | --- | --- | --- |
| Failback armed (backup→primary) | 0 (reset) | primary | `None` | set (backup) |
| Probe success 1 | 1 | primary | `None` | set (backup) |
| Probe success 2 | 2 | primary | `None` | set (backup) |
| Probe success 3 (settle) | 0 (reset) | primary | `None` | cleared |
| Probe failure after success 1/2 | 0 (reset) | backup (re-seated) | re-armed (`now + FAILBACK_AFTER_SECS`) | cleared |
| Backup success (non-primary) | unchanged | backup | unchanged (armed) | `None` |
| Shutdown | discarded | — | — | — |

#### F-08 — JA4 baseline overflow suppresses detail, never the deviation decision

The per-ordinal JA4 set baseline (SP-005, §SP-005 — Per-ordinal JA4 set baseline) stores up to K=16 distinct observed JA4 strings per ordinal and suppresses every further add until restart. A compromised application can deliberately generate 16 syntactically accepted ClientHello variants, fill the set, and then make subsequent profile changes collapse into the overflow count: the overflow count reveals saturation, but the set can no longer provide distinct change detail for later attacker profiles or legitimate clients, and because the baseline is never updated this blindness persists for the process lifetime. Resolution: the deviation decision is separated from the bounded detail set. The 16-entry set remains the immutable comparison reference (`Ja4BaselineTable`, `src/serving.rs`); every first-seen JA4 beyond set capacity fires the per-ordinal JA4-change deviation signal (`d<j>j` count, `d<j>v` latest overflowed value, `d<j>p` triggering peer), regardless of set capacity — the 17th and every later distinct JA4 each fire the decision. Overflow suppresses detail only, never the decision: the overflowed value is not added to the set (the set is never updated, preserving the SP-005 baseline-never-updated doctrine), only the latest overflowed value is retained, and the per-ordinal detail-loss flag `d<j>x` latches to signal the operator that detail was suppressed. The loss flag is a latched boolean, not a counted fact, and does not fold into `facts_total`. This refines SP-005's suppress-with-count semantics: the count and the loss flag are the operator-visible overflow surface, and the decision is capacity-independent. Deterministic tests prove a 17th distinct JA4 fires the decision and latches the loss flag, and an 18th distinct JA4 fires the decision again with the retained value following the newest overflow (`ja4_set_overflow_fires_decision_on_each_new_distinct_beyond_capacity`, `src/serving/tests.rs`).

#### F-10 — Zero-TTL entries never admit stale serving; refresh at the one-second boundary

A received TTL of zero is promoted to one second (§Configuration & DNS), after which the ordinary stale-authorization path applies: the stale-serving window (§Configuration & DNS, `STALE_SERVING_WINDOW` = 3600 seconds) does not exclude zero-TTL-derived entries, so a DNS owner explicitly requesting no caching could have its address authorize new connections for the full stale-serving window. Resolution: each entry carries a per-entry **stale-allowed** bit derived from the earliest supporting TTL — the minimum across the supporting CNAME chain and terminal A/AAAA records (`src/dns.rs`), the same TTL that fixes the entry's freshness deadline (§Configuration & DNS). A zero-TTL entry keeps the specified one-second fresh usability but never admits stale serving: `servable()` gates the stale arm on the bit, so the entry is served only while `now < freshness` and is never served past its freshness deadline regardless of `STALE_SERVING_WINDOW` (`src/cache.rs`). To preserve steering availability for zero-TTL names without extending authorization, the normal refresh interval for a zero-TTL entry is the one-second boundary (`normal_refresh_interval(0) == 1`, `src/schedule.rs`) — the sole exception to the 5-second refresh floor (§Configuration & DNS), scoped to zero-TTL entries only; every nonzero-TTL entry keeps `min(900 seconds, max(5 seconds, entry TTL))` unchanged. Because a zero-TTL entry is never served stale and its next revalidation is scheduled at the freshness boundary, a delayed refresh never extends authorization. This refines RT-006 (§RT-005 — CNAME bailiwick parent-zone note) and the refresh-scheduling clause (§Configuration & DNS). Deterministic tests prove the before/at/after freshness boundary for a zero-TTL entry in `servable()` and the bit derivation at publication time (`zero_ttl_entry_never_served_stale`, `publish_positive_derives_stale_allowed_from_raw_ttl`, `src/cache.rs`; `normal_refresh_interval_honors_bounds`, `src/schedule.rs`).

#### F-11 — DoT client negotiates TLS 1.3 only

The DoT handshake clauses (`alumina-dot-chain-v1-v5`, §Verifier — strict pin + FQDN/SAN, or empty-root CA-chain, §Transport confinement and lifecycle) require identity validation without specifying an allowed protocol-version set, and the recorded rustls configuration carried the `tls12` feature (`Cargo.toml`, `alumina-zai` §Zero-Allocation Invariant scope), so the DoT specification permitted a pinned, SAN-valid TLS 1.2 session even though the tunnel ClientHello profile (§TLS ClientHello profile) and the serving surface are TLS 1.3-only. Resolution: the DoT client negotiates TLS 1.3 only — `build_tls_connection` (`src/startup_dns.rs`) now calls `with_protocol_versions(&[&rustls::version::TLS13])`, and the `tls12` feature is removed from the rustls dependency (`Cargo.toml`), so the client contains no TLS 1.2 code at all. A DoT peer that cannot complete a TLS 1.3 handshake — including a TLS 1.2-only resolver — is deterministically refused at the handshake and counted as a connect failure; the client never negotiates down and never falls back to plain DNS. This refines the DoT handshake clauses (§Verifier — strict pin + FQDN/SAN, or empty-root CA-chain, §Transport confinement and lifecycle) to bind the client to the same TLS 1.3-only profile as the serving surface. A consequence is recorded: a TLS 1.2-only public resolver is excluded and fails closed until it upgrades. Deterministic tests prove the client fails closed against a TLS 1.2-only peer — a raw responder answering with the TLS 1.2 `protocol_version` fatal alert (`0x46`) that such a server sends to a TLS 1.3-only offer — on both the pinned and CA-chain branches, and negotiates TLS 1.3 with a TLS 1.3-only server (`pinned_dot_rejects_tls12_only_peer`, `unpinned_dot_rejects_tls12_only_peer`, `pinned_dot_negotiates_tls13_with_tls13_only_server`, `src/startup_dns/dot_tests.rs`).

#### F-12 — Monitor loss-flag render compacts to a single `dx=` bitset

The per-ordinal JA4-change detail-loss flag (`d<j>x`, F-08, §F-08 — JA4 baseline overflow suppresses detail, never the deviation decision) is a latched boolean per ordinal, rendered by the monitor record as one `d<j>x=1` key per latched ordinal. With all 32 ordinals latched the per-ordinal renders add 214 B to the worst-case monitor record, pushing it to 8372 B — over the 8192-byte log-slot bound (§Verification requirements), which would have made `enqueue_reserved` silently drop the record (violating the §Verification requirements "every valid configuration" guarantee and the §Startup-final record shape headroom known risk). Resolution: the 32 latched per-ordinal flags render as a single `dx=<hex>` 32-bit bitset — bit i = ordinal i's `ja4_change_loss` latch, lowercase hex, leading zeros omitted, emitted once only when any flag is set (`encode_monitor`, `src/log.rs`). The per-ordinal latch and accessor are unchanged (`src/enforcement/monitor.rs`); only the render compacts, so the fixed profile and zero-heap record path are preserved. `saturate_all_for_test` now latches all 32 flags so the worst-case slot test exercises the bitset render. The worst-case monitor record re-measures at 8170 B against the 8192-byte slot — 22 B of headroom — restoring the §Verification requirements guarantee and superseding the stale 8139 B / 53 B measurement (§Startup-final record shape). This supersedes the F-08 section's `d<j>x` render reference (§F-08 — JA4 baseline overflow suppresses detail, never the deviation decision) and its Status row: the loss-flag vocabulary is now the single `dx=` bitset. It also corrects SP-013 (§SP-013 — Latest-change value keyed per-ordinal with triggering peer source address): the first-seen JA4 baseline is per-ordinal (SP-005, `Ja4BaselineTable`, `src/serving.rs` — a 36-byte JA4 per entry, no per-IP element), the latest changed JA4 is keyed per-ordinal, and the triggering peer's source address is carried in the flare/monitor record as a fixed tagged IPv4/IPv6 union — there is no per-(ordinal, IP) baseline. SP-013's forward reference ("sub-mission 6") is fulfilled by this increment. Deterministic tests prove the exact monitor grammar (`dx=1` for a single ordinal-0 latch) and the worst-case slot fit with margin (`logging_monitor_summary_exact_grammar_and_zero_suppression`, `logging_worst_case_record_per_kind_fits_the_slot_with_margin`, `src/log.rs`).

## Lossless peer-IP hex render and 10 KiB log slot

The alox7 F-12 monitor record (§F-10 — Zero-TTL entries never admit stale serving; refresh at the one-second boundary) carries the latest JA4-change overflow's triggering
peer as a fixed tagged IPv4/IPv6 union rendered through `IpAddr` Display (`d<j>p`). The
widest legal peer — a full 16-byte IPv6 address — renders as 39 characters (`ffff:ffff:ffff:
ffff:ffff:ffff:ffff:ffff`), and with the 8 KiB slot the all-saturated monitor worst case
overflows the fixed 8192-byte slot (§Verification requirements), silently dropping the record and violating the
"every valid configuration" guarantee. Resolution: the `d<j>p` peer-address field renders as
raw lowercase hex of the address's fixed bytes — V4 = 8 chars, V6 = 32 chars, each byte
zero-padded to two digits so leading zeros are never dropped (lossless; `203.0.113.1` →
`cb007101`) — written straight into the entry with no intermediate allocation
(`push_indexed_key_addr`, `src/log.rs`), preserving the zero-heap record path. The log slot
is widened from 8 KiB to a fixed 10 KiB (`SLOT_BYTES = 10 * 1024`, `src/log.rs`; the queue
stays 256 slots, `LOG_QUEUE_BYTES = 256 × 10 KiB`, `src/inventory.rs`), and the worst-case
monitor record re-measures at 8191 B against the 10240-byte slot — 2049 B of headroom.
The fixed profile is restated unchanged
except for the log queue geometry: 512 tunnels, 128 pending setups, two 128 KiB per-slot
buffers, 128 MiB traffic storage, the 256 × 10 KiB log queue, 16-op/64 KiB visits,
at-most-256-visit recheck, DNS response/candidate/incident caps, the 90-second startup
window, and all deadlines — 10/2/300/5/8/3600 seconds. Deterministic tests prove the exact
monitor grammar renders `d0p="cb007101"` for the V4 peer and the all-saturated monitor
record with a full V6 max peer fits the 10240-byte slot with margin
(`logging_monitor_summary_exact_grammar_and_zero_suppression`,
`logging_worst_case_record_per_kind_fits_the_slot_with_margin`, `src/log.rs`).

## 2 KiB log slot and monitor family split


The fixed profile is restated unchanged except for the log queue geometry: 512 tunnels,
128 pending setups, two 128 KiB per-slot buffers, 128 MiB traffic storage, the 256 × 2 KiB
log queue (512 KiB), 16-op/64 KiB visits, at-most-256-visit recheck, DNS
response/candidate/incident caps, the 90-second startup window, and all deadlines —
10/2/300/5/8/3600 seconds. The per-slot encoded-entry bound is a fixed 2048-byte slot
(`SLOT_BYTES = 2 * 1024`, `src/log.rs:50`; `MONITOR_RECORD_MAX = 2048`, `src/log.rs:55`; the
queue stays 256 slots, `QUEUE_SLOTS = 256`, `src/log.rs:49`, with
`LOG_QUEUE_BYTES = 256 × 2 KiB`, `src/inventory.rs:38`, and the compile-time assertion
`QUEUE_SLOTS * SLOT_BYTES == LOG_QUEUE_BYTES`, `src/log.rs:150`), replacing the alox8 10 KiB
geometry.

The monitor family is split into an always-emitted, authoritative `kind=monitor` summary and
best-effort `monitor_domain` / `monitor_capture` detail batches. The summary carries a fixed
core — 13 globals, 10 scalars, 19 `c<i>` counters, 4 `unk<i>` counters, and the `dx=` loss
bitset — and is enqueued reserved (commit-point, `enqueue_reserved(Kind::Monitor, …)`,
`src/log.rs:1677`) at every report cadence, so the aggregate readiness outcome is always
recorded even when every detail batch is dropped. The detail batches are best-effort:
`monitor_domain` packs the 32 domain blocks into 3 batches (~11/11/10 blocks, `DOMAIN_BATCH
= 11`, `src/log.rs:57`) and `monitor_capture` packs the 64 capture details into 3 batches
(~22/22/20 details, `CAPTURE_BATCH = 22`, `src/log.rs:59`), each batch ≤ 2048 B with
`part=<n>/<total>`, emitted only when the underlying data is nonzero. Detail loss never
blocks the summary: `report_drops` counts each dropped `monitor_domain` batch once per batch;
`capture_drops` counts capture-detail loss with mixed units — once per detail at capture time
(a later detection relation on an already-captured connection is suppressed,
`src/serving.rs:2331`, or a detail is evicted when the 64-detail window is full,
`src/enforcement/monitor.rs:330`) and once per batch when a `monitor_capture` batch is
dropped at report time (`src/log.rs:1701`, up to 22 details lost in one counted batch) — the
per-batch/per-detail unit mixing is intentional and documented; both are saturating counters
with overflow flags in the summary's fixed core.

The worst-case encoded lengths re-measure against the fixed 2048-byte slot (widest legal
configuration, 32 keyed FQDNs at the 253-byte maximum with `u64::MAX` counters, terminal
newline framing included): `resolver_probe` is the tightest record at 1857 B / 191 B of
headroom; the monitor family measures `monitor_summary` 763 B / 1285 B, `monitor_domain`
1370 B / 678 B, and `monitor_capture` 1237 B / 811 B. Any future addition to any
monitor-family record shape must re-measure against the 2048-byte slot before it is
accepted.


Deterministic tests prove the exact monitor grammar and the worst-case slot fit with margin
for every record kind against the 2048-byte slot
(`logging_monitor_summary_exact_grammar_and_zero_suppression`,
`logging_worst_case_record_per_kind_fits_the_slot_with_margin`, `src/log.rs`).

## Explicit CNAME bailiwick: self-default zone + declared suffix union


#### SP-014 — Explicit CNAME bailiwick: self-default zone + declared suffix union

The implicit parent-zone derivation is replaced by an explicit two-part bailiwick:

- **Self-default zone**: each allowlisted name's own zone is itself — the allowlist name and
  its subdomains only, matched at label boundaries. A CNAME chain rooted at an allowlisted
  name may land on the name itself or any subdomain of it.
- **Declared suffix union**: an optional per-entry `cname_bailiwick` array of bare-name
  suffixes (`[allowed_fqdn."<fqdn>:<port>"].cname_bailiwick = ["<suffix>", ...]`) widens the
  bailiwick for that entry to the union of the self-default zone and every declared suffix,
  each matched at label boundaries. A declared suffix covers itself and its subdomains.

A followed CNAME link must land inside the entry's union (self-default zone or a declared
suffix) or the exchange fails with the distinct `BailiwickViolation` outcome, unchanged. The
union is per-entry: an entry with no declared suffixes is restricted to its self-default zone
only. Cross-allowlist coverage is preserved only to the extent another allowlisted name's zone
falls within the entry's own self-default or declared-suffix union.

Configuration validation: `cname_bailiwick` is optional; when present it is an array of
validated bare names — no port, no wildcard, no IP literal, at least two labels — and the
total declared suffixes across all entries is at most `ALLOWLIST_MAX` (32), else invalid
configuration (exit 78). This refines the cfgk exactly-one-key rule at §Keyed allowlist tables: an
`[allowed_fqdn."..."]` table now contains the mandatory `early_data` key and an optional
`cname_bailiwick` key; every other key remains invalid configuration (exit 78).

This **supersedes and refines RT-005** (§SP-013 — Latest-change value keyed per-ordinal with triggering peer source address): the parent-zone granularity note is replaced
by the explicit self-default + declared-suffix model. The residual RT-005 acknowledged (a
parent-zone compromise pivots allowlist names inside that zone) is narrowed to the
operator-declared suffix union: the operator, not the derivation, now chooses the zone
granularity; a declared suffix is an explicit trust boundary, and the residual is bounded to
zones the operator declared. The §Configuration & DNS bailiwick sentence is amended accordingly.

Implementation: `BailiwickZones` (`src/dns.rs`) holds the allowlist entries and the declared
suffixes in fixed `[DnsName; ALLOWLIST_MAX]` arrays (no heap), with a parallel `suffix_owner`
slot index so every suffix is attributed to the allowlist entry that declared it.
`covers_for(root, name)` accepts `name` only when it falls inside `root`'s own self-default
zone (the allowlist entry and its label-boundary subdomains) or inside one of that same
entry's declared suffixes, via the existing `soa_covers` label-boundary match — a neighbour
entry's zone never widens the bailiwick. `Config::cname_bailiwick()` returns the validated
per-entry suffix lists; `from_allowlist(allowlist, &suffix_lists)` builds the zones in
allowlist order. Allocation profile unchanged (fixed-slot storage, no post-boot heap).

#### Fixed-profile accounting follow-up

The `BailiwickZones` change adds no heap, but the DNS named-buffer accounting figure at
§Retained serving workspace (`BootInventory::named_fixed_buffer_bytes` ≈ 196 MiB lower bound) was re-measured once
the amendment was authorized: the fixed `[DnsName; ALLOWLIST_MAX]` zone storage measures
`size_of::<BailiwickZones>()` = 17168 B (16.77 KiB) — zones 8448 B + suffixes 8448 B +
`suffix_owner` 256 B + len/suffix_len 16 B — with `size_of::<DnsName>()` = 264 B (256-byte
buffer + 8 B len) (`src/dns.rs:793-799`). One retained instance exists: the field of the
single `StartupDns` transport (`src/startup_dns.rs:1089`). `DNS_NAMED_BUFFER_BYTES` =
`QUERY_BUF_LEN` (512) + `RECV_BUF_LEN` (`DNS_MSG_LIMIT` + 2 = 16386) + `size_of::<ResponseWorkspace>()`
(`src/inventory.rs:32-33`); the re-measured total ≈ 196 MiB is unchanged within rounding
(17168 B ≈ 0.0164 MiB), so the §Retained serving workspace note requires no textual edit.

This supersedes the superseded §Configuration & DNS bailiwick sentence and the RT-005 note at §SP-013 — Latest-change value keyed per-ordinal with triggering peer source address; the
hrdn3 recitals at §Vec 11 — CNAME bailiwick enforcement and the prior alox blocks remain in place as historical record
and are not individually edited.

## F-02 close: reject early_data block domain/all at startup; remove K-connection corroboration


#### F-02 — Upstream-sourced early data cannot select a Domain/All block

The K-connection corroboration gate proposed by SP-002 is removed as permanently
ineligible. The resolution is structural: `early_data = { action = "block", scope = "domain" | "all" }`
is invalid configuration, rejected at startup with exit 78 (EX_CONFIG); the only legal
`block` scope for `early_data` is `connection`. The baseline mandatory denial is kept
(terminate setup on early upstream data while the gate is closed, rp2e §Action catalog and attribution), and the
corroboration state and gate are removed from the enforcement path. Because Domain/All
block scopes are unreachable from configuration, the upstream-sourced signal can no longer
fire the per-domain latch or a process-wide latch; the `connection` scope terminates only
the originating setup.

## P-A6b fold: L3 bare-CR, L8 non-host_name SNI, SP-006 sigalg bound


#### L3 — CONNECT bare-CR rejection

The CONNECT request head is rejected when it contains a bare carriage return (a `0x0d` not
immediately followed by `0x0a`) or a bare line feed (`0x0a` not immediately preceded by
`0x0d`), located incrementally while scanning for the `\r\n\r\n` head terminator
(`src/connect.rs:274`/`:277`, `bare_line_feed` `src/connect.rs:331`, `bare_carriage_return`
`src/connect.rs:339`). Tests: `rejects_bare_lf` (`src/connect.rs:832`),
`rejects_bare_carriage_return_in_header_value` (`src/connect.rs:838`),
`rejects_bare_carriage_return_before_delimiter` (`src/connect.rs:847`).

#### L8 — Non-`host_name` `server_name` rejection

Within the `server_name` extension, any entry whose name type is not `host_name` (0) is
rejected as `non-host_name name type` rather than ignored (`src/client_hello.rs:737-739` in
`parse_server_names` `src/client_hello.rs:715`). Test: `non_host_name_sni_rejected`
(`src/client_hello.rs:1586`).

#### SP-006 — >64 sigalgs rejected; `count:02` overflow saturates

The `signature_algorithms` list is bounded at `MAX_SIGALGS = 64` (`src/client_hello.rs:40`);
a list declaring more than 64 entries is rejected as `TooManySigAlgs` — an AnyIllegal profile
violation, not a JA4 admit/reject — so the JA4 hash input is never silently truncated
(`parse_sig_algs` `src/client_hello.rs:805-806`). The `count:02` token saturates at 99 with no
literal marker (`count_token` `src/client_hello.rs:874-876`). Tests:
`sigalgs_over_max_sigalgs_rejected` (`src/client_hello.rs:2032`),
`sigalgs_at_max_sigalgs_accepted` (`src/client_hello.rs:2041`),
`sigalgs_over_max_rejects_as_profile` (`src/client_hello.rs:2053`).


## P-B7b note: one-label allowlist names accepted (no minimum label count)


#### One-label allowlist names are accepted; only `cname_bailiwick` requires ≥ 2 labels

An allowlist entry key is parsed by `Fqdn::parse` (`src/config.rs:27-37`): it requires a
`<fqdn>:<port>` shape (`rsplit_once(':')`, `src/config.rs:28-30`), rejects an IP-literal
host shape (`is_ip_literal_shape`, `src/config.rs:32-34`), and validates the bare name via
`validate_bare_name` (`src/config.rs:79-91`). `validate_bare_name` enforces the shared
lowercase-ASCII label rules (`validate_label`, `src/config.rs:56-71`) and the 253-byte
`FQDN_MAX_LEN` bound, but imposes no minimum label count — the contract note at
`src/config.rs:77-78` leaves shape-specific checks such as minimum label count to the
caller, and `Fqdn::parse` never applies one. The only configuration surface that requires
at least two labels is the declared `cname_bailiwick` zone suffix
(`parse_cname_bailiwick_suffix`, `src/config.rs:96-105`, ≥ 2-label check at
`src/config.rs:101-103`), a distinct F-07 safety rule; it never constrains the allowlist
name itself. The allowlist key path is `parse_allowed_fqdn_table` (`src/config.rs:825`),
which parses each key through `Fqdn::parse`.

Tests: `Fqdn::parse("1.2.3.4:443").is_err()` and `Fqdn::parse("93.184.216.34:443").is_err()`
(IP literals rejected) with `Fqdn::parse("4example.com:443").is_ok()` (`src/config.rs:322-324`);
the accepted-entries list at `src/config.rs:353-356`; and `rejects_bare_fqdn_key`
(`src/config.rs:1365`) confirming the only allowlist-key rejection is a missing `:port`,
not a label count.


## Register fold: SP-001/003/004/005, RT-001, SP-009/010, RT-006/007 implemented


#### SP-001 — bounded fact threshold; fixed constants; no speculative pacing

All-scope latch arms fire only after a bounded fact counter crosses a fixed threshold within
a fixed window, with fixed constants and no speculative pacing (`src/enforcement/state.rs:16`,
`decide` `src/enforcement/state.rs:132`). Tests: `any_illegal_folds_every_fact_by_exact_cause_and_latches_all_once`
(`src/enforcement/state.rs:397`), `single_any_illegal_never_latches_all`
(`src/enforcement/state.rs:766`), `three_any_illegal_facts_within_the_window_latch_all`
(`src/enforcement/state.rs:787`).

#### SP-003 — homogeneous-trust resolver arrays

A resolver array must be trust-homogeneous; a mixed plain (bare-IP) and DoT (`IP#fqdn`) set
is rejected at startup exit 78 (`src/config.rs:661`). Test: `resolver_mixed_plain_and_dot_trust_rejected`
(`src/config.rs:1973`).

#### SP-004 — sustained-negative incident class

`INCIDENT_N` negatives across `INCIDENT_M` windows raise an `rd`-class incident in hourly
summaries (`src/schedule.rs:22`/`:26`/`:29`). Test: `sustained_negative_streak_opens_incident_at_n_across_m_windows`
(`src/schedule.rs:1202`).

#### SP-005 — per-ordinal JA4 set up to K=16

Each ordinal holds a set of up to `MAX_ADDRESSES` (16) distinct JA4 strings; overflow
suppresses adds and increments a count; seeding events are recorded (`src/serving.rs:564`,
`src/serving.rs:576`, `src/cache.rs:7`). Test: `ja4_baseline_set_overflow_suppresses_and_dedups_unchanged`
(`src/serving/tests.rs:7368`).

#### RT-001 — sigalg-list bound at 64

The `signature_algorithms` list is bounded at `MAX_SIGALGS = 64` with no silent truncation
of the JA4 hash input (`src/client_hello.rs:40`, `TooManySigAlgs` `src/client_hello.rs:183`,
`src/client_hello.rs:805-806`). Tests: `sigalgs_over_max_sigalgs_rejected`
(`src/client_hello.rs:2032`), `sigalgs_at_max_sigalgs_accepted` (`src/client_hello.rs:2041`).

#### SP-009 — probe-relocation counter disjoint from `dp=`

The probe-relocation counter (`probe_relocations` → `pr=`) is disjoint from the serving
`downgrade_to_plain` (`dp=`) downgrade surface (`src/startup_dns.rs:1152`/`:1146`). Test:
`src/startup_dns/tests.rs:3163-3165`.

#### SP-010 — log-queue priority classes; reserved records; drop newest-lowest

Latch/event records are reserved and drop newest-lowest first (`is_reserved`
`src/log.rs:280`, `enqueue_reserved` `src/log.rs:1940`). Tests: `logging_reserved_startup_final_displaces_newest_normal_when_full`
(`src/log.rs:3369`), `logging_reserved_records_survive_normal_overflow` (`src/log.rs:3411`),
`logging_all_reserved_full_drops_newest_reserved` (`src/log.rs:3448`).

#### RT-006 — independent stale-serving window

`STALE_SERVING_WINDOW` (3600 s) is independent of the 259200 s retention deadline
(`src/cache.rs:15`, `src/cache.rs:145`). Tests: `src/cache.rs:706`, `:710`, `:740-741`,
`src/serving/tests.rs:6958-6977`.

#### RT-007 — pin-branch validity check non-blocking + distinct expired-cert fact

The pin-branch Not-Before/Not-After check is non-blocking and emits a distinct expired-cert
warning fact (`cert_outside_validity_window` `src/startup_dns.rs:1029`, `expired_pin_certs`
`src/startup_dns.rs:795-796`). Tests: `pinned_dot_accepts_expired_cert_with_matching_pin`
(`src/startup_dns/dot_tests.rs:1012`), `:1040-1042`, `:1067-1078`.


## Reject unknown ECH codepoint 0xffce fail-closed

The `0xffce` codepoint is treated as ECH-present and rejected fail-closed, consistent with the existing `0xfe0d` handling. The `0xff01` (`renegotiation_info`) codepoint is deliberately not folded in; it appears only in JA4 golden test vectors and is not an ECH signal.

The `encrypted_server_name` codepoint is folded into the same `has_ech` profile
fact as `encrypted_client_hello` (`src/client_hello.rs:51`, match arm
`src/client_hello.rs:669`), so `validate` rejects it with `ChError::EchPresent`
(`src/client_hello.rs:1063-1065`). Test: `rejects_esni_codepoint`
(`src/client_hello.rs:1431`).


## Fail-stop bailiwick suffix-slot bound


The flat union of declared `cname_bailiwick` suffixes is bounded by the Resource-Bounds
Invariant (§II. Memory & Resource Invariants): exhaustion rejects work rather than expanding storage without bound. The
config validator already rejects a suffix total above `ALLOWLIST_MAX`
(`CnameBailiwickTooMany`, `src/config.rs:1072-1077`; Display `src/config.rs:604`), so the
overflow is unreachable through validated configuration — this amendment makes the defence
structural. `from_allowlist` (`src/dns.rs:826`) now returns `Result<BailiwickZones, DnsError>`
and replaces the debug-only assert on the suffix slot with the typed
`DnsError::BailiwickSuffixOverflow { got, max }` fail-stop check, propagated at boot through
the new `StartupDnsError::BailiwickSuffixOverflow` variant (`src/startup_dns.rs`) so any future
divergence fails loudly and typed at boot rather than as a generic index-out-of-bounds panic.
Test: `from_allowlist_fails_stop_on_suffix_slot_overflow` (`src/dns.rs`).


## Capture cache generation at exchange start


Previously the apply step re-read the entry generation from the cache at the moment of
publication, so an exchange that started against generation *G* and applied after the entry
had advanced to *G*+1 would re-read *G*+1 and publish, defeating the guard. Now
`start_exchange` (`src/startup_dns.rs:2817-2824`) takes the generation captured by its
caller, and `ActiveExchange` carries it (`src/startup_dns.rs:236-240`); the apply step
(`src/startup_dns.rs:2413`) passes `ex.generation` to `apply_outcome`, so an obsolete
in-flight result is refused with `StaleGeneration` exactly as the guard intends. The
startup blocking driver captures the current entry generation before starting
(`src/startup_dns.rs:2950-2955`), and the serving seam does the same
(`src/serve.rs:519-531`). A post-window probe is a pure sensor that never applies cache
state, so its exchange carries `Generation::INITIAL` and never compares
(`src/startup_dns.rs:3148`). Test: `stale_generation_is_refused_at_apply`
(`src/startup_dns/tests.rs:1146`) bumps the entry generation while an exchange is in
flight and asserts the apply is refused.


## Bounded corroboration on sustained-negative open


The corroboration is a pure-sensor probe in the F-03 sense: it runs with the probe flag and
`Generation::INITIAL` (`src/startup_dns.rs`), so the receive step returns
`RecvStep::Published` before any cache apply and the corroboration never mutates the name
cache or the refresh schedule — byte-for-byte unchanged on both a consistent and a conflict
outcome. It is latched exactly once on the apply path when the sustained-negative incident
opens (`IncidentTransition::Opened`, `src/startup_dns.rs`), only for a set of at least two
resolvers, and is never overwritten or stacked. The serving owner begins it when the
transport is idle (`ServeStorage::step_corroboration`, `src/serve.rs`, driven from
`Runtime::turn` after the post-window probe sweep and before refresh scheduling,
`src/runtime.rs`); while any exchange or probe is in flight the begin defers, and a pending
request is never hijacked into a failback probe (`maybe_begin_failback` guard,
`src/startup_dns.rs`). The exchange is bounded: one begin consumes the pending request, and
no re-begin or retry follows its conclusion.

On conclusion, a consistent negative (or a positive with no eligible bindings) restores the
active resolver with no degradation change, no relocation, and no fact. A conflict — the
different resolver returned a positive with eligible bindings while the active resolver
returned a negative — emits the distinct `cc=` anomaly fact
(`DnsAnomalyKind::CorroborationConflict`, `src/enforcement/monitor.rs`, rendered in the
monitor record `src/log.rs`), advances the active resolver's degradation by exactly one
counted failure, and relocates a degraded active resolver to the next healthy resolver
(arming failback grace on a non-primary, mirroring the failover choke point) while a
below-threshold advance leaves it in place. A failed corroboration exchange (network) restores
the active resolver with no degradation change and no fact. The retained corroboration
connection is always closed so the next exchange re-dials the restored or relocated resolver.


## P-F09 closure: JA4 whole-monitor-record loss


Three claims are confirmed at source level. First, the fixed core is always encoded: the
always-emitted monitor summary (`encode_monitor_summary`, `src/log.rs:835`) carries the
aggregate counters and ALL aggregate overflow flags folded into `ofacts`
(`src/log.rs:858-864`: any-illegal, early-data, unknown, resolver-degraded, dns-anomaly,
downgrade-to-plain, probe-relocations, expired-pin-cert, ja4-change, ja4-seed) plus the
per-ordinal `dx` hex loss bitset (`src/log.rs:969-978`). The adversarial-population
worst-case test `logging_monitor_all_saturated_record_fits_the_2k_slot`
(`src/log.rs:3277`) saturates the whole Monitor (`saturate_all_for_test`) and asserts every
emitted record fits the 2 KiB slot, carrying `ofacts=1` / `ocapture_drops=1` / `sn=32` /
`js=4294967295` / `d31p` — the fixed core is never dropped. Family-split variants assert the
same worst case with serving-stale latched (`src/log.rs:3464`) and exactly one summary plus
3 domain and 3 capture batches each under the 2048 B cap (`src/log.rs:3499`).

Second, JA4 detail is sharded: per-ordinal `d<i>j` (change count), `d<i>v` (36-byte JA4
value), and `d<i>p` (latest-overflow peer IP) ride the best-effort `monitor_domain` detail
batches (`src/log.rs:1030-1060`), packed `DOMAIN_BATCH=11` ordinals per batch so 32
ordinals span 3 batches, never the fixed core. The counters live in
`FactCounters` (`src/enforcement/monitor.rs:12-27`): `ja4_change`
`[SaturatingCounter; ALLOWLIST_MAX]`, `ja4_change_loss` `[bool; ALLOWLIST_MAX]`, `ja4_value`
`[[u8; 36]; ALLOWLIST_MAX]`, `ja4_seed`, `ja4_peer_ip` `NumericAddr`, `ja4_peer_ordinal`
`Option<DomainOrdinal>`. The serving path keeps a fixed 512-entry zero-heap
`Ja4BaselineTable` (`src/serving.rs:557-582`, `ALLOWLIST_MAX` × `MAX_ADDRESSES` = 32 × 16)
with `BaselineOutcome { FirstSeen, Unchanged, Overflow }`; overflow counts as a change signal.

Third, an explicit loss flag exists on detail suppression:
`note_fact_ja4_change` (`src/enforcement/monitor.rs:272-284`) latches the per-ordinal
`ja4_change_loss` flag on overflow — the deviation decision fires regardless of set
capacity, but the overflowed value is not added to the set, so the operator sees detail was
suppressed. The summary always encodes the `dx` hex bitset of loss flags when any is set
(`src/log.rs:969-978`); the exact-grammar test
`logging_monitor_summary_exact_grammar_and_zero_suppression` (`src/log.rs:3145`) asserts the
summary carries the fixed core and the `dx` bitset while the single nonzero domain block
rides its `monitor_domain` batch.

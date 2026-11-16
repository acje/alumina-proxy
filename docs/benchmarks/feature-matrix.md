# Alumina — capability matrix vs Envoy and HAProxy

**Verified: 2026-11-15 · Envoy v1.40.2 · HAProxy v3.4.0.** Any version bump requires
re-verifying every row before this pin changes.

Provenance: one first-party evidence pass over official documentation and tagged source,
with no runtime verification. Absence of evidence is never graded as absence of
capability, and everything this pass did not establish is listed under Unconfirmed below.
Each row's mechanism and citation are recorded in bd `alumina-8bdgu`, keyed by row id.

## Legend

| Mark | Grade | Rule |
|---|---|---|
| `✓` | Exact | Same outcome; any mechanism difference is named in bd `alumina-8bdgu`. |
| `≈` | Similar | Same or closely related outcome by another mechanism — the specific difference is named in bd `alumina-8bdgu`, or the mark is downgraded to `?`. |
| `✗` | None | No first-party mechanism found for the pinned version (absence of evidence). |
| `?` | Unknown | Not established in this pass; never promoted to `✗` by assumption. |

The Alumina column is `✓` on every row: each row states an implemented Alumina control, so
that column is the reference the comparator columns are graded against, not a match against
itself. Grid columns are `A` = Alumina, `E` = Envoy v1.40.2, `H` = HAProxy v3.4.0. A `†`
after a row number marks a resource or telemetry contract rather than a security gate; `✗`
on such a row means no counterpart contract (a scope difference, not a missing control).
Each capability carries its governing spec section in parentheses.

## Matrix

Blocks are capability families; numbers are stable and never reused.

### A — Tunnel & wire contract

| # | Capability (§spec) | A | E | H |
|---|---|---|---|---|
| A1 | CONNECT tunnel; 200 sent before any client payload (§Protocol contract) | ✓ | ✓ | ≈ |
| A2 | Distinct pre-200 refusal classes (400/403/502/503/504) with static bodies (§Block and Notify semantics) | ✓ | ≈ | ≈ |
| A3 | Bounded CONNECT parse (8 KiB head, 16 header lines, bare-CR rejection, canonical decimal digits) (§L3, §Hardening: CONNECT header-line count bound) | ✓ | ? | ? |
| A4 | Opaque relay — no payload inspection, no TLS interception, proxy holds no keys (§Design philosophy) | ✓ | ✓ | ≈ |
| A5 | Two forwarding barriers: hold client bytes until the ClientHello validates; terminate if upstream speaks first (§Gate) | ✓ | ✗ | ≈ |

### B — ClientHello inspection

| # | Capability (§spec) | A | E | H |
|---|---|---|---|---|
| B1 | TLS 1.3-only ClientHello profile on a NON-terminated tunnel (§TLS ClientHello profile) | ✓ | ✗ | ≈ |
| B2 | SNI must equal the CONNECT authority hostname (§L10, §TLS profile) | ✓ | ✗ | ≈ |
| B3 | Structural ClientHello validation: exactly one `server_name` of `host_name` type, duplicate-extension rejection, GREASE skipping (§L8) | ✓ | ✗ | ≈ |
| B4 | ECH extension (0xfe0d, incl. GREASE form) rejected, never stripped (§Reject unknown ECH codepoint) | ✓ | ✗ | ✗ |
| B5 | JA4 fingerprint + first-seen baseline per destination + change signal (§JA4 tripwire, §C1) | ✓ | ✗ | ✗ |

### C — Authorisation & enforcement

| # | Capability (§spec) | A | E | H |
|---|---|---|---|---|
| C1 | Exact `<fqdn>:<port>` allowlist enforced before the upstream dial (§Keyed allowlist) | ✓ | ✓ | ✓ |
| C2 | Per-control actions (notify/block) scoped connection / destination / global (§T3, §T6) | ✓ | ≈ | ≈ |
| C3 | Threshold+window bar per violation class (§SP-001 gate sections) | ✓ | ≈ | ≈ |

### D — DNS assurance

| # | Capability (§spec) | A | E | H |
|---|---|---|---|---|
| D1 | Per-entry DNS assurance class: trusted / authenticated / delegated DNSSEC (§Hardening: per-entry DNS assurance) | ✓ | ✗ | ✗ |
| D2 | DoT to a strict SPKI-pinned resolver; unpinned fails closed (§DoT transport V1/V5) | ✓ | ✗ | ≈ |
| D3 | Resolver endpoint identity as `IP#fqdn` (§V37) | ✓ | ? | ? |
| D4 | CNAME bailiwick enforcement (§Explicit CNAME bailiwick) | ✓ | ✗ | ✗ |
| D5 | Reject non-global-unicast DNS answers (private/loopback/LL/CGNAT/NAT64/Teredo) (§Destination-address hardening) | ✓ | ≈ | ✗ |
| D6 | TTL clamp, zero-TTL handling, bounded stale serving (§Configuration & DNS, §F-10) | ✓ | ≈ | ✗ |
| D7 | Failover with consecutive-failure degrade + consecutive-success failback hysteresis (§V18, §Failback hysteresis) | ✓ | ≈ | ≈ |

### E — Runtime & resource

| # | Capability (§spec) | A | E | H |
|---|---|---|---|---|
| E1† | Guaranteed zero post-boot first-party heap allocation on the serving path (§Zero-Allocation Invariant) | ✓ | ✗ | ✗ |
| E2† | Fixed compile-time caps + distinct capacity refusal (512 tunnels, 128 pending, 2×128 KiB) (§Initial resource profile) | ✓ | ≈ | ≈ |
| E3† | Single boot owner + single serving owner (§Invariants III) | ✓ | ≈ | ≈ |
| E4† | Static single binary, no interpreter (§Design philosophy) | ✓ | ≈ | ≈ |
| E5 | Policy configurable only from a file — no CLI/env overrides (§Configuration) | ✓ | ✗ | ✗ |

### F — Lifecycle, telemetry & operations

| # | Capability (§spec) | A | E | H |
|---|---|---|---|---|
| F1 | Mandatory unprivileged preflight: non-root, empty caps, `no_new_privs=1`, refuse start (exit 78) (§L; §Deployment) | ✓ | ✗ | ✗ |
| F2 | stdout-only bounded log, whole-record drops counted, never blocks serving (§L18, §Monitoring) | ✓ | ≈ | ✓ |
| F3† | Record geometry: 2 KiB log slot, monitor family split, lossless peer-IP rendering (§2 KiB log slot) | ✓ | ✗ | ✗ |
| F4 | SIGTERM drain of established tunnels, non-extendable grace, distinct exit codes (0/70) (§Lifecycle) | ✓ | ≈ | ≈ |
| F5 | Terminal exit on unrecoverable stdout-sink failure (74), never continuing blind (§P-F09) | ✓ | ? | ? |

The reserved `tarpit` action is deferred and not configurable, so it is not a row here. The
benchmark measures configured subjects whose configurations are a small subset of their
capability ceilings, so throughput is not security equivalence: this matrix is the capability
view, the [benchmark method](e2-micro-1gbps.md) is the measurement view.

## Unconfirmed

- Envoy docs say the 200 is synthesized "on receipt of initial TCP data from upstream"; v1.40.2 code synthesizes it on upstream-pool-ready. Doc sentence may be stale; the code was cited.
- Whether a 400 body is emitted pre-200 for every malformed-CONNECT shape was not enumerated.
- Whether Lua/Wasm/ext_proc can read Envoy's JA4 hash was not traced.
- No dropped-record counter was found on Envoy's access-log surface, but not every sink was audited.
- Envoy's vendored BoringSSL ECH capability was not determined.
- Third-party extensions (Wasm, dynamic modules, Go filters) were not surveyed for either product.
- HAProxy 3.4 patch level: only `v3.4.0` was readable; patch drift unobserved.
- Whether `capture.req.uri` returns authority-form for CONNECT is not documented, so rows B2/C1 rely on `req.hdr(host)`.
- HAProxy class→code mapping for its own built-in statuses is not documented.
- HAProxy `answer_record->ttl` "never read" was verified within `src/resolvers.c` only.
- 3.2 LTS was keyword-diffed, not re-derived row by row.
- HAProxy auxiliary-thread inventory under `nbthread 1` was not observed.
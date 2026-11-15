# Alumina — capability matrix vs Envoy and HAProxy

**Verified: 2026-11-15 · Envoy v1.40.2 · HAProxy v3.4.0.** Any version bump requires
re-verifying every cited row before this pin changes.

Provenance: one first-party evidence pass over official documentation and tagged source,
with no runtime verification. Absence of evidence is never graded as absence of
capability, and everything this pass did not establish is listed under Unconfirmed below.

## Legend

| Grade | Rule |
|---|---|
| `Exact` | Same outcome; the mechanism may differ and is named in the Difference column. |
| `Similar` | Same or closely related outcome by another mechanism — the difference MUST be named in the same row, or the cell is downgraded to `Unknown`. |
| `None` | No first-party mechanism found for the pinned version (absence of evidence). |
| `Unknown` | Not established in this pass; never promoted to `None` by assumption. |

`Class` is `Gate` (security enforcement) or `Profile` (resource/telemetry contract). A
`Profile` row graded `None` means no counterpart contract (scope difference, not a defect).

## Matrix

Blocks are capability families; numbers are stable and never reused. Alumina is `Have` on
every row — all 30 controls are implemented — and `Spec` names the governing requirement.

### A — Tunnel & wire contract

| # | Capability | Class | Alumina | Envoy v1.40.2 | HAProxy v3.4.0 | Difference (mechanism, cited) | Spec |
|---|---|---|---|---|---|---|---|
| A1 | CONNECT tunnel; 200 sent before any client payload | Gate | Have | Exact | Similar | Envoy: `upgrade_configs[CONNECT]` + `connect_config`; 200 synthesized in `TcpUpstream::encodeHeaders` on upstream-pool-ready (`source/extensions/upstreams/http/tcp/upstream_request.cc:74-77@v1.40.2`). HAProxy: mux blocks client TX (`H1S_F_TX_BLK`) then tunnels, but never originates the 2xx — it relays the configured `server`'s 200, and the dial target is the `server` line, not the CONNECT authority (`src/mux_h1.c@v3.4.0:L2972-2987,L1537,L2275`). | §Protocol contract |
| A2 | Distinct pre-200 refusal classes (400/403/502/503/504) with static bodies | Gate | Have | Similar | Similar | Envoy: `LocalReplyConfig`/`ResponseMapper` remaps status+body, but class→code is Envoy's own default, not a declared per-class contract; 400 exists only at the HTTP/1 codec layer (`http_connection_manager.proto:1004`, `router.cc`, `codec_impl.cc:805@v1.40.2`). HAProxy: `deny status <code>` + inline body, and `errorfile` enumerates per-code bodies; no CONNECT-specific contract, each class is an authored ACL (`doc/configuration.txt@v3.4.0:L15755-L15770,L7611-L7645`). | §Block and Notify semantics |
| A3 | Bounded CONNECT parse (8 KiB head, 16 header lines, bare-CR rejection, canonical decimal digits) | Gate | Have | Unknown | Unknown | Not established in the 2026-11-15 pass. Both products bound request heads at the codec layer, but equivalence to this declared contract was not verified. | §L3, §Hardening: CONNECT header-line count bound |
| A4 | Opaque relay — no payload inspection, no TLS interception, proxy holds no keys | Gate | Have | Exact | Similar | Envoy: raw-TCP upstream via `connect_config`, no TLS role in the upstream path. HAProxy: tunnels after the relayed 2xx, but upstream is a fixed `server` (so destination binding is config, not the CONNECT authority). | §Design philosophy |
| A5 | Two forwarding barriers: hold client bytes until the ClientHello validates; terminate if upstream speaks first | Gate | Have | None | Similar | Envoy: `paused_for_connect_` is a connect-ordering pause, not a validation barrier; no early-upstream-byte rule; the HTTP `buffer` filter is documented as incompatible with upgrades. HAProxy: `tcp-request inspect-delay` provides barrier 1; barrier 2 is not expressible — after a CONNECT 2xx the mux switches to tunnel mode and stops applying content rules (`doc/configuration.txt@v3.4.0:L14486-L14515`, `src/mux_h1.c@v3.4.0:L2983-L2987`). | §Gate |

### B — ClientHello inspection

| # | Capability | Class | Alumina | Envoy v1.40.2 | HAProxy v3.4.0 | Difference (mechanism, cited) | Spec |
|---|---|---|---|---|---|---|---|
| B1 | TLS 1.3-only ClientHello profile on a NON-terminated tunnel | Gate | Have | None | Similar | Envoy: `tls_inspector` is a listener filter on the accepted socket's first bytes — on a CONNECT proxy those are the `CONNECT` line, so tunnel payload is never parsed; it also enforces only `max_client_hello_size` ≤ 16 KiB (`tls_inspector.cc:53,79,201,223,245@v1.40.2`). HAProxy: `req.ssl_*` parses the raw ClientHello and `req.ssl_ver` is checkable, but there is no compression-method fetch and no raw `supported_versions` (`doc/configuration.txt@v3.4.0:L27063-L27077,L27290-L27360`). | §TLS ClientHello profile |
| B2 | SNI must equal the CONNECT authority hostname | Gate | Have | None | Similar | Envoy: no component compares two independently parsed values; SNI is available only from a listener-terminated handshake. HAProxy: `req.ssl_sni` compared via `strcmp(var)` (documented domain-fronting example), but HAProxy's built-in CONNECT check is authority-vs-`Host`, not SNI-vs-authority, so this is authored (`doc/configuration.txt@v3.4.0:L23003-L23018,L27069-L27300`). | §L10, §TLS profile |
| B3 | Structural ClientHello validation: exactly one `server_name` of `host_name` type, duplicate-extension rejection, GREASE skipping | Gate | Have | None | Similar | Envoy: no structural validator; GREASE skipping exists only inside JA4 string construction, not as policy. HAProxy: raw walker requires `name_type == 0` and skips unknown types by declared length (so GREASE is inert), but there is no duplicate-extension rejection and "exactly one" is not derivable from fetches (`src/payload.c@v3.4.0:L864-L890`). | §L8 |
| B4 | ECH extension (0xfe0d, incl. GREASE form) rejected, never stripped | Gate | Have | None | None | Envoy: zero ECH awareness in protos or `tls_inspector`. HAProxy: ECH exists only as server-side decryption on terminated binds (`src/ech.c@v3.4.0:L413-L435`); no fetch exposes ECH presence for a tunnel. | §Reject unknown ECH codepoint |
| B5 | JA4 fingerprint + first-seen baseline per destination + change signal | Gate | Have | None | None | Envoy: `enable_ja4_fingerprinting` computes JA4 only where TLS terminates at the listener, stores it via `Socket::setJA4Hash`, is absent from `StreamInfo`, and there is no baseline store or change detection. HAProxy: zero case-insensitive `ja4` matches in the v3.4.0 tree; only JA3-shaped components, mostly `ssl_fc_*` (terminated). | §JA4 tripwire, §C1 |

### C — Authorisation & enforcement

| # | Capability | Class | Alumina | Envoy v1.40.2 | HAProxy v3.4.0 | Difference (mechanism, cited) | Spec |
|---|---|---|---|---|---|---|---|
| C1 | Exact `<fqdn>:<port>` allowlist enforced before the upstream dial | Gate | Have | Exact | Exact | Envoy: route `domains` match the CONNECT target including port; exact strings unless the operator writes a wildcard. HAProxy: ACL default matching is exact (`str`); caveat case-sensitive without `-i`, and per-destination dialing needs `do-resolve` + `set-dst`. | §Keyed allowlist |
| C2 | Per-control actions (notify/block) scoped connection / destination / global | Gate | Have | Similar | Similar | Envoy: connection = local reply; global = runtime keys + admin `/runtime`; destination-wide requires config/runtime mutation — no destination-keyed enforcement state. HAProxy: `deny`/`reject` = connection; a table keyed on the destination = all connections to it; no first-class scoped-action object, and notify-only is `log`/`do-log`. | §T3, §T6 |
| C3 | Threshold+window bar per violation class | Gate | Have | Similar | Similar | Envoy: `local_ratelimit` token bucket (`fill_interval` ≥ 50 ms) with runtime fractions; no per-violation-class counters and no peer-keyed "N bad handshakes in W" rule in-process. HAProxy: stick-tables (`expire`, `store http_err_cnt,http_req_rate(10s)`, `sc-inc-gpc0`, `deny if { sc0_http_req_rate gt N }`); no "block for W seconds" state, no per-class escalation. | §SP-001 gate sections |

### D — DNS assurance

| # | Capability | Class | Alumina | Envoy v1.40.2 | HAProxy v3.4.0 | Difference (mechanism, cited) | Spec |
|---|---|---|---|---|---|---|---|
| D1 | Per-entry DNS assurance class: trusted / authenticated / delegated DNSSEC | Gate | Have | None | None | Envoy: resolver config has no assurance concept (no AD-bit validation, no validator policy). HAProxy: `resolvers` section has no DNSSEC validation and no AD inspection. | §Hardening: per-entry DNS assurance |
| D2 | DoT to a strict SPKI-pinned resolver; unpinned fails closed | Gate | Have | None | Similar | Envoy: c-ares resolver proto carries plain addresses only — zero TLS occurrences, so no DoT at all. HAProxy: DoT reachable via stream prefix + `use_ssl`, but verification is CA-based (`verify required` + `ca-file`); no SPKI pinning exists. | §DoT transport V1/V5 |
| D3 | Resolver endpoint identity as `IP#fqdn` | Gate | Have | Unknown | Unknown | Not established in the 2026-11-15 pass. | §V37 |
| D4 | CNAME bailiwick enforcement | Gate | Have | None | None | Envoy: c-ares follows chains; Envoy filters only resulting addresses. HAProxy: the parser rejects an owner that is neither the queried name nor the previous CNAME target, but has no zone/bailiwick concept and does not query the target separately (`src/resolvers.c@v3.4.0:L1183-L1199,L1253-L1265`). | §Explicit CNAME bailiwick |
| D5 | Reject non-global-unicast DNS answers (private/loopback/LL/CGNAT/NAT64/Teredo) | Gate | Have | Similar | None | Envoy: `DnsCacheConfig.resolved_address_filter` is documented as an SSRF/rebinding control, but it is an operator-authored matcher on the DFPC path, with no built-in taxonomy and no IPv4-mapped/NAT64/Teredo normalisation. HAProxy: `resolve-net` is explicitly a preference, not a filter ("If no address matches … another address is selected"). | §Destination-address hardening |
| D6 | TTL clamp, zero-TTL handling, bounded stale serving | Gate | Have | Similar | None | Envoy: lower clamp via `dns_min_refresh_rate` (default 5 s); no upper clamp and no bounded stale-serving (failure refresh or cache-miss fail-closed). HAProxy: answer TTL is parsed but unread; lifetime comes from `hold valid`/`hold obsolete`, so no clamp and no zero-TTL case (`src/resolvers.c@v3.4.0:L1226,L1490`). | §Configuration & DNS, §F-10 |
| D7 | Failover with consecutive-failure degrade + consecutive-success failback hysteresis | Gate | Have | Similar | Similar | Envoy: resolver list + `use_resolvers_as_fallback` + per-attempt rotation; degradation state lives inside c-ares, neither configurable nor observable. HAProxy: `resolve_retries`/`timeout retry`/`hold valid`; `hold` is a time window, not a consecutive-failure counter, and failback is immediate ("marked UP immediately upon receiving a valid status"). | §V18, §Failback hysteresis |

### E — Runtime & resource

| # | Capability | Class | Alumina | Envoy v1.40.2 | HAProxy v3.4.0 | Difference (mechanism, cited) | Spec |
|---|---|---|---|---|---|---|---|
| E1 | Guaranteed zero post-boot first-party heap allocation on the serving path | Profile | Have | None | None | No such invariant in either product. Envoy: `OwnedImpl` ring growth reallocates plus per-request header maps. HAProxy: every stream allocates from a pool (`stream_new`, `src/stream.c@v3.4.0:L346-L352`); pools are preallocated but refilled. No counterpart contract (scope difference, not a defect). | §Zero-Allocation Invariant |
| E2 | Fixed compile-time caps + distinct capacity refusal (512 tunnels, 128 pending, 2×128 KiB) | Profile | Have | Similar | Similar | Envoy: overload manager + circuit breakers, runtime-configured; capacity refusal shares 503 with other classes. HAProxy: `SYSTEM_MAXCONN`/`tune.bufsize` are build-time, but exhaustion means "stop accepting" or a 503, not a distinct refusal. | §Initial resource profile |
| E3 | Single boot owner + single serving owner | Profile | Have | Similar | Similar | Envoy: `--concurrency 1` gives one worker, but a main thread plus auxiliary threads remain and the knob is a CLI flag. HAProxy: `nbthread 1`, but the default auto-selects CPU count on affinity-capable hosts and master-worker adds a non-serving master. | §Invariants III |
| E4 | Static single binary, no interpreter | Profile | Have | Similar | Similar | Envoy: `//source/exe:envoy-static` is a supported target; glibc/tcmalloc-linked, extensions may be dynamic modules. HAProxy: single native binary; default linkage is dynamic libc and TLS exists only with `USE_OPENSSL`. | §Design philosophy |
| E5 | Policy configurable only from a file — no CLI/env overrides | Gate | Have | None | None | Envoy: `--config-yaml` merges over the file, `--service-cluster` overrides file values, env affects `--concurrency`. HAProxy: the config supports `${VAR}` environment expansion and `-n` overrides `maxconn`. | §Configuration |

### F — Lifecycle, telemetry & operations

| # | Capability | Class | Alumina | Envoy v1.40.2 | HAProxy v3.4.0 | Difference (mechanism, cited) | Spec |
|---|---|---|---|---|---|---|---|
| F1 | Mandatory unprivileged preflight: non-root, empty caps, `no_new_privs=1`, refuse start (exit 78) | Gate | Have | None | None | Envoy: no uid/capability/`no_new_privs` check; only `--enable-core-dump`, the opposite direction. HAProxy: drop-privileges-after-bind model (it "must be started with superuser privileges"), zero `no_new_privs` occurrences, no start refusal. | §L; §Deployment |
| F2 | stdout-only bounded log, whole-record drops counted, never blocks serving | Gate | Have | Similar | Exact | Envoy: stdout access logger exists, but component logs go to stderr by default and no dropped-record counter is documented. HAProxy: `log stdout` = `fd@1`, unbuffered one-`writev`-per-record, `DroppedLogs` counter; caveat: the write happens on the serving thread (`src/log.c@v3.4.0:L1801-L1803`). | §L18, §Monitoring |
| F3 | Record geometry: 2 KiB log slot, monitor family split, lossless peer-IP rendering | Profile | Have | None | None | No counterpart contract in either product (scope difference, not a defect). | §2 KiB log slot |
| F4 | SIGTERM drain of established tunnels, non-extendable grace, distinct exit codes (0/70) | Gate | Have | Similar | Similar | Envoy: SIGTERM → immediate `instance.shutdown()`, no drain; a bounded drain exists only via admin `drain_listeners?graceful`/LDS, and CONNECT streams are explicitly RESET; exit codes are only SUCCESS/FAILURE. HAProxy: graceful drain is on SIGUSR1, SIGTERM closes immediately; `hard-stop-after` bounds the soft-stop; no drained-vs-forced exit codes documented. | §Lifecycle |
| F5 | Terminal exit on unrecoverable stdout-sink failure (74), never continuing blind | Gate | Have | Unknown | Unknown | Not established in the 2026-11-15 pass. | §P-F09 |

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

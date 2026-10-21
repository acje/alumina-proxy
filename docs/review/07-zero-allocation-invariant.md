# Group 7 — Zero-Allocation Invariant

**Subsystem:** serving-path allocation confinement across `src/startup_dns.rs`, `src/runtime.rs`, `src/serve.rs`, `src/config.rs`, `src/resolver.rs`, `src/schedule.rs`, `src/cache.rs`; rustls 0.23.46
**TRUE POSITIVE findings:** 10 (7 unique + 3 collapsed duplicates)
**Severity mix:** Critical ×1, High ×2, Medium ×2, Low ×2, +3 collapsed duplicates (High/Critical ×1, High ×1, High ×1)

---

## W2-L2b-F4 — Low — Zero-Allocation Invariant unqualified; DoT setup allocs reachable on serving refresh

**Scorecard row:**
```
| W2-L2b-F4 | Low | serving path | TRUE POSITIVE | FP,TP,TP,TP,TP → 4T-1F | high | Zero-Allocation Invariant unqualified (docs/alumina-proxy.md:211, covers "refreshing DNS"); DoT setup allocs reachable on serving refresh: starts_due_dns_if_idle (runtime.rs:274-295) → start_exchange (startup_dns.rs:2283-2284) → step_connect upgrade_to_tls (:1484-1486) → build_tls_connection (:766-780: Arc provider :769, Arc verifier :772, to_owned String :777, ClientConnection::new :780) + Box (:1562); per-refresh re-alloc because RecvStep::Published with !window_open → conclude_shared_transport → close_connection conn.take() (:2373-2375,:1092-1098,:1048), window_open true only in startup window (:979-999,:1093,:1110); alloc witnesses use bare-IP resolver ["1.1.1.1"] only (startup_dns/tests.rs:293, runtime/tests.rs:12), dot_tests.rs has zero alloc/run_phase refs → DoT path unwitnessed; docs scorecard :432-435 "no new serving-path runtime surface" inaccurate; Low fair (bounded per-connect, DoT-config only); 1 dissenting pass |
```

**Working description (alox-f, L2b):**
[Low] Alloc confinement on serving path — Zero-Allocation Invariant unqualified (covers "refreshing DNS"); DoT setup allocs reachable on serving refresh via `build_tls_connection`; per-refresh re-alloc because serving refresh always closes the transport; DoT path unwitnessed by alloc witnesses. Bounded per-connect, DoT-config only.

---

## W4-L4a-F2 — Low — boot-time `Vec::with_capacity` deviates from fixed-size pattern

**Scorecard row:**
```
| W4-L4a-F2 | Low | src/config.rs:714-722 | TRUE POSITIVE | TP,TP,TP,TP,FP → 4T-1F | high | Vec::with_capacity (config.rs:714) boot-time, bounded ≤5 (MAX_RESOLVERS resolver.rs:17, guard :711), transient (copied into fixed array resolver.rs:377-381,392-393, dropped); genuine deviation from resolver.rs fixed-array/no-heap pattern (resolver.rs:28-31 "no heap allocation (fixed profile)"); Zero-Allocation Invariant (docs/alumina-proxy.md:211) boot exemption → not a violation, Low fair; 1 dissenting pass (boot-exempt/bounded/transient → not an issue) |
```

**Working description (alox-f, L4a):**
[Low] `build_resolver_set` uses `Vec::with_capacity` during boot, `src/config.rs:714-722` — trivial (MAX_RESOLVERS=5) but deviates from the resolver.rs fixed-array/no-heap pattern; boot-exempt → not a violation.

---

## W5-L5a-F2 — Low — DUPLICATE of W4-L4a-F2 (collapsed)

> **Collapsed duplicate:** this row duplicates `W4-L4a-F2` (same root cause, re-reported by an independent scan). See the canonical row above.

**Scorecard row (verbatim):**
```
| W5-L5a-F2 | Low | src/config.rs:714-722 | TRUE POSITIVE | TP,FP,TP,TP,FP → 3T-2F | medium | DUPLICATE of W4-L4a-F2 (re-run): Vec::with_capacity (config.rs:714) boot-time, bounded ≤5 (MAX_RESOLVERS resolver.rs:17, guard :711), transient (copied into fixed array resolver.rs:377-381,392-393, dropped); genuine deviation from resolver.rs fixed-array/no-heap pattern (:28-31); Zero-Allocation Invariant (docs/alumina-proxy.md:211) boot exemption → not a violation, Low fair; 2 dissenting passes (boot-exempt/bounded/transient + Vec pervasive in config.rs → FP/Info) |
```

---

## W5-H5b-F1 — Critical — serving refresh re-creates rustls client post-boot (fixed-profile VIOLATION)

**Scorecard row:**
```
| W5-H5b-F1 | Critical | src/startup_dns.rs:2370-2377,1092-1098,766-781; runtime.rs:274-295 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | serving refresh closes transport after every published refresh (advance_exchange RecvStep::Published → if !window_open conclude_shared_transport :2370-2377 → close_connection conn.take()→None :1046-1048,:1092-1098); window_open true only in begin_window (:999, serving/startup.rs:54), cleared at window end (serving/startup.rs:213) + cancel_for_shutdown (:1110) → serving refreshes always close; next due refresh re-dials (starts_due_dns_if_idle runtime.rs:274-295 → start_dns_exchange serve.rs:432-444 → start_exchange dials when conn.is_none() :2283-2287 → begin_connect TcpStream::connect :1151-1181 → step_connect :1462 → upgrade_to_tls :1546 → build_tls_connection :766-781); build_tls_connection allocates (Arc::new(provider) :769, Arc::new(AluminaServerCertVerifier) :772, fqdn.to_owned() :777, ClientConnection::new(Arc::new(config),..) :780, Box::new(conn) :1562, no memoization); single-threaded serving (main.rs:27-122, all thread::spawn cfg(test)-only serve.rs:1237); contradicts docs/alumina-proxy.md:211 Zero-Allocation Invariant + architecture.md:116-120 §6 T1 + AGENTS.md; nuances: DoT-only reachability (bare-IP tls_target=None stays allocation-free); DoT amendment alumina-dot-chain-v1-v5 (:649-699) documents per-connect seam but asserts invariants unloosened (:697-699) → contradiction stands; bounded per-connect cost |
```

**Working description (alox-f, H5b):**
**F1 [Critical]** Serving-phase DoT refresh re-creates rustls client post-boot — fixed-profile VIOLATION: every published serving refresh closes the transport; the next due refresh re-dials and `build_tls_connection` allocates (`Arc` provider/verifier, `to_owned` fqdn, `ClientConnection::new`, `Box`) with no memoization; contradicts the Zero-Allocation Invariant (`docs/alumina-proxy.md:211`) + architecture §6 T1 + AGENTS.md. Nuance: DoT-only reachability (bare-IP stays allocation-free); bounded per-connect cost.

---

## W7-H7b-F1 — High/Critical — DUPLICATE of W5-H5b-F1 (collapsed)

> **Collapsed duplicate:** this row duplicates `W5-H5b-F1` (same root cause, re-reported by an independent scan). See the canonical row above.

**Scorecard row (verbatim):**
```
| W7-H7b-F1 | High/Critical | src/startup_dns.rs:766-781,1046-1076,1092-1098; serving/startup.rs:213; runtime.rs:314-327,274-295 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | serving refresh closes transport after every published refresh (advance_exchange RecvStep::Published → if !window_open conclude_shared_transport :2370-2377 → close_connection conn.take()→None :1046-1048,:1092-1098); window_open true only in begin_window (:999, serving/startup.rs:54), cleared at window end (serving/startup.rs:213) + cancel_for_shutdown (:1110) → serving refreshes always close; next due refresh re-dials (starts_due_dns_if_idle runtime.rs:274-295 → start_dns_exchange serve.rs:432-444 → start_exchange dials when conn.is_none() :2283-2287 → begin_connect TcpStream::connect :1151-1181 → step_connect :1462 → upgrade_to_tls :1546 → build_tls_connection :766-781); build_tls_connection allocates (Arc::new(provider) :769, Arc::new(AluminaServerCertVerifier) :772, fqdn.to_owned() :777, ClientConnection::new(Arc::new(config),..) :780, Box::new(conn) :1562, no memoization); single-threaded serving (main.rs:27-122, all thread::spawn cfg(test)-only serve.rs:1237); contradicts docs/alumina-proxy.md:211 Zero-Allocation Invariant + architecture.md:116-120 §6 T1 + AGENTS.md; nuances: DoT-only reachability (bare-IP tls_target=None stays allocation-free); DoT amendment alumina-dot-chain-v1-v5 (:649-699) documents per-connect seam but asserts invariants unloosened (:697-699) → contradiction stands; bounded per-connect cost |
```

---

## W5-H5b-F2 — High — rustls 0.23.46 allocates on TLS read/write serving path

**Scorecard row:**
```
| W5-H5b-F2 | High | rustls 0.23.46 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | Cargo.toml:201 rustls = "=0.23.46" (default-features=false, ring/std/tls12/logging), Cargo.lock:164-167; no allocator-avoidance/unbuffered feature in 0.23.46 (read_buf nightly-only, not enabled); inbound warm per-record alloc: ExpectTraffic::handle → take_received_plaintext (client/tls13.rs:1608-1610, server_conn.rs:1190) → received.append(bytes.into_vec()) (common_state.rs:554-557) → Payload::into_vec on Borrowed → bytes.to_vec() (base.rs:41-45) fresh heap Vec per inbound app-data message → ChunkVecBuffer VecDeque push (vecbuf.rs:75-87); outbound warm per-record alloc: writer().write → send_plain → encrypt_outgoing → Tls13MessageEncrypter::encrypt PrefixedPayload::with_capacity (ring/tls13.rs:204-222, outbound.rs:215-222) fresh Vec per outbound record; queue_tls_message → m.encode() (common_state.rs:507-510, outbound.rs:192-199) → sendable_tls.append VecDeque push (vecbuf.rs:16-27); reachable warm: step_recv try_recv read_tls/process_new_packets/reader().read (startup_dns.rs:1946-1975), step_send_tls tls_send_probe writer().write/drain_tls_write/write_tls (:2629-2671), only after handshake completes (SendReady/Receiving stages) → established connection; contradicts docs/alumina-proxy.md:211 + :679/:694 "confined to per-connect seam" + startup_dns.rs:221-222/:784-785 "exchange loop performs no heap allocation"; nuances: deframer sub-claim overstated (prepare_read steady-state no-op, shrink_to hint); load-bearing allocs = inbound to_vec + outbound PrefixedPayload/encode; bounded per-record (≤~16-18 KiB); citation nits (vecbuf.rs at src/vecbuf.rs; server_conn.rs:1190 is server variant, live client path common_state.rs:554-557) |
```

**Working description (alox-f, H5b):**
**F2 [High]** rustls 0.23.46 itself allocates on TLS read/write serving path — inbound fresh heap `Vec` per app-data message (`Payload::into_vec` → `bytes.to_vec()`), outbound fresh `Vec` per record (`PrefixedPayload::with_capacity` + `m.encode()`); reachable warm after handshake completes; contradicts the Zero-Allocation Invariant + "confined to per-connect seam". Bounded per-record (≤~16-18 KiB).

---

## W7-H7b-F2 — High — DUPLICATE of W5-H5b-F2 (collapsed)

> **Collapsed duplicate:** this row duplicates `W5-H5b-F2` (same root cause, re-reported by an independent scan). See the canonical row above.

**Scorecard row (verbatim):**
```
| W7-H7b-F2 | High | rustls 0.23.46 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | Cargo.toml:201 rustls = "=0.23.46" (default-features=false, ring/std/tls12/logging), Cargo.lock:164-167; no allocator-avoidance/unbuffered feature in 0.23.46 (read_buf nightly-only, not enabled); inbound warm per-record alloc: ExpectTraffic::handle → take_received_plaintext (client/tls13.rs:1608-1610, server_conn.rs:1190) → received.append(bytes.into_vec()) (common_state.rs:554-557) → Payload::into_vec on Borrowed → bytes.to_vec() (base.rs:41-45) fresh heap Vec per inbound app-data message → ChunkVecBuffer VecDeque push (vecbuf.rs:75-87); outbound warm per-record alloc: writer().write → send_plain → encrypt_outgoing → Tls13MessageEncrypter::encrypt PrefixedPayload::with_capacity (ring/tls13.rs:204-222, outbound.rs:215-222) fresh Vec per outbound record; queue_tls_message → m.encode() (common_state.rs:507-510, outbound.rs:192-199) → sendable_tls.append VecDeque push (vecbuf.rs:16-27); reachable warm: step_recv try_recv read_tls/process_new_packets/reader().read (startup_dns.rs:1946-1975), step_send_tls tls_send_probe writer().write/drain_tls_write/write_tls (:2629-2671), only after handshake completes (SendReady/Receiving stages) → established connection; contradicts docs/alumina-proxy.md:211 + :679/:694 "confined to per-connect seam" + startup_dns.rs:221-222/:784-785 "exchange loop performs no heap allocation"; nuances: deframer sub-claim overstated (prepare_read steady-state no-op, shrink_to hint); load-bearing allocs = inbound to_vec + outbound PrefixedPayload/encode; bounded per-record (≤~16-18 KiB); citation nits (finding cites buffers.rs:199-249 — actual ChunkVecBuffer in common_state.rs; vecbuf.rs at src/vecbuf.rs; server_conn.rs:1190 is server variant, live client path common_state.rs:554-557) |
```

---

## W5-H5b-F3 — High — zero alloc-witness coverage of DoT/failover surface

**Scorecard row:**
```
| W5-H5b-F3 | High | tests | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | dot_tests.rs has 0 run_phase/alloc refs (5 DoT tests functional only, dot_tests.rs:351-532); all alloc-witness tests plain-IP (startup_dns/tests.rs:291-296 ["1.1.1.1"], :1084-1134 cold-start witness; runtime/tests.rs:10-12, :1656-1738 warm refresh witness; serving/tests.rs:10-12 + 7 witnesses :4094,:5278,:5337,:5378,:5428,:6531,:6834); no pinned-resolver/FQDN/port-853 config in any run_phase test anywhere (grep pin-sha256/fqdn absent from runtime/serving witness tests); failover/failback tests (startup_dns/tests.rs:1651-1867) plain state-machine, unwitnessed; DoT path allocates (build_tls_connection startup_dns.rs:766-781: Arc provider :769, Arc verifier :772, to_owned :777, ClientConnection::new :780, Box :1562) reachable via FQDN entries (resolver.rs:202-208 port 853, :305-340 pin parse); invariant unfalsifiable for DoT/failover surface — a regression there passes the whole alloc-witness suite; nuance: DoT setup allocs documented bounded per-connect cost (startup_dns.rs:683-684,:761-765), finding is coverage/robustness claim, holds under either reading of boot-exemption |
```

**Working description (alox-f, H5b):**
**F3 [High]** Zero alloc-witness coverage of DoT/failover surface — `dot_tests.rs` has 0 `run_phase`/alloc refs; all alloc-witness tests are plain-IP; no pinned-resolver/FQDN/port-853 config in any `run_phase` test; failover/failback tests are plain state-machine, unwitnessed; invariant unfalsifiable for DoT/failover surface — a regression there passes the whole alloc-witness suite.

---

## W7-H7b-F3 — High — DUPLICATE of W5-H5b-F3 (collapsed)

> **Collapsed duplicate:** this row duplicates `W5-H5b-F3` (same root cause, re-reported by an independent scan). See the canonical row above.

**Scorecard row (verbatim):**
```
| W7-H7b-F3 | High | tests | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | dot_tests.rs has 0 run_phase/alloc refs (5 DoT tests functional only, dot_tests.rs:352-532); all alloc-witness tests plain-IP (startup_dns/tests.rs:291-296 ["1.1.1.1"], :1084-1134 cold-start witness; runtime/tests.rs:10-12, :1656-1738 warm refresh witness; serving/tests.rs:10-12 + 7 witnesses :4094,:5278,:5337,:5378,:5428,:6531,:6834); no pinned-resolver/FQDN/port-853 config in any run_phase test anywhere; failover/failback tests (startup_dns/tests.rs:1651-1867) plain state-machine, unwitnessed; DoT path allocates (build_tls_connection startup_dns.rs:766-781: Arc provider :769, Arc verifier :772, to_owned :777, ClientConnection::new :780, Box :1562) reachable via FQDN entries (resolver.rs:202-208 port 853, :305-340 pin parse); invariant unfalsifiable for DoT/failover surface — a regression there passes the whole alloc-witness suite; nuance: "no witness drives serving refresh" literally overstated — runtime/tests.rs:1694 due_refresh_owner_path_spends_zero_allocations drives a real serving refresh inside Phase::BackgroundRefresh but over bare-IP plain DNS (runtime/tests.rs:12); operative "none over TLS" holds; claim's witness list is a subset (omits runtime/tests.rs:1694, serving/tests.rs:4094-6834, tests/mio_matrix.rs, tests/eligibility.rs, tests/foundations.rs); DoT setup allocs documented bounded per-connect cost (startup_dns.rs:683-684,:761-765), finding is coverage/robustness claim, holds under either reading of boot-exemption |
```

---

## W5-H5b-F4 — Medium — boot alloc-zero claim holds only for plain DNS

**Scorecard row:**
```
| W5-H5b-F4 | Medium | boot alloc-zero claim holds only for plain DNS | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | sole boot-window witness startup_dns/tests.rs:1084-1134 (run_phase Phase::StartupDns :1090,:1111, asserts counts.all_zero() :1117 over storage.run_startup_within :1113) uses config() resolver=["1.1.1.1"] (tests.rs:291-296,:293) → tls_target None → upgrade_to_tls unreachable; no DoT config reaches any alloc-witness test (pin-sha256/fqdn only in dot_tests.rs functional + config/resolver parse tests, none run_phase-gated); DoT boot allocates in-window: begin_window seeds tls_target from primary fqdn (startup_dns.rs:995-998), resolve_window :2143-2150; step_connect :1485-1486 → upgrade_to_tls :1546 → build_tls_connection :766-781 (Arc :769,:772, to_owned :777, ClientConnection::new :780) + Box :1562; allocation precedes handshake (probe_tls_handshake :1564) so trips regardless of success; boot alloc-zero claim (docs/alumina-proxy.md:211,:235; tests.rs:1118) verified only for plain DNS; Medium fair (verification/claim-coverage gap, not runtime bug) |
```

**Working description (alox-f, H5b):**
**F4 [Medium]** Boot alloc-zero claim holds only for plain DNS — DoT-configured boot would trip the witness: the sole boot-window witness uses `resolver=["1.1.1.1"]` → `tls_target None` → `upgrade_to_tls` unreachable; DoT boot allocates in-window and allocation precedes the handshake, so it trips regardless of success. Verification/claim-coverage gap, not a runtime bug.

---

## W5-H5b-F5 — Medium — failover/failback re-seat re-dial inherits F1 on serving path

**Scorecard row:**
```
| W5-H5b-F5 | Medium | failover/failback re-seat re-dial | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | machine logic CONFINED (repoint_to_active startup_dns.rs:2441-2452, next_healthy_after_active :2458-2469, maybe_begin_failback :2477-2493, on_exchange_failed :2504-2528 — pure Copy/index/field mutation, no alloc); dial-after-reseat VIOLATION for DoT: every failure path closes conn before note_failure→on_exchange_failed→repoint_to_active sets self.addr (resolver.rs:202-208 port 853 iff fqdn); next exchange start_exchange :2283-2287 re-dials self.addr when conn.is_none() → step_connect :1484-1502 → upgrade_to_tls :1546-1570 → build_tls_connection :766-781 (Arc :769,:772, to_owned :777, ClientConnection::new :780) + Box :1562; serving path drives it (Runtime::serve runtime.rs:314-327 → turn :251-272 → starts_due_dns_if_idle :274-295 → start_dns_exchange serve.rs:432-444 → advance_exchange startup_dns.rs:2320-2385); UNWITNESSED: all alloc-witness tests bare-IP plain-DNS (startup_dns/tests.rs:291-296,:1086-1134; runtime/tests.rs:12,:1654-1738; serving/tests.rs:12), failover/failback tests (startup_dns/tests.rs:1650-1864) plain state-machine via resolver_set_of bare-IP, dot_tests.rs zero failover/run_phase refs; contradicts docs/alumina-proxy.md:211 Zero-Allocation Invariant; nuance: distinct from F1 (relocation-to-DoT-trigger entry point), genuinely unwitnessed; Medium fair |
```

**Working description (alox-f, H5b):**
**F5 [Medium]** Failover/failback re-seat re-dial inherits F1 on serving path — machine logic CONFINED (pure Copy/index/field mutation, no alloc), but dial-after-reseat VIOLATION for DoT: every failure path closes conn, next exchange re-dials `self.addr` → `upgrade_to_tls` → `build_tls_connection` allocates; UNWITNESSED by alloc witnesses. Distinct from F1 (relocation-to-DoT-trigger entry point), genuinely unwitnessed.

---

## W5-H5b-F7 — Low — anomaly counters/drains CONFINED

**Scorecard row:**
```
| W5-H5b-F7 | Low | anomaly counters/drains | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | anomaly counters/drains CONFINED — fixed arrays (`dns_anomalies: [u32; DnsAnomalyKind::COUNT=3]` startup_dns.rs:861,:929; monitor `[SaturatingCounter;3]` monitor.rs:14, COUNT=3 :34; `SaturatingCounter{value,overflow}` state.rs:6-9); bump-only (`note_dns_anomaly` saturating_add :1279-1281, monitor bump :156-159/state.rs:19-25; only test-only `saturate_for_test` state.rs:36-39); drain allocation-free (`take_dns_anomalies` mem::take :1285-1287; `drain_dns_anomalies` serve.rs:401-411 iter fixed-3 + const `from_index` monitor.rs:40-47; invoked advance_dns serve.rs:383 + run_startup_within serve.rs:601); ZAI docs/alumina-proxy.md:211 not contradicted; nuance: drain path run_phase-witness-covered (startup_dns/tests.rs:1084-1134 asserts all_zero :1116-1119), non-zero note path only non-witness unit tests (startup_dns/tests.rs:363,:401; monitor.rs:534-558) — "witness-covered" sub-part partial |
```

**Working description (alox-f, H5b):**
**F7 [Low]** Anomaly counters/drains CONFINED — fixed arrays (`[u32; DnsAnomalyKind::COUNT=3]`, `[SaturatingCounter;3]`), bump-only (`saturating_add`), drain allocation-free (`mem::take`, fixed-3 iter); ZAI not contradicted. Nuance: drain path run_phase-witness-covered; non-zero note path only non-witness unit tests.

---

## W5-H5b-F8 — Low — resolver-set data model CONFINED (inline Copy, heap-free)

**Scorecard row:**
```
| W5-H5b-F8 | Low | resolver-set data model CONFINED (inline Copy, heap-free) | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | resolver-set data model CONFINED — `ResolverSet { entries: [Nameserver; MAX_RESOLVERS=5], len }` resolver.rs:377-381, all Copy (ResolverSet :377, Nameserver :184-189, Fqdn `[u8;253]+len` :32-36, SpiPin `[u8;32]` :103-106); stored inline by value (Config.resolver config.rs:385, StartupDns.resolvers startup_dns.rs:831, seated begin_window :993, deref-copy serving/startup.rs:50); no Box/Arc/Vec in model or serving path; TlsTarget{fqdn,pin} Copy startup_dns.rs:676-679; "correct pattern" documented resolver.rs:28-31,:98-102 + docs/alumina-proxy.md:624; nuance: construction path transient boot-time `Vec::with_capacity` config.rs:714 + error-path Strings resolver.rs:237-243 — pre-boot, outside model/serving, scoped out by claim |
```

**Working description (alox-f, H5b):**
**F8 [Low]** Resolver-set data model CONFINED (inline Copy, heap-free) — `ResolverSet { entries: [Nameserver; MAX_RESOLVERS=5], len }`, all `Copy`, stored inline by value; no `Box`/`Arc`/`Vec` in model or serving path; correct pattern, anchor for F1/F5 fix.

---

## W5-H5b-F9 — Low — no new serving-path allocs or input-driven panics in window additions

**Scorecard row:**
```
| W5-H5b-F9 | Low | connect.rs/client_hello.rs/dns.rs window additions | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | all 3 files changed in window (connect.rs +186, client_hello.rs +57, dns.rs +500); every production addition is an error-returning guard over bounded input: connect.rs MAX_HEADER_LINES counter (connect.rs:267-272) bounded by 8 KiB head buffer + early TooManyHeaderLines return, parse_target authority-form guard (416-421) starts_with/windows(3) cannot panic on short targets, parse_request_line only error-variant refinements with .position()-bounded slicing; client_hello.rs HandshakeTooLarge gate (393-396) returns before any need-based indexing, 4+msg_len ≤ 0xFFFFFF no overflow; dns.rs BailiwickZones fixed stack array [DnsName;32] (769-816, DnsName=[u8;256]+len :44-48) no heap, from_allowlist indexing bounded by config-capped ALLOWLIST_MAX=32 (config.rs:882), zone_of split().count() lazy no alloc, parse_response additions (extreme_ttl, CnameCoexist, rdlen checks :912-1049) pure predicates with early Err, root_chain bailiwick check (1141-1143) calls pre-existing bounds-safe soa_covers; all vec!/Vec::with_capacity/expect/panic!/assert additions cfg(test)-only; from_allowlist runs startup/reload (startup_dns.rs:2046,:2152) not per-exchange serving path (startup_dns.rs:1869 passes pre-built &self.bailiwick); serving-path reachability confirmed (connect.rs via serving.rs:2105, client_hello.rs via serving.rs:2524, dns.rs via startup_dns.rs:1869); no new unsafe/unwrap/expect/panic or wire-derived indexing in any non-test added line |
```

**Working description (alox-f, H5b):**
**F9 [Low]** No new serving-path allocs or input-driven panics in `connect.rs`/`client_hello.rs`/`dns.rs` window additions — every production addition is an error-returning guard over bounded input; all `vec!`/`Vec::with_capacity`/`expect`/`panic!`/`assert` additions are `cfg(test)`-only; `from_allowlist` runs startup/reload, not the per-exchange serving path.

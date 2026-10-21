# Group 10 — Test / Coverage Gaps

**Subsystem:** `dot_tests.rs`, `dns.rs`, `connect.rs`, `startup_dns.rs`, `serve.rs`, `tests/*.rs`, `e2e_relay.py`
**TRUE POSITIVE findings:** 9
**Severity mix:** Medium ×1, Low ×3, Info ×4, Unknown ×1

---

## W1-H1a-F7 — Info — DoT adversarial responses not fed over TLS

**Scorecard row:**
```
| W1-H1a-F7 | Info | tests | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | TLS loopback responder serve_queries (dot_tests.rs:249-279) always replies echo_positive (140-171) — no wrong-TID/oversize/mangled path over TLS; adversarial steps (PositiveAMismatchedTid/Malformed/FragmentedPositive) only in plain-TCP tests.rs (471,514,831); oversize untested over any transport; parser-level coverage (dns.rs unit tests, fuzz.rs DnsWire) doesn't invalidate the transport-level gap; Info severity fair |
```

**Working description (alox-f, H1a):**
[Info] Test gap — DoT adversarial responses (wrong-TID/oversize/mangled) not fed over TLS.

---

## W1-H1b-F3 — Low — `TerminalWithoutData` branch untested

**Scorecard row:**
```
| W1-H1b-F3 | Low | src/dns.rs:1096-1098 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | TerminalWithoutData branch (dns.rs:1096-1098) fires iff RCODE=NXDOMAIN AND terminal owner has has_addr_data (set only by same-family A/AAAA, dns.rs:932/955); every NXDOMAIN test (dns.rs:1563,2160,2169,2190,2275; startup_dns/tests.rs:124-128) uses SOA-only or wrong-family records → flag false; two tests explicitly assert "never TerminalWithoutData" (dns.rs:2186,2201); fuzz harness (fuzz.rs:178-197) checks panic-freedom only, asserts no error variant; branch reachable from untrusted input → gap meaningful; Low fair |
```

**Working description (alox-f, H1b):**
F3 [Low] Test coverage gap — `TerminalWithoutData` (`dns.rs:1096-1098`) branch untested at base and HEAD.

---

## W2-H2a-F1 — Medium — V35 header-line bound not covered at integration level

**Scorecard row:**
```
| W2-H2a-F1 | Medium | V35 integration coverage gap | TRUE POSITIVE | TP,TP,TP,TP,TP → 5-0 | high | MAX_HEADER_LINES=16 (connect.rs:13), TooManyHeaderLines (:267-272), enforced serving path (serving.rs:2124-2131 via ConnectHeadReason::from_connect_error → refuse BadRequest, policy.rs:400); bound unit-tested only (connect.rs:826-842, in-module parse_full); zero integration/e2e over-long-head test: tests/*.rs send header-less 403 CONNECTs only (stdout_stall.rs:60, monitor_stdout.rs:69, main_thread_stack.rs:45), e2e_relay.py always single-Host head (:217-236), case list :31-60,:1065-1140 has no over-long case; docs claim implementation only (docs/alumina-proxy.md:507,:522; future-hardening-vectors.md:148); Medium fair |
```

**Working description (alox-f, H2a):**
[Medium] V35 integration coverage gap — header-line bound not covered at integration level.

---

## W2-H2a-F2 — Low — V19 valid-negative recovery untested

**Scorecard row:**
```
| W2-H2a-F2 | Low | V19 valid-negative recovery untested | TRUE POSITIVE | TP,TP,TP,TP,TP → 5-0 | high | V19 degraded state machine (startup_dns.rs:604 DEGRADED_AFTER=3, note_failure :613-626, note_success :628-630, on_exchange_failed :2504-2528, on_exchange_succeeded :2536-2547); valid negative counts as success (step_recv → RecvStep::Published :1899 → on_exchange_succeeded :2372; classify_published NxDomain/NoData → Negative :179-181); degraded-enter tested (tests.rs:1450,:1523); recovery tested only via positive A (tests.rs:1559-1627 Step::PositiveA :1564-1567) or direct on_exchange_succeeded unit calls (:1733,:1794); all valid-negative tests (tests.rs:335-1146) run from healthy state, never assert degradation; no test does 3-failures→Degraded→valid-negative→assert recovery/exit-crossing; dot_tests.rs/tests/*.rs zero degradation refs; Low fair |
```

**Working description (alox-f, H2a):**
[Low] V19 valid-negative recovery untested.

---

## W2-H2b-F6 — Low — hrdn3 coverage gaps (placeholder, reconstructed)

**Scorecard row:**
```
| W2-H2b-F6 | Low | hrdn3 test coverage | TRUE POSITIVE | T,T,T,T,T → 5-0 | high | placeholder (terse "coverage gaps"); concrete untested paths verified at HEAD: CnameTooDeep chain-length guard (dns.rs:1146-1148, MAX_CNAME_LINKS=8 :13) zero test refs anywhere (longest test chain = 2 links, dns.rs:1455-1456); real non-seam peer-mismatch branch (probe_connect startup_dns.rs:1532-1536) only reachable via cfg(test) force_peer_mismatch (:1526-1531; tests.rs:420); transport-level BailiwickViolation anomaly note (:1902-1903) never exercised (tests only assert bv==0, tests.rs:391,:436; Step responder enum tests.rs:10-40 has no CNAME variant); serve-level drain_dns_anomalies fold (serve.rs:401-411, called :383,:601) untested; positive rpm=/xttl= log emission (log.rs:531-537) untested (log.rs:1886-1890 assert only zero-suppression); parse-level bailiwick failure modes well covered (dns.rs:1436,:1450,:1465,:1486,:1422,:1944) → Low fair |
```

**Working description (alox-f, H2b):**
[Low] Coverage gaps (FINDING-6) — placeholder finding (terse "coverage gaps"). Concrete untested paths verified at HEAD: `CnameTooDeep` chain-length guard (zero test refs anywhere); real non-seam peer-mismatch branch only reachable via `cfg(test)` `force_peer_mismatch`; transport-level BailiwickViolation anomaly note never exercised; serve-level `drain_dns_anomalies` fold untested; positive `rpm=`/`xttl=` log emission untested.

---

## W4-H4a-F1 — Unknown — live handshake against real public DoT resolver not run

**Scorecard row:**
```
| W4-H4a-F1 | Unknown | live handshake not run | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | caveat holds: no test dials a real public DoT resolver — dot_tests.rs:1-5 declares "no real DoT resolver is ever dialed", all 5 DoT tests use embedded rustls responder on 127.0.0.1:0 (dot_tests.rs:320-321,:351,:382,:411,:440,:467), zero #[ignore]/network-gated tests, public IPs (1.1.1.1/8.8.8.8) only as config-parse fixtures or lo-bound aliases; e2e runs in --network none container with plain DNS only (e2e_relay.sh:280,:128), no port-853 dial anywhere; docs corroborate (alumina-proxy.md:683) |
```

**Working description (alox-f, H4a):**
[caveat] Live handshake against real public DoT resolver not run (no external dial) — Unknown.

---

## W4-H4b-F1 — Info — Q2: happy-path heavy in places

**Scorecard row:**
```
| W4-H4b-F1 | Info | Q2 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | "mixed; happy-path heavy in places" holds: fail-closed/security assertions present (dot_tests.rs:382 pin mismatch, :411 SAN mismatch, :440 empty root store — all failed=4/nothing published; startup_dns/tests.rs:1686,:1801 fail-closed; dns.rs:2227 candidates-exceeded) but happy-path pockets exist (tests.rs:1705,:1784 failback-recovery success arcs, dot_tests.rs:351 pure DoT exchange, dns.rs:2128 lone opposite-family acceptance); window overall skews fail-closed, "happy-path heavy" fair for specific pockets only (1 hedged pass) |
```

**Working description (alox-f, H4b):**
Q2 (new tests assert security behavior?): mixed — happy-path heavy in places.

---

## W4-H4b-F2 — Info — Q3: buffer-bounds oversize uncovered

**Scorecard row:**
```
| W4-H4b-F2 | Info | Q3 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | "uncovered security behaviors" holds narrowly: 4/5 listed behaviors ARE covered (fail-closed exhaustion tests.rs:1801,:1686,:1121 Exit75; pin mismatch dot_tests.rs:383; empty root store dot_tests.rs:441; no-fallback dot_tests.rs:400) but buffer-bounds oversize genuinely UNCOVERED — no test asserts MessageTooLong/QueryTooLong (dns.rs:852-853,:422,:437) or the length-prefix guard (startup_dns.rs:1858); fuzz target caps at DNS_MSG_LIMIT (fuzz.rs:180-181) so bound unreachable by fuzzing; all test responders build small replies; finding overstates breadth (4/5 covered) |
```

**Working description (alox-f, H4b):**
Q3 (uncovered security behaviors): gaps noted (fail-closed exhaustion, pin mismatch, empty root store, no-fallback, buffer bounds).

---

## W4-H4b-F3 — Info — Q4: `force_peer_mismatch` seam masks production detection

**Scorecard row:**
```
| W4-H4b-F3 | Info | Q4 | TRUE POSITIVE | FP,TP,TP,TP,TP → 4T-1F | high | force_peer_mismatch (startup_dns.rs:866-867 cfg(test), :1526-1531) short-circuits production peer==self.addr comparison (:1532); only test using it (tests.rs:401-443) dials the CORRECT peer (responder==nameserver) and forces the flag — never a real mismatched peer; peer_matches (:1272-1275) is a cfg(test)-only duplicate of the comparison, tested separately (tests.rs:1867-1884) → production detection path never verified with real values, a defect there would pass all tests; mismatch branch near-unreachable via real TCP bounds severity; 1 dissenting pass (seams benign, inject state production reaches via other routes) |
```

**Working description (alox-f, H4b):**
Q4 (test seams masking production): `force_peer_mismatch` etc. noted.

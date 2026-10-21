# Group 1 — DNS Parsing / Validation

**Subsystem:** `src/dns.rs` parser, bailiwick/CNAME handling, response validation
**TRUE POSITIVE findings:** 8
**Severity mix:** High ×2, Medium ×1, Low ×2, Info ×2, Low/Obs ×1

---

## W1-L1a-F2 — High — malformed SOA rdata validation gap

**Scorecard row:**
```
| W1-L1a-F2 | High | src/dns.rs:670 | TRUE POSITIVE | TP,TP,FP,TP,TP → 4T-1F | high | length check is additive-only; no cumulative sub-component validation of the 20-byte SOA tail; malformed fields pass |
```

**Working description (alox-f, L1a):**
[High] Protocol integrity, `src/dns.rs:670` — malformed SOA rdata validation gap: `rdlen != (used2-rd_start)+20 || used2+20 != end`; crafted SOA where used2+20==end but 20 bytes malformed/truncated fields; no cumulative sub-component length check.

---

## W1-L1a-F5 — Low — bailiwick check timing on terminal name

**Scorecard row:**
```
| W1-L1a-F5 | Low | src/dns.rs:1141 | TRUE POSITIVE | TP,FP,TP,TP,TP → 4T-1F | high | root_chain returns terminal (dns.rs:1152-1153,1157) without zones.covers() check on final name; 1 dissenting pass |
```

**Working description (alox-f, L1a):**
[Low] Protocol compliance, `src/dns.rs:1141` — bailiwick violation check timing: terminal name at end of root_chain not explicitly covered by `zones.covers()`.

---

## W1-H1a-F1 — High — bailiwick hard-fail breaks CDN chains

**Scorecard row:**
```
| W1-H1a-F1 | High | src/dns.rs:1141-1143,769-816 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5-0 | high | root_chain returns Err(BailiwickViolation) hard-fail (dns.rs:1141-1143); propagates via parse_response; startup_dns.rs:1902-1905 closes connection, no stale fallback; CDN-chain availability regression real |
```

**Working description (alox-f, H1a):**
[High] Availability/compat, `src/dns.rs:1141-1143, 769-816` — bailiwick hard-fail breaks CDN chains: allowlist holds customer zones; CDN chains terminate in CDN zone (*.cloudfront.net etc.) → allowlisted names resolve via stale grace then hard-fail with retries; silent availability regression vs base `:71` which permitted cross-suffix CNAME targets and `:128` promises CDN endpoints.

---

## W1-H1a-F6 — Info — bailiwick zone union widens CNAME pool

**Scorecard row:**
```
| W1-H1a-F6 | Info | src/dns.rs:787-798 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | BailiwickZones::from_allowlist = union across all allowlisted zones (dns.rs:787-798); covers any-zone (811-815); root_chain gates only on union covers (1141-1143) → cross-allowlist CNAME accepted, pinned by test accepts_apex_allowlist_subdomain_target (dns.rs:1485-1504); documented design, Info accurate |
```

**Working description (alox-f, H1a):**
[Info] Bailiwick zone union widens CNAME pool — cross-allowlist CNAME pollution (dns.rs:787-798).

---

## W1-H1b-F1 — Low — wrong-family CnameCoexist vestige (order-dependent)

**Scorecard row:**
```
| W1-H1b-F1 | Low | src/dns.rs:922-924,945-947 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | out-of-family A/AAAA branches return CnameCoexist when cname.is_some() (dns.rs:922-924,945-947); reverse order skips record (925-926,948-949) → EmptyNoerrorWithoutSoa (1087); order-dependence pinned by 4 tests (2060,2080,2100,2114); both orders reject → Low fair; vestige framing interpretive (docs :476 document reverse-direction fix only) |
```

**Working description (alox-f, H1b):**
F1 [Low] Wrong-family CnameCoexist vestige, `src/dns.rs:922-924, 945-947` — identical RR set {CNAME, opposite-family address} classifies differently by emission order (CNAME-then-AAAA → Err(CnameCoexist); AAAA-then-CNAME → Err(EmptyNoerrorWithoutSoa)); order-dependent classification, violates "truly ignored" contract.

---

## W1-H1b-F6 — Info — E3 strictness rejects whole response on bad glue rdlen

**Scorecard row:**
```
| W1-H1b-F6 | Info | E3 strictness | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | E3 guards in all three sections: answer via parse_rdata (dns.rs:629-655, called :917), authority (dns.rs:997-1010), additional/glue (dns.rs:1031-1044); each is return Err(BadRdataLength) inside per-record loop aborting entire parse_response; authority/additional added by E3 commit 1c98067; caller treats any Err as failed exchange (startup_dns.rs:1901-1907); no skip/isolate path; guard runs before family gate but well-formed out-of-family records (rdlen 4/16) still pass; no valid packet caught (A=4/AAAA=16 fixed by RFC 1035); pinned by rejects_malformed_a_rdlen_in_authority (dns.rs:1687-1703) + rejects_malformed_aaaa_rdlen_in_additional (dns.rs:1705-1721) with valid answer present; intentional fail-closed; Info fair |
```

**Working description (alox-f, H1b):**
F6 [Info] E3 strictness — any A/AAAA glue with non-4/16 rdlen rejects whole response (intentional fail-closed; no valid packet caught).

---

## W2-H2b-F2 — Medium — CDN-chain bailiwick availability

**Scorecard row:**
```
| W2-H2b-F2 | Medium | CDN-chain bailiwick | TRUE POSITIVE | T,T,T,T,T → 5-0 | high | hard-fail Err(BailiwickViolation) on every CNAME link target (dns.rs:1141-1143, loop-internal :1120-1156); union covers only allowlisted zones (from_allowlist :787-798, zone_of :821-829, soa_covers :1175-1185); Err → close+note_failure, nothing published, no stale rescue (startup_dns.rs:1901-1908; apply_outcome only on Ok :1887); retries deterministic-fail; mitigation = allowlist CDN apex → security widening (connect.rs:480-484; vec-32 weakened); base had no bailiwick check (aa12dc7^ dns.rs root_chain; spec :71); spec :128 promises CDN endpoints |
```

**Working description (alox-f, H2b):**
[Medium] CDN-chain bailiwick availability (FINDING-2).

---

## W6-H6b-F3 — Low/Obs — out-of-family A/AAAA silently skipped

**Scorecard row:**
```
| W6-H6b-F3 | Low/Obs | src/dns.rs:925,948 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | out-of-family A/AAAA without CNAME at same owner silently reader.skip(rdlen) confirmed: A-skip dns.rs:919-927 (family != A → ensure_owner, no-CNAME guard, skip :925), AAAA-skip :942-950 (skip :948); CNAME at owner yields CnameCoexist instead (no-CNAME condition exact); test accepts_lone_opposite_family_address_without_cname dns.rs:2128-2143 asserts skip (out != Err(CnameCoexist), == Err(EmptyNoerrorWithoutSoa)); no cross-family poisoning doubly guarded — skip path never writes owners[idx].addrs nor sets has_addr_data (bindings built only from addrs :1063-1065), cache entries family-keyed cache.rs:288-298 + StagedPositive::stage rejects cross-family FamilyMismatch cache.rs:170-174; liberal acceptance not fail-open (validated outcome, coexist invariant still enforced); "silently skip" accurate — DnsAnomalyKind has only 3 variants (monitor.rs:22-31), note_dns_anomaly only at startup_dns.rs:1480/1897/1903, dns.rs:925/948 emits no anomaly/log; Low/Obs fair; nuance: skip branch still ensure_owner-allocates a fixed-workspace slot (bounded, not security) |
```

**Working description (alox-f, H6b):**
F3 [Low/Obs] Out-of-family A/AAAA without CNAME at same owner silently `reader.skip(rdlen)` (`dns.rs:925,948`) — deliberate+tested (`accepts_lone_opposite_family_address_without_cname` :2128); publication keyed by query family → no cross-family poisoning; liberal acceptance, not fail-open. Optional: fold into DnsAnomalyKind.

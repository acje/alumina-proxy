# Group 9 — Docs / Doc-Drift

**Subsystem:** `AGENTS.md`, `docs/alumina-proxy.md`, `docs/verification.md`, `src/` doc comments and operator-facing strings
**TRUE POSITIVE findings:** 9
**Severity mix:** Medium ×1, Low ×2, Info ×6

---

## W1-H1a-F2 — Medium — AGENTS.md amendment list stale (governance/spec self-contradiction)

**Scorecard row:**
```
| W1-H1a-F2 | Medium | AGENTS.md | TRUE POSITIVE | TP,TP,TP,TP,TP → 5-0 | high | AGENTS.md:12-22 list stops at alumina-mema; spec records hrdn/hrdn2/hrdn3/hrdn4/v37/v1-v5 (docs/alumina-proxy.md:470,501,532,567,616,651); git log confirms stale AGENTS.md |
```

**Working description (alox-f, H1a):**
[Medium] Governance/spec self-contradiction — AGENTS.md amendment list stops at alumina-mema; hrdn/hrdn2/hrdn3/hrdn4/v37/v1-v5 absent; doc body clauses byte-identical to base but contradict appended amendments.

---

## W1-H1b-F2 — Low — V33 doc/runtime contract overstatement

**Scorecard row:**
```
| W1-H1b-F2 | Low | src/startup_dns.rs:1901-1908 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | EmptyNoerrorWithoutSoa is Err(DnsError) (dns.rs:246,1087; Display :308-311 "is not NODATA"); runtime every Err → close_connection + note_failure + RecvStep::Failed (startup_dns.rs:1901-1908) → backoff retry (schedule.rs:319-336); never published (classify_published only NxDomain/NoData, startup_dns.rs:171-183); V33 doc :476 "validated negative outcome... clean NODATA-class result" overstates; base spec :88/:97 agrees with code; Low fair |
```

**Working description (alox-f, H1b):**
F2 [Low] V33 doc/runtime contract overstatement — `EmptyNoerrorWithoutSoa` is an `Err(DnsError)`; runtime treats every Err as close + note_failure + reconnect (`startup_dns.rs:1901-1908`); never a published negative; only NXDOMAIN case is genuinely clean.

---

## W1-H1b-F7 — Info — hrdn amendment COUNT/KIND_COUNT stale vs code

**Scorecard row:**
```
| W1-H1b-F7 | Info | docs | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | docs/alumina-proxy.md:484 (hrdn, Vec 36) states COUNT=13/KIND_COUNT=18 with labels c13/a13; docs/alumina-proxy.md:507 (hrdn2, Vec 35) states 14/19 with c14/a14; code at HEAD: ConnectHeadReason has 14 variants (connect.rs:112-127), COUNT=14 (connect.rs:160); HelloRejectReason::COUNT=4 (client_hello.rs:233); KIND_COUNT=14+1+4=19 (policy.rs:21); live log labels c14/a14 (log.rs:1866,1894,1981); hrdn line ref connect.rs:148 stale (COUNT now at :160); vec-36 prose (docs/alumina-proxy.md:484) has "windows(3)://" as scheme example = .windows(3) slice call from connect.rs:418 leaked into prose; Info fair |
```

**Working description (alox-f, H1b):**
F7 [Info] Docs snapshot drift — hrdn amendment COUNT=13/KIND_COUNT=18 stale vs hrdn2 (14/19); vec-36 prose has accidental code-render.

---

## W2-H2a-F3 — Info — hrdn2 doc drift ×4 (placeholder, reconstructed)

**Scorecard row:**
```
| W2-H2a-F3 | Info | hrdn2 doc drift ×4 | TRUE POSITIVE | TP,TP,I,I,TP → 3T-2I | medium | placeholder finding (4 undetailed Info observations, unrecoverable verbatim); passes 1/2/5 reconstructed concrete Info observations that hold at HEAD: V19 doc citation drift (docs/alumina-proxy.md:511 cites startup_dns.rs:550/:536-546/:1804-1821, actual :604/:591-594/:2504/:2536 — symbols renamed by later hrdn4; serve.rs:381/:585 vs :382/:600); rd= is edge-triggered crossing count, not current-state bit (startup_dns.rs:2509-2511,:2540-2542; serve.rs:391-396); V35 empty-line continue unreachable (connect.rs:228-233 feed truncates at CRLFCRLF, :273-275 dead, disclosed docs:507); V14 floor 30→5 raises low-TTL refresh cadence (schedule.rs:5,:42-44); 2 dissenting passes: placeholder too underspecified → INDETERMINATE; majority TP, medium |
```

**Working description (alox-f, H2a):**
[Info] ×4 — placeholder finding (4 undetailed Info observations, unrecoverable verbatim). Majority-TP verdict reconstructed from 3 concrete Info observations that hold at HEAD: V19 doc citation drift (symbols renamed by later hrdn4); `rd=` is an edge-triggered crossing count, not a current-state bit; V35 empty-line continue unreachable; V14 floor 30→5 raises low-TTL refresh cadence.

---

## W2-H2b-F4 — Info — hrdn3 doc drift + `peer_matches` (placeholder, reconstructed)

**Scorecard row:**
```
| W2-H2b-F4 | Info | hrdn3 doc drift + peer_matches | TRUE POSITIVE | T,T,T,T,T → 5-0 | high | placeholder (2 undetailed Info); 2 concrete Info observations reconstructed and verified at HEAD: (1) hrdn3 doc line-ref drift in startup_dns.rs (docs/alumina-proxy.md:546,:550; future-hardening-vectors.md:125,:133): peer_matches cited :1010/:1090 → actual :1273; dns_anomalies :622→:861; note_dns_anomaly :1022→:1279; take_dns_anomalies :1028→:1285; step_connect peer check :1216-1223→:1462 (inline probe_connect :1518-1539); extreme-TTL :1412-1414→:1896-1898; drain_dns_anomalies serve.rs:603→:601; dns.rs refs (:769-816,:1142) accurate — drift confined to startup_dns.rs (hrdn4 failover shift); (2) peer_matches #[cfg(test)]-only (startup_dns.rs:1272-1275; tests.rs:1877,1881) but docs present it as production seam; production check inline probe_connect :1525-1536 (peer==self.addr); bv=/rpm=/xttl= keys consistent (log.rs:528,532,536) — rejected candidate |
```

**Working description (alox-f, H2b):**
[Info] ×2 (FINDING-4/5) — placeholder finding (2 undetailed Info observations, unrecoverable verbatim). Majority-TP verdict reconstructed from 2 concrete Info observations verified at HEAD: (1) hrdn3 doc line-ref drift in `startup_dns.rs` (drift confined to startup_dns.rs — hrdn4 failover shift; dns.rs refs accurate); (2) `peer_matches` is `#[cfg(test)]`-only but docs present it as a production seam; production check is inline in `probe_connect`.

---

## W3-H3a-F4 — Info — doc says relocation on "next counted failure"; code relocates on the same 3rd failure

**Scorecard row:**
```
| W3-H3a-F4 | Info | docs/alumina-proxy.md:594 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | doc says relocation on "next counted failure" after degradation; code relocates on the SAME 3rd failure — on_exchange_failed (startup_dns.rs:2504-2528) note_failure :2508 degrades at consecutive+1>=DEGRADED_AFTER then relocates atomically :2519-2527; code doc comment :2495-2503 confirms intent; doc also cites on_exchange_failed at :2012 (actual :2504); Info fair |
```

**Working description (alox-f, H3a):**
FINDING 4 [Info] Doc wording — `docs/alumina-proxy.md:594` says relocation happens on the "next counted failure" after degradation; code relocates on the SAME 3rd failure (degrades then relocates atomically in `on_exchange_failed`); doc also cites `on_exchange_failed` at a stale line ref.

---

## W3-H3a-F5 — Info — fixed-port-53 doc wording stale at HEAD

**Scorecard row:**
```
| W3-H3a-F5 | Info | docs/alumina-proxy.md:575,597,604 | TRUE POSITIVE | TP,TP,FP,FP,TP → 3T-2F | medium | docs/alumina-proxy.md:575/:597/:604 carry fixed-port-53 wording; :597 "Nameserver fixes the port at 53" false at HEAD — port is per-entry (853 iff fqdn, resolver.rs:202-208); Package 2 dial table (:659-665) is correct but does not explicitly supersede the hrdn4 port-53 statements; 2 dissenting passes: hrdn4 is accurate historical record predating FQDN/DoT; Info fair |
```

**Working description (alox-f, H3a):**
FINDING 5 [Info] Port 53 doc drift — `docs/alumina-proxy.md:575/:597/:604` carry fixed-port-53 wording; `:597` "Nameserver fixes the port at 53" is false at HEAD — port is per-entry (853 iff fqdn); Package 2 dial table is correct but does not explicitly supersede the hrdn4 port-53 statements. *(2 dissenting passes: hrdn4 is an accurate historical record predating FQDN/DoT.)*

---

## W3-H3b-F2 — Info — stale "future DoT" wording in source code

**Scorecard row:**
```
| W3-H3b-F2 | Info | src/resolver.rs:219-220; src/boot.rs:41-45; src/main.rs:53 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | stale "future DoT" wording in SOURCE code (resolver.rs:219-220, boot.rs:41-45, main.rs:53 operator warning) — uncorrected at HEAD though DoT implemented+wired (resolver.rs:202-208, startup_dns.rs:766-781, docs :649-699 "Implemented"); docs instances (:616/:626/:643/:647) are accurate historical records explicitly superseded by Package 2 (:651); main.rs:53 string would mislead operators; Info fair |
```

**Working description (alox-f, H3b):**
FINDING-2 [Info] Stale "future DoT" wording — `src/resolver.rs:219-220`, `src/boot.rs:41-45`, `src/main.rs:53` (operator warning) still describe DoT as future work, uncorrected at HEAD though DoT is implemented+wired; docs instances are accurate historical records explicitly superseded by Package 2; `main.rs:53` string would mislead operators.

---

## W5-H5a-F2 — Low — docs 7-root canonical set stale vs verify.sh 8 roots

**Scorecard row:**
```
| W5-H5a-F2 | Low | docs/verification.md:35-43 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | docs claim "7-root canonical set" + list 7 roots (verification.md:35-38) + "all 12 docs" (:39,:43); verify.sh:22 DOCSLINK_ROOTS has 8 roots (docs/future-hardening-vectors.md added in commit 38b6593, which did not touch verification.md); corpus count also stale (future-hardening-vectors.md now retained, absent from docs argv) |
```

**Working description (alox-f, H5a):**
F-02 [Low] `docs/verification.md:35-43` stale vs `verify.sh:22` — 7-root → 8-root set, docs corpus count stale.

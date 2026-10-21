# Group 4 — Resolver & Config Data Model

**Subsystem:** `src/resolver.rs` resolver set/FQDN/SPI-pin model, `src/config.rs` config document loading + validation
**TRUE POSITIVE findings:** 10 (9 unique + 1 collapsed duplicate)
**Severity mix:** Info/Low ×1, Low ×3, Info ×5, +1 collapsed duplicate (Info)

---

## W2-L2a-F1 — Low — SpiPin Debug redaction is value-independent

**Scorecard row:**
```
| W2-L2a-F1 | Low | src/resolver.rs:131 | TRUE POSITIVE | TP,TP,FP,TP,TP → 4T-1F | high | Debug impl prints constant "SpiPin([redacted])" (resolver.rs:128-133, value-independent); redaction intentional (:130 "never print its bytes"); Option<SpiPin> (resolver.rs:188) distinguishes missing vs present today; finding hedges "fine today"/"if type expanded"; genuine Info/Low Debug-hygiene observation, 1 dissenting pass |
```

**Working description (alox-f, L2a):**
[Low] Information leak / Debug hygiene, `src/resolver.rs:131` — `SpiPin` Debug prints a constant redaction; fine today but cannot distinguish "missing" vs "redacted" if type expanded. Observation.

---

## W3-H3a-F1 — Low — duplicate resolver entries accepted (no dedup)

**Scorecard row:**
```
| W3-H3a-F1 | Low | src/resolver.rs:387-398; src/config.rs:709-726 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | ResolverSet::from_slice (resolver.rs:387-398) + build_resolver_set (config.rs:709-726) accept duplicates with no dedup; index-based relocation next_healthy_after_active (startup_dns.rs:2458-2469) can dial the same peer that just failed ([A,A] → index 1 = same A); allowlist path DOES reject duplicates (config.rs:454,:891) — pattern exists but not applied to resolvers; Low fair (availability footgun) |
```

**Working description (alox-f, H3a):**
FINDING 1 [Low] Duplicate resolver entries accepted — `ResolverSet::from_slice` + `build_resolver_set` accept duplicates with no dedup; index-based relocation can dial the same peer that just failed; allowlist path rejects duplicates but the pattern is not applied to resolvers.

---

## W3-H3b-F1 — Low — all-numeric final label accepted as FQDN but invalid SNI

**Scorecard row:**
```
| W3-H3b-F1 | Low | src/resolver.rs:45-78 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | resolver Fqdn::parse (resolver.rs:45-78) accepts all-numeric final labels; rustls ServerName rejects them ("example.123" → Err at startup_dns.rs:777-779; "1.2.3.4" → ServerName::IpAddress, no SNI, fails cert verify) → DoT resolver permanently non-functional, fail-closed but undiagnosed (generic Connect failure); allowlist Fqdn type (config.rs:17-78, is_ip_literal_shape :55-57) is a DIFFERENT type that rejects IP literals — genuine asymmetry; Low fair |
```

**Working description (alox-f, H3b):**
FINDING-1 [Low] All-numeric final label accepted as FQDN but invalid SNI — `resolver Fqdn::parse` accepts all-numeric final labels; rustls `ServerName` rejects them → DoT resolver permanently non-functional, fail-closed but undiagnosed (generic Connect failure); allowlist `Fqdn` type rejects IP literals — genuine asymmetry.

---

## W3-H3b-F4 — Info — `#fqdn`/`#pin-sha256=` suffixes count against the 4 KiB bound

**Scorecard row:**
```
| W3-H3b-F4 | Info | src/config.rs:603-625 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | 4 KiB bound (config.rs:603-625, CONFIG_DOC_LIMIT=4096 :10) measures raw on-disk TOML bytes including #fqdn/#pin-sha256= suffixes; repo's own tests pin over-limit totals (config.rs:1204-1267: 4084 B compact fits, 4103 B with IP#fqdn rejected, 4151 B with pinned rejected; golden 5×IP#fqdn = 437 B fits at :1497-1522); suffixes not "free" — Info fair |
```

**Working description (alox-f, H3b):**
FINDING-4 [Info] `#fqdn` strings count against 4 KiB bound — the cap measures raw on-disk TOML bytes including `#fqdn`/`#pin-sha256=` suffixes; repo's own tests pin over-limit totals; suffixes not "free".

---

## W4-L4a-F3 — Info — 4 KiB preflight robust (capped read, double-checked)

**Scorecard row:**
```
| W4-L4a-F3 | Info | src/config.rs:603-625 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | read capped via file.take((CONFIG_DOC_LIMIT+1) as u64) (config.rs:609-610), CONFIG_DOC_LIMIT=4096 (:10); double-checked at :615-620 and again :636-641; no re-read/TOCTOU (same buffer, opened/read once); sole production loader boot.rs:70; positive claim holds at HEAD |
```

**Working description (alox-f, L4a):**
[Info] 4 KiB preflight robust, `src/config.rs:603-625` — capped read at `CONFIG_DOC_LIMIT+1`, double-checked, no re-read/TOCTOU (same buffer, opened/read once); sole production loader `boot.rs:70`.

---

## W5-L5a-F3 — Info — DUPLICATE of W4-L4a-F3 (collapsed)

> **Collapsed duplicate:** this row duplicates `W4-L4a-F3` (same root cause, re-reported by an independent scan). See the canonical row above.

**Scorecard row (verbatim):**
```
| W5-L5a-F3 | Info | src/config.rs:603-625 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | DUPLICATE of W4-L4a-F3 (re-run): read capped via file.take((CONFIG_DOC_LIMIT+1) as u64) (config.rs:609-610), CONFIG_DOC_LIMIT=4096 (:10); double-checked at :615-620 and again :636-641; no re-read/TOCTOU (same buffer, opened/read once); sole production loader boot.rs:70; cap on raw bytes pre-TOML; pinned tests/boot.rs:67-93, config.rs:1174-1282 |
```

---

## W7-H7a-F1 — Info/Low — resolver array accepts exact duplicates (NEW-ISSUE)

**Scorecard row:**
```
| W7-H7a-F1 | Info/Low | src/config.rs:709-726; resolver.rs:305-340,387-398 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | resolver array accepts exact duplicates, no dedup at HEAD: build_resolver_set (config.rs:709-726) — require_string_list (:710, no dedup :838-864), count-only check (:711-713, MAX_RESOLVERS=5 resolver.rs:17), per-entry select (:715-722), from_slice (:723-725); select (resolver.rs:305-340) single-token parse, no cross-entry comparison; from_slice (:387-398) count-only guard, copies verbatim — duplicates coexist; resolver=["1.1.1.1"×5] parses+boots clean (test resolver_five_accepted config.rs:1353-1369; 6 rejected :1383-1395); allowlist rejects duplicates via HashSet+DuplicateAllowlistName (config.rs:885-894) — asymmetry holds ("dedup" wording loose: allowlist rejects, not dedups); failover diversity reduced — per-index degradations (startup_dns.rs:842), next_healthy_after_active advances by index (:2458-2469), repoint_to_active dials set.get(index) (:2441-2452), duplicates dial same address, effective distinct count 1 while set_len=5; NEW-ISSUE confirmed — git show 3bb5865 introduces resolver field+build_resolver_set+ConfigError::{ResolverCountOutOfRange,InvalidResolver}, 3bb5865^ has none, ancestor of HEAD; Nameserver derives PartialEq,Eq (resolver.rs:184) so dedup fix straightforward |
```

**Working description (alox-f, H7a):**
F1 [Info/Low] Resolver array accepts exact duplicates, no dedup at HEAD — `build_resolver_set` + `from_slice` copy verbatim, count-only guard; `resolver=["1.1.1.1"×5]` parses+boots clean; allowlist rejects duplicates (asymmetry holds); failover diversity reduced (duplicates dial same address, effective distinct count 1 while `set_len=5`); NEW-ISSUE confirmed — introduced by commit `3bb5865` (ancestor of HEAD); `Nameserver` derives `PartialEq,Eq` so dedup fix straightforward.

---

## W7-H7a-F2 — Low — bare-IP entry → cleartext port 53, stdout-only warning

**Scorecard row:**
```
| W7-H7a-F2 | Low | src/resolver.rs:201-208; boot.rs:46-51; main.rs:51-56 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | bare-IP entry → cleartext port 53: RESOLVER_PORT=53 (resolver.rs:4), DOT_PORT=853 (:9); port() returns DOT_PORT only when fqdn.is_some() else RESOLVER_PORT (:201-208); bare-IP parsed fqdn:None (select :305-317); cleartext transport DnsConn::Plain(TcpStream) for bare-IP (startup_dns.rs:685-688), "plain TCP for a bare-IP resolver... dials plain DNS with no TLS upgrade" (:681-684,:790-797), tls_target None for bare-IP (:765,:995,:2037-2047,:2447), TLS upgrade gated on tls_target Some (:1485-1502), dial addr SocketAddr::new(resolver.addr(),resolver.port()) (:2446-2450), TcpStream::connect (:1156), main.rs:84-87 builds startup dial from primary().addr()+port(); warning stdout-only sole signal: boot.rs:46-51 ip_only_resolvers() filters all fqdn().is_none() (all bare-IP entries, unconditional), main.rs:51-56 println! (stdout, not stderr) "alumina: warning: resolver {} has no FQDN ... plain DNS over port 53 only", boot proceeds no exit; no DoT-only toggle: config.rs:659-674 accepts only 6 top-level keys (allowlist|listen|startup_unresolved_allowance|resolver|any_illegal|actions), unknown rejected, build_resolver_set (:709-726) accepts bare-IP no rejection, main.rs:17-19 no CLI/env policy reads, no std::env::var/args() policy reads; intentional documented design (resolver.rs:197-200,:219-222,:300-301; boot.rs:41-45; startup_dns.rs:672-684), DoT entries never fall back to plain (resolver.rs:210-213; dot_tests.rs:400); "silently" slightly strong (warning exists) but finding itself qualifies "only a stdout warning"; stdout not stderr → lost when piped; tests pin behavior: resolver.rs:526-536, boot.rs:227-234, config.rs:1469-1473 |
```

**Working description (alox-f, H7a):**
F2 [Low] Bare-IP resolver entries silently dial cleartext DNS on 53, only a stdout warning — `port()` returns 853 iff `fqdn.is_some()` else 53; cleartext `DnsConn::Plain` for bare-IP; no DoT-only toggle; intentional documented design, DoT entries never fall back to plain; "silently" slightly strong (warning exists) but warning is stdout-only (lost when piped).

---

## W7-H7a-F3 — Info — config collapses distinct resolver sub-reasons into one `InvalidResolver`

**Scorecard row:**
```
| W7-H7a-F3 | Info | src/config.rs:717-721 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | collapse explicit and total: config.rs:717-720 map_err(\|_\| ConfigError::InvalidResolver{index, value: value.clone()}) — \|_\| discards entire ResolverError; sole production call site of resolver::select (config.rs:717); 7 distinct discriminants below: resolver.rs:235-244 ResolverError { InvalidAddress, NonUnicastAddress, ZonedAddress, InvalidFqdn, WildcardFqdn, IdnFqdn, InvalidPin } each value: String; produced by select (:305-340) + parse_ip (:344-364), FQDN path maps FqdnError → InvalidFqdn/WildcardFqdn/IdnFqdn (:321-331), pin path InvalidPin (:334-336), exercised by resolver tests (:456-726) — real reachable sub-reasons; InvalidResolver payload index: usize + value: String only (config.rs:485-488), no source field, no #[source]; Display generic message enumerating all formats (config.rs:585-589) — doesn't state which validation failed; diagnostic-precision-only accurate: exit_status() constant 78 for all variants (config.rs:491-496), behavior unaffected, index+value preserved → operator knows which entry and what value, only the why (reason) lost; nuance: finding's "cannot tell which entry... or why" slightly overbroad on first half (index+value preserved), core claim holds |
```

**Working description (alox-f, H7a):**
F3 [Info] Config layer collapses distinct resolver sub-reasons into one `InvalidResolver` — `map_err(|_| ...)` discards the entire `ResolverError` (7 distinct reachable discriminants); `index`+`value` preserved so operator knows which entry and what value, only the *why* is lost; diagnostic-precision-only, behavior unaffected.

---

## W7-H7a-F4 — Info — dead/misleading `ActionsLengthMismatch{expected: ALLOWLIST_MAX}` branch

**Scorecard row:**
```
| W7-H7a-F4 | Info | src/config.rs:692-698 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | ALLOWLIST_MAX=32 (config.rs:12); ActionsLengthMismatch defined :477-481; build_allowlist (:878-898) rejects empty AllowlistEmpty :879-881 and >ALLOWLIST_MAX AllowlistTooMany :882-884 → allowlist.len()∈1..=32 before :692; parse_actions (:752-802) enforces kinds.len()!=allowlist_len \|\| scopes.len()!=allowlist_len → Err(ActionsLengthMismatch{expected: allowlist_len}) at :768-774 (the REACHABLE construction), zip loop emits exactly allowlist_len entries → domain_actions.len()==allowlist.len()∈1..=32; ControlTable::new (enforcement/action.rs:142-158) returns None only when count==0 \|\| count>ALLOWLIST_MAX :147-149, doc :139-141 "config path supplies exactly the allowlist count, within bound"; from_table (config.rs:655) sole production caller of ControlTable::new at :692 (other call sites state.rs:200, monitor.rs:493, policy.rs:103, action.rs:199-208 all #[cfg(test)]); else branch :692-698 unreachable; expected: ALLOWLIST_MAX (:696) misleading — actual invariant len==allowlist_len∈1..=32, reachable site uses expected: allowlist_len :769-773, Display :573-580 "must equal allowlist length {expected}" would misreport; secondary nit got_kind/got_scope both set to domain_actions.len() :694-695; test rejects_actions_length_mismatch (config.rs:1104-1117) exercises reachable :769 path only; dead code not correctness bug, Info appropriate |
```

**Working description (alox-f, H7a):**
F4 [Info] Dead/misleading `ActionsLengthMismatch{expected: ALLOWLIST_MAX}` branch — the `else` branch at `config.rs:692-698` is unreachable from production (`ControlTable::new` sole production caller at `:692`; reachable construction uses `expected: allowlist_len` at `:768-774`); `expected: ALLOWLIST_MAX` misleading; dead code, not a correctness bug.

---

## W7-H7a-F5 — Info — UTF-8 BOM silently stripped by toml lexer; cannot bypass 4 KiB bound

**Scorecard row:**
```
| W7-H7a-F5 | Info | src/config.rs:608-620 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | CONFIG_DOC_LIMIT=4096 (config.rs:10); load_config_document (:608-620) file.take((CONFIG_DOC_LIMIT+1) as u64).read_to_end(&mut buf), if buf.len() > CONFIG_DOC_LIMIT → OversizedDocument, raw byte length before from_utf8 (:621) and before toml::from_str (:624); parse_config_document (:635-641) second gate doc.len() > CONFIG_DOC_LIMIT before toml::from_str (:642); from_utf8 preserves BOM bytes (valid UTF-8 U+FEFF) → BOM counts in both buf.len() and doc.len(); BOM silently stripped by toml lexer: Cargo.toml:183 toml = "=1.1.8" features std,parse,serde; Cargo.lock:271-283 toml 1.1.8+spec-1.1.0 → toml_parser 1.1.5+spec-1.1.0 (:295-301) → winnow 1.0.4 (:416-419); toml::from_str → Deserializer::parse → de/parser/mod.rs:32 source.lex().into_vec() → Source::lex (source.rs:19-20) → Lexer::new (lexer/mod.rs:33-45) if input.as_bytes().starts_with(BOM) { stream.next_slice(offset) }; const BOM = b"\xEF\xBB\xBF" (lexer/mod.rs:81) — skipped no error/token; no bypass: cap on raw bytes, parsing content-reducing, effective content ≤ raw ≤ 4096, BOM reduces budget by 3 (max effective 4093); sole production loader boot.rs:70 → load_config_document; Info robustness note, PRESERVED accurate; BOM strip is spec-mandated TOML 1.1 behavior; no in-repo BOM test |
```

**Working description (alox-f, H7a):**
F5 [Info] UTF-8 BOM silently stripped by toml lexer; cannot bypass 4 KiB bound — cap is on raw bytes before parse, BOM counts toward the budget (max effective content 4093); BOM strip is spec-mandated TOML 1.1 behavior; no in-repo BOM test.

# Group 2 — DoT / TLS Transport

**Subsystem:** `src/startup_dns.rs` TLS upgrade, `src/resolver.rs` port/pin selection, `src/main.rs`/`src/boot.rs` warnings
**TRUE POSITIVE findings:** 5
**Severity mix:** Low ×3, Info ×2

---

## W1-H1a-F3 — Low — unpinned IP#fqdn DoT fails closed against empty root store

**Scorecard row:**
```
| W1-H1a-F3 | Low | src/startup_dns.rs (dot_tests.rs:441-465) | TRUE POSITIVE | TP,TP,TP,TP,TP → 5-0 | high | unpinned IP#fqdn → verify_server_cert_signed_by_trust_anchor(&cert, &RootCertStore::empty()) (startup_dns.rs:728-734) → any chain fails; pin optional (resolver.rs:305-340); no startup warning on failing path (main.rs:51-56, boot.rs:237-243); test asserts failed==4/exchanges==0 (dot_tests.rs:441-465); intended fail-closed-by-design, Low footgun accurate |
```

**Working description (alox-f, H1a):**
[Low] Operational footgun — unpinned IP#fqdn DoT validates against empty root store → deterministic fail-closed (dot_tests.rs:441-465); easy to trip.

---

## W1-H1a-F5 — Info — TLS-profile drift (client vs serving)

**Scorecard row:**
```
| W1-H1a-F5 | Info | TLS-profile drift | TRUE POSITIVE | TP,TP,TP,TP,TP → 5-0 | high | DoT client with_safe_default_protocol_versions → TLS1.2+1.3 (startup_dns.rs:770; rustls DEFAULT_VERSIONS, tls12 feature Cargo.toml:201, dual verifier :744/:753); serving validate_versions TLS1.3-only (client_hello.rs:512-527, enforced serving.rs:2552); drift real, benign/Info |
```

**Working description (alox-f, H1a):**
[Info] TLS-profile drift — DoT client TLS1.2+1.3 vs serving TLS1.3-only.

---

## W2-L2b-F5 — Info — empty root store (no-pin DoT can never complete handshake)

**Scorecard row:**
```
| W2-L2b-F5 | Info | empty root store | TRUE POSITIVE | TP,TP,TP,TP,TP → 5-0 | high | no-pin IP#fqdn branch calls verify_server_cert_signed_by_trust_anchor(&cert, &RootCertStore::empty(), ...) (startup_dns.rs:728-734); empty store (only RootCertStore ref is :730, no webpki-roots/add_trust_anchor anywhere) ⇒ chain validation always fails ⇒ handshake deterministically fails closed; IP#fqdn (pin None) is a legal DoT entry on port 853 (resolver.rs:305-340,:202-208); all 4 tls_target sites carry pin: resolver.pin().copied() (startup_dns.rs:995-998,:2037-2044,:2143-2150,:2447-2450); documented intentional chain-transition stub (startup_dns.rs:695-700, docs/alumina-proxy.md:673,:675,:692, future-hardening-vectors.md:51-53, scorecard:393-394); test pins fail-closed failed==4 (dot_tests.rs:441-465); no proactive boot warning for no-pin IP#fqdn (main.rs:51-53 warns only bare-IP); Info fair |
```

**Working description (alox-f, L2b):**
[Info] Empty root store.

---

## W6-H6b-F1 — Low — TLS identity failure classified as generic Connect

**Scorecard row:**
```
| W6-H6b-F1 | Low | src/startup_dns.rs:1567,1586 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | TLS identity failure lands in generic Connect bucket: FailureReason enum has only Connect|Send|Receive|Timeout (startup_dns.rs:322-328), no TlsIdentity/TlsHandshake variant anywhere; pin/SAN mismatch → verify_server_cert Err InvalidCertificate(ApplicationVerificationFailure) (:717 SAN, :722-724 pin) → process_new_packets().is_err() → HandshakeProbe::Failed (:1629-1631, rustls error detail discarded) → close_connection + note_failure(Connect) (:1586; TLS-build failure also Connect :1567); operator surface: startup_final reasonN token = "connect" (log.rs:895-901) byte-identical to plain TCP connect failure, startup_warning first-failure carries no reason (log.rs:1040-1048), no TLS anomaly kind (monitor.rs:22-44); degraded/exit-75 reason-blind (startup_decision counts unresolved only serve.rs:532-550, main.rs:105 exit 75); fail-closed holds — close_connection before note_failure, no plain-DNS fallback (upgrade_to_tls doc :1541-1545), tests wrong-pin/SAN fail all exchanges publish nothing (dot_tests.rs:383-438) |
```

**Working description (alox-f, H6b):**
F1 [Low] TLS identity failure classified as generic `FailureReason::Connect` (`startup_dns.rs:1567,1586`) — operator with misconfigured pin sees only generic connect failures / degraded resolver / exit-75, indistinguishable from resolver outage. Fail-closed so security nil; diagnosability gap. Fix: distinct TlsIdentity/TlsHandshake failure class.

---

## W6-H6b-F2 — Low — unpinned DoT entry config-valid but never completes handshake, no diagnostic

**Scorecard row:**
```
| W6-H6b-F2 | Low | src/resolver.rs:300-334; main.rs:51-56 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | unpinned DoT entry config-valid + can never complete handshake + no diagnostic: pin optional for IP#fqdn (resolver.rs:318-339 select() pin None without #pin-sha256 suffix; config.rs:1429-1441 test asserts pin().is_none(); golden-path example config all unpinned FQDN config.rs:1497-1505); unpinned FQDN → port 853 (resolver.rs:202-208), tls_target pin None (startup_dns.rs:995-998,:2446-2450), verify against RootCertStore::empty() (:718-735) → deterministic fail; test unpinned_dot_with_empty_root_store... (dot_tests.rs:441-465) failed==4 exchanges==0; main.rs:51-56 warns only ip_only_resolvers (fqdn().is_none(), boot.rs:46-51) → FQDN-without-pin excluded; boot.rs:237-252 test treats unpinned FQDN as golden path no warning; no plain-DNS fallback (resolver.rs:200, startup_dns.rs:1541-1545); nuance: generic per-exchange startup_warning fires on first failure but is generic DNS-failure record, doesn't diagnose root cause; degradation permanent |
```

**Working description (alox-f, H6b):**
F2 [Low] Unpinned DoT entry is config-valid (`IP#fqdn` makes pin optional, `resolver.rs:300-334`) but can never complete handshake (empty root store); `main.rs` warns only for no-FQDN entries (`ip_only_resolvers` :51-56) — FQDN-without-pin gets NO diagnostic → silent permanent degradation. Fix: startup warning for FQDN-without-pin, or require pin.

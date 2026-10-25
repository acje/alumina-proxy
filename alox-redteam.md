# Alumina-Proxy — Adversarial Security Analysis

**Mode**: security (adversarial red-team, code + canonical spec)
**Scope**: whole codebase `src/**` (~26k LOC exc. tests), reviewed chapter-by-chapter against the fixed spec `docs/alumina-proxy.md` and its recorded amendments; **Part 2** red-teams the spec itself (governing document + 20+ amendments, sha256 `42ee92b8…25de`).
**Verdict**: DONE — 18 findings (0 Critical / 1 High / 7 Medium / 4 Low / 6 Info). Of the initial 21, three were pruned as unanimous (3/3) voter false positives (RT-002, RT-008, SP-011); the vote record is retained in **Part 3**.
**Started**: 2026-10-24

Findings are appended incrementally during the review. Severity: Critical / High / Medium / Low / Info. Each finding carries an OWASP reference per the security-review convention.

**Bottom line**: the implementation is exceptionally hardened — parser, cache, gate, allocator and log surfaces survived adversarial review with only truncation/detection-integrity and hygiene-level observations. The weakest logical surfaces are in the *spec design*: enforcement actions that single unauthenticated events can latch process-wide (SP-001), upstream-sourced tripwire attribution (SP-002), a downgrade path baked into the resolver array (SP-003), sustained-NXDOMAIN eviction/observability asymmetry (SP-004), JA4 baseline-tripwire design gaps (SP-005/SP-006), and one literal body-vs-amendment contradiction on enforced constants (SP-007).

### Severity summary

| Severity | Count | IDs |
| --- | --- | --- |
| Critical | 0 | — |
| High | 1 | SP-001 |
| Medium | 7 | RT-001, SP-002, SP-003, SP-004, SP-005, SP-006, SP-007 |
| Low | 4 | RT-003, SP-008, SP-009, SP-010 |
| Info | 6 | RT-004, RT-005, RT-006, RT-007, SP-012, SP-013 |
| **Total** | **18** | |

> **Voter cross-examination** (Part 3, 3 independent `general` voters): all 18 listed findings confirmed TP (17 unanimous + RT-006 2–1). The three 3/3-FP findings (RT-002, RT-008, SP-011) are **pruned** from Parts 1–2; the vote record is kept in Part 3. Per-voter tallies: V1 17 TP / 4 FP · V2 18 TP / 3 FP · V3 18 TP / 3 FP.

Cleared-as-hardened (no exploitable finding): `connect.rs`, `client_hello.rs`, `gate.rs`, `config.rs`, `dns.rs` (wire parse/bailiwick), `cache.rs`, `eligibility.rs`, `log.rs`, `alloc.rs`, `inventory.rs`, `worker.rs` substrate, `accept_all`, `preflight.rs`, `resolver.rs`, `schedule.rs`, `serving/startup.rs`.

---

## Findings

### RT-001 — Medium — JA4 fingerprint truncation defeats the JA4-change tripwire

**Category**: Cryptography / Detection integrity
**File**: `src/client_hello.rs:783-801` (`parse_sig_algs`), `:516-534` (`parse_cipher_list`)

**Issue**: `signature_algorithms` entries are retained leniently and **deterministically truncated** to the first `MAX_SIGALGS = 64` entries; overlong lists never reject the ClientHello ("neither rejects the ClientHello, mirroring the ALPN retention"). The JA4 fingerprint (`ja4_fingerprint`, `:949-986`) is computed from the truncated list and is the keystroke of the JA4-baseline `Changed` signal (`src/serving.rs:2740-2745`).

**Risk**: A client that offers ≥ 66 `signature_algorithms` entries can vary entries 65..N (e.g. rotating the effective TLS profile, swapping in an unusual signing scheme on a re-pinned connection) with the changed material never reaching the fingerprint. The first connection seeds the baseline from the truncated stable prefix, later profile pivots beyond entry 64 never raise `BaselineOutcome::Changed`, and the monitor's `note_fact_ja4_change` never fires. Same class, lower capacity: ciphers are capped at `MAX_CIPHERS` (8 192) — the cap is unreachable in a 16 KiB handshake, so only the sigalg truncation is practically weaponisable, but the ALPN 255-byte cut and `count_token` capping at 99 are entry points in the same direction.

**Fix**: Reject a `signature_algorithms` list longer than 64 entries (the retained bound may be raised, e.g. to 256, but surplus lists must still be rejected) as a profile violation (analogous to the duplicate-extension rule) instead of lopping it, or fold a length/truncation marker into `ehash12` so any list beyond the retained prefix changes the hash.

**Reference**: <https://owasp.org/www-community/Improper_Error_Handling>

---

### RT-003 — Low — CONNECT parser re-entry after `Complete` silently re-parses

**Category**: Enforcement-tooling robustness
**File**: `src/connect.rs:222-240` (`ConnectParser::feed`), `Item 2 in serving.rs:2163` (`buffer_and_parse`)

**Issue**: `feed()` is documented "Once `Complete` is returned the parser must not be fed again for the same connection", but `feed()` has no state check: a second call re-locates the already-present delimiter, re-parses `parse_request(head)`, and overwrites `self.result` — deterministically the same verdict today, but nothing enforces the contract. The ChInspector counterpart *does* enforce idempotency (`ChInspector::feed` short-circuits at `self.hello.is_some()`, `src/client_hello.rs:396-399`), so the CONNECT parser diverges from its sibling's defence.

**Risk**: A future serving-path regression (e.g. a re-feed on a budget-limited re-visit) would replay the parse over the whole 8 KiB head — a bounded but surprising re-parse with renewed relative-cost asymmetry (attacker pre-filled head re-scans). No current reachable call site; advisory to align enforcement with `ChInspector`.

**Fix**: Add `if self.result.is_some() { return Ok(self.last_feed_state()); }` (store the last `Feed`) so re-entry is structurally a no-op like the hello inspector.

**Reference**: <https://owasp.org/www-community/Improper_Input_Validation> (hardening note)

---

### RT-004 — Info — Slot `reset()` leaves prior connection's payload resident in the 2×128 KiB buffers

**Category**: Data retention / cleartext hygiene
**File**: `src/serving.rs:780-808` (`SlotWorkspace::reset`), buffers at `:70-79` (`HOLD_CAP`/`DOWN_CAP`)

**Issue**: The two boot-allocated 128 KiB per-slot buffers are "allocated once before the postboot phase and reused across connections", and `reset()` clears every state/cursor field (`buf_len`, `fwd`, `down_len`, …) but never zero-fills `self.buf`/`down_buf`. Previous connection bytes (decrypted-style relay payload, CONNECT heads captured, ClientHello fragments) remain resident in RAM until overwritten by the next connection on that slot.

**Risk**: No reachable disclosure path today: cursors are reset, all reads/writes are length-bounded to freshly written content, and the zero-allocation invariant forbids runtime deallocation — the retention is a by-product of the fixed profile. The residual becomes accessible only through an as-yet-nonexistent out-of-bounds primitive; recorded as defense-in-depth/deployment-hygiene (memory dump, core file, hibernation image leaks former tenants' traffic).

**Fix**: Zero-fill each buffer once in `reset()` (a relaxed fill within the zero-alloc invariant — no allocation) so old payload provably never spans connections; cheapest at the slot handoff.

**Reference**: <https://cwe.mitre.org/data/definitions/244.html> (OWASP A05 — Security Misconfiguration, data-hygiene class)

---

### RT-005 — Info — CNAME bailiwick trusts the whole parent zone (pivots on parent compromise)

**Category**: DNS trust-boundary scoping
**File**: `src/dns.rs:833-841` (`zone_of`), bailiwick enforcement `src/dns.rs` (`soa_covers`)

**Issue**: Bailiwick enforcement derives the CNAME target's authorization zone by dropping only the leftmost label of its owner name once (`zone_of("a.b.example.com") -> b.example.com`), keyed on the SOA answer of the chain's origin. Authority is therefore granted at the granularity of the entire parent zone: any sub-zone delegated by `example.com` (e.g. `unrelated.example.com` served by an attacker-controlled DNS operator after a NS hijack at the *parent's* registrar level) is within bailiwick.

**Risk**: Documented design (aggressive CNAME-following is bounded to the parent's SOA), so not a code defect — a threat-model note. A compromise of the *parent zone's* delegation or hosting (registrar/registry operator of `example.com`) pivots the proxy's allowlist names anywhere inside that whole parent zone; the per-name OCSP-free validation cannot distinguish it, and the anomaly surface (`BailiwickViolation`) only fires *outside* the parent SOA.

**Fix**: Spec-level hardening note only: require nothing more today, but surface parent-zone SOA changes for an allowlist name as an anomaly fact (the SOA MNAME/serial rotation rate is a strong hijack tell already available in-band).

**Reference**: <https://owasp.org/www-project-top-ten/2021/A08_2021-Software_and_Data_Integrity_Failures>

---

### RT-006 — Info — 3-day stale grace keeps serving a captured/hijacked answer after recovery

**Category**: Availability / recovery-window design
**File**: `src/cache.rs:10` (`STALE_GRACE: u64 = 259_200`), retirement arithmetic `:334`, `src/schedule.rs` (`BACKOFF_STAGES` cap 30 s)

**Issue**: `STALE_GRACE` extends cache-entry serving (serving-from-stale, `alumina-sslv`) to `TTL_expiry + 259200 s` = up to three days past a validated answer's TTL. In a hijack scenario: attacker poisons the resolver path once (via the resolver's own transport — NS compromise), the proxy validates and caches bad bindings at `T` with TTL capped at `TTL_CAP = 86400`; the resolver is repaired at `T+d`; the attacker's stale answer remains **actively served** until the grace deadline, and the refresh backoff ladder tops out at a 30 s cadence — the stale answer is *not* pinned to a "verify always" rule but keeps cycling.

**Risk**: Documented tradeoff (3-day graceful degradation amid resolver outage). The window favors the attacker: 72 h of tenant misrouting capacity per successful single-answer hijack, with only log-fact (anomaly/`serving-from-stale` observability) — no proxy-side kill switch, no per-name forced revalidation knob.

**Fix**: Spec-level: cap the *stale-serving* deadline independently of the *retention* deadline (e.g. serve stale only while the refresh schedule still actively re-attempts; or expose a per-name "do not serve past X" = first refreshed failure marker, drop stale at the earliest failed refresh).

**Reference**: <https://owasp.org/www-project-top-ten/2021/A04_2021-Insecure_Design>

---

### RT-007 — Info — Strict-pin DoT path skips certificate validity window

**Category**: Cryptography / defense-in-depth
**File**: `src/startup_dns.rs:758-786` (`AluminaServerCertVerifier::verify_server_cert`; pin branch `:768-777`)

**Issue**: On the pin path, `verify_server_cert` checks SAN (`verify_server_name`) and the SHA-256 SPKI digest against the pin, then asserts — `now: UnixTime` is consumed by the not-taken CA-branch only. Certificate Not-Before/Not-After is never evaluated on pinned entries (parse-level `ParsedCertificate` fails only on malformed DER). Revocation is likewise out of scope by design.

**Risk**: Realistically nil until key compromise: the pin match plus `verify_tls12/13_signature` still require possession of the pinned private key, so an unkeyed attacker cannot complete a handshake. With a compromised or deliberately persistent key holder, the pin intentionally never ages out — a stolen SPKI key retains trust indefinitely with zero expiry/rekey forcing or operator-visible "pin in use, cert long-expired" telemetry beyond the handshake success logs.

**Fix**: Check `cert.validity().not_after/until` bounds against `now` even on the pin branch (cheap, inside the existing verifier, no downstream consequences); emit a distinct warning fact when serving over an expired cert to force pin rotation.

**Reference**: <https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography> (transport identity series)

---

# Part 2 — Spec-level red-team: logical weaknesses in `docs/alumina-proxy.md`

Analysis of the canonical specification body plus its recorded amendments for design-level
gaps, contradictory or ambiguous requirements, missing threat-model cases, and amendment
interactions. Line references `:NNN` are spec line numbers.

### SP-001 — High — One unauthenticated control failure can latch `Block All`: no threshold between Connection and All, no unblock path

**Category**: Availability / enforcement design (rp2e amendment `:249-:263`)
**Spec**: `:253-:254` (AnyIllegal first-slot Block scope Connection/All), `:263` (Block All — "persists until restart; there is no runtime unblock interface")

**Issue**: `[any_illegal] scope = "all"` is valid configuration: the **first** AnyIllegal control failure selects the configured `Block` with scope `All`, which "synchronously prevents all subsequent application I/O … then performs bounded physical closure of at most 512 slots" and persists until restart. AnyIllegal events are produced by *unauthenticated* input against the listener: a malformed CONNECT head, a wrong HTTP version, missing/malformed SNI, ECH presence. There is no pacing, threshold, or aggregation step between "Connection-scope" and "All-scope" in the schema — it is a per-connection wiring choice, and `All` triggers at the first occurrence. Any traffic class that terminates the tunnels — including a VPC health-checker casual port-scan, a misconfigured sidecar sending plain HTTP to the proxy port, or the attacker — fires it.

**Risk**: One unauthenticated request converts into a process-wide egress outage until an operator redeploy. The threat model (`:13`) accepts *VPC egress unavailability* from the compromised application's own westward path failure — it does not accept a single-shot attacker-controlled global kill switch. The `Block All` surface is a tripwire against the compromised app, but its trigger class is the *lowest effort* one to synthesize for anyone inside the VPC (`:116` ingress restriction is deployment's job and outside Alumina's control plane).

**Fix**: Give `All`-scope an intermediate pacing gate in the schema (e.g. `All` arms only from a bounded fact counter crossing a threshold, or from a distinct fact class such as repeated-per-source), and/or define explicit operator-visible one-per-window summaries so a latch is reviewable; at minimum document the single-shot property as a deployment decision with its DoS consequence stated in the threat model.

**Reference**: <https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration>

---

### SP-002 — Medium — Early-upstream-data attribution contradicts the spec's own "do not infer arrival ordering" doctrine; wrong-vantage trigger

**Category**: Threat-model inconsistency (rp2e `:255` × protocol contract `:30-:32`, `:231`)
**Spec**: `:32` ("Do not infer arrival ordering for activity first observed after the gate opens"), `:255` (early upstream data attributed to the validated configured domain), `:206` (upstream data while gate closed terminates setup)

**Issue**: The rp2e amendment keys the *configured domain's* `Block Domain`/`All` action to "upstream Data observed through actual I/O after a matching, validated ClientHello but before the forwarding gate opens" — bytes arriving **from the upstream side** during the validate→gate window. In that window the client has already sent nothing but the validated ClientHello (the gate hands off exactly those bytes), so the client has no agency over the signal: the trigger is entirely chosen by the *upstream endpoint*. A malicious or partially compromised upstream on an admitted FQDN (a capability `:15` explicitly accepts: "An approved endpoint may expose attacker-controlled resources") can fire the per-domain latch at will, including steering `Block All` (when that domain's scope is `All`, per SP-001). The protocol contract itself disclaims the inference at the neighboring boundary — `:32` says send(2) completion "does not confirm remote receipt" and Do not infer arrival ordering for activity first observed after the gate opens — so the same byte stream carries an enforcement-grade inference *before* the gate and a doctrine of "no inference" *after* it.

**Risk**: A remote party (attacker-controlled endpoint, CDN node, or hijacked-zone peer) can flip a persistent per-domain乃至 process-wide egress latch with a single pre-gate byte; honest-but-fast upstream behavior during the write-completion window is indistinguishable from malicious early data because the write-completion caveat already removed ordering knowledge. The enforcement vantage (upstream behavior) is orthogonal to the enforcement subject (the compromised application) that the amendment's monitoring and actions are designed for.

**Fix**: Keep the baseline mandatory denial (terminate setup) but strip the domain-attribution/Action selection from upstream-*sourced* events, or require corroboration (e.g. K consecutive connections with early data across distinct source sockets) before a Domain/All scope may arm; state the boundary inference explicitly in the amendment text rather than leaving `:32` to disclaim it.

**Reference**: <https://owasp.org/www-project-top-ten/2021/A04_2021-Insecure_Design>

---

### SP-003 — Medium — Mixed-trust resolver array converts sustained DoT blocking into a silent cleartext-DNS downgrade; `NXDOMAIN-as-success` masks the degradation

**Category**: Downgrade / trust-boundary design (hrdn4 Stage 2 × dot-chain V1/V5 × hrdn2 Vec 35)
**Spec**: `:591-:599` (failover to next healthy, wrap semantics), `:675` (unpinned DoT fails closed), `:667` ("no silent plain-DNS fallback"), `:513` ("A valid negative response counts as a successful exchange"), `:774` (`dp=` counter)

**Issue**: With a resolver array mixing DoT (`IP#fqdn[^pin]`) and plain (`IP`) entries, a failback/`on_exchange_failed` relocation "scanning forward with wrap" legitimately lands on the bare-IP entry, dialing port-53 cleartext DNS. Anyone able to make port 853 fail (middlebox reset, gap in egress ACL, or the DoT server refusing handshakes) can advance the active resolver's consecutive-failure state at the cost of 3 failures + 1 relocation, restoring an anonymous-impersonation-able plaintext DNS channel to the *same* on-path attacker — the classic do not fall back doctrine (`:97` "Do not fall back to another transport… to reinterpret an unsupported response") is stated for response reinterpretation but bypassed structurally by array failover. Compounding: an attacker who has poisoned the *active* (now plain) link answers `NXDOMAIN` = a **validated negative**, which (a) evicts bindings, and (b) resets the resolver's degradation counter ("a valid negative response counts as a successful exchange", `:513`) — so the failover state machine reads *healthy* while the attacker supplies every negative. The single observable is the `dp=` counter, which is saturating, folded into the best-effort drop-prone log queue, and zero-suppressed (SP-010), and confounded by probe-sweep artifacts (SP-009).

**Risk**: An on-path attacker never breaks a security control — they merely let a transport fail three times and receive a public-resolver-grade cleartext DNS channel over which they can redirect the VPC's entire allowlisted egress. The "no downgrade" doctrine texts (`:667`, `:766`, `:807`) read as a guarantee but scope only to *within an entry*: the array graph itself is the downgrade path, and the deployment-visible signal for that pivot is one counter byte in a steerable log stream.

**Fix**: Treat cross-entry trust as transitive homogeneous: (a) validation-time homogeneous-trust requirement (all-DoT or all-plain per array, or a per-array minimum `pinned_only` knob), or (b) when the relocated-to resolver is a lower trust class than the current one, enter a *DNS-untrusted* mode that publishes nothing (fail-closed) with the `dp=` counter as exit evidence; and require a fresh *positive* validated exchange (not a negative) to count toward degradation recovery when the transport is on a plain entry.

**Reference**: <https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures>

---

### SP-004 — Medium — Sustained-NXDOMAIN is cheap, instant, incident-clearing, and after one transition notification the spec goes silent

**Category**: DoS-recovery asymmetry / observability gap
**Spec**: `:74` ("validated recursive negative answer evicts immediately without stale grace… NXDOMAIN is name-wide"), `:79` (NXDOMAIN clears exchange-failure incidents; no negative-incident window), `:77` (negative refresh 30–900 s)

**Issue**: The stale grace exists exclusively for *failed* refreshes: a **validated** NXDOMAIN evicts both families immediately, "update[s] both schedules, and clear[s] both exchange-failure incidents" (`:79`, `:93`). Notification surface: one immediate error at the "has bindings → has none" transition (`:79`) and then — since honest NXDOMAIN refreshes are not exchange failures — nothing: no incident window opens, no hourly summary fires, `rd=` doesn't count it. Steady-state attacker-forced NXDOMAIN (network path compromise; the plain-transport case of SP-003) reads as a deliberate name removal in the log stream, with 502-per-connect at runtime and no recurring observable. The recovery asymmetry matches: one spoofable exchange to evict; undownage requires a sustained stream of honest positives to re-cache cyclically (regained gradually via per-second rate guards), while the attacker must merely keep the sequence.

**Risk**: Attacker-cost for the longest-lived binding kill (evict both families with no grace) is a single validated answer that passes all provenance validation (legitimately shaped NXDOMAIN); operator-facing recovery signal is one log line, indefinitely. The design treats a negative as *more* authoritative than stale positives — consistent fail-closed doctrine, but the asymmetric observability (sustained negative ≠ sustained adversary) is an uneinal threat-model case: "acting resolver says the third-party FQDN is permanently gone" is indistinguishable from "zone owner really did delete it" inside the spec.

**Fix**: Add a sustained-negative incident class: e.g. after N consecutive validated negatives across M windows, open a (negative refresh) incident that participates in hourly summaries and the `rd`-class monitor facts, so an operator sees a *persistent* deletion signal rather than a single event; explicitly acknowledge the eviction-vs-recovery asymmetry in the DNS trust section.

**Reference**: <https://owasp.org/www-project-top-ten/2021/A08_2021-Software_and_Data_Integrity_Failures>

---

### SP-005 — Medium — JA4 first-seen baseline: multi-client false positives, IP-churn re-seeding, and unspecified >16-peer behavior

**Category**: Detection-integrity design (JA4 tripwire amendment `:875-:947`)
**Spec**: `:925` (baseline "32 ordinals × 16 addresses", one JA4 per (ordinal, IP), never updated), `:968` ("a baseline is never updated after first-seen")

**Issue**: Three design gaps compound:

1. **Multi-client conflation**: one baseline per (ordinal, IP) assumes one TLS stack per peer address. The typical deployment is several trusted applications behind the same proxy dialing the same allowlisted third party with different TLS libraries; the second client's first connection flares `Changed` against the first's seeded baseline — every its connection afterwards generates change noise the operator must instinctively tune out of (and the 36-byte value table (`:955`) attributes generously).
2. **IP churn defeats the tripwire**: CDN providers legitimately rotate IPs. The baseline seeds on *first-seen* for each (ordinal, IP) pair, so steering DNS to a fresh address re-seeds a new baseline from whatever连接 arrived there first; a compromised app (whose evasion of JA4-baseline detection is the tripwire's purpose) is precisely the threat model party positioned to influence客户端 DNS preference inside its VPC identity, or to simply re-connect into whatever fresh-IP slot the CDN hands out — each newly seeded baseline makes its JA4 look "first-seen normal".
3. **Runtime capacity unspecified**: the fixed table holds 512 entries = 32 × 16 = MAX_ADDRESSES; the spec does not say what happens when a **seventeenth** distinct peer IP appears for an ordinal (eviction policy? which row reuses? does the tripwire silently stop covering that peer?), nor how IP→row conflicts are specified when an entry's deduplicated bindings (≤16 per family, `:170`) rotate into fewer than 16 slots.

**Risk**: The tripwire's realistic false-positive (case 1) and false-negative (cases 2, 3) rates make the `jf`-class signal unusable as a primary detection in the nominal multi-app + CDN deployment — i.e., exactly the "typical use case" `:7` describes — while it is presented in the amendment with baseline-never-updated commodity language.

**Fix**: Specify: (a) baseline keying that tolerates client heterogeneity (e.g. per-ordinal *set* of up to K distinct observed JA4 strings limited to the allowlist's peer population — resolved explicitly rather than implicitly), (b) defined behavior at row-capacity overflow (evict-or-suppress policy with an observable fact), and (c) operator-visible baseline-seeding events so re-seeding churn is distinguishable from attacker-driven re-seed.

**Reference**: <https://owasp.org/www-project-top-ten/2021/A09_2021-Security_Logging_and_Monitoring_Failures>

---

### SP-006 — Medium — Spec pins canonical-JA4 byte-for-byte fidelity but mandates input truncation (sigalgs [u16; 64]) and leaves `count:02` overflow undefined

**Category**: Detection-integrity / canonical divergence (JA4 amendment `:884-:947` × ClientHello retention `:923`, `:925` with sigalgs `[u16; 64]`)
**Spec**: `:894` (hash12 of full unsorted sigalgs list), `:925` (`[u16; 64]` sigalg retention), `:938` ("byte-for-byte per spec vectors")

**Issue**: The spec (a) defines the JA4 hash input as the *full* unsorted `signature_algorithms` list (`:894`), (b) mandates per-slot retention storage `[u16; 64]` for that list (`:925`), and (c) claims canonical FoxIO byte-for-byte fidelity. A ClientHello offering >64 signature algorithms cannot satisfy all three: the retention cap silently truncates the hash input and the resulting fingerprint diverges from the canonical format with no rejection rule in the spec (the code mirror of this gap is RT-001 — the truncation is the spec-file-root cause, and the lop-not-reject decision is rendered at spec level, leaving code-level remedies to chase a moving definition). Same class: `cipher_count:02` / `ext_count:02` are two-digit counts (`:890-:891`) while ciphers are retained in `[u16; 8192]` (`:923`) — the spec never defines the rendering for counts >99 (canonical FoxIO behavior at overflow is not specified either), so a ClientHello with >99 extension types or >99 cipher offers (admissible inside the 16 KiB plaintext bound) produces an ambiguously-digit count whose canonical rendering is undefined and thus implementation-defined.

**Risk**: The "byte-for-byte" claim is unsatisfiable at the boundary where JA4 is exactly its threat value (the fingerprint is the tripwire's dedup key, change-detect content, and `d<j>v` value). Silent truncation at spec level normalizes profile pivots beyond the retained prefix (RT-001's risk statement — an attacker varies sigalgs index 65..N with zero signal).

**Fix**: Specify the boundary semantics in the amendment: either reject a ClientHello whose sigalg list exceeds 64 entries (admissible under the duplicate/QDU-pattern precedent), or fold a length/truncation marker into the retained representation (e.g. the JA4 string's 13 field or a `+t` suffix) so any list beyond the retained prefix changes output; define `count:02` overflow rendering explicitly.

**Reference**: <https://owasp.org/www-project-top-ten/2021/A09_2021-Security_Logging_and_Monitoring_Failures>

---

### SP-007 — Medium — Resource-profile rows contradict their own amendment: `:177-:178` still say 30/300 while `alumina-hrdn2` says they were amended to 5/900

**Category**: Spec-internal contradiction / doc-integrity
**Spec**: body table `:177` ("Normal DNS refresh interval, lower / upper | 30 seconds / 300 seconds"), `:178` ("SOA-based negative DNS refresh interval, lower / upper | 30 seconds / 300 seconds") vs `alumina-hrdn2` `:515-:517` ("The normal refresh band widens to min(900 seconds, max(5 seconds, entry TTL)) … the SOA-based negative refresh band becomes min(900 seconds, max(30 seconds, min(SOA TTL, SOA.MINIMUM))) with its own 30-second floor", citing "the profile rows `:176`/`:177`" as the amended rows)

**Issue**: `alumina-hrdn2` (Vec 14) explicitly claims to amend the profile rows to the widened 5/900 (normal) and 30/900 (negative) bands, matching the code (`REFRESH_MIN=5`, `REFRESH_MAX=900`, `NEGATIVE_REFRESH_MIN=30` in `src/schedule.rs:5-11`, plus `normal_refresh_interval`/`negative_refresh_interval` clamps). The body table still reads 30/300 for **both** rows (`:177`, `:178`). The amendment's own row citation is also stale by one line against the current file: its "`:176`/`:177`" now points at the "DNS exchange deadline | 5 seconds" row and the normal-refresh row. The doc-integrity pattern is inconsistent across amendments: `alumina-5sx` *did* update its body row in place (`:176` now says "5 seconds"), and `alumina-cfgk` updated the config-size row (`:158` — 16 KiB); `alumina-hrdn2` did not, leaving the body and its own amendment text in direct conflict on currently-enforced constants.

**Risk**: The doc is byte-canonical and governs more than code: any implementer, incident reviewer, QA gate, or future amendment citing the resource-profile table reads 30/300 as binding while the shipped daemon behaves 5/900 — the very class of spec-drift the document's amendment protocol exists to prevent. Verification activity (`:230`) references both texts.

**Fix**: Fold the hrdn2 Vec-14 row values into the body table rows `:177-:178` exactly as the 5sx/cfgk amendments did (a factual row edit, then `sh scripts/verify.sh docs`), or record in the hrdn2 section that the body rows are superseded-in-place and must be read via the amendment.

**Reference**: <https://owasp.org/www-project-top-ten/2021/A08_2021-Software_and_Data_Integrity_Failures>

---

### SP-008 — Low — CONNECT response corpus is an allowlist-enumeration and cache-state oracle, unacknowledged in the threat model

**Category**: Information disclosure (response design `:43`)
**Spec**: `:43` (400 malformed vs 403 not-allowlisted vs 502/503/504 with "a fixed plain-text body stating the reason"), `:15` ("a status: default-deny egress"), `:75` (stale/retired semantics)

**Issue**: The response taxonomy gives any VPC-facing sender an unthrottled oracle: 403 vs 400 discriminates allowlist membership from malformed syntax (enumerate the 32-entry allowlist by probing names), and 502-vs-503-vs-504 discriminates DNS-cache state (negative/unresolved/retired vs capacity vs deadline) at each allowlisted name. The body text and threat model never reference this information channel: `:7`'s default-deny model and `:116`'s ingress confinement assume separation, but the *outcomes* leak both the policy contents and the resolver/cache health continuously. `alumina-sslv`'s `ss=` bit and the 502 body text ("no resolved addresses" vs "upstream connection failed") add value-differentiated cache-state detail.

**Risk**: Low by design (the info is also obtainable by timing and by an attacker who can already send their own traffic); but the spec's threat model treats the compromised app as unable to read the config file while the response corpus directly publishes its contents, and the cache-state oracles assist staged targeted reflection on exactly the names in the allowlist. No rate/ throttling, normalization, or acceptance clause exists.

**Fix**: Acknowledge the oracle in the threat model / response-error clause; optionally expose identical bodies for 403/502-family outcomes (distinguished only by status code line) and/or apply per-source bounded rate to CONNECT error responses.

**Reference**: <https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering>

---

### SP-009 — Low — `dp=` downgrade counter is polluted by post-decision probe-sweep relocations, making real DoT→plain failovers indistinguishable from probe noise

**Category**: Observability integrity (rbp amendment × dotdg)
**Spec**: `:829` ("A DoT→plain probe relocation records the existing `dp=` downgrade counter"), `:774` (dotdg — `dp=` is the sole downgrade surface)

**Issue**: The `alumina-rbp` probe sweep relocates the single transport to each unprobed resolver once after the startup decision. With a mixed DoT/plain resolver set, each DoT→plain *probe* relocation increments `dp=`, and the sweep restores the transport — so every boot with a mixed set emits downgrade "events" that are pure probe artifacts. The dotdg counter exists to mark real failover/failback re-seats where the transport actually grounded on a weaker trust class for serving (SP-003's class of event); the reuse picks exactly that counting channel for a scheduled, always-present synthetic source, with no probe-context tag or separate bounded counter.

**Risk**: Hitting the DoT→plain degradation of SP-003 becomes indistinguishable from routine sweep noise in the monitor stream: an operator sees `dp=1..5` every mixed-set boot as normal, so the number cannot be used as a degradation tell; the signal is corrupted transitively at the precise intervals where SP-003 needs it to be loud. A saturating counter also masks the volume relation (probe-synthetic events easily dominate real downgrade events over months).

**Fix**: Count probe relocations in a separate bounded fact (or zero-suppressed only for non-probe relocations: tag sweep relocations distinctly — even one extra saturating slot, like the `bv`/`rpm`/`xttl` triple, keeps the real and synthetic sources disjoint); require the probe record to carry `dp` deltas in its own inline segment.

**Reference**: <https://owasp.org/www-project-top-ten/2021/A09_2021-Security_Logging_and_Monitoring_Failures>

---

### SP-010 — Low — No priority class in the drop policy: the most consequential records (Block All latch, startup final, incident summaries) lose their slots like any best-effort entry

**Category**: Logging availability (body `:199`; rp2e `:290`)
**Spec**: `:199` ("Drop and count new entries when the queue is full or the encoded record exceeds its limit"), `:290` ("a shutdown report is never guaranteed lossless"), `:263` (Block All — the process-wide latch record)

**Issue**: The log queue is a flat 256-entry FIFO with whole-record drop-and-count on overflow. Every record class competes on FIFO: the `Block All` latch record, the `startup_final` verdict, per-hostname incident summaries, `dp=`/`ss=`/`rd=` monitor keys, and `resolver_probe` all fall out under queue pressure identically. Sink stalls (stdout pipe full — the log reader is deployment-owned; `:199` "A stalled sink must not delay rejection, tunnel I/O, DNS, or deadlines") fill the queue within bounded time under an incident (e.g. 32 hostnames × hourly summaries plus monitor records plus interior warning flares); a sustained stall during the exact window a `Block All` latch arms or a `-f≥` monitor record tries to detail the trigger yields a process state the operator cannot reconstruct — by the design's own admission, the shutdown report "is never guaranteed lossless" (`:290`). Drops are counted, but no traffic shaping/prioritization exists.

**Risk**: The enforcement/monitoring amendments build their *whole value* on the stdout record stream, then inherit the drop policy with no priority classes: at the moments requiring evidence most (the latch, the degradation, the shutdown), the design's answer is "count a drop".

**Fix**: Reserve bounded slots for a small severity class set: e.g. latch/event records (`Block All`, `startup_final`, `resolver_probe`) cannot be dropped by *new unrelated entries* (drop the *newest* from the lowest class first); or coalesce dropped-class counter records into the periodic monitor stream so the evidence loss carries its own flag.

**Reference**: <https://owasp.org/www-project-top-ten/2021/A09_2021-Security_Logging_and_Monitoring_Failures>

---

### SP-012 — Info — "Conflicting settings" remains an unenumerated catch-all in config validation, against the discriminated-rejection precedent the doc itself set

**Category**: Spec-consistency (`:58` × hrdn Vec 36)
**Spec**: `:58` ("…out-of-range values, conflicting settings, and unmet local prerequisites cause immediate startup failure with exit status 78 (EX_CONFIG)"), cf. `:486` ("replaces the coarse parse-failure classification with exact, finite discriminants … every prior `NotHttp` rejection is now attributable to exactly one of the new discriminants")

**Issue**: The CONNECT surface was hardened to eliminate a coarse catch-all (`NotHttp`) in favor of exact discriminants, with the explicit reasoning that a coarse class "carried no additional information". The configuration surface retains "conflicting settings" as an unnamed failure reason — no definition of what settings can conflict (mandated sets vs forbidden pairs: e.g. `[any_illegal] scope="all"` alongside a per-domain `scope="all"`? duplicate-normalized entries are separately enumerated; `[reserved]/[unknown] defaults…` are enumerated). A diagnostic is required to identify the field, but the set of *conflict* predicates is not enumerable from the spec, and any future per-key pairing added will need its own amendment just to be categorized.

**Risk**: Cosmetic/consistency-level: a reviewer cannot audit the exit-78 coverage of conflict classes from the text, and misconfigurations surface as "conflicting settings" without the spec predicting them. No runtime impact — fail-closed as always.

**Fix**: Enumerate the conflict predicates in the configuration clause the way Vec 36 enumerable the CONNECT discriminants (or drop the clause and classify by field name, which the diagnostic already carries).

**Reference**: <https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration>

---

### SP-013 — Info — Incidental doc-drift: the C1 changed-value table is keyed per ordinal, so the `d<j>v` value can attribute a different peer's profile to the flare

**Category**: Observability attribution nuance (alumina-c1-1023 `:955-:968`)
**Spec**: `:955` ("retained per ordinal in a fixed `[[u8; 36]; ALLOWLIST_MAX]` table"), versus the baseline table's per-(ordinal, IP) keying (`:925`, `:305`)

**Issue**: The C1 amendment stores the *latest changed* 36-byte JA4 per **ordinal**, while the first-seen baseline table it reacts against is keyed per (ordinal, IP). With multiple peers per ordinal (CDN multi-IP under SP-005's rotation), the `d<j>v` value emitted alongside the flared counter belongs to whichever peer most recently changed the baseline — a value from peer B can be reported while the triggering change originated from peer A's row, and the flare's IP context (the first-seen row's 4-byte IP, `:303`) is not propagated into the change record.

**Risk**: Minor evidence-quality drift: the changed-fingerprint record that ops use to pivot into hunt mode points at a JA4 that may belong to a different (honest second-app) peer than the one whose change fired. The spec never requires this alignment. Cf. the first-seen row's 4-byte IP field (`:303`), which is not propagated into the change record.

**Fix**: Key the latest-change value by the same (ordinal, IP) as its baseline, or include the triggering peer's IP in the flare record.

**Reference**: <https://owasp.org/www-project-top-ten/2021/A09_2021-Security_Logging_and_Monitoring_Failures>

---

# Part 3 — Independent voter cross-examination

Three independent `general` voter sessions (fresh contexts, identical instructions, no visibility of each other or of the report's authoring process) re-verified all 21 findings from ground truth — the cited `src/**` lines and `docs/alumina-proxy.md` clauses — and voted **TP** (the described state exists and the issue is as characterized) or **FP** (misread, non-existent, already-prevented, or a load-bearing citation materially wrong). Majority = 2 of 3. Severity and Fix recommendations were explicitly out of scope (a voter could add a severity objection to a TP).

| ID | V1 | V2 | V3 | Majority | Note |
| --- | --- | --- | --- | --- | --- |
| RT-001 | TP | TP | TP | **TP 3–0** | Confirmed at `client_hello.rs:783-801`; truncated list feeds JA4 and the `Changed` baseline. |
| RT-002 | FP | FP | FP | **FP 3–0** | Pruned: head stops at the first CRLFCRLF (`connect.rs:229-234`), so interior empty lines cannot exist; budget-on-empty is unreachable (spec `:509`). |
| RT-003 | TP | TP | TP | **TP 3–0** | Confirmed `feed()` re-entry re-parses; note: no reachable caller today — `ChInspector` short-circuits (`client_hello.rs:396-399`), so it is defense-in-depth. |
| RT-004 | TP | TP | TP | **TP 3–0** | Confirmed: `reset()` clears cursors/fields only; `buf`/`down` never zero-filled (`serving.rs:780-808`). |
| RT-005 | TP | TP | TP | **TP 3–0** | Parent-zone bailiwick confirmed; **minor mis-statement**: zones derive from the allowlist FQDN, not the SOA answer — the parent-zone effect stands. |
| RT-006 | FP | TP | TP | **TP 2–1** | Dissent (V1): a validated positive refresh *replaces* bindings, so "keeps serving after recovery" overstates; V2 adds severity-objection (overstated). Window arithmetic itself confirmed (`cache.rs:10`, `:333-335`). |
| RT-007 | TP | TP | TP | **TP 3–0** | Confirmed: pin branch returns after SAN+SPKI; `now` consumed only by the untaken CA branch (`startup_dns.rs:758-786`). |
| RT-008 | FP | FP | FP | **FP 3–0** | Pruned: boot emits an explicit stderr warning per unpinned DoT resolver (`main.rs:119-139`, `boot.rs:53-67`); "no warning" premise false (spec `:677`). |
| SP-001 | TP | TP | TP | **TP 3–0** | Confirmed: `scope="all"` + first-event latch with restart-only reset (`:253-254`, `:263`). |
| SP-002 | TP | TP | TP | **TP 3–0** | Confirmed: pre-gate upstream Data attributed to the ordinal; trigger is upstream-chosen; `:32` disclaims the inference. |
| SP-003 | TP | TP | TP | **TP 3–0** | Confirmed: failover wrap reaches a bare-IP:53 entry; validated negatives reset degradation (`:591-599`, `:513`). |
| SP-004 | TP | TP | TP | **TP 3–0** | Confirmed: NXDOMAIN evicts + clears incidents; only one transition error, no recurring fact (`:74`, `:79`). |
| SP-005 | TP | TP | TP | **TP 3–0** | Confirmed: per-(ordinal,IP) first-seen baseline, never updated; 17th-IP policy unspecified (`:925`, `:968`). |
| SP-006 | TP | TP | TP | **TP 3–0** | Sigalg truncation-vs-full-hash confirmed (`:894` vs `:923`); **narrowed**: `count:02` overflow applies to ciphers only (>99 extensions impossible under the 64-extension cap). |
| SP-007 | TP | TP | TP | **TP 3–0** | Confirmed: body `:177-:178` still 30/300 vs hrdn2 5/900 and 30/900; amendment's own row citation stale; code matches amendment. |
| SP-008 | TP | TP | TP | **TP 3–0** | Confirmed: 400/403 mirror + value-differentiated 502 family; no throttle or threat-model note (`:43`). |
| SP-009 | TP | TP | TP | **TP 3–0** | Confirmed: `:829` probe relocations increment the same `dp=` counter (`:774`). |
| SP-010 | TP | TP | TP | **TP 3–0** | Confirmed: flat 256-record FIFO, class-agnostic drop policy (`:199`, `:290`). |
| SP-011 | FP | FP | FP | **FP 3–0** | Pruned: per-domain action is co-located in its table; spec `:1048-1050` states pairing is unaffected by ordinal ordering (ordinals order only the baseline). |
| SP-012 | TP | TP | TP | **TP 3–0** | Confirmed: "conflicting settings" unenumerated vs the Vec 36 exact-discriminant precedent (`:58`, `:486`). |
| SP-013 | TP | TP | TP | **TP 3–0** | Confirmed: per-ordinal changed-value vs per-(ordinal,IP) baseline; no peer IP in the flare (`:955`, `:925`); cited `:303` now at `:305` (drift only). |

**Vote tally**: TP 18 (17 unanimous + RT-006 2–1) · FP 3 (unanimous: RT-002, RT-008, SP-011).

**Post-vote corrections applied**: the three 3/3-FP findings (RT-002, RT-008, SP-011) were pruned from Parts 1–2 and the header counts updated to 18; their rows above are the retained audit record. RT-005/SP-006 wording narrowed per voter notes (sub-claims the voters disproved); RT-003/RT-006 annotated as defense-in-depth / split verdict. SP-004's voter note corroborates SP-007's `:77` body-row drift.

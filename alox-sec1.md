# Security Review: Alumina code + spec (alox-sec1)

**Mode**: security / adversarial red-team (code + spec)
**Scope**: full first-party surface — `src/` (all modules), `docs/alumina-proxy.md` (byte-canonical governing spec, amendments through `alox9`), `Cargo.toml`/`deny.toml`/`rust-toolchain.toml`, prior alox artifacts (`alox-redteam2.md`, `alox-spec-review.md`, `alox-vote-results.md`).
**Method**: source-level adversarial review by module cluster (CONNECT/ClientHello, DNS core, DoT transport, serving core/gate, event loop, logging/enforcement, config/boot/deps), each adjudicated against the governing spec's threat model and deployment idioms to suppress false positives. No builds/tests/fuzzers run (mechanical verification is out of scope for this review; execution-owned gates stay with their owners).
**Status**: IN PROGRESS — sections appended as cluster reviews complete.

## Threat model & false-positive discipline (adjudication basis)

Adversaries in scope (`docs/alumina-proxy.md:9-15`): (1) the compromised application in the same VPC = the CONNECT client (all client bytes untrusted); (2) a malicious/compromised recursive resolver or on-path DNS attacker (all DNS response bytes untrusted); (3) malicious approved upstream endpoints (origin authentication explicitly out of scope, `:15`/`:50`). Trusted: validated TOML config, OS/deployment, operator. Fail-closed doctrine (`:208`).

Not re-raised here (accepted residuals / by design — prior voter adjudication and spec acknowledgements):

- No upstream cert/origin authentication; domain fronting; connection coalescing (`:15`, `:50`).
- CONNECT error-response corpus is an acknowledged allowlist/cache-state oracle (SP-008, `:43`).
- Parent-zone CNAME bailiwick granularity / parent-zone compromise (RT-005); public-suffix derivation (F-07 HELD by voters).
- Bare-IP plain-DNS resolver entries are a tolerated, startup-warned degraded-trust form; unpinned DoT against the empty root store failing closed is a deliberate chain-transition state.
- No local DNSSEC; stale-retention tradeoffs (72 h retention / 1 h stale-serving window) are accepted bounds.
- Availability within fixed resource limits is not guaranteed (`:13`); capacity exhaustion → best-effort 503; log drop-and-count best-effort are by design.
- JA4 data is observability-only, never admit/reject (`:909`).
- Deployment confinement (VPC isolation, alternate egress) is operator-owned (`:99-120`).
- rustls per-record heap allocations on the warm DoT path are a documented exempt bounded seam (`alumina-zai`, `:788-808`); first-party allocs allowed only at boot + the `build_tls_connection` DoT setup seam.
- `Block All` as an operator-configured fail-closed isolation control is deliberate design (F-01 HELD); only its current code state is reported.

Known-open register (spec-authorized, status "Planned — later sub-mission" in `alumina-redtm`/`alox7` tables; each is verified below for live code state and cataloged as OPEN-CONFIRMED, not as a new discovery): SP-001, SP-002, SP-003, SP-004, SP-006+RT-001, SP-009, SP-010, RT-007.

## Findings summary

(filled at completion)

## Findings by cluster

### Cluster A — CONNECT parser + ClientHello inspection (`src/connect.rs`, `src/client_hello.rs`)

**Verdict**: clean at Critical/High; 2 Low + 2 Info NEW; three prior-finding bundles verified fixed in code.

#### A-1 [FIXED-VERIFIED][High→closed] SP-006/RT-001 — sigalg list >64 no longer silently truncated

- Files: `src/client_hello.rs:791-812` (rejection `:805-807`), `:183` (`TooManySigAlgs`), `:314` (folds to `Profile`→AnyIllegal), `src/serving/reject.rs:68-77`; tests `:2032-2058`
- Spec: `docs/alumina-proxy.md:1243-1266` (status row stale — see A-6)
- Witness: `parse_sig_algs` rejects `count > MAX_SIGALGS (64)`; at-bound accepted, over-bound rejected; JA4 hash input never lopped. Verified: `TooManySigAlgs` at `client_hello.rs:805-806` is live.
- Note: spec status table `:1376` still says "Planned — later sub-mission"; code landed ahead of the record (doc lag, A-6).

#### A-2 [FIXED-VERIFIED][bundle] sechd L3/L8/L9/L10/L11, icdl, hrdn Vec34, hrdn2 Vec35, hrdn discriminant split

All live with tests: L3 bare-CR (`connect.rs:333-335`, tests `:826-847`); L8 non-`host_name` SNI (`client_hello.rs:737-741`, tests `:1586-1616`); L9 ≥4-byte first-record handshake payload (`:470-472`); L10 SNI trailing-dot + case-insensitive via shared `FixedHostname::normalize` (`:747`, `:1019`); L11 caps 64-ext (`:596-598`, check-before-write, no wrap at 65th) / 32-versions (`:700-704`); icdl canonical `Content-Length: 0` digits (`connect.rs:422-435`); Vec34 16 KiB handshake bound with exact-at-bound acceptance (`client_hello.rs:485-491`); Vec35 16 header lines (`connect.rs:281-285`); Vec36 exact discriminants, no `NotHttp` catch-all (`connect.rs:47-62`).

#### A-3 [FIXED-VERIFIED][Medium→closed] Embedded-dot label confusion class on client-side names

- Files: `src/config.rs:153-203` (`FixedHostname::normalize`: empty label/label>63/trailing-dot/ASCII-only/IP-literal-shape all rejected), `src/connect.rs:478,502-506` (byte-exact compare), `src/client_hello.rs:747,1019`; tests `connect.rs:1053-1073`, `client_hello.rs:1643-1651`, `config.rs:255-259`
- Witness: CONNECT target and SNI pass through the same normalization as config entries; authorization is a byte-exact comparison of normalized values — no two distinct allowlist spellings can alias, no dot-boundary ambiguity between SNI and approved name.

#### A-4 [NEW][Low] Draft-ESNI/ECH codepoints other than `0xfe0d` are not treated as ECH

- Files: `src/client_hello.rs:49,616-618,625`
- Spec: `:49` (reject the `encrypted_client_hello` extension, incl. ECH GREASE)
- Witness: only type `0xfe0d` sets `has_ech` (verified live); every other extension type is skipped by length (`_ => {}` at `:625`). Draft-ietf-tls-esni ≤-08 used `encrypted_server_name (0xffce)`; a client sending `0xffce`-encrypted SNI is admitted (outer SNI must still match) and produces a normal JA4 fingerprint — the spec-mandated ECH tripwire is blind to draft-codepoint ECH/ESNI.
- Impact: security — destination binding unaffected (DNS + outer-SNI = CONNECT host; inner-name concealment is the accepted domain-fronting residual `:15`/`:50`), but golden-path compliance signal is blind to a whole known ECH codepoint family.
- Fix: match `0xffce` as ECH-present (or count a distinct profile fact); do **not** fold in `0xff01` (renegotiation_info — appears in golden-path hellos per the published JA4 vector at `client_hello.rs:1768`). Requires a spec amendment since `:49` names only `encrypted_client_hello`.

#### A-5 [NEW][Low] ~392 KiB of avoidable memset per connection teardown

- Files: `src/serving/reject.rs:88` (`close_slot` → `ws.reset()` on every release incl. attacker-triggered rejects); `src/serving.rs:764-794` (`ConnectParser::new` = 8 KiB zeroed (`connect.rs:200`), `ChInspector::new` = 2×64 KiB zeroed (`client_hello.rs:377-386`), `buf/down.fill(0)` = 256 KiB); `src/client_hello.rs:537` — `parse_cipher_list` zero-inits `[u16; 8192]` (16 KiB) per parsed hello only to fill `cs_count` entries.
- Witness: every read of these buffers is cursor-bounded (`head_len`, `len/scan_pos/flat`, `buf_len`), so zeroing is dead work; a client spamming malformed CONNECTs forces ~0.4 MiB of memset per attempt.
- Impact: performance — O(1) per connection but pure dead work on the setup/teardown hot path (Priority 4).
- Fix: `clear()` methods resetting cursors/Option state only; keep `fill(0)` only if deliberate cross-connection slab hygiene is required (then document it); zero only `ciphers[..cs_count]`.

#### A-6 [NEW][Info] ×2 — port>65535 misclassification; stale spec status rows

- `connect.rs:459-464`: `CONNECT host:65536` fails closed but lands in `MalformedRequestLine("port is not numeric")`, not a range discriminant — monitoring-signal granularity only; fix via dedicated `PortOutOfRange`.
- `docs/alumina-proxy.md:333,335,1376`: sechd/redtm status rows still say "planned" for L3/L8/SP-006 while code+tests are live — doc/reality drift on enforcement-status honesty; doc-only fold.

**Areas checked clean (A)**: request-line token/version/NUL/whitespace ambiguities; port parsing (`+`, non-ASCII, >5 digits, leading zeros, `0`); hostname shape (IPv6 brackets, empty labels, >253/254, UTF-8, IP-literal, punycode A-label accepted); SNI validation (empty/IP-literal/>63/>253/duplicate/NameType≠0); ECH GREASE payload-independent detection; supported_versions (odd/short/>32/GREASE-only/TLS1.2-mixed/legacy_version); 65th-extension rejection before write; fragmentation across records/reads boundary-independence; 16 KiB/64 KiB bounds exact-at-boundary; JA4 fidelity pinned to published vectors (GREASE filter, SCSV counting, count:02 saturation at 99, ALPN hex-fallback, unsorted sigalgs, `d/i` presence rule); no `unwrap/expect/panic` on production paths; resumable cursored parsing (linear under 1-byte dribbles, single copy into scratch).

**Positive (A)**: single shared `FixedHostname::normalize` makes CONNECT/SNI identity comparison injective by construction; `HelloAccepted`/`ValidatedHello` capability types make an unvalidated hello boundary unrepresentable; deliberate at-bound/over-bound test pairs pin off-by-one behavior; byte-for-byte JA4 vector gates + allocation-witness test under `Phase::Serving`.

### Cluster B — DNS wire, cache, schedule, eligibility (`src/dns.rs`, `src/cache.rs`, `src/schedule.rs`, `src/eligibility.rs`)

**Verdict**: all three prior code-level findings verified fixed; 1 NEW Low (latent), 1 NEW open spec-surface item, 2 Info; one proposed Medium dismissed as spec-authorized.

#### B-1 [FIXED-VERIFIED][High→closed] alox-redteam2 "DNS names lose label boundaries"

- Files: `src/dns.rs:574-577` (strict per-byte check inside the decode loop — compression-pointer hops re-enter the same loop), applied at question qname (`:916`), all section owners, CNAME targets (`:667`), SOA owner; lenient only at SOA mname/rname (`:682,686` — cursor-only discards, test-pinned `accepts_embedded_dot_in_soa_mname_rname` at `:3028`); `zone_of` (`:843-851`) splits only trusted config strings whose charset excludes dots; tests `:2861-3025` cover qname/owner/CNAME target/terminal owner/duplicate owner key/bailiwick suffix/SOA owner + adversarial witness.
- Impact: eliminated representation ambiguity in bailiwick/SOA/owner matching.

#### B-2 [FIXED-VERIFIED][High→closed] alox-redteam2 "duplicate identical CNAMEs ignore shorter TTL"

- Files: `src/dns.rs:993` (CNAME duplicate min), `:1100-1105` (entry TTL = min across whole chain + every terminal-owner record — covers duplicate addresses in any order), `src/cache.rs:364` (clamp 1..86400, L12), `:374-379` (publication dedup, L13); tests `dns.rs:2694-2817`, `cache.rs:552-640`. Gap noted: no dedicated duplicate-A-with-differing-TTLs test (guarantee is structural via the min fold).

#### B-3 [FIXED-VERIFIED][Low→closed] root SOA coverage

`soa_covers` returns true for empty root owner (`src/dns.rs:1202-1204`); tests `:1642-1692` (direct NODATA, CNAME-terminal NODATA, NXDOMAIN with root SOA).

#### B-4 [FIXED-VERIFIED] F-10 zero-TTL never stale-served; generation isolation

- Zero-TTL: `stale_allowed = staged.ttl != 0` from the raw earliest supporting TTL (`cache.rs:393`), `servable()` gates the stale arm (`:140-151`), `normal_refresh_interval(0)==1` (`schedule.rs:55-61`); tests `cache.rs:717-777`, `schedule.rs:958-972`.
- Generation isolation: every mutation advances the entry generation (`checked_next`, refusing at u64::MAX with both entries untouched, `cache.rs:357-363,407-440`); publish refuses stale-generation staged results (test `cache.rs:868-898`). Live-path isolation currently rests on the single-active-exchange invariant — see B-6.

#### B-5 [NEW][Medium|observability — OPEN, planned slice] Spec `:79-81` DNS incident-notification surface is not implemented

- Files: absent from `src/` — only the alox7 sustained-negative incident (`schedule.rs:457-489`, `startup_dns.rs:1159-1323`, `enforcement/state.rs:316-321`) and the per-exchange `exchange_failed` log record exist; there is no per-type exchange-failure incident state, no first-failure warn, no 3600 s per-hostname error summary, no immediate error on the has-bindings→none transition, no recovery info notification, and no 512 per-slot window-marker activity accounting from `:81`.
- Spec: `:74` ("clear both exchange-failure incidents" — nothing to clear), `:79-81`, `:235`; `docs/build-plan.md:85` (Slice 2 lists `:79-81` — unlanded increment).
- Witness: grep of `src/` for the `:79` vocabulary finds only sustained-negative + `exchange_failed`; the NXDOMAIN apply arm (`dns.rs:368-375`) has no incident surface to clear.
- Impact: security (observability) — operators are blind to the per-type incident narrative and activity-window summaries during resolver attacks/eviction storms; no authorization impact. Repo status is a scoped testQA candidate with serving-qualification gates open, so this is an open planned-slice item, not a regression.
- Fix: land Slice 2's `:79-81` increment before serving qualification; wire the NXDOMAIN arm to clear both per-type incidents per `:74`.

#### B-6 [NEW][Low] Cache generation captured at receipt, not exchange start — guard tautological on the live path

- Files: `src/startup_dns.rs:2390-2400` (generation read immediately before apply), `:2803-2804` (single-active-exchange guard is the real isolation), `src/cache.rs:357-359`
- Spec: `:74` ("obsolete results cannot overwrite newer cache state")
- Witness: `apply_outcome` reads the entry generation right before applying, so the `staged.generation != entry.generation` guard can never fire in the single-threaded owner; isolation is structural (one active exchange + one worker). Any future second mutation path silently voids the `:74` armor.
- Impact: security (latent) — no live exploit today.
- Fix: capture the generation into `ActiveExchange` at `start_exchange` and compare at receipt so the cache guard becomes load-bearing.

#### B-7 [NEW][Info] ×2 — 256-octet wire-name admission; one-label allowlist names

- `src/dns.rs:547,561-563`: length accounting omits the root byte, admitting 256-octet wire names (one octet over RFC 1035); decoded forms still fit `DnsName`, comparisons exact, no ambiguity — byte-exact conformance fix only.
- `src/config.rs:38-53` + `src/dns.rs:843-851`: one-label entries (`localhost:443`) are accepted and derive **themselves** as bailiwick zone — conservative (self+subdomains only, no root escape); document or reject one-label entries.

#### B-8 [DISMISSED — spec-authorized] NXDOMAIN with wrong-family record at the queried name evicts both families

- Proposed by the cluster review as Medium: wrong-family records are discarded before `ensure_owner` (`dns.rs:942-949,965-972`), so the NXDOMAIN terminal-contradiction guard (`:1122`) sees only same-family data; an AAAA query answered `NXDOMAIN` + an A record at the queried name yields a clean `NxDomain` that evicts both families (`cache.rs:407-421`), while spec `:93`/`:86` read as "contradictory → exchange failure".
- Dismissed on two grounds: (1) the `alumina-hrdn` Vec 33 amendment explicitly adjudicates this exact case — "an NXDOMAIN carrying a wrong-family record at the terminal owner remains a clean `NxDomain`, never `TerminalWithoutData` (tests `nxdomain_with_opposite_family_*`)" (`docs/alumina-proxy.md:479`); (2) no adversarial delta — a resolver can already evict both families with a bare NXDOMAIN (no records needed); the wrong-family record grants nothing beyond it.
- Recorded here (not silently dropped) because the `:93` body text and the Vec 33 amendment read differently at first pass; a future doc fold could make the amendment's precedence over the body row explicit for this case.

**Areas checked clean (B)**: wire frame/binding (TID/QR/opcode/TC/rcode `dns.rs:881-901`, QDCOUNT=1 `:906`, exact question match `:916-925`, `TrailingBytes` on section-count excess `:1079-1081`); compression rules (strictly-earlier pointers, cycle bound, reserved label types, pointers only in owner/CNAME/SOA names; unknown-type RDATA incl. OPT skipped positionally pointer-free and bounded, counted inside 128-RR/16 KiB bounds); RDLENGTH exact for A/AAAA/CNAME/SOA; CNAME chain (≤8 links, loops, one-target-per-owner, coexistence rejection both orders, bailiwick on every followed link, terminal-owner-only candidates, NXDOMAIN-through-chain and NODATA covering-SOA rules, non-covering/ambiguous/duplicate SOA rejection); eligibility tables byte-verified against spec `:73` (all 15 IPv4 exclusions; IPv6 `2000::/3` membership structurally rejecting IPv4-mapped/NAT64/6to4/Teredo); cache/schedule arithmetic (checked/saturating adds; TTL 0→1s; 86400 cap; NXDOMAIN both-families / NODATA queried-only; refresh formulas; backoff ladder with correct reset/advance rules; one-start-per-second whole-second guard; rotating round-robin with no starvation/skip-forever and overdue coalescing; fixed `[[Slot;2];32]` storage with cached `next_due` recomputed only on mutation); performance (no per-parse workspace memset — only `owner_len`/`soa`/`extreme_ttl` reset at `:877-879`; O(128×len) bounded owner scans; no first-party heap alloc/format! on publish/refresh paths — alloc-witness tests `cache.rs:1239-1315`, `schedule.rs:1155-1199`; no production unwrap/expect).

**Positive (B)**: staging-then-publish with generation advance and two-phase prepare/commit keeps cache and schedule consistent and refuses obsolete results; wrong-family discard and the embedded-dot rejection together close the name-confusion class; eligibility comparisons are numeric with structural rejection of translation prefixes; the rotating scheduler proves no starvation under repeated failures across the full allowlist.

# Security Review: Alumina CONNECT, TLS, DNS, and DoT

**Mode**: security / adversarial source review
**Scope**: `docs/alumina-proxy.md`; `src/connect.rs`, `src/client_hello.rs`, `src/gate.rs`, `src/serving.rs`, `src/dns.rs`, `src/cache.rs`, `src/eligibility.rs`, `src/resolver.rs`, `src/config.rs`, `src/startup_dns.rs`, `src/schedule.rs`, `src/serve.rs`, `src/worker.rs`, `src/runtime.rs`, and `src/serving/startup.rs`
**Verdict**: **FAIL** — two High-severity DNS validation weaknesses are unacknowledged by the current specification.
**Validation**: Source inspection only. No builds, tests, fuzzers, binaries, network probes, or other verification tools were run.

## Findings summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 2 |
| Medium | 1 |
| Low | 2 |
| Info | 1 |

## Findings

### [HIGH] DNS names lose label boundaries, allowing query-identity and bailiwick confusion

**Category**: Auth / input canonicalization
**Files**: `src/dns.rs:40-90`, `src/dns.rs:539-600`, `src/dns.rs:752-773`, `src/dns.rs:909-918`, `src/dns.rs:1075-1087`, `src/dns.rs:1159-1161`, `src/dns.rs:1193-1203`
**Spec**: `docs/alumina-proxy.md:68-71`, `docs/alumina-proxy.md:86`, `docs/alumina-proxy.md:205`, `docs/alumina-proxy.md:540`

**Issue**: `read_name` decodes a DNS name into a printable-like byte string by inserting `.` between labels, but it does not reject or escape a literal `.` inside a wire label. Consequently, the distinct DNS names `[ "sub.example.org" ]` and `[ "sub", "example", "org" ]` have the same `DnsName` representation.

This representation is then treated as a canonical identity for the exact outstanding-question check, owner deduplication, CNAME-chain links, terminal-address selection, bailiwick checks, and SOA coverage.

**Adversarial witness**: For an outstanding query for the three-label name `sub.example.org`, a malicious or compromised resolver can return a response with the correct TID, type, and class, but encode the question and answer owner as the **single** label `sub.example.org` (length 15). The parser lowercases and flattens that label to `sub.example.org`; the comparison at `src/dns.rs:913-917` therefore accepts it as the exact question, and the direct address is collected at `src/dns.rs:1079-1102`. No CNAME is needed for this witness.

The same confusion can merge two distinct owners in `ensure_owner`, make an out-of-zone CNAME target appear inside a configured zone, or associate a CNAME target with address records belonging to a different wire name. This violates exact response binding and weakens the Destination-Binding Invariant rather than merely accepting an unusual presentation form.

**Risk**: A resolver or response-injection adversary able to supply a syntactically valid DNS message can publish an address whose actual wire-level owner is not the approved hostname. The subsequent eligibility checks limit the address to the permitted public ranges but do not restore name provenance. A malicious authoritative zone or compromised recursive resolver can therefore bypass a security boundary that the CNAME/bailiwick and exact-question rules are intended to enforce.

**Fix**:
- Preserve DNS labels as length-delimited values throughout comparison and suffix operations; never use an unescaped dot-joined string as the canonical wire-name key.
- A smaller fixed-profile alternative is to retain a label-boundary bitmap alongside the existing bytes and include it in equality and `soa_covers`, or reject `.` within labels for the hostname-identity, CNAME, and SOA names consumed by this security policy.
- Handle the empty root label explicitly.
- Add regression vectors for embedded-dot labels in the question, direct answer owner, CNAME target, terminal address owner, duplicate owner keys, bailiwick suffix, and SOA owner. Assert rejection (or distinct treatment) before any cache mutation.

**Reference**: https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication

---

### [HIGH] Duplicate identical CNAMEs can ignore a shorter supporting TTL

**Category**: Dependency & configuration / cache-lifetime enforcement
**Files**: `src/dns.rs:980-990`, `src/dns.rs:1091-1102`, `src/dns.rs:1128-1175`, `src/cache.rs:339-380`
**Spec**: `docs/alumina-proxy.md:74`, `docs/alumina-proxy.md:205-207`, `docs/alumina-proxy.md:382`

**Issue**: When an owner has repeated CNAME records with the same target, the parser accepts the duplicate but retains only the first record's TTL:

```rust
if let Some((existing, _)) = &ws.owners[idx].cname {
    if !existing.eq_bytes(target.as_slice()) {
        return Err(DnsError::ConflictingCname);
    }
    // The new ttl is discarded.
}
```

The specification instead requires the entry TTL to be the **earliest TTL of every supporting CNAME or address record**, subsequently capped at 86,400 seconds.

**Adversarial witness**: A positive response can contain, for the same chain owner, `CNAME target TTL=86400` followed by the identical `CNAME target TTL=1`. Both records support the accepted chain. The parser keeps 86,400 and never takes the minimum with 1. `root_chain` therefore returns the longer TTL, and `publish_positive` establishes freshness from that value instead of expiring after one second.

**Risk**: A malformed or adversarial response can keep a destination authorized long after the shortest supporting record required it to become stale. This is a direct cache-lifetime/destination-authorization violation. The 24-hour TTL cap limits the maximum extension but does not correct the bypass; the stale-serving window is then added to the incorrectly extended freshness period.

**Fix**:
- On every identical CNAME duplicate, update the stored TTL to `min(existing_ttl, new_ttl)` while retaining the single unambiguous target; alternatively, reject duplicate CNAME RRs with differing TTLs as contradictory.
- Add order-independent tests: long-then-short and short-then-long duplicates must produce the same earliest TTL. Include direct and multi-link chains and confirm the cache freshness deadline, not just the parsed outcome.

**Reference**: https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration

---

### [MEDIUM] Startup-window expiry neither reliably gates publication nor cancels obsolete work

**Category**: Error handling / lifecycle isolation
**Files**: `src/startup_dns.rs:2203-2301`, `src/serving/startup.rs:65-206`, `src/runtime.rs:252-267`
**Spec**: `docs/alumina-proxy.md:64-65`, `docs/alumina-proxy.md:207`, `docs/alumina-proxy.md:226`

**Issue**: `step_recv` parses and applies a complete result before checking the exchange deadline; the deadline check at `src/startup_dns.rs:2295` is reached only when no result was published. In addition, when the cooperative startup loop observes the 90-second window deadline, its non-shutdown exit path does not call `cancel_for_shutdown`, clear `active`, close the exchange, or otherwise invalidate it. The expired exchange can subsequently be advanced by the serving runtime.

**Adversarial witness**: A resolver stalls a startup exchange until the window boundary and then supplies a complete response. If the response is processed in a turn that began just before expiry, publication can complete after the deadline because there is no pre-publication clock check. If the loop exits at expiry with the exchange still active, the retained `active` state survives `settle_startup`; a later serving turn can receive and publish that old response before the expired-deadline failure arm is reached.

**Risk**: An obsolete startup exchange can establish, replace, or evict authorization state outside the specified startup transaction. A late positive can make a previously unresolved name usable; a late NXDOMAIN can evict both families after the readiness snapshot. This breaks the specification's strict-before-deadline and obsolete-work-isolation guarantees and makes startup authorization dependent on event timing at the boundary.

**Fix**:
- Check `Instant::now() < ex.deadline` immediately before every successful stage transition that is required to finish before expiry, and especially before `dns::apply_outcome`; at or after expiry, fail without publication.
- On every startup-window expiry path, explicitly clear the active exchange and schedule selection, close the transport, and prevent its later reuse before entering serving refresh.
- Add boundary tests for a complete response already readable at expiry, a response completing during the final turn, and an active exchange retained across `settle_startup`. Assert no cache/schedule mutation and no later publication from the cancelled exchange.

**Reference**: https://owasp.org/www-community/Improper_Error_Handling

---

### [LOW] Root SOA is not recognized as covering every terminal name

**Category**: Error handling / DNS negative classification
**File**: `src/dns.rs:1178-1203`
**Spec**: `docs/alumina-proxy.md:88`

**Issue**: `soa_covers` handles an equal owner and an owner that is a proper suffix at a label boundary, but not the empty root owner. For a nonempty terminal and an empty SOA owner, it computes a boundary at the terminal's final byte and requires that byte to be `.`, which is false for the normalized representation.

The DNS root is an ancestor of every name, so a root-owned SOA satisfies the specification's “terminal name or its ancestor at a DNS label boundary” rule.

**Adversarial witness**: A `NOERROR` response with no terminal addresses and a valid authority SOA owned by the root (`0x00`) is rejected as `NonCoveringSoa` instead of producing NODATA. A resolver or authoritative server can therefore turn a valid negative into repeated exchange failures and backoff, affecting availability and delaying stable negative classification.

**Fix**: Return `true` from `soa_covers` when `soa_owner.is_empty()` (the root covers every terminal, including root). Add direct and CNAME-terminal NODATA vectors with root SOA, plus NXDOMAIN-with-root-SOA scheduling coverage.

**Reference**: https://owasp.org/www-community/Improper_Error_Handling

---

### [LOW] Security-critical normative clauses in the governing specification contradict later amendments

**Category**: Dependency & configuration / specification integrity
**File**: `docs/alumina-proxy.md:62-77`, `docs/alumina-proxy.md:180`, `docs/alumina-proxy.md:651-701`, `docs/alumina-proxy.md:1331-1360`

**Issue**: The byte-canonical document retains stale body requirements alongside incompatible later amendments. Examples include:

- `:62` still requires reading the platform resolver file and selecting only its first server, while the config implementation and DoT amendments require a validated TOML resolver set with failover.
- `:68` still says plain DNS over TCP only, while `:651-701` authorizes DoT and SPKI pinning.
- `:71` permits cross-suffix CNAME targets, while `:540` confines followed links to allowlist-derived bailiwick zones.
- `:75` and the profile row at `:180` still describe 72-hour stale authorization, while RT-006 introduces the independent one-hour stale-serving window implemented in `src/cache.rs:12-15,134-142`.
- `:76-77` retain 30/300-second refresh formulas, while the profile and code use 5/900 normal and 30/900 negative intervals.

**Risk**: The amendments do authorize the newer behavior, so this is not evidence that the implementation chose the wrong side. It is a specification-integrity weakness: an auditor or future implementation reading the normative body can restore weaker transport, provenance, freshness, or retry behavior while believing it is compliant. It also makes invariant citations ambiguous during security review.

**Fix**: Fold each authorized amendment into the original body and profile rows, leaving the amendment history as history rather than as a second competing ruleset. In particular, make stale **retention** versus stale **serving** explicit wherever authorization lifetime is stated.

**Reference**: https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration

---

### [INFO] Explicitly accepted trust-model limitations were not counted as new defects

The following remain adversarial capabilities but are explicitly accepted or previously remediated in the governing document, so they are not duplicated as findings here: no upstream certificate/origin authentication (`:15`, `:50`); plaintext resolver arrays as a degraded trust form; parent-zone CNAME bailiwick granularity (RT-005); pinned-certificate validity being warning-only (RT-007); no local DNSSEC validation; and the CONNECT response-corpus oracle (SP-008). Deployments must account for these residuals separately from the implementation defects above.

## Action items

1. Make DNS name comparison label-aware and add an embedded-dot query-binding regression before relying on any CNAME/bailiwick result.
2. Apply the earliest TTL across duplicate supporting CNAMEs and prove order independence through to cache deadlines.
3. Enforce exchange/startup deadlines before publication and cancel all outstanding startup work at window expiry.
4. Correct root-SOA coverage.
5. Reconcile the governing specification's body with its authorized amendments.

## What looks good

- CONNECT authority-form parsing, exact `<fqdn>:<port>` allowlist matching, IP-literal rejection, and normalized SNI comparison form a coherent authorization chain.
- The serving path keeps client and upstream bytes behind separate barriers until complete ClientHello validation and successful forwarding through the validated boundary.
- Destination candidates are filtered at publication and checked again at peer selection, with fixed public-address tables matching the stated profile.
- DoT strict-pin validation checks both SAN identity and SPKI equality and does not silently downgrade a failed DoT exchange to plaintext.
- DNS response parsing has explicit message/record/candidate/chain bounds, backward-only compression pointers, exact question type/class/TID checks, and staged cache/schedule application.

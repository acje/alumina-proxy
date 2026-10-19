# Alumina — Future Hardening Vectors (research register)

**Status:** read-only research roadmap. This document **does not amend**
`docs/alumina-proxy.md` (the sole, byte-canonical governing specification) and
carries no normative authority. It restates and cites the canonical spec and
the implementation only, and enumerates candidate hardening vectors for
**research and feasibility study** — not for immediate implementation. Any
vector that reaches implementation is a **spec amendment requiring explicit
user authorization** (`AGENTS.md`: "no further amendment authority is implied"),
and the open serving-qualification gates (F1–F4, BOUNDARY, E2E —
`docs/build-plan.md`) should close before any hardening feature lands.

## 1. Baseline DNS posture (already implemented)

| Control | Status | Evidence |
|---|---|---|
| DNS over TCP only, 1 conn / 1 outstanding query | Implemented | `docs/alumina-proxy.md:68`; `src/dns.rs` |
| CSPRNG transaction IDs (`getrandom`) | Implemented | `docs/alumina-proxy.md:68` |
| Strict response validation (flag, opcode, TID, question name/type/class match; truncation/oversize rejection) | Implemented | `src/dns.rs:753-1010` |
| CNAME provenance (≤8 links, no loops, no conflicting targets, no CNAME/A coexistence, no DNAME) | Implemented | `docs/alumina-proxy.md:71`; `src/dns.rs:1016-1057` |
| Answer-section-only candidates (authority/additional never become candidates) | Implemented | `docs/alumina-proxy.md:71`; `src/dns.rs` |
| Destination-address eligibility (globally routable unicast only; blocks private/loopback/link-local/CGNAT/6to4/Teredo/NAT64) | Implemented | `docs/alumina-proxy.md:73`; `src/eligibility.rs` |
| TTL: 0 treated as 1 s; honored TTL capped at 86400 s (L12; max auth lifetime 345600 s) | Implemented | `docs/alumina-proxy.md:74,377-379` |
| Bounded stale grace (72 h), negative-answer eviction, retry backoff, incident summaries | Implemented | `docs/alumina-proxy.md:74-82` |
| Fixed peer per tunnel; per-attempt revalidation; no DNS-rebinding exposure | Implemented | `docs/alumina-proxy.md:82` |
| Upstream certificate validation | **Out of scope by design** (non-decrypting invariant IV-3) | `docs/alumina-proxy.md:15,50,219`; `traceability.md:68` |
| **0x20 case randomization** | **Absent** | no match in `src/` |
| **QNAME minimization (RFC 7816)** | **Absent** | no match in `src/` |
| **EDNS0 / DO bit / DNSSEC validation** | **Absent** | `docs/alumina-proxy.md:63` (explicitly out of scope) |
| **DoT / DoH / DNSCrypt / DoQ** | **Absent** | `docs/alumina-proxy.md:63`; `build-plan.md:186` (non-goal) |
| **Multi-resolver / fallback / split-horizon cross-check** | **Absent** | 1 resolver, no fallback (`docs/alumina-proxy.md:68`) |
| **Full bailiwick enforcement on CNAME targets** | **Partial** | answer-section provenance only; cross-suffix CNAME accepted (`docs/alumina-proxy.md:71`) |

## 2. All candidate hardening vectors (grouped by threat-model dimension)

### A. Channel confidentiality & integrity (on-path tampering of the resolver query/response)

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 1 | **DNS-over-TLS (DoT)** | On-path injection of fake responses | High (new TLS client dep, cert handling, resource profile) | Low — explicit non-goal | Feasibility study; defer unless user authorizes amendment |
| 2 | **DNS-over-HTTPS (DoH)** | Same via 443; bootstrap/CA complexity | High | Low — non-goal | Feasibility study; defer |
| 3 | **DNSCrypt** | Authenticated channel (less standard) | Medium | Low | Low priority |
| 4 | **DNS-over-QUIC (DoQ)** | Low-latency encrypted DNS | High | Low — Alumina is TCP-only by design | Low priority |
| 5 | **Resolver certificate pinning / TOFU** | CA-compromise resistance | Medium | Low (prerequisite for DoT) | Study as part of DoT |

### B. Data authenticity (end-to-end; defends against a *compromised* resolver)

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 6 | **DNSSEC validation** | Forged records even from a malicious/poisoned resolver — strongest fit to the "fake DNS record" threat | High (new crypto, new dependency, resource profile) | Low | **Top research priority** — feasibility study for a zero-alloc fixed-profile validating stub |
| 7 | **AD-bit / DO-bit handling** | Require authenticated data; treat unauthenticated answers as lower-trust | Medium | Low | Study as part of DNSSEC |
| 8 | **Multi-resolver cross-validation / split-horizon detection** | Detect a single compromised resolver | High | Low — violates 1-conn/1-query + no-fallback doctrine | Defer; document as a design-revision candidate |

### C. Response-format hardening (off-path / cache-poisoning resistance)

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 9 | **0x20 case randomization** | Off-path spoofing (correct response must echo randomized case) | Low–medium | Medium (wire change; question-match impact) | **Top research priority** — study impact on lowercase normalization + question-match validation |
| 10 | **EDNS0 / larger-buffer negotiation** | Truncation | Low | Low value (TCP-only avoids truncation) | Low priority |
| 11 | **Bailiwick enforcement on CNAME targets** | CNAME chaining into attacker zones | Medium | Medium (narrow amendment) | **Top research priority** — restrict CNAME targets to allowlisted/known zones; measure breakage |
| 12 | **Source-port randomization** | Off-path spoofing | N/A | N/A (TCP only; TID already CSPRNG) | Not applicable |
| 13 | **Strict answer-section-only acceptance** | Poisoning via authority/additional | Done | — | Covered |
| 33 | **Wrong-family records in a positive answer: tolerated vs. rejected** | Ambiguity in `:71` — a wrong-family record (e.g., AAAA in an A query's answer section) is currently tolerated-and-ignored (never a candidate) unless it coexists with a CNAME at its owner (which fails, `CnameCoexist`); the spec does not state this explicitly | Low | Medium (clarity pin) | Pin the tolerated-and-ignored behavior in the spec to match `src/dns.rs:824-829,848-855`, or decide fail-closed; avoids a spec/code drift like the F6 case |

### D. Cache & TTL policy hardening

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 14 | **TTL floor (min-TTL)** | Reject/raise implausibly low TTLs | Low | Low — contradicts `:74` (deliberate zero-TTL-steering support) | Study the tradeoff; low value for a server |
| 15 | **TTL cap** | Long-lived poisoned/stale records | Done (L12, 86400 s) | — | Covered |
| 16 | **Stale-answer / RFC 8767 served-stale** | Availability vs freshness | Done (72 h) | — | Covered |
| 17 | **Authoritative-freshness bound** | Resolver returning stale data as fresh | Medium | Medium (deployment-side) | Study deployment-enforced upstream stale bound (`docs/alumina-proxy.md:130`) |

### E. Availability & resilience (DNS DoS / resolver failure)

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 18 | **Multi-resolver failover** | Resolver outage | Medium | Low — contradicts no-fallback doctrine | Defer; document as design-revision candidate |
| 19 | **Resolver health probing / degraded signaling** | Early detection of SERVFAIL/timeout storms | Low | Medium | Low priority (incidents already cover this) |
| 20 | **Query pacing / rate limiting** | Query flooding / monopolization | Done (1 query/sec/name) | — | Covered |

### F. Detection & observability of tampering

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 21 | **Anomaly logging / tripwire on suspicious DNS** | Detect unexpected TTLs, bailiwick violations, CNAME anomalies, resolver identity changes; feed rp2e enforcement | Medium–high | Medium (log-vocabulary amendment) | **Top research priority** — which anomalies are signal vs noise for a server |
| 22 | **Resolver identity / response-source verification** | Confirm responses originate from the configured resolver | Low | Low (TCP peer is the resolver, so partially inherent) | Low priority |
| 23 | **Cross-resolver divergence reporting** | Detect resolver disagreement | Low | Low (only meaningful with multi-resolver) | Low priority unless vector 8 |
| 24 | **Startup-DNS trust-boundary hardening** | Encrypted/authenticated resolver config (currently plaintext `resolv.conf`) | Low–medium | Medium | Study |

### G. Privacy / information-leakage reduction

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 25 | **QNAME minimization (RFC 7816)** | Reduce name leakage to resolvers; reduce poisoning surface | Medium | Medium | Low priority (single-resolver full-FQDN queries limit value) |
| 26 | **Query-name normalization / IDN** | Homograph/IDN confusion | Done (A-label only) | — | Covered |

### H. Protocol / feature-surface hardening

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 27 | **DNAME rejection** | Synthesized CNAME abuse | Done | — | Covered |
| 28 | **Additional/authority-section strictness** | Poisoning via non-answer sections | Done (never candidates) | — | Covered |
| 29 | **Message-size / record-count caps** | Oversized/amplified responses | Done (16 KiB / 128 RR) | — | Covered |
| 34 | **ClientHello handshake-length field bound** | The 3-byte handshake `length` is bounded only indirectly via the 64 KiB buffered-TLS cap (`:165`) and 16 KiB record-payload cap (`:166`); not stated explicitly | Low | Medium (clarity pin) | Add explicit bound: a ClientHello whose handshake `length` exceeds the buffered-TLS bound is rejected as malformed framing |
| 35 | **CONNECT header-line count bound** | CONNECT headers capped at 8 KiB (`:164`) but no explicit max header-line count | Low | Medium (clarity pin) | Add explicit header-count bound to the resource profile |
| 36 | **Non-CONNECT method / request-target form rejection** | Spec says "plaintext HTTP/1.1 CONNECT" but does not explicitly enumerate rejecting other methods or non-authority-form request-targets (rejected indirectly via hostname authorization) | Low | Medium (clarity pin) | Add explicit "reject any method other than CONNECT" and "reject request-target not in authority-form" |

### I. Application-layer / post-resolution hardening (beyond DNS itself)

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 30 | **Upstream certificate validation** | Fake/malicious upstream | N/A — non-decrypting invariant IV-3 | N/A | Deployment/operator vector only (operator-owned CONNECT+TLS check, `docs/alumina-proxy.md:122`) |
| 31 | **DNS-rebinding defense** | Attacker-controlled IP rotation | Done (fixed peer + per-attempt revalidation) | — | Covered |
| 32 | **CNAME-chain pinning to known-good zones** | Chaining into attacker zones | Medium | Medium | Overlaps vector 11 |

## 3. Ranked research priorities

Ranked by **value-to-Alumina ÷ cost-and-doctrine-fit**:

| Rank | Vector | Why | Doctrine fit | Research action |
|---|---|---|---|---|
| 1 | **DNSSEC validation (B6/B7)** | Directly defeats the "fake DNS record" threat even against a *compromised* resolver — the strongest hardening | Low | Feasibility study: minimal validating stub (crypto, memory, deadline) |
| 2 | **Bailiwick on CNAME targets (C11)** | Closes the documented cross-suffix-CNAME accepted limitation; cheap, spec-adjacent | Medium | Study: restrict CNAME targets to allowlisted/known zones; measure breakage |
| 3 | **0x20 case randomization (C9)** | Cheap off-path poisoning defense; well-understood | Medium | Study: impact on lowercase normalization + question-match validation |
| 4 | **Anomaly detection/tripwire on DNS (F21)** | Fits existing incident + rp2e enforcement machinery | Medium | Study: which anomalies are signal vs noise for a server |
| 5 | **DoT/DoH (A1/A2)** | The consumer-facing recommendation; explicit non-goal, high cost | Low | Defer unless user authorizes amendment |
| 6 | **Multi-resolver cross-validation (B8)** | High value but violates 1-conn/1-query + no-fallback doctrine | Low | Defer; document as a design-revision candidate |
| 7 | **QNAME minimization (G25)** | Limited value for single-resolver full-FQDN queries | Low | Low priority |

## 4. Risks / abort conditions

- **Any vector reaching implementation is a spec amendment requiring explicit user authorization** (doctrine). Abort any such work without it.
- **DNSSEC / DoT / DoH add crypto dependencies** that risk breaking the zero-allocation and fixed-resource-profile invariants (`docs/alumina-proxy.md:206-207`); research must explicitly scope memory + deadline feasibility before any design.
- **The open serving-qualification gates** (F1–F4, BOUNDARY, E2E — `docs/build-plan.md`) should close before any hardening feature lands.

## 5. Open questions (blocking, medium+ risk)

1. Which vectors to dispatch for research first — recommendation: the top-4 (DNSSEC feasibility, CNAME bailiwick, 0x20, DNS anomaly tripwire).
2. Whether a spec amendment is on the table at all (e.g., DoT/DoH or DNSSEC), or whether this research strictly informs a future decision while staying within the fixed spec for now.

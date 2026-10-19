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

**Pruned (2026-10-19):** vectors 13, 15, 16, 20, 26, 27, 28, 29, 31 were
removed from the candidate register as **fully covered** — each is implemented
and verified in the current codebase (see §1 Baseline DNS posture and
`docs/future-hardening-vectors-scorecard.md`). Vectors 2 (DoH), 3 (DNSCrypt),
4 (DoQ), and 25 (QNAME minimization) were additionally pruned as
**low-plausibility / high-risk research discards** (see scorecard). On the same
date vectors 33, 34, and 36 were **promoted out of candidate research as
implemented and pinned**: their formerly ambiguous behavior was sharpened in the
`alumina-hrdn` hardening increment (recorded in `docs/alumina-proxy.md`) and
each row below is marked **DONE** with its pinned semantics and code location.
On the same date vectors 14, 19, and 35 were **implemented** via the
`alumina-hrdn2` hardening increment (recorded in `docs/alumina-proxy.md`) and
each row below is marked **DONE** with its pinned semantics and code location.
Vectors 1 (DoT), 5 (cert pinning), 6 (DNSSEC), and 8 (multi-resolver
cross-validation) are **deferred** (marked **DEFERRED** below): high
architectural risk for high-but-costly security value, retained for research
only. Vector numbers are retained as stable identifiers; gaps are intentional.

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
| 1 | **DEFERRED** **DNS-over-TLS (DoT)** | On-path injection of fake responses | High (new TLS client dep, cert handling, resource profile) | Low — explicit non-goal | Feasibility study; defer unless user authorizes amendment |
| 5 | **DEFERRED** **Resolver certificate pinning / TOFU** | CA-compromise resistance | Medium | Low (prerequisite for DoT) | Study as part of DoT |

### B. Data authenticity (end-to-end; defends against a *compromised* resolver)

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 6 | **DEFERRED** **DNSSEC validation** | Forged records even from a malicious/poisoned resolver — strongest fit to the "fake DNS record" threat | High (new crypto, new dependency, resource profile) | Low | **Top research priority** — feasibility study for a zero-alloc fixed-profile validating stub |
| 7 | **AD-bit / DO-bit handling** | Require authenticated data; treat unauthenticated answers as lower-trust | Medium | Low | Study as part of DNSSEC |
| 8 | **DEFERRED** **Multi-resolver cross-validation / split-horizon detection** | Detect a single compromised resolver | High | Low — violates 1-conn/1-query + no-fallback doctrine | Defer; document as a design-revision candidate |

### C. Response-format hardening (off-path / cache-poisoning resistance)

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 9 | **0x20 case randomization** | Off-path spoofing (correct response must echo randomized case) | Low–medium | Medium (wire change; question-match impact) | **Top research priority** — study impact on lowercase normalization + question-match validation |
| 10 | **EDNS0 / larger-buffer negotiation** | Truncation | Low | Low value (TCP-only avoids truncation) | Low priority |
| 11 | **Bailiwick enforcement on CNAME targets** | CNAME chaining into attacker zones | Medium | Medium (narrow amendment) | **Top research priority** — restrict CNAME targets to allowlisted/known zones; measure breakage |
| 12 | **Source-port randomization** | Off-path spoofing | N/A | N/A (TCP only; TID already CSPRNG) | Not applicable |
| 33 | **DONE** **Wrong-family records in a positive answer: tolerated vs. rejected** *(implemented & pinned, 2026-10-19)* | Ambiguity in `:71` — a wrong-family record (e.g., AAAA in an A query's answer section) is tolerated-and-ignored (never a candidate) and never marks its terminal owner as carrying address data; coexist with a CNAME at its owner still fails `CnameCoexist` | Low | Medium (clarity pin) | **Pinned by `alumina-hrdn`** (2026-10-19): promoted out of candidate research; wrong-family records are truly ignored (`src/dns.rs:824-830,847-853`), and NXDOMAIN at an opposite-family-only terminal is a clean `NxDomain`, never `TerminalWithoutData` |

### D. Cache & TTL policy hardening

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 14 | **DONE** **TTL floor (min-TTL)** *(widened refresh band, implemented 2026-10-19)* | Reject/raise implausibly low TTLs | Low | Low — contradicts `:74` (deliberate zero-TTL-steering support) | **Widened by `alumina-hrdn2`** (2026-10-19): promoted out of candidate research; the refresh band is widened to `REFRESH_MIN=5` / `REFRESH_MAX=900` with `NEGATIVE_REFRESH_MIN=30`, and normal/negative refresh intervals clamp into those bands (`src/schedule.rs`) — per-record low-TTL steering per `:74` is untouched (`src/cache.rs`) |
| 17 | **Authoritative-freshness bound** | Resolver returning stale data as fresh | Medium | Medium (deployment-side) | Study deployment-enforced upstream stale bound (`docs/alumina-proxy.md:130`) |

### E. Availability & resilience (DNS DoS / resolver failure)

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 18 | **Multi-resolver failover** | Resolver outage | Medium | Low — contradicts no-fallback doctrine | Defer; document as design-revision candidate |
| 19 | **DONE** **Resolver health probing / degraded signaling** *(implemented, 2026-10-19)* | Early detection of SERVFAIL/timeout storms | Low | Medium | **Implemented by `alumina-hrdn2`** (2026-10-19): promoted out of candidate research; passive degraded signaling in `StartupDns` — ≥3 consecutive failed exchanges (`DEGRADED_AFTER=3`) enter `Degraded`, any successful exchange (a valid negative included) recovers; `ResolverDegraded` monitor fact emitted only on enter/exit transitions and surfaced as the zero-suppressed `rd=` monitor key (`src/startup_dns.rs`, `src/enforcement/monitor.rs`, `src/enforcement/state.rs`, `src/log.rs`) |

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
| *(pruned: 25 QNAME minimization)* | | | | | |

### H. Protocol / feature-surface hardening

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 34 | **DONE** **ClientHello handshake-length field bound** *(implemented & pinned, 2026-10-19)* | The 3-byte handshake `length` is bounded only indirectly via the 64 KiB buffered-TLS cap (`:165`) and 16 KiB record-payload cap (`:166`); now stated explicitly | Low | Medium (clarity pin) | **Pinned by `alumina-hrdn`** (2026-10-19): promoted out of candidate research; a ClientHello handshake message whose `4 + length` exceeds 16 KiB is rejected with a distinct `HandshakeTooLarge` discriminant (`src/client_hello.rs:MAX_HANDSHAKE_LEN`, `scan_available`) |
| 35 | **DONE** **CONNECT header-line count bound** *(implemented, 2026-10-19)* | CONNECT headers capped at 8 KiB (`:164`) but no explicit max header-line count | Low | Medium (clarity pin) | **Implemented by `alumina-hrdn2`** (2026-10-19): promoted out of candidate research; an explicit `MAX_HEADER_LINES=16` bound rejects a CONNECT head with a header-line count >16 via a distinct `TooManyHeaderLines` (`ConnectError` + `ConnectHeadReason`, `src/connect.rs`), rippling `ConnectHeadReason::COUNT` 13→14 and `AnyIllegalCause::KIND_COUNT` 18→19 on the rp2e tripwire surface |
| 36 | **DONE** **Non-CONNECT method / request-target form rejection** *(implemented & pinned, 2026-10-19)* | Spec says "plaintext HTTP/1.1 CONNECT" but does not explicitly enumerate rejecting other methods or non-authority-form request-targets (rejected indirectly via hostname authorization) | Low | Medium (clarity pin) | **Pinned by `alumina-hrdn`** (2026-10-19): promoted out of candidate research; a method other than byte-exact `CONNECT`, a version other than `HTTP/1.1`, and a non-authority-form request-target each carry distinct finite discriminants (`src/connect.rs` `MethodNotConnect`/`UnsupportedVersion`/`TargetNotAuthorityForm`) feeding the rp2e tripwire surface |

### I. Application-layer / post-resolution hardening (beyond DNS itself)

| # | Vector | Threat addressed | Cost | Doctrine fit | Research action |
|---|---|---|---|---|---|
| 30 | **Upstream certificate validation** | Fake/malicious upstream | N/A — non-decrypting invariant IV-3 | N/A | Deployment/operator vector only (operator-owned CONNECT+TLS check, `docs/alumina-proxy.md:122`) |
| 32 | **CNAME-chain pinning to known-good zones** | Chaining into attacker zones | Medium | Medium | Overlaps vector 11 |

## 3. Ranked research priorities

Ranked by **value-to-Alumina ÷ cost-and-doctrine-fit**:

| Rank | Vector | Why | Doctrine fit | Research action |
|---|---|---|---|---|
| 1 | **DNSSEC validation (B6/B7)** | Directly defeats the "fake DNS record" threat even against a *compromised* resolver — the strongest hardening | Low | Feasibility study: minimal validating stub (crypto, memory, deadline) |
| 2 | **Bailiwick on CNAME targets (C11)** | Closes the documented cross-suffix-CNAME accepted limitation; cheap, spec-adjacent | Medium | Study: restrict CNAME targets to allowlisted/known zones; measure breakage |
| 3 | **0x20 case randomization (C9)** | Cheap off-path poisoning defense; well-understood | Medium | Study: impact on lowercase normalization + question-match validation |
| 4 | **Anomaly detection/tripwire on DNS (F21)** | Fits existing incident + rp2e enforcement machinery | Medium | Study: which anomalies are signal vs noise for a server |
| 5 | **DoT (A1)** | The consumer-facing recommendation; explicit non-goal, high cost | Low | Defer unless user authorizes amendment |
| 6 | **Multi-resolver cross-validation (B8)** | High value but violates 1-conn/1-query + no-fallback doctrine | Low | Defer; document as a design-revision candidate |

## 4. Risks / abort conditions

- **Any vector reaching implementation is a spec amendment requiring explicit user authorization** (doctrine). Abort any such work without it.
- **DNSSEC / DoT add crypto dependencies** that risk breaking the zero-allocation and fixed-resource-profile invariants (`docs/alumina-proxy.md:206-207`); research must explicitly scope memory + deadline feasibility before any design.
- **The open serving-qualification gates** (F1–F4, BOUNDARY, E2E — `docs/build-plan.md`) should close before any hardening feature lands.

## 5. Open questions (blocking, medium+ risk)

1. Which vectors to dispatch for research first — recommendation: the top-4 (DNSSEC feasibility, CNAME bailiwick, 0x20, DNS anomaly tripwire).
2. Whether a spec amendment is on the table at all (e.g., DoT or DNSSEC), or whether this research strictly informs a future decision while staying within the fixed spec for now.

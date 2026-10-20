# Alumina — Future Hardening Vectors: Scorecard

**Status:** read-only research artifact. This document **does not amend**
`docs/alumina-proxy.md` (the sole, byte-canonical governing specification) and
carries no normative authority. It is a scored companion to
`docs/future-hardening-vectors.md` (the vector register), restating and citing the
implementation only.

**Scope:** the 19 active hardening vectors from `docs/future-hardening-vectors.md`
(excluded: 12, 30 — not applicable by design; 17 — pruned 2026-10-19 as a
deployment-side vector, rationale below). Vectors 13, 15, 16, 20, 26, 27,
28, 29, 31 were pruned from the register as fully covered, and vectors 2 (DoH),
3 (DNSCrypt), 4 (DoQ), 9 (0x20 case randomization), 25 (QNAME minimization) as
low-plausibility/high-risk research discards (2026-10-19); vector 9 is strictly
dominated by the TCP + CSPRNG-TID transport and adds zero value under the future
DoT path. Vector 17 (authoritative-freshness bound) was pruned as a
**deployment-side vector** (2026-10-19): Alumina cannot observe the age of
authoritative data, the genuine upstream stale-answer bound is deployment-enforced
resolver serve-stale control (RFC 8767) already recorded as a deployment
responsibility at `docs/alumina-proxy.md:130`, and the only Alumina-side lever (a
configurable honored-TTL cap) does not bound total staleness across renewals —
analogous to vector 30 (deployment/operator vector only). Its row is removed
from the ranked table below; the rationale is recorded here for the record.
Since scoring (2026-10-19), vectors 33, 34, and
36 were **implemented and pinned** via the `alumina-hrdn` hardening increment
(`docs/alumina-proxy.md`); they are marked **DONE** in the ranked table and
per-vector detail sections, and their rows remain with their original scores.
On the same date vectors 14, 19, and 35 were **implemented** via the
`alumina-hrdn2` hardening increment (`docs/alumina-proxy.md`); they are likewise
marked **DONE** below, with rows remaining at their original scores.
On the same date vectors 11, 21, 22, and 32 were **implemented** via the
`alumina-hrdn3` hardening increment (`docs/alumina-proxy.md`); they are likewise
marked **DONE** below, with rows remaining at their original scores.
On 2026-10-20 vectors 24 and 18 were **implemented** via the `alumina-hrdn4`
hardening increment (`docs/alumina-proxy.md`); they are likewise marked
**DONE** below, with rows remaining at their original scores.
Vectors 1 (DoT), 5 (cert pinning), 6 (DNSSEC), 7 (AD-bit / DO-bit handling),
and 8 (multi-resolver cross-validation) are **deferred** (marked **DEFERRED**):
high architectural risk for high-but-costly security value, retained for
research only. Vector 7 defers as a dependent of 6 — the AD/DO bits are only
meaningful with authenticated data. Vector 37 (resolver endpoint as IP+FQDN,
golden path) was added to the register as a candidate on 2026-10-20; it is not
yet scored (pending the 8-rater evaluation) and is therefore not ranked below.

**Method:** 8 independent deep-analysis scores per vector = 4 `linus` (Rust-specialist)
+ 4 `general` raters. Every rater read the actual source before scoring. Scores are 1–10.

**Scoring goal:** *an advanced explicit forward proxy for secure high-trust egress
filtering of TLS tunnels* — NOT the existing fixed spec invariants.

**Rubric:**
- **Effectiveness** — how much the vector advances the product goal (security, trust, egress-filtering capability).
- **Plausibility** — feasibility of implementing it WELL in this codebase (zero-alloc, fixed-resource profile; deps/crypto/memory/complexity).
- **Risk** (architectural-change risk) — 1 = localized change … 10 = core redesign.
- **Overall** = mean(effectiveness, plausibility). Risk reported separately (not folded into rank).

Generated from `scores.jsonl` (200 score lines; 19 scored vectors shown).

## Ranked table

| Rank | # | Vector | Overall | Eff | Plaus | Risk |
|---|---|---|---|---|---|---|
| 1 | 11 | **DONE** Bailiwick enforcement on CNAME targets — implemented (2026-10-19) | 7.88 | 7.88 | 7.88 | 3.12 |
| 2 | 21 | **DONE** Anomaly logging / tripwire on DNS — implemented (2026-10-19) | 7.69 | 7.75 | 7.62 | 3.38 |
| 3 | 14 | **DONE** TTL floor (min-TTL) — implemented (2026-10-19) | 7.62 | 5.88 | 9.38 | 2.00 |
| 4 | 34 | **DONE** ClientHello handshake-length field bound — implemented (2026-10-19) | 7.50 | 5.50 | 9.50 | 1.12 |
| 5 | 19 | **DONE** Resolver health probing / degraded signaling — implemented (2026-10-19) | 7.44 | 6.50 | 8.38 | 2.38 |
| 6 | 32 | **DONE** CNAME-chain pinning to known-good zones — implemented (2026-10-19) | 7.44 | 7.38 | 7.50 | 3.00 |
| 7 | 24 | **DONE** Startup-DNS trust-boundary hardening — implemented (2026-10-20) | 7.12 | 7.12 | 7.12 | 2.75 |
| 8 | 33 | **DONE** Wrong-family records tolerated-vs-rejected pin — implemented (2026-10-19) | 6.81 | 4.38 | 9.25 | 1.38 |
| 9 | 36 | **DONE** Non-CONNECT method / request-target form rejection — implemented (2026-10-19) | 6.81 | 4.12 | 9.50 | 1.12 |
| 10 | 7 | **DEFERRED** AD-bit / DO-bit handling | 6.56 | 6.62 | 6.50 | 4.50 |
| 11 | 22 | **DONE** Resolver identity / response-source verification — implemented (2026-10-19) | 6.50 | 5.38 | 7.62 | 2.75 |
| 12 | 35 | **DONE** CONNECT header-line count bound — implemented (2026-10-19) | 6.50 | 3.62 | 9.38 | 1.25 |
| 13 | 18 | **DONE** Multi-resolver failover — implemented (2026-10-20) | 6.38 | 5.50 | 7.25 | 4.38 |
| 14 | 23 | Cross-resolver divergence reporting | 6.12 | 4.88 | 7.38 | 4.50 |
| 15 | 5 | **DEFERRED** Resolver cert pinning / TOFU | 6.06 | 7.25 | 4.88 | 6.75 |
| 16 | 8 | **DEFERRED** Multi-resolver cross-validation | 6.00 | 7.75 | 4.25 | 8.00 |
| 17 | 1 | **DEFERRED** DNS-over-TLS (DoT) | 5.62 | 7.88 | 3.38 | 7.12 |
| 18 | 6 | **DEFERRED** DNSSEC validation | 5.62 | 8.75 | 2.50 | 8.12 |
| 19 | 10 | EDNS0 / larger-buffer negotiation | 3.69 | 1.12 | 6.25 | 1.62 |

## Per-vector detail (all 8 scores, eff/plaus/risk)

### Rank 1 — Vector 11: Bailiwick enforcement on CNAME targets — **DONE**

Overall **7.88** · Eff **7.88** · Plaus **7.88** · Risk **3.12**

**Status:** **DONE** — implemented (2026-10-19, `alumina-hrdn3`) — a followed
CNAME link must land inside an allowlist bailiwick zone (parent domain for
>2-label names, the apex itself for 2-label names) or the exchange fails with
`BailiwickViolation` (`BailiwickZones`, `src/dns.rs:769-816`, gate at `:1142`).

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 9 | 8 | 3 |
| general | 7 | 8 | 3 |
| general | 7 | 8 | 3 |
| linus | 9 | 8 | 3 |
| general | 7 | 8 | 3 |
| general | 6 | 8 | 3 |
| linus | 9 | 8 | 3 |
| linus | 9 | 7 | 4 |

### Rank 2 — Vector 21: Anomaly logging / tripwire on DNS — **DONE**

Overall **7.69** · Eff **7.75** · Plaus **7.62** · Risk **3.38**

**Status:** **DONE** — implemented (2026-10-19, `alumina-hrdn3`) — a typed
`DnsAnomalyKind` surface (`BailiwickViolation`/`ResolverPeerMismatch`/`ExtremeTtl`,
incl. >96 h extreme-TTL detection) drains via `drain_dns_anomalies` into
saturating rp2e counters surfaced as zero-suppressed `bv=`/`rpm=`/`xttl=`
monitor keys (`src/enforcement/monitor.rs`, `src/startup_dns.rs`, `src/serve.rs`,
`src/log.rs`).

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 9 | 8 | 3 |
| linus | 9 | 7 | 4 |
| general | 7 | 8 | 3 |
| general | 7 | 8 | 3 |
| general | 6 | 7 | 3 |
| general | 6 | 8 | 3 |
| linus | 9 | 7 | 4 |
| linus | 9 | 8 | 4 |

### Rank 3 — Vector 14: TTL floor (min-TTL) — **DONE**

Overall **7.62** · Eff **5.88** · Plaus **9.38** · Risk **2.00**

**Status:** **DONE** — implemented (2026-10-19, `alumina-hrdn2`) — refresh
intervals widened: `normal_refresh_interval` clamps to
`[REFRESH_MIN=5, REFRESH_MAX=900]` and `negative_refresh_interval` to
`[NEGATIVE_REFRESH_MIN=30, REFRESH_MAX]` (`src/schedule.rs`), distinct from the
per-record TTL clamp (`src/cache.rs`; `docs/alumina-proxy.md:74` low-TTL
steering untouched); the 1 query/sec/slot rate guard still covers a 5 s polling
cadence.

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 7 | 10 | 2 |
| general | 4 | 9 | 2 |
| general | 6 | 9 | 2 |
| linus | 8 | 10 | 2 |
| linus | 7 | 9 | 2 |
| general | 4 | 9 | 2 |
| general | 4 | 9 | 2 |
| linus | 7 | 10 | 2 |

### Rank 4 — Vector 34: ClientHello handshake-length field bound — **DONE**

Overall **7.50** · Eff **5.50** · Plaus **9.50** · Risk **1.12**

**Status:** **DONE** — implemented & pinned (2026-10-19, `alumina-hrdn`) — a ClientHello handshake message whose `4 + length` exceeds 16 KiB (`MAX_HANDSHAKE_LEN`) is rejected with a distinct `HandshakeTooLarge` discriminant.

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| general | 2 | 9 | 1 |
| general | 4 | 9 | 1 |
| linus | 8 | 10 | 1 |
| linus | 8 | 10 | 2 |
| general | 3 | 9 | 1 |
| general | 3 | 9 | 1 |
| linus | 8 | 10 | 1 |
| linus | 8 | 10 | 1 |

### Rank 5 — Vector 19: Resolver health probing / degraded signaling — **DONE**

Overall **7.44** · Eff **6.50** · Plaus **8.38** · Risk **2.38**

**Status:** **DONE** — implemented (2026-10-19, `alumina-hrdn2`) — passive
degraded signaling in `StartupDns`: ≥3 consecutive failed exchanges
(`DEGRADED_AFTER=3`) enter `Degraded`, any successful exchange (a valid negative
included) recovers; `ResolverDegraded` monitor fact emitted only on enter/exit
transitions and surfaced as the zero-suppressed `rd=` monitor key
(`src/startup_dns.rs`, `src/enforcement/monitor.rs`, `src/enforcement/state.rs`,
`src/log.rs`).

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 7 | 9 | 3 |
| general | 6 | 8 | 2 |
| general | 5 | 8 | 2 |
| linus | 7 | 8 | 3 |
| linus | 7 | 9 | 3 |
| general | 6 | 8 | 2 |
| general | 6 | 8 | 2 |
| linus | 8 | 9 | 2 |

### Rank 6 — Vector 32: CNAME-chain pinning to known-good zones — **DONE**

Overall **7.44** · Eff **7.38** · Plaus **7.50** · Risk **3.00**

**Status:** **DONE** — implemented (2026-10-19, `alumina-hrdn3`) — the
"known-good zones" pinning is realized by the same `BailiwickZones` gate as
vector 11: a followed link outside every allowlist zone fails the exchange with
`BailiwickViolation` (`src/dns.rs:769-816`, `:1142`).

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| general | 7 | 8 | 2 |
| general | 6 | 8 | 2 |
| general | 6 | 8 | 2 |
| general | 7 | 8 | 2 |
| linus | 8 | 7 | 4 |
| linus | 9 | 7 | 4 |
| linus | 8 | 7 | 4 |
| linus | 8 | 7 | 4 |

### Rank 7 — Vector 24: Startup-DNS trust-boundary hardening — **DONE**

Overall **7.12** · Eff **7.12** · Plaus **7.12** · Risk **2.75**

**Status:** **DONE** — implemented (2026-10-20, `alumina-hrdn4`) — the resolver
endpoint moved into the validated TOML config as a mandatory `resolver` array
(1..=5 numeric unicast IPv4/IPv6, port 53, no zone id; `MAX_RESOLVERS=5`,
`src/resolver.rs:6`), the `resolv.conf` reader
(`read_resolver_config_file`/`parse_resolver_config`/`Scanner`) was deleted,
`run_boot(config_path)` reads the resolver from the validated config
(`src/boot.rs`), and the 4 KiB document preflight re-measured 4084 B with the
one-entry key (`src/config.rs:1204-1211`).

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| general | 7 | 7 | 3 |
| general | 6 | 7 | 2 |
| general | 6 | 8 | 2 |
| general | 6 | 7 | 2 |
| linus | 8 | 7 | 3 |
| linus | 8 | 7 | 3 |
| linus | 8 | 7 | 3 |
| linus | 8 | 7 | 4 |

### Rank 8 — Vector 33: Wrong-family records tolerated-vs-rejected pin — **DONE**

Overall **6.81** · Eff **4.38** · Plaus **9.25** · Risk **1.38**

**Status:** **DONE** — implemented & pinned (2026-10-19, `alumina-hrdn`) — a wrong-family record is truly ignored (never marks its terminal owner as carrying address data; `src/dns.rs:824-830,847-853`); NXDOMAIN at an opposite-family-only terminal is a clean `NxDomain`, never `TerminalWithoutData`.

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| general | 5 | 9 | 1 |
| general | 4 | 9 | 1 |
| general | 4 | 9 | 1 |
| general | 3 | 9 | 1 |
| linus | 7 | 10 | 2 |
| linus | 4 | 10 | 1 |
| linus | 4 | 9 | 2 |
| linus | 4 | 9 | 2 |

### Rank 9 — Vector 36: Non-CONNECT method / request-target form rejection — **DONE**

Overall **6.81** · Eff **4.12** · Plaus **9.50** · Risk **1.12**

**Status:** **DONE** — implemented & pinned (2026-10-19, `alumina-hrdn`) — the former `NotHttp` catch-all is split into distinct `MethodNotConnect` / `UnsupportedVersion` / `TargetNotAuthorityForm` finite discriminants feeding the rp2e tripwire surface (`ConnectHeadReason::COUNT` 11→13).

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| general | 2 | 9 | 1 |
| general | 3 | 9 | 2 |
| linus | 7 | 10 | 1 |
| linus | 4 | 10 | 1 |
| general | 2 | 9 | 1 |
| general | 4 | 9 | 1 |
| linus | 7 | 10 | 1 |
| linus | 4 | 10 | 1 |

### Rank 10 — Vector 7: AD-bit / DO-bit handling — **DEFERRED**

Overall **6.56** · Eff **6.62** · Plaus **6.50** · Risk **4.50**

**Status:** **DEFERRED** — dependent on DNSSEC (v6): the AD/DO bits are only meaningful with authenticated data; retained as part of the DNSSEC feasibility study.

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 8 | 6 | 5 |
| linus | 8 | 6 | 5 |
| general | 5 | 7 | 3 |
| general | 5 | 8 | 4 |
| linus | 8 | 6 | 5 |
| linus | 8 | 5 | 7 |
| general | 5 | 6 | 4 |
| general | 6 | 8 | 3 |

### Rank 11 — Vector 22: Resolver identity / response-source verification — **DONE**

Overall **6.50** · Eff **5.38** · Plaus **7.62** · Risk **2.75**

**Status:** **DONE** — implemented (2026-10-19, `alumina-hrdn3`) — a completed
connect landing on a peer other than the configured nameserver fails the
exchange (`FailureReason::Connect`) and counts a `ResolverPeerMismatch` anomaly
(`peer_matches`/`step_connect`, `src/startup_dns.rs:1010`, `:1216-1223`).

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| general | 3 | 8 | 1 |
| general | 6 | 5 | 6 |
| general | 4 | 9 | 2 |
| general | 2 | 8 | 1 |
| linus | 8 | 9 | 3 |
| linus | 4 | 8 | 2 |
| linus | 8 | 7 | 3 |
| linus | 8 | 7 | 4 |

### Rank 12 — Vector 35: CONNECT header-line count bound — **DONE**

Overall **6.50** · Eff **3.62** · Plaus **9.38** · Risk **1.25**

**Status:** **DONE** — implemented (2026-10-19, `alumina-hrdn2`) — CONNECT head
header-line count capped at `MAX_HEADER_LINES=16`; a count >16 rejects with a
distinct `TooManyHeaderLines` (`ConnectError` + `ConnectHeadReason`,
`src/connect.rs`), rippling `ConnectHeadReason::COUNT` 13→14 and
`AnyIllegalCause::KIND_COUNT` 18→19 on the rp2e tripwire surface.

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| general | 4 | 9 | 1 |
| general | 3 | 9 | 1 |
| linus | 4 | 10 | 2 |
| linus | 4 | 10 | 1 |
| general | 3 | 9 | 1 |
| general | 3 | 9 | 1 |
| linus | 4 | 10 | 1 |
| linus | 4 | 9 | 2 |

### Rank 13 — Vector 18: Multi-resolver failover — **DONE**

Overall **6.38** · Eff **5.50** · Plaus **7.25** · Risk **4.38**

**Status:** **DONE** — implemented (2026-10-20, `alumina-hrdn4`) — the
transport relocates across the validated `resolver` array under per-resolver
passive degradation (`DEGRADED_AFTER=3`), with bounded failback to the primary
(`FAILBACK_AFTER=900 s`), fail-closed on exhaustion, peer assertion vs the
active resolver only, and the 1-conn/1-query transport preserved
(`ActiveResolver`, `src/startup_dns.rs:588-615`; `on_exchange_failed` `:2012`;
`maybe_begin_failback` `:1792`; `peer_matches` `:1090`).

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 5 | 7 | 5 |
| general | 5 | 7 | 3 |
| general | 6 | 8 | 5 |
| linus | 4 | 6 | 7 |
| linus | 6 | 7 | 4 |
| general | 6 | 8 | 4 |
| general | 5 | 8 | 3 |
| linus | 7 | 7 | 4 |

### Rank 14 — Vector 23: Cross-resolver divergence reporting

Overall **6.12** · Eff **4.88** · Plaus **7.38** · Risk **4.50**

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| general | 4 | 8 | 2 |
| general | 5 | 7 | 3 |
| general | 5 | 8 | 3 |
| general | 5 | 6 | 6 |
| linus | 4 | 7 | 6 |
| linus | 6 | 8 | 5 |
| linus | 4 | 8 | 6 |
| linus | 6 | 7 | 5 |

### Rank 15 — Vector 5: Resolver cert pinning / TOFU — **DEFERRED**

Overall **6.06** · Eff **7.25** · Plaus **4.88** · Risk **6.75**

**Status:** **DEFERRED** — only valuable as a prerequisite of DoT (v1); deferred with it as the DoT trust model.

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 9 | 6 | 7 |
| linus | 9 | 4 | 7 |
| general | 6 | 5 | 7 |
| general | 6 | 4 | 7 |
| linus | 9 | 6 | 7 |
| linus | 9 | 6 | 7 |
| general | 6 | 3 | 6 |
| general | 4 | 5 | 6 |

### Rank 16 — Vector 8: Multi-resolver cross-validation — **DEFERRED**

Overall **6.00** · Eff **7.75** · Plaus **4.25** · Risk **8.00**

**Status:** **DEFERRED** — violates the 1-conn/1-query + no-fallback doctrine; a design-revision candidate, not an incremental hardening.

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 9 | 4 | 8 |
| linus | 9 | 3 | 9 |
| general | 7 | 6 | 8 |
| general | 6 | 4 | 8 |
| linus | 9 | 3 | 9 |
| linus | 9 | 4 | 8 |
| general | 7 | 6 | 6 |
| general | 6 | 4 | 8 |

### Rank 17 — Vector 1: DNS-over-TLS (DoT) — **DEFERRED**

Overall **5.62** · Eff **7.88** · Plaus **3.38** · Risk **7.12**

**Status:** **DEFERRED** — high architectural risk (new TLS client dep, cert handling, resource profile) for high security value; retained for research only. Defer unless the user authorizes a spec amendment.

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 9 | 3 | 8 |
| linus | 9 | 3 | 8 |
| general | 7 | 5 | 4 |
| general | 7 | 3 | 6 |
| linus | 8 | 4 | 9 |
| linus | 9 | 3 | 9 |
| general | 7 | 3 | 8 |
| general | 7 | 3 | 5 |

### Rank 18 — Vector 6: DNSSEC validation — **DEFERRED**

Overall **5.62** · Eff **8.75** · Plaus **2.50** · Risk **8.12**

**Status:** **DEFERRED** — highest effectiveness (8.75) but highest risk (8.12) and lowest plausibility (2.50); feasibility study required before any commitment.

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 9 | 3 | 8 |
| linus | 10 | 2 | 9 |
| general | 8 | 3 | 9 |
| general | 8 | 3 | 7 |
| linus | 9 | 2 | 9 |
| linus | 10 | 2 | 9 |
| general | 8 | 3 | 6 |
| general | 8 | 2 | 8 |

### Rank 19 — Vector 10: EDNS0 / larger-buffer negotiation

Overall **3.69** · Eff **1.12** · Plaus **6.25** · Risk **1.62**

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 1 | 8 | 2 |
| general | 1 | 8 | 1 |
| general | 2 | 9 | 1 |
| linus | 1 | 4 | 3 |
| linus | 1 | 4 | 2 |
| general | 1 | 7 | 1 |
| general | 1 | 7 | 1 |
| linus | 1 | 3 | 2 |


# Alumina — Future Hardening Vectors: Scorecard

**Status:** read-only research artifact. This document **does not amend**
`docs/alumina-proxy.md` (the sole, byte-canonical governing specification) and
carries no normative authority. It is a scored companion to
`docs/future-hardening-vectors.md` (the vector register), restating and citing the
implementation only.

**Scope:** the 22 active hardening vectors from `docs/future-hardening-vectors.md`
(excluded: 12, 30 — not applicable by design). Vectors 13, 15, 16, 20, 26, 27,
28, 29, 31 were pruned from the register as fully covered, and vectors 2 (DoH),
4 (DoQ), 25 (QNAME minimization) as low-plausibility/high-risk research discards
(2026-10-19). Since scoring (2026-10-19), vectors 33, 34, and 36 were
**implemented and pinned** via the `alumina-hrdn` hardening increment
(`docs/alumina-proxy.md`); their rows remain in the ranked table with their
original scores and are marked implemented in the per-vector detail sections.

**Method:** 8 independent deep-analysis scores per vector = 4 `linus` (Rust-specialist)
+ 4 `general` raters. Every rater read the actual source before scoring. Scores are 1–10.

**Scoring goal:** *an advanced explicit forward proxy for secure high-trust egress
filtering of TLS tunnels* — NOT the existing fixed spec invariants.

**Rubric:**
- **Effectiveness** — how much the vector advances the product goal (security, trust, egress-filtering capability).
- **Plausibility** — feasibility of implementing it WELL in this codebase (zero-alloc, fixed-resource profile; deps/crypto/memory/complexity).
- **Risk** (architectural-change risk) — 1 = localized change … 10 = core redesign.
- **Overall** = mean(effectiveness, plausibility). Risk reported separately (not folded into rank).

Generated from `scores.jsonl` (200 score lines; 22 scored vectors shown).

## Ranked table

| Rank | # | Vector | Overall | Eff | Plaus | Risk |
|---|---|---|---|---|---|---|
| 1 | 11 | Bailiwick enforcement on CNAME targets | 7.88 | 7.88 | 7.88 | 3.12 |
| 2 | 21 | Anomaly logging / tripwire on DNS | 7.69 | 7.75 | 7.62 | 3.38 |
| 3 | 14 | TTL floor (min-TTL) | 7.62 | 5.88 | 9.38 | 2.00 |
| 4 | 34 | ClientHello handshake-length field bound — implemented (2026-10-19) | 7.50 | 5.50 | 9.50 | 1.12 |
| 5 | 19 | Resolver health probing / degraded signaling | 7.44 | 6.50 | 8.38 | 2.38 |
| 6 | 32 | CNAME-chain pinning to known-good zones | 7.44 | 7.38 | 7.50 | 3.00 |
| 7 | 17 | Authoritative-freshness bound | 7.25 | 7.00 | 7.50 | 3.25 |
| 8 | 9 | 0x20 case randomization | 7.19 | 6.75 | 7.62 | 2.88 |
| 9 | 24 | Startup-DNS trust-boundary hardening | 7.12 | 7.12 | 7.12 | 2.75 |
| 10 | 33 | Wrong-family records tolerated-vs-rejected pin — implemented (2026-10-19) | 6.81 | 4.38 | 9.25 | 1.38 |
| 11 | 36 | Non-CONNECT method / request-target form rejection — implemented (2026-10-19) | 6.81 | 4.12 | 9.50 | 1.12 |
| 12 | 7 | AD-bit / DO-bit handling | 6.56 | 6.62 | 6.50 | 4.50 |
| 13 | 22 | Resolver identity / response-source verification | 6.50 | 5.38 | 7.62 | 2.75 |
| 14 | 35 | CONNECT header-line count bound | 6.50 | 3.62 | 9.38 | 1.25 |
| 15 | 18 | Multi-resolver failover | 6.38 | 5.50 | 7.25 | 4.38 |
| 16 | 23 | Cross-resolver divergence reporting | 6.12 | 4.88 | 7.38 | 4.50 |
| 17 | 5 | Resolver cert pinning / TOFU | 6.06 | 7.25 | 4.88 | 6.75 |
| 18 | 8 | Multi-resolver cross-validation | 6.00 | 7.75 | 4.25 | 8.00 |
| 19 | 1 | DNS-over-TLS (DoT) | 5.62 | 7.88 | 3.38 | 7.12 |
| 20 | 6 | DNSSEC validation | 5.62 | 8.75 | 2.50 | 8.12 |
| 21 | 3 | DNSCrypt | 5.31 | 7.12 | 3.50 | 6.88 |
| 22 | 10 | EDNS0 / larger-buffer negotiation | 3.69 | 1.12 | 6.25 | 1.62 |

## Per-vector detail (all 8 scores, eff/plaus/risk)

### Rank 1 — Vector 11: Bailiwick enforcement on CNAME targets

Overall **7.88** · Eff **7.88** · Plaus **7.88** · Risk **3.12**

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

### Rank 2 — Vector 21: Anomaly logging / tripwire on DNS

Overall **7.69** · Eff **7.75** · Plaus **7.62** · Risk **3.38**

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

### Rank 3 — Vector 14: TTL floor (min-TTL)

Overall **7.62** · Eff **5.88** · Plaus **9.38** · Risk **2.00**

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

### Rank 4 — Vector 34: ClientHello handshake-length field bound

Overall **7.50** · Eff **5.50** · Plaus **9.50** · Risk **1.12**

**Status:** implemented & pinned (2026-10-19, `alumina-hrdn`) — a ClientHello handshake message whose `4 + length` exceeds 16 KiB (`MAX_HANDSHAKE_LEN`) is rejected with a distinct `HandshakeTooLarge` discriminant.

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

### Rank 5 — Vector 19: Resolver health probing / degraded signaling

Overall **7.44** · Eff **6.50** · Plaus **8.38** · Risk **2.38**

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

### Rank 6 — Vector 32: CNAME-chain pinning to known-good zones

Overall **7.44** · Eff **7.38** · Plaus **7.50** · Risk **3.00**

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

### Rank 7 — Vector 17: Authoritative-freshness bound

Overall **7.25** · Eff **7.00** · Plaus **7.50** · Risk **3.25**

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 8 | 7 | 4 |
| general | 6 | 8 | 3 |
| general | 6 | 8 | 2 |
| linus | 8 | 7 | 5 |
| linus | 8 | 7 | 4 |
| general | 6 | 8 | 2 |
| general | 6 | 8 | 2 |
| linus | 8 | 7 | 4 |

### Rank 8 — Vector 9: 0x20 case randomization

Overall **7.19** · Eff **6.75** · Plaus **7.62** · Risk **2.88**

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 8 | 7 | 4 |
| linus | 8 | 7 | 4 |
| general | 5 | 8 | 2 |
| general | 7 | 8 | 2 |
| linus | 7 | 8 | 3 |
| linus | 8 | 7 | 4 |
| general | 7 | 8 | 2 |
| general | 4 | 8 | 2 |

### Rank 9 — Vector 24: Startup-DNS trust-boundary hardening

Overall **7.12** · Eff **7.12** · Plaus **7.12** · Risk **2.75**

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

### Rank 10 — Vector 33: Wrong-family records tolerated-vs-rejected pin

Overall **6.81** · Eff **4.38** · Plaus **9.25** · Risk **1.38**

**Status:** implemented & pinned (2026-10-19, `alumina-hrdn`) — a wrong-family record is truly ignored (never marks its terminal owner as carrying address data; `src/dns.rs:824-830,847-853`); NXDOMAIN at an opposite-family-only terminal is a clean `NxDomain`, never `TerminalWithoutData`.

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

### Rank 11 — Vector 36: Non-CONNECT method / request-target form rejection

Overall **6.81** · Eff **4.12** · Plaus **9.50** · Risk **1.12**

**Status:** implemented & pinned (2026-10-19, `alumina-hrdn`) — the former `NotHttp` catch-all is split into distinct `MethodNotConnect` / `UnsupportedVersion` / `TargetNotAuthorityForm` finite discriminants feeding the rp2e tripwire surface (`ConnectHeadReason::COUNT` 11→13).

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

### Rank 12 — Vector 7: AD-bit / DO-bit handling

Overall **6.56** · Eff **6.62** · Plaus **6.50** · Risk **4.50**

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

### Rank 13 — Vector 22: Resolver identity / response-source verification

Overall **6.50** · Eff **5.38** · Plaus **7.62** · Risk **2.75**

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

### Rank 14 — Vector 35: CONNECT header-line count bound

Overall **6.50** · Eff **3.62** · Plaus **9.38** · Risk **1.25**

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

### Rank 15 — Vector 18: Multi-resolver failover

Overall **6.38** · Eff **5.50** · Plaus **7.25** · Risk **4.38**

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

### Rank 16 — Vector 23: Cross-resolver divergence reporting

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

### Rank 17 — Vector 5: Resolver cert pinning / TOFU

Overall **6.06** · Eff **7.25** · Plaus **4.88** · Risk **6.75**

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

### Rank 18 — Vector 8: Multi-resolver cross-validation

Overall **6.00** · Eff **7.75** · Plaus **4.25** · Risk **8.00**

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

### Rank 19 — Vector 1: DNS-over-TLS (DoT)

Overall **5.62** · Eff **7.88** · Plaus **3.38** · Risk **7.12**

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

### Rank 20 — Vector 6: DNSSEC validation

Overall **5.62** · Eff **8.75** · Plaus **2.50** · Risk **8.12**

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

### Rank 21 — Vector 3: DNSCrypt

Overall **5.31** · Eff **7.12** · Plaus **3.50** · Risk **6.88**

| Rater | Eff | Plaus | Risk |
|---|---|---|---|
| linus | 8 | 3 | 9 |
| linus | 8 | 3 | 8 |
| general | 5 | 3 | 4 |
| general | 6 | 5 | 5 |
| linus | 9 | 3 | 8 |
| linus | 8 | 3 | 9 |
| general | 7 | 5 | 6 |
| general | 6 | 3 | 6 |

### Rank 22 — Vector 10: EDNS0 / larger-buffer negotiation

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


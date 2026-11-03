# Trust telemetry design note — honest DNS chain-of-trust logging

Status: **design note, not normative**. Behaviour rules stay in
[`alumina-proxy.md`](alumina-proxy.md); this document records the design of the DNS
trust/telemetry logging surface, the evidence behind it, and the questions still open for
review. Implementation is tracked in the issue tracker, not here.

## 1. Problem

Alumina reports DNS outcomes honestly at the *volume* level and dishonestly at the *trust*
level. Three clamps were confirmed at `30f943b`:

1. **One token for four situations.** `FailureReason::TlsIdentity` (`git:30f943b9689b21c23b123db6077cecd34b013b05:src/startup_dns.rs#L376-L382`)
   covers strict pin mismatch, structural empty-trust-anchor failure, SAN/FQDN mismatch, and
   generic handshake alert/EOF. In production on 2026-10-30 an entry that is *deliberately
   unpinned* was reported as `verdict=failed reason="tls_identity"` — the log said "identity
   mismatch" where the truth was "no trust anchors exist, so this entry can never validate".
2. **No observed identity.** A trust failure records the verdict only — no SPKI, issuer, SAN
   result, or validity. The 2026-10-30 resolver key rotation could not be explained from the
   logs at all; it took an `openssl` probe from a different machine.
3. **No resolver attribution.** `exchange_failed` (`git:30f943b9689b21c23b123db6077cecd34b013b05:src/log.rs#L1725-L1732`) and the incident family
   carry the FQDN but never the resolver, so a mid-life trust failure cannot be tied to an
   entry, and the `rd=`/`ep=` counters have no subject.

Two further ambiguities: `ProbeVerdict::NotProbed` (`git:30f943b9689b21c23b123db6077cecd34b013b05:src/startup_dns.rs#L738-L746`) means "exercised
successfully in the window", "window closed", or "skipped" — indistinguishable; and
`startup_warning` (`git:30f943b9689b21c23b123db6077cecd34b013b05:src/log.rs#L1711-L1719`) carries no reason at all.

### The clamp is upstream of the log layer

`HandshakeProbe` (`git:30f943b9689b21c23b123db6077cecd34b013b05:src/startup_dns.rs#L361-L365`) is `{ Waiting, Transition, Failed }`. The
handshake probe returns a bare `Failed` from six sites; `git:30f943b9689b21c23b123db6077cecd34b013b05:src/startup_dns.rs#L2176-L2178` is where
`rustls` reports `ApplicationVerificationFailure` (the pin mismatch), `NotValidForName`,
`UnknownIssuer`, `Expired`/`NotValidYet`, or an unsupported signature algorithm — all
discarded by `.is_err()`. The caller (`git:30f943b9689b21c23b123db6077cecd34b013b05:src/startup_dns.rs#L2119-L2127`) then stamps `TlsIdentity` on
every one of them.

The fix is therefore *stop discarding the cause, then map it* — not *widen a log enum*.

## 2. Design rules

1. **No clamping.** A token may not stand for two situations with different operator actions.
2. **Accuracy over volume.** A fact that cannot be emitted honestly within the record budget is
   dropped explicitly and counted — never replaced by a vague stand-in.
3. **No chatter.** Every signal must retire a named ambiguity and be rate-bounded: per boot,
   per incident, or per periodic summary — never per exchange, never per success.
4. **Lints do not get to force bad modelling.** Where a lint encumbers an accurate enum, use a
   reasoned `#[expect]` or segment further; merging variants to silence a lint is prohibited.

## 3. Vocabulary

One token per operator action; lowercase snake; maximum 20 bytes.

### Transport

| Situation | Token |
| --- | --- |
| `connect` ECONNREFUSED | `connect_refused` |
| `connect` unreachable/host-down/other connect error | `connect_unreachable` |
| deadline expired during connect | `deadline_connect` |
| query write error | `send_failed` |
| read returns 0 mid-exchange | `recv_eof` |
| ECONNRESET mid-read | `recv_reset` |
| other socket error | `socket_error` |
| deadline expired during send | `deadline_send` |
| deadline expired awaiting the answer | `deadline_receive` |

### Identity / chain (DoT)

| Situation | Token |
| --- | --- |
| pinned leaf SPKI ≠ configured pin | `pin_mismatch` |
| unpinned `IP#fqdn` entry, empty trust-anchor store (structural) | `no_trust_anchor` |
| `verify_server_name` failure | `san_mismatch` |
| chain validation failure (unknown issuer, bad signature) | `chain_invalid` |
| certificate expired (warning class on the pin branch) | `cert_expired` |
| certificate not yet valid (warning class on the pin branch) | `cert_not_yet_valid` |
| no shared TLS version/ALPN/signature algorithm | `protocol_unsupported` |
| peer alert | `handshake_alert` |
| peer closed during handshake | `handshake_eof` |
| socket error during handshake | `handshake_io` |
| handshake attempted on a non-TLS connection | `not_tls` |

`cert_expired` / `cert_not_yet_valid` are **reporting-class only** on the pin branch: a
pin-matching certificate outside its validity window is accepted with a counted warning
(`expired_pin_certs`), never rejected.

### DNS protocol

| Situation | Token |
| --- | --- |
| RCODE 3 | `dns_rcode_nxdomain` |
| RCODE 2 | `dns_rcode_servfail` |
| RCODE 5 | `dns_rcode_refused` |
| any other RCODE | `dns_rcode_other` |
| truncated response | `dns_truncated` |
| parse/message-identity failures | `dns_malformed` |
| size-bound failures | `dns_oversized` |
| bailiwick violation / suffix overflow | `dns_bailiwick` |

The four RCODE classes stay separate because the operator action differs (delegation, upstream
outage, ACL, upstream defect). The parse and size families group within class because the
action is identical.

`REASON_TOKEN_MAX` (`src/log.rs:83`) grows 13 → 20.

## 4. Enum segmentation

Split by domain; every mapping enum is exhaustive with **no `_ =>` arm** (a wildcard would
re-introduce the clamp at compile time). `#[non_exhaustive]` stays on the existing public
`StartupDnsError` only.

```rust
pub enum ExchangeFailure {                 // replaces FailureReason
    Transport(TransportFailure),
    Identity(IdentityFailure),
    Dns(DnsFailure),
}
pub enum TransportFailure {
    ConnectRefused, ConnectUnreachable, Send, RecvEof, RecvReset, Socket,
    Deadline(DeadlineStage),
}
pub enum DeadlineStage { Connect, Send, Receive }
pub enum IdentityFailure {
    PinMismatch, NoTrustAnchor, SanMismatch, ChainInvalid,
    Expired, NotYetValid, ProtocolUnsupported, Alert, Eof, Io, NotTls,
}
pub enum DnsFailure { Rcode(RcodeClass), Truncated, Malformed, Oversized, Bailiwick }
pub enum RcodeClass { NxDomain, ServFail, Refused, Other }
```

Handshake seam — the actual fix:

```rust
enum HandshakeProbe { Waiting, Transition, Failed(IdentityFailure) }
```

`probe_tls_handshake` classifies the `rustls::Error` at the boundary through an exhaustive
`fn classify_tls(err: rustls::Error) -> IdentityFailure`. The error itself is not carried (it
is not `Copy`); the classification is. All payloads are small and `Copy`, which also keeps
`large_enum_variant` satisfied by construction.

Token rendering is one small `fn token()` per class, so no single match grows large and each
class is reviewable in isolation.

## 5. Lint policy

| Lint | Disposition |
| --- | --- |
| `large_enum_variant` (`Cargo.toml:121`, warn) | avoid by construction (boundary classification, `Copy` classes); if a variant later needs a payload, box it or split the enum — never merge variants |
| `too_many_lines` (`Cargo.toml:19`, warn) | one `token()` per class; reasoned `#[expect]` only if a single exhaustive match still exceeds |
| `enum_variant_names` | short variants (`Expired`, not `CertExpired`); the enum carries the class |
| `unwrap_used` / `expect_used` (`src/lib.rs:1`, deny) | exhaustive match on `Copy` enums; no unwrap introduced |

## 6. Record budget

Measured worst cases (spec §Recorded worst-case encoded lengths, `docs/alumina-proxy.md:883`):

| Record | Now | After taxonomy | Headroom after |
| --- | --- | --- | --- |
| `resolver_probe` | 1857 B | 1892 B (+7 per segment × 5) | 156 B |
| `startup_name` | 380 B | 387 B | 1661 B |
| `exchange_failed` | 341 B | 348 B (≈393 B with resolver attribution) | 1655 B |
| `startup_warning` | 331 B | 352 B (gains `reason=`) | 1696 B |
| `monitor_summary` | 763 B | ≈775 B (packed per-resolver counters) | ≈1273 B |

Adding a per-segment observed-identity field (SPKI, 51 B framed) to `resolver_probe` would
take it to **2147 B — over the 2048 B slot**. Not admissible. Observed identity therefore
belongs in a separate `resolver_identity` record (one per failing resolver, ≈260 B).

Rules: `resolver_probe` may grow at most 100 B across the whole design; any identity field
that would exceed that goes to `resolver_identity`; overflow is counted, never truncated into
an ambiguous token.

## 7. Chatter budget

Measured in production on 2026-10-30 for one allowlisted name in a steady 1-second-recovery
flap: `exchange_failed` 71, `incident_open` 68, `incident_recovered` 67 in 61 minutes —
approximately 3.4 records per minute for a single flapping name.

Design: **one record per event, not per stage.** `exchange_failed` is emitted only when no
incident is open for the same name and family; while an incident is open, the
open/recovered pair is the signal. Steady flapping drops to roughly 2.2 records per minute
with no accuracy loss — the incident pair carries name, family, reason class, and duration.

Rate envelopes:

| Signal | Rate |
| --- | --- |
| `resolver_probe` | once per boot |
| structured per-resolver trust state | once per boot, per configured resolver |
| `resolver_identity` | once per failing resolver per boot, and per trust incident |
| resolver attribution fields | per incident (rides existing records) |
| per-resolver cause counters | per monitor summary |
| allowlist provenance summary | once per period |

Rejected outright: per-exchange identity lines, per-success lines, per-resolver per-minute
health lines, a second probe summary.

## 8. Open questions for review

| # | Question | Options | Recommendation |
| --- | --- | --- | --- |
| Q1 | Deadline granularity | (a) three tokens `deadline_connect`/`_send`/`_receive`; (b) one `exchange_deadline` | **(a)** — the stage is the operator's action |
| Q2 | DNS protocol class scope | (a) admit the eight `dns_*` tokens now; (b) defer to a separate increment so the taxonomy increment stays transport+identity | **(b)** — keeps the first increment reviewable |
| Q3 | Fold `exchange_failed` into the incident lifecycle | (a) yes, one record per event (spec amendment required, behaviour change); (b) keep current per-failure emission | **(a)** — the only real chatter reduction available |
| Q4 | `startup_warning` gains `reason=` | (a) yes (+21 B; the record currently retires no ambiguity); (b) leave as-is | **(a)** |
| Q5 | Where observed identity lives | (a) separate `resolver_identity` record; (b) trim `fqdn` from probe segments to make room in `resolver_probe` | **(a)** — the FQDN is the SAN target and must stay |
| Q6 | Pin-branch validity handling | (a) `cert_expired`/`cert_not_yet_valid` remain warning-class, never a rejection (RT-007); (b) treat them as failures | **(a)** — RT-007 is binding |
| Q7 | Does the per-resolver "intended trust" state (mode + expected identity) replace the boot stderr prose entirely, or is stderr kept as a convenience duplicate? | (a) records are authoritative, stderr kept; (b) records only | **(a)** — stderr is useful at boot, but must never be the only surface |

## 9. Out of scope

- Trust-anchor policy and the intake itself (`alumina-proxy.md` §Open TODO).
- The provenance summary shape and its period.
- Any change to the resolver set or the allowlist.

## 10. Acceptance

- Every situation in §3 has exactly one token; no token serves two rows.
- Every token is ≤ 20 bytes and appears in the §6 arithmetic.
- The §7 rate envelopes admit no signal whose ambiguity is retired elsewhere.
- The honesty property is testable: a table-driven test fails if two situations collide on a
  token, and a volume test asserts the healthy-path record rate did not increase.

# Alumina specification red-team review

**Mode:** security / adversarial specification review  
**Scope:** `docs/alumina-proxy.md`, including amendments through `alumina-redtm`  
**Verdict:** **FAIL** — two High-impact enforcement weaknesses and ten additional hardening opportunities remain actionable within the existing architecture.  
**Validation:** Specification inspection only. No builds, tests, fuzzers, binaries, network probes, or other verification commands were run. Findings below concern normative semantics, not claims that the current source implements a particular reading.

## Grading

- **Impact — High:** process-wide or destination-authorization effect, or a persistent security-control failure.
- **Impact — Medium:** bounded availability, provenance, freshness, or security-telemetry degradation.
- **Impact — Low:** defense-in-depth or specification ambiguity with a narrower exploit consequence.
- **Cost — S:** local policy/state-machine clarification or removal plus focused boundary tests.
- **Cost — M:** a bounded table, explicit state transition, or constrained configuration-schema change. No finding requires a new worker, runtime control plane, TLS termination, unbounded storage, or deployment-topology change.

## Findings summary

| ID | Finding | Impact | Cost |
| --- | --- | --- | --- |
| F-01 | AnyIllegal threshold still lets a client arm irreversible `Block All` | High | S |
| F-02 | Early-data corroboration measures repetition, not client attribution | High | S |
| F-03 | Observational resolver probes are not isolated from authorization state | Medium | S |
| F-04 | Failover transition count invalidates the 75-second startup budget proof | Medium | S |
| F-05 | Failback reset rule makes three consecutive successes unreachable | Medium | S |
| F-06 | Sustained valid negatives cannot trigger resolver recovery | Medium | M |
| F-07 | Parent-zone heuristic can derive public or shared-tenant bailiwicks | Medium | M |
| F-08 | Sixteen-entry JA4 set can be poisoned into permanent detail blindness | Medium | S |
| F-09 | Adversarial JA4 state can force whole-monitor-record loss | Medium | M |
| F-10 | Zero-TTL answers retain stale-serving authorization | Medium | S |
| F-11 | DoT has no TLS 1.3-only invariant | Low | S |
| F-12 | JA4 baseline keying and address-width requirements conflict | Low | S |

## Findings

### F-01 — AnyIllegal threshold still lets a client arm irreversible `Block All`

**Impact:** High  
**Cost:** S  
**Spec:** `docs/alumina-proxy.md:253-255`, `:261-264`, `:1176-1187`  
**Category:** Auth/authorization; availability

AnyIllegal is expressly the channel for unknown or unattributable client input. SP-001 changes activation of `All` from one illegal request to a fixed number within a fixed window, but every required fact remains entirely client-generated. A compromised workload can send the threshold number of malformed CONNECT requests or invalid ClientHellos inside the window. The result is still synchronous process-wide I/O prevention and closure, persistent until restart.

The threshold reduces accidental activation and raises request count; it is not an authorization boundary and does not materially resist the compromised-application adversary already in scope. Unlike transient slot exhaustion, this outage survives the end of the attack and requires operator intervention.

**Strengthening:** Remove `all` as a legal `[any_illegal]` scope; retain connection-scoped denial. If `Block All` is retained for a future trigger catalog, require a fact that a network client cannot synthesize. Do not add a runtime arming/unblocking interface. If the threshold remains during transition, specify `>=` versus `>`, window shape, reset behavior, and exact boundary tests, but do not treat those details as a security fix.

**Reference:** https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication

---

### F-02 — Early-data corroboration measures repetition, not client attribution

**Impact:** High  
**Cost:** S  
**Spec:** `docs/alumina-proxy.md:249-256`, `:261-264`, `:1189-1201`  
**Category:** Auth/authorization; availability

SP-002 permits Domain/All action selection after `K` consecutive early-upstream-data connections across distinct source sockets. The upstream endpoint controls the decisive byte on every connection. Distinct sockets can be ordinary retries or can be created by one compromised application; they do not establish independent client behavior or a different trust vantage.

A malicious or faulty approved upstream can therefore send one byte before the forwarding gate on each of `K` connections and arm the same Domain/All latch the remediation is intended to protect. The client need not send any illegal input. `K` and the reset/window semantics do not repair this attribution error.

**Strengthening:** Make upstream-sourced early data permanently ineligible for Domain/All enforcement. Keep the mandatory connection denial and emit `FlareOnly` telemetry. Restrict wider enforcement to facts attributable to the validated client identity; if no such fact exists in the current catalog, reject `early_data = { action = "block", scope = "domain" | "all" }` at configuration validation rather than silently downgrading it. This also removes the corroboration state and its boundary ambiguity.

**Reference:** https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication

---

### F-03 — Observational resolver probes are not isolated from authorization state

**Impact:** Medium  
**Cost:** S  
**Spec:** `docs/alumina-proxy.md:74-78`, `:90-97`, `:809-833`  
**Category:** Auth/authorization; error handling

The post-window sweep is described as an observability increment, but it runs a standard A exchange for allowlist ordinal 0 and does not state that the result is barred from normal cache publication. Ordinary validated positives replace bindings, NXDOMAIN evicts both families, and NODATA evicts one family. The probe clauses explicitly enumerate resolver-health mutations but are silent about name-cache, schedule, generation, retry, and incident mutations.

Under the permitted mutating reading, a backup resolver that was not selected for serving can return NXDOMAIN during its one-time probe and evict working bindings obtained from the active resolver. A positive can similarly replace the active resolver's addresses. This turns an observational sweep into an undocumented authorization write path.

**Strengthening:** Add a **Probe-Isolation Invariant**: probe responses may determine only the probe verdict and explicitly enumerated probed-resolver health state. Parse and validate in staging, then discard the name outcome. Probes must not mutate any allowlist-name cache entry, generation, freshness/retirement/stale-serving deadline, refresh/retry schedule, name incident, or admission counter. Require opposite-answer tests in which active and probed resolvers return different valid outcomes and all name-authorization state remains byte-for-byte unchanged.

**Reference:** https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication

---

### F-04 — Failover transition count invalidates the 75-second startup budget proof

**Impact:** Medium  
**Cost:** S  
**Spec:** `docs/alumina-proxy.md:593-599`, `:849-869`  
**Category:** Error handling; availability

A resolver enters degraded mode on its third consecutive failure, but relocation occurs only on the **next** counted failure. Thus each relocation away from a resolver requires four failures, not three. With five resolvers, reaching and exhausting the fifth requires at least:

```text
4 + 4 + 4 + 4 + 3 = 19 exchanges
19 × 5 seconds = 95 seconds
```

This already exceeds the absolute 90-second startup window before scheduling overhead. The stated `5 × 3 × 5 = 75 ≤ 90` proof counts degradation transitions, not the actual failover path. A healthy later resolver can remain untried when startup exits 75.

**Strengthening:** Relocate on the same transition that records the third failure and marks the active resolver degraded. That makes the 15-exchange/75-second bound correspond to the state machine. Keep the 90-second deadline unchanged. Add deterministic tests for the exact failure ordinal that closes, repoints, and starts against each resolver, plus the complete five-resolver startup budget.

**Reference:** https://owasp.org/www-community/Improper_Error_Handling

---

### F-05 — Failback reset rule makes three consecutive successes unreachable

**Impact:** Medium  
**Cost:** S  
**Spec:** `docs/alumina-proxy.md:722-735`  
**Category:** Error handling; availability

The failback amendment requires three consecutive successful primary probes, but also resets `failback_successes` to zero **when a failback probe begins**. Read literally, every attempt starts at zero and each success reaches only one; the next attempt resets it again. The three-success settle state is unreachable.

The resulting permanent probe loop can keep serving on a backup indefinitely and cause repeated 900-second relocation/disruption cycles. It also undermines the claimed hysteresis state machine even if source code happens to implement a different reset point.

**Strengthening:** Reset the success counter when failback is initially armed and when a probe fails, not when every subsequent probe starts. Specify where the transport resides between successful but not-yet-settling probes and whether the grace is re-armed. A compact transition table should cover success 1, success 2, success 3, failure after success 1/2, backup success, and shutdown.

**Reference:** https://owasp.org/www-community/Improper_Error_Handling

---

### F-06 — Sustained valid negatives cannot trigger resolver recovery

**Impact:** Medium  
**Cost:** M  
**Spec:** `docs/alumina-proxy.md:74-79`, `:513-517`, `:591-599`, `:1215-1226`  
**Category:** Error handling; availability

Validated negatives count as successful exchanges, reset resolver health, and clear exchange-failure incidents. Failover is driven only by counted exchange failures. Consequently, one configured resolver can return syntactically valid but stale or erroneous NXDOMAIN/NODATA responses indefinitely while other already-configured resolvers return positive answers; it remains healthy and no relocation occurs.

SP-004 adds a sustained-negative incident, but monitoring alone does not recover egress. This does not require adding a new trust actor or resolver: it concerns disagreement within the existing validated resolver set and ordinary resolver/zone failure modes.

**Strengthening:** Use the sustained-negative trigger to start a bounded, isolated corroboration exchange against another configured resolver. Consistent negatives remain authoritative cache outcomes; a positive/negative conflict emits a distinct fact and applies a fixed degradation/relocation rule. Do not publish a corroboration probe directly, do not treat disagreement as proof of attacker activity, and do not add undeclared resolvers or transports. Reuse the F-03 probe-isolation boundary.

**Reference:** https://owasp.org/www-community/Improper_Error_Handling

---

### F-07 — Parent-zone heuristic can derive public or shared-tenant bailiwicks

**Impact:** Medium  
**Cost:** M  
**Spec:** `docs/alumina-proxy.md:71`, `:128`, `:532-545`, `:1331-1339`  
**Category:** Auth/authorization; configuration

The bailiwick rule derives the parent domain for every name with more than two labels. This is not necessarily an administrative or “known-good” zone. For example, an allowlisted `example.co.uk` derives `co.uk`, allowing a followed CNAME target anywhere beneath that public suffix. An entry beneath a shared hosting parent can likewise authorize sibling tenants beneath that parent.

This is narrower than the already accepted parent-zone-compromise residual: the issue is that the heuristic may derive a zone that was never an appropriate trust unit in the first place. A public-suffix-list-only fix would also be insufficient for shared eTLD+1 tenants.

**Strengthening:** Replace implicit parent derivation with a bounded, explicit per-allowlist CNAME policy: exact approved terminal names and/or validated suffixes. A minimal default is same-name or subdomain-only, with any broader suffix declared in configuration and included in the fixed boot inventory. Validate on DNS label boundaries and retain the eight-link/no-loop rules. No PSL dependency or runtime discovery is required.

**Reference:** https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication

---

### F-08 — Sixteen-entry JA4 set can be poisoned into permanent detail blindness

**Impact:** Medium  
**Cost:** S  
**Spec:** `docs/alumina-proxy.md:914-929`, `:949-968`, `:1228-1239`  
**Category:** Data exposure / security telemetry

SP-005 stores up to 16 distinct JA4 strings per ordinal and suppresses every further add until restart. A compromised application can deliberately generate 16 syntactically accepted ClientHello variants, fill the set, and then make subsequent profile changes collapse into the overflow count. The overflow count reveals saturation, but the baseline set can no longer provide distinct change detail for either later attacker profiles or legitimate clients.

Because the baseline is never updated, this blindness persists for the process lifetime and is cheap to induce immediately after deployment.

**Strengthening:** Separate an immutable comparison reference from the bounded distinct-value detail set. Evaluate every ClientHello against the reference and count deviations regardless of set capacity; overflow may suppress additional detail, never the deviation decision itself. Alternatively, specify bounded eviction with explicit loss semantics, but do not let capacity suppress the security signal. Add a 17th-distinct-fingerprint test followed by another distinct fingerprint to prove that change detection still fires.

**Reference:** https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure

---

### F-09 — Adversarial JA4 state can force whole-monitor-record loss

**Impact:** Medium  
**Cost:** M  
**Spec:** `docs/alumina-proxy.md:183-184`, `:199`, `:288-306`, `:1103-1127`, `:1284-1293`, `:1321-1329`  
**Category:** Data exposure / security telemetry; resource exhaustion

The widest existing monitor record is documented at 8,139 bytes with only 53 bytes of headroom in its 8,192-byte slot. SP-009 adds a probe-relocation field and SP-013 adds keyed JA4 values plus triggering peer addresses, while requiring only re-measurement. A literal all-(ordinal, IP) latest-value encoding can far exceed the slot.

A client can drive JA4 changes across ordinals and maximize populated values and counter widths precisely when monitoring matters most. Whole-record drop then removes the aggregate security facts together with the optional detail. Priority-queue classes do not help when the record cannot be encoded in the first place.

**Strengthening:** Define a hard encoded-size invariant by construction, not only a measurement obligation. Keep a fixed core containing latches, aggregate counters, overflow flags, and drop accounting; shard or independently emit bounded JA4 detail. Detail suppression must set an explicit loss flag and must never remove core enforcement/DNS facts. Re-measurement remains useful evidence but is not a remediation rule. Test the maximum adversarially populated state and every detail-loss path.

**Reference:** https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure

---

### F-10 — Zero-TTL answers retain stale-serving authorization

**Impact:** Medium  
**Cost:** S  
**Spec:** `docs/alumina-proxy.md:74-78`, `:205-207`, `:1341-1349`  
**Category:** Configuration / destination freshness

A received TTL of zero is promoted to one second, after which the ordinary stale-authorization path applies. RT-006 introduces an independent stale-serving window but does not exclude zero-TTL-derived entries. Thus a DNS owner explicitly requesting no caching can still have its address authorize new connections after freshness expiry for the full stale-serving window.

This does not challenge the accepted general stale-retention tradeoff. It identifies an avoidable amplification of a deliberate zero-TTL deviation into a much longer authorization lifetime, including for fast-rebinding or steering names.

**Strengthening:** Carry a per-entry `stale_allowed` bit derived from the earliest supporting TTL. When that TTL is zero, permit the specified one-second fresh usability but prohibit stale admission. Schedule refresh at the corresponding one-second boundary if zero-TTL steering availability must be preserved; never extend authorization because refresh is delayed. Test immediate-before/at/after freshness expiry with delayed timers and cache replacement between attempts.

**Reference:** https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration

---

### F-11 — DoT has no TLS 1.3-only invariant

**Impact:** Low  
**Cost:** S  
**Spec:** `docs/alumina-proxy.md:19`, `:47-50`, `:651-701`, `:787-807`  
**Category:** Cryptography / protocol surface

The tunnel ClientHello profile is explicitly TLS 1.3-only, but the DoT handshake clauses require identity validation without specifying an allowed protocol-version set. The recorded rustls configuration also carries the `tls12` feature. The DoT specification therefore permits a pinned, SAN-valid TLS 1.2 session even though the golden path elsewhere minimizes protocol surface through TLS 1.3-only negotiation.

This is defense-in-depth rather than a claim that rustls TLS 1.2 is broken or that an on-path attacker can bypass the pin.

**Strengthening:** Require TLS 1.3 as the only DoT protocol version and fail the exchange on any other negotiated/offered profile. Remove the unused TLS 1.2 feature when dependency configuration next changes, subject to the normal dependency-intake process. Add explicit TLS 1.2-only server rejection and TLS 1.3 success vectors for both pinned and CA-chain branches.

**Reference:** https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration

---

### F-12 — JA4 baseline keying and address-width requirements conflict

**Impact:** Low  
**Cost:** S  
**Spec:** `docs/alumina-proxy.md:60`, `:303-304`, `:920-925`, `:1228-1239`, `:1321-1329`  
**Category:** Data exposure / security telemetry; specification integrity

SP-005 replaces the per-(ordinal, IP) baseline with a per-ordinal set. SP-013 then requires the latest-change value to use “the same (ordinal, IP) as its baseline,” referring to a key that no longer exists. Separately, the fixed baseline row reserves only a four-byte IP address even though the listener accepts IPv6. These clauses do not define a unique, implementation-independent attribution model and invite IPv6 collapsing or accidental reintroduction of per-IP baselines.

**Strengthening:** Keep SP-005's per-ordinal baseline and define SP-013 as the latest changed JA4 for that ordinal plus the triggering source address as event detail. Represent the address with a fixed tagged IPv4/IPv6 union (16-byte address storage plus family), or explicitly state and size an alternative. Remove the claim that a per-IP baseline remains. Update the boot-memory inventory accordingly.

**Reference:** https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure

## Recommended order

1. **F-01 / F-02:** remove the two network-triggerable process-wide latch paths before tuning thresholds or corroboration counts.
2. **F-03 / F-04 / F-05:** close probe authorization writes and make resolver transition arithmetic match the stated proofs.
3. **F-08 / F-09:** ensure hostile input cannot disable the tripwire's decision signal or force loss of core monitor facts.
4. **F-06 / F-07 / F-10:** tighten DNS recovery, provenance, and freshness with bounded state.
5. **F-11 / F-12:** close the remaining protocol and attribution ambiguities.

## Existing strengths worth preserving

- Exact allowlisted `<fqdn>:<port>` authorization, normalized SNI equality, ECH rejection, and authorization-before-forwarding form a clear admission chain.
- Destination addresses are filtered before publication and again before every connection attempt; established peers remain fixed.
- DNS outcomes are staged, bounded, generation-isolated, and denied permissive fallback across transports, resolvers outside the configured set, and endpoint-discovery mechanisms.
- CONNECT and ClientHello parsers have explicit byte/count/deadline bounds and fail-closed ambiguous identity handling.
- The single-owner, fixed-slot, no-runtime-control-plane architecture provides simple seams for every recommended fix.

## Explicitly not re-raised as findings

The review does not reclassify the accepted lack of upstream origin/certificate authentication, domain fronting or connection coalescing, the CONNECT response-corpus oracle, homogeneous plain-DNS deployments, warning-only pinned-certificate validity, general fixed-resource availability limits, or the acknowledged parent-zone compromise residual. F-07 is limited to derivation of inappropriate public/shared zones, not a demand to solve parent-zone compromise.

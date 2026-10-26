# Alox spec-review findings — 5-voter TP/FP adjudication

**Date:** 2026-10-25
**Method:** 5 independent voters, run strictly serially (at most one running at any time), each in a fresh context with no knowledge of the other voters' answers or the requester's prior. Spec-only, read-only assessment of `docs/alumina-proxy.md` (byte-canonical) and `alox-spec-review.md`. No builds/tests/probes run.
**Vote semantics:** TP = implementing the finding's strengthening improves the security posture required by the spec; FP = implementing it does not (weakens an existing control, removes a needed enforcement property, redundant, or not a real gap).
**Decision rule:** per-finding majority of 5.
**Status (2026-10-25):** F-01 and F-07 are **HELD — further research required** (not resolved by this vote). Remaining 10 findings are resolved by majority.
**Resolution (2026-10-26):** F-01 resolved **FALSE POSITIVE** by requester's deployment/threat-model review (see F-01 section). F-07 remains **HELD**.

## Vote matrix

| ID | V1 | V2 | V3 | V4 | V5 | Majority | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| F-01 | TP | TP | TP | TP | TP | 5-0 | **HELD** → **FALSE POSITIVE** (resolved 2026-10-26) |
| F-02 | TP | TP | TP | TP | TP | 5-0 | TRUE POSITIVE |
| F-03 | TP | TP | TP | TP | TP | 5-0 | TRUE POSITIVE |
| F-04 | TP | TP | TP | TP | TP | 5-0 | TRUE POSITIVE |
| F-05 | TP | TP | TP | TP | TP | 5-0 | TRUE POSITIVE |
| F-06 | TP | TP | TP | TP | TP | 5-0 | TRUE POSITIVE |
| F-07 | FP | TP | TP | FP | TP | 3-2 | **HELD** — further research |
| F-08 | TP | TP | TP | TP | TP | 5-0 | TRUE POSITIVE |
| F-09 | TP | TP | TP | TP | TP | 5-0 | TRUE POSITIVE |
| F-10 | TP | TP | TP | TP | TP | 5-0 | TRUE POSITIVE |
| F-11 | TP | TP | TP | TP | TP | 5-0 | TRUE POSITIVE |
| F-12 | TP | TP | TP | TP | TP | 5-0 | TRUE POSITIVE |

**Aggregate:** 10/12 findings TRUE POSITIVE by majority; F-01 and F-07 **HELD** for further research. Individual tallies: V1 11TP/1FP, V2 12TP/0FP, V3 12TP/0FP, V4 11TP/1FP, V5 12TP/0FP. Total 58 TP / 2 FP votes (both FP votes on F-07). F-01 resolved **FALSE POSITIVE** by requester's deployment/threat-model review (2026-10-26); F-07 remains **HELD**.

## Dissents

### F-07 — closest split (3-2) — **HELD for further research**
- **FP rationale (V1, V4):** RT-005 (`:1331-1339`) explicitly and deliberately accepted parent-zone bailiwick granularity as a threat-model note ("require nothing more today"). F-07's public/shared-tenant framing (e.g. `example.co.uk` → `co.uk`) is the same derivation mechanism and consequence re-raised, not a distinct gap.
- **TP rationale (V2, V3, V5):** deriving a public suffix or shared-tenant parent is a distinct, unhandled weakening of bailiwick enforcement that the accepted parent-zone-compromise residual does not cover; an explicit per-allowlist suffix policy is a real defense-in-depth improvement.
- **Hold reason:** genuine 3-2 split on whether this is a distinct gap or a re-raise of an accepted residual; needs further research (e.g. whether the spec's bailiwick rule can be narrowed without a PSL dependency or new trust actor).

### F-01 — 5-0 TP vs requester's stated FP baseline — **resolved FALSE POSITIVE (2026-10-26)**
- **Voter majority (TP):** SP-001's threshold is a count, not an authorization boundary; every required fact remains client-synthesizable, so a compromised workload can still arm the irreversible, restart-persistent, process-wide `Block All` (`:263`). Removing client-triggerable `all` scope (or requiring a non-synthesizable fact) closes a real availability/authorization gap.
- **Requester's baseline (FP):** `Block All` is a deliberate, operator-configured fail-closed isolation control. When the operator sets `scope = "all"` on `any_illegal`, immediate full isolation on any illegal control failure is the intended security outcome. F-01's strengthening (remove `all` scope) removes that capability, so a compromised system can no longer be immediately and fully isolated — implementing F-01 makes the system less secure for operators who explicitly configure `all`.
- **Crux:** whether `Block All` is (a) an operator-chosen fail-closed isolation control (→ FP) or (b) a client-triggerable persistent-outage liability (→ TP). The 5-voter majority adopted (b); the requester's baseline asserts (a). The voters were given the fact that `Block All` is the only immediate synchronous process-wide egress isolation path but still voted TP, weighing the availability-DoS framing over the fail-closed-isolation framing.
- **Hold reason:** direct disagreement between the 5-0 majority and the requester's baseline on the security nature of `Block All`; needs further research (threat-model position of the compromised workload, operator intent for `scope = "all"`, and whether a non-synthesizable trigger fact is feasible within the fixed profile).
- **Resolution (2026-10-26, requester):** **FALSE POSITIVE** in the target deployment and threat model. The mechanism is factually real — 3 client-synthesizable AnyIllegal facts within 60s arm an irreversible, restart-persistent, process-wide `Block All` (`src/enforcement/state.rs:13-17`; `src/serving.rs:2238-2248`; no source attribution, `src/serving.rs:2279`) — but the finding's High impact rating and TP framing miss the deployment and threat model: ingress is restricted to intended workloads (`docs/alumina-proxy.md:116`; private TCP ingress `:136`), so the only client able to reach Alumina is the already-trusted workload or its compromised self — there is no external attacker; the availability blast radius of any outage is the compromised VPC's own egress path, which `:13` explicitly declares non-critical ("the unavailability of egress from a compromised VPC will not be the critical issue"); and `scope = "all"` is a deliberate operator opt-in (required config key, exactly two legal values, `src/config.rs:737-742`) trading availability for fail-closed isolation, which aligns with the spec's critical concern (exfiltration, `:14`). By the vote semantics, implementing the strengthening does not improve posture required by the spec — it removes a deliberate operator control and is not a real gap in the target deployment. Residual: Low-impact defense-in-depth note (collateral within the VPC; `connection` scope is the operator's alternative); would become TP only under a multi-tenant deployment (one Alumina fronting multiple VPCs), which the spec's single-VPC blast radius does not model.

## Note
Voters were deliberately not shown the requester's F-01 prior to preserve independence; the disagreement above is surfaced for the requester's decision.

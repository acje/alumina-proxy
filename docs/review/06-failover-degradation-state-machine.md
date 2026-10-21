# Group 6 — Failover / Degradation State Machine

**Subsystem:** `src/startup_dns.rs` failover/failback machine, `src/resolver.rs` port/transport selection
**TRUE POSITIVE findings:** 2
**Severity mix:** High ×1, Low/Info ×1

---

## W1-H1a-F4 — Low/Info — silent DoT→plain transport switch on failover

**Scorecard row:**
```
| W1-H1a-F4 | Low/Info | failover | TRUE POSITIVE | FP,TP,TP,TP,TP → 4T-1F | high | mixed set relocates DoT→plain: port() 853 iff fqdn (resolver.rs:202-208); DEGRADED_AFTER=3 (startup_dns.rs:604); on_exchange_failed→next_healthy_after_active→repoint_to_active sets tls_target=None for bare-IP (2441-2452,2504-2528) → plain :53 dial; no runtime warn in failover path; only boot IP-only warning (main.rs:51-56) + Info rd counter; 1 dissenting pass |
```

**Working description (alox-f, H1a):**
[Low/Info] Silent transport switch on failover — mixed set (bare-IP `:53` + IP#fqdn `:853`) can relocate DoT→plain DNS after 3 failures with only startup-class warning; network-positioned adversary can force downgrade.

---

## W3-L3a-F1 — High — single-strike failback probe flap

**Scorecard row:**
```
| W3-L3a-F1 | High | src/startup_dns.rs:2477-2547 | TRUE POSITIVE | T,T,T,T,T → 5-0 | high | single-strike failback confirmed — maybe_begin_failback (startup_dns.rs:2477-2493) re-seats to primary after 900s grace (FAILBACK_AFTER_SECS=900 :610), called at top of start_exchange (:2282); on_exchange_succeeded (:2536-2547) clears failback_source/failback_due on ONE probe success, no consecutive-success counter (note_success :628-630 resets to Healthy{0}; only `consecutive` counter tracks failures); failover needs 3 consecutive failures (DEGRADED_AFTER=3 :604) vs failback needs 1 success → no count hysteresis; 900s grace bounds flap period (~15 min) but doesn't prevent oscillation; each flip closes connection + re-dials; pinned by test failback_probes_primary_after_grace_and_success_recovers_it (tests.rs:1705-1743); finding's "probe-then-re-seat" order slightly imprecise (re-seats before probe) but substance accurate; High defensible (on startup DNS path, not serving data path) |
```

**Working description (alox-f, L3a):**
[High] Failback probe single-strike flap, `src/startup_dns.rs:2504-2528` — probe-then-re-seat; transient primary slowness → secondary failover → oscillation. *(Scorecard nuance: failover needs 3 consecutive failures vs failback needs 1 success — no count hysteresis; 900s grace bounds flap period but doesn't prevent oscillation.)*

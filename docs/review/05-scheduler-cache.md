# Group 5 — Scheduler & Cache

**Subsystem:** `src/schedule.rs` due/not_before scheduling, `src/cache.rs` binding cache + stale grace
**TRUE POSITIVE findings:** 5
**Severity mix:** Info ×3, Unknown ×1, Low/Obs (pre-existing) ×1

---

## W4-L4b-F2 — Info — cache size bound to ALLOWLIST_MAX (zero-heap satisfied)

**Scorecard row:**
```
| W4-L4b-F2 | Info | src/cache.rs:220 | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | entries: [[Entry;2]; ALLOWLIST_MAX] fixed array (cache.rs:220), ALLOWLIST_MAX=32 (config.rs:12); Cache/Entry derive Copy, no Vec/Box/HashMap in serving path (publish_positive stages fixed [UNUSED_SLOT; MAX_ADDRESSES] :336); Cache::new rejects >ALLOWLIST_MAX (:235); alloc-witness tests assert all_zero (cache.rs:1111,1204); positive claim holds at HEAD |
```

**Working description (alox-f, L4b):**
[Info] Cache size bound to ALLOWLIST_MAX, `src/cache.rs:220` — `entries: [[Entry;2]; ALLOWLIST_MAX]` fixed array, `Cache`/`Entry` derive `Copy`, no `Vec`/`Box`/`HashMap` in serving path; `Cache::new` rejects >ALLOWLIST_MAX; zero-heap satisfied.

---

## W5-L5b-F3 — Info — monotonicity handled via `due.max(not_before)`

**Scorecard row:**
```
| W5-L5b-F3 | Info | src/schedule.rs | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | clamp real: earliest_selectable_at computes selectable_at=due.max(slot.not_before) (schedule.rs:181), feeds recompute_next_due :187-189 → next_selectable_due :541-546 (owner wake serving.rs:2975); select_due enforces same bound (:512 not_before>now, :518 due>now); not_before sole write select_due :521-524, never decreased (grep: only schedule.rs); no regression path even via overwrite_due_at; tests pin: next_selectable_due_guides_the_owner_wake (:702-752), oracle due.max(not_before) (:770) cached_next_due_matches_oracle (:776-821) |
```

**Working description (alox-f, L5b):**
[Info] Monotonicity handled via `due.max(not_before)` — `earliest_selectable_at` clamps `selectable_at = due.max(slot.not_before)`; `not_before` sole write in `select_due`, never decreased; tests pin with an oracle `due.max(not_before)`.

---

## W5-L5b-F4 — Info — fixed-size `[[Slot;2]; ALLOWLIST_MAX]` — zero-alloc

**Scorecard row:**
```
| W5-L5b-F4 | Info | fixed-size [[Slot;2]; ALLOWLIST_MAX] | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | table exactly [[Slot;2]; ALLOWLIST_MAX] (schedule.rs:127), ALLOWLIST_MAX=32 compile-time const (config.rs:12); Slot Copy heap-free scalars (schedule.rs:68-74); constructed from const UNDUE array-repeat (:138-149) inline in by-value Schedules (serve.rs:45); zero allocation sites in schedule.rs (grep: no Vec/Box/String/format!/HashMap); alloc-witness test scheduler_paths_do_not_allocate_or_deallocate (:1051-1095, feature-gated) constructs Schedules::new inside run_phase and asserts all_zero → pins zero-alloc for construction+use; Zero-Allocation Invariant docs/alumina-proxy.md:211 |
```

**Working description (alox-f, L5b):**
[Info] Fixed-size `[[Slot;2]; ALLOWLIST_MAX]` — `Slot` is `Copy` heap-free scalars; zero allocation sites in `schedule.rs`; alloc-witness test `scheduler_paths_do_not_allocate_or_deallocate` pins zero-alloc for construction+use.

---

## W5-L5b-F5 — Unknown — cache interaction race (due vs Retired)

**Scorecard row:**
```
| W5-L5b-F5 | Unknown | cache interaction race (due vs Retired) | TRUE POSITIVE | FP,TP,TP,FP,TP → 3T-2F | medium | divergence real: select_due (schedule.rs:502-531) never consults cache; Retired computed from retirement_deadline (cache.rs:113-122); sustained-failure path: schedule note_exchange_failure backoff ≤30s (:319-336) keeps retrying, cache note_exchange_failure no-op never extends retirement (:412-419, pinned cache.rs:841-863) → after ~3d (STALE_GRACE=259200) entry Retired while slot stays due; claimed mitigation "caller re-verify" exists at serve time: worker.rs:902 usable_peer + serve.rs:709 usable_name gate on Fresh|Stale, Retired never served; no pre-refresh re-verify but refresh is recovery mechanism (publish_positive republishes on success dns.rs:328-383); benign/expected recovery, not defect; "race" = logical divergence not data race (single-owner cooperative runtime); 2 dissenting passes (FP: mitigation absent on refresh path, safety via different mechanisms) |
```

**Working description (alox-f, L5b):**
[Unknown] Cache interaction race (due vs Retired) — `select_due` never consults the cache; a slot can stay due after its entry is `Retired` (sustained-failure path never extends retirement); mitigated by caller re-verify at serve time (`usable_peer`/`usable_name` gate on Fresh|Stale, Retired never served); benign/expected recovery, not a defect; "race" = logical divergence, not a data race.

---

## W6-H6b-F5 — Low/Obs (pre-existing) — serve-stale during all-degraded; degraded surfacing event-only

**Scorecard row:**
```
| W6-H6b-F5 | Low/Obs, pre-existing | STALE_GRACE=259200 (3d, cache.rs:10) | TRUE POSITIVE | TP,TP,TP,TP,TP → 5T-0F | high | STALE_GRACE=259_200 at cache.rs:10, identical at base 8b0bd5b (git show) → pre-existing; in-grace expired servable: cache.rs:333-335 retirement=freshness+STALE_GRACE, EntryState::Stale spans freshness<=now<retirement (cache.rs:113-122), serving accepts Fresh|Stale (worker.rs:902 usable_peer, serve.rs:709 usable_name), pinned by stale_positive_binding_remains_usable serve.rs:808-813; all-degraded: serving path (worker.rs:859-910 select_peer→usable_peer) reads cache directly, never consults resolver health; degradation gates only DNS transport (startup_dns.rs:2454-2469 next_healthy_after_active None → stays put fail-closed :2499-2500) while stale bindings continue authorizing; deliberate per docs/alumina-proxy.md:207 Fail-Closed Invariant ("only DNS-failure tolerance is continued use of existing positive binding within bounded stale grace"), :75 RFC 8767 max stale timer, :130 "trades freshness for availability"; degraded surfacing event-only: rd = facts_resolver_degraded() SaturatingCounter (monitor.rs:13, log.rs:523-524), counts enter+exit crossings both directions (startup_dns.rs:838-841,:853-856), zero-suppressed, no persistent "currently serving from stale" bit (grep stale_serv/stale_admission = 0); nuance: spec's DNS incident summaries (docs:75,80) have no src/ implementation → blind spot slightly wider than stated; Low/Obs fair |
```

**Working description (alox-f, H6b):**
F5 [Low/Obs, pre-existing NOT window] Serve-stale: `STALE_GRACE=259200` (3d, `cache.rs:10`, present at base) — in-grace expired binding servable during all-degraded; degraded surfacing event-only (`rd` crossing count). Availability/monitoring blind spot, deliberate serve-stale design. Fix: periodic "serving from stale" state bit.

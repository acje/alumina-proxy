use super::*;
use crate::config::parse_config_document;
use crate::connect::ConnectParser;
use crate::dns::cache::{Generation, StagedPositive};
use std::net::{Ipv4Addr, Ipv6Addr};

const CONFIG: &str = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"sub.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n[allowed_fqdn.\"z.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n";

const ALLOWLIST_XY: &str = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"x.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n[allowed_fqdn.\"y.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n";

const ALLOWLIST_AX: &str = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"a.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n[allowed_fqdn.\"x.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n";

fn config() -> Config {
    parse_config_document(CONFIG).expect("valid config")
}

fn v4(octets: [u8; 4]) -> NumericAddr {
    NumericAddr::V4(Ipv4Addr::from(octets))
}

fn v6(octets: [u8; 16]) -> NumericAddr {
    NumericAddr::V6(Ipv6Addr::from(octets))
}

fn pub_v4() -> NumericAddr {
    v4([8, 8, 8, 8])
}

fn pub_v4_b() -> NumericAddr {
    v4([1, 1, 1, 1])
}

fn pub_v6() -> NumericAddr {
    v6([0x26, 0x00, 0x1f, 0x39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
}

fn second_v6() -> NumericAddr {
    v6([0x24, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

fn cache_with(name_count: usize) -> Cache {
    Cache::new(name_count).expect("cache")
}

fn view_of<'a>(cfg: &'a Config, cache: &'a Cache) -> WorkerView<'a> {
    WorkerView::new(cfg, cache, clock(Instant::now()))
}

fn view_of_clocked<'a>(cfg: &'a Config, cache: &'a Cache, clock: WorkerClock) -> WorkerView<'a> {
    WorkerView::new(cfg, cache, clock)
}

/// The decision-core anchor instant; deadlines and the cache clock derive
/// from it. Each test uses one anchor so `now`, `setup` and the cache
/// clock share a single origin.
fn anchor() -> Instant {
    Instant::now()
}

fn clock(anchor: Instant) -> WorkerClock {
    WorkerClock::new(anchor, 0)
}

const DNS_EPOCH: u64 = 1_700_000_000;

/// `secs` whole seconds after the anchor.
fn later(anchor: Instant, secs: u64) -> Instant {
    anchor + Duration::from_secs(secs)
}

fn setup_at(anchor: Instant) -> Deadline {
    Deadline::setup(anchor)
}

fn assert_counters_match_rescan(worker: &Worker) {
    let occupied = worker
        .slots
        .iter()
        .filter(|s| !matches!(s, SlotState::Free))
        .count();
    let pending = worker
        .slots
        .iter()
        .filter(|s| matches!(s, SlotState::InSetup { .. }))
        .count();
    assert_eq!(
        worker.occupied_count, occupied,
        "cached occupied diverges from a truthful rescanned count"
    );
    assert_eq!(
        worker.pending_count, pending,
        "cached pending diverges from a truthful rescanned count"
    );
    assert_eq!(
        worker.free_count,
        MAX_TUNNELS - occupied,
        "cached free count diverges from the free seats in the slot table"
    );
}

fn publish(
    cache: &mut Cache,
    name: NameIndex,
    family: Family,
    addrs: &[NumericAddr],
    receipt: u64,
    ttl: u64,
) {
    let staged = StagedPositive::stage(name, family, Generation::INITIAL, addrs, receipt, ttl)
        .expect("staged valid");
    cache.publish_positive(&staged).expect("published");
}

fn name(cache: &Cache, ordinal: usize) -> NameIndex {
    cache.name_index(ordinal).expect("admitted name")
}

fn parse_head(head: &[u8]) -> ConnectRequest {
    let mut parser = ConnectParser::new();
    match parser.feed(head).expect("head feed") {
        crate::connect::Feed::Complete { .. } => parser.result().copied().expect("result"),
        crate::connect::Feed::Incomplete => panic!("head incomplete"),
    }
    .expect("valid connect")
}

fn auth_request(host: &str) -> ConnectRequest {
    let head = format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n");
    parse_head(head.as_bytes())
}

#[test]
fn forbidden_host_is_effect_nonreachable_even_with_usable_cache() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let req = auth_request("evil.example.net");
    let t0 = anchor();
    let phase = next_phase(
        &view.resolve(&req),
        later(t0, 1),
        AttemptCounts::new(),
        None,
        setup_at(t0),
    )
    .expect("decision");
    assert_eq!(phase, ConnectPhase::Forbidden);
}

#[test]
/// Authorization requires the exact configured `<fqdn>:<port>` pair: the
/// same allowlisted hostname at a different CONNECT port is a pair miss
/// (`HostNotAllowlisted` forbid), even with a usable cache binding.
fn same_host_different_port_is_forbidden_even_with_usable_cache() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let req = parse_head(b"CONNECT sub.example.org:8443 HTTP/1.1\r\n\r\n");
    let t0 = anchor();
    let phase = next_phase(
        &view.resolve(&req),
        later(t0, 1),
        AttemptCounts::new(),
        None,
        setup_at(t0),
    )
    .expect("decision");
    assert_eq!(
        phase,
        ConnectPhase::Forbidden,
        "a same-host different-port pair must be denied even when the hostname is allowlisted"
    );
}

#[test]
fn allowlisted_authorizes_and_selects_ipv4_first_when_both_families_remain() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
    publish(&mut cache, n, Family::Aaaa, &[pub_v6()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let req = auth_request("sub.example.org");
    let t0 = anchor();
    let now = later(t0, 1);
    let setup = setup_at(t0);
    let phase =
        next_phase(&view.resolve(&req), now, AttemptCounts::new(), None, setup).expect("decision");
    assert_eq!(
        phase,
        ConnectPhase::Peer {
            addr: pub_v4(),
            family: Family::A,
            connect_deadline: Deadline::connect_attempt(now, setup),
        }
    );
}

#[test]
fn alternates_to_aaaa_after_a_first_attempt() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
    publish(&mut cache, n, Family::Aaaa, &[pub_v6()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let counts = AttemptCounts::new().record(Family::A);
    let req = auth_request("sub.example.org");
    let t0 = anchor();
    let now = later(t0, 1);
    let setup = setup_at(t0);
    let phase =
        next_phase(&view.resolve(&req), now, counts, Some(Family::A), setup).expect("decision");
    assert_eq!(
        phase,
        ConnectPhase::Peer {
            addr: pub_v6(),
            family: Family::Aaaa,
            connect_deadline: Deadline::connect_attempt(now, setup),
        }
    );
}

#[test]
fn address_index_equals_earlier_attempts_in_family() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4(), pub_v4_b()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let counts = AttemptCounts::new().record(Family::A);
    let req = auth_request("sub.example.org");
    let t0 = anchor();
    let now = later(t0, 1);
    let setup = setup_at(t0);
    let phase = next_phase(&view.resolve(&req), now, counts, None, setup).expect("decision");
    assert_eq!(
        phase,
        ConnectPhase::Peer {
            addr: pub_v4_b(),
            family: Family::A,
            connect_deadline: Deadline::connect_attempt(now, setup),
        }
    );
}

#[test]
fn single_family_remains_uses_it() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::Aaaa, &[pub_v6()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let req = auth_request("sub.example.org");
    let t0 = anchor();
    let now = later(t0, 1);
    let setup = setup_at(t0);
    let phase =
        next_phase(&view.resolve(&req), now, AttemptCounts::new(), None, setup).expect("decision");
    assert_eq!(
        phase,
        ConnectPhase::Peer {
            addr: pub_v6(),
            family: Family::Aaaa,
            connect_deadline: Deadline::connect_attempt(now, setup),
        }
    );
}

#[test]
fn retired_binding_is_not_usable() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 1, 1);
    let decision = select_peer(&cache, n, 300_000, AttemptCounts::new(), None).expect("selection");
    assert_eq!(decision, PeerDecision::NoFamily);
}

#[test]
fn family_exhausted_at_current_address_count_uses_other_family() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
    publish(&mut cache, n, Family::Aaaa, &[pub_v6()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let counts = AttemptCounts::new().record(Family::A).record(Family::A);
    let req = auth_request("sub.example.org");
    let t0 = anchor();
    let now = later(t0, 1);
    let setup = setup_at(t0);
    let phase =
        next_phase(&view.resolve(&req), now, counts, Some(Family::A), setup).expect("decision");
    assert_eq!(
        phase,
        ConnectPhase::Peer {
            addr: pub_v6(),
            family: Family::Aaaa,
            connect_deadline: Deadline::connect_attempt(now, setup),
        }
    );
}

#[test]
fn setup_deadline_expiry_returns_deadline_exhausted() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let req = auth_request("sub.example.org");
    let t0 = anchor();
    let phase = next_phase(
        &view.resolve(&req),
        later(t0, 10),
        AttemptCounts::new(),
        None,
        setup_at(t0),
    )
    .expect("decision");
    assert_eq!(phase, ConnectPhase::DeadlineExhausted);
}

#[test]
fn expired_prior_connect_deadline_retries_while_setup_is_live() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let req = auth_request("sub.example.org");
    let t0 = anchor();
    let now = later(t0, 9);
    let setup = setup_at(t0);
    let phase =
        next_phase(&view.resolve(&req), now, AttemptCounts::new(), None, setup).expect("decision");
    let ConnectPhase::Peer {
        addr,
        family,
        connect_deadline,
    } = phase
    else {
        panic!("setup is live: expected a retried Peer, got {phase:?}");
    };
    assert_eq!(addr, pub_v4());
    assert_eq!(family, Family::A);
    assert_eq!(connect_deadline.limit(), setup.limit());
}

#[test]
fn attempt_budget_exhausted_returns_candidates_exhausted() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let req = auth_request("sub.example.org");
    let counts = AttemptCounts::new()
        .record(Family::A)
        .record(Family::Aaaa)
        .record(Family::A)
        .record(Family::Aaaa);
    let t0 = anchor();
    let phase = next_phase(
        &view.resolve(&req),
        later(t0, 1),
        counts,
        None,
        setup_at(t0),
    )
    .expect("decision");
    assert_eq!(phase, ConnectPhase::CandidatesExhausted);
}

#[test]
fn worker_admits_up_to_128_pending_setups_and_rejects_the_129th() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    for _ in 0..MAX_PENDING_SETUPS {
        worker
            .admit(t0)
            .expect("admitted within the pending budget");
    }
    assert_eq!(worker.pending(), MAX_PENDING_SETUPS);
    assert_eq!(worker.admit(t0), Err(AdmissionError::PendingCapacity));
}

#[test]
fn releasing_a_setup_slot_frees_pending_capacity() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    for _ in 0..MAX_PENDING_SETUPS - 1 {
        worker.admit(t0).expect("admitted");
    }
    let last = worker.admit(t0).expect("admitted at the pending cap");
    worker.release(last);
    worker.admit(t0).expect("seat freed by release");
    assert_eq!(worker.pending(), MAX_PENDING_SETUPS);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "release requires an in-setup slot")]
fn release_rejects_a_slot_that_is_not_in_setup() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    let slot = worker.admit(t0).expect("admitted");
    worker.slots[slot.index()] = SlotState::Established {
        setup_deadline: Deadline::setup(t0),
    };
    worker.release(slot);
}

#[test]
fn worker_binds_slot_capacity_at_512_occupied_tunnels() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    let mut tunnels = Vec::new();
    for _ in 0..MAX_TUNNELS {
        let slot = worker.admit(t0).expect("admitted to a free slot");
        tunnels.push(worker.finish_setup(slot));
    }
    assert_eq!(worker.admit(t0), Err(AdmissionError::SlotCapacity));
    assert_eq!(worker.pending(), 0);
    assert_eq!(worker.occupied(), MAX_TUNNELS);
    for tunnel in tunnels {
        worker.release_tunnel(tunnel);
    }
    assert_eq!(worker.occupied(), 0);
    assert_eq!(worker.pending(), 0);
}

#[test]
fn graduating_or_releasing_one_slot_never_touches_another_slots_pending() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    let a = worker.admit(t0).expect("slot a");
    let b = worker.admit(t0).expect("slot b");
    assert_eq!(worker.pending(), 2);
    let a_tunnel = worker.finish_setup(a);
    assert_eq!(
        worker.pending(),
        1,
        "graduating slot a must drop only a's pending seat"
    );
    assert_eq!(worker.occupied(), 2);
    worker.release_tunnel(a_tunnel);
    assert_eq!(
        worker.pending(),
        1,
        "releasing established a must not touch b's pending seat"
    );
    assert_eq!(worker.occupied(), 1);
    worker.release(b);
    assert_eq!(worker.pending(), 0);
    assert_eq!(worker.occupied(), 0);
}

#[test]
fn admitted_slot_carries_its_absolute_setup_deadline() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    let slot = worker.admit(t0).expect("admitted");
    assert_eq!(worker.setup_deadline(&slot), Some(Deadline::setup(t0)));
    let tunnel = worker.finish_setup(slot);
    assert_eq!(
        worker.tunnel_setup_deadline(&tunnel),
        Some(Deadline::setup(t0)),
        "the setup deadline starts at accept and is never reset by graduation"
    );
    assert_eq!(worker.pending(), 0);
    worker.release_tunnel(tunnel);
    assert_eq!(worker.occupied(), 0);
}

#[test]
fn cached_occupancy_counters_track_the_slot_table_across_a_lifecycle_churn() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    let mut tunnels = Vec::new();
    for _ in 0..MAX_TUNNELS {
        let slot = worker.admit(t0).expect("admitted to a free slot");
        tunnels.push(worker.finish_setup(slot));
    }
    for tunnel in tunnels {
        worker.release_tunnel(tunnel);
    }
    for _ in 0..MAX_PENDING_SETUPS {
        let slot = worker.admit(t0).expect("admitted after full teardown");
        worker.release(slot);
    }
    assert_counters_match_rescan(&worker);
}

#[test]
fn free_list_names_each_free_slot_exactly_once_through_a_full_churn() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    assert_eq!(
        worker.free_count, MAX_TUNNELS,
        "all 512 slots are free at boot"
    );
    let mut seen = vec![0usize; MAX_TUNNELS];
    for &idx in &worker.free_heap[..worker.free_count] {
        let free = matches!(worker.slots[idx as usize], SlotState::Free);
        assert!(free, "free list names a non-free slot {idx}");
        seen[idx as usize] += 1;
    }
    assert!(
        seen.iter().all(|&c| c == 1),
        "each free slot appears on the free list exactly once"
    );
    let mut tunnels = Vec::new();
    for _ in 0..MAX_TUNNELS {
        let slot = worker.admit(t0).expect("admitted to a free slot");
        tunnels.push(worker.finish_setup(slot));
    }
    assert_eq!(worker.free_count, 0, "free list empty at full occupancy");
    for tunnel in tunnels {
        worker.release_tunnel(tunnel);
    }
    assert_eq!(
        worker.free_count, MAX_TUNNELS,
        "free list refills after full teardown"
    );
    assert_counters_match_rescan(&worker);
}

#[test]
fn admit_reuses_the_lowest_index_free_slot() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    let a = worker.admit(t0).expect("admitted");
    assert_eq!(SlotIndex::index(&a), 0, "first admit takes slot 0");
    let b = worker.admit(t0).expect("admitted");
    assert_eq!(SlotIndex::index(&b), 1, "second admit takes slot 1");
    worker.release(a);
    let c = worker.admit(t0).expect("re-admitted");
    assert_eq!(
        SlotIndex::index(&c),
        0,
        "the freed lowest free slot is reused by the next admit"
    );
    let _ = b;
}

#[test]
fn setup_deadline_is_exactly_ten_seconds_after_accept() {
    let t0 = anchor();
    assert_eq!(
        Deadline::setup(t0).limit(),
        t0 + Duration::from_secs(SETUP_DEADLINE_SECS)
    );
}

#[test]
fn connect_deadline_expires_full_two_seconds_after_a_fractional_initiation() {
    let t0 = anchor();
    let setup = Deadline::setup(t0);
    let initiated = t0 + Duration::from_millis(1900);
    let attempt = Deadline::connect_attempt(initiated, setup);
    assert_eq!(
        attempt.limit(),
        initiated + Duration::from_secs(CONNECT_DEADLINE_SECS),
        "a 2 s connect deadline initiated at x.9 s must expire at exactly \
             x.9 + 2.0 s, never earlier through whole-second truncation"
    );
}

#[test]
fn connect_deadline_clips_to_the_setup_deadline_when_fresh_would_exceed_it() {
    let t0 = anchor();
    let setup = Deadline::setup(t0);
    let late = t0 + Duration::from_secs(9);
    assert_eq!(
        Deadline::connect_attempt(late, setup).limit(),
        setup.limit(),
        "a connect initiated 1 s before setup end must clip to the setup deadline"
    );
}

#[test]
fn selecting_after_a_a_aaaa_uses_a_not_aaaa() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(
        &mut cache,
        n,
        Family::A,
        &[pub_v4(), pub_v4_b(), v4([9, 9, 9, 9])],
        100,
        3600,
    );
    publish(
        &mut cache,
        n,
        Family::Aaaa,
        &[pub_v6(), second_v6()],
        100,
        3600,
    );
    let counts = AttemptCounts::new()
        .record(Family::A)
        .record(Family::A)
        .record(Family::Aaaa);
    let decision = select_peer(&cache, n, 1000, counts, Some(Family::Aaaa)).expect("selection");
    assert_eq!(
        decision,
        PeerDecision::Peer {
            addr: v4([9, 9, 9, 9]),
            family: Family::A
        }
    );
}

#[test]
fn selecting_after_a_aaaa_a_uses_aaaa_not_a() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(
        &mut cache,
        n,
        Family::A,
        &[pub_v4(), pub_v4_b(), v4([9, 9, 9, 9])],
        100,
        3600,
    );
    publish(
        &mut cache,
        n,
        Family::Aaaa,
        &[pub_v6(), second_v6()],
        100,
        3600,
    );
    let counts = AttemptCounts::new()
        .record(Family::A)
        .record(Family::A)
        .record(Family::Aaaa);
    let decision = select_peer(&cache, n, 1000, counts, Some(Family::A)).expect("selection");
    assert_eq!(
        decision,
        PeerDecision::Peer {
            addr: second_v6(),
            family: Family::Aaaa
        }
    );
}

#[test]
fn all_ineligible_family_publishes_empty_and_other_family_is_used() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[v4([127, 0, 0, 1])], 100, 3600);
    publish(&mut cache, n, Family::Aaaa, &[pub_v6()], 100, 3600);
    let decision = select_peer(&cache, n, 1000, AttemptCounts::new(), None).expect("selection");
    assert_eq!(
        decision,
        PeerDecision::Peer {
            addr: pub_v6(),
            family: Family::Aaaa
        }
    );
}

#[test]
fn cache_for_config_matches_the_allowlist_for_every_ordinal() {
    let cfg = config();
    let cache = Cache::for_config(&cfg).expect("cache for config");
    assert_eq!(cache.name_count(), cfg.allowlist().len());
    for ordinal in 0..cfg.allowlist().len() {
        assert!(
            cache.name_index(ordinal).is_some(),
            "allowlist ordinal {ordinal} is admitted by the cache"
        );
    }
}

#[test]
fn refusal_statuses_follow_the_canonical_fixed_matrix() {
    let t0 = anchor();
    assert_eq!(ConnectPhase::Forbidden.status(), 403);
    assert_eq!(ConnectPhase::NoBinding.status(), 502);
    assert_eq!(ConnectPhase::CandidatesExhausted.status(), 502);
    assert_eq!(ConnectPhase::DeadlineExhausted.status(), 504);
    assert_eq!(
        ConnectPhase::Peer {
            addr: pub_v4(),
            family: Family::A,
            connect_deadline: setup_at(t0)
        }
        .status(),
        200
    );
}

#[test]
fn never_resolved_and_exhausted_attempts_are_distinct_502_verdicts() {
    let cache = cache_with(2);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let req = auth_request("sub.example.org");
    let t0 = anchor();
    let never_resolved = next_phase(
        &view.resolve(&req),
        later(t0, 1),
        AttemptCounts::new(),
        None,
        setup_at(t0),
    )
    .expect("decision");
    assert_eq!(never_resolved, ConnectPhase::NoBinding);

    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let counts = AttemptCounts::new()
        .record(Family::A)
        .record(Family::Aaaa)
        .record(Family::A)
        .record(Family::Aaaa);
    let exhausted = next_phase(
        &view.resolve(&req),
        later(t0, 1),
        counts,
        None,
        setup_at(t0),
    )
    .expect("decision");
    assert_eq!(exhausted, ConnectPhase::CandidatesExhausted);
}

#[test]
fn chunked_connect_feed_still_authorizes() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
    let head = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n";
    let mut parser = ConnectParser::new();
    for chunk in head.chunks(3) {
        match parser.feed(chunk).expect("head feed") {
            crate::connect::Feed::Incomplete => {}
            crate::connect::Feed::Complete { .. } => break,
        }
    }
    let req = parser.result().copied().expect("result").expect("valid");
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let t0 = anchor();
    let now = later(t0, 1);
    let setup = setup_at(t0);
    let phase =
        next_phase(&view.resolve(&req), now, AttemptCounts::new(), None, setup).expect("decision");
    assert_eq!(
        phase,
        ConnectPhase::Peer {
            addr: pub_v4(),
            family: Family::A,
            connect_deadline: Deadline::connect_attempt(now, setup),
        }
    );
}

#[test]
fn traffic_buffer_matches_boot_storage_unit() {
    assert_eq!(std::mem::size_of::<TrafficBuffer>(), BUFFER_BYTES);
}

#[test]
fn cache_secs_is_mounted_on_the_dns_epoch_not_zero() {
    let t0 = anchor();
    let clock = WorkerClock::new(t0, DNS_EPOCH);
    assert_eq!(
        clock.cache_secs(later(t0, 5)),
        DNS_EPOCH + 5,
        "serving cache seconds must count from the DNS epoch the startup \
             receipts were written on, otherwise a goal-scale entry is \
             evaluated at ~0..N seconds and stays permanently Fresh (1cws M2r)"
    );
}

#[test]
fn worker_decide_reads_the_slot_deadline_instead_of_a_free_setup() {
    let t0 = anchor();
    let clock = WorkerClock::new(t0, DNS_EPOCH);
    let cfg = config();
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], DNS_EPOCH, 3600);
    let view = view_of_clocked(&cfg, &cache, clock);
    let mut worker = Worker::boot(clock);
    let slot = worker.admit(t0).expect("admitted");
    let req = auth_request("sub.example.org");
    let phase = worker
        .decide(&slot, &view.resolve(&req), later(t0, 1))
        .expect("decision from the slot-bound deadline");
    assert!(
        matches!(
            phase,
            ConnectPhase::Peer {
                family: Family::A,
                ..
            }
        ),
        "slot-bound setup must authorize this owned cache: {phase:?}"
    );
    let ConnectPhase::Peer {
        connect_deadline, ..
    } = phase
    else {
        panic!("expected Peer");
    };
    assert_eq!(
        connect_deadline.limit(),
        later(t0, 1) + Duration::from_secs(CONNECT_DEADLINE_SECS),
        "the per-attempt deadline is freshly clipped from the slot's setup deadline"
    );
    worker.release(slot);
    assert_eq!(worker.occupied(), 0);
}

#[test]
fn unknown_pair_forbids_even_when_setup_expired_and_cache_usable() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let req = auth_request("evil.example.net");
    let t0 = anchor();
    let phase = next_phase(
        &view.resolve(&req),
        later(t0, 10),
        AttemptCounts::new(),
        None,
        setup_at(t0),
    )
    .expect("decision");
    assert_eq!(
        phase,
        ConnectPhase::Forbidden,
        "a pair miss must Forbid before the expired setup deadline is consulted"
    );
}

#[test]
fn name_out_of_range_precedes_deadline_expiry_and_attempt_exhaust() {
    let cache = cache_with(1);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let req = auth_request("z.example.org");
    let t0 = anchor();
    let counts = AttemptCounts::new()
        .record(Family::A)
        .record(Family::Aaaa)
        .record(Family::A)
        .record(Family::Aaaa);
    let result = next_phase(
        &view.resolve(&req),
        later(t0, 10),
        counts,
        None,
        setup_at(t0),
    );
    assert_eq!(
        result,
        Err(crate::dns::cache::CacheError::NameOutOfRange),
        "a cache-name lookup miss precedes the expired deadline and the exhausted budget"
    );
}

#[test]
fn setup_deadline_expiry_precedes_attempt_budget_exhaust() {
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
    let cfg = config();
    let view = view_of(&cfg, &cache);
    let req = auth_request("sub.example.org");
    let t0 = anchor();
    let counts = AttemptCounts::new()
        .record(Family::A)
        .record(Family::Aaaa)
        .record(Family::A)
        .record(Family::Aaaa);
    let phase = next_phase(
        &view.resolve(&req),
        later(t0, 10),
        counts,
        None,
        setup_at(t0),
    )
    .expect("decision");
    assert_eq!(
        phase,
        ConnectPhase::DeadlineExhausted,
        "setup-deadline expiry is decided before the attempt-budget exhaust is consulted"
    );
}

#[test]
fn invalid_slot_handle_stays_notinsetup_before_unknown_pair_is_consulted() {
    let t0 = anchor();
    let clock = WorkerClock::new(t0, DNS_EPOCH);
    let cfg = config();
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], DNS_EPOCH, 3600);
    let view = view_of_clocked(&cfg, &cache, clock);
    let worker = Worker::boot(clock);
    let mut other = Worker::boot(clock);
    let slot = other.admit(t0).expect("admitted in the other worker");
    let req = auth_request("evil.example.net");
    let err = worker
        .decide(&slot, &view.resolve(&req), later(t0, 1))
        .expect_err("a foreign slot handle does not name a live setup in this worker");
    assert_eq!(
        err,
        DecideError::NotInSetup,
        "the invalid setup handle precedes the unknown-pair Forbidden decision"
    );
}

#[test]
fn decide_reads_its_budget_from_the_slot_ledger_not_a_caller_arg() {
    let t0 = anchor();
    let clock = WorkerClock::new(t0, DNS_EPOCH);
    let cfg = config();
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(
        &mut cache,
        n,
        Family::A,
        &[pub_v4(), pub_v4_b(), v4([9, 9, 9, 9])],
        DNS_EPOCH,
        3600,
    );
    publish(
        &mut cache,
        n,
        Family::Aaaa,
        &[
            pub_v6(),
            second_v6(),
            v6([0x26, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        ],
        DNS_EPOCH,
        3600,
    );
    let view = view_of_clocked(&cfg, &cache, clock);
    let mut worker = Worker::boot(clock);
    let slot = worker.admit(t0).expect("admitted");
    let req = auth_request("sub.example.org");
    let phase = worker
        .decide(&slot, &view.resolve(&req), later(t0, 1))
        .expect("decision from the slot-bound budget");
    assert!(
        matches!(
            phase,
            ConnectPhase::Peer {
                family: Family::A,
                ..
            }
        ),
        "a fresh slot ledger must offer its first attempt, got {phase:?}"
    );
    let mut seen = Vec::new();
    for i in 1..=MAX_UPSTREAM_ATTEMPTS {
        let phase = worker
            .decide(
                &slot,
                &view.resolve(&req),
                later(t0, u64::try_from(i).unwrap()),
            )
            .expect("decision within budget");
        let ConnectPhase::Peer { family, .. } = phase else {
            panic!("an in-budget decision must offer a peer, got {phase:?}");
        };
        seen.push(family);
        worker
            .record_attempt(&slot, family)
            .expect("record attempt");
    }
    assert_eq!(
        seen,
        vec![Family::A, Family::Aaaa, Family::A, Family::Aaaa],
        "the slot ledger must alternate to the family not used last time"
    );
    let phase = worker
        .decide(&slot, &view.resolve(&req), later(t0, 5))
        .expect("decision past the budget");
    assert_eq!(
        phase,
        ConnectPhase::CandidatesExhausted,
        "the slot ledger must self-enforce the {MAX_UPSTREAM_ATTEMPTS}-attempt budget"
    );
    worker.release(slot);
}

#[test]
fn record_attempt_updates_the_slot_ledger_and_previous_family() {
    let t0 = anchor();
    let clock = WorkerClock::new(t0, DNS_EPOCH);
    let mut worker = Worker::boot(clock);
    let slot = worker.admit(t0).expect("admitted");
    let fresh = worker.attempt_ledger(&slot).expect("in-setup ledger");
    assert_eq!(fresh.counts().total(), 0, "a fresh ledger has no attempts");
    assert_eq!(
        fresh.previous(),
        None,
        "a fresh ledger has no previous family"
    );
    assert_eq!(
        AttemptLedger::default(),
        AttemptLedger::new(),
        "the derived Default must equal the explicit fresh ledger"
    );
    let a_ledger = worker.record_attempt(&slot, Family::A).expect("record A");
    assert_eq!(a_ledger.counts().a(), 1, "one A attempt recorded");
    assert_eq!(a_ledger.previous(), Some(Family::A), "A is now previous");
    let alternate_ledger = worker
        .record_attempt(&slot, Family::Aaaa)
        .expect("record AAAA");
    assert_eq!(
        alternate_ledger.counts().aaaa(),
        1,
        "one AAAA attempt recorded"
    );
    assert_eq!(
        alternate_ledger.previous(),
        Some(Family::Aaaa),
        "AAAA is now previous"
    );
    worker.release(slot);
}

#[test]
fn releasing_a_slot_consumes_the_handle_and_frees_capacity_for_reuse() {
    let t0 = anchor();
    let clock = WorkerClock::new(t0, DNS_EPOCH);
    let mut worker = Worker::boot(clock);
    let a = worker.admit(t0).expect("slot a");
    assert_eq!(worker.occupied(), 1);
    worker.release(a);
    assert_eq!(worker.occupied(), 0, "release consumes the granted handle");
    let b = worker.admit(t0).expect("the freed seat is reusable");
    assert_eq!(worker.occupied(), 1);
    let b_tunnel = worker.finish_setup(b);
    assert_eq!(worker.pending(), 0);
    worker.release_tunnel(b_tunnel);
    assert_eq!(worker.occupied(), 0);
}

#[cfg(feature = "alloc-witness")]
#[test]
fn serving_decision_path_does_not_allocate_or_deallocate() {
    use crate::alloc::{Phase, run_phase};
    let cfg = config();
    let mut cache = cache_with(2);
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4(), pub_v4_b()], 100, 3600);
    publish(&mut cache, n, Family::Aaaa, &[pub_v6()], 100, 3600);
    let view = view_of(&cfg, &cache);
    let req = auth_request("sub.example.org");
    let t0 = anchor();
    let clock = clock(t0);
    let setup = setup_at(t0);
    let now = later(t0, 1);
    let (_, control) = run_phase(Phase::Serving, || 0usize);
    assert!(control.all_zero(), "baseline should be quiet: {control:?}");
    let (outcome, counts) = run_phase(Phase::Serving, || {
        let mut counts = AttemptCounts::new();
        for _ in 0..=MAX_UPSTREAM_ATTEMPTS {
            let _phase = next_phase(&view.resolve(&req), now, counts, None, setup);
            counts = counts.record(Family::A);
        }
        counts.total()
    });
    assert!(
        counts.all_zero(),
        "serving decision path allocated: {counts:?}"
    );
    assert_eq!(
        outcome,
        u8::try_from(MAX_UPSTREAM_ATTEMPTS + 1).expect("upstream attempt boundary fits u8")
    );
    let (select, select_counts) = run_phase(Phase::Serving, || {
        select_peer(&cache, n, clock.cache_secs(now), AttemptCounts::new(), None).unwrap()
    });
    assert_eq!(
        select,
        PeerDecision::Peer {
            addr: pub_v4(),
            family: Family::A
        }
    );
    assert!(
        select_counts.all_zero(),
        "select_peer allocated: {select_counts:?}"
    );
}

#[test]
fn each_view_binds_the_same_request_to_its_own_config_position() {
    let cfg_a = parse_config_document(ALLOWLIST_XY).expect("cfg_a");
    let cfg_b = parse_config_document(ALLOWLIST_AX).expect("cfg_b");
    let mut cache_a = cache_with(2);
    let x_a = name(&cache_a, 0);
    publish(&mut cache_a, x_a, Family::A, &[pub_v4()], 100, 3600);
    let y_a = name(&cache_a, 1);
    publish(&mut cache_a, y_a, Family::A, &[pub_v4_b()], 100, 3600);
    let mut cache_b = cache_with(2);
    let a_b = name(&cache_b, 0);
    publish(&mut cache_b, a_b, Family::A, &[pub_v4_b()], 100, 3600);
    let x_b = name(&cache_b, 1);
    publish(&mut cache_b, x_b, Family::A, &[pub_v4()], 100, 3600);
    let view_a = view_of(&cfg_a, &cache_a);
    let view_b = view_of(&cfg_b, &cache_b);
    let request = auth_request("x.example.org");
    let t0 = anchor();
    let now = later(t0, 1);
    let expected = || ConnectPhase::Peer {
        addr: pub_v4(),
        family: Family::A,
        connect_deadline: Deadline::connect_attempt(now, setup_at(t0)),
    };
    assert_eq!(view_a.resolve(&request).ordinal(), Some(0));
    assert_eq!(
        next_phase(
            &view_a.resolve(&request),
            now,
            AttemptCounts::new(),
            None,
            setup_at(t0),
        )
        .expect("decision under cfg_a"),
        expected()
    );
    assert_eq!(view_b.resolve(&request).ordinal(), Some(1));
    assert_eq!(
        next_phase(
            &view_b.resolve(&request),
            now,
            AttemptCounts::new(),
            None,
            setup_at(t0),
        )
        .expect("decision under cfg_b"),
        expected()
    );
}

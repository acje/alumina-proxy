use super::*;
use crate::config::parse_config_document;
use crate::dns::cache::{Generation, StagedPositive, evidence};
use crate::inspection::connect::ConnectParser;
use std::net::{Ipv4Addr, Ipv6Addr};

const CONFIG: &str = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"sub.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n[allowed_fqdn.\"z.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n";

const ALLOWLIST_XY: &str = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"x.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n[allowed_fqdn.\"y.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n";

const ALLOWLIST_AX: &str = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"a.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n[allowed_fqdn.\"x.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n";

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

/// One canonical loopback peer for the per-peer accounting tests: distinct
/// tags are distinct peers without needing a second loopback address (macOS
/// refuses to bind 127.0.0.0/8 aliases beyond .1).
fn peer(tag: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(
        127,
        0,
        0,
        u8::try_from(tag + 1).expect("peer tag fits an IPv4 octet"),
    ))
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
        crate::inspection::connect::Feed::Complete { .. } => {
            parser.result().copied().expect("result")
        }
        crate::inspection::connect::Feed::Incomplete => panic!("head incomplete"),
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
fn dial_guard_admits_fresh_auth_evidence_then_denies_after_expiry() {
    let mut cache =
        Cache::with_requirement(2, evidence::AssuranceRequirement::ResolverAuthenticated)
            .expect("cache");
    let n = name(&cache, 0);
    let ev = evidence::Evidence::new(
        true,
        true,
        false,
        evidence::ResolverSource::index(0).expect("resolver"),
        Some(60),
        DNS_EPOCH + 1000,
    )
    .expect("AD0 auth evidence");
    let staged = StagedPositive::stage_with_evidence(
        n,
        Family::A,
        Generation::INITIAL,
        &[pub_v4()],
        DNS_EPOCH + 1001,
        60,
        Some(ev),
    )
    .expect("staged");
    cache.publish_positive(&staged).expect("published");
    let cfg = config();
    let anchor = anchor();
    let view = view_of_clocked(&cfg, &cache, WorkerClock::new(anchor, DNS_EPOCH + 1000));
    let req = auth_request("sub.example.org");
    let resolved = view.resolve(&req);
    assert_eq!(resolved.dial_admits(pub_v4(), later(anchor, 1)), Ok(true));
    assert_eq!(resolved.dial_admits(pub_v4(), later(anchor, 60)), Ok(false));
}

#[test]
fn dial_guard_reports_absent_cache_name_as_error() {
    let cache = cache_with(1);
    let cfg = config();
    let anchor = anchor();
    let view = view_of_clocked(&cfg, &cache, WorkerClock::new(anchor, DNS_EPOCH));
    let req = auth_request("z.example.org");
    let resolved = view.resolve(&req);
    assert_eq!(
        resolved.dial_admits(pub_v4(), later(anchor, 0)),
        Err(crate::dns::cache::CacheError::NameOutOfRange)
    );
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
fn owned_requirement_peer_selection_uses_cache_owner_minimum() {
    use crate::dns::cache::evidence::AssuranceRequirement as Req;
    use crate::dns::cache::evidence::Evidence;
    use crate::dns::cache::evidence::ResolverSource;
    let mut cache = Cache::with_requirement(1, Req::ResolverAuthenticated).expect("cache");
    let n = name(&cache, 0);
    publish(&mut cache, n, Family::A, &[pub_v4()], 1_001, 60);
    let ev = Evidence::new(
        false,
        true,
        false,
        ResolverSource::index(0).expect("source"),
        Some(60),
        1_000,
    )
    .expect("evidence");
    let staged = StagedPositive::stage_with_evidence(
        n,
        Family::Aaaa,
        Generation::INITIAL,
        &[pub_v6()],
        1_001,
        60,
        Some(ev),
    )
    .expect("staged");
    cache.publish_positive(&staged).expect("published");

    let first = select_peer(&cache, n, 1_001, AttemptCounts::new(), None).expect("selection");
    assert_eq!(
        first,
        PeerDecision::Peer {
            addr: pub_v6(),
            family: Family::Aaaa
        }
    );
    let expired = select_peer(&cache, n, 1_060, AttemptCounts::new(), None).expect("selection");
    assert_eq!(expired, PeerDecision::NoFamily);
    cache.evict_nodata(n, Family::Aaaa).expect("evict");
    let no_grade = select_peer(&cache, n, 1_001, AttemptCounts::new(), None).expect("selection");
    assert_eq!(no_grade, PeerDecision::NoFamily);
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
    // The global 128-seat budget fills across distinct peers, because every
    // peer may hold at most MAX_PENDING_PER_PEER pending setups.
    let peers = MAX_PENDING_SETUPS / MAX_PENDING_PER_PEER;
    let mut first_peer_slot = None;
    for seat in 0..MAX_PENDING_SETUPS {
        let slot = worker
            .admit(t0, peer(seat % peers))
            .expect("admitted within the pending budget");
        if seat == 0 {
            first_peer_slot = Some(slot);
        }
    }
    assert_eq!(worker.pending(), MAX_PENDING_SETUPS);
    assert_eq!(
        worker.admit(t0, peer(peers)),
        Err(AdmissionError::PendingCapacity),
        "a fresh peer is still refused at the global pending cap"
    );
    // The global cap, not per-peer ownership, was the blocker: a seat released
    // by one peer is available to a distinct peer.
    worker.release(first_peer_slot.expect("first admitted seat"));
    worker
        .admit(t0, peer(peers))
        .expect("a seat freed at the global cap admits a distinct peer");
    assert_eq!(worker.pending(), MAX_PENDING_SETUPS);
}

#[test]
/// The per-peer pending cap: one peer can fill exactly its own seats and is
/// then refused through the existing `PendingCapacity` path, while a distinct
/// peer still gets a pending seat — a single reachable peer can never deny
/// admission to another peer.
fn per_peer_pending_cap_denies_one_peer_and_admits_a_distinct_peer() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    let peer_a = peer(0);
    let peer_b = peer(1);
    for _ in 0..MAX_PENDING_PER_PEER {
        worker.admit(t0, peer_a).expect("within the per-peer cap");
    }
    assert_eq!(worker.pending(), MAX_PENDING_PER_PEER);
    assert_eq!(
        worker.admit(t0, peer_a),
        Err(AdmissionError::PendingCapacity),
        "a peer at its per-peer pending cap must be refused through the capacity path"
    );
    assert_eq!(
        worker.pending(),
        MAX_PENDING_PER_PEER,
        "the refused setup consumes no pending seat"
    );
    let b_slot = worker
        .admit(t0, peer_b)
        .expect("a distinct peer must still get a pending seat");
    assert_eq!(
        worker.pending(),
        MAX_PENDING_PER_PEER + 1,
        "the distinct peer's seat is admitted on top of the capped peer's seats"
    );
    worker.release(b_slot);
}

#[test]
/// Release and graduation free only the releasing peer's own pending seat: a
/// peer at its cap regains exactly one seat per freed slot (never another
/// peer's), and the other peer's pending count is untouched.
fn per_peer_pending_cap_frees_only_its_own_peer_seat() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    let peer_a = peer(0);
    let peer_b = peer(1);
    let mut a_slots = Vec::new();
    for _ in 0..MAX_PENDING_PER_PEER {
        a_slots.push(worker.admit(t0, peer_a).expect("within the per-peer cap"));
    }
    assert_eq!(
        worker.admit(t0, peer_a),
        Err(AdmissionError::PendingCapacity)
    );
    let b_slot = worker.admit(t0, peer_b).expect("distinct peer admitted");

    // Releasing one A seat restores exactly one A seat.
    worker.release(a_slots.pop().expect("an A seat to release"));
    worker
        .admit(t0, peer_a)
        .expect("A's released seat restores one A seat");
    assert_eq!(
        worker.admit(t0, peer_a),
        Err(AdmissionError::PendingCapacity),
        "only the released seat returns; A is not admitted beyond its cap"
    );

    // Graduating one A setup frees its pending seat the same way.
    worker.finish_setup(a_slots.pop().expect("an A seat to graduate"));
    worker
        .admit(t0, peer_a)
        .expect("A's graduated setup frees one A pending seat");
    assert_eq!(
        worker.pending(),
        MAX_PENDING_PER_PEER + 1,
        "A holds its cap again plus B's untouched seat"
    );
    worker.release(b_slot);
}

#[test]
fn releasing_a_setup_slot_frees_pending_capacity() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    let peers = MAX_PENDING_SETUPS / MAX_PENDING_PER_PEER;
    for seat in 0..MAX_PENDING_SETUPS - 1 {
        worker.admit(t0, peer(seat % peers)).expect("admitted");
    }
    let last_peer = (MAX_PENDING_SETUPS - 1) % peers;
    let last = worker
        .admit(t0, peer(last_peer))
        .expect("admitted at the pending cap");
    worker.release(last);
    worker
        .admit(t0, peer(last_peer))
        .expect("seat freed by release");
    assert_eq!(worker.pending(), MAX_PENDING_SETUPS);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "release requires an in-setup slot")]
fn release_rejects_a_slot_that_is_not_in_setup() {
    let t0 = anchor();
    let mut worker = Worker::boot(clock(t0));
    let slot = worker.admit(t0, peer(0)).expect("admitted");
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
        let slot = worker.admit(t0, peer(0)).expect("admitted to a free slot");
        tunnels.push(worker.finish_setup(slot));
    }
    assert_eq!(worker.admit(t0, peer(0)), Err(AdmissionError::SlotCapacity));
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
    let a = worker.admit(t0, peer(0)).expect("slot a");
    let b = worker.admit(t0, peer(0)).expect("slot b");
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
    let slot = worker.admit(t0, peer(0)).expect("admitted");
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
        let slot = worker.admit(t0, peer(0)).expect("admitted to a free slot");
        tunnels.push(worker.finish_setup(slot));
    }
    for tunnel in tunnels {
        worker.release_tunnel(tunnel);
    }
    for _ in 0..MAX_PENDING_SETUPS {
        let slot = worker
            .admit(t0, peer(0))
            .expect("admitted after full teardown");
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
        let slot = worker.admit(t0, peer(0)).expect("admitted to a free slot");
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
    let a = worker.admit(t0, peer(0)).expect("admitted");
    assert_eq!(SlotIndex::index(&a), 0, "first admit takes slot 0");
    let b = worker.admit(t0, peer(0)).expect("admitted");
    assert_eq!(SlotIndex::index(&b), 1, "second admit takes slot 1");
    worker.release(a);
    let c = worker.admit(t0, peer(0)).expect("re-admitted");
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
            crate::inspection::connect::Feed::Incomplete => {}
            crate::inspection::connect::Feed::Complete { .. } => break,
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
    let slot = worker.admit(t0, peer(0)).expect("admitted");
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
    let slot = other
        .admit(t0, peer(0))
        .expect("admitted in the other worker");
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
    let slot = worker.admit(t0, peer(0)).expect("admitted");
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
    let slot = worker.admit(t0, peer(0)).expect("admitted");
    let fresh = worker.attempt_ledger(&slot).expect("in-setup ledger");
    assert_eq!(fresh.counts().total(), 0, "a fresh ledger has no attempts");
    assert_eq!(
        fresh.previous(),
        None,
        "a fresh ledger has no previous family"
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
    let a = worker.admit(t0, peer(0)).expect("slot a");
    assert_eq!(worker.occupied(), 1);
    worker.release(a);
    assert_eq!(worker.occupied(), 0, "release consumes the granted handle");
    let b = worker
        .admit(t0, peer(0))
        .expect("the freed seat is reusable");
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

/// A model-based machine over the fixed slot table [`Worker`] owns. The
/// scripted tests above walk the lifecycles somebody wrote down; this machine
/// admits, records attempts, graduates, releases and re-admits in generated
/// orders until the fixed caps bind, and checks the table's accounting and
/// ownership after every rule.
///
/// Invariants (all `always_run`, so each sees every intermediate state):
/// S1 `occupied() <= MAX_TUNNELS`, `pending() <= MAX_PENDING_SETUPS`, and no
///    canonical peer holds more than `MAX_PENDING_PER_PEER` pending setups.
/// S2 `occupied()` equals the model's live handle count and `pending()` equals
///    its live setup handle count.
/// S3 live slot indices are pairwise distinct and all below `MAX_TUNNELS`.
/// S4 a graduated slot exposes no in-setup ledger, while a live setup does.
/// S5 an index released by `release`/`release_tunnel` is never live again
///    without a fresh admit, and every live handle's subject slot is occupied
///    in the class its handle type names.
///
/// Independence: the model is a `Vec` of the *handles the subject handed out*,
/// never a second scan of the subject's slot array. S2 is therefore a genuine
/// cross-check — the subject's cached counters against the model's handle
/// count — and not a restatement of the debug lockstep scan; S1's per-peer
/// clause reads the drawn peers the model remembered, not the subject's
/// `InSetup` peer fields; S3 and S5 are set properties over those handles. The
/// admit rule additionally asserts the subject's accept/refuse result and
/// refusal reason against the model's own capacity state, which is what makes
/// the per-peer cap observable: the subject exposes no per-peer counter.
mod slot_table_machine {
    use super::*;
    use hegel::TestCase;
    use hegel::generators as gs;

    /// Five canonical peers, so the global pending budget (four per-peer caps
    /// would reach exactly `MAX_PENDING_SETUPS` with four) is independently
    /// binding and a dropped global check cannot hide behind the per-peer one.
    const CANONICAL_PEERS: usize = 5;

    /// The drawn peers, each with the canonical peer it belongs to. The first
    /// two are one peer under two spellings, so the per-peer cap must count
    /// them once.
    const PEERS: [(IpAddr, u8); 6] = [
        (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
        (
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
            0,
        ),
        (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1),
        (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 2),
        (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)), 3),
        (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)), 4),
    ];

    #[derive(Debug)]
    enum Live {
        Setup { slot: SlotIndex, peer: u8 },
        Established(TunnelIndex),
    }

    impl Live {
        fn index(&self) -> usize {
            match self {
                Live::Setup { slot, .. } => SlotIndex::index(slot),
                Live::Established(tunnel) => TunnelIndex::index(tunnel),
            }
        }

        fn is_setup(&self) -> bool {
            matches!(self, Live::Setup { .. })
        }
    }

    /// A probe handle naming a slot index: the machine keeps the handles the
    /// subject handed out, and re-mints one here only to ask the subject what
    /// state that index is in. A handle mints no capacity — the table owns the
    /// accounting — so a probe can never free or graduate a slot.
    fn probe(index: usize) -> SlotIndex {
        SlotIndex(u16::try_from(index).expect("a slot index fits u16"))
    }

    pub(super) struct SlotTable {
        worker: Worker,
        now: Instant,
        live: Vec<Live>,
    }

    impl SlotTable {
        pub(super) fn start() -> SlotTable {
            let now = anchor();
            SlotTable {
                worker: Worker::boot(clock(now)),
                now,
                live: Vec::new(),
            }
        }

        fn pending_from(&self, peer: u8) -> usize {
            self.live
                .iter()
                .filter(|live| matches!(live, Live::Setup { peer: p, .. } if *p == peer))
                .count()
        }

        /// The position of a live handle of the drawn class, drawn uniformly
        /// over the handles of that class; `None` when none is live.
        fn draw_live(&self, tc: &TestCase, setup: bool) -> Option<usize> {
            let candidates = self
                .live
                .iter()
                .filter(|live| live.is_setup() == setup)
                .count();
            if candidates == 0 {
                return None;
            }
            let pick = tc.draw(
                gs::integers::<usize>()
                    .min_value(0)
                    .max_value(candidates - 1),
            );
            let mut seen = 0usize;
            for (position, live) in self.live.iter().enumerate() {
                if live.is_setup() == setup {
                    if seen == pick {
                        return Some(position);
                    }
                    seen += 1;
                }
            }
            None
        }

        fn take_setup(&mut self, position: usize) -> Option<(SlotIndex, u8)> {
            match self.live.swap_remove(position) {
                Live::Setup { slot, peer } => Some((slot, peer)),
                other @ Live::Established(_) => {
                    self.live.push(other);
                    None
                }
            }
        }

        fn take_established(&mut self, position: usize) -> Option<TunnelIndex> {
            match self.live.swap_remove(position) {
                Live::Established(tunnel) => Some(tunnel),
                other @ Live::Setup { .. } => {
                    self.live.push(other);
                    None
                }
            }
        }
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "the hegel state-machine macro hands each rule its own TestCase by value"
    )]
    #[hegel::state_machine]
    impl SlotTable {
        #[rule(weight = 12.0)]
        fn admit(&mut self, tc: TestCase) {
            let (peer, canonical) = tc.draw(gs::sampled_from(&PEERS[..]));
            let predicted = if self.worker.occupied() >= MAX_TUNNELS {
                Err(AdmissionError::SlotCapacity)
            } else if self.worker.pending() >= MAX_PENDING_SETUPS
                || self.pending_from(canonical) >= MAX_PENDING_PER_PEER
            {
                Err(AdmissionError::PendingCapacity)
            } else {
                Ok(())
            };
            match (predicted, self.worker.admit(self.now, peer)) {
                (Ok(()), Ok(slot)) => self.live.push(Live::Setup {
                    slot,
                    peer: canonical,
                }),
                (Ok(()), Err(actual)) => {
                    panic!("the model predicted a free seat, the worker refused: {actual:?}")
                }
                (Err(expected), Ok(_)) => {
                    panic!("the model predicted {expected:?}, the worker admitted a seat")
                }
                (Err(expected), Err(actual)) => assert_eq!(
                    actual, expected,
                    "the worker's refusal reason disagrees with the model's capacity state"
                ),
            }
        }

        #[rule(weight = 2.0)]
        fn record_attempt(&mut self, tc: TestCase) {
            let Some(position) = self.draw_live(&tc, true) else {
                return;
            };
            let family = tc.draw(gs::sampled_from(&[Family::A, Family::Aaaa][..]));
            let Some((slot, peer)) = self.take_setup(position) else {
                return;
            };
            let before = self
                .worker
                .attempt_ledger(&slot)
                .expect("a live setup carries a ledger");
            let after = self
                .worker
                .record_attempt(&slot, family)
                .expect("a live setup records an attempt");
            assert_eq!(
                after.previous(),
                Some(family),
                "the recorded attempt is the ledger's previous family"
            );
            assert!(
                after.counts().a() >= before.counts().a()
                    && after.counts().aaaa() >= before.counts().aaaa(),
                "an attempt never decreases a family counter"
            );
            self.live.push(Live::Setup { slot, peer });
        }

        #[rule(weight = 2.0)]
        fn finish_setup(&mut self, tc: TestCase) {
            let Some(position) = self.draw_live(&tc, true) else {
                return;
            };
            let Some((slot, _)) = self.take_setup(position) else {
                return;
            };
            let index = SlotIndex::index(&slot);
            let occupied_before = self.worker.occupied();
            let pending_before = self.worker.pending();
            let tunnel = self.worker.finish_setup(slot);
            assert_eq!(
                self.worker.occupied(),
                occupied_before,
                "graduation keeps the slot occupied"
            );
            assert_eq!(
                self.worker.pending(),
                pending_before - 1,
                "graduation frees exactly one pending seat"
            );
            assert_eq!(
                TunnelIndex::index(&tunnel),
                index,
                "graduation keeps the physical slot"
            );
            assert!(
                self.worker.attempt_ledger(&probe(index)).is_none(),
                "an established tunnel must not expose an in-setup ledger"
            );
            self.live.push(Live::Established(tunnel));
        }

        #[rule(weight = 2.0)]
        fn release(&mut self, tc: TestCase) {
            let Some(position) = self.draw_live(&tc, true) else {
                return;
            };
            let Some((slot, _)) = self.take_setup(position) else {
                return;
            };
            let index = SlotIndex::index(&slot);
            let occupied_before = self.worker.occupied();
            let pending_before = self.worker.pending();
            self.worker.release(slot);
            assert_eq!(
                self.worker.occupied(),
                occupied_before - 1,
                "release frees the occupied seat"
            );
            assert_eq!(
                self.worker.pending(),
                pending_before - 1,
                "release frees the pending seat"
            );
            assert!(
                !self.live.iter().any(|live| live.index() == index),
                "a released index must leave the live set"
            );
            assert!(
                matches!(self.worker.slots[index], SlotState::Free),
                "a released slot must be free in the table"
            );
        }

        #[rule(weight = 2.0)]
        fn release_tunnel(&mut self, tc: TestCase) {
            let Some(position) = self.draw_live(&tc, false) else {
                return;
            };
            let Some(tunnel) = self.take_established(position) else {
                return;
            };
            let index = TunnelIndex::index(&tunnel);
            let occupied_before = self.worker.occupied();
            let pending_before = self.worker.pending();
            self.worker.release_tunnel(tunnel);
            assert_eq!(
                self.worker.occupied(),
                occupied_before - 1,
                "releasing an established tunnel frees its occupied seat"
            );
            assert_eq!(
                self.worker.pending(),
                pending_before,
                "releasing an established tunnel leaves the pending count alone"
            );
            assert!(
                !self.live.iter().any(|live| live.index() == index),
                "a released index must leave the live set"
            );
            assert!(
                matches!(self.worker.slots[index], SlotState::Free),
                "a released slot must be free in the table"
            );
        }

        #[rule(weight = 1.0)]
        fn observe(&mut self, _: TestCase) {
            let occupied = self.worker.occupied();
            let pending = self.worker.pending();
            assert_eq!(
                self.worker.occupied(),
                occupied,
                "reading the occupied count must not move it"
            );
            assert_eq!(
                self.worker.pending(),
                pending,
                "reading the pending count must not move it"
            );
        }

        #[invariant(always_run)]
        fn s1_fixed_capacity_caps_hold(&self, _: TestCase) {
            assert!(
                self.worker.occupied() <= MAX_TUNNELS,
                "occupied {} exceeds the fixed slot budget",
                self.worker.occupied()
            );
            assert!(
                self.worker.pending() <= MAX_PENDING_SETUPS,
                "pending {} exceeds the fixed pending budget",
                self.worker.pending()
            );
            for peer in 0..CANONICAL_PEERS {
                let pending = self.pending_from(u8::try_from(peer).expect("five canonical peers"));
                assert!(
                    pending <= MAX_PENDING_PER_PEER,
                    "peer {peer} holds {pending} pending setups, above the per-peer cap"
                );
            }
        }

        #[invariant(always_run)]
        fn s2_counters_match_the_model_handles(&self, _: TestCase) {
            let setups = self.live.iter().filter(|live| live.is_setup()).count();
            assert_eq!(
                self.worker.occupied(),
                self.live.len(),
                "the occupied counter disagrees with the model's live handles"
            );
            assert_eq!(
                self.worker.pending(),
                setups,
                "the pending counter disagrees with the model's setup handles"
            );
        }

        #[invariant(always_run)]
        fn s3_live_indices_are_distinct_and_in_range(&self, _: TestCase) {
            let mut seen = [false; MAX_TUNNELS];
            for live in &self.live {
                let index = live.index();
                assert!(
                    index < MAX_TUNNELS,
                    "live slot index {index} is outside the fixed table"
                );
                assert!(!seen[index], "slot index {index} is live more than once");
                seen[index] = true;
            }
        }

        #[invariant(always_run)]
        fn s4_ledger_follows_the_handle_class(&self, _: TestCase) {
            for live in &self.live {
                let index = live.index();
                let ledger = self.worker.attempt_ledger(&probe(index));
                if live.is_setup() {
                    assert!(
                        ledger.is_some(),
                        "live setup at slot {index} exposes no attempt ledger"
                    );
                } else {
                    assert!(
                        ledger.is_none(),
                        "established tunnel at slot {index} still exposes an in-setup ledger"
                    );
                }
            }
        }

        #[invariant(always_run)]
        fn s5_owner_is_the_handle_the_table_granted(&self, _: TestCase) {
            for live in &self.live {
                let index = live.index();
                let occupied = !matches!(self.worker.slots[index], SlotState::Free);
                assert!(
                    occupied,
                    "slot {index} is free while a live handle names it"
                );
                let in_setup = matches!(self.worker.slots[index], SlotState::InSetup { .. });
                assert_eq!(
                    in_setup,
                    live.is_setup(),
                    "slot {index} is in the wrong lifecycle state for its handle"
                );
            }
        }
    }
}

/// The slot table as a state machine: model-based coverage of admission,
/// graduation, release and re-admission under the fixed caps, driving the same
/// production [`Worker`] the scripted tests above drive. Its invariant list and
/// independence argument are on [`slot_table_machine`]; `hegel.toml` owns the
/// case count.
#[hegel::test(derandomize = true)]
fn worker_slot_table_keeps_capacity_and_ownership(tc: hegel::TestCase) {
    hegel::stateful::machine(slot_table_machine::SlotTable::start())
        .steps(400)
        .run(tc);
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

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
///
/// The single-admit rule cannot reach `occupied() == MAX_TUNNELS` on its own:
/// the pending budget `MAX_PENDING_SETUPS` (128) binds before the slot budget
/// `MAX_TUNNELS` (512). The `admit_burst` rule graduates each admitted seat,
/// freeing its pending seat while keeping it occupied, so a case reaches the
/// full-table `SlotCapacity` refusal that S1's first clause needs.
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

        /// A burst of up to 64 admissions. The pending budget
        /// ([`MAX_PENDING_SETUPS`], 128) is smaller than the slot budget
        /// ([`MAX_TUNNELS`], 512), so a burst of bare admits would stop at
        /// `PendingCapacity` with the table still below its slot budget. Each
        /// admitted seat is graduated immediately instead: graduation keeps the
        /// occupied seat and frees its pending seat, so successive bursts raise
        /// `occupied()` by up to 64 without the pending counter accumulating
        /// until the table is full.
        ///
        /// The full-table [`AdmissionError::SlotCapacity`] path is reached only
        /// from a fresh seat: when `occupied()` is at [`MAX_TUNNELS`] no seat is
        /// left to admit, so no admitted seat is graduated and the table stays
        /// full for the rest of the burst.
        ///
        /// [`AdmissionError::PendingCapacity`] is returned on any attempt whose
        /// drawn peer is gated. The global [`MAX_PENDING_SETUPS`] budget gates
        /// an attempt whose `pending()` is already at the cap; the burst cannot
        /// spend that budget itself, because each admitted seat is graduated,
        /// but interleaved admits from the other rules can. The per-peer
        /// [`MAX_PENDING_PER_PEER`] budget gates an attempt that draws a peer
        /// already holding its cap; graduating the admitted seat frees the
        /// pending seat of that peer only, so the other peers' counts are
        /// unchanged across attempts and a later attempt can still be refused.
        /// Every refusal is checked against the model's own capacity state: the
        /// `occupied_at_slot_capacity` and `slot_capacity_refusal` events mark
        /// the full-table path, and `per_peer_capacity_refusal` marks a refusal
        /// gated by the drawn peer's own budget.
        #[rule(weight = 8.0)]
        fn admit_burst(&mut self, tc: TestCase) {
            let attempts = tc.draw(gs::integers::<usize>().min_value(1).max_value(64));
            for attempt in 0..attempts {
                let (peer, canonical) = tc.draw(gs::sampled_from(&PEERS[..]));
                let gated_by_peer = self.pending_from(canonical) >= MAX_PENDING_PER_PEER;
                let predicted = if self.worker.occupied() >= MAX_TUNNELS {
                    Err(AdmissionError::SlotCapacity)
                } else if self.worker.pending() >= MAX_PENDING_SETUPS || gated_by_peer {
                    Err(AdmissionError::PendingCapacity)
                } else {
                    Ok(())
                };
                match (predicted, self.worker.admit(self.now, peer)) {
                    (Ok(()), Ok(slot)) => {
                        let index = SlotIndex::index(&slot);
                        let occupied = self.worker.occupied();
                        let tunnel = self.worker.finish_setup(slot);
                        assert_eq!(
                            TunnelIndex::index(&tunnel),
                            index,
                            "graduating an admitted seat keeps its physical slot"
                        );
                        assert_eq!(
                            self.worker.occupied(),
                            occupied,
                            "graduating an admitted seat keeps it occupied"
                        );
                        self.live.push(Live::Established(tunnel));
                        if occupied == MAX_TUNNELS {
                            tc.event("occupied_at_slot_capacity");
                        }
                    }
                    (Err(expected), Err(actual)) => {
                        assert_eq!(
                            actual, expected,
                            "the worker's refusal reason disagrees with the model's capacity state"
                        );
                        if expected == AdmissionError::SlotCapacity {
                            tc.event("slot_capacity_refusal");
                            let (peer, _) = tc.draw(gs::sampled_from(&PEERS[..]));
                            let follow_up = (attempts - attempt - 1).max(1);
                            for _ in 0..follow_up {
                                assert_eq!(
                                    self.worker.admit(self.now, peer),
                                    Err(AdmissionError::SlotCapacity),
                                    "the table admitted a seat after reporting SlotCapacity while full"
                                );
                            }
                        } else if gated_by_peer {
                            tc.event("per_peer_capacity_refusal");
                        }
                        return;
                    }
                    (Ok(()), Err(actual)) => {
                        panic!("the model predicted a free seat, the worker refused: {actual:?}")
                    }
                    (Err(expected), Ok(_)) => {
                        panic!("the model predicted {expected:?}, the worker admitted a seat")
                    }
                }
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

/// The CONNECT authorization and peer-selection decision as a model-based
/// state machine over drawn cache states and drawn attempt sequences.
///
/// The subject is the production [`Worker`]: its `decide`, `record_attempt`,
/// `finish_setup` and `release` transitions, with the decision itself made by
/// the crate-internal `next_phase` from the slot's own setup deadline and
/// attempt ledger. The model owns a [`Cache`] published through the same
/// staged-positive route the production DNS adapter uses, the attempt counters
/// it recorded, and the setup instant it admitted. Every invariant is computed
/// from the model's own publication record and attempt ledger plus the
/// subject's returned [`ConnectPhase`]; none re-calls `select_peer` or reads a
/// selection cursor as an oracle.
///
/// The drawn address pools hold only eligible, pairwise-distinct addresses, so
/// publication is the identity on a drawn binding set: the cache's own
/// eligibility filter and dedup have nothing to remove. The publish rule
/// asserts that identity against the cache, which makes "a binding the model
/// published" and "a binding the cache holds" the same set without the
/// invariants reading the cache.
///
/// One admitted setup slot is always live. The initial admit is anchored on
/// the machine's clock origin so every rule starts from a decidable slot; the
/// release and graduation rules draw a fresh setup instant on re-admission, so
/// the setup deadline and a reset attempt budget are drawn state too.
///
/// Invariants (each `#[invariant(always_run)]`, evaluated over the snapshot
/// captured at the decision):
/// - P1 a `Forbidden` result holds exactly when the resolved ordinal is absent.
///   The model knows the drawn request's allowlist position by construction
///   (`auth_request` of an allowlisted name or an unlisted host), never by
///   asking the subject.
/// - P2 `DeadlineExhausted` holds exactly when the model's own clock has
///   reached the setup deadline it derived from its drawn admit instant; it is
///   never returned before that deadline.
/// - P3 `CandidatesExhausted` holds exactly when the model's own recorded
///   attempt total has reached `MAX_UPSTREAM_ATTEMPTS` and the deadline has not
///   passed.
/// - P4 a `Peer` names the binding the model published at the index equal to
///   the model's earlier attempts in that family in the current generation, is
///   eligible, and comes from a servable (never retired) publication. The
///   generation cross-check reads the cache's publication tag, which is
///   publication bookkeeping, not the selection cursor.
/// - P5 after an attempt in family F, if the other family has a usable
///   published binding at its cursor the next `Peer` is in the other family;
///   otherwise it stays in F.
/// - P6 `NoBinding` holds exactly when neither family has an unused,
///   non-retired, eligible binding at its cursor and neither the deadline nor
///   the attempt budget has terminated the decision.
/// - P7 a `Peer`'s `connect_deadline` equals the model's own `now + 2 s` clip
///   to the setup deadline and is never later than it.
mod peer_selection_machine {
    use super::*;
    use crate::dns::cache::{STALE_GRACE, STALE_SERVING_WINDOW};
    use hegel::TestCase;
    use hegel::generators as gs;

    /// Clock advances that reach every modelled boundary exactly: before,
    /// at, and just past the 10 s setup deadline; a whole minute for freshness
    /// drift; and one full stale-grace jump to retire a publication without
    /// spending thousands of steps on the cache clock.
    const CLOCK_STEPS: [u64; 12] = [0, 1, 2, 3, 4, 5, 9, 10, 11, 60, 3_600, STALE_GRACE];

    /// Three eligible IPv4 destinations, so a drawn mask enumerates every
    /// distinct binding subset.
    fn a_pool() -> [NumericAddr; 3] {
        [v4([8, 8, 8, 8]), v4([1, 1, 1, 1]), v4([9, 9, 9, 9])]
    }

    /// Three eligible IPv6 destinations, disjoint from the IPv4 pool.
    fn aaaa_pool() -> [NumericAddr; 3] {
        [
            pub_v6(),
            second_v6(),
            v6([
                0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
            ]),
        ]
    }

    fn pool(family: Family) -> [NumericAddr; 3] {
        match family {
            Family::A => a_pool(),
            Family::Aaaa => aaaa_pool(),
        }
    }

    const fn fam_index(family: Family) -> usize {
        match family {
            Family::A => 0,
            Family::Aaaa => 1,
        }
    }

    const fn count_in(counts: AttemptCounts, family: Family) -> u8 {
        match family {
            Family::A => counts.a(),
            Family::Aaaa => counts.aaaa(),
        }
    }

    fn draw_family(tc: &TestCase) -> Family {
        tc.draw(gs::sampled_from(&[Family::A, Family::Aaaa][..]))
    }

    /// The setup deadline the model derives from its drawn admit instant, using
    /// the fixed setup budget and the same checked-add saturation as
    /// `Deadline::setup`. Model-owned: the subject is never asked for it.
    fn model_setup_limit(admit: Instant) -> Instant {
        admit
            .checked_add(Duration::from_secs(SETUP_DEADLINE_SECS))
            .unwrap_or(admit)
    }

    /// The per-attempt connect deadline the model expects: `now + 2 s` clipped
    /// to the setup limit, computed from the model's own instants rather than
    /// by calling `Deadline::connect_attempt`.
    fn model_connect_limit(now: Instant, setup_limit: Instant) -> Instant {
        let fresh = now
            .checked_add(Duration::from_secs(CONNECT_DEADLINE_SECS))
            .unwrap_or(now);
        fresh.min(setup_limit)
    }

    /// A handle naming a slot index. A probe mints no capacity (the table owns
    /// the accounting), so it can only ask the subject what state an index is
    /// in; the machine re-mints one to observe that a released or graduated
    /// handle refuses to decide.
    fn probe(index: usize) -> SlotIndex {
        SlotIndex(u16::try_from(index).expect("a slot index fits u16"))
    }

    /// The model's record of one family's last publication: the exact binding
    /// sequence the staged-positive route published and the freshness and
    /// retirement limits derived from the drawn receipt and TTL. Servability
    /// and the cursor candidate are computed from those drawn facts, never from
    /// the cache's entry. The model only draws nonzero TTLs, so a stale entry
    /// always admits stale serving; zero-TTL non-serving is covered by the
    /// scripted examples.
    #[derive(Clone)]
    struct Published {
        addrs: Vec<NumericAddr>,
        generation: Generation,
        fresh_deadline: u64,
        retirement_deadline: u64,
    }

    impl Published {
        fn servable(&self, now: u64) -> bool {
            if self.addrs.is_empty() || now >= self.retirement_deadline {
                return false;
            }
            if now < self.fresh_deadline {
                return true;
            }
            now < self.fresh_deadline.saturating_add(STALE_SERVING_WINDOW)
        }

        /// The binding the documented selection rule uses for this family at
        /// `cursor`: the entry must be servable and the cursor must name a
        /// published binding. Candidates are drawn only from the eligible pool,
        /// so eligibility and membership hold by construction, not by reading
        /// the cache.
        fn candidate(&self, cursor: u8, now: u64) -> Option<NumericAddr> {
            if !self.servable(now) {
                return None;
            }
            self.addrs.get(usize::from(cursor)).copied()
        }
    }

    /// The model state captured at one decision: the model's own publication
    /// records, attempt ledger, previous family, drawn allowlist ordinal and
    /// clock, plus the subject's returned phase. The invariants read this
    /// snapshot only, so a later rule that republishes or evicts cannot
    /// retroactively reinterpret an earlier decision.
    struct Snapshot {
        ordinal: Option<usize>,
        phase: ConnectPhase,
        now: Instant,
        cache_now: u64,
        setup_limit: Instant,
        counts: AttemptCounts,
        previous: Option<Family>,
        published: [Option<Published>; 2],
        cache_generations: [Generation; 2],
    }

    impl Snapshot {
        fn candidate(&self, family: Family) -> Option<NumericAddr> {
            let published = self.published[fam_index(family)].as_ref()?;
            published.candidate(count_in(self.counts, family), self.cache_now)
        }

        fn live_generation(&self, family: Family) -> Option<&Published> {
            self.published[fam_index(family)].as_ref()
        }
    }

    pub(super) struct PeerSelection {
        cfg: Config,
        cache: Cache,
        worker: Worker,
        clock: WorkerClock,
        base: Instant,
        now: Instant,
        allowed_request: ConnectRequest,
        forbidden_request: ConnectRequest,
        slot: Option<SlotIndex>,
        setup_limit: Instant,
        attempts: AttemptCounts,
        previous: Option<Family>,
        published: [Option<Published>; 2],
        generations: [Generation; 2],
        last: Option<Snapshot>,
        seen_phases: u8,
    }

    impl PeerSelection {
        pub(super) fn start() -> PeerSelection {
            let base = anchor();
            let cfg = config();
            let cache = Cache::for_config(&cfg).expect("a cache sized to the allowlist");
            let clock = WorkerClock::new(base, DNS_EPOCH);
            let mut worker = Worker::boot(clock);
            let allowed_request = auth_request("sub.example.org");
            let forbidden_request = auth_request("evil.example.net");
            {
                let view = view_of_clocked(&cfg, &cache, clock);
                assert_eq!(
                    view.resolve(&allowed_request).ordinal(),
                    Some(0),
                    "the drawn allowlisted request owns ordinal 0"
                );
                assert_eq!(
                    view.resolve(&forbidden_request).ordinal(),
                    None,
                    "the drawn forbidden request owns no allowlist ordinal"
                );
            }
            for addrs in [a_pool(), aaaa_pool()] {
                for addr in addrs {
                    assert!(
                        addr.is_eligible(),
                        "the drawn address pool must hold only eligible destinations"
                    );
                }
            }
            let slot = worker.admit(base, peer(0)).expect("a free setup seat");
            PeerSelection {
                cfg,
                cache,
                worker,
                clock,
                base,
                now: base,
                allowed_request,
                forbidden_request,
                slot: Some(slot),
                setup_limit: model_setup_limit(base),
                attempts: AttemptCounts::new(),
                previous: None,
                published: [None, None],
                generations: [Generation::INITIAL; 2],
                last: None,
                seen_phases: 0,
            }
        }

        fn name(&self) -> NameIndex {
            self.cache.name_index(0).expect("ordinal 0 is admitted")
        }

        fn cache_now_at(&self, now: Instant) -> u64 {
            DNS_EPOCH.saturating_add(now.saturating_duration_since(self.base).as_secs())
        }

        fn cache_now(&self) -> u64 {
            self.cache_now_at(self.now)
        }

        /// Admits the fresh setup the model will decide from, drawing its
        /// setup instant forward from the current clock, and resets the model's
        /// attempt ledger to the fresh slot's empty one.
        fn readmit(&mut self, tc: &TestCase) {
            let delta = tc.draw(gs::integers::<u64>().min_value(0).max_value(5));
            self.now = later(self.now, delta);
            let slot = self
                .worker
                .admit(self.now, peer(0))
                .expect("a free setup seat");
            self.setup_limit = model_setup_limit(self.now);
            self.attempts = AttemptCounts::new();
            self.previous = None;
            self.slot = Some(slot);
        }

        fn decide_probe(&self, index: usize) -> Result<ConnectPhase, DecideError> {
            let view = view_of_clocked(&self.cfg, &self.cache, self.clock);
            let resolved = view.resolve(&self.allowed_request);
            self.worker.decide(&probe(index), &resolved, self.now)
        }

        /// Publishes a drawn eligible distinct binding set for one family,
        /// advances the model's generation, and records the publication. The
        /// identity assertion makes "the model published" and "the cache holds"
        /// the same set, so the invariants need not read the cache.
        fn publish_drawn(
            &mut self,
            family: Family,
            addrs: Vec<NumericAddr>,
            receipt: u64,
            ttl: u64,
        ) {
            let family_index = fam_index(family);
            let generation = self.generations[family_index];
            let staged =
                StagedPositive::stage(self.name(), family, generation, &addrs, receipt, ttl)
                    .expect("a drawn eligible distinct set stages");
            self.cache
                .publish_positive(&staged)
                .expect("the drawn generation publishes");
            let next = generation.checked_next().expect("generation has room");
            self.generations[family_index] = next;
            let entry = self
                .cache
                .entry(self.name(), family)
                .expect("admitted entry");
            assert_eq!(
                entry.bindings(),
                &addrs[..],
                "publication must be the identity on the drawn eligible distinct set"
            );
            assert_eq!(
                entry.generation(),
                next,
                "publication must advance the family generation by one"
            );
            self.published[family_index] = Some(Published {
                addrs,
                generation: next,
                fresh_deadline: receipt + ttl,
                retirement_deadline: receipt + ttl + STALE_GRACE,
            });
        }
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "the hegel state-machine macro hands each rule its own TestCase by value"
    )]
    #[hegel::state_machine]
    impl PeerSelection {
        #[rule(weight = 14.0)]
        fn decide(&mut self, tc: TestCase) {
            let Some(slot) = self.slot.as_ref() else {
                return;
            };
            let allowlisted = tc.draw(gs::booleans());
            let (request, ordinal) = if allowlisted {
                (&self.allowed_request, Some(0usize))
            } else {
                (&self.forbidden_request, None)
            };
            let view = view_of_clocked(&self.cfg, &self.cache, self.clock);
            let resolved = view.resolve(request);
            assert_eq!(
                resolved.ordinal(),
                ordinal,
                "the model's drawn allowlist ordinal must match the resolution"
            );
            let published = self.published.clone();
            let cache_generations = [
                self.cache
                    .entry(self.name(), Family::A)
                    .expect("admitted entry")
                    .generation(),
                self.cache
                    .entry(self.name(), Family::Aaaa)
                    .expect("admitted entry")
                    .generation(),
            ];
            let phase = self
                .worker
                .decide(slot, &resolved, self.now)
                .expect("a live setup decides");
            let (bit, label) = match phase {
                ConnectPhase::Forbidden => (0b000_001u8, "decide_forbidden"),
                ConnectPhase::NoBinding => (0b000_010u8, "decide_no_binding"),
                ConnectPhase::DeadlineExhausted => (0b000_100u8, "decide_deadline_exhausted"),
                ConnectPhase::CandidatesExhausted => (0b001_000u8, "decide_candidates_exhausted"),
                ConnectPhase::Peer {
                    family: Family::A, ..
                } => (0b010_000u8, "decide_peer_ipv4"),
                ConnectPhase::Peer {
                    family: Family::Aaaa,
                    ..
                } => (0b100_000u8, "decide_peer_ipv6"),
            };
            if self.seen_phases & bit == 0 {
                self.seen_phases |= bit;
                tc.event(label);
            }
            self.last = Some(Snapshot {
                ordinal,
                phase,
                now: self.now,
                cache_now: self.cache_now(),
                setup_limit: self.setup_limit,
                counts: self.attempts,
                previous: self.previous,
                published,
                cache_generations,
            });
        }

        #[rule(weight = 9.0)]
        fn record_attempt(&mut self, tc: TestCase) {
            let Some(slot) = self.slot.as_ref() else {
                return;
            };
            let family = draw_family(&tc);
            let ledger = self
                .worker
                .record_attempt(slot, family)
                .expect("a live setup records an attempt");
            self.attempts = self.attempts.record(family);
            self.previous = Some(family);
            assert_eq!(
                ledger.counts(),
                self.attempts,
                "the subject ledger must agree with the model's recorded attempts"
            );
            assert_eq!(
                ledger.previous(),
                self.previous,
                "the subject ledger must remember the model's previous family"
            );
            tc.event("rule_record_attempt");
        }

        #[rule(weight = 6.0)]
        fn advance_clock(&mut self, tc: TestCase) {
            let delta = tc.draw(gs::sampled_from(&CLOCK_STEPS[..]));
            self.now = later(self.now, delta);
            tc.event("rule_advance_clock");
        }

        #[rule(weight = 6.0)]
        fn publish_bindings(&mut self, tc: TestCase) {
            let family = draw_family(&tc);
            let mask = tc.draw(gs::integers::<u8>().min_value(0).max_value(7));
            let addrs: Vec<NumericAddr> = pool(family)
                .iter()
                .enumerate()
                .filter(|(bit, _)| mask & (1u8 << *bit) != 0)
                .map(|(_, addr)| *addr)
                .collect();
            let ttl = tc.draw(gs::integers::<u64>().min_value(1).max_value(64));
            let state_choice = tc.draw(gs::integers::<u8>().min_value(0).max_value(4));
            let age = match state_choice {
                0 => 0,
                1 => ttl - 1,
                2 => ttl + 1,
                3 => ttl + STALE_SERVING_WINDOW,
                _ => ttl + STALE_GRACE,
            };
            let receipt = self.cache_now().saturating_sub(age);
            self.publish_drawn(family, addrs, receipt, ttl);
            tc.event("rule_publish_bindings");
        }

        /// Publishes a fresh, non-empty binding set to both families in one
        /// rule, so the both-families-usable alternation state is reached many
        /// times per case rather than depending on the draw order of two
        /// single-family publications.
        #[rule(weight = 6.0)]
        fn publish_both_bindings(&mut self, tc: TestCase) {
            for family in [Family::A, Family::Aaaa] {
                let count = tc.draw(gs::integers::<u8>().min_value(1).max_value(3));
                let addrs: Vec<NumericAddr> = pool(family)
                    .iter()
                    .take(usize::from(count))
                    .copied()
                    .collect();
                let ttl = tc.draw(gs::integers::<u64>().min_value(1).max_value(64));
                let receipt = self.cache_now();
                self.publish_drawn(family, addrs, receipt, ttl);
            }
            tc.event("rule_publish_both");
        }

        #[rule(weight = 3.0)]
        fn evict(&mut self, tc: TestCase) {
            if tc.draw(gs::booleans()) {
                self.cache
                    .evict_nxdomain(self.name())
                    .expect("an admitted name evicts");
                self.generations[0] = self.generations[0]
                    .checked_next()
                    .expect("generation has room");
                self.generations[1] = self.generations[1]
                    .checked_next()
                    .expect("generation has room");
                self.published[0] = None;
                self.published[1] = None;
                tc.event("rule_evict_name");
            } else {
                let family = draw_family(&tc);
                let family_index = fam_index(family);
                self.cache
                    .evict_nodata(self.name(), family)
                    .expect("an admitted family evicts");
                self.generations[family_index] = self.generations[family_index]
                    .checked_next()
                    .expect("generation has room");
                self.published[family_index] = None;
                tc.event("rule_evict_family");
            }
        }

        #[rule(weight = 2.0)]
        fn release_and_readmit(&mut self, tc: TestCase) {
            let Some(slot) = self.slot.take() else {
                return;
            };
            let index = SlotIndex::index(&slot);
            self.worker.release(slot);
            assert!(
                self.worker.attempt_ledger(&probe(index)).is_none(),
                "a released setup exposes no attempt ledger"
            );
            assert_eq!(
                self.decide_probe(index),
                Err(DecideError::NotInSetup),
                "a released handle must not decide"
            );
            self.readmit(&tc);
            tc.event("rule_release_setup");
        }

        #[rule(weight = 2.0)]
        fn graduate_and_readmit(&mut self, tc: TestCase) {
            let Some(slot) = self.slot.take() else {
                return;
            };
            let index = SlotIndex::index(&slot);
            let tunnel = self.worker.finish_setup(slot);
            assert_eq!(
                TunnelIndex::index(&tunnel),
                index,
                "graduation keeps the physical slot"
            );
            assert!(
                self.worker.attempt_ledger(&probe(index)).is_none(),
                "an established tunnel exposes no setup ledger"
            );
            assert_eq!(
                self.decide_probe(index),
                Err(DecideError::NotInSetup),
                "an established handle must not decide"
            );
            self.worker.release_tunnel(tunnel);
            self.readmit(&tc);
            tc.event("rule_graduate_setup");
        }

        #[invariant(always_run)]
        fn p1_forbidden_iff_no_ordinal(&self, _: TestCase) {
            let Some(snapshot) = &self.last else {
                return;
            };
            assert_eq!(
                snapshot.phase == ConnectPhase::Forbidden,
                snapshot.ordinal.is_none(),
                "P1: Forbidden must hold exactly when the resolved allowlist ordinal is absent"
            );
        }

        #[invariant(always_run)]
        fn p2_deadline_exhausted_iff_setup_expired(&self, _: TestCase) {
            let Some(snapshot) = &self.last else {
                return;
            };
            if snapshot.ordinal.is_none() {
                return;
            }
            assert_eq!(
                snapshot.phase == ConnectPhase::DeadlineExhausted,
                snapshot.now >= snapshot.setup_limit,
                "P2: DeadlineExhausted must hold exactly when now has reached the model's setup deadline"
            );
        }

        #[invariant(always_run)]
        fn p3_candidates_exhausted_iff_budget_spent(&self, _: TestCase) {
            let Some(snapshot) = &self.last else {
                return;
            };
            if snapshot.ordinal.is_none() {
                return;
            }
            let budget_spent = usize::from(snapshot.counts.total()) >= MAX_UPSTREAM_ATTEMPTS;
            assert_eq!(
                snapshot.phase == ConnectPhase::CandidatesExhausted,
                snapshot.now < snapshot.setup_limit && budget_spent,
                "P3: CandidatesExhausted must hold exactly when the model's attempt total reached the fixed budget before the setup deadline"
            );
        }

        #[invariant(always_run)]
        fn p4_peer_is_the_published_binding_at_the_family_cursor(&self, _: TestCase) {
            let Some(snapshot) = &self.last else {
                return;
            };
            let ConnectPhase::Peer { addr, family, .. } = snapshot.phase else {
                return;
            };
            assert!(
                snapshot.ordinal.is_some(),
                "P4: a Peer must never follow an unauthorized request"
            );
            assert!(
                addr.is_eligible(),
                "P4: a selected peer must be an eligible destination"
            );
            let published = snapshot
                .live_generation(family)
                .expect("a Peer requires a published family record");
            let cursor = count_in(snapshot.counts, family);
            assert_eq!(
                published.addrs.get(usize::from(cursor)).copied(),
                Some(addr),
                "P4: the Peer must be the binding published at index {cursor} of {family:?}, the model's earlier attempt count"
            );
            assert!(
                published.servable(snapshot.cache_now),
                "P4: a selected peer must come from a non-retired, servable publication"
            );
            assert_eq!(
                snapshot.cache_generations[fam_index(family)],
                published.generation,
                "P4: the model's published record must be the family's current generation"
            );
        }

        #[invariant(always_run)]
        fn p5_alternates_only_while_the_other_family_remains(&self, _: TestCase) {
            let Some(snapshot) = &self.last else {
                return;
            };
            let ConnectPhase::Peer { family, .. } = snapshot.phase else {
                return;
            };
            if snapshot.ordinal.is_none() {
                return;
            }
            let Some(previous) = snapshot.previous else {
                return;
            };
            let other = match previous {
                Family::A => Family::Aaaa,
                Family::Aaaa => Family::A,
            };
            if snapshot.candidate(other).is_some() {
                assert_eq!(
                    family, other,
                    "P5: after an attempt in {previous:?}, the next Peer must use the other family while it has a usable binding"
                );
            } else {
                assert_eq!(
                    family, previous,
                    "P5: after an attempt in {previous:?} with no usable {other:?} binding, the next Peer must stay in {previous:?}"
                );
            }
        }

        #[invariant(always_run)]
        fn p6_no_binding_iff_no_usable_cursor(&self, _: TestCase) {
            let Some(snapshot) = &self.last else {
                return;
            };
            if snapshot.ordinal.is_none() {
                return;
            }
            let cursor_blocked = snapshot.now < snapshot.setup_limit
                && usize::from(snapshot.counts.total()) < MAX_UPSTREAM_ATTEMPTS
                && snapshot.candidate(Family::A).is_none()
                && snapshot.candidate(Family::Aaaa).is_none();
            assert_eq!(
                snapshot.phase == ConnectPhase::NoBinding,
                cursor_blocked,
                "P6: NoBinding must hold exactly when neither family has a usable published binding at its attempt cursor"
            );
        }

        #[invariant(always_run)]
        fn p7_connect_deadline_is_clipped(&self, _: TestCase) {
            let Some(snapshot) = &self.last else {
                return;
            };
            let ConnectPhase::Peer {
                connect_deadline, ..
            } = snapshot.phase
            else {
                return;
            };
            if snapshot.ordinal.is_none() {
                return;
            }
            let expected = model_connect_limit(snapshot.now, snapshot.setup_limit);
            assert_eq!(
                connect_deadline.limit(),
                expected,
                "P7: the connect deadline must be now + 2 s clipped to the model's setup deadline"
            );
            assert!(
                connect_deadline.limit() <= snapshot.setup_limit,
                "P7: the connect deadline must never outlive the setup deadline"
            );
        }
    }
}

/// The CONNECT authorization and peer-selection decision as a state machine
/// over drawn cache states and drawn attempt sequences: model-based coverage of
/// the selection invariants the scripted examples pin one scenario at a time,
/// driving the same production [`Worker`] those examples drive. Its invariant
/// list and independence arguments are on [`peer_selection_machine`];
/// `hegel.toml` owns the case count.
#[hegel::test(derandomize = true)]
fn worker_connect_peer_selection_holds_its_invariants(tc: hegel::TestCase) {
    hegel::stateful::machine(peer_selection_machine::PeerSelection::start())
        .steps(120)
        .run(tc);
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

/// The multi-client admission surface as a concurrent model-based machine.
///
/// The subject is the production [`Worker`] slot table. One [`Mutex`] guards
/// the subject and the model's handle/peer accounting together, so every
/// invariant reads exactly one consistent snapshot; all rules share the single
/// `ops` group, so worker threads really interleave them on that lock. The
/// model keeps only the handles the subject handed out, never a second scan of
/// the subject's slot array.
///
/// Invariants (each `#[invariant(always_run)]`, evaluated on the main thread
/// between rounds after every worker has joined):
/// - CH1 `occupied() <= MAX_TUNNELS`, `pending() <= MAX_PENDING_SETUPS`, and
///   each peer's pending setups `<= MAX_PENDING_PER_PEER`.
/// - CH2 `occupied()` equals the model's live-handle count and `pending()`
///   equals its setup-handle count.
/// - CH3 live slot indices are pairwise distinct and inside `0..MAX_TUNNELS`.
/// - CH4 an admitted index was not live when it was handed out, so an index is
///   only ever reused after its release.
///
/// Independence: CH2 is a cross-check of the subject's cached counters against
/// the model's handle list, not a restatement of a slot-array scan; CH3 is a
/// set property over those handles; CH4 is evidence recorded at admit time from
/// the live set observed under the same lock as the admit, so it is not implied
/// by the snapshot CH3 reads. The per-peer cap is checked from the model's own
/// peer record because the subject exposes no per-peer counter, and CH1 is its
/// single owner: the admit rule licenses a `PendingCapacity` refusal exactly
/// when the canonical peer already holds its cap, so a subject that admits one
/// further seat there is caught by CH1 counting the seat the model recorded.
///
/// Peer canonicalisation: the drawn spellings include an IPv4-mapped IPv6 form
/// of a peer already in the pool, and the model records the canonical peer on
/// every setup it admits ([`IpAddr::to_canonical`] maps the mapped form to that
/// peer's IPv4 address), so the per-peer count is keyed by the peer the kernel
/// accepted, never by the spelling drawn. Dropping the `to_canonical` call in
/// [`Worker::admit`] splits one peer into two budgets: the subject admits a
/// seat the model counts against a peer already at [`MAX_PENDING_PER_PEER`],
/// and CH1 fails on the per-peer cap.
///
/// Documented non-claims (covered elsewhere, never by this machine): a refused
/// client's bytes never reach an upstream (the byte-pinned 400/403/502 reactor
/// tests); shutdown observed by every live tunnel (the owner/runtime
/// alloc-witness turns and the e2e shutdown gate); no peer buffer is reused
/// while live (the buffer is boot-transferred and cursor-managed, and only the
/// stale-generation token hazard is covered by the reactor coalescer machine).
mod concurrent_admission_machine {
    use super::*;
    use hegel::TestCase;
    use hegel::generators as gs;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    /// The drawn peer spellings, each with the canonical peer it stands for.
    /// The first two are one peer under two spellings — `127.0.0.1` and its
    /// IPv4-mapped IPv6 form, which [`IpAddr::to_canonical`] maps to the same
    /// address — so the per-peer cap must count them once. Five canonical peers
    /// keep the per-peer cap (32) and the global pending cap (128)
    /// independently reachable, so neither cap check can hide behind the other.
    const PEERS: [(IpAddr, usize); 6] = [
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

    /// The distinct canonical peers the spellings above collapse to.
    const CANONICAL_PEERS: usize = 5;

    /// The handles the subject handed out, in no particular order. Each variant
    /// carries the live handle of its class, so a rule can only apply the
    /// transition that handle type permits. A setup also carries the canonical
    /// peer it was admitted for, so the per-peer count never splits one peer by
    /// the spelling the rule drew.
    enum Live {
        Setup { slot: SlotIndex, peer: usize },
        Established(TunnelIndex),
    }

    impl Live {
        const fn index(&self) -> usize {
            match self {
                Live::Setup { slot, .. } => SlotIndex::index(slot),
                Live::Established(tunnel) => TunnelIndex::index(tunnel),
            }
        }

        const fn is_setup(&self) -> bool {
            matches!(self, Live::Setup { .. })
        }
    }

    /// One admit's reuse evidence: whether the index the subject returned was
    /// already live when it was handed out.
    struct ReuseEvidence {
        index: usize,
        was_live: bool,
    }

    struct Inner {
        worker: Worker,
        live: Vec<Live>,
        reuses: Vec<ReuseEvidence>,
    }

    impl Inner {
        /// The position of the `wanted`-th live handle of the drawn class; the
        /// pick is a fixed-range draw taken before the lock, so no draw depends
        /// on lock state.
        fn position(&self, pick: usize, setup: bool) -> Option<usize> {
            let candidates = self
                .live
                .iter()
                .filter(|live| live.is_setup() == setup)
                .count();
            if candidates == 0 {
                return None;
            }
            let wanted = pick % candidates;
            let mut seen = 0;
            for (position, live) in self.live.iter().enumerate() {
                if live.is_setup() == setup {
                    if seen == wanted {
                        return Some(position);
                    }
                    seen += 1;
                }
            }
            None
        }
    }

    fn peer_pending(live: &[Live], peer: usize) -> usize {
        live.iter()
            .filter(|live| matches!(live, Live::Setup { peer: p, .. } if *p == peer))
            .count()
    }

    fn guard(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
        inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) struct Admission {
        inner: Mutex<Inner>,
        now: Instant,
    }

    impl Admission {
        pub(super) fn start() -> Admission {
            let now = anchor();
            Admission {
                inner: Mutex::new(Inner {
                    worker: Worker::boot(clock(now)),
                    live: Vec::new(),
                    reuses: Vec::new(),
                }),
                now,
            }
        }
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "the hegel concurrent state-machine macro hands each rule its own TestCase by value"
    )]
    #[hegel::concurrent_state_machine]
    impl Admission {
        /// Admits a drawn peer. The capacity prediction and the admit call
        /// share one guard, so the refusal reason is compared against the exact
        /// state the subject decided on, never a stale pre-lock snapshot.
        #[rule(groups = ["ops"], weight = 12.0)]
        /// Admits a drawn peer spelling. The capacity prediction and the admit
        /// call share one guard, so the refusal reason is compared against the
        /// exact state the subject decided on, never a stale pre-lock snapshot.
        /// The predicted refusal covers the full table and the global pending
        /// budget; the per-peer budget is licensed here (a refusal is only
        /// allowed when the canonical peer holds its cap) and capped by CH1.
        #[rule(groups = ["ops"], weight = 12.0)]
        fn admit(&self, tc: TestCase) {
            let (peer, canonical) = tc.draw(gs::sampled_from(&PEERS[..]));
            let mut inner = guard(&self.inner);
            let per_peer = peer_pending(&inner.live, canonical);
            let gated_by_peer = per_peer >= MAX_PENDING_PER_PEER;
            let expected = if inner.worker.occupied() >= MAX_TUNNELS {
                Err(AdmissionError::SlotCapacity)
            } else if inner.worker.pending() >= MAX_PENDING_SETUPS {
                Err(AdmissionError::PendingCapacity)
            } else {
                Ok(())
            };
            match (expected, inner.worker.admit(self.now, peer)) {
                (Ok(()), Ok(slot)) => {
                    tc.event("admitted");
                    let index = SlotIndex::index(&slot);
                    let occupied = inner.live.len() + 1;
                    if occupied >= MAX_TUNNELS / 2 {
                        tc.event("occupied_at_least_256");
                    }
                    if occupied >= MAX_TUNNELS {
                        tc.event("occupied_at_slot_capacity");
                    }
                    let was_live = inner.live.iter().any(|live| live.index() == index);
                    inner.reuses.push(ReuseEvidence { index, was_live });
                    inner.live.push(Live::Setup {
                        slot,
                        peer: canonical,
                    });
                }
                (Ok(()), Err(AdmissionError::PendingCapacity)) if gated_by_peer => {
                    tc.event("refusal_per_peer_capacity");
                }
                (Ok(()), Err(actual)) => {
                    panic!("the model predicted a free seat, the worker refused: {actual:?}");
                }
                (Err(predicted), Ok(slot)) => {
                    panic!(
                        "the model predicted {predicted:?}, the worker admitted slot {}",
                        SlotIndex::index(&slot)
                    );
                }
                (Err(predicted), Err(actual)) => {
                    tc.event(match predicted {
                        AdmissionError::SlotCapacity => "refusal_slot_capacity",
                        AdmissionError::PendingCapacity => "refusal_pending_capacity",
                    });
                    assert_eq!(
                        actual, predicted,
                        "the worker's refusal reason disagrees with the model's capacity state"
                    );
                }
            }
        }

        /// Records one drawn family on a live setup.
        #[rule(groups = ["ops"], weight = 1.0)]
        fn record_attempt(&self, tc: TestCase) {
            let family = tc.draw(gs::sampled_from(&[Family::A, Family::Aaaa][..]));
            let pick = tc.draw(
                gs::integers::<usize>()
                    .min_value(0)
                    .max_value(MAX_TUNNELS - 1),
            );
            let mut inner = guard(&self.inner);
            let Some(position) = inner.position(pick, true) else {
                return;
            };
            let Inner { worker, live, .. } = &mut *inner;
            let Live::Setup { slot, .. } = &live[position] else {
                panic!("the model picked a non-setup handle for an attempt record");
            };
            let after = worker
                .record_attempt(slot, family)
                .expect("a live setup records an attempt");
            assert_eq!(
                after.previous(),
                Some(family),
                "the recorded attempt is the ledger's previous family"
            );
        }

        /// Graduates a live setup: the seat stays occupied, one pending seat is
        /// freed, and the physical slot is unchanged.
        #[rule(groups = ["ops"], weight = 8.0)]
        fn finish_setup(&self, tc: TestCase) {
            let pick = tc.draw(
                gs::integers::<usize>()
                    .min_value(0)
                    .max_value(MAX_TUNNELS - 1),
            );
            let mut inner = guard(&self.inner);
            let Some(position) = inner.position(pick, true) else {
                return;
            };
            let occupied_before = inner.worker.occupied();
            let pending_before = inner.worker.pending();
            let Live::Setup { slot, .. } = inner.live.swap_remove(position) else {
                panic!("the model picked a non-setup handle for graduation");
            };
            let index = SlotIndex::index(&slot);
            let tunnel = inner.worker.finish_setup(slot);
            tc.event("graduated_seat");
            assert_eq!(
                TunnelIndex::index(&tunnel),
                index,
                "graduating an admitted seat keeps its physical slot"
            );
            assert_eq!(
                inner.worker.occupied(),
                occupied_before,
                "graduation keeps the seat occupied"
            );
            assert_eq!(
                inner.worker.pending(),
                pending_before - 1,
                "graduation frees exactly one pending seat"
            );
            inner.live.push(Live::Established(tunnel));
        }

        /// Releases a live setup, freeing one occupied and one pending seat.
        #[rule(groups = ["ops"], weight = 2.0)]
        fn release(&self, tc: TestCase) {
            let pick = tc.draw(
                gs::integers::<usize>()
                    .min_value(0)
                    .max_value(MAX_TUNNELS - 1),
            );
            let mut inner = guard(&self.inner);
            let Some(position) = inner.position(pick, true) else {
                return;
            };
            let occupied_before = inner.worker.occupied();
            let pending_before = inner.worker.pending();
            let Live::Setup { slot, .. } = inner.live.swap_remove(position) else {
                panic!("the model picked a non-setup handle for release");
            };
            let index = SlotIndex::index(&slot);
            inner.worker.release(slot);
            tc.event("released_setup");
            assert_eq!(
                inner.worker.occupied(),
                occupied_before - 1,
                "release frees the occupied seat"
            );
            assert_eq!(
                inner.worker.pending(),
                pending_before - 1,
                "release frees the pending seat"
            );
            assert!(
                matches!(inner.worker.slots[index], SlotState::Free),
                "a released slot must be free in the table"
            );
        }

        /// Releases a live established tunnel: one occupied seat is freed and
        /// the pending count is untouched.
        #[rule(groups = ["ops"], weight = 2.0)]
        fn release_tunnel(&self, tc: TestCase) {
            let pick = tc.draw(
                gs::integers::<usize>()
                    .min_value(0)
                    .max_value(MAX_TUNNELS - 1),
            );
            let mut inner = guard(&self.inner);
            let Some(position) = inner.position(pick, false) else {
                return;
            };
            let occupied_before = inner.worker.occupied();
            let pending_before = inner.worker.pending();
            let Live::Established(tunnel) = inner.live.swap_remove(position) else {
                panic!("the model picked a non-established handle for release");
            };
            let index = TunnelIndex::index(&tunnel);
            inner.worker.release_tunnel(tunnel);
            tc.event("released_tunnel");
            assert_eq!(
                inner.worker.occupied(),
                occupied_before - 1,
                "releasing an established tunnel frees its occupied seat"
            );
            assert_eq!(
                inner.worker.pending(),
                pending_before,
                "releasing an established tunnel leaves the pending count alone"
            );
            assert!(
                matches!(inner.worker.slots[index], SlotState::Free),
                "a released slot must be free in the table"
            );
        }

        #[invariant(always_run)]
        fn ch1_fixed_caps_hold(&self, _: TestCase) {
            let inner = guard(&self.inner);
            let occupied = inner.worker.occupied();
            let pending = inner.worker.pending();
            assert!(
                occupied <= MAX_TUNNELS,
                "occupied {occupied} exceeds the fixed slot budget"
            );
            assert!(
                pending <= MAX_PENDING_SETUPS,
                "pending {pending} exceeds the fixed pending budget"
            );
            for peer in 0..CANONICAL_PEERS {
                let held = peer_pending(&inner.live, peer);
                assert!(
                    held <= MAX_PENDING_PER_PEER,
                    "peer {peer} holds {held} pending setups, above the per-peer cap"
                );
            }
        }

        #[invariant(always_run)]
        fn ch2_counters_match_the_model_handles(&self, _: TestCase) {
            let inner = guard(&self.inner);
            let setups = inner.live.iter().filter(|live| live.is_setup()).count();
            assert_eq!(
                inner.worker.occupied(),
                inner.live.len(),
                "the occupied counter disagrees with the model's live handles"
            );
            assert_eq!(
                inner.worker.pending(),
                setups,
                "the pending counter disagrees with the model's setup handles"
            );
        }

        #[invariant(always_run)]
        fn ch3_live_indices_are_distinct_and_in_range(&self, _: TestCase) {
            let inner = guard(&self.inner);
            let mut seen = [false; MAX_TUNNELS];
            for live in &inner.live {
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
        fn ch4_admit_never_hands_out_a_live_index(&self, _: TestCase) {
            let inner = guard(&self.inner);
            for reuse in &inner.reuses {
                assert!(
                    !reuse.was_live,
                    "CH4: admit handed out slot {} while it was already live",
                    reuse.index
                );
            }
        }
    }
}

/// The multi-client admission surface as a concurrent state machine: model-based
/// coverage of the fixed capacity caps, handle/peer accounting and index
/// ownership under real thread interleaving on one lock, driving the same
/// production [`Worker`] the scripted tests above drive. Its invariant list,
/// independence argument and documented non-claims are on
/// [`concurrent_admission_machine`]; `hegel.toml` owns the case count.
#[hegel::test(derandomize = true)]
fn worker_concurrent_admission_keeps_capacity_and_ownership(tc: hegel::TestCase) {
    hegel::stateful::machine(concurrent_admission_machine::Admission::start())
        .steps(250)
        .min_concurrency(2)
        .max_concurrency(4)
        .run_concurrent(tc);
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

use super::*;
use crate::cache::{Generation, StagedPositive};
use crate::eligibility::NumericAddr;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

const FRESH: u64 = 1000;
const TTL: u64 = 10;
const RETIREMENT: u64 = FRESH + TTL + crate::cache::STALE_GRACE;

fn idx(cache: &Cache, ordinal: usize) -> NameIndex {
    cache.name_index(ordinal).expect("admitted name ordinal")
}

fn v4(octets: [u8; 4]) -> NumericAddr {
    NumericAddr::V4(Ipv4Addr::from(octets))
}

fn v6(octets: [u8; 16]) -> NumericAddr {
    NumericAddr::V6(Ipv6Addr::from(octets))
}

fn config_with_allowance(count: usize, allowance: u8) -> Config {
    let names = match count {
        1 => vec!["alpha.example.org:443"],
        2 => vec!["alpha.example.org:443", "beta.example.org:443"],
        3 => vec![
            "alpha.example.org:443",
            "beta.example.org:443",
            "gamma.example.org:443",
        ],
        _ => panic!("test allowlist helper supports 1..=3 names"),
    };
    let mut doc = format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = {allowance}\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n"
    );
    for name in names {
        let _ = write!(
            doc,
            "[allowed_fqdn.\"{name}\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
        );
    }
    crate::config::parse_config_document(&doc).expect("valid test config")
}

fn booted(count: usize, allowance: u8) -> ServeStorage {
    ServeStorage::boot(&config_with_allowance(count, allowance)).expect("boot serving storage")
}

fn with_boot_stack(body: impl FnOnce() + Send + 'static) {
    let t = std::thread::Builder::new()
        .name("boot-test".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(body)
        .expect("spawn boot thread");
    t.join().expect("boot thread");
}

fn publish_a(cache: &mut Cache, ordinal: usize, receipt: u64, ttl: u64) {
    let name = cache.name_index(ordinal).expect("admitted name ordinal");
    let addrs = [v4([1, 1, 1, 1])];
    let staged = StagedPositive::stage(name, Family::A, Generation::INITIAL, &addrs, receipt, ttl)
        .expect("stage A binding");
    cache.publish_positive(&staged).expect("publish A binding");
}

fn publish_aaaa(cache: &mut Cache, ordinal: usize, receipt: u64, ttl: u64) {
    let name = cache.name_index(ordinal).expect("admitted name ordinal");
    let addrs = [v6([
        0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
        0x11,
    ])];
    let staged = StagedPositive::stage(
        name,
        Family::Aaaa,
        Generation::INITIAL,
        &addrs,
        receipt,
        ttl,
    )
    .expect("stage AAAA binding");
    cache
        .publish_positive(&staged)
        .expect("publish AAAA binding");
}

#[test]
fn empty_cache_names_are_unresolved() {
    let cache = Cache::new(1).unwrap();
    assert_eq!(usable_name(&cache, idx(&cache, 0), 0), Ok(false));
}

#[test]
fn fresh_positive_binding_makes_name_usable() {
    let mut cache = Cache::new(1).unwrap();
    publish_a(&mut cache, 0, FRESH, TTL);
    assert_eq!(usable_name(&cache, idx(&cache, 0), FRESH), Ok(true));
}

#[test]
fn stale_positive_binding_remains_usable() {
    let mut cache = Cache::new(1).unwrap();
    publish_a(&mut cache, 0, FRESH, TTL);
    let stale = FRESH + TTL + 1;
    assert!(stale < RETIREMENT);
    assert_eq!(usable_name(&cache, idx(&cache, 0), stale), Ok(true));
}

#[test]
fn retired_binding_is_unresolved() {
    let mut cache = Cache::new(1).unwrap();
    publish_a(&mut cache, 0, FRESH, TTL);
    assert_eq!(usable_name(&cache, idx(&cache, 0), RETIREMENT), Ok(false));
}

#[test]
fn drain_dns_anomalies_accumulates_into_the_enforcement_monitor() {
    let mut storage = booted(1, 0);
    storage
        .dns
        .note_dns_anomaly(DnsAnomalyKind::BailiwickViolation);
    storage
        .dns
        .note_dns_anomaly(DnsAnomalyKind::BailiwickViolation);
    storage
        .dns
        .note_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch);
    storage.dns.note_dns_anomaly(DnsAnomalyKind::ExtremeTtl);
    storage.drain_dns_anomalies();
    assert_eq!(
        storage
            .enforcement
            .monitor()
            .facts_dns_anomaly(DnsAnomalyKind::BailiwickViolation),
        2
    );
    assert_eq!(
        storage
            .enforcement
            .monitor()
            .facts_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch),
        1
    );
    assert_eq!(
        storage
            .enforcement
            .monitor()
            .facts_dns_anomaly(DnsAnomalyKind::ExtremeTtl),
        1
    );
    storage.drain_dns_anomalies();
    assert_eq!(
        storage
            .enforcement
            .monitor()
            .facts_dns_anomaly(DnsAnomalyKind::BailiwickViolation),
        2,
        "a second drain must not double-count a drained anomaly"
    );
}

#[test]
fn either_family_positive_makes_name_usable() {
    let mut cache = Cache::new(1).unwrap();
    publish_aaaa(&mut cache, 0, FRESH, TTL);
    assert_eq!(usable_name(&cache, idx(&cache, 0), FRESH + 5), Ok(true));
}

#[test]
fn nxdomain_eviction_makes_name_unresolved() {
    let mut cache = Cache::new(1).unwrap();
    publish_a(&mut cache, 0, FRESH, TTL);
    cache.evict_nxdomain(idx(&cache, 0)).unwrap();
    assert_eq!(usable_name(&cache, idx(&cache, 0), FRESH + 5), Ok(false));
}

#[test]
fn all_names_usable_decides_full_serve() {
    let mut storage = booted(2, 0);
    publish_a(&mut storage.cache, 0, FRESH, TTL);
    publish_a(&mut storage.cache, 1, FRESH, TTL);
    assert_eq!(
        storage.startup_decision(FRESH + 5),
        Ok(StartupDecision::Serve(ServingMode::Full))
    );
}

#[test]
fn unresolved_within_allowance_serves_degraded() {
    let mut storage = booted(2, 1);
    publish_a(&mut storage.cache, 0, FRESH, TTL);
    let decision = storage.startup_decision(FRESH + 5).unwrap();
    assert_eq!(decision, StartupDecision::Serve(ServingMode::Degraded));
}

#[test]
fn allowance_zero_requires_every_name_usable() {
    let mut storage = booted(2, 0);
    publish_a(&mut storage.cache, 0, FRESH, TTL);
    let decision = storage.startup_decision(FRESH + 5).unwrap();
    assert_eq!(decision, StartupDecision::Exit75 { unresolved: 1 });
}

#[test]
fn trailing_unresolved_name_counts_against_allowance() {
    with_boot_stack(|| {
        let mut strict = booted(2, 0);
        publish_a(&mut strict.cache, 0, FRESH, TTL);
        let decision = strict.startup_decision(FRESH + 5).unwrap();
        assert_eq!(decision, StartupDecision::Exit75 { unresolved: 1 });
        let mut tolerant = booted(2, 1);
        publish_a(&mut tolerant.cache, 0, FRESH, TTL);
        let decision = tolerant.startup_decision(FRESH + 5).unwrap();
        assert_eq!(decision, StartupDecision::Serve(ServingMode::Degraded));
    });
}

#[test]
fn trailing_last_name_unresolved_is_counted() {
    with_boot_stack(|| {
        let mut strict = booted(3, 0);
        publish_a(&mut strict.cache, 0, FRESH, TTL);
        publish_a(&mut strict.cache, 1, FRESH, TTL);
        let decision = strict.startup_decision(FRESH + 5).unwrap();
        assert_eq!(decision, StartupDecision::Exit75 { unresolved: 1 });
        let mut tolerant = booted(3, 1);
        publish_a(&mut tolerant.cache, 0, FRESH, TTL);
        publish_a(&mut tolerant.cache, 1, FRESH, TTL);
        let decision = tolerant.startup_decision(FRESH + 5).unwrap();
        assert_eq!(decision, StartupDecision::Serve(ServingMode::Degraded));
    });
}

#[test]
fn retired_everywhere_is_exit75_with_exact_unresolved_count() {
    let mut storage = booted(2, 1);
    publish_a(&mut storage.cache, 0, FRESH, TTL);
    publish_a(&mut storage.cache, 1, FRESH, TTL);
    let decision = storage.startup_decision(RETIREMENT).unwrap();
    assert_eq!(decision, StartupDecision::Exit75 { unresolved: 2 });
}

#[test]
fn binding_published_strictly_before_deadline_counts_at_the_snapshot() {
    let mut storage = booted(1, 0);
    publish_a(&mut storage.cache, 0, 1089, 1);
    assert_eq!(
        storage.startup_decision(1090).unwrap(),
        StartupDecision::Serve(ServingMode::Full)
    );
}

#[test]
fn serve_storage_boot_corresponds_allowlist_at_boundary() {
    let config = config_with_allowance(2, 1);
    let storage = ServeStorage::boot(&config).expect("boot serving storage");
    assert_eq!(storage.cache().name_count(), config.allowlist().len());
    assert_eq!(storage.schedules().name_count(), config.allowlist().len());
    assert_eq!(
        storage.cache().name_count(),
        storage.schedules().name_count()
    );
}

#[test]
fn work_view_is_bound_to_the_owning_storages_state() {
    use crate::connect::{ConnectParser, Feed};
    use crate::worker::{ConnectPhase, Deadline};
    use std::time::Instant;
    let mut storage = booted(1, 0);
    publish_a(&mut storage.cache, 0, FRESH + 5, TTL);
    let t0 = Instant::now();
    let now = t0 + Duration::from_secs(1);
    let mut parser = ConnectParser::new();
    let head = b"CONNECT alpha.example.org:443 HTTP/1.1\r\n\r\n";
    match parser.feed(head).expect("valid connect head") {
        Feed::Complete { .. } => {}
        Feed::Incomplete => panic!("head should parse to completion"),
    }
    let req = *parser
        .result()
        .copied()
        .expect("connect result present")
        .as_ref()
        .expect("valid connect request");
    let slot = storage.accept(t0).expect("admitted via the owned seam");
    let phase = storage
        .decide(&slot, &storage.resolve_request(&req), now)
        .expect("decision via the owned seam");
    assert!(
        matches!(
            phase,
            ConnectPhase::Peer {
                family: Family::A,
                ..
            }
        ),
        "the owned seam must authorize this storage's own cache: {phase:?}"
    );
    assert_eq!(phase.status(), 200);
    assert_eq!(
        storage.setup_deadline(&slot),
        Some(Deadline::setup(t0)),
        "the accepted slot carries its own setup deadline"
    );
    storage.release(slot);
    assert_eq!(storage.occupied(), 0);
}

#[test]
fn storage_cache_secs_is_mounted_on_the_dns_epoch() {
    use std::time::Instant;
    const DNS_EPOCH: u64 = 1_700_000_000;
    let mut storage = booted(1, 0);
    let origin = Instant::now();
    storage.mount_clock(origin, DNS_EPOCH);
    let later = origin + Duration::from_secs(7);
    assert_eq!(
        storage.cache_secs(later),
        DNS_EPOCH + 7,
        "serving cache seconds must continue from the mounted DNS epoch"
    );
    assert_eq!(
        storage.cache_secs(origin),
        DNS_EPOCH,
        "the mounted origin evaluates to the epoch itself, not zero"
    );
}

#[test]
fn storage_decide_reads_slot_deadline_and_epoch_scale() {
    use crate::connect::{ConnectParser, Feed};
    use crate::worker::ConnectPhase;
    use std::time::Instant;
    const DNS_EPOCH: u64 = 1_700_000_000;
    let mut storage = booted(1, 0);
    storage.mount_clock(Instant::now(), DNS_EPOCH);
    publish_a(&mut storage.cache, 0, DNS_EPOCH + 1, 1);
    let t0 = Instant::now();
    let slot = storage.accept(t0).expect("admitted");
    let mut parser = ConnectParser::new();
    let head = b"CONNECT alpha.example.org:443 HTTP/1.1\r\n\r\n";
    match parser.feed(head).expect("valid connect head") {
        Feed::Complete { .. } => {}
        Feed::Incomplete => panic!("head should parse to completion"),
    }
    let req = *parser
        .result()
        .copied()
        .expect("connect result present")
        .as_ref()
        .expect("valid connect request");
    let phase = storage
        .decide(&slot, &storage.resolve_request(&req), t0)
        .expect("decision");
    assert!(
        matches!(
            phase,
            ConnectPhase::Peer {
                family: Family::A,
                ..
            }
        ),
        "fresh on the DNS scale must authorize the peer: {phase:?}"
    );
    let ConnectPhase::Peer {
        connect_deadline, ..
    } = phase
    else {
        panic!("expected Peer");
    };
    assert_eq!(
        connect_deadline.limit(),
        t0 + Duration::from_secs(crate::worker::CONNECT_DEADLINE_SECS),
        "the per-attempt deadline clips to the slot's setup deadline from its own fresh span"
    );
    storage.release(slot);
    assert_eq!(storage.occupied(), 0);
}

#[test]
fn monitor_report_emits_at_whole_second_cadence_clears_on_commit_and_admits_ring_full_summary() {
    use crate::enforcement::action::FirstSlot;
    use crate::enforcement::policy::{AnyIllegalCause, Violation};
    use std::time::Instant;
    const DNS_EPOCH: u64 = 1_700_000_000;
    let mut storage = booted(1, 0);
    let origin = Instant::now();
    storage.mount_clock(origin, DNS_EPOCH);

    assert!(
        !storage.report_monitor_if_due(origin, false),
        "a clean monitor is never due"
    );

    let secs = storage.cache_secs(origin);
    storage.enforcement_mut().decide(
        &mut FirstSlot::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::HostNotAllowlisted,
        },
        secs,
    );
    assert!(
        storage.report_monitor_if_due(origin, false),
        "a dirty monitor is due at the whole-second boundary"
    );
    assert_eq!(
        storage.enforcement().monitor().report_drops(),
        0,
        "an unforced successful commit is not detail loss"
    );
    assert!(
        !storage.report_monitor_if_due(origin, false),
        "the same second suppresses the re-emission"
    );
    let one_second = origin + Duration::from_secs(1);
    assert!(
        !storage.report_monitor_if_due(one_second, false),
        "H1: no new event between seconds, a committed aggregate is not due again"
    );

    let secs = storage.cache_secs(one_second);
    storage.enforcement_mut().decide(
        &mut FirstSlot::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::HostNotAllowlisted,
        },
        secs,
    );
    assert!(
        storage.report_monitor_if_due(one_second, false),
        "a fresh event re-dirties the aggregate at the next whole second"
    );

    {
        let ring = storage.logs_mut();
        for _ in 0..(crate::log::QUEUE_SLOTS) {
            ring.startup_warning(DNS_EPOCH, "sub.example.org", Family::A, "timeout");
        }
    }
    let next = one_second + Duration::from_secs(1);
    let secs = storage.cache_secs(next);
    storage.enforcement_mut().decide(
        &mut FirstSlot::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::HostNotAllowlisted,
        },
        secs,
    );
    assert!(
        storage.report_monitor_if_due(next, false),
        "a ring-full summary is still due at the next whole second"
    );
    assert_eq!(
        storage.enforcement().monitor().report_drops(),
        0,
        "SP-010: the reserved summary is admitted on the full ring, so no detail loss"
    );
    assert!(
        !storage.report_monitor_if_due(next + Duration::from_secs(1), false),
        "SP-010: the admitted summary clears the aggregate, so no re-emission without a fresh event"
    );
}

#[cfg(all(test, feature = "alloc-witness"))]
#[test]
fn startup_split_emission_over_full_allowlist_spends_zero_allocations() {
    use crate::alloc::{Phase, run_phase};
    use crate::config::ALLOWLIST_MAX;
    use crate::startup_dns::{FailureReason, NameOutcome, StartupReport};
    let mut doc = String::from(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n",
    );
    for ordinal in 0..ALLOWLIST_MAX {
        let _ = write!(
            doc,
            "[allowed_fqdn.\"n{ordinal}.example.org:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
        );
    }
    let config = crate::config::parse_config_document(&doc).expect("32-name config");
    let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
    let report = StartupReport {
        exchanges: 64,
        failed: 64,
        cancelled: 0,
        not_attempted: 0,
        resolved_names: 0,
        outcomes: [NameOutcome::Failed(FailureReason::Timeout); ALLOWLIST_MAX],
        first_failure: None,
    };
    let ((), counts) = run_phase(Phase::Logging, || {
        storage.emit_startup_records(9, &report, StartupDecision::Serve(ServingMode::Degraded));
    });
    assert!(
        counts.all_zero(),
        "32 startup_name attempts + the summary record allocate nothing: {counts:?}"
    );
    assert_eq!(
        storage.logs().dropped(),
        0,
        "the full-allowlist split enqueues all 33 records"
    );
}

#[cfg(all(test, feature = "alloc-witness"))]
#[test]
fn monitor_detection_report_and_drain_paths_spend_zero_allocations() {
    use crate::alloc::{Phase, run_phase};
    use crate::enforcement::action::FirstSlot;
    use crate::enforcement::policy::{AnyIllegalCause, Violation};
    const DNS_EPOCH: u64 = 1_700_000_000;
    let mut storage = booted(1, 0);
    storage.mount_clock(Instant::now(), DNS_EPOCH);
    let cause = AnyIllegalCause::HostNotAllowlisted;
    let ((), counts) = run_phase(Phase::Serving, || {
        for _ in 0..256 {
            storage.enforcement_mut().decide(
                &mut FirstSlot::new(),
                Violation::AnyIllegal { cause },
                DNS_EPOCH,
            );
        }
    });
    assert!(
        counts.all_zero(),
        "the detection fold (facts + first-slot action) allocates nothing: {counts:?}"
    );
    let ((), counts) = run_phase(Phase::Logging, || {
        for _ in 0..4 {
            let now = Instant::now();
            storage.report_monitor_if_due(now, false);
            storage.logs_mut().drain_sink();
        }
    });
    assert!(
        counts.all_zero(),
        "the summary report encode + ring + sink drain allocate nothing: {counts:?}"
    );
}

#[cfg(all(test, feature = "alloc-witness"))]
#[test]
fn monitor_nonempty_detail_ring_report_and_drain_spend_zero_allocations() {
    use crate::alloc::{Phase, run_phase};
    use crate::enforcement::action::Scope;
    use crate::enforcement::monitor::{CapturedDetail, CapturedFact, SlotCapture};
    use crate::enforcement::policy::{AnyIllegalCause, Effect};
    const DNS_EPOCH: u64 = 1_700_000_000;
    let mut storage = booted(1, 0);
    storage.mount_clock(Instant::now(), DNS_EPOCH);
    let cause = AnyIllegalCause::HostNotAllowlisted;
    let effect = Effect::Block {
        scope: Scope::Connection,
    };
    for slot in 0..crate::enforcement::monitor::CAPTURE_DETAIL_LEN {
        storage
            .enforcement_mut()
            .note_consumed_capture(SlotCapture {
                slot,
                generation: slot as u64,
                detail: Some(CapturedDetail {
                    fact: CapturedFact::AnyIllegal(cause),
                    effect,
                }),
            });
    }
    assert_eq!(
        storage.enforcement().monitor().capture_detail_len(),
        crate::enforcement::monitor::CAPTURE_DETAIL_LEN,
        "the witness populates a nonempty correlated-detail ring"
    );
    let ((), counts) = run_phase(Phase::Logging, || {
        for _ in 0..4 {
            let now = Instant::now();
            storage.report_monitor_if_due(now, false);
            storage.logs_mut().drain_sink();
        }
    });
    assert!(
        counts.all_zero(),
        "the correlated-detail x-segment encode + drain allocate nothing on a populated ring: {counts:?}"
    );
}

fn connect_request(head: &[u8]) -> crate::connect::ConnectRequest {
    use crate::connect::{ConnectParser, Feed};
    let mut parser = ConnectParser::new();
    match parser.feed(head).expect("valid connect head") {
        Feed::Complete { .. } => {}
        Feed::Incomplete => panic!("head should parse to completion"),
    }
    *parser
        .result()
        .copied()
        .expect("connect result present")
        .as_ref()
        .expect("valid connect request")
}

#[test]
fn resolve_request_binds_exact_port_to_allowlist_position_without_re_resolution() {
    let storage = booted(2, 1);
    let exact = connect_request(b"CONNECT alpha.example.org:443 HTTP/1.1\r\n\r\n");
    let resolved_exact = storage.resolve_request(&exact);
    assert_eq!(
        resolved_exact.ordinal(),
        Some(0),
        "the exact allowlist pair binds to its shared allowlist position"
    );
    assert_eq!(
        resolved_exact
            .ordinal()
            .and_then(|i| storage.enforcement().control().ordinal(i)),
        storage.enforcement().control().ordinal(0),
        "the minted raw position converts to the exact entry's enforcement ordinal"
    );
    let other_port = connect_request(b"CONNECT alpha.example.org:8443 HTTP/1.1\r\n\r\n");
    let resolved_other = storage.resolve_request(&other_port);
    assert_eq!(
        resolved_other.ordinal(),
        None,
        "same hostname on an unlisted port binds to no position (9t6w B1)"
    );
}

#[test]
fn schedule_due_instant_saturates_instead_of_collapsing_to_now() {
    use std::time::Instant;
    let storage = booted(1, 0);
    let far = storage.schedule_due_instant(u64::MAX);
    assert!(
        far > Instant::now(),
        "overflow must saturate to the farthest instant, never collapse to now"
    );
}

#[test]
fn report_incident_if_due_emits_window_summary_through_real_path() {
    let mut storage = booted(1, 0);
    let origin = Instant::now();
    storage.mount_clock(origin, 1000);
    // Open the A incident and its reporting window at secs 1000.
    storage
        .schedules_mut()
        .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
        .expect("open A incident");
    storage.report_incident_if_due(origin);
    // A second failure inside the window updates the latest reason.
    storage
        .schedules_mut()
        .note_exchange_failure(0, Family::A, 2000, FailureReason::Connect)
        .expect("update A incident");
    // The 3600s boundary rotation must emit the error summary for the
    // closed window through the real orchestration path (M2).
    storage.report_incident_if_due(origin + Duration::from_secs(3600));
    let record = storage
        .logs()
        .last_record_bytes()
        .expect("incident summary record");
    let text = String::from_utf8_lossy(record);
    assert!(
        text.contains("kind=incident_summary") && text.contains("level=error"),
        "the boundary rotation must emit the error summary: {text}"
    );
    assert!(
        text.contains("window_start=1000")
            && text.contains("window_end=4600")
            && text.contains("duration=3600"),
        "the summary must span the full closed window: {text}"
    );
    assert!(
        text.contains("types=\"a\"") && text.contains("a_start=1000"),
        "the summary must report the window's A incident: {text}"
    );
    assert!(
        text.contains("a_reason=\"connect\""),
        "the summary must carry the latest failure reason: {text}"
    );
}

#[test]
/// G4 — delayed/skipped reporting windows identify the skipped interval in
/// the record instead of merging it into a purported one-hour report: a
/// rotation observed 2.5 windows after the window opened spans both full
/// intervals (`window_end = start + 2*W`, `duration = 2*W`) and sets
/// `skipped=1`, the exact shape D1/D2 build on
/// (docs/alumina-proxy.md:122-124).
fn delayed_window_summary_reports_skip_count_instead_of_one_hour_merger() {
    let mut storage = booted(1, 0);
    let origin = Instant::now();
    storage.mount_clock(origin, 1000);
    // Open the A incident and its reporting window at secs 1000.
    storage
        .schedules_mut()
        .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
        .expect("open A incident");
    storage.report_incident_if_due(origin);
    // No report turn until 2.5 windows later: two full windows elapsed with
    // the second never observed until now.
    storage.report_incident_if_due(origin + Duration::from_secs(2 * 3600 + 1800));
    let record = storage
        .logs()
        .last_record_bytes()
        .expect("delayed summary record");
    let text = String::from_utf8_lossy(record);
    assert!(
        text.contains("kind=incident_summary")
            && text.contains("window_start=1000")
            && text.contains("window_end=8200")
            && text.contains("duration=7200")
            && text.contains("skipped=1"),
        "the record must span both intervals and mark the skipped window: {text}"
    );
    // Pin the fresh window's start to the last rotation boundary, never the
    // observation time: a mutation that anchored the next window at `now`
    // (10000) would pass the closed-record checks above while silently
    // dropping every byte in [8200,10000) from this report onward.
    // Activity inside the skipped-over gap must land in the next window.
    storage
        .incident_report_mut()
        .note_tunnel_bytes(0, 0, 1, 60, 9000);
    storage
        .incident_report_mut()
        .note_tunnel_bytes(0, 0, 1, 5, 9000);
    let next = storage
        .incident_report_mut()
        .close_window(0, 9600)
        .expect("close window 2");
    assert_eq!(
        next.window_start, 8200,
        "fresh window opens at the rotation boundary, never at now"
    );
    assert_eq!(
        next.activity.tunnels.value, 1,
        "two gap writes on one generation are one tunnel"
    );
    assert_eq!(
        next.activity.bytes.value, 65,
        "gap bytes reach the report instead of being dropped"
    );
}

#[test]
/// G4 — enqueue failure: a full log ring drops the closed-window summary
/// exactly once (drop accounting increments) but the rotation already reset
/// the window counters, so the next window starts fresh and later activity
/// is not merged into the dropped window. The incident-report pass never
/// changes authorization or retry scheduling: the schedule still holds the
/// open A incident after the failed enqueue (docs/alumina-proxy.md:193).
fn enqueue_failure_drops_summary_resets_window_and_counts_drop() {
    use crate::schedule::TypeIncident;
    let mut storage = booted(1, 0);
    let origin = Instant::now();
    storage.mount_clock(origin, 1000);
    // Open the A incident and its reporting window at secs 1000.
    storage
        .schedules_mut()
        .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
        .expect("open A incident");
    storage.report_incident_if_due(origin);
    // Activity in window 1: one exchange failure, one forwarded tunnel byte.
    storage
        .incident_report_mut()
        .note_exchange_failure(0, Family::A, 1010, "timeout", None);
    storage
        .incident_report_mut()
        .note_tunnel_bytes(0, 0, 1, 50, 1020);
    // Fill the log ring to capacity: the closed-window summary cannot fit.
    {
        let ring = storage.logs_mut();
        for _ in 0..crate::log::QUEUE_SLOTS {
            ring.startup_warning(1, "sub.example.org", Family::A, "timeout");
        }
    }
    assert!(storage.logs().is_full(), "ring must be at capacity");
    let before = storage.logs().dropped();
    // Rotate at the boundary: the window closes and its counters reset, then
    // the summary enqueue fails on the full ring and is dropped exactly once
    // (drop accounting increments by one, never more).
    storage.report_incident_if_due(origin + Duration::from_secs(3600));
    assert_eq!(
        storage.logs().dropped(),
        before + 1,
        "enqueue failure is dropped whole and counted exactly once"
    );
    // Pin record identity, not just the counter: a reserved displacement
    // path would also bump `dropped` by one yet COMMIT the summary into the
    // ring (log.rs `displace_reserved`). The newest slot must therefore
    // still hold a fill-time startup_warning, proving the closed-window
    // summary was dropped whole and never entered the ring.
    let newest = storage
        .logs()
        .last_record_bytes()
        .expect("ring holds a record after fill");
    let newest_text = String::from_utf8_lossy(newest);
    assert!(
        newest_text.contains("kind=startup_warning")
            && !newest_text.contains("kind=incident_summary"),
        "the closed-window summary must be dropped whole, never displaced \
             into the ring: {newest_text}"
    );
    // The rotation reset the window counters regardless of the enqueue
    // outcome: new activity lands in the fresh window starting at 4600 with
    // none of window-1's bytes or failures carried forward.
    storage
        .incident_report_mut()
        .note_tunnel_bytes(0, 1, 2, 100, 4700);
    let partial = storage
        .incident_report_mut()
        .close_window(0, 4800)
        .expect("new-window partial summary");
    assert_eq!(partial.window_start, 1000 + 3600);
    assert_eq!(partial.activity.tunnels.value, 1, "only the new tunnel");
    assert_eq!(partial.activity.bytes.value, 100, "window-1 bytes reset");
    assert_eq!(
        partial.per_type[0].failures.value, 0,
        "window-1 failures reset"
    );
    // The incident-report pass never changes authorization or retry
    // scheduling: the A incident stays open and keeps being reported.
    assert!(
        matches!(
            storage.schedules().incident(0, Family::A),
            Some(TypeIncident::Open { .. })
        ),
        "the report pass must not close or reschedule the incident"
    );
}

#[test]
fn boundary_recovery_coincidence_reports_window_incident_activity() {
    let mut storage = booted(1, 0);
    let origin = Instant::now();
    storage.mount_clock(origin, 1000);
    // Open the A incident and its reporting window at secs 1000.
    storage
        .schedules_mut()
        .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
        .expect("open A incident");
    storage.report_incident_if_due(origin);
    // A full recovery detected at the boundary turn: both incidents clear.
    storage
        .schedules_mut()
        .clear_exchange_incident(0, Family::A, 1000 + 3600)
        .expect("clear A incident");
    storage.report_incident_if_due(origin + Duration::from_secs(3600));
    // M1: the window's error summary must reflect the window's actual A
    // incident activity even though the incident recovered at the boundary
    // turn; L1: the zero-duration info summary must be suppressed, so the
    // error summary is the last record.
    let record = storage
        .logs()
        .last_record_bytes()
        .expect("incident summary record");
    let text = String::from_utf8_lossy(record);
    assert!(
        text.contains("kind=incident_summary") && text.contains("level=error"),
        "the boundary rotation must emit the error summary: {text}"
    );
    assert!(
        text.contains("types=\"a\"") && text.contains("a_start=1000"),
        "the error summary must report the window's A incident, not types=none: {text}"
    );
    assert!(
        text.contains("window_start=1000") && text.contains("window_end=4600"),
        "the error summary must span the full closed window: {text}"
    );
}

#[test]
fn summary_reports_remaining_freshness_and_retirement_deadlines() {
    let mut storage = booted(1, 0);
    let origin = Instant::now();
    storage.mount_clock(origin, 1000);
    // A binding with receipt 1000 and TTL 10: freshness deadline 1010,
    // retirement deadline 1010 + STALE_GRACE = 260210.
    storage.publish_test_a(0);
    storage
        .schedules_mut()
        .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
        .expect("open A incident");
    storage.report_incident_if_due(origin);
    // Full recovery closes the partial window at secs 1500.
    storage
        .schedules_mut()
        .clear_exchange_incident(0, Family::A, 1500)
        .expect("clear A incident");
    storage.report_incident_if_due(origin + Duration::from_secs(500));
    let record = storage
        .logs()
        .last_record_bytes()
        .expect("info summary record");
    let text = String::from_utf8_lossy(record);
    assert!(
        text.contains("kind=incident_summary") && text.contains("level=info"),
        "the recovery must emit the info summary: {text}"
    );
    // L2: the deadlines are reported as remaining seconds (deadline - secs),
    // not the absolute monotonic deadlines. The summary's secs is the
    // emission-time clock read (1000 here): freshness 1010 - 1000 = 10,
    // retirement 260210 - 1000 = 259210.
    assert!(
        text.contains("a_freshness=10") && text.contains("a_retirement=259210"),
        "a_freshness/a_retirement must be remaining seconds, not absolute: {text}"
    );
}

#[test]
fn startup_warning_first_emits_typed_reason_on_probe_branch() {
    let mut storage = booted(1, 0);
    storage.startup_warning_first(1, 0, Family::A, "pin_mismatch");
    assert_eq!(
        storage.logs().len(),
        1,
        "prod-branch first warning emits exactly one record"
    );
    let text = String::from_utf8_lossy(
        storage
            .logs()
            .last_record_bytes()
            .expect("one warning queued"),
    );
    assert!(
        text.contains("kind=startup_warning") && text.contains("reason=\"pin_mismatch\""),
        "prod-branch first warning must carry the typed reason token: {text}"
    );
}

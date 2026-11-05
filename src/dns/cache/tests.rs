use super::*;
use crate::eligibility::NumericAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

fn v4(octets: [u8; 4]) -> NumericAddr {
    NumericAddr::V4(Ipv4Addr::from(octets))
}

fn pub_addr() -> NumericAddr {
    v4([1, 1, 1, 1])
}

fn priv_addr() -> NumericAddr {
    v4([10, 0, 0, 1])
}

fn publish_simple(
    cache: &mut Cache,
    name: NameIndex,
    family: Family,
    tag: Generation,
    addrs: &[NumericAddr],
    receipt: u64,
    ttl: u64,
) {
    let staged = StagedPositive::stage(name, family, tag, addrs, receipt, ttl).unwrap();
    cache
        .publish_positive(&staged)
        .unwrap_or_else(|e| panic!("publish failed: {e:?}"));
}

fn current_gen(cache: &Cache, name: NameIndex, family: Family) -> Generation {
    cache.entry(name, family).unwrap().generation()
}

fn read(cache: &Cache, name: NameIndex, family: Family) -> Entry {
    cache.entry(name, family).unwrap()
}

#[test]
#[expect(
    clippy::large_stack_arrays,
    reason = "test staging buffer, not runtime path"
)]
fn cache_new_rejects_out_of_range_name_count() {
    assert_eq!(Cache::new(0), Err(CacheError::NameOutOfRange));
    assert_eq!(
        Cache::new(ALLOWLIST_MAX + 1),
        Err(CacheError::NameOutOfRange)
    );
    assert_eq!(
        Cache::new(1),
        Ok(Cache {
            name_count: 1,
            entries: [[Entry::EMPTY; 2]; ALLOWLIST_MAX],
        })
    );
    assert_eq!(
        Cache::new(ALLOWLIST_MAX).unwrap().name_count(),
        ALLOWLIST_MAX
    );
}

#[test]
fn name_index_admission_is_bounded() {
    let cache = Cache::new(2).unwrap();
    assert_eq!(cache.name_index(0), Some(NameIndex(0)));
    assert_eq!(cache.name_index(1), Some(NameIndex(1)));
    assert_eq!(cache.name_index(2), None);
    assert_eq!(cache.name_index(999), None);
}

#[test]
fn ttl_zero_is_treated_as_one_second() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        0,
    );
    let entry = read(&cache, name, Family::A);
    assert_eq!(entry.deadlines(), (Some(1001), Some(1001 + STALE_GRACE)));
    assert_eq!(entry.state(1000), EntryState::Fresh);
}

#[test]
fn ttl_above_cap_is_clamped_to_max_freshness() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        TTL_CAP + 1,
    );
    let entry = read(&cache, name, Family::A);
    assert_eq!(
        entry.deadlines(),
        (Some(1000 + TTL_CAP), Some(1000 + TTL_CAP + STALE_GRACE))
    );
    assert_eq!(entry.state(1000 + TTL_CAP - 1), EntryState::Fresh);
    assert_eq!(entry.state(1000 + TTL_CAP), EntryState::Stale);
}

#[test]
fn ttl_at_cap_passes_unchanged() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        TTL_CAP,
    );
    let entry = read(&cache, name, Family::A);
    assert_eq!(
        entry.deadlines(),
        (Some(1000 + TTL_CAP), Some(1000 + TTL_CAP + STALE_GRACE))
    );
    assert_eq!(entry.state(1000 + TTL_CAP - 1), EntryState::Fresh);
    assert_eq!(entry.state(1000 + TTL_CAP), EntryState::Stale);
}

#[test]
fn publish_deduplicates_identical_addresses() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    let addrs = &[
        pub_addr(),
        priv_addr(),
        pub_addr(),
        v4([8, 8, 8, 8]),
        pub_addr(),
    ];
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        addrs,
        1000,
        300,
    );
    let entry = read(&cache, name, Family::A);
    assert_eq!(entry.bindings(), &[pub_addr(), v4([8, 8, 8, 8])]);
}

#[test]
fn publish_deduplicates_identical_v6_addresses() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    let first = NumericAddr::V6(Ipv6Addr::from(
        0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
    ));
    let second = NumericAddr::V6(Ipv6Addr::from(
        0x2606_4700_4700_0000_0000_0000_0000_2222_u128,
    ));
    publish_simple(
        &mut cache,
        name,
        Family::Aaaa,
        Generation::INITIAL,
        &[first, second, first],
        1000,
        300,
    );
    let entry = read(&cache, name, Family::Aaaa);
    assert_eq!(entry.bindings(), &[first, second]);
}

#[test]
fn fresh_stale_retired_boundaries_across_receipt_ttls() {
    for ttl in [0u64, 1, 29, 30, 31, 299, 300, 301] {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        let effective = ttl.max(1);
        publish_simple(
            &mut cache,
            name,
            Family::A,
            Generation::INITIAL,
            &[pub_addr()],
            1000,
            ttl,
        );
        let entry = read(&cache, name, Family::A);
        let retirement = 1000 + effective + STALE_GRACE;
        assert_eq!(
            entry.state(1000 + effective - 1),
            EntryState::Fresh,
            "ttl={ttl}, before freshness"
        );
        assert_eq!(
            entry.state(1000 + effective),
            EntryState::Stale,
            "ttl={ttl}, at freshness"
        );
        assert_eq!(
            entry.state(retirement - 1),
            EntryState::Stale,
            "ttl={ttl}, before retirement"
        );
        assert_eq!(
            entry.state(retirement),
            EntryState::Retired,
            "ttl={ttl}, at retirement"
        );
        assert_eq!(
            entry.state(retirement + 1),
            EntryState::Retired,
            "ttl={ttl}, after retirement"
        );
    }
}

#[test]
fn servable_serves_fresh_and_stale_within_window_only() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        120,
    );
    let entry = read(&cache, name, Family::A);
    let freshness = 1000 + 120;
    let retirement = freshness + STALE_GRACE;
    assert!(entry.servable(freshness - 1), "fresh is served");
    assert!(entry.servable(freshness), "stale at freshness is served");
    assert!(
        entry.servable(freshness + STALE_SERVING_WINDOW - 1),
        "stale just inside the serving window is served"
    );
    assert!(
        !entry.servable(freshness + STALE_SERVING_WINDOW),
        "stale past the serving window is not served"
    );
    assert!(!entry.servable(retirement), "retired is never served");
}

#[test]
fn zero_ttl_entry_never_served_stale() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        0,
    );
    let entry = read(&cache, name, Family::A);
    let freshness = 1000 + 1;
    assert!(
        entry.servable(freshness - 1),
        "fresh usability before the 1s boundary"
    );
    assert!(
        !entry.servable(freshness),
        "no stale admission at the 1s boundary"
    );
    assert!(
        !entry.servable(freshness + STALE_SERVING_WINDOW - 1),
        "no stale admission inside the stale-serving window"
    );
}

#[test]
fn publish_positive_derives_stale_allowed_from_raw_ttl() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        0,
    );
    let zero_ttl = read(&cache, name, Family::A);
    assert!(
        !zero_ttl.stale_allowed(),
        "a zero-TTL answer never admits stale serving"
    );
    publish_simple(
        &mut cache,
        name,
        Family::A,
        zero_ttl.generation(),
        &[pub_addr()],
        2000,
        120,
    );
    let nonzero_ttl = read(&cache, name, Family::A);
    assert!(
        nonzero_ttl.stale_allowed(),
        "a nonzero-TTL answer admits stale serving"
    );
}

#[test]
fn delayed_timer_reports_retired_when_now_past_deadline() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::Aaaa,
        Generation::INITIAL,
        &[NumericAddr::V6(Ipv6Addr::from(
            0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
        ))],
        500,
        30,
    );
    let retirement = 500 + 30 + STALE_GRACE;
    assert_eq!(
        read(&cache, name, Family::Aaaa).state(retirement + 7000),
        EntryState::Retired
    );
}

#[test]
fn positive_publish_replaces_not_merges() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[v4([8, 8, 8, 8]), v4([9, 9, 9, 9])],
        100,
        60,
    );
    let first_gen = current_gen(&cache, name, Family::A);
    assert_eq!(
        read(&cache, name, Family::A).bindings(),
        &[v4([8, 8, 8, 8]), v4([9, 9, 9, 9])]
    );
    let first_retirement = read(&cache, name, Family::A).deadlines().1;

    publish_simple(
        &mut cache,
        name,
        Family::A,
        first_gen,
        &[v4([8, 8, 8, 8])],
        200,
        30,
    );
    let entry = read(&cache, name, Family::A);
    assert_eq!(entry.bindings(), &[v4([8, 8, 8, 8])]);
    assert_ne!(entry.deadlines().1, first_retirement);
    assert_ne!(current_gen(&cache, name, Family::A), first_gen);
}

#[test]
fn empty_eligible_positive_evicts_and_advances_generation() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        100,
        60,
    );
    let first_gen = current_gen(&cache, name, Family::A);

    publish_simple(
        &mut cache,
        name,
        Family::A,
        first_gen,
        &[priv_addr()],
        200,
        60,
    );
    let entry = read(&cache, name, Family::A);
    assert!(entry.is_empty());
    assert_eq!(entry.deadlines(), (None, None));
    assert_eq!(entry.state(300), EntryState::Empty);
    assert_ne!(current_gen(&cache, name, Family::A), first_gen);
}

#[test]
fn stale_generation_positive_rejected_state_unchanged() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        100,
        60,
    );
    let current = current_gen(&cache, name, Family::A);
    let bindings_before = read(&cache, name, Family::A).bindings().to_vec();

    let stale = StagedPositive::stage(
        name,
        Family::A,
        Generation::INITIAL,
        &[v4([8, 8, 8, 8])],
        200,
        60,
    )
    .unwrap();
    assert_eq!(
        cache.publish_positive(&stale),
        Err(CacheError::StaleGeneration)
    );
    assert_eq!(read(&cache, name, Family::A).bindings(), bindings_before);
    assert_eq!(current_gen(&cache, name, Family::A), current);
}

#[test]
fn nxdomain_evicts_both_families() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        100,
        60,
    );
    publish_simple(
        &mut cache,
        name,
        Family::Aaaa,
        Generation::INITIAL,
        &[NumericAddr::V6(Ipv6Addr::from(
            0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
        ))],
        100,
        60,
    );
    let a_gen = current_gen(&cache, name, Family::A);
    let aaaa_gen = current_gen(&cache, name, Family::Aaaa);

    cache.evict_nxdomain(name).unwrap();
    assert!(read(&cache, name, Family::A).is_empty());
    assert!(read(&cache, name, Family::Aaaa).is_empty());
    assert_ne!(current_gen(&cache, name, Family::A), a_gen);
    assert_ne!(current_gen(&cache, name, Family::Aaaa), aaaa_gen);
}

#[test]
fn nodata_evicts_only_queried_family() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        100,
        60,
    );
    publish_simple(
        &mut cache,
        name,
        Family::Aaaa,
        Generation::INITIAL,
        &[NumericAddr::V6(Ipv6Addr::from(
            0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
        ))],
        100,
        60,
    );

    let a_gen_before = current_gen(&cache, name, Family::A);
    let aaaa_gen_before = current_gen(&cache, name, Family::Aaaa);

    cache.evict_nodata(name, Family::A).unwrap();
    assert!(read(&cache, name, Family::A).is_empty());
    assert!(!read(&cache, name, Family::Aaaa).is_empty());
    assert_ne!(current_gen(&cache, name, Family::A), a_gen_before);
    assert_eq!(current_gen(&cache, name, Family::Aaaa), aaaa_gen_before);
}

#[test]
fn exchange_failure_retains_bindings_and_never_extends_retirement() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr(), v4([8, 8, 8, 8])],
        1000,
        30,
    );
    let before = read(&cache, name, Family::A);
    let retirement = before.deadlines().1.unwrap();

    cache.note_exchange_failure(name, Family::A).unwrap();
    cache.note_exchange_failure(name, Family::A).unwrap();
    let after = read(&cache, name, Family::A);
    assert_eq!(after.bindings(), &[pub_addr(), v4([8, 8, 8, 8])]);
    assert_eq!(after.deadlines().1, Some(retirement));
    assert_eq!(after.state(retirement - 1), EntryState::Stale);
    assert_eq!(after.state(retirement), EntryState::Retired);
}

#[test]
fn stage_rejects_overflow_without_truncation() {
    let addrs: Vec<NumericAddr> = (0u8..=16).map(|i| v4([10, 0, 0, i])).collect();
    let err = StagedPositive::stage(NameIndex(0), Family::A, Generation::INITIAL, &addrs, 1, 60);
    assert_eq!(err, Err(CacheError::BindingCapacityExceeded));
}

#[test]
fn stage_rejects_family_mismatch() {
    let err = StagedPositive::stage(
        NameIndex(0),
        Family::A,
        Generation::INITIAL,
        &[NumericAddr::V6(Ipv6Addr::from(
            0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
        ))],
        1,
        60,
    );
    assert_eq!(err, Err(CacheError::FamilyMismatch));
    let err2 = StagedPositive::stage(
        NameIndex(0),
        Family::Aaaa,
        Generation::INITIAL,
        &[pub_addr()],
        1,
        60,
    );
    assert_eq!(err2, Err(CacheError::FamilyMismatch));
}

#[test]
fn generation_exhaustion_is_controlled_and_preserves_state() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    cache.entry_mut(name, Family::A).generation = Generation(u64::MAX);
    let staged =
        StagedPositive::stage(name, Family::A, Generation(u64::MAX), &[pub_addr()], 1, 60).unwrap();
    assert_eq!(
        cache.publish_positive(&staged),
        Err(CacheError::GenerationExhausted)
    );
    assert_eq!(current_gen(&cache, name, Family::A), Generation(u64::MAX));
    assert!(read(&cache, name, Family::A).is_empty());
}

fn v6_addr() -> NumericAddr {
    NumericAddr::V6(Ipv6Addr::from(
        0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
    ))
}

#[test]
fn foreign_cache_index_ops_rejected_at_boundary() {
    let mut small = Cache::new(1).unwrap();
    let foreign = Cache::new(2).unwrap().name_index(1).unwrap();

    let staged = StagedPositive::stage(
        foreign,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1,
        60,
    )
    .unwrap();
    assert_eq!(
        small.publish_positive(&staged),
        Err(CacheError::NameOutOfRange)
    );
    assert_eq!(
        small.evict_nxdomain(foreign),
        Err(CacheError::NameOutOfRange)
    );
    assert_eq!(
        small.evict_nodata(foreign, Family::A),
        Err(CacheError::NameOutOfRange)
    );
    assert_eq!(
        small.note_exchange_failure(foreign, Family::A),
        Err(CacheError::NameOutOfRange)
    );
}

#[test]
fn nxdomain_generation_exhaustion_aaaa_at_max_leaves_both_unchanged() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        100,
        60,
    );
    cache.entry_mut(name, Family::Aaaa).generation = Generation(u64::MAX);
    let a_bindings = read(&cache, name, Family::A).bindings().to_vec();
    let a_gen = current_gen(&cache, name, Family::A);
    let aaaa_gen = current_gen(&cache, name, Family::Aaaa);

    assert_eq!(
        cache.evict_nxdomain(name),
        Err(CacheError::GenerationExhausted)
    );
    assert_eq!(
        read(&cache, name, Family::A).bindings(),
        a_bindings.as_slice()
    );
    assert_eq!(current_gen(&cache, name, Family::A), a_gen);
    assert!(read(&cache, name, Family::Aaaa).is_empty());
    assert_eq!(current_gen(&cache, name, Family::Aaaa), aaaa_gen);
}

#[test]
fn nxdomain_generation_exhaustion_a_at_max_leaves_both_unchanged() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::Aaaa,
        Generation::INITIAL,
        &[v6_addr()],
        100,
        60,
    );
    cache.entry_mut(name, Family::A).generation = Generation(u64::MAX);
    let aaaa_bindings = read(&cache, name, Family::Aaaa).bindings().to_vec();
    let a_gen = current_gen(&cache, name, Family::A);
    let aaaa_gen = current_gen(&cache, name, Family::Aaaa);

    assert_eq!(
        cache.evict_nxdomain(name),
        Err(CacheError::GenerationExhausted)
    );
    assert_eq!(
        read(&cache, name, Family::Aaaa).bindings(),
        aaaa_bindings.as_slice()
    );
    assert!(read(&cache, name, Family::A).is_empty());
    assert_eq!(current_gen(&cache, name, Family::A), a_gen);
    assert_eq!(current_gen(&cache, name, Family::Aaaa), aaaa_gen);
}

#[test]
fn nodata_generation_exhaustion_preserves_other_family() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    cache.entry_mut(name, Family::A).generation = Generation(u64::MAX);
    publish_simple(
        &mut cache,
        name,
        Family::Aaaa,
        Generation::INITIAL,
        &[v6_addr()],
        100,
        60,
    );
    let aaaa_bindings = read(&cache, name, Family::Aaaa).bindings().to_vec();
    let a_gen = current_gen(&cache, name, Family::A);
    let aaaa_gen = current_gen(&cache, name, Family::Aaaa);

    assert_eq!(
        cache.evict_nodata(name, Family::A),
        Err(CacheError::GenerationExhausted)
    );
    assert_eq!(current_gen(&cache, name, Family::A), a_gen);
    assert_eq!(current_gen(&cache, name, Family::Aaaa), aaaa_gen);
    assert_eq!(
        read(&cache, name, Family::Aaaa).bindings(),
        aaaa_bindings.as_slice()
    );
}

#[test]
fn freshness_deadline_overflow_leaves_entry_unchanged() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        100,
        60,
    );
    let before = read(&cache, name, Family::A);
    let staged = StagedPositive::stage(
        name,
        Family::A,
        before.generation(),
        &[v4([8, 8, 8, 8])],
        u64::MAX,
        60,
    )
    .unwrap();
    assert_eq!(
        cache.publish_positive(&staged),
        Err(CacheError::DeadlineOverflow)
    );
    let after = read(&cache, name, Family::A);
    assert_eq!(after.bindings(), before.bindings());
    assert_eq!(after.deadlines(), before.deadlines());
    assert_eq!(after.generation(), before.generation());
}

#[test]
fn grace_deadline_overflow_leaves_entry_unchanged() {
    let mut cache = Cache::new(1).unwrap();
    let name = NameIndex(0);
    publish_simple(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        100,
        60,
    );
    let before = read(&cache, name, Family::A);
    let receipt = u64::MAX - STALE_GRACE;
    let staged = StagedPositive::stage(
        name,
        Family::A,
        before.generation(),
        &[v4([8, 8, 8, 8])],
        receipt,
        1,
    )
    .unwrap();
    assert_eq!(
        cache.publish_positive(&staged),
        Err(CacheError::DeadlineOverflow)
    );
    let after = read(&cache, name, Family::A);
    assert_eq!(after.bindings(), before.bindings());
    assert_eq!(after.deadlines(), before.deadlines());
    assert_eq!(after.generation(), before.generation());
}

#[test]
#[cfg(feature = "alloc-witness")]
fn cache_zero_heap_after_positive_control() {
    use crate::alloc::{self, Phase};
    let ((), positive) = alloc::run_phase(Phase::BackgroundRefresh, || {
        let bytes = Box::new([0u8; 64]);
        std::hint::black_box(bytes);
    });
    assert!(
        positive.allocs > 0 && positive.deallocs > 0,
        "counter must attribute a local alloc/dealloc: {positive:?}"
    );

    eprintln!(
        "size_of Entry={} Cache={}",
        size_of::<Entry>(),
        size_of::<Cache>()
    );
    let ((), counts) = alloc::run_phase(Phase::BackgroundRefresh, || {
        let mut cache = Cache::new(32).unwrap();
        let name = cache.name_index(0).unwrap();
        let aaaa = cache.name_index(31).unwrap();
        publish_simple(
            &mut cache,
            name,
            Family::A,
            Generation::INITIAL,
            &[pub_addr(), v4([8, 8, 8, 8])],
            1000,
            30,
        );
        publish_simple(
            &mut cache,
            aaaa,
            Family::Aaaa,
            Generation::INITIAL,
            &[NumericAddr::V6(Ipv6Addr::from(
                0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
            ))],
            1000,
            30,
        );
        let tag = current_gen(&cache, name, Family::A);
        publish_simple(
            &mut cache,
            name,
            Family::A,
            tag,
            &[priv_addr(), v4([8, 8, 8, 8])],
            2000,
            300,
        );
        cache.evict_nxdomain(aaaa).unwrap();
        cache.evict_nodata(name, Family::A).unwrap();
        cache.note_exchange_failure(name, Family::Aaaa).unwrap();
        let mut sink = 0u128;
        for i in 0..32 {
            let n = cache.name_index(i).unwrap();
            for f in Family::ALL {
                let entry = read(&cache, n, f);
                sink = sink
                    .wrapping_add(u128::from(
                        entry.state(
                            5000 + u64::from(u8::try_from(i).expect("name ordinal fits u8")),
                        ) == EntryState::Fresh,
                    ))
                    .wrapping_add(u128::from(entry.generation().0))
                    .wrapping_add(entry.bindings().len() as u128);
            }
        }
        std::hint::black_box((cache, sink));
    });
    assert!(
        counts.all_zero(),
        "cache core must not allocate: {counts:?}"
    );
}

#[test]
fn foreign_cache_index_read_rejected_and_local_legal() {
    let small = Cache::new(1).unwrap();
    let local = small.name_index(0).unwrap();
    let foreign = Cache::new(2).unwrap().name_index(1).unwrap();
    assert_eq!(
        small.entry(foreign, Family::A),
        Err(CacheError::NameOutOfRange)
    );
    assert_eq!(
        small.entry(foreign, Family::Aaaa),
        Err(CacheError::NameOutOfRange)
    );
    assert!(read(&small, local, Family::A).is_empty());
}

#[test]
#[cfg(feature = "alloc-witness")]
fn cache_zero_heap_on_error_paths() {
    use crate::alloc::{self, Phase};
    let ((), positive) = alloc::run_phase(Phase::BackgroundRefresh, || {
        let bytes = Box::new([0u8; 64]);
        std::hint::black_box(bytes);
    });
    assert!(
        positive.allocs > 0 && positive.deallocs > 0,
        "counter must attribute a local alloc/dealloc: {positive:?}"
    );

    let ((), counts) = alloc::run_phase(Phase::BackgroundRefresh, || {
        let mut cache = Cache::new(1).unwrap();
        let local = cache.name_index(0).unwrap();
        let foreign = Cache::new(2).unwrap().name_index(1).unwrap();

        let _ = cache.entry(foreign, Family::A);
        let _ = cache.evict_nxdomain(foreign);
        let _ = cache.evict_nodata(foreign, Family::A);
        let _ = cache.note_exchange_failure(foreign, Family::A);
        let staged_f = StagedPositive::stage(
            foreign,
            Family::A,
            Generation::INITIAL,
            &[pub_addr()],
            1,
            60,
        )
        .unwrap();
        let _ = cache.publish_positive(&staged_f);

        cache.entry_mut(local, Family::A).generation = Generation(u64::MAX);
        let staged_gen =
            StagedPositive::stage(local, Family::A, Generation(u64::MAX), &[pub_addr()], 1, 60)
                .unwrap();
        let _ = cache.publish_positive(&staged_gen);
        let staged_stale = StagedPositive::stage(
            local,
            Family::A,
            Generation(u64::MAX - 1),
            &[pub_addr()],
            1,
            60,
        )
        .unwrap();
        let _ = cache.publish_positive(&staged_stale);

        cache.entry_mut(local, Family::A).generation = Generation::INITIAL;
        let staged_ovf = StagedPositive::stage(
            local,
            Family::A,
            Generation::INITIAL,
            &[v4([8, 8, 8, 8])],
            u64::MAX,
            60,
        )
        .unwrap();
        let _ = cache.publish_positive(&staged_ovf);

        std::hint::black_box((cache, local));
    });
    assert!(
        counts.all_zero(),
        "cache error paths must not allocate: {counts:?}"
    );
}

mod evidence_value {
    use super::evidence::{Evidence, EvidenceError, ProofClass, ResolverSource};

    fn v4e(ad: bool, origin: bool, qualified: bool, ttl: Option<u32>, start: u64) -> Evidence {
        Evidence::new(
            ad,
            origin,
            qualified,
            ResolverSource::index(0).unwrap(),
            ttl,
            start,
        )
        .unwrap()
    }

    #[test]
    fn class_plain_ad_never_authenticates() {
        assert_eq!(
            v4e(true, false, false, Some(60), 10).class(),
            ProofClass::Trusted
        );
        assert_eq!(
            v4e(true, false, true, Some(60), 10).class(),
            ProofClass::Trusted
        );
    }

    #[test]
    fn class_authenticated_combinations() {
        assert_eq!(
            v4e(true, true, false, Some(60), 10).class(),
            ProofClass::Authenticated
        );
        assert_eq!(
            v4e(false, true, true, Some(60), 10).class(),
            ProofClass::Authenticated
        );
        assert_eq!(
            v4e(true, true, true, Some(60), 10).class(),
            ProofClass::Delegated
        );
        // Unqualified AD=0 is still an authenticated origin, never plain.
        assert_eq!(
            v4e(false, true, false, Some(60), 10).class(),
            ProofClass::Authenticated
        );
    }

    #[test]
    fn authenticated_unqualified_ad0_is_at_least_authenticated() {
        let e = v4e(false, true, false, Some(60), 1_000);
        assert_eq!(e.class(), ProofClass::Authenticated);
        assert_eq!(e.active_class(1_030), Some(ProofClass::Authenticated));
    }

    #[test]
    fn deadline_anchors_at_query_start_and_caps() {
        assert_eq!(
            v4e(false, true, false, Some(60), 1_000).evidential_deadline(),
            Some(1_060)
        );
        assert_eq!(
            v4e(false, true, false, Some(200_000), 1_000).evidential_deadline(),
            Some(1_000 + 86_400)
        );
        assert_eq!(
            v4e(false, true, false, Some(0), 1_000).evidential_deadline(),
            Some(1_000)
        );
        assert_eq!(
            v4e(false, true, false, None, 1_000).evidential_deadline(),
            None
        );
    }

    #[test]
    fn unknown_ttl_distinct_from_explicit_zero() {
        let unknown = v4e(true, true, false, None, 1_000);
        let zero = v4e(true, true, false, Some(0), 1_000);
        assert_eq!(unknown.raw_supporting_ttl(), None);
        assert_eq!(zero.raw_supporting_ttl(), Some(0));
        assert_ne!(unknown, zero);
        assert_eq!(unknown.active_class(2_000), None);
        assert_eq!(zero.active_class(2_000), None);
    }

    #[test]
    fn active_class_requires_unexpired_authenticated_lease() {
        let auth = v4e(true, true, false, Some(60), 1_000);
        assert_eq!(auth.active_class(1_030), Some(ProofClass::Authenticated));
        assert_eq!(auth.active_class(1_060), None);
        assert_eq!(auth.active_class(2_000), None);
        let accredited = v4e(false, true, true, Some(60), 1_000);
        assert_eq!(
            accredited.active_class(1_030),
            Some(ProofClass::Authenticated)
        );
        let delegated = v4e(true, true, true, Some(60), 1_000);
        assert_eq!(delegated.active_class(1_030), Some(ProofClass::Delegated));
    }

    #[test]
    fn active_class_never_before_query_start() {
        // now below the query-start floor is never active even inside the
        // upper deadline.
        let delegated = v4e(true, true, true, Some(60), 1_000);
        assert_eq!(delegated.evidential_deadline(), Some(1_060));
        assert_eq!(delegated.active_class(999), None);
        assert_eq!(delegated.active_class(1_000), Some(ProofClass::Delegated));
    }

    #[test]
    fn active_class_absent_without_reusable_lease() {
        assert_eq!(
            v4e(true, true, false, None, 1_000).active_class(1_030),
            None
        );
        // Explicit-zero TTL: deadline == query-start floor, so the lease has
        // already arrived the instant it begins — never authenticates, even
        // with the start in the past (now > deadline).
        assert_eq!(
            v4e(true, true, false, Some(0), 1_000).active_class(1_000),
            None
        );
        assert_eq!(
            v4e(true, true, false, Some(0), 1_000).active_class(2_000),
            None
        );
        // Plain AD=1 never authenticates.
        assert_eq!(
            v4e(true, false, false, Some(60), 1_000).active_class(1_030),
            None
        );
    }

    #[test]
    fn deadline_overflow_refuses() {
        assert_eq!(
            Evidence::new(
                false,
                true,
                false,
                ResolverSource::index(0).unwrap(),
                Some(60),
                u64::MAX,
            )
            .err(),
            Some(EvidenceError::DeadlineOverflow)
        );
        assert_eq!(
            Evidence::new(
                false,
                true,
                false,
                ResolverSource::index(0).unwrap(),
                None,
                u64::MAX,
            )
            .map(Evidence::evidential_deadline),
            Ok(None)
        );
    }

    #[test]
    fn source_index_bounded_and_unknown_explicit() {
        assert!(ResolverSource::index(0).is_some());
        assert!(ResolverSource::index(4).is_some());
        assert_eq!(ResolverSource::index(5), None);
        assert_eq!(ResolverSource::index(u8::MAX), None);
        assert_eq!(ResolverSource::UNKNOWN.get(), None);
        assert_eq!(ResolverSource::index(2).unwrap().get(), Some(2));
    }

    #[test]
    fn raw_facts_retained_losslessly() {
        let e = Evidence::new(
            true,
            true,
            true,
            ResolverSource::index(3).unwrap(),
            Some(7),
            5,
        )
        .unwrap();
        assert!(e.raw_ad());
        assert!(e.origin_authenticated());
        assert!(e.qualified());
        assert_eq!(e.source(), ResolverSource::index(3).unwrap());
        assert_eq!(e.raw_supporting_ttl(), Some(7));
        assert_eq!(e.class(), ProofClass::Delegated);
        assert_eq!(e.active_class(11), Some(ProofClass::Delegated));
        assert_eq!(e.active_class(12), None);
    }

    #[test]
    fn authenticated_origin_requires_attributable_source() {
        assert_eq!(
            Evidence::new(true, true, false, ResolverSource::UNKNOWN, Some(60), 1_000).err(),
            Some(EvidenceError::AuthenticatedWithoutSource)
        );
        assert_eq!(
            Evidence::new(true, true, true, ResolverSource::UNKNOWN, Some(60), 1_000).err(),
            Some(EvidenceError::AuthenticatedWithoutSource)
        );
        assert!(Evidence::new(true, true, false, ResolverSource::UNKNOWN, None, 1_000).is_err());
        // An attributable source satisfies an authenticated origin; plain
        // origins may remain unknown.
        assert!(
            Evidence::new(
                true,
                true,
                false,
                ResolverSource::index(0).unwrap(),
                Some(60),
                1_000
            )
            .is_ok()
        );
        assert!(
            Evidence::new(true, false, false, ResolverSource::UNKNOWN, Some(60), 1_000).is_ok()
        );
    }
}

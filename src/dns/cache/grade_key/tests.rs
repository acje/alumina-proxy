//! Grade-key regression suite: corrected H2/M1 semantics against the real
//! cache owner and its publication machinery.
use super::{EntryGradeKey, Outcome, RetainedKind};
use crate::dns::cache::evidence::{AssuranceRequirement, Evidence, ProofClass, ResolverSource};
use crate::dns::cache::{Cache, CacheError, Family, Generation, NameIndex, StagedPositive};
use crate::eligibility::NumericAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

fn v4(octets: [u8; 4]) -> NumericAddr {
    NumericAddr::V4(Ipv4Addr::from(octets))
}

fn pub_addr() -> NumericAddr {
    v4([9, 9, 9, 9])
}

fn pub_v6() -> NumericAddr {
    NumericAddr::V6(Ipv6Addr::from([
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
    ]))
}

fn delegated(receipt: u64, ttl: u32) -> Evidence {
    Evidence::new(
        true,
        true,
        true,
        ResolverSource::index(0).unwrap(),
        Some(ttl),
        receipt,
    )
    .unwrap()
}

fn trusted(receipt: u64, ttl: u32) -> Evidence {
    Evidence::new(
        false,
        false,
        false,
        ResolverSource::UNKNOWN,
        Some(ttl),
        receipt,
    )
    .unwrap()
}

fn publish(
    cache: &mut Cache,
    name: NameIndex,
    family: Family,
    generation: Generation,
    addrs: &[NumericAddr],
    receipt: u64,
    ttl: u32,
    evidence: Option<Evidence>,
) {
    let staged = StagedPositive::stage_with_evidence(
        name,
        family,
        generation,
        addrs,
        receipt,
        u64::from(ttl),
        evidence,
    )
    .unwrap();
    cache.publish_positive(&staged).unwrap();
}

fn a_key(cache: &Cache, now: u64) -> EntryGradeKey {
    cache.grade_key(cache.name_index(0).unwrap(), now).unwrap()
}

#[test]
fn h2_same_grade_nodata_and_nx_are_silent() {
    let mut cache = Cache::with_requirement(1, AssuranceRequirement::DelegatedDnssec).unwrap();
    let name = cache.name_index(0).unwrap();
    publish(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        600,
        Some(delegated(1000, 600)),
    );
    let before = a_key(&cache, 1100);
    assert_eq!(before.a, Some(ProofClass::Delegated));
    cache
        .evict_nodata_evidenced(name, Family::A, delegated(1200, 600))
        .unwrap();
    let after = a_key(&cache, 1300);
    assert_eq!(
        after, before,
        "H2: secure positive -> secure NODATA must be level-equal"
    );
    assert_eq!(after.a, Some(ProofClass::Delegated));
    cache
        .evict_nxdomain_evidenced(name, delegated(1400, 600))
        .unwrap();
    let nx = a_key(&cache, 1500);
    assert_eq!(
        nx.a,
        Some(ProofClass::Delegated),
        "NX kind is silent on the A axis"
    );
    assert_eq!(
        nx.aaaa,
        Some(ProofClass::Delegated),
        "NX also establishes the other family at that grade"
    );
}

#[test]
fn m1_trusted_ttl_validity_churn_is_silent() {
    let mut cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    publish(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        600,
        Some(trusted(1000, 600)),
    );
    let in_window = a_key(&cache, 1100);
    let out_window = a_key(&cache, 3000);
    assert_eq!(in_window.a, Some(ProofClass::Trusted));
    assert_eq!(out_window.a, Some(ProofClass::Trusted));
    assert_eq!(
        out_window, in_window,
        "M1: Trusted retained-validity TTL flip must be silent"
    );
}

#[test]
fn strong_expiry_downgrade_and_recovery_change_key() {
    let mut cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    publish(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        600,
        Some(delegated(1000, 600)),
    );
    let fresh = a_key(&cache, 1100);
    assert_eq!(fresh.a, Some(ProofClass::Delegated));
    let expired = a_key(&cache, 3000);
    assert_eq!(expired.a, Some(ProofClass::Trusted));
    assert_ne!(expired, fresh);
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[v4([8, 8, 8, 8])],
        4000,
        600,
        Some(delegated(4000, 600)),
    );
    let recovered = a_key(&cache, 4100);
    assert_eq!(recovered.a, Some(ProofClass::Delegated));
    assert_eq!(
        recovered, fresh,
        "recovery returns to the same grade key despite a new address"
    );
}

#[test]
fn establishment_loss_and_negative_expiry_are_honest() {
    let mut cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    let empty = a_key(&cache, 1000);
    assert_eq!(empty.a, None);
    publish(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        600,
        Some(delegated(1000, 600)),
    );
    let established = a_key(&cache, 1100);
    assert_ne!(established, empty);
    cache
        .evict_nodata_evidenced(name, Family::A, delegated(1200, 600))
        .unwrap();
    let committed = a_key(&cache, 1300);
    assert_eq!(committed.a, Some(ProofClass::Delegated));
    let after_expiry = a_key(&cache, 3000);
    assert_eq!(
        after_expiry.a, None,
        "an expired negative must not revive a grade"
    );
    assert_eq!(
        after_expiry, empty,
        "establishment loss is a genuine transition back to None"
    );
}

#[test]
fn distinct_families_are_independently_addressable() {
    let mut cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    publish(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        600,
        Some(delegated(1000, 600)),
    );
    let a_only = a_key(&cache, 1100);
    assert_eq!(
        a_only.aaaa, None,
        "AAAA stays independent while A is established"
    );
    let v6 = NumericAddr::V6(Ipv6Addr::from([
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
    ]));
    publish(
        &mut cache,
        name,
        Family::Aaaa,
        Generation::INITIAL,
        &[v6],
        2000,
        600,
        Some(delegated(2000, 600)),
    );
    let both = a_key(&cache, 2100);
    assert_eq!(both.aaaa, Some(ProofClass::Delegated));
    assert_ne!(both, a_only, "family slots are independent and both signed");
}

#[test]
fn required_minimum_is_carried_honestly() {
    let strict = Cache::with_requirement(1, AssuranceRequirement::DelegatedDnssec).unwrap();
    let k = a_key(&strict, 1000);
    assert_eq!(k.required, AssuranceRequirement::DelegatedDnssec);
    assert_eq!(k.a, None);
    let ordinary = Cache::new(1).unwrap();
    let t = a_key(&ordinary, 1000);
    assert_eq!(t.required, AssuranceRequirement::ResolverTrusted);
    assert_ne!(
        t, k,
        "differently configured entries stay independently addressable"
    );
}

#[test]
fn retained_expiry_is_stored_not_absent() {
    let mut cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    publish(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        600,
        Some(delegated(1000, 600)),
    );
    let fresh = cache
        .family_retained(name, Family::A, 1100)
        .unwrap()
        .unwrap();
    assert!(fresh.time_valid() && fresh.applicable());
    let stale = cache
        .family_retained(name, Family::A, 3000)
        .unwrap()
        .unwrap();
    assert_eq!(
        stale.class(),
        ProofClass::Delegated,
        "expiry revokes no stored proof"
    );
    assert!(!stale.time_valid() && !stale.applicable());
}

#[test]
fn invalid_name_is_err_and_empty_is_none() {
    let cache = Cache::new(1).unwrap();
    assert!(matches!(
        cache.family_retained(NameIndex(5), Family::A, 1000),
        Err(CacheError::NameOutOfRange)
    ));
    assert_eq!(
        cache.family_retained(cache.name_index(0).unwrap(), Family::A, 1000),
        Ok(None)
    );
}

#[test]
fn family_snapshot_distinguishes_current_retained_usable() {
    let mut cache = Cache::with_requirement(2, AssuranceRequirement::DelegatedDnssec).unwrap();
    let name = cache.name_index(0).unwrap();
    assert!(
        cache
            .family_snapshot(NameIndex(9), Family::A, 1000)
            .is_err()
    );
    let absent = cache
        .family_snapshot(cache.name_index(1).unwrap(), Family::A, 1000)
        .unwrap();
    assert_eq!((absent.usable(), absent.outcome()), (0, Outcome::Unknown));
    publish(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[pub_addr()],
        1000,
        600,
        Some(delegated(1000, 600)),
    );
    let fresh = cache.family_snapshot(name, Family::A, 1100).unwrap();
    assert_eq!(
        (fresh.current(), fresh.outcome()),
        (Some(ProofClass::Delegated), Outcome::Positive)
    );
    assert_eq!(fresh.usable(), 1);
    let expired = cache.family_snapshot(name, Family::A, 3000).unwrap();
    assert_eq!(
        (expired.current(), expired.usable()),
        (Some(ProofClass::Trusted), 0)
    );
    assert!(!expired.retained().unwrap().time_valid());
    cache
        .evict_nodata_evidenced(name, Family::A, delegated(4000, 600))
        .unwrap();
    let nodata = cache.family_snapshot(name, Family::A, 4100).unwrap();
    assert_eq!((nodata.usable(), nodata.outcome()), (0, Outcome::NoData));
    cache
        .evict_nxdomain_evidenced(name, delegated(5000, 600))
        .unwrap();
    let nx = cache.family_snapshot(name, Family::A, 5100).unwrap();
    assert_eq!((nx.usable(), nx.outcome()), (0, Outcome::Nx));
}

#[test]
fn expired_negative_is_retained_but_not_current() {
    let mut cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    cache
        .evict_nodata_evidenced(name, Family::A, delegated(1000, 600))
        .unwrap();
    let live = cache.family_snapshot(name, Family::A, 1100).unwrap();
    assert_eq!(
        (live.current(), live.outcome(), live.usable()),
        (Some(ProofClass::Delegated), Outcome::NoData, 0)
    );
    let proof = live.retained().unwrap();
    assert_eq!(proof.kind(), RetainedKind::NoData);
    assert_eq!(proof.class(), ProofClass::Delegated);
    assert_eq!(proof.source(), ResolverSource::index(0).unwrap());
    assert!(proof.time_valid() && proof.applicable());
    let gone = cache.family_snapshot(name, Family::A, 2000).unwrap();
    assert_eq!(
        (gone.current(), gone.outcome(), gone.usable()),
        (None, Outcome::Unknown, 0),
        "expired negative is not a current NoData answer"
    );
    let stale = gone.retained().unwrap();
    assert_eq!(stale.kind(), RetainedKind::NoData);
    assert!(
        !stale.time_valid() && !stale.applicable(),
        "historical kind survives expiry, current applicability does not"
    );
}

#[test]
fn nx_republished_sibling_is_time_valid_but_not_current() {
    let mut cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    cache
        .evict_nxdomain_evidenced(name, delegated(1000, 600))
        .unwrap();
    let live = cache.family_snapshot(name, Family::A, 1100).unwrap();
    assert_eq!(
        (live.current(), live.outcome()),
        (Some(ProofClass::Delegated), Outcome::Nx)
    );
    assert!(live.retained().unwrap().applicable());
    let sibling_generation = cache.entry(name, Family::Aaaa).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::Aaaa,
        sibling_generation,
        &[pub_v6()],
        1200,
        600,
        Some(delegated(1200, 600)),
    );
    let side = cache.family_snapshot(name, Family::A, 1300).unwrap();
    assert_eq!(
        (side.current(), side.outcome()),
        (None, Outcome::Unknown),
        "republished sibling revokes current NX even inside the proof window"
    );
    let proof = side.retained().unwrap();
    assert_eq!(proof.kind(), RetainedKind::Nx);
    assert!(proof.time_valid());
    assert!(!proof.applicable());
    let sibling = cache.family_snapshot(name, Family::Aaaa, 1300).unwrap();
    assert_eq!(
        (sibling.current(), sibling.outcome(), sibling.usable()),
        (Some(ProofClass::Delegated), Outcome::Positive, 1),
        "two families non-contradictory: Unknown stale NX beside positive sibling"
    );
}

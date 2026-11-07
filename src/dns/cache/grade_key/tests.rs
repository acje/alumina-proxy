//! Grade-key regression suite: corrected H2/M1 semantics against the real
//! cache owner and its publication machinery.
use super::{EntryGradeKey, EntryGradeMarker, Outcome, RetainedKind};
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

fn material(before: EntryGradeKey, after: EntryGradeKey) -> bool {
    EntryGradeMarker::new(before).observe(after)
}

fn assert_same_raw_facts(before: EntryGradeKey, after: EntryGradeKey) {
    assert_eq!(before.required, after.required);
    assert_eq!((before.a, before.aaaa), (after.a, after.aaaa));
    assert_eq!(
        (before.a_retained, before.aaaa_retained),
        (after.a_retained, after.aaaa_retained)
    );
}

#[test]
fn reestablish_valid_proof_after_strong_loss_before_address() {
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
    let mut marker = EntryGradeMarker::new(a_key(&cache, 1100));
    cache.evict_nodata(name, Family::A).unwrap();
    assert!(
        marker.observe(a_key(&cache, 1101)),
        "the strong loss is material"
    );
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[],
        1200,
        600,
        Some(delegated(1200, 600)),
    );
    let proof_only = a_key(&cache, 1201);
    assert_eq!(
        proof_only.a, None,
        "no eligible address means no current grade"
    );
    let retained = proof_only.a_retained.unwrap();
    assert_eq!(retained.class, ProofClass::Delegated);
    assert!(retained.valid);
    assert!(!cache.is_name_admissible(name, 1201).unwrap());
    assert!(
        marker.observe(proof_only),
        "valid proof establishment after loss is material even without addresses"
    );
    assert!(
        !marker.observe(proof_only),
        "the establishment is not repeated"
    );
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[],
        1300,
        600,
        Some(delegated(1300, 600)),
    );
    assert!(
        !marker.observe(a_key(&cache, 1301)),
        "same-class empty refresh is silent"
    );
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1400,
        600,
        Some(delegated(1400, 600)),
    );
    assert!(
        !marker.observe(a_key(&cache, 1401)),
        "same-proof-class address availability is silent"
    );
}

#[test]
fn reestablish_valid_proof_from_unresolved_aaaa_before_address() {
    let mut cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    let mut marker = EntryGradeMarker::new(a_key(&cache, 1000));
    let evidence = |at| {
        Evidence::new(
            false,
            true,
            false,
            ResolverSource::index(0).unwrap(),
            Some(600),
            at,
        )
        .unwrap()
    };
    publish(
        &mut cache,
        name,
        Family::Aaaa,
        Generation::INITIAL,
        &[],
        1100,
        600,
        Some(evidence(1100)),
    );
    let proof_only = a_key(&cache, 1101);
    assert_eq!(
        proof_only.aaaa, None,
        "no eligible address means no current grade"
    );
    let retained = proof_only.aaaa_retained.unwrap();
    assert_eq!(retained.class, ProofClass::Authenticated);
    assert!(retained.valid);
    assert!(!cache.is_name_admissible(name, 1101).unwrap());
    assert!(
        marker.observe(proof_only),
        "valid proof establishment from unresolved is material even without addresses"
    );
    assert!(
        !marker.observe(proof_only),
        "the establishment is not repeated"
    );
    let generation = cache.entry(name, Family::Aaaa).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::Aaaa,
        generation,
        &[],
        1200,
        600,
        Some(evidence(1200)),
    );
    assert!(
        !marker.observe(a_key(&cache, 1201)),
        "same-class empty refresh is silent"
    );
    let generation = cache.entry(name, Family::Aaaa).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::Aaaa,
        generation,
        &[pub_v6()],
        1300,
        600,
        Some(evidence(1300)),
    );
    assert!(
        !marker.observe(a_key(&cache, 1301)),
        "same-proof-class address availability is silent"
    );
}

#[test]
fn material_retention_gap_grade_change_after_address_loss() {
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
    let mut marker = EntryGradeMarker::new(a_key(&cache, 1100));
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[],
        1200,
        600,
        Some(delegated(1200, 600)),
    );
    assert!(
        !marker.observe(a_key(&cache, 1201)),
        "same-class address loss is silent"
    );
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1300,
        600,
        Some(trusted(1300, 600)),
    );
    let downgraded = a_key(&cache, 1301);
    assert_eq!(downgraded.a, Some(ProofClass::Trusted));
    assert!(
        marker.observe(downgraded),
        "valid Delegated-to-Trusted downgrade across gap is material"
    );
    assert!(
        !marker.observe(downgraded),
        "advanced marker does not repeat"
    );
}

#[test]
fn material_retention_gap_validity_loss_after_proof_disappearance() {
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
    let mut marker = EntryGradeMarker::new(a_key(&cache, 1100));
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1100,
        600,
        None,
    );
    assert!(
        !marker.observe(a_key(&cache, 1101)),
        "absence alone is silent"
    );
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1200,
        0,
        Some(trusted(1200, 0)),
    );
    let invalid = a_key(&cache, 1200);
    assert_eq!(invalid.a, Some(ProofClass::Trusted));
    assert!(
        marker.observe(invalid),
        "valid-to-invalid across absence is material"
    );
    assert!(!marker.observe(invalid), "invalid state is not repeated");
}

#[test]
fn material_retention_gap_no_address_class_roundtrip_and_family_control() {
    let mut cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    publish(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[],
        1000,
        600,
        Some(delegated(1000, 600)),
    );
    publish(
        &mut cache,
        name,
        Family::Aaaa,
        Generation::INITIAL,
        &[],
        1000,
        600,
        Some(delegated(1000, 600)),
    );
    let mut marker = EntryGradeMarker::new(a_key(&cache, 1100));
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[],
        1200,
        600,
        Some(trusted(1200, 600)),
    );
    let weaker = a_key(&cache, 1201);
    assert_eq!((weaker.a, weaker.aaaa), (None, None));
    assert!(
        marker.observe(weaker),
        "Delegated-to-Trusted retained class change in empty family is material"
    );
    assert!(!marker.observe(weaker));
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[],
        1300,
        600,
        Some(delegated(1300, 600)),
    );
    let stronger = a_key(&cache, 1301);
    assert!(
        marker.observe(stronger),
        "Trusted-to-Delegated roundtrip must not coalesce"
    );
    assert!(!marker.observe(stronger));
    for receipt in [1400, 1500] {
        let generation = cache.entry(name, Family::A).unwrap().generation();
        publish(
            &mut cache,
            name,
            Family::A,
            generation,
            &[],
            receipt,
            600,
            Some(delegated(receipt, 600)),
        );
        assert!(
            !marker.observe(a_key(&cache, receipt + 1)),
            "unchanged empty-family class remains silent"
        );
    }
    let generation = cache.entry(name, Family::Aaaa).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::Aaaa,
        generation,
        &[],
        1600,
        600,
        Some(delegated(1600, 600)),
    );
    assert!(
        !marker.observe(a_key(&cache, 1601)),
        "unchanged AAAA class/validity is silent"
    );
}

#[test]
fn material_retention_gap_initial_empty_strong_grade_is_remembered() {
    let mut cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    publish(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[],
        1000,
        600,
        Some(delegated(1000, 600)),
    );
    let mut marker = EntryGradeMarker::new(a_key(&cache, 1100));
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[],
        1200,
        600,
        Some(trusted(1200, 600)),
    );
    assert!(
        marker.observe(a_key(&cache, 1201)),
        "initial valid retained class must not vanish when current grade is None"
    );
}

#[test]
fn invalid_retained_class_churn_does_not_invent_current_assurance() {
    let mut cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    publish(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[],
        1000,
        0,
        Some(trusted(1000, 0)),
    );
    let initial = a_key(&cache, 1000);
    assert_eq!(initial.a, None);
    let mut marker = EntryGradeMarker::new(initial);
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[],
        1100,
        0,
        Some(delegated(1100, 0)),
    );
    let changed_historical = a_key(&cache, 1100);
    assert_eq!(changed_historical.a, None);
    assert!(
        !marker.observe(changed_historical),
        "invalid historical class alone cannot establish or change current assurance"
    );
}

#[test]
fn invalid_retained_class_churn_with_trusted_fallback_is_silent() {
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
    let expired = a_key(&cache, 1600);
    assert_eq!(expired.a, Some(ProofClass::Trusted));
    let mut marker = EntryGradeMarker::new(expired);
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1700,
        0,
        Some(trusted(1700, 0)),
    );
    let first = a_key(&cache, 1700);
    assert_eq!(first.a, Some(ProofClass::Trusted));
    assert!(!marker.observe(first));
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1800,
        0,
        Some(delegated(1800, 0)),
    );
    let second = a_key(&cache, 1800);
    assert_eq!(second.a, Some(ProofClass::Trusted));
    assert!(
        !marker.observe(second),
        "invalid retained class must not promote the trusted current grade"
    );
}

#[test]
fn expired_empty_strong_proof_does_not_make_later_availability_a_downgrade() {
    let mut cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    publish(
        &mut cache,
        name,
        Family::A,
        Generation::INITIAL,
        &[],
        1000,
        2,
        Some(delegated(1000, 2)),
    );
    let mut marker = EntryGradeMarker::new(a_key(&cache, 1001));
    let expired = a_key(&cache, 1002);
    assert_eq!(expired.a, None);
    assert!(
        marker.observe(expired),
        "valid proof expiry is material even without an address"
    );
    assert!(!marker.observe(expired), "expiry does not repeat");
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1003,
        0,
        Some(delegated(1003, 0)),
    );
    let available = a_key(&cache, 1003);
    assert_eq!(available.a, Some(ProofClass::Trusted));
    assert!(
        !marker.observe(available),
        "an invalid historical class cannot turn availability into a downgrade"
    );
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
    assert_same_raw_facts(before, after);
    assert_eq!(after.a, Some(ProofClass::Delegated));
    assert!(
        !material(before, after),
        "same-grade answer-kind change is silent"
    );
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
fn m1_trusted_retained_proof_expiry_is_material_once() {
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
    let out_window = a_key(&cache, 1600);
    assert_eq!(in_window.a, Some(ProofClass::Trusted));
    assert_eq!(out_window.a, Some(ProofClass::Trusted));
    assert_ne!(
        out_window.a_retained, in_window.a_retained,
        "Trusted retained proof expiry must be observable even when current grade stays Trusted"
    );
    assert!(material(in_window, out_window), "expiry is material");
    let still_expired = a_key(&cache, 1601);
    assert!(
        !material(out_window, still_expired),
        "the advanced marker does not repeat expiry"
    );
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1700,
        600,
        Some(trusted(1700, 600)),
    );
    let recovered = a_key(&cache, 1701);
    assert_eq!(recovered.a, Some(ProofClass::Trusted));
    assert!(
        material(still_expired, recovered),
        "a valid retained proof really recovered"
    );
    assert!(
        !material(recovered, a_key(&cache, 1702)),
        "valid countdown is silent"
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
    assert_ne!(expired.a, fresh.a);
    assert!(
        material(fresh, expired),
        "current delegated-to-trusted grade change is material"
    );
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
    assert_same_raw_facts(recovered, fresh);
    assert!(
        material(expired, recovered),
        "the actual grade recovery is material"
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
    assert_ne!(established.a, empty.a);
    assert!(
        material(empty, established),
        "newly established valid grade is material"
    );
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
    assert!(
        material(committed, after_expiry),
        "negative proof expiry is material"
    );
    assert!(
        !material(after_expiry, empty),
        "retained historical proof disappearance alone is silent"
    );
}

#[test]
fn strong_grade_loss_is_material_but_same_proof_availability_is_silent() {
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
    let available = a_key(&cache, 1100);
    let mut marker = EntryGradeMarker::new(available);
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[],
        1200,
        600,
        Some(delegated(1200, 600)),
    );
    let no_address = a_key(&cache, 1201);
    assert_eq!(no_address.a, None);
    assert!(
        !material(available, no_address),
        "same-valid-proof address loss alone is silent"
    );
    assert!(!marker.observe(no_address));
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1300,
        600,
        Some(delegated(1300, 600)),
    );
    let restored = a_key(&cache, 1301);
    assert!(
        !material(no_address, restored),
        "same-valid-proof address recovery is silent"
    );
    assert!(!marker.observe(restored));
    cache.evict_nodata(name, Family::A).unwrap();
    let no_proof = a_key(&cache, 1302);
    assert_eq!(no_proof.a, None);
    assert!(
        material(restored, no_proof),
        "losing a current strong grade and its proof is material"
    );
    assert!(marker.observe(no_proof));
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1400,
        600,
        Some(delegated(1400, 600)),
    );
    let recovered = a_key(&cache, 1401);
    assert!(
        marker.observe(recovered),
        "strong grade establishment after a material loss is observable"
    );
    assert!(!marker.observe(recovered));
}

#[test]
fn presence_address_and_source_churn_do_not_fabricate_events() {
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
    let valid = a_key(&cache, 1100);
    let generation = cache.entry(name, Family::A).unwrap().generation();
    let relocated = Evidence::new(
        false,
        false,
        false,
        ResolverSource::index(1).unwrap(),
        Some(600),
        1101,
    )
    .unwrap();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1101,
        600,
        Some(relocated),
    );
    let same_grade = a_key(&cache, 1102);
    let mut marker = EntryGradeMarker::new(same_grade);
    assert!(
        !material(valid, same_grade),
        "equivalent resolver and deadline refresh are silent"
    );
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[v4([8, 8, 8, 8])],
        1200,
        600,
        None,
    );
    let absent = a_key(&cache, 1201);
    assert_eq!(same_grade.a, absent.a);
    assert_ne!(
        same_grade.a_retained, absent.a_retained,
        "presence remains a distinct raw fact"
    );
    assert!(
        !material(same_grade, absent),
        "proof removal and address change alone are silent"
    );
    assert!(!marker.observe(absent));
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1300,
        600,
        Some(trusted(1300, 600)),
    );
    let restored = a_key(&cache, 1301);
    assert!(
        !material(absent, restored),
        "proof presence alone at the same grade is silent"
    );
    assert!(!marker.observe(restored));
    let expired = a_key(&cache, 1900);
    assert!(
        material(restored, expired),
        "a retained proof really expired"
    );
    assert!(marker.observe(expired));
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        1901,
        600,
        None,
    );
    let expired_then_absent = a_key(&cache, 1902);
    assert!(
        !material(expired, expired_then_absent),
        "expired proof disappearing is not a fabricated recovery"
    );
    assert!(!marker.observe(expired_then_absent));
    let generation = cache.entry(name, Family::A).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::A,
        generation,
        &[pub_addr()],
        2000,
        600,
        Some(trusted(2000, 600)),
    );
    let recovered = a_key(&cache, 2001);
    assert!(
        marker.observe(recovered),
        "new valid proof after an absent interval is a real recovery"
    );
    assert!(!marker.observe(recovered), "recovery is not repeated");
}

#[test]
fn expired_positive_availability_loss_does_not_repeat_expiry() {
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
    let expired = a_key(&cache, 1600);
    let unavailable = a_key(&cache, 5200);
    assert_eq!(expired.a, Some(ProofClass::Trusted));
    assert_eq!(unavailable.a, None, "the stale serving window is exhausted");
    assert!(
        !material(expired, unavailable),
        "availability loss after expiry alone is silent"
    );
}

#[test]
fn family_expiry_and_recovery_are_independent() {
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
    publish(
        &mut cache,
        name,
        Family::Aaaa,
        Generation::INITIAL,
        &[pub_v6()],
        1000,
        60,
        Some(trusted(1000, 60)),
    );
    let both_valid = a_key(&cache, 1059);
    let mut marker = EntryGradeMarker::new(both_valid);
    let v6_expired = a_key(&cache, 1060);
    assert_eq!(
        (both_valid.a, both_valid.aaaa),
        (v6_expired.a, v6_expired.aaaa)
    );
    assert!(material(both_valid, v6_expired));
    assert!(marker.observe(v6_expired));
    assert!(!material(v6_expired, a_key(&cache, 1061)));
    assert!(!marker.observe(a_key(&cache, 1061)));
    let generation = cache.entry(name, Family::Aaaa).unwrap().generation();
    publish(
        &mut cache,
        name,
        Family::Aaaa,
        generation,
        &[pub_v6()],
        1100,
        60,
        Some(trusted(1100, 60)),
    );
    assert!(material(v6_expired, a_key(&cache, 1101)));
    assert!(marker.observe(a_key(&cache, 1101)));
}

#[cfg(feature = "alloc-witness")]
#[test]
fn fixed_observation_keys_and_material_comparison_spend_zero_allocations() {
    use crate::alloc::{Phase, run_phase};
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
    let (result, counts) = run_phase(Phase::Logging, || {
        let before = cache.grade_key(name, 1599)?;
        let after = cache.grade_key(name, 1600)?;
        let mut marker = EntryGradeMarker::new(before);
        Ok::<bool, CacheError>(marker.observe(after))
    });
    assert_eq!(result, Ok(true));
    assert!(
        counts.all_zero(),
        "cache observation and material comparison: {counts:?}"
    );
    let key = std::mem::size_of::<EntryGradeKey>();
    let markers = std::mem::size_of::<[Option<EntryGradeMarker>; 32]>();
    println!(
        "entry_key_bytes={key} marker_bytes={} optional_32_entry_marker_bytes={markers} family_slots=64",
        std::mem::size_of::<EntryGradeMarker>()
    );
    assert_eq!(
        markers,
        32 * std::mem::size_of::<Option<EntryGradeMarker>>()
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
    assert_ne!(
        both.aaaa, a_only.aaaa,
        "family slots are independent and both signed"
    );
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
        t.required, k.required,
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
    let mut marker = EntryGradeMarker::new(a_key(&cache, 1100));
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
    assert!(
        !marker.observe(a_key(&cache, 1300)),
        "a sibling generation-only NX applicability change is silent at the same valid class"
    );
    let sibling = cache.family_snapshot(name, Family::Aaaa, 1300).unwrap();
    assert_eq!(
        (sibling.current(), sibling.outcome(), sibling.usable()),
        (Some(ProofClass::Delegated), Outcome::Positive, 1),
        "two families non-contradictory: Unknown stale NX beside positive sibling"
    );
}

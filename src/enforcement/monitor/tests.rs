use std::net::Ipv4Addr;

use super::*;
use crate::enforcement::action::{
    ActionKind, AnyIllegalControl, Control, FirstSlot, PerFqdnControl, Scope,
};
use crate::enforcement::policy::{Effect, Violation};
use crate::enforcement::state::{Enforcement, GateSet};

fn any_controls(kind: ActionKind, scope: Scope) -> [Control; AnyIllegalControl::COUNT] {
    [Control::new(kind, scope); AnyIllegalControl::COUNT]
}

fn table(
    any: [Control; AnyIllegalControl::COUNT],
    early: &[(ActionKind, Scope)],
    ja4: &[(ActionKind, Scope)],
) -> crate::enforcement::action::ControlTable {
    use crate::enforcement::action::ControlTable;
    let early: Vec<PerFqdnControl> = early
        .iter()
        .map(|&(kind, scope)| PerFqdnControl::control(kind, scope))
        .collect();
    let ja4: Vec<PerFqdnControl> = ja4
        .iter()
        .map(|&(kind, scope)| PerFqdnControl::control(kind, scope))
        .collect();
    ControlTable::new(any, &early, &ja4).expect("in-bound test table")
}

#[test]
fn committed_emission_clears_dirty_and_a_new_event_re_dirtes() {
    let mut m = Monitor::new();
    assert!(!m.report_due(5), "clean aggregate is never due");
    m.note_fact_unknown(UnknownReason::Unattributed);
    assert!(m.report_due(5), "dirty aggregate is due at the boundary");
    m.mark_reported(5);
    assert!(!m.report_due(5), "same second suppresses the re-emission");
    assert!(
        !m.report_due(6),
        "H1: no event between seconds, a committed aggregate is not due again"
    );
    assert_eq!(m.report_drops(), 0);
    m.note_fact_unknown(UnknownReason::Unattributed);
    assert!(m.report_due(6), "a new event re-dirties the aggregate");
    m.mark_reported(6);
    assert_eq!(
        m.report_drops(),
        0,
        "a summary is always committed; no honest-detail-loss path remains"
    );
    assert!(
        !m.report_due(7),
        "the always-committed summary leaves a clean aggregate"
    );
}

#[test]
fn serving_stale_latches_persists_across_reports_and_clears_on_fresh() {
    let mut m = Monitor::new();
    assert!(!m.serving_stale(), "a fresh monitor is not serving stale");
    assert!(!m.report_due(5), "clean aggregate is never due");
    m.note_serving_stale();
    assert!(m.serving_stale(), "a stale admission latches the level bit");
    assert!(m.report_due(5), "the latch dirties the aggregate");
    m.mark_reported(5);
    assert!(
        m.serving_stale(),
        "the level bit survives a committed report (level, not an event fold)"
    );
    assert!(
        !m.report_due(6),
        "a committed report without a new event is clean"
    );
    m.note_serving_fresh();
    assert!(
        !m.serving_stale(),
        "a later fresh admission clears the level bit"
    );
    assert!(
        !m.report_due(6),
        "clearing via fresh admission is not itself an event (no log-volume regression)"
    );
    m.note_serving_stale();
    assert!(
        m.report_due(6),
        "a new stale admission re-dirties after the fresh clear"
    );
}

#[test]
fn each_dns_anomaly_kind_fires_its_own_index() {
    let mut m = Monitor::new();
    m.note_fact_dns_anomaly(DnsAnomalyKind::BailiwickViolation);
    m.note_fact_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch);
    m.note_fact_dns_anomaly(DnsAnomalyKind::ExtremeTtl);
    assert_eq!(m.facts_dns_anomaly(DnsAnomalyKind::BailiwickViolation), 1);
    assert_eq!(m.facts_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch), 1);
    assert_eq!(m.facts_dns_anomaly(DnsAnomalyKind::ExtremeTtl), 1);
}

#[test]
fn dns_anomalies_fold_into_facts_total_and_saturate() {
    let mut m = Monitor::new();
    assert_eq!(m.facts_total(), 0, "no anomaly means no fold");
    m.note_fact_dns_anomaly(DnsAnomalyKind::BailiwickViolation);
    m.note_fact_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch);
    m.note_fact_dns_anomaly(DnsAnomalyKind::ExtremeTtl);
    assert_eq!(
        m.facts_total(),
        3,
        "every dns-anomaly fact folds into the aggregate"
    );
    assert!(!m.facts_dns_anomaly_overflow());
    m.saturate_all_for_test();
    assert_eq!(m.facts_dns_anomaly(DnsAnomalyKind::ExtremeTtl), u32::MAX);
    assert!(m.facts_dns_anomaly_overflow());
}

#[test]
fn ja4_facts_fold_into_facts_total_and_saturate() {
    let mut m = Monitor::new();
    assert_eq!(m.facts_total(), 0, "no fact means no fold");
    let ordinal = DomainOrdinal::from_index(0).expect("bound-level ordinal");
    let peer = NumericAddr::V4(Ipv4Addr::from([203, 0, 113, 1]));
    m.note_fact_ja4_seed();
    assert_eq!(
        m.facts_total(),
        1,
        "every ja4-seed fact folds into the aggregate"
    );
    assert_eq!(m.facts_ja4_seed(), 1);
    assert!(
        !m.facts_ja4_change_loss(ordinal),
        "a first-seen seeding never sets the detail-loss flag"
    );
    m.note_fact_ja4_change(ordinal, *b"t13d1516h2_8daaf6152771_02713d6af862", peer);
    assert_eq!(
        m.facts_total(),
        2,
        "seed and change facts fold into the aggregate"
    );
    assert_eq!(m.facts_ja4_change(ordinal), 1);
    assert!(
        !m.facts_ja4_change_loss(ordinal),
        "a change record alone never latches the detail-loss flag"
    );
    m.note_fact_ja4_change_loss(ordinal);
    assert!(
        m.facts_ja4_change_loss(ordinal),
        "an overflowed baseline suppresses detail and latches the loss flag"
    );
    assert_eq!(m.ja4_peer_ordinal(), Some(ordinal));
    assert_eq!(m.ja4_peer_ip(), peer);
    m.saturate_all_for_test();
    assert_eq!(m.facts_ja4_change(ordinal), u32::MAX);
    assert!(m.facts_ja4_change_overflow());
    assert_eq!(m.facts_ja4_seed(), u32::MAX);
    assert!(m.facts_ja4_seed_overflow());
    assert_eq!(
        m.ja4_peer_ordinal(),
        DomainOrdinal::from_index(ALLOWLIST_MAX - 1),
        "saturation keys the latest-overflow peer to the last ordinal"
    );
}

#[test]
fn report_drop_is_counted_once_and_mark_reported_clears() {
    let mut m = Monitor::new();
    m.note_report_drop();
    assert_eq!(
        m.report_drops(),
        1,
        "a dropped detail batch is honest detail loss"
    );
    assert!(
        m.report_due(5),
        "the drop dirties the aggregate for the next summary"
    );
    m.mark_reported(5);
    assert_eq!(
        m.report_drops(),
        1,
        "mark_reported never re-counts the earlier drop"
    );
    assert!(
        !m.report_due(6),
        "the always-committed summary clears the aggregate"
    );
}

#[test]
fn split_facts_actions_and_refusals_through_enforcement() {
    let mut latch = FirstSlot::new();
    let mut en = Enforcement::new(
        table(
            any_controls(ActionKind::Block, Scope::Connection),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        ),
        GateSet::default(),
    );
    let cause = AnyIllegalCause::HostNotAllowlisted;
    let v = en.decide(&mut latch, Violation::AnyIllegal { cause }, 0);
    assert_eq!(
        v,
        Effect::Block {
            scope: Scope::Connection
        }
    );
    en.decide(&mut latch, Violation::AnyIllegal { cause }, 0);
    assert_eq!(
        en.counters().facts_any_illegal_total(),
        2,
        "every detection folds a fact independent of the spent first-slot latch (ogot B3b)"
    );
    assert_eq!(
        en.counters().actions_first_slot_block(Scope::Connection),
        1,
        "the Block action applies exactly once per connection"
    );
    assert_eq!(en.counters().refusals_total(), 0, "no refusal here");
}

#[test]
fn domain_block_action_and_later_refusal_are_distinct_channels() {
    let actions = [(ActionKind::Block, Scope::Domain)];
    let mut en = Enforcement::new(
        table(
            any_controls(ActionKind::Block, Scope::Connection),
            &actions,
            &actions,
        ),
        GateSet::default(),
    );
    let ordinal = DomainOrdinal::from_index(0).expect("bound-level ordinal");
    let v = en.decide(
        &mut FirstSlot::new(),
        Violation::EarlyUpstreamData { ordinal },
        0,
    );
    assert_eq!(
        v,
        Effect::Block {
            scope: Scope::Domain
        }
    );
    assert_eq!(en.counters().actions_domain_block(ordinal), 1);
    assert_eq!(en.counters().refusals_blocked_domain(ordinal), 0);
    en.note_domain_block(ordinal);
    assert_eq!(en.counters().actions_domain_block(ordinal), 1);
    assert_eq!(en.counters().refusals_blocked_domain(ordinal), 1);
    assert_eq!(
        en.counters().refusals_total(),
        1,
        "the action and the later refusal fold their own truthful totals"
    );
}

#[test]
fn two_saturated_counters_total_exactly_2x_u32_max_without_panic_or_wrap() {
    use crate::inspection::connect::ConnectHeadReason;
    let mut m = Monitor::new();
    m.saturate_facts_any_illegal_for_test(AnyIllegalCause::HostNotAllowlisted);
    m.saturate_facts_any_illegal_for_test(AnyIllegalCause::ConnectParse(
        ConnectHeadReason::TooLong,
    ));
    m.note_fact_any_illegal(AnyIllegalCause::HostNotAllowlisted);
    m.note_fact_any_illegal(AnyIllegalCause::ConnectParse(ConnectHeadReason::TooLong));
    assert_eq!(
        m.facts_any_illegal_total(),
        2 * u64::from(u32::MAX),
        "M1: per-element u64 widening sums two saturated u32 counters exactly"
    );
}

#[test]
fn consumed_capture_is_correlated_with_slot_generation_fact_and_effect() {
    let cause = AnyIllegalCause::HostNotAllowlisted;
    let effect = Effect::Block {
        scope: Scope::Connection,
    };
    let cap = |slot, generation| SlotCapture {
        slot,
        generation,
        detail: Some(CapturedDetail {
            fact: CapturedFact::AnyIllegal(cause),
            effect,
        }),
    };
    let mut m = Monitor::new();
    m.note_consumed_capture(cap(0, 42));
    m.note_consumed_capture(cap(1, 7));
    assert_eq!(
        m.capture_detail_len(),
        2,
        "H3: consumed captures fold into detail"
    );
    let first = m.capture_detail(0).expect("first capture");
    assert_eq!((first.slot, first.generation), (0, 42));
    assert_eq!(
        first.detail.fact,
        CapturedFact::AnyIllegal(cause),
        "the fact travels with the capture"
    );
    let second = m.capture_detail(1).expect("second capture");
    assert_eq!((second.slot, second.generation), (1, 7));
    assert_eq!(
        m.capture_drops(),
        0,
        "no detail loss until the ring overflows"
    );
    assert!(m.report_due(1), "a consumed capture dirties the aggregate");
}

#[test]
fn two_slots_at_equal_generation_are_distinct_identities_and_reuse_bumps_generation() {
    let cause = AnyIllegalCause::HostNotAllowlisted;
    let effect = Effect::Block {
        scope: Scope::Connection,
    };
    let cap = |slot, generation| SlotCapture {
        slot,
        generation,
        detail: Some(CapturedDetail {
            fact: CapturedFact::AnyIllegal(cause),
            effect,
        }),
    };
    let mut m = Monitor::new();
    m.note_consumed_capture(cap(0, 1));
    m.note_consumed_capture(cap(1, 1));
    let first = m.capture_detail(0).expect("slot 0 capture");
    let second = m.capture_detail(1).expect("slot 1 capture");
    assert_eq!((first.slot, first.generation), (0, 1));
    assert_eq!((second.slot, second.generation), (1, 1));
    assert_ne!(
        first, second,
        "H1': equal per-slot generations on different slots are distinct connection identities"
    );
    m.note_consumed_capture(cap(0, 2));
    let reused = m.capture_detail(2).expect("reused slot capture");
    assert_eq!((reused.slot, reused.generation), (0, 2));
    assert_ne!(
        reused, first,
        "H1': a reused slot at a new generation is a fresh identity"
    );
}

#[test]
fn mark_reported_always_consumes_the_detail_window_and_suppression_counts_once() {
    let cause = AnyIllegalCause::HostNotAllowlisted;
    let effect = Effect::Block {
        scope: Scope::Connection,
    };
    let cap = |slot| SlotCapture {
        slot,
        generation: 1,
        detail: Some(CapturedDetail {
            fact: CapturedFact::AnyIllegal(cause),
            effect,
        }),
    };
    let mut m = Monitor::new();
    m.note_consumed_capture(cap(0));
    assert_eq!(
        m.capture_detail_len(),
        1,
        "a consumed capture fills the window"
    );
    m.mark_reported(5);
    assert_eq!(
        m.capture_detail_len(),
        0,
        "M2': mark_reported always consumes its detail window"
    );
    assert!(!m.report_due(5), "the emission leaves a clean aggregate");
    m.note_consumed_capture(cap(0));
    m.note_suppressed_detail();
    assert_eq!(
        m.capture_detail_len(),
        1,
        "M2': a fresh capture refills the window"
    );
    assert_eq!(
        m.capture_drops(),
        1,
        "M2': the suppression is counted correlated-detail loss"
    );
    m.mark_reported(6);
    assert_eq!(
        m.capture_detail_len(),
        0,
        "M2': mark_reported consumes the window even after a suppression"
    );
    assert_eq!(
        m.capture_drops(),
        1,
        "M2': the earlier suppression is not re-counted"
    );
    assert!(
        !m.report_due(7),
        "M2': the emission leaves a clean aggregate"
    );
}

#[test]
fn capture_ring_overflow_keeps_latest_and_counts_the_drops() {
    let cause = AnyIllegalCause::HostNotAllowlisted;
    let effect = Effect::Block {
        scope: Scope::Connection,
    };
    let cap = |slot, generation| SlotCapture {
        slot,
        generation,
        detail: Some(CapturedDetail {
            fact: CapturedFact::AnyIllegal(cause),
            effect,
        }),
    };
    let mut m = Monitor::new();
    let overflow = 5u64;
    for generation in 0..(CAPTURE_DETAIL_LEN as u64 + overflow) {
        m.note_consumed_capture(cap(0, generation));
    }
    assert_eq!(
        m.capture_detail_len(),
        CAPTURE_DETAIL_LEN,
        "the ring holds at most the fixed detail window"
    );
    assert_eq!(
        m.capture_drops(),
        u32::try_from(overflow).expect("test overflow counter fits u32"),
        "every capture past the window is honest counted detail loss"
    );
    assert_eq!(
        m.capture_detail(0).expect("oldest held").generation,
        overflow,
        "the oldest held capture is the first one that fits the window"
    );
    assert_eq!(
        m.capture_detail(CAPTURE_DETAIL_LEN - 1)
            .expect("newest held")
            .generation,
        CAPTURE_DETAIL_LEN as u64 + overflow - 1,
        "the newest capture is always kept"
    );
}

#[test]
fn a_capture_without_a_relation_is_never_folded_into_the_ring() {
    let mut m = Monitor::new();
    let bare = SlotCapture::fresh(3, 9);
    m.note_consumed_capture(bare);
    assert_eq!(
        m.capture_detail_len(),
        0,
        "L1: a slot that detected nothing contributes no ring entry"
    );
    assert_eq!(m.capture_drops(), 0, "never a fake loss for an absent fact");
    assert!(
        !m.report_due(1),
        "an empty capture leaves the aggregate clean"
    );
}

#[test]
fn suppressed_later_relation_is_counted_correlated_detail_loss() {
    let mut m = Monitor::new();
    m.note_suppressed_detail();
    assert_eq!(
        m.capture_drops(),
        1,
        "L2: a later relation suppressed behind the first is counted correlated-detail loss"
    );
    assert!(
        m.report_due(1),
        "the suppression dirties the aggregate for the next summary"
    );
    m.mark_reported(1);
    assert_eq!(
        m.capture_drops(),
        1,
        "the committed summary does not re-count the earlier suppression"
    );
    assert!(
        !m.report_due(2),
        "the accepted summary leaves a clean aggregate"
    );
}

#[test]
fn monitor_overflow_flags_latch_and_totals_do_not_wrap() {
    let mut m = Monitor::new();
    m.saturate_facts_any_illegal_for_test(AnyIllegalCause::HostNotAllowlisted);
    m.note_fact_any_illegal(AnyIllegalCause::HostNotAllowlisted);
    assert!(
        m.facts_any_illegal_overflow(),
        "the overflow flag latches once a counter saturates"
    );
    assert_eq!(
        m.facts_any_illegal(AnyIllegalCause::HostNotAllowlisted),
        u32::MAX,
        "a saturated counter never wraps"
    );
    assert!(
        m.facts_total() >= u64::from(u32::MAX),
        "the total stays truthful under saturation, never wraps: {}",
        m.facts_total()
    );
    assert!(
        m.report_due(1),
        "a saturated-and-dirty aggregate is still due for reporting"
    );
}

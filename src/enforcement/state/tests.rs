use super::*;
use crate::enforcement::action::{ActionKind, Control};
use crate::enforcement::monitor::DnsAnomalyKind;
use crate::enforcement::policy::{AnyIllegalCause, UnknownReason};
use crate::inspection::client_hello::HelloRejectReason;
use crate::inspection::connect::ConnectHeadReason;

#[expect(
    clippy::duplicate_mod,
    reason = "one physical owner is included by several test modules in this crate"
)]
#[path = "../../../tests/support/enforcement_tables.rs"]
mod enforcement_tables;
use enforcement_tables::{any_controls, block_all_table, block_connection_table, table};

fn gate(threshold: u32, window: u64) -> AllScopeGate {
    AllScopeGate::new(
        NonZeroU32::new(threshold).expect("nonzero threshold"),
        NonZeroU64::new(window).expect("nonzero window"),
    )
}

fn en(t: ControlTable) -> EnforcementState {
    EnforcementState::new(t, GateSet::default())
}

fn en_gated(t: ControlTable, gates: GateSet) -> EnforcementState {
    EnforcementState::new(t, gates)
}

fn gates_illegal_fqdn(threshold: u32, window: u64) -> GateSet {
    GateSet::new(
        AllScopeGate::default(),
        gate(threshold, window),
        AllScopeGate::default(),
        AllScopeGate::default(),
    )
}

fn all_actions_table() -> ControlTable {
    table(
        any_controls(ActionKind::Block, Scope::All),
        &[(ActionKind::Block, Scope::All)],
        &[(ActionKind::Block, Scope::All)],
    )
}

fn domain_actions_table() -> ControlTable {
    table(
        any_controls(ActionKind::Block, Scope::Connection),
        &[(ActionKind::Block, Scope::Domain)],
        &[(ActionKind::Block, Scope::Domain)],
    )
}

fn notify_connection_table() -> ControlTable {
    table(
        any_controls(ActionKind::Notify, Scope::Connection),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Notify, Scope::Connection)],
    )
}

fn decide_at(en: &mut EnforcementState, violation: Violation, secs: u64) -> Effect {
    en.decide(&mut FirstIllegalLatch::new(), violation, secs)
}

fn isolated_gate_arrangement(
    early_data: AllScopeGate,
    ja4: AllScopeGate,
) -> (ControlTable, EnforcementState) {
    let t = all_actions_table();
    let en = en_gated(
        t,
        GateSet::new(
            AllScopeGate::default(),
            AllScopeGate::default(),
            early_data,
            ja4,
        ),
    );
    (t, en)
}

fn count_only_arrangement() -> (ControlTable, EnforcementState) {
    let t = table(
        any_controls(ActionKind::Block, Scope::All),
        &[
            (ActionKind::Notify, Scope::Connection),
            (ActionKind::Block, Scope::All),
        ],
        &[
            (ActionKind::Notify, Scope::Connection),
            (ActionKind::Block, Scope::All),
        ],
    );
    let en = en_gated(
        t,
        GateSet::new(
            AllScopeGate::default(),
            AllScopeGate::default(),
            gate(3, 60),
            gate(3, 60),
        ),
    );
    (t, en)
}

#[test]
fn all_scope_gate_zero_is_unrepresentable_at_the_type_boundary() {
    assert!(
        NonZeroU32::new(0).is_none(),
        "threshold 0 is unrepresentable: AllScopeGate::new requires NonZeroU32"
    );
    assert!(
        NonZeroU64::new(0).is_none(),
        "window_secs 0 is unrepresentable: AllScopeGate::new requires NonZeroU64"
    );
    assert_eq!(
        NonZeroU32::new(1).expect("1 is nonzero").get(),
        1,
        "the minimum threshold is 1"
    );
    assert_eq!(
        NonZeroU64::new(1).expect("1 is nonzero").get(),
        1,
        "the minimum window is 1"
    );
}

#[test]
fn saturating_counter_reports_wrapped_value_and_overflow() {
    let mut c = SaturatingCounter::new();
    for _ in 0..u64::from(u32::MAX) {
        c.bump();
    }
    assert_eq!(c.value(), u32::MAX);
    assert!(!c.overflow());
    c.bump();
    assert_eq!(c.value(), u32::MAX);
    assert!(c.overflow());
}

#[test]
fn note_fact_dns_anomaly_passes_through_to_the_monitor() {
    let t = block_connection_table();
    let mut en = en(t);
    en.note_fact_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch);
    assert_eq!(
        en.counters()
            .facts_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch),
        1
    );
    assert_eq!(
        en.counters()
            .facts_dns_anomaly(DnsAnomalyKind::BailiwickViolation),
        0
    );
}

#[test]
fn note_fact_downgrade_to_plain_passes_through_to_the_monitor() {
    let t = block_connection_table();
    let mut en = en(t);
    en.note_fact_downgrade_to_plain();
    assert_eq!(en.counters().facts_downgrade_to_plain(), 1);
    assert_eq!(
        en.counters().facts_total(),
        1,
        "the downgrade fact folds into the aggregate fact total"
    );
}

#[test]
fn note_fact_probe_relocation_passes_through_to_the_monitor() {
    let t = block_connection_table();
    let mut en = en(t);
    en.note_fact_probe_relocation();
    en.note_fact_probe_relocation();
    assert_eq!(en.counters().facts_probe_relocations(), 2);
    assert_eq!(
        en.counters().facts_total(),
        2,
        "the probe-relocation fact folds into the aggregate fact total"
    );
}

#[test]
fn note_fact_expired_pin_cert_passes_through_to_the_monitor() {
    let t = block_connection_table();
    let mut en = en(t);
    en.note_fact_expired_pin_cert();
    assert_eq!(en.counters().facts_expired_pin_certs(), 1);
    assert_eq!(
        en.counters().facts_total(),
        1,
        "the expired-pin-cert fact folds into the aggregate fact total"
    );
}

#[test]
fn any_illegal_folds_every_fact_by_exact_cause_and_latches_all_once() {
    let t = block_all_table();
    let mut en = en_gated(
        t,
        GateSet::new(
            gate(10, 60),
            gate(3, 60),
            AllScopeGate::default(),
            AllScopeGate::default(),
        ),
    );
    let first = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: crate::enforcement::policy::AnyIllegalCause::HostNotAllowlisted,
        },
        0,
    );
    assert_eq!(
        first,
        Effect::BaselineOnly,
        "SP-001: one HostNotAllowlisted fact must not arm the illegal_fqdn latch"
    );
    assert!(!en.block_all());
    assert_eq!(
        en.counters()
            .facts_any_illegal(AnyIllegalCause::HostNotAllowlisted),
        1
    );
    assert_eq!(en.counters().facts_any_illegal_total(), 1);
    let second = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::TlsProfile(HelloRejectReason::ServerNameMismatch),
        },
        1,
    );
    assert_eq!(second, Effect::BaselineOnly);
    assert!(
        !en.block_all(),
        "a bad_handshake-class fact never arms the illegal_fqdn gate"
    );
    assert_eq!(
        en.counters().facts_any_illegal(AnyIllegalCause::TlsProfile(
            HelloRejectReason::ServerNameMismatch
        )),
        1,
        "a later AnyIllegal fact still folds by its exact cause"
    );
    assert_eq!(en.counters().facts_any_illegal_total(), 2);
    let third = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::HostNotAllowlisted,
        },
        2,
    );
    assert_eq!(
        third,
        Effect::BaselineOnly,
        "two HostNotAllowlisted facts are still below the illegal_fqdn threshold"
    );
    let fourth = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::HostNotAllowlisted,
        },
        3,
    );
    assert_eq!(
        fourth,
        Effect::Block { scope: Scope::All },
        "the third HostNotAllowlisted fact within the window crosses the illegal_fqdn threshold"
    );
    assert!(en.block_all());
    assert_eq!(
        en.counters().actions_block_all(),
        1,
        "the All latch records one transition"
    );
    let fifth = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::HostNotAllowlisted,
        },
        4,
    );
    assert_eq!(
        fifth,
        Effect::Block { scope: Scope::All },
        "once armed the All latch stays armed for later HostNotAllowlisted facts"
    );
    assert!(en.block_all());
    assert_eq!(
        en.counters().facts_any_illegal_total(),
        5,
        "every AnyIllegal fact folds regardless of the gating"
    );
}

#[test]
fn wrong_port_and_transfer_encoding_fold_into_distinct_cause_counters() {
    let t = block_all_table();
    let mut en = en(t);
    let mut latch = FirstIllegalLatch::new();
    en.decide(
        &mut latch,
        Violation::AnyIllegal {
            cause: AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort),
        },
        0,
    );
    en.decide(
        &mut latch,
        Violation::AnyIllegal {
            cause: AnyIllegalCause::ConnectParse(ConnectHeadReason::TransferEncoding),
        },
        1,
    );
    assert_eq!(
        en.counters()
            .facts_any_illegal(AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort)),
        1,
        "WrongPort folds into its own counter"
    );
    assert_eq!(
        en.counters()
            .facts_any_illegal(AnyIllegalCause::ConnectParse(
                ConnectHeadReason::TransferEncoding
            )),
        1,
        "TransferEncoding folds into its own distinct counter"
    );
    assert_eq!(en.counters().facts_any_illegal_total(), 2);
}

#[test]
fn early_data_block_domain_sets_bitset_and_counts() {
    let t = domain_actions_table();
    let mut en = en(t);
    let ordinal = t.ordinal(0).expect("ordinal");
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::EarlyUpstreamData { ordinal },
        0,
    );
    assert_eq!(
        effect,
        Effect::Block {
            scope: Scope::Domain
        },
        "a single early Block{{Domain}} applies immediately without corroboration"
    );
    assert!(en.test_blocked(ordinal));
    assert_eq!(en.counters().actions_domain_block(ordinal), 1);
    assert!(!en.block_all());
}

#[test]
fn early_data_notify_counts_per_ordinal() {
    let t = block_connection_table();
    let mut en = en(t);
    let mut latch = FirstIllegalLatch::new();
    let ordinal = t.ordinal(0).expect("ordinal");
    assert_eq!(
        en.decide(&mut latch, Violation::EarlyUpstreamData { ordinal }, 0),
        Effect::Notify {
            scope: Scope::Connection
        }
    );
    assert_eq!(en.counters().actions_notify(ordinal), 1);
    assert_eq!(en.counters().actions_domain_block(ordinal), 0);
}

#[test]
fn all_transition_is_a_derived_latch_count_not_a_duplicate_action_total() {
    let t = block_all_table();
    let mut en = en_gated(t, gates_illegal_fqdn(3, 60));
    for i in 0..3u64 {
        en.decide(
            &mut FirstIllegalLatch::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
            i,
        );
    }
    assert!(
        en.block_all(),
        "three HostNotAllowlisted facts arm the illegal_fqdn latch"
    );
    assert_eq!(
        en.counters().actions_block_all(),
        1,
        "the All latch records one transition"
    );
    assert_eq!(
        en.counters().actions_total(),
        1,
        "M2: the one applied first-slot Block is the only action counted; ba is a derived view"
    );
}

#[test]
fn block_all_latch_counts_the_transition_once_not_every_all_application() {
    let t = table(
        any_controls(ActionKind::Block, Scope::All),
        &[(ActionKind::Block, Scope::All); 2],
        &[(ActionKind::Block, Scope::All); 2],
    );
    let mut en = en_gated(
        t,
        GateSet::new(
            AllScopeGate::default(),
            gate(3, 60),
            gate(3, 60),
            AllScopeGate::default(),
        ),
    );
    let ordinal = t.ordinal(0).expect("big table ordinal");
    for i in 0..3u64 {
        en.decide(
            &mut FirstIllegalLatch::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
            i,
        );
    }
    assert!(
        en.block_all(),
        "three HostNotAllowlisted facts arm the illegal_fqdn latch"
    );
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::EarlyUpstreamData { ordinal },
        10,
    );
    assert_eq!(
        effect,
        Effect::BaselineOnly,
        "a single early-data All application is below the early_data gate"
    );
    assert!(
        en.block_all(),
        "an early-data downgrade keeps the All latch"
    );
    assert_eq!(
        en.counters().actions_block_all(),
        1,
        "L1: the latch transition counts once even across a later All application"
    );
}

#[test]
fn early_data_unknown_outcome_is_one_detection_fact_not_two() {
    let small = block_connection_table();
    let mut en = en(small);
    let mut latch = FirstIllegalLatch::new();
    let big = table(
        any_controls(ActionKind::Block, Scope::Connection),
        &[(ActionKind::Block, Scope::All); 2],
        &[(ActionKind::Block, Scope::All); 2],
    );
    let unbound = big.ordinal(1).expect("big table ordinal");
    let effect = en.decide(
        &mut latch,
        Violation::EarlyUpstreamData { ordinal: unbound },
        0,
    );
    assert!(matches!(effect, Effect::Unknown { .. }));
    assert_eq!(
        en.counters().facts_total(),
        1,
        "M2: an early-data Unknown outcome is one detection event, not two"
    );
    assert_eq!(
        en.counters().facts_early_data(unbound),
        1,
        "the detection is typed as early upstream data on its ordinal"
    );
    assert_eq!(
        en.counters().facts_unknown(UnknownReason::UnboundOrdinal),
        0,
        "M2: the Unknown is the outcome, carried by the correlation, not a second fact"
    );
}

#[test]
fn unbound_and_insufficient_evidence_fold_unknown_by_reason_not_baseline() {
    let small = block_all_table();
    let mut en = en(small);
    let mut latch = FirstIllegalLatch::new();
    let big = table(
        any_controls(ActionKind::Block, Scope::All),
        &[(ActionKind::Block, Scope::All); 2],
        &[(ActionKind::Block, Scope::All); 2],
    );
    let unbound = big.ordinal(1).expect("big table ordinal");
    let effect = en.decide(
        &mut latch,
        Violation::EarlyUpstreamData { ordinal: unbound },
        0,
    );
    assert!(matches!(
        effect,
        Effect::Unknown {
            reason: UnknownReason::UnboundOrdinal
        }
    ));
    assert_eq!(
        en.counters().facts_early_data(unbound),
        1,
        "the early-data detection folds its own fact exactly once"
    );
    assert_eq!(
        en.counters().facts_unknown(UnknownReason::UnboundOrdinal),
        0,
        "M2: an early-data Unknown outcome is one detection fact, not a second unknown"
    );
    assert_eq!(en.counters().unknown_total(), 0);
    assert_eq!(
        en.decide(&mut latch, Violation::EvidenceInsufficient, 0),
        Effect::Unknown {
            reason: UnknownReason::NotYetValidated
        }
    );
    assert_eq!(
        en.counters().facts_unknown(UnknownReason::NotYetValidated),
        1
    );
    assert_eq!(en.counters().unknown_total(), 1);
    assert!(!en.block_all(), "Unknown must never set the All latch");
}

#[test]
fn missing_result_and_unattributed_fold_distinct_unknown_never_block() {
    let t = all_actions_table();
    let mut en = en(t);
    let mut latch = FirstIllegalLatch::new();
    let effect = en.decide(&mut latch, Violation::MissingParseResult, 0);
    assert_eq!(
        effect,
        Effect::Unknown {
            reason: UnknownReason::MissingParseResult
        }
    );
    assert!(
        !matches!(effect, Effect::Block { .. }),
        "a missing internal parse result must never latch Block-All"
    );
    let effect = en.decide(&mut latch, Violation::Unattributed, 0);
    assert_eq!(
        effect,
        Effect::Unknown {
            reason: UnknownReason::Unattributed
        }
    );
    assert!(!en.block_all());
    assert_eq!(
        en.counters()
            .facts_unknown(UnknownReason::MissingParseResult),
        1
    );
    assert_eq!(en.counters().facts_unknown(UnknownReason::Unattributed), 1);
    assert!(
        !en.test_blocked(t.ordinal(0).expect("ordinal")),
        "Unknown must never mark a configured domain blocked"
    );
}

#[test]
fn windowed_counter_arms_at_threshold_within_window_and_stays_armed() {
    let mut c = WindowedCounter::new(3, 60);
    assert!(!c.note(0), "below the fixed threshold");
    assert!(!c.note(1), "below the fixed threshold");
    assert!(c.note(2), "the threshold is crossed within the window");
    assert!(c.note(3), "once armed the counter stays armed");
    assert!(
        c.note(100),
        "the armed state persists past the window until restart"
    );
}

#[test]
fn windowed_counter_rebases_when_the_window_expires() {
    let mut c = WindowedCounter::new(3, 60);
    assert!(!c.note(0));
    assert!(!c.note(1));
    assert!(
        !c.note(61),
        "61 - 0 >= 60: the expired window rebases the count to a fresh window"
    );
    assert!(!c.note(62));
    assert!(
        c.note(63),
        "three facts in the fresh window cross the threshold"
    );
}

#[test]
fn windowed_counter_uses_configured_window() {
    let mut c = WindowedCounter::new(2, 10);
    assert!(!c.note(0), "below the configured threshold");
    assert!(
        c.note(5),
        "the configured threshold is crossed within the configured window"
    );
    assert!(c.note(6), "once armed the counter stays armed");
    let mut rebased = WindowedCounter::new(2, 10);
    assert!(!rebased.note(0));
    assert!(
        !rebased.note(11),
        "11 - 0 >= 10: the expired configured window rebases the count"
    );
    assert!(
        rebased.note(12),
        "two facts in the fresh window cross the configured threshold"
    );
}

#[test]
fn single_any_illegal_below_threshold_never_latches_all() {
    let t = all_actions_table();
    let mut en = en_gated(t, gates_illegal_fqdn(3, 60));
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::HostNotAllowlisted,
        },
        0,
    );
    assert_eq!(
        effect,
        Effect::BaselineOnly,
        "SP-001: a single unauthenticated HostNotAllowlisted must not arm the illegal_fqdn latch"
    );
    assert!(!en.block_all());
    assert_eq!(en.counters().actions_block_all(), 0);
    assert_eq!(en.counters().actions_total(), 0);
}

#[test]
fn three_any_illegal_facts_within_the_window_latch_all() {
    let t = all_actions_table();
    let mut en = en_gated(t, gates_illegal_fqdn(3, 60));
    assert_eq!(
        en.decide(
            &mut FirstIllegalLatch::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
            0,
        ),
        Effect::BaselineOnly
    );
    assert_eq!(
        en.decide(
            &mut FirstIllegalLatch::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
            1,
        ),
        Effect::BaselineOnly
    );
    assert_eq!(
        en.decide(
            &mut FirstIllegalLatch::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
            2,
        ),
        Effect::Block { scope: Scope::All },
        "the third HostNotAllowlisted fact within the window crosses the illegal_fqdn threshold"
    );
    assert!(en.block_all());
}

#[test]
fn single_any_illegal_arms_all_scope_at_default_threshold() {
    let t = all_actions_table();
    let mut en = en(t);
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::HostNotAllowlisted,
        },
        0,
    );
    assert_eq!(
        effect,
        Effect::Block { scope: Scope::All },
        "SP-001 default: the FIRST deviation arms the All-scope block"
    );
    assert!(en.block_all());
    assert_eq!(en.counters().actions_block_all(), 1);
}

#[test]
fn per_control_any_illegal_notify_is_recorded_as_first_slot_action() {
    let t = notify_connection_table();
    let mut en = en(t);
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::HostNotAllowlisted,
        },
        0,
    );
    assert_eq!(
        effect,
        Effect::Notify {
            scope: Scope::Connection
        },
        "a notify-configured any_illegal control fires Notify on its first occurrence"
    );
    assert_eq!(
        en.counters().actions_first_slot_block(Scope::Connection),
        1,
        "the first-slot action is recorded by scope regardless of kind"
    );
    assert!(!en.block_all());
}

#[test]
fn per_fqdn_all_scope_block_is_gated_by_sp001() {
    let t = all_actions_table();
    let mut en = en_gated(
        t,
        GateSet::new(
            AllScopeGate::default(),
            AllScopeGate::default(),
            gate(3, 60),
            AllScopeGate::default(),
        ),
    );
    let ordinal = t.ordinal(0).expect("ordinal");
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::EarlyUpstreamData { ordinal },
        0,
    );
    assert_eq!(
        effect,
        Effect::BaselineOnly,
        "SP-001: a single per-FQDN All-scope block must not arm the early_data latch"
    );
    assert!(!en.block_all());
    assert_eq!(en.counters().actions_domain_block(ordinal), 0);
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::EarlyUpstreamData { ordinal },
        1,
    );
    assert_eq!(
        effect,
        Effect::BaselineOnly,
        "two early-data All facts still below the early_data gate"
    );
    assert_eq!(en.counters().actions_domain_block(ordinal), 0);
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::EarlyUpstreamData { ordinal },
        2,
    );
    assert_eq!(
        effect,
        Effect::Block { scope: Scope::All },
        "the third early-data All fact crosses the early_data gate"
    );
    assert!(en.block_all());
    assert_eq!(
        en.counters().actions_domain_block(ordinal),
        1,
        "the crossing application is the first per-FQDN All block"
    );
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::EarlyUpstreamData { ordinal },
        10,
    );
    assert_eq!(
        effect,
        Effect::Block { scope: Scope::All },
        "once armed, a per-FQDN All-scope block applies"
    );
    assert_eq!(
        en.counters().actions_domain_block(ordinal),
        2,
        "the armed application is the second per-FQDN All block"
    );
}

#[test]
fn ja4_change_projects_the_per_fqdn_action() {
    let t = table(
        any_controls(ActionKind::Block, Scope::Connection),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Block, Scope::Domain)],
    );
    let mut en = en(t);
    let ordinal = t.ordinal(0).expect("ordinal");
    let effect = en.decide(&mut FirstIllegalLatch::new(), Violation::Ja4Change { ordinal }, 0);
    assert_eq!(
        effect,
        Effect::Block {
            scope: Scope::Domain
        },
        "a ja4 change projects the per-FQDN ja4 control's action"
    );
    assert_eq!(en.counters().actions_domain_block(ordinal), 1);
    assert!(en.test_blocked(ordinal));
    assert_eq!(
        en.counters().facts_total(),
        0,
        "the ja4-change fact itself is noted by the serving path, not here"
    );
}

#[test]
fn bad_handshake_facts_never_arm_the_illegal_fqdn_gate() {
    let t = all_actions_table();
    let mut en = en_gated(
        t,
        GateSet::new(
            gate(10, 60),
            gate(3, 60),
            AllScopeGate::default(),
            AllScopeGate::default(),
        ),
    );
    for i in 0..3u64 {
        let effect = en.decide(
            &mut FirstIllegalLatch::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort),
            },
            i,
        );
        assert_eq!(
            effect,
            Effect::BaselineOnly,
            "bad_handshake facts stay below the high bad_handshake gate"
        );
    }
    assert!(
        !en.block_all(),
        "bad_handshake facts never arm the illegal_fqdn gate"
    );
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::HostNotAllowlisted,
        },
        3,
    );
    assert_eq!(
        effect,
        Effect::BaselineOnly,
        "a single HostNotAllowlisted is below illegal_fqdn 3/60: bad_handshake facts did not count toward illegal_fqdn"
    );
    assert!(!en.block_all());
}

#[test]
fn illegal_fqdn_facts_never_arm_the_bad_handshake_gate() {
    let t = all_actions_table();
    let mut en = en_gated(
        t,
        GateSet::new(
            gate(3, 60),
            gate(10, 60),
            AllScopeGate::default(),
            AllScopeGate::default(),
        ),
    );
    for i in 0..3u64 {
        let effect = en.decide(
            &mut FirstIllegalLatch::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
            i,
        );
        assert_eq!(
            effect,
            Effect::BaselineOnly,
            "illegal_fqdn facts stay below the high illegal_fqdn gate"
        );
    }
    assert!(
        !en.block_all(),
        "illegal_fqdn facts never arm the bad_handshake gate"
    );
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort),
        },
        3,
    );
    assert_eq!(
        effect,
        Effect::BaselineOnly,
        "a single ConnectParse is below bad_handshake 3/60: illegal_fqdn facts did not count toward bad_handshake"
    );
    assert!(!en.block_all());
}

#[test]
fn early_data_and_ja4_gates_are_isolated() {
    let (t, mut en) = isolated_gate_arrangement(gate(3, 60), gate(10, 60));
    let ordinal = t.ordinal(0).expect("ordinal");
    for i in 0..3u64 {
        let effect = en.decide(&mut FirstIllegalLatch::new(), Violation::Ja4Change { ordinal }, i);
        assert_eq!(
            effect,
            Effect::BaselineOnly,
            "ja4 facts stay below the high ja4 gate"
        );
    }
    assert!(!en.block_all(), "ja4 facts never arm the early_data gate");
    let effect = decide_at(&mut en, Violation::EarlyUpstreamData { ordinal }, 3);
    assert_eq!(
        effect,
        Effect::BaselineOnly,
        "a single EarlyUpstreamData Block-All is below early_data 3/60: ja4 facts did not count toward early_data"
    );
    assert!(!en.block_all());
    let (_, mut en) = isolated_gate_arrangement(gate(10, 60), gate(3, 60));
    for i in 0..3u64 {
        let effect = decide_at(&mut en, Violation::EarlyUpstreamData { ordinal }, i);
        assert_eq!(
            effect,
            Effect::BaselineOnly,
            "early_data facts stay below the high early_data gate"
        );
    }
    assert!(!en.block_all(), "early_data facts never arm the ja4 gate");
    let effect = decide_at(&mut en, Violation::Ja4Change { ordinal }, 3);
    assert_eq!(
        effect,
        Effect::BaselineOnly,
        "a single Ja4Change Block-All is below ja4 3/60: early_data facts did not count toward ja4"
    );
    assert!(!en.block_all());
}

#[test]
fn single_bad_handshake_fact_arms_bad_handshake_not_illegal_fqdn() {
    let t = all_actions_table();
    let mut en = en_gated(
        t,
        GateSet::new(
            AllScopeGate::default(),
            gate(3, 60),
            AllScopeGate::default(),
            AllScopeGate::default(),
        ),
    );
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort),
        },
        0,
    );
    assert_eq!(
        effect,
        Effect::Block { scope: Scope::All },
        "SP-001 default: the FIRST bad_handshake fact arms the bad_handshake gate"
    );
    assert!(en.block_all(), "bad_handshake latches all-scope block");
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::HostNotAllowlisted,
        },
        1,
    );
    assert_eq!(
        effect,
        Effect::BaselineOnly,
        "a single HostNotAllowlisted is below illegal_fqdn 3/60: the bad_handshake arm did not arm illegal_fqdn"
    );
}

#[test]
fn any_illegal_notify_still_counts_its_class_facts() {
    let controls = [
        Control::new(ActionKind::Notify, Scope::Connection),
        Control::new(ActionKind::Notify, Scope::Connection),
        Control::new(ActionKind::Block, Scope::All),
        Control::new(ActionKind::Notify, Scope::Connection),
    ];
    let t = table(
        controls,
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Notify, Scope::Connection)],
    );
    let mut en = en_gated(
        t,
        GateSet::new(
            gate(3, 60),
            AllScopeGate::default(),
            AllScopeGate::default(),
            AllScopeGate::default(),
        ),
    );
    for i in 0..3u64 {
        let effect = en.decide(
            &mut FirstIllegalLatch::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort),
            },
            i,
        );
        assert_eq!(
            effect,
            Effect::Notify {
                scope: Scope::Connection
            },
            "notify-configured connect_parse fires Notify"
        );
    }
    assert!(!en.block_all(), "Notify never latches all-scope block");
    let effect = en.decide(
        &mut FirstIllegalLatch::new(),
        Violation::AnyIllegal {
            cause: AnyIllegalCause::TlsProfile(HelloRejectReason::ServerNameMismatch),
        },
        3,
    );
    assert_eq!(
        effect,
        Effect::Block { scope: Scope::All },
        "the three notify-configured bad_handshake facts armed the bad_handshake gate, so the Block-All tls_profile fact applies"
    );
    assert!(en.block_all());
}

#[test]
fn early_data_and_ja4_count_only_on_block_all() {
    let (t, mut en) = count_only_arrangement();
    let notify_ordinal = t.ordinal(0).expect("ordinal");
    let block_ordinal = t.ordinal(1).expect("ordinal");
    let notify_early = Violation::EarlyUpstreamData {
        ordinal: notify_ordinal,
    };
    let block_early = Violation::EarlyUpstreamData {
        ordinal: block_ordinal,
    };
    let notify_ja4 = Violation::Ja4Change {
        ordinal: notify_ordinal,
    };
    let block_ja4 = Violation::Ja4Change {
        ordinal: block_ordinal,
    };
    for i in 0..3u64 {
        let effect = decide_at(&mut en, notify_early, i);
        assert_eq!(
            effect,
            Effect::Notify {
                scope: Scope::Connection
            },
            "notify-configured early_data fires Notify"
        );
    }
    let effect = decide_at(&mut en, block_early, 3);
    assert_eq!(
        effect,
        Effect::BaselineOnly,
        "the three Notify early_data facts did NOT count toward early_data: a single Block-All early_data fact is below early_data 3/60"
    );
    assert!(!en.block_all());
    for i in 0..3u64 {
        let effect = decide_at(&mut en, notify_ja4, i);
        assert_eq!(
            effect,
            Effect::Notify {
                scope: Scope::Connection
            },
            "notify-configured ja4 fires Notify"
        );
    }
    let effect = decide_at(&mut en, block_ja4, 3);
    assert_eq!(
        effect,
        Effect::BaselineOnly,
        "the three Notify ja4 facts did NOT count toward ja4: a single Block-All ja4 fact is below ja4 3/60"
    );
    assert!(!en.block_all());
}

/// A Hegel state machine over `EnforcementState::decide`, asserting the gate and
/// latch invariants after every rule.
///
/// The model draws its own `ControlTable` (an action/scope for each of the
/// four `any_illegal` surfaces and for each of 1..=3 per-ordinal
/// `early_data`/`ja4` entries) and its own `GateSet` (every class's threshold
/// and window drawn from 1..=3, so a window rollover fits inside one case).
/// Rules draw only their violation parameters; `secs` is the model's logical
/// clock, advanced by a drawn step, so same-second facts increment a window
/// and a clock step can roll it. The model keeps *its own* per-class window
/// arithmetic and its own attribution of facts to classes; the subject's gate
/// counters are read only as the comparison target of E5, never as the source
/// of E4's crossing decision.
///
/// Invariants (each `always_run`, so every intermediate state is checked):
///
/// - **E1 monotonicity**: the All-scope block latch and the per-ordinal
///   blocked bits only ever go false -> true. E1 also pins the blocked bitset
///   to the model's own expectation, so a bit set by the wrong class fails.
/// - **E2 first-slot latch**: `Armed -> Spent` only; a decision carrying an
///   `AnyIllegal` leaves it `Spent`, and a per-FQDN or unknown decision leaves
///   it untouched — a per-FQDN violation never consumes the per-connection
///   latch.
/// - **E3 action-after-fact**: every decision that notes a fact increments
///   exactly that counter by one, and an effect is `Block`/`Notify` only when
///   its fact was counted. `Ja4Change` is the documented exception: its fact
///   is noted by the serving path, not by `decide`, so the machine instead
///   asserts that a `Ja4Change` decision changes no fact total.
/// - **E4 per-class gate independence**: `block_all` is true exactly when one
///   class's own crossing has admitted an All-scope block, computed from the
///   model's per-class window arithmetic and class attribution. This is
///   deliberately *not* "`block_all` iff any gate is armed": a gate arms on the
///   connection that noted its crossing fact even when that class's All-scope
///   block cannot apply (for example the first-slot latch is already `Spent`,
///   so every later `AnyIllegal` projects `BaselineOnly`). The model therefore
///   records the crossing and the admission separately, which is why it is not
///   a mirror of the subject's `block_all` field.
/// - **E5 window arithmetic**: for every class the subject's `armed`, `count`,
///   `window_start`, `threshold`, and `window_secs` equal the model's own
///   re-derivation (`secs - window_start >= window_secs` rolls, otherwise
///   increments; an armed counter freezes).
/// - **E6 saturating counters never gate**: see `SaturationModel`.
///
/// bd `alumina-mxlil` disposition: the production overflow path needs
/// `u32::MAX` increments (infeasible), there is no production-blessed near-max
/// seed, and adding a bump-by-N seam is out of scope. The machine therefore
/// drives the existing `#[cfg(test)]` saturation seam and proves the
/// *no-gating* property — the load-bearing claim — rather than the overflow
/// arithmetic itself. No new seam was added and no production code changed.
mod hegel_machine {
    use super::enforcement_tables::table;
    use super::gate;
    use crate::enforcement::action::{
        ActionKind, AnyIllegalControl, Control, ControlTable, DomainOrdinal, FirstIllegalLatch, Scope,
    };
    use crate::enforcement::policy::{
        AnyIllegalCause, Effect, UnknownReason, Violation, decide as pure_decide,
    };
    use crate::enforcement::state::{AllScopeGate, EnforcementState, GateSet, WindowedCounter};
    use crate::inspection::client_hello::HelloRejectReason;
    use crate::inspection::connect::ConnectHeadReason;
    use hegel::TestCase;

    // ---------------------------------------------------------------------
    // Drawn boot configuration and rule parameters.
    // ---------------------------------------------------------------------

    fn draw_index(tc: &TestCase, max: usize) -> usize {
        tc.draw(
            hegel::generators::integers::<usize>()
                .min_value(0)
                .max_value(max),
        )
    }

    /// One drawn `(kind, scope)` control; all six legal combinations, because
    /// the gate arithmetic must be independent of which action a class fires.
    fn drawn_control(tc: &TestCase) -> Control {
        match draw_index(tc, 5) {
            0 => Control::new(ActionKind::Block, Scope::All),
            1 => Control::new(ActionKind::Block, Scope::Domain),
            2 => Control::new(ActionKind::Block, Scope::Connection),
            3 => Control::new(ActionKind::Notify, Scope::All),
            4 => Control::new(ActionKind::Notify, Scope::Domain),
            _ => Control::new(ActionKind::Notify, Scope::Connection),
        }
    }

    fn drawn_actions(tc: &TestCase, count: usize) -> Vec<(ActionKind, Scope)> {
        (0..count)
            .map(|_| {
                let control = drawn_control(tc);
                (control.kind(), control.scope())
            })
            .collect()
    }

    fn drawn_table(tc: &TestCase) -> ControlTable {
        let mut any = [Control::new(ActionKind::Block, Scope::All); AnyIllegalControl::COUNT];
        for control in &mut any {
            *control = drawn_control(tc);
        }
        let count = draw_index(tc, 2) + 1;
        table(any, &drawn_actions(tc, count), &drawn_actions(tc, count))
    }

    /// Thresholds and windows both from 1..=3, so a threshold crossing and a
    /// window rollover are both reachable inside one drawn case.
    fn drawn_gate(tc: &TestCase) -> AllScopeGate {
        let threshold = tc.draw(
            hegel::generators::integers::<u32>()
                .min_value(1)
                .max_value(3),
        );
        let window = tc.draw(
            hegel::generators::integers::<u64>()
                .min_value(1)
                .max_value(3),
        );
        gate(threshold, window)
    }

    fn drawn_gates(tc: &TestCase) -> GateSet {
        GateSet::new(
            drawn_gate(tc),
            drawn_gate(tc),
            drawn_gate(tc),
            drawn_gate(tc),
        )
    }

    /// The four `any_illegal` classes' representative causes. `TlsProfile`
    /// never carries `EchPresent`: the production constructor routes it to
    /// `Ech`, so the drawn set stays on reachable causes.
    fn drawn_any_illegal_cause(tc: &TestCase) -> AnyIllegalCause {
        match draw_index(tc, 6) {
            0 => AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort),
            1 => AnyIllegalCause::ConnectParse(ConnectHeadReason::TransferEncoding),
            2 => AnyIllegalCause::HostNotAllowlisted,
            3 => AnyIllegalCause::TlsProfile(HelloRejectReason::ServerNameMismatch),
            4 => AnyIllegalCause::TlsProfile(HelloRejectReason::InvalidServerName),
            5 => AnyIllegalCause::TlsProfile(HelloRejectReason::Profile),
            _ => AnyIllegalCause::Ech,
        }
    }

    // ---------------------------------------------------------------------
    // The gate/latch model.
    // ---------------------------------------------------------------------

    /// The four independent gate classes, in `GateSet` order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum GateClass {
        BadHandshake,
        IllegalFqdn,
        EarlyData,
        Ja4,
    }

    const GATE_CLASSES: [GateClass; 4] = [
        GateClass::BadHandshake,
        GateClass::IllegalFqdn,
        GateClass::EarlyData,
        GateClass::Ja4,
    ];

    impl GateClass {
        const fn index(self) -> usize {
            match self {
                GateClass::BadHandshake => 0,
                GateClass::IllegalFqdn => 1,
                GateClass::EarlyData => 2,
                GateClass::Ja4 => 3,
            }
        }
    }

    /// The model's per-class bookkeeping: the windowed counts it derives
    /// itself, and whether a crossing of this class has admitted an All-scope
    /// block (E4's admission, distinct from the crossing).
    #[derive(Clone, Copy, Debug)]
    struct ModelGate {
        count: u32,
        window_start: u64,
        armed: bool,
        admitted_all: bool,
        threshold: u32,
        window_secs: u64,
    }

    impl ModelGate {
        const fn new(gate: AllScopeGate) -> ModelGate {
            ModelGate {
                count: 0,
                window_start: 0,
                armed: false,
                admitted_all: false,
                threshold: gate.threshold(),
                window_secs: gate.window_secs(),
            }
        }

        /// The model's own window arithmetic, re-derived from the documented
        /// rule: a fact at `secs` rolls the window when
        /// `secs - window_start >= window_secs`, otherwise increments; an
        /// armed counter freezes.
        fn note(&mut self, secs: u64) -> bool {
            if self.armed {
                return true;
            }
            if secs.saturating_sub(self.window_start) >= self.window_secs {
                self.count = 0;
                self.window_start = secs;
            }
            self.count += 1;
            if self.count >= self.threshold {
                self.armed = true;
            }
            self.armed
        }
    }

    fn subject_gate(en: &EnforcementState, class: GateClass) -> &WindowedCounter {
        match class {
            GateClass::BadHandshake => &en.bad_handshake_gate,
            GateClass::IllegalFqdn => &en.illegal_fqdn_gate,
            GateClass::EarlyData => &en.early_data_gate,
            GateClass::Ja4 => &en.ja4_gate,
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum StepKind {
        Time,
        AnyIllegal,
        EarlyData,
        Ja4,
        Unknown,
    }

    /// What the last rule decided, kept so the `always_run` invariants can
    /// check the fact/action and latch relations of the just-applied step.
    #[derive(Clone, Copy, Debug)]
    struct LastStep {
        kind: StepKind,
        latch_before: FirstIllegalLatch,
        fact_before: u32,
        fact_after: u32,
        fact_tracked: bool,
        total_before: u64,
        total_after: u64,
        effect: Effect,
        expected_effect: Effect,
    }

    impl LastStep {
        const INITIAL: LastStep = LastStep {
            kind: StepKind::Time,
            latch_before: FirstIllegalLatch::Armed,
            fact_before: 0,
            fact_after: 0,
            fact_tracked: false,
            total_before: 0,
            total_after: 0,
            effect: Effect::BaselineOnly,
            expected_effect: Effect::BaselineOnly,
        };
    }

    struct GateModel {
        en: EnforcementState,
        table: ControlTable,
        gates: [ModelGate; 4],
        latch: FirstIllegalLatch,
        now: u64,
        expected_blocked: u32,
        prev_block_all: bool,
        prev_blocked: u32,
        prev_latch: FirstIllegalLatch,
        last: LastStep,
    }

    impl GateModel {
        fn new(table: ControlTable, gates: GateSet) -> GateModel {
            GateModel {
                en: EnforcementState::new(table, gates),
                table,
                gates: [
                    ModelGate::new(gates.bad_handshake()),
                    ModelGate::new(gates.illegal_fqdn()),
                    ModelGate::new(gates.early_data()),
                    ModelGate::new(gates.ja4()),
                ],
                latch: FirstIllegalLatch::new(),
                now: 0,
                expected_blocked: 0,
                prev_block_all: false,
                prev_blocked: 0,
                prev_latch: FirstIllegalLatch::Armed,
                last: LastStep::INITIAL,
            }
        }

        /// Snapshot the subject before a rule so the monotonicity invariants
        /// compare against the previous step, not a constant.
        fn begin(&mut self) {
            self.prev_block_all = self.en.block_all();
            self.prev_blocked = self.subject_blocked_mask();
            self.prev_latch = self.latch;
        }

        fn subject_blocked_mask(&self) -> u32 {
            let mut mask = 0;
            for index in 0..self.table.len() {
                let ordinal = self.table.ordinal(index).expect("index below table len");
                if self.en.is_blocked(ordinal) {
                    mask |= 1u32 << ordinal.get();
                }
            }
            mask
        }

        /// The monitor fact counter this violation must fold exactly once, or
        /// `None` when `decide` does not note a fact for it (`Ja4Change`).
        fn fact_counter(&self, violation: Violation) -> Option<u32> {
            let counters = self.en.counters();
            match violation {
                Violation::AnyIllegal { cause } => Some(counters.facts_any_illegal(cause)),
                Violation::EarlyUpstreamData { ordinal } => {
                    Some(counters.facts_early_data(ordinal))
                }
                Violation::EvidenceInsufficient => {
                    Some(counters.facts_unknown(UnknownReason::NotYetValidated))
                }
                Violation::Unattributed => {
                    Some(counters.facts_unknown(UnknownReason::Unattributed))
                }
                Violation::MissingParseResult => {
                    Some(counters.facts_unknown(UnknownReason::MissingParseResult))
                }
                Violation::Ja4Change { .. } => None,
            }
        }

        const fn gate_class(violation: Violation, raw: Effect) -> Option<GateClass> {
            match violation {
                Violation::AnyIllegal { cause } => Some(match cause {
                    AnyIllegalCause::HostNotAllowlisted => GateClass::IllegalFqdn,
                    AnyIllegalCause::ConnectParse(_)
                    | AnyIllegalCause::TlsProfile(_)
                    | AnyIllegalCause::Ech => GateClass::BadHandshake,
                }),
                Violation::EarlyUpstreamData { .. } => {
                    if matches!(raw, Effect::Block { scope: Scope::All }) {
                        Some(GateClass::EarlyData)
                    } else {
                        None
                    }
                }
                Violation::Ja4Change { .. } => {
                    if matches!(raw, Effect::Block { scope: Scope::All }) {
                        Some(GateClass::Ja4)
                    } else {
                        None
                    }
                }
                Violation::EvidenceInsufficient
                | Violation::Unattributed
                | Violation::MissingParseResult => None,
            }
        }

        const fn step_kind(violation: Violation) -> StepKind {
            match violation {
                Violation::AnyIllegal { .. } => StepKind::AnyIllegal,
                Violation::EarlyUpstreamData { .. } => StepKind::EarlyData,
                Violation::Ja4Change { .. } => StepKind::Ja4,
                Violation::EvidenceInsufficient
                | Violation::Unattributed
                | Violation::MissingParseResult => StepKind::Unknown,
            }
        }

        const fn per_fqdn_ordinal(violation: Violation) -> Option<DomainOrdinal> {
            match violation {
                Violation::EarlyUpstreamData { ordinal } | Violation::Ja4Change { ordinal } => {
                    Some(ordinal)
                }
                Violation::AnyIllegal { .. }
                | Violation::EvidenceInsufficient
                | Violation::Unattributed
                | Violation::MissingParseResult => None,
            }
        }

        /// Apply one violation: note the class gate from the model's own
        /// arithmetic, project the gated effect the model expects, then let
        /// the subject decide and record the observation the invariants read.
        fn step(&mut self, tc: &TestCase, violation: Violation) {
            self.begin();
            let mut probe = self.latch;
            let raw = pure_decide(&self.table, &mut probe, violation);
            let class = Self::gate_class(violation, raw);
            let class_index = class.map(GateClass::index);
            let (was_armed, window_start_before) = class_index.map_or((false, 0), |index| {
                (self.gates[index].armed, self.gates[index].window_start)
            });
            let crossed = class_index.is_some_and(|index| self.gates[index].note(self.now));
            if let Some(index) = class_index {
                if crossed && !was_armed {
                    tc.event("gate_armed");
                }
                if !was_armed && self.gates[index].window_start != window_start_before {
                    tc.event("window_rollover");
                }
                if !crossed {
                    tc.event("below_threshold");
                }
            }
            let expected_effect = match raw {
                Effect::Block { scope: Scope::All } if !crossed => Effect::BaselineOnly,
                other => other,
            };
            if matches!(expected_effect, Effect::Block { scope: Scope::All }) {
                tc.event("all_block_admitted");
            }
            let fact_before = self.fact_counter(violation);
            let total_before = self.en.counters().facts_total();
            let effect = self.en.decide(&mut self.latch, violation, self.now);
            let fact_after = self.fact_counter(violation);
            let total_after = self.en.counters().facts_total();
            match expected_effect {
                Effect::Block { scope: Scope::All } => {
                    let class = class.expect("an All-scope effect is attributed to a class");
                    self.gates[class.index()].admitted_all = true;
                }
                Effect::Block {
                    scope: Scope::Domain,
                } => {
                    if let Some(ordinal) = Self::per_fqdn_ordinal(violation) {
                        self.expected_blocked |= 1u32 << ordinal.get();
                    }
                }
                Effect::Block {
                    scope: Scope::Connection,
                }
                | Effect::Notify { .. }
                | Effect::BaselineOnly
                | Effect::Unknown { .. } => {}
            }
            self.last = LastStep {
                kind: Self::step_kind(violation),
                latch_before: self.prev_latch,
                fact_before: fact_before.unwrap_or(0),
                fact_after: fact_after.unwrap_or(0),
                fact_tracked: fact_before.is_some(),
                total_before,
                total_after,
                effect,
                expected_effect,
            };
        }

        fn advance_clock(&mut self, step: u64) {
            self.begin();
            self.now += step;
            self.last = LastStep {
                kind: StepKind::Time,
                latch_before: self.prev_latch,
                fact_before: 0,
                fact_after: 0,
                fact_tracked: false,
                total_before: self.en.counters().facts_total(),
                total_after: self.en.counters().facts_total(),
                effect: Effect::BaselineOnly,
                expected_effect: Effect::BaselineOnly,
            };
        }
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "the hegel state-machine macro hands each rule its own TestCase by value"
    )]
    #[hegel::state_machine]
    impl GateModel {
        #[rule]
        fn any_illegal(&mut self, tc: TestCase) {
            let cause = drawn_any_illegal_cause(&tc);
            self.step(&tc, Violation::AnyIllegal { cause });
        }

        #[rule]
        fn early_upstream_data(&mut self, tc: TestCase) {
            let index = draw_index(&tc, self.table.len() - 1);
            let ordinal = self
                .table
                .ordinal(index)
                .expect("drawn index is within the table");
            self.step(&tc, Violation::EarlyUpstreamData { ordinal });
        }

        #[rule]
        fn ja4_change(&mut self, tc: TestCase) {
            let index = draw_index(&tc, self.table.len() - 1);
            let ordinal = self
                .table
                .ordinal(index)
                .expect("drawn index is within the table");
            self.step(&tc, Violation::Ja4Change { ordinal });
        }

        #[rule]
        fn evidence_insufficient(&mut self, tc: TestCase) {
            self.step(&tc, Violation::EvidenceInsufficient);
        }

        #[rule]
        fn unattributed(&mut self, tc: TestCase) {
            self.step(&tc, Violation::Unattributed);
        }

        #[rule]
        fn missing_parse_result(&mut self, tc: TestCase) {
            self.step(&tc, Violation::MissingParseResult);
        }

        #[rule]
        fn advance_time(&mut self, tc: TestCase) {
            let step = tc.draw(
                hegel::generators::integers::<u64>()
                    .min_value(0)
                    .max_value(4),
            );
            self.advance_clock(step);
        }

        #[invariant(always_run)]
        fn e1_block_latches_are_monotone(&self, _: TestCase) {
            assert!(
                !self.prev_block_all || self.en.block_all(),
                "E1: the All-scope block latch cleared"
            );
            let now = self.subject_blocked_mask();
            assert_eq!(
                now & self.prev_blocked,
                self.prev_blocked,
                "E1: a per-ordinal blocked bit cleared"
            );
            assert_eq!(
                now, self.expected_blocked,
                "E1: the per-ordinal blocked bitset diverged from the model"
            );
        }

        #[invariant(always_run)]
        fn e2_first_slot_latch_is_armed_to_spent(&self, _: TestCase) {
            assert!(
                !self.prev_latch_is_spent_with_armed_latch(),
                "E2: the first-slot latch went Spent -> Armed"
            );
            match self.last.kind {
                StepKind::AnyIllegal => assert_eq!(
                    self.latch,
                    FirstIllegalLatch::Spent,
                    "E2: an AnyIllegal decision left the first-slot latch Armed"
                ),
                StepKind::Time | StepKind::EarlyData | StepKind::Ja4 | StepKind::Unknown => {
                    assert_eq!(
                        self.latch, self.last.latch_before,
                        "E2: a non-AnyIllegal decision touched the first-slot latch"
                    );
                }
            }
        }

        #[invariant(always_run)]
        fn e3_action_only_after_its_fact(&self, _: TestCase) {
            if self.last.fact_tracked {
                assert_eq!(
                    self.last.fact_after,
                    self.last.fact_before + 1,
                    "E3: the decision did not fold its fact exactly once"
                );
            }
            if matches!(self.last.kind, StepKind::Ja4) {
                assert_eq!(
                    self.last.total_after, self.last.total_before,
                    "E3: Ja4Change must not count a fact in decide (the serving path owns it)"
                );
                return;
            }
            if matches!(
                self.last.effect,
                Effect::Block { .. } | Effect::Notify { .. }
            ) {
                assert!(
                    self.last.fact_tracked,
                    "E3: an action fired for a decision that counted no fact"
                );
                assert!(
                    self.last.fact_after > self.last.fact_before,
                    "E3: an action fired before its fact was counted"
                );
            }
        }

        #[invariant(always_run)]
        fn e4_block_all_follows_a_class_crossing(&self, _: TestCase) {
            let any_admitted = self.gates.iter().any(|gate| gate.admitted_all);
            assert_eq!(
                self.en.block_all(),
                any_admitted,
                "E4: block_all is not exactly a class crossing that admitted an All-scope block"
            );
            if self.en.block_all() {
                assert!(
                    self.gates.iter().any(|gate| gate.armed),
                    "E4: block_all is set with no class gate armed"
                );
            }
            assert_eq!(
                self.en.counters().actions_block_all(),
                u32::from(self.en.block_all()),
                "E4: the All-latch transition count does not match the latch"
            );
            assert_eq!(
                self.last.effect, self.last.expected_effect,
                "E4: the gated projection diverged from the model's per-class crossing"
            );
        }

        #[invariant(always_run)]
        fn e5_window_arithmetic_matches_the_model(&self, _: TestCase) {
            for class in GATE_CLASSES {
                let model = &self.gates[class.index()];
                let subject = subject_gate(&self.en, class);
                assert_eq!(
                    subject.armed, model.armed,
                    "E5: {class:?} armed diverged from the model's window arithmetic"
                );
                assert_eq!(
                    subject.count, model.count,
                    "E5: {class:?} count diverged from the model's window arithmetic"
                );
                assert_eq!(
                    subject.window_start, model.window_start,
                    "E5: {class:?} window_start diverged from the model's window arithmetic"
                );
                assert_eq!(subject.threshold, model.threshold, "E5: threshold diverged");
                assert_eq!(
                    subject.window_secs, model.window_secs,
                    "E5: window_secs diverged"
                );
            }
        }
    }

    impl GateModel {
        const fn prev_latch_is_spent_with_armed_latch(&self) -> bool {
            matches!(self.prev_latch, FirstIllegalLatch::Spent) && matches!(self.latch, FirstIllegalLatch::Armed)
        }
    }

    // ---------------------------------------------------------------------
    // E6: a saturated monitor changes no decision.
    // ---------------------------------------------------------------------

    /// Two subjects with the same drawn table and gates: one with every
    /// monitor counter saturated through the existing `#[cfg(test)]` seam,
    /// one clean. Rules apply the same violation stream to both and the
    /// invariant asserts the returned effects are identical and the saturated
    /// counters still report `u32::MAX` and overflow.
    struct SaturationModel {
        saturated: EnforcementState,
        control: EnforcementState,
        latch_saturated: FirstIllegalLatch,
        latch_control: FirstIllegalLatch,
        now: u64,
        probe_ordinal: DomainOrdinal,
        last_saturated: Effect,
        last_control: Effect,
    }

    impl SaturationModel {
        fn new(table: ControlTable, gates: GateSet) -> SaturationModel {
            let mut saturated = EnforcementState::new(table, gates);
            saturated.monitor_mut().saturate_all_for_test();
            SaturationModel {
                saturated,
                control: EnforcementState::new(table, gates),
                latch_saturated: FirstIllegalLatch::new(),
                latch_control: FirstIllegalLatch::new(),
                now: 0,
                probe_ordinal: table.ordinal(0).expect("a drawn table has an ordinal"),
                last_saturated: Effect::BaselineOnly,
                last_control: Effect::BaselineOnly,
            }
        }

        fn step(&mut self, violation: Violation) {
            self.last_saturated =
                self.saturated
                    .decide(&mut self.latch_saturated, violation, self.now);
            self.last_control = self
                .control
                .decide(&mut self.latch_control, violation, self.now);
        }

        fn advance_clock(&mut self, step: u64) {
            self.now += step;
        }
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "the hegel state-machine macro hands each rule its own TestCase by value"
    )]
    #[hegel::state_machine]
    impl SaturationModel {
        #[rule]
        fn any_illegal(&mut self, tc: TestCase) {
            let cause = drawn_any_illegal_cause(&tc);
            self.step(Violation::AnyIllegal { cause });
        }

        #[rule]
        fn early_upstream_data(&mut self, tc: TestCase) {
            let last = self.control.control().len() - 1;
            let index = draw_index(&tc, last);
            let ordinal = self
                .control
                .control()
                .ordinal(index)
                .expect("drawn index is within the drawn table");
            self.step(Violation::EarlyUpstreamData { ordinal });
        }

        #[rule]
        fn ja4_change(&mut self, tc: TestCase) {
            let last = self.control.control().len() - 1;
            let index = draw_index(&tc, last);
            let ordinal = self
                .control
                .control()
                .ordinal(index)
                .expect("drawn index is within the drawn table");
            self.step(Violation::Ja4Change { ordinal });
        }

        #[rule]
        fn evidence_insufficient(&mut self, _: TestCase) {
            self.step(Violation::EvidenceInsufficient);
        }

        #[rule]
        fn unattributed(&mut self, _: TestCase) {
            self.step(Violation::Unattributed);
        }

        #[rule]
        fn missing_parse_result(&mut self, _: TestCase) {
            self.step(Violation::MissingParseResult);
        }

        #[rule]
        fn advance_time(&mut self, tc: TestCase) {
            let step = tc.draw(
                hegel::generators::integers::<u64>()
                    .min_value(0)
                    .max_value(4),
            );
            self.advance_clock(step);
        }

        #[invariant(always_run)]
        fn e6_saturation_never_gates(&self, _: TestCase) {
            assert_eq!(
                self.last_saturated, self.last_control,
                "E6: a saturated monitor changed the decision"
            );
            let counters = self.saturated.counters();
            assert_eq!(
                counters.facts_any_illegal(AnyIllegalCause::Ech),
                u32::MAX,
                "E6: the saturated fact counter did not report u32::MAX"
            );
            assert!(
                counters.facts_any_illegal_overflow(),
                "E6: the saturated fact counter did not report overflow"
            );
            assert_eq!(
                counters.facts_early_data(self.probe_ordinal),
                u32::MAX,
                "E6: the saturated early-data counter did not report u32::MAX"
            );
            assert_eq!(
                counters.facts_unknown(UnknownReason::Unattributed),
                u32::MAX,
                "E6: the saturated unknown counter did not report u32::MAX"
            );
            assert_eq!(
                counters.actions_block_all(),
                u32::MAX,
                "E6: the saturated All-block action counter did not report u32::MAX"
            );
            assert!(
                counters.actions_overflow(),
                "E6: the saturated action counters did not report overflow"
            );
        }
    }

    // ---------------------------------------------------------------------
    // Wrappers.
    // ---------------------------------------------------------------------

    #[hegel::test(derandomize = true)]
    fn enforcement_gates_and_latches_follow_the_model(tc: TestCase) {
        let table = drawn_table(&tc);
        let gates = drawn_gates(&tc);
        hegel::stateful::machine(GateModel::new(table, gates))
            .steps(50)
            .run(tc);
    }

    #[hegel::test(derandomize = true)]
    fn enforcement_saturated_monitor_never_gates(tc: TestCase) {
        let table = drawn_table(&tc);
        let gates = drawn_gates(&tc);
        hegel::stateful::machine(SaturationModel::new(table, gates))
            .steps(50)
            .run(tc);
    }
}

use super::*;
use crate::enforcement::action::{ActionKind, AnyIllegalControl, Control, PerFqdnControl};
use crate::enforcement::monitor::DnsAnomalyKind;
use crate::enforcement::policy::{AnyIllegalCause, UnknownReason};
use crate::inspection::client_hello::HelloRejectReason;
use crate::inspection::connect::ConnectHeadReason;

fn any_controls(kind: ActionKind, scope: Scope) -> [Control; AnyIllegalControl::COUNT] {
    [Control::new(kind, scope); AnyIllegalControl::COUNT]
}

fn per_fqdn(actions: &[(ActionKind, Scope)]) -> Vec<PerFqdnControl> {
    actions
        .iter()
        .map(|&(kind, scope)| PerFqdnControl::control(kind, scope))
        .collect()
}

fn table(
    any: [Control; AnyIllegalControl::COUNT],
    early: &[(ActionKind, Scope)],
    ja4: &[(ActionKind, Scope)],
) -> ControlTable {
    ControlTable::new(any, &per_fqdn(early), &per_fqdn(ja4)).expect("in-bound test table")
}

fn gate(threshold: u32, window: u64) -> AllScopeGate {
    AllScopeGate::new(
        NonZeroU32::new(threshold).expect("nonzero threshold"),
        NonZeroU64::new(window).expect("nonzero window"),
    )
}

fn en(t: ControlTable) -> Enforcement {
    Enforcement::new(t, GateSet::default())
}

fn en_gated(t: ControlTable, gates: GateSet) -> Enforcement {
    Enforcement::new(t, gates)
}

fn gates_illegal_fqdn(threshold: u32, window: u64) -> GateSet {
    GateSet::new(
        AllScopeGate::default(),
        gate(threshold, window),
        AllScopeGate::default(),
        AllScopeGate::default(),
    )
}

fn block_connection_table() -> ControlTable {
    table(
        any_controls(ActionKind::Block, Scope::Connection),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Notify, Scope::Connection)],
    )
}

fn block_all_table() -> ControlTable {
    table(
        any_controls(ActionKind::Block, Scope::All),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Notify, Scope::Connection)],
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

fn decide_at(en: &mut Enforcement, violation: Violation, secs: u64) -> Effect {
    en.decide(&mut FirstSlot::new(), violation, secs)
}

fn isolated_gate_arrangement(
    early_data: AllScopeGate,
    ja4: AllScopeGate,
) -> (ControlTable, Enforcement) {
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

fn count_only_arrangement() -> (ControlTable, Enforcement) {
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
        &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
    let mut latch = FirstSlot::new();
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
        &mut FirstSlot::new(),
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
    let mut latch = FirstSlot::new();
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
            &mut FirstSlot::new(),
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
            &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
    let mut latch = FirstSlot::new();
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
    let mut latch = FirstSlot::new();
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
    let mut latch = FirstSlot::new();
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
        &mut FirstSlot::new(),
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
            &mut FirstSlot::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
            0,
        ),
        Effect::BaselineOnly
    );
    assert_eq!(
        en.decide(
            &mut FirstSlot::new(),
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
            1,
        ),
        Effect::BaselineOnly
    );
    assert_eq!(
        en.decide(
            &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
    let effect = en.decide(&mut FirstSlot::new(), Violation::Ja4Change { ordinal }, 0);
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
fn ja4_change_ignore_is_baseline_only() {
    let any = any_controls(ActionKind::Block, Scope::Connection);
    let early = vec![PerFqdnControl::control(
        ActionKind::Notify,
        Scope::Connection,
    )];
    let ja4 = vec![PerFqdnControl::Ignore];
    let t = ControlTable::new(any, &early, &ja4).expect("in-bound test table");
    let mut en = en(t);
    let ordinal = t.ordinal(0).expect("ordinal");
    let effect = en.decide(&mut FirstSlot::new(), Violation::Ja4Change { ordinal }, 0);
    assert_eq!(
        effect,
        Effect::BaselineOnly,
        "ja4 ignore suppresses the change signal to no action"
    );
    assert_eq!(en.counters().actions_domain_block(ordinal), 0);
    assert_eq!(en.counters().actions_notify(ordinal), 0);
    assert!(!en.test_blocked(ordinal));
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
            &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
            &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
        let effect = en.decide(&mut FirstSlot::new(), Violation::Ja4Change { ordinal }, i);
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
        &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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
            &mut FirstSlot::new(),
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
        &mut FirstSlot::new(),
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

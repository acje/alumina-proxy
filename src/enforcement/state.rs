use crate::eligibility::NumericAddr;

use super::action::{AnyIllegalScope, ControlTable, DomainOrdinal, FirstSlot, Scope};
use super::monitor::{DnsAnomalyKind, Monitor, SlotCapture};
use super::policy::{Effect, UnknownReason, Violation, decide as pure_decide};

/// The fixed number of `AnyIllegal` facts that must cross within the fixed
/// window before the All-scope latch may arm (SP-001; fixed constants, no
/// speculative pacing).
pub const ANY_ILLEGAL_THRESHOLD: u32 = 3;

/// The fixed whole-second window within which the threshold facts must arrive
/// (SP-001).
pub const ANY_ILLEGAL_WINDOW_SECS: u64 = 60;

/// A bounded fact counter that arms once the fixed threshold is crossed within
/// the fixed window. The armed state is sticky until restart (rp2e :263).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowedCounter {
    count: u32,
    window_start: u64,
    armed: bool,
}

impl WindowedCounter {
    pub const fn new() -> WindowedCounter {
        WindowedCounter {
            count: 0,
            window_start: 0,
            armed: false,
        }
    }

    /// Notes a fact at `secs`; returns whether the counter is armed (crossed
    /// the threshold within the window). Once armed it stays armed.
    pub const fn note(&mut self, secs: u64) -> bool {
        if self.armed {
            return true;
        }
        if secs.saturating_sub(self.window_start) >= ANY_ILLEGAL_WINDOW_SECS {
            self.count = 0;
            self.window_start = secs;
        }
        self.count += 1;
        if self.count >= ANY_ILLEGAL_THRESHOLD {
            self.armed = true;
        }
        self.armed
    }
}

impl Default for WindowedCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaturatingCounter {
    value: u32,
    overflow: bool,
}

impl SaturatingCounter {
    pub const fn new() -> SaturatingCounter {
        SaturatingCounter {
            value: 0,
            overflow: false,
        }
    }

    pub const fn bump(&mut self) {
        if self.value == u32::MAX {
            self.overflow = true;
        } else {
            self.value += 1;
        }
    }

    pub const fn value(self) -> u32 {
        self.value
    }

    pub const fn overflow(self) -> bool {
        self.overflow
    }

    #[cfg(test)]
    pub const fn saturate_for_test(&mut self) {
        self.value = u32::MAX;
        self.overflow = true;
    }
}

impl Default for SaturatingCounter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Enforcement {
    control: ControlTable,
    block_all: bool,
    blocked: u32,
    monitor: Monitor,
    any_illegal_gate: WindowedCounter,
}

impl Enforcement {
    pub fn new(control: ControlTable) -> Enforcement {
        Enforcement {
            control,
            block_all: false,
            blocked: 0,
            monitor: Monitor::new(),
            any_illegal_gate: WindowedCounter::new(),
        }
    }

    pub const fn control(&self) -> ControlTable {
        self.control
    }

    pub const fn block_all(&self) -> bool {
        self.block_all
    }

    pub const fn is_blocked(&self, ordinal: DomainOrdinal) -> bool {
        (self.blocked >> ordinal.get()) & 1 == 1
    }

    pub fn decide(&mut self, latch: &mut FirstSlot, violation: Violation, secs: u64) -> Effect {
        let raw = pure_decide(&self.control, latch, violation);
        let effect = match violation {
            Violation::AnyIllegal { cause: _ } => {
                let crossed = self.any_illegal_gate.note(secs);
                match raw {
                    Effect::Block { scope: Scope::All } if !crossed => Effect::BaselineOnly,
                    _ => raw,
                }
            }
            _ => raw,
        };
        match violation {
            Violation::AnyIllegal { cause } => {
                self.monitor.note_fact_any_illegal(cause);
                match effect {
                    Effect::Block {
                        scope: Scope::Connection,
                    } => {
                        self.monitor
                            .note_action_first_slot_block(AnyIllegalScope::Connection);
                    }
                    Effect::Block { scope: Scope::All } => {
                        let was_latched = self.block_all;
                        self.block_all = true;
                        self.monitor
                            .note_action_first_slot_block(AnyIllegalScope::All);
                        if !was_latched {
                            self.monitor.note_block_all();
                        }
                    }
                    _ => {}
                }
            }
            Violation::EarlyUpstreamData { ordinal } => {
                self.monitor.note_fact_early_data(ordinal);
                match effect {
                    Effect::FlareOnly { .. } => {
                        self.monitor.note_action_flare(ordinal);
                    }
                    Effect::Block { scope } => {
                        self.monitor.note_action_domain_block(ordinal);
                        match scope {
                            Scope::Domain => self.blocked |= 1 << ordinal.get(),
                            Scope::All => {
                                let was_latched = self.block_all;
                                self.block_all = true;
                                if !was_latched {
                                    self.monitor.note_block_all();
                                }
                            }
                            Scope::Connection => {}
                        }
                    }
                    Effect::Unknown { .. } | Effect::BaselineOnly => {}
                }
            }
            Violation::EvidenceInsufficient => {
                self.monitor
                    .note_fact_unknown(UnknownReason::NotYetValidated);
            }
            Violation::Unattributed => {
                self.monitor.note_fact_unknown(UnknownReason::Unattributed);
            }
            Violation::MissingParseResult => {
                self.monitor
                    .note_fact_unknown(UnknownReason::MissingParseResult);
            }
        }
        effect
    }

    pub const fn note_domain_block(&mut self, ordinal: DomainOrdinal) {
        self.monitor.note_refusal_blocked_domain(ordinal);
    }

    pub(crate) const fn note_consumed_capture(&mut self, capture: SlotCapture) {
        self.monitor.note_consumed_capture(capture);
    }

    pub(crate) const fn note_suppressed_detail(&mut self) {
        self.monitor.note_suppressed_detail();
    }

    pub(crate) const fn note_fact_resolver_degraded(&mut self) {
        self.monitor.note_fact_resolver_degraded();
    }

    pub(crate) const fn note_fact_dns_anomaly(&mut self, kind: DnsAnomalyKind) {
        self.monitor.note_fact_dns_anomaly(kind);
    }

    pub(crate) const fn note_fact_downgrade_to_plain(&mut self) {
        self.monitor.note_fact_downgrade_to_plain();
    }

    pub(crate) const fn note_fact_probe_relocation(&mut self) {
        self.monitor.note_fact_probe_relocation();
    }

    pub(crate) const fn note_fact_expired_pin_cert(&mut self) {
        self.monitor.note_fact_expired_pin_cert();
    }

    pub(crate) const fn note_incident_open(&mut self) {
        self.monitor.note_incident_open();
    }

    pub(crate) const fn note_incident_close(&mut self) {
        self.monitor.note_incident_close();
    }

    pub(crate) const fn note_fact_ja4_change(
        &mut self,
        ordinal: DomainOrdinal,
        ja4: [u8; 36],
        peer_ip: NumericAddr,
    ) {
        self.monitor.note_fact_ja4_change(ordinal, ja4, peer_ip);
    }

    pub(crate) const fn note_fact_ja4_seed(&mut self) {
        self.monitor.note_fact_ja4_seed();
    }

    pub(crate) const fn note_serving_stale(&mut self) {
        self.monitor.note_serving_stale();
    }

    pub(crate) const fn note_serving_fresh(&mut self) {
        self.monitor.note_serving_fresh();
    }

    #[cfg(test)]
    pub(crate) const fn monitor(&self) -> &Monitor {
        &self.monitor
    }

    pub(crate) const fn monitor_mut(&mut self) -> &mut Monitor {
        &mut self.monitor
    }

    pub(crate) fn monitor_due(&self, secs: u64) -> bool {
        self.monitor.report_due(secs)
    }

    pub(crate) fn mark_monitor_reported(&mut self, secs: u64) {
        self.monitor.mark_reported(secs);
    }

    pub(crate) fn mark_forced_monitor_reported(&mut self) {
        self.monitor.mark_forced_reported();
    }

    #[cfg(test)]
    pub const fn counters(&self) -> &Monitor {
        &self.monitor
    }

    #[cfg(test)]
    pub(crate) const fn test_blocked(&self, ordinal: DomainOrdinal) -> bool {
        self.is_blocked(ordinal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_hello::HelloRejectReason;
    use crate::connect::ConnectHeadReason;
    use crate::enforcement::action::{ActionKind, AnyIllegalScope, DomainAction};
    use crate::enforcement::monitor::DnsAnomalyKind;
    use crate::enforcement::policy::{AnyIllegalCause, UnknownReason};

    fn table(any_illegal: AnyIllegalScope, actions: &[(ActionKind, Scope)]) -> ControlTable {
        let entries: Vec<DomainAction> = actions
            .iter()
            .map(|&(kind, scope)| DomainAction::new(kind, scope))
            .collect();
        ControlTable::new(any_illegal, &entries).expect("in-bound test table")
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
        let t = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(t);
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
        let t = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(t);
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
        let t = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(t);
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
        let t = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(t);
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
        let t = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(t);
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
            "SP-001: one AnyIllegal fact must not arm the All latch"
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
            "two AnyIllegal facts are still below the fixed threshold"
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
                cause: AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort),
            },
            2,
        );
        assert_eq!(
            third,
            Effect::Block { scope: Scope::All },
            "the third AnyIllegal fact within the window crosses the threshold"
        );
        assert!(en.block_all());
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
            "once armed the All latch stays armed for later AnyIllegal facts"
        );
        assert!(en.block_all());
        assert_eq!(
            en.counters().facts_any_illegal_total(),
            4,
            "every AnyIllegal fact folds regardless of the gating"
        );
    }

    #[test]
    fn wrong_port_and_transfer_encoding_fold_into_distinct_cause_counters() {
        let t = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(t);
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
        let t = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::Block, Scope::Domain)],
        );
        let mut en = Enforcement::new(t);
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
    fn early_data_flare_counts_per_ordinal() {
        let t = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(t);
        let mut latch = FirstSlot::new();
        let ordinal = t.ordinal(0).expect("ordinal");
        assert_eq!(
            en.decide(&mut latch, Violation::EarlyUpstreamData { ordinal }, 0),
            Effect::FlareOnly {
                scope: Scope::Connection
            }
        );
        assert_eq!(en.counters().actions_flare(ordinal), 1);
        assert_eq!(en.counters().actions_domain_block(ordinal), 0);
    }

    #[test]
    fn all_transition_is_a_derived_latch_count_not_a_duplicate_action_total() {
        let t = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(t);
        for i in 0..3u64 {
            en.decide(
                &mut FirstSlot::new(),
                Violation::AnyIllegal {
                    cause: AnyIllegalCause::HostNotAllowlisted,
                },
                i,
            );
        }
        assert!(en.block_all(), "three AnyIllegal facts arm the All latch");
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
        let t = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::All); 2]);
        let mut en = Enforcement::new(t);
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
        assert!(en.block_all(), "three AnyIllegal facts arm the All latch");
        en.decide(
            &mut FirstSlot::new(),
            Violation::EarlyUpstreamData { ordinal },
            10,
        );
        assert!(
            en.block_all(),
            "an early-data All application keeps the latch"
        );
        assert_eq!(
            en.counters().actions_block_all(),
            1,
            "L1: the latch transition counts once even across a later All application"
        );
    }

    #[test]
    fn early_data_unknown_outcome_is_one_detection_fact_not_two() {
        let small = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(small);
        let mut latch = FirstSlot::new();
        let big = table(
            AnyIllegalScope::Connection,
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
        let small = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(small);
        let mut latch = FirstSlot::new();
        let big = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::All); 2]);
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
        let t = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::All)]);
        let mut en = Enforcement::new(t);
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
        let mut c = WindowedCounter::new();
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
        let mut c = WindowedCounter::new();
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
    fn single_any_illegal_never_latches_all() {
        let t = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::All)]);
        let mut en = Enforcement::new(t);
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
            "SP-001: a single unauthenticated AnyIllegal must not arm the All latch"
        );
        assert!(!en.block_all());
        assert_eq!(en.counters().actions_block_all(), 0);
        assert_eq!(en.counters().actions_total(), 0);
    }

    #[test]
    fn three_any_illegal_facts_within_the_window_latch_all() {
        let t = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::All)]);
        let mut en = Enforcement::new(t);
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
            "the third AnyIllegal fact within the window crosses the threshold"
        );
        assert!(en.block_all());
    }
}

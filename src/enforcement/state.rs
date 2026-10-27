use crate::eligibility::NumericAddr;

use super::action::{ControlTable, DomainOrdinal, FirstSlot, Scope};
use super::monitor::{DnsAnomalyKind, Monitor, SlotCapture};
use super::policy::{Effect, UnknownReason, Violation, decide as pure_decide};

/// The default All-scope gate threshold: at the default the FIRST deviation
/// arms the All-scope block, sticky until restart. Operator-configurable via
/// `[all_scope_gate]`.
pub const ALL_SCOPE_GATE_DEFAULT_THRESHOLD: u32 = 1;

/// The default All-scope gate window: the whole-second window within which the
/// threshold facts must arrive. Operator-configurable via `[all_scope_gate]`.
pub const ALL_SCOPE_GATE_DEFAULT_WINDOW_SECS: u64 = 900;

/// Operator-configurable SP-001 All-scope gate parameters: the threshold of
/// `AnyIllegal` facts that must cross within `window_secs` before the
/// All-scope latch may arm. The defaults are trigger-happy — at threshold 1
/// the FIRST deviation arms the All-scope block, sticky until restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllScopeGate {
    threshold: u32,
    window_secs: u64,
}

impl AllScopeGate {
    pub const fn new(threshold: u32, window_secs: u64) -> AllScopeGate {
        AllScopeGate {
            threshold,
            window_secs,
        }
    }

    pub const fn threshold(self) -> u32 {
        self.threshold
    }

    pub const fn window_secs(self) -> u64 {
        self.window_secs
    }
}

impl Default for AllScopeGate {
    fn default() -> Self {
        Self::new(
            ALL_SCOPE_GATE_DEFAULT_THRESHOLD,
            ALL_SCOPE_GATE_DEFAULT_WINDOW_SECS,
        )
    }
}

/// A bounded fact counter that arms once the configured threshold is crossed
/// within the configured window. The armed state is sticky until restart
/// (rp2e :263).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowedCounter {
    count: u32,
    window_start: u64,
    armed: bool,
    threshold: u32,
    window_secs: u64,
}

impl WindowedCounter {
    pub const fn new(threshold: u32, window_secs: u64) -> WindowedCounter {
        WindowedCounter {
            count: 0,
            window_start: 0,
            armed: false,
            threshold,
            window_secs,
        }
    }

    /// Notes a fact at `secs`; returns whether the counter is armed (crossed
    /// the threshold within the window). Once armed it stays armed.
    pub const fn note(&mut self, secs: u64) -> bool {
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

impl Default for WindowedCounter {
    fn default() -> Self {
        Self::new(
            ALL_SCOPE_GATE_DEFAULT_THRESHOLD,
            ALL_SCOPE_GATE_DEFAULT_WINDOW_SECS,
        )
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
    pub fn new(control: ControlTable, gate: AllScopeGate) -> Enforcement {
        Enforcement {
            control,
            block_all: false,
            blocked: 0,
            monitor: Monitor::new(),
            any_illegal_gate: WindowedCounter::new(gate.threshold(), gate.window_secs()),
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
        let crossed = match violation {
            Violation::AnyIllegal { .. } => self.any_illegal_gate.note(secs),
            Violation::EarlyUpstreamData { .. } | Violation::Ja4Change { .. } => {
                if matches!(raw, Effect::Block { scope: Scope::All }) {
                    self.any_illegal_gate.note(secs)
                } else {
                    false
                }
            }
            _ => false,
        };
        let effect = match raw {
            Effect::Block { scope: Scope::All } if !crossed => Effect::BaselineOnly,
            _ => raw,
        };
        match violation {
            Violation::AnyIllegal { cause } => {
                self.monitor.note_fact_any_illegal(cause);
                match effect {
                    Effect::Notify { scope } => {
                        self.monitor.note_action_first_slot_block(scope);
                    }
                    Effect::Block { scope } => {
                        self.monitor.note_action_first_slot_block(scope);
                        match scope {
                            Scope::All => {
                                let was_latched = self.block_all;
                                self.block_all = true;
                                if !was_latched {
                                    self.monitor.note_block_all();
                                }
                            }
                            Scope::Connection | Scope::Domain => {}
                        }
                    }
                    _ => {}
                }
            }
            Violation::EarlyUpstreamData { ordinal } => {
                self.monitor.note_fact_early_data(ordinal);
                self.apply_per_fqdn_action(effect, ordinal);
            }
            Violation::Ja4Change { ordinal } => {
                self.apply_per_fqdn_action(effect, ordinal);
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

    /// Applies a per-FQDN effect (from `early_data` or `ja4`) to the monitor
    /// and the blocked-domain bitset. `BaselineOnly` and `Unknown` apply
    /// nothing; `Notify` counts the per-ordinal notify action; `Block` counts
    /// the domain block and latches the `Domain`/`All` scope.
    const fn apply_per_fqdn_action(&mut self, effect: Effect, ordinal: DomainOrdinal) {
        match effect {
            Effect::Notify { .. } => {
                self.monitor.note_action_notify(ordinal);
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
    use crate::enforcement::action::{ActionKind, AnyIllegalControl, Control, PerFqdnControl};
    use crate::enforcement::monitor::DnsAnomalyKind;
    use crate::enforcement::policy::{AnyIllegalCause, UnknownReason};

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

    fn en(t: ControlTable) -> Enforcement {
        Enforcement::new(t, AllScopeGate::default())
    }

    fn en_gated(t: ControlTable, threshold: u32, window: u64) -> Enforcement {
        Enforcement::new(t, AllScopeGate::new(threshold, window))
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
            any_controls(ActionKind::Block, Scope::Connection),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        );
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
        let t = table(
            any_controls(ActionKind::Block, Scope::Connection),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        );
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
        let t = table(
            any_controls(ActionKind::Block, Scope::Connection),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        );
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
        let t = table(
            any_controls(ActionKind::Block, Scope::Connection),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        );
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
        let t = table(
            any_controls(ActionKind::Block, Scope::All),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        );
        let mut en = en_gated(t, 3, 60);
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
            any_controls(ActionKind::Block, Scope::All),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        );
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
        let t = table(
            any_controls(ActionKind::Block, Scope::Connection),
            &[(ActionKind::Block, Scope::Domain)],
            &[(ActionKind::Block, Scope::Domain)],
        );
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
        let t = table(
            any_controls(ActionKind::Block, Scope::Connection),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        );
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
        let t = table(
            any_controls(ActionKind::Block, Scope::All),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        );
        let mut en = en_gated(t, 3, 60);
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
        let t = table(
            any_controls(ActionKind::Block, Scope::All),
            &[(ActionKind::Block, Scope::All); 2],
            &[(ActionKind::Block, Scope::All); 2],
        );
        let mut en = en_gated(t, 3, 60);
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
            any_controls(ActionKind::Block, Scope::Connection),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        );
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
        let small = table(
            any_controls(ActionKind::Block, Scope::All),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        );
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
        let t = table(
            any_controls(ActionKind::Block, Scope::All),
            &[(ActionKind::Block, Scope::All)],
            &[(ActionKind::Block, Scope::All)],
        );
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
        let t = table(
            any_controls(ActionKind::Block, Scope::All),
            &[(ActionKind::Block, Scope::All)],
            &[(ActionKind::Block, Scope::All)],
        );
        let mut en = en_gated(t, 3, 60);
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
        let t = table(
            any_controls(ActionKind::Block, Scope::All),
            &[(ActionKind::Block, Scope::All)],
            &[(ActionKind::Block, Scope::All)],
        );
        let mut en = en_gated(t, 3, 60);
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

    #[test]
    fn single_any_illegal_arms_all_scope_at_default_threshold() {
        let t = table(
            any_controls(ActionKind::Block, Scope::All),
            &[(ActionKind::Block, Scope::All)],
            &[(ActionKind::Block, Scope::All)],
        );
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
        let t = table(
            any_controls(ActionKind::Notify, Scope::Connection),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        );
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
        let t = table(
            any_controls(ActionKind::Block, Scope::All),
            &[(ActionKind::Block, Scope::All)],
            &[(ActionKind::Block, Scope::All)],
        );
        let mut en = en_gated(t, 3, 60);
        let ordinal = t.ordinal(0).expect("ordinal");
        let effect = en.decide(
            &mut FirstSlot::new(),
            Violation::EarlyUpstreamData { ordinal },
            0,
        );
        assert_eq!(
            effect,
            Effect::BaselineOnly,
            "SP-001: a single per-FQDN All-scope block must not arm the All latch"
        );
        assert!(!en.block_all());
        assert_eq!(en.counters().actions_domain_block(ordinal), 0);
        for i in 1..3u64 {
            en.decide(
                &mut FirstSlot::new(),
                Violation::AnyIllegal {
                    cause: AnyIllegalCause::HostNotAllowlisted,
                },
                i,
            );
        }
        assert!(en.block_all(), "the AnyIllegal facts arm the All latch");
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
        assert_eq!(en.counters().actions_domain_block(ordinal), 1);
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
}

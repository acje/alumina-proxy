use std::num::{NonZeroU32, NonZeroU64};

use crate::eligibility::NumericAddr;

use super::action::{ControlTable, DomainOrdinal, FirstSlot, Scope};
use super::monitor::{DnsAnomalyKind, Monitor, SlotCapture};
use super::policy::{AnyIllegalCause, Effect, UnknownReason, Violation, decide as pure_decide};

/// The default per-class All-scope gate threshold: at the default the FIRST
/// deviation of a class arms that class's All-scope block, sticky until
/// restart. Operator-configurable per class via the configurable gate sections.
pub const ALL_SCOPE_GATE_DEFAULT_THRESHOLD: u32 = 1;

/// The default per-class All-scope gate window: the whole-second window within
/// which the threshold facts of a class must arrive. Operator-configurable per
/// class via the configurable gate sections.
pub const ALL_SCOPE_GATE_DEFAULT_WINDOW_SECS: u64 = 900;

/// Operator-configurable SP-001 All-scope gate parameters: the threshold of
/// `AnyIllegal` facts that must cross within `window_secs` before the
/// All-scope latch may arm. At the default threshold of 1 the FIRST deviation
/// arms the All-scope block, sticky until restart. Both
/// fields are `NonZero`, so the `threshold >= 1` / `window_secs >= 1`
/// invariant is type-enforced: a gate that could never arm is unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllScopeGate {
    threshold: NonZeroU32,
    window_secs: NonZeroU64,
}

impl AllScopeGate {
    pub const fn new(threshold: NonZeroU32, window_secs: NonZeroU64) -> AllScopeGate {
        AllScopeGate {
            threshold,
            window_secs,
        }
    }

    pub const fn threshold(self) -> u32 {
        self.threshold.get()
    }

    pub const fn window_secs(self) -> u64 {
        self.window_secs.get()
    }
}

impl Default for AllScopeGate {
    #[expect(
        clippy::expect_used,
        reason = "default gate constants threshold 1 and window 900 are nonzero by definition"
    )]
    fn default() -> Self {
        Self::new(
            NonZeroU32::new(ALL_SCOPE_GATE_DEFAULT_THRESHOLD)
                .expect("default threshold 1 is nonzero"),
            NonZeroU64::new(ALL_SCOPE_GATE_DEFAULT_WINDOW_SECS)
                .expect("default window 900 is nonzero"),
        )
    }
}

/// The four per-class SP-001 All-scope gate parameter sets, one per violation
/// class: `bad_handshake` (`ConnectParse`/`TlsProfile`/`Ech`), `illegal_fqdn`
/// (`HostNotAllowlisted`), `early_data` (`EarlyUpstreamData`), and `ja4`
/// (`Ja4Change`). Each class's gate counts only that class's facts, so the
/// operator chooses the action AND the bar per class; production configuration
/// always installs `AllScopeGate::default()` for the `early_data` slot because
/// its gate section is rejected at load (exit 78), so its bar is not
/// operator-chosen. `GateSet::new` still takes the slot as a parameter so unit
/// tests can exercise a non-default bar; no production path supplies one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateSet {
    bad_handshake: AllScopeGate,
    illegal_fqdn: AllScopeGate,
    early_data: AllScopeGate,
    ja4: AllScopeGate,
}

impl GateSet {
    pub const fn new(
        bad_handshake: AllScopeGate,
        illegal_fqdn: AllScopeGate,
        early_data: AllScopeGate,
        ja4: AllScopeGate,
    ) -> GateSet {
        GateSet {
            bad_handshake,
            illegal_fqdn,
            early_data,
            ja4,
        }
    }

    pub const fn bad_handshake(self) -> AllScopeGate {
        self.bad_handshake
    }

    pub const fn illegal_fqdn(self) -> AllScopeGate {
        self.illegal_fqdn
    }

    pub const fn early_data(self) -> AllScopeGate {
        self.early_data
    }

    pub const fn ja4(self) -> AllScopeGate {
        self.ja4
    }
}

impl Default for GateSet {
    fn default() -> Self {
        Self::new(
            AllScopeGate::default(),
            AllScopeGate::default(),
            AllScopeGate::default(),
            AllScopeGate::default(),
        )
    }
}

/// A bounded fact counter that arms once the configured threshold is crossed
/// within the configured window. The armed state is sticky until restart
/// (rp2e :263). The counter assumes `threshold >= 1` and `window_secs >= 1`,
/// guaranteed by construction from an `AllScopeGate` whose `NonZero` fields
/// make zero unrepresentable.
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
    bad_handshake_gate: WindowedCounter,
    illegal_fqdn_gate: WindowedCounter,
    early_data_gate: WindowedCounter,
    ja4_gate: WindowedCounter,
}

impl Enforcement {
    pub fn new(control: ControlTable, gates: GateSet) -> Enforcement {
        Enforcement {
            control,
            block_all: false,
            blocked: 0,
            monitor: Monitor::new(),
            bad_handshake_gate: WindowedCounter::new(
                gates.bad_handshake().threshold(),
                gates.bad_handshake().window_secs(),
            ),
            illegal_fqdn_gate: WindowedCounter::new(
                gates.illegal_fqdn().threshold(),
                gates.illegal_fqdn().window_secs(),
            ),
            early_data_gate: WindowedCounter::new(
                gates.early_data().threshold(),
                gates.early_data().window_secs(),
            ),
            ja4_gate: WindowedCounter::new(gates.ja4().threshold(), gates.ja4().window_secs()),
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
        let effect = self.select_gated_effect(latch, violation, secs);
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

    fn select_gated_effect(
        &mut self,
        latch: &mut FirstSlot,
        violation: Violation,
        secs: u64,
    ) -> Effect {
        let raw = pure_decide(&self.control, latch, violation);
        let crossed = match violation {
            Violation::AnyIllegal { cause } => match cause {
                AnyIllegalCause::ConnectParse(_)
                | AnyIllegalCause::TlsProfile(_)
                | AnyIllegalCause::Ech => self.bad_handshake_gate.note(secs),
                AnyIllegalCause::HostNotAllowlisted => self.illegal_fqdn_gate.note(secs),
            },
            Violation::EarlyUpstreamData { .. } => {
                if matches!(raw, Effect::Block { scope: Scope::All }) {
                    self.early_data_gate.note(secs)
                } else {
                    false
                }
            }
            Violation::Ja4Change { .. } => {
                if matches!(raw, Effect::Block { scope: Scope::All }) {
                    self.ja4_gate.note(secs)
                } else {
                    false
                }
            }
            _ => false,
        };
        match raw {
            Effect::Block { scope: Scope::All } if !crossed => Effect::BaselineOnly,
            _ => raw,
        }
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
mod tests;

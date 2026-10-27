use std::net::Ipv4Addr;

use super::action::{DomainOrdinal, Scope};
use super::policy::{AnyIllegalCause, Effect, UnknownReason};
use super::state::SaturatingCounter;
use crate::config::ALLOWLIST_MAX;
use crate::eligibility::NumericAddr;

pub(crate) const CAPTURE_DETAIL_LEN: usize = 64;

#[derive(Clone, Copy, Debug)]
pub struct FactCounters {
    pub(crate) any_illegal: [SaturatingCounter; AnyIllegalCause::KIND_COUNT],
    pub(crate) early_data: [SaturatingCounter; ALLOWLIST_MAX],
    pub(crate) unknown: [SaturatingCounter; UnknownReason::COUNT],
    pub(crate) resolver_degraded: SaturatingCounter,
    pub(crate) dns_anomaly: [SaturatingCounter; DnsAnomalyKind::COUNT],
    pub(crate) downgrade_to_plain: SaturatingCounter,
    pub(crate) probe_relocations: SaturatingCounter,
    pub(crate) expired_pin_certs: SaturatingCounter,
    pub(crate) ja4_change: [SaturatingCounter; ALLOWLIST_MAX],
    pub(crate) ja4_change_loss: [bool; ALLOWLIST_MAX],
    pub(crate) ja4_value: [[u8; 36]; ALLOWLIST_MAX],
    pub(crate) ja4_seed: SaturatingCounter,
    pub(crate) ja4_peer_ip: NumericAddr,
    pub(crate) ja4_peer_ordinal: Option<DomainOrdinal>,
}

impl Default for FactCounters {
    fn default() -> Self {
        FactCounters {
            any_illegal: std::array::from_fn(|_| SaturatingCounter::new()),
            early_data: std::array::from_fn(|_| SaturatingCounter::new()),
            unknown: std::array::from_fn(|_| SaturatingCounter::new()),
            resolver_degraded: SaturatingCounter::new(),
            dns_anomaly: std::array::from_fn(|_| SaturatingCounter::new()),
            downgrade_to_plain: SaturatingCounter::new(),
            probe_relocations: SaturatingCounter::new(),
            expired_pin_certs: SaturatingCounter::new(),
            ja4_change: std::array::from_fn(|_| SaturatingCounter::new()),
            ja4_change_loss: [false; ALLOWLIST_MAX],
            ja4_value: [[0; 36]; ALLOWLIST_MAX],
            ja4_seed: SaturatingCounter::new(),
            ja4_peer_ip: NumericAddr::V4(Ipv4Addr::UNSPECIFIED),
            ja4_peer_ordinal: None,
        }
    }
}

/// The typed DNS anomaly surface folded into the monitor alongside the
/// resolver-degraded state: every variant is a per-exchange detection noted on
/// the transport, drained by the serving storage into one counter per kind, and
/// zero-suppressed in the monitor record (`bv`, `rpm`, `xttl`, `cc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsAnomalyKind {
    /// A followed CNAME link target escaped every allowlist bailiwick zone.
    BailiwickViolation,
    /// The completed nonblocking connect landed on a peer other than the
    /// configured nameserver (vec-22).
    ResolverPeerMismatch,
    /// A published answer carried a resource-record TTL above the extreme
    /// threshold (96 h).
    ExtremeTtl,
    /// A corroboration exchange against a different configured resolver
    /// returned a positive with eligible bindings while the active resolver
    /// returned a negative (a sustained-negative conflict, alox18).
    CorroborationConflict,
}

impl DnsAnomalyKind {
    pub(crate) const COUNT: usize = 4;

    pub(crate) const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn from_index(index: usize) -> Option<DnsAnomalyKind> {
        match index {
            0 => Some(DnsAnomalyKind::BailiwickViolation),
            1 => Some(DnsAnomalyKind::ResolverPeerMismatch),
            2 => Some(DnsAnomalyKind::ExtremeTtl),
            3 => Some(DnsAnomalyKind::CorroborationConflict),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ActionCounters {
    pub(crate) first_slot_block: [SaturatingCounter; Scope::COUNT],
    pub(crate) domain_block: [SaturatingCounter; ALLOWLIST_MAX],
    pub(crate) notify: [SaturatingCounter; ALLOWLIST_MAX],
    pub(crate) block_all: SaturatingCounter,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RefusalCounters {
    pub(crate) blocked_domain: [SaturatingCounter; ALLOWLIST_MAX],
}

#[derive(Clone, Copy, Debug)]
pub struct Monitor {
    pub(crate) facts: FactCounters,
    pub(crate) actions: ActionCounters,
    pub(crate) refusals: RefusalCounters,
    pub(crate) report_drops: SaturatingCounter,
    captures: [Option<ConsumedCapture>; CAPTURE_DETAIL_LEN],
    capture_head: usize,
    capture_len: usize,
    capture_drops: SaturatingCounter,
    dirty: bool,
    serving_stale: bool,
    sustained_negatives: u8,
    last_report_secs: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapturedFact {
    AnyIllegal(AnyIllegalCause),
    EarlyData(DomainOrdinal),
    Unknown(UnknownReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapturedDetail {
    pub(crate) fact: CapturedFact,
    pub(crate) effect: Effect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumedCapture {
    pub(crate) slot: usize,
    pub(crate) generation: u64,
    pub(crate) detail: CapturedDetail,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotCapture {
    pub(crate) slot: usize,
    pub(crate) generation: u64,
    pub(crate) detail: Option<CapturedDetail>,
}

impl SlotCapture {
    pub(crate) const fn fresh(slot: usize, generation: u64) -> SlotCapture {
        SlotCapture {
            slot,
            generation,
            detail: None,
        }
    }
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Monitor {
    pub(crate) fn new() -> Monitor {
        Monitor {
            facts: FactCounters::default(),
            actions: ActionCounters::default(),
            refusals: RefusalCounters::default(),
            report_drops: SaturatingCounter::new(),
            captures: std::array::from_fn(|_| None),
            capture_head: 0,
            capture_len: 0,
            capture_drops: SaturatingCounter::new(),
            dirty: false,
            serving_stale: false,
            sustained_negatives: 0,
            last_report_secs: None,
        }
    }

    pub(crate) const fn note_fact_any_illegal(&mut self, cause: AnyIllegalCause) {
        self.facts.any_illegal[cause.kind_index()].bump();
        self.dirty = true;
    }

    pub(crate) const fn note_fact_early_data(&mut self, ordinal: DomainOrdinal) {
        self.facts.early_data[ordinal.get()].bump();
        self.dirty = true;
    }

    pub(crate) const fn note_fact_unknown(&mut self, reason: UnknownReason) {
        self.facts.unknown[reason.index()].bump();
        self.dirty = true;
    }

    pub(crate) const fn note_fact_resolver_degraded(&mut self) {
        self.facts.resolver_degraded.bump();
        self.dirty = true;
    }

    /// Latches the persistent "serving from a stale cache entry" level bit
    /// (W6-H6b-F5). The bit is a level, not an event fold: it survives
    /// `mark_reported` and is cleared only by a later fresh admission.
    pub(crate) const fn note_serving_stale(&mut self) {
        self.serving_stale = true;
        self.dirty = true;
    }

    /// Clears the stale-serving level bit on a fresh admission. Deliberately
    /// does not dirty the aggregate: a normal fresh admission is not an event
    /// worth its own summary emission.
    pub(crate) const fn note_serving_fresh(&mut self) {
        self.serving_stale = false;
    }

    /// Raises the sustained-negative incident level (`sn=`) by one, clamped to
    /// the 0..=32 name span. A level, not an event fold: it survives
    /// `mark_reported` and is lowered only by `note_incident_close`.
    pub(crate) const fn note_incident_open(&mut self) {
        self.sustained_negatives = if self.sustained_negatives >= 32 {
            32
        } else {
            self.sustained_negatives + 1
        };
        self.dirty = true;
    }

    /// Lowers the sustained-negative incident level (`sn=`) by one, clamped at
    /// zero. A level, not an event fold.
    pub(crate) const fn note_incident_close(&mut self) {
        self.sustained_negatives = self.sustained_negatives.saturating_sub(1);
        self.dirty = true;
    }

    pub(crate) const fn note_fact_dns_anomaly(&mut self, kind: DnsAnomalyKind) {
        self.facts.dns_anomaly[kind.index()].bump();
        self.dirty = true;
    }

    /// Counts one DoT→plain downgrade relocation (`dp=`), noted by the serving
    /// storage when the DNS transport drains a downgrade. The counter is an
    /// event fold like `rd`, never a latched level.
    pub(crate) const fn note_fact_downgrade_to_plain(&mut self) {
        self.facts.downgrade_to_plain.bump();
        self.dirty = true;
    }

    /// Counts one post-window probe-sweep relocation (`pr=`), noted by the
    /// serving storage when the DNS transport drains a probe relocation. The
    /// counter is an event fold disjoint from the serving `dp=` downgrade
    /// surface, never a latched level.
    pub(crate) const fn note_fact_probe_relocation(&mut self) {
        self.facts.probe_relocations.bump();
        self.dirty = true;
    }

    /// Counts one pin-matching certificate whose Not-Before/Not-After window
    /// excluded the handshake instant (`ep=`), noted by the serving storage
    /// when the DNS transport drains a warning (RT-007). The counter is an
    /// event fold like `dp`/`pr`, never a latched level.
    pub(crate) const fn note_fact_expired_pin_cert(&mut self) {
        self.facts.expired_pin_certs.bump();
        self.dirty = true;
    }

    /// Counts one first-seen JA4 baseline overflow for an ordinal: the serving
    /// path records a JA4 that does not fit the ordinal's set (the set holds
    /// up to `MAX_ADDRESSES` distinct strings). The per-ordinal counter is an
    /// event fold, emitted by the monitor record's JA4-change surface; the
    /// 36-byte value is retained as the latest overflowed JA4 for the ordinal,
    /// keyed to the triggering peer's destination IP (SP-013). The overflow
    /// also latches the per-ordinal detail-loss flag (`d<j>x`): the deviation
    /// decision fires regardless of set capacity, but the overflowed value is
    /// not added to the set, so the operator sees that detail was suppressed.
    pub(crate) const fn note_fact_ja4_change(
        &mut self,
        ordinal: DomainOrdinal,
        ja4: [u8; 36],
        peer_ip: NumericAddr,
    ) {
        self.facts.ja4_change[ordinal.get()].bump();
        self.facts.ja4_change_loss[ordinal.get()] = true;
        self.facts.ja4_value[ordinal.get()] = ja4;
        self.facts.ja4_peer_ip = peer_ip;
        self.facts.ja4_peer_ordinal = Some(ordinal);
        self.dirty = true;
    }

    /// Counts one first-seen JA4 baseline seeding event: a JA4 added to an
    /// ordinal's set. The global counter is an operator-visible fact so
    /// re-seeding churn is distinguishable from attacker-driven re-seed
    /// (SP-005).
    pub(crate) const fn note_fact_ja4_seed(&mut self) {
        self.facts.ja4_seed.bump();
        self.dirty = true;
    }

    pub(crate) const fn note_action_first_slot_block(&mut self, scope: Scope) {
        self.actions.first_slot_block[scope as usize].bump();
        self.dirty = true;
    }

    pub(crate) const fn note_action_domain_block(&mut self, ordinal: DomainOrdinal) {
        self.actions.domain_block[ordinal.get()].bump();
        self.dirty = true;
    }

    pub(crate) const fn note_action_notify(&mut self, ordinal: DomainOrdinal) {
        self.actions.notify[ordinal.get()].bump();
        self.dirty = true;
    }

    pub(crate) const fn note_block_all(&mut self) {
        self.actions.block_all.bump();
        self.dirty = true;
    }

    pub(crate) const fn note_refusal_blocked_domain(&mut self, ordinal: DomainOrdinal) {
        self.refusals.blocked_domain[ordinal.get()].bump();
        self.dirty = true;
    }

    pub(crate) const fn note_report_drop(&mut self) {
        self.report_drops.bump();
        self.dirty = true;
    }

    pub(crate) const fn note_consumed_capture(&mut self, capture: SlotCapture) {
        let Some(detail) = capture.detail else {
            return;
        };
        let consumed = ConsumedCapture {
            slot: capture.slot,
            generation: capture.generation,
            detail,
        };
        if self.capture_len == CAPTURE_DETAIL_LEN {
            self.capture_drops.bump();
            self.captures[self.capture_head] = Some(consumed);
            self.capture_head = (self.capture_head + 1) % CAPTURE_DETAIL_LEN;
        } else {
            let index = (self.capture_head + self.capture_len) % CAPTURE_DETAIL_LEN;
            self.captures[index] = Some(consumed);
            self.capture_len += 1;
        }
        self.dirty = true;
    }

    pub(crate) const fn note_suppressed_detail(&mut self) {
        self.capture_drops.bump();
        self.dirty = true;
    }

    pub(crate) fn report_due(&self, secs: u64) -> bool {
        self.dirty && self.last_report_secs != Some(secs)
    }

    pub(crate) fn mark_reported(&mut self, secs: u64) {
        self.last_report_secs = Some(secs);
        self.dirty = false;
        self.clear_captures();
    }

    pub(crate) fn mark_forced_reported(&mut self) {
        self.dirty = false;
        self.clear_captures();
    }

    fn clear_captures(&mut self) {
        self.captures = std::array::from_fn(|_| None);
        self.capture_head = 0;
        self.capture_len = 0;
    }

    #[cfg(test)]
    pub(crate) const fn facts_any_illegal(&self, cause: AnyIllegalCause) -> u32 {
        self.facts.any_illegal[cause.kind_index()].value()
    }

    pub(crate) fn facts_any_illegal_total(&self) -> u64 {
        self.facts
            .any_illegal
            .iter()
            .map(|c| u64::from(c.value()))
            .sum()
    }

    pub(crate) const fn facts_early_data(&self, ordinal: DomainOrdinal) -> u32 {
        self.facts.early_data[ordinal.get()].value()
    }

    pub(crate) const fn facts_ja4_change(&self, ordinal: DomainOrdinal) -> u32 {
        self.facts.ja4_change[ordinal.get()].value()
    }

    pub(crate) const fn facts_ja4_change_loss(&self, ordinal: DomainOrdinal) -> bool {
        self.facts.ja4_change_loss[ordinal.get()]
    }

    pub(crate) const fn facts_ja4_value(&self, ordinal: DomainOrdinal) -> [u8; 36] {
        self.facts.ja4_value[ordinal.get()]
    }

    pub(crate) const fn facts_ja4_seed(&self) -> u32 {
        self.facts.ja4_seed.value()
    }

    pub(crate) const fn ja4_peer_ordinal(&self) -> Option<DomainOrdinal> {
        self.facts.ja4_peer_ordinal
    }

    pub(crate) const fn ja4_peer_ip(&self) -> NumericAddr {
        self.facts.ja4_peer_ip
    }

    #[cfg(test)]
    pub(crate) const fn facts_unknown(&self, reason: UnknownReason) -> u32 {
        self.facts.unknown[reason.index()].value()
    }

    pub(crate) const fn facts_any_illegal_by_index(&self, index: usize) -> u32 {
        self.facts.any_illegal[index].value()
    }

    pub(crate) const fn facts_unknown_by_index(&self, index: usize) -> u32 {
        self.facts.unknown[index].value()
    }

    pub(crate) const fn facts_resolver_degraded(&self) -> u32 {
        self.facts.resolver_degraded.value()
    }

    pub(crate) const fn facts_resolver_degraded_overflow(&self) -> bool {
        self.facts.resolver_degraded.overflow()
    }

    pub(crate) const fn facts_dns_anomaly(&self, kind: DnsAnomalyKind) -> u32 {
        self.facts.dns_anomaly[kind.index()].value()
    }

    pub(crate) fn facts_dns_anomaly_overflow(&self) -> bool {
        self.facts.dns_anomaly.iter().any(|c| c.overflow())
    }

    pub(crate) const fn facts_downgrade_to_plain(&self) -> u32 {
        self.facts.downgrade_to_plain.value()
    }

    pub(crate) const fn facts_downgrade_to_plain_overflow(&self) -> bool {
        self.facts.downgrade_to_plain.overflow()
    }

    pub(crate) const fn facts_probe_relocations(&self) -> u32 {
        self.facts.probe_relocations.value()
    }

    pub(crate) const fn facts_probe_relocations_overflow(&self) -> bool {
        self.facts.probe_relocations.overflow()
    }

    pub(crate) const fn facts_expired_pin_certs(&self) -> u32 {
        self.facts.expired_pin_certs.value()
    }

    pub(crate) const fn facts_expired_pin_certs_overflow(&self) -> bool {
        self.facts.expired_pin_certs.overflow()
    }

    pub(crate) fn unknown_total(&self) -> u64 {
        self.facts
            .unknown
            .iter()
            .map(|c| u64::from(c.value()))
            .sum()
    }

    pub(crate) fn facts_total(&self) -> u64 {
        self.facts_any_illegal_total()
            + self
                .facts
                .early_data
                .iter()
                .map(|c| u64::from(c.value()))
                .sum::<u64>()
            + self.unknown_total()
            + u64::from(self.facts.resolver_degraded.value())
            + self
                .facts
                .dns_anomaly
                .iter()
                .map(|c| u64::from(c.value()))
                .sum::<u64>()
            + u64::from(self.facts.downgrade_to_plain.value())
            + u64::from(self.facts.probe_relocations.value())
            + u64::from(self.facts.expired_pin_certs.value())
            + u64::from(self.facts.ja4_seed.value())
            + self
                .facts
                .ja4_change
                .iter()
                .map(|c| u64::from(c.value()))
                .sum::<u64>()
    }

    pub(crate) const fn actions_block_all(&self) -> u32 {
        self.actions.block_all.value()
    }

    pub(crate) const fn actions_domain_block(&self, ordinal: DomainOrdinal) -> u32 {
        self.actions.domain_block[ordinal.get()].value()
    }

    pub(crate) const fn refusals_blocked_domain(&self, ordinal: DomainOrdinal) -> u32 {
        self.refusals.blocked_domain[ordinal.get()].value()
    }

    pub(crate) const fn actions_first_slot_block(&self, scope: Scope) -> u32 {
        self.actions.first_slot_block[scope as usize].value()
    }

    pub(crate) fn actions_total(&self) -> u64 {
        self.actions
            .domain_block
            .iter()
            .map(|c| u64::from(c.value()))
            .sum::<u64>()
            + self
                .actions
                .notify
                .iter()
                .map(|c| u64::from(c.value()))
                .sum::<u64>()
            + self
                .actions
                .first_slot_block
                .iter()
                .map(|c| u64::from(c.value()))
                .sum::<u64>()
    }

    pub(crate) const fn actions_notify(&self, ordinal: DomainOrdinal) -> u32 {
        self.actions.notify[ordinal.get()].value()
    }

    pub(crate) fn refusals_total(&self) -> u64 {
        self.refusals
            .blocked_domain
            .iter()
            .map(|c| u64::from(c.value()))
            .sum()
    }

    pub(crate) const fn capture_detail_len(&self) -> usize {
        self.capture_len
    }

    pub(crate) const fn capture_detail(&self, i: usize) -> Option<ConsumedCapture> {
        if i >= self.capture_len {
            return None;
        }
        self.captures[(self.capture_head + i) % CAPTURE_DETAIL_LEN]
    }

    pub(crate) const fn capture_drops(&self) -> u32 {
        self.capture_drops.value()
    }

    pub(crate) const fn capture_drops_overflow(&self) -> bool {
        self.capture_drops.overflow()
    }

    pub(crate) const fn report_drops(&self) -> u32 {
        self.report_drops.value()
    }

    pub(crate) const fn serving_stale(&self) -> bool {
        self.serving_stale
    }

    pub(crate) const fn sustained_negatives(&self) -> u8 {
        self.sustained_negatives
    }

    pub(crate) fn facts_any_illegal_overflow(&self) -> bool {
        self.facts.any_illegal.iter().any(|c| c.overflow())
    }

    pub(crate) fn facts_early_data_overflow(&self) -> bool {
        self.facts.early_data.iter().any(|c| c.overflow())
    }

    pub(crate) fn facts_ja4_change_overflow(&self) -> bool {
        self.facts.ja4_change.iter().any(|c| c.overflow())
    }

    pub(crate) const fn facts_ja4_seed_overflow(&self) -> bool {
        self.facts.ja4_seed.overflow()
    }

    pub(crate) fn facts_unknown_overflow(&self) -> bool {
        self.facts.unknown.iter().any(|c| c.overflow())
    }

    pub(crate) fn actions_overflow(&self) -> bool {
        self.actions.first_slot_block.iter().any(|c| c.overflow())
            || self.actions.domain_block.iter().any(|c| c.overflow())
            || self.actions.notify.iter().any(|c| c.overflow())
            || self.actions.block_all.overflow()
    }

    pub(crate) fn refusals_overflow(&self) -> bool {
        self.refusals.blocked_domain.iter().any(|c| c.overflow())
    }

    pub(crate) const fn report_drops_overflow(&self) -> bool {
        self.report_drops.overflow()
    }

    #[cfg(test)]
    pub(crate) const fn saturate_facts_any_illegal_for_test(&mut self, cause: AnyIllegalCause) {
        self.facts.any_illegal[cause.kind_index()].saturate_for_test();
        self.dirty = true;
    }

    #[cfg(test)]
    pub(crate) fn saturate_all_for_test(&mut self) {
        for c in &mut self.facts.any_illegal {
            c.saturate_for_test();
        }
        for c in &mut self.facts.early_data {
            c.saturate_for_test();
        }
        for c in &mut self.facts.unknown {
            c.saturate_for_test();
        }
        self.facts.resolver_degraded.saturate_for_test();
        for c in &mut self.facts.dns_anomaly {
            c.saturate_for_test();
        }
        self.facts.downgrade_to_plain.saturate_for_test();
        self.facts.probe_relocations.saturate_for_test();
        self.facts.expired_pin_certs.saturate_for_test();
        self.facts.ja4_seed.saturate_for_test();
        self.facts.ja4_peer_ip = NumericAddr::V4(Ipv4Addr::from([203, 0, 113, 1]));
        self.facts.ja4_peer_ordinal = DomainOrdinal::from_index(ALLOWLIST_MAX - 1);
        for c in &mut self.facts.ja4_change {
            c.saturate_for_test();
        }
        self.facts.ja4_change_loss.fill(true);
        self.facts
            .ja4_value
            .fill(*b"t13d1516h2_8daaf6152771_02713d6af862");
        for c in &mut self.actions.first_slot_block {
            c.saturate_for_test();
        }
        for c in &mut self.actions.domain_block {
            c.saturate_for_test();
        }
        for c in &mut self.actions.notify {
            c.saturate_for_test();
        }
        self.actions.block_all.saturate_for_test();
        for c in &mut self.refusals.blocked_domain {
            c.saturate_for_test();
        }
        self.report_drops.saturate_for_test();
        for _ in 0..CAPTURE_DETAIL_LEN {
            let index = (self.capture_head + self.capture_len) % CAPTURE_DETAIL_LEN;
            self.captures[index] = Some(ConsumedCapture {
                slot: crate::inventory::TUNNEL_SLOTS - 1,
                generation: u64::MAX,
                detail: CapturedDetail {
                    fact: CapturedFact::AnyIllegal(AnyIllegalCause::TlsProfile(
                        crate::client_hello::HelloRejectReason::Profile,
                    )),
                    effect: Effect::Block {
                        scope: crate::enforcement::action::Scope::Domain,
                    },
                },
            });
            self.capture_len += 1;
        }
        self.capture_drops.saturate_for_test();
        self.sustained_negatives = 32;
        self.dirty = true;
    }

    #[cfg(test)]
    pub(crate) fn set_peer_ip_v6_max_for_test(&mut self) {
        self.facts.ja4_peer_ip = NumericAddr::V6(std::net::Ipv6Addr::from([0xff; 16]));
        self.dirty = true;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::enforcement::action::{
        ActionKind, AnyIllegalControl, Control, FirstSlot, PerFqdnControl, Scope,
    };
    use crate::enforcement::policy::{Effect, Violation};
    use crate::enforcement::state::Enforcement;

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
        let mut en = Enforcement::new(table(
            any_controls(ActionKind::Block, Scope::Connection),
            &[(ActionKind::Notify, Scope::Connection)],
            &[(ActionKind::Notify, Scope::Connection)],
        ));
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
        let mut en = Enforcement::new(table(
            any_controls(ActionKind::Block, Scope::Connection),
            &actions,
            &actions,
        ));
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
        use crate::connect::ConnectHeadReason;
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
}

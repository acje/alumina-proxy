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
pub(crate) mod tests;

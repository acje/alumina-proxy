use crate::config::ALLOWLIST_MAX;
use crate::dns::cache::Family;
use crate::dns::outcome::FailureReason;

/// Lower bound of the normal refresh interval, in seconds.
pub const REFRESH_MIN: u64 = 5;

/// Upper bound of the normal and negative refresh intervals, in seconds.
pub const REFRESH_MAX: u64 = 900;

/// Lower bound of the negative refresh interval, in seconds.
pub const NEGATIVE_REFRESH_MIN: u64 = 30;

/// The bounded retry backoff ladder, in seconds. The final stage repeats until
/// a validated positive answer with cacheable bindings resets the type.
pub const BACKOFF_STAGES: [u64; 6] = [1, 2, 4, 8, 16, 30];

#[expect(clippy::cast_possible_truncation, reason = "six backoff stages fit u8")]
const LAST_BACKOFF_STAGE: u8 = (BACKOFF_STAGES.len() - 1) as u8;

/// The sustained-negative incident threshold: a name opens an incident when
/// its consecutive validated-NXDOMAIN streak reaches this count.
pub const INCIDENT_N: u8 = 8;

/// The number of distinct whole-hour windows a sustained-negative streak must
/// span before the incident opens.
pub const INCIDENT_M: u8 = 2;

/// The whole-hour window length for the incident span test, in seconds.
pub const INCIDENT_WINDOW: u64 = 3600;

/// The SOA TTL and MINIMUM of a validated negative answer, used to schedule
/// the next negative refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Soa {
    ttl: u64,
    minimum: u64,
}

impl Soa {
    #[must_use]
    pub const fn new(ttl: u64, minimum: u64) -> Soa {
        Soa { ttl, minimum }
    }

    fn min_ttl(self) -> u64 {
        self.ttl.min(self.minimum)
    }
}

/// Returns the normal refresh interval for an entry TTL, honoring the fixed
/// 5/900-second bounds. A zero TTL (one-second fresh usability, no stale
/// admission) refreshes at the one-second boundary so steering availability is
/// preserved without ever extending authorization (F-10).
#[must_use]
pub fn normal_refresh_interval(ttl: u64) -> u64 {
    if ttl == 0 {
        1
    } else {
        ttl.clamp(REFRESH_MIN, REFRESH_MAX)
    }
}

/// Returns the negative refresh interval for a validated negative answer's
/// SOA, honoring its own 30/900-second bounds after taking the earlier of its
/// TTL and MINIMUM.
#[must_use]
pub fn negative_refresh_interval(soa: Soa) -> u64 {
    soa.min_ttl().clamp(NEGATIVE_REFRESH_MIN, REFRESH_MAX)
}

fn advance_backoff(stage: u8) -> u8 {
    stage.saturating_add(1).min(LAST_BACKOFF_STAGE)
}

/// Reasons a scheduling operation can refuse; every failure leaves the table
/// unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleError {
    NameOutOfRange,
    DeadlineOverflow,
}

/// One fixed schedule slot: one due time per name and family, one in-flight
/// flag, one start-rate guard, and one independent retry backoff stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    due: Option<u64>,
    pending: bool,
    not_before: u64,
    backoff: u8,
}

const UNDUE: Slot = Slot {
    due: None,
    pending: false,
    not_before: 0,
    backoff: 0,
};

/// A by-value record of one exchange selected from the due table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DueToken {
    name: usize,
    family: Family,
}

impl DueToken {
    /// The admitted name index of the selected exchange, matching
    /// `Cache::name_index` numbering for later cache integration.
    #[must_use]
    pub const fn name(&self) -> usize {
        self.name
    }

    /// The record family of the selected exchange.
    #[must_use]
    pub const fn family(&self) -> Family {
        self.family
    }
}

/// The per-name sustained-negative streak state: the consecutive validated
/// NXDOMAIN count, the distinct whole-hour windows the streak has spanned, and
/// the last window the streak touched. NODATA and exchange failures never
/// touch it; a validated positive (either family) resets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NegativeStreak {
    count: u8,
    windows: u8,
    last_window: u64,
}

const STREAK_CLEAR: NegativeStreak = NegativeStreak {
    count: 0,
    windows: 0,
    last_window: u64::MAX,
};

/// The incident-state delta one validated outcome produces for a name:
/// whether a sustained-negative incident opened or closed, or neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncidentTransition {
    Opened,
    Closed,
    None,
}

/// The per-type exchange-failure incident state for one allowlist name and
/// family: either closed, or open with the monotonic second at which it opened
/// and the reason of the most recent failure while open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TypeIncident {
    Closed,
    Open {
        opened_at: u64,
        reason: FailureReason,
    },
}

const INCIDENT_CLEAR: TypeIncident = TypeIncident::Closed;

/// The per-type incident delta one exchange failure or validated outcome
/// produces for one family: whether a per-type incident opened, updated
/// silently, recovered, or stayed unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerTypeTransition {
    Opened,
    SilentUpdate,
    Recovered { duration: u64 },
    None,
}

/// The incident deltas a validated outcome produces for one name: the
/// sustained-negative delta plus the per-type deltas in A/Aaaa slot order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutcomeIncidents {
    pub sustained: IncidentTransition,
    pub per_type: [PerTypeTransition; 2],
}

pub(crate) const fn family_slot(family: Family) -> usize {
    match family {
        Family::A => 0,
        Family::Aaaa => 1,
    }
}

/// A fully computed single-family schedule delta, prepared without mutating the
/// table so a two-resource outcome (schedule plus cache) can be validated
/// before the cache commits: any refusal is observed with neither resource
/// changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedDue {
    due: u64,
    backoff: u8,
}

/// The fixed per-name, per-family DNS due table with independent retry state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedules {
    name_count: u8,
    next_scan: u8,
    slots: [[Slot; 2]; ALLOWLIST_MAX],
    next_due: Option<u64>,
    negative_streaks: [NegativeStreak; ALLOWLIST_MAX],
    exchange_incidents: [[TypeIncident; 2]; ALLOWLIST_MAX],
}

impl Schedules {
    /// Constructs a fixed due table admitting `name_count` allowlist names.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name_count` is zero or exceeds
    /// `ALLOWLIST_MAX`.
    pub fn new(name_count: usize) -> Result<Schedules, ScheduleError> {
        if name_count == 0 || name_count > ALLOWLIST_MAX {
            return Err(ScheduleError::NameOutOfRange);
        }
        let name_count = u8::try_from(name_count).map_err(|_| ScheduleError::NameOutOfRange)?;
        Ok(Schedules {
            name_count,
            next_scan: 0,
            slots: [[UNDUE; 2]; ALLOWLIST_MAX],
            next_due: None,
            negative_streaks: [STREAK_CLEAR; ALLOWLIST_MAX],
            exchange_incidents: [[INCIDENT_CLEAR; 2]; ALLOWLIST_MAX],
        })
    }

    /// The number of admitted names.
    #[must_use]
    pub fn name_count(&self) -> usize {
        usize::from(self.name_count)
    }

    const fn slot(&self, name: usize, family: Family) -> &Slot {
        &self.slots[name][family_slot(family)]
    }

    const fn slot_mut(&mut self, name: usize, family: Family) -> &mut Slot {
        &mut self.slots[name][family_slot(family)]
    }

    fn earliest_selectable_at(&self) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        let total = self.name_count() * 2;
        for linear in 0..total {
            let name = linear >> 1;
            let family = match linear & 1 == 0 {
                true => Family::A,
                false => Family::Aaaa,
            };
            let slot = self.slot(name, family);
            if slot.pending {
                continue;
            }
            let Some(due) = slot.due else {
                continue;
            };
            let selectable_at = due.max(slot.not_before);
            earliest = Some(earliest.map_or(selectable_at, |e| e.min(selectable_at)));
        }
        earliest
    }

    fn recompute_next_due(&mut self) {
        self.next_due = self.earliest_selectable_at();
    }

    fn admit(&self, name: usize) -> Result<(), ScheduleError> {
        if name < self.name_count() {
            Ok(())
        } else {
            Err(ScheduleError::NameOutOfRange)
        }
    }

    /// The currently scheduled due time for `name` and `family`, when any.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted.
    pub fn due_time(&self, name: usize, family: Family) -> Result<Option<u64>, ScheduleError> {
        self.admit(name)?;
        Ok(self.slot(name, family).due)
    }

    /// Overwrites the due time for `name` and `family` with `due`, superseding
    /// any prior schedule for the same slot and its in-flight marker.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted.
    pub fn overwrite_due_at(
        &mut self,
        name: usize,
        family: Family,
        due: u64,
    ) -> Result<(), ScheduleError> {
        self.admit(name)?;
        let slot = self.slot_mut(name, family);
        slot.due = Some(due);
        slot.pending = false;
        self.recompute_next_due();
        Ok(())
    }

    /// Completes a selection that performed no exchange: clears the in-flight
    /// marker while preserving the due time and the one-second start guard. A
    /// resolved name's skipped sibling family therefore stays selectable for a
    /// later serving refresh without its pending flag leaking.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted.
    pub fn release_selection(&mut self, name: usize, family: Family) -> Result<(), ScheduleError> {
        self.admit(name)?;
        self.slot_mut(name, family).pending = false;
        self.recompute_next_due();
        Ok(())
    }

    /// Records a validated positive outcome for one family.
    ///
    /// A cacheable positive resets that family's backoff and schedules the next
    /// normal refresh from `receipt`; a positive without cacheable bindings
    /// advances the backoff and schedules a retry from `now`.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` or `DeadlineOverflow`; on either the slot is
    /// unchanged.
    pub fn note_positive(
        &mut self,
        name: usize,
        family: Family,
        receipt: u64,
        ttl: u64,
        cacheable: bool,
        now: u64,
    ) -> Result<(), ScheduleError> {
        let prepared = self.prepare_positive(name, family, receipt, ttl, cacheable, now)?;
        self.commit_positive(name, family, prepared);
        Ok(())
    }

    /// Computes the single-family schedule delta a validated positive would
    /// apply, without mutating the table, so a caller can validate the whole
    /// outcome before the cache changes: a `DeadlineOverflow` or out-of-range
    /// name is refused with the slot untouched.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` or `DeadlineOverflow` exactly as
    /// [`Self::note_positive`].
    pub(crate) fn prepare_positive(
        &self,
        name: usize,
        family: Family,
        receipt: u64,
        ttl: u64,
        cacheable: bool,
        now: u64,
    ) -> Result<PreparedDue, ScheduleError> {
        self.admit(name)?;
        let slot = self.slot(name, family);
        let stage = slot.backoff;
        let (due, backoff) = if cacheable {
            (
                receipt
                    .checked_add(normal_refresh_interval(ttl))
                    .ok_or(ScheduleError::DeadlineOverflow)?,
                0,
            )
        } else {
            (
                now.checked_add(BACKOFF_STAGES[usize::from(stage)])
                    .ok_or(ScheduleError::DeadlineOverflow)?,
                advance_backoff(stage),
            )
        };
        Ok(PreparedDue { due, backoff })
    }

    /// Commits a prepared single-family delta; never fails after
    /// [`Self::prepare_positive`] succeeded.
    pub(crate) fn commit_positive(&mut self, name: usize, family: Family, prepared: PreparedDue) {
        self.commit_slot(name, family, prepared);
    }

    /// Records an exchange failure for one family, scheduling a retry from
    /// `now` at that family's current backoff stage and advancing the ladder.
    /// The failure also advances the per-type incident for the family: the
    /// first failure opens it, a later failure updates it silently.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` or `DeadlineOverflow`; on either the slot is
    /// unchanged and the incident is untouched.
    pub fn note_exchange_failure(
        &mut self,
        name: usize,
        family: Family,
        now: u64,
        reason: FailureReason,
    ) -> Result<PerTypeTransition, ScheduleError> {
        self.admit(name)?;
        let slot = self.slot_mut(name, family);
        let stage = slot.backoff;
        let new_due = now
            .checked_add(BACKOFF_STAGES[usize::from(stage)])
            .ok_or(ScheduleError::DeadlineOverflow)?;
        slot.due = Some(new_due);
        slot.backoff = advance_backoff(stage);
        slot.pending = false;
        self.recompute_next_due();
        let incident = &mut self.exchange_incidents[name][family_slot(family)];
        match *incident {
            TypeIncident::Open { opened_at, .. } => {
                *incident = TypeIncident::Open { opened_at, reason };
                Ok(PerTypeTransition::SilentUpdate)
            }
            TypeIncident::Closed => {
                *incident = TypeIncident::Open {
                    opened_at: now,
                    reason,
                };
                Ok(PerTypeTransition::Opened)
            }
        }
    }

    /// Clears an open per-type incident for one family, reporting the elapsed
    /// duration since it opened. A closed incident clears nothing.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted.
    pub fn clear_exchange_incident(
        &mut self,
        name: usize,
        family: Family,
        now: u64,
    ) -> Result<PerTypeTransition, ScheduleError> {
        self.admit(name)?;
        let incident = &mut self.exchange_incidents[name][family_slot(family)];
        match *incident {
            TypeIncident::Open { opened_at, .. } => {
                let duration = now.saturating_sub(opened_at);
                *incident = INCIDENT_CLEAR;
                Ok(PerTypeTransition::Recovered { duration })
            }
            TypeIncident::Closed => Ok(PerTypeTransition::None),
        }
    }

    /// Returns the per-type exchange-failure incident state for one allowlist
    /// name and family, or `None` when `name` is not admitted. Read-only; used
    /// by the serving-side reporting surface to reconcile its windows with the
    /// schedule's incident state (including incidents opened before serving
    /// began).
    pub(crate) fn incident(&self, name: usize, family: Family) -> Option<TypeIncident> {
        if name >= usize::from(self.name_count) {
            return None;
        }
        Some(self.exchange_incidents[name][family_slot(family)])
    }

    /// Records a validated NXDOMAIN for the whole name.
    ///
    /// With an SOA, both families are scheduled for the negative refresh from
    /// `receipt` and their backoff stages are left untouched; without an SOA,
    /// both families advance their backoff and schedule from `now`.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` or `DeadlineOverflow`; on either error no slot
    /// changes.
    pub fn note_nxdomain(
        &mut self,
        name: usize,
        soa: Option<Soa>,
        receipt: u64,
        now: u64,
    ) -> Result<(), ScheduleError> {
        let prepared = self.prepare_nxdomain(name, soa, receipt, now)?;
        self.commit_nxdomain(name, prepared);
        Ok(())
    }

    /// Computes the two-family schedule delta a validated NXDOMAIN would
    /// apply, without mutating the table, so a caller can validate the whole
    /// outcome before the cache changes: a `DeadlineOverflow` or out-of-range
    /// name is refused with every slot untouched.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` or `DeadlineOverflow` exactly as
    /// [`Self::note_nxdomain`].
    pub(crate) fn prepare_nxdomain(
        &self,
        name: usize,
        soa: Option<Soa>,
        receipt: u64,
        now: u64,
    ) -> Result<[PreparedDue; 2], ScheduleError> {
        self.admit(name)?;
        let mut prepared = [PreparedDue { due: 0, backoff: 0 }; 2];
        for family in [Family::A, Family::Aaaa] {
            let slot = self.slot(name, family);
            let (due, backoff) = match soa {
                Some(soa) => (
                    receipt
                        .checked_add(negative_refresh_interval(soa))
                        .ok_or(ScheduleError::DeadlineOverflow)?,
                    slot.backoff,
                ),
                None => (
                    now.checked_add(BACKOFF_STAGES[usize::from(slot.backoff)])
                        .ok_or(ScheduleError::DeadlineOverflow)?,
                    advance_backoff(slot.backoff),
                ),
            };
            prepared[family_slot(family)] = PreparedDue { due, backoff };
        }
        Ok(prepared)
    }

    /// Commits a prepared two-family delta; never fails after
    /// [`Self::prepare_nxdomain`] succeeded.
    pub(crate) fn commit_nxdomain(&mut self, name: usize, prepared: [PreparedDue; 2]) {
        for family in [Family::A, Family::Aaaa] {
            self.commit_slot(name, family, prepared[family_slot(family)]);
        }
    }

    /// Records one validated NXDOMAIN on the name's sustained-negative streak
    /// and returns whether the incident opened. The streak increments only on
    /// a validated NXDOMAIN; NODATA and exchange failures never touch it. The
    /// incident opens once the streak reaches `INCIDENT_N` across
    /// `INCIDENT_M` distinct whole-hour windows, and stays open (no re-open)
    /// until a validated positive resets it.
    pub(crate) const fn note_negative_streak(
        &mut self,
        name: usize,
        now: u64,
    ) -> IncidentTransition {
        let streak = &mut self.negative_streaks[name];
        let was_incident = streak.count >= INCIDENT_N && streak.windows >= INCIDENT_M;
        streak.count = streak.count.saturating_add(1);
        let window = now / INCIDENT_WINDOW;
        if window != streak.last_window {
            streak.windows = streak.windows.saturating_add(1);
            streak.last_window = window;
        }
        let is_incident = streak.count >= INCIDENT_N && streak.windows >= INCIDENT_M;
        if is_incident && !was_incident {
            IncidentTransition::Opened
        } else {
            IncidentTransition::None
        }
    }

    /// Resets the name's sustained-negative streak on a validated positive
    /// (either family) and returns whether an open incident closed.
    pub(crate) const fn reset_negative_streak(&mut self, name: usize) -> IncidentTransition {
        let streak = &mut self.negative_streaks[name];
        let was_incident = streak.count >= INCIDENT_N && streak.windows >= INCIDENT_M;
        *streak = STREAK_CLEAR;
        if was_incident {
            IncidentTransition::Closed
        } else {
            IncidentTransition::None
        }
    }

    /// Records a validated NODATA for the queried family only.
    ///
    /// With an SOA, the family is scheduled for the negative refresh from
    /// `receipt` and its backoff stage is left untouched; without an SOA, its
    /// backoff advances and schedules from `now`. The other family is
    /// unaffected.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` or `DeadlineOverflow`; on either the slot is
    /// unchanged.
    pub fn note_nodata(
        &mut self,
        name: usize,
        family: Family,
        soa: Option<Soa>,
        receipt: u64,
        now: u64,
    ) -> Result<(), ScheduleError> {
        let prepared = self.prepare_nodata(name, family, soa, receipt, now)?;
        self.commit_nodata(name, family, prepared);
        Ok(())
    }

    /// Computes the single-family schedule delta a validated NODATA would
    /// apply, without mutating the table, so a caller can validate the whole
    /// outcome before the cache changes: a `DeadlineOverflow` or out-of-range
    /// name is refused with the slot untouched.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` or `DeadlineOverflow` exactly as
    /// [`Self::note_nodata`].
    pub(crate) fn prepare_nodata(
        &self,
        name: usize,
        family: Family,
        soa: Option<Soa>,
        receipt: u64,
        now: u64,
    ) -> Result<PreparedDue, ScheduleError> {
        self.admit(name)?;
        let slot = self.slot(name, family);
        let stage = slot.backoff;
        let (due, backoff) = match soa {
            Some(soa) => (
                receipt
                    .checked_add(negative_refresh_interval(soa))
                    .ok_or(ScheduleError::DeadlineOverflow)?,
                stage,
            ),
            None => (
                now.checked_add(BACKOFF_STAGES[usize::from(stage)])
                    .ok_or(ScheduleError::DeadlineOverflow)?,
                advance_backoff(stage),
            ),
        };
        Ok(PreparedDue { due, backoff })
    }

    /// Commits a prepared single-family delta; never fails after
    /// [`Self::prepare_nodata`] succeeded.
    pub(crate) fn commit_nodata(&mut self, name: usize, family: Family, prepared: PreparedDue) {
        self.commit_slot(name, family, prepared);
    }

    /// Non-fallible commit of a [`PreparedDue`] onto its slot, clearing the
    /// in-flight marker; reserved for values returned by a successful
    /// `prepare_*`.
    fn commit_slot(&mut self, name: usize, family: Family, prepared: PreparedDue) {
        let slot = self.slot_mut(name, family);
        slot.due = Some(prepared.due);
        slot.backoff = prepared.backoff;
        slot.pending = false;
        self.recompute_next_due();
    }

    /// Selects at most one due exchange, scanning in fixed rotating
    /// round-robin order from the last served slot so repeated failures cannot
    /// monopolize selection.
    ///
    /// A selected slot is marked pending and rate-limited to at most one start
    /// per second until an outcome routes back; the returned token is by value,
    /// and tracking a single globally outstanding exchange belongs to the later
    /// transport owner. Delayed processing coalesces: an overdue slot is simply
    /// selected once when scanned, with no catch-up queue.
    ///
    /// # Errors
    ///
    /// Returns `DeadlineOverflow` only when the start-rate timestamp cannot be
    /// represented (at `now == u64::MAX`); no slot is changed.
    ///
    /// # Panics
    ///
    /// Panics on the fixed `expect` only if the round-robin scan index does not
    /// fit `u8`, impossible given the bounded slot count.
    #[expect(
        clippy::expect_used,
        reason = "round-robin scan index is bounded by the fixed slot count, which fits u8"
    )]
    pub fn select_due(&mut self, now: u64) -> Result<Option<DueToken>, ScheduleError> {
        let total = self.name_count() * 2;
        for step in 0..total {
            let linear = (usize::from(self.next_scan) + step) % total;
            let name = linear >> 1;
            let family = match linear & 1 == 0 {
                true => Family::A,
                false => Family::Aaaa,
            };
            let slot = self.slot(name, family);
            if slot.pending || slot.not_before > now {
                continue;
            }
            let Some(due) = slot.due else {
                continue;
            };
            if due > now {
                continue;
            }
            let not_before = now.checked_add(1).ok_or(ScheduleError::DeadlineOverflow)?;
            let slot = self.slot_mut(name, family);
            slot.pending = true;
            slot.not_before = not_before;
            self.next_scan =
                u8::try_from((linear + 1) % total).expect("scan index bounded by slot count");
            self.recompute_next_due();
            return Ok(Some(DueToken { name, family }));
        }
        Ok(None)
    }

    /// The earliest whole-second moment at which some non-pending slot becomes
    /// selectable for a due refresh, for a single owner folding the refresh
    /// schedule into its one serving poll wait: a slot contributes the later of
    /// its due time and start-rate guard, and an in-flight slot contributes
    /// nothing (the outstanding exchange's own deadline already bounds the wait
    /// and its outcome rewrites the due time). Returns `Some(now)` when work is
    /// already selectable this instant, and `None` when no slot is scheduled.
    #[must_use]
    pub const fn next_selectable_due(&self, now: u64) -> Option<u64> {
        match self.next_due {
            Some(e) if e <= now => Some(now),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests;

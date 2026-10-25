use crate::cache::Family;
use crate::config::ALLOWLIST_MAX;

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
/// 5/900-second bounds. The floor subsumes the zero-TTL-as-one-second rule.
#[must_use]
pub fn normal_refresh_interval(ttl: u64) -> u64 {
    ttl.clamp(REFRESH_MIN, REFRESH_MAX)
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

const fn family_slot(family: Family) -> usize {
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
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` or `DeadlineOverflow`; on either the slot is
    /// unchanged.
    pub fn note_exchange_failure(
        &mut self,
        name: usize,
        family: Family,
        now: u64,
    ) -> Result<(), ScheduleError> {
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
        Ok(())
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
mod tests {
    use super::*;

    #[cfg(feature = "alloc-witness")]
    use crate::alloc::{Phase, run_phase};

    #[test]
    fn new_admits_only_actual_configured_count() {
        assert_eq!(Schedules::new(0), Err(ScheduleError::NameOutOfRange));
        assert_eq!(
            Schedules::new(ALLOWLIST_MAX + 1),
            Err(ScheduleError::NameOutOfRange)
        );
        for count in [1usize, 2, 31, ALLOWLIST_MAX] {
            assert_eq!(Schedules::new(count).unwrap().name_count(), count);
        }
    }

    #[test]
    fn out_of_range_operations_err_without_mutation() {
        let mut schedules = Schedules::new(2).unwrap();
        let before = schedules;
        assert_eq!(
            schedules.due_time(7, Family::A),
            Err(ScheduleError::NameOutOfRange)
        );
        assert_eq!(
            schedules.overwrite_due_at(7, Family::A, 0),
            Err(ScheduleError::NameOutOfRange)
        );
        assert_eq!(
            schedules.note_positive(7, Family::A, 0, 60, true, 0),
            Err(ScheduleError::NameOutOfRange)
        );
        assert_eq!(
            schedules.note_exchange_failure(7, Family::A, 0),
            Err(ScheduleError::NameOutOfRange)
        );
        assert_eq!(
            schedules.note_nxdomain(7, None, 0, 0),
            Err(ScheduleError::NameOutOfRange)
        );
        assert_eq!(
            schedules.note_nodata(7, Family::A, None, 0, 0),
            Err(ScheduleError::NameOutOfRange)
        );
        assert_eq!(schedules, before, "out-of-range calls must not mutate");
    }

    #[test]
    fn overwrite_supersedes_without_queue() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules
            .note_positive(0, Family::A, 1000, 60, true, 0)
            .unwrap();
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(1060));
        schedules.note_exchange_failure(0, Family::A, 2000).unwrap();
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(2001));
    }

    #[test]
    fn rotating_scan_selects_every_slot_once_per_pass() {
        let mut schedules = Schedules::new(ALLOWLIST_MAX).unwrap();
        for name in 0..ALLOWLIST_MAX {
            schedules.overwrite_due_at(name, Family::A, 0).unwrap();
            schedules.overwrite_due_at(name, Family::Aaaa, 0).unwrap();
        }
        let mut selected = [[false; 2]; ALLOWLIST_MAX];
        for _ in 0..(ALLOWLIST_MAX * 2) {
            let token = schedules.select_due(0).unwrap().expect("due");
            assert!(
                !selected[token.name()][family_slot(token.family())],
                "slot re-selected before a full pass"
            );
            selected[token.name()][family_slot(token.family())] = true;
        }
        assert_eq!(schedules.select_due(0).unwrap(), None, "pass exhausted");
    }

    #[test]
    fn repeated_failures_do_not_starve_other_names() {
        let mut schedules = Schedules::new(2).unwrap();
        for name in 0..2 {
            schedules.overwrite_due_at(name, Family::A, 0).unwrap();
            schedules.overwrite_due_at(name, Family::Aaaa, 0).unwrap();
        }
        for now in [0u64, 1] {
            let mut served = [[false; 2]; 2];
            for _ in 0..4 {
                let token = schedules.select_due(now).unwrap().expect("due");
                assert!(!served[token.name()][family_slot(token.family())]);
                served[token.name()][family_slot(token.family())] = true;
                schedules
                    .note_exchange_failure(token.name(), token.family(), now)
                    .unwrap();
            }
            for row in &served {
                for slot in row {
                    assert!(slot, "slot served");
                }
            }
        }
    }

    #[test]
    fn selected_slot_stays_pending_until_outcome_completes() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.overwrite_due_at(0, Family::A, 0).unwrap();
        let token = schedules.select_due(0).unwrap().unwrap();
        assert_eq!((token.name(), token.family()), (0, Family::A));
        assert_eq!(
            schedules.select_due(0).unwrap(),
            None,
            "pending slot is not re-selected"
        );
        schedules.overwrite_due_at(0, Family::A, 0).unwrap();
        assert_eq!(
            schedules.select_due(0).unwrap(),
            None,
            "start-rate guard blocks reselection in the same second"
        );
        assert!(
            schedules.select_due(1).unwrap().is_some(),
            "completed slot re-selectable after the one-second start guard"
        );
    }

    #[test]
    fn start_rate_guard_holds_within_a_five_second_refresh_cadence() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.overwrite_due_at(0, Family::A, 1000).unwrap();
        let token = schedules.select_due(1000).unwrap().unwrap();
        assert_eq!((token.name(), token.family()), (0, Family::A));
        schedules.overwrite_due_at(0, Family::A, 1005).unwrap();
        schedules.release_selection(0, Family::A).unwrap();
        assert_eq!(
            schedules.select_due(1000).unwrap(),
            None,
            "even at a 5-second fast cadence the one-query-per-second slot guard \
             blocks a same-instant reselect"
        );
        assert_eq!(
            schedules
                .select_due(1005)
                .unwrap()
                .map(|t| (t.name(), t.family())),
            Some((0, Family::A)),
            "once the guard and the 5-second due elapse the same slot is reusable"
        );
    }

    #[test]
    fn select_due_at_u64_max_errors_without_mutation() {
        // G5-C08: `now == u64::MAX` makes the start-rate `checked_add(1)`
        // overflow; the error must surface before any slot is mutated.
        let mut schedules = Schedules::new(1).unwrap();
        schedules.overwrite_due_at(0, Family::A, 0).unwrap();
        let before = schedules;
        assert_eq!(
            schedules.select_due(u64::MAX),
            Err(ScheduleError::DeadlineOverflow)
        );
        assert_eq!(schedules, before, "overflow must not mutate any slot");
        assert_eq!(
            schedules.due_time(0, Family::A).unwrap(),
            Some(0),
            "due time unchanged"
        );
    }

    #[test]
    fn next_selectable_due_guides_the_owner_wake() {
        let mut schedules = Schedules::new(2).unwrap();
        assert_eq!(
            schedules.next_selectable_due(1000),
            None,
            "nothing scheduled yields no wake"
        );

        schedules.overwrite_due_at(0, Family::A, 1000).unwrap();
        assert_eq!(
            schedules.next_selectable_due(999),
            Some(1000),
            "a future due reports the exact selectable moment"
        );
        assert_eq!(
            schedules.next_selectable_due(1005),
            Some(1005),
            "already-selectable work clamps the wake to the present"
        );

        let token = schedules.select_due(1005).unwrap().unwrap();
        assert_eq!(
            (token.name(), token.family()),
            (0, Family::A),
            "the due slot is selected by the owner"
        );
        assert_eq!(
            schedules.next_selectable_due(1005),
            None,
            "an in-flight slot contributes no wake (the exchange deadline owns the wait)"
        );

        schedules.overwrite_due_at(1, Family::Aaaa, 1050).unwrap();
        assert_eq!(
            schedules.next_selectable_due(1005),
            Some(1050),
            "a different slot's future due still drives the owner wake"
        );

        schedules.release_selection(0, Family::A).unwrap();
        assert_eq!(
            schedules.next_selectable_due(1005),
            Some(1006),
            "the one-second start guard holds a due slot until it elapses"
        );
        assert_eq!(
            schedules.next_selectable_due(1007),
            Some(1007),
            "once the guard elapses the slot is selectable now"
        );
    }

    fn oracle_next_due(schedules: &Schedules) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        let total = schedules.name_count() * 2;
        for linear in 0..total {
            let name = linear >> 1;
            let family = match linear & 1 == 0 {
                true => Family::A,
                false => Family::Aaaa,
            };
            let slot = schedules.slot(name, family);
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

    #[test]
    fn cached_next_due_matches_oracle_through_all_mutations() {
        let mut schedules = Schedules::new(3).unwrap();
        let check = |s: &Schedules| {
            let oracle = oracle_next_due(s);
            assert_eq!(s.next_due, oracle, "cache must equal a fresh oracle scan");
            let public = s.next_selectable_due(1000);
            assert_eq!(
                public,
                match oracle {
                    Some(e) if e <= 1000 => Some(1000),
                    other => other,
                },
                "public wake must equal the same scan clamped at `now`"
            );
        };
        check(&schedules);

        schedules.overwrite_due_at(0, Family::A, 1000).unwrap();
        check(&schedules);
        schedules.overwrite_due_at(0, Family::Aaaa, 1020).unwrap();
        check(&schedules);
        let token = schedules.select_due(1000).unwrap().unwrap();
        assert_eq!((token.name(), token.family()), (0, Family::A));
        check(&schedules);
        schedules.note_exchange_failure(0, Family::A, 1000).unwrap();
        check(&schedules);
        schedules.release_selection(0, Family::A).unwrap();
        check(&schedules);
        schedules
            .note_positive(0, Family::A, 1000, 60, true, 1000)
            .unwrap();
        check(&schedules);

        schedules.overwrite_due_at(1, Family::A, 2000).unwrap();
        check(&schedules);
        schedules.note_nxdomain(1, None, 0, 1000).unwrap();
        check(&schedules);
        schedules.note_nodata(1, Family::A, None, 0, 1500).unwrap();
        check(&schedules);

        schedules.overwrite_due_at(2, Family::Aaaa, 500).unwrap();
        check(&schedules);
        schedules.overwrite_due_at(2, Family::Aaaa, 3000).unwrap();
        check(&schedules);
    }

    #[test]
    fn release_selection_clears_pending_keeps_due_and_guard() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.overwrite_due_at(0, Family::Aaaa, 1000).unwrap();
        let token = schedules.select_due(1000).unwrap().expect("due");
        assert_eq!((token.name(), token.family()), (0, Family::Aaaa));
        assert_eq!(
            schedules.select_due(1000).unwrap(),
            None,
            "selected slot is pending until released"
        );
        schedules.release_selection(0, Family::Aaaa).unwrap();
        assert_eq!(schedules.due_time(0, Family::Aaaa).unwrap(), Some(1000));
        assert_eq!(
            schedules.select_due(1000).unwrap(),
            None,
            "start guard still rate-limits re-selection in the same second"
        );
        assert!(schedules.select_due(1001).unwrap().is_some());
        assert_eq!(
            schedules.due_time(0, Family::Aaaa).unwrap(),
            Some(1000),
            "release must not retarget the due time"
        );
        assert_eq!(
            schedules.release_selection(1, Family::A),
            Err(ScheduleError::NameOutOfRange)
        );
    }

    #[test]
    fn normal_refresh_interval_honors_bounds() {
        let vectors = [
            (0u64, 5u64),
            (4, 5),
            (5, 5),
            (6, 6),
            (50, 50),
            (899, 899),
            (900, 900),
            (901, 900),
        ];
        for (ttl, expect) in vectors {
            assert_eq!(normal_refresh_interval(ttl), expect, "ttl={ttl}");
        }
    }

    #[test]
    fn negative_refresh_interval_honors_soa_and_bounds() {
        let cases = [
            (Soa::new(1, 1), 30u64),
            (Soa::new(4, 1000), 30),
            (Soa::new(29, 1000), 30),
            (Soa::new(30, 30), 30),
            (Soa::new(50, 10), 30),
            (Soa::new(31, 1000), 31),
            (Soa::new(899, 1000), 899),
            (Soa::new(1000, 900), 900),
            (Soa::new(901, 901), 900),
        ];
        for (soa, expect) in cases {
            assert_eq!(negative_refresh_interval(soa), expect, "soa={soa:?}");
        }
    }

    #[test]
    fn backoff_ladder_is_exact_and_capped() {
        let mut schedules = Schedules::new(1).unwrap();
        let mut dues = [0u64; 8];
        for due in dues.iter_mut() {
            schedules.note_exchange_failure(0, Family::A, 0).unwrap();
            *due = schedules.due_time(0, Family::A).unwrap().unwrap();
        }
        assert_eq!(&dues[..], &[1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn nxdomain_schedules_both_families_nodata_only_own() {
        let mut schedules = Schedules::new(1).unwrap();
        let soa = Soa::new(60, 60);
        schedules.note_nxdomain(0, Some(soa), 1000, 0).unwrap();
        let expected = 1000 + negative_refresh_interval(soa);
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(expected));
        assert_eq!(schedules.due_time(0, Family::Aaaa).unwrap(), Some(expected));

        schedules.overwrite_due_at(0, Family::A, 5000).unwrap();
        schedules.overwrite_due_at(0, Family::Aaaa, 6000).unwrap();
        schedules
            .note_nodata(0, Family::A, Some(soa), 2000, 0)
            .unwrap();
        let nodata_expected = 2000 + negative_refresh_interval(soa);
        assert_eq!(
            schedules.due_time(0, Family::A).unwrap(),
            Some(nodata_expected)
        );
        assert_eq!(
            schedules.due_time(0, Family::Aaaa).unwrap(),
            Some(6000),
            "NODATA must not touch the other family"
        );
    }

    #[test]
    fn soa_negatives_leave_backoff_stage_unchanged() {
        let mut schedules = Schedules::new(1).unwrap();
        for _ in 0..2 {
            schedules.note_exchange_failure(0, Family::A, 0).unwrap();
            schedules.note_exchange_failure(0, Family::Aaaa, 0).unwrap();
        }
        let soa = Soa::new(60, 60);
        schedules.note_nxdomain(0, Some(soa), 1000, 0).unwrap();
        schedules
            .note_nodata(0, Family::A, Some(soa), 2000, 0)
            .unwrap();
        schedules.note_exchange_failure(0, Family::A, 3000).unwrap();
        schedules
            .note_exchange_failure(0, Family::Aaaa, 4000)
            .unwrap();
        assert_eq!(
            schedules.due_time(0, Family::A).unwrap(),
            Some(3004),
            "stage 2 ladder used after SOA negatives on own family"
        );
        assert_eq!(
            schedules.due_time(0, Family::Aaaa).unwrap(),
            Some(4004),
            "stage 2 ladder used after SOA negatives on other family"
        );
    }

    #[test]
    fn nxdomain_without_soa_one_family_overflow_commits_nothing() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.note_exchange_failure(0, Family::Aaaa, 0).unwrap();
        let before = schedules;
        let near_max = u64::MAX - 1;
        assert_eq!(
            schedules.note_nxdomain(0, None, 0, near_max),
            Err(ScheduleError::DeadlineOverflow),
            "A fits while Aaaa overflows; two-phase commit must refuse both"
        );
        assert_eq!(schedules, before, "no partial application");
    }

    #[test]
    fn long_overdue_slot_selects_once_without_catchup() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.overwrite_due_at(0, Family::A, 0).unwrap();
        let token = schedules.select_due(1000).unwrap().unwrap();
        assert_eq!((token.name(), token.family()), (0, Family::A));
        schedules.note_exchange_failure(0, Family::A, 1000).unwrap();
        assert_eq!(
            schedules.select_due(1000).unwrap(),
            None,
            "overdue delay yields one selection, not a catch-up queue"
        );
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(1001));
    }

    #[test]
    fn nxdomain_without_soa_advances_both_backoffs() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.note_nxdomain(0, None, 0, 1000).unwrap();
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(1001));
        assert_eq!(schedules.due_time(0, Family::Aaaa).unwrap(), Some(1001));
        schedules.note_nxdomain(0, None, 0, 2000).unwrap();
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(2002));
        assert_eq!(schedules.due_time(0, Family::Aaaa).unwrap(), Some(2002));
    }

    #[test]
    fn cacheable_positive_resets_only_its_own_family_backoff() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.note_exchange_failure(0, Family::A, 0).unwrap();
        schedules.note_exchange_failure(0, Family::Aaaa, 0).unwrap();
        schedules
            .note_positive(0, Family::A, 1000, 60, true, 0)
            .unwrap();
        schedules.note_exchange_failure(0, Family::A, 2000).unwrap();
        assert_eq!(
            schedules.due_time(0, Family::A).unwrap(),
            Some(2001),
            "cacheable positive resets its own backoff"
        );
        schedules
            .note_exchange_failure(0, Family::Aaaa, 3000)
            .unwrap();
        assert_eq!(
            schedules.due_time(0, Family::Aaaa).unwrap(),
            Some(3002),
            "other family's backoff is untouched"
        );
    }

    #[test]
    fn empty_eligible_positive_advances_backoff() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules
            .note_positive(0, Family::A, 1000, 60, false, 0)
            .unwrap();
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(1));
        schedules
            .note_positive(0, Family::A, 2000, 60, false, 0)
            .unwrap();
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(2));
    }

    #[test]
    fn deadline_overflow_errs_without_mutation() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.overwrite_due_at(0, Family::A, 100).unwrap();
        schedules.overwrite_due_at(0, Family::Aaaa, 200).unwrap();
        let before = schedules;
        let near_max = u64::MAX - 10;
        assert_eq!(
            schedules.note_positive(0, Family::A, near_max, 60, true, 0),
            Err(ScheduleError::DeadlineOverflow)
        );
        assert_eq!(
            schedules.note_nxdomain(0, Some(Soa::new(60, 60)), near_max, 0),
            Err(ScheduleError::DeadlineOverflow)
        );
        assert_eq!(
            schedules, before,
            "deadline overflow must not mutate either slot"
        );
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn scheduler_paths_do_not_allocate_or_deallocate() {
        let (_, control) = run_phase(Phase::BackgroundRefresh, || 0usize);
        assert!(control.all_zero(), "baseline should be quiet: {control:?}");
        let ((), failure_path) = run_phase(Phase::BackgroundRefresh, || {
            let mut schedules = Schedules::new(2).unwrap();
            for name in 0..2 {
                schedules.overwrite_due_at(name, Family::A, 0).unwrap();
                schedules.overwrite_due_at(name, Family::Aaaa, 0).unwrap();
            }
            for now in [0u64, 1] {
                while let Some(token) = schedules.select_due(now).unwrap() {
                    schedules
                        .note_exchange_failure(token.name(), token.family(), now)
                        .unwrap();
                }
            }
        });
        assert!(
            failure_path.all_zero(),
            "failure path allocated: {failure_path:?}"
        );
        let ((), success_path) = run_phase(Phase::BackgroundRefresh, || {
            let mut schedules = Schedules::new(1).unwrap();
            schedules
                .note_positive(0, Family::A, 1000, 60, true, 0)
                .unwrap();
            schedules
                .note_nxdomain(0, Some(Soa::new(60, 60)), 2000, 0)
                .unwrap();
            schedules
                .note_nodata(0, Family::Aaaa, None, 0, 3000)
                .unwrap();
            while let Some(token) = schedules.select_due(3000).unwrap() {
                schedules
                    .note_exchange_failure(token.name(), token.family(), 3000)
                    .unwrap();
            }
        });
        assert!(
            success_path.all_zero(),
            "success path allocated: {success_path:?}"
        );
    }

    #[test]
    fn sustained_negative_streak_opens_incident_at_n_across_m_windows() {
        let mut schedules = Schedules::new(1).unwrap();
        for _ in 0..(INCIDENT_N - 1) {
            assert_eq!(
                schedules.note_negative_streak(0, 0),
                IncidentTransition::None,
                "below N no incident even within one window"
            );
        }
        assert_eq!(
            schedules.note_negative_streak(0, 0),
            IncidentTransition::None,
            "count at N but a single window does not open an incident"
        );
        assert_eq!(
            schedules.note_negative_streak(0, INCIDENT_WINDOW),
            IncidentTransition::Opened,
            "count >= N across two distinct windows opens the incident"
        );
        assert_eq!(
            schedules.note_negative_streak(0, INCIDENT_WINDOW * 2),
            IncidentTransition::None,
            "an already-open incident does not re-open"
        );
        assert_eq!(
            schedules.reset_negative_streak(0),
            IncidentTransition::Closed,
            "a validated positive resets the streak and closes the incident"
        );
        assert_eq!(
            schedules.note_negative_streak(0, INCIDENT_WINDOW * 3),
            IncidentTransition::None,
            "the streak restarts from zero after the reset"
        );
    }

    #[test]
    fn sustained_negative_streak_ignores_nodata_and_exchange_failures() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.note_nodata(0, Family::A, None, 0, 0).unwrap();
        schedules.note_exchange_failure(0, Family::A, 0).unwrap();
        assert_eq!(
            schedules.note_negative_streak(0, 0),
            IncidentTransition::None,
            "a single NXDOMAIN after NODATA/failure stays below N"
        );
        assert_eq!(
            schedules.reset_negative_streak(0),
            IncidentTransition::None,
            "a positive without an open incident closes nothing"
        );
    }
}

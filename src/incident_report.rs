//! Pure per-name DNS incident reporting state: window rotation, per-type
//! exchange counters, tunnel-activity slot markers, and eligible-binding
//! transition tracking (docs/alumina-proxy.md:79-81).
//!
//! Everything here is allocation-free and preallocated at boot: one report per
//! configured name and one last-counted window marker per tunnel slot. The
//! serving side owns the emission seam; this module only decides *what* a
//! closed window contains and *when* a window rotates.

use crate::cache::Family;
use crate::config::ALLOWLIST_MAX;
use crate::inventory::TUNNEL_SLOTS;

/// The fixed reporting-window length in seconds (docs/alumina-proxy.md:79).
pub(crate) const REPORT_WINDOW_SECS: u64 = 3600;

/// A saturating counter: saturates at `u64::MAX` and latches an overflow flag
/// rather than wrapping (docs/alumina-proxy.md:81).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Sat {
    pub value: u64,
    pub overflow: bool,
}

impl Sat {
    const ZERO: Sat = Sat {
        value: 0,
        overflow: false,
    };

    const fn add(&mut self, n: u64) {
        let (value, overflow) = self.value.overflowing_add(n);
        self.value = if overflow { u64::MAX } else { value };
        self.overflow = self.overflow || overflow;
    }

    const fn bump(&mut self) {
        self.add(1);
    }
}

const fn family_slot(family: Family) -> usize {
    match family {
        Family::A => 0,
        Family::Aaaa => 1,
    }
}

/// Per-type window counters: exchange attempts and exchange failures during
/// the open reporting window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct TypeWindow {
    pub attempts: Sat,
    pub failures: Sat,
}

/// Window activity: distinct tunnels that forwarded bytes, total forwarded
/// bytes, and new tunnels admitted with stale bindings.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Activity {
    pub tunnels: Sat,
    pub bytes: Sat,
    pub stale: Sat,
}

/// The per-family incident snapshot captured when a window closes: the
/// monotonic second the type incident opened and the latest failure reason
/// while open, or `None` when the family had no incident during the window.
/// Sticky within a window: a recovery mid-window does not clear it, so the
/// closing summary reflects the window's actual incident activity even when
/// the incident recovered at the boundary turn (docs/alumina-proxy.md:80).
pub(crate) type IncidentSnapshot = Option<(u64, &'static str)>;

/// The closed-window snapshot captured at rotation or final recovery: the
/// window span, the coalesced skipped-window count, the per-type and activity
/// counters, the monotonic last-positive times, the per-family incident
/// snapshot, and the aggregated overflow flag (docs/alumina-proxy.md:80-81).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ClosedWindow {
    pub window_start: u64,
    pub window_end: u64,
    pub skipped: u32,
    pub per_type: [TypeWindow; 2],
    pub activity: Activity,
    pub last_positive: [Option<u64>; 2],
    pub incident: [IncidentSnapshot; 2],
    pub overflow: bool,
}

impl ClosedWindow {
    pub(crate) const fn duration(&self) -> u64 {
        self.window_end - self.window_start
    }
}

/// Per-name reporting state. One instance per configured allowlist name,
/// preallocated at boot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct NameReport {
    window_open: bool,
    window_start: u64,
    pending: Option<ClosedWindow>,
    per_type: [TypeWindow; 2],
    activity: Activity,
    last_positive: [Option<u64>; 2],
    /// The per-family incident snapshot observed during the current window:
    /// set from the schedule when the window opens and on every exchange
    /// failure, sticky within the window, reset at rotation.
    incident: [IncidentSnapshot; 2],
    had_eligible: Option<bool>,
}

impl NameReport {
    const fn new() -> NameReport {
        NameReport {
            window_open: false,
            window_start: 0,
            pending: None,
            per_type: [TypeWindow {
                attempts: Sat::ZERO,
                failures: Sat::ZERO,
            }; 2],
            activity: Activity {
                tunnels: Sat::ZERO,
                bytes: Sat::ZERO,
                stale: Sat::ZERO,
            },
            last_positive: [None, None],
            incident: [None, None],
            had_eligible: None,
        }
    }

    /// Closes the open window when `now` is at or past the boundary and
    /// captures it into `pending`, advancing `window_start` to the most recent
    /// boundary and resetting the per-window counters. Delayed rotation
    /// coalesces skipped windows into one snapshot with a `skipped` count
    /// rather than emitting a catch-up burst (docs/alumina-proxy.md:81).
    fn rotate_if_due(&mut self, now: u64) {
        if !self.window_open || now < self.window_start + REPORT_WINDOW_SECS {
            return;
        }
        let elapsed = (now - self.window_start) / REPORT_WINDOW_SECS;
        let end = self.window_start + elapsed * REPORT_WINDOW_SECS;
        self.pending = Some(self.capture(self.window_start, end, elapsed - 1));
        self.window_start = end;
        for t in &mut self.per_type {
            t.attempts = Sat::ZERO;
            t.failures = Sat::ZERO;
        }
        self.activity = Activity {
            tunnels: Sat::ZERO,
            bytes: Sat::ZERO,
            stale: Sat::ZERO,
        };
        self.incident = [None, None];
    }

    /// Captures the current window as a [`ClosedWindow`] spanning
    /// `[start, end)` with the given skipped-window count. `last_positive` is
    /// preserved (it is monotonic and persists across windows); the overflow
    /// flag aggregates every counter's latched overflow.
    fn capture(&self, start: u64, end: u64, skipped: u64) -> ClosedWindow {
        let overflow = self
            .per_type
            .iter()
            .any(|t| t.attempts.overflow || t.failures.overflow)
            || self.activity.tunnels.overflow
            || self.activity.bytes.overflow
            || self.activity.stale.overflow;
        ClosedWindow {
            window_start: start,
            window_end: end,
            skipped: u32::try_from(skipped).unwrap_or(u32::MAX),
            per_type: self.per_type,
            activity: self.activity,
            last_positive: self.last_positive,
            incident: self.incident,
            overflow,
        }
    }
}

/// The eligible-binding transition for one name since the previous per-turn
/// observation (docs/alumina-proxy.md:79).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EligibleTransition {
    Lost,
    Recovered,
}

/// The per-type summary fields for one record family, built by the serving
/// side from the schedule's incident state and the cache entry at emission
/// time (docs/alumina-proxy.md:80). `freshness`/`retirement` carry the
/// remaining seconds until the entry's freshness and retirement deadlines
/// (deadline minus the record's `secs`), not the absolute monotonic deadlines.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct TypeSummary {
    pub start: Option<u64>,
    pub elapsed: u64,
    pub reason: Option<&'static str>,
    pub last_positive: Option<u64>,
    pub attempts: u64,
    pub failures: u64,
    pub addrs: u64,
    pub state: &'static str,
    pub freshness: Option<u64>,
    pub retirement: Option<u64>,
}

impl TypeSummary {
    pub(crate) const EMPTY: TypeSummary = TypeSummary {
        start: None,
        elapsed: 0,
        reason: None,
        last_positive: None,
        attempts: 0,
        failures: 0,
        addrs: 0,
        state: "empty",
        freshness: None,
        retirement: None,
    };
}

/// The full incident summary record payload (docs/alumina-proxy.md:80).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct IncidentSummary {
    pub window_start: u64,
    pub window_end: u64,
    pub duration: u64,
    pub skipped: u32,
    pub overflow: bool,
    pub types: [TypeSummary; 2],
    pub tunnels: u64,
    pub bytes: u64,
    pub stale: u64,
}

/// The boot-preallocated incident reporting surface: per-name window state and
/// one last-counted window marker per tunnel slot.
pub(crate) struct IncidentReport {
    names: [NameReport; ALLOWLIST_MAX],
    slot_markers: [Option<(u64, u64)>; TUNNEL_SLOTS],
}

impl IncidentReport {
    pub(crate) const fn new() -> IncidentReport {
        IncidentReport {
            names: [NameReport::new(); ALLOWLIST_MAX],
            slot_markers: [None; TUNNEL_SLOTS],
        }
    }

    /// Opens the reporting window for `name` when it first enters an incident:
    /// the first window starts at `now` and per-window counters reset. A
    /// window already open is a no-op — the window is never restarted when the
    /// other type fails or recovers (docs/alumina-proxy.md:79). The passed
    /// per-family incident snapshot (from the schedule) refreshes the sticky
    /// window snapshot: families currently open are recorded with their
    /// `opened_at` and latest reason, and a family already recorded is never
    /// cleared, so a recovery mid-window does not erase the window's incident
    /// activity.
    pub(crate) const fn note_incident_open(
        &mut self,
        name: usize,
        now: u64,
        incident: [IncidentSnapshot; 2],
    ) {
        let nr = &mut self.names[name];
        if let Some((opened_at, reason)) = incident[0] {
            nr.incident[0] = Some((opened_at, reason));
        }
        if let Some((opened_at, reason)) = incident[1] {
            nr.incident[1] = Some((opened_at, reason));
        }
        if nr.window_open {
            return;
        }
        nr.window_open = true;
        nr.window_start = now;
        nr.per_type = [TypeWindow {
            attempts: Sat::ZERO,
            failures: Sat::ZERO,
        }; 2];
        nr.activity = Activity {
            tunnels: Sat::ZERO,
            bytes: Sat::ZERO,
            stale: Sat::ZERO,
        };
    }

    /// Records one exchange attempt for `name` and `family`. Rotation precedes
    /// the recording (docs/alumina-proxy.md:81); the attempt is counted only
    /// while a window is open, so attempts outside an incident belong to no
    /// window.
    pub(crate) fn note_exchange_attempt(&mut self, name: usize, family: Family, now: u64) {
        let nr = &mut self.names[name];
        nr.rotate_if_due(now);
        if nr.window_open {
            nr.per_type[family_slot(family)].attempts.bump();
        }
    }

    /// Records one exchange failure for `name` and `family`. Rotation precedes
    /// the recording; the failure is counted only while a window is open. The
    /// failure also updates the window's sticky per-family incident snapshot:
    /// the family is recorded as in-incident with the latest failure reason,
    /// keeping the earliest observed `opened_at`.
    pub(crate) fn note_exchange_failure(
        &mut self,
        name: usize,
        family: Family,
        now: u64,
        reason: &'static str,
    ) {
        let nr = &mut self.names[name];
        nr.rotate_if_due(now);
        let slot = family_slot(family);
        nr.incident[slot] = Some(match nr.incident[slot] {
            Some((opened_at, _)) => (opened_at, reason),
            None => (now, reason),
        });
        if nr.window_open {
            nr.per_type[slot].failures.bump();
        }
    }

    /// Records the last positive-resolution time for `name` and `family`. The
    /// time is monotonic and persists across windows and incidents.
    pub(crate) fn note_positive(&mut self, name: usize, family: Family, now: u64) {
        let nr = &mut self.names[name];
        nr.rotate_if_due(now);
        nr.last_positive[family_slot(family)] = Some(now);
    }

    /// Records forwarded tunnel bytes for the tunnel in `slot` (identified by
    /// its generation stamp) belonging to `name`. The tunnel is counted as a
    /// distinct active tunnel once per window: the slot marker
    /// `(window_start, slot_gen)` resets on slot reuse (a new generation) and
    /// never matches across windows (`window_start` is monotonic), so a tunnel
    /// is counted fresh in each window it forwards bytes in. Bytes are counted
    /// on every successful write (docs/alumina-proxy.md:80-81).
    pub(crate) fn note_tunnel_bytes(
        &mut self,
        name: usize,
        slot: usize,
        slot_gen: u64,
        bytes: u64,
        now: u64,
    ) {
        let nr = &mut self.names[name];
        nr.rotate_if_due(now);
        if !nr.window_open {
            return;
        }
        let marker = (nr.window_start, slot_gen);
        if self.slot_markers[slot] != Some(marker) {
            self.slot_markers[slot] = Some(marker);
            nr.activity.tunnels.bump();
        }
        nr.activity.bytes.add(bytes);
    }

    /// Records one new tunnel admitted with a stale binding for `name`.
    /// Retries and relay activity are not admissions (docs/alumina-proxy.md:80).
    pub(crate) fn note_stale_admission(&mut self, name: usize, now: u64) {
        let nr = &mut self.names[name];
        nr.rotate_if_due(now);
        if nr.window_open {
            nr.activity.stale.bump();
        }
    }

    /// Observes the name's current eligible-binding state and returns the
    /// transition since the previous observation. The first observation only
    /// sets the baseline (never emitting, so a name already ineligible at
    /// serving start does not report a spurious recovery); later observations
    /// report `Lost` on eligible→none and `Recovered` on none→eligible
    /// (docs/alumina-proxy.md:79).
    pub(crate) const fn note_eligible_state(
        &mut self,
        name: usize,
        has_eligible: bool,
    ) -> Option<EligibleTransition> {
        let nr = &mut self.names[name];
        match nr.had_eligible {
            None => {
                nr.had_eligible = Some(has_eligible);
                None
            }
            Some(prev) if prev == has_eligible => None,
            Some(true) => {
                nr.had_eligible = Some(false);
                Some(EligibleTransition::Lost)
            }
            Some(false) => {
                nr.had_eligible = Some(true);
                Some(EligibleTransition::Recovered)
            }
        }
    }

    /// Rotates every open window that is due at `now`, so a window boundary is
    /// honored even when no event crossed it (docs/alumina-proxy.md:79,81).
    pub(crate) fn rotate_all_if_due(&mut self, now: u64) {
        for nr in &mut self.names {
            nr.rotate_if_due(now);
        }
    }

    /// Takes the closed-window snapshot a rotation or final recovery captured
    /// for `name`, if any.
    pub(crate) const fn take_pending_summary(&mut self, name: usize) -> Option<ClosedWindow> {
        self.names[name].pending.take()
    }

    /// Closes the open window for `name` at `now` (a full hostname incident
    /// recovery) and returns the partial-window snapshot, or `None` when no
    /// window is open (docs/alumina-proxy.md:80).
    pub(crate) fn close_window(&mut self, name: usize, now: u64) -> Option<ClosedWindow> {
        let nr = &mut self.names[name];
        if !nr.window_open {
            return None;
        }
        nr.window_open = false;
        Some(nr.capture(nr.window_start, now, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: u64 = REPORT_WINDOW_SECS;

    #[test]
    fn window_rotates_at_boundary_and_resets_counters() {
        let mut rep = IncidentReport::new();
        rep.note_incident_open(0, 1000, [None, None]);
        rep.note_exchange_attempt(0, Family::A, 1010);
        rep.note_exchange_failure(0, Family::A, 1020, "timeout");
        // Just before the boundary: no rotation.
        rep.note_exchange_attempt(0, Family::A, 1000 + W - 1);
        assert!(rep.take_pending_summary(0).is_none());
        // At the boundary: rotation closes the window and resets counters. The
        // attempt at the boundary itself belongs to the new window.
        rep.note_exchange_attempt(0, Family::A, 1000 + W);
        let closed = rep.take_pending_summary(0).expect("closed window");
        assert_eq!(closed.window_start, 1000);
        assert_eq!(closed.window_end, 1000 + W);
        assert_eq!(closed.skipped, 0);
        assert_eq!(closed.per_type[0].attempts.value, 2);
        assert_eq!(closed.per_type[0].failures.value, 1);
        assert_eq!(closed.duration(), W);
        // The new window starts at the boundary with fresh counters; the
        // boundary attempt and this one both belong to it.
        rep.note_exchange_attempt(0, Family::A, 1000 + W + 1);
        let partial = rep.close_window(0, 1000 + W + 1).expect("partial window");
        assert_eq!(partial.window_start, 1000 + W);
        assert_eq!(partial.per_type[0].attempts.value, 2);
        assert_eq!(partial.per_type[0].failures.value, 0);
    }

    #[test]
    fn reused_slot_resets_its_reporting_marker() {
        let mut rep = IncidentReport::new();
        rep.note_incident_open(0, 1000, [None, None]);
        // Tunnel generation 1 forwards bytes in slot 3: counted once.
        rep.note_tunnel_bytes(0, 3, 1, 100, 1010);
        rep.note_tunnel_bytes(0, 3, 1, 50, 1020);
        // Slot reused: the new generation counts as a fresh tunnel.
        rep.note_tunnel_bytes(0, 3, 2, 200, 1030);
        let closed = rep.close_window(0, 1100).expect("closed");
        assert_eq!(closed.activity.tunnels.value, 2);
        assert_eq!(closed.activity.bytes.value, 350);
    }

    #[test]
    fn per_type_summary_captures_attempts_failures_and_last_positive() {
        let mut rep = IncidentReport::new();
        rep.note_incident_open(0, 1000, [None, None]);
        rep.note_exchange_attempt(0, Family::A, 1010);
        rep.note_exchange_failure(0, Family::A, 1020, "timeout");
        rep.note_positive(0, Family::A, 1030);
        rep.note_exchange_attempt(0, Family::Aaaa, 1040);
        rep.note_exchange_failure(0, Family::Aaaa, 1050, "timeout");
        let closed = rep.close_window(0, 1060).expect("closed");
        assert_eq!(closed.per_type[0].attempts.value, 1);
        assert_eq!(closed.per_type[0].failures.value, 1);
        assert_eq!(closed.last_positive[0], Some(1030));
        assert_eq!(closed.per_type[1].attempts.value, 1);
        assert_eq!(closed.per_type[1].failures.value, 1);
        assert_eq!(closed.last_positive[1], None);
    }

    #[test]
    fn eligible_state_reports_loss_and_recovery_after_baseline() {
        let mut rep = IncidentReport::new();
        // First observation sets the baseline without emitting.
        assert_eq!(rep.note_eligible_state(0, true), None);
        assert_eq!(rep.note_eligible_state(0, true), None);
        // Eligible → none: Lost.
        assert_eq!(
            rep.note_eligible_state(0, false),
            Some(EligibleTransition::Lost)
        );
        // none → eligible: Recovered.
        assert_eq!(
            rep.note_eligible_state(0, true),
            Some(EligibleTransition::Recovered)
        );
        // A name already ineligible at start never emits a spurious recovery.
        assert_eq!(rep.note_eligible_state(1, false), None);
        assert_eq!(rep.note_eligible_state(1, false), None);
        assert_eq!(
            rep.note_eligible_state(1, true),
            Some(EligibleTransition::Recovered)
        );
    }

    #[test]
    fn close_window_returns_partial_summary_with_actual_duration() {
        let mut rep = IncidentReport::new();
        rep.note_incident_open(0, 1000, [None, None]);
        rep.note_exchange_failure(0, Family::A, 1005, "timeout");
        let closed = rep.close_window(0, 2500).expect("partial window");
        assert_eq!(closed.window_start, 1000);
        assert_eq!(closed.window_end, 2500);
        assert_eq!(closed.duration(), 1500);
        assert_eq!(closed.skipped, 0);
        // A second close on a closed window is a no-op.
        assert!(rep.close_window(0, 2600).is_none());
        // A new incident opens a fresh window.
        rep.note_incident_open(0, 3000, [None, None]);
        assert!(rep.close_window(0, 3100).is_some());
    }

    #[test]
    fn counters_saturate_and_latch_overflow() {
        let mut sat = Sat::ZERO;
        sat.add(u64::MAX);
        assert_eq!(sat.value, u64::MAX);
        assert!(!sat.overflow);
        sat.bump();
        assert_eq!(sat.value, u64::MAX);
        assert!(sat.overflow);
    }

    #[test]
    fn delayed_rotation_coalesces_skipped_windows() {
        let mut rep = IncidentReport::new();
        rep.note_incident_open(0, 1000, [None, None]);
        rep.note_exchange_failure(0, Family::A, 1010, "timeout");
        // The next event lands 2.5 windows later: two full windows elapsed.
        let late = 1000 + 2 * W + 1800;
        rep.note_exchange_failure(0, Family::A, late, "timeout");
        let closed = rep.take_pending_summary(0).expect("closed");
        assert_eq!(closed.window_start, 1000);
        assert_eq!(closed.window_end, 1000 + 2 * W);
        assert_eq!(closed.skipped, 1);
        assert_eq!(closed.duration(), 2 * W);
    }

    #[test]
    fn window_opens_only_once_across_types() {
        let mut rep = IncidentReport::new();
        rep.note_incident_open(0, 1000, [None, None]);
        // The other type failing or recovering must not restart the window.
        rep.note_incident_open(0, 2000, [None, None]);
        let closed = rep.close_window(0, 2500).expect("closed");
        assert_eq!(closed.window_start, 1000);
    }

    #[test]
    fn incident_snapshot_is_sticky_within_a_window() {
        let mut rep = IncidentReport::new();
        rep.note_incident_open(0, 1000, [None, None]);
        rep.note_exchange_failure(0, Family::A, 1010, "timeout");
        // A recovery mid-window must not erase the window's recorded incident
        // activity: the closing summary reflects what was failing during the
        // window even when the incident recovered before the window closed.
        rep.note_positive(0, Family::A, 1020);
        let closed = rep.close_window(0, 1060).expect("closed");
        assert_eq!(closed.incident[0], Some((1010, "timeout")));
        assert_eq!(closed.incident[1], None);
    }
}

//! Pure per-name DNS incident reporting state: window rotation, per-type
//! exchange counters, tunnel-activity slot markers, and eligible-binding
//! transition tracking (docs/alumina-proxy.md:79-81).
//!
//! Everything here is allocation-free and preallocated at boot: one report per
//! configured name and one last-counted window marker per tunnel slot. The
//! serving side owns the emission seam; this module only decides *what* a
//! closed window contains and *when* a window rotates.

use crate::config::ALLOWLIST_MAX;
use crate::dns::cache::Family;
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
/// monotonic second the type incident opened, the latest failure reason while
/// open, and the zero-based configured-resolver origin captured with that
/// reason, or `None` when the family had no incident during the window.
/// Sticky within a window: a recovery mid-window does not clear it, so the
/// closing summary reflects the window's actual incident activity even when
/// the incident recovered at the boundary turn (docs/alumina-proxy.md:80).
/// The origin is the saved per-family table value at failure time, never a
/// live current-actor lookup at emission.
pub(crate) type IncidentSnapshot = Option<(u64, &'static str, Option<u8>)>;

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

    pub(crate) fn to_summary(self, secs: u64, cache: [SummaryCache; 2]) -> IncidentSummary {
        let mut types = [TypeSummary::EMPTY; 2];
        let mut i = 0;
        while i < 2 {
            let (start, reason, resolver) = match self.incident[i] {
                Some((opened_at, reason, origin)) => (Some(opened_at), Some(reason), origin),
                None => (None, None, None),
            };
            types[i] = TypeSummary {
                start,
                elapsed: start.map_or(0, |s| self.window_end.saturating_sub(s)),
                reason,
                resolver,
                last_positive: self.last_positive[i],
                attempts: self.per_type[i].attempts.value,
                failures: self.per_type[i].failures.value,
                addrs: cache[i].addrs,
                state: cache[i].state,
                freshness: cache[i].freshness.map(|f| f.saturating_sub(secs)),
                retirement: cache[i].retirement.map(|r| r.saturating_sub(secs)),
            };
            i += 1;
        }
        IncidentSummary {
            window_start: self.window_start,
            window_end: self.window_end,
            duration: self.duration(),
            skipped: self.skipped,
            overflow: self.overflow,
            types,
            tunnels: self.activity.tunnels.value,
            bytes: self.activity.bytes.value,
            stale: self.activity.stale.value,
        }
    }
}

/// Live-cache facts folded into one per-type summary field: raw binding
/// count, entry state at the shared emission second, and the absolute
/// freshness and retirement deadlines.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct SummaryCache {
    pub addrs: u64,
    pub state: &'static str,
    pub freshness: Option<u64>,
    pub retirement: Option<u64>,
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
    /// failure, sticky within the window, reset at rotation and when the
    /// window closes.
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
        self.reset_window_counters();
        self.incident = [None, None];
    }

    const fn reset_window_counters(&mut self) {
        self.per_type = [TypeWindow {
            attempts: Sat::ZERO,
            failures: Sat::ZERO,
        }; 2];
        self.activity = Activity {
            tunnels: Sat::ZERO,
            bytes: Sat::ZERO,
            stale: Sat::ZERO,
        };
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

/// The per-type summary fields for one record family, projected by
/// [`ClosedWindow::to_summary`] from the window's captured incident snapshot
/// and the serving-provided live cache facts (docs/alumina-proxy.md:80).
/// `freshness`/`retirement` carry the remaining seconds until the entry's
/// freshness and retirement deadlines (deadline minus the record's `secs`),
/// not the absolute monotonic deadlines.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct TypeSummary {
    pub start: Option<u64>,
    pub elapsed: u64,
    pub reason: Option<&'static str>,
    pub resolver: Option<u8>,
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
        resolver: None,
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
    /// `opened_at`, latest reason, and paired captured origin, and a family
    /// already recorded is never cleared, so a recovery mid-window does not
    /// erase the window's incident activity.
    pub(crate) const fn note_incident_open(
        &mut self,
        name: usize,
        now: u64,
        incident: [IncidentSnapshot; 2],
    ) {
        let nr = &mut self.names[name];
        if let Some((opened_at, reason, origin)) = incident[0] {
            nr.incident[0] = Some((opened_at, reason, origin));
        }
        if let Some((opened_at, reason, origin)) = incident[1] {
            nr.incident[1] = Some((opened_at, reason, origin));
        }
        if nr.window_open {
            return;
        }
        nr.window_open = true;
        nr.window_start = now;
        nr.reset_window_counters();
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
    /// the family is recorded as in-incident with the latest failure reason and
    /// its paired captured configured-resolver origin, keeping the earliest
    /// observed `opened_at`. The closed snapshot keeps the window-captured
    /// origin, never a live current-actor lookup at emission.
    pub(crate) fn note_exchange_failure(
        &mut self,
        name: usize,
        family: Family,
        now: u64,
        reason: &'static str,
        resolver: Option<u8>,
    ) {
        let nr = &mut self.names[name];
        nr.rotate_if_due(now);
        let slot = family_slot(family);
        nr.incident[slot] = Some(match nr.incident[slot] {
            Some((opened_at, _, _)) => (opened_at, reason, resolver),
            None => (now, reason, resolver),
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
    /// window is open (docs/alumina-proxy.md:80). The snapshot is captured
    /// before the per-family incident state is cleared, so the closing summary
    /// keeps the window's incident activity while a window opened later starts
    /// with no recorded family: a later incident reports only the families
    /// that fail in it.
    pub(crate) fn close_window(&mut self, name: usize, now: u64) -> Option<ClosedWindow> {
        let nr = &mut self.names[name];
        if !nr.window_open {
            return None;
        }
        nr.window_open = false;
        let closed = nr.capture(nr.window_start, now, 0);
        nr.incident = [None, None];
        Some(closed)
    }
}

#[cfg(test)]
mod tests;

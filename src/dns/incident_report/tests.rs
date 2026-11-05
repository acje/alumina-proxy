use super::*;

const W: u64 = REPORT_WINDOW_SECS;

#[test]
fn window_rotates_at_boundary_and_resets_counters() {
    let mut rep = IncidentReport::new();
    rep.note_incident_open(0, 1000, [None, None]);
    rep.note_exchange_attempt(0, Family::A, 1010);
    rep.note_exchange_failure(0, Family::A, 1020, "timeout", None);
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
/// G4.R1 — stale-marker / delayed-attribution rejection: a live tunnel
/// retains its `(window_start, slot_gen)` marker across a window rotation
/// and is counted exactly once per applicable window; a stale marker from a
/// closed window never pre-populates the current window's tunnel count, and
/// bytes landing one second past a boundary belong to the new window, not
/// the closed one (contract at src/incident_report.rs:337-343;
/// rotate-before-record and marker overwrite at :353-361).
fn live_tunnel_retains_marker_across_rotations_counted_per_window() {
    let mut rep = IncidentReport::new();
    rep.note_incident_open(0, 1000, [None, None]);
    // Window 1: two distinct tunnels forward bytes, so two slot markers.
    rep.note_tunnel_bytes(0, 2, 7, 100, 1010);
    rep.note_tunnel_bytes(0, 0, 1, 60, 1020);
    rep.note_stale_admission(0, 1030);
    assert_eq!(
        rep.slot_markers[2],
        Some((1000, 7)),
        "marker carries window and generation"
    );
    assert_eq!(rep.slot_markers[0], Some((1000, 1)));
    // A write one second past the boundary rotates first: the closed window
    // holds only pre-boundary bytes; the write is attributed to window 2.
    rep.note_tunnel_bytes(0, 2, 7, 30, 1000 + W + 1);
    let closed = rep.take_pending_summary(0).expect("closed window 1");
    assert_eq!(closed.window_start, 1000);
    assert_eq!(closed.window_end, 1000 + W);
    assert_eq!(closed.activity.tunnels.value, 2);
    assert_eq!(closed.activity.bytes.value, 160);
    assert_eq!(closed.activity.stale.value, 1);
    // The rotation re-keyed the live marker to the new window_start: the
    // stale (1000, 7) pair can never match the current window again.
    assert_eq!(
        rep.slot_markers[2],
        Some((1000 + W, 7)),
        "rotation replaces the stale marker"
    );
    // The same live tunnel forwards in window 2: counted fresh, once.
    rep.note_tunnel_bytes(0, 2, 7, 40, 1000 + W + 2);
    let w2 = rep.close_window(0, 1000 + W + 5).expect("close window 2");
    assert_eq!(w2.window_start, 1000 + W);
    assert_eq!(
        w2.activity.tunnels.value, 1,
        "only the tunnel active in window 2"
    );
    assert_eq!(
        w2.activity.bytes.value, 70,
        "the boundary write plus the new write"
    );
    assert_eq!(
        w2.activity.stale.value, 0,
        "window-1 admissions do not carry forward"
    );
    assert_eq!(rep.slot_markers[2], Some((1000 + W, 7)));
}

#[test]
/// G4.R2 — same-window dedup: repeated `note_tunnel_bytes` for the same
/// `(slot, slot_gen)` pair keep one marker and one tunnel count while bytes
/// sum exactly; a generation change on the same slot is a fresh tunnel and
/// resets the marker (contract at src/incident_report.rs:337-343;
/// marker compare/overwrite at :353-361).
fn marker_dedups_same_window_and_reuse_resets_it() {
    let mut rep = IncidentReport::new();
    rep.note_incident_open(0, 1000, [None, None]);
    rep.note_tunnel_bytes(0, 1, 9, 80, 1010);
    rep.note_tunnel_bytes(0, 1, 9, 20, 1020);
    rep.note_tunnel_bytes(0, 1, 9, 100, 1030);
    assert_eq!(
        rep.slot_markers[1],
        Some((1000, 9)),
        "marker unchanged across repeated writes"
    );
    // Reuse resets the marker: the new generation is a distinct tunnel.
    rep.note_tunnel_bytes(0, 1, 10, 50, 1040);
    assert_eq!(
        rep.slot_markers[1],
        Some((1000, 10)),
        "reuse replaces the marker"
    );
    let closed = rep.close_window(0, 1100).expect("closed");
    assert_eq!(closed.activity.tunnels.value, 2);
    assert_eq!(closed.activity.bytes.value, 250);
}

#[test]
/// G4.R3 — one rotation at a pre-wrap generation: the maximal constructible
/// `slot_gen` is recorded exactly as a `(window_start, slot_gen)` marker,
/// and a window rotation re-keys the marker to the new window so the
/// pre-wrap pair can never become current again for the reused slot. The
/// full 2^64 cycle that would return a slot to an earlier generation is
/// unreachable by construction (the fixed profile adds no production hook)
/// and stays BLOCKED/Unknown per decision bead alumina-v52be; no wrap
/// policy is invented here (the stored marker key,
/// `src/incident_report.rs:244`, is built as `(window_start, slot_gen)` at
/// :357).
fn pre_wrap_generation_marker_is_rekeyed_on_rotation() {
    let mut rep = IncidentReport::new();
    rep.note_incident_open(0, 1000, [None, None]);
    // Near-wrap generations: each distinct slot_gen is its own marker and
    // tunnel, recorded exactly at the extreme value.
    rep.note_tunnel_bytes(0, 0, u64::MAX - 1, 100, 1010);
    rep.note_tunnel_bytes(0, 0, u64::MAX, 50, 1020);
    assert_eq!(rep.slot_markers[0], Some((1000, u64::MAX)));
    // Rotation at the boundary re-keys the near-wrap marker to the new
    // window, so the pre-wrap (1000, u64::MAX) pair can never match the
    // reused slot's current window again.
    rep.note_tunnel_bytes(0, 0, u64::MAX, 77, 1000 + W + 1);
    let closed = rep.take_pending_summary(0).expect("closed window 1");
    assert_eq!(closed.activity.tunnels.value, 2);
    assert_eq!(closed.activity.bytes.value, 150);
    assert_eq!(
        rep.slot_markers[0],
        Some((1000 + W, u64::MAX)),
        "rotation replaces the near-wrap marker"
    );
    let w2 = rep.close_window(0, 1000 + W + 5).expect("close window 2");
    assert_eq!(w2.activity.tunnels.value, 1);
    assert_eq!(w2.activity.bytes.value, 77);
}

#[test]
/// G4.R3 — the marker records extreme generation values exactly on the
/// same slot: a wrapped-to-zero generation is a distinct `(window_start,
/// slot_gen)` pair from the pre-wrap `u64::MAX` marker and is never
/// deduped against it, so all three generations count as separate tunnels
/// in one window (the u64 width witness at `src/incident_report.rs:244`
/// records the residue exactly; per decision bead alumina-v52be it is
/// an artifact, not a proof).
fn marker_records_extreme_generation_values_exactly() {
    let mut rep = IncidentReport::new();
    rep.note_incident_open(0, 1000, [None, None]);
    // Three generations on the SAME slot: near-wrap, wrap boundary, and a
    // wrap-equivalent zero. Each overwrites the marker; never dedup. The
    // marker is asserted between calls so each generation's exact value
    // is the witness, not the final overwrite.
    rep.note_tunnel_bytes(0, 0, u64::MAX - 1, 100, 1010);
    assert_eq!(
        rep.slot_markers[0],
        Some((1000, u64::MAX - 1)),
        "pre-wrap generation recorded exactly"
    );
    rep.note_tunnel_bytes(0, 0, u64::MAX, 50, 1020);
    assert_eq!(
        rep.slot_markers[0],
        Some((1000, u64::MAX)),
        "near-wrap generation overwrites the marker"
    );
    rep.note_tunnel_bytes(0, 0, 0, 5, 1030);
    assert_eq!(
        rep.slot_markers[0],
        Some((1000, 0)),
        "a wrapped-to-zero generation is a distinct marker on the same slot"
    );
    let closed = rep.close_window(0, 1100).expect("closed");
    assert_eq!(
        closed.activity.tunnels.value, 3,
        "three same-slot generations count as three distinct tunnels, never deduped"
    );
    assert_eq!(closed.activity.bytes.value, 155);
}

#[test]
fn per_type_summary_captures_attempts_failures_and_last_positive() {
    let mut rep = IncidentReport::new();
    rep.note_incident_open(0, 1000, [None, None]);
    rep.note_exchange_attempt(0, Family::A, 1010);
    rep.note_exchange_failure(0, Family::A, 1020, "timeout", None);
    rep.note_positive(0, Family::A, 1030);
    rep.note_exchange_attempt(0, Family::Aaaa, 1040);
    rep.note_exchange_failure(0, Family::Aaaa, 1050, "timeout", None);
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
    rep.note_exchange_failure(0, Family::A, 1005, "timeout", None);
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
/// G4 — window counters saturate with the overflow flag instead of wrapping
/// (docs/alumina-proxy.md:340 logging contract): a byte write past
/// `u64::MAX` pins the closed window's byte count at the maximum and
/// latches `overflow`, without disturbing the exact-once tunnel count, and
/// the next window's fresh counters clear the flag.
fn window_bytes_saturate_and_latch_overflow_instead_of_wrapping() {
    let mut rep = IncidentReport::new();
    rep.note_incident_open(0, 1000, [None, None]);
    rep.note_tunnel_bytes(0, 0, 1, u64::MAX, 1010);
    // The next write has no headroom left: the counter saturates and the
    // overflow flag latches on the closing summary.
    rep.note_tunnel_bytes(0, 0, 1, 1, 1020);
    let closed = rep.close_window(0, 1100).expect("closed");
    assert_eq!(
        closed.activity.bytes.value,
        u64::MAX,
        "saturate, never wrap to 0"
    );
    assert!(
        closed.overflow,
        "overflow flag latches on the closed window"
    );
    assert_eq!(
        closed.activity.tunnels.value, 1,
        "saturation does not disturb exact-once tunnel counting"
    );
    // The latch is per-window: a fresh incident window's counters reset,
    // so it closes without the previous window's overflow flag.
    rep.note_incident_open(0, 2000, [None, None]);
    rep.note_tunnel_bytes(0, 1, 2, 10, 2010);
    let next = rep.close_window(0, 2100).expect("next window");
    assert!(!next.overflow, "overflow clearance on the next window");
    assert_eq!(next.activity.bytes.value, 10);
}

#[test]
fn delayed_rotation_coalesces_skipped_windows() {
    let mut rep = IncidentReport::new();
    rep.note_incident_open(0, 1000, [None, None]);
    rep.note_exchange_failure(0, Family::A, 1010, "timeout", None);
    // The next event lands 2.5 windows later: two full windows elapsed.
    let late = 1000 + 2 * W + 1800;
    rep.note_exchange_failure(0, Family::A, late, "timeout", None);
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
    rep.note_exchange_failure(0, Family::A, 1010, "timeout", None);
    // A recovery mid-window must not erase the window's recorded incident
    // activity: the closing summary reflects what was failing during the
    // window even when the incident recovered before the window closed.
    rep.note_positive(0, Family::A, 1020);
    let closed = rep.close_window(0, 1060).expect("closed");
    assert_eq!(closed.incident[0], Some((1010, "timeout", None)));
    assert_eq!(closed.incident[1], None);
}

#[test]
fn closed_window_keeps_paired_origin_through_reason_update_and_rotation() {
    let mut rep = IncidentReport::new();
    rep.note_incident_open(
        0,
        1000,
        [
            Some((1000, "timeout", Some(0))),
            Some((1010, "timeout", Some(1))),
        ],
    );
    rep.note_exchange_failure(0, Family::A, 1500, "connect", Some(2));
    rep.note_exchange_attempt(0, Family::A, 1000 + W);
    let closed = rep.take_pending_summary(0).expect("closed window 1");
    assert_eq!(closed.incident[0], Some((1000, "connect", Some(2))));
    assert_eq!(closed.incident[1], Some((1010, "timeout", Some(1))));
    rep.note_exchange_failure(0, Family::A, 1000 + W + 1, "timeout", Some(3));
    assert_eq!(
        rep.take_pending_summary(0),
        None,
        "the closed record is already taken, never rewritten"
    );
}

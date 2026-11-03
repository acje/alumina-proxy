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
        schedules.note_exchange_failure(7, Family::A, 0, FailureReason::Timeout),
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
    schedules
        .note_exchange_failure(0, Family::A, 2000, FailureReason::Timeout)
        .unwrap();
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
                .note_exchange_failure(token.name(), token.family(), now, FailureReason::Timeout)
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
    schedules
        .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
        .unwrap();
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
        (0u64, 1u64),
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
        schedules
            .note_exchange_failure(0, Family::A, 0, FailureReason::Timeout)
            .unwrap();
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
        schedules
            .note_exchange_failure(0, Family::A, 0, FailureReason::Timeout)
            .unwrap();
        schedules
            .note_exchange_failure(0, Family::Aaaa, 0, FailureReason::Timeout)
            .unwrap();
    }
    let soa = Soa::new(60, 60);
    schedules.note_nxdomain(0, Some(soa), 1000, 0).unwrap();
    schedules
        .note_nodata(0, Family::A, Some(soa), 2000, 0)
        .unwrap();
    schedules
        .note_exchange_failure(0, Family::A, 3000, FailureReason::Timeout)
        .unwrap();
    schedules
        .note_exchange_failure(0, Family::Aaaa, 4000, FailureReason::Timeout)
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
    schedules
        .note_exchange_failure(0, Family::Aaaa, 0, FailureReason::Timeout)
        .unwrap();
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
    schedules
        .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
        .unwrap();
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
    schedules
        .note_exchange_failure(0, Family::A, 0, FailureReason::Timeout)
        .unwrap();
    schedules
        .note_exchange_failure(0, Family::Aaaa, 0, FailureReason::Timeout)
        .unwrap();
    schedules
        .note_positive(0, Family::A, 1000, 60, true, 0)
        .unwrap();
    schedules
        .note_exchange_failure(0, Family::A, 2000, FailureReason::Timeout)
        .unwrap();
    assert_eq!(
        schedules.due_time(0, Family::A).unwrap(),
        Some(2001),
        "cacheable positive resets its own backoff"
    );
    schedules
        .note_exchange_failure(0, Family::Aaaa, 3000, FailureReason::Timeout)
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
                    .note_exchange_failure(
                        token.name(),
                        token.family(),
                        now,
                        FailureReason::Timeout,
                    )
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
                .note_exchange_failure(token.name(), token.family(), 3000, FailureReason::Timeout)
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
    schedules
        .note_exchange_failure(0, Family::A, 0, FailureReason::Timeout)
        .unwrap();
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

#[test]
fn exchange_failure_opens_then_silently_updates_incident() {
    let mut schedules = Schedules::new(1).unwrap();
    assert_eq!(
        schedules
            .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
            .unwrap(),
        PerTypeTransition::Opened,
        "the first failure opens the per-type incident"
    );
    assert_eq!(
        schedules
            .note_exchange_failure(0, Family::A, 1001, FailureReason::Connect)
            .unwrap(),
        PerTypeTransition::SilentUpdate,
        "a later failure updates the open incident silently"
    );
}

#[test]
fn clear_exchange_incident_reports_recovery_duration() {
    let mut schedules = Schedules::new(1).unwrap();
    schedules
        .note_exchange_failure(0, Family::A, 5000, FailureReason::Timeout)
        .unwrap();
    assert_eq!(
        schedules
            .clear_exchange_incident(0, Family::A, 5012)
            .unwrap(),
        PerTypeTransition::Recovered { duration: 12 },
        "clearing an open incident reports the elapsed duration"
    );
    assert_eq!(
        schedules
            .clear_exchange_incident(0, Family::A, 5099)
            .unwrap(),
        PerTypeTransition::None,
        "a second clear on a closed incident is a no-op"
    );
}

#[test]
fn incident_state_is_per_family() {
    let mut schedules = Schedules::new(1).unwrap();
    schedules
        .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
        .unwrap();
    assert_eq!(
        schedules
            .clear_exchange_incident(0, Family::Aaaa, 1001)
            .unwrap(),
        PerTypeTransition::None,
        "clearing one family never touches the other"
    );
    assert_eq!(
        schedules
            .clear_exchange_incident(0, Family::A, 1005)
            .unwrap(),
        PerTypeTransition::Recovered { duration: 5 },
        "the open family clears with the elapsed duration"
    );
}

#[test]
fn clear_exchange_incident_out_of_range_errs() {
    let mut schedules = Schedules::new(2).unwrap();
    assert_eq!(
        schedules.clear_exchange_incident(7, Family::A, 0),
        Err(ScheduleError::NameOutOfRange)
    );
}

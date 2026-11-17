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
    // `now == u64::MAX` makes the start-rate `checked_add(1)`
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

#[test]
fn next_due_is_the_written_down_expectation_at_every_mutation() {
    let mut schedules = Schedules::new(3).unwrap();

    // No slot is scheduled: no wake at any instant.
    assert_eq!(schedules.next_due, None);
    assert_eq!(schedules.next_selectable_due(1000), None);

    schedules.overwrite_due_at(0, Family::A, 1000).unwrap();
    // The one scheduled slot is due at its own stamp, inside the clamp.
    assert_eq!(schedules.next_due, Some(1000));
    assert_eq!(schedules.next_selectable_due(1000), Some(1000));

    schedules.overwrite_due_at(0, Family::Aaaa, 1020).unwrap();
    // Both slots are selectable; the earlier overwritten due wins.
    assert_eq!(schedules.next_due, Some(1000));
    assert_eq!(schedules.next_selectable_due(1000), Some(1000));

    let token = schedules.select_due(1000).unwrap().unwrap();
    assert_eq!((token.name(), token.family()), (0, Family::A));
    // The selected slot is in flight and contributes nothing; its sibling's
    // 1020 due is the next selectable moment.
    assert_eq!(schedules.next_due, Some(1020));
    assert_eq!(schedules.next_selectable_due(1000), Some(1020));

    schedules
        .note_exchange_failure(0, Family::A, 1000, FailureReason::Timeout)
        .unwrap();
    // The stage-0 backoff retries from the failure instant at 1000 + 1, which
    // equals the start-rate guard left by the selection.
    assert_eq!(schedules.next_due, Some(1001));
    assert_eq!(schedules.next_selectable_due(1000), Some(1001));

    schedules.release_selection(0, Family::A).unwrap();
    // Releasing only clears the in-flight marker: the 1001 due and its
    // one-second start guard are unchanged.
    assert_eq!(schedules.next_due, Some(1001));
    assert_eq!(schedules.next_selectable_due(1000), Some(1001));

    schedules
        .note_positive(0, Family::A, 1000, 60, true, 1000)
        .unwrap();
    // A cacheable positive reschedules from receipt at the TTL floor:
    // 1000 + clamp(60, 5, 900) = 1060, so the sibling's 1020 due is earliest.
    assert_eq!(schedules.next_due, Some(1020));
    assert_eq!(schedules.next_selectable_due(1000), Some(1020));

    schedules.overwrite_due_at(1, Family::A, 2000).unwrap();
    // A second name's 2000 due is later than the still-earliest 1020.
    assert_eq!(schedules.next_due, Some(1020));
    assert_eq!(schedules.next_selectable_due(1000), Some(1020));

    schedules.note_nxdomain(1, None, 0, 1000).unwrap();
    // NXDOMAIN without an SOA retries both families from `now` at stage 0:
    // 1000 + 1, earlier than every other slot.
    assert_eq!(schedules.next_due, Some(1001));
    assert_eq!(schedules.next_selectable_due(1000), Some(1001));

    schedules.note_nodata(1, Family::A, None, 0, 1500).unwrap();
    // NODATA without an SOA advances only A to stage 1: 1500 + 2 = 1502; the
    // untouched AAAA sibling stays the earliest slot at 1001.
    assert_eq!(schedules.next_due, Some(1001));
    assert_eq!(schedules.next_selectable_due(1000), Some(1001));

    schedules.overwrite_due_at(2, Family::Aaaa, 500).unwrap();
    // The fresh 500 due is already selectable, so the cached moment keeps 500
    // while the public wake clamps to the present.
    assert_eq!(schedules.next_due, Some(500));
    assert_eq!(schedules.next_selectable_due(1000), Some(1000));

    schedules.overwrite_due_at(2, Family::Aaaa, 3000).unwrap();
    // Retargeting name 2 past every other slot hands the cache back to the
    // 1001 due of name 1's AAAA family.
    assert_eq!(schedules.next_due, Some(1001));
    assert_eq!(schedules.next_selectable_due(1000), Some(1001));
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

/// A model-based state machine over the refresh schedule and its incidents.
///
/// The subject is one production [`Schedules`]; the model owns only what the
/// schedule does not expose: the in-flight flag and start guard it believes per
/// slot, the per-type incident it believes is open, and the documented window
/// each slot's last outcome wrote. Every wake assertion therefore recomputes
/// from the subject's exposed [`Schedules::due_time`] plus that bookkeeping —
/// never from the private `next_due` cache, so a stale cache, a guard-ignoring
/// scan, or a selection that forgets its in-flight marker cannot hide behind a
/// model that agrees with itself.
///
/// Two readings are narrowed deliberately. D3 is per-slot: the machine selects
/// twice at one instant and requires the second selection never to name the
/// first slot (with several slots due the second call legitimately returns
/// another one), while the released slot's re-selectability once its guard
/// elapses is D7's global eligibility. D6 anchors the SOA window at the
/// outcome's own `receipt`; a receipt drawn ahead of the clock makes a
/// `now`-anchored upper bound false even though the documented clamp holds.
mod schedule_machine {
    use super::*;
    use hegel::TestCase;
    use hegel::generators as gs;

    /// TTLs and SOA TTL/MINIMUM values that straddle every documented bound:
    /// the zero-TTL one-second refresh, the 5-second normal floor, the
    /// 30-second negative floor, and both sides of the 900-second ceiling.
    const STRADDLE_TTLS: [u64; 10] = [0, 1, 4, 5, 29, 30, 899, 900, 901, 10_000];

    /// The widest documented retry interval: the ladder's final stage.
    const BACKOFF_MAX: u64 = BACKOFF_STAGES[BACKOFF_STAGES.len() - 1];

    const REASONS: [FailureReason; 9] = [
        FailureReason::Connect,
        FailureReason::Send,
        FailureReason::Receive,
        FailureReason::Timeout,
        FailureReason::PinMismatch,
        FailureReason::NameMismatch,
        FailureReason::NoTrustAnchor,
        FailureReason::TlsProtocol,
        FailureReason::InsufficientAssurance,
    ];

    const REFUSAL_OPS: [&str; 8] = [
        "overwrite_due_at",
        "note_positive",
        "note_exchange_failure",
        "note_nxdomain",
        "note_nodata",
        "clear_exchange_incident",
        "release_selection",
        "due_time",
    ];

    /// What the model believes about one slot's in-flight flag and start guard.
    /// The due time is deliberately absent: every assertion reads the subject's
    /// exposed `due_time`, so the model never becomes its own oracle.
    #[derive(Clone, Copy, Debug)]
    struct ModelSlot {
        pending: bool,
        guard: u64,
    }

    const IDLE: ModelSlot = ModelSlot {
        pending: false,
        guard: 0,
    };

    /// The documented window a slot's last outcome wrote, anchored at the
    /// outcome's own `receipt` or `now`. A cacheable positive refreshes from
    /// `receipt` at its TTL-derived interval, an SOA negative from `receipt` at
    /// its SOA-derived interval, and every backoff retry from `now` at the
    /// current ladder stage.
    #[derive(Clone, Copy, Debug)]
    enum Bound {
        Positive { receipt: u64 },
        NegativeSoa { receipt: u64 },
        Backoff { now: u64 },
    }

    impl Bound {
        const fn label(self) -> &'static str {
            match self {
                Bound::Positive { .. } => "cacheable positive",
                Bound::NegativeSoa { .. } => "SOA negative refresh",
                Bound::Backoff { .. } => "backoff retry",
            }
        }

        const fn window(self) -> (u64, u64) {
            match self {
                Bound::Positive { receipt } => (receipt + 1, receipt + REFRESH_MAX),
                Bound::NegativeSoa { receipt } => {
                    (receipt + NEGATIVE_REFRESH_MIN, receipt + REFRESH_MAX)
                }
                Bound::Backoff { now } => (now + 1, now + BACKOFF_MAX),
            }
        }
    }

    /// A selection recorded at the instant it was made, before any later rule
    /// can retarget or release the slot.
    #[derive(Clone, Copy, Debug)]
    struct Selection {
        name: usize,
        family: Family,
        due: u64,
        guard: u64,
        now: u64,
    }

    /// The two selections one `select_due` rule performed at the same instant.
    #[derive(Clone, Copy, Debug)]
    struct DoubleCheck {
        first: (usize, Family),
        second: Option<(usize, Family)>,
    }

    /// A release recorded with the due time on both sides of the call; a slot
    /// that was never scheduled has no due time on either side.
    #[derive(Clone, Copy, Debug)]
    struct ReleaseCheck {
        name: usize,
        family: Family,
        due_before: Option<u64>,
        due_after: Option<u64>,
    }

    /// The model's eligible set and the subject's answer for one selection.
    #[derive(Clone, Copy, Debug)]
    struct SelectCheck {
        now: u64,
        eligible: bool,
        returned: bool,
    }

    /// One out-of-range call: which operation, whether it refused, and whether
    /// the whole table stayed equal to its prior value.
    #[derive(Clone, Copy, Debug)]
    struct RefusalCheck {
        op: &'static str,
        refused: bool,
        unchanged: bool,
    }

    /// The per-type incident the model believes is open for one slot.
    #[derive(Clone, Copy, Debug)]
    struct OpenIncident {
        opened_at: u64,
        reason: FailureReason,
    }

    fn expected_incident(model: Option<OpenIncident>) -> TypeIncident {
        model.map_or(TypeIncident::Closed, |incident| TypeIncident::Open {
            opened_at: incident.opened_at,
            reason: incident.reason,
        })
    }

    fn draw_family(tc: &TestCase) -> Family {
        tc.draw(gs::sampled_from(&[Family::A, Family::Aaaa][..]))
    }

    fn draw_reason(tc: &TestCase) -> FailureReason {
        tc.draw(gs::sampled_from(&REASONS[..]))
    }

    fn draw_straddle_ttl(tc: &TestCase) -> u64 {
        tc.draw(gs::sampled_from(&STRADDLE_TTLS[..]))
    }

    fn draw_soa(tc: &TestCase) -> Option<Soa> {
        if !tc.draw(gs::booleans()) {
            return None;
        }
        Some(Soa::new(draw_straddle_ttl(tc), draw_straddle_ttl(tc)))
    }

    fn draw_offset(tc: &TestCase) -> u64 {
        tc.draw(gs::integers::<u64>().min_value(0).max_value(4000))
    }

    /// The machine's fixed slot table is sized for the three names the wrapper
    /// may draw.
    const MAX_NAMES: usize = 3;

    pub(super) struct ScheduleMachine {
        subject: Schedules,
        name_count: usize,
        now: u64,
        slots: [[ModelSlot; 2]; MAX_NAMES],
        incidents: [[Option<OpenIncident>; 2]; MAX_NAMES],
        bounds: [[Option<Bound>; 2]; MAX_NAMES],
        last_selection: Option<Selection>,
        last_double: Option<DoubleCheck>,
        last_release: Option<ReleaseCheck>,
        last_select: Option<SelectCheck>,
        last_refusal: Option<RefusalCheck>,
    }

    impl ScheduleMachine {
        pub(super) fn start(name_count: usize) -> ScheduleMachine {
            ScheduleMachine {
                subject: Schedules::new(name_count).expect("the wrapper draws 1..=3 names"),
                name_count,
                now: 0,
                slots: [[IDLE; 2]; MAX_NAMES],
                incidents: [[None; 2]; MAX_NAMES],
                bounds: [[None; 2]; MAX_NAMES],
                last_selection: None,
                last_double: None,
                last_release: None,
                last_select: None,
                last_refusal: None,
            }
        }

        fn slot(&self, name: usize, family: Family) -> ModelSlot {
            self.slots[name][family_slot(family)]
        }

        fn set_slot(&mut self, name: usize, family: Family, slot: ModelSlot) {
            self.slots[name][family_slot(family)] = slot;
        }

        fn clear_pending(&mut self, name: usize, family: Family) {
            let slot = self.slot(name, family);
            self.set_slot(
                name,
                family,
                ModelSlot {
                    pending: false,
                    guard: slot.guard,
                },
            );
        }

        fn draw_name(&self, tc: &TestCase) -> usize {
            tc.draw(
                gs::integers::<usize>()
                    .min_value(0)
                    .max_value(self.name_count - 1),
            )
        }

        /// The model's answer to "is any non-pending slot due and past its
        /// guard at the current instant?", computed from the subject's exposed
        /// due time and the model's own bookkeeping.
        fn any_eligible(&self) -> bool {
            for name in 0..self.name_count {
                for family in Family::ALL {
                    let slot = self.slot(name, family);
                    if slot.pending || slot.guard > self.now {
                        continue;
                    }
                    let due = self.subject.due_time(name, family).expect("admitted name");
                    if due.is_some_and(|due| due <= self.now) {
                        return true;
                    }
                }
            }
            false
        }

        /// The wake the subject must report: the clamp to `now` of the minimum
        /// selectable moment over the model's non-pending slots.
        fn expected_wake(&self) -> Option<u64> {
            let mut earliest: Option<u64> = None;
            for name in 0..self.name_count {
                for family in Family::ALL {
                    let slot = self.slot(name, family);
                    if slot.pending {
                        continue;
                    }
                    let due = self.subject.due_time(name, family).expect("admitted name");
                    let Some(due) = due else { continue };
                    let selectable_at = due.max(slot.guard);
                    earliest = Some(earliest.map_or(selectable_at, |at| at.min(selectable_at)));
                }
            }
            earliest.map(|at| at.max(self.now))
        }

        /// Checks one returned token against the model's pre-call state and
        /// marks its slot in flight with the one-second start guard the
        /// subject applies.
        fn record_selection(&mut self, token: DueToken) -> (usize, Family) {
            let name = token.name();
            let family = token.family();
            assert!(
                name < self.name_count,
                "D2: the token names name {name} outside the admitted range"
            );
            let slot = self.slot(name, family);
            assert!(
                !slot.pending,
                "D2: the schedule selected slot ({name}, {family:?}) while the model holds it in flight"
            );
            assert!(
                slot.guard <= self.now,
                "D2: the schedule selected slot ({name}, {family:?}) at {} before its model start guard {}",
                self.now,
                slot.guard
            );
            let due = self
                .subject
                .due_time(name, family)
                .expect("admitted name")
                .expect("a selected slot carries a due time");
            assert!(
                due <= self.now,
                "D2: the schedule selected slot ({name}, {family:?}) due at {due} ahead of now {}",
                self.now
            );
            self.set_slot(
                name,
                family,
                ModelSlot {
                    pending: true,
                    guard: self.now + 1,
                },
            );
            self.last_selection = Some(Selection {
                name,
                family,
                due,
                guard: slot.guard,
                now: self.now,
            });
            (name, family)
        }
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "the hegel state-machine macro hands each rule its own TestCase by value"
    )]
    #[hegel::state_machine]
    impl ScheduleMachine {
        #[rule(weight = 8.0)]
        fn overwrite_due_at(&mut self, tc: TestCase) {
            let name = self.draw_name(&tc);
            let family = draw_family(&tc);
            let due = self.now + draw_offset(&tc);
            self.subject
                .overwrite_due_at(name, family, due)
                .expect("admitted name");
            self.clear_pending(name, family);
            self.bounds[name][family_slot(family)] = None;
        }

        #[rule(weight = 8.0)]
        fn note_positive(&mut self, tc: TestCase) {
            let name = self.draw_name(&tc);
            let family = draw_family(&tc);
            let ttl = draw_straddle_ttl(&tc);
            let cacheable = tc.draw(gs::booleans());
            let receipt = self.now + draw_offset(&tc);
            self.subject
                .note_positive(name, family, receipt, ttl, cacheable, self.now)
                .expect("admitted name");
            self.clear_pending(name, family);
            self.bounds[name][family_slot(family)] = Some(if cacheable {
                Bound::Positive { receipt }
            } else {
                Bound::Backoff { now: self.now }
            });
        }

        #[rule(weight = 8.0)]
        fn note_exchange_failure(&mut self, tc: TestCase) {
            let name = self.draw_name(&tc);
            let family = draw_family(&tc);
            let reason = draw_reason(&tc);
            let transition = self
                .subject
                .note_exchange_failure(name, family, self.now, reason)
                .expect("admitted name");
            let slot = family_slot(family);
            let opened_at = if let Some(open) = self.incidents[name][slot] {
                assert_eq!(
                    transition,
                    PerTypeTransition::SilentUpdate,
                    "D5: a repeat failure re-opened the per-type incident instead of updating it"
                );
                open.opened_at
            } else {
                assert_eq!(
                    transition,
                    PerTypeTransition::Opened,
                    "D5: the first failure did not open the per-type incident"
                );
                self.now
            };
            self.incidents[name][slot] = Some(OpenIncident { opened_at, reason });
            self.clear_pending(name, family);
            self.bounds[name][slot] = Some(Bound::Backoff { now: self.now });
        }

        #[rule(weight = 5.0)]
        fn note_nxdomain(&mut self, tc: TestCase) {
            let name = self.draw_name(&tc);
            let soa = draw_soa(&tc);
            let receipt = self.now + draw_offset(&tc);
            self.subject
                .note_nxdomain(name, soa, receipt, self.now)
                .expect("admitted name");
            for family in Family::ALL {
                self.clear_pending(name, family);
                self.bounds[name][family_slot(family)] = Some(match soa {
                    Some(_) => Bound::NegativeSoa { receipt },
                    None => Bound::Backoff { now: self.now },
                });
                if soa.is_some() {
                    let due = self
                        .subject
                        .due_time(name, family)
                        .expect("admitted name")
                        .expect("the outcome wrote a due time");
                    assert!(
                        due >= self.now + NEGATIVE_REFRESH_MIN,
                        "D6: the SOA negative due {due} is below now + NEGATIVE_REFRESH_MIN"
                    );
                }
            }
        }

        #[rule(weight = 5.0)]
        fn note_nodata(&mut self, tc: TestCase) {
            let name = self.draw_name(&tc);
            let family = draw_family(&tc);
            let soa = draw_soa(&tc);
            let receipt = self.now + draw_offset(&tc);
            self.subject
                .note_nodata(name, family, soa, receipt, self.now)
                .expect("admitted name");
            self.clear_pending(name, family);
            let slot = family_slot(family);
            self.bounds[name][slot] = Some(match soa {
                Some(_) => Bound::NegativeSoa { receipt },
                None => Bound::Backoff { now: self.now },
            });
            if soa.is_some() {
                let due = self
                    .subject
                    .due_time(name, family)
                    .expect("admitted name")
                    .expect("the outcome wrote a due time");
                assert!(
                    due >= self.now + NEGATIVE_REFRESH_MIN,
                    "D6: the SOA negative due {due} is below now + NEGATIVE_REFRESH_MIN"
                );
            }
        }

        #[rule(weight = 4.0)]
        fn clear_exchange_incident(&mut self, tc: TestCase) {
            let name = self.draw_name(&tc);
            let family = draw_family(&tc);
            let slot = family_slot(family);
            let expected = self.incidents[name][slot];
            let transition = self
                .subject
                .clear_exchange_incident(name, family, self.now)
                .expect("admitted name");
            match expected {
                Some(open) => assert_eq!(
                    transition,
                    PerTypeTransition::Recovered {
                        duration: self.now.saturating_sub(open.opened_at)
                    },
                    "D5: clearing an open incident reported the wrong elapsed duration"
                ),
                None => assert_eq!(
                    transition,
                    PerTypeTransition::None,
                    "D5: clearing a closed incident reported a recovery"
                ),
            }
            self.incidents[name][slot] = None;
        }

        #[rule(weight = 14.0)]
        fn select_due(&mut self, _: TestCase) {
            let eligible = self.any_eligible();
            let first = self
                .subject
                .select_due(self.now)
                .expect("a drawn clock is far below u64::MAX");
            let first_key = first.map(|token| self.record_selection(token));
            assert_eq!(
                first.is_some(),
                eligible,
                "D7: select_due(now={}) returned {} while the model's eligible set was {eligible}",
                self.now,
                first.is_some()
            );
            let second = self
                .subject
                .select_due(self.now)
                .expect("a drawn clock is far below u64::MAX");
            let second_key = second.map(|token| (token.name(), token.family()));
            if let (Some(first), Some(second)) = (first_key, second_key) {
                assert_ne!(
                    second, first,
                    "D3: select_due started slot {first:?} twice at one instant (now={})",
                    self.now
                );
            }
            if let Some(token) = second {
                self.record_selection(token);
            }
            self.last_double = first_key.map(|first| DoubleCheck {
                first,
                second: second_key,
            });
            self.last_select = Some(SelectCheck {
                now: self.now,
                eligible,
                returned: first.is_some(),
            });
        }

        #[rule(weight = 10.0)]
        fn release_selection(&mut self, tc: TestCase) {
            let name = self.draw_name(&tc);
            let family = draw_family(&tc);
            let due_before = self.subject.due_time(name, family).expect("admitted name");
            self.subject
                .release_selection(name, family)
                .expect("admitted name");
            let due_after = self.subject.due_time(name, family).expect("admitted name");
            assert_eq!(
                due_before, due_after,
                "D4: release_selection retargeted the due time of ({name}, {family:?})"
            );
            self.clear_pending(name, family);
            self.last_release = Some(ReleaseCheck {
                name,
                family,
                due_before,
                due_after,
            });
        }

        #[rule(weight = 7.0)]
        fn advance_clock(&mut self, tc: TestCase) {
            let step = tc.draw(gs::integers::<u64>().min_value(0).max_value(400));
            self.now += step;
        }

        #[rule(weight = 4.0)]
        fn refuse_out_of_range(&mut self, tc: TestCase) {
            let name = self.name_count;
            let family = draw_family(&tc);
            let op = tc.draw(
                gs::integers::<usize>()
                    .min_value(0)
                    .max_value(REFUSAL_OPS.len() - 1),
            );
            assert!(
                self.subject.incident(name, family).is_none(),
                "D8: the incident read admitted an out-of-range name"
            );
            let before = self.subject;
            let refused = match op {
                0 => {
                    self.subject.overwrite_due_at(name, family, self.now)
                        == Err(ScheduleError::NameOutOfRange)
                }
                1 => {
                    self.subject
                        .note_positive(name, family, self.now, 60, true, self.now)
                        == Err(ScheduleError::NameOutOfRange)
                }
                2 => {
                    self.subject.note_exchange_failure(
                        name,
                        family,
                        self.now,
                        FailureReason::Timeout,
                    ) == Err(ScheduleError::NameOutOfRange)
                }
                3 => {
                    self.subject.note_nxdomain(name, None, self.now, self.now)
                        == Err(ScheduleError::NameOutOfRange)
                }
                4 => {
                    self.subject
                        .note_nodata(name, family, None, self.now, self.now)
                        == Err(ScheduleError::NameOutOfRange)
                }
                5 => {
                    self.subject.clear_exchange_incident(name, family, self.now)
                        == Err(ScheduleError::NameOutOfRange)
                }
                6 => {
                    self.subject.release_selection(name, family)
                        == Err(ScheduleError::NameOutOfRange)
                }
                _ => {
                    self.subject.due_time(name, family).map(|_| ())
                        == Err(ScheduleError::NameOutOfRange)
                }
            };
            let unchanged = self.subject == before;
            assert!(
                refused,
                "D8: {} accepted an out-of-range name",
                REFUSAL_OPS[op]
            );
            assert!(
                unchanged,
                "D8: {} on an out-of-range name mutated the table",
                REFUSAL_OPS[op]
            );
            self.last_refusal = Some(RefusalCheck {
                op: REFUSAL_OPS[op],
                refused,
                unchanged,
            });
        }

        #[invariant(always_run)]
        fn d1_wake_agreement(&self, _: TestCase) {
            assert_eq!(
                self.subject.next_selectable_due(self.now),
                self.expected_wake(),
                "D1: the owner wake disagrees with the wake recomputed from due_time and the model's in-flight/guard record at now={}",
                self.now
            );
        }

        #[invariant(always_run)]
        fn d2_selection_legality(&self, _: TestCase) {
            let Some(selection) = self.last_selection else {
                return;
            };
            assert!(
                selection.name < self.name_count,
                "D2: the last selection named name {} outside the admitted range",
                selection.name
            );
            assert!(
                selection.due <= selection.now,
                "D2: the last selection took a slot due at {} after its own instant {}",
                selection.due,
                selection.now
            );
            assert!(
                selection.guard <= selection.now,
                "D2: the last selection ignored the start guard {} at {}",
                selection.guard,
                selection.now
            );
            assert!(
                self.subject
                    .due_time(selection.name, selection.family)
                    .expect("an admitted name")
                    .is_some(),
                "D2: a selected slot lost its due time"
            );
        }

        #[invariant(always_run)]
        fn d3_no_double_start(&self, _: TestCase) {
            if let Some(double) = self.last_double {
                assert_ne!(
                    double.second,
                    Some(double.first),
                    "D3: one instant started slot {:?} twice",
                    double.first
                );
            }
        }

        #[invariant(always_run)]
        fn d4_release_discipline(&self, _: TestCase) {
            if let Some(release) = self.last_release {
                assert_eq!(
                    release.due_before, release.due_after,
                    "D4: release_selection moved the due time of ({}, {:?})",
                    release.name, release.family
                );
            }
        }

        #[invariant(always_run)]
        fn d5_incident_monotonicity(&self, _: TestCase) {
            for name in 0..self.name_count {
                for family in Family::ALL {
                    let subject = self
                        .subject
                        .incident(name, family)
                        .expect("an admitted name carries an incident slot");
                    let expected = expected_incident(self.incidents[name][family_slot(family)]);
                    assert_eq!(
                        subject, expected,
                        "D5: the incident state of ({name}, {family:?}) diverged from the model's open/opened_at/reason record"
                    );
                }
            }
        }

        #[invariant(always_run)]
        fn d6_interval_bounds(&self, _: TestCase) {
            for name in 0..self.name_count {
                for family in Family::ALL {
                    let Some(bound) = self.bounds[name][family_slot(family)] else {
                        continue;
                    };
                    let due = self
                        .subject
                        .due_time(name, family)
                        .expect("an admitted name")
                        .expect("an outcome-written slot carries a due time");
                    let (lo, hi) = bound.window();
                    assert!(
                        due >= lo && due <= hi,
                        "D6: the {} due {due} of ({name}, {family:?}) left its documented window [{lo}, {hi}]",
                        bound.label()
                    );
                }
            }
        }

        #[invariant(always_run)]
        fn d7_liveness(&self, _: TestCase) {
            if let Some(check) = self.last_select {
                let SelectCheck {
                    now,
                    eligible,
                    returned,
                } = check;
                assert_eq!(
                    returned, eligible,
                    "D7: select_due(now={now}) returned {returned} while the model's eligible set was {eligible}"
                );
            }
        }

        #[invariant(always_run)]
        fn d8_refusal_purity(&self, _: TestCase) {
            if let Some(refusal) = self.last_refusal {
                assert!(
                    refusal.refused,
                    "D8: {} accepted an out-of-range name",
                    refusal.op
                );
                assert!(
                    refusal.unchanged,
                    "D8: {} on an out-of-range name mutated the table",
                    refusal.op
                );
            }
        }
    }
}

/// Drives the refresh schedule through generated overwrite / outcome / selection
/// / release / clock interleavings, including out-of-range refusal calls, and
/// checks the wake agreement, selection legality, in-flight discipline, incident
/// monotonicity, interval bounds, liveness and refusal purity after every rule.
/// The invariant list and its independence argument are on
/// [`schedule_machine`]; `hegel.toml` owns the case count.
#[hegel::test(derandomize = true)]
fn refresh_schedule_and_incidents_follow_the_model(tc: hegel::TestCase) {
    let name_count = tc.draw(
        hegel::generators::integers::<usize>()
            .min_value(1)
            .max_value(3),
    );
    hegel::stateful::machine(schedule_machine::ScheduleMachine::start(name_count))
        .steps(80)
        .run(tc);
}

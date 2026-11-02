use super::*;
use crate::config::ALLOWLIST_MAX;

fn any_controls(kind: ActionKind, scope: Scope) -> [Control; AnyIllegalControl::COUNT] {
    [Control::new(kind, scope); AnyIllegalControl::COUNT]
}

fn per_fqdn(actions: &[(ActionKind, Scope)]) -> Vec<PerFqdnControl> {
    actions
        .iter()
        .map(|&(kind, scope)| PerFqdnControl::control(kind, scope))
        .collect()
}

fn table(
    any: [Control; AnyIllegalControl::COUNT],
    early: &[(ActionKind, Scope)],
    ja4: &[(ActionKind, Scope)],
) -> ControlTable {
    ControlTable::new(any, &per_fqdn(early), &per_fqdn(ja4)).expect("in-bound test table")
}

fn any(cause: AnyIllegalCause) -> Violation {
    Violation::AnyIllegal { cause }
}

#[test]
fn first_any_illegal_fires_its_control_action_once() {
    let t = table(
        any_controls(ActionKind::Block, Scope::All),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Notify, Scope::Connection)],
    );
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(&t, &mut latch, any(AnyIllegalCause::HostNotAllowlisted)),
        Effect::Block { scope: Scope::All }
    );
    assert_eq!(
        decide(
            &t,
            &mut latch,
            any(AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort)),
        ),
        Effect::BaselineOnly,
        "a later AnyIllegal on the same connection is BaselineOnly"
    );
}

#[test]
fn first_any_illegal_scoped_connection_yields_block_connection() {
    let t = table(
        any_controls(ActionKind::Block, Scope::Connection),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Notify, Scope::Connection)],
    );
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(
            &t,
            &mut latch,
            any(AnyIllegalCause::TlsProfile(
                HelloRejectReason::ServerNameMismatch
            )),
        ),
        Effect::Block {
            scope: Scope::Connection
        }
    );
}

#[test]
fn any_illegal_cause_selects_its_own_control() {
    let controls = [
        Control::new(ActionKind::Notify, Scope::Connection),
        Control::new(ActionKind::Block, Scope::All),
        Control::new(ActionKind::Notify, Scope::All),
        Control::new(ActionKind::Block, Scope::Connection),
    ];
    let t = table(
        controls,
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Block, Scope::Domain)],
    );
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(
            &t,
            &mut latch,
            any(AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort)),
        ),
        Effect::Notify {
            scope: Scope::Connection
        },
        "connect_parse selects the connect_parse control"
    );
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(&t, &mut latch, any(AnyIllegalCause::HostNotAllowlisted)),
        Effect::Block { scope: Scope::All },
        "host_not_allowlisted selects the host_not_allowlisted control"
    );
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(
            &t,
            &mut latch,
            any(AnyIllegalCause::TlsProfile(
                HelloRejectReason::ServerNameMismatch
            )),
        ),
        Effect::Notify { scope: Scope::All },
        "tls_profile selects the tls_profile control"
    );
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(&t, &mut latch, any(AnyIllegalCause::Ech)),
        Effect::Block {
            scope: Scope::Connection
        },
        "ech selects the ech control"
    );
}

#[test]
fn latched_connection_cannot_fire_twice() {
    let t = table(
        any_controls(ActionKind::Block, Scope::All),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Notify, Scope::Connection)],
    );
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(
            &t,
            &mut latch,
            any(AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort)),
        ),
        Effect::Block { scope: Scope::All }
    );
    assert_eq!(
        decide(
            &t,
            &mut latch,
            any(AnyIllegalCause::TlsProfile(
                HelloRejectReason::ServerNameMismatch
            )),
        ),
        Effect::BaselineOnly
    );
    assert_eq!(
        decide(&t, &mut latch, any(AnyIllegalCause::HostNotAllowlisted)),
        Effect::BaselineOnly
    );
}

#[test]
fn early_data_selects_configured_block_connection() {
    let t = table(
        any_controls(ActionKind::Block, Scope::All),
        &[(ActionKind::Block, Scope::Connection)],
        &[(ActionKind::Notify, Scope::Connection)],
    );
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(
            &t,
            &mut latch,
            Violation::EarlyUpstreamData {
                ordinal: t.ordinal(0).expect("ordinal"),
            }
        ),
        Effect::Block {
            scope: Scope::Connection
        },
        "connection is the only early_data block scope reachable from valid config; fqdn/all block scopes are rejected at config parse (docs F-02 close), so early-data can no longer select a per-domain or process-wide latch"
    );
    assert_eq!(
        latch,
        FirstSlot::Armed,
        "early-data must not consume the first-slot latch"
    );
}

#[test]
fn early_data_selects_configured_notify_scope() {
    let t = table(
        any_controls(ActionKind::Block, Scope::Connection),
        &[
            (ActionKind::Notify, Scope::Connection),
            (ActionKind::Notify, Scope::All),
        ],
        &[
            (ActionKind::Notify, Scope::Connection),
            (ActionKind::Notify, Scope::Connection),
        ],
    );
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(
            &t,
            &mut latch,
            Violation::EarlyUpstreamData {
                ordinal: t.ordinal(0).expect("ordinal"),
            }
        ),
        Effect::Notify {
            scope: Scope::Connection
        }
    );
    assert_eq!(
        decide(
            &t,
            &mut latch,
            Violation::EarlyUpstreamData {
                ordinal: t.ordinal(1).expect("ordinal"),
            }
        ),
        Effect::Notify { scope: Scope::All }
    );
}

#[test]
fn early_data_ignore_is_baseline_only() {
    let any = any_controls(ActionKind::Block, Scope::All);
    let early = vec![PerFqdnControl::Ignore];
    let ja4 = vec![PerFqdnControl::control(
        ActionKind::Notify,
        Scope::Connection,
    )];
    let t = ControlTable::new(any, &early, &ja4).expect("in-bound test table");
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(
            &t,
            &mut latch,
            Violation::EarlyUpstreamData {
                ordinal: t.ordinal(0).expect("ordinal"),
            }
        ),
        Effect::BaselineOnly,
        "ignore is the per-FQDN opt-out: no action"
    );
    assert_eq!(
        latch,
        FirstSlot::Armed,
        "ignore must not consume the first-slot latch"
    );
}

#[test]
fn ja4_change_selects_configured_action() {
    let any = any_controls(ActionKind::Block, Scope::All);
    let early = vec![PerFqdnControl::control(
        ActionKind::Notify,
        Scope::Connection,
    )];
    let ja4 = vec![PerFqdnControl::control(ActionKind::Block, Scope::Domain)];
    let t = ControlTable::new(any, &early, &ja4).expect("in-bound test table");
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(
            &t,
            &mut latch,
            Violation::Ja4Change {
                ordinal: t.ordinal(0).expect("ordinal"),
            }
        ),
        Effect::Block {
            scope: Scope::Domain
        },
        "ja4 change selects the per-FQDN ja4 control"
    );
    assert_eq!(
        latch,
        FirstSlot::Armed,
        "ja4 change must not consume the first-slot latch"
    );
}

#[test]
fn ja4_change_ignore_is_baseline_only() {
    let any = any_controls(ActionKind::Block, Scope::All);
    let early = vec![PerFqdnControl::control(
        ActionKind::Notify,
        Scope::Connection,
    )];
    let ja4 = vec![PerFqdnControl::Ignore];
    let t = ControlTable::new(any, &early, &ja4).expect("in-bound test table");
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(
            &t,
            &mut latch,
            Violation::Ja4Change {
                ordinal: t.ordinal(0).expect("ordinal"),
            }
        ),
        Effect::BaselineOnly,
        "ja4 ignore suppresses the change signal to no action"
    );
}

#[test]
fn early_data_unbound_ordinal_is_unknown_not_baseline() {
    let mut many = Vec::new();
    for _ in 0..ALLOWLIST_MAX {
        many.push((ActionKind::Notify, Scope::All));
    }
    let big = table(any_controls(ActionKind::Block, Scope::All), &many, &many);
    let unbound = big.ordinal(5).expect("index 5 configured in a full table");
    let small = table(
        any_controls(ActionKind::Block, Scope::All),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Notify, Scope::Connection)],
    );
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(
            &small,
            &mut latch,
            Violation::EarlyUpstreamData { ordinal: unbound }
        ),
        Effect::Unknown {
            reason: UnknownReason::UnboundOrdinal
        },
        "an unbound ordinal is Evidence Unknown, never a legal BaselineOnly"
    );
}

#[test]
fn evidence_insufficient_is_unknown_not_baseline() {
    let t = table(
        any_controls(ActionKind::Block, Scope::All),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Block, Scope::All)],
    );
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(&t, &mut latch, Violation::EvidenceInsufficient),
        Effect::Unknown {
            reason: UnknownReason::NotYetValidated
        }
    );
    assert_eq!(
        latch,
        FirstSlot::Armed,
        "insufficient evidence must not consume the first-slot latch"
    );
}

#[test]
fn unattributed_is_unknown_not_any_illegal() {
    let t = table(
        any_controls(ActionKind::Block, Scope::All),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Block, Scope::All)],
    );
    let mut latch = FirstSlot::new();
    assert_eq!(
        decide(&t, &mut latch, Violation::Unattributed),
        Effect::Unknown {
            reason: UnknownReason::Unattributed
        }
    );
    assert_eq!(
        latch,
        FirstSlot::Armed,
        "an unattributed anomaly must not consume the first-slot latch"
    );
    assert_eq!(
        decide(&t, &mut latch, Violation::Unattributed),
        Effect::Unknown {
            reason: UnknownReason::Unattributed
        }
    );
}

#[test]
fn missing_parse_result_is_unknown_never_an_action() {
    let t = table(
        any_controls(ActionKind::Block, Scope::All),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Block, Scope::All)],
    );
    let mut latch = FirstSlot::new();
    let effect = decide(&t, &mut latch, Violation::MissingParseResult);
    assert_eq!(
        effect,
        Effect::Unknown {
            reason: UnknownReason::MissingParseResult
        }
    );
    assert!(
        !matches!(effect, Effect::Block { .. }),
        "a missing internal parse result must never select a Block action"
    );
    assert_eq!(
        latch,
        FirstSlot::Armed,
        "a missing internal parse result must not consume the first-slot latch"
    );
}

#[test]
fn finite_cause_discriminants_stay_distinct_through_latch() {
    let t = table(
        any_controls(ActionKind::Block, Scope::Connection),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Notify, Scope::Connection)],
    );
    let mut latch = FirstSlot::new();
    let first = decide(
        &t,
        &mut latch,
        any(AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort)),
    );
    assert_eq!(
        first,
        Effect::Block {
            scope: Scope::Connection
        }
    );
    let second = decide(
        &t,
        &mut latch,
        any(AnyIllegalCause::ConnectParse(
            ConnectHeadReason::TransferEncoding,
        )),
    );
    assert_eq!(
        second,
        Effect::BaselineOnly,
        "the first-slot action fires once, but the discriminant is not erased"
    );
    assert_ne!(
        AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::TransferEncoding),
        "WrongPort and TransferEncoding are distinct finite causes"
    );
    let mut seen = [false; AnyIllegalCause::KIND_COUNT];
    let kinds = [
        AnyIllegalCause::ConnectParse(ConnectHeadReason::TooLong),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::MethodNotConnect),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::UnsupportedVersion),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::TargetNotAuthorityForm),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::MalformedRequestLine),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::BareLineFeed),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::BareCarriageReturn),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::ObsFold),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::InvalidHostname),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::PortOutOfRange),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::TransferEncoding),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::NonzeroContentLength),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::DuplicateContentLength),
        AnyIllegalCause::ConnectParse(ConnectHeadReason::TooManyHeaderLines),
        AnyIllegalCause::HostNotAllowlisted,
        AnyIllegalCause::TlsProfile(HelloRejectReason::ServerNameMismatch),
        AnyIllegalCause::TlsProfile(HelloRejectReason::InvalidServerName),
        AnyIllegalCause::TlsProfile(HelloRejectReason::Profile),
        AnyIllegalCause::Ech,
    ];
    for kind in kinds {
        let i = kind.kind_index();
        assert!(i < seen.len(), "kind index {i} within the fixed array");
        assert!(!seen[i], "kind index {i} is assigned exactly once");
        seen[i] = true;
    }
    assert!(
        seen.iter().all(|&s| s),
        "every cause-kind slot is covered by exactly one finite discriminant"
    );
}

#[test]
fn from_hello_reject_routes_ech_to_the_ech_control() {
    assert_eq!(
        AnyIllegalCause::from_hello_reject(HelloRejectReason::EchPresent),
        AnyIllegalCause::Ech
    );
    assert_eq!(
        AnyIllegalCause::from_hello_reject(HelloRejectReason::ServerNameMismatch),
        AnyIllegalCause::TlsProfile(HelloRejectReason::ServerNameMismatch)
    );
    assert_eq!(
        AnyIllegalCause::from_hello_reject(HelloRejectReason::InvalidServerName),
        AnyIllegalCause::TlsProfile(HelloRejectReason::InvalidServerName)
    );
    assert_eq!(
        AnyIllegalCause::from_hello_reject(HelloRejectReason::Profile),
        AnyIllegalCause::TlsProfile(HelloRejectReason::Profile)
    );
}

#[test]
fn unknown_and_cause_reason_kinds_are_finite_and_ordered() {
    assert_eq!(UnknownReason::COUNT, 4);
    assert_eq!(
        UnknownReason::UnboundOrdinal.index(),
        0,
        "the fold array must map reason to index in declaration order"
    );
    assert_eq!(UnknownReason::NotYetValidated.index(), 1);
    assert_eq!(UnknownReason::MissingParseResult.index(), 2);
    assert_eq!(UnknownReason::Unattributed.index(), 3);
    assert_eq!(
        AnyIllegalCause::KIND_COUNT,
        15 + 1 + 3 + 1,
        "15 CONNECT-head + HostNotAllowlisted + 3 hello-reject (EchPresent split to Ech) + Ech"
    );
}

#[test]
fn control_table_storage_fits_planned_bound() {
    let t = table(
        any_controls(ActionKind::Block, Scope::All),
        &[(ActionKind::Notify, Scope::Connection)],
        &[(ActionKind::Block, Scope::All)],
    );
    assert!(
        core::mem::size_of_val(&t) <= 256,
        "data table at {} bytes",
        core::mem::size_of_val(&t)
    );
    assert_eq!(core::mem::size_of::<Control>(), 2);
    assert_eq!(t.len(), 1);
}

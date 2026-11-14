//! Test-only owner of the control-table builders shared by the `policy` and
//! `state` tests: both decision paths must read the same table, so the
//! construction has one owner and cannot drift between the two.
#![allow(
    dead_code,
    reason = "shared `#[path]` owner; each inclusion site uses only its subset"
)]

use crate::enforcement::action::{
    ActionKind, AnyIllegalControl, Control, ControlTable, PerFqdnControl, Scope,
};

pub(super) fn any_controls(kind: ActionKind, scope: Scope) -> [Control; AnyIllegalControl::COUNT] {
    [Control::new(kind, scope); AnyIllegalControl::COUNT]
}

pub(super) fn per_fqdn(actions: &[(ActionKind, Scope)]) -> Vec<PerFqdnControl> {
    actions
        .iter()
        .map(|&(kind, scope)| PerFqdnControl::control(kind, scope))
        .collect()
}

pub(super) fn table(
    any: [Control; AnyIllegalControl::COUNT],
    early: &[(ActionKind, Scope)],
    ja4: &[(ActionKind, Scope)],
) -> ControlTable {
    ControlTable::new(any, &per_fqdn(early), &per_fqdn(ja4)).expect("in-bound test table")
}

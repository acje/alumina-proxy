//! Legal configuration values for the tripwire/action control surface
//! (docs/alumina-proxy.md tripwire amendment): scopes, per-control actions,
//! the fixed per-ordinal table, and the per-connection first-AnyIllegal
//! latch. Tarpit is reserved and has no type here.

use crate::config::ALLOWLIST_MAX;

/// Block/Notify supplement scope; the legal action scopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Scope {
    Connection = 0,
    Domain = 1,
    All = 2,
}

impl Scope {
    /// The number of scopes; the fixed index bound of any per-scope counter
    /// array.
    pub const COUNT: usize = 3;
}

/// Per-control action kind. `Tarpit` is reserved and is not a legal
/// operational action; configuration selecting it is rejected at parse with
/// an explicit reserved-keyword diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ActionKind {
    Notify = 0,
    Block = 1,
}

/// Exactly one configured control: one action kind and one scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    kind: ActionKind,
    scope: Scope,
}

impl Control {
    /// Build a control from a kind and scope.
    pub const fn new(kind: ActionKind, scope: Scope) -> Control {
        Control { kind, scope }
    }

    /// The action kind.
    pub const fn kind(self) -> ActionKind {
        self.kind
    }

    /// The action scope: enforcement scope for `Block`, reporting scope for
    /// `Notify`. An implicit Notify for an applied `Block` inherits that
    /// Block's scope.
    pub const fn scope(self) -> Scope {
        self.scope
    }
}

/// A per-FQDN control value: either a configured action/scope or the
/// per-FQDN-only `ignore` opt-out (no action, no flare; the JA4 baseline is
/// still recorded, the change signal is suppressed). `ignore` is never a
/// global default and is invalid on `any_illegal` controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerFqdnControl {
    Ignore,
    Control(Control),
}

impl PerFqdnControl {
    /// The per-FQDN `ignore` opt-out.
    pub const fn ignore() -> PerFqdnControl {
        PerFqdnControl::Ignore
    }

    /// A configured per-FQDN control from a kind and scope.
    pub const fn control(kind: ActionKind, scope: Scope) -> PerFqdnControl {
        PerFqdnControl::Control(Control::new(kind, scope))
    }
}

/// The four `any_illegal` controls, keyed by attribution surface: they fire
/// before a domain is validated, so no ordinal is attributable. No `ignore`
/// is representable here: the suspicious class is always observable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AnyIllegalControl {
    ConnectParse = 0,
    HostNotAllowlisted = 1,
    TlsProfile = 2,
    Ech = 3,
}

impl AnyIllegalControl {
    /// The number of `any_illegal` controls.
    pub const COUNT: usize = 4;
}

/// A 0-based configured-allowlist ordinal whose range is bound by the table
/// that minted it (`ControlTable::ordinal`). The constructor is private: an
/// ordinal is produced only against a specific table's entry count, so a
/// value outside that table's configured range cannot be minted from it.
/// Attacker-controlled hostnames or IP strings are never keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainOrdinal(u8);

impl DomainOrdinal {
    #[expect(
        clippy::expect_used,
        reason = "mint guards index < count <= ALLOWLIST_MAX (32), so the ordinal fits u8"
    )]
    fn mint(index: usize, count: usize) -> Option<DomainOrdinal> {
        (index < count && count <= ALLOWLIST_MAX)
            .then(|| DomainOrdinal(u8::try_from(index).expect("ordinal bounded by ALLOWLIST_MAX")))
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "index below ALLOWLIST_MAX fits u8"
    )]
    pub(crate) const fn from_index(index: usize) -> Option<DomainOrdinal> {
        if index < ALLOWLIST_MAX {
            Some(DomainOrdinal(index as u8))
        } else {
            None
        }
    }

    /// The 0-based ordinal value, always below the allowlist bound.
    pub const fn get(self) -> usize {
        self.0 as usize
    }
}

/// Per-connection first-AnyIllegal state: armed once, then spent forever, so
/// the special first-slot action can apply at most once per connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FirstSlot {
    #[default]
    Armed,
    Spent,
}

impl FirstSlot {
    /// A fresh per-connection latch, armed for the first `AnyIllegal`.
    pub const fn new() -> FirstSlot {
        FirstSlot::Armed
    }

    /// Whether this is the first `AnyIllegal` on the connection; consumes the
    /// latch exactly once.
    pub fn take_if_armed(&mut self) -> bool {
        if *self == FirstSlot::Armed {
            *self = FirstSlot::Spent;
            true
        } else {
            false
        }
    }
}

/// Boot-fixed control table: the four `any_illegal` controls plus per-ordinal
/// `early_data` and `ja4` per-FQDN controls. Storage is fixed
/// (`[Control; 4]` plus two `[PerFqdnControl; ALLOWLIST_MAX]`), with the exact
/// configured count; construction rejects an empty or over-limit set and
/// ordinals are minted only from the table, so no unconfigured position
/// carries a fabricated configured action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlTable {
    any_illegal: [Control; AnyIllegalControl::COUNT],
    early_data: [PerFqdnControl; ALLOWLIST_MAX],
    ja4: [PerFqdnControl; ALLOWLIST_MAX],
    count: usize,
}

impl ControlTable {
    /// Build the table from the configured controls (crate-internal; the
    /// config path supplies exactly the allowlist count, within bound).
    /// `None` when the set is empty, exceeds the allowlist bound, or the
    /// `early_data` and `ja4` counts disagree.
    pub(crate) fn new(
        any_illegal: [Control; AnyIllegalControl::COUNT],
        early_data: &[PerFqdnControl],
        ja4: &[PerFqdnControl],
    ) -> Option<ControlTable> {
        let count = early_data.len();
        if count == 0 || count > ALLOWLIST_MAX || ja4.len() != count {
            return None;
        }
        let mut early = [PerFqdnControl::Ignore; ALLOWLIST_MAX];
        early[..count].copy_from_slice(early_data);
        let mut j4 = [PerFqdnControl::Ignore; ALLOWLIST_MAX];
        j4[..count].copy_from_slice(ja4);
        Some(ControlTable {
            any_illegal,
            early_data: early,
            ja4: j4,
            count,
        })
    }

    /// The configured control for one `any_illegal` control key.
    pub const fn any_illegal(&self, control: AnyIllegalControl) -> Control {
        self.any_illegal[control as usize]
    }

    /// The configured per-FQDN `early_data` control for an ordinal, or `None`
    /// when the ordinal is not within this table's configured count (including
    /// an ordinal minted by a different, larger table). A filler entry is
    /// never reachable.
    pub fn early_data(&self, ordinal: DomainOrdinal) -> Option<PerFqdnControl> {
        (ordinal.get() < self.count).then(|| self.early_data[ordinal.get()])
    }

    /// The configured per-FQDN `ja4` control for an ordinal, or `None` when
    /// the ordinal is not within this table's configured count (including an
    /// ordinal minted by a different, larger table). A filler entry is never
    /// reachable.
    pub fn ja4(&self, ordinal: DomainOrdinal) -> Option<PerFqdnControl> {
        (ordinal.get() < self.count).then(|| self.ja4[ordinal.get()])
    }

    /// Number of configured domain entries.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// The configured ordinal position (0-based) for this table, or `None`
    /// when the index is not within this table's configured count.
    pub fn ordinal(&self, index: usize) -> Option<DomainOrdinal> {
        DomainOrdinal::mint(index, self.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: usize) -> PerFqdnControl {
        let kind = if i.is_multiple_of(2) {
            ActionKind::Notify
        } else {
            ActionKind::Block
        };
        PerFqdnControl::control(kind, Scope::Connection)
    }

    fn table(count: usize) -> ControlTable {
        let any_illegal = [Control::new(ActionKind::Block, Scope::All); AnyIllegalControl::COUNT];
        let early: Vec<PerFqdnControl> = (0..count).map(entry).collect();
        let ja4: Vec<PerFqdnControl> = (0..count).map(entry).collect();
        ControlTable::new(any_illegal, &early, &ja4).expect("in-bound test table")
    }

    #[test]
    fn new_rejects_empty_and_over_limit_sets() {
        let any_illegal = [Control::new(ActionKind::Block, Scope::All); AnyIllegalControl::COUNT];
        assert!(ControlTable::new(any_illegal, &[], &[]).is_none());
        let over: Vec<PerFqdnControl> = (0..=ALLOWLIST_MAX).map(entry).collect();
        assert!(ControlTable::new(any_illegal, &over, &over).is_none());
        let max: Vec<PerFqdnControl> = (0..ALLOWLIST_MAX).map(entry).collect();
        assert!(ControlTable::new(any_illegal, &max, &max).is_some());
    }

    #[test]
    fn new_rejects_mismatched_per_fqdn_counts() {
        let any_illegal = [Control::new(ActionKind::Block, Scope::All); AnyIllegalControl::COUNT];
        let early: Vec<PerFqdnControl> = (0..2).map(entry).collect();
        let ja4: Vec<PerFqdnControl> = (0..1).map(entry).collect();
        assert!(
            ControlTable::new(any_illegal, &early, &ja4).is_none(),
            "early_data and ja4 counts must agree"
        );
    }

    #[test]
    fn two_entry_table_mints_only_its_configured_range() {
        let t = table(2);
        assert!(t.ordinal(0).is_some());
        assert!(t.ordinal(1).is_some());
        assert!(t.ordinal(2).is_none());
        assert!(
            t.ordinal(5).is_none(),
            "two-entry/index5 witness: index 5 is not configured"
        );
    }

    #[test]
    fn per_fqdn_controls_are_read_back_by_ordinal() {
        let t = table(2);
        let zero = t.ordinal(0).expect("in table range");
        let one = t.ordinal(1).expect("in table range");
        assert_eq!(t.early_data(zero), Some(entry(0)));
        assert_eq!(t.early_data(one), Some(entry(1)));
        assert_eq!(t.ja4(zero), Some(entry(0)));
        assert_eq!(t.ja4(one), Some(entry(1)));
        assert_eq!(
            t.any_illegal(AnyIllegalControl::ConnectParse),
            Control::new(ActionKind::Block, Scope::All)
        );
        assert_eq!(
            t.any_illegal(AnyIllegalControl::Ech),
            Control::new(ActionKind::Block, Scope::All)
        );
    }

    #[test]
    fn unconfigured_ordinal_reads_no_configured_control() {
        let t = table(1);
        let unbound = DomainOrdinal::from_index(ALLOWLIST_MAX - 1).expect("bound-level ordinal");
        assert_eq!(
            t.early_data(unbound),
            None,
            "an unconfigured position exposes no control, never a fabricated action"
        );
        assert_eq!(t.ja4(unbound), None);
    }

    #[test]
    fn control_table_storage_fits_planned_bound() {
        let t = table(1);
        assert!(
            core::mem::size_of_val(&t) <= 256,
            "data table at {} bytes",
            core::mem::size_of_val(&t)
        );
        assert_eq!(core::mem::size_of::<Control>(), 2);
        assert_eq!(t.len(), 1);
    }
}

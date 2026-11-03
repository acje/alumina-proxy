use super::action::{
    ActionKind, AnyIllegalControl, Control, ControlTable, DomainOrdinal, FirstSlot, PerFqdnControl,
    Scope,
};
use crate::inspection::client_hello::HelloRejectReason;
use crate::inspection::connect::ConnectHeadReason;

/// The finite, unattributable illegal-class discriminants. Each maps to
/// exactly one [`AnyIllegalControl`] key; `Ech` is a separate control from
/// `TlsProfile` (the ECH-presence rejection routes to the `ech` control, the
/// other hello-reject reasons to `tls_profile`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnyIllegalCause {
    ConnectParse(ConnectHeadReason),
    HostNotAllowlisted,
    TlsProfile(HelloRejectReason),
    Ech,
}

impl AnyIllegalCause {
    /// Routes a hello-reject reason onto its control: ECH presence is its own
    /// `ech` control, every other reason the `tls_profile` control. This is
    /// the sole production constructor for the hello-reject causes, so
    /// `TlsProfile` never carries `EchPresent`.
    pub const fn from_hello_reject(reason: HelloRejectReason) -> AnyIllegalCause {
        match reason {
            HelloRejectReason::EchPresent => AnyIllegalCause::Ech,
            other => AnyIllegalCause::TlsProfile(other),
        }
    }

    pub const fn kind_index(self) -> usize {
        match self {
            AnyIllegalCause::ConnectParse(reason) => reason.index(),
            AnyIllegalCause::HostNotAllowlisted => ConnectHeadReason::COUNT,
            AnyIllegalCause::TlsProfile(reason) => {
                ConnectHeadReason::COUNT + 1 + tls_profile_index(reason)
            }
            AnyIllegalCause::Ech => ConnectHeadReason::COUNT + 1 + 3,
        }
    }

    pub const KIND_COUNT: usize = ConnectHeadReason::COUNT + 1 + 3 + 1;
}

/// The 0-based offset of a hello-reject reason within the `tls_profile`
/// control's three discriminants. `EchPresent` is excluded by construction
/// (`from_hello_reject` routes it to the `ech` control); the mapping is total,
/// so a stray direct `TlsProfile(EchPresent)` would collide with the `ech`
/// control's slot — unreachable, since `from_hello_reject` is the sole
/// production constructor.
const fn tls_profile_index(reason: HelloRejectReason) -> usize {
    match reason {
        HelloRejectReason::ServerNameMismatch => 0,
        HelloRejectReason::InvalidServerName => 1,
        HelloRejectReason::Profile => 2,
        HelloRejectReason::EchPresent => 3,
    }
}

/// The `any_illegal` control key attributed to a cause: the surface on which
/// the violation fired, selecting that control's configured action.
const fn any_illegal_control(cause: AnyIllegalCause) -> AnyIllegalControl {
    match cause {
        AnyIllegalCause::ConnectParse(_) => AnyIllegalControl::ConnectParse,
        AnyIllegalCause::HostNotAllowlisted => AnyIllegalControl::HostNotAllowlisted,
        AnyIllegalCause::TlsProfile(_) => AnyIllegalControl::TlsProfile,
        AnyIllegalCause::Ech => AnyIllegalControl::Ech,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum UnknownReason {
    UnboundOrdinal,
    NotYetValidated,
    MissingParseResult,
    Unattributed,
}

impl UnknownReason {
    pub const fn index(self) -> usize {
        self as usize
    }

    pub const COUNT: usize = 4;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    AnyIllegal { cause: AnyIllegalCause },
    EarlyUpstreamData { ordinal: DomainOrdinal },
    Ja4Change { ordinal: DomainOrdinal },
    EvidenceInsufficient,
    Unattributed,
    MissingParseResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    BaselineOnly,
    Notify { scope: Scope },
    Block { scope: Scope },
    Unknown { reason: UnknownReason },
}

/// The uniform violation-to-effect projection for both surfaces: an
/// `AnyIllegal` fires its own control's action on the first occurrence (the
/// connection-level latch), per-FQDN violations select their per-FQDN
/// `early_data`/`ja4` control, and `ignore` is the per-FQDN opt-out that
/// yields `BaselineOnly`. The `AnyIllegal` latch is consumed by the first
/// `AnyIllegal` only; per-FQDN violations never consume it.
pub fn decide(table: &ControlTable, latch: &mut FirstSlot, violation: Violation) -> Effect {
    match violation {
        Violation::AnyIllegal { cause } => {
            if latch.take_if_armed() {
                control_effect(table.any_illegal(any_illegal_control(cause)))
            } else {
                Effect::BaselineOnly
            }
        }
        Violation::EarlyUpstreamData { ordinal } => match table.early_data(ordinal) {
            None => Effect::Unknown {
                reason: UnknownReason::UnboundOrdinal,
            },
            Some(PerFqdnControl::Ignore) => Effect::BaselineOnly,
            Some(PerFqdnControl::Control(control)) => control_effect(control),
        },
        Violation::Ja4Change { ordinal } => match table.ja4(ordinal) {
            None => Effect::Unknown {
                reason: UnknownReason::UnboundOrdinal,
            },
            Some(PerFqdnControl::Ignore) => Effect::BaselineOnly,
            Some(PerFqdnControl::Control(control)) => control_effect(control),
        },
        Violation::EvidenceInsufficient => Effect::Unknown {
            reason: UnknownReason::NotYetValidated,
        },
        Violation::Unattributed => Effect::Unknown {
            reason: UnknownReason::Unattributed,
        },
        Violation::MissingParseResult => Effect::Unknown {
            reason: UnknownReason::MissingParseResult,
        },
    }
}

const fn control_effect(control: Control) -> Effect {
    match control.kind() {
        ActionKind::Notify => Effect::Notify {
            scope: control.scope(),
        },
        ActionKind::Block => Effect::Block {
            scope: control.scope(),
        },
    }
}

#[cfg(test)]
mod tests;

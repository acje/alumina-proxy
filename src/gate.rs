//! Legacy public facade: the connect gate lives canonically in
//! [`crate::runtime::gate`].

pub use crate::runtime::gate::{
    Activity, GatePhase, TerminateReason, TunnelGate, UpstreamWrite, ValidatedHello,
};

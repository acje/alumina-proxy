//! Legacy public facade: the tunnel decision substrate lives canonically in
//! [`crate::runtime::tunnel`].

pub use crate::runtime::tunnel::{
    AdmissionError, AttemptCounts, AttemptLedger, CONNECT_DEADLINE_SECS, CONNECT_HEAD_LIMIT,
    ConnectPhase, Deadline, DecideError, MAX_PENDING_SETUPS, MAX_TUNNELS, MAX_UPSTREAM_ATTEMPTS,
    PeerDecision, SETUP_DEADLINE_SECS, SlotIndex, SlotState, TrafficBuffer, TunnelIndex, Worker,
    WorkerClock, WorkerView,
};

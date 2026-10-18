//! The pure two-barrier forwarding gate for one tunnel (architecture D1-D5b;
//! docs/alumina-proxy.md:32,201). This is the *authority* over byte flow across the two
//! forwarding barriers; the byte buffers themselves live in the boot-owned
//! per-slot workspace, so the gate is a small fixed-offset state machine with
//! no sockets and no I/O, deterministic and unit-testable.
//!
//! Barrier A (client->upstream): no client bytes, including ClientHello, are
//! forwarded before complete validation with exactly-one SNI normalized-equal
//! to the approved CONNECT hostname, no ECH, TLS1.3 profile ([`crate::client_hello::validate`]
//! supplies the verdict; the gate tracks the hello boundary in the stream).
//! Barrier B (upstream->client): no upstream bytes are forwarded before the
//! gate opens. A successful CONNECT response alone authorizes neither
//! direction (D2).
//!
//! The gate opens atomically in the same transition whose successful
//! client->upstream write accounting reaches the end of the validated
//! ClientHello (H), before any subsequent upstream read (D3). A single
//! successful write may cross H and include coalesced trailing bytes (X);
//! those X bytes are relay-from-open and already forwarded by that write.
//! Ordered progress is kept by monotonic committed offsets (D5): a partial
//! successful write advances its own bytes, WouldBlock/readiness is not
//! activity (D4), and actual upstream data/EOF/reset observed while barrier B
//! is closed terminates setup with no forwarding.

use std::fmt;

use crate::client_hello::HelloAccepted;

/// How far a client->upstream write may currently go (barrier A), and what
/// happened to the gate as a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamWrite {
    /// Barrier A closed: the ClientHello is not yet fully validated, so no
    /// tunnel bytes may be written upstream.
    BlockedByBarrierA,
    /// Validated but barrier A/B transition pending: exactly the validated
    /// hello prefix may be written; the write is not yet at H.
    WritingHello { total: usize },
    /// The gate opened in this transition: `crossing` cumulative upstream
    /// bytes committed, of which `relay_from_open` were coalesced trailing
    /// bytes (X) beyond H forwarded by the same write (D3).
    GateOpened {
        crossing: usize,
        relay_from_open: usize,
    },
    /// The gate is open: the full relay buffer may flow upstream.
    Open,
}

/// Actual upstream activity observed while barrier B is closed (D4): only
/// observation terminates setup; WouldBlock or readiness alone is not
/// activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    Data,
    Eof,
    Reset,
}

/// Why a setup terminated before the gate opened. All terminators forbid
/// forwarding in both directions from the moment they fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminateReason {
    /// ClientHello validation failed barrier A (profile, ECH, SNI mismatch,
    /// or framing error).
    ClientHelloRejected,
    /// Actual upstream data/EOF/reset observed while barrier B was closed.
    EarlyUpstream(Activity),
}

/// The setup lifecycle of one tunnel with respect to the two barriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatePhase {
    /// Reading the CONNECT head (barrier A closed).
    AwaitConnect,
    /// CONNECT authorized; upstream connect in progress (barrier A closed).
    Connecting,
    /// Connected; the upstream CONNECT response is being parsed (barrier B
    /// closed).
    AwaitResponse,
    /// The successful CONNECT response completed (SENT_200); the client
    /// ClientHello is being validated (barrier A closed, barrier B closed).
    Validating,
    /// Both barriers open; ordered relay.
    RelayActive,
    /// Setup terminated before the gate opened; no forwarding.
    Terminated(TerminateReason),
}

/// The pure per-tunnel gate: phase plus the byte-offset accounting for the two
/// barriers. Holds only the tunnel's own domain state (nothing detachable, no
/// freestanding provenance).
pub struct TunnelGate {
    phase: GatePhase,
    /// Number of client-stream bytes consumed by the CONNECT head (never
    /// forwarded; the proxy handshake). Tunnel bytes start here.
    head_len: usize,
    /// Hello start in the client stream (== head_len when the hello is
    /// contiguous after the head).
    hello_start: usize,
    /// H: exclusive end of the fully validated ClientHello in the client
    /// stream, present once validation passes.
    hello_end: Option<usize>,
    /// Cumulative tunnel bytes successfully written upstream (barrier A
    /// progress; monotonic). Only a permitted write can advance it: blocked
    /// or terminated reports never record bytes, and with the delta-based
    /// reporter a backwards movement is structurally unrepresentable.
    upstream_committed: usize,
    /// Cumulative bytes successfully written downstream (barrier B progress;
    /// monotonic).
    downstream_committed: usize,
}

/// A capability record that the complete ClientHello validated against the
/// approved hostname: the exclusive end offset H of the validated hello in the
/// client stream. Mintable only with a [`HelloAccepted`] witness, which only
/// [`crate::client_hello::validate`] can produce, so a gate can never be told
/// a caller-invented hello boundary (xz3f N7). Test code uses the
/// non-production [`ValidatedHello::test_new`] constructor.
pub struct ValidatedHello {
    end: usize,
}

impl ValidatedHello {
    /// Records the validated hello end bound to a real validator witness.
    pub(crate) const fn new(_accepted: HelloAccepted, end: usize) -> ValidatedHello {
        ValidatedHello { end }
    }

    /// Test-only constructor carrying no validator witness, so it can never be
    /// reached outside the test build.
    #[cfg(test)]
    pub(crate) const fn test_new(end: usize) -> ValidatedHello {
        ValidatedHello { end }
    }

    /// The exclusive end offset of the validated hello in the client stream.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }
}

impl TunnelGate {
    /// A closed gate at the start of CONNECT setup.
    #[must_use]
    pub const fn new() -> TunnelGate {
        TunnelGate {
            phase: GatePhase::AwaitConnect,
            head_len: 0,
            hello_start: 0,
            hello_end: None,
            upstream_committed: 0,
            downstream_committed: 0,
        }
    }

    /// The CONNECT head completed, consuming `head_len` client-stream bytes.
    /// Those bytes are never forwarded; tunnel bytes begin after them. Only
    /// the initial `AwaitConnect` head is recorded, so a late re-application
    /// cannot corrupt the hello window (I9).
    pub fn on_connect_head(&mut self, head_len: usize) {
        if self.phase == GatePhase::AwaitConnect {
            self.head_len = head_len;
            self.hello_start = head_len;
        }
    }

    /// CONNECT authorized and peer selected; the upstream connect begins.
    /// Barrier A stays closed.
    pub fn on_authorized(&mut self) {
        if self.phase == GatePhase::AwaitConnect {
            self.phase = GatePhase::Connecting;
        }
    }

    /// The upstream connect completed; the CONNECT response starts arriving.
    /// Barrier B stays closed.
    pub fn on_upstream_connected(&mut self) {
        if self.phase == GatePhase::Connecting {
            self.phase = GatePhase::AwaitResponse;
        }
    }

    /// The successful CONNECT response completed (SENT_200). ClientHello
    /// inspection may begin; both barriers stay closed.
    pub fn on_response_ok(&mut self) {
        if self.phase == GatePhase::AwaitResponse {
            self.phase = GatePhase::Validating;
        }
    }

    /// The client ClientHello was fully validated (a [`ValidatedHello`]
    /// capability from the serving validation path). Barrier A now releases
    /// exactly the validated hello; the gate is still closed.
    pub fn on_hello_validated(&mut self, hello: ValidatedHello) {
        if self.phase != GatePhase::Validating {
            return;
        }
        self.hello_end = Some(hello.end());
    }

    /// ClientHello validation failed barrier A: setup terminates, no
    /// forwarding in either direction.
    pub fn on_hello_rejected(&mut self) {
        self.terminate(TerminateReason::ClientHelloRejected);
    }

    /// A successful upstream write of `advance` client->upstream tunnel bytes
    /// since the last report (barrier A progress). The gate accumulates the
    /// delta reports into a monotonic committed offset, so a backwards
    /// movement is structurally unrepresentable while partial successful
    /// writes keep ordered progress (D5). Only a *permitted* write advances
    /// the ledger: a terminated or barrier-A-closed gate reports
    /// [`UpstreamWrite::BlockedByBarrierA`] and records nothing (I10). This
    /// is the only transition that can open the gate (D3).
    pub const fn upstream_write(&mut self, advance: usize) -> UpstreamWrite {
        match self.phase {
            GatePhase::Terminated(_) => UpstreamWrite::BlockedByBarrierA,
            GatePhase::AwaitConnect
            | GatePhase::Connecting
            | GatePhase::AwaitResponse
            | GatePhase::Validating => match self.hello_end {
                None => UpstreamWrite::BlockedByBarrierA,
                Some(h_end) => {
                    self.upstream_committed = self.upstream_committed.saturating_add(advance);
                    let total = self.upstream_committed;
                    let hello_len = h_end - self.hello_start;
                    if total < hello_len {
                        UpstreamWrite::WritingHello { total: hello_len }
                    } else {
                        let crossing = total;
                        let relay_from_open = total - hello_len;
                        self.phase = GatePhase::RelayActive;
                        UpstreamWrite::GateOpened {
                            crossing,
                            relay_from_open,
                        }
                    }
                }
            },
            GatePhase::RelayActive => UpstreamWrite::Open,
        }
    }

    /// Actual upstream activity observed while barrier B is closed (D4):
    /// terminates setup with no forwarding. WouldBlock/readiness is not
    /// activity and must not be reported here.
    pub fn observe_upstream_activity(&mut self, activity: Activity) {
        match self.phase {
            GatePhase::Connecting | GatePhase::AwaitResponse | GatePhase::Validating => {
                self.terminate(TerminateReason::EarlyUpstream(activity));
            }
            _ => {}
        }
    }

    /// Whether the gate is open (both barriers) or the phase otherwise permits
    /// downstream forwarding.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.phase == GatePhase::RelayActive
    }

    /// The validated hello end in the client stream, if any.
    #[must_use]
    pub const fn hello_end(&self) -> Option<usize> {
        self.hello_end
    }

    /// Cumulative client->upstream bytes successfully written.
    #[must_use]
    pub const fn upstream_committed(&self) -> usize {
        self.upstream_committed
    }

    /// Phase of the gate.
    #[must_use]
    pub const fn phase(&self) -> GatePhase {
        self.phase
    }

    fn terminate(&mut self, reason: TerminateReason) {
        if self.phase != GatePhase::RelayActive {
            self.phase = GatePhase::Terminated(reason);
        }
    }
}

impl Default for TunnelGate {
    fn default() -> Self {
        TunnelGate::new()
    }
}

impl fmt::Debug for TunnelGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelGate")
            .field("phase", &self.phase)
            .field("head_len", &self.head_len)
            .field("hello_start", &self.hello_start)
            .field("hello_end", &self.hello_end)
            .field("upstream_committed", &self.upstream_committed)
            .field("downstream_committed", &self.downstream_committed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorized_gate() -> TunnelGate {
        let mut gate = TunnelGate::new();
        gate.on_connect_head(120);
        gate.on_authorized();
        gate.on_upstream_connected();
        gate.on_response_ok();
        gate
    }

    #[test]
    fn barrier_a_blocks_tunnel_bytes_until_the_hello_is_validated() {
        let mut gate = authorized_gate();
        let hello_end = 120 + 200;
        assert!(matches!(
            gate.upstream_write(0),
            UpstreamWrite::BlockedByBarrierA
        ));
        assert_eq!(gate.upstream_write(200), UpstreamWrite::BlockedByBarrierA);
        gate.on_hello_validated(ValidatedHello::test_new(hello_end));
        assert_eq!(
            gate.upstream_write(200),
            UpstreamWrite::GateOpened {
                crossing: 200,
                relay_from_open: 0
            },
            "a successful write reaching H exactly opens the gate in that transition"
        );
        assert!(gate.is_open());
    }

    #[test]
    fn gate_opens_in_the_same_write_that_crosses_h() {
        let mut gate = authorized_gate();
        let hello_end = 120 + 200;
        gate.on_hello_validated(ValidatedHello::test_new(hello_end));
        assert_eq!(
            gate.upstream_write(150),
            UpstreamWrite::WritingHello { total: 200 }
        );
        assert!(!gate.is_open());
        assert_eq!(
            gate.upstream_write(90),
            UpstreamWrite::GateOpened {
                crossing: 240,
                relay_from_open: 40
            }
        );
        assert!(gate.is_open());
        assert_eq!(gate.phase(), GatePhase::RelayActive);
    }

    #[test]
    fn relay_and_coalesced_bytes_are_ordered_and_never_duplicated() {
        let mut gate = authorized_gate();
        let hello_end = 120 + 200;
        gate.on_hello_validated(ValidatedHello::test_new(hello_end));
        let advances = [0, 150, 90, 60, 0, 212];
        let mut last_open_at = None;
        for &step in &advances {
            let w = gate.upstream_write(step);
            if let UpstreamWrite::GateOpened {
                crossing,
                relay_from_open,
            } = w
            {
                last_open_at = Some((crossing, relay_from_open));
            }
        }
        let (crossing, relay) = last_open_at.expect("crossing transition observed");
        assert_eq!(crossing, 240);
        assert_eq!(relay, 40);
        assert_eq!(
            gate.upstream_committed(),
            240,
            "delta reports accumulate to the opening crossing; relay reports acknowledge without recording"
        );
        assert!(gate.is_open());
        assert_eq!(
            gate.upstream_write(0),
            UpstreamWrite::Open,
            "relay reports are acknowledged without recording further bytes"
        );
    }

    #[test]
    fn hello_rejected_closes_without_forwarding_any_direction() {
        let mut gate = authorized_gate();
        gate.on_hello_rejected();
        assert_eq!(
            gate.phase(),
            GatePhase::Terminated(TerminateReason::ClientHelloRejected)
        );
        assert_eq!(gate.upstream_write(50), UpstreamWrite::BlockedByBarrierA);
    }

    #[test]
    fn pre_open_upstream_activity_terminates_without_forwarding() {
        let mut gate = authorized_gate();
        gate.observe_upstream_activity(Activity::Data);
        assert_eq!(
            gate.phase(),
            GatePhase::Terminated(TerminateReason::EarlyUpstream(Activity::Data))
        );
        let mut gate2 = authorized_gate();
        gate2.observe_upstream_activity(Activity::Eof);
        assert_eq!(
            gate2.phase(),
            GatePhase::Terminated(TerminateReason::EarlyUpstream(Activity::Eof))
        );
        let mut gate3 = authorized_gate();
        gate3.observe_upstream_activity(Activity::Reset);
        assert_eq!(
            gate3.phase(),
            GatePhase::Terminated(TerminateReason::EarlyUpstream(Activity::Reset))
        );
    }

    #[test]
    fn connecting_phase_rejects_actual_upstream_activity() {
        let mut data = TunnelGate::new();
        data.on_connect_head(120);
        data.on_authorized();
        data.observe_upstream_activity(Activity::Data);
        assert_eq!(
            data.phase(),
            GatePhase::Terminated(TerminateReason::EarlyUpstream(Activity::Data))
        );

        let mut eof = TunnelGate::new();
        eof.on_connect_head(120);
        eof.on_authorized();
        eof.observe_upstream_activity(Activity::Eof);
        assert_eq!(
            eof.phase(),
            GatePhase::Terminated(TerminateReason::EarlyUpstream(Activity::Eof))
        );

        let mut reset = TunnelGate::new();
        reset.on_connect_head(120);
        reset.on_authorized();
        reset.observe_upstream_activity(Activity::Reset);
        assert_eq!(
            reset.phase(),
            GatePhase::Terminated(TerminateReason::EarlyUpstream(Activity::Reset))
        );

        let mut early = TunnelGate::new();
        early.observe_upstream_activity(Activity::Data);
        assert_eq!(
            early.phase(),
            GatePhase::AwaitConnect,
            "no upstream exists before the CONNECT head; activity must not advance AwaitConnect"
        );
    }

    #[test]
    fn gate_starts_closed_and_authorization_advances_phase() {
        let mut gate = TunnelGate::new();
        assert_eq!(gate.phase(), GatePhase::AwaitConnect);
        assert!(!gate.is_open());
        gate.on_connect_head(80);
        gate.on_authorized();
        assert_eq!(gate.phase(), GatePhase::Connecting);
        gate.on_upstream_connected();
        assert_eq!(gate.phase(), GatePhase::AwaitResponse);
        gate.on_response_ok();
        assert_eq!(gate.phase(), GatePhase::Validating);
        assert!(!gate.is_open());
    }

    #[test]
    fn re_applying_the_connect_head_after_it_completed_is_ignored() {
        let mut gate = authorized_gate();
        let hello_end = 120 + 200;
        gate.on_hello_validated(ValidatedHello::test_new(hello_end));
        gate.on_connect_head(180);
        assert_eq!(
            gate.upstream_write(240),
            UpstreamWrite::GateOpened {
                crossing: 240,
                relay_from_open: 40,
            },
            "a late head re-application must not shift the hello window"
        );
    }

    #[test]
    fn terminated_and_blocked_writes_never_record_committed_bytes() {
        let mut terminated = authorized_gate();
        terminated.on_hello_rejected();
        assert_eq!(
            terminated.upstream_write(50),
            UpstreamWrite::BlockedByBarrierA
        );
        assert_eq!(
            terminated.upstream_committed(),
            0,
            "a terminated gate must not record committed bytes"
        );

        let mut unvalidated = authorized_gate();
        assert_eq!(
            unvalidated.upstream_write(50),
            UpstreamWrite::BlockedByBarrierA
        );
        assert_eq!(
            unvalidated.upstream_committed(),
            0,
            "a barrier-A-closed gate must not record committed bytes"
        );
    }
}

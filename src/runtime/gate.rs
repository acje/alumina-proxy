//! The pure two-barrier forwarding gate for one tunnel (docs/alumina-proxy.md
//! §Protocol contract and §Architecture). This is the *authority* over byte
//! flow across the two forwarding barriers; the byte buffers live in the
//! boot-owned per-slot workspace, so the gate is a small fixed-offset state machine with
//! no sockets and no I/O, deterministic and unit-testable.
//!
//! Barrier A (client->upstream): no client bytes, including `ClientHello`, are
//! forwarded before complete validation with exactly-one SNI normalized-equal
//! to the approved CONNECT hostname, no ECH, TLS1.3 profile ([`crate::inspection::client_hello::validate`]
//! supplies the verdict; the gate tracks the hello boundary in the stream).
//! Barrier B (upstream->client): no upstream bytes are forwarded before the
//! gate opens. A successful CONNECT response alone authorizes neither
//! direction.
//!
//! The gate opens atomically in the same transition whose successful
//! client->upstream write accounting reaches the end of the validated
//! `ClientHello` (H), before any subsequent upstream read. A single
//! successful write may cross H and include coalesced trailing bytes (X);
//! those X bytes are relay-from-open and already forwarded by that write.
//! Ordered progress is kept by monotonic committed offsets: a partial
//! successful write advances its own bytes, WouldBlock/readiness is not
//! activity, and actual upstream data/EOF/reset observed while barrier B
//! is closed terminates setup with no forwarding.

use std::fmt;

use crate::inspection::client_hello::HelloAccepted;

/// How far a client->upstream write may currently go (barrier A), and what
/// happened to the gate as a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamWrite {
    /// Barrier A closed: the `ClientHello` is not yet fully validated, so no
    /// tunnel bytes may be written upstream.
    BlockedByBarrierA,
    /// Validated but barrier A/B transition pending: exactly the validated
    /// hello prefix may be written; the write is not yet at H.
    WritingHello { total: usize },
    /// The gate opened in this transition: `crossing` cumulative upstream
    /// bytes committed, of which `relay_from_open` were coalesced trailing
    /// bytes (X) beyond H forwarded by the same write.
    GateOpened {
        crossing: usize,
        relay_from_open: usize,
    },
    /// The gate is open: the full relay buffer may flow upstream.
    Open,
}

/// Actual upstream activity observed while barrier B is closed: only
/// observation terminates setup; `WouldBlock` or readiness alone is not
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
    /// `ClientHello` validation failed barrier A (profile, ECH, SNI mismatch,
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
    /// The successful CONNECT response completed (`SENT_200`); the client
    /// `ClientHello` is being validated (barrier A closed, barrier B closed).
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
    /// Hello start in the client stream (== `head_len` when the hello is
    /// contiguous after the head).
    hello_start: usize,
    /// H: exclusive end of the fully validated `ClientHello` in the client
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

/// A capability record that the complete `ClientHello` validated against the
/// approved hostname: the exclusive end offset H of the validated hello in the
/// client stream. Mintable only with a [`HelloAccepted`] witness, which only
/// [`crate::inspection::client_hello::validate`] can produce, so a gate can never be told
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

    /// The successful CONNECT response completed (`SENT_200`). `ClientHello`
    /// inspection may begin; both barriers stay closed.
    pub fn on_response_ok(&mut self) {
        if self.phase == GatePhase::AwaitResponse {
            self.phase = GatePhase::Validating;
        }
    }

    /// The client `ClientHello` was fully validated (a [`ValidatedHello`]
    /// capability from the serving validation path). Barrier A now releases
    /// exactly the validated hello; the gate is still closed.
    pub fn on_hello_validated(&mut self, hello: ValidatedHello) {
        if self.phase != GatePhase::Validating {
            return;
        }
        self.hello_end = Some(hello.end());
    }

    /// `ClientHello` validation failed barrier A: setup terminates, no
    /// forwarding in either direction.
    pub fn on_hello_rejected(&mut self) {
        self.terminate(TerminateReason::ClientHelloRejected);
    }

    /// A successful upstream write of `advance` client->upstream tunnel bytes
    /// since the last report (barrier A progress). The gate accumulates the
    /// delta reports into a monotonic committed offset, so a backwards
    /// movement is structurally unrepresentable while partial successful
    /// writes keep ordered progress. Only a *permitted* write advances
    /// the ledger: a terminated or barrier-A-closed gate reports
    /// [`UpstreamWrite::BlockedByBarrierA`] and records nothing (I10). This
    /// is the only transition that can open the gate.
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

    /// Actual upstream activity observed while barrier B is closed:
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
    #[cfg(test)]
    pub const fn upstream_committed(&self) -> usize {
        self.upstream_committed
    }

    /// Phase of the gate.
    #[must_use]
    #[cfg(test)]
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

    /// Characterises the behaviour alumina-14l0s records as a finding: the
    /// `Terminated` *variant* is absorbing but the settled *cause* is not,
    /// because `terminate` guards on `phase != RelayActive` and `Terminated(_)`
    /// satisfies that guard. This pins what the gate does *today*, not what it
    /// should do; making `terminate` total (alumina-14l0s option 1) is meant to
    /// trip this test.
    ///
    /// The ordering is reachable on the public surface but unreachable in the
    /// reactor, where caller teardown discards the gate before a second
    /// terminator can arrive: `observe_upstream_activity` at
    /// `src/runtime/reactor.rs:3337` is followed by `close_slot` ->
    /// `ws.reset()` -> `TunnelGate::new()` (`src/runtime/reactor.rs:854-857`),
    /// and `on_hello_rejected`'s only production caller is `reject_hello`
    /// (`src/runtime/reactor/reject.rs:69`), reached solely from the
    /// hello-validation path (`src/runtime/reactor.rs:1293`/`:3405`/`:3428`),
    /// which also closes the slot.
    #[test]
    fn re_termination_overwrites_the_settled_cause_on_the_public_surface() {
        let mut gate = TunnelGate::new();
        assert_eq!(gate.phase(), GatePhase::AwaitConnect);
        gate.on_authorized();
        assert_eq!(gate.phase(), GatePhase::Connecting);
        gate.observe_upstream_activity(Activity::Data);
        assert_eq!(
            gate.phase(),
            GatePhase::Terminated(TerminateReason::EarlyUpstream(Activity::Data))
        );
        gate.on_hello_rejected();
        assert_eq!(
            gate.phase(),
            GatePhase::Terminated(TerminateReason::ClientHelloRejected),
            "alumina-14l0s: the second terminator overwrites the settled cause"
        );
    }

    /// A model-based machine over [`TunnelGate`]'s two-barrier lifecycle. The
    /// example tests above pin the orderings somebody wrote down; this machine
    /// explores the interleavings nobody did — a late head re-application, a
    /// rejection after the gate opened, a validation in every phase, upstream
    /// activity observed at every point, writes before and after the hello
    /// boundary — and checks the barrier invariants after every rule.
    ///
    /// Invariants (all `always_run`, so each sees every intermediate state):
    /// G1 `is_open()` implies `hello_end()` is `Some`: the gate never opens
    ///    without a validated hello.
    /// G2 `Terminated` is absorbing as a *variant*, and a terminated setup is
    ///    never open.
    /// G2b the settled *cause* is absorbing too: from `Terminated(r)`, every
    ///    rule the runtime can deliver leaves exactly `Terminated(r)`. The
    ///    runtime delivers none, because both production terminator sites tear
    ///    the slot down synchronously (`src/runtime/reactor.rs:3337` ->
    ///    `close_slot` -> `ws.reset()` -> `TunnelGate::new()`, reset at
    ///    `src/runtime/reactor.rs:854-857`; `reject_hello` at
    ///    `src/runtime/reactor/reject.rs:69`, reachable only from the
    ///    hello-validation path). `(phase, reason)` absorption is therefore a
    ///    caller-teardown guarantee, not a pub-API property; the one pub-API
    ///    exception, `on_hello_rejected` after an early-upstream termination,
    ///    is asserted in `g2b_termination_settles_the_cause` and
    ///    characterised in
    ///    `re_termination_overwrites_the_settled_cause_on_the_public_surface`
    ///    (alumina-14l0s). Each rule tags itself in `begin`.
    /// G3 `upstream_committed()` is monotone non-decreasing across every rule.
    /// G4 a write reports `BlockedByBarrierA` exactly when the pre-write state
    ///    had no hello end or was terminated, and `GateOpened`/`Open` only with
    ///    a hello end.
    /// G5 the observed phase edges are exactly `AwaitConnect` → `Connecting` →
    ///    `AwaitResponse` → `Validating` → `RelayActive`, plus termination out
    ///    of every pre-relay phase; every other observed move is a no-op.
    ///
    /// Independence: none of these re-runs the gate's own branch table. G1, G2,
    /// G2b and G4 relate the public surface (`is_open`, `hello_end`, the returned
    /// [`UpstreamWrite`]) to the state observed *before* a transition, so a
    /// missing or misplaced guard cannot satisfy its own check; G3 compares
    /// successive observations across the whole walk instead of trusting the
    /// accumulator; G5 is an edge table the gate never materialises, checked
    /// against the model's own previous observation.
    ///
    /// The rule weights keep both branches reachable in one walk: the progress
    /// rules outrank the terminators so the relay-open path is entered (24 of
    /// the 64 `development`-profile cases reach `RelayActive`), while the
    /// remaining cases terminate before opening and then exercise the absorbing
    /// phase.
    mod lifecycle_machine {
        use super::*;
        use hegel::TestCase;
        use hegel::generators as gs;

        const MAX_HEAD_LEN: usize = 4096;
        const MAX_HELLO_LEN: usize = 8192;
        const MAX_WRITE_ADVANCE: usize = 4096;
        const ACTIVITIES: [Activity; 3] = [Activity::Data, Activity::Eof, Activity::Reset];

        pub(super) struct GateLifecycle {
            gate: TunnelGate,
            /// The CONNECT head length the model applied, which anchors the
            /// drawn validated-hello boundary.
            head_len: usize,
            /// The drawn validated-hello end, when the model applied one.
            hello_end: Option<usize>,
            phase_before: GatePhase,
            committed_before: usize,
            /// The rule that produced the transition under inspection.
            last_rule: Option<Rule>,
            write: Option<WriteObservation>,
        }

        /// Rule identity, tagged by each rule body through `begin`, so an
        /// invariant can condition on the rule that produced a transition.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Rule {
            ConnectHead,
            Authorized,
            UpstreamConnected,
            ResponseOk,
            HelloValidated,
            HelloRejected,
            ObserveUpstreamActivity,
            UpstreamWrite,
        }

        struct WriteObservation {
            result: UpstreamWrite,
            hello_end_before: Option<usize>,
            terminated_before: bool,
        }

        impl GateLifecycle {
            pub(super) fn start() -> GateLifecycle {
                let gate = TunnelGate::new();
                GateLifecycle {
                    phase_before: gate.phase(),
                    committed_before: gate.upstream_committed(),
                    gate,
                    head_len: 0,
                    hello_end: None,
                    last_rule: None,
                    write: None,
                }
            }

            /// Snapshots the pre-transition state and tags the rule about to
            /// run, so invariants compare the state and the rule together.
            fn begin(&mut self, rule: Rule) {
                self.phase_before = self.gate.phase();
                self.committed_before = self.gate.upstream_committed();
                self.last_rule = Some(rule);
            }
        }

        fn is_written_down_edge(from: GatePhase, to: GatePhase) -> bool {
            matches!(
                (from, to),
                (GatePhase::AwaitConnect, GatePhase::Connecting)
                    | (GatePhase::Connecting, GatePhase::AwaitResponse)
                    | (GatePhase::AwaitResponse, GatePhase::Validating)
                    | (GatePhase::Validating, GatePhase::RelayActive)
                    | (
                        GatePhase::AwaitConnect
                            | GatePhase::Connecting
                            | GatePhase::AwaitResponse
                            | GatePhase::Validating,
                        GatePhase::Terminated(_)
                    )
            )
        }

        #[expect(
            clippy::needless_pass_by_value,
            reason = "the hegel state-machine macro hands each rule its own TestCase by value"
        )]
        #[hegel::state_machine]
        impl GateLifecycle {
            #[rule(weight = 3.0)]
            fn on_connect_head(&mut self, tc: TestCase) {
                self.begin(Rule::ConnectHead);
                let head_len =
                    tc.draw(gs::integers::<usize>().min_value(0).max_value(MAX_HEAD_LEN));
                if self.phase_before == GatePhase::AwaitConnect {
                    self.head_len = head_len;
                }
                self.gate.on_connect_head(head_len);
            }

            #[rule(weight = 20.0)]
            fn on_authorized(&mut self, _: TestCase) {
                self.begin(Rule::Authorized);
                self.gate.on_authorized();
            }

            #[rule(weight = 20.0)]
            fn on_upstream_connected(&mut self, _: TestCase) {
                self.begin(Rule::UpstreamConnected);
                self.gate.on_upstream_connected();
            }

            #[rule(weight = 20.0)]
            fn on_response_ok(&mut self, _: TestCase) {
                self.begin(Rule::ResponseOk);
                self.gate.on_response_ok();
            }

            #[rule(weight = 20.0)]
            fn on_hello_validated(&mut self, tc: TestCase) {
                self.begin(Rule::HelloValidated);
                let offset = tc.draw(
                    gs::integers::<usize>()
                        .min_value(0)
                        .max_value(MAX_HELLO_LEN),
                );
                let end = self.head_len + offset;
                let before = self.gate.hello_end();
                self.gate.on_hello_validated(ValidatedHello::test_new(end));
                if self.phase_before == GatePhase::Validating {
                    self.hello_end = Some(end);
                    assert_eq!(
                        self.gate.hello_end(),
                        self.hello_end,
                        "a hello validated in Validating is recorded at the drawn end"
                    );
                } else {
                    assert_eq!(
                        self.gate.hello_end(),
                        before,
                        "a hello validation outside Validating must not move the boundary"
                    );
                }
            }

            #[rule(weight = 1.0)]
            fn on_hello_rejected(&mut self, _: TestCase) {
                self.begin(Rule::HelloRejected);
                self.gate.on_hello_rejected();
            }

            #[rule(weight = 1.0)]
            fn observe_upstream_activity(&mut self, tc: TestCase) {
                self.begin(Rule::ObserveUpstreamActivity);
                let activity = tc.draw(gs::sampled_from(&ACTIVITIES[..]));
                self.gate.observe_upstream_activity(activity);
            }

            #[rule(weight = 20.0)]
            fn upstream_write(&mut self, tc: TestCase) {
                self.begin(Rule::UpstreamWrite);
                let advance = tc.draw(
                    gs::integers::<usize>()
                        .min_value(0)
                        .max_value(MAX_WRITE_ADVANCE),
                );
                let hello_end_before = self.gate.hello_end();
                let terminated_before = matches!(self.phase_before, GatePhase::Terminated(_));
                let result = self.gate.upstream_write(advance);
                self.write = Some(WriteObservation {
                    result,
                    hello_end_before,
                    terminated_before,
                });
            }

            #[invariant(always_run)]
            fn g1_open_implies_a_validated_hello(&self, _: TestCase) {
                if self.gate.is_open() {
                    assert!(
                        self.gate.hello_end().is_some(),
                        "the gate opened without a validated hello boundary"
                    );
                }
            }

            #[invariant(always_run)]
            fn g2_termination_is_absorbing(&self, _: TestCase) {
                if matches!(self.gate.phase(), GatePhase::Terminated(_)) {
                    assert!(
                        !self.gate.is_open(),
                        "a terminated setup reports an open gate"
                    );
                }
                if matches!(self.phase_before, GatePhase::Terminated(_)) {
                    assert!(
                        matches!(self.gate.phase(), GatePhase::Terminated(_)),
                        "a terminated setup left the terminating phase: {:?}",
                        self.gate.phase()
                    );
                }
            }

            #[invariant(always_run)]
            fn g2b_termination_settles_the_cause(&self, _: TestCase) {
                let GatePhase::Terminated(settled) = self.phase_before else {
                    return;
                };
                if self.last_rule != Some(Rule::HelloRejected) {
                    assert_eq!(
                        self.gate.phase(),
                        self.phase_before,
                        "rule {:?} changed the settled termination {settled:?} without re-terminating",
                        self.last_rule
                    );
                }
                if self.gate.phase() != self.phase_before {
                    assert_eq!(
                        self.last_rule,
                        Some(Rule::HelloRejected),
                        "rule {:?} overwrote the settled cause {settled:?}",
                        self.last_rule
                    );
                    assert_eq!(
                        self.gate.phase(),
                        GatePhase::Terminated(TerminateReason::ClientHelloRejected),
                        "the permitted re-termination must record ClientHelloRejected"
                    );
                }
            }

            #[invariant(always_run)]
            fn g3_committed_offset_is_monotone(&self, _: TestCase) {
                assert!(
                    self.gate.upstream_committed() >= self.committed_before,
                    "upstream_committed moved backwards: {} after {}",
                    self.gate.upstream_committed(),
                    self.committed_before
                );
            }

            #[invariant(always_run)]
            fn g4_write_classification_follows_the_barrier_state(&self, _: TestCase) {
                let Some(write) = &self.write else { return };
                let blocked = write.result == UpstreamWrite::BlockedByBarrierA;
                let should_block = write.hello_end_before.is_none() || write.terminated_before;
                assert_eq!(
                    blocked, should_block,
                    "a write reported {:?} with hello end {:?} and terminated {} before it",
                    write.result, write.hello_end_before, write.terminated_before
                );
                if matches!(
                    write.result,
                    UpstreamWrite::GateOpened { .. } | UpstreamWrite::Open
                ) {
                    assert!(
                        write.hello_end_before.is_some(),
                        "the gate opened in a write issued without a validated hello"
                    );
                }
            }

            #[invariant(always_run)]
            fn g5_phase_edges_are_the_written_down_set(&self, _: TestCase) {
                let from = self.phase_before;
                let to = self.gate.phase();
                if from == to {
                    return;
                }
                if matches!(from, GatePhase::Terminated(_))
                    && matches!(to, GatePhase::Terminated(_))
                {
                    return;
                }
                assert!(
                    is_written_down_edge(from, to),
                    "phase edge {from:?} -> {to:?} is outside the written-down set"
                );
            }
        }
    }

    /// The two-barrier lifecycle as a state machine: model-based coverage of the
    /// gate's interleavings, over the same production [`TunnelGate`] the example
    /// tests drive. Its invariant list and independence argument are on
    /// [`lifecycle_machine`]; `hegel.toml` owns the case count.
    #[hegel::test(derandomize = true)]
    fn gate_lifecycle_is_two_barrier_ordered(tc: hegel::TestCase) {
        hegel::stateful::machine(lifecycle_machine::GateLifecycle::start())
            .steps(400)
            .run(tc);
    }
}

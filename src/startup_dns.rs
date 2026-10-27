//! Startup DNS-over-TCP transport (docs/alumina-proxy.md:62-68, 82, 171, 180): a single
//! reusable connection with one outstanding query, transaction ids drawn from
//! the OS CSPRNG, and publication of only fully validated outcomes into the
//! cache and schedule.
//!
//! The exchange deadline is 5 seconds (`EXCHANGE_DEADLINE_SECS`), clipped to the
//! caller's absolute startup window deadline. On timeout, malformed, mismatched, truncated or
//! oversized responses the connection is closed, nothing is published, and the
//! exchange counts as failed. Startup readiness evaluation from the published
//! cache remains a caller concern.
//!
//! Cooperative turns never wait: [`StartupDns::advance_exchange`] performs at
//! most one nonblocking I/O attempt and returns [`TurnResult::Pending`] when
//! more readiness is needed; the single process owner owns the wait.
//! [`StartupDns::exchange_deadline`] and [`StartupDns::wait_dns_readiness`]
//! export the deadline and a wakeup the owner folds into its one combined
//! wait, so the shared reactor can observe traffic, log, and shutdown
//! readiness without DNS-internal blocking (docs/alumina-proxy.md:146).

use std::fmt;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Registry, Token};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{
    ClientConnection, verify_server_cert_signed_by_trust_anchor, verify_server_name,
};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::cache::{Cache, CacheError, Family, Generation};
use crate::config::{ALLOWLIST_MAX, Config, Fqdn};
use crate::dns::{self, BailiwickZones, DNS_MSG_LIMIT, DnsError, ResponseWorkspace};
use crate::enforcement::monitor::DnsAnomalyKind;
use crate::log;
use crate::resolver::{Fqdn as ResolverFqdn, MAX_RESOLVERS, ResolverSet, SpiPin};
use crate::schedule::{PerTypeTransition, ScheduleError, Schedules};

pub const EXCHANGE_DEADLINE_SECS: u64 = 5;
pub const STARTUP_WINDOW_SECS: u64 = 90;
pub const QUERY_BUF_LEN: usize = 512;
pub const RECV_BUF_LEN: usize = DNS_MSG_LIMIT + 2;

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupDnsError {
    Dns(DnsError),
    Cache(CacheError),
    Schedule(ScheduleError),
    /// A counted per-exchange network failure (connect refused, write
    /// failure, socket error, deadline). It increments `StartupReport.failed`
    /// and advances the schedule backoff; it is never returned by `resolve`
    /// and does not abort resolution.
    Exchange {
        kind: io::ErrorKind,
        detail: &'static str,
    },
    /// A non-allocating fatal lifecycle refusal: `kind` carries the OS error
    /// class and `detail` names the stage (register, deregister, poll). Both
    /// fields are `Copy`.
    Transport {
        kind: io::ErrorKind,
        detail: &'static str,
    },
    /// The boot-owned log queue or its stdout sink could not be prepared.
    LogStore(log::LogStoreError),
    /// The OS entropy source failed while drawing a transaction id.
    Entropy,
    /// The monotonic poll-token generation is exhausted; no token is reused.
    TokenExhausted,
    /// The monotonic clock cannot represent the startup window deadline; the
    /// window is not extended, shortened, or clamped.
    DeadlineOverflow,
    /// The flat union of declared `cname_bailiwick` suffixes exceeds the fixed
    /// `ALLOWLIST_MAX` slot bound; boot fails loudly and typed rather than
    /// panicking out of bounds.
    BailiwickSuffixOverflow {
        got: usize,
        max: usize,
    },
    /// The cooperative driver was asked to advance an exchange that is not in
    /// progress; start one first.
    ExchangeInactive,
    /// A start was requested while an exchange is already in progress; the
    /// outstanding exchange, its schedule accounting, and its connection are
    /// preserved untouched rather than silently replaced.
    ExchangeActive,
    /// The retained transport was asked to join the shared owner's registry
    /// while it still holds an open connection bound to the DNS-private poll.
    /// Attach only a transport with no open connection; a source can belong to
    /// exactly one registry.
    SharedAttachConflict,
}

impl fmt::Display for StartupDnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupDnsError::Dns(err) => write!(f, "startup DNS: {err}"),
            StartupDnsError::Cache(err) => write!(f, "startup DNS cache: {err}"),
            StartupDnsError::Schedule(err) => write!(f, "startup DNS schedule: {err:?}"),
            StartupDnsError::Exchange { kind, detail } => {
                write!(f, "startup DNS exchange ({detail}): {kind}")
            }
            StartupDnsError::Transport { kind, detail } => {
                write!(f, "startup DNS transport ({detail}): {kind}")
            }
            StartupDnsError::Entropy => write!(f, "startup DNS entropy unavailable"),
            StartupDnsError::TokenExhausted => {
                write!(f, "startup DNS poll-token generation exhausted")
            }
            StartupDnsError::DeadlineOverflow => write!(
                f,
                "startup DNS window deadline not representable on this clock"
            ),
            StartupDnsError::BailiwickSuffixOverflow { got, max } => write!(
                f,
                "startup DNS declared cname_bailiwick suffix count {got} exceeds the {max} slot bound"
            ),
            StartupDnsError::ExchangeInactive => {
                write!(f, "startup DNS exchange not in progress")
            }
            StartupDnsError::ExchangeActive => {
                write!(f, "startup DNS exchange already in progress")
            }
            StartupDnsError::SharedAttachConflict => {
                write!(f, "startup DNS transport holds a private-poll connection")
            }
            StartupDnsError::LogStore(err) => write!(f, "startup log store: {err:?}"),
        }
    }
}

impl From<log::LogStoreError> for StartupDnsError {
    fn from(err: log::LogStoreError) -> Self {
        StartupDnsError::LogStore(err)
    }
}

impl From<DnsError> for StartupDnsError {
    fn from(err: DnsError) -> Self {
        match err {
            DnsError::BailiwickSuffixOverflow { got, max } => {
                StartupDnsError::BailiwickSuffixOverflow { got, max }
            }
            other => StartupDnsError::Dns(other),
        }
    }
}

impl From<CacheError> for StartupDnsError {
    fn from(err: CacheError) -> Self {
        StartupDnsError::Cache(err)
    }
}

impl From<ScheduleError> for StartupDnsError {
    fn from(err: ScheduleError) -> Self {
        StartupDnsError::Schedule(err)
    }
}

/// What a fully validated published exchange left in the cache, so the
/// startup report can tell a validated negative from an attempted positive
/// with no eligible bindings instead of collapsing both into one catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishedKind {
    /// A positive answer published at least one eligible binding.
    ResolvedPositive,
    /// A positive answer whose candidates were all ineligible; nothing was
    /// published.
    NoEligible,
    /// A validated NXDOMAIN or NODATA answer was applied.
    Negative,
}

/// Classifies a validated DNS outcome into the window-level published kind: a
/// positive contributes a usable name only when at least one of its binding
/// candidates is eligible, so an all-ineligible positive is `NoEligible`.
fn classify_published(outcome: &crate::dns::Outcome) -> PublishedKind {
    match outcome {
        crate::dns::Outcome::Positive { bindings, .. }
            if bindings.as_slice().iter().any(|b| b.is_eligible()) =>
        {
            PublishedKind::ResolvedPositive
        }
        crate::dns::Outcome::Positive { .. } => PublishedKind::NoEligible,
        crate::dns::Outcome::NxDomain { .. } | crate::dns::Outcome::NoData { .. } => {
            PublishedKind::Negative
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExchangeResult {
    Published(PublishedKind),
    Failed(FailureReason),
}

/// The full legal context of one outstanding cooperative exchange, owned as a
/// single value on [`StartupDns`] so that at most one exchange can exist. A
/// transaction id, identity, deadline, per-stage state, and any deferred
/// synchronous connect error travel together; `None` means no exchange is in
/// progress. The step state advances by at most one stage per cooperative
/// turn.
#[derive(Debug)]
struct ActiveExchange {
    ordinal: usize,
    family: Family,
    deadline: Instant,
    step: ExchangeStep,
    /// `query_buf[..qlen]` is the length-prefixed query awaiting writes.
    qlen: usize,
    /// A synchronous connect error deferred to the first connecting turn so it
    /// settles as the counted failure it is, never aborted.
    connect_err: Option<io::ErrorKind>,
    tid: u16,
    /// Whether the exchange was started by the serving runtime (a refresh)
    /// rather than the startup window. The serving runtime cancels a retained
    /// startup exchange whose window already expired; a serving refresh is
    /// never cancelled by that path.
    serving: bool,
    /// Whether the exchange is a post-window probe rather than a startup or
    /// serving exchange. A probe is a pure sensor: it parses and validates a
    /// response to record a resolver verdict, but never publishes
    /// name-authorization state (docs/alumina-proxy.md:826).
    probe: bool,
    /// The cache entry generation captured at exchange start. Apply compares
    /// the staged result against this captured value so an obsolete result
    /// cannot overwrite newer cache state (docs/alumina-proxy.md:74,
    /// cache.rs:357-359).
    generation: Generation,
}

/// The stage of one outstanding exchange, advanced by at most one stage each
/// cooperative turn by [`StartupDns::advance_exchange`]. Turns never wait for
/// readiness (docs/alumina-proxy.md:146); the owner decides when to advance again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeStep {
    /// A nonblocking connect is in progress toward the exchange deadline; the
    /// query is not written until the socket is verifiably connected.
    Connecting,
    /// A `DoT` exchange whose TCP socket is connected is driving the rustls
    /// client handshake toward `is_handshaking() == false`; the query is not
    /// written until the handshake completes (TLS setup allocations are
    /// confined to this per-connect seam).
    TlsHandshake,
    /// The length-prefixed query is not yet fully written and the send can
    /// proceed without waiting; the next turn attempts another nonblocking
    /// write.
    SendReady,
    /// The last nonblocking write refused the socket (`WouldBlock`); the
    /// backpressure is recorded in the type and the owner must wait for a
    /// writable edge before another send attempt. No kernel or peer send-buffer
    /// capacity is assumed.
    AwaitWritable,
    /// Awaiting or assembling a response within the exchange deadline.
    Receiving,
}

/// The outcome of one cooperative turn, returned by
/// [`StartupDns::advance_exchange`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TurnResult {
    /// The exchange needs another turn; the worker may do other bounded work
    /// and then call [`StartupDns::advance_exchange`] again.
    Pending,
    /// A fully validated response was applied to the cache and schedule; the
    /// published-outcome classification is carried structurally.
    Published(PublishedKind),
    /// A counted per-exchange network failure; the connection is closed and
    /// the schedule backoff has been advanced exactly once. The failure reason
    /// is carried structurally.
    Failed(FailureReason),
}

/// The progress of one nonblocking connect step.
enum ConnectStep {
    /// The connection is not yet established; the exchange stays in scope.
    Waiting,
    /// The socket is connected; `next` names the following stage — the `DoT`
    /// handshake when the resolver carries an FQDN/pin target, or the direct
    /// send for a bare-IP resolver.
    Transition { next: ExchangeStep },
    /// A counted failure; the exchange has been settled and closed.
    Failed(FailureReason),
}

/// The outcome of one nonblocking connect probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectProbe {
    /// The connect is not yet completed; the exchange stays in scope.
    NotReady,
    /// The socket is connected; the exchange may transition to its next stage.
    Connected,
    /// A counted socket error; the exchange is settled and closed.
    SocketError,
    /// The completed connect landed on an unexpected peer; a resolver-peer
    /// anomaly is counted and the exchange fails closed.
    PeerMismatch,
}

/// The progress of one nonblocking query-write step.
enum SendStep {
    /// Some or all of the query remains unsent and the send can proceed without
    /// waiting; the exchange stays able to retry next turn.
    Waiting,
    /// The socket refused the write (`WouldBlock`); the exchange is held in
    /// `AwaitWritable` and the owner waits for a writable edge before retrying.
    Blocked,
    /// The query is fully written; advance moves to the receiving stage next
    /// turn (the readiness interest switches to reads).
    Transition,
    /// A counted failure; the exchange has been settled and closed.
    Failed(FailureReason),
}

/// The progress of one nonblocking response-read step.
enum RecvStep {
    Waiting,
    Failed(FailureReason),
    Published(PublishedKind),
}

/// The progress of one nonblocking `DoT` TLS-handshake step.
enum HandshakeStep {
    /// The handshake is not complete; the exchange stays in scope and the
    /// owner waits for socket readiness before another turn.
    Waiting,
    /// The handshake finished (peer authenticated); advance moves to the
    /// sending stage next turn.
    Transition,
    /// A counted failure (certificate/identity rejection, alert, EOF, or
    /// socket error); the exchange has been settled and closed.
    Failed(FailureReason),
}

/// The outcome of one nonblocking TLS-handshake probe, decided inside the
/// scoped borrow over the retained connection so the caller can close and
/// count outside the borrow.
enum HandshakeProbe {
    Waiting,
    Transition,
    Failed,
}

/// The reason a startup exchange failed, captured at the step where the
/// failure was first observable (connect, send, recv, deadline, or the `DoT`
/// TLS identity/handshake layer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    Connect,
    Send,
    Receive,
    Timeout,
    /// A `DoT` TLS-layer failure: the rustls client connection could not be
    /// built for the target, or the handshake failed (certificate/pin/`SAN`
    /// identity rejection, alert, `EOF`, or socket error). Distinct from
    /// [`FailureReason::Connect`] so an operator with a misconfigured pin or
    /// `FQDN` sees a TLS-specific reason instead of an indistinguishable
    /// plain-TCP connect failure.
    TlsIdentity,
}

impl FailureReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            FailureReason::Connect => "connect",
            FailureReason::Send => "send",
            FailureReason::Receive => "receive",
            FailureReason::Timeout => "timeout",
            FailureReason::TlsIdentity => "tls_identity",
        }
    }
}

/// The reason a name was never attempted inside the startup window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAttemptedReason {
    /// The fixed startup window closed before any exchange for the name was
    /// attempted (the only not-attempted state the window produces).
    WindowClosed,
}

impl NotAttemptedReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            NotAttemptedReason::WindowClosed => "window_closed",
        }
    }
}

/// The per-name terminal outcome of a single exchanged result, as the resolve
/// loops track it: `Resolved` is terminal (a usable name is never re-attempted),
/// otherwise the latest concluded exchange's outcome or reason is kept (704q:
/// capture where still known, never infer at formatting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Latest {
    Unattempted,
    Failed(FailureReason),
    NoEligible,
    Negative,
    Resolved,
}

impl Latest {
    fn merge(&mut self, result: ExchangeResult) {
        if *self == Latest::Resolved {
            return;
        }
        *self = match result {
            ExchangeResult::Published(PublishedKind::ResolvedPositive) => Latest::Resolved,
            ExchangeResult::Published(PublishedKind::Negative) => Latest::Negative,
            ExchangeResult::Published(PublishedKind::NoEligible) => Latest::NoEligible,
            ExchangeResult::Failed(reason) => Latest::Failed(reason),
        };
    }

    const fn to_outcome(self) -> NameOutcome {
        match self {
            Latest::Resolved => NameOutcome::Resolved,
            Latest::Negative => NameOutcome::Negative,
            Latest::NoEligible => NameOutcome::NoEligible,
            Latest::Failed(reason) => NameOutcome::Failed(reason),
            Latest::Unattempted => NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed),
        }
    }
}

/// The per-name terminal outcome of the startup window, carried by the
/// per-name `startup_name` records. A name is reported from its actual latest
/// exchange results: a validated negative (NXDOMAIN or empty NODATA answer)
/// stays distinct from an attempted positive with no eligible bindings and
/// from an exchange failure with its reason, so the final entry never collapses
/// distinct outcome classes into one catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameOutcome {
    /// At least one family holds an eligible non-retired positive binding.
    Resolved,
    /// The latest published outcome for the name was a validated negative
    /// (NXDOMAIN, or an NODATA answer with no eligible bindings).
    Negative,
    /// The latest published outcome was a positive answer whose candidates
    /// were all ineligible, so no binding was published.
    NoEligible,
    /// The latest concluded exchange for the name failed with this reason.
    Failed(FailureReason),
    /// No exchange for the name concluded inside the window.
    NotAttempted(NotAttemptedReason),
}

impl Default for NameOutcome {
    fn default() -> Self {
        NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StartupReport {
    pub exchanges: u32,
    pub failed: u32,
    pub cancelled: u32,
    pub not_attempted: u32,
    pub resolved_names: u32,
    /// One entry per configured name in allowlist ordinal order.
    pub outcomes: [NameOutcome; ALLOWLIST_MAX],
    /// The first counted exchange failure: name ordinal plus address family.
    pub first_failure: Option<(u16, Family)>,
}

impl StartupReport {
    /// Records the first counted exchange failure (name ordinal + family) if
    /// none has been captured yet.
    pub(crate) fn record_first_failure(&mut self, ordinal: usize, family: Family) {
        if self.first_failure.is_none() {
            self.first_failure = Some((
                u16::try_from(ordinal).expect("name ordinal bounded by ALLOWLIST_MAX"),
                family,
            ));
        }
    }
}

/// The per-name, per-family bookkeeping of one startup window, shared between
/// the private blocking driver (`resolve_window`) and the shared owner's
/// cooperative window so both produce the identical typed report from the
/// identical selection/backoff rule set. Kept here so the private [`Latest`]
/// classification and [`PublishedKind`] resolution stay encapsulated: the
/// selected/exchanged/report math never leaks raw stages to an owner.
#[derive(Debug)]
pub(crate) struct WindowLedger {
    resolved: [bool; ALLOWLIST_MAX],
    attempted: [bool; ALLOWLIST_MAX * 2],
    latest: [Latest; ALLOWLIST_MAX],
    names: usize,
}

impl WindowLedger {
    pub(crate) const fn new(names: usize) -> WindowLedger {
        WindowLedger {
            resolved: [false; ALLOWLIST_MAX],
            attempted: [false; ALLOWLIST_MAX * 2],
            latest: [Latest::Unattempted; ALLOWLIST_MAX],
            names,
        }
    }

    pub(crate) const fn names(&self) -> usize {
        self.names
    }

    pub(crate) fn resolved(&self) -> &[bool] {
        &self.resolved[..self.names]
    }

    pub(crate) const fn is_resolved(&self, ordinal: usize) -> bool {
        self.resolved[ordinal]
    }

    pub(crate) fn all_resolved(&self) -> bool {
        self.resolved[..self.names].iter().all(|&r| r)
    }

    pub(crate) const fn track_attempt(&mut self, ordinal: usize, family: Family) {
        self.attempted[ordinal * 2 + family_index(family)] = true;
    }

    /// Merges a concluded exchange into the ledger: a resolved-positive answer
    /// (with at least one eligible binding) marks the name usable and terminal;
    /// a validated negative or no-eligible answer is recorded as its own class
    /// and never re-attempted as resolved.
    pub(crate) fn mark_published(&mut self, ordinal: usize, kind: PublishedKind) {
        match kind {
            PublishedKind::ResolvedPositive => self.resolved[ordinal] = true,
            PublishedKind::Negative | PublishedKind::NoEligible => {}
        }
        self.latest[ordinal].merge(ExchangeResult::Published(kind));
    }

    /// Overlays the "usable name" binding check: a name counts as resolved only
    /// when a published positive answer actually left at least one eligible
    /// binding, exactly as the private driver computes it.
    pub(crate) const fn resolve(&mut self, ordinal: usize, has: bool) {
        self.resolved[ordinal] |= has;
    }

    pub(crate) fn mark_failed(&mut self, ordinal: usize, reason: FailureReason) {
        self.latest[ordinal].merge(ExchangeResult::Failed(reason));
    }

    /// Finishes the window ledger into the typed startup report, applying the
    /// canonical count and outcome rules: attempted per name-family pair,
    /// not-attempted as the remainder, resolved names where a usable binding
    /// was published, and each unresolved name reported from its latest
    /// classified outcome rather than inferred.
    pub(crate) fn finish(
        &self,
        exchanges: u32,
        failed: u32,
        first_failure: Option<(u16, Family)>,
    ) -> StartupReport {
        let attempted_count = u32::try_from(
            self.attempted[..self.names * 2]
                .iter()
                .filter(|&&t| t)
                .count(),
        )
        .expect("attempted count bounded by ALLOWLIST_MAX * 2");
        let resolved_names =
            u32::try_from(self.resolved[..self.names].iter().filter(|&&r| r).count())
                .expect("resolved count bounded by ALLOWLIST_MAX");
        let mut report = StartupReport {
            exchanges,
            failed,
            cancelled: 0,
            not_attempted: u32::try_from(self.names * 2).expect("names bounded by ALLOWLIST_MAX")
                - attempted_count,
            resolved_names,
            outcomes: [NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed); ALLOWLIST_MAX],
            first_failure,
        };
        for ordinal in 0..self.names {
            report.outcomes[ordinal] = if self.resolved[ordinal] {
                NameOutcome::Resolved
            } else {
                self.latest[ordinal].to_outcome()
            };
        }
        report
    }
}

/// A tightly scoped test hook that substitutes the outcome of the next
/// nonblocking send attempt, so a deterministically forced send backpressure
/// (a real `WouldBlock`) can be exercised without depending on any kernel or
/// peer send-buffer capacity.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
enum WriteForce {
    WouldBlock,
    Partial(usize),
}

/// Whether the retained transport belongs to this transport's own private poll
/// or to the shared owner's single serving poll. A source has exactly one
/// registry (mio rejects a second); the variants make the two owners
/// mutually exclusive, and `armed` records the interest currently registered
/// for the shared registry's stream: `Some(interest)` while registered,
/// `None` while the stream is fresh or closed. Only `Private` ever touches the
/// DNS-private poll.
#[derive(Debug)]
enum Registration {
    Private,
    Shared {
        token: Token,
        armed: Option<Interest>,
    },
}

/// Passive resolver degradation state advanced at the two exchange choke
/// points: every counted failure and every successful publication. `Healthy`
/// carries only 0..`DEGRADED_AFTER` consecutive failures, because the failure
/// transition relocates the state to `Degraded` at the threshold — a value can
/// never claim health while holding three consecutive failures, so the
/// degraded boundary is structural rather than checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolverDegradation {
    Healthy { consecutive: usize },
    Degraded,
}

impl Default for ResolverDegradation {
    fn default() -> Self {
        ResolverDegradation::Healthy { consecutive: 0 }
    }
}

/// The number of consecutive failed exchanges that relocate the resolver state
/// into passive degraded mode before any successful exchange resets it.
const DEGRADED_AFTER: usize = 3;

/// The number of consecutive successful primary probes that settle a failback
/// probe, symmetric with [`DEGRADED_AFTER`] so a transient primary is not
/// re-adopted on a single probe success.
const FAILBACK_SUCCESSES: usize = 3;

/// The whole-second span Alumina spends on a non-primary resolver before the
/// next exchange probes the primary again (bounded failback recovery). One
/// failed probe re-degrades the primary and re-arms the timer; a successful
/// probe recovers the primary as the active resolver.
pub const FAILBACK_AFTER_SECS: u64 = 900;

impl ResolverDegradation {
    const fn note_failure(self) -> ResolverDegradation {
        match self {
            ResolverDegradation::Degraded => ResolverDegradation::Degraded,
            ResolverDegradation::Healthy { consecutive } => {
                if consecutive + 1 >= DEGRADED_AFTER {
                    ResolverDegradation::Degraded
                } else {
                    ResolverDegradation::Healthy {
                        consecutive: consecutive + 1,
                    }
                }
            }
        }
    }

    const fn note_success() -> ResolverDegradation {
        ResolverDegradation::Healthy { consecutive: 0 }
    }
}

/// Which resolver of the configured [`ResolverSet`] the transport currently
/// points at. The index and the set length travel together as one value, so an
/// out-of-range active resolver is unrepresentable: construction starts at the
/// primary and every failover transition advances within `0..set_len` by the
/// state machine, never by an unbounded caller-supplied index. A length below
/// the index is a build-time impossibility (`ResolverSet` never holds zero
/// entries, `src/resolver.rs:89`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ActiveResolver {
    index: usize,
    set_len: usize,
}

impl ActiveResolver {
    const fn at(index: usize, set_len: usize) -> ActiveResolver {
        ActiveResolver { index, set_len }
    }

    /// The primary resolver is index 0 of the set.
    const fn primary(set_len: usize) -> ActiveResolver {
        ActiveResolver { index: 0, set_len }
    }

    const fn index(&self) -> usize {
        self.index
    }

    const fn set_len(&self) -> usize {
        self.set_len
    }

    const fn is_primary(&self) -> bool {
        self.index == 0
    }
}

/// The per-resolver verdict of the post-window probe sweep, recorded once each
/// probed resolver's exchange concludes. `Ok` and `Failed` are recorded only
/// for resolvers the sweep actually probed; a resolver the sweep skipped (the
/// active resolver at sweep begin) stays `NotProbed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    Ok,
    Failed(FailureReason),
    NotProbed,
}

impl ProbeVerdict {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            ProbeVerdict::Ok => "ok",
            ProbeVerdict::Failed(_) => "failed",
            ProbeVerdict::NotProbed => "not_probed",
        }
    }
}

/// The post-window probe sweep state: which configured resolvers remain to be
/// probed, the active resolver the sweep began from (restored after each probe
/// and after the sweep), the per-resolver verdicts accumulated so far, and the
/// probe target currently in flight. All fixed-size; no heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProbeSweep {
    remaining: [bool; MAX_RESOLVERS],
    active_before: ActiveResolver,
    verdicts: [ProbeVerdict; MAX_RESOLVERS],
    current: Option<ActiveResolver>,
}

/// A latched corroboration request: a sustained-negative incident opened for an
/// admitted name and the resolver set holds at least two resolvers, so a
/// different configured resolver must be cross-checked once against the active
/// resolver's negative. Set on the apply path when the incident opens and
/// consumed by the serving owner when the transport is idle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CorroborationPending {
    ordinal: usize,
    family: Family,
}

/// The in-flight corroboration exchange state: the target resolver being
/// cross-checked and the active resolver the transport must restore (or advance
/// its degradation on a conflict). All fixed-size; no heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Corroboration {
    target: ActiveResolver,
    active_before: ActiveResolver,
    ordinal: usize,
    family: Family,
}

/// The `DoT` identity the transport hands the rustls client for one connection:
/// the resolver FQDN used as SNI and validated against the presented
/// certificate's SAN, plus an optional strict SPKI pin. Carried only for
/// `IP#fqdn`/`IP#fqdn#pin-sha256=` resolver entries; a bare-IP entry keeps
/// `None` and dials plain DNS, so the FQDN presence is the transport signal
/// with no silent plain-DNS fallback.
#[derive(Clone, Copy, PartialEq, Eq)]
struct TlsTarget {
    fqdn: ResolverFqdn,
    pin: Option<SpiPin>,
}

/// A connected transport: plain TCP for a bare-IP resolver, or a rustls
/// client connection over its own TCP socket for a `DoT` resolver. The boxed
/// connection keeps the fixed [`StartupDns`] struct small while TLS setup
/// allocations stay confined to the per-connect [`Self::upgrade_to_tls`] seam.
enum DnsConn {
    Plain(TcpStream),
    Tls(TlsConn),
}

struct TlsConn {
    tcp: TcpStream,
    tls: Box<ClientConnection>,
    /// The shared pin-branch expired/not-yet-valid warning counter, drained
    /// into the owning transport's `ep` fold once at handshake transition.
    expired_pin_certs: Arc<AtomicU32>,
}

/// A custom [`ServerCertVerifier`] for the `DoT` resolver set: an empty
/// [`RootCertStore`] is held so a pinned entry's `verify_server_cert` trusts
/// the pin (with FQDN/SAN validation) instead of any CA chain, while a
/// CA-chain (no-pin) entry deterministically fails chain validation until a
/// future trust-anchor intake lands. Everything delegates to the rustls/webpki
/// verify helpers with the provider's supported algorithms.
#[derive(Debug)]
struct AluminaServerCertVerifier {
    pin: Option<SpiPin>,
    supported: WebPkiSupportedAlgorithms,
    /// The shared counter for pin-matching certificates whose Not-Before/
    /// Not-After window excludes the handshake instant (RT-007). The pin
    /// branch treats validity as a warning, never a rejection, so the count
    /// is drained into the monitor `ep` fact by the owning transport.
    expired_pin_certs: Arc<AtomicU32>,
}

impl ServerCertVerifier for AluminaServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        verify_server_name(&cert, server_name)?;
        if let Some(pin) = self.pin {
            let digest =
                ring::digest::digest(&ring::digest::SHA256, &cert.subject_public_key_info());
            if digest.as_ref() != pin.as_bytes().as_slice() {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
            if cert_outside_validity_window(end_entity.as_ref(), now) {
                self.expired_pin_certs.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(ServerCertVerified::assertion());
        }
        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &RootCertStore::empty(),
            intermediates,
            now,
            self.supported.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// One DER TLV element: the tag byte, the value slice, and the bytes remaining
/// after the element.
struct DerElement<'a> {
    tag: u8,
    value: &'a [u8],
    rest: &'a [u8],
}

/// Reads one DER TLV element from the front of `input`, returning the element
/// and the remaining bytes. `None` on any structural anomaly (short header,
/// truncated length, overlong length form) so the caller can fail open.
fn read_der_element(input: &[u8]) -> Option<DerElement<'_>> {
    let (&tag, rest) = input.split_first()?;
    let (&len_byte, rest) = rest.split_first()?;
    let (len, rest) = if len_byte & 0x80 == 0 {
        (usize::from(len_byte), rest)
    } else {
        let count = usize::from(len_byte & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let (len_bytes, rest) = rest.split_at_checked(count)?;
        let mut len = 0usize;
        for &b in len_bytes {
            len = len.checked_mul(256)?.checked_add(usize::from(b))?;
        }
        (len, rest)
    };
    let (value, rest) = rest.split_at_checked(len)?;
    Some(DerElement { tag, value, rest })
}

/// Extracts the certificate validity window (`notBefore`, `notAfter`) as Unix
/// seconds from a DER-encoded X.509 certificate by walking the fixed
/// `Certificate` → `TBSCertificate` → `Validity` spine. `None` on any
/// structural anomaly so the caller can fail open: this parse only drives a
/// warning counter and must never reject a pin-matching handshake.
fn cert_validity_epochs(der: &[u8]) -> Option<(i64, i64)> {
    let cert = read_der_element(der)?;
    if cert.tag != 0x30 {
        return None;
    }
    let tbs = read_der_element(cert.value)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut rest = tbs.value;
    if rest.first() == Some(&0xa0) {
        let version = read_der_element(rest)?;
        rest = version.rest;
    }
    let serial = read_der_element(rest)?;
    if serial.tag != 0x02 {
        return None;
    }
    rest = serial.rest;
    let signature = read_der_element(rest)?;
    if signature.tag != 0x30 {
        return None;
    }
    rest = signature.rest;
    let issuer = read_der_element(rest)?;
    if issuer.tag != 0x30 {
        return None;
    }
    let validity = read_der_element(issuer.rest)?;
    if validity.tag != 0x30 {
        return None;
    }
    let not_before = read_der_element(validity.value)?;
    let not_after = read_der_element(not_before.rest)?;
    Some((
        der_time_to_epoch(&not_before)?,
        der_time_to_epoch(&not_after)?,
    ))
}

/// Converts a DER time element (`UTCTime` `YYMMDDHHMMSSZ` or `GeneralizedTime`
/// `YYYYMMDDHHMMSSZ`) to Unix seconds. `None` on any malformed or
/// out-of-range input so the caller can fail open.
fn der_time_to_epoch(element: &DerElement<'_>) -> Option<i64> {
    let value = element.value;
    match element.tag {
        0x17 => {
            let (year, rest) = value.split_at_checked(2)?;
            let (month, rest) = rest.split_at_checked(2)?;
            let (day, rest) = rest.split_at_checked(2)?;
            let (hour, rest) = rest.split_at_checked(2)?;
            let (minute, rest) = rest.split_at_checked(2)?;
            let (second, rest) = rest.split_at_checked(2)?;
            if rest != b"Z" {
                return None;
            }
            let yy = i64::from(digits2(year)?);
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            ymd_to_epoch(
                year,
                i64::from(digits2(month)?),
                i64::from(digits2(day)?),
                i64::from(digits2(hour)?),
                i64::from(digits2(minute)?),
                i64::from(digits2(second)?),
            )
        }
        0x18 => {
            let (year, rest) = value.split_at_checked(4)?;
            let (month, rest) = rest.split_at_checked(2)?;
            let (day, rest) = rest.split_at_checked(2)?;
            let (hour, rest) = rest.split_at_checked(2)?;
            let (minute, rest) = rest.split_at_checked(2)?;
            let (second, rest) = rest.split_at_checked(2)?;
            if rest != b"Z" {
                return None;
            }
            ymd_to_epoch(
                i64::from(digits4(year)?),
                i64::from(digits2(month)?),
                i64::from(digits2(day)?),
                i64::from(digits2(hour)?),
                i64::from(digits2(minute)?),
                i64::from(digits2(second)?),
            )
        }
        _ => None,
    }
}

/// Parses a two-ASCII-digit field as a `u16`, `None` unless both bytes are
/// decimal digits.
fn digits2(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 2 {
        return None;
    }
    let a = bytes[0].checked_sub(b'0')?;
    let b = bytes[1].checked_sub(b'0')?;
    if a > 9 || b > 9 {
        return None;
    }
    Some(u16::from(a) * 10 + u16::from(b))
}

/// Parses a four-ASCII-digit field as a `u16`, `None` unless every byte is a
/// decimal digit and the value fits.
fn digits4(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    let mut value = 0u16;
    for &b in bytes {
        let d = b.checked_sub(b'0')?;
        if d > 9 {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u16::from(d))?;
    }
    Some(value)
}

/// Converts a civil date/time to Unix seconds via the days-from-civil
/// algorithm (Hinnant). `None` when the month is out of range or an
/// intermediate product overflows.
fn ymd_to_epoch(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> Option<i64> {
    if !(1..=12).contains(&month) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    days.checked_mul(86_400)?
        .checked_add(hour * 3600)?
        .checked_add(minute * 60)?
        .checked_add(second)
}

/// Days from civil (Hinnant's `days_from_civil`): the number of days since
/// 1970-01-01 for a proleptic Gregorian date.
const fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Reports whether the end-entity certificate's validity window excludes the
/// handshake instant. This is a warning-only probe on the pin branch: the pin
/// match already grounded the identity, and the non-blocking Not-Before/
/// Not-After check (RT-007) must never reject a pin-matching handshake. The
/// DER walk is fail-open — any parse anomaly reports no warning rather than
/// risking a false rejection.
fn cert_outside_validity_window(der: &[u8], now: UnixTime) -> bool {
    let Some((not_before, not_after)) = cert_validity_epochs(der) else {
        return false;
    };
    let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    now < not_before || now > not_after
}

/// Builds the rustls client connection for a `DoT` resolver target: the ring
/// crypto provider, a custom verifier (strict SPKI pin + SNI/SAN validation,
/// or empty-root CA-chain validation), and the resolver FQDN as the SNI name.
/// The heap allocations here are the bounded per-connection `DoT` setup cost —
/// never on the bare-IP path, which constructs no TLS state at all.
///
/// The client negotiates TLS 1.3 only (`with_protocol_versions(&[TLS13])`,
/// with the `tls12` feature removed, `Cargo.toml`), matching the serving-side
/// profile which enforces TLS 1.3 only (`validate_versions`). A `DoT` resolver
/// that offers only TLS 1.2 is deterministically refused at the handshake; the
/// client never negotiates down. This is an intentional hardening: the `DoT`
/// client and the serving surface share one TLS profile, at the cost of
/// excluding TLS 1.2-only public resolvers.
fn build_tls_connection(
    target: TlsTarget,
    expired_pin_certs: Arc<AtomicU32>,
) -> Result<ClientConnection, rustls::Error> {
    let provider = rustls::crypto::ring::default_provider();
    let supported = provider.signature_verification_algorithms;
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AluminaServerCertVerifier {
            pin: target.pin,
            supported,
            expired_pin_certs,
        }))
        .with_no_client_auth();
    let server_name = ServerName::try_from(target.fqdn.as_str().to_owned()).map_err(|_| {
        rustls::Error::General("resolver FQDN is not a valid TLS server name".into())
    })?;
    ClientConnection::new(Arc::new(config), server_name)
}

/// A boot-owned reusable DNS transport. Constructed once before the
/// startup-window phase so the exchange loop performs no heap allocation or
/// deallocation: the poll registry, fixed query/recv buffers, and the response
/// workspace all pre-exist.
/// A per-type exchange-failure incident notification awaiting drain by the
/// owning serving runtime into the log pipeline: either a first-failure open
/// (warn, suppressed during startup) or a recovery (info, with the elapsed
/// duration). At most two notes accumulate per serving turn — one exchange
/// concludes per turn, producing either one open or up to two recoveries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IncidentNote {
    Open {
        ordinal: usize,
        family: Family,
        reason: FailureReason,
    },
    Recovered {
        ordinal: usize,
        family: Family,
        duration: u64,
    },
}

/// The startup-window DNS driver and, after the window, the retained serving
/// transport owner.
pub struct StartupDns {
    poll: Poll,
    events: Events,
    /// The connected transport: plain TCP for a bare-IP resolver, or a rustls
    /// client connection over its own TCP socket for a `DoT` resolver. `None`
    /// between connections (closed, cancelled, or before the first connect).
    conn: Option<DnsConn>,
    /// The `DoT` identity of the resolver the transport currently points at:
    /// FQDN (SNI and SAN validation) plus an optional strict SPKI pin. `None`
    /// for a bare-IP resolver, which dials plain DNS with no TLS upgrade.
    tls_target: Option<TlsTarget>,
    query_buf: [u8; QUERY_BUF_LEN],
    recv_buf: [u8; RECV_BUF_LEN],
    workspace: ResponseWorkspace,
    bailiwick: BailiwickZones,
    written: usize,
    filled: usize,
    msglen: Option<usize>,
    now0: u64,
    start: Instant,
    addr: SocketAddr,
    watch: Token,
    token_gen: usize,
    registration: Registration,
    active: Option<ActiveExchange>,
    /// The configured resolver set owned for failover/failback decisions,
    /// installed at window begin from the config. `None` before any window
    /// (and in loopback tests that seed only a peer) and then treated as a
    /// one-entry set, so the state machine degrades gracefully without a
    /// configured set to consult.
    resolvers: Option<ResolverSet>,
    /// Which resolver of the set the transport currently points at. The index
    /// and the set length travel together, so an out-of-range active resolver
    /// is unrepresentable; the state machine seats it to the primary at window
    /// begin and relocates it only via [`Self::on_exchange_failed`] and
    /// [`Self::maybe_begin_failback`].
    active_resolver: ActiveResolver,
    /// The passive per-resolver degradation state advanced at the two exchange
    /// choke points, indexed by resolver within the set; the transition
    /// counter below records only entered/exited crossings, never the
    /// individual failures or resets that precede them.
    degradations: [ResolverDegradation; MAX_RESOLVERS],
    /// The whole-second (`now0`-scale) time at which the next exchange must
    /// probe the primary again, armed when the active resolver is not the
    /// primary and cleared when the primary recovers. `None` while no probe is
    /// scheduled.
    failback_due: Option<u64>,
    /// The resolver the transport was on when a failback probe began, kept so
    /// a failed probe re-seats onto that backup instead of cascading into
    /// another failover while the primary is being probed. `None` while no
    /// failback probe is in flight.
    failback_source: Option<ActiveResolver>,
    /// The count of consecutive successful primary probes in the current
    /// failback probe cycle; the probe settles only at `FAILBACK_SUCCESSES`.
    /// Reset to zero when a probe begins or fails; always zero while no probe
    /// is in flight.
    failback_successes: usize,
    /// The number of degraded-mode enter and exit crossings awaiting drain by
    /// the owning `ServeStorage` into the monitor's `rd` fact fold. Transitions
    /// accumulate across a startup window and are drained once after it closes.
    resolver_transitions: usize,
    /// The per-kind DNS anomaly counts (`bv`, `rpm`, `xttl`) awaiting drain by
    /// the owning `ServeStorage` into the monitor anomaly surface. They
    /// accumulate across the resolved set and are taken exactly once so a later
    /// drain never double-counts a detection.
    dns_anomalies: [u32; DnsAnomalyKind::COUNT],
    /// The count of DoT→plain downgrade relocations awaiting drain by the
    /// owning `ServeStorage` into the monitor `dp` fact fold. A relocation is a
    /// downgrade exactly when the departed active resolver carried an `IP#fqdn`
    /// FQDN and the relocated-to resolver is a bare-IP entry; it accumulates
    /// across the failover/failback paths and is taken exactly once.
    downgrade_to_plain: usize,
    /// The count of post-window probe-sweep relocations awaiting drain by the
    /// owning `ServeStorage` into the monitor `pr` fact fold. Every
    /// `relocate_for_probe` call seats the transport onto a probe target and
    /// counts here, disjoint from the serving `dp=` downgrade surface; it is
    /// taken exactly once.
    probe_relocations: usize,
    /// The count of pin-matching certificates whose Not-Before/Not-After
    /// window excluded the handshake instant, awaiting drain by the owning
    /// `ServeStorage` into the monitor `ep` fact fold (RT-007). The pin branch
    /// treats validity as a warning, never a rejection; the count is taken
    /// exactly once at handshake transition.
    expired_pin_certs: usize,
    /// The count of sustained-negative incident opens awaiting drain by the
    /// owning `ServeStorage` into the monitor `sn=` level. Each validated
    /// NXDOMAIN that opens a new incident raises the level by one; opens
    /// accumulate across the resolved set and are taken exactly once.
    incident_opens: usize,
    /// The count of sustained-negative incident closes awaiting drain by the
    /// owning `ServeStorage` into the monitor `sn=` level. Each validated
    /// positive that closes an open incident lowers the level by one; closes
    /// accumulate across the resolved set and are taken exactly once.
    incident_closes: usize,
    /// The per-type exchange-failure incident notes awaiting drain by the
    /// owning serving runtime into the log pipeline. Each slot holds at most
    /// one note; the fixed two-slot buffer bounds a single serving turn, which
    /// concludes exactly one exchange (one open, or up to two recoveries).
    pending_incident_notes: [Option<IncidentNote>; 2],
    /// The post-window probe sweep state, present only while the sweep is in
    /// progress: which configured resolvers remain to be probed, the active
    /// resolver the sweep began from, the accumulated per-resolver verdicts,
    /// and the probe currently in flight. `None` before the sweep begins and
    /// after its verdicts are taken.
    probe_sweep: Option<ProbeSweep>,
    /// The once-only latch that keeps the post-window probe sweep from
    /// re-beginning on a later serving turn after its verdicts are taken. Lives
    /// outside [`ProbeSweep`] so the spec-mandated sweep shape stays exact.
    sweep_ran: bool,
    /// Which configured resolvers the startup window exercised — every resolver
    /// that became the active resolver at least once, from the seeded primary
    /// through each failover/failback relocation. The post-window probe sweep
    /// skips these as already exercised, probing only resolvers the window
    /// never touched (docs/alumina-proxy.md:826).
    window_exercised: [bool; MAX_RESOLVERS],
    /// The latched corroboration request awaiting the serving owner: present
    /// only while a sustained-negative incident has opened for an admitted name
    /// and the corroboration has not yet begun. Consumed exactly once when the
    /// corroboration exchange starts (alox18).
    corroboration_pending: Option<CorroborationPending>,
    /// The in-flight corroboration exchange state, present only while the
    /// corroboration probe is in flight. The exchange is a pure-sensor probe
    /// that never applies cache state; on conclusion the active resolver is
    /// restored or its degradation advanced (alox18).
    corroboration: Option<Corroboration>,
    /// The corroboration outcome captured at the receive step (probe path),
    /// read by the conclusion handler to decide conflict vs consistent. `None`
    /// while no corroboration exchange is in flight or after it concludes.
    corroboration_outcome: Option<PublishedKind>,
    #[cfg(test)]
    poll_ticks: u64,
    #[cfg(test)]
    force_write: Option<WriteForce>,
    #[cfg(test)]
    force_peer_mismatch: bool,
}

/// The borrowed startup-window resolution context fed to
/// [`StartupDns::resolve_window`]: the config, cache, schedules, nameserver,
/// process-relative second anchor, and window duration are the single startup
/// input set, bundled so the resolve seam stays within the clippy argument
/// budget (L1). The boot-owned log store stays a separate per-run parameter
/// because the witness hoists a pre-reserved store into the measured window.
pub(crate) struct WindowInputs<'a> {
    pub(crate) config: &'a Config,
    pub(crate) cache: &'a mut Cache,
    pub(crate) schedules: &'a mut Schedules,
    pub(crate) nameserver: SocketAddr,
    pub(crate) now0: u64,
    pub(crate) window: Duration,
}

impl StartupDns {
    /// Constructs the transport and its registration backing.
    ///
    /// # Errors
    ///
    /// Returns `Transport` when the poll registry cannot be created.
    #[expect(
        clippy::large_stack_arrays,
        reason = "designed DNS-recv fixed-profile buffer; no runtime heap"
    )]
    pub fn new() -> Result<StartupDns, StartupDnsError> {
        let poll = Poll::new().map_err(|e| StartupDnsError::Transport {
            kind: e.kind(),
            detail: "poll",
        })?;
        let events = Events::with_capacity(8);
        Ok(StartupDns {
            poll,
            events,
            conn: None,
            tls_target: None,
            query_buf: [0; QUERY_BUF_LEN],
            recv_buf: [0; RECV_BUF_LEN],
            workspace: ResponseWorkspace::default(),
            bailiwick: BailiwickZones::default(),
            written: 0,
            filled: 0,
            msglen: None,
            now0: 0,
            start: Instant::now(),
            addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            watch: Token(0),
            token_gen: 0,
            registration: Registration::Private,
            active: None,
            resolvers: None,
            active_resolver: ActiveResolver::primary(1),
            degradations: [ResolverDegradation::default(); MAX_RESOLVERS],
            failback_due: None,
            failback_source: None,
            failback_successes: 0,
            resolver_transitions: 0,
            dns_anomalies: [0; DnsAnomalyKind::COUNT],
            downgrade_to_plain: 0,
            probe_relocations: 0,
            expired_pin_certs: 0,
            incident_opens: 0,
            incident_closes: 0,
            pending_incident_notes: [None, None],
            probe_sweep: None,
            sweep_ran: false,
            window_exercised: [false; MAX_RESOLVERS],
            corroboration_pending: None,
            corroboration: None,
            corroboration_outcome: None,
            #[cfg(test)]
            poll_ticks: 0,
            #[cfg(test)]
            force_write: None,
            #[cfg(test)]
            force_peer_mismatch: false,
        })
    }

    fn fresh_tid() -> Result<u16, StartupDnsError> {
        let mut bytes = [0u8; 2];
        getrandom::fill(&mut bytes).map_err(|_| StartupDnsError::Entropy)?;
        Ok(u16::from_be_bytes(bytes))
    }

    /// Resolve the whole-second DNS epoch clock from the window anchor; the
    /// private driver and the shared owner read the same seconds value.
    pub(crate) fn now_u64(&self) -> u64 {
        self.now0.saturating_add(self.start.elapsed().as_secs())
    }

    /// The exact monotonic origin of the most recent `resolve_window` run —
    /// the single elapsed base startup receipts were written on. The owning
    /// storage re-anchors its serving clock to this origin so cache seconds
    /// continue seamlessly from startup into serving (one anchor, 1cws M2r).
    pub(crate) const fn window_start(&self) -> Instant {
        self.start
    }

    /// Drains the accumulated degraded-mode enter and exit crossings for the
    /// owning storage to fold into the monitor's `rd` fact, resetting the
    /// pending count to zero for the next window or serving turn.
    pub(crate) fn take_resolver_transitions(&mut self) -> usize {
        std::mem::take(&mut self.resolver_transitions)
    }

    /// Drains the accumulated DoT→plain downgrade relocations for the owning
    /// storage to fold into the monitor's `dp` fact, resetting the pending
    /// count to zero for the next window or serving turn.
    pub(crate) fn take_downgrade_to_plain(&mut self) -> usize {
        std::mem::take(&mut self.downgrade_to_plain)
    }

    /// Drains the accumulated post-window probe-sweep relocations for the
    /// owning storage to fold into the monitor's `pr` fact, resetting the
    /// pending count to zero for the next window or serving turn.
    pub(crate) fn take_probe_relocations(&mut self) -> usize {
        std::mem::take(&mut self.probe_relocations)
    }

    /// Drains the accumulated pin-branch expired/not-yet-valid certificate
    /// warnings for the owning storage to fold into the monitor's `ep` fact,
    /// resetting the pending count to zero for the next window or serving
    /// turn.
    pub(crate) fn take_expired_pin_certs(&mut self) -> usize {
        std::mem::take(&mut self.expired_pin_certs)
    }

    /// Drains the accumulated sustained-negative incident opens and closes for
    /// the owning storage to fold into the monitor's `sn=` level, resetting
    /// both pending counts to zero for the next window or serving turn.
    pub(crate) fn take_incident_transitions(&mut self) -> (usize, usize) {
        (
            std::mem::take(&mut self.incident_opens),
            std::mem::take(&mut self.incident_closes),
        )
    }

    /// Drains the accumulated per-type exchange-failure incident notes for the
    /// owning serving runtime to emit into the log pipeline, resetting the
    /// fixed two-slot buffer to empty for the next serving turn.
    pub(crate) fn take_incident_notes(&mut self) -> [Option<IncidentNote>; 2] {
        std::mem::take(&mut self.pending_incident_notes)
    }

    /// Seats one incident note into the first empty slot of the fixed
    /// two-slot buffer. The buffer never fills in a serving turn (one exchange
    /// concludes per turn); a full buffer drops the note rather than allocate.
    fn note_incident(&mut self, note: IncidentNote) {
        for slot in &mut self.pending_incident_notes {
            if slot.is_none() {
                *slot = Some(note);
                return;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn resolver_degraded_for_test(&self) -> bool {
        self.degradations[self.active_resolver.index()] == ResolverDegradation::Degraded
    }

    /// Starts a startup window on the retained transport without owning the
    /// wait: it anchors the DNS epoch and monotonic origin, seats the failover
    /// state machine onto the configured resolver set with the primary active,
    /// pins the nameserver peer seed, and returns the absolute window
    /// deadline. From here the shared owner drives selection and cooperative
    /// exchanges over the serving poll and reports through
    /// [`Self::finalize_window`]; the private driver uses the same anchor
    /// inside [`Self::resolve_window`].
    pub(crate) fn begin_window(
        &mut self,
        nameserver: SocketAddr,
        resolvers: ResolverSet,
        now0: u64,
        window: Duration,
    ) -> Result<Instant, StartupDnsError> {
        self.now0 = now0;
        self.start = Instant::now();
        let deadline = self
            .start
            .checked_add(window)
            .ok_or(StartupDnsError::DeadlineOverflow)?;
        self.addr = nameserver;
        self.resolvers = Some(resolvers);
        self.active_resolver = ActiveResolver::primary(resolvers.len());
        self.mark_window_exercised(self.active_resolver);
        self.tls_target = resolvers.primary().fqdn().map(|fqdn| TlsTarget {
            fqdn: *fqdn,
            pin: resolvers.primary().pin().copied(),
        });
        Ok(deadline)
    }

    /// The bounded wait the shared owner folds into its single serving poll
    /// between startup selections: the earliest scheduled step among
    /// not-yet-usable names (with the one-second start guard and floor), or
    /// the maximum wait when nothing is scheduled, so the poll only sleeps to
    /// the clipped window deadline instead of deciding early.
    pub(crate) fn next_due_wait(
        &self,
        schedules: &Schedules,
        ledger: &WindowLedger,
    ) -> Result<Duration, StartupDnsError> {
        wait_until_next_step(self, schedules, ledger.names(), ledger.resolved())
    }

    /// The outstanding exchange ordinal and family, captured together for a
    /// shared owner settling a concluded exchange against its ledger.
    pub(crate) fn active_identity(&self) -> Option<(usize, Family)> {
        self.active.as_ref().map(|ex| (ex.ordinal, ex.family))
    }

    /// Whether the outstanding exchange was started by the serving runtime
    /// rather than the startup window, for the runtime-boundary guard that a
    /// retained startup exchange must not survive into serving.
    #[cfg(test)]
    pub(crate) fn active_is_serving(&self) -> bool {
        self.active.as_ref().is_some_and(|ex| ex.serving)
    }

    /// The configured resolver set, for the serving owner to fold per-resolver
    /// verdicts into the `resolver_probe` log record. `None` before any window.
    pub(crate) const fn resolvers(&self) -> Option<ResolverSet> {
        self.resolvers
    }

    /// Closes the transport connection exactly once. In private mode the
    /// source is deregistered against the DNS-private poll; a `NotFound`
    /// deregister is the benign already-closed case, any other failure is
    /// surfaced as a lifecycle `Transport` error because it leaks a registry
    /// registration. In shared mode the socket belongs to the owner's registry:
    /// dropping it is the deregistration at the kernel layer (closing the fd
    /// removes it from any poll set, and mio keeps no token-keyed table), so
    /// the same token is reusable on a fresh source and `armed` clears to keep
    /// the registration state consistent with the closed stream.
    fn close_connection(&mut self) -> Result<(), StartupDnsError> {
        let mut deregister_error = None;
        if let Some(conn) = self.conn.take() {
            let mut stream = match conn {
                DnsConn::Plain(stream) => stream,
                DnsConn::Tls(conn) => conn.tcp,
            };
            match &mut self.registration {
                Registration::Private => match self.poll.registry().deregister(&mut stream) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => deregister_error = Some(e.kind()),
                },
                Registration::Shared { armed, .. } => {
                    *armed = None;
                }
            }
        } else if let Registration::Shared { armed, .. } = &mut self.registration {
            *armed = None;
        }
        self.filled = 0;
        self.written = 0;
        self.msglen = None;
        if let Some(kind) = deregister_error {
            return Err(StartupDnsError::Transport {
                kind,
                detail: "deregister",
            });
        }
        Ok(())
    }

    fn next_token(&mut self) -> Result<Token, StartupDnsError> {
        self.token_gen = self
            .token_gen
            .checked_add(1)
            .ok_or(StartupDnsError::TokenExhausted)?;
        Ok(Token(self.token_gen))
    }

    /// Cancels the retained transport for owner shutdown: the outstanding
    /// exchange is cleared (no deadline or active-exchange predicate remains
    /// to keep the shared poll hot) and the connection closed exactly once.
    /// In shared mode closing the fd removes the source from the owner's poll
    /// set at the kernel layer; the retained transport and its heap stay owned
    /// until process exit, so the cancellation is infallible rather than
    /// surfacing a deregistration bookkeeping error on an abandoned socket
    /// that would otherwise turn a clean drain into a forced failure.
    pub(crate) fn cancel_for_shutdown(&mut self) {
        self.active = None;
        self.conn = None;
        if let Registration::Shared { armed, .. } = &mut self.registration {
            *armed = None;
        }
        self.filled = 0;
        self.written = 0;
        self.msglen = None;
        self.probe_sweep = None;
        self.corroboration = None;
        self.corroboration_outcome = None;
        self.corroboration_pending = None;
    }

    /// Marks the outstanding exchange as a serving-runtime refresh, so the
    /// runtime-boundary guard ([`Self::cancel_retained_startup_exchange`])
    /// never cancels a refresh the serving runtime owns. A no-op when idle;
    /// the startup window never calls this, so a retained startup exchange
    /// stays distinguishable from a serving refresh.
    pub(crate) const fn mark_serving_started(&mut self) {
        if let Some(ex) = self.active.as_mut() {
            ex.serving = true;
        }
    }

    /// Marks the outstanding exchange as a post-window probe, so the receive
    /// step discards the name outcome instead of publishing name-authorization
    /// state. A no-op when idle; only the probe sweep calls this, so a probe
    /// stays distinguishable from a startup or serving exchange.
    pub(crate) const fn mark_probe_started(&mut self) {
        if let Some(ex) = self.active.as_mut() {
            ex.probe = true;
        }
    }

    /// Cancels a retained startup exchange whose window already expired: the
    /// serving runtime must never advance or publish it
    /// (docs/alumina-proxy.md:64-65). The discriminator targets only a
    /// genuinely-startup exchange — one that is neither a serving refresh nor a
    /// post-window probe — so a serving-runtime refresh, a probe-sweep probe,
    /// and a corroboration exchange (all owned by the serving path) are never
    /// cancelled here, and the refresh schedule is left untouched — the startup
    /// window already released the in-flight selection on the expiry path, so
    /// no stuck-pending slot can block a later refresh.
    pub(crate) fn cancel_retained_startup_exchange(&mut self) {
        if self
            .active
            .as_ref()
            .is_some_and(|ex| !ex.serving && !ex.probe)
        {
            self.cancel_for_shutdown();
        }
    }

    /// Test-only readiness probe on the retained shared stream: true only once
    /// the owner-side socket has response bytes queued that the window has not
    /// yet read. Uses a nonblocking `peek` (never consumes data), so `Ok(n) if
    /// n > 0` holds exactly for queued bytes — unlike a raw `poll` readiness
    /// bit, which stays set on POLLHUP/POLLERR once the responder drops its
    /// socket after the write-ack.
    #[cfg(test)]
    pub(crate) fn test_fd_readable(&self) -> bool {
        let Some(stream) = raw_stream_ref(&self.conn) else {
            return false;
        };
        let mut probe = [0u8; 1];
        matches!(stream.peek(&mut probe), Ok(n) if n > 0)
    }

    /// Test-only stage probe: whether the active exchange has sent its full
    /// query and is awaiting the response (the responder withholds answers
    /// only once a query is on the wire).
    #[cfg(test)]
    pub(crate) fn test_active_receiving(&self) -> bool {
        matches!(
            self.active.as_ref(),
            Some(ex) if ex.step == ExchangeStep::Receiving
        )
    }

    /// Performs the nonblocking connect and registers the source, leaving the
    /// connection to be completed by [`Self::step_connect`] turns. A
    /// synchronous connect error is returned so the caller can defer it to the
    /// first connecting turn, where it settles as the counted failure it is
    /// rather than aborting.
    fn begin_connect(
        &mut self,
        addr: SocketAddr,
    ) -> Result<Option<io::ErrorKind>, StartupDnsError> {
        let watch = self.next_token()?;
        let mut stream = match TcpStream::connect(addr) {
            Ok(stream) => stream,
            Err(e) => return Ok(Some(e.kind())),
        };
        self.watch = watch;
        match &mut self.registration {
            Registration::Private => {
                self.poll
                    .registry()
                    .register(
                        &mut stream,
                        watch,
                        Interest::READABLE.add(Interest::WRITABLE),
                    )
                    .map_err(|e| StartupDnsError::Transport {
                        kind: e.kind(),
                        detail: "register",
                    })?;
            }
            Registration::Shared { armed, .. } => {
                *armed = None;
            }
        }
        self.conn = Some(DnsConn::Plain(stream));
        Ok(None)
    }

    /// Restricts the registered interest to reads, so the owner's single wait
    /// wakes only for response data (or EOF), never on the always-ready
    /// writable edge once the query is fully sent.
    fn set_stream_interest_readable(&mut self) -> Result<(), StartupDnsError> {
        let Some(stream) = raw_stream(&mut self.conn) else {
            return Ok(());
        };
        if matches!(self.registration, Registration::Shared { .. }) {
            return Ok(());
        }
        self.poll
            .registry()
            .reregister(stream, self.watch, Interest::READABLE)
            .map_err(|e| StartupDnsError::Transport {
                kind: e.kind(),
                detail: "reregister",
            })
    }

    /// Re-arms the writable interest when a would-block send moves the
    /// exchange to `AwaitWritable`. Re-arming after `EAGAIN` is the standard
    /// event-loop idiom: it makes the owner's subsequent poll deterministically
    /// wait on the writable edge even if an earlier writable event was consumed
    /// by the completed connect. Drops the readable interest because no
    /// response can arrive before the query is fully written.
    fn set_stream_interest_writable(&mut self) -> Result<(), StartupDnsError> {
        let Some(stream) = raw_stream(&mut self.conn) else {
            return Ok(());
        };
        if matches!(self.registration, Registration::Shared { .. }) {
            return Ok(());
        }
        self.poll
            .registry()
            .reregister(stream, self.watch, Interest::WRITABLE)
            .map_err(|e| StartupDnsError::Transport {
                kind: e.kind(),
                detail: "reregister",
            })
    }

    /// The absolute deadline of the outstanding exchange, or `None` when idle.
    /// An owner that waits on more than one source folds this into its single
    /// earliest-deadline wait.
    pub(crate) fn exchange_deadline(&self) -> Option<Instant> {
        self.active.as_ref().map(|ex| ex.deadline)
    }

    /// Whether an exchange is currently in progress, so a shared owner can
    /// decide whether DNS work is due without treating idle as an error.
    pub(crate) const fn has_active_exchange(&self) -> bool {
        self.active.is_some()
    }

    /// The allowlist ordinal of the outstanding exchange, for the owner to
    /// recover the query name from the configuration and cache.
    pub(crate) fn active_ordinal(&self) -> Option<usize> {
        self.active.as_ref().map(|ex| ex.ordinal)
    }

    /// The allowlist ordinal of a latched corroboration request, for the
    /// serving owner to recover the query name from the configuration before
    /// beginning the corroboration exchange (alox18).
    pub(crate) fn corroboration_pending_ordinal(&self) -> Option<usize> {
        self.corroboration_pending.map(|pending| pending.ordinal)
    }

    /// The stage of the outstanding exchange, for the shared owner to observe
    /// progress (e.g. that a query has been fully written and the exchange
    /// awaits a response).
    #[cfg(test)]
    pub(crate) fn exchange_step(&self) -> Option<ExchangeStep> {
        self.active.as_ref().map(|ex| ex.step)
    }

    /// The transport peer the next exchange dials: the active resolver's
    /// address, seeded at window begin and relocated by failover and failback.
    #[cfg(test)]
    pub(crate) const fn peer(&self) -> SocketAddr {
        self.addr
    }

    /// Test-only peer seed for the loopback injection seam: the serving tests
    /// that short-circuit the startup window point the transport at a local
    /// responder directly, since the configured resolver set always dials
    /// port 53. Mirrors the pre-window single-resolver state, where the peer
    /// is the caller's injected address and no configured set is consulted.
    #[cfg(test)]
    pub(crate) const fn set_peer_for_test(&mut self, addr: SocketAddr) {
        self.addr = addr;
        self.tls_target = None;
    }

    /// Whether a completed nonblocking connect landed on the configured
    /// transport peer. Under test the seam can force a mismatch so the
    /// resolver-peer-anomaly branch is exercised end to end (vec-22).
    #[cfg(test)]
    pub(crate) fn peer_matches(&self, peer: SocketAddr) -> bool {
        !self.force_peer_mismatch && peer == self.addr
    }

    /// Records a DNS anomaly by kind on the retained transport, saturating so
    /// a pathological upstream can never wrap the drain.
    pub(crate) const fn note_dns_anomaly(&mut self, kind: DnsAnomalyKind) {
        self.dns_anomalies[kind.index()] = self.dns_anomalies[kind.index()].saturating_add(1);
    }

    /// Drains every accumulated DNS anomaly into a fixed slice, leaving the
    /// retained transport clean so the next drain never double-counts.
    pub(crate) fn take_dns_anomalies(&mut self) -> [u32; DnsAnomalyKind::COUNT] {
        std::mem::take(&mut self.dns_anomalies)
    }

    /// Registers the retained transport with an external single-poll owner so
    /// DNS freshness joins traffic readiness in one wait. The private poll is
    /// bypassed from here on: the shared registry is the source's only
    /// registry. The transport must hold no open connection (the startup path
    /// closes before transfer); attaching one still bound to the private poll
    /// is refused as [`StartupDnsError::SharedAttachConflict`] rather than
    /// double-registering a source.
    ///
    /// # Errors
    ///
    /// Returns `SharedAttachConflict` when the transport holds an open
    /// connection, and `Transport` when the external registration fails.
    pub(crate) fn attach_shared(
        &mut self,
        registry: &Registry,
        token: Token,
    ) -> Result<(), StartupDnsError> {
        if matches!(self.registration, Registration::Shared { .. }) {
            return Ok(());
        }
        if self.conn.is_some() {
            return Err(StartupDnsError::SharedAttachConflict);
        }
        self.registration = Registration::Shared { token, armed: None };
        self.sync_shared(registry)
    }

    /// Re-aligns the shared registration to the current exchange phase: it
    /// registers the transport the first time it is observed, re-registers it
    /// only when the phase's desired interest changes, and deregisters
    /// (or no-ops after a close) when the exchange is idle. Calling every
    /// turn is cheap: an unchanged interest performs no syscall, so an idle or
    /// quiet owner never spins a permanently-ready socket.
    ///
    /// # Errors
    ///
    /// Returns `Transport` when the external registration, re-registration, or
    /// deregistration fails.
    pub(crate) fn sync_shared(&mut self, registry: &Registry) -> Result<(), StartupDnsError> {
        if !matches!(self.registration, Registration::Shared { .. }) {
            return Ok(());
        }
        let desired = self.shared_desired_interest();
        let (token, armed) = match &mut self.registration {
            Registration::Shared { token, armed } => (*token, armed),
            Registration::Private => return Ok(()),
        };
        let Some(stream) = raw_stream(&mut self.conn) else {
            *armed = None;
            return Ok(());
        };
        if *armed == desired {
            return Ok(());
        }
        let was_armed = *armed;
        match desired {
            Some(interest) => {
                let result = if was_armed.is_some() {
                    registry.reregister(stream, token, interest)
                } else {
                    registry.register(stream, token, interest)
                };
                result.map_err(|e| StartupDnsError::Transport {
                    kind: e.kind(),
                    detail: "shared",
                })?;
            }
            None => {
                registry
                    .deregister(stream)
                    .map_err(|e| StartupDnsError::Transport {
                        kind: e.kind(),
                        detail: "deregister",
                    })?;
            }
        }
        *armed = desired;
        Ok(())
    }

    /// The interest the shared registry must currently arm for the exchange
    /// phase: `None` while idle so an owner never waits on a retained socket,
    /// the writable edge while connecting or backpressured, the readable edge
    /// while awaiting a response, and both while the next write can proceed on
    /// its own.
    fn shared_desired_interest(&self) -> Option<Interest> {
        match self.active.as_ref().map(|ex| ex.step) {
            Some(ExchangeStep::TlsHandshake | ExchangeStep::SendReady) => {
                Some(Interest::READABLE | Interest::WRITABLE)
            }
            Some(ExchangeStep::Receiving) => Some(Interest::READABLE),
            Some(ExchangeStep::Connecting | ExchangeStep::AwaitWritable) => {
                Some(Interest::WRITABLE)
            }
            None => None,
        }
    }

    #[cfg(test)]
    const fn arm_write(&mut self, force: WriteForce) {
        self.force_write = Some(force);
    }

    #[cfg(test)]
    fn active_step(&self) -> Option<ExchangeStep> {
        self.active.as_ref().map(|ex| ex.step)
    }

    /// Whether the owner must wait for network readiness before advancing the
    /// exchange again. Connecting needs the connect-completion edge;
    /// `AwaitWritable` needs a writable edge after a real would-block send;
    /// Receiving needs response data. `SendReady` never does — the next turn's
    /// nonblocking write attempt proceeds on its own, so the owner yields
    /// instead of blocking on a stale edge; a would-block observed there
    /// transitions the exchange to `AwaitWritable` and arms this wait rather
    /// than spinning on an assumed write window.
    pub(crate) const fn needs_wait(&self) -> bool {
        let Some(ex) = self.active.as_ref() else {
            return false;
        };
        matches!(
            ex.step,
            ExchangeStep::Connecting
                | ExchangeStep::TlsHandshake
                | ExchangeStep::AwaitWritable
                | ExchangeStep::Receiving
        )
    }

    /// The single owner-owned DNS wait: exactly one poll over the DNS-private
    /// registry, with the timeout clipped to `until` and to the outstanding
    /// exchange deadline so the wait never outlives the exchange. This is the
    /// discourse between turns, not part of the turn API, and performs no DNS
    /// work. Returns whether readiness for the DNS source was observed, so a
    /// caller can re-advance immediately; a timeout means re-advance to settle
    /// at the deadline. A turn that needs no readiness (a sendable exchange
    /// whose next write proceeds on its own) yields the owner immediately
    /// instead of blocking on a stale edge; a would-block send has moved the
    /// exchange to `AwaitWritable`, so this wait polls for the writable edge.
    pub(crate) fn wait_dns_readiness(&mut self, until: Instant) -> Result<bool, StartupDnsError> {
        if !self.needs_wait() {
            return Ok(false);
        }
        #[cfg(test)]
        {
            self.poll_ticks += 1;
        }
        let deadline = self.exchange_deadline().unwrap_or(until);
        loop {
            let now = Instant::now();
            let timeout = if now >= deadline || now >= until {
                Duration::ZERO
            } else {
                deadline.min(until).saturating_duration_since(now)
            };
            match self.poll.poll(&mut self.events, Some(timeout)) {
                Ok(()) => break,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) => {
                    return Err(StartupDnsError::Transport {
                        kind: err.kind(),
                        detail: "poll",
                    });
                }
            }
        }
        Ok(self.events.iter().any(|event| event.token() == self.watch))
    }

    /// One nonblocking connect step. The socket is deemed connected only once
    /// `peer_addr` is resolvable (a completed nonblocking connect); the
    /// exchange transitions to sending on the next turn, never in the same
    /// turn that completes the connect.
    fn step_connect(
        &mut self,
        ex: &mut ActiveExchange,
        schedules: &mut Schedules,
    ) -> Result<ConnectStep, StartupDnsError> {
        if let Some(_kind) = ex.connect_err.take() {
            self.close_connection()?;
            let reason = self.note_failure(
                ex.ordinal,
                ex.family,
                ex.probe,
                ex.serving,
                schedules,
                FailureReason::Connect,
            )?;
            return Ok(ConnectStep::Failed(reason));
        }
        match self.probe_connect() {
            ConnectProbe::SocketError => {
                self.close_connection()?;
                let reason = self.note_failure(
                    ex.ordinal,
                    ex.family,
                    ex.probe,
                    ex.serving,
                    schedules,
                    FailureReason::Connect,
                )?;
                return Ok(ConnectStep::Failed(reason));
            }
            ConnectProbe::PeerMismatch => {
                self.close_connection()?;
                self.note_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch);
                let reason = self.note_failure(
                    ex.ordinal,
                    ex.family,
                    ex.probe,
                    ex.serving,
                    schedules,
                    FailureReason::Connect,
                )?;
                return Ok(ConnectStep::Failed(reason));
            }
            ConnectProbe::Connected => {
                let next = if let Some(target) = self.tls_target {
                    if let Some(reason) = self.upgrade_to_tls(ex, schedules, target)? {
                        return Ok(ConnectStep::Failed(reason));
                    }
                    let needs_handshake = matches!(
                        &self.conn,
                        Some(DnsConn::Tls(conn)) if conn.tls.is_handshaking()
                    );
                    if needs_handshake {
                        ExchangeStep::TlsHandshake
                    } else {
                        ExchangeStep::SendReady
                    }
                } else {
                    ExchangeStep::SendReady
                };
                return Ok(ConnectStep::Transition { next });
            }
            ConnectProbe::NotReady => {}
        }
        if Instant::now() >= ex.deadline {
            self.close_connection()?;
            let reason = self.note_failure(
                ex.ordinal,
                ex.family,
                ex.probe,
                ex.serving,
                schedules,
                FailureReason::Timeout,
            )?;
            return Ok(ConnectStep::Failed(reason));
        }
        Ok(ConnectStep::Waiting)
    }

    /// Probes one nonblocking connect: the socket is connected only once
    /// `peer_addr` is resolvable (a completed nonblocking connect), and a
    /// completed connect is checked against the configured transport peer so an
    /// unexpected landing is counted as a resolver-peer anomaly by the caller.
    fn probe_connect(&mut self) -> ConnectProbe {
        let Some(stream) = raw_stream(&mut self.conn) else {
            return ConnectProbe::NotReady;
        };
        if let Ok(Some(_err)) = stream.take_error() {
            return ConnectProbe::SocketError;
        }
        if let Ok(peer) = stream.peer_addr() {
            #[cfg(test)]
            {
                if self.force_peer_mismatch {
                    return ConnectProbe::PeerMismatch;
                }
            }
            return if peer == self.addr {
                ConnectProbe::Connected
            } else {
                ConnectProbe::PeerMismatch
            };
        }
        ConnectProbe::NotReady
    }

    /// Upgrades an established plain TCP connection to the `DoT` TLS layer: the
    /// rustls client connection is built against the target (the bounded
    /// per-connect `DoT` setup allocations) and the retained connection becomes
    /// a [`DnsConn::Tls`]. A build failure settles as a counted connect
    /// failure; the upgrade never downgrades back to plain text.
    fn upgrade_to_tls(
        &mut self,
        ex: &mut ActiveExchange,
        schedules: &mut Schedules,
        target: TlsTarget,
    ) -> Result<Option<FailureReason>, StartupDnsError> {
        let tcp = match self.conn.take() {
            Some(DnsConn::Plain(stream)) => stream,
            other => {
                self.conn = other;
                return Ok(None);
            }
        };
        let expired_pin_certs = Arc::new(AtomicU32::new(0));
        if let Ok(conn) = build_tls_connection(target, Arc::clone(&expired_pin_certs)) {
            self.conn = Some(DnsConn::Tls(TlsConn {
                tcp,
                tls: Box::new(conn),
                expired_pin_certs,
            }));
            self.probe_tls_handshake();
            Ok(None)
        } else {
            self.close_connection()?;
            let reason = self.note_failure(
                ex.ordinal,
                ex.family,
                ex.probe,
                ex.serving,
                schedules,
                FailureReason::TlsIdentity,
            )?;
            Ok(Some(reason))
        }
    }

    /// One nonblocking `DoT` TLS-handshake step: at most one read and one write
    /// pass, then readiness is re-checked and the exchange deadline honoured.
    /// A failure (certificate/identity rejection, alert, EOF, socket error) is
    /// settled as a counted connect failure, not an abort.
    fn step_handshake(
        &mut self,
        ex: &mut ActiveExchange,
        schedules: &mut Schedules,
    ) -> Result<HandshakeStep, StartupDnsError> {
        match self.probe_tls_handshake() {
            HandshakeProbe::Waiting => {}
            HandshakeProbe::Transition => return Ok(HandshakeStep::Transition),
            HandshakeProbe::Failed => {
                self.close_connection()?;
                let reason = self.note_failure(
                    ex.ordinal,
                    ex.family,
                    ex.probe,
                    ex.serving,
                    schedules,
                    FailureReason::TlsIdentity,
                )?;
                return Ok(HandshakeStep::Failed(reason));
            }
        }
        if Instant::now() >= ex.deadline {
            self.close_connection()?;
            let reason = self.note_failure(
                ex.ordinal,
                ex.family,
                ex.probe,
                ex.serving,
                schedules,
                FailureReason::Timeout,
            )?;
            return Ok(HandshakeStep::Failed(reason));
        }
        Ok(HandshakeStep::Waiting)
    }

    /// Probes one nonblocking handshake pass: pending outbound flights (the
    /// initial `ClientHello` on the first turn, later client flights after
    /// processing server records) are drained, then one `read_tls` attempt is
    /// processed. A `WouldBlock` on either side leaves the exchange waiting on
    /// the armed socket edges; the handshake completes once rustls reports it
    /// `is_handshaking() == false`.
    fn probe_tls_handshake(&mut self) -> HandshakeProbe {
        let Some(DnsConn::Tls(conn)) = self.conn.as_mut() else {
            return HandshakeProbe::Failed;
        };
        let mut write_blocked = false;
        loop {
            match conn.tls.write_tls(&mut conn.tcp) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    write_blocked = true;
                    break;
                }
                Err(_) => return HandshakeProbe::Failed,
                Ok(_) => {}
            }
            if !conn.tls.wants_write() {
                break;
            }
        }
        if !write_blocked {
            match conn.tls.read_tls(&mut conn.tcp) {
                Ok(0) => {
                    return HandshakeProbe::Failed;
                }
                Ok(_n) => {
                    if conn.tls.process_new_packets().is_err() {
                        return HandshakeProbe::Failed;
                    }
                    loop {
                        match conn.tls.write_tls(&mut conn.tcp) {
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => return HandshakeProbe::Failed,
                            Ok(_) => {}
                        }
                        if !conn.tls.wants_write() {
                            break;
                        }
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    return HandshakeProbe::Failed;
                }
            }
        }
        if conn.tls.is_handshaking() {
            HandshakeProbe::Waiting
        } else {
            self.expired_pin_certs += conn.expired_pin_certs.swap(0, Ordering::Relaxed) as usize;
            HandshakeProbe::Transition
        }
    }

    /// One nonblocking query-write step, routing by transport: `DoT` connections
    /// write through the TLS writer via [`Self::step_send_tls`]; plain TCP
    /// connections write the raw length-prefixed query via
    /// [`Self::step_send_plain`].
    fn step_send(
        &mut self,
        ex: &mut ActiveExchange,
        schedules: &mut Schedules,
    ) -> Result<SendStep, StartupDnsError> {
        if matches!(self.conn, Some(DnsConn::Tls(_))) {
            return self.step_send_tls(ex, schedules);
        }
        self.step_send_plain(ex, schedules)
    }

    /// One nonblocking plain query-write step: at most one write attempt, then
    /// the deadline is checked before yielding so a completed write is
    /// honoured even at the boundary (faithful to the original `send_query`
    /// loop). A would-block is reported as `Blocked` so the stage moves to
    /// `AwaitWritable`; any other partial progress stays sendable.
    #[expect(
        clippy::too_many_lines,
        reason = "faithful plain-write loop with test force-write scaffolding; each failure arm threads the counted reason"
    )]
    fn step_send_plain(
        &mut self,
        ex: &mut ActiveExchange,
        schedules: &mut Schedules,
    ) -> Result<SendStep, StartupDnsError> {
        let mut blocked = false;
        #[cfg(test)]
        let mut forced_partial = 0usize;
        #[cfg(test)]
        {
            if let Some(force) = self.force_write.take() {
                blocked = true;
                if let (Some(stream), WriteForce::Partial(n)) =
                    (plain_stream(&mut self.conn), force)
                {
                    let end = (self.written + n).min(ex.qlen);
                    if end > self.written {
                        match stream.write(&self.query_buf[self.written..end]) {
                            Ok(0) => {
                                self.close_connection()?;
                                let reason = self.note_failure(
                                    ex.ordinal,
                                    ex.family,
                                    ex.probe,
                                    ex.serving,
                                    schedules,
                                    FailureReason::Send,
                                )?;
                                return Ok(SendStep::Failed(reason));
                            }
                            Ok(w) => {
                                self.written += w;
                                forced_partial = w;
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                            Err(_) => {
                                self.close_connection()?;
                                let reason = self.note_failure(
                                    ex.ordinal,
                                    ex.family,
                                    ex.probe,
                                    ex.serving,
                                    schedules,
                                    FailureReason::Send,
                                )?;
                                return Ok(SendStep::Failed(reason));
                            }
                        }
                    }
                }
            }
        }
        if !blocked && self.written < ex.qlen {
            if let Some(stream) = plain_stream(&mut self.conn) {
                match stream.write(&self.query_buf[self.written..ex.qlen]) {
                    Ok(0) => {
                        self.close_connection()?;
                        let reason = self.note_failure(
                            ex.ordinal,
                            ex.family,
                            ex.probe,
                            ex.serving,
                            schedules,
                            FailureReason::Send,
                        )?;
                        return Ok(SendStep::Failed(reason));
                    }
                    Ok(n) => {
                        self.written += n;
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted =>
                    {
                        blocked = true;
                    }
                    Err(_) => {
                        self.close_connection()?;
                        let reason = self.note_failure(
                            ex.ordinal,
                            ex.family,
                            ex.probe,
                            ex.serving,
                            schedules,
                            FailureReason::Send,
                        )?;
                        return Ok(SendStep::Failed(reason));
                    }
                }
            } else {
                self.close_connection()?;
                let reason = self.note_failure(
                    ex.ordinal,
                    ex.family,
                    ex.probe,
                    ex.serving,
                    schedules,
                    FailureReason::Send,
                )?;
                return Ok(SendStep::Failed(reason));
            }
        }
        if self.written >= ex.qlen {
            self.set_stream_interest_readable()?;
            return Ok(SendStep::Transition);
        }
        if Instant::now() >= ex.deadline {
            self.close_connection()?;
            let reason = self.note_failure(
                ex.ordinal,
                ex.family,
                ex.probe,
                ex.serving,
                schedules,
                FailureReason::Timeout,
            )?;
            return Ok(SendStep::Failed(reason));
        }
        if blocked {
            #[cfg(test)]
            {
                if forced_partial > 0 {
                    return Ok(SendStep::Waiting);
                }
            }
            self.set_stream_interest_writable()?;
            return Ok(SendStep::Blocked);
        }
        Ok(SendStep::Waiting)
    }

    /// One nonblocking `DoT` query-write step: the remaining length-prefixed
    /// plaintext is buffered through the rustls writer and the resulting
    /// outbound ciphertext flushed to the socket, honouring the exchange
    /// deadline. A would-block on either side is backpressure; a writer or
    /// socket error settles as a counted send failure.
    fn step_send_tls(
        &mut self,
        ex: &mut ActiveExchange,
        schedules: &mut Schedules,
    ) -> Result<SendStep, StartupDnsError> {
        let probe = match &mut self.conn {
            Some(DnsConn::Tls(conn)) => tls_send_probe(
                &self.query_buf[..ex.qlen],
                &mut self.written,
                &mut conn.tcp,
                &mut conn.tls,
            ),
            _ => TlsSendProbe::Fail,
        };
        match probe {
            TlsSendProbe::Fail => self.fail_send(ex, schedules),
            TlsSendProbe::Blocked => {
                self.set_stream_interest_writable()?;
                if Instant::now() >= ex.deadline {
                    self.close_connection()?;
                    let reason = self.note_failure(
                        ex.ordinal,
                        ex.family,
                        ex.probe,
                        ex.serving,
                        schedules,
                        FailureReason::Timeout,
                    )?;
                    return Ok(SendStep::Failed(reason));
                }
                Ok(SendStep::Blocked)
            }
            TlsSendProbe::Progress => {
                if Instant::now() >= ex.deadline {
                    self.close_connection()?;
                    let reason = self.note_failure(
                        ex.ordinal,
                        ex.family,
                        ex.probe,
                        ex.serving,
                        schedules,
                        FailureReason::Timeout,
                    )?;
                    return Ok(SendStep::Failed(reason));
                }
                Ok(SendStep::Waiting)
            }
            TlsSendProbe::Complete => {
                self.set_stream_interest_readable()?;
                Ok(SendStep::Transition)
            }
        }
    }

    /// Settles a counted send failure: closes the connection exactly once and
    /// advances the schedule backoff for the send reason.
    fn fail_send(
        &mut self,
        ex: &mut ActiveExchange,
        schedules: &mut Schedules,
    ) -> Result<SendStep, StartupDnsError> {
        self.close_connection()?;
        let reason = self.note_failure(
            ex.ordinal,
            ex.family,
            ex.probe,
            ex.serving,
            schedules,
            FailureReason::Send,
        )?;
        Ok(SendStep::Failed(reason))
    }

    /// One nonblocking response-read step: at most one read, then a complete
    /// validated message is published; an API/EOF/deadline failure settles the
    /// counted failure and closes the connection exactly once.
    #[expect(
        clippy::too_many_lines,
        reason = "faithful response-read step threading the counted reason through every failure arm plus the probe/name publish gate"
    )]
    fn step_recv(
        &mut self,
        ex: &mut ActiveExchange,
        fqdn: &Fqdn,
        cache: &mut Cache,
        schedules: &mut Schedules,
    ) -> Result<RecvStep, StartupDnsError> {
        let want = self.msglen.map_or(2, |len| len + 2);
        if self.filled < want {
            match self.try_recv() {
                RecvTry::Failure => {
                    self.close_connection()?;
                    let reason = self.note_failure(
                        ex.ordinal,
                        ex.family,
                        ex.probe,
                        ex.serving,
                        schedules,
                        FailureReason::Receive,
                    )?;
                    return Ok(RecvStep::Failed(reason));
                }
                RecvTry::Wait | RecvTry::Progress => {}
            }
        }
        if self.msglen.is_none() && self.filled >= 2 {
            let len = usize::from(u16::from_be_bytes([self.recv_buf[0], self.recv_buf[1]]));
            if len == 0 || len > DNS_MSG_LIMIT {
                self.close_connection()?;
                let reason = self.note_failure(
                    ex.ordinal,
                    ex.family,
                    ex.probe,
                    ex.serving,
                    schedules,
                    FailureReason::Receive,
                )?;
                return Ok(RecvStep::Failed(reason));
            }
            self.msglen = Some(len);
        }
        if let Some(len) = self.msglen
            && self.filled >= len + 2
        {
            let message = &self.recv_buf[2..2 + len];
            let outcome = dns::parse_response(
                &mut self.workspace,
                &self.bailiwick,
                fqdn,
                ex.family,
                ex.tid,
                message,
            );
            self.msglen = None;
            self.filled = 0;
            match outcome {
                Ok(outcome) => {
                    if Instant::now() >= ex.deadline {
                        self.close_connection()?;
                        let reason = self.note_failure(
                            ex.ordinal,
                            ex.family,
                            ex.probe,
                            ex.serving,
                            schedules,
                            FailureReason::Timeout,
                        )?;
                        return Ok(RecvStep::Failed(reason));
                    }
                    let kind = classify_published(&outcome);
                    if ex.probe {
                        if self.workspace.extreme_ttl() {
                            self.note_dns_anomaly(DnsAnomalyKind::ExtremeTtl);
                        }
                        if self.corroboration.is_some() {
                            self.corroboration_outcome = Some(kind);
                        }
                        return Ok(RecvStep::Published(kind));
                    }
                    let receipt = self.now_u64();
                    let incidents = dns::apply_outcome(
                        cache,
                        schedules,
                        ex.ordinal,
                        ex.generation,
                        receipt,
                        self.now_u64(),
                        &outcome,
                    )?;
                    match incidents.sustained {
                        crate::schedule::IncidentTransition::Opened => {
                            self.incident_opens += 1;
                            self.latch_corroboration(ex.ordinal, ex.family);
                        }
                        crate::schedule::IncidentTransition::Closed => self.incident_closes += 1,
                        crate::schedule::IncidentTransition::None => {}
                    }
                    if ex.serving {
                        for (family, transition) in [Family::A, Family::Aaaa]
                            .into_iter()
                            .zip(incidents.per_type)
                        {
                            if let PerTypeTransition::Recovered { duration } = transition {
                                self.note_incident(IncidentNote::Recovered {
                                    ordinal: ex.ordinal,
                                    family,
                                    duration,
                                });
                            }
                        }
                    }
                    if self.workspace.extreme_ttl() {
                        self.note_dns_anomaly(DnsAnomalyKind::ExtremeTtl);
                    }
                    return Ok(RecvStep::Published(kind));
                }
                Err(err) => {
                    if matches!(err, DnsError::BailiwickViolation) {
                        self.note_dns_anomaly(DnsAnomalyKind::BailiwickViolation);
                    }
                    self.close_connection()?;
                    let reason = self.note_failure(
                        ex.ordinal,
                        ex.family,
                        ex.probe,
                        ex.serving,
                        schedules,
                        FailureReason::Receive,
                    )?;
                    return Ok(RecvStep::Failed(reason));
                }
            }
        }
        if Instant::now() >= ex.deadline {
            self.close_connection()?;
            let reason = self.note_failure(
                ex.ordinal,
                ex.family,
                ex.probe,
                ex.serving,
                schedules,
                FailureReason::Timeout,
            )?;
            return Ok(RecvStep::Failed(reason));
        }
        Ok(RecvStep::Waiting)
    }

    /// Fills the fixed receive buffer from the connected transport: plain
    /// connections read the raw socket, `DoT` connections feed `read_tls` through
    /// `process_new_packets` and drain the decrypted plaintext via the reader.
    fn try_recv(&mut self) -> RecvTry {
        match &mut self.conn {
            None => RecvTry::Failure,
            Some(DnsConn::Plain(stream)) => {
                let filled_before = self.filled;
                match stream.read(&mut self.recv_buf[self.filled..]) {
                    Ok(0) => RecvTry::Failure,
                    Ok(n) => {
                        self.filled += n;
                        if self.filled > filled_before {
                            RecvTry::Progress
                        } else {
                            RecvTry::Wait
                        }
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted =>
                    {
                        RecvTry::Wait
                    }
                    Err(_) => RecvTry::Failure,
                }
            }
            Some(DnsConn::Tls(conn)) => {
                let filled_before = self.filled;
                match conn.tls.read_tls(&mut conn.tcp) {
                    Ok(0) => return RecvTry::Failure,
                    Ok(_) => {
                        if conn.tls.process_new_packets().is_err() {
                            return RecvTry::Failure;
                        }
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return RecvTry::Failure,
                }
                loop {
                    match conn.tls.reader().read(&mut self.recv_buf[self.filled..]) {
                        Ok(0) => break,
                        Ok(n) => self.filled += n,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => return RecvTry::Failure,
                    }
                    break;
                }
                if self.filled > filled_before {
                    RecvTry::Progress
                } else {
                    RecvTry::Wait
                }
            }
        }
    }

    /// Single-pass test-support resolution: visits each admitted name and
    /// record type once inside the fixed startup window, with no retries.
    /// This is not the startup policy path — [`Self::resolve_window`] owns the
    /// retrying window with a single clipped deadline. It exists so the
    /// in-crate transport tests can drive deterministic first-attempt
    /// behaviour without the retry schedule.
    ///
    /// # Errors
    ///
    /// Returns an error for a fatal storage, entropy, lifecycle, poll,
    /// deadline, or token-exhaustion failure; resolution aborts rather than
    /// continuing with corrupt or reused state. Counted per-exchange network
    /// failures (connect refused, write failure, socket error, deadline) are
    /// recorded in the returned report and never stop the loop.
    #[cfg(test)]
    fn resolve(
        &mut self,
        config: &Config,
        cache: &mut Cache,
        schedules: &mut Schedules,
        nameserver: SocketAddr,
        now0: u64,
    ) -> Result<StartupReport, StartupDnsError> {
        let null = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .map_err(|_| StartupDnsError::Transport {
                kind: std::io::ErrorKind::Other,
                detail: "test null sink",
            })?;
        let mut logs = log::LogStore::with_fd(&null).expect("null sink store");
        self.resolve_body(config, cache, schedules, nameserver, now0, &mut logs)
    }

    /// The shared test driver body used by [`Self::resolve`], parameterised over
    /// an already-constructed log store so an alloc-witness caller can hoist
    /// the one-time queue reservation (a boot cost, not a per-exchange cost)
    /// outside the measured phase.
    #[cfg(test)]
    fn resolve_body(
        &mut self,
        config: &Config,
        cache: &mut Cache,
        schedules: &mut Schedules,
        nameserver: SocketAddr,
        now0: u64,
        logs: &mut log::LogStore,
    ) -> Result<StartupReport, StartupDnsError> {
        self.now0 = now0;
        self.start = Instant::now();
        let window_deadline = self
            .start
            .checked_add(Duration::from_secs(STARTUP_WINDOW_SECS))
            .ok_or(StartupDnsError::DeadlineOverflow)?;
        self.addr = nameserver;
        self.resolvers = Some(*config.resolver_set());
        self.active_resolver = ActiveResolver::primary(config.resolver_set().len());
        self.mark_window_exercised(self.active_resolver);
        self.tls_target = config
            .resolver_set()
            .primary()
            .fqdn()
            .map(|fqdn| TlsTarget {
                fqdn: *fqdn,
                pin: config.resolver_set().primary().pin().copied(),
            });
        let allowlist = config.allowlist();
        self.bailiwick = BailiwickZones::from_allowlist(allowlist, config.cname_bailiwick())?;
        let names = allowlist.len();
        let mut report = StartupReport::default();
        let mut resolved = [false; ALLOWLIST_MAX];
        let mut latest = [Latest::Unattempted; ALLOWLIST_MAX];

        for (ordinal, name) in allowlist.iter().enumerate() {
            for family in Family::ALL {
                if Instant::now() >= window_deadline {
                    report.not_attempted += 1;
                    continue;
                }
                let name_index = cache
                    .name_index(ordinal)
                    .ok_or(CacheError::NameOutOfRange)?;
                let remaining = window_deadline.duration_since(Instant::now());
                let exchange_deadline =
                    Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS).min(remaining);
                match self.exchange(
                    name,
                    family,
                    ordinal,
                    cache,
                    schedules,
                    exchange_deadline,
                    logs,
                ) {
                    Ok(ExchangeResult::Published(kind)) => {
                        report.exchanges += 1;
                        let has = !cache.entry(name_index, family)?.bindings().is_empty();
                        resolved[ordinal] |= has;
                        latest[ordinal].merge(ExchangeResult::Published(kind));
                    }
                    Ok(ExchangeResult::Failed(reason)) => {
                        report.failed += 1;
                        report.record_first_failure(ordinal, family);
                        latest[ordinal].merge(ExchangeResult::Failed(reason));
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        report.resolved_names = u32::try_from(resolved[..names].iter().filter(|&&r| r).count())
            .expect("resolved count bounded by ALLOWLIST_MAX");
        for ordinal in 0..names {
            report.outcomes[ordinal] = if resolved[ordinal] {
                NameOutcome::Resolved
            } else {
                latest[ordinal].to_outcome()
            };
        }
        self.close_connection()?;
        Ok(report)
    }

    /// Resolves the allowlist inside one absolute startup window whose
    /// monotonic deadline is the single deadline for every exchange. The
    /// schedule due table drives the attempts: each name and family is seeded
    /// due at the window start, a failed lookup is retried on its backoff
    /// ladder with every exchange deadline clipped to the window, and a name
    /// already usable is never re-attempted or refreshed. Returns early once
    /// every name is usable; otherwise returns at the deadline, together with
    /// the whole second count since the window opened at which the caller's
    /// readiness decision is anchored — a single owned anchor, never a second
    /// clock read. Receipts use the process-relative `now0` second scale.
    ///
    /// # Errors
    ///
    /// Returns the underlying fatal storage, entropy, lifecycle, poll, token,
    /// deadline, or schedule error; counted per-exchange network failures are
    /// carried by the report.
    #[expect(
        clippy::too_many_lines,
        reason = "long resolve-window driver covering exchange steps, timeouts, and publish bookkeeping"
    )]
    pub(crate) fn resolve_window(
        &mut self,
        inputs: WindowInputs<'_>,
        logs: &mut log::LogStore,
    ) -> Result<(StartupReport, u64), StartupDnsError> {
        let WindowInputs {
            config,
            cache,
            schedules,
            nameserver,
            now0,
            window,
        } = inputs;
        self.now0 = now0;
        self.start = Instant::now();
        let window_deadline = self
            .start
            .checked_add(window)
            .ok_or(StartupDnsError::DeadlineOverflow)?;
        self.addr = nameserver;
        self.resolvers = Some(*config.resolver_set());
        self.active_resolver = ActiveResolver::primary(config.resolver_set().len());
        self.mark_window_exercised(self.active_resolver);
        self.tls_target = config
            .resolver_set()
            .primary()
            .fqdn()
            .map(|fqdn| TlsTarget {
                fqdn: *fqdn,
                pin: config.resolver_set().primary().pin().copied(),
            });
        let allowlist = config.allowlist();
        self.bailiwick = BailiwickZones::from_allowlist(allowlist, config.cname_bailiwick())?;
        let names = allowlist.len();
        let mut report = StartupReport::default();
        let mut resolved = [false; ALLOWLIST_MAX];
        let mut attempted = [false; ALLOWLIST_MAX * 2];
        let mut latest = [Latest::Unattempted; ALLOWLIST_MAX];

        for ordinal in 0..names {
            for family in Family::ALL {
                schedules.overwrite_due_at(ordinal, family, now0)?;
            }
        }

        loop {
            if resolved[..names].iter().all(|&r| r) {
                break;
            }
            if Instant::now() >= window_deadline {
                break;
            }
            let now = self.now_u64();
            match schedules.select_due(now) {
                Ok(Some(token)) => {
                    let ordinal = token.name();
                    let family = token.family();
                    if resolved[ordinal] {
                        schedules.release_selection(ordinal, family)?;
                        continue;
                    }
                    let Some(name) = allowlist.get(ordinal) else {
                        return Err(StartupDnsError::Cache(CacheError::NameOutOfRange));
                    };
                    let remaining = window_deadline.saturating_duration_since(Instant::now());
                    let exchange_deadline =
                        Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS).min(remaining);
                    let name_index = cache
                        .name_index(ordinal)
                        .ok_or(CacheError::NameOutOfRange)?;
                    attempted[ordinal * 2 + family_index(family)] = true;
                    match self.exchange(
                        name,
                        family,
                        ordinal,
                        cache,
                        schedules,
                        exchange_deadline,
                        logs,
                    ) {
                        Ok(ExchangeResult::Published(kind)) => {
                            report.exchanges += 1;
                            let has = !cache.entry(name_index, family)?.bindings().is_empty();
                            resolved[ordinal] |= has;
                            latest[ordinal].merge(ExchangeResult::Published(kind));
                        }
                        Ok(ExchangeResult::Failed(reason)) => {
                            report.failed += 1;
                            let first = report.first_failure.is_none();
                            report.record_first_failure(ordinal, family);
                            if first {
                                logs.startup_warning(now, name.as_str(), family);
                            }
                            latest[ordinal].merge(ExchangeResult::Failed(reason));
                        }
                        Err(err) => return Err(err),
                    }
                }
                Ok(None) => {
                    let remaining = window_deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    logs.drain_sink();
                    let dns_wait =
                        wait_until_next_step(self, schedules, names, &resolved)?.min(remaining);
                    let now_i = Instant::now();
                    let log_wait = logs
                        .next_drain(now_i)
                        .map(|retry| retry.saturating_duration_since(now_i));
                    let wait = log_wait.map_or(dns_wait, |log_wait| dns_wait.min(log_wait));
                    if wait.is_zero() {
                        continue;
                    }
                    thread::sleep(wait);
                }
                Err(err) => return Err(StartupDnsError::from(err)),
            }
        }
        self.close_connection()?;
        let attempted_count = u32::try_from(attempted[..names * 2].iter().filter(|&&t| t).count())
            .expect("attempted count bounded by ALLOWLIST_MAX * 2");
        report.not_attempted =
            u32::try_from(names * 2).expect("names bounded by ALLOWLIST_MAX") - attempted_count;
        report.resolved_names = u32::try_from(resolved[..names].iter().filter(|&&r| r).count())
            .expect("resolved count bounded by ALLOWLIST_MAX");
        for ordinal in 0..names {
            report.outcomes[ordinal] = if resolved[ordinal] {
                NameOutcome::Resolved
            } else {
                latest[ordinal].to_outcome()
            };
        }
        Ok((report, self.start.elapsed().as_secs()))
    }

    /// Starts a cooperative DNS exchange without waiting for network
    /// readiness: it opens-or-reuses the transport connection, draws a fresh
    /// transaction id, builds the fixed query, and records the exchange
    /// (name/family/absolute deadline) so subsequent
    /// [`Self::advance_exchange`] turns can conclude it. Counted per-exchange
    /// network failures never surface here; they terminate a later turn as
    /// [`TurnResult::Failed`].
    ///
    /// # Errors
    ///
    /// Returns a fatal storage, entropy, lifecycle, poll, deadline, or
    /// token-exhaustion error when the exchange cannot begin; a query build or
    /// registry failure aborts rather than continuing with corrupt state.
    /// Returns [`StartupDnsError::ExchangeActive`] when an exchange is already
    /// in progress, leaving the outstanding exchange, its schedule accounting,
    /// and its connection untouched.
    pub(crate) fn start_exchange(
        &mut self,
        fqdn: &Fqdn,
        family: Family,
        ordinal: usize,
        deadline: Instant,
        generation: Generation,
    ) -> Result<(), StartupDnsError> {
        if self.active.is_some() {
            return Err(StartupDnsError::ExchangeActive);
        }
        self.maybe_begin_failback()?;
        let connect_err = if self.conn.is_none() {
            self.begin_connect(self.addr)?
        } else {
            None
        };
        let tid = Self::fresh_tid()?;
        let qlen = dns::build_query(fqdn, family, tid, &mut self.query_buf[2..])?;
        let total = qlen + 2;
        let wire_len = u16::try_from(qlen).expect("dns query length fits u16 prefix");
        self.query_buf[..2].copy_from_slice(&wire_len.to_be_bytes());
        self.written = 0;
        self.filled = 0;
        self.msglen = None;
        self.active = Some(ActiveExchange {
            ordinal,
            family,
            deadline,
            step: ExchangeStep::Connecting,
            qlen: total,
            connect_err,
            tid,
            serving: false,
            probe: false,
            generation,
        });
        Ok(())
    }

    /// Advances the in-progress cooperative exchange by one turn. A turn never
    /// waits: it performs at most one nonblocking I/O attempt and at most one
    /// stage transition, re-checks the absolute exchange deadline, and
    /// otherwise returns [`TurnResult::Pending`] so the single owner keeps
    /// control of all waiting (docs/alumina-proxy.md:146).
    ///
    /// # Errors
    ///
    /// Returns a fatal storage, entropy, lifecycle, poll, deadline, or
    /// token-exhaustion error. Counted per-exchange network failures return
    /// [`TurnResult::Failed`] with the backoff already advanced; an exchange
    /// that is not in progress is a fatal caller error.
    pub(crate) fn advance_exchange(
        &mut self,
        fqdn: &Fqdn,
        cache: &mut Cache,
        schedules: &mut Schedules,
    ) -> Result<TurnResult, StartupDnsError> {
        let Some(mut ex) = self.active.take() else {
            return Err(StartupDnsError::ExchangeInactive);
        };
        let next_step = match ex.step {
            ExchangeStep::Connecting => match self.step_connect(&mut ex, schedules)? {
                ConnectStep::Waiting => None,
                ConnectStep::Transition { next } => Some(next),
                ConnectStep::Failed(reason) => {
                    self.active = None;
                    return Ok(TurnResult::Failed(reason));
                }
            },
            ExchangeStep::TlsHandshake => match self.step_handshake(&mut ex, schedules)? {
                HandshakeStep::Waiting => None,
                HandshakeStep::Transition => Some(ExchangeStep::SendReady),
                HandshakeStep::Failed(reason) => {
                    self.active = None;
                    return Ok(TurnResult::Failed(reason));
                }
            },
            ExchangeStep::SendReady => match self.step_send(&mut ex, schedules)? {
                SendStep::Waiting => None,
                SendStep::Blocked => Some(ExchangeStep::AwaitWritable),
                SendStep::Transition => Some(ExchangeStep::Receiving),
                SendStep::Failed(reason) => {
                    self.active = None;
                    return Ok(TurnResult::Failed(reason));
                }
            },
            ExchangeStep::AwaitWritable => match self.step_send(&mut ex, schedules)? {
                SendStep::Waiting => Some(ExchangeStep::SendReady),
                SendStep::Blocked => None,
                SendStep::Transition => Some(ExchangeStep::Receiving),
                SendStep::Failed(reason) => {
                    self.active = None;
                    return Ok(TurnResult::Failed(reason));
                }
            },
            ExchangeStep::Receiving => match self.step_recv(&mut ex, fqdn, cache, schedules)? {
                RecvStep::Waiting => None,
                RecvStep::Failed(reason) => {
                    self.active = None;
                    return Ok(TurnResult::Failed(reason));
                }
                RecvStep::Published(kind) => {
                    self.active = None;
                    self.on_exchange_succeeded()?;
                    return Ok(TurnResult::Published(kind));
                }
            },
        };
        if let Some(step) = next_step {
            ex.step = step;
        }
        self.active = Some(ex);
        Ok(TurnResult::Pending)
    }

    /// The startup-only blocking driver (nonserving): it starts the exchange
    /// and then owns every wait itself via [`Self::wait_dns_readiness`],
    /// polling the DNS registry once per turn until the exchange concludes
    /// within its single clipped deadline. The boot-owned log store is passed
    /// at this seam so logging steps and the log retry deadline participate in
    /// the same wait without restarting the 90s or 5s deadlines (704q); any
    /// other owner replaces this driver body with a fold of the DNS readiness
    /// and [`Self::exchange_deadline`] into its own combined wait.
    #[expect(
        clippy::too_many_arguments,
        reason = "startup-only blocking driver (2 callsites, startup_dns.rs:1385/1501); params span identity/state/deadline/logs with interleaved &mut cache/schedules/logs — a bundle struct would conceal their ownership"
    )]
    fn exchange(
        &mut self,
        fqdn: &Fqdn,
        family: Family,
        ordinal: usize,
        cache: &mut Cache,
        schedules: &mut Schedules,
        deadline: Instant,
        logs: &mut log::LogStore,
    ) -> Result<ExchangeResult, StartupDnsError> {
        let name_index = cache
            .name_index(ordinal)
            .ok_or(CacheError::NameOutOfRange)?;
        let generation = cache.entry(name_index, family)?.generation();
        self.start_exchange(fqdn, family, ordinal, deadline, generation)?;
        loop {
            match self.advance_exchange(fqdn, cache, schedules)? {
                TurnResult::Pending => {
                    logs.drain_sink();
                    let now = Instant::now();
                    let wake = logs
                        .next_drain(now)
                        .map_or(deadline, |retry| deadline.min(retry));
                    self.wait_dns_readiness(wake)?;
                }
                TurnResult::Published(kind) => {
                    return Ok(ExchangeResult::Published(kind));
                }
                TurnResult::Failed(reason) => {
                    return Ok(ExchangeResult::Failed(reason));
                }
            }
        }
    }

    /// Seats the transport peer to whichever resolver the active index names,
    /// so the next exchange dials the relocated resolver. A transport without
    /// a configured set keeps its seeded peer (the pre-window and loopback
    /// cases), where the active index stays the primary and the peer is the
    /// caller's injected address.
    fn repoint_to_active(&mut self) {
        let Some(set) = self.resolvers else {
            return;
        };
        if let Some(resolver) = set.get(self.active_resolver.index()) {
            self.addr = SocketAddr::new(resolver.addr(), resolver.port());
            self.tls_target = resolver.fqdn().map(|fqdn| TlsTarget {
                fqdn: *fqdn,
                pin: resolver.pin().copied(),
            });
        }
    }

    /// Records that the startup window exercised the given resolver — it became
    /// the active resolver at least once, from the seeded primary through each
    /// failover/failback relocation — so the post-window probe sweep skips it
    /// as already exercised and probes only resolvers the window never touched
    /// (docs/alumina-proxy.md:826).
    const fn mark_window_exercised(&mut self, resolver: ActiveResolver) {
        self.window_exercised[resolver.index()] = true;
    }

    /// The next resolver after the active one, wrapping within the set, that is
    /// not passively degraded. `None` when the set is single-resolver or every
    /// candidate resolver is degraded, in which case the transport stays on the
    /// active resolver and fails closed.
    fn next_healthy_after_active(&self, active: ActiveResolver) -> Option<ActiveResolver> {
        if active.set_len() == 1 {
            return None;
        }
        for step in 1..=active.set_len() {
            let index = (active.index() + step) % active.set_len();
            if self.degradations[index] != ResolverDegradation::Degraded {
                return Some(ActiveResolver::at(index, active.set_len()));
            }
        }
        None
    }

    /// Probes the primary again when the active resolver is not the primary and
    /// the failback grace has elapsed: the transport is closed so the next
    /// exchange dials the primary, with the departed resolver kept as
    /// [`Self::failback_source`] so a failed probe re-seats onto it. Called at
    /// the top of [`Self::start_exchange`] so the probe is the next exchange,
    /// never a background or timer-owned action.
    fn maybe_begin_failback(&mut self) -> Result<(), StartupDnsError> {
        if self.probe_sweep.is_some()
            || self.corroboration_pending.is_some()
            || self.corroboration.is_some()
            || self.active_resolver.is_primary()
            || self.failback_source.is_some()
        {
            return Ok(());
        }
        let Some(due) = self.failback_due else {
            return Ok(());
        };
        if self.now_u64() < due {
            return Ok(());
        }
        let from = self.active_resolver;
        self.close_connection()?;
        self.failback_source = Some(from);
        self.failback_successes = 0;
        let to = ActiveResolver::primary(from.set_len());
        self.note_downgrade_if_dot_to_plain(from, to);
        self.active_resolver = to;
        self.mark_window_exercised(self.active_resolver);
        self.failback_due = None;
        self.repoint_to_active();
        Ok(())
    }

    /// Counts a DoT→plain downgrade when a relocation moves the active
    /// resolver from an `IP#fqdn` entry onto a bare-IP entry, so the monitor
    /// can surface the failover downgrade path (`dp=`). A relocation that keeps
    /// or gains an FQDN is not a downgrade and is not counted.
    fn note_downgrade_if_dot_to_plain(&mut self, from: ActiveResolver, to: ActiveResolver) {
        let from_is_dot = self
            .resolvers
            .as_ref()
            .and_then(|set| set.get(from.index()))
            .is_some_and(|ns| ns.fqdn().is_some());
        let to_is_plain = self
            .resolvers
            .as_ref()
            .and_then(|set| set.get(to.index()))
            .is_some_and(|ns| ns.fqdn().is_none());
        if from_is_dot && to_is_plain {
            self.downgrade_to_plain = self.downgrade_to_plain.saturating_add(1);
        }
    }

    /// Begins the post-window probe sweep exactly once: after the startup
    /// decision, every configured resolver the window did not exercise is
    /// probed once so the operator sees a per-resolver verdict. The sweep is
    /// latched (`sweep_ran`) so it never re-begins on a later turn, deferred
    /// while a failback probe is in flight so the two probes never overlap,
    /// and skipped entirely for a single-resolver set or a missing set.
    pub(crate) fn maybe_begin_sweep(&mut self) {
        if self.sweep_ran || self.probe_sweep.is_some() || self.failback_source.is_some() {
            return;
        }
        let Some(set) = self.resolvers else {
            return;
        };
        if set.len() <= 1 {
            return;
        }
        let mut remaining = [false; MAX_RESOLVERS];
        for (index, _) in set.iter().enumerate() {
            remaining[index] = !self.window_exercised[index];
        }
        self.probe_sweep = Some(ProbeSweep {
            remaining,
            active_before: self.active_resolver,
            verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            current: None,
        });
    }

    /// Whether a post-window probe sweep is currently in progress, so the
    /// serving owner drives the next probe only while one is active.
    pub(crate) const fn sweep_active(&self) -> bool {
        self.probe_sweep.is_some()
    }

    /// Test-only seam seeding the post-window probe sweep directly, so a
    /// serving-loop test can exercise the `sweep_active` deferral guard without
    /// a startup window or a real probe dial. The probe target is seeded
    /// `current`, so `sweep_next_probe` defers; `resolvers` stays `None`, so
    /// `repoint_to_active` never overrides the peer seeded by
    /// `set_peer_for_test`.
    #[cfg(test)]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "test-only probe-sweep seeding seam; constness is not load-bearing"
    )]
    pub(crate) fn seed_probe_sweep_for_test(&mut self) {
        self.probe_sweep = Some(ProbeSweep {
            remaining: [false; MAX_RESOLVERS],
            active_before: self.active_resolver,
            verdicts: [ProbeVerdict::NotProbed; MAX_RESOLVERS],
            current: Some(self.active_resolver),
        });
    }

    /// Test-only seam seeding an in-flight corroboration exchange directly, so
    /// a serving-loop test can exercise the corroboration lifecycle through
    /// `Runtime::turn` without a real sustained-negative incident or a real
    /// dial. The corroboration targets the next resolver after the active one
    /// (a two-resolver set); the peer is overridden separately with
    /// [`Self::set_peer_for_test`], and `resolvers` stays `None` so
    /// `repoint_to_active` never overrides that peer.
    #[cfg(test)]
    pub(crate) fn seed_corroboration_for_test(
        &mut self,
        fqdn: &Fqdn,
    ) -> Result<(), StartupDnsError> {
        let active = ActiveResolver::primary(2);
        let target = ActiveResolver::at(1, 2);
        self.active_resolver = target;
        self.corroboration = Some(Corroboration {
            target,
            active_before: active,
            ordinal: 0,
            family: Family::A,
        });
        self.corroboration_outcome = None;
        let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
        self.start_exchange(fqdn, Family::A, 0, deadline, Generation::INITIAL)?;
        self.mark_probe_started();
        Ok(())
    }

    /// Starts the next probe of the sweep when idle, returning `true` when the
    /// sweep has no unprobed resolver left. The transport is relocated onto the
    /// probe target (closing the retained connection and recording any DoT→plain
    /// downgrade), then a single primary-allowlist `A` exchange begins with the
    /// fixed five-second deadline. While a probe is in flight the call defers
    /// and returns `false`.
    pub(crate) fn sweep_next_probe(&mut self, fqdn: &Fqdn) -> Result<bool, StartupDnsError> {
        let (index, target) = {
            let Some(sweep) = self.probe_sweep.as_ref() else {
                return Ok(true);
            };
            if sweep.current.is_some() || self.active.is_some() {
                return Ok(false);
            }
            let Some(index) = sweep.remaining.iter().position(|&r| r) else {
                return Ok(true);
            };
            let set_len = self.active_resolver.set_len();
            (index, ActiveResolver::at(index, set_len))
        };
        self.relocate_for_probe(target)?;
        let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
        // A probe is a pure sensor that never applies cache state
        // (mark_probe_started sets probe=true; advance_exchange returns
        // RecvStep::Published before the cache apply), so the captured
        // generation is the initial value and is never compared.
        self.start_exchange(fqdn, Family::A, 0, deadline, Generation::INITIAL)?;
        self.mark_probe_started();
        if let Some(sweep) = &mut self.probe_sweep {
            sweep.remaining[index] = false;
            sweep.current = Some(target);
        }
        Ok(false)
    }

    /// Latches a corroboration request when a sustained-negative incident opens
    /// for an admitted name and the resolver set holds at least two resolvers:
    /// the serving owner later cross-checks the active resolver's negative
    /// against a different configured resolver exactly once (alox18). A
    /// single-resolver set has no different resolver to cross-check, and a
    /// pending request is never overwritten or stacked.
    const fn latch_corroboration(&mut self, ordinal: usize, family: Family) {
        if self.corroboration_pending.is_some() {
            return;
        }
        let Some(set) = self.resolvers else {
            return;
        };
        if set.len() <= 1 {
            return;
        }
        self.corroboration_pending = Some(CorroborationPending { ordinal, family });
    }

    /// Begins the single corroboration exchange when a latched request is
    /// pending and the transport is idle, returning `true` when there is
    /// nothing to do (no pending request, a single-resolver set, or a stale
    /// request already concluded). The corroboration targets the next
    /// configured resolver after the active one and runs as a pure-sensor
    /// probe (initial generation, probe flag) so it never applies cache state;
    /// on conclusion the active resolver is restored or its degradation
    /// advanced (alox18). While any exchange or probe is in flight the call
    /// defers and preserves the pending request (single-active guard).
    pub(crate) fn step_corroboration(&mut self, fqdn: &Fqdn) -> Result<bool, StartupDnsError> {
        let Some(pending) = self.corroboration_pending else {
            return Ok(true);
        };
        if self.active.is_some() || self.probe_sweep.is_some() {
            return Ok(false);
        }
        let Some(set) = self.resolvers else {
            self.corroboration_pending = None;
            return Ok(true);
        };
        if set.len() <= 1 {
            self.corroboration_pending = None;
            return Ok(true);
        }
        let active = self.active_resolver;
        let target = ActiveResolver::at((active.index() + 1) % set.len(), set.len());
        self.corroboration_pending = None;
        self.corroboration = Some(Corroboration {
            target,
            active_before: active,
            ordinal: pending.ordinal,
            family: pending.family,
        });
        self.corroboration_outcome = None;
        self.relocate_for_corroboration(target)?;
        let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
        self.start_exchange(
            fqdn,
            pending.family,
            pending.ordinal,
            deadline,
            Generation::INITIAL,
        )?;
        self.mark_probe_started();
        Ok(false)
    }

    /// Relocates the retained transport onto a probe target: the connection is
    /// closed so the next exchange dials the target, the probe relocation is
    /// counted, and the active resolver is re-seated. Used by the post-window
    /// probe sweep; the pre-sweep active resolver is kept by the sweep for
    /// restore.
    fn relocate_for_probe(&mut self, target: ActiveResolver) -> Result<(), StartupDnsError> {
        self.close_connection()?;
        self.probe_relocations = self.probe_relocations.saturating_add(1);
        self.active_resolver = target;
        self.repoint_to_active();
        Ok(())
    }

    /// Relocates the retained transport onto the corroboration target: the
    /// connection is closed so the next exchange dials the target, and the
    /// active resolver is re-seated. Unlike a probe-sweep relocation this is
    /// never counted as a probe relocation — the corroboration is a
    /// serving-owner cross-check against a different configured resolver, not
    /// a post-window probe (alox18).
    fn relocate_for_corroboration(
        &mut self,
        target: ActiveResolver,
    ) -> Result<(), StartupDnsError> {
        self.close_connection()?;
        self.active_resolver = target;
        self.repoint_to_active();
        Ok(())
    }

    /// Takes the accumulated per-resolver verdicts and clears the sweep,
    /// latching it so it never re-begins on a later turn. Called once when the
    /// sweep has no unprobed resolver left; the serving owner folds the
    /// verdicts into a single `resolver_probe` log record.
    pub(crate) fn take_sweep_verdicts(&mut self) -> [ProbeVerdict; MAX_RESOLVERS] {
        self.sweep_ran = true;
        self.probe_sweep
            .take()
            .map_or([ProbeVerdict::NotProbed; MAX_RESOLVERS], |sweep| {
                sweep.verdicts
            })
    }

    /// Concludes the in-flight corroboration exchange from its captured
    /// outcome: a positive with eligible bindings from the different
    /// configured resolver while the active resolver returned a negative is a
    /// conflict — a distinct anomaly fact is emitted, the active resolver's
    /// degradation advances by exactly one counted failure, and a degraded
    /// active resolver relocates to the next healthy resolver (arming failback
    /// grace on a non-primary) while a below-threshold advance leaves it in
    /// place. A consistent negative (or a positive with no eligible bindings)
    /// restores the active resolver with no degradation change and no fact.
    /// The retained corroboration connection is always closed so the next
    /// exchange re-dials the restored or relocated resolver (alox18).
    ///
    /// # Errors
    ///
    /// Returns a lifecycle `Transport` error when the retained corroboration
    /// connection cannot be deregistered; the restore/relocation and any fact
    /// are already recorded before the close is attempted.
    fn conclude_corroboration(&mut self) -> Result<(), StartupDnsError> {
        let Some(corr) = self.corroboration.take() else {
            return Ok(());
        };
        let conflict = self.corroboration_outcome.take() == Some(PublishedKind::ResolvedPositive);
        if conflict {
            self.note_dns_anomaly(DnsAnomalyKind::CorroborationConflict);
            let active_index = corr.active_before.index();
            let was_degraded = self.degradations[active_index] == ResolverDegradation::Degraded;
            self.degradations[active_index] = self.degradations[active_index].note_failure();
            if !was_degraded && self.degradations[active_index] == ResolverDegradation::Degraded {
                self.resolver_transitions += 1;
            }
            if self.degradations[active_index] == ResolverDegradation::Degraded
                && let Some(next) = self.next_healthy_after_active(corr.active_before)
            {
                self.note_downgrade_if_dot_to_plain(corr.active_before, next);
                self.active_resolver = next;
                self.mark_window_exercised(self.active_resolver);
                if !next.is_primary() {
                    self.failback_due = Some(self.now_u64().saturating_add(FAILBACK_AFTER_SECS));
                }
                self.repoint_to_active();
            } else {
                self.active_resolver = corr.active_before;
                self.repoint_to_active();
            }
        } else {
            self.active_resolver = corr.active_before;
            self.repoint_to_active();
        }
        self.close_connection()?;
        Ok(())
    }

    /// Advances the failover/failback state machine at the single recognized
    /// failure choke point. Every counted failure degrades the active resolver,
    /// recording exactly one enter crossing when healthy resolves cross the
    /// threshold. A degraded active resolver relocates to the next healthy
    /// resolver in the set, or stays put when no candidate exists (all-degraded
    /// fail-closed); relocation to a non-primary arms the failback grace so the
    /// primary is probed again. While a failback probe is in flight, a failed
    /// probe re-seats onto the backup it came from instead of cascading into
    /// another failover. While a post-window probe is in flight, a failure
    /// advances the probed resolver's degradation count but never relocates the
    /// healthy pre-sweep transport: the probe target stays `current` so the
    /// caller records the verdict with its reason, and the pre-sweep active
    /// resolver is restored with relocation/failback arming suppressed
    /// entirely.
    fn on_exchange_failed(&mut self, now: u64) {
        if let Some(corr) = self.corroboration.take() {
            // A failed corroboration exchange is a pure-sensor cross-check that
            // never advances the active resolver's degradation and never emits a
            // fact: the transport simply restores the active resolver it left
            // (alox18).
            self.corroboration_outcome = None;
            self.active_resolver = corr.active_before;
            self.repoint_to_active();
            return;
        }
        let probe = self.probe_sweep.as_ref().and_then(|sweep| {
            sweep
                .current
                .map(|target| (target.index(), sweep.active_before))
        });
        if let Some((probed, active_before)) = probe {
            let was_degraded = self.degradations[probed] == ResolverDegradation::Degraded;
            self.degradations[probed] = self.degradations[probed].note_failure();
            if !was_degraded && self.degradations[probed] == ResolverDegradation::Degraded {
                self.resolver_transitions += 1;
            }
            self.active_resolver = active_before;
            self.repoint_to_active();
            return;
        }
        let active = self.active_resolver;
        let active_index = active.index();
        let was_degraded = self.degradations[active_index] == ResolverDegradation::Degraded;
        self.degradations[active_index] = self.degradations[active_index].note_failure();
        if !was_degraded && self.degradations[active_index] == ResolverDegradation::Degraded {
            self.resolver_transitions += 1;
        }
        if let Some(source) = self.failback_source {
            self.note_downgrade_if_dot_to_plain(active, source);
            self.active_resolver = source;
            self.mark_window_exercised(self.active_resolver);
            self.failback_source = None;
            self.failback_successes = 0;
            self.failback_due = Some(now.saturating_add(FAILBACK_AFTER_SECS));
            self.repoint_to_active();
            return;
        }
        if self.degradations[active_index] == ResolverDegradation::Degraded
            && let Some(next) = self.next_healthy_after_active(active)
        {
            self.note_downgrade_if_dot_to_plain(active, next);
            self.active_resolver = next;
            self.mark_window_exercised(self.active_resolver);
            if !next.is_primary() {
                self.failback_due = Some(now.saturating_add(FAILBACK_AFTER_SECS));
            }
            self.repoint_to_active();
        }
    }

    /// Advances the resolver state at the single recognized success choke
    /// point, recording exactly one exit crossing when a degraded resolver
    /// publishes a valid outcome: the active resolver recovers to healthy, and
    /// a successful primary probe advances the consecutive-success counter,
    /// settling the failback (clearing probe source and grace) only at
    /// `FAILBACK_SUCCESSES` so a transient primary is not re-adopted on a
    /// single success. A success on a non-primary leaves the counter and the
    /// failback grace untouched, so the primary is still probed on the next
    /// due exchange.
    ///
    /// A successful post-window probe records an `Ok` verdict against the
    /// probed resolver, resets its degradation to healthy, restores the
    /// pre-sweep active transport, closes the retained probe-target connection
    /// so the next exchange re-dials the restored resolver, and clears the
    /// in-flight probe target; the failback machinery is never touched by a
    /// sweep probe.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle `Transport` error when the retained probe-target
    /// connection cannot be deregistered; the probe verdict and restore are
    /// already recorded before the close is attempted.
    fn on_exchange_succeeded(&mut self) -> Result<(), StartupDnsError> {
        if self.corroboration.is_some() {
            return self.conclude_corroboration();
        }
        let probe = self.probe_sweep.as_ref().and_then(|sweep| {
            sweep
                .current
                .map(|target| (target.index(), sweep.active_before))
        });
        if let Some((probed, active_before)) = probe {
            let was_degraded = self.degradations[probed] == ResolverDegradation::Degraded;
            self.degradations[probed] = ResolverDegradation::note_success();
            if was_degraded {
                self.resolver_transitions += 1;
            }
            if let Some(sweep) = &mut self.probe_sweep {
                sweep.verdicts[probed] = ProbeVerdict::Ok;
                sweep.current = None;
            }
            self.active_resolver = active_before;
            self.repoint_to_active();
            self.close_connection()?;
            return Ok(());
        }
        let active_index = self.active_resolver.index();
        let was_degraded = self.degradations[active_index] == ResolverDegradation::Degraded;
        self.degradations[active_index] = ResolverDegradation::note_success();
        if was_degraded {
            self.resolver_transitions += 1;
        }
        if self.failback_source.is_some() && self.active_resolver.is_primary() {
            self.failback_successes += 1;
            if self.failback_successes >= FAILBACK_SUCCESSES {
                self.failback_source = None;
                self.failback_due = None;
                self.failback_successes = 0;
            }
        }
        Ok(())
    }

    fn note_failure(
        &mut self,
        ordinal: usize,
        family: Family,
        probe: bool,
        serving: bool,
        schedules: &mut Schedules,
        reason: FailureReason,
    ) -> Result<FailureReason, StartupDnsError> {
        let now = self.now_u64();
        self.on_exchange_failed(now);
        let probed = self
            .probe_sweep
            .as_ref()
            .and_then(|sweep| sweep.current.map(|target| target.index()));
        if let Some(index) = probed
            && let Some(sweep) = &mut self.probe_sweep
        {
            sweep.verdicts[index] = ProbeVerdict::Failed(reason);
            sweep.current = None;
        }
        if !probe {
            let transition = schedules.note_exchange_failure(ordinal, family, now, reason)?;
            if serving && matches!(transition, PerTypeTransition::Opened) {
                self.note_incident(IncidentNote::Open {
                    ordinal,
                    family,
                    reason,
                });
            }
        }
        Ok(reason)
    }
}

/// The raw TCP socket of the connected transport, whether the connection is
/// plain or carries a TLS layer, for registry/reregister and readiness
/// operations that are common to both. A free function over the `conn` field so
/// callers keep field-precise borrows (`&mut self.conn` only), never a whole-
/// struct borrow.
const fn raw_stream(conn: &mut Option<DnsConn>) -> Option<&mut TcpStream> {
    match conn {
        Some(DnsConn::Plain(stream)) => Some(stream),
        Some(DnsConn::Tls(conn)) => Some(&mut conn.tcp),
        None => None,
    }
}

/// Shared-borrow form of [`raw_stream`] for read-only readiness probes.
#[cfg(test)]
const fn raw_stream_ref(conn: &Option<DnsConn>) -> Option<&TcpStream> {
    match conn {
        Some(DnsConn::Plain(stream)) => Some(stream),
        Some(DnsConn::Tls(conn)) => Some(&conn.tcp),
        None => None,
    }
}

/// The raw TCP socket only for a plain connection: a TLS upgrade never
/// downgrades, so the plain query-write path (which emits the raw
/// length-prefixed query) is structurally separated from the `DoT` path, which
/// writes through the TLS writer instead.
const fn plain_stream(conn: &mut Option<DnsConn>) -> Option<&mut TcpStream> {
    match conn {
        Some(DnsConn::Plain(stream)) => Some(stream),
        _ => None,
    }
}

/// The progress of one nonblocking TLS application-data write probe, decided
/// inside the scoped borrow over the retained connection so the caller can arm
/// interests and settle failures outside the borrow.
enum TlsSendProbe {
    /// Either zero plaintext was accepted this turn or a previous turn's
    /// outbound ciphertext remains pending; the writer/socket reported
    /// `WouldBlock` and a writable edge is required.
    Blocked,
    /// Some plaintext was accepted and flushed with no full drain; the next
    /// write pass can proceed without waiting.
    Progress,
    /// Every remaining plaintext byte is buffered and every outbound
    /// ciphertext byte is flushed; the exchange transitions to receiving.
    Complete,
    /// A writer or socket error was observed; the exchange is settled and
    /// closed by the caller.
    Fail,
}

/// The progress of one nonblocking receive probe across the plain/TLS split:
/// `Wait` when no bytes were absorbed this turn, `Progress` when the fixed
/// receive buffer grew, `Failure` on EOF or a transport/decryption error.
enum RecvTry {
    Wait,
    Progress,
    Failure,
}

/// Pushes buffered outbound ciphertext to the socket, nonblocking. Returns
/// `Ok(true)` when the rustls write buffer is empty, `Ok(false)` when a
/// `WouldBlock` leaves outbound data pending for the next writable turn.
fn drain_tls_write(tcp: &mut TcpStream, tls: &mut ClientConnection) -> io::Result<bool> {
    loop {
        match tls.write_tls(tcp) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        if !tls.wants_write() {
            return Ok(true);
        }
    }
}

/// Performs one nonblocking plaintext-write pass through the TLS writer and
/// flushes the resulting outbound ciphertext to the socket, classifying the
/// next cooperative turn's backpressure.
fn tls_send_probe(
    plaintext: &[u8],
    written: &mut usize,
    tcp: &mut TcpStream,
    tls: &mut ClientConnection,
) -> TlsSendProbe {
    loop {
        match tls.writer().write(&plaintext[*written..]) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Ok(0) => return TlsSendProbe::Fail,
            Ok(n) => *written += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => return TlsSendProbe::Fail,
        }
        if *written >= plaintext.len() {
            break;
        }
    }
    match drain_tls_write(tcp, tls) {
        Ok(drained) if *written >= plaintext.len() && drained => TlsSendProbe::Complete,
        Ok(true) => TlsSendProbe::Progress,
        Ok(false) => TlsSendProbe::Blocked,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => TlsSendProbe::Blocked,
        Err(_) => TlsSendProbe::Fail,
    }
}

/// The fixed per-name, per-family slot index used by the attempt ledger.
const fn family_index(family: Family) -> usize {
    match family {
        Family::A => 0,
        Family::Aaaa => 1,
    }
}

/// The bounded wait until the earliest scheduled startup step among
/// not-yet-usable names. The one-second per-slot start guard can hold a due
/// slot back; the floor keeps that wake window short and spin-free. The caller
/// clips the result to the absolute window deadline. A name that has no
/// scheduled step at all yields the maximum wait, so the caller sleeps to the
/// window deadline instead of deciding early.
fn wait_until_next_step(
    transport: &StartupDns,
    schedules: &Schedules,
    names: usize,
    resolved: &[bool],
) -> Result<Duration, StartupDnsError> {
    let mut min_due: Option<u64> = None;
    for (ordinal, is_resolved) in resolved[..names].iter().enumerate() {
        if *is_resolved {
            continue;
        }
        for family in Family::ALL {
            if let Some(due) = schedules.due_time(ordinal, family)? {
                min_due = Some(min_due.map_or(due, |min| min.min(due)));
            }
        }
    }
    let Some(min_due) = min_due else {
        return Ok(Duration::MAX);
    };
    let due_instant = transport
        .start
        .checked_add(Duration::from_secs(min_due.saturating_sub(transport.now0)))
        .ok_or(StartupDnsError::DeadlineOverflow)?;
    let mut wait = due_instant.saturating_duration_since(Instant::now());
    if wait.is_zero() {
        wait = Duration::from_millis(100);
    }
    Ok(wait)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod dot_tests;

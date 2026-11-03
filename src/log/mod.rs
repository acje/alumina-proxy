//! Boot-owned bounded allocation-free logging.
//!
//! The log store is a preallocated queue of 256 fixed 2 KiB slots. Records are
//! encoded directly into a slot with a deterministic escaping grammar, never
//! truncated: a record that would exceed its 2 KiB slot (including the
//! terminating newline framing) is dropped whole and counted. Enqueue and
//! drain are allocation-free and nonblocking; a stalled stdout sink yields
//! with its partial write cursor retained and never delays traffic, DNS, or
//! deadlines (docs/alumina-proxy.md:178-179,193-194).
//!
//! Grammar: `level=<warn|info|error> kind=<kind> <key>=<value>...\n`.
//! Text values are double-quoted; `\` and `"` are backslash-escaped and every
//! control byte is emitted as a deterministic `\xNN` escape, so no record
//! ever contains a bare newline except the terminal frame. Numeric values are
//! plain decimal. The exact field set is kind-specific.
//!
//! The startup result is deliberately split across two record shapes so a
//! valid configuration can never lose it whole: one `startup_name` record per
//! unresolved name, carrying the full (never truncated) FQDN, its outcome and
//! its reason, followed by one `startup_final` summary record carrying the
//! canonical counts plus `names_dropped`. Every per-name attempt that cannot be
//! enqueued (full queue or encode overflow) is dropped whole and increments the
//! shared drop counter exactly once; `names_dropped` reports how many of those
//! attempts failed, so it is a subset of the summary's cumulative `dropped`
//! tally and the two are never summed (docs/alumina-proxy.md:236).
//!
//! Address fields are never escaped: resolver `SocketAddr` Display emits only
//! digits, `.`, `:`, `[`, `]`, and `%`, none of which require quoting, and is
//! written straight into the entry without an intermediate allocation. The `%`
//! occurs only as the IPv6 zone id, which std formats as a plain decimal `u32`,
//! so a scoped address never widens the character set. The monitor's indexed
//! peer-address fields (`d<i>p`) instead render fixed-width lowercase hex of
//! the raw address bytes (V4 = 8 chars, V6 = 32 chars), zero-padded per byte.

use std::fmt;
use std::io;
use std::io::IoSlice;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::dns::cache::Family;
use crate::dns::outcome::{NameOutcome, ProbeVerdict};
use crate::dns::resolver::Fqdn;
use crate::enforcement::action::{DomainOrdinal, Scope};
use crate::enforcement::monitor::{CapturedFact, DnsAnomalyKind, Monitor};
use crate::enforcement::policy::{AnyIllegalCause, Effect, UnknownReason};
use crate::incident_report::{EligibleTransition, IncidentSummary};
use crate::inventory;

pub(crate) const QUEUE_SLOTS: usize = 256;
pub(crate) const SLOT_BYTES: usize = 2 * 1024;
/// Monitor family record geometry (alox9-01): the always-emitted summary plus
/// best-effort `monitor_domain` / `monitor_capture` detail batches each stay
/// within this bound, matching the 2 KiB slot (alox9-02).
#[cfg(test)]
pub(crate) const MONITOR_RECORD_MAX: usize = 2048;
/// Nonzero domain blocks packed per `monitor_domain` batch (32 ordinals -> 3).
const DOMAIN_BATCH: usize = 11;
/// Nonzero capture details packed per `monitor_capture` batch (64 -> 3).
const CAPTURE_BATCH: usize = 22;
/// Per-turn sink budget: at most this many write calls or this many bytes,
/// whichever is exhausted first (docs/alumina-proxy.md:178,194,146).
pub(crate) const SINK_MAX_OPS: usize = 16;
pub(crate) const SINK_MAX_BYTES: usize = 64 * 1024;
/// The bounded retry deadline after a `WouldBlock`: the sink cannot accept more
/// right now, so the owner wakes to try again on this cadence instead of
/// busy-spinning (704q N4/T3: a stalled stdout sink never delays traffic, DNS,
/// or deadlines).
const LOG_RETRY: Duration = Duration::from_millis(100);

const QUEUE_MASK: usize = QUEUE_SLOTS - 1;

/// Longest decimal rendering of a `u64` field (`secs`, counters).
const U64_DIGITS: usize = 20;
/// Longest decimal rendering of the `ordinal` field, which is a `u32`.
const ORDINAL_DIGITS: usize = 10;
/// Longest outcome token (`not_attempted`).
const OUTCOME_TOKEN_MAX: usize = 13;
/// Longest failure/not-attempted reason token (`window_closed`).
const REASON_TOKEN_MAX: usize = 13;
/// Longest textual rendering of an [`IpAddr`] field (an uncompressed IPv6).
const IP_ADDR_TEXT_MAX: usize = 45;

/// Deterministic worst-case encoded length of one `startup_name` record,
/// including framing: header, `secs` and `ordinal` at their maximum decimal
/// widths, the full [`crate::config::FQDN_MAX_LEN`] name inside its quotes, the
/// longest outcome token, and the longest reason token inside its quotes. A
/// validated FQDN is lowercase `[a-z0-9-.]` ASCII, so escaping never widens it.
const STARTUP_NAME_MAX: usize = b"level=info kind=startup_name".len()
    + b" secs=".len()
    + U64_DIGITS
    + b" ordinal=".len()
    + ORDINAL_DIGITS
    + b" name=\"".len()
    + crate::config::FQDN_MAX_LEN
    + 1
    + b" outcome=".len()
    + OUTCOME_TOKEN_MAX
    + b" reason=\"".len()
    + REASON_TOKEN_MAX
    + 1
    + 1;

/// Deterministic worst-case encoded length of one `resolver_probe` segment:
/// the indexed address (uncompressed IPv6 inside its quotes), the indexed FQDN
/// inside its quotes, the pin flag, the `failed` verdict and its reason inside
/// its quotes. Indices are at most `MAX_RESOLVERS - 1`, one decimal digit.
const RESOLVER_PROBE_SEGMENT_MAX: usize = b" resolver=\"".len()
    + 1
    + IP_ADDR_TEXT_MAX
    + 1
    + b" fqdn=\"".len()
    + 1
    + crate::config::FQDN_MAX_LEN
    + 1
    + b" pin=".len()
    + 1
    + 1
    + b" verdict=".len()
    + 1
    + "failed".len()
    + b" reason=\"".len()
    + 1
    + REASON_TOKEN_MAX
    + 1;

/// Deterministic worst-case encoded length of one `resolver_probe` record,
/// including framing: header, `secs` at its maximum width, and one worst-case
/// segment per configured resolver.
const RESOLVER_PROBE_MAX: usize = b"level=info kind=resolver_probe".len()
    + b" secs=".len()
    + U64_DIGITS
    + crate::config::MAX_RESOLVERS * RESOLVER_PROBE_SEGMENT_MAX
    + 1;

const _: () = assert!(
    STARTUP_NAME_MAX < SLOT_BYTES,
    "one startup_name record at the validated FQDN bound must fit its 2 KiB slot"
);
const _: () = assert!(
    RESOLVER_PROBE_MAX < SLOT_BYTES,
    "one resolver_probe record over MAX_RESOLVERS full FQDNs must fit its 2 KiB slot"
);

/// Threshold edges: attempt an error record when usage first exceeds 80%,
/// and again when it falls below 70% (docs/alumina-proxy.md:193).
const HIGH_PCT_NUMBER: u64 = 80;
const LOW_PCT_NUMBER: u64 = 70;

const _: () = assert!(
    QUEUE_SLOTS * SLOT_BYTES == inventory::LOG_QUEUE_BYTES,
    "log ring geometry must match the inventory log queue bytes"
);
const _: () = assert!(
    QUEUE_SLOTS.is_power_of_two(),
    "log slot count must be a power of two for ring-mask indexing"
);

/// The severity vocabulary carried by every record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Level {
    Info,
    Warn,
    Error,
}

/// The fixed reason vocabulary for a rejected connection (docs/alumina-proxy.md:193).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectReason {
    Capacity,
    BadRequest,
    Forbidden,
    DialFailed,
    SetupTimeout,
    TlsValidation,
}

impl RejectReason {
    const fn as_str(self) -> &'static str {
        match self {
            RejectReason::Capacity => "capacity",
            RejectReason::BadRequest => "bad_request",
            RejectReason::Forbidden => "forbidden",
            RejectReason::DialFailed => "dial_failed",
            RejectReason::SetupTimeout => "setup_timeout",
            RejectReason::TlsValidation => "tls_validation",
        }
    }
}

/// The fixed reason vocabulary for a tunnel closed for early upstream
/// activity (docs/alumina-proxy.md:193).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivityKind {
    Data,
    Eof,
    Reset,
}

impl ActivityKind {
    const fn as_str(self) -> &'static str {
        match self {
            ActivityKind::Data => "data",
            ActivityKind::Eof => "eof",
            ActivityKind::Reset => "reset",
        }
    }
}

/// The fixed occupancy dimension a capacity threshold edge reports
/// (docs/alumina-proxy.md:193).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dimension {
    Slots,
    Setups,
    Queue,
}

impl Dimension {
    const fn as_str(self) -> &'static str {
        match self {
            Dimension::Slots => "slots",
            Dimension::Setups => "setups",
            Dimension::Queue => "queue",
        }
    }
}

impl Level {
    const fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

/// The record kinds this increment emits.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    StartupWarning,
    StartupName,
    StartupFinal,
    Fatal,
    ShutdownFinal,
    Reject,
    EarlyActivity,
    CapacityHigh,
    CapacityLow,
    QueueHigh,
    QueueLow,
    Monitor,
    ResolverProbe,
    ExchangeFailed,
    IncidentOpen,
    IncidentRecovered,
    IncidentSummary,
    IncidentEligibleLoss,
    IncidentEligibleRecovered,
}

impl Kind {
    const fn as_str(self) -> &'static str {
        match self {
            Kind::StartupWarning => "startup_warning",
            Kind::StartupName => "startup_name",
            Kind::StartupFinal => "startup_final",
            Kind::Fatal => "fatal",
            Kind::ShutdownFinal => "shutdown_final",
            Kind::Reject => "reject",
            Kind::EarlyActivity => "early_activity",
            Kind::CapacityHigh => "capacity_high",
            Kind::CapacityLow => "capacity_low",
            Kind::QueueHigh => "queue_high",
            Kind::QueueLow => "queue_low",
            Kind::Monitor => "monitor",
            Kind::ResolverProbe => "resolver_probe",
            Kind::ExchangeFailed => "exchange_failed",
            Kind::IncidentOpen => "incident_open",
            Kind::IncidentRecovered => "incident_recovered",
            Kind::IncidentSummary => "incident_summary",
            Kind::IncidentEligibleLoss => "incident_eligible_loss",
            Kind::IncidentEligibleRecovered => "incident_eligible_recovered",
        }
    }

    /// The priority class (docs/alumina-proxy.md:1299-1301): latch/event
    /// records are reserved against normal overflow, so they displace the
    /// newest normal record under pressure instead of being dropped whole.
    const fn is_reserved(self) -> bool {
        matches!(
            self,
            Kind::Monitor | Kind::StartupFinal | Kind::ResolverProbe
        )
    }
}

/// The terminal startup status carried by the final startup record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupStatus {
    Full,
    Degraded,
    Failed,
    Terminated,
}

impl StartupStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            StartupStatus::Full => "full",
            StartupStatus::Degraded => "degraded",
            StartupStatus::Failed => "failure",
            StartupStatus::Terminated => "terminated",
        }
    }
}

/// The typed terminal outcome of a SIGTERM shutdown drain: a clean drain of
/// every established tunnel (or an empty drain with no tunnels) exits 0; a
/// deadline-forced closure of remaining sockets is a failure and exits
/// `EX_SOFTWARE` (70) (docs/alumina-proxy.md:220). Emitted as the single shutdown record
/// before the owner exits so a forced closure is never silently lost.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShutdownStatus {
    Drained,
    Forced,
}

impl ShutdownStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            ShutdownStatus::Drained => "drained",
            ShutdownStatus::Forced => "forced",
        }
    }
}

mod encoding;
mod queue;
mod sink;

pub(crate) use self::encoding::fuzz_encode_text;
use self::encoding::{
    Field, Val, count_capture_batches, count_domain_batches, encode_fatal,
    encode_monitor_capture_batch, encode_monitor_domain_batch, encode_monitor_summary,
    encode_record, encode_record_final, encode_record_name, encode_record_probe,
    incident_summary_fields, resolver_val,
};

use self::queue::note_usage;

/// One fixed 2 KiB slot. `bytes` is the encoded record length; `reserved`
/// marks a priority-class record that normal overflow must never displace.
/// Slots are reused, so a stale `bytes` on an unconsumed slot is never
/// committed and the reserved flag is always rewritten on commit.
#[derive(Clone, Copy)]
struct Slot {
    buf: [u8; SLOT_BYTES],
    bytes: usize,
    reserved: bool,
}

impl Slot {
    const fn empty() -> Slot {
        Slot {
            buf: [0; SLOT_BYTES],
            bytes: 0,
            reserved: false,
        }
    }
}

/// A partial write is a cursor state, not a first-class value; this newtype
/// keeps the drain loop from re-sending an already-acknowledged prefix.
#[derive(Clone, Copy)]
struct Cursor {
    off: usize,
}

/// Latched threshold state: a high edge is emitted when usage first exceeds
/// 80%, and the low edge when it later falls below 70%.
#[derive(Clone, Copy)]
struct Watermark {
    crossed_high: bool,
}

impl Watermark {
    const fn new() -> Watermark {
        Watermark {
            crossed_high: false,
        }
    }
}

/// A threshold transition: the store emitted, or should emit, a high edge
/// (first exceed of 80%) or the low edge (fall below 70%).
#[derive(Clone, Copy)]
enum Edge {
    High { used: u64, cap: u64 },
    Low { used: u64, cap: u64 },
}

/// The sink write target. `Stdout` is the production path: an owned clone of
/// fd 1, made nonblocking once by [`LogStore::prepare_stdout`]; `Fd` is the
/// test seam over an owned duplicate of a caller's file or pipe descriptor,
/// written through the same `write_vectored` path so file/pipe/socket
/// behaviour is exercised on a real descriptor.
enum SinkIo {
    Stdout(UnixStream),
    #[cfg(test)]
    Fd(UnixStream),
    /// Test-only one-shot stall seam; see [`ScriptedFirst`].
    #[cfg(test)]
    Scripted(ScriptedSink),
}

/// A one-shot first-write outcome a scripted sink injects before turning into
/// a faithful byte sink.
#[cfg(test)]
enum ScriptedFirst {
    /// First write answers `Err(io::ErrorKind::Interrupted)`.
    Interrupted,
    /// First write answers `Ok(0)`.
    Zero,
    Partial(std::num::NonZeroUsize),
}

/// A test-only sink seam: the first write injects the scripted [`ScriptedFirst`]
/// outcome once; every later write is a faithful byte sink,
/// appending the submitted fragments to [`ScriptedSink::out`] so the drained
/// stream can be compared byte-for-byte against a reference store.
#[cfg(test)]
struct ScriptedSink {
    /// Captured stream bytes in submission order.
    out: Vec<u8>,
    /// The injected first-write outcome, consumed exactly once.
    first: ScriptedFirst,
    /// Whether the first write has already injected; latched so the stall
    /// happens once and the sink is faithful afterwards.
    dispatched: bool,
}

#[cfg(test)]
impl ScriptedSink {
    fn new(first: ScriptedFirst) -> ScriptedSink {
        ScriptedSink {
            out: Vec::new(),
            first,
            dispatched: false,
        }
    }

    /// The seam write path: inject the scripted first-write stall exactly
    /// once, then record and acknowledge every submitted fragment.
    fn write_vectored(&mut self, iovs: &[IoSlice<'_>]) -> io::Result<usize> {
        if !self.dispatched {
            self.dispatched = true;
            return match self.first {
                ScriptedFirst::Interrupted => Err(io::Error::from(io::ErrorKind::Interrupted)),
                ScriptedFirst::Zero => Ok(0),
                ScriptedFirst::Partial(limit) => {
                    let total: usize = iovs.iter().map(|iov| iov.len()).sum();
                    let consumed = total.min(limit.get());
                    let mut remaining = consumed;
                    for iov in iovs {
                        let take = iov.len().min(remaining);
                        self.out.extend_from_slice(&iov[..take]);
                        remaining -= take;
                        if remaining == 0 {
                            break;
                        }
                    }
                    Ok(consumed)
                }
            };
        }
        let total = iovs.iter().map(|iov| iov.len()).sum();
        for iov in iovs {
            self.out.extend_from_slice(iov);
        }
        Ok(total)
    }
}

impl SinkIo {
    /// Writes the gathered fragments in a single nonblocking `write_vectored`
    /// call (the std `writev` equivalent). Returns the total bytes accepted or
    /// the first error, exactly as the underlying descriptor would report.
    fn write_vectored(&mut self, iovs: &[IoSlice<'_>]) -> io::Result<usize> {
        match self {
            SinkIo::Stdout(stream) => stream.write_vectored(iovs),
            #[cfg(test)]
            SinkIo::Fd(stream) => stream.write_vectored(iovs),
            #[cfg(test)]
            SinkIo::Scripted(sink) => sink.write_vectored(iovs),
        }
    }
}

struct SinkState {
    io: SinkIo,
    failed: bool,
    /// Latched while the last drain retained a partial cursor on
    /// WouldBlock/zero progress: the owner wakes on [`LOG_RETRY`] instead of
    /// polling immediately, and a successful partial write clears it so a
    /// drain that made progress stays runnable.
    blocked: bool,
    #[cfg(test)]
    ops: usize,
    /// Write-vector syscalls issued (test observation of the gathering gain).
    #[cfg(test)]
    syscalls: usize,
}

/// Failure to construct the boot-owned store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStoreError {
    /// The 512 KiB backing queue could not be reserved.
    Reserve,
    /// The sink descriptor could not be duplicated into an owned handle.
    SinkClone,
    /// fd 1 could not be made nonblocking.
    StdoutNonblocking,
}

/// The boot-owned log store retained through serving. Constructed once before
/// the startup DNS window and never freed until process exit.
pub(crate) struct LogStore {
    slots: Vec<Slot>,
    front: usize,
    count: usize,
    dropped: u64,
    dropped_overflow: bool,
    cursor: Option<Cursor>,
    sink: SinkState,
    slots_wm: Watermark,
    setups_wm: Watermark,
    queue_wm: Watermark,
    secs: u64,
}

/// The startup-final result counts carried by the summary record.
#[derive(Clone, Copy, Default)]
pub(crate) struct FinalCounts {
    pub(crate) allowance: u64,
    pub(crate) usable: u64,
    pub(crate) unresolved: u64,
    pub(crate) exchanges: u64,
    pub(crate) failed: u64,
    pub(crate) not_attempted: u64,
    pub(crate) dropped: u64,
    /// Per-name `startup_name` attempts that were dropped whole. A subset of
    /// `dropped`, reported separately so the split's own loss is attributable;
    /// never added to `dropped`.
    pub(crate) names_dropped: u64,
}

/// One unresolved name emitted as its own `startup_name` record: the allowlist
/// ordinal (the deterministic key), the full name and its latest outcome.
/// `Resolved` names are never passed; the outcome vocabulary still covers them
/// for completeness.
#[derive(Clone, Copy)]
pub(crate) struct StartupUnresolved<'a> {
    pub(crate) ordinal: u32,
    pub(crate) name: &'a str,
    pub(crate) outcome: NameOutcome,
}

impl StartupUnresolved<'_> {
    const fn outcome_token(&self) -> &'static str {
        match self.outcome {
            NameOutcome::Resolved => "resolved",
            NameOutcome::Negative => "negative",
            NameOutcome::NoEligible => "no_eligible",
            NameOutcome::Failed(_) => "failed",
            NameOutcome::NotAttempted(_) => "not_attempted",
        }
    }

    const fn reason_token(&self) -> Option<&'static str> {
        match self.outcome {
            NameOutcome::Failed(reason) => Some(reason.as_str()),
            NameOutcome::NotAttempted(reason) => Some(reason.as_str()),
            NameOutcome::Resolved | NameOutcome::Negative | NameOutcome::NoEligible => None,
        }
    }
}

/// One resolver embedded inline in the single post-window probe record: the
/// resolver index (the deterministic key suffix), its address with FQDN/pin
/// presence, and the probe verdict with the failure reason when failed.
#[derive(Clone, Copy)]
pub(crate) struct ResolverProbeSegment<'a> {
    pub(crate) index: u32,
    pub(crate) addr: IpAddr,
    pub(crate) fqdn: Option<&'a Fqdn>,
    pub(crate) pin: bool,
    pub(crate) verdict: ProbeVerdict,
}

impl LogStore {
    /// Builds the full queue over an owned clone of the production stdout
    /// descriptor (fd 1). The clone shares the underlying file description, so
    /// a later [`LogStore::prepare_stdout`] making it nonblocking also flips
    /// the process's real stdout — a full or absent stdout pipe can never
    /// stall serving.
    ///
    /// # Errors
    ///
    /// Returns [`LogStoreError`] when the 512 KiB backing queue cannot be
    /// reserved or fd 1 cannot be duplicated into an owned handle.
    pub(crate) fn new() -> Result<LogStore, LogStoreError> {
        let owned = std::io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| LogStoreError::SinkClone)?;
        Self::with_io(SinkIo::Stdout(UnixStream::from(owned)))
    }

    /// Test construction over a caller-owned descriptor: a real file (never
    /// `WouldBlock` at this volume) or a nonblocking pipe writer (`WouldBlock`
    /// once full). The store duplicates the descriptor into an owned handle
    /// sharing the file description (so the caller's nonblocking flag and file
    /// offset apply); the caller keeps the original for its own use.
    #[cfg(test)]
    pub(crate) fn with_fd(fd: &impl AsFd) -> Result<LogStore, LogStoreError> {
        let owned = fd
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| LogStoreError::SinkClone)?;
        Self::with_io(SinkIo::Fd(UnixStream::from(owned)))
    }

    /// Test construction over a scripted sink (see [`ScriptedSink`]): the first
    /// `drain_sink` write receives the scripted one-shot stall, then the sink
    /// drains faithfully, so the `Interrupted` / zero-progress stall arms run
    /// deterministically and the resumed stream can be observed.
    #[cfg(test)]
    fn with_scripted_sink(first: ScriptedFirst) -> Result<LogStore, LogStoreError> {
        Self::with_io(SinkIo::Scripted(ScriptedSink::new(first)))
    }

    fn with_io(io: SinkIo) -> Result<LogStore, LogStoreError> {
        let mut slots: Vec<Slot> = Vec::new();
        slots
            .try_reserve_exact(QUEUE_SLOTS)
            .map_err(|_| LogStoreError::Reserve)?;
        slots.resize_with(QUEUE_SLOTS, Slot::empty);
        Ok(LogStore {
            slots,
            front: 0,
            count: 0,
            dropped: 0,
            dropped_overflow: false,
            cursor: None,
            sink: SinkState {
                io,
                failed: false,
                blocked: false,
                #[cfg(test)]
                ops: 0,
                #[cfg(test)]
                syscalls: 0,
            },
            slots_wm: Watermark::new(),
            setups_wm: Watermark::new(),
            queue_wm: Watermark::new(),
            secs: 0,
        })
    }

    /// Records the current monotonic second so next capacity-edge record
    /// carries real time (review M3).
    pub(crate) const fn set_now(&mut self, secs: u64) {
        self.secs = secs;
    }

    /// The startup first-failure warning: exactly one attempt across all
    /// names and record types (docs/alumina-proxy.md:67), enqueued at the time of the
    /// first counted exchange failure inside the startup window.
    pub(crate) fn startup_warning(
        &mut self,
        secs: u64,
        name: &str,
        family: Family,
        reason: &'static str,
    ) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(family)),
            Field::new("reason", Val::Str(reason)),
        ];
        self.enqueue(Level::Warn, Kind::StartupWarning, &fields);
    }

    /// One warn per counted exchange failure in the serving loop
    /// (docs/alumina-proxy.md:67): the allowlist name (when the ordinal is
    /// still recoverable after the exchange settled), the structural failure
    /// reason, and the configured-resolver origin (`unknown` when metadata is
    /// absent).
    pub(crate) fn exchange_failed(
        &mut self,
        secs: u64,
        name: Option<&str>,
        reason: &'static str,
        origin: Option<u8>,
    ) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("name", Val::OptStr(name)),
            Field::new("reason", Val::Str(reason)),
            Field::new("resolver", resolver_val(true, origin)),
        ];
        self.enqueue(Level::Warn, Kind::ExchangeFailed, &fields);
    }

    /// One warn per per-type exchange-failure incident open in the serving loop
    /// (docs/alumina-proxy.md:79): the allowlist FQDN, the family, and the
    /// structural failure reason. Startup-window failures never emit this
    /// record; only serving failures do.
    pub(crate) fn incident_open(
        &mut self,
        secs: u64,
        name: &str,
        family: Family,
        reason: &'static str,
        origin: Option<u8>,
    ) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(family)),
            Field::new("reason", Val::Str(reason)),
            Field::new("resolver", resolver_val(true, origin)),
        ];
        self.enqueue(Level::Warn, Kind::IncidentOpen, &fields);
    }

    /// One info per per-type exchange-failure incident recovery in the serving
    /// loop (docs/alumina-proxy.md:79): the allowlist FQDN, the family, and the
    /// elapsed duration the incident stayed open.
    pub(crate) fn incident_recovered(
        &mut self,
        secs: u64,
        name: &str,
        family: Family,
        duration: u64,
        origin: Option<u8>,
    ) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(family)),
            Field::new("duration", Val::U64(duration)),
            Field::new("resolver", resolver_val(true, origin)),
        ];
        self.enqueue(Level::Info, Kind::IncidentRecovered, &fields);
    }

    /// One error summary per hostname after each 3600-second reporting window
    /// while either type has an incident, or the info-level final partial
    /// summary on full hostname incident recovery (docs/alumina-proxy.md:79-80).
    /// The full record payload is built by the serving side; this encoder only
    /// formats it.
    pub(crate) fn incident_summary(
        &mut self,
        secs: u64,
        name: &str,
        level: Level,
        summary: &IncidentSummary,
    ) {
        self.set_now(secs);
        let fields = incident_summary_fields(secs, name, summary);
        self.enqueue(level, Kind::IncidentSummary, &fields);
    }

    /// One typed eligible-binding transition for a hostname: `Lost` logs one
    /// error when the name transitions to having no eligible bindings,
    /// `Recovered` logs one info when they recover (docs/alumina-proxy.md:79).
    pub(crate) fn incident_eligible(
        &mut self,
        secs: u64,
        name: &str,
        transition: EligibleTransition,
    ) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("name", Val::Str(name)),
        ];
        let (level, kind) = match transition {
            EligibleTransition::Lost => (Level::Error, Kind::IncidentEligibleLoss),
            EligibleTransition::Recovered => (Level::Info, Kind::IncidentEligibleRecovered),
        };
        self.enqueue(level, kind, &fields);
    }

    /// One `startup_name` record for a single unresolved name: `secs`, the
    /// allowlist `ordinal`, the full FQDN, the outcome and (when the outcome
    /// carries one) the reason. Returns `true` when the record was enqueued;
    /// a full queue or an encode overflow drops it whole and increments the
    /// shared drop counter exactly once, so the caller can count per-name loss
    /// without touching the counter itself.
    pub(crate) fn startup_name(&mut self, secs: u64, un: StartupUnresolved<'_>) -> bool {
        self.set_now(secs);
        if self.count >= QUEUE_SLOTS {
            self.drop_one();
            self.note_queue_usage();
            return false;
        }
        let index = self.write_index();
        if let Some(len) = encode_record_name(&mut self.slots[index].buf, secs, &un) {
            self.commit_record(index, len);
            self.note_queue_usage();
            true
        } else {
            self.drop_one();
            self.note_queue_usage();
            false
        }
    }

    /// The `startup_final` summary record, emitted after one `startup_name`
    /// record per unresolved name: the canonical counts in their existing order
    /// plus the appended `names_dropped` per-name accounting. No names are
    /// embedded here, so the record has a fixed field set and always fits.
    pub(crate) fn startup_final(&mut self, secs: u64, status: StartupStatus, counts: FinalCounts) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("status", Val::Str(status.as_str())),
            Field::new("allowance", Val::U64(counts.allowance)),
            Field::new("usable", Val::U64(counts.usable)),
            Field::new("unresolved", Val::U64(counts.unresolved)),
            Field::new("exchanges", Val::U64(counts.exchanges)),
            Field::new("failed", Val::U64(counts.failed)),
            Field::new("not_attempted", Val::U64(counts.not_attempted)),
            Field::new("dropped", Val::U64(counts.dropped)),
            Field::new("names_dropped", Val::U64(counts.names_dropped)),
        ];
        self.enqueue_reserved(Kind::StartupFinal, |buf| {
            encode_record_final(buf, Level::Info, Kind::StartupFinal, &fields)
        });
        self.note_queue_usage();
    }

    /// The single post-window probe record (docs/alumina-proxy.md:67): one inline
    /// segment per resolver in index order with its probe verdict and failure
    /// reason. All resolvers share this one record — the sweep result is never
    /// fanned out into per-resolver records. An oversize record is dropped
    /// whole and counted like every other.
    pub(crate) fn resolver_probe(&mut self, secs: u64, segments: &[ResolverProbeSegment<'_>]) {
        self.set_now(secs);
        self.enqueue_reserved(Kind::ResolverProbe, |buf| {
            encode_record_probe(buf, secs, segments)
        });
        self.note_queue_usage();
    }

    /// One error record for a process-fatal post-sink failure: emitted on the
    /// boot-owned stdout store before the owner exits, so an attach/serve/
    /// listener failure never writes to a stderr that could block a separate
    /// blocked descriptor (docs/alumina-proxy.md:149, B1). The message is formatted
    /// directly into the fixed slot (no heap String) and escaped by the same
    /// deterministic grammar as a `Str` field; an oversize record is dropped
    /// whole and counted.
    pub(crate) fn fatal(&mut self, secs: u64, args: fmt::Arguments<'_>) {
        self.set_now(secs);
        if self.count >= QUEUE_SLOTS {
            self.drop_one();
        } else {
            let index = self.write_index();
            let len = encode_fatal(&mut self.slots[index].buf, secs, args);
            match len {
                Some(len) => self.commit_record(index, len),
                None => self.drop_one(),
            }
        }
        self.note_queue_usage();
    }

    /// One warn per rejected connection (docs/alumina-proxy.md:193): `reason` selects the
    /// fixed vocabulary; the hostname is included only when valid.
    pub(crate) fn reject(
        &mut self,
        secs: u64,
        reason: RejectReason,
        client: Option<SocketAddr>,
        hostname: Option<&str>,
    ) {
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("reason", Val::Str(reason.as_str())),
            Field::new("client", Val::OptAddr(client)),
            Field::new("hostname", Val::OptStr(hostname)),
        ];
        self.set_now(secs);
        self.enqueue(Level::Warn, Kind::Reject, &fields);
    }

    /// One warn per tunnel closed for early upstream activity (docs/alumina-proxy.md:193):
    /// the peer address and whether data, EOF, or reset was observed.
    pub(crate) fn early_activity(
        &mut self,
        secs: u64,
        hostname: Option<&str>,
        peer: Option<SocketAddr>,
        activity: ActivityKind,
    ) {
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("hostname", Val::OptStr(hostname)),
            Field::new("peer", Val::OptAddr(peer)),
            Field::new("activity", Val::Str(activity.as_str())),
        ];
        self.set_now(secs);
        self.enqueue(Level::Warn, Kind::EarlyActivity, &fields);
    }

    /// The single typed shutdown record emitted before the owner exits on a
    /// SIGTERM: `status` names whether the drain finished clean or was
    /// deadline-forced, so a forced closure is never silently lost to the
    /// immediate `process::exit` that follows (docs/alumina-proxy.md:220). The caller
    /// drains once after this, and the drain is bounded/nonblocking so a
    /// stalled stdout can never delay the exit verdict.
    pub(crate) fn shutdown_final(&mut self, secs: u64, status: ShutdownStatus, dropped: u64) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("status", Val::Str(status.as_str())),
            Field::new("dropped", Val::U64(dropped)),
        ];
        self.enqueue(Level::Info, Kind::ShutdownFinal, &fields);
    }

    pub(crate) fn monitor_summary(&mut self, secs: u64, monitor: &mut Monitor) -> bool {
        self.set_now(secs);
        let committed = self.enqueue_reserved(Kind::Monitor, |buf| {
            let monitor_ref = &*monitor;
            encode_monitor_summary(buf, secs, monitor_ref)
        });
        if committed {
            let mut start = 0usize;
            let total = count_domain_batches(monitor);
            for part in 1..=total {
                let ok = self.enqueue_normal(|buf| {
                    let monitor_ref = &*monitor;
                    encode_monitor_domain_batch(buf, secs, part, total, monitor_ref, &mut start)
                });
                if !ok {
                    monitor.note_report_drop();
                }
            }
            let mut start = 0usize;
            let total = count_capture_batches(monitor);
            for part in 1..=total {
                let ok = self.enqueue_normal(|buf| {
                    let monitor_ref = &*monitor;
                    encode_monitor_capture_batch(buf, secs, part, total, monitor_ref, &mut start)
                });
                if !ok {
                    monitor.note_suppressed_detail();
                }
            }
        }
        self.note_queue_usage();
        committed
    }

    /// Evaluates the 80%/70% capacity thresholds for tunnel slots and pending
    /// setups (docs/alumina-proxy.md:193). Call after any occupancy transition.
    pub(crate) fn note_capacity(&mut self, secs: u64, occupied: usize, pending: usize) {
        self.secs = secs;
        if let Some(edge) = note_usage(
            &mut self.slots_wm,
            occupied,
            crate::runtime::tunnel::MAX_TUNNELS,
        ) {
            self.capacity_edge(Dimension::Slots, edge);
        }
        if let Some(edge) = note_usage(
            &mut self.setups_wm,
            pending,
            crate::runtime::tunnel::MAX_PENDING_SETUPS,
        ) {
            self.capacity_edge(Dimension::Setups, edge);
        }
    }
}

#[cfg(test)]
mod tests;

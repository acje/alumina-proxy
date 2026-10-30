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
use std::time::{Duration, Instant};

use crate::cache::Family;
use crate::enforcement::action::{DomainOrdinal, Scope};
use crate::enforcement::monitor::{CapturedFact, DnsAnomalyKind, Monitor};
use crate::enforcement::policy::{AnyIllegalCause, Effect, UnknownReason};
use crate::incident_report::IncidentSummary;
use crate::inventory;
use crate::resolver::Fqdn;
use crate::startup_dns::{NameOutcome, ProbeVerdict};

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

/// A single encoded field. `OptVar` variants emit nothing when the value is
/// absent, so a caller never supplies an empty quoted value.
#[derive(Clone, Copy)]
pub(crate) enum Val<'a> {
    Str(&'a str),
    OptStr(Option<&'a str>),
    U64(u64),
    OptU64(Option<u64>),
    OptAddr(Option<SocketAddr>),
    Family(Family),
}

#[derive(Clone, Copy)]
pub(crate) struct Field<'a> {
    key: &'static str,
    val: Val<'a>,
}

impl<'a> Field<'a> {
    const fn new(key: &'static str, val: Val<'a>) -> Self {
        Field { key, val }
    }
}

/// An unbuffered writer over a fixed slot buffer; every write that does not
/// fit returns `false` (or `fmt::Error`), so the encoder aborts on overflow.
struct Entry<'a> {
    buf: &'a mut [u8; SLOT_BYTES],
    len: usize,
}

impl Entry<'_> {
    fn push(&mut self, bytes: &[u8]) -> bool {
        if self.len + bytes.len() > self.buf.len() {
            return false;
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        true
    }
}

impl fmt::Write for Entry<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.push(s.as_bytes()) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_escaped(w: &mut Entry<'_>, text: &str) -> bool {
    for &b in text.as_bytes() {
        match b {
            b'"' => {
                if !w.push(b"\\\"") {
                    return false;
                }
            }
            b'\\' => {
                if !w.push(b"\\\\") {
                    return false;
                }
            }
            0x00..=0x1f | 0x7f => {
                let hi = HEX[(b >> 4) as usize];
                let lo = HEX[(b & 0x0f) as usize];
                if !w.push(b"\\x") || !w.push(&[hi, lo]) {
                    return false;
                }
            }
            _ => {
                if !w.push(&[b]) {
                    return false;
                }
            }
        }
    }
    true
}

/// A [`fmt::Write`] adapter that pushes every written span through the same
/// quoted escaping as a `Str` field, so a formatted message cannot inject a
/// quote, backslash, or control boundary into the framed record.
struct EscapedEntry<'a, 'e> {
    entry: &'e mut Entry<'a>,
}

impl fmt::Write for EscapedEntry<'_, '_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if push_escaped(self.entry, s) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

fn write_fmt_escaped(w: &mut Entry<'_>, args: fmt::Arguments<'_>) -> bool {
    fmt::Write::write_fmt(&mut EscapedEntry { entry: w }, args).is_ok()
}

/// Encodes one record into `slot_buf` and returns its length on success, or
/// `None` when the record would exceed the slot. On overflow the slot content
/// is garbage but the caller never commits it.
fn encode_record(
    slot_buf: &mut [u8; SLOT_BYTES],
    level: Level,
    kind: Kind,
    fields: &[Field<'_>],
) -> Option<usize> {
    let mut w = Entry {
        buf: slot_buf,
        len: 0,
    };
    if !write_header(&mut w, level, kind) || !write_fields(&mut w, fields) {
        return None;
    }
    if !w.push(b"\n") {
        return None;
    }
    Some(w.len)
}

/// Verification seam for the in-repo fuzz campaign (docs/alumina-proxy.md:390):
/// encodes attacker-controlled text as a single `name` string field of an info
/// `startup_warning` record into a fixed slot, returning `Some(length)` when
/// the record fit. Only the fuzz driver reaches this; no production path calls
/// it. Overflow returns `None` with the slot left uncommitted.
pub(crate) fn fuzz_encode_text(text: &str) -> Option<usize> {
    let mut slot = [0u8; SLOT_BYTES];
    encode_record(
        &mut slot,
        Level::Info,
        Kind::StartupWarning,
        &[Field::new("name", Val::Str(text))],
    )
}

fn write_header(w: &mut Entry<'_>, level: Level, kind: Kind) -> bool {
    w.push(b"level=")
        && w.push(level.as_str().as_bytes())
        && w.push(b" kind=")
        && w.push(kind.as_str().as_bytes())
}

fn write_fields(w: &mut Entry<'_>, fields: &[Field<'_>]) -> bool {
    for field in fields {
        if let Val::OptStr(None) | Val::OptAddr(None) | Val::OptU64(None) = field.val {
            continue;
        }
        if !w.push(b" ") || !w.push(field.key.as_bytes()) || !w.push(b"=") {
            return false;
        }
        match field.val {
            Val::Str(s) | Val::OptStr(Some(s)) => {
                if !w.push(b"\"") || !push_escaped(w, s) || !w.push(b"\"") {
                    return false;
                }
            }
            Val::U64(value) | Val::OptU64(Some(value)) => {
                if fmt::Write::write_fmt(w, format_args!("{value}")).is_err() {
                    return false;
                }
            }
            Val::OptAddr(Some(addr)) => {
                if !w.push(b"\"") {
                    return false;
                }
                if fmt::Write::write_fmt(w, format_args!("{addr}")).is_err() {
                    return false;
                }
                if !w.push(b"\"") {
                    return false;
                }
            }
            Val::Family(family) => {
                if fmt::Write::write_fmt(w, format_args!("{family:?}")).is_err() {
                    return false;
                }
            }
            Val::OptStr(None) | Val::OptAddr(None) | Val::OptU64(None) => {}
        }
    }
    true
}

/// The `types=` token for an incident summary: which record families are
/// currently in incident (`start` present), in A/Aaaa order.
const fn summary_types(summary: &IncidentSummary) -> &'static str {
    match (
        summary.types[0].start.is_some(),
        summary.types[1].start.is_some(),
    ) {
        (true, true) => "both",
        (true, false) => "a",
        (false, true) => "aaaa",
        (false, false) => "none",
    }
}

/// The fixed 31-field incident summary record (docs/alumina-proxy.md:80):
/// window span, coalescing and overflow flags, window activity, and the
/// per-type incident/cache snapshot. Optional fields emit nothing when absent.
fn incident_summary_fields<'a>(
    secs: u64,
    name: &'a str,
    summary: &'a IncidentSummary,
) -> [Field<'a>; 31] {
    [
        Field::new("secs", Val::U64(secs)),
        Field::new("name", Val::Str(name)),
        Field::new("window_start", Val::U64(summary.window_start)),
        Field::new("window_end", Val::U64(summary.window_end)),
        Field::new("duration", Val::U64(summary.duration)),
        Field::new("skipped", Val::U64(u64::from(summary.skipped))),
        Field::new("overflow", Val::U64(u64::from(summary.overflow))),
        Field::new("types", Val::Str(summary_types(summary))),
        Field::new("tunnels", Val::U64(summary.tunnels)),
        Field::new("bytes", Val::U64(summary.bytes)),
        Field::new("stale", Val::U64(summary.stale)),
        Field::new("a_start", Val::OptU64(summary.types[0].start)),
        Field::new("a_elapsed", Val::U64(summary.types[0].elapsed)),
        Field::new("a_reason", Val::OptStr(summary.types[0].reason)),
        Field::new(
            "a_last_positive",
            Val::OptU64(summary.types[0].last_positive),
        ),
        Field::new("a_attempts", Val::U64(summary.types[0].attempts)),
        Field::new("a_failures", Val::U64(summary.types[0].failures)),
        Field::new("a_addrs", Val::U64(summary.types[0].addrs)),
        Field::new("a_state", Val::Str(summary.types[0].state)),
        Field::new("a_freshness", Val::OptU64(summary.types[0].freshness)),
        Field::new("a_retirement", Val::OptU64(summary.types[0].retirement)),
        Field::new("aaaa_start", Val::OptU64(summary.types[1].start)),
        Field::new("aaaa_elapsed", Val::U64(summary.types[1].elapsed)),
        Field::new("aaaa_reason", Val::OptStr(summary.types[1].reason)),
        Field::new(
            "aaaa_last_positive",
            Val::OptU64(summary.types[1].last_positive),
        ),
        Field::new("aaaa_attempts", Val::U64(summary.types[1].attempts)),
        Field::new("aaaa_failures", Val::U64(summary.types[1].failures)),
        Field::new("aaaa_addrs", Val::U64(summary.types[1].addrs)),
        Field::new("aaaa_state", Val::Str(summary.types[1].state)),
        Field::new("aaaa_freshness", Val::OptU64(summary.types[1].freshness)),
        Field::new("aaaa_retirement", Val::OptU64(summary.types[1].retirement)),
    ]
}

fn push_quoted(w: &mut Entry<'_>, key: &[u8], text: &str) -> bool {
    w.push(b" ") && w.push(key) && w.push(b"=\"") && push_escaped(w, text) && w.push(b"\"")
}

fn push_token(w: &mut Entry<'_>, key: &[u8], token: &str) -> bool {
    w.push(b" ") && w.push(key) && w.push(b"=") && w.push(token.as_bytes())
}

fn push_indexed_quoted(w: &mut Entry<'_>, key: &[u8], index: u32, text: &str) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    if !w.push(b"=\"") || !push_escaped(w, text) || !w.push(b"\"") {
        return false;
    }
    true
}

fn push_indexed_key_quoted(
    w: &mut Entry<'_>,
    key: &[u8],
    index: u32,
    suffix: &[u8],
    text: &str,
) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    if !w.push(suffix) || !w.push(b"=\"") || !push_escaped(w, text) || !w.push(b"\"") {
        return false;
    }
    true
}

fn push_indexed_token(w: &mut Entry<'_>, key: &[u8], index: u32, token: &str) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    if !w.push(b"=") || !w.push(token.as_bytes()) {
        return false;
    }
    true
}

/// Writes an indexed resolver address field quoted but never escaped: `IpAddr`
/// Display emits only digits, `.`, `:`, `[`, and `]`, none of which require
/// quoting, so it is written straight into the entry without an intermediate
/// allocation (same rule as `SocketAddr` fields).
fn push_indexed_addr(w: &mut Entry<'_>, key: &[u8], index: u32, addr: IpAddr) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    if !w.push(b"=\"") {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{addr}")).is_err() {
        return false;
    }
    if !w.push(b"\"") {
        return false;
    }
    true
}

/// Writes an indexed keyed peer-address field quoted but never escaped: the
/// address is rendered as raw lowercase hex of its fixed bytes (V4 = 8 chars,
/// V6 = 32 chars), each byte zero-padded to two digits so leading zeros are
/// never dropped. The fixed-width `[0-9a-f]` set needs no quoting, so it is
/// written straight into the entry without an intermediate allocation (same
/// rule as `push_indexed_addr`).
fn push_indexed_key_addr(w: &mut Entry<'_>, key: &[u8], index: u32, addr: IpAddr) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    if !w.push(b"p=\"") {
        return false;
    }
    if !push_addr_hex(w, addr) {
        return false;
    }
    if !w.push(b"\"") {
        return false;
    }
    true
}

/// Renders `addr` as fixed-width lowercase hex of its raw bytes (V4 = 8 chars,
/// V6 = 32 chars), byte-wise zero-padded to two digits, never dropping leading
/// zeros. Written straight into the entry; no intermediate allocation.
fn push_addr_hex(w: &mut Entry<'_>, addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => push_octets_hex(w, &v4.octets()),
        IpAddr::V6(v6) => push_octets_hex(w, &v6.octets()),
    }
}

/// Writes `octets` as lowercase hex, one byte at a time, each zero-padded to
/// two digits.
fn push_octets_hex(w: &mut Entry<'_>, octets: &[u8]) -> bool {
    for &b in octets {
        if !w.push(&[HEX[(b >> 4) as usize], HEX[(b & 0x0f) as usize]]) {
            return false;
        }
    }
    true
}

/// Encodes one `startup_name` record: `secs`, the allowlist `ordinal`, the full
/// validated FQDN (never truncated), the outcome token, and the reason only
/// when the outcome carries one. A validated FQDN is lowercase `[a-z0-9-.]`
/// ASCII, so the escaping pass is a no-op and the encoded length is a
/// deterministic function of [`FQDN_MAX_LEN`] (see [`STARTUP_NAME_MAX`]).
fn encode_record_name(
    slot_buf: &mut [u8; SLOT_BYTES],
    secs: u64,
    un: &StartupUnresolved<'_>,
) -> Option<usize> {
    let mut w = Entry {
        buf: slot_buf,
        len: 0,
    };
    let fitted = write_header(&mut w, Level::Info, Kind::StartupName)
        && push_u64(&mut w, b"secs", secs)
        && push_u64(&mut w, b"ordinal", u64::from(un.ordinal))
        && push_quoted(&mut w, b"name", un.name)
        && push_token(&mut w, b"outcome", un.outcome_token())
        && un
            .reason_token()
            .is_none_or(|reason| push_quoted(&mut w, b"reason", reason))
        && w.push(b"\n");
    fitted.then_some(w.len)
}

/// Encodes the `startup_final` summary record: the canonical startup counts in
/// their existing order, with the appended `names_dropped` per-name accounting.
/// The unresolved names are NOT embedded here — each was emitted first as its
/// own `startup_name` record — so this record has a fixed field set and always
/// fits its slot for any count values.
fn encode_record_final(
    slot_buf: &mut [u8; SLOT_BYTES],
    level: Level,
    kind: Kind,
    fields: &[Field<'_>],
) -> Option<usize> {
    encode_record(slot_buf, level, kind, fields)
}

/// Encodes the single post-window probe record: the header fields plus, in
/// resolver index order, one inline segment per resolver — `resolverN` (the
/// address, with FQDN/pin presence), `verdictN`, and (for a failed probe)
/// `reasonN`. The segments are embedded in the same fixed 2 KiB entry as the
/// header, so the probe result is exactly one record that never exceeds its
/// slot; an oversize record is dropped whole and counted like every other.
fn encode_record_probe(
    slot_buf: &mut [u8; SLOT_BYTES],
    secs: u64,
    segments: &[ResolverProbeSegment<'_>],
) -> Option<usize> {
    let mut w = Entry {
        buf: slot_buf,
        len: 0,
    };
    if !write_header(&mut w, Level::Info, Kind::ResolverProbe) {
        return None;
    }
    if !push_u64(&mut w, b"secs", secs) {
        return None;
    }
    for seg in segments {
        let index = seg.index;
        if !push_indexed_addr(&mut w, b"resolver", index, seg.addr) {
            return None;
        }
        if let Some(fqdn) = seg.fqdn
            && !push_indexed_quoted(&mut w, b"fqdn", index, fqdn.as_str())
        {
            return None;
        }
        if seg.pin && !push_indexed_token(&mut w, b"pin", index, "1") {
            return None;
        }
        if !push_indexed_token(&mut w, b"verdict", index, seg.verdict.as_str()) {
            return None;
        }
        if let ProbeVerdict::Failed(reason) = seg.verdict
            && !push_indexed_quoted(&mut w, b"reason", index, reason.as_str())
        {
            return None;
        }
    }
    if !w.push(b"\n") {
        return None;
    }
    Some(w.len)
}

/// True when a per-ordinal domain block carries at least one `d<i>*` field
/// (early-data, block, notify, refusal, or ja4-change fold).
const fn domain_block_nonzero(monitor: &Monitor, ordinal: DomainOrdinal) -> bool {
    monitor.facts_early_data(ordinal) > 0
        || monitor.actions_domain_block(ordinal) > 0
        || monitor.actions_notify(ordinal) > 0
        || monitor.refusals_blocked_domain(ordinal) > 0
        || monitor.facts_ja4_change(ordinal) > 0
}

/// Number of `monitor_domain` batches needed to carry every nonzero domain
/// block (32 ordinals -> ceil(nonzero / `DOMAIN_BATCH`), zero when none).
#[expect(
    clippy::expect_used,
    reason = "nonzero count is bounded by ALLOWLIST_MAX=32 and the DOMAIN_BATCH division only shrinks it, so it fits u32"
)]
fn count_domain_batches(monitor: &Monitor) -> u32 {
    let mut nonzero = 0usize;
    for index in 0..crate::config::ALLOWLIST_MAX {
        let Some(ordinal) = DomainOrdinal::from_index(index) else {
            break;
        };
        if domain_block_nonzero(monitor, ordinal) {
            nonzero += 1;
        }
    }
    u32::try_from(nonzero.div_ceil(DOMAIN_BATCH)).expect("domain batch count fits u32")
}

/// Number of `monitor_capture` batches needed to carry every capture detail
/// (64 details -> ceil(len / `CAPTURE_BATCH`), zero when the window is empty).
#[expect(
    clippy::expect_used,
    reason = "capture detail count is bounded by CAPTURE_DETAIL_LEN=64 and the CAPTURE_BATCH division only shrinks it, so it fits u32"
)]
fn count_capture_batches(monitor: &Monitor) -> u32 {
    u32::try_from(monitor.capture_detail_len().div_ceil(CAPTURE_BATCH))
        .expect("capture batch count fits u32")
}

/// Encodes the always-emitted monitor summary: fixed core globals plus
/// zero-suppressed scoped folds, but no per-ordinal `d<i>*` or per-capture
/// `x<i>*` detail (those ride the best-effort detail batches). Sole commit
/// point of the monitor family (alox9-01).
#[expect(
    clippy::too_many_lines,
    reason = "long monitor record serializer emitting every indexed field into the fixed slot buffer"
)]
#[expect(
    clippy::expect_used,
    reason = "enumerated cause and unknown-reason indices stay below their small compile-time counts, fitting u32"
)]
fn encode_monitor_summary(
    slot_buf: &mut [u8; SLOT_BYTES],
    secs: u64,
    monitor: &Monitor,
) -> Option<usize> {
    let mut w = Entry {
        buf: slot_buf,
        len: 0,
    };
    if !write_header(&mut w, Level::Info, Kind::Monitor) {
        return None;
    }
    if !push_u64(&mut w, b"secs", secs) {
        return None;
    }
    let ofacts = monitor.facts_any_illegal_overflow()
        || monitor.facts_early_data_overflow()
        || monitor.facts_unknown_overflow()
        || monitor.facts_resolver_degraded_overflow()
        || monitor.facts_dns_anomaly_overflow()
        || monitor.facts_downgrade_to_plain_overflow()
        || monitor.facts_probe_relocations_overflow()
        || monitor.facts_expired_pin_certs_overflow()
        || monitor.facts_ja4_change_overflow()
        || monitor.facts_ja4_seed_overflow();
    let globals: [(&[u8], u64); 13] = [
        (&b"facts_total"[..], monitor.facts_total()),
        (&b"actions_total"[..], monitor.actions_total()),
        (&b"refusals_total"[..], monitor.refusals_total()),
        (&b"ofacts"[..], u64::from(ofacts)),
        (&b"oactions"[..], u64::from(monitor.actions_overflow())),
        (&b"orefusals"[..], u64::from(monitor.refusals_overflow())),
        (&b"report_drops"[..], u64::from(monitor.report_drops())),
        (
            &b"oreport_drops"[..],
            u64::from(monitor.report_drops_overflow()),
        ),
        (&b"capture_drops"[..], u64::from(monitor.capture_drops())),
        (
            &b"ocapture_drops"[..],
            u64::from(monitor.capture_drops_overflow()),
        ),
        (
            &b"s0"[..],
            u64::from(monitor.actions_first_slot_block(Scope::Connection)),
        ),
        (
            &b"s1"[..],
            u64::from(monitor.actions_first_slot_block(Scope::All)),
        ),
        (&b"ba"[..], u64::from(monitor.actions_block_all())),
    ];
    for (key, value) in globals {
        if !push_u64(&mut w, key, value) {
            return None;
        }
    }
    let resolver_degraded = monitor.facts_resolver_degraded();
    if resolver_degraded > 0 && !push_u64(&mut w, b"rd", u64::from(resolver_degraded)) {
        return None;
    }
    if monitor.serving_stale() && !push_u64(&mut w, b"ss", 1) {
        return None;
    }
    let sustained_negatives = monitor.sustained_negatives();
    if sustained_negatives > 0 && !push_u64(&mut w, b"sn", u64::from(sustained_negatives)) {
        return None;
    }
    let downgrade_to_plain = monitor.facts_downgrade_to_plain();
    if downgrade_to_plain > 0 && !push_u64(&mut w, b"dp", u64::from(downgrade_to_plain)) {
        return None;
    }
    let probe_relocations = monitor.facts_probe_relocations();
    if probe_relocations > 0 && !push_u64(&mut w, b"pr", u64::from(probe_relocations)) {
        return None;
    }
    let expired_pin_certs = monitor.facts_expired_pin_certs();
    if expired_pin_certs > 0 && !push_u64(&mut w, b"ep", u64::from(expired_pin_certs)) {
        return None;
    }
    let ja4_seed = monitor.facts_ja4_seed();
    if ja4_seed > 0 && !push_u64(&mut w, b"js", u64::from(ja4_seed)) {
        return None;
    }
    let bailiwick_violation = monitor.facts_dns_anomaly(DnsAnomalyKind::BailiwickViolation);
    if bailiwick_violation > 0 && !push_u64(&mut w, b"bv", u64::from(bailiwick_violation)) {
        return None;
    }
    let resolver_peer_mismatch = monitor.facts_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch);
    if resolver_peer_mismatch > 0 && !push_u64(&mut w, b"rpm", u64::from(resolver_peer_mismatch)) {
        return None;
    }
    let extreme_ttl = monitor.facts_dns_anomaly(DnsAnomalyKind::ExtremeTtl);
    if extreme_ttl > 0 && !push_u64(&mut w, b"xttl", u64::from(extreme_ttl)) {
        return None;
    }
    let corroboration_conflict = monitor.facts_dns_anomaly(DnsAnomalyKind::CorroborationConflict);
    if corroboration_conflict > 0 && !push_u64(&mut w, b"cc", u64::from(corroboration_conflict)) {
        return None;
    }
    for index in 0..AnyIllegalCause::KIND_COUNT {
        let value = monitor.facts_any_illegal_by_index(index);
        if value > 0
            && !push_indexed_u64(
                &mut w,
                b"c",
                u32::try_from(index).expect("cause index fits u32"),
                u64::from(value),
            )
        {
            return None;
        }
    }
    for index in 0..UnknownReason::COUNT {
        let value = monitor.facts_unknown_by_index(index);
        if value > 0
            && !push_indexed_u64(
                &mut w,
                b"unk",
                u32::try_from(index).expect("unknown cause index fits u32"),
                u64::from(value),
            )
        {
            return None;
        }
    }
    let mut loss_bitset: u32 = 0;
    for index in 0..crate::config::ALLOWLIST_MAX {
        let Some(ordinal) = DomainOrdinal::from_index(index) else {
            break;
        };
        if monitor.facts_ja4_change_loss(ordinal) {
            loss_bitset |= 1u32 << index;
        }
    }
    if loss_bitset != 0 && !push_u64_hex(&mut w, b"dx", u64::from(loss_bitset)) {
        return None;
    }
    if !w.push(b"\n") {
        return None;
    }
    Some(w.len)
}

/// Encodes one best-effort `monitor_domain` batch: its own hardcoded header
/// (no `Kind` variant exists for detail batches), `secs`, `part=n/total`, then
/// up to [`DOMAIN_BATCH`] nonzero domain blocks scanned ascending from `start`,
/// advancing `start` past every examined ordinal.
#[expect(
    clippy::expect_used,
    reason = "allowlist index is below ALLOWLIST_MAX=32 (fits u32) and monitor JA4 values are stored as ASCII bytes (UTF-8 decode cannot fail)"
)]
fn encode_monitor_domain_batch(
    slot_buf: &mut [u8; SLOT_BYTES],
    secs: u64,
    part: u32,
    total: u32,
    monitor: &Monitor,
    start: &mut usize,
) -> Option<usize> {
    let mut w = Entry {
        buf: slot_buf,
        len: 0,
    };
    if !w.push(b"level=info kind=monitor_domain") {
        return None;
    }
    if !push_u64(&mut w, b"secs", secs) {
        return None;
    }
    if !w.push(b" part=") || fmt::Write::write_fmt(&mut w, format_args!("{part}/{total}")).is_err()
    {
        return None;
    }
    let mut packed = 0usize;
    let mut index = *start;
    while index < crate::config::ALLOWLIST_MAX {
        let Some(ordinal) = DomainOrdinal::from_index(index) else {
            break;
        };
        if domain_block_nonzero(monitor, ordinal) {
            let index32 = u32::try_from(index).expect("allowlist ordinal fits u32");
            let facts = monitor.facts_early_data(ordinal);
            let blocks = monitor.actions_domain_block(ordinal);
            let notifies = monitor.actions_notify(ordinal);
            let refusals = monitor.refusals_blocked_domain(ordinal);
            if facts > 0 && !push_indexed_key_u64(&mut w, b"d", index32, b"f", u64::from(facts)) {
                return None;
            }
            if blocks > 0 && !push_indexed_key_u64(&mut w, b"d", index32, b"b", u64::from(blocks)) {
                return None;
            }
            if notifies > 0
                && !push_indexed_key_u64(&mut w, b"d", index32, b"n", u64::from(notifies))
            {
                return None;
            }
            if refusals > 0
                && !push_indexed_key_u64(&mut w, b"d", index32, b"r", u64::from(refusals))
            {
                return None;
            }
            let ja4_changes = monitor.facts_ja4_change(ordinal);
            if ja4_changes > 0 {
                if !push_indexed_key_u64(&mut w, b"d", index32, b"j", u64::from(ja4_changes)) {
                    return None;
                }
                let ja4 = monitor.facts_ja4_value(ordinal);
                let ja4 = std::str::from_utf8(&ja4).expect("ja4 is ASCII");
                if !push_indexed_key_quoted(&mut w, b"d", index32, b"v", ja4) {
                    return None;
                }
                if monitor.ja4_peer_ordinal() == Some(ordinal)
                    && !push_indexed_key_addr(
                        &mut w,
                        b"d",
                        index32,
                        monitor.ja4_peer_ip().to_ip_addr(),
                    )
                {
                    return None;
                }
            }
            packed += 1;
        }
        index += 1;
        if packed == DOMAIN_BATCH {
            break;
        }
    }
    *start = index;
    if !w.push(b"\n") {
        return None;
    }
    Some(w.len)
}

/// Encodes one best-effort `monitor_capture` batch: its own hardcoded header,
/// `secs`, `part=n/total`, then up to [`CAPTURE_BATCH`] capture details scanned
/// ascending from `start`, advancing `start` past every examined detail.
#[expect(
    clippy::expect_used,
    reason = "capture detail index is bounded by CAPTURE_DETAIL_LEN=64, which fits u32"
)]
fn encode_monitor_capture_batch(
    slot_buf: &mut [u8; SLOT_BYTES],
    secs: u64,
    part: u32,
    total: u32,
    monitor: &Monitor,
    start: &mut usize,
) -> Option<usize> {
    let mut w = Entry {
        buf: slot_buf,
        len: 0,
    };
    if !w.push(b"level=info kind=monitor_capture") {
        return None;
    }
    if !push_u64(&mut w, b"secs", secs) {
        return None;
    }
    if !w.push(b" part=") || fmt::Write::write_fmt(&mut w, format_args!("{part}/{total}")).is_err()
    {
        return None;
    }
    let mut packed = 0usize;
    let mut index = *start;
    while index < monitor.capture_detail_len() {
        let Some(cap) = monitor.capture_detail(index) else {
            break;
        };
        let index32 = u32::try_from(index).expect("capture detail index fits u32");
        if !push_indexed_key_u64(&mut w, b"x", index32, b"s", cap.slot as u64) {
            return None;
        }
        if !push_indexed_key_u64(&mut w, b"x", index32, b"g", cap.generation) {
            return None;
        }
        if !push_indexed_token_prefix(&mut w, b"x", index32, b"t")
            || !push_fact_token(&mut w, cap.detail.fact)
        {
            return None;
        }
        if !push_indexed_token_prefix(&mut w, b"x", index32, b"a")
            || !push_effect_token(&mut w, cap.detail.effect)
        {
            return None;
        }
        packed += 1;
        index += 1;
        if packed == CAPTURE_BATCH {
            break;
        }
    }
    *start = index;
    if !w.push(b"\n") {
        return None;
    }
    Some(w.len)
}

fn push_u64(w: &mut Entry<'_>, key: &[u8], value: u64) -> bool {
    w.push(b" ")
        && w.push(key)
        && w.push(b"=")
        && fmt::Write::write_fmt(w, format_args!("{value}")).is_ok()
}

fn push_u64_hex(w: &mut Entry<'_>, key: &[u8], value: u64) -> bool {
    w.push(b" ")
        && w.push(key)
        && w.push(b"=")
        && fmt::Write::write_fmt(w, format_args!("{value:x}")).is_ok()
}

fn push_indexed_u64(w: &mut Entry<'_>, key: &[u8], index: u32, value: u64) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    if !w.push(b"=") {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{value}")).is_err() {
        return false;
    }
    true
}

fn push_indexed_key_u64(
    w: &mut Entry<'_>,
    key: &[u8],
    index: u32,
    suffix: &[u8],
    value: u64,
) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    if !w.push(suffix) || !w.push(b"=") {
        return false;
    }
    fmt::Write::write_fmt(w, format_args!("{value}")).is_ok()
}

fn push_indexed_token_prefix(w: &mut Entry<'_>, key: &[u8], index: u32, suffix: &[u8]) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    w.push(suffix) && w.push(b"=")
}

fn push_fact_token(w: &mut Entry<'_>, fact: CapturedFact) -> bool {
    match fact {
        CapturedFact::AnyIllegal(cause) => {
            if !w.push(b"a") {
                return false;
            }
            fmt::Write::write_fmt(w, format_args!("{}", cause.kind_index())).is_ok()
        }
        CapturedFact::EarlyData(ordinal) => {
            if !w.push(b"d") {
                return false;
            }
            fmt::Write::write_fmt(w, format_args!("{}", ordinal.get())).is_ok()
        }
        CapturedFact::Unknown(reason) => {
            if !w.push(b"u") {
                return false;
            }
            fmt::Write::write_fmt(w, format_args!("{}", reason.index())).is_ok()
        }
    }
}

fn push_effect_token(w: &mut Entry<'_>, effect: Effect) -> bool {
    match effect {
        Effect::BaselineOnly => w.push(b"none"),
        Effect::Notify { scope } => push_scope_token(w, b"ntf", scope),
        Effect::Block { scope } => push_scope_token(w, b"blk", scope),
        Effect::Unknown { reason } => {
            if !w.push(b"unk") {
                return false;
            }
            fmt::Write::write_fmt(w, format_args!("{}", reason.index())).is_ok()
        }
    }
}

fn push_scope_token(w: &mut Entry<'_>, prefix: &[u8], scope: Scope) -> bool {
    if !w.push(prefix) || !w.push(b":") {
        return false;
    }
    match scope {
        Scope::Connection => w.push(b"c"),
        Scope::Domain => w.push(b"d"),
        Scope::All => w.push(b"a"),
    }
}

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
/// a faithful byte sink. The unit variants keep the injected result
/// unambiguous: an `Interrupted` error or a zero-progress `Ok(0)`, never both.
#[cfg(test)]
enum ScriptedFirst {
    /// First write answers `Err(io::ErrorKind::Interrupted)`.
    Interrupted,
    /// First write answers `Ok(0)`.
    Zero,
}

/// A test-only sink seam: the first write injects the scripted [`ScriptedFirst`]
/// outcome without consuming bytes; every later write is a faithful byte sink,
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

    /// Arms the production stdout sink: makes the owned stdout clone
    /// nonblocking so a full or absent stdout pipe can never stall serving.
    /// Because the clone shares the file description with fd 1, this also
    /// flips the process's real stdout. Only the process that owns stdout (the
    /// binary) calls this once after boot, so tests and the library never flip
    /// the descriptor.
    pub(crate) fn prepare_stdout(&mut self) -> Result<(), LogStoreError> {
        match &self.sink.io {
            SinkIo::Stdout(stream) => stream
                .set_nonblocking(true)
                .map_err(|_| LogStoreError::StdoutNonblocking)?,
            #[cfg(test)]
            SinkIo::Fd(_) => {}
            #[cfg(test)]
            SinkIo::Scripted(_) => {}
        }
        Ok(())
    }

    /// Whole-record drops so far; saturates at `u64::MAX`.
    pub(crate) const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Records the current monotonic second so next capacity-edge record
    /// carries real time (review M3).
    pub(crate) const fn set_now(&mut self, secs: u64) {
        self.secs = secs;
    }

    /// Whether the drop counter has been saturated (the overflow state).
    #[cfg(test)]
    pub(crate) const fn dropped_overflow(&self) -> bool {
        self.dropped_overflow
    }

    /// Queued (not yet flushed) record count.
    #[cfg(test)]
    pub(crate) const fn len(&self) -> usize {
        self.count
    }

    /// Whether the queue holds `QUEUE_SLOTS` records.
    #[cfg(test)]
    pub(crate) const fn is_full(&self) -> bool {
        self.count >= QUEUE_SLOTS
    }

    /// The bytes of the most recently committed queued record: test
    /// observation of the exact emitted record text without draining to a
    /// sink, so an integration test can assert the folded monitor fields.
    #[cfg(test)]
    pub(crate) fn last_record_bytes(&self) -> Option<&[u8]> {
        if self.count == 0 {
            return None;
        }
        let index = (self.write_index() + QUEUE_MASK) & QUEUE_MASK;
        Some(&self.slots[index].buf[..self.slots[index].bytes])
    }

    /// The next Instant at which draining the queued logs is useful (N4/T3):
    /// queued non-WouldBlock logs are immediately runnable, WouldBlock-blocked
    /// logs retry on the bounded [`LOG_RETRY`] cadence, and an empty or failed
    /// sink is quiescent (it never wakes a poll).
    pub(crate) fn next_drain(&self, now: Instant) -> Option<Instant> {
        if self.count == 0 || self.sink.failed {
            return None;
        }
        if self.sink.blocked {
            Some(now + LOG_RETRY)
        } else {
            Some(now)
        }
    }

    /// Whether a further drain turn can still deliver queued records: records
    /// remain and the sink is neither stalled mid-write (a retained cursor
    /// awaiting the bounded [`LOG_RETRY`] cadence) nor latched failed. A boot
    /// seam that must deliver more than one [`SINK_MAX_OPS`] budget repeats
    /// [`Self::drain_sink`] only while this holds, so a stalled sink costs one
    /// turn instead of spinning.
    pub(crate) const fn sink_ready(&self) -> bool {
        self.count > 0 && !self.sink.blocked && !self.sink.failed
    }

    /// Accounts for every queued record that no later drain turn can deliver
    /// because the owner is about to exit: each is dropped whole and counted
    /// exactly once in the shared drop tally, and any retained partial cursor
    /// is cleared. Returns how many records were stranded. Used only on the
    /// exit paths, where the queue would otherwise be destroyed uncounted:
    /// queue-accepted records that cannot be drained before the process ends
    /// are counted under the existing whole-record drop accounting, never
    /// silently lost (docs/alumina-proxy.md:197, L18). A path that keeps
    /// running never calls this — it leaves the records queued and retries on
    /// the bounded [`LOG_RETRY`] cadence (`next_drain`).
    pub(crate) const fn strand_queued(&mut self) -> u64 {
        let mut stranded = 0u64;
        while self.count > 0 {
            self.drop_one();
            self.count -= 1;
            stranded += 1;
        }
        self.cursor = None;
        stranded
    }

    /// Total write calls made by the sink (test observation of the per-turn
    /// op budget).
    #[cfg(test)]
    pub(crate) const fn sink_ops(&self) -> usize {
        self.sink.ops
    }

    /// Total write-vector syscalls issued by the sink (test observation of
    /// the gather: fewer syscalls than fragments when fragments coalesce).
    #[cfg(test)]
    pub(crate) const fn sink_syscalls(&self) -> usize {
        self.sink.syscalls
    }

    /// Whether the sink latched failed after a non-WouldBlock write error
    /// (e.g. the stdout pipe closed). The latch is persistent state: no later
    /// drain consumes or clears it, so the serving owner reads it after each
    /// per-turn drain and exits `EX_IOERR` when it is set (F-09).
    pub(crate) const fn sink_has_failed(&self) -> bool {
        self.sink.failed
    }

    /// Marks the drop counter saturated as a test hook for the overflow flag.
    #[cfg(test)]
    pub(crate) const fn saturate_dropped_for_test(&mut self) {
        self.dropped = u64::MAX;
        self.dropped_overflow = true;
    }

    /// The startup first-failure warning: exactly one attempt across all
    /// names and record types (docs/alumina-proxy.md:67), enqueued at the time of the
    /// first counted exchange failure inside the startup window.
    pub(crate) fn startup_warning(&mut self, secs: u64, name: &str, family: Family) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(family)),
        ];
        self.enqueue(Level::Warn, Kind::StartupWarning, &fields);
    }

    /// One warn per counted exchange failure in the serving loop
    /// (docs/alumina-proxy.md:67): the allowlist name (when the ordinal is
    /// still recoverable after the exchange settled) and the structural
    /// failure reason.
    pub(crate) fn exchange_failed(&mut self, secs: u64, name: Option<&str>, reason: &'static str) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("name", Val::OptStr(name)),
            Field::new("reason", Val::Str(reason)),
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
    ) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(family)),
            Field::new("reason", Val::Str(reason)),
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
    ) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(family)),
            Field::new("duration", Val::U64(duration)),
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

    /// One error when a hostname transitions from having eligible bindings to
    /// having none (docs/alumina-proxy.md:79).
    pub(crate) fn incident_eligible_loss(&mut self, secs: u64, name: &str) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("name", Val::Str(name)),
        ];
        self.enqueue(Level::Error, Kind::IncidentEligibleLoss, &fields);
    }

    /// One info when a hostname's eligible bindings recover (docs/alumina-proxy.md:79).
    pub(crate) fn incident_eligible_recovered(&mut self, secs: u64, name: &str) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("name", Val::Str(name)),
        ];
        self.enqueue(Level::Info, Kind::IncidentEligibleRecovered, &fields);
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
            let len = {
                let slot = &mut self.slots[index].buf;
                let mut w = Entry { buf: slot, len: 0 };
                let fits = write_header(&mut w, Level::Error, Kind::Fatal)
                    && w.push(b" secs=")
                    && fmt::Write::write_fmt(&mut w, format_args!("{secs}")).is_ok()
                    && w.push(b" message=\"")
                    && write_fmt_escaped(&mut w, args)
                    && w.push(b"\"")
                    && w.push(b"\n");
                fits.then_some(w.len)
            };
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
        if let Some(edge) = note_usage(&mut self.slots_wm, occupied, crate::worker::MAX_TUNNELS) {
            self.capacity_edge(Dimension::Slots, edge);
        }
        if let Some(edge) = note_usage(
            &mut self.setups_wm,
            pending,
            crate::worker::MAX_PENDING_SETUPS,
        ) {
            self.capacity_edge(Dimension::Setups, edge);
        }
    }

    fn capacity_edge(&mut self, dimension: Dimension, edge: Edge) {
        let (kind, level, used, cap) = match (dimension, edge) {
            (Dimension::Queue, Edge::High { used, cap }) => {
                (Kind::QueueHigh, Level::Error, used, cap)
            }
            (Dimension::Queue, Edge::Low { used, cap }) => (Kind::QueueLow, Level::Info, used, cap),
            (Dimension::Slots | Dimension::Setups, Edge::High { used, cap }) => {
                (Kind::CapacityHigh, Level::Error, used, cap)
            }
            (Dimension::Slots | Dimension::Setups, Edge::Low { used, cap }) => {
                (Kind::CapacityLow, Level::Info, used, cap)
            }
        };
        let secs = self.secs;
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("dimension", Val::Str(dimension.as_str())),
            Field::new("used", Val::U64(used)),
            Field::new("cap", Val::U64(cap)),
        ];
        self.enqueue(level, kind, &fields);
    }

    /// Evaluates the queue watermark on enqueue and again on each drain step
    /// (real-time threshold transitions per review M3).
    fn note_queue_usage(&mut self) {
        if let Some(edge) = note_usage(&mut self.queue_wm, self.count, QUEUE_SLOTS) {
            self.capacity_edge(Dimension::Queue, edge);
        }
    }

    /// Drains the queue through the nonblocking stdout sink under the
    /// per-turn work budget: at most [`SINK_MAX_OPS`] gathered fragments or
    /// [`SINK_MAX_BYTES`] bytes, emitted in a single `write_vectored` call per
    /// turn. A `WouldBlock` retains the partial cursor and yields
    /// immediately; a write/close failure latches the sink failed so no later
    /// drain spins or blocks. The latch is the owner's signal: the serving
    /// owner observes it through [`Self::sink_has_failed`] after each drain
    /// (F-09), and it is persistent state — never consumed or cleared by a
    /// later drain — so a startup-window or probe drain that latches it is
    /// still seen by the first serving owner turn.
    pub(crate) fn drain_sink(&mut self) {
        if self.sink.failed {
            return;
        }
        let mut ops = 0usize;
        let mut bytes_out = 0usize;
        loop {
            if ops >= SINK_MAX_OPS || bytes_out >= SINK_MAX_BYTES {
                return;
            }
            let (index, off) = if let Some(cursor) = self.cursor {
                (self.front, cursor.off)
            } else {
                if self.count == 0 {
                    return;
                }
                (self.front, 0)
            };
            let rec_len = self.slots[index].bytes;
            if off >= rec_len {
                self.advance_front();
                continue;
            }
            let mut iovs: [IoSlice<'_>; SINK_MAX_OPS] = [IoSlice::new(&[]); SINK_MAX_OPS];
            let mut remain = SINK_MAX_BYTES - bytes_out;
            let mut gathered = 0usize;
            while gathered < self.count && gathered < SINK_MAX_OPS && remain > 0 {
                let fi = (index + gathered) & QUEUE_MASK;
                let start = if gathered == 0 { off } else { 0 };
                let end = self.slots[fi].bytes;
                let part = (end - start).min(remain);
                iovs[gathered] = IoSlice::new(&self.slots[fi].buf[start..start + part]);
                gathered += 1;
                remain -= part;
            }
            let written = self.sink.io.write_vectored(&iovs[..gathered]);
            match written {
                Err(ref err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::Interrupted =>
                {
                    self.sink.blocked = true;
                    self.cursor = Some(Cursor { off });
                    return;
                }
                Err(_) => {
                    self.sink.failed = true;
                    while self.count > 0 {
                        self.drop_one();
                        self.count -= 1;
                    }
                    self.cursor = None;
                    return;
                }
                Ok(0) => {
                    self.sink.blocked = true;
                    self.cursor = Some(Cursor { off });
                    return;
                }
                Ok(n) => {
                    ops += gathered;
                    #[cfg(test)]
                    {
                        self.sink.ops += gathered;
                        self.sink.syscalls += 1;
                    }
                    bytes_out += n;
                    self.sink.blocked = false;
                    if self.consume_gathered(index, off, gathered, n) {
                        return;
                    }
                }
            }
        }
    }

    /// Accounts `n` written bytes over the `gathered` fragments of a single
    /// `writev`, advancing the queue front once per fully-emitted record so
    /// watermark edges observe true per-record occupancy. Returns `true` when
    /// the write stopped mid-record (a partial write): the turn must end with
    /// the cursor retained for the drain to resume at the exact residue.
    fn consume_gathered(
        &mut self,
        index: usize,
        off: usize,
        gathered: usize,
        mut n: usize,
    ) -> bool {
        for k in 0..gathered {
            let start = if k == 0 { off } else { 0 };
            let remain = self.slots[(index + k) & QUEUE_MASK].bytes - start;
            if n < remain {
                self.cursor = Some(Cursor { off: start + n });
                return true;
            }
            n -= remain;
            self.advance_front();
        }
        false
    }

    fn advance_front(&mut self) {
        self.cursor = None;
        if self.count > 0 {
            self.count -= 1;
            self.front = (self.front + 1) & QUEUE_MASK;
            self.note_queue_usage();
        }
    }

    const fn write_index(&self) -> usize {
        (self.front + self.count) & QUEUE_MASK
    }

    fn enqueue(&mut self, level: Level, kind: Kind, fields: &[Field<'_>]) {
        if self.count >= QUEUE_SLOTS {
            self.drop_one();
        } else {
            let index = self.write_index();
            match encode_record(&mut self.slots[index].buf, level, kind, fields) {
                Some(len) => self.commit_record(index, len),
                None => self.drop_one(),
            }
        }
        self.note_queue_usage();
    }

    fn commit_record(&mut self, index: usize, len: usize) {
        self.slots[index].bytes = len;
        self.slots[index].reserved = false;
        self.count += 1;
    }

    /// Best-effort enqueue for a non-reserved record built by `encode` (the
    /// `monitor_domain` / `monitor_capture` detail batches). On a full ring the
    /// record is dropped whole without running `encode`; on encode failure it
    /// is dropped too. Returns whether the record was committed. Never calls
    /// `note_queue_usage` (the caller accounts queue pressure once per turn).
    fn enqueue_normal(
        &mut self,
        encode: impl FnOnce(&mut [u8; SLOT_BYTES]) -> Option<usize>,
    ) -> bool {
        if self.count >= QUEUE_SLOTS {
            self.drop_one();
            return false;
        }
        let index = self.write_index();
        if let Some(len) = encode(&mut self.slots[index].buf) {
            self.commit_record(index, len);
            true
        } else {
            self.drop_one();
            false
        }
    }

    /// Enqueues a reserved priority-class record (docs/alumina-proxy.md:1299-1301).
    /// On a full ring the record is encoded into a stack scratch slot first and
    /// only on encode success displaces the newest normal record, so a failed
    /// encode never evicts a held record. Returns whether the record was
    /// committed (admitted or displacing).
    fn enqueue_reserved(
        &mut self,
        kind: Kind,
        encode: impl FnOnce(&mut [u8; SLOT_BYTES]) -> Option<usize>,
    ) -> bool {
        debug_assert!(
            kind.is_reserved(),
            "only reserved priority-class kinds reach enqueue_reserved"
        );
        if self.count >= QUEUE_SLOTS {
            let mut scratch = [0u8; SLOT_BYTES];
            if let Some(len) = encode(&mut scratch) {
                self.displace_reserved(&scratch[..len]);
                true
            } else {
                self.drop_one();
                false
            }
        } else {
            let index = self.write_index();
            if let Some(len) = encode(&mut self.slots[index].buf) {
                self.commit_reserved(index, len);
                true
            } else {
                self.drop_one();
                false
            }
        }
    }

    fn commit_reserved(&mut self, index: usize, len: usize) {
        self.slots[index].bytes = len;
        self.slots[index].reserved = true;
        self.count += 1;
    }

    /// Displaces the newest normal record to admit a reserved one on a full
    /// ring: the reserved block newer than the victim shifts one slot toward
    /// the front and the encoded record takes the newest slot, so only the
    /// newest-lowest-priority record is lost. When every held record is
    /// reserved the newest reserved record is the bounded-not-lossless victim
    /// (docs/alumina-proxy.md:290, :1303).
    fn displace_reserved(&mut self, scratch: &[u8]) {
        let victim = (0..QUEUE_SLOTS)
            .rev()
            .find(|&j| !self.slots[(self.front + j) & QUEUE_MASK].reserved)
            .unwrap_or(QUEUE_SLOTS - 1);
        for j in (victim + 1)..QUEUE_SLOTS {
            self.slots[(self.front + j - 1) & QUEUE_MASK] =
                self.slots[(self.front + j) & QUEUE_MASK];
        }
        self.drop_one();
        let index = (self.front + QUEUE_SLOTS - 1) & QUEUE_MASK;
        self.slots[index].buf[..scratch.len()].copy_from_slice(scratch);
        self.slots[index].bytes = scratch.len();
        self.slots[index].reserved = true;
    }

    const fn drop_one(&mut self) {
        self.dropped = self.dropped.saturating_add(1);
        if self.dropped == u64::MAX {
            self.dropped_overflow = true;
        }
    }
}

/// Evaluates the 80%/70% threshold on a single watermark and latches the
/// transition. Returns the edge to emit, or `None` when no transition occurred.
const fn note_usage(wm: &mut Watermark, used: usize, cap: usize) -> Option<Edge> {
    let used = used as u64;
    let cap = cap as u64;
    let exceeds_high = used.saturating_mul(100) > HIGH_PCT_NUMBER.saturating_mul(cap);
    let below_low = used.saturating_mul(100) < LOW_PCT_NUMBER.saturating_mul(cap);
    if exceeds_high && !wm.crossed_high {
        wm.crossed_high = true;
        Some(Edge::High { used, cap })
    } else if below_low && wm.crossed_high {
        wm.crossed_high = false;
        Some(Edge::Low { used, cap })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::Write as _;

    use crate::config::{CONFIG_DOC_LIMIT, FQDN_MAX_LEN};

    use std::fs::File;
    use std::io::{Read, Seek};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_file() -> File {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "alumina-log-{}-{}.log",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("create temp file")
    }

    fn file_logstore() -> (LogStore, File) {
        let file = temp_file();
        let store = LogStore::with_fd(&file).expect("file sink store");
        (store, file)
    }

    fn read_all(file: &mut File) -> Vec<u8> {
        let mut buf = Vec::new();
        file.rewind().expect("rewind");
        file.read_to_end(&mut buf).expect("read file");
        buf
    }

    fn flush_all(store: &mut LogStore) {
        for _ in 0..(QUEUE_SLOTS + 8) {
            store.drain_sink();
            if store.len() == 0 {
                break;
            }
        }
    }

    #[test]
    fn logging_encoder_frames_and_escapes_deterministically() {
        let (mut store, mut file) = file_logstore();
        store.reject(
            7,
            RejectReason::Capacity,
            Some("127.0.0.1:40000".parse().unwrap()),
            Some("sub.example.org"),
        );
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("ascii record");
        let line = text.lines().next().expect("one record");
        assert!(
            line.starts_with(
                "level=warn kind=reject secs=7 reason=\"capacity\" client=\"127.0.0.1:40000\" hostname=\"sub.example.org\""
            ),
            "got: {line}"
        );
        assert!(text.ends_with('\n'), "newline framing ends the record");
    }

    #[test]
    fn logging_encoder_frames_exchange_failed_with_name_and_reason() {
        let (mut store, mut file) = file_logstore();
        store.exchange_failed(7, Some("sub.example.org"), "tls_identity");
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("ascii record");
        let line = text.lines().next().expect("one record");
        assert!(
            line.starts_with(
                "level=warn kind=exchange_failed secs=7 name=\"sub.example.org\" reason=\"tls_identity\""
            ),
            "got: {line}"
        );
    }

    #[test]
    fn logging_encoder_frames_incident_open_with_family_and_reason() {
        let (mut store, mut file) = file_logstore();
        store.incident_open(7, "sub.example.org", Family::Aaaa, "tls_identity");
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("ascii record");
        let line = text.lines().next().expect("one record");
        assert!(
            line.starts_with(
                "level=warn kind=incident_open secs=7 name=\"sub.example.org\" family=Aaaa reason=\"tls_identity\""
            ),
            "got: {line}"
        );
    }

    #[test]
    fn logging_encoder_frames_incident_recovered_with_family_and_duration() {
        let (mut store, mut file) = file_logstore();
        store.incident_recovered(9, "sub.example.org", Family::A, 42);
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("ascii record");
        let line = text.lines().next().expect("one record");
        assert!(
            line.starts_with(
                "level=info kind=incident_recovered secs=9 name=\"sub.example.org\" family=A duration=42"
            ),
            "got: {line}"
        );
    }

    #[test]
    fn logging_encoder_escapes_quote_backslash_and_control_bytes() {
        let mut name = String::new();
        name.push_str("a\"b");
        name.push('\\');
        name.push('\n');
        name.push('\x01');
        name.push_str(".example.org");
        let (mut store, mut file) = file_logstore();
        store.startup_warning(1, &name, Family::A);
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("escaped ascii");
        assert!(
            text.contains("name=\"a\\\"b\\\\\\x0a\\x01.example.org\""),
            "deterministic escape of quote/backslash/control: {text:?}"
        );
        assert_eq!(
            text.matches('\\').count(),
            5,
            "five escapes, no raw controls"
        );
        assert!(!text.as_bytes().contains(&b'\n') || text.ends_with('\n'));
    }

    /// A distinct 253-byte FQDN (the `FQDN_MAX_LEN` bound) for index `i`:
    /// 63 + 1 + 63 + 1 + 63 + 1 + 61 bytes of legal lowercase labels.
    fn widest_name(index: usize) -> String {
        format!(
            "{index:02}{}.{}.{}.{}",
            "a".repeat(61),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        )
    }

    /// Builds and parses the widest legal configuration: `ALLOWLIST_MAX` keyed
    /// allowlist tables each carrying a `FQDN_MAX_LEN`-byte name, plus
    /// `MAX_RESOLVERS` resolvers carrying `FQDN_MAX_LEN`-byte FQDNs and pins,
    /// all inside `CONFIG_DOC_LIMIT`. The name-bearing worst cases are measured
    /// from this real document rather than a synthetic string.
    fn widest_legal_config() -> (crate::config::Config, String) {
        use crate::config::{ALLOWLIST_MAX, MAX_RESOLVERS};
        let pin = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let mut doc = String::new();
        doc.push_str("listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [");
        for i in 0..MAX_RESOLVERS {
            if i > 0 {
                doc.push_str(", ");
            }
            let _ = write!(
                doc,
                "\"2001:abcd:1234:5678:9abc:def0:1234:567{}#{pin_name}#pin-sha256={pin}\"",
                i + 1,
                pin_name = widest_name(i)
            );
        }
        doc.push_str(
            "]\n[any_illegal]\nconnect_parse = { action = \"block\", scope = \"all\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"all\" }\n",
        );
        for i in 0..ALLOWLIST_MAX {
            let _ = writeln!(
                doc,
                "[allowed_fqdn.\"{name}:443\"]\nearly_data = {{ action = \"block\", scope = \"connection\" }}\nja4 = {{ action = \"block\", scope = \"connection\" }}\n",
                name = widest_name(i)
            );
        }
        let config = crate::config::parse_config_document(&doc).expect("widest legal config");
        (config, doc)
    }

    #[test]
    fn logging_startup_split_records_fit_widest_legal_config() {
        use crate::config::{ALLOWLIST_MAX, CONFIG_DOC_LIMIT};
        use crate::startup_dns::{NameOutcome, NotAttemptedReason};
        let (config, doc) = widest_legal_config();
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "widest legal config fits the documented 16384-byte bound: {}",
            doc.len()
        );
        assert_eq!(config.allowlist().len(), ALLOWLIST_MAX);
        let (mut store, mut file) = file_logstore();
        for (ordinal, name) in config.allowlist().iter().enumerate() {
            assert!(
                store.startup_name(
                    u64::MAX,
                    StartupUnresolved {
                        ordinal: u32::try_from(ordinal).expect("allowlist ordinal fits u32"),
                        name: name.as_str(),
                        outcome: NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed),
                    },
                ),
                "per-name record {ordinal} is never dropped at the widest legal input"
            );
        }
        store.startup_final(
            u64::MAX,
            StartupStatus::Failed,
            FinalCounts {
                unresolved: ALLOWLIST_MAX as u64,
                exchanges: 64,
                failed: 64,
                ..FinalCounts::default()
            },
        );
        assert_eq!(
            store.dropped(),
            0,
            "no size-drop for the widest legal configuration"
        );
        flush_all(&mut store);
        let out = read_all(&mut file);
        let records: Vec<&[u8]> = out
            .split(|&b| b == b'\n')
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(
            records.len(),
            ALLOWLIST_MAX + 1,
            "one startup_name record per unresolved name, then the summary"
        );
        for (ordinal, record) in records.iter().enumerate().take(ALLOWLIST_MAX) {
            assert!(
                record.len() < SLOT_BYTES,
                "per-name record {ordinal} incl framing fits the 2 KiB entry: {}",
                record.len()
            );
            let text = std::str::from_utf8(record).expect("ASCII record");
            assert!(
                text.starts_with("level=info kind=startup_name "),
                "each unresolved name is its own startup_name record: {text}"
            );
            assert!(
                text.contains(config.allowlist().get(ordinal).expect("name").as_str()),
                "the full 253-byte FQDN is carried untruncated: {text}"
            );
        }
        let summary = records[ALLOWLIST_MAX];
        assert!(
            summary.starts_with(b"level=info kind=startup_final "),
            "the last record is the summary"
        );
        assert!(
            summary.windows(13).any(|w| w == b"names_dropped")
                && std::str::from_utf8(summary)
                    .expect("ASCII summary")
                    .contains(" names_dropped=0"),
            "the summary carries the per-name drop accounting"
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one measurement table building the worst-case input for every record kind"
    )]
    fn logging_worst_case_record_per_kind_fits_the_slot_with_margin() {
        use crate::enforcement::monitor::Monitor;
        use crate::incident_report::TypeSummary;
        use crate::startup_dns::{FailureReason, NotAttemptedReason, ProbeVerdict};
        let (config, doc) = widest_legal_config();
        let name = config.allowlist().get(0).expect("widest name").as_str();
        assert_eq!(name.len(), FQDN_MAX_LEN);
        let mut slot = [0u8; SLOT_BYTES];
        let mut worst: Vec<(&str, usize)> = Vec::new();

        let warn = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(Family::Aaaa)),
        ];
        worst.push((
            "startup_warning",
            encode_record(&mut slot, Level::Warn, Kind::StartupWarning, &warn).expect("fits"),
        ));

        worst.push((
            "startup_name",
            encode_record_name(
                &mut slot,
                u64::MAX,
                &StartupUnresolved {
                    ordinal: u32::MAX,
                    name,
                    outcome: NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed),
                },
            )
            .expect("fits"),
        ));

        let summary = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("status", Val::Str("terminated")),
            Field::new("allowance", Val::U64(u64::MAX)),
            Field::new("usable", Val::U64(u64::MAX)),
            Field::new("unresolved", Val::U64(u64::MAX)),
            Field::new("exchanges", Val::U64(u64::MAX)),
            Field::new("failed", Val::U64(u64::MAX)),
            Field::new("not_attempted", Val::U64(u64::MAX)),
            Field::new("dropped", Val::U64(u64::MAX)),
            Field::new("names_dropped", Val::U64(u64::MAX)),
        ];
        worst.push((
            "startup_final",
            encode_record_final(&mut slot, Level::Info, Kind::StartupFinal, &summary)
                .expect("fits"),
        ));

        let fatal_msg = "m".repeat(300);
        let fatal = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("message", Val::Str(&fatal_msg)),
        ];
        worst.push((
            "fatal",
            encode_record(&mut slot, Level::Error, Kind::Fatal, &fatal).expect("fits"),
        ));

        let shutdown = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("status", Val::Str("drained")),
            Field::new("dropped", Val::U64(u64::MAX)),
        ];
        worst.push((
            "shutdown_final",
            encode_record(&mut slot, Level::Info, Kind::ShutdownFinal, &shutdown).expect("fits"),
        ));

        let peer: SocketAddr = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535"
            .parse()
            .expect("widest peer");
        let reject = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("reason", Val::Str("tls_validation")),
            Field::new("client", Val::OptAddr(Some(peer))),
            Field::new("hostname", Val::OptStr(Some(name))),
        ];
        worst.push((
            "reject",
            encode_record(&mut slot, Level::Warn, Kind::Reject, &reject).expect("fits"),
        ));

        let activity = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("hostname", Val::OptStr(Some(name))),
            Field::new("peer", Val::OptAddr(Some(peer))),
            Field::new("activity", Val::Str("reset")),
        ];
        worst.push((
            "early_activity",
            encode_record(&mut slot, Level::Warn, Kind::EarlyActivity, &activity).expect("fits"),
        ));

        let threshold = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("dimension", Val::Str("setups")),
            Field::new("used", Val::U64(u64::MAX)),
            Field::new("cap", Val::U64(u64::MAX)),
        ];
        for (kind_name, kind, level) in [
            ("capacity_high", Kind::CapacityHigh, Level::Error),
            ("capacity_low", Kind::CapacityLow, Level::Info),
            ("queue_high", Kind::QueueHigh, Level::Error),
            ("queue_low", Kind::QueueLow, Level::Info),
        ] {
            worst.push((
                kind_name,
                encode_record(&mut slot, level, kind, &threshold).expect("fits"),
            ));
        }

        let exchange = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("name", Val::OptStr(Some(name))),
            Field::new("reason", Val::Str("tls_identity")),
        ];
        worst.push((
            "exchange_failed",
            encode_record(&mut slot, Level::Warn, Kind::ExchangeFailed, &exchange).expect("fits"),
        ));

        let incident_open = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(Family::Aaaa)),
            Field::new("reason", Val::Str("tls_identity")),
        ];
        worst.push((
            "incident_open",
            encode_record(&mut slot, Level::Warn, Kind::IncidentOpen, &incident_open)
                .expect("fits"),
        ));

        let incident_recovered = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(Family::Aaaa)),
            Field::new("duration", Val::U64(u64::MAX)),
        ];
        worst.push((
            "incident_recovered",
            encode_record(
                &mut slot,
                Level::Info,
                Kind::IncidentRecovered,
                &incident_recovered,
            )
            .expect("fits"),
        ));

        let incident_summary = IncidentSummary {
            window_start: u64::MAX - 1,
            window_end: u64::MAX,
            duration: 1,
            skipped: u32::MAX,
            overflow: true,
            types: [
                TypeSummary {
                    start: Some(u64::MAX - 1),
                    elapsed: u64::MAX,
                    reason: Some("tls_identity"),
                    last_positive: Some(u64::MAX),
                    attempts: u64::MAX,
                    failures: u64::MAX,
                    addrs: u64::MAX,
                    state: "retired",
                    freshness: Some(u64::MAX),
                    retirement: Some(u64::MAX),
                },
                TypeSummary {
                    start: Some(u64::MAX - 1),
                    elapsed: u64::MAX,
                    reason: Some("tls_identity"),
                    last_positive: Some(u64::MAX),
                    attempts: u64::MAX,
                    failures: u64::MAX,
                    addrs: u64::MAX,
                    state: "retired",
                    freshness: Some(u64::MAX),
                    retirement: Some(u64::MAX),
                },
            ],
            tunnels: u64::MAX,
            bytes: u64::MAX,
            stale: u64::MAX,
        };
        worst.push((
            "incident_summary",
            encode_record(
                &mut slot,
                Level::Error,
                Kind::IncidentSummary,
                &incident_summary_fields(u64::MAX, name, &incident_summary),
            )
            .expect("fits"),
        ));

        let incident_eligible = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("name", Val::Str(name)),
        ];
        worst.push((
            "incident_eligible_loss",
            encode_record(
                &mut slot,
                Level::Error,
                Kind::IncidentEligibleLoss,
                &incident_eligible,
            )
            .expect("fits"),
        ));
        worst.push((
            "incident_eligible_recovered",
            encode_record(
                &mut slot,
                Level::Info,
                Kind::IncidentEligibleRecovered,
                &incident_eligible,
            )
            .expect("fits"),
        ));

        let mut monitor = Monitor::new();
        monitor.saturate_all_for_test();
        monitor.set_peer_ip_v6_max_for_test();
        monitor.note_serving_stale();
        monitor.note_fact_downgrade_to_plain();
        worst.push((
            "monitor_summary",
            encode_monitor_summary(&mut slot, u64::MAX, &monitor).expect("fits"),
        ));
        let mut domain_start = 0usize;
        worst.push((
            "monitor_domain",
            encode_monitor_domain_batch(&mut slot, u64::MAX, 1, 3, &monitor, &mut domain_start)
                .expect("fits"),
        ));
        let mut capture_start = 0usize;
        worst.push((
            "monitor_capture",
            encode_monitor_capture_batch(&mut slot, u64::MAX, 1, 3, &monitor, &mut capture_start)
                .expect("fits"),
        ));

        let set = config.resolver_set();
        let mut segments = [ResolverProbeSegment {
            index: 0,
            addr: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            fqdn: None,
            pin: false,
            verdict: ProbeVerdict::NotProbed,
        }; crate::config::MAX_RESOLVERS];
        for (i, seg) in segments.iter_mut().enumerate() {
            let resolver = set.get(i).expect("widest resolver");
            *seg = ResolverProbeSegment {
                index: u32::try_from(i).expect("resolver index fits u32"),
                addr: resolver.addr(),
                fqdn: resolver.fqdn(),
                pin: resolver.pin().is_some(),
                verdict: ProbeVerdict::Failed(FailureReason::TlsIdentity),
            };
        }
        worst.push((
            "resolver_probe",
            encode_record_probe(&mut slot, u64::MAX, &segments).expect("fits"),
        ));

        assert_eq!(worst.len(), 21, "every record kind is measured");
        for (kind_name, len) in &worst {
            eprintln!(
                "worst-case {kind_name:<16} {len:>5} B record, {:>5} B margin",
                SLOT_BYTES - len
            );
            assert!(
                *len < SLOT_BYTES,
                "{kind_name} worst case incl framing fits the 2 KiB entry: {len}"
            );
            if kind_name.starts_with("monitor") {
                assert!(
                    *len <= MONITOR_RECORD_MAX,
                    "{kind_name} worst case fits the 2048 B monitor record bound: {len}"
                );
            }
        }
        let name_len = worst
            .iter()
            .find(|(k, _)| *k == "startup_name")
            .expect("startup_name measured")
            .1;
        assert_eq!(
            name_len, STARTUP_NAME_MAX,
            "the measured startup_name worst case is exactly the const bound"
        );
        let probe_len = worst
            .iter()
            .find(|(k, _)| *k == "resolver_probe")
            .expect("probe measured")
            .1;
        assert!(
            probe_len <= RESOLVER_PROBE_MAX,
            "measured resolver_probe worst case {probe_len} within the const bound {RESOLVER_PROBE_MAX}"
        );
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "the widest legal document stays inside the config bound: {}",
            doc.len()
        );
    }

    #[test]
    fn logging_startup_name_drop_counts_exactly_once_per_attempt() {
        use crate::startup_dns::NameOutcome;
        let un = StartupUnresolved {
            ordinal: 0,
            name: "a.example.org",
            outcome: NameOutcome::Negative,
        };
        let (mut full, _file) = file_logstore();
        let mut filled = 0usize;
        while !full.is_full() {
            assert!(full.startup_name(1, un), "filling the queue");
            filled += 1;
            assert!(filled <= QUEUE_SLOTS, "the queue fills within its capacity");
        }
        let before = full.dropped();
        assert!(
            !full.startup_name(1, un),
            "a full queue refuses the per-name record"
        );
        assert_eq!(
            full.dropped(),
            before + 1,
            "a queue-full per-name attempt increments the shared counter once"
        );

        let long = "z".repeat(SLOT_BYTES * 2);
        let (mut store, _file) = file_logstore();
        assert!(
            !store.startup_name(
                1,
                StartupUnresolved {
                    ordinal: 0,
                    name: &long,
                    outcome: NameOutcome::Negative,
                }
            ),
            "an oversize per-name record is dropped whole"
        );
        assert_eq!(
            store.dropped(),
            1,
            "an encode-overflow per-name attempt increments the shared counter once"
        );
        assert_eq!(
            store.len(),
            0,
            "nothing is committed for the dropped record"
        );
    }

    #[test]
    fn logging_fatal_record_exact_grammar() {
        let (mut store, mut file) = file_logstore();
        store.fatal(7, format_args!("serving failed"));
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text, "level=error kind=fatal secs=7 message=\"serving failed\"\n",
            "the fatal record is one error record carrying the bounded message field"
        );
    }

    #[test]
    fn logging_startup_split_carries_each_name_outcome_and_reason() {
        use crate::startup_dns::{FailureReason, NameOutcome, NotAttemptedReason};
        let (mut store, mut file) = file_logstore();
        for un in [
            StartupUnresolved {
                ordinal: 0,
                name: "neg.example.org",
                outcome: NameOutcome::Negative,
            },
            StartupUnresolved {
                ordinal: 1,
                name: "fail.example.org",
                outcome: NameOutcome::Failed(FailureReason::Timeout),
            },
            StartupUnresolved {
                ordinal: 2,
                name: "skip.example.org",
                outcome: NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed),
            },
        ] {
            assert!(store.startup_name(9, un), "per-name record enqueued");
        }
        store.startup_final(9, StartupStatus::Failed, FinalCounts::default());
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text,
            "level=info kind=startup_name secs=9 ordinal=0 name=\"neg.example.org\" outcome=negative\n\
             level=info kind=startup_name secs=9 ordinal=1 name=\"fail.example.org\" outcome=failed reason=\"timeout\"\n\
             level=info kind=startup_name secs=9 ordinal=2 name=\"skip.example.org\" outcome=not_attempted reason=\"window_closed\"\n\
             level=info kind=startup_final secs=9 status=\"failure\" allowance=0 usable=0 unresolved=0 exchanges=0 failed=0 not_attempted=0 dropped=0 names_dropped=0\n",
            "each name carries its outcome and reason in its own record, then the summary"
        );
    }

    #[test]
    fn logging_oversize_record_is_dropped_whole_and_counted() {
        let long = "z".repeat(SLOT_BYTES * 2);
        let (mut store, _file) = file_logstore();
        store.startup_warning(1, &long, Family::A);
        assert_eq!(store.dropped(), 1, "oversize record dropped whole");
        assert_eq!(store.len(), 0, "nothing queued for the oversize record");
    }

    #[test]
    fn logging_resolver_probe_embeds_segments_inline_with_reasons() {
        use crate::startup_dns::FailureReason;
        let b64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let doc = format!(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1#one.one.one.one\", \"9.9.9.9#dns.quad9.net\", \"8.8.8.8#dns.google#pin-sha256={b64}\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"a.example:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
        );
        let config = crate::config::parse_config_document(&doc).expect("valid config");
        let resolvers = config.resolver_set();
        let bare = resolvers.get(0).expect("resolver 0");
        let quad9 = resolvers.get(1).expect("resolver 1");
        let google = resolvers.get(2).expect("resolver 2");
        let (mut store, mut file) = file_logstore();
        store.resolver_probe(
            11,
            &[
                ResolverProbeSegment {
                    index: 0,
                    addr: bare.addr(),
                    fqdn: bare.fqdn(),
                    pin: bare.pin().is_some(),
                    verdict: ProbeVerdict::Ok,
                },
                ResolverProbeSegment {
                    index: 1,
                    addr: quad9.addr(),
                    fqdn: quad9.fqdn(),
                    pin: quad9.pin().is_some(),
                    verdict: ProbeVerdict::Failed(FailureReason::Timeout),
                },
                ResolverProbeSegment {
                    index: 2,
                    addr: google.addr(),
                    fqdn: google.fqdn(),
                    pin: google.pin().is_some(),
                    verdict: ProbeVerdict::NotProbed,
                },
            ],
        );
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text,
            "level=info kind=resolver_probe secs=11 resolver0=\"1.1.1.1\" fqdn0=\"one.one.one.one\" verdict0=ok resolver1=\"9.9.9.9\" fqdn1=\"dns.quad9.net\" verdict1=failed reason1=\"timeout\" resolver2=\"8.8.8.8\" fqdn2=\"dns.google\" pin2=1 verdict2=not_probed\n",
            "single probe record embeds resolver/verdict/reason inline per resolver, no fan-out"
        );
    }

    #[test]
    fn logging_oversize_probe_record_is_dropped_whole_and_counted() {
        use crate::startup_dns::FailureReason;
        let doc = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1#dns.google\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n";
        let config = crate::config::parse_config_document(doc).expect("valid config");
        let fqdn = config
            .resolver_set()
            .primary()
            .fqdn()
            .expect("fqdn carried");
        // The probe record is structurally bounded (MAX_RESOLVERS × FQDN_MAX_LEN
        // ≪ 2 KiB) for any real resolver set, so the only way to reach the
        // oversize path is a caller-supplied segment set far beyond the slot.
        let segments: Vec<ResolverProbeSegment<'_>> = (0..3000u32)
            .map(|i| ResolverProbeSegment {
                index: i,
                addr: "1.1.1.1".parse().expect("ip"),
                fqdn: Some(fqdn),
                pin: true,
                verdict: ProbeVerdict::Failed(FailureReason::Timeout),
            })
            .collect();
        let (mut store, _file) = file_logstore();
        store.resolver_probe(1, &segments);
        assert_eq!(store.dropped(), 1, "oversize probe record dropped whole");
        assert_eq!(
            store.len(),
            0,
            "nothing queued for the oversize probe record"
        );
    }

    #[test]
    fn logging_queue_drops_when_full_and_counts() {
        let (mut store, _file) = file_logstore();
        for _ in 0..(QUEUE_SLOTS + 40) {
            store.startup_warning(1, "sub.example.org", Family::A);
        }
        assert!(store.is_full(), "queue must be full after overfilling");
        assert_eq!(store.len(), QUEUE_SLOTS, "capacity never exceeds the bound");
        assert_eq!(
            store.dropped(),
            41,
            "296 warnings + 1 high edge on a 256-slot queue: whole-record drops are counted exactly (review M6)"
        );
        assert!(!store.dropped_overflow());
    }

    #[test]
    fn logging_monitor_full_queue_tallies_refused_detail_batches_per_class() {
        use crate::enforcement::monitor::{CapturedDetail, SlotCapture};
        let (mut store, _file) = file_logstore();
        for _ in 0..QUEUE_SLOTS {
            store.startup_warning(1, "sub.example.org", Family::A);
        }
        assert!(store.is_full(), "ring is full before the monitor summary");
        let mut m = Monitor::new();
        for index in 0..(2 * DOMAIN_BATCH) {
            m.note_fact_early_data(DomainOrdinal::from_index(index).expect("ordinal in range"));
        }
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        for i in 0..(CAPTURE_BATCH + 1) {
            m.note_consumed_capture(SlotCapture {
                slot: i,
                generation: 1,
                detail: Some(CapturedDetail {
                    fact: CapturedFact::AnyIllegal(cause),
                    effect,
                }),
            });
        }
        let domain_batches = count_domain_batches(&m);
        let capture_batches = count_capture_batches(&m);
        assert_eq!(
            domain_batches, 2,
            "22 nonzero ordinals pack into 2 monitor_domain batches at 11 ordinals each"
        );
        assert_eq!(
            capture_batches, 2,
            "23 captures pack into 2 monitor_capture batches at 22 details each"
        );
        let dropped_before = store.dropped();
        assert!(
            store.monitor_summary(9, &mut m),
            "the reserved summary always commits (displaces a normal record on a full ring)"
        );
        assert_eq!(
            m.report_drops(),
            2,
            "RC2 F1: one report_drop per refused monitor_domain batch — exactly 2 batches on this full queue"
        );
        assert_eq!(
            m.capture_drops(),
            2,
            "RC3 F1: one capture_drop per refused monitor_capture batch — exactly 2 batches on this full queue"
        );
        assert_eq!(
            store.dropped(),
            dropped_before + 1 + u64::from(domain_batches + capture_batches),
            "whole-record accounting: the reserved displacement plus one generic drop per refused detail batch (no silent loss)"
        );
    }

    #[test]
    fn logging_monitor_queued_capture_batch_stranded_on_sink_failure_is_generic_drop() {
        use crate::enforcement::monitor::{CapturedDetail, SlotCapture};
        let (reader, writer) = UnixStream::pair().expect("socketpair");
        drop(reader);
        let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
        let mut m = Monitor::new();
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        for i in 0..CAPTURE_BATCH {
            m.note_consumed_capture(SlotCapture {
                slot: i,
                generation: 1,
                detail: Some(CapturedDetail {
                    fact: CapturedFact::AnyIllegal(cause),
                    effect,
                }),
            });
        }
        assert_eq!(
            count_capture_batches(&m),
            1,
            "22 captures pack into a single monitor_capture batch"
        );
        assert!(
            store.monitor_summary(9, &mut m),
            "the detail batch enqueues while the sink is still healthy"
        );
        assert_eq!(
            m.capture_drops(),
            0,
            "a successfully queued detail batch is never a capture_drop"
        );
        assert_eq!(m.report_drops(), 0, "and never a report_drop either");
        assert_eq!(
            store.len(),
            2,
            "reserved summary plus one capture detail batch are queued"
        );
        let dropped_before = store.dropped();
        store.drain_sink();
        assert!(store.sink_has_failed(), "EPIPE latches the sink failed");
        assert_eq!(
            store.len(),
            0,
            "stranded records are cleared, never retained"
        );
        assert_eq!(
            store.dropped(),
            dropped_before + 2,
            "RC4 F4-F7: an already-queued detail batch stranded at drain is counted as a whole-record drop"
        );
        assert_eq!(
            m.capture_drops(),
            0,
            "capture_drops untouched: drain_sink's whole-record drop path is type-separated from the monitor counters (unit-split pin, not a runtime call)"
        );
        let _ = writer;
    }

    #[test]
    fn logging_strand_queued_counts_forced_summary_residue_never_monitor_drops() {
        use crate::enforcement::monitor::{CapturedDetail, SlotCapture};
        let (mut store, _file) = file_logstore();
        let mut m = Monitor::new();
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        for i in 0..CAPTURE_BATCH {
            m.note_consumed_capture(SlotCapture {
                slot: i,
                generation: 1,
                detail: Some(CapturedDetail {
                    fact: CapturedFact::AnyIllegal(cause),
                    effect,
                }),
            });
        }
        assert!(
            store.monitor_summary(9, &mut m),
            "the forced monitor summary commits like the shutdown forced-report path"
        );
        assert_eq!(
            store.len(),
            2,
            "reserved summary plus one capture detail batch are queued"
        );
        let dropped_before = store.dropped();
        let stranded = store.strand_queued();
        assert_eq!(stranded, 2, "the exit path strands every queued record");
        assert_eq!(
            store.dropped(),
            dropped_before + 2,
            "stranded residue (incl. a forced shutdown summary) is counted once as whole-record drops, never silently lost (L18)"
        );
        assert_eq!(
            m.capture_drops(),
            0,
            "capture_drops untouched: strand_queued takes only &mut LogStore, so the monitor counters are type-separated here (mechanism-level pin, not call-site)"
        );
        assert_eq!(
            m.report_drops(),
            0,
            "report_drops untouched: type-separated from LogStore::strand_queued by its signature"
        );
        assert_eq!(store.len(), 0, "queue is empty after stranding");
    }

    #[test]
    fn logging_drop_counter_saturation_sets_overflow_state() {
        let (mut store, _file) = file_logstore();
        store.saturate_dropped_for_test();
        store.startup_warning(1, "sub.example.org", Family::A);
        assert_eq!(
            store.dropped(),
            u64::MAX,
            "drop count saturates, never wraps"
        );
        assert!(store.dropped_overflow(), "overflow flag latches");
    }

    #[test]
    fn logging_sink_budget_binds_on_ops_then_bytes() {
        let (mut store, mut file) = file_logstore();
        let filler = "filler.example.org";
        for _ in 0..(SINK_MAX_BYTES / 512) {
            store.startup_warning(1, filler, Family::A);
        }
        store.drain_sink();
        assert!(
            store.sink_ops() <= SINK_MAX_OPS,
            "op cap bounds one turn: {} ops",
            store.sink_ops()
        );
        let out = read_all(&mut file);
        assert!(
            out.len() <= SINK_MAX_BYTES,
            "byte cap bounds one turn: {}",
            out.len()
        );
        assert!(
            store.len() > 0,
            "unspent records stay queued for a later turn"
        );
        flush_all(&mut store);
        assert_eq!(store.len(), 0, "later turns flush the remainder");
    }

    #[test]
    fn logging_threshold_high_then_low_edges() {
        let (mut store, mut file) = file_logstore();
        for used in 0..=410usize {
            store.note_capacity(1, used, 0);
        }
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=capacity_high secs=1 dimension=\"slots\" used=410 cap=512"),
            "high edge at first exceed of 80%: {text}"
        );
        assert!(
            !text.contains("kind=capacity_low"),
            "no low edge before any high edge"
        );
        store.note_capacity(2, 358, 0);
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=capacity_low secs=2 dimension=\"slots\" used=358 cap=512"),
            "low edge after crossing below 70%: {text}"
        );
    }

    #[test]
    fn logging_early_activity_exact_record_unique_keys() {
        let (mut store, mut file) = file_logstore();
        store.early_activity(
            4,
            Some("sub.example.org"),
            Some("127.0.0.1:40000".parse().unwrap()),
            ActivityKind::Data,
        );
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text,
            "level=warn kind=early_activity secs=4 hostname=\"sub.example.org\" peer=\"127.0.0.1:40000\" activity=\"data\"\n",
            "exact early-activity record, no duplicate kind key (review R3/M1)"
        );
        assert_eq!(
            text.matches("kind=").count(),
            1,
            "the record key kind appears exactly once"
        );
    }

    #[test]
    fn logging_queue_threshold_edges_real_secs_on_enqueue_and_drain() {
        let (mut store, mut file) = file_logstore();
        for _ in 0..249 {
            store.startup_warning(100, "sub.example.org", Family::A);
        }
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=queue_high secs=100 dimension=\"queue\" used=205 cap=256"),
            "high edge at first exceed of 80% with the enqueue secs: {text}"
        );
        assert_eq!(
            store.dropped(),
            0,
            "204.8 threshold crossing must not drop records"
        );
        assert!(
            text.contains("kind=queue_low"),
            "low edge present after drain: {text}"
        );
        let low_line = text.lines().find(|l| l.contains("kind=queue_low")).unwrap();
        let exp = "kind=queue_low secs=";
        let idx = low_line.find(exp).expect("low edge has real secs");
        assert!(
            low_line[idx..].starts_with(exp) && !low_line[idx + exp.len()..].starts_with('0'),
            "low edge carries the real monotonic sec (review M3), got: {low_line}"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn logging_monitor_summary_exact_grammar_and_zero_suppression() {
        use crate::eligibility::NumericAddr;
        use crate::enforcement::action::{DomainOrdinal, Scope};
        use crate::enforcement::monitor::{DnsAnomalyKind, Monitor};
        use crate::enforcement::policy::UnknownReason;
        use std::net::Ipv4Addr;
        let mut m = Monitor::new();
        m.note_fact_any_illegal(crate::enforcement::policy::AnyIllegalCause::HostNotAllowlisted);
        m.note_fact_any_illegal(crate::enforcement::policy::AnyIllegalCause::HostNotAllowlisted);
        m.note_fact_unknown(UnknownReason::Unattributed);
        m.note_fact_resolver_degraded();
        m.note_fact_dns_anomaly(DnsAnomalyKind::BailiwickViolation);
        let ordinal = DomainOrdinal::from_index(0).expect("bound-level ordinal");
        m.note_fact_early_data(ordinal);
        m.note_fact_expired_pin_cert();
        m.note_fact_ja4_seed();
        m.note_fact_ja4_change(
            ordinal,
            *b"t13d1516h2_8daaf6152771_02713d6af862",
            NumericAddr::V4(Ipv4Addr::from([203, 0, 113, 1])),
        );
        m.note_action_first_slot_block(Scope::Connection);
        m.note_action_domain_block(ordinal);
        m.note_action_notify(ordinal);
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text,
            "level=info kind=monitor secs=7 facts_total=9 actions_total=3 refusals_total=0 \
             ofacts=0 oactions=0 orefusals=0 report_drops=0 oreport_drops=0 capture_drops=0 \
             ocapture_drops=0 s0=1 s1=0 ba=0 rd=1 ep=1 js=1 bv=1 \
             c15=2 unk3=1 dx=1\n\
             level=info kind=monitor_domain secs=7 part=1/1 d0f=1 d0b=1 d0n=1 d0j=1 \
             d0v=\"t13d1516h2_8daaf6152771_02713d6af862\" d0p=\"cb007101\"\n",
            "exact monitor grammar: the summary carries the fixed core and dx bitset, the single nonzero domain block rides its monitor_domain batch"
        );
        assert!(
            text.contains(" rd=1"),
            "the resolver-degraded fact key carries its fold: {text}"
        );
        assert!(
            !text.contains("rd=0"),
            "a zero resolver-degraded fold stays suppressed: {text}"
        );
        assert!(
            text.contains(" ep=1"),
            "the expired-pin-cert fact key carries its fold: {text}"
        );
        assert!(
            !text.contains("ep=0"),
            "a zero expired-pin-cert fold stays suppressed: {text}"
        );
        assert!(
            text.contains(" rd=1 ep=1 js=1 bv=1"),
            "the expired-pin fold and ja4-seed fold follow the resolver-degraded fold, then the dns-anomaly `bv` key: {text}"
        );
        assert!(
            text.contains(" js=1"),
            "the ja4-seed fact key carries its fold: {text}"
        );
        assert!(
            text.contains(" bv=1"),
            "the bailiwick-violation anomaly key carries its fold: {text}"
        );
        assert!(
            !text.contains("rpm="),
            "a zero ResolverPeerMismatch fold stays suppressed: {text}"
        );
        assert!(
            !text.contains("xttl="),
            "a zero ExtremeTtl fold stays suppressed: {text}"
        );
        assert!(
            text.contains(" c15=2"),
            "the AnyIllegal cause index 15 (HostNotAllowlisted) carries its fold: {text}"
        );
        assert!(
            text.contains("unk3=1"),
            "the Unattributed unknown reason index 3 carries its fold: {text}"
        );
        assert!(
            !text.contains("c0="),
            "zero causes stay suppressed (no c0 key)"
        );
        assert!(!text.contains(" d0="), "M4: no empty-valued d0 marker key");
        assert!(
            !text.contains(" r=1"),
            "M4: per-field zero-suppression drops the zero refusal field"
        );
        assert!(
            text.contains(" d0j=1"),
            "the per-ordinal ja4-change fold carries its key: {text}"
        );
        assert!(
            text.contains(" d0v=\"t13d1516h2_8daaf6152771_02713d6af862\""),
            "the per-ordinal ja4-change value carries the 36-char JA4: {text}"
        );
        assert!(
            text.contains(" d0p=\"cb007101\""),
            "the latest-overflow ordinal's peer IP rides beside the ja4-change value: {text}"
        );
        assert!(
            !text.contains("d1j="),
            "a zero ja4-change fold on another ordinal stays suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_summary_emits_positive_rpm_and_xttl() {
        use crate::enforcement::monitor::{DnsAnomalyKind, Monitor};
        let mut m = Monitor::new();
        m.note_fact_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch);
        m.note_fact_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch);
        m.note_fact_dns_anomaly(DnsAnomalyKind::ExtremeTtl);
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains(" rpm=2"),
            "the resolver-peer-mismatch anomaly key carries its fold: {text}"
        );
        assert!(
            text.contains(" xttl=1"),
            "the extreme-ttl anomaly key carries its fold: {text}"
        );
    }

    #[cfg(test)]
    #[test]
    fn logging_monitor_all_saturated_record_fits_the_2k_slot() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.saturate_all_for_test();
        assert!(
            m.capture_detail_len() == crate::enforcement::monitor::CAPTURE_DETAIL_LEN,
            "the worst-case fixture fills the whole correlated-detail ring"
        );
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        for line in text.lines() {
            assert!(
                line.len() + 1 < SLOT_BYTES,
                "every emitted record stays inside the 2 KiB slot: {} bytes in {line}",
                line.len() + 1
            );
        }
        assert!(
            text.contains("ofacts=1"),
            "saturation latches the aggregate overflow flags: {text}"
        );
        assert!(
            text.contains("ocapture_drops=1"),
            "correlated-detail loss latches its own overflow: {text}"
        );
        assert!(
            text.contains("x0g="),
            "the correlated-detail section is emitted once captures exist: {text}"
        );
        assert!(
            text.contains("x0s=511"),
            "the all-saturated capture ring carries its worst legal slot identity: {text}"
        );
        assert!(
            text.contains(" sn=32"),
            "the saturated sustained-negatives level is emitted: {text}"
        );
        assert!(
            text.contains(" js=4294967295"),
            "the saturated ja4-seed fold is emitted: {text}"
        );
        assert!(
            text.contains(" d31p=\"cb007101\""),
            "saturation keys the latest-overflow peer IP to the last ordinal: {text}"
        );
    }

    #[test]
    fn logging_monitor_emits_serving_stale_level_bit_when_latched() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.note_serving_stale();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains(" ss=1"),
            "the latched stale-serving level bit must be emitted: {text}"
        );
        assert!(
            !text.contains("ss=0"),
            "the bit is emitted only when latched, never as a zero: {text}"
        );
    }

    #[test]
    fn logging_monitor_suppresses_serving_stale_when_clear() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            !text.contains("ss="),
            "a clear stale-serving bit stays zero-suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_emits_sustained_negatives_when_nonzero() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.note_incident_open();
        m.note_incident_open();
        m.note_incident_open();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains(" sn=3"),
            "the sustained-negatives level carries its count: {text}"
        );
        assert!(
            !text.contains("sn=0"),
            "a zero sustained-negatives level stays suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_suppresses_sustained_negatives_when_zero() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            !text.contains("sn="),
            "a zero sustained-negatives level stays zero-suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_emits_downgrade_to_plain_when_nonzero() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.note_fact_downgrade_to_plain();
        m.note_fact_downgrade_to_plain();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains(" dp=2"),
            "the downgrade-to-plain fact key carries its fold: {text}"
        );
        assert!(
            !text.contains("dp=0"),
            "a zero downgrade fold stays suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_suppresses_downgrade_to_plain_when_zero() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            !text.contains("dp="),
            "a zero downgrade-to-plain fold stays zero-suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_emits_probe_relocations_when_nonzero() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.note_fact_probe_relocation();
        m.note_fact_probe_relocation();
        m.note_fact_probe_relocation();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains(" pr=3"),
            "the probe-relocation fact key carries its fold: {text}"
        );
        assert!(
            !text.contains("pr=0"),
            "a zero probe-relocation fold stays suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_suppresses_probe_relocations_when_zero() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            !text.contains("pr="),
            "a zero probe-relocation fold stays zero-suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_all_saturated_with_serving_stale_fits_the_2k_slot() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.saturate_all_for_test();
        m.note_serving_stale();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        for line in text.lines() {
            assert!(
                line.len() + 1 < SLOT_BYTES,
                "every emitted record stays inside the 2 KiB slot: {} bytes in {line}",
                line.len() + 1
            );
        }
        assert!(
            text.contains(" ss=1"),
            "the latched stale-serving bit survives the saturated record: {text}"
        );
        assert!(
            text.contains(" sn=32"),
            "the saturated sustained-negatives level survives the saturated record: {text}"
        );
        assert!(
            text.contains(" js=4294967295"),
            "the saturated ja4-seed fold survives the saturated record: {text}"
        );
        assert!(
            text.contains(" d31p=\"cb007101\""),
            "the latest-overflow peer IP survives the saturated record: {text}"
        );
    }

    #[test]
    fn logging_monitor_family_each_record_fits_monitor_record_max() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.saturate_all_for_test();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            7,
            "the saturated family is one summary plus 3 domain and 3 capture batches: {text}"
        );
        let mut summaries = 0;
        let mut domains = 0;
        let mut captures = 0;
        for line in &lines {
            assert!(
                line.len() + 1 < MONITOR_RECORD_MAX,
                "every family record stays under the 2048 B cap: {} bytes in {line}",
                line.len() + 1
            );
            if line.starts_with("level=info kind=monitor ") {
                summaries += 1;
            } else if line.starts_with("level=info kind=monitor_domain ") {
                domains += 1;
            } else if line.starts_with("level=info kind=monitor_capture ") {
                captures += 1;
            }
        }
        assert_eq!(summaries, 1, "exactly one summary record");
        assert_eq!(
            domains, 3,
            "32 saturated ordinals pack into 3 domain batches"
        );
        assert_eq!(
            captures, 3,
            "64 saturated details pack into 3 capture batches"
        );
        let mut parts: Vec<&str> = lines
            .iter()
            .filter(|l| l.starts_with("level=info kind=monitor_domain "))
            .map(|l| {
                l.split(" part=")
                    .nth(1)
                    .expect("part field")
                    .split(' ')
                    .next()
                    .expect("part token")
            })
            .collect();
        parts.sort_unstable();
        assert_eq!(
            parts,
            vec!["1/3", "2/3", "3/3"],
            "domain batches carry sequential part=n/total markers"
        );
        let mut capture_parts: Vec<&str> = lines
            .iter()
            .filter(|l| l.starts_with("level=info kind=monitor_capture "))
            .map(|l| {
                l.split(" part=")
                    .nth(1)
                    .expect("part field")
                    .split(' ')
                    .next()
                    .expect("part token")
            })
            .collect();
        capture_parts.sort_unstable();
        assert_eq!(
            capture_parts,
            vec!["1/3", "2/3", "3/3"],
            "capture batches carry sequential part=n/total markers"
        );
    }

    #[cfg(test)]
    #[test]
    fn logging_monitor_emits_distinct_slot_identity_for_equal_generation_slots() {
        use crate::enforcement::monitor::{CapturedDetail, SlotCapture};
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        let cap = |slot, generation| SlotCapture {
            slot,
            generation,
            detail: Some(CapturedDetail {
                fact: CapturedFact::AnyIllegal(cause),
                effect,
            }),
        };
        let mut m = Monitor::new();
        m.note_consumed_capture(cap(0, 1));
        m.note_consumed_capture(cap(1, 1));
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("x0s=0") && text.contains("x1s=1"),
            "H1': the encoded identity carries each capture's actual slot: {text}"
        );
        assert!(
            text.contains("x0g=1") && text.contains("x1g=1"),
            "H1': both slots share the equal per-slot generation: {text}"
        );
        assert!(
            text.contains("x0t=a15") && text.contains("x1t=a15"),
            "H1': both captures emit their typed fact: {text}"
        );
        assert!(
            text.contains("x0a=blk:c") && text.contains("x1a=blk:c"),
            "H1': both captures emit their applied effect: {text}"
        );
    }

    #[test]
    fn logging_monitor_summary_on_full_ring_displaces_newest_normal() {
        use crate::enforcement::monitor::Monitor;
        use crate::enforcement::policy::UnknownReason;
        let (mut store, mut file) = file_logstore();
        let mut guard = 0;
        while store.len() < QUEUE_SLOTS - 1 && guard < 8 * QUEUE_SLOTS {
            store.startup_warning(100, "sub.example.org", Family::A);
            guard += 1;
        }
        assert_eq!(store.len(), QUEUE_SLOTS - 1, "fill leaves one free slot");
        store.shutdown_final(101, ShutdownStatus::Drained, store.dropped());
        assert_eq!(
            store.len(),
            QUEUE_SLOTS,
            "the shutdown verdict holds the last free ring slot"
        );
        let dropped_before = store.dropped();
        let mut m = Monitor::new();
        m.note_fact_unknown(UnknownReason::Unattributed);
        assert!(
            store.monitor_summary(101, &mut m),
            "a reserved monitor summary is admitted even on a full ring"
        );
        assert_eq!(
            store.dropped(),
            dropped_before + 1,
            "H2: the admitted summary displaces and counts the newest normal record"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "the ring stays at capacity");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=monitor"),
            "the reserved monitor summary is emitted: {text}"
        );
        assert!(
            !text.contains("kind=shutdown_final"),
            "the newest normal record (shutdown_final) is the displaced victim: {text}"
        );
    }

    #[test]
    fn logging_reserved_startup_final_displaces_newest_normal_when_full() {
        let (mut store, mut file) = file_logstore();
        for i in 0..(QUEUE_SLOTS - 1) {
            store.startup_warning(100, &format!("n{i}.example.org"), Family::A);
        }
        assert_eq!(
            store.len(),
            QUEUE_SLOTS,
            "the high-edge record fills the last ring slot"
        );
        assert_eq!(store.dropped(), 0, "no warning is dropped during the fill");
        store.startup_final(
            101,
            StartupStatus::Full,
            FinalCounts {
                unresolved: 1,
                ..FinalCounts::default()
            },
        );
        assert_eq!(
            store.dropped(),
            1,
            "the reserved summary displaces and counts the newest normal record"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "the ring stays at capacity");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=startup_final"),
            "the reserved record is emitted: {text}"
        );
        assert!(
            !text.contains("n254.example.org"),
            "the newest normal warning is the displaced victim: {text}"
        );
        assert!(
            text.contains("n0.example.org") && text.contains("n253.example.org"),
            "the older normal warnings survive: {text}"
        );
    }

    #[test]
    fn logging_reserved_records_survive_normal_overflow() {
        let (mut store, mut file) = file_logstore();
        for i in 0..QUEUE_SLOTS {
            store.startup_final(
                100 + i as u64,
                StartupStatus::Full,
                FinalCounts {
                    unresolved: 1,
                    ..FinalCounts::default()
                },
            );
        }
        assert_eq!(store.len(), QUEUE_SLOTS, "reserved records fill the ring");
        let dropped_before = store.dropped();
        for _ in 0..16 {
            store.startup_warning(200, "sub.example.org", Family::A);
        }
        assert_eq!(
            store.dropped(),
            dropped_before + 16,
            "normal overflow records are dropped whole, never displacing reserved ones"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "the ring stays at capacity");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text.matches("kind=startup_final").count(),
            QUEUE_SLOTS,
            "every reserved record survives the normal overflow: {text}"
        );
        assert!(
            !text.contains("kind=startup_warning"),
            "no normal overflow record is admitted: {text}"
        );
    }

    #[test]
    fn logging_all_reserved_full_drops_newest_reserved() {
        use crate::enforcement::monitor::Monitor;
        use crate::enforcement::policy::UnknownReason;
        let (mut store, mut file) = file_logstore();
        for i in 0..QUEUE_SLOTS {
            store.startup_final(
                100 + i as u64,
                StartupStatus::Full,
                FinalCounts {
                    unresolved: 1,
                    ..FinalCounts::default()
                },
            );
        }
        assert_eq!(store.len(), QUEUE_SLOTS, "reserved records fill the ring");
        let dropped_before = store.dropped();
        let mut m = Monitor::new();
        m.note_fact_unknown(UnknownReason::Unattributed);
        assert!(
            store.monitor_summary(101, &mut m),
            "a reserved monitor summary is admitted on an all-reserved full ring"
        );
        assert_eq!(
            store.dropped(),
            dropped_before + 1,
            "the newest reserved record is the bounded-not-lossless victim"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "the ring stays at capacity");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=monitor"),
            "the monitor summary is emitted: {text}"
        );
        assert!(
            !text.contains("secs=355"),
            "the newest reserved record is the displaced victim: {text}"
        );
        assert!(
            text.contains("secs=100"),
            "the oldest reserved records survive: {text}"
        );
    }

    #[test]
    fn shutdown_final_record_carries_the_dropped_count() {
        let (mut store, mut file) = file_logstore();
        store.shutdown_final(101, ShutdownStatus::Drained, store.dropped());
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("dropped=0"),
            "the shutdown verdict names the dropped-record count: {text}"
        );
    }

    #[test]
    fn logging_stalled_pipe_yields_retains_cursor_and_counts_drops() {
        let (reader, writer) = UnixStream::pair().expect("socketpair");
        writer.set_nonblocking(true).expect("writer nonblocking");
        let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
        let big = "p".repeat(1000);
        let mut turns = 0;
        while turns < 8 * QUEUE_SLOTS && store.len() < QUEUE_SLOTS {
            store.startup_warning(1, &big, Family::A);
            store.drain_sink();
            turns += 1;
        }
        assert_eq!(
            store.len(),
            QUEUE_SLOTS,
            "stalled sink retains the full queue"
        );
        assert!(
            !store.sink_has_failed(),
            "a full pipe is WouldBlock, not a sink failure"
        );
        let dropped_before = store.dropped();
        for _ in 0..16 {
            store.startup_warning(1, &big, Family::A);
        }
        assert_eq!(
            store.dropped(),
            dropped_before + 16,
            "enqueue keeps dropping whole records while the sink is stalled"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "queued records stay put");
        let _ = reader;
        let _ = writer;
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn logging_enqueue_drop_drain_paths_spend_zero_allocations() {
        use crate::alloc::{Phase, run_phase};
        use crate::startup_dns::{FailureReason, NameOutcome};
        let v4: SocketAddr = "192.0.2.10:40000".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
        let long = "z".repeat(SLOT_BYTES * 2);
        let unresolved = [
            StartupUnresolved {
                ordinal: 0,
                name: "sub.example.org",
                outcome: NameOutcome::Failed(FailureReason::Receive),
            },
            StartupUnresolved {
                ordinal: 1,
                name: "sub.example.org",
                outcome: NameOutcome::Negative,
            },
        ];
        let (_, control) = run_phase(Phase::Logging, || 0usize);
        assert!(control.all_zero(), "baseline should be quiet: {control:?}");
        let (mut store, _file) = file_logstore();
        let mut stdout_store = LogStore::new().expect("stdout sink store");
        let ((), counts) = run_phase(Phase::Logging, || {
            store.startup_warning(1, "sub.example.org", Family::A);
            for un in unresolved {
                store.startup_name(2, un);
            }
            store.startup_final(2, StartupStatus::Failed, FinalCounts::default());
            store.early_activity(3, Some("sub.example.org"), Some(v4), ActivityKind::Data);
            store.reject(4, RejectReason::Capacity, Some(v4), Some("sub.example.org"));
            store.reject(
                5,
                RejectReason::DialFailed,
                Some(v6),
                Some("sub.example.org"),
            );
            store.reject(6, RejectReason::TlsValidation, None, None);
            store.note_capacity(7, 410, 0);
            store.note_capacity(8, 410, 103);
            for _ in 0..20 {
                store.startup_warning(9, &long, Family::A);
            }
            for _ in 0..(QUEUE_SLOTS + 4) {
                store.startup_warning(10, "sub.example.org", Family::A);
            }
            for _ in 0..(SINK_MAX_OPS + 4) {
                store.drain_sink();
            }
            for _ in 0..(QUEUE_SLOTS + 4) {
                stdout_store.startup_warning(11, "sub.example.org", Family::A);
            }
            for _ in 0..(SINK_MAX_OPS + 4) {
                stdout_store.drain_sink();
            }
        });
        assert!(
            counts.all_zero(),
            "enqueue/drop/drain paths (file and stdout sink variants) must not allocate or deallocate after boot: {counts:?}"
        );
    }

    #[test]
    fn logging_sink_failure_latches_and_never_blocks() {
        let (reader, writer) = UnixStream::pair().expect("socketpair");
        drop(reader);
        let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
        store.startup_warning(1, "sub.example.org", Family::A);
        store.drain_sink();
        assert!(
            store.sink_has_failed(),
            "EPIPE latches the sink failed (SIGPIPE ignored by std per oracle B17)"
        );
        assert_eq!(
            store.dropped(),
            1,
            "the stranded record is counted as dropped, never silently lost (L18)"
        );
        assert_eq!(
            store.len(),
            0,
            "the stranded record is cleared, not retained (L18)"
        );
        store.drain_sink();
        assert!(
            store.sink_has_failed(),
            "a later turn keeps the failure latched"
        );
        assert_eq!(store.dropped(), 1, "no double-counting on a later turn");
        let _ = writer;
    }

    #[test]
    fn logging_sink_failure_latch_is_observed_by_owner_and_wouldblock_never_fails() {
        {
            let (reader, writer) = UnixStream::pair().expect("socketpair");
            drop(reader);
            let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
            store.startup_warning(1, "sub.example.org", Family::A);
            store.drain_sink();
            assert!(
                store.sink_has_failed(),
                "the non-WouldBlock write error latches the sink (F-09)"
            );
            store.drain_sink();
            assert!(
                store.sink_has_failed(),
                "a later drain on the already-failed sink never consumes or clears the latch, so the owner observes it at the turn"
            );
            let _ = writer;
        }
        {
            let (reader, writer) = UnixStream::pair().expect("socketpair");
            writer.set_nonblocking(true).expect("writer nonblocking");
            let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
            let big = "p".repeat(1000);
            for _ in 0..QUEUE_SLOTS {
                store.startup_warning(1, &big, Family::A);
            }
            let mut turns = 0;
            while store.len() > 0 && turns < 8 * QUEUE_SLOTS {
                store.drain_sink();
                assert!(
                    !store.sink_has_failed(),
                    "a WouldBlock-stalled sink never latches fatal (F-09)"
                );
                turns += 1;
            }
            assert!(store.len() > 0, "the pipe fills and records stay queued");
            assert!(
                !store.sink_has_failed(),
                "backpressure stalls the sink, it never fails it (F-09)"
            );
            let _ = reader;
        }
    }

    #[test]
    fn logging_sink_failure_counts_stranded_records_as_dropped() {
        let (reader, writer) = UnixStream::pair().expect("socketpair");
        drop(reader);
        let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
        let big = "p".repeat(1000);
        let mut guard = 0;
        while guard < 8 * QUEUE_SLOTS && store.len() < QUEUE_SLOTS {
            store.startup_warning(1, &big, Family::A);
            guard += 1;
        }
        assert_eq!(
            store.len(),
            QUEUE_SLOTS,
            "queue holds records before the failure"
        );
        let dropped_before = store.dropped();
        store.drain_sink();
        assert!(store.sink_has_failed(), "EPIPE latches the sink failed");
        assert_eq!(
            store.dropped(),
            dropped_before + QUEUE_SLOTS as u64,
            "every record stranded at the failure is counted under whole-record drop accounting (L18)"
        );
        assert_eq!(
            store.len(),
            0,
            "stranded records are cleared, not retained (L18)"
        );
        store.drain_sink();
        assert_eq!(
            store.dropped(),
            dropped_before + QUEUE_SLOTS as u64,
            "a later turn never double-counts the stranded records"
        );
        assert!(store.sink_has_failed(), "the failed latch persists");
        let _ = writer;
    }

    #[test]
    fn logging_next_drain_contract_runnable_blocked_and_quiescent() {
        let now = Instant::now();
        let (empty, _empty_file) = file_logstore();
        assert_eq!(
            empty.next_drain(now),
            None,
            "an empty queue is quiescent and never wakes a poll"
        );

        {
            let (reader, writer) = UnixStream::pair().expect("socketpair");
            drop(reader);
            let mut epipe = LogStore::with_fd(&writer).expect("pipe sink store");
            epipe.startup_warning(1, "sub.example.org", Family::A);
            epipe.drain_sink();
            assert!(epipe.sink_has_failed());
            assert_eq!(
                epipe.next_drain(now),
                None,
                "a failed sink is quiescent and never wakes a poll"
            );
            let _ = writer;
        }

        let (reader, writer) = UnixStream::pair().expect("socketpair");
        writer.set_nonblocking(true).expect("writer nonblocking");
        let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
        let big = "p".repeat(1000);
        for _ in 0..QUEUE_SLOTS {
            store.startup_warning(1, &big, Family::A);
        }
        let mut turns = 0;
        while store.len() > 0 && turns < 8 * QUEUE_SLOTS {
            store.drain_sink();
            turns += 1;
        }
        assert!(store.len() > 0, "the pipe fills and records stay queued");
        assert_eq!(
            store.next_drain(now),
            Some(now + LOG_RETRY),
            "a WouldBlock-stalled sink retries on the bounded monotonic LOG_RETRY deadline, never busy-spinning"
        );

        let (mut runnable, _file) = file_logstore();
        runnable.startup_warning(1, "sub.example.org", Family::A);
        assert_eq!(
            runnable.next_drain(now),
            Some(now),
            "queued non-blocked records are immediately runnable"
        );
        let _ = reader;
    }

    #[test]
    fn logging_sink_gathers_multiple_fragments_in_one_writev() {
        let (mut subject, mut subject_file) = file_logstore();
        let (mut reference, mut reference_file) = file_logstore();
        for i in 0..SINK_MAX_OPS {
            let name = format!("host-{i}.example.org");
            subject.startup_warning(1, &name, Family::A);
            reference.startup_warning(1, &name, Family::A);
        }
        subject.drain_sink();
        assert_eq!(
            subject.sink_syscalls(),
            1,
            "one writev gathers the whole per-turn fragment budget"
        );
        assert_eq!(
            subject.sink_ops(),
            SINK_MAX_OPS,
            "the per-turn op budget is spent in gathered fragments"
        );
        assert_eq!(subject.len(), 0, "the gathered turn drains the queue");
        flush_all(&mut reference);
        let expected = read_all(&mut reference_file);
        let got = read_all(&mut subject_file);
        assert_eq!(
            got, expected,
            "writev gather emits the byte-identical stream"
        );
    }

    #[test]
    fn logging_writev_partial_write_keeps_cursor_and_stream_identical() {
        use std::io::Read as _;
        let (mut reader, writer) = UnixStream::pair().expect("socketpair");
        writer.set_nonblocking(true).expect("writer nonblocking");
        reader.set_nonblocking(true).expect("reader nonblocking");
        let mut subject = LogStore::with_fd(&writer).expect("pipe sink store");
        let big = "p".repeat(1000);
        for _ in 0..40 {
            subject.startup_warning(1, &big, Family::A);
        }
        let expected = {
            let (mut reference, mut file) = file_logstore();
            for _ in 0..40 {
                reference.startup_warning(1, &big, Family::A);
            }
            flush_all(&mut reference);
            read_all(&mut file)
        };
        let mut got: Vec<u8> = Vec::new();
        let mut first_turn_bytes = 0usize;
        let mut turns = 0usize;
        while subject.len() > 0 && turns < 8 * QUEUE_SLOTS {
            subject.drain_sink();
            turns += 1;
            let mut chunk = [0u8; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&chunk[..n]),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("read: {e}"),
                }
            }
            if turns == 1 {
                first_turn_bytes = got.len();
            }
        }
        assert!(
            turns > 1,
            "the socket buffer must split the gather across turns"
        );
        assert!(
            first_turn_bytes < expected.len(),
            "the first writev is a partial write ({first_turn_bytes} < {})",
            expected.len()
        );
        assert_eq!(
            subject.dropped(),
            0,
            "a live stalled sink never drops records"
        );
        assert_eq!(
            got, expected,
            "partial writev turns never re-emit or skip bytes (byte-identical stream)"
        );
        let _ = reader;
        let _ = writer;
    }

    fn scripted_out(store: &LogStore) -> &[u8] {
        let SinkIo::Scripted(sink) = &store.sink.io else {
            panic!("expected a scripted sink");
        };
        &sink.out
    }

    fn assert_scripted_stall_preserves_cursor_and_stream(first: ScriptedFirst, label: &str) {
        let mut subject = LogStore::with_scripted_sink(first).expect("scripted sink store");
        let (mut reference, mut reference_file) = file_logstore();
        for i in 0..40 {
            let name = format!("host-{i}.sub.example.org");
            subject.startup_warning(1, &name, Family::A);
            reference.startup_warning(1, &name, Family::A);
        }
        let enqueued = subject.len();
        subject.drain_sink();
        assert_eq!(
            subject.cursor.map(|cursor| cursor.off),
            Some(0),
            "{label}: the injected stall retains the cursor at the gather-start offset"
        );
        assert!(
            subject.sink.blocked,
            "{label}: the injected stall latches the sink blocked"
        );
        assert_eq!(
            subject.len(),
            enqueued,
            "{label}: the stalled write advances no queued record"
        );
        assert_eq!(
            subject.dropped(),
            0,
            "{label}: a live stalled sink never drops records"
        );
        flush_all(&mut reference);
        let expected = read_all(&mut reference_file);
        let mut turns = 0usize;
        while subject.len() > 0 && turns < 8 * QUEUE_SLOTS {
            subject.drain_sink();
            turns += 1;
        }
        assert_eq!(
            subject.len(),
            0,
            "{label}: the queue drains after the stall"
        );
        assert!(
            !subject.sink.blocked,
            "{label}: the successful resume clears the blocked latch"
        );
        assert_eq!(
            scripted_out(&subject),
            expected,
            "{label}: the drain resumes at the exact residue and emits a byte-identical stream"
        );
    }

    #[test]
    fn logging_writev_interrupted_keeps_cursor_and_stream_identical() {
        assert_scripted_stall_preserves_cursor_and_stream(
            ScriptedFirst::Interrupted,
            "Interrupted",
        );
    }

    #[test]
    fn logging_writev_zero_progress_keeps_cursor_and_stream_identical() {
        assert_scripted_stall_preserves_cursor_and_stream(ScriptedFirst::Zero, "zero progress");
    }
}

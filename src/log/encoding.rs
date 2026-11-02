use super::{
    AnyIllegalCause, CAPTURE_BATCH, CapturedFact, DOMAIN_BATCH, DnsAnomalyKind, DomainOrdinal,
    Effect, Family, IncidentSummary, IpAddr, Kind, Level, Monitor, ProbeVerdict,
    ResolverProbeSegment, SLOT_BYTES, Scope, SocketAddr, StartupUnresolved, UnknownReason,
};
use std::fmt;

/// A single encoded field. `OptVar` variants emit nothing when the value is
/// absent, so a caller never supplies an empty quoted value.
#[derive(Clone, Copy)]
pub(super) enum Val<'a> {
    Str(&'a str),
    OptStr(Option<&'a str>),
    U64(u64),
    OptU64(Option<u64>),
    OptAddr(Option<SocketAddr>),
    Family(Family),
}

#[derive(Clone, Copy)]
pub(super) struct Field<'a> {
    key: &'static str,
    val: Val<'a>,
}

impl<'a> Field<'a> {
    pub(super) const fn new(key: &'static str, val: Val<'a>) -> Self {
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
pub(super) fn encode_record(
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

/// The fixed 33-field incident summary record (docs/alumina-proxy.md:80):
/// window span, coalescing and overflow flags, window activity, and the
/// per-type incident/cache snapshot. Optional fields emit nothing when absent.
pub(super) fn incident_summary_fields<'a>(
    secs: u64,
    name: &'a str,
    summary: &'a IncidentSummary,
) -> [Field<'a>; 33] {
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
            "a_resolver",
            resolver_val(summary.types[0].reason.is_some(), summary.types[0].resolver),
        ),
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
            "aaaa_resolver",
            resolver_val(summary.types[1].reason.is_some(), summary.types[1].resolver),
        ),
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

pub(super) fn resolver_val(emit: bool, origin: Option<u8>) -> Val<'static> {
    match (emit, origin) {
        (true, Some(index)) => Val::U64(u64::from(index)),
        (true, None) => Val::Str("unknown"),
        (false, _) => Val::OptU64(None),
    }
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
pub(super) fn encode_record_name(
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
pub(super) fn encode_record_final(
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
pub(super) fn encode_record_probe(
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
pub(super) fn count_domain_batches(monitor: &Monitor) -> u32 {
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
pub(super) fn count_capture_batches(monitor: &Monitor) -> u32 {
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
pub(super) fn encode_monitor_summary(
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
pub(super) fn encode_monitor_domain_batch(
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
pub(super) fn encode_monitor_capture_batch(
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

pub(super) fn encode_fatal(
    buf: &mut [u8; SLOT_BYTES],
    secs: u64,
    args: fmt::Arguments<'_>,
) -> Option<usize> {
    let mut w = Entry { buf, len: 0 };
    let fits = write_header(&mut w, Level::Error, Kind::Fatal)
        && w.push(b" secs=")
        && fmt::Write::write_fmt(&mut w, format_args!("{secs}")).is_ok()
        && w.push(b" message=\"")
        && write_fmt_escaped(&mut w, args)
        && w.push(b"\"")
        && w.push(b"\n");
    fits.then_some(w.len)
}

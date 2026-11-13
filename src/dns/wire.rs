use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::config::{ALLOWLIST_MAX, Allowlist, Fqdn};
use crate::dns::cache::evidence::{Evidence, EvidenceError, ResolverSource};
use crate::dns::cache::{Cache, CacheError, Family, MAX_ADDRESSES};
use crate::dns::publication::{self, ApplyContext};
use crate::dns::resolver::RecursionPolicy;
use crate::dns::schedule::{OutcomeIncidents, Schedules, Soa};
use crate::eligibility::NumericAddr;

/// Maximum DNS message size accepted over the wire (16 KiB).
pub const DNS_MSG_LIMIT: usize = 16 * 1024;

/// Maximum rooted CNAME chain length accepted in one answer.
pub const MAX_CNAME_LINKS: usize = 8;

/// Maximum total resource records (question excluded) inspected per message,
/// bounded before any per-record work so a peer header cannot drive
/// allocation.
pub const MAX_TOTAL_RR: usize = 128;

/// A resource-record TTL above this bound is treated as an extreme-TTL DNS
/// anomaly: 96 hours. Published addresses with such a TTL still validate and
/// serve, but the exchange is surfaced on the monitoring anomaly surface so a
/// pathological or hostile upstream cannot pin cache entries for months
/// unnoticed.
pub const EXTREME_TTL_THRESHOLD: u32 = 345_600;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_DNAME: u16 = 39;
const CLASS_IN: u16 = 1;

const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;

const MAX_NAME_BYTES: usize = 255;
const NAME_CAP: usize = 256;

/// A decoded DNS name (lowercase, without a trailing root label), stored in a
/// fixed buffer so the response path allocates nothing after boot. The decoded
/// length bound is `MAX_NAME_BYTES` per the canonical wire contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DnsName {
    bytes: [u8; NAME_CAP],
    len: usize,
}

impl Default for DnsName {
    fn default() -> Self {
        DnsName {
            bytes: [0; NAME_CAP],
            len: 0,
        }
    }
}

impl DnsName {
    fn from_exact(source: &[u8]) -> DnsName {
        debug_assert!(
            source.len() <= NAME_CAP,
            "DNS name source must fit the fixed name buffer"
        );
        let mut out = DnsName::default();
        out.bytes[..source.len()].copy_from_slice(source);
        out.len = source.len();
        out
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn eq_bytes(&self, other: &[u8]) -> bool {
        self.len == other.len() && &self.bytes[..self.len] == other
    }

    const fn push(&mut self, byte: u8) -> Result<(), DnsError> {
        if self.len >= MAX_NAME_BYTES {
            return Err(DnsError::NameTooLong);
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        Ok(())
    }
}

/// Up to `MAX_ADDRESSES` validated numeric candidates in fixed storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingList {
    addrs: [NumericAddr; MAX_ADDRESSES],
    len: u8,
}

impl Default for BindingList {
    fn default() -> Self {
        BindingList {
            addrs: [NumericAddr::V4(Ipv4Addr::UNSPECIFIED); MAX_ADDRESSES],
            len: 0,
        }
    }
}

impl BindingList {
    /// The eligible candidate addresses.
    #[must_use]
    pub fn as_slice(&self) -> &[NumericAddr] {
        &self.addrs[..usize::from(self.len)]
    }

    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, addr: NumericAddr) -> Result<(), DnsError> {
        if usize::from(self.len) >= MAX_ADDRESSES {
            return Err(DnsError::CandidatesExceeded {
                limit: MAX_ADDRESSES,
            });
        }
        self.addrs[usize::from(self.len)] = addr;
        self.len += 1;
        Ok(())
    }

    /// Builds a list from validated candidates, rejecting any set that exceeds
    /// `MAX_ADDRESSES` rather than retaining a truncated subset.
    ///
    /// # Errors
    ///
    /// Returns `CandidatesExceeded` when `addrs` has more than `MAX_ADDRESSES`
    /// entries.
    ///
    /// # Panics
    ///
    /// Panics only if the bounded candidate count does not fit `u8`, impossible
    /// given the `MAX_ADDRESSES` bound.
    #[expect(
        clippy::expect_used,
        reason = "candidate count is checked against MAX_ADDRESSES=16, which fits u8"
    )]
    pub fn from_slice(addrs: &[NumericAddr]) -> Result<BindingList, DnsError> {
        if addrs.len() > MAX_ADDRESSES {
            return Err(DnsError::CandidatesExceeded {
                limit: MAX_ADDRESSES,
            });
        }
        let mut out = BindingList::default();
        out.addrs[..addrs.len()].copy_from_slice(addrs);
        out.len = u8::try_from(addrs.len()).expect("candidate count bounded by MAX_ADDRESSES");
        Ok(out)
    }
}

/// A validated DNS outcome, ready for cache and schedule application.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[expect(
    clippy::large_enum_variant,
    reason = "no-heap fixed-profile; boxing the large variant would add a post-boot allocation; lint cannot be satisfied idiomatically here"
)]
pub enum Outcome {
    /// Validated positive answer with eligible candidates and the earliest
    /// supporting TTL across the rooted CNAME chain.
    Positive {
        family: Family,
        bindings: BindingList,
        ttl: u64,
    },
    /// Name-wide validated NXDOMAIN; the SOA, when present, governs negative
    /// refresh scheduling.
    NxDomain { soa: Option<Soa> },
    /// Per-type validated NODATA; a covering SOA is required for NODATA.
    NoData { family: Family, soa: Option<Soa> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsError {
    BufferExhausted,
    MessageTooLong,
    QueryTooLong,
    BadTid {
        expected: u16,
        got: u16,
    },
    NotResponse,
    BadOpcode {
        got: u8,
    },
    BadRcode {
        code: u8,
    },
    Truncated,
    QuestionCount {
        got: usize,
    },
    QuestionMismatch,
    ExcessiveRecords {
        total: usize,
        limit: usize,
    },
    BailiwickSuffixOverflow {
        got: usize,
        max: usize,
    },
    BadClass {
        got: u16,
    },
    BadType {
        got: u16,
    },
    BadRdataLength {
        ty: u16,
        got: usize,
        expected: usize,
    },
    MalformedSoa,
    TrailingBytes,
    ReservedLabelType {
        offset: usize,
    },
    LabelTooLong {
        len: usize,
    },
    NameTooLong,
    EmbeddedDotInLabel,
    PointerNotBackward,
    PointerCycle,
    ConflictingCname,
    CnameCoexist,
    CnameLoop,
    CnameTooDeep {
        links: usize,
    },
    TerminalWithoutData,
    DnameUnsupported,
    CandidatesExceeded {
        limit: usize,
    },
    SoaCount {
        got: usize,
    },
    NonCoveringSoa,
    EmptyNoerrorWithoutSoa,
    BailiwickViolation,
    Cache(CacheError),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::BufferExhausted => write!(f, "DNS encoding buffer exhausted"),
            DnsError::MessageTooLong => write!(f, "DNS message exceeds 16 KiB"),
            DnsError::QueryTooLong => write!(f, "DNS query name too long"),
            DnsError::BadTid { expected, got } => {
                write!(
                    f,
                    "DNS transaction id mismatch: expected {expected}, got {got}"
                )
            }
            DnsError::NotResponse => write!(f, "DNS message is not a response"),
            DnsError::BadOpcode { got } => write!(f, "DNS response opcode {got} is not QUERY"),
            DnsError::BadRcode { code } => write!(f, "DNS response code {code} not handled"),
            DnsError::Truncated => write!(f, "DNS response truncated"),
            DnsError::QuestionCount { got } => write!(f, "DNS question count {got}, expected 1"),
            DnsError::QuestionMismatch => write!(f, "DNS question does not match the query"),
            DnsError::ExcessiveRecords { total, limit } => write!(
                f,
                "DNS record count {total} exceeds the {limit} inspection bound"
            ),
            DnsError::BailiwickSuffixOverflow { got, max } => write!(
                f,
                "declared cname_bailiwick suffix count {got} exceeds the {max} slot bound"
            ),
            DnsError::BadClass { got } => write!(f, "DNS record class {got} is not IN"),
            DnsError::BadType { got } => write!(f, "DNS unsupported record type {got}"),
            DnsError::BadRdataLength { ty, got, expected } => {
                write!(f, "DNS type {ty} rdata {got} bytes, expected {expected}")
            }
            DnsError::MalformedSoa => write!(f, "DNS SOA rdata malformed"),
            DnsError::TrailingBytes => write!(f, "DNS message has trailing bytes"),
            DnsError::ReservedLabelType { offset } => {
                write!(f, "DNS reserved label type at offset {offset}")
            }
            DnsError::LabelTooLong { len } => write!(f, "DNS label {len} bytes exceeds 63"),
            DnsError::NameTooLong => write!(f, "DNS name exceeds 255 bytes"),
            DnsError::EmbeddedDotInLabel => {
                write!(f, "DNS label content contains an embedded dot")
            }
            DnsError::PointerNotBackward => write!(f, "DNS compression pointer not backward"),
            DnsError::PointerCycle => write!(f, "DNS compression pointer cycle"),
            DnsError::ConflictingCname => write!(f, "DNS conflicting CNAME targets"),
            DnsError::CnameCoexist => {
                write!(f, "DNS CNAME coexists with address data at the same owner")
            }
            DnsError::CnameLoop => write!(f, "DNS CNAME chain loop"),
            DnsError::CnameTooDeep { links } => {
                write!(f, "DNS CNAME chain exceeds 8 links ({links})")
            }
            DnsError::TerminalWithoutData => write!(
                f,
                "DNS terminal owner carries address data contradicting NXDOMAIN"
            ),
            DnsError::DnameUnsupported => write!(f, "DNS DNAME present; unsupported"),
            DnsError::CandidatesExceeded { limit } => write!(
                f,
                "DNS candidate addresses exceed the {limit} inspection bound"
            ),
            DnsError::SoaCount { got } => {
                write!(f, "DNS authority SOA count {got}, expected at most 1")
            }
            DnsError::NonCoveringSoa => write!(f, "DNS SOA does not cover the terminal name"),
            DnsError::EmptyNoerrorWithoutSoa => write!(
                f,
                "DNS empty NOERROR answer without covering SOA is not NODATA"
            ),
            DnsError::BailiwickViolation => {
                write!(f, "DNS CNAME chain leaves the allowlist bailiwick zone")
            }
            DnsError::Cache(err) => write!(f, "DNS cache refused: {err:?}"),
        }
    }
}

const fn family_qtype(family: Family) -> u16 {
    match family {
        Family::A => TYPE_A,
        Family::Aaaa => TYPE_AAAA,
    }
}

const HEADER_LEN: usize = 12;

const RD_FLAG: u8 = 0x01;
const AD_FLAG: u8 = 0x20;

fn write_header(buf: &mut [u8], tid: u16) -> Result<(), DnsError> {
    if buf.len() < HEADER_LEN {
        return Err(DnsError::BufferExhausted);
    }
    buf[0] = (tid >> 8) as u8;
    buf[1] = (tid & 0xff) as u8;
    buf[2] = RD_FLAG;
    buf[3] = AD_FLAG;
    buf[4] = 0x00;
    buf[5] = 0x01;
    buf[6..12].fill(0);
    Ok(())
}

fn write_qname(buf: &mut [u8], mut pos: usize, name: &str) -> Result<usize, DnsError> {
    let bytes = name.as_bytes();
    let mut label_start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'.' {
            continue;
        }
        let label_len = i - label_start;
        if label_len == 0 {
            return Err(DnsError::QueryTooLong);
        }
        pos = write_label(buf, pos, &bytes[label_start..label_start + label_len])?;
        label_start = i + 1;
    }
    let tail = &bytes[label_start..];
    if !tail.is_empty() {
        pos = write_label(buf, pos, tail)?;
    }
    if pos >= buf.len() {
        return Err(DnsError::BufferExhausted);
    }
    buf[pos] = 0;
    Ok(pos + 1)
}

/// Writes one length-prefixed label at `pos`, returning the cursor past it.
#[expect(
    clippy::expect_used,
    reason = "label length is checked to be <= 63 before encoding, fitting u8"
)]
fn write_label(buf: &mut [u8], pos: usize, label: &[u8]) -> Result<usize, DnsError> {
    if label.len() > 63 {
        return Err(DnsError::QueryTooLong);
    }
    if pos + 1 + label.len() > buf.len() {
        return Err(DnsError::BufferExhausted);
    }
    buf[pos] = u8::try_from(label.len()).expect("dns label at most 63 bytes");
    buf[pos + 1..pos + 1 + label.len()].copy_from_slice(label);
    Ok(pos + 1 + label.len())
}

/// Builds a single-question IN DNS query for the exact allowlisted `name` and
/// `family` with transaction id `tid`, returning the message length written
/// into `buf`.
///
/// # Errors
///
/// Returns `QueryTooLong` or `BufferExhausted` when the name cannot be encoded
/// into `buf`.
///
/// # Panics
///
/// Panics on the fixed `expect` only if the DNS `CLASS_IN` constant does not
/// fit the one-byte wire field, which cannot happen.
#[expect(
    clippy::expect_used,
    reason = "CLASS_IN is the constant 1, which always fits the one-byte u8 wire field"
)]
pub fn build_query(
    fqdn: &Fqdn,
    family: Family,
    tid: u16,
    buf: &mut [u8],
) -> Result<usize, DnsError> {
    write_header(buf, tid)?;
    let mut pos = HEADER_LEN;
    pos = write_qname(buf, pos, fqdn.as_str())?;
    if pos + 4 > buf.len() {
        return Err(DnsError::BufferExhausted);
    }
    buf[pos..pos + 2].copy_from_slice(&family_qtype(family).to_be_bytes());
    buf[pos + 2] = 0;
    buf[pos + 3] = u8::try_from(CLASS_IN).expect("DNS class IN fits the u8 wire field");
    Ok(pos + 4)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Result<u8, DnsError> {
        let byte = self
            .data
            .get(self.pos)
            .copied()
            .ok_or(DnsError::MessageTooLong)?;
        self.pos += 1;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16, DnsError> {
        let hi = self.u8()?;
        let lo = self.u8()?;
        Ok(u16::from_be_bytes([hi, lo]))
    }

    fn u32(&mut self) -> Result<u32, DnsError> {
        let hi = self.u16()?;
        let lo = self.u16()?;
        Ok((u32::from(hi) << 16) | u32::from(lo))
    }

    const fn skip(&mut self, n: usize) -> Result<(), DnsError> {
        if self.remaining() < n {
            return Err(DnsError::MessageTooLong);
        }
        self.pos += n;
        Ok(())
    }
}

/// Decodes a (possibly compressed) name at `at`, returning the decoded bytes
/// without a trailing root label plus the cursor just past the name as it is
/// encoded at `at`. Names follow only backward compression pointers with a
/// bounded visited set. The returned cursor measures the encoded field (labels,
/// root, or 2-byte pointer) as written at `at`, never the end of an expanded
/// name reached by following a pointer, so callers can resume field parsing at
/// the correct offset after a compressed owner, CNAME target, or SOA name.
fn read_name(msg: &[u8], at: usize, strict: bool) -> Result<(DnsName, usize), DnsError> {
    let mut out = DnsName::default();
    let mut cursor = NameCursor::new(at);
    loop {
        let byte = msg
            .get(cursor.decode)
            .copied()
            .ok_or(DnsError::MessageTooLong)?;
        match byte & 0xc0 {
            0x00 => {
                if let Some(end) = cursor.read_label(msg, byte, strict, &mut out)? {
                    return Ok((out, end));
                }
            }
            0xc0 => cursor.follow_pointer(msg, byte)?,
            _ => {
                return Err(DnsError::ReservedLabelType {
                    offset: cursor.decode,
                });
            }
        }
    }
}

/// Decode cursor for one name: the encoded-field offset, the decode offset, the
/// accumulated name length, and the bounded pointer count.
struct NameCursor {
    field: usize,
    decode: usize,
    total: usize,
    pointers: usize,
    closed_by_pointer: bool,
}

impl NameCursor {
    const fn new(at: usize) -> NameCursor {
        NameCursor {
            field: at,
            decode: at,
            total: 0,
            pointers: 0,
            closed_by_pointer: false,
        }
    }

    /// Consumes one label, returning the encoded-field cursor once the root
    /// label closes the name.
    fn read_label(
        &mut self,
        msg: &[u8],
        byte: u8,
        strict: bool,
        out: &mut DnsName,
    ) -> Result<Option<usize>, DnsError> {
        let len = usize::from(byte);
        if len == 0 {
            return self.read_root().map(Some);
        }
        if len > 63 {
            return Err(DnsError::LabelTooLong { len });
        }
        self.total += len + 1;
        if self.total > MAX_NAME_BYTES {
            return Err(DnsError::NameTooLong);
        }
        let start = self.decode + 1;
        let end = start + len;
        if end >= msg.len() {
            return Err(DnsError::MessageTooLong);
        }
        if !out.is_empty() {
            out.push(b'.')?;
        }
        push_label_bytes(out, &msg[start..end], strict)?;
        self.decode = end;
        if !self.closed_by_pointer {
            self.field = end;
        }
        Ok(None)
    }

    /// Consumes the root label, returning the cursor just past the encoded name.
    const fn read_root(&mut self) -> Result<usize, DnsError> {
        self.total += 1;
        if self.total > MAX_NAME_BYTES {
            return Err(DnsError::NameTooLong);
        }
        if self.closed_by_pointer {
            Ok(self.field)
        } else {
            Ok(self.field + 1)
        }
    }

    /// Follows one backward compression pointer, bounding the visited count.
    fn follow_pointer(&mut self, msg: &[u8], byte: u8) -> Result<(), DnsError> {
        let hi = usize::from(byte & 0x3f);
        let lo = usize::from(
            msg.get(self.decode + 1)
                .copied()
                .ok_or(DnsError::MessageTooLong)?,
        );
        let target = (hi << 8) | lo;
        if target >= self.decode {
            return Err(DnsError::PointerNotBackward);
        }
        if !self.closed_by_pointer {
            self.field = self.decode + 2;
            self.closed_by_pointer = true;
        }
        self.decode = target;
        self.pointers += 1;
        if self.pointers > 8 {
            return Err(DnsError::PointerCycle);
        }
        Ok(())
    }
}

/// Appends one label's bytes in lowercase, rejecting an embedded dot under
/// strict decoding.
fn push_label_bytes(out: &mut DnsName, bytes: &[u8], strict: bool) -> Result<(), DnsError> {
    for &b in bytes {
        if strict && b == b'.' {
            return Err(DnsError::EmbeddedDotInLabel);
        }
        out.push(b.to_ascii_lowercase())?;
    }
    Ok(())
}

/// One raw resource-record header as read from the wire: the consumed owner
/// name, type, class, and TTL, then the RDLENGTH and the rdata start offset
/// that follow them in every RR section.
struct RawRr {
    owner: DnsName,
    ty: u16,
    class: u16,
    ttl: u32,
    rdlen: usize,
    rd_start: usize,
}

fn read_rr(msg: &[u8], reader: &mut Reader) -> Result<RawRr, DnsError> {
    let start = reader.pos;
    let (owner, end) = read_name(msg, start, true)?;
    reader.pos = end;
    let ty = reader.u16()?;
    let class = reader.u16()?;
    let ttl = reader.u32()?;
    let rdlen = usize::from(reader.u16()?);
    let rd_start = reader.pos;
    Ok(RawRr {
        owner,
        ty,
        class,
        ttl,
        rdlen,
        rd_start,
    })
}

#[expect(
    clippy::large_enum_variant,
    reason = "no-heap fixed-profile; boxing the large variant would add a post-boot allocation; lint cannot be satisfied idiomatically here"
)]
enum Rdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(DnsName),
    Soa { minimum: u32 },
}

/// Shared A/AAAA fixed-length guard: returns `BadRdataLength { ty, got,
/// expected }` when an A record is not 4 bytes or an AAAA not 16; all other
/// types pass through untouched.
const fn check_fixed_addr_rdata_len(ty: u16, rdlen: usize) -> Result<(), DnsError> {
    let expected = match ty {
        TYPE_A => 4,
        TYPE_AAAA => 16,
        _ => return Ok(()),
    };
    if rdlen == expected {
        Ok(())
    } else {
        Err(DnsError::BadRdataLength {
            ty,
            got: rdlen,
            expected,
        })
    }
}

fn parse_rdata(msg: &[u8], rd_start: usize, rdlen: usize, ty: u16) -> Result<Rdata, DnsError> {
    let end = rd_start
        .checked_add(rdlen)
        .ok_or(DnsError::MessageTooLong)?;
    if end > msg.len() {
        return Err(DnsError::MessageTooLong);
    }
    match ty {
        TYPE_A => {
            check_fixed_addr_rdata_len(ty, rdlen)?;
            Ok(Rdata::A(Ipv4Addr::new(
                msg[rd_start],
                msg[rd_start + 1],
                msg[rd_start + 2],
                msg[rd_start + 3],
            )))
        }
        TYPE_AAAA => {
            check_fixed_addr_rdata_len(ty, rdlen)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&msg[rd_start..rd_start + 16]);
            Ok(Rdata::Aaaa(Ipv6Addr::from(octets)))
        }
        TYPE_CNAME => {
            let (target, used) = read_name(msg, rd_start, true)?;
            if used != end {
                return Err(DnsError::BadRdataLength {
                    ty,
                    got: rdlen,
                    expected: used - rd_start,
                });
            }
            Ok(Rdata::Cname(target))
        }
        TYPE_SOA => {
            // Cumulative sub-component validation: each parsed name must stay
            // within the rdata, and the fixed 20-byte tail (serial, refresh,
            // retry, expire, minimum) must follow exactly, so the tail slice
            // is provably in-bounds and exactly 20 bytes before it is read.
            let (_, used) = read_name(msg, rd_start, false)?;
            if used > end {
                return Err(DnsError::MalformedSoa);
            }
            let (_, used2) = read_name(msg, used, false)?;
            if used2 > end {
                return Err(DnsError::MalformedSoa);
            }
            if end - used2 != 20 {
                return Err(DnsError::MalformedSoa);
            }
            let mut r = Reader::new(&msg[used2..end]);
            r.skip(16)?;
            let minimum = r.u32()?;
            Ok(Rdata::Soa { minimum })
        }
        TYPE_DNAME => Err(DnsError::DnameUnsupported),
        _ => Err(DnsError::BadType { got: ty }),
    }
}

#[derive(Clone, Copy, Debug)]
struct Owner {
    name: DnsName,
    cname: Option<(DnsName, u32)>,
    addrs: [(NumericAddr, u32); MAX_ADDRESSES],
    addr_len: u8,
    has_addr_data: bool,
}

impl Owner {
    fn empty() -> Owner {
        Owner {
            name: DnsName::default(),
            cname: None,
            addrs: [(NumericAddr::V4(Ipv4Addr::UNSPECIFIED), 0); MAX_ADDRESSES],
            addr_len: 0,
            has_addr_data: false,
        }
    }

    /// Appends one validated address binding: rejects a name that already
    /// carries a CNAME, marks the name as having address data, and fails
    /// (before any write) when the fixed address table is full.
    fn push_address(&mut self, addr: NumericAddr, ttl: u32) -> Result<(), DnsError> {
        if self.cname.is_some() {
            return Err(DnsError::CnameCoexist);
        }
        self.has_addr_data = true;
        let slot = usize::from(self.addr_len);
        if slot >= MAX_ADDRESSES {
            return Err(DnsError::CandidatesExceeded {
                limit: MAX_ADDRESSES,
            });
        }
        self.addrs[slot] = (addr, ttl);
        self.addr_len += 1;
        Ok(())
    }

    /// Records a validated CNAME: an identical earlier target keeps the
    /// earliest TTL, a different target on the same name is a conflict, and a
    /// name that already published address data cannot also carry a CNAME.
    fn push_cname(&mut self, target: DnsName, ttl: u32) -> Result<(), DnsError> {
        if let Some((existing, existing_ttl)) = &self.cname {
            if !existing.eq_bytes(target.as_slice()) {
                return Err(DnsError::ConflictingCname);
            }
            let earliest = (*existing_ttl).min(ttl);
            self.cname = Some((target, earliest));
            return Ok(());
        }
        if self.has_addr_data {
            return Err(DnsError::CnameCoexist);
        }
        self.cname = Some((target, ttl));
        Ok(())
    }
}

/// Reusable fixed-capacity response-parse workspace, owned by the caller (a
/// boot slot) and reused across responses so the parse path performs no heap
/// allocation or deallocation after boot.
#[derive(Clone, Debug)]
pub struct ResponseWorkspace {
    owners: [Owner; MAX_TOTAL_RR],
    owner_len: usize,
    soa: Option<(DnsName, u32, u32)>,
    extreme_ttl: bool,
    supporting_ttl_cap: Option<u32>,
}

impl Default for ResponseWorkspace {
    #[expect(
        clippy::large_stack_arrays,
        reason = "designed response-parse workspace fixed-profile buffer; no runtime heap"
    )]
    fn default() -> Self {
        ResponseWorkspace {
            owners: [Owner::empty(); MAX_TOTAL_RR],
            owner_len: 0,
            soa: None,
            extreme_ttl: false,
            supporting_ttl_cap: None,
        }
    }
}

impl ResponseWorkspace {
    /// Whether the most recent parse observed an answer-section record with a
    /// TTL above [`EXTREME_TTL_THRESHOLD`], surfaced on the monitoring
    /// anomaly surface without disturbing the validated outcome.
    pub(crate) const fn extreme_ttl(&self) -> bool {
        self.extreme_ttl
    }

    /// The conservative raw supporting-TTL cap bound from the same parse: the
    /// minimum across every supporting CNAME and address TTL for a positive
    /// reply, or the minimum across the supporting CNAME chain and the
    /// covering SOA's TTL and MINIMUM for a negative reply with an SOA. With
    /// no SOA the supporting lifetime is unknown (`None`). Observed only, on
    /// the fixed workspace, with a zero TTL preserved (never clamped).
    pub(crate) const fn supporting_ttl_cap(&self) -> Option<u32> {
        self.supporting_ttl_cap
    }
}

fn ensure_owner(ws: &mut ResponseWorkspace, name: &DnsName) -> Result<usize, DnsError> {
    for (index, owner) in ws.owners[..ws.owner_len].iter().enumerate() {
        if owner.name.eq_bytes(name.as_slice()) {
            return Ok(index);
        }
    }
    if ws.owner_len >= MAX_TOTAL_RR {
        return Err(DnsError::ExcessiveRecords {
            total: ws.owner_len + 1,
            limit: MAX_TOTAL_RR,
        });
    }
    ws.owners[ws.owner_len] = Owner {
        name: *name,
        ..Owner::empty()
    };
    ws.owner_len += 1;
    Ok(ws.owner_len - 1)
}

/// The fixed-capacity allowlist-derived bailiwick zone set consulted while
/// rooting a CNAME chain: every followed link target must stay inside the
/// chain root's own bailiwick — the root's self-default zone (the root name
/// itself plus its label-boundary subdomains) or one of the root entry's own
/// declared `cname_bailiwick` suffixes. Built once from the allowlist plus
/// each entry's declared `cname_bailiwick` suffixes (or, by the wire-parser
/// fuzz target, from a single query context), it performs no heap allocation:
/// `ALLOWLIST_MAX` fixed `DnsName` slots mirror the `ResponseWorkspace`
/// fixed-profile pattern, and each suffix slot records the allowlist index
/// that declared it so coverage stays per-entry.
#[derive(Clone, Debug)]
pub struct BailiwickZones {
    zones: [DnsName; ALLOWLIST_MAX],
    len: usize,
    suffixes: [DnsName; ALLOWLIST_MAX],
    suffix_owner: [usize; ALLOWLIST_MAX],
    suffix_len: usize,
}

impl Default for BailiwickZones {
    fn default() -> Self {
        BailiwickZones {
            zones: [DnsName::default(); ALLOWLIST_MAX],
            len: 0,
            suffixes: [DnsName::default(); ALLOWLIST_MAX],
            suffix_owner: [0; ALLOWLIST_MAX],
            suffix_len: 0,
        }
    }
}

impl BailiwickZones {
    /// Derives the per-entry bailiwick: each allowlist hostname contributes
    /// itself as its self-default zone (so only its own subdomains are
    /// covered), and each declared `cname_bailiwick` suffix is recorded
    /// against the allowlist entry that declared it. Coverage is per-entry —
    /// a CNAME target is accepted only when it falls inside the chain root's
    /// own self-default zone or one of that root entry's own declared
    /// suffixes; another allowlist entry's zone never widens a neighbour's
    /// bailiwick (alox-f07 SP-014).
    ///
    /// # Errors
    ///
    /// Returns `DnsError::BailiwickSuffixOverflow` when the flat union of
    /// declared suffixes exceeds the fixed `ALLOWLIST_MAX` slot bound; the
    /// write is fail-stop rather than an out-of-bounds panic.
    pub(crate) fn from_allowlist(
        allowlist: &Allowlist,
        suffixes: &[Vec<String>],
    ) -> Result<BailiwickZones, DnsError> {
        debug_assert_eq!(
            suffixes.len(),
            allowlist.len(),
            "declared cname_bailiwick lists are parallel to the allowlist"
        );
        let mut zones = [DnsName::default(); ALLOWLIST_MAX];
        let mut len = 0;
        for fqdn in allowlist.iter() {
            zones[len] = DnsName::from_exact(fqdn.as_str().as_bytes());
            len += 1;
        }
        let mut suffix_slots = [DnsName::default(); ALLOWLIST_MAX];
        let mut suffix_owner = [0usize; ALLOWLIST_MAX];
        let mut suffix_len = 0;
        for (index, suffix_list) in suffixes.iter().enumerate() {
            for suffix in suffix_list {
                let bytes = suffix.as_bytes();
                let already = (0..suffix_len)
                    .any(|j| suffix_owner[j] == index && suffix_slots[j].eq_bytes(bytes));
                if already {
                    continue;
                }
                if suffix_len >= ALLOWLIST_MAX {
                    return Err(DnsError::BailiwickSuffixOverflow {
                        got: suffix_len + 1,
                        max: ALLOWLIST_MAX,
                    });
                }
                suffix_slots[suffix_len] = DnsName::from_exact(bytes);
                suffix_owner[suffix_len] = index;
                suffix_len += 1;
            }
        }
        Ok(BailiwickZones {
            zones,
            len,
            suffixes: suffix_slots,
            suffix_owner,
            suffix_len,
        })
    }

    /// A single-zone set covering one allowlist hostname's bailiwick, used by
    /// the wire-parser fuzz target that holds no allowlist.
    pub(crate) fn single(fqdn: &Fqdn) -> BailiwickZones {
        let mut zones = [DnsName::default(); ALLOWLIST_MAX];
        let zone = fqdn.as_str().as_bytes();
        zones[0] = DnsName::from_exact(zone);
        BailiwickZones {
            zones,
            len: 1,
            suffixes: [DnsName::default(); ALLOWLIST_MAX],
            suffix_owner: [0; ALLOWLIST_MAX],
            suffix_len: 0,
        }
    }

    /// Whether `name` is inside `root`'s bailiwick — exactly equal to `root`
    /// or a label-boundary subdomain of it (the self-default zone), or inside
    /// one of the allowlist entry `root` declared `cname_bailiwick` suffixes.
    pub(crate) fn covers_for(&self, root: &[u8], name: &[u8]) -> bool {
        if soa_covers(name, root) {
            return true;
        }
        let Some(index) = self.zones[..self.len].iter().position(|z| z.eq_bytes(root)) else {
            return false;
        };
        self.suffixes[..self.suffix_len]
            .iter()
            .zip(&self.suffix_owner[..self.suffix_len])
            .any(|(suffix, &owner)| owner == index && soa_covers(name, suffix.as_slice()))
    }
}

/// What a fully validated published exchange left in the cache, so the startup
/// report can tell a validated negative from an attempted positive with no
/// eligible bindings instead of collapsing both into one catch-all.
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
pub(crate) fn classify_published(outcome: &Outcome) -> PublishedKind {
    match outcome {
        Outcome::Positive { bindings, .. }
            if bindings.as_slice().iter().any(|b| b.is_eligible()) =>
        {
            PublishedKind::ResolvedPositive
        }
        Outcome::Positive { .. } => PublishedKind::NoEligible,
        Outcome::NxDomain { .. } | Outcome::NoData { .. } => PublishedKind::Negative,
    }
}

#[derive(Clone, Copy)]
enum ReplyFacts {
    WithSupportingTtl { ad: bool, extreme: bool, ttl: u32 },
    WithoutSupportingTtl { ad: bool, extreme: bool },
}

impl ReplyFacts {
    const fn ad(self) -> bool {
        match self {
            ReplyFacts::WithSupportingTtl { ad, .. }
            | ReplyFacts::WithoutSupportingTtl { ad, .. } => ad,
        }
    }

    const fn extreme(self) -> bool {
        match self {
            ReplyFacts::WithSupportingTtl { extreme, .. }
            | ReplyFacts::WithoutSupportingTtl { extreme, .. } => extreme,
        }
    }

    /// The conservative raw supporting-TTL cap bound from the same validated
    /// parse: `Some` for a positive with a reachable answer-section TTL, `None`
    /// when no supporting record survived. Consumed by the closed production
    /// publish route from the same reply.
    const fn supporting_ttl_cap(self) -> Option<u32> {
        match self {
            ReplyFacts::WithSupportingTtl { ttl, .. } => Some(ttl),
            ReplyFacts::WithoutSupportingTtl { .. } => None,
        }
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the conservative supporting cap is always a minimum over at least one reachable wire u32 operand (address TTL for positive; SOA TTL or MINIMUM for negative), so the sentinel-bearing u64 chain value cannot exceed u32::MAX here and the narrowing is lossless"
)]
const fn wire_ttl_floor(ttl: u64) -> u32 {
    ttl as u32
}

/// The validated outcome of one response parse bound to the extreme-TTL flag,
/// the raw header AD bit, and the conservative supporting-TTL cap captured from
/// that same successful parse, owned by the receiver so a later reuse of the
/// parse workspace cannot repurpose the observation.
pub(crate) struct ParsedReply {
    outcome: Outcome,
    observation: ReplyFacts,
}

impl ParsedReply {
    /// Parses a response through the unchanged public [`parse_response`],
    /// binding the extreme-TTL observation and the raw AD flag from that same
    /// successful parse; on error no [`ParsedReply`] exists and the workspace
    /// flag is left as the parse left it.
    ///
    /// # Errors
    ///
    /// Returns exactly the errors [`parse_response`] returns.
    pub(crate) fn parse_reply(
        ws: &mut ResponseWorkspace,
        zones: &BailiwickZones,
        fqdn: &Fqdn,
        family: Family,
        tid: u16,
        msg: &[u8],
    ) -> Result<ParsedReply, DnsError> {
        let outcome = parse_response(ws, zones, fqdn, family, tid, msg)?;
        let extreme_ttl = ws.extreme_ttl();
        let ad = msg.get(3).is_some_and(|b| b & AD_FLAG != 0);
        let observation = ws.supporting_ttl_cap().map_or(
            ReplyFacts::WithoutSupportingTtl {
                ad,
                extreme: extreme_ttl,
            },
            |ttl| ReplyFacts::WithSupportingTtl {
                ad,
                extreme: extreme_ttl,
                ttl,
            },
        );
        Ok(ParsedReply {
            outcome,
            observation,
        })
    }

    /// Observes this reply into a private borrowed view over the whole
    /// [`ParsedReply`]: the published-kind classification is computed once here
    /// and every fact the receive path reads (raw AD, extreme-TTL flag,
    /// supporting-TTL cap, application outcome) resolves through the one
    /// borrowed reply, so the whole exchange reads one consistent fact set.
    pub(crate) fn observe(&self) -> ObservedReply<'_> {
        ObservedReply {
            reply: self,
            kind: classify_published(&self.outcome),
        }
    }

    /// Whether the same parse that produced this outcome observed an
    /// answer-section record with a TTL above [`EXTREME_TTL_THRESHOLD`]. The
    /// receive path reads this through the observed view; the test payload
    /// oracle keeps the direct getter under `cfg(test)`.
    #[cfg(test)]
    pub(crate) const fn extreme_ttl(&self) -> bool {
        self.observation.extreme()
    }

    /// The raw AD wire assertion from the same validated parse. It is a raw
    /// observation of one bit in a fully validated reply, never authentication
    /// of the resolver or DNS data.
    #[cfg(test)]
    pub(crate) const fn raw_ad_fact(&self) -> bool {
        self.observation.ad()
    }

    /// The conservative raw supporting-TTL cap bound from the same validated
    /// parse: `Some` for a positive with a reachable answer-section TTL, `None`
    /// otherwise. The receive path reads it through the observed view; the test
    /// payload oracle keeps the direct getter under `cfg(test)`.
    #[cfg(test)]
    pub(crate) const fn supporting_ttl_cap(&self) -> Option<u32> {
        self.observation.supporting_ttl_cap()
    }
}

/// The transport-side origin facts an apply needs but the reply itself cannot
/// carry: the connection-captured delivering source, the genuine query-start
/// floor, the completed strict-pin authentication fact, and the declared
/// recursion policy of the saved configured set that source belongs to. The
/// reply-derived raw AD and supporting-TTL facts stay on the reply so every
/// positive binds evidence from the same [`ParsedReply`] it is built from.
#[derive(Clone, Copy)]
pub(crate) struct ApplyOrigin {
    pub(crate) source: ResolverSource,
    pub(crate) query_floor: u64,
    pub(crate) origin_authenticated: bool,
    pub(crate) origin_policy: RecursionPolicy,
}

/// Maps an evidence construction refusal into the corresponding cache error so
/// the production apply surfaces it explicitly instead of silently dropping
/// the evidence (a dead-floor overflow is `DeadlineOverflow`; an authenticated
/// origin without an attributable source is `EvidenceInconsistent`).
const fn map_evidence_error(err: EvidenceError) -> CacheError {
    match err {
        EvidenceError::DeadlineOverflow => CacheError::DeadlineOverflow,
        EvidenceError::AuthenticatedWithoutSource => CacheError::EvidenceInconsistent,
    }
}

/// A private borrowed view over a whole local [`ParsedReply`] created by
/// [`ParsedReply::observe`]: the published-kind classification is captured at
/// observe time, and every other fact the receive path reads (raw AD, the
/// extreme-TTL flag, the supporting-TTL cap, the application outcome) resolves
/// through the one borrowed reply, so the receive path reads one consistent
/// fact set for the whole exchange. The borrow is bounded to the local reply
/// value and is never stored on the receiver, the cache, or a schedule.
pub(crate) struct ObservedReply<'a> {
    reply: &'a ParsedReply,
    kind: PublishedKind,
}

impl<'a> ObservedReply<'a> {
    /// The raw AD wire assertion from the same validated reply the receive
    /// path is publishing. A raw observation of one bit in a fully validated
    /// reply, never authentication of the resolver or DNS data.
    pub(crate) const fn ad_fact(&self) -> bool {
        ReplyFacts::ad(self.reply.observation)
    }

    /// The conservative raw supporting-TTL cap bound from the same validated
    /// reply: `Some` for a positive with a reachable answer-section TTL, `None`
    /// when no supporting record survived.
    pub(crate) const fn supporting_ttl_cap(&self) -> Option<u32> {
        ReplyFacts::supporting_ttl_cap(self.reply.observation)
    }

    /// The pure probe-sensor facts of the observed reply — the published kind,
    /// the extreme-TTL flag, and the raw header AD bit — with no cache or
    /// schedule side effects. The AD element is a raw assertion of one bit in
    /// the validated reply, never authentication of the resolver or DNS data.
    pub(crate) const fn probe_facts(&self) -> (PublishedKind, bool, bool) {
        (
            self.kind,
            ReplyFacts::extreme(self.reply.observation),
            ReplyFacts::ad(self.reply.observation),
        )
    }

    pub(super) fn apply(
        self,
        cache: &mut Cache,
        schedules: &mut Schedules,
        context: ApplyContext,
        origin: ApplyOrigin,
    ) -> Result<(PublishedKind, bool, OutcomeIncidents), DnsError> {
        self.apply_observed(cache, schedules, context, origin, &mut |_, _, _, _| {})
    }

    pub(super) fn apply_observed<F>(
        self,
        cache: &mut Cache,
        schedules: &mut Schedules,
        context: ApplyContext,
        origin: ApplyOrigin,
        observer: &mut F,
    ) -> Result<(PublishedKind, bool, OutcomeIncidents), DnsError>
    where
        F: FnMut(publication::ObservationPhase, &Cache, crate::dns::cache::NameIndex, u64),
    {
        let evidence = match &self.reply.outcome {
            Outcome::Positive { .. } | Outcome::NxDomain { .. } | Outcome::NoData { .. } => Some(
                Evidence::new(
                    self.ad_fact(),
                    origin.origin_authenticated,
                    origin.origin_policy.is_declared(),
                    origin.source,
                    self.supporting_ttl_cap(),
                    origin.query_floor,
                )
                .map_err(|err| DnsError::Cache(map_evidence_error(err)))?,
            ),
        };
        let incidents = publication::apply_route_observed(
            cache,
            schedules,
            context,
            &self.reply.outcome,
            evidence,
            observer,
        )?;
        Ok((
            self.kind,
            ReplyFacts::extreme(self.reply.observation),
            incidents,
        ))
    }
}

/// Parses and validates a DNS response against the exact outstanding query,
/// returning a classified outcome. The caller supplies a reusable
/// [`ResponseWorkspace`]; the parse path performs no heap allocation or
/// deallocation after boot. Unknown-but-well-formed records are ignored; only
/// validated outcomes classify. DNAME anywhere is rejected.
///
/// # Errors
///
/// Returns every refusal in `DnsError` without any cache mutation.
pub fn parse_response(
    ws: &mut ResponseWorkspace,
    zones: &BailiwickZones,
    fqdn: &Fqdn,
    family: Family,
    tid: u16,
    msg: &[u8],
) -> Result<Outcome, DnsError> {
    if msg.len() > DNS_MSG_LIMIT {
        return Err(DnsError::MessageTooLong);
    }
    ws.owner_len = 0;
    ws.soa = None;
    ws.extreme_ttl = false;
    ws.supporting_ttl_cap = None;
    let mut reader = Reader::new(msg);
    let header = read_reply_header(&mut reader, tid)?;
    read_question(msg, &mut reader, fqdn, family)?;
    for _ in 0..header.answer_count {
        let rr = read_rr(msg, &mut reader)?;
        apply_answer_rr(ws, msg, &mut reader, &rr, family)?;
    }
    parse_authority_section(ws, msg, &mut reader, header.authority_count)?;
    parse_additional_section(msg, &mut reader, header.additional_count)?;

    if reader.remaining() > 0 {
        return Err(DnsError::TrailingBytes);
    }

    finish_response(ws, zones, fqdn, family, header.rcode)
}

/// The fixed reply header plus the section counts a response declares.
struct ReplyHeader {
    rcode: u8,
    answer_count: usize,
    authority_count: usize,
    additional_count: usize,
}

/// Reads the reply header, validating its flags and count bounds in wire order.
fn read_reply_header(reader: &mut Reader<'_>, tid: u16) -> Result<ReplyHeader, DnsError> {
    let got_tid = reader.u16()?;
    if got_tid != tid {
        return Err(DnsError::BadTid {
            expected: tid,
            got: got_tid,
        });
    }
    let flags = reader.u16()?;
    let qr = (flags >> 15) & 1;
    let opcode = ((flags >> 11) & 0x0f) as u8;
    let tc = (flags >> 9) & 1;
    let rcode = (flags & 0x0f) as u8;
    if qr != 1 {
        return Err(DnsError::NotResponse);
    }
    if opcode != 0 {
        return Err(DnsError::BadOpcode { got: opcode });
    }
    if tc == 1 {
        return Err(DnsError::Truncated);
    }
    let qdcount = usize::from(reader.u16()?);
    let answer_count = usize::from(reader.u16()?);
    let authority_count = usize::from(reader.u16()?);
    let additional_count = usize::from(reader.u16()?);
    if qdcount != 1 {
        return Err(DnsError::QuestionCount { got: qdcount });
    }
    let total_rr = answer_count + authority_count + additional_count;
    if total_rr > MAX_TOTAL_RR {
        return Err(DnsError::ExcessiveRecords {
            total: total_rr,
            limit: MAX_TOTAL_RR,
        });
    }
    Ok(ReplyHeader {
        rcode,
        answer_count,
        authority_count,
        additional_count,
    })
}

/// Reads the single question and matches it against the outstanding query.
fn read_question(
    msg: &[u8],
    reader: &mut Reader<'_>,
    fqdn: &Fqdn,
    family: Family,
) -> Result<(), DnsError> {
    let (qname, after_q) = read_name(msg, reader.pos, true)?;
    reader.pos = after_q;
    let qtype = reader.u16()?;
    let qclass = reader.u16()?;
    if qname.as_slice() != fqdn.as_str().as_bytes()
        || qtype != family_qtype(family)
        || qclass != CLASS_IN
    {
        return Err(DnsError::QuestionMismatch);
    }
    Ok(())
}

/// Applies one answer-section record and advances the reader past its rdata.
fn apply_answer_rr(
    ws: &mut ResponseWorkspace,
    msg: &[u8],
    reader: &mut Reader<'_>,
    rr: &RawRr,
    family: Family,
) -> Result<(), DnsError> {
    if rr.class != CLASS_IN {
        return Err(DnsError::BadClass { got: rr.class });
    }
    if matches!(rr.ty, TYPE_A | TYPE_AAAA | TYPE_CNAME) && rr.ttl > EXTREME_TTL_THRESHOLD {
        ws.extreme_ttl = true;
    }
    match rr.ty {
        TYPE_A | TYPE_AAAA | TYPE_CNAME | TYPE_SOA => {
            let rdata = parse_rdata(msg, rr.rd_start, rr.rdlen, rr.ty)?;
            apply_rdata(ws, &rdata, rr, family)?;
        }
        TYPE_DNAME => return Err(DnsError::DnameUnsupported),
        _ => {}
    }
    reader.skip(rr.rdlen)
}

/// Applies one parsed answer rdata to the workspace, silently discarding an
/// address record of the other family.
fn apply_rdata(
    ws: &mut ResponseWorkspace,
    rdata: &Rdata,
    rr: &RawRr,
    family: Family,
) -> Result<(), DnsError> {
    match rdata {
        Rdata::A(ip) => {
            if family != Family::A {
                // Wrong-family record: discarded silently, with no anomaly or
                // telemetry (docs/alumina-proxy.md:476).
                return Ok(());
            }
            let idx = ensure_owner(ws, &rr.owner)?;
            ws.owners[idx].push_address(NumericAddr::V4(*ip), rr.ttl)
        }
        Rdata::Aaaa(ip) => {
            if family != Family::Aaaa {
                // Wrong-family record: discarded silently, with no anomaly or
                // telemetry (docs/alumina-proxy.md:476).
                return Ok(());
            }
            let idx = ensure_owner(ws, &rr.owner)?;
            ws.owners[idx].push_address(NumericAddr::V6(*ip), rr.ttl)
        }
        Rdata::Cname(target) => {
            let idx = ensure_owner(ws, &rr.owner)?;
            ws.owners[idx].push_cname(*target, rr.ttl)
        }
        Rdata::Soa { .. } => Ok(()),
    }
}

/// Roots the CNAME chain, collects terminal bindings, and classifies the rcode.
fn finish_response(
    ws: &mut ResponseWorkspace,
    zones: &BailiwickZones,
    fqdn: &Fqdn,
    family: Family,
    rcode: u8,
) -> Result<Outcome, DnsError> {
    let root = DnsName::from_exact(fqdn.as_str().as_bytes());
    let (chain, chain_ttl) = root_chain(&root, zones, ws)?;
    let terminal = chain.terminal.as_slice();
    match rcode {
        RCODE_NOERROR => noerror_outcome(ws, family, terminal, chain_ttl),
        RCODE_NXDOMAIN => nxdomain_outcome(ws, terminal, chain_ttl),
        code => Err(DnsError::BadRcode { code }),
    }
}

/// The conservative negative TTL cap: the chain, SOA, and SOA MINIMUM floor.
fn negative_cap(ws: &ResponseWorkspace, chain_ttl: u64) -> Option<u32> {
    ws.soa.as_ref().map(|(_owner, ttl, minimum)| {
        wire_ttl_floor(chain_ttl.min(u64::from(*ttl)).min(u64::from(*minimum)))
    })
}

/// Assembles the positive or NODATA outcome for a NOERROR reply.
fn noerror_outcome(
    ws: &mut ResponseWorkspace,
    family: Family,
    terminal: &[u8],
    chain_ttl: u64,
) -> Result<Outcome, DnsError> {
    let mut bindings = BindingList::default();
    let mut earliest = chain_ttl;
    if let Some(owner) = ws.owners[..ws.owner_len]
        .iter()
        .find(|o| o.name.eq_bytes(terminal))
    {
        for (addr, addr_ttl) in &owner.addrs[..usize::from(owner.addr_len)] {
            bindings.push(*addr)?;
            earliest = earliest.min(u64::from(*addr_ttl));
        }
    }
    if !bindings.is_empty() {
        ws.supporting_ttl_cap = Some(wire_ttl_floor(earliest));
        return Ok(Outcome::Positive {
            family,
            bindings,
            ttl: earliest,
        });
    }
    let Some(soa) = classify_soa(terminal, ws.soa.as_ref())? else {
        return Err(DnsError::EmptyNoerrorWithoutSoa);
    };
    let cap = negative_cap(ws, chain_ttl);
    ws.supporting_ttl_cap = cap;
    Ok(Outcome::NoData {
        family,
        soa: Some(soa),
    })
}

/// Assembles the NXDOMAIN outcome, rejecting terminal address data.
fn nxdomain_outcome(
    ws: &mut ResponseWorkspace,
    terminal: &[u8],
    chain_ttl: u64,
) -> Result<Outcome, DnsError> {
    let soa = classify_soa(terminal, ws.soa.as_ref())?;
    let terminal_data = ws.owners[..ws.owner_len]
        .iter()
        .find(|o| o.name.eq_bytes(terminal))
        .is_some_and(|o| o.has_addr_data);
    if terminal_data {
        return Err(DnsError::TerminalWithoutData);
    }
    let cap = negative_cap(ws, chain_ttl);
    ws.supporting_ttl_cap = cap;
    Ok(Outcome::NxDomain { soa })
}

fn parse_authority_section(
    ws: &mut ResponseWorkspace,
    msg: &[u8],
    reader: &mut Reader<'_>,
    count: usize,
) -> Result<(), DnsError> {
    for _ in 0..count {
        let rr = read_rr(msg, reader)?;
        if rr.class != CLASS_IN {
            return Err(DnsError::BadClass { got: rr.class });
        }
        if rr.ty == TYPE_DNAME {
            return Err(DnsError::DnameUnsupported);
        }
        check_fixed_addr_rdata_len(rr.ty, rr.rdlen)?;
        if rr.ty == TYPE_SOA
            && let Rdata::Soa { minimum } = parse_rdata(msg, rr.rd_start, rr.rdlen, rr.ty)?
        {
            if ws.soa.is_some() {
                return Err(DnsError::SoaCount { got: 2 });
            }
            ws.soa = Some((rr.owner, rr.ttl, minimum));
        }
        reader.skip(rr.rdlen)?;
    }
    Ok(())
}

fn parse_additional_section(
    msg: &[u8],
    reader: &mut Reader<'_>,
    count: usize,
) -> Result<(), DnsError> {
    for _ in 0..count {
        let rr = read_rr(msg, reader)?;
        if rr.ty == TYPE_DNAME {
            return Err(DnsError::DnameUnsupported);
        }
        check_fixed_addr_rdata_len(rr.ty, rr.rdlen)?;
        reader.skip(rr.rdlen)?;
    }
    Ok(())
}

struct Chain {
    terminal: DnsName,
}

fn root_chain(
    root: &DnsName,
    zones: &BailiwickZones,
    ws: &ResponseWorkspace,
) -> Result<(Chain, u64), DnsError> {
    let mut current = *root;
    let mut links = 0usize;
    let mut cname_ttl = u64::MAX;
    let mut visited = [DnsName::default(); MAX_CNAME_LINKS + 2];
    let mut visited_len = 0usize;
    loop {
        if visited[..visited_len]
            .iter()
            .any(|v| v.eq_bytes(current.as_slice()))
        {
            return Err(DnsError::CnameLoop);
        }
        visited[visited_len] = current;
        visited_len += 1;
        let entry = ws.owners[..ws.owner_len]
            .iter()
            .find(|o| o.name.eq_bytes(current.as_slice()));
        let Some(entry) = entry else {
            break;
        };
        let Some((target, ttl)) = &entry.cname else {
            break;
        };
        if target.eq_bytes(root.as_slice()) {
            return Err(DnsError::CnameLoop);
        }
        if !zones.covers_for(root.as_slice(), target.as_slice()) {
            return Err(DnsError::BailiwickViolation);
        }
        cname_ttl = cname_ttl.min(u64::from(*ttl));
        links += 1;
        if links > MAX_CNAME_LINKS {
            return Err(DnsError::CnameTooDeep { links });
        }
        let next = ws.owners[..ws.owner_len]
            .iter()
            .find(|o| o.name.eq_bytes(target.as_slice()));
        let Some(next) = next else {
            return Ok((Chain { terminal: *target }, cname_ttl));
        };
        current = next.name;
    }
    Ok((Chain { terminal: current }, cname_ttl))
}

fn classify_soa(
    terminal: &[u8],
    soa: Option<&(DnsName, u32, u32)>,
) -> Result<Option<Soa>, DnsError> {
    match soa {
        None => Ok(None),
        Some((owner, ttl, minimum)) => {
            if !soa_covers(terminal, owner.as_slice()) {
                return Err(DnsError::NonCoveringSoa);
            }
            Ok(Some(Soa::new(u64::from(*ttl), u64::from(*minimum))))
        }
    }
}

fn soa_covers(name: &[u8], soa_owner: &[u8]) -> bool {
    if soa_owner.is_empty() {
        return true;
    }
    if name == soa_owner {
        return true;
    }
    if soa_owner.len() >= name.len() {
        return false;
    }
    let boundary = name.len() - soa_owner.len() - 1;
    let suffix = &name[name.len() - soa_owner.len()..];
    suffix == soa_owner && name[boundary] == b'.'
}

#[cfg(test)]
mod tests;

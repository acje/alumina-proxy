use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::cache::{CacheError, Family, MAX_ADDRESSES};
use crate::config::{ALLOWLIST_MAX, Allowlist, Fqdn};
use crate::eligibility::NumericAddr;
use crate::schedule::Soa;

mod publication;

pub use publication::apply_outcome;

pub(crate) mod outcome;

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
#[non_exhaustive]
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

fn write_header(buf: &mut [u8], tid: u16) -> Result<(), DnsError> {
    if buf.len() < HEADER_LEN {
        return Err(DnsError::BufferExhausted);
    }
    buf[0] = (tid >> 8) as u8;
    buf[1] = (tid & 0xff) as u8;
    buf[2] = 0x01;
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x01;
    buf[6..12].fill(0);
    Ok(())
}

#[expect(
    clippy::expect_used,
    reason = "label and tail lengths are checked to be <= 63 before encoding, fitting u8"
)]
fn write_qname(buf: &mut [u8], mut pos: usize, name: &str) -> Result<usize, DnsError> {
    let bytes = name.as_bytes();
    let mut label_start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'.' {
            let label_len = i - label_start;
            if label_len == 0 || label_len > 63 {
                return Err(DnsError::QueryTooLong);
            }
            if pos + 1 + label_len > buf.len() {
                return Err(DnsError::BufferExhausted);
            }
            buf[pos] = u8::try_from(label_len).expect("dns label at most 63 bytes");
            buf[pos + 1..pos + 1 + label_len]
                .copy_from_slice(&bytes[label_start..label_start + label_len]);
            pos += 1 + label_len;
            label_start = i + 1;
        }
    }
    let tail = bytes.len() - label_start;
    if tail > 0 {
        if tail > 63 {
            return Err(DnsError::QueryTooLong);
        }
        if pos + 1 + tail > buf.len() {
            return Err(DnsError::BufferExhausted);
        }
        buf[pos] = u8::try_from(tail).expect("dns label at most 63 bytes");
        buf[pos + 1..pos + 1 + tail].copy_from_slice(&bytes[label_start..]);
        pos += 1 + tail;
    }
    if pos >= buf.len() {
        return Err(DnsError::BufferExhausted);
    }
    buf[pos] = 0;
    Ok(pos + 1)
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
    let mut field = at;
    let mut decode = at;
    let mut total = 0usize;
    let mut pointers = 0usize;
    let mut closed_by_pointer = false;
    loop {
        let byte = msg.get(decode).copied().ok_or(DnsError::MessageTooLong)?;
        match byte & 0xc0 {
            0x00 => {
                let len = usize::from(byte);
                if len == 0 {
                    total += 1;
                    if total > MAX_NAME_BYTES {
                        return Err(DnsError::NameTooLong);
                    }
                    return Ok((out, if closed_by_pointer { field } else { field + 1 }));
                }
                if len > 63 {
                    return Err(DnsError::LabelTooLong { len });
                }
                total += len + 1;
                if total > MAX_NAME_BYTES {
                    return Err(DnsError::NameTooLong);
                }
                let start = decode + 1;
                let end = start + len;
                if end >= msg.len() {
                    return Err(DnsError::MessageTooLong);
                }
                if !out.is_empty() {
                    out.push(b'.')?;
                }
                for &b in &msg[start..end] {
                    if strict && b == b'.' {
                        return Err(DnsError::EmbeddedDotInLabel);
                    }
                    out.push(b.to_ascii_lowercase())?;
                }
                decode = end;
                if !closed_by_pointer {
                    field = end;
                }
            }
            0xc0 => {
                let hi = usize::from(byte & 0x3f);
                let lo = usize::from(
                    msg.get(decode + 1)
                        .copied()
                        .ok_or(DnsError::MessageTooLong)?,
                );
                let target = (hi << 8) | lo;
                if target >= decode {
                    return Err(DnsError::PointerNotBackward);
                }
                if !closed_by_pointer {
                    field = decode + 2;
                    closed_by_pointer = true;
                }
                decode = target;
                pointers += 1;
                if pointers > 8 {
                    return Err(DnsError::PointerCycle);
                }
            }
            _ => return Err(DnsError::ReservedLabelType { offset: decode }),
        }
    }
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
                if !already {
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

/// Parses and validates a DNS response against the exact outstanding query,
/// returning a classified outcome. The caller supplies a reusable
/// [`ResponseWorkspace`]; the parse path performs no heap allocation or
/// deallocation after boot. Unknown-but-well-formed records are ignored; only
/// validated outcomes classify. DNAME anywhere is rejected.
///
/// # Errors
///
/// Returns every refusal in `DnsError` without any cache mutation.
#[expect(
    clippy::too_many_lines,
    reason = "long multi-phase DNS response parser (frame, name, RR validation) kept inline for bounded fixed-buffer parsing"
)]
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
    let mut reader = Reader::new(msg);
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

    for _ in 0..answer_count {
        let rr = read_rr(msg, &mut reader)?;
        if rr.class != CLASS_IN {
            return Err(DnsError::BadClass { got: rr.class });
        }
        if matches!(rr.ty, TYPE_A | TYPE_AAAA | TYPE_CNAME) && rr.ttl > EXTREME_TTL_THRESHOLD {
            ws.extreme_ttl = true;
        }
        match rr.ty {
            TYPE_A | TYPE_AAAA | TYPE_CNAME | TYPE_SOA => {
                let rdata = parse_rdata(msg, rr.rd_start, rr.rdlen, rr.ty)?;
                match rdata {
                    Rdata::A(ip) => {
                        if family != Family::A {
                            // Wrong-family record: discarded silently — no
                            // address data, no CNAME interaction, and no
                            // anomaly/telemetry emitted (docs/alumina-proxy.md
                            // :476; DnsAnomalyKind has no variant for this).
                            reader.skip(rr.rdlen)?;
                            continue;
                        }
                        let idx = ensure_owner(ws, &rr.owner)?;
                        ws.owners[idx].push_address(NumericAddr::V4(ip), rr.ttl)?;
                    }
                    Rdata::Aaaa(ip) => {
                        if family != Family::Aaaa {
                            // Wrong-family record: discarded silently — no
                            // address data, no CNAME interaction, and no
                            // anomaly/telemetry emitted (docs/alumina-proxy.md
                            // :476; DnsAnomalyKind has no variant for this).
                            reader.skip(rr.rdlen)?;
                            continue;
                        }
                        let idx = ensure_owner(ws, &rr.owner)?;
                        ws.owners[idx].push_address(NumericAddr::V6(ip), rr.ttl)?;
                    }
                    Rdata::Cname(target) => {
                        let idx = ensure_owner(ws, &rr.owner)?;
                        ws.owners[idx].push_cname(target, rr.ttl)?;
                    }
                    Rdata::Soa { .. } => {}
                }
            }
            TYPE_DNAME => return Err(DnsError::DnameUnsupported),
            _ => {}
        }
        reader.skip(rr.rdlen)?;
    }

    for _ in 0..authority_count {
        let rr = read_rr(msg, &mut reader)?;
        if rr.class != CLASS_IN {
            return Err(DnsError::BadClass { got: rr.class });
        }
        if rr.ty == TYPE_DNAME {
            return Err(DnsError::DnameUnsupported);
        }
        // E3 fail-closed guard: a malformed A/AAAA rdata in the authority
        // section aborts the entire parse (no skip/isolate path). The answer
        // section is guarded the same way inside parse_rdata.
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

    for _ in 0..additional_count {
        let rr = read_rr(msg, &mut reader)?;
        if rr.ty == TYPE_DNAME {
            return Err(DnsError::DnameUnsupported);
        }
        // E3 fail-closed guard: the same strictness applies to
        // additional/glue records — any malformed A/AAAA rdata here rejects
        // the entire response rather than being skipped.
        check_fixed_addr_rdata_len(rr.ty, rr.rdlen)?;
        reader.skip(rr.rdlen)?;
    }

    if reader.remaining() > 0 {
        return Err(DnsError::TrailingBytes);
    }

    let root = DnsName::from_exact(fqdn.as_str().as_bytes());
    let (chain, chain_ttl) = root_chain(&root, zones, ws)?;
    let terminal = chain.terminal.as_slice();

    let mut bindings = BindingList::default();
    let terminal_owner = ws.owners[..ws.owner_len]
        .iter()
        .find(|o| o.name.eq_bytes(terminal));
    if let Some(owner) = terminal_owner {
        for (addr, _) in &owner.addrs[..usize::from(owner.addr_len)] {
            bindings.push(*addr)?;
        }
    }

    match rcode {
        RCODE_NOERROR => {
            if !bindings.is_empty() {
                let mut earliest = chain_ttl;
                if let Some(owner) = terminal_owner {
                    for (_, addr_ttl) in &owner.addrs[..usize::from(owner.addr_len)] {
                        earliest = earliest.min(u64::from(*addr_ttl));
                    }
                }
                return Ok(Outcome::Positive {
                    family,
                    bindings,
                    ttl: earliest,
                });
            }
            let soa = classify_soa(terminal, ws.soa.as_ref())?;
            soa.map_or(Err(DnsError::EmptyNoerrorWithoutSoa), |soa| {
                Ok(Outcome::NoData {
                    family,
                    soa: Some(soa),
                })
            })
        }
        RCODE_NXDOMAIN => {
            let soa = classify_soa(terminal, ws.soa.as_ref())?;
            let terminal_data = terminal_owner.is_some_and(|o| o.has_addr_data);
            if terminal_data {
                return Err(DnsError::TerminalWithoutData);
            }
            Ok(Outcome::NxDomain { soa })
        }
        code => Err(DnsError::BadRcode { code }),
    }
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

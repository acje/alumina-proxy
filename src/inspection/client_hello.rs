use std::fmt;

use crate::names::hostname::{FQDN_MAX_LEN, FixedHostname};

mod ja4;

pub use ja4::{Ja4Error, ja4_fingerprint};

/// Maximum inspected `ClientHello` size including TLS record framing.
pub const MAX_CLIENT_HELLO: usize = 64 * 1024;

/// Maximum plaintext payload per TLS record during inspection.
pub const RECORD_PAYLOAD_LIMIT: usize = 16 * 1024;

/// Maximum `ClientHello` handshake message length (4-byte header plus body).
///
/// A deliberate interop bound (V34, docs/alumina-proxy.md:478-480): RFC 8446
/// §5.1 lets a handshake message span multiple TLS records (each ≤ 2^14
/// payload), so a spec-legal multi-record `ClientHello` larger than 16 KiB is
/// rejected as `HandshakeTooLarge` rather than reassembled (W1-H1b-F5). The
/// per-record payload cap is `RECORD_PAYLOAD_LIMIT`.
pub const MAX_HANDSHAKE_LEN: usize = 16 * 1024;

/// Maximum number of offered `supported_versions` entries retained.
const MAX_VERSIONS: usize = 32;

/// Maximum number of distinct extensions tracked for duplicate rejection.
const MAX_EXTENSIONS: usize = 64;

/// Maximum number of cipher suites retained from the `ClientHello` body.
///
/// The cipher-suite list is a `u16`-length-prefixed run of 2-byte suites, so a
/// full 16 KiB handshake body can hold at most `MAX_HANDSHAKE_LEN / 2` suites.
const MAX_CIPHERS: usize = MAX_HANDSHAKE_LEN / 2;

/// Maximum length in bytes of the retained ALPN first protocol value.
///
/// An ALPN protocol name is `u8`-length-prefixed, so a single value is at most
/// 255 bytes.
const MAX_ALPN_VALUE: usize = 255;

/// Maximum number of `signature_algorithms` (13) entries retained from the
/// `ClientHello` body.
const MAX_SIGALGS: usize = 64;

const RANDOM_LEN: usize = 32;

const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;

const SUPPORTED_VERSIONS: u16 = 43;
const SERVER_NAME: u16 = 0;
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const ENCRYPTED_SERVER_NAME: u16 = 0xffce;
const ALPN: u16 = 16;
const SIGNATURE_ALGORITHMS: u16 = 13;

const TLS13: u16 = 0x0304;
const TLS12: u16 = 0x0303;
const TLS10: u16 = 0x0301;

/// A parsed and framed `ClientHello`, before profile validation. All fields are
/// fixed-capacity so the gate allocates nothing on the serving path.
#[derive(Clone)]
pub struct ClientHello {
    versions: [u16; MAX_VERSIONS],
    versions_len: usize,
    record_version: u16,
    sni: [u8; FQDN_MAX_LEN],
    sni_len: usize,
    sni_entries: u8,
    has_ech: bool,
    ciphers: [u16; MAX_CIPHERS],
    ciphers_len: usize,
    extensions: [u16; MAX_EXTENSIONS],
    extensions_len: usize,
    alpn: [u8; MAX_ALPN_VALUE],
    alpn_len: usize,
    sigalgs: [u16; MAX_SIGALGS],
    sigalgs_len: usize,
}

impl ClientHello {
    /// The offered non-GREASE supported versions in raw wire order, unfiltered.
    #[must_use]
    pub fn offered_versions(&self) -> &[u16] {
        &self.versions[..self.versions_len]
    }

    /// The first normalized SNI `host_name` offered.
    #[must_use]
    pub fn server_name(&self) -> &[u8] {
        &self.sni[..self.sni_len]
    }

    /// The number of `host_name` entries offered in the `server_name` extension.
    #[must_use]
    pub const fn sni_entries(&self) -> u8 {
        self.sni_entries
    }

    /// Whether the `encrypted_client_hello` (ECH) extension was present.
    #[must_use]
    pub const fn has_ech(&self) -> bool {
        self.has_ech
    }

    /// The offered cipher suites in wire order, including SCSV `0x00ff` and
    /// GREASE, unfiltered. Bounded by the 16 KiB handshake cap.
    #[must_use]
    pub fn ciphers(&self) -> &[u16] {
        &self.ciphers[..self.ciphers_len]
    }

    /// The distinct extension types present in wire order, including ALPN (16)
    /// and `signature_algorithms` (13), unfiltered.
    #[must_use]
    pub fn extensions(&self) -> &[u16] {
        &self.extensions[..self.extensions_len]
    }

    /// The raw bytes of the first ALPN protocol value offered, or empty when no
    /// well-formed ALPN extension was present.
    #[must_use]
    pub fn alpn_first_value(&self) -> &[u8] {
        &self.alpn[..self.alpn_len]
    }

    /// The offered `signature_algorithms` (13) values in wire order, unfiltered.
    /// Retained leniently: a malformed (odd-length) extension retains nothing;
    /// an overlong list (> 64 entries) rejects the `ClientHello` as
    /// `TooManySigAlgs` rather than silently truncating.
    #[must_use]
    pub fn sigalgs(&self) -> &[u16] {
        &self.sigalgs[..self.sigalgs_len]
    }

    /// The canonical `FoxIO` `JA4` client fingerprint for this `ClientHello`, using
    /// the highest non-GREASE offered version and SNI presence per the
    /// `alumina-xfbq8` amendment (docs/alumina-proxy.md:879-895). When no
    /// non-GREASE `supported_versions` is offered the record-layer protocol
    /// version supplies the `ver` token. Allocation-free.
    ///
    /// # Panics
    ///
    /// Never on any reachable path: the parser bounds `ciphers` to
    /// `MAX_CIPHERS` and `extensions` to `MAX_EXTENSIONS`, so the internal
    /// capacity checks in [`ja4_fingerprint`] cannot fire.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "the parser bounds ciphers to MAX_CIPHERS and extensions to MAX_EXTENSIONS, so the internal capacity checks cannot fire"
    )]
    pub fn ja4(&self) -> [u8; 36] {
        let version = self
            .offered_versions()
            .iter()
            .copied()
            .filter(|&v| !is_grease(v))
            .max()
            .unwrap_or(self.record_version);
        ja4_fingerprint(
            version,
            self.ciphers(),
            self.extensions(),
            self.alpn_first_value(),
            self.sigalgs(),
        )
        .expect("parser-bounded: ciphers <= MAX_CIPHERS and extensions <= MAX_EXTENSIONS")
    }
}

impl fmt::Debug for ClientHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHello")
            .field("versions", &self.offered_versions())
            .field("versions_len", &self.versions_len)
            .field("record_version", &self.record_version)
            .field("sni", &self.server_name())
            .field("sni_len", &self.sni_len)
            .field("sni_entries", &self.sni_entries)
            .field("has_ech", &self.has_ech)
            .field("ciphers", &self.ciphers())
            .field("ciphers_len", &self.ciphers_len)
            .field("extensions", &self.extensions())
            .field("extensions_len", &self.extensions_len)
            .field("alpn", &self.alpn_first_value())
            .field("alpn_len", &self.alpn_len)
            .field("sigalgs", &self.sigalgs())
            .field("sigalgs_len", &self.sigalgs_len)
            .finish()
    }
}

impl PartialEq for ClientHello {
    fn eq(&self, other: &Self) -> bool {
        self.offered_versions() == other.offered_versions()
            && self.versions_len == other.versions_len
            && self.record_version == other.record_version
            && self.server_name() == other.server_name()
            && self.sni_len == other.sni_len
            && self.sni_entries == other.sni_entries
            && self.has_ech == other.has_ech
            && self.ciphers() == other.ciphers()
            && self.ciphers_len == other.ciphers_len
            && self.extensions() == other.extensions()
            && self.extensions_len == other.extensions_len
            && self.alpn_first_value() == other.alpn_first_value()
            && self.alpn_len == other.alpn_len
            && self.sigalgs() == other.sigalgs()
            && self.sigalgs_len == other.sigalgs_len
    }
}

impl Eq for ClientHello {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelloAccepted {
    _private: (),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChError {
    TooLarge,
    HandshakeTooLarge { got: usize },
    RecordTooLarge { got: usize },
    ZeroLengthRecord,
    NotHandshake { content_type: u8 },
    Sslv2Framing,
    BadRecordVersion { got: u16 },
    NotClientHello { handshake_type: u8 },
    TruncatedHandshake,
    MalformedBody { detail: &'static str },
    UnsupportedLegacyVersion { got: u16 },
    MissingSupportedVersions,
    InvalidVersionOffer { version: u16 },
    MissingCompressionMethods,
    NonNullCompression,
    DuplicateExtension { ext: u16 },
    MalformedExtension { ext: u16 },
    TooManyExtensions,
    TooManySigAlgs,
    EchPresent,
    InvalidServerName { detail: &'static str },
    ServerNameMismatch,
}

impl fmt::Display for ChError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChError::TooLarge => write!(f, "ClientHello exceeds 64 KiB inspection bound"),
            ChError::HandshakeTooLarge { got } => {
                write!(
                    f,
                    "ClientHello handshake message length {got} exceeds 16 KiB"
                )
            }
            ChError::RecordTooLarge { got } => {
                write!(f, "TLS record payload {got} exceeds 16 KiB")
            }
            ChError::ZeroLengthRecord => write!(f, "TLS handshake record has zero payload"),
            ChError::NotHandshake { content_type } => {
                write!(
                    f,
                    "TLS content type {content_type} is not handshake before ClientHello"
                )
            }
            ChError::Sslv2Framing => write!(f, "SSLv2 ClientHello framing rejected"),
            ChError::BadRecordVersion { got } => {
                write!(
                    f,
                    "TLS record legacy version {got:04x} not accepted for initial ClientHello"
                )
            }
            ChError::NotClientHello { handshake_type } => {
                write!(f, "handshake type {handshake_type} is not ClientHello")
            }
            ChError::TruncatedHandshake => write!(f, "handshake message truncated"),
            ChError::MalformedBody { detail } => write!(f, "ClientHello body malformed: {detail}"),
            ChError::UnsupportedLegacyVersion { got } => {
                write!(
                    f,
                    "legacy_version {got:04x} is not TLS 1.2 compatibility 0x0303"
                )
            }
            ChError::MissingSupportedVersions => write!(
                f,
                "ClientHello lacks the supported_versions extension (TLS 1.3-only profile)"
            ),
            ChError::InvalidVersionOffer { version } => {
                write!(
                    f,
                    "supported_versions offers non-GREASE version {version:04x} other than TLS 1.3"
                )
            }
            ChError::MissingCompressionMethods => {
                write!(f, "ClientHello lacks compression methods")
            }
            ChError::NonNullCompression => write!(
                f,
                "ClientHello compression method is not the single null method"
            ),
            ChError::DuplicateExtension { ext } => {
                write!(f, "duplicate ClientHello extension {ext}")
            }
            ChError::MalformedExtension { ext } => {
                write!(f, "ClientHello extension {ext} malformed")
            }
            ChError::TooManyExtensions => {
                write!(f, "ClientHello carries more than 64 distinct extensions")
            }
            ChError::TooManySigAlgs => {
                write!(
                    f,
                    "ClientHello carries more than 64 signature_algorithms entries"
                )
            }
            ChError::EchPresent => write!(
                f,
                "encrypted_client_hello (ECH) extension present; rejected"
            ),
            ChError::InvalidServerName { detail } => {
                write!(f, "server_name extension invalid: {detail}")
            }
            ChError::ServerNameMismatch => write!(f, "SNI does not match the approved hostname"),
        }
    }
}

/// The payload-less finite discriminant of a `ClientHello` rejection: it covers
/// the enumerated identity/profile catalog — ECH, SNI mismatch, missing-or-
/// malformed SNI, and the TLS-profile/framing rejections — keyed only by
/// variant identity, never by an attacker-supplied extension id or detail
/// string, so per-cause capture/fold stays bounded and exact-in-kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HelloRejectReason {
    EchPresent,
    ServerNameMismatch,
    InvalidServerName,
    Profile,
}

impl HelloRejectReason {
    /// Projects a [`ChError`] onto its finite discriminant. The SNI-missing /
    /// malformed / duplicate / illegal-name cases all share the
    /// `InvalidServerName` kind; record/version/extension/compression and
    /// framing violations collapse to `Profile`.
    #[must_use]
    pub const fn from_ch_error(err: &ChError) -> HelloRejectReason {
        match err {
            ChError::EchPresent => HelloRejectReason::EchPresent,
            ChError::ServerNameMismatch => HelloRejectReason::ServerNameMismatch,
            ChError::InvalidServerName { .. } => HelloRejectReason::InvalidServerName,
            ChError::TooLarge
            | ChError::HandshakeTooLarge { .. }
            | ChError::RecordTooLarge { .. }
            | ChError::ZeroLengthRecord
            | ChError::NotHandshake { .. }
            | ChError::Sslv2Framing
            | ChError::BadRecordVersion { .. }
            | ChError::NotClientHello { .. }
            | ChError::TruncatedHandshake
            | ChError::MalformedBody { .. }
            | ChError::UnsupportedLegacyVersion { .. }
            | ChError::MissingSupportedVersions
            | ChError::InvalidVersionOffer { .. }
            | ChError::MissingCompressionMethods
            | ChError::NonNullCompression
            | ChError::DuplicateExtension { .. }
            | ChError::MalformedExtension { .. }
            | ChError::TooManyExtensions
            | ChError::TooManySigAlgs => HelloRejectReason::Profile,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Inspect {
    /// The full `ClientHello` handshake message is not yet buffered.
    NeedMore,
    /// The `ClientHello` is framed, parsed, and fully captured. `consumed` is the
    /// number of fed bytes that ended the `ClientHello` message, so a forwarding
    /// gate can forward exactly those bytes upstream while retaining the rest.
    /// The parsed message is available via [`ChInspector::hello`].
    Complete { consumed: usize },
}

/// Incremental TLS record/handshake inspector that preserves all fed bytes and
/// produces a `ClientHello` once the complete initial `ClientHello` message is
/// available across one or more consecutive handshake records. It rejects
/// `SSLv2` framing, non-handshake records seen before the `ClientHello` completes,
/// zero-length handshake records, record payloads over 16 KiB, a `ClientHello`
/// handshake message over 16 KiB, and an inspection total over 64 KiB.
///
/// The inspector retains its scan position and flattened-message scratch
/// across feeds, so each record payload is copied exactly once regardless of
/// the peer's fragmentation pattern. It is sized for boot-owned slot storage
/// (one instance per in-flight setup, reused across connections); it must not
/// be constructed per connection on the stack.
#[derive(Clone, Debug)]
pub struct ChInspector {
    buf: [u8; MAX_CLIENT_HELLO],
    len: usize,
    scan_pos: usize,
    flat: usize,
    scratch: [u8; MAX_CLIENT_HELLO],
    hello: Option<ClientHello>,
    consumed: usize,
}

impl Default for ChInspector {
    fn default() -> Self {
        ChInspector::new()
    }
}

impl ChInspector {
    #[must_use]
    #[expect(
        clippy::large_stack_arrays,
        reason = "designed serving-path two 64 KiB slot buffers; no runtime heap"
    )]
    pub const fn new() -> Self {
        ChInspector {
            buf: [0u8; MAX_CLIENT_HELLO],
            len: 0,
            scan_pos: 0,
            flat: 0,
            scratch: [0u8; MAX_CLIENT_HELLO],
            hello: None,
            consumed: 0,
        }
    }

    /// The parsed `ClientHello`, present once `feed` returned `Inspect::Complete`.
    #[must_use]
    pub const fn hello(&self) -> Option<&ClientHello> {
        self.hello.as_ref()
    }

    /// Feeds bytes into the inspector.
    ///
    /// # Errors
    ///
    /// Returns `TooLarge` when the fed bytes exceed the remaining inspection
    /// capacity before a complete `ClientHello` was reached, `HandshakeTooLarge`
    /// when the `ClientHello` handshake message length exceeds 16 KiB, and the
    /// framing or profile errors above at the earliest decidable byte count.
    pub fn feed(&mut self, data: &[u8]) -> Result<Inspect, ChError> {
        if self.hello.is_some() {
            return Ok(Inspect::Complete {
                consumed: self.consumed,
            });
        }
        let room = MAX_CLIENT_HELLO - self.len;
        let take = data.len().min(room);
        if take > 0 {
            self.buf[self.len..self.len + take].copy_from_slice(&data[..take]);
            self.len += take;
        }
        match self.scan_available()? {
            None => {
                if take < data.len() || self.len >= MAX_CLIENT_HELLO {
                    return Err(ChError::TooLarge);
                }
                Ok(Inspect::NeedMore)
            }
            Some((msg_len, consumed)) => {
                let record_version = u16::from_be_bytes([self.buf[1], self.buf[2]]);
                self.hello = Some(parse_body(&self.scratch[4..4 + msg_len], record_version)?);
                self.consumed = consumed;
                Ok(Inspect::Complete { consumed })
            }
        }
    }

    /// Continues flattening fully-buffered leading handshake records into the
    /// persistent scratch, copying each record payload exactly once. Returns
    /// `Some((msg_len, consumed))` once the complete `ClientHello` handshake
    /// message (4-byte header plus body) is captured, with the stream byte
    /// count consumed to the end of that message.
    fn scan_available(&mut self) -> Result<Option<(usize, usize)>, ChError> {
        loop {
            if self.scan_pos >= self.len {
                return Ok(None);
            }
            let pos = self.scan_pos;
            if self.buf[pos] & 0x80 != 0 {
                return Err(ChError::Sslv2Framing);
            }
            if pos + 5 > self.len {
                return Ok(None);
            }
            if self.buf[pos] != CONTENT_HANDSHAKE {
                return Err(ChError::NotHandshake {
                    content_type: self.buf[pos],
                });
            }
            let record_version = u16::from_be_bytes([self.buf[pos + 1], self.buf[pos + 2]]);
            if record_version != TLS10 && record_version != TLS12 {
                return Err(ChError::BadRecordVersion {
                    got: record_version,
                });
            }
            let rlen = usize::from(u16::from_be_bytes([self.buf[pos + 3], self.buf[pos + 4]]));
            if rlen > RECORD_PAYLOAD_LIMIT {
                return Err(ChError::RecordTooLarge { got: rlen });
            }
            if rlen == 0 {
                return Err(ChError::ZeroLengthRecord);
            }
            let rec_end = pos + 5 + rlen;
            if rec_end > self.len {
                return Ok(None);
            }
            if self.flat == 0 && rlen < 4 {
                return Err(ChError::TruncatedHandshake);
            }
            if self.flat + rlen > MAX_CLIENT_HELLO {
                return Err(ChError::TooLarge);
            }
            self.scratch[self.flat..self.flat + rlen].copy_from_slice(&self.buf[pos + 5..rec_end]);
            self.flat += rlen;
            self.scan_pos = rec_end;
            if self.flat >= 4 {
                if self.scratch[0] != HANDSHAKE_CLIENT_HELLO {
                    return Err(ChError::NotClientHello {
                        handshake_type: self.scratch[0],
                    });
                }
                let msg_len = (usize::from(self.scratch[1]) << 16)
                    | (usize::from(self.scratch[2]) << 8)
                    | usize::from(self.scratch[3]);
                let need = 4 + msg_len;
                if need > MAX_HANDSHAKE_LEN {
                    return Err(ChError::HandshakeTooLarge { got: need });
                }
                if self.flat >= need {
                    let consumed = self.scan_pos + need - self.flat;
                    return Ok(Some((msg_len, consumed)));
                }
            }
        }
    }
}

fn u16_at(buf: &[u8], at: usize) -> Result<u16, ChError> {
    let hi = *buf.get(at).ok_or(ChError::MalformedBody {
        detail: "short read u16",
    })?;
    let lo = *buf.get(at + 1).ok_or(ChError::MalformedBody {
        detail: "short read u16",
    })?;
    Ok(u16::from_be_bytes([hi, lo]))
}

fn u8_at(buf: &[u8], at: usize) -> Result<u8, ChError> {
    buf.get(at).copied().ok_or(ChError::MalformedBody {
        detail: "short read u8",
    })
}

/// Reads the `u16`-length-prefixed cipher-suite list at `at` into a fixed
/// `[u16; MAX_CIPHERS]` buffer, returning `(count, buffer)`.
///
/// # Errors
///
/// Returns `MalformedBody` when the list length is odd, when it exceeds
/// `MAX_CIPHERS` suites, or when the list overruns the body.
fn parse_cipher_list(body: &[u8], at: usize) -> Result<(usize, [u16; MAX_CIPHERS]), ChError> {
    let list_len = usize::from(u16_at(body, at)?);
    if list_len % 2 != 0 {
        return Err(ChError::MalformedBody {
            detail: "odd cipher-suite list",
        });
    }
    let cs_count = list_len / 2;
    if cs_count > MAX_CIPHERS {
        return Err(ChError::MalformedBody {
            detail: "cipher-suite list exceeds bound",
        });
    }
    let mut ciphers = [0u16; MAX_CIPHERS];
    for (i, slot) in ciphers[..cs_count].iter_mut().enumerate() {
        *slot = u16_at(body, at + 2 + i * 2)?;
    }
    Ok((cs_count, ciphers))
}

#[expect(
    clippy::too_many_lines,
    reason = "single cohesive ClientHello body parser; splitting would harm readability"
)]
fn parse_body(body: &[u8], record_version: u16) -> Result<ClientHello, ChError> {
    let legacy = u16_at(body, 0)?;
    if legacy != TLS12 {
        return Err(ChError::UnsupportedLegacyVersion { got: legacy });
    }
    let mut pos = 2 + RANDOM_LEN;
    let sid_len = usize::from(u8_at(body, pos)?);
    pos += 1 + sid_len;
    let (cs_count, ciphers) = parse_cipher_list(body, pos)?;
    pos += 2 + cs_count * 2;
    let comp_len = usize::from(u8_at(body, pos)?);
    if comp_len != 1 {
        if comp_len == 0 {
            return Err(ChError::MissingCompressionMethods);
        }
        return Err(ChError::NonNullCompression);
    }
    let comp = u8_at(body, pos + 1)?;
    if comp != 0 {
        return Err(ChError::NonNullCompression);
    }
    pos += 1 + comp_len;
    let ext_total = usize::from(u16_at(body, pos)?);
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end != body.len() {
        return Err(ChError::MalformedBody {
            detail: "extensions do not fill the ClientHello body",
        });
    }
    let mut versions = [0u16; MAX_VERSIONS];
    let mut versions_len = 0usize;
    let mut sv_present = false;
    let mut sni = [0u8; FQDN_MAX_LEN];
    let mut sni_len = 0usize;
    let mut sni_entries = 0u8;
    let mut has_ech = false;
    let mut alpn = [0u8; MAX_ALPN_VALUE];
    let mut alpn_len = 0usize;
    let mut sigalgs = [0u16; MAX_SIGALGS];
    let mut sigalgs_len = 0usize;
    let mut seen = [0u16; MAX_EXTENSIONS];
    let mut seen_count = 0usize;
    while pos < ext_end {
        let ext_type = u16_at(body, pos)?;
        if seen[..seen_count].contains(&ext_type) {
            return Err(ChError::DuplicateExtension { ext: ext_type });
        }
        if seen_count == seen.len() {
            return Err(ChError::TooManyExtensions);
        }
        seen[seen_count] = ext_type;
        seen_count += 1;
        let ext_len = usize::from(u16_at(body, pos + 2)?);
        let ext_start = pos + 4;
        let ext_end_i = ext_start + ext_len;
        if ext_end_i > body.len() {
            return Err(ChError::MalformedExtension { ext: ext_type });
        }
        let ext_data = &body[ext_start..ext_end_i];
        match ext_type {
            SUPPORTED_VERSIONS => {
                versions_len = parse_supported_versions(ext_data, &mut versions)?;
                sv_present = true;
            }
            SERVER_NAME => {
                parse_server_names(ext_data, &mut sni, &mut sni_len, &mut sni_entries)?;
            }
            ENCRYPTED_CLIENT_HELLO | ENCRYPTED_SERVER_NAME => {
                has_ech = true;
            }
            ALPN => {
                parse_alpn_first_value(ext_data, &mut alpn, &mut alpn_len);
            }
            SIGNATURE_ALGORITHMS => {
                sigalgs_len = parse_sig_algs(ext_data, &mut sigalgs)?;
            }
            _ => {}
        }
        pos = ext_end_i;
    }
    if !sv_present {
        return Err(ChError::MissingSupportedVersions);
    }
    validate_versions(&versions[..versions_len])?;
    Ok(ClientHello {
        versions,
        versions_len,
        record_version,
        sni,
        sni_len,
        sni_entries,
        has_ech,
        ciphers,
        ciphers_len: cs_count,
        extensions: seen,
        extensions_len: seen_count,
        alpn,
        alpn_len,
        sigalgs,
        sigalgs_len,
    })
}

fn validate_versions(versions: &[u16]) -> Result<(), ChError> {
    let mut has_tls13 = false;
    for &version in versions {
        if is_grease(version) {
            continue;
        }
        if version != TLS13 {
            return Err(ChError::InvalidVersionOffer { version });
        }
        has_tls13 = true;
    }
    if !has_tls13 {
        return Err(ChError::InvalidVersionOffer { version: 0 });
    }
    Ok(())
}

const fn is_grease(value: u16) -> bool {
    let hi = value >> 8;
    let lo = value & 0xff;
    hi == lo
        && matches!(
            hi,
            0x0a | 0x1a
                | 0x2a
                | 0x3a
                | 0x4a
                | 0x5a
                | 0x6a
                | 0x7a
                | 0x8a
                | 0x9a
                | 0xaa
                | 0xba
                | 0xca
                | 0xda
                | 0xea
                | 0xfa
        )
}

fn parse_supported_versions(data: &[u8], out: &mut [u16; MAX_VERSIONS]) -> Result<usize, ChError> {
    if data.is_empty() || usize::from(data[0]) + 1 != data.len() {
        return Err(ChError::MalformedExtension {
            ext: SUPPORTED_VERSIONS,
        });
    }
    let count = usize::from(data[0]);
    if count % 2 != 0 || count / 2 > MAX_VERSIONS {
        return Err(ChError::MalformedExtension {
            ext: SUPPORTED_VERSIONS,
        });
    }
    let mut at = 1usize;
    let mut n = 0usize;
    while at < data.len() {
        out[n] = u16_at(data, at)?;
        n += 1;
        at += 2;
    }
    Ok(n)
}

fn parse_server_names(
    data: &[u8],
    sni: &mut [u8; FQDN_MAX_LEN],
    sni_len: &mut usize,
    entries: &mut u8,
) -> Result<(), ChError> {
    if data.len() < 2 || usize::from(u16_at(data, 0)?) + 2 != data.len() {
        return Err(ChError::InvalidServerName {
            detail: "list-length mismatch",
        });
    }
    let mut at = 2usize;
    while at < data.len() {
        let name_type = u8_at(data, at)?;
        let len = usize::from(u16_at(data, at + 1)?);
        let start = at + 3;
        let end = start + len;
        if end > data.len() {
            return Err(ChError::InvalidServerName {
                detail: "name overflows list",
            });
        }
        if name_type != 0 {
            return Err(ChError::InvalidServerName {
                detail: "non-host_name name type",
            });
        }
        *entries = entries.checked_add(1).ok_or(ChError::InvalidServerName {
            detail: "too many host_name entries",
        })?;
        if *entries == 1 {
            let raw = &data[start..end];
            let normalized = FixedHostname::normalize(raw).ok_or(ChError::InvalidServerName {
                detail: "host_name is not a legal FQDN",
            })?;
            let bytes = normalized.as_bytes();
            sni[..bytes.len()].copy_from_slice(bytes);
            *sni_len = bytes.len();
        }
        at = end;
    }
    Ok(())
}

/// Retains the first ALPN protocol value bytes, raw and bounded by
/// `MAX_ALPN_VALUE`. Lenient by design: a malformed ALPN extension retains
/// nothing but never rejects the `ClientHello`, preserving the pre-retention
/// accept-everything behaviour for this extension.
fn parse_alpn_first_value(data: &[u8], out: &mut [u8; MAX_ALPN_VALUE], out_len: &mut usize) {
    if data.len() < 2 {
        return;
    }
    let list_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let list_end = 2 + list_len;
    if list_end > data.len() {
        return;
    }
    let list = &data[2..list_end];
    if list.is_empty() {
        return;
    }
    let first_len = usize::from(list[0]);
    let first_end = 1 + first_len;
    if first_end > list.len() {
        return;
    }
    let value = &list[1..first_end];
    let take = value.len().min(MAX_ALPN_VALUE);
    out[..take].copy_from_slice(&value[..take]);
    *out_len = take;
}

/// Retains the `signature_algorithms` (13) list values, raw and bounded by
/// `MAX_SIGALGS`. Lenient by design: a malformed (odd-length or
/// over-declared) list retains nothing. An overlong list is rejected as
/// `TooManySigAlgs` so the JA4 hash input is never silently lopped.
fn parse_sig_algs(data: &[u8], out: &mut [u16; MAX_SIGALGS]) -> Result<usize, ChError> {
    if data.len() < 2 {
        return Ok(0);
    }
    let list_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let list_end = 2 + list_len;
    if list_end > data.len() {
        return Ok(0);
    }
    let list = &data[2..list_end];
    if !list.len().is_multiple_of(2) {
        return Ok(0);
    }
    let count = list.len() / 2;
    if count > MAX_SIGALGS {
        return Err(ChError::TooManySigAlgs);
    }
    for (i, slot) in out[..count].iter_mut().enumerate() {
        *slot = u16::from_be_bytes([list[i * 2], list[i * 2 + 1]]);
    }
    Ok(count)
}

/// Validates the parsed `ClientHello` against the TLS 1.3-only golden path and
/// the approved CONNECT hostname. Unknown and GREASE extensions were already
/// skipped by length during parsing; ECH is rejected here as a profile rule.
///
/// On success mints the [`HelloAccepted`] capability: its field is private and
/// no constructor exists outside this module, so the returned witness can only
/// be produced by an actual validation (xz3f N7), never by caller discipline.
///
/// # Errors
///
/// Returns `ServerNameMismatch` when the SNI does not equal `approved`, and
/// the profile errors above when the ECH or identity rules fail.
pub fn validate(ch: &ClientHello, approved: &FixedHostname) -> Result<HelloAccepted, ChError> {
    if ch.has_ech {
        return Err(ChError::EchPresent);
    }
    if ch.sni_entries != 1 {
        return Err(ChError::InvalidServerName {
            detail: "requires exactly one host_name entry",
        });
    }
    if ch.server_name() != approved.as_bytes() {
        return Err(ChError::ServerNameMismatch);
    }
    Ok(HelloAccepted { _private: () })
}

#[cfg(test)]
mod tests;

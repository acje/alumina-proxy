use std::fmt;

use crate::config::{FQDN_MAX_LEN, FixedHostname};

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
const ALPN: u16 = 16;
const SIGNATURE_ALGORITHMS: u16 = 13;

const TLS13: u16 = 0x0304;
const TLS12: u16 = 0x0303;
const TLS10: u16 = 0x0301;

/// A parsed and framed `ClientHello`, before profile validation. All fields are
/// fixed-capacity so the gate allocates nothing on the serving path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    versions: [u16; MAX_VERSIONS],
    versions_len: usize,
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
    /// an overlong list is deterministically truncated to the first 64 entries
    /// and never rejects.
    #[must_use]
    pub fn sigalgs(&self) -> &[u16] {
        &self.sigalgs[..self.sigalgs_len]
    }

    /// The canonical `FoxIO` `JA4` client fingerprint for this `ClientHello`, using
    /// the highest non-GREASE offered version and SNI presence per the
    /// `alumina-xfbq8` amendment (docs/alumina-proxy.md:879-895).
    /// Allocation-free.
    #[must_use]
    pub fn ja4(&self) -> [u8; 36] {
        let version = self
            .offered_versions()
            .iter()
            .copied()
            .filter(|&v| !is_grease(v))
            .max()
            .unwrap_or(0);
        ja4_fingerprint(
            version,
            self.ciphers(),
            self.extensions(),
            self.alpn_first_value(),
            self.sigalgs(),
        )
    }
}

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
            | ChError::TooManyExtensions => HelloRejectReason::Profile,
        }
    }

    /// The zero-based index into a fixed per-discriminant counter array
    /// (offset from the CONNECT-head kinds by [`ConnectHeadReason::COUNT`] +
    /// the single `HostNotAllowlisted` kind).
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The number of finite hello-rejection discriminants.
    pub const COUNT: usize = 4;
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
                self.hello = Some(parse_body(&self.scratch[4..4 + msg_len])?);
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

fn parse_body(body: &[u8]) -> Result<ClientHello, ChError> {
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
            ENCRYPTED_CLIENT_HELLO => {
                has_ech = true;
            }
            ALPN => {
                parse_alpn_first_value(ext_data, &mut alpn, &mut alpn_len);
            }
            SIGNATURE_ALGORITHMS => {
                sigalgs_len = parse_sig_algs(ext_data, &mut sigalgs);
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
/// `MAX_SIGALGS`. Lenient by design: an odd-length list retains nothing; an
/// overlong list is deterministically truncated to the first `MAX_SIGALGS`
/// entries. Neither rejects the `ClientHello`, mirroring the ALPN retention.
fn parse_sig_algs(data: &[u8], out: &mut [u16; MAX_SIGALGS]) -> usize {
    if data.len() < 2 {
        return 0;
    }
    let list_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let list_end = 2 + list_len;
    if list_end > data.len() {
        return 0;
    }
    let list = &data[2..list_end];
    if !list.len().is_multiple_of(2) {
        return 0;
    }
    let count = list.len() / 2;
    let take = count.min(MAX_SIGALGS);
    for (i, slot) in out[..take].iter_mut().enumerate() {
        *slot = u16::from_be_bytes([list[i * 2], list[i * 2 + 1]]);
    }
    take
}

/// Computes the canonical `FoxIO` `JA4` client fingerprint as the fixed 36-byte
/// ASCII string `t{ver}{sni}{cc:02}{ec:02}{alpn}_{chash}_{ehash}` per the
/// `alumina-xfbq8` amendment (docs/alumina-proxy.md:879-895). Pure and
/// allocation-free: the SHA-256 inputs are fed incrementally through a
/// stack-based `ring::digest::Context`, and the sorted cipher/extension lists
/// are materialized in fixed-capacity stack buffers.
///
/// `version` is the highest non-GREASE offered version; `ciphers` and
/// `extensions` are the retained wire-order lists; `alpn` is the raw first
/// ALPN value; `sigalgs` the retained `signature_algorithms` values in wire
/// order. SNI presence (`d`/`i`) is derived from `extensions` containing
/// extension `0x0000`.
#[must_use]
pub fn ja4_fingerprint(
    version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    alpn: &[u8],
    sigalgs: &[u16],
) -> [u8; 36] {
    let ver = version_token(version);
    let sni = if extensions.contains(&SERVER_NAME) {
        b'd'
    } else {
        b'i'
    };
    let cc = count_token(non_grease_count(ciphers));
    let ec = count_token(non_grease_count(extensions));
    let alpn = alpn_token(alpn);
    let chash = cipher_hash12(ciphers);
    let ehash = ehash12(extensions, sigalgs);

    let mut out = [0u8; 36];
    out[0] = b't';
    out[1..3].copy_from_slice(&ver);
    out[3] = sni;
    out[4..6].copy_from_slice(&cc);
    out[6..8].copy_from_slice(&ec);
    out[8..10].copy_from_slice(&alpn);
    out[10] = b'_';
    out[11..23].copy_from_slice(&chash);
    out[23] = b'_';
    out[24..36].copy_from_slice(&ehash);
    out
}

const fn version_token(version: u16) -> [u8; 2] {
    match version {
        TLS13 => *b"13",
        TLS12 => *b"12",
        0x0302 => *b"11",
        TLS10 => *b"10",
        _ => *b"00",
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "count capped at 99 fits u8"
)]
const fn count_token(count: usize) -> [u8; 2] {
    let c = if count > 99 { 99 } else { count } as u8;
    [b'0' + c / 10, b'0' + c % 10]
}

const fn is_alnum(b: u8) -> bool {
    b.is_ascii_digit() || b.is_ascii_lowercase() || b.is_ascii_uppercase()
}

const fn hex_nibble(v: u8) -> u8 {
    let n = v & 0x0f;
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

const fn alpn_token(alpn: &[u8]) -> [u8; 2] {
    if alpn.is_empty() {
        return *b"00";
    }
    if alpn.len() == 1 {
        let c = alpn[0];
        if is_alnum(c) {
            return [c, c];
        }
        return [hex_nibble(c >> 4), hex_nibble(c)];
    }
    let first = alpn[0];
    let last = alpn[alpn.len() - 1];
    if is_alnum(first) && is_alnum(last) {
        [first, last]
    } else {
        [hex_nibble(first >> 4), hex_nibble(last)]
    }
}

fn non_grease_count(values: &[u16]) -> usize {
    values.iter().filter(|&&v| !is_grease(v)).count()
}

#[expect(clippy::cast_possible_truncation, reason = "nibble extraction fits u8")]
fn feed_u16_hex(ctx: &mut ring::digest::Context, value: u16) {
    let mut buf = [0u8; 4];
    for (i, slot) in buf.iter_mut().enumerate() {
        let shift = 12 - 4 * i;
        *slot = hex_nibble((value >> shift) as u8);
    }
    ctx.update(&buf);
}

fn hash12_finish(ctx: ring::digest::Context) -> [u8; 12] {
    let digest = ctx.finish();
    let bytes = digest.as_ref();
    let mut out = [0u8; 12];
    for (i, slot) in out.iter_mut().enumerate() {
        let byte = bytes[i / 2];
        let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
        *slot = hex_nibble(nibble);
    }
    out
}

fn cipher_hash12(ciphers: &[u16]) -> [u8; 12] {
    let mut sorted = [0u16; MAX_CIPHERS];
    let mut n = 0usize;
    for &c in ciphers {
        if !is_grease(c) {
            sorted[n] = c;
            n += 1;
        }
    }
    if n == 0 {
        return [b'0'; 12];
    }
    sorted[..n].sort_unstable();
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut first = true;
    for &c in &sorted[..n] {
        if !first {
            ctx.update(b",");
        }
        first = false;
        feed_u16_hex(&mut ctx, c);
    }
    hash12_finish(ctx)
}

fn ehash12(extensions: &[u16], sigalgs: &[u16]) -> [u8; 12] {
    let mut sorted = [0u16; MAX_EXTENSIONS];
    let mut n = 0usize;
    for &e in extensions {
        if !is_grease(e) && e != SERVER_NAME && e != ALPN {
            sorted[n] = e;
            n += 1;
        }
    }
    if n == 0 {
        return [b'0'; 12];
    }
    sorted[..n].sort_unstable();
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut first = true;
    for &e in &sorted[..n] {
        if !first {
            ctx.update(b",");
        }
        first = false;
        feed_u16_hex(&mut ctx, e);
    }
    if sigalgs.iter().any(|&s| !is_grease(s)) {
        ctx.update(b"_");
    }
    first = true;
    for &s in sigalgs {
        if is_grease(s) {
            continue;
        }
        if !first {
            ctx.update(b",");
        }
        first = false;
        feed_u16_hex(&mut ctx, s);
    }
    hash12_finish(ctx)
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
mod tests {
    use super::*;

    fn hello_msg(legacy: u16, versions: &[u16], snis: &[&str], ech: bool) -> Vec<u8> {
        hello_msg_comp(legacy, versions, snis, ech, 0)
    }

    fn hello_msg_comp(
        legacy: u16,
        versions: &[u16],
        snis: &[&str],
        ech: bool,
        comp: u8,
    ) -> Vec<u8> {
        let mut versions_data =
            vec![u8::try_from(versions.len() * 2).expect("versions data length fits u8")];
        for v in versions {
            versions_data.extend_from_slice(&v.to_be_bytes());
        }
        let mut snis_data = Vec::new();
        let mut names_data = Vec::new();
        for name in snis {
            names_data.push(0u8);
            names_data.extend_from_slice(
                &u16::try_from(name.len())
                    .expect("sni name fits u16 wire length")
                    .to_be_bytes(),
            );
            names_data.extend_from_slice(name.as_bytes());
        }
        snis_data.extend_from_slice(
            &u16::try_from(names_data.len())
                .expect("sni names block fits u16")
                .to_be_bytes(),
        );
        snis_data.extend_from_slice(&names_data);

        let mut exts = Vec::new();
        exts.extend_from_slice(&SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(
            &u16::try_from(versions_data.len())
                .expect("versions data fits u16")
                .to_be_bytes(),
        );
        exts.extend_from_slice(&versions_data);
        exts.extend_from_slice(&SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(
            &u16::try_from(snis_data.len())
                .expect("sni data fits u16")
                .to_be_bytes(),
        );
        exts.extend_from_slice(&snis_data);
        if ech {
            exts.extend_from_slice(&ENCRYPTED_CLIENT_HELLO.to_be_bytes());
            exts.extend_from_slice(&0u16.to_be_bytes());
        }

        let mut body = Vec::new();
        body.extend_from_slice(&legacy.to_be_bytes());
        body.extend_from_slice(&[0u8; RANDOM_LEN]);
        body.push(0);
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
        body.push(1);
        body.push(comp);
        body.extend_from_slice(
            &u16::try_from(exts.len())
                .expect("extensions data fits u16")
                .to_be_bytes(),
        );
        body.extend_from_slice(&exts);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let hl = u32::try_from(body.len()).expect("client hello body fits u32");
        handshake.extend_from_slice(&hl.to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![CONTENT_HANDSHAKE];
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(
            &u16::try_from(handshake.len())
                .expect("handshake fits u16 wire length")
                .to_be_bytes(),
        );
        record.extend_from_slice(&handshake);
        record
    }

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![CONTENT_HANDSHAKE];
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(
            &u16::try_from(payload.len())
                .expect("record payload fits u16 wire length")
                .to_be_bytes(),
        );
        record.extend_from_slice(payload);
        record
    }

    fn parse_one(bytes: &[u8]) -> Result<ClientHello, ChError> {
        let mut inspector = ChInspector::new();
        match inspector.feed(bytes)? {
            Inspect::Complete { .. } => Ok(inspector.hello().expect("complete has hello").clone()),
            Inspect::NeedMore => panic!("test message must complete within a single feed"),
        }
    }

    fn approved(name: &str) -> FixedHostname {
        FixedHostname::normalize(name.as_bytes()).expect("valid approved name")
    }

    fn server_name_ext(names: &[(u8, &[u8])]) -> Vec<u8> {
        let mut names_data = Vec::new();
        for (ty, name) in names {
            names_data.push(*ty);
            names_data.extend_from_slice(
                &u16::try_from(name.len())
                    .expect("sni name fits u16 wire length")
                    .to_be_bytes(),
            );
            names_data.extend_from_slice(name);
        }
        let mut ext = Vec::new();
        ext.extend_from_slice(
            &u16::try_from(names_data.len())
                .expect("sni names block fits u16")
                .to_be_bytes(),
        );
        ext.extend_from_slice(&names_data);
        ext
    }

    fn hello_with_extensions(exts: &[(u16, &[u8])]) -> Vec<u8> {
        hello_with_ciphers_and_extensions(&[0x002f], exts)
    }

    fn hello_with_ciphers_and_extensions(ciphers: &[u16], exts: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&TLS12.to_be_bytes());
        body.extend_from_slice(&[0u8; RANDOM_LEN]);
        body.push(0);
        body.extend_from_slice(
            &u16::try_from(ciphers.len() * 2)
                .expect("cipher list fits u16")
                .to_be_bytes(),
        );
        for cipher in ciphers {
            body.extend_from_slice(&cipher.to_be_bytes());
        }
        body.push(1);
        body.push(0);
        let mut blob = Vec::new();
        for (ty, data) in exts {
            blob.extend_from_slice(&ty.to_be_bytes());
            blob.extend_from_slice(
                &u16::try_from(data.len())
                    .expect("extension data fits u16")
                    .to_be_bytes(),
            );
            blob.extend_from_slice(data);
        }
        body.extend_from_slice(
            &u16::try_from(blob.len())
                .expect("extensions blob fits u16")
                .to_be_bytes(),
        );
        body.extend_from_slice(&blob);
        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let hl = u32::try_from(body.len()).expect("client hello body fits u32");
        handshake.extend_from_slice(&hl.to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        record(&handshake)
    }

    fn alpn_ext(values: &[&[u8]]) -> Vec<u8> {
        let mut names = Vec::new();
        for value in values {
            names.push(u8::try_from(value.len()).expect("alpn value fits u8"));
            names.extend_from_slice(value);
        }
        let mut ext = Vec::new();
        ext.extend_from_slice(
            &u16::try_from(names.len())
                .expect("alpn names block fits u16")
                .to_be_bytes(),
        );
        ext.extend_from_slice(&names);
        ext
    }

    #[test]
    fn accepts_tls13_with_single_sni() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        let ch = parse_one(&msg).expect("parse");
        let v = validate(&ch, &approved("sub.example.org"));
        assert!(v.is_ok(), "valid TLS1.3 ClientHello: {v:?}");
        assert_eq!(ch.offered_versions(), &[TLS13]);
        assert_eq!(ch.server_name(), b"sub.example.org");
        assert_eq!(ch.sni_entries(), 1);
        assert!(!ch.has_ech());
    }

    #[test]
    fn fragmented_records_are_boundary_independent() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        let mut inspector = ChInspector::new();
        for chunk in msg.chunks(4) {
            match inspector.feed(chunk).expect("feed") {
                Inspect::NeedMore => {}
                Inspect::Complete { .. } => {
                    let hello = inspector.hello().expect("complete has hello");
                    validate(hello, &approved("sub.example.org")).expect("valid");
                    return;
                }
            }
        }
        panic!("never completed");
    }

    #[test]
    fn handshake_split_across_records_completes() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        let mut split = record(&msg[5..5 + 12]);
        split.extend_from_slice(&record(&msg[5 + 12..]));
        let mut inspector = ChInspector::new();
        match inspector.feed(&split).expect("feed") {
            Inspect::Complete { consumed } => {
                let hello = inspector.hello().expect("complete has hello");
                validate(hello, &approved("sub.example.org")).expect("valid");
                assert_eq!(consumed, split.len(), "consumed ends at the hello");
            }
            Inspect::NeedMore => panic!("multi-record handshake must complete"),
        }
    }

    #[test]
    fn rejects_tls12_only_offer() {
        let msg = hello_msg(TLS12, &[TLS12], &["sub.example.org"], false);
        assert_eq!(
            parse_one(&msg),
            Err(ChError::InvalidVersionOffer { version: TLS12 })
        );
    }

    #[test]
    fn rejects_mixed_offer_with_extra_non_grease() {
        let msg = hello_msg(TLS12, &[TLS13, TLS12], &["sub.example.org"], false);
        assert_eq!(
            parse_one(&msg),
            Err(ChError::InvalidVersionOffer { version: TLS12 })
        );
    }

    #[test]
    fn allows_grease_versions_alongside_tls13() {
        let msg = hello_msg(TLS12, &[0x0a0a, TLS13, 0x1a1a], &["sub.example.org"], false);
        parse_one(&msg).expect("grease allowed");
    }

    #[test]
    fn rejects_grease_only_versions() {
        let msg = hello_msg(TLS12, &[0x0a0a], &["sub.example.org"], false);
        assert_eq!(
            parse_one(&msg),
            Err(ChError::InvalidVersionOffer { version: 0 })
        );
    }

    #[test]
    fn rejects_missing_supported_versions() {
        let no_ext = [0u8, 0u8];
        let mut body = Vec::new();
        body.extend_from_slice(&TLS12.to_be_bytes());
        body.extend_from_slice(&[0u8; RANDOM_LEN]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&no_ext);
        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let hl = u32::try_from(body.len()).expect("client hello body fits u32");
        handshake.extend_from_slice(&hl.to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        let record = record(&handshake);
        assert_eq!(parse_one(&record), Err(ChError::MissingSupportedVersions));
    }

    #[test]
    fn rejects_non_null_compression() {
        let msg = hello_msg_comp(TLS12, &[TLS13], &["sub.example.org"], false, 1);
        assert_eq!(parse_one(&msg), Err(ChError::NonNullCompression));
    }

    #[test]
    fn rejects_multiple_compression_methods() {
        let msg = hello_msg_comp(TLS12, &[TLS13], &["sub.example.org"], false, 0);
        let mut multi = vec![HANDSHAKE_CLIENT_HELLO];
        let handshake = &msg[5..];
        let body = &handshake[4..];
        let hl = u32::try_from(body.len()).expect("client hello body fits u32");
        multi.extend_from_slice(&hl.to_be_bytes()[1..]);
        multi.extend_from_slice(&body[..41]);
        multi.push(2);
        multi.push(0);
        multi.push(1);
        multi.extend_from_slice(&body[44..]);
        let record = record(&multi);
        assert_eq!(parse_one(&record), Err(ChError::NonNullCompression));
    }

    #[test]
    fn trailing_bytes_after_extensions_rejected() {
        let mut body = Vec::new();
        body.extend_from_slice(&TLS12.to_be_bytes());
        body.extend_from_slice(&[0u8; RANDOM_LEN]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1);
        body.push(0);
        let sv = [0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
        body.extend_from_slice(
            &u16::try_from(sv.len())
                .expect("supported versions data fits u16")
                .to_be_bytes(),
        );
        body.extend_from_slice(&sv);
        body.extend_from_slice(&[0xab; 5]);
        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let hl = u32::try_from(body.len()).expect("client hello body fits u32");
        handshake.extend_from_slice(&hl.to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        let record = record(&handshake);
        assert!(matches!(
            parse_one(&record),
            Err(ChError::MalformedBody { .. })
        ));
    }

    #[test]
    fn rejects_ech() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], true);
        let ch = parse_one(&msg).expect("parse");
        assert_eq!(
            validate(&ch, &approved("sub.example.org")),
            Err(ChError::EchPresent)
        );
    }

    #[test]
    fn rejects_mismatched_sni() {
        let msg = hello_msg(TLS12, &[TLS13], &["other.example.net"], false);
        let ch = parse_one(&msg).expect("parse");
        assert_eq!(
            validate(&ch, &approved("sub.example.org")),
            Err(ChError::ServerNameMismatch)
        );
    }

    #[test]
    fn trailing_dot_sni_matches_approved() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org."], false);
        let ch = parse_one(&msg).expect("parse");
        assert_eq!(ch.server_name(), b"sub.example.org");
        assert!(validate(&ch, &approved("sub.example.org")).is_ok());
    }

    #[test]
    fn uppercase_sni_matches_approved() {
        let msg = hello_msg(TLS12, &[TLS13], &["SUB.Example.ORG"], false);
        let ch = parse_one(&msg).expect("parse");
        assert_eq!(ch.server_name(), b"sub.example.org");
        assert!(validate(&ch, &approved("sub.example.org")).is_ok());
    }

    #[test]
    fn rejects_two_sni_entries() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org", "other.test"], false);
        let ch = parse_one(&msg).expect("parse");
        assert_eq!(
            validate(&ch, &approved("sub.example.org")),
            Err(ChError::InvalidServerName {
                detail: "requires exactly one host_name entry",
            })
        );
    }

    #[test]
    fn rejects_duplicate_extension() {
        let mut body = Vec::new();
        body.extend_from_slice(&TLS12.to_be_bytes());
        body.extend_from_slice(&[0u8; RANDOM_LEN]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1);
        body.push(0);
        let mut exts = Vec::new();
        for _ in 0..2 {
            exts.extend_from_slice(&0xfe00u16.to_be_bytes());
            exts.extend_from_slice(&0u16.to_be_bytes());
        }
        body.extend_from_slice(
            &u16::try_from(exts.len())
                .expect("extensions data fits u16")
                .to_be_bytes(),
        );
        body.extend_from_slice(&exts);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let hl = u32::try_from(body.len()).expect("client hello body fits u32");
        handshake.extend_from_slice(&hl.to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        let record = record(&handshake);
        assert_eq!(
            parse_one(&record),
            Err(ChError::DuplicateExtension { ext: 0xfe00 })
        );
    }

    #[test]
    fn rejects_ssl_framing_first_byte() {
        let mut msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        msg[0] = 0x80;
        assert_eq!(parse_one(&msg), Err(ChError::Sslv2Framing));
    }

    #[test]
    fn rejects_ssl_framing_feed_time() {
        let mut inspector = ChInspector::new();
        assert_eq!(inspector.feed(&[0x80]), Err(ChError::Sslv2Framing));
    }

    #[test]
    fn rejects_non_handshake_at_feed_time() {
        let mut inspector = ChInspector::new();
        let mut header = vec![23u8, 0x03, 0x01, 0x00, 0x00];
        header.extend_from_slice(&[0xab; 4]);
        assert_eq!(
            inspector.feed(&header),
            Err(ChError::NotHandshake { content_type: 23 })
        );
    }

    #[test]
    fn short_record_does_not_panic() {
        let mut inspector = ChInspector::new();
        let result = inspector.feed(&[22, 3, 1, 0, 0]);
        assert_eq!(result, Err(ChError::ZeroLengthRecord));
    }

    #[test]
    fn short_two_byte_payload_does_not_panic() {
        let mut inspector = ChInspector::new();
        let result = inspector.feed(&[22, 3, 1, 0, 2, 1, 0]);
        assert_eq!(result, Err(ChError::TruncatedHandshake));
    }

    #[test]
    fn rejects_record_payload_over_limit() {
        let big = vec![0xabu8; RECORD_PAYLOAD_LIMIT + 1];
        let mut record = vec![CONTENT_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(
            &u16::try_from(big.len())
                .expect("oversized payload fits u16")
                .to_be_bytes(),
        );
        record.extend_from_slice(&big);
        assert_eq!(
            parse_one(&record),
            Err(ChError::RecordTooLarge {
                got: RECORD_PAYLOAD_LIMIT + 1
            })
        );
    }

    #[test]
    fn rejects_handshake_length_claim_over_bound() {
        let claimed = 0x0000_ffff_u32;
        let mut payload = vec![HANDSHAKE_CLIENT_HELLO];
        payload.extend_from_slice(&claimed.to_be_bytes()[1..]);
        payload.extend_from_slice(&[0xabu8; 28]);
        let wire = record(&payload);
        assert_eq!(
            parse_one(&wire),
            Err(ChError::HandshakeTooLarge {
                got: 4 + claimed as usize,
            }),
            "a ClientHello whose 3-byte handshake length claims more than 16 KiB must be rejected"
        );
    }

    #[test]
    fn handshake_claim_exactly_at_bound_is_not_length_rejected() {
        let claimed =
            u32::try_from(MAX_HANDSHAKE_LEN - 4).expect("16 KiB handshake bound fits u32");
        let mut payload = vec![HANDSHAKE_CLIENT_HELLO];
        payload.extend_from_slice(&claimed.to_be_bytes()[1..]);
        payload.extend_from_slice(&[0xabu8; 28]);
        let mut inspector = ChInspector::new();
        assert_eq!(
            inspector.feed(&record(&payload)),
            Ok(Inspect::NeedMore),
            "a handshake claiming exactly the 16 KiB cap is incomplete, not length-rejected"
        );
    }

    #[test]
    fn rejects_zero_length_handshake_record_between_fragments() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        let mut split = record(&msg[5..5 + 12]);
        split.extend_from_slice(&record(&[]));
        split.extend_from_slice(&record(&msg[5 + 12..]));
        assert_eq!(parse_one(&split), Err(ChError::ZeroLengthRecord));
    }

    #[test]
    fn exact_fill_64k_incomplete_stream_does_not_panic() {
        let mut wire = Vec::with_capacity(MAX_CLIENT_HELLO);
        let mut first = vec![HANDSHAKE_CLIENT_HELLO, 0x00, 0xff, 0xfc];
        first.extend_from_slice(&[0u8; 16380]);
        for payload in [first, vec![0u8; 16384], vec![0u8; 16384], vec![0u8; 16364]] {
            wire.push(CONTENT_HANDSHAKE);
            wire.extend_from_slice(&0x0301u16.to_be_bytes());
            wire.extend_from_slice(
                &u16::try_from(payload.len())
                    .expect("record payload fits u16 wire length")
                    .to_be_bytes(),
            );
            wire.extend_from_slice(&payload);
        }
        assert_eq!(
            wire.len(),
            MAX_CLIENT_HELLO,
            "exactly fills the inspection budget"
        );
        let mut inspector = ChInspector::new();
        let result = inspector.feed(&wire);
        assert_eq!(
            result,
            Err(ChError::HandshakeTooLarge { got: 65536 }),
            "full buffer without a complete hello must not panic"
        );
    }

    #[test]
    fn non_handshake_pre_clienthello_rejected() {
        let mut msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        msg[0] = 23;
        assert_eq!(
            parse_one(&msg),
            Err(ChError::NotHandshake { content_type: 23 })
        );
    }

    const SV: &[u8] = &[0x02, 0x03, 0x04];

    #[test]
    fn non_host_name_sni_rejected() {
        let wire = hello_with_extensions(&[
            (SUPPORTED_VERSIONS, SV),
            (SERVER_NAME, &server_name_ext(&[(1, b"unrecognized-type")])),
        ]);
        assert_eq!(
            parse_one(&wire),
            Err(ChError::InvalidServerName {
                detail: "non-host_name name type",
            }),
            "a server_name entry whose NameType is not host_name (0) must fail closed"
        );
    }

    #[test]
    fn host_name_then_non_host_name_entry_rejected() {
        let wire = hello_with_extensions(&[
            (SUPPORTED_VERSIONS, SV),
            (
                SERVER_NAME,
                &server_name_ext(&[(0, b"sub.example.org"), (1, b"other")]),
            ),
        ]);
        assert_eq!(
            parse_one(&wire),
            Err(ChError::InvalidServerName {
                detail: "non-host_name name type",
            }),
            "a non-host_name entry must not be silently ignored, even alongside a valid host_name"
        );
    }

    #[test]
    fn absent_sni_is_missing_identity() {
        let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV)]);
        let ch = parse_one(&wire).expect("an absent-SNI hello parses; validation denies it");
        assert_eq!(ch.sni_entries(), 0);
        assert_eq!(
            validate(&ch, &approved("sub.example.org")),
            Err(ChError::InvalidServerName {
                detail: "requires exactly one host_name entry",
            })
        );
    }

    #[test]
    fn fragmented_short_first_record_is_rejected() {
        let mut inspector = ChInspector::new();
        assert_eq!(inspector.feed(&[22, 3, 1, 0, 2]), Ok(Inspect::NeedMore));
        assert_eq!(
            inspector.feed(&[1, 0]),
            Err(ChError::TruncatedHandshake),
            "a <4-byte first-record payload must fail closed regardless of fragmentation"
        );
    }

    #[test]
    fn trailing_dot_other_domain_mismatch_still_rejected() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.com."], false);
        let ch = parse_one(&msg).expect("parse");
        assert_eq!(ch.server_name(), b"sub.example.com");
        assert_eq!(
            validate(&ch, &approved("sub.example.org")),
            Err(ChError::ServerNameMismatch),
            "normalizing a trailing dot must not mask a genuine two-domain mismatch"
        );
    }

    #[test]
    fn accepts_exactly_32_offered_versions() {
        let versions = [TLS13; 32];
        let msg = hello_msg(TLS12, &versions, &["sub.example.org"], false);
        let ch = parse_one(&msg).expect("32 offered versions must parse");
        assert_eq!(ch.offered_versions().len(), 32);
    }

    #[test]
    fn rejects_more_than_32_offered_versions() {
        let versions = [TLS13; 33];
        let msg = hello_msg(TLS12, &versions, &["sub.example.org"], false);
        assert_eq!(
            parse_one(&msg),
            Err(ChError::MalformedExtension {
                ext: SUPPORTED_VERSIONS,
            })
        );
    }

    #[test]
    fn accepts_exactly_64_extensions() {
        let sni = server_name_ext(&[(0, b"sub.example.org")]);
        let mut exts = vec![(SUPPORTED_VERSIONS, SV), (SERVER_NAME, &sni)];
        for i in 0..62u16 {
            exts.push((0x100 + i, &b""[..]));
        }
        let ch =
            parse_one(&hello_with_extensions(&exts)).expect("64 distinct extensions must parse");
        assert_eq!(ch.sni_entries(), 1);
        assert_eq!(ch.server_name(), b"sub.example.org");
    }

    #[test]
    fn rejects_more_than_64_extensions() {
        let sni = server_name_ext(&[(0, b"sub.example.org")]);
        let mut exts = vec![(SUPPORTED_VERSIONS, SV), (SERVER_NAME, &sni)];
        for i in 0..63u16 {
            exts.push((0x100 + i, &b""[..]));
        }
        assert_eq!(
            parse_one(&hello_with_extensions(&exts)),
            Err(ChError::TooManyExtensions)
        );
    }

    #[test]
    fn retains_cipher_list_including_scsv() {
        let ciphers = [0x1301u16, 0x1302, 0x00ff, 0x002f];
        let wire = hello_with_ciphers_and_extensions(&ciphers, &[(SUPPORTED_VERSIONS, SV)]);
        let ch = parse_one(&wire).expect("parse");
        assert_eq!(ch.ciphers(), &ciphers);
    }

    #[test]
    fn retains_extension_type_list_including_alpn_and_sigalgs() {
        let alpn = alpn_ext(&[b"h2"]);
        let sigalgs = [0x00u8, 0x04, 0x04, 0x01, 0x04, 0x03];
        let wire = hello_with_extensions(&[
            (SUPPORTED_VERSIONS, SV),
            (ALPN, &alpn),
            (SIGNATURE_ALGORITHMS, &sigalgs),
        ]);
        let ch = parse_one(&wire).expect("parse");
        assert_eq!(
            ch.extensions(),
            &[SUPPORTED_VERSIONS, ALPN, SIGNATURE_ALGORITHMS]
        );
    }

    #[test]
    fn retains_alpn_first_value_bytes() {
        let alpn = alpn_ext(&[b"h2"]);
        let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (ALPN, &alpn)]);
        let ch = parse_one(&wire).expect("parse");
        assert_eq!(ch.alpn_first_value(), b"h2");
    }

    #[test]
    fn retains_only_first_alpn_value() {
        let alpn = alpn_ext(&[b"h2", b"http/1.1"]);
        let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (ALPN, &alpn)]);
        let ch = parse_one(&wire).expect("parse");
        assert_eq!(ch.alpn_first_value(), b"h2");
    }

    #[test]
    fn malformed_alpn_is_skipped_not_rejected() {
        let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (ALPN, &[0xff])]);
        let ch = parse_one(&wire).expect("a malformed ALPN extension must not reject the hello");
        assert_eq!(ch.alpn_first_value(), b"");
    }

    fn sigalgs_ext(values: &[u16]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(
            &u16::try_from(values.len() * 2)
                .expect("sigalgs list fits u16")
                .to_be_bytes(),
        );
        for value in values {
            data.extend_from_slice(&value.to_be_bytes());
        }
        data
    }

    #[test]
    fn ja4_v1_published_vector_byte_for_byte() {
        let ciphers = [
            0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
            0xc02f, 0xc030, 0xcca8, 0xcca9,
        ];
        let ehash_exts = [
            0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d,
            0x0033, 0x4469, 0xff01,
        ];
        let sigalgs = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let alpn = alpn_ext(&[b"h2"]);
        let sni = server_name_ext(&[(0, b"sub.example.org")]);
        let sigalgs_data = sigalgs_ext(&sigalgs);
        let mut exts: Vec<(u16, &[u8])> = Vec::new();
        for ext in ehash_exts {
            let data: &[u8] = if ext == SUPPORTED_VERSIONS {
                SV
            } else if ext == SIGNATURE_ALGORITHMS {
                &sigalgs_data
            } else {
                &[]
            };
            exts.push((ext, data));
        }
        exts.push((SERVER_NAME, &sni));
        exts.push((ALPN, &alpn));
        let wire = hello_with_ciphers_and_extensions(&ciphers, &exts);
        let ch = parse_one(&wire).expect("parse");
        assert_eq!(ch.ja4(), *b"t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn ja4_v4_spec_consistent_vector_byte_for_byte() {
        let ciphers = [
            0xaaaa, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let sigalgs = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let alpn = alpn_ext(&[&[0xba, 0xad]]);
        let sni = server_name_ext(&[(0, b"sub.example.org")]);
        let sigalgs_data = sigalgs_ext(&sigalgs);
        let exts: Vec<(u16, &[u8])> = vec![
            (0x9a9a, &[]),
            (0xff01, &[]),
            (0x0033, &[]),
            (0x002d, &[]),
            (0x0005, &[]),
            (0x4469, &[]),
            (SIGNATURE_ALGORITHMS, &sigalgs_data),
            (ALPN, &alpn),
            (0x0023, &[]),
            (0x001b, &[]),
            (SUPPORTED_VERSIONS, SV),
            (SERVER_NAME, &sni),
            (0x0012, &[]),
            (0x000a, &[]),
            (0x0017, &[]),
            (0x000b, &[]),
            (0x6a6a, &[]),
            (0x0015, &[]),
        ];
        let wire = hello_with_ciphers_and_extensions(&ciphers, &exts);
        let ch = parse_one(&wire).expect("parse");
        assert_eq!(ch.ja4(), *b"t13d1516bd_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn ja4_grease_filtered_from_counts_and_hashes() {
        let ciphers = [
            0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
            0xc02f, 0xc030, 0xcca8, 0xcca9, 0x1a1a,
        ];
        let ehash_exts = [
            0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d,
            0x0033, 0x4469, 0xff01, 0x2a2a,
        ];
        let sigalgs = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let alpn = alpn_ext(&[b"h2"]);
        let sni = server_name_ext(&[(0, b"sub.example.org")]);
        let sigalgs_data = sigalgs_ext(&sigalgs);
        let mut exts: Vec<(u16, &[u8])> = Vec::new();
        for ext in ehash_exts {
            let data: &[u8] = if ext == SUPPORTED_VERSIONS {
                SV
            } else if ext == SIGNATURE_ALGORITHMS {
                &sigalgs_data
            } else {
                &[]
            };
            exts.push((ext, data));
        }
        exts.push((SERVER_NAME, &sni));
        exts.push((ALPN, &alpn));
        let wire = hello_with_ciphers_and_extensions(&ciphers, &exts);
        let ch = parse_one(&wire).expect("parse");
        assert_eq!(
            ch.ja4(),
            *b"t13d1516h2_8daaf6152771_e5627efa2ab1",
            "GREASE ciphers and extensions must be filtered from counts and hashes"
        );
    }

    #[test]
    fn ja4_version_tokens() {
        for (version, token) in [
            (0x0304u16, b"13"),
            (0x0303, b"12"),
            (0x0302, b"11"),
            (0x0301, b"10"),
            (0x0300, b"00"),
            (0x0400, b"00"),
        ] {
            let out = ja4_fingerprint(version, &[], &[], &[], &[]);
            assert_eq!(&out[1..3], token, "version token for {version:#06x}");
        }
    }

    #[test]
    fn ja4_alpn_tokens() {
        assert_eq!(alpn_token(&[]), *b"00");
        assert_eq!(alpn_token(b"h2"), *b"h2");
        assert_eq!(alpn_token(b"x"), *b"xx");
        assert_eq!(alpn_token(b"h"), *b"hh");
        assert_eq!(alpn_token(&[0xab]), *b"ab");
        assert_eq!(alpn_token(&[0x20]), *b"20");
        assert_eq!(alpn_token(&[0x20, 0x61]), *b"21");
        assert_eq!(alpn_token(&[0x30, 0xab, 0xcd, 0x31]), *b"01");
        assert_eq!(alpn_token(&[0xab, 0xcd]), *b"ad");
        assert_eq!(alpn_token(&[0xba, 0xad]), *b"bd");
    }

    #[test]
    fn ja4_v2_structural_intent_tls12_no_alpn() {
        let ciphers: Vec<u16> = (0..19u16).map(|i| 0x0100 + i).collect();
        let exts: Vec<u16> = std::iter::once(0x0000)
            .chain((0..7u16).map(|i| 0x1000 + i))
            .collect();
        let out = ja4_fingerprint(0x0303, &ciphers, &exts, &[], &[]);
        assert_eq!(
            out, *b"t12d190800_e5f6c4506bb0_04d33385c057",
            "empty sigalgs must omit the e-hash underscore (JA4.md: no sigalgs -> string ends without underscore)"
        );
    }

    #[test]
    fn ja4_v3_structural_intent_46_ciphers_with_scsv() {
        let mut ciphers: Vec<u16> = (0..46u16).map(|i| 0x0100 + i).collect();
        ciphers[0] = 0x00ff;
        let alpn = alpn_ext(&[b"h2"]);
        let sni = server_name_ext(&[(0, b"sub.example.org")]);
        let exts = [
            (SUPPORTED_VERSIONS, SV),
            (SERVER_NAME, &sni),
            (ALPN, &alpn),
            (0x0005, &b""[..]),
            (0x000a, &b""[..]),
        ];
        let wire = hello_with_ciphers_and_extensions(&ciphers, &exts);
        let ch = parse_one(&wire).expect("parse");
        assert_eq!(&ch.ja4()[..10], b"t13d4605h2");
        assert_eq!(ch.ja4().len(), 36);
    }

    /// Byte-for-byte V2 gate: S4 (latest.pcapng stream 3, SNI
    /// discovery.cem.cloud.us) wire lists from evidence bead alumina-2rkgn.
    /// `legacy_version` 0303, no 0x002b, no ALPN, no GREASE.
    #[test]
    fn ja4_v2_published_vector_byte_for_byte() {
        let ciphers = [
            0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014,
            0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x000a,
        ];
        let exts = [
            0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0023, 0x0017, 0xff01,
        ];
        let sigalgs = [
            0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601,
            0x0603,
        ];
        let out = ja4_fingerprint(0x0303, &ciphers, &exts, &[], &sigalgs);
        assert_eq!(out, *b"t12d190800_d83cc789557e_7af1ed941c26");
    }

    /// Byte-for-byte V3 gate: S5 (tls-alpn-h2.pcap stream 0, SNI
    /// www.cloudflare.com) wire lists from evidence bead alumina-2rkgn.
    /// `legacy_version` 0303, no 0x002b, ALPN first value "h2", no GREASE.
    #[test]
    fn ja4_v3_published_vector_byte_for_byte() {
        let ciphers = [
            0xc030, 0xc02c, 0xc028, 0xc024, 0xc014, 0xc00a, 0x009f, 0x006b, 0x0039, 0xcca9, 0xcca8,
            0xccaa, 0xff85, 0x00c4, 0x0088, 0x0081, 0x009d, 0x003d, 0x0035, 0x00c0, 0x0084, 0xc02f,
            0xc02b, 0xc027, 0xc023, 0xc013, 0xc009, 0x009e, 0x0067, 0x0033, 0x00be, 0x0045, 0x009c,
            0x003c, 0x002f, 0x00ba, 0x0041, 0xc011, 0xc007, 0x0005, 0x0004, 0xc012, 0xc008, 0x0016,
            0x000a, 0x00ff,
        ];
        let exts = [0x0000, 0x000b, 0x000a, 0x000d, 0x0010];
        let sigalgs = [
            0x0601, 0x0603, 0xefef, 0x0501, 0x0503, 0x0401, 0x0403, 0xeeee, 0xeded, 0x0301, 0x0303,
            0x0201, 0x0203,
        ];
        let out = ja4_fingerprint(0x0303, &ciphers, &exts, b"h2", &sigalgs);
        assert_eq!(out, *b"t12d4605h2_85626a9a5f7f_aaf95bb78ec9");
    }

    #[test]
    fn ja4_empty_lists_use_sentinel_hashes() {
        let out = ja4_fingerprint(0x0304, &[], &[], &[], &[]);
        assert_eq!(out, *b"t13i000000_000000000000_000000000000");
    }

    #[test]
    fn retains_sigalgs_values_in_wire_order() {
        let sigalgs = [0x0403u16, 0x0804, 0x0401];
        let data = sigalgs_ext(&sigalgs);
        let wire =
            hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (SIGNATURE_ALGORITHMS, &data)]);
        let ch = parse_one(&wire).expect("parse");
        assert_eq!(ch.sigalgs(), &sigalgs);
    }

    #[test]
    fn sigalgs_odd_length_retains_nothing() {
        let sigalgs = [0x00u8, 0x03, 0x04, 0x03, 0x04];
        let wire =
            hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (SIGNATURE_ALGORITHMS, &sigalgs)]);
        let ch = parse_one(&wire).expect("parse");
        assert!(ch.sigalgs().is_empty(), "sigalgs should be empty");
    }

    #[test]
    fn sigalgs_declared_len_exceeding_data_retains_nothing() {
        let sigalgs = [0x00u8, 0x64, 0x04, 0x03];
        let wire =
            hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (SIGNATURE_ALGORITHMS, &sigalgs)]);
        let ch = parse_one(&wire).expect("parse");
        assert!(ch.sigalgs().is_empty(), "sigalgs should be empty");
    }

    #[test]
    fn sigalgs_capped_at_max_sigalgs() {
        let values: Vec<u16> = (0..70u16).map(|i| 0x0400 + i).collect();
        let data = sigalgs_ext(&values);
        let wire =
            hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (SIGNATURE_ALGORITHMS, &data)]);
        let ch = parse_one(&wire).expect("parse");
        assert_eq!(ch.sigalgs().len(), MAX_SIGALGS);
        assert_eq!(ch.sigalgs(), &values[..MAX_SIGALGS]);
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn ja4_path_is_allocation_free() {
        use crate::alloc::{self, Phase};
        let ciphers = [
            0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
            0xc02f, 0xc030, 0xcca8, 0xcca9,
        ];
        let ehash_exts = [
            0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d,
            0x0033, 0x4469, 0xff01,
        ];
        let sigalgs = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let alpn = alpn_ext(&[b"h2"]);
        let sni = server_name_ext(&[(0, b"sub.example.org")]);
        let sigalgs_data = sigalgs_ext(&sigalgs);
        let mut exts: Vec<(u16, &[u8])> = Vec::new();
        for ext in ehash_exts {
            let data: &[u8] = if ext == SUPPORTED_VERSIONS {
                SV
            } else if ext == SIGNATURE_ALGORITHMS {
                &sigalgs_data
            } else {
                &[]
            };
            exts.push((ext, data));
        }
        exts.push((SERVER_NAME, &sni));
        exts.push((ALPN, &alpn));
        let wire = hello_with_ciphers_and_extensions(&ciphers, &exts);
        let ch = parse_one(&wire).expect("parse");
        let full_exts = [
            0x0005,
            0x000a,
            0x000b,
            0x000d,
            0x0012,
            0x0015,
            0x0017,
            0x001b,
            0x0023,
            0x002b,
            0x002d,
            0x0033,
            0x4469,
            0xff01,
            SERVER_NAME,
            ALPN,
        ];

        let (out, counts) = alloc::run_phase(Phase::Serving, || {
            let pure = ja4_fingerprint(0x0304, &ciphers, &full_exts, b"h2", &sigalgs);
            let method = ch.ja4();
            (pure, method)
        });
        assert_eq!(out.0, *b"t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(out.1, out.0);
        assert!(
            counts.all_zero(),
            "the JA4 computation path (pure fn + ClientHello::ja4) must be allocation-free: {counts:?}"
        );
    }
}

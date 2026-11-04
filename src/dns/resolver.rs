use std::fmt;
use std::net::IpAddr;

use crate::names::hostname::FixedHostname;

pub const RESOLVER_PORT: u16 = 53;

/// The `DoT` (DNS-over-TLS, RFC 7858) port an `IP#fqdn` (or `IP#fqdn#pin-sha256=`)
/// resolver entry dials. `DoT` is signalled by FQDN presence, so a bare `IP`
/// entry stays on [`RESOLVER_PORT`] with plain DNS.
pub const DOT_PORT: u16 = 853;

/// The suffix marker that turns an `IP#fqdn` resolver entry into a strict-pin
/// `DoT` entry (V5): the base64 SPKI SHA-256 pin follows the marker. The marker
/// is a sub-suffix of the `#fqdn` rest, so the single `#` boundary that splits
/// IP from the rest never reopens when a pin is present.
pub const PIN_SHA256_SUFFIX: &str = "#pin-sha256=";

pub const MAX_RESOLVERS: usize = 5;

/// The maximum byte length of a validated resolver FQDN (RFC 1035 logical
/// name, no trailing dot).
pub const FQDN_MAX_LEN: usize = crate::names::rules::FQDN_MAX_LEN;

/// A validated resolver FQDN (the `fqdn` in an `IP#fqdn` entry): lowercase
/// ASCII DNS-name syntax (labels 1..=63 `[a-z0-9-]`, no leading/trailing
/// hyphen), total length at most [`FQDN_MAX_LEN`], no wildcard `*`, no
/// IDN/non-ASCII bytes, no leading or trailing dot. Carried inline as a
/// [`FixedHostname`] payload so [`Nameserver`] and [`ResolverSet`] stay
/// `Copy` with no heap allocation (fixed profile): construction reuses the
/// shared payload type, and [`Fqdn::parse`] applies the strict resolver
/// gates before the payload is built, so every constructed value already
/// passed the boundary rules.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fqdn {
    payload: FixedHostname,
}

enum FqdnError {
    Invalid,
    Wildcard,
    Idn,
}

impl Fqdn {
    fn parse(value: &str) -> Result<Fqdn, FqdnError> {
        if value.bytes().any(|b| b == b'*') {
            return Err(FqdnError::Wildcard);
        }
        if value.bytes().any(|b| !b.is_ascii()) {
            return Err(FqdnError::Idn);
        }
        if value.is_empty() || value.len() > FQDN_MAX_LEN {
            return Err(FqdnError::Invalid);
        }
        if value.starts_with('.') || value.ends_with('.') {
            return Err(FqdnError::Invalid);
        }
        for label in value.split('.') {
            if crate::names::rules::classify_label(label.as_bytes()).is_err() {
                return Err(FqdnError::Invalid);
            }
        }
        if crate::names::rules::is_ip_literal_shape(value.as_bytes()) {
            return Err(FqdnError::Invalid);
        }
        let payload = FixedHostname::normalize(value.as_bytes()).ok_or(FqdnError::Invalid)?;
        Ok(Fqdn { payload })
    }

    /// The validated lowercase ASCII FQDN (no trailing dot).
    ///
    /// # Panics
    ///
    /// Never: the inline bytes were validated as ASCII at construction.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.payload.as_str()
    }
}

impl fmt::Debug for Fqdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fqdn({:?})", self.as_str())
    }
}

/// A validated SPKI SHA-256 pin from a `#pin-sha256=` resolver suffix: 32 raw
/// digest bytes carried inline so [`Nameserver`] stays `Copy` with no heap
/// allocation (fixed profile). Crypto-free: the per-handshake ring digest
/// comparison lives in the `DoT` verifier (`startup_dns`), not here — this type
/// only holds bytes already validated at the config boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SpiPin {
    bytes: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
enum PinError {
    Invalid,
}

impl SpiPin {
    fn parse(value: &str) -> Result<SpiPin, PinError> {
        decode_b64_32(value)
            .map(|bytes| SpiPin { bytes })
            .map_err(|()| PinError::Invalid)
    }

    /// The 32 raw SPKI SHA-256 digest bytes the `DoT` verifier compares against
    /// the presented certificate's subject public key info.
    #[must_use]
    pub const fn as_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}

impl fmt::Debug for SpiPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A pin is a cryptographic identity; never print its bytes.
        f.write_str("SpiPin([redacted])")
    }
}

/// Maps one base64 character to its six-bit value, accepting both the standard
/// (`+/`) and URL-safe (`-_`) alphabets. `None` for any other ASCII byte; the
/// caller already gated on the ASCII byte slice length, so non-ASCII cannot
/// reach here.
const fn b64_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Decodes a 32-byte SPKI SHA-256 pin from its text form: exactly 43 unpadded
/// base64 characters, or 43 data characters plus one `=` pad (44 total with
/// the standard alphabet). Always decodes to exactly 32 bytes; rejects wrong
/// lengths, characters outside either base64 alphabet, and non-zero leftover
/// (trailing) bits that a well-formed 32-byte encoding cannot carry.
fn decode_b64_32(input: &str) -> Result<[u8; 32], ()> {
    let s = input.as_bytes();
    if !(s.len() == 43 || (s.len() == 44 && s[43] == b'=')) {
        return Err(());
    }
    let mut out = [0u8; 32];
    let mut written = 0usize;
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;
    for &b in &s[..43] {
        let v = b64_value(b).ok_or(())?;
        acc = (acc << 6) | u32::from(v);
        acc_bits += 6;
        if acc_bits >= 8 {
            acc_bits -= 8;
            out[written] = u8::try_from((acc >> acc_bits) & 0xff).map_err(|_| ())?;
            written += 1;
            acc &= (1u32 << acc_bits) - 1;
        }
    }
    if written != 32 {
        return Err(());
    }
    if acc & ((1u32 << acc_bits) - 1) != 0 {
        return Err(());
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nameserver {
    addr: IpAddr,
    fqdn: Option<Fqdn>,
    pin: Option<SpiPin>,
}

impl Nameserver {
    #[must_use]
    pub const fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The per-entry dial port: [`DOT_PORT`] (853) for a `DoT` entry carrying an
    /// FQDN, [`RESOLVER_PORT`] (53) for a bare-IP entry. A pin is only parsed
    /// behind an FQDN, so the FQDN presence is both the `DoT` signal and the
    /// port signal; there is no silent plain-DNS fallback for a `DoT` entry.
    #[must_use]
    pub const fn port(&self) -> u16 {
        if self.fqdn.is_some() {
            DOT_PORT
        } else {
            RESOLVER_PORT
        }
    }

    /// The optional strict SPKI pin of an `IP#fqdn#pin-sha256=` entry: when
    /// present, the `DoT` handshake requires the server's subject public key
    /// info SHA-256 to equal [`SpiPin::as_bytes`]. A pinned entry never
    /// falls back to CA-chain validation or plain DNS.
    #[must_use]
    pub const fn pin(&self) -> Option<&SpiPin> {
        self.pin.as_ref()
    }

    /// The optional validated FQDN of an `IP#fqdn` entry: carried as the `SNI`/
    /// `SAN` identity target for the `DoT` handshake (`port 853`, V1).
    /// `None` for a bare-IP entry, which stays valid on plain DNS (`port 53`)
    /// with a startup warning.
    #[must_use]
    pub const fn fqdn(&self) -> Option<&Fqdn> {
        self.fqdn.as_ref()
    }

    /// Whether this resolver entry carries no `IP#fqdn` FQDN metadata.
    #[must_use]
    pub const fn is_ip_only(&self) -> bool {
        self.fqdn.is_none()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResolverError {
    InvalidAddress { value: String },
    NonUnicastAddress { value: String },
    ZonedAddress { value: String },
    InvalidFqdn { value: String },
    WildcardFqdn { value: String },
    IdnFqdn { value: String },
    InvalidPin { value: String },
}

impl fmt::Display for ResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolverError::InvalidAddress { value } => {
                write!(
                    f,
                    "resolver nameserver {value:?} is not a numeric IP address"
                )
            }
            ResolverError::NonUnicastAddress { value } => {
                write!(
                    f,
                    "resolver nameserver {value:?} is not unicast (multicast/broadcast/unspecified rejected)"
                )
            }
            ResolverError::ZonedAddress { value } => {
                write!(
                    f,
                    "resolver nameserver {value:?} carries a zone identifier (not allowed)"
                )
            }
            ResolverError::InvalidFqdn { value } => {
                write!(
                    f,
                    "resolver nameserver {value:?} FQDN part invalid: expected lowercase ASCII DNS-name syntax (labels 1-63 [a-z0-9-], total <= 253, no leading or trailing dot)"
                )
            }
            ResolverError::WildcardFqdn { value } => {
                write!(
                    f,
                    "resolver nameserver {value:?} FQDN part is a wildcard (not allowed)"
                )
            }
            ResolverError::IdnFqdn { value } => {
                write!(
                    f,
                    "resolver nameserver {value:?} FQDN part carries non-ASCII/IDN characters (use A-label form)"
                )
            }
            ResolverError::InvalidPin { value } => {
                write!(
                    f,
                    "resolver nameserver {value:?} #pin-sha256= pin invalid: expected 32 bytes as base64 (43-char unpadded base64url, or 43 data chars + one '=' padding)"
                )
            }
        }
    }
}

/// Validates one configured resolver entry: a numeric unicast IPv4 or IPv6
/// address (port fixed per entry, no zone identifier), optionally followed by
/// `#fqdn` — `IP#fqdn` — where the FQDN is validated as [`Fqdn`] and carried
/// as the `DoT` `SNI`/`SAN` target (port 853), and optionally further followed
/// by `#pin-sha256=<b64>` — `IP#fqdn#pin-sha256=...` — where the base64 suffix
/// is decoded to a 32-byte strict [`SpiPin`]. A bare `IP` entry (no `#fqdn`)
/// remains valid on plain DNS (port 53) and is flagged at startup (IP-only).
/// The `#` boundary splits IP from the rest exactly once; the pin marker is a
/// sub-suffix of that rest, so the two suffixes compose without reopening the
/// IP/rest boundary.
pub(crate) fn select(token: &str) -> Result<Nameserver, ResolverError> {
    let (ip_part, rest) = match token.split_once('#') {
        Some((ip, fqdn)) => (ip, Some(fqdn)),
        None => (token, None),
    };
    let addr = parse_ip(ip_part)?;
    let Some(rest) = rest else {
        return Ok(Nameserver {
            addr,
            fqdn: None,
            pin: None,
        });
    };
    let (dot_name, pin_b64) = rest
        .split_once(PIN_SHA256_SUFFIX)
        .map_or((rest, None), |(name, pin)| (name, Some(pin)));
    let fqdn = Some(Fqdn::parse(dot_name).map_err(|err| match err {
        FqdnError::Invalid => ResolverError::InvalidFqdn {
            value: token.to_owned(),
        },
        FqdnError::Wildcard => ResolverError::WildcardFqdn {
            value: token.to_owned(),
        },
        FqdnError::Idn => ResolverError::IdnFqdn {
            value: token.to_owned(),
        },
    })?);
    let pin = pin_b64
        .map(|text| {
            SpiPin::parse(text).map_err(|_| ResolverError::InvalidPin {
                value: token.to_owned(),
            })
        })
        .transpose()?;
    Ok(Nameserver { addr, fqdn, pin })
}

/// Validates the IP half of a resolver entry exactly as the pre-V37 surface
/// did: non-empty, no zone identifier, a numeric unicast IPv4/IPv6 address.
fn parse_ip(part: &str) -> Result<IpAddr, ResolverError> {
    if part.is_empty() {
        return Err(ResolverError::InvalidAddress {
            value: part.to_owned(),
        });
    }
    if part.contains(['%', '@']) {
        return Err(ResolverError::ZonedAddress {
            value: part.to_owned(),
        });
    }
    let addr: IpAddr = part.parse().map_err(|_| ResolverError::InvalidAddress {
        value: part.to_owned(),
    })?;
    if !is_unicast(addr) {
        return Err(ResolverError::NonUnicastAddress {
            value: part.to_owned(),
        });
    }
    Ok(addr)
}

const fn is_unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => !ip.is_multicast() && !ip.is_broadcast() && !ip.is_unspecified(),
        IpAddr::V6(ip) => !ip.is_multicast() && !ip.is_unspecified(),
    }
}

/// The validated resolver set from configuration: a fixed `MAX_RESOLVERS`
/// array holding the declared resolvers. Construction goes through
/// [`ResolverSet::from_slice`], which refuses empty and over-capacity inputs,
/// so index 0 (the primary) and `len() >= 1` are structural facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolverSet {
    entries: [Nameserver; MAX_RESOLVERS],
    len: usize,
}

impl ResolverSet {
    /// Builds a set from `entries` (1..=`MAX_RESOLVERS`); `None` when empty or
    /// over capacity. The sole construction route, guarding the non-empty
    /// invariant at the config boundary.
    pub(crate) fn from_slice(entries: &[Nameserver]) -> Option<ResolverSet> {
        let count = entries.len();
        if count == 0 || count > MAX_RESOLVERS {
            return None;
        }
        let mut arr = [entries[0]; MAX_RESOLVERS];
        arr[..count].copy_from_slice(entries);
        Some(ResolverSet {
            entries: arr,
            len: count,
        })
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// A set is never empty by construction: an empty slice is refused at
    /// [`ResolverSet::from_slice`]. `is_empty` therefore returns `false` and
    /// is present for the standard `len`/`is_empty` accessor pairing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The primary resolver (index 0). Infallible: a zero-count set is
    /// unrepresentable.
    #[must_use]
    pub const fn primary(&self) -> &Nameserver {
        &self.entries[0]
    }

    #[must_use]
    pub const fn get(&self, index: usize) -> Option<&Nameserver> {
        if index < self.len {
            Some(&self.entries[index])
        } else {
            None
        }
    }

    /// Iterates the declared resolvers in order (index 0 is the primary).
    pub fn iter(&self) -> std::slice::Iter<'_, Nameserver> {
        self.entries[..self.len].iter()
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod hostname_rules {
    use super::*;

    fn err(token: &str) -> String {
        select(token).expect_err(token).to_string()
    }

    #[test]
    fn hostname_rules_resolver_mixed_fault_class_order_and_text() {
        let wildcard =
            |t: &str| format!("resolver nameserver {t:?} FQDN part is a wildcard (not allowed)");
        let idn = |t: &str| {
            format!(
                "resolver nameserver {t:?} FQDN part carries non-ASCII/IDN characters (use A-label form)"
            )
        };
        let over_wild = format!("1.1.1.1#*.{}", "a".repeat(253));
        let idn_over = format!("1.1.1.1#{}", "ü".repeat(127));
        for (token, expected) in [
            ("1.1.1.1#*ü", wildcard("1.1.1.1#*ü")),
            ("1.1.1.1#ü*", wildcard("1.1.1.1#ü*")),
            (over_wild.as_str(), wildcard(&over_wild)),
            ("1.1.1.1#-.ü", idn("1.1.1.1#-.ü")),
            (idn_over.as_str(), idn(&idn_over)),
        ] {
            assert_eq!(err(token), expected, "class/order for {token:?}");
        }
        assert_eq!(
            err("1.1.1.1#-bad"),
            "resolver nameserver \"1.1.1.1#-bad\" FQDN part invalid: expected lowercase ASCII DNS-name syntax (labels 1-63 [a-z0-9-], total <= 253, no leading or trailing dot)"
        );
    }
}

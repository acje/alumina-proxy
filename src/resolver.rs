use std::fmt;
use std::net::IpAddr;

pub const RESOLVER_PORT: u16 = 53;

pub const MAX_RESOLVERS: usize = 5;

/// The maximum byte length of a validated resolver FQDN (RFC 1035 logical
/// name, no trailing dot).
pub const FQDN_MAX_LEN: usize = 253;

const FQDN_MAX_LABEL: usize = 63;

/// A validated resolver FQDN (the `fqdn` in an `IP#fqdn` entry): lowercase
/// ASCII DNS-name syntax (labels 1..=63 `[a-z0-9-]`, no leading/trailing
/// hyphen), total length at most [`FQDN_MAX_LEN`], no wildcard `*`, no
/// IDN/non-ASCII bytes, no leading or trailing dot. Carried inline so
/// [`Nameserver`] and [`ResolverSet`] stay `Copy` with no heap allocation
/// (fixed profile): the validated bytes are the type, so every constructed
/// value already passed the boundary rules in [`Fqdn::parse`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fqdn {
    bytes: [u8; FQDN_MAX_LEN],
    len: u8,
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
            if label.is_empty() || label.len() > FQDN_MAX_LABEL {
                return Err(FqdnError::Invalid);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(FqdnError::Invalid);
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(FqdnError::Invalid);
            }
        }
        let mut bytes = [0u8; FQDN_MAX_LEN];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Fqdn {
            bytes,
            len: u8::try_from(value.len()).expect("FQDN_MAX_LEN fits u8"),
        })
    }

    /// The validated lowercase ASCII FQDN (no trailing dot).
    ///
    /// # Panics
    ///
    /// Never: the inline bytes were validated as ASCII at construction.
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..usize::from(self.len)])
            .expect("Fqdn stores validated ASCII bytes")
    }
}

impl fmt::Debug for Fqdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fqdn({:?})", self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nameserver {
    addr: IpAddr,
    fqdn: Option<Fqdn>,
}

impl Nameserver {
    #[must_use]
    pub const fn addr(&self) -> IpAddr {
        self.addr
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        RESOLVER_PORT
    }

    /// The optional validated FQDN of an `IP#fqdn` entry: carried as the `SNI`/
    /// `SAN` identity target for the future `DoT` handshake (`port 853`, V1).
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
        }
    }
}

/// Validates one configured resolver entry: a numeric unicast IPv4 or IPv6
/// address (`port` fixed at 53, no zone identifier), optionally followed by
/// `#fqdn` — `IP#fqdn` — where the FQDN is validated as [`Fqdn`] and carried
/// as the future `DoT` `SNI`/`SAN` target. A bare `IP` entry (no `#fqdn`)
/// remains valid on plain DNS and is flagged at startup (IP-only). The first
/// `#` splits IP from the rest, so Package 2's `#pin-sha256=` suffix (V5) can
/// extend the grammar without reopening this boundary.
pub(crate) fn select(token: &str) -> Result<Nameserver, ResolverError> {
    let (ip_part, fqdn_part) = match token.split_once('#') {
        Some((ip, fqdn)) => (ip, Some(fqdn)),
        None => (token, None),
    };
    let addr = parse_ip(ip_part)?;
    let fqdn = match fqdn_part {
        Some(f) => Some(Fqdn::parse(f).map_err(|err| match err {
            FqdnError::Invalid => ResolverError::InvalidFqdn {
                value: token.to_owned(),
            },
            FqdnError::Wildcard => ResolverError::WildcardFqdn {
                value: token.to_owned(),
            },
            FqdnError::Idn => ResolverError::IdnFqdn {
                value: token.to_owned(),
            },
        })?),
        None => None,
    };
    Ok(Nameserver { addr, fqdn })
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
mod tests {
    use super::*;

    #[test]
    fn select_accepts_numeric_unicast_v4_and_v6_at_port53() {
        let v4 = select("1.1.1.1").expect("unicast v4");
        assert_eq!(v4.addr(), "1.1.1.1".parse::<IpAddr>().expect("parse"));
        assert_eq!(v4.port(), 53);
        let v6 = select("2606:4700:4700::1111").expect("unicast v6");
        assert_eq!(
            v6.addr(),
            "2606:4700:4700::1111".parse::<IpAddr>().expect("parse")
        );
        assert_eq!(v6.port(), 53);
    }

    #[test]
    fn select_rejects_non_numeric_zoned_and_non_unicast() {
        assert!(matches!(
            select("not-an-address"),
            Err(ResolverError::InvalidAddress { .. })
        ));
        assert!(matches!(
            select(""),
            Err(ResolverError::InvalidAddress { .. })
        ));
        assert!(matches!(
            select("fe80::1%eth0"),
            Err(ResolverError::ZonedAddress { .. })
        ));
        for addr in ["255.255.255.255", "0.0.0.0", "224.0.0.1", "ff02::1", "::"] {
            assert!(
                matches!(select(addr), Err(ResolverError::NonUnicastAddress { .. })),
                "{addr} must be rejected as non-unicast"
            );
        }
    }

    #[test]
    fn resolver_set_guards_zero_and_overflow_count() {
        assert!(ResolverSet::from_slice(&[]).is_none());
        let five = [
            select("1.1.1.1").expect("ns"),
            select("8.8.8.8").expect("ns"),
            select("9.9.9.9").expect("ns"),
            select("208.67.222.222").expect("ns"),
            select("94.140.14.14").expect("ns"),
        ];
        assert_eq!(ResolverSet::from_slice(&five).expect("5 fits").len(), 5);
        let six = [
            select("1.1.1.1").expect("ns"),
            select("8.8.8.8").expect("ns"),
            select("1.0.0.1").expect("ns"),
            select("8.8.4.4").expect("ns"),
            select("9.9.9.9").expect("ns"),
            select("208.67.222.222").expect("ns"),
        ];
        assert!(ResolverSet::from_slice(&six).is_none());
    }

    #[test]
    fn resolver_set_primary_and_indexed_access() {
        let entries = [
            select("1.1.1.1").expect("ns"),
            select("8.8.8.8").expect("ns"),
        ];
        let set = ResolverSet::from_slice(&entries).expect("2 fits");
        assert_eq!(set.len(), 2);
        assert_eq!(set.primary().addr().to_string(), "1.1.1.1");
        assert_eq!(set.get(1).expect("index 1").addr().to_string(), "8.8.8.8");
        assert!(set.get(2).is_none());
    }

    #[test]
    fn select_accepts_ip_fqdn_and_carries_fqdn() {
        let v4 = select("1.1.1.1#dns.google").expect("IP#fqdn accepted");
        assert_eq!(v4.addr(), "1.1.1.1".parse::<IpAddr>().expect("parse"));
        assert_eq!(v4.port(), 53);
        assert_eq!(v4.fqdn().expect("fqdn carried").as_str(), "dns.google");
        assert!(!v4.is_ip_only());
        let v6 = select("2606:4700:4700::1111#one.one.one.one").expect("v6 IP#fqdn");
        assert_eq!(
            v6.addr(),
            "2606:4700:4700::1111".parse::<IpAddr>().expect("parse")
        );
        assert_eq!(v6.fqdn().expect("fqdn carried").as_str(), "one.one.one.one");
    }

    #[test]
    fn select_bare_ip_has_no_fqdn_and_is_ip_only() {
        let ns = select("1.1.1.1").expect("bare IP accepted");
        assert!(ns.fqdn().is_none(), "bare IP carries no fqdn");
        assert!(ns.is_ip_only());
        assert_eq!(ns.port(), 53, "port stays 53 in V37 (DoT 853 is Package 2)");
    }

    #[test]
    fn select_rejects_empty_or_separator_only_fqdn() {
        assert!(matches!(
            select("1.1.1.1#"),
            Err(ResolverError::InvalidFqdn { .. })
        ));
        assert!(matches!(
            select("1.1.1.1##"),
            Err(ResolverError::InvalidFqdn { .. })
        ));
        assert!(matches!(
            select("#dns.google"),
            Err(ResolverError::InvalidAddress { .. })
        ));
        assert!(matches!(
            select("#"),
            Err(ResolverError::InvalidAddress { .. })
        ));
    }

    #[test]
    fn select_rejects_invalid_fqdn_shapes() {
        for bad in [
            ".example.com",
            "example.com.",
            "example..com",
            "-bad.example.com",
            "bad-.example.com",
            "ExAmPLe.Com",
            "bad_host.example",
            "bad host.example",
        ] {
            let token = format!("1.1.1.1#{bad}");
            let err = select(&token)
                .err()
                .unwrap_or_else(|| panic!("{token} must be rejected"));
            assert!(
                matches!(err, ResolverError::InvalidFqdn { .. }),
                "{token} must be InvalidFqdn, got {err:?}"
            );
        }
    }

    #[test]
    fn select_allows_rfc1123_digit_leading_label() {
        assert_eq!(
            select("1.1.1.1#4example.com")
                .expect("digit-leading label is RFC 1123 DNS-name syntax")
                .fqdn()
                .expect("fqdn")
                .as_str(),
            "4example.com"
        );
    }

    #[test]
    fn select_rejects_wildcard_fqdn() {
        for bad in ["*.example.com", "*.", "*", "a.*.example"] {
            let token = format!("1.1.1.1#{bad}");
            let err = select(&token)
                .err()
                .unwrap_or_else(|| panic!("{token} must be rejected"));
            assert!(
                matches!(err, ResolverError::WildcardFqdn { .. }),
                "{token} must be WildcardFqdn, got {err:?}"
            );
        }
    }

    #[test]
    fn select_rejects_idn_or_non_ascii_fqdn() {
        for bad in ["bücher.example", "例え.jp", "dns.google\u{200d}"] {
            let token = format!("1.1.1.1#{bad}");
            let err = select(&token)
                .err()
                .unwrap_or_else(|| panic!("{token} must be rejected"));
            assert!(
                matches!(err, ResolverError::IdnFqdn { .. }),
                "{token:?} must be IdnFqdn, got {err:?}"
            );
        }
    }

    #[test]
    fn select_enforces_fqdn_label_and_total_length() {
        let ok_label = "a".repeat(63);
        assert!(
            select(&format!("8.8.8.8#{ok_label}.com")).is_ok(),
            "63-char label accepted"
        );
        let over_label = "a".repeat(64);
        assert!(matches!(
            select(&format!("8.8.8.8#{over_label}.com")),
            Err(ResolverError::InvalidFqdn { .. })
        ));
        let max_total = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(max_total.len(), 253);
        assert!(
            select(&format!("8.8.8.8#{max_total}")).is_ok(),
            "253-char total accepted"
        );
        let over_total = format!("{max_total}x");
        assert!(matches!(
            select(&format!("8.8.8.8#{over_total}")),
            Err(ResolverError::InvalidFqdn { .. })
        ));
    }

    #[test]
    fn select_rejects_v5_pin_suffix_until_package2() {
        assert!(
            select("9.9.9.9#dns.quad9.net#pin-sha256=abcd").is_err(),
            "the V5 #pin-sha256= suffix grammar is not valid in V37"
        );
    }

    #[test]
    fn resolver_set_carries_fqdn_through_slice_and_copy() {
        let entries = [
            select("1.1.1.1#dns.google").expect("ns"),
            select("8.8.8.8").expect("ns"),
        ];
        let set = ResolverSet::from_slice(&entries).expect("2 fits");
        assert_eq!(set.len(), 2);
        let copied = set;
        assert_eq!(
            copied.primary().fqdn().expect("fqdn carried").as_str(),
            "dns.google"
        );
        assert!(copied.get(1).expect("index 1").fqdn().is_none());
        let iterated: Vec<&str> = copied
            .iter()
            .map(|ns| ns.fqdn().map_or("<none>", Fqdn::as_str))
            .collect();
        assert_eq!(iterated, ["dns.google", "<none>"]);
    }
}

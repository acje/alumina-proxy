use std::fmt;
use std::net::IpAddr;

pub const RESOLVER_PORT: u16 = 53;

pub const MAX_RESOLVERS: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nameserver {
    addr: IpAddr,
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
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResolverError {
    InvalidAddress { value: String },
    NonUnicastAddress { value: String },
    ZonedAddress { value: String },
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
        }
    }
}

/// Validates one configured resolver address: a numeric unicast IPv4 or IPv6
/// address, port fixed at 53, with no zone identifier.
pub(crate) fn select(token: &str) -> Result<Nameserver, ResolverError> {
    if token.is_empty() {
        return Err(ResolverError::InvalidAddress {
            value: String::new(),
        });
    }
    if token.contains(['%', '@']) {
        return Err(ResolverError::ZonedAddress {
            value: token.to_owned(),
        });
    }
    let addr: IpAddr = token.parse().map_err(|_| ResolverError::InvalidAddress {
        value: token.to_owned(),
    })?;
    if !is_unicast(addr) {
        return Err(ResolverError::NonUnicastAddress {
            value: token.to_owned(),
        });
    }
    Ok(Nameserver { addr })
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
}

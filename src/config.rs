use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use crate::enforcement::action::{ActionKind, AnyIllegalScope, ControlTable, DomainAction, Scope};
use crate::resolver::{self, ResolverSet};

pub const CONFIG_DOC_LIMIT: usize = 16384;
pub const ALLOWLIST_MIN: usize = 1;
pub const ALLOWLIST_MAX: usize = 32;
pub const FQDN_MAX_LEN: usize = 253;
pub const MAX_RESOLVERS: usize = resolver::MAX_RESOLVERS;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fqdn {
    name: String,
    port: u16,
}

impl Fqdn {
    /// Parses one validated `<fqdn>:<port>` allowlist entry. Crate-internal
    /// constructor; the fuzz campaign uses it to anchor the DNS-wire target on
    /// a fixed query context, and config parsing owns the production
    /// construction path.
    pub(crate) fn parse(input: &str) -> Result<Fqdn, String> {
        let (host, port) = input
            .rsplit_once(':')
            .ok_or_else(|| "allowlist entry lacks a <fqdn>:<port> port".to_string())?;
        let name = normalize_trailing_dot(host)?;
        if name.is_empty() {
            return Err("empty hostname".into());
        }
        if name.len() > FQDN_MAX_LEN {
            return Err("hostname exceeds 253 bytes".into());
        }
        for label in name.split('.') {
            if label.is_empty() {
                return Err("empty label".into());
            }
            if label.len() > 63 {
                return Err("label exceeds 63 bytes".into());
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err("label starts or ends with hyphen".into());
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(format!("label {label:?} not lowercase ASCII [a-z0-9-]"));
            }
        }
        if is_ip_literal_shape(name.as_bytes()) {
            return Err("allowlist entry is an IP literal; use a DNS hostname".into());
        }
        let port = parse_config_port(port)?;
        Ok(Fqdn {
            name: name.to_owned(),
            port,
        })
    }

    /// The normalized bare `<fqdn>` (no port, no trailing dot): the key used
    /// for DNS cache entries, queries, and logs, so `NameIndex(u8)` stays
    /// keyed by the bare name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// The validated upstream dial port for this allowlist entry (1..=65535).
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

fn parse_config_port(port: &str) -> Result<u16, String> {
    if port.is_empty() {
        return Err("port is empty".into());
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err("port is not canonical decimal".into());
    }
    if port.len() > 1 && port.starts_with('0') {
        return Err("port has a leading zero".into());
    }
    let port: u16 = port.parse().map_err(|_| "port exceeds 65535".to_string())?;
    if port == 0 {
        return Err("port 0 is invalid".into());
    }
    Ok(port)
}

fn normalize_trailing_dot(name: &str) -> Result<&str, String> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Ok(name);
    }
    if bytes.len() > 1 && bytes[bytes.len() - 1] == b'.' && bytes[bytes.len() - 2] == b'.' {
        return Err("multiple trailing dots".into());
    }
    if bytes[bytes.len() - 1] == b'.' {
        Ok(&name[..name.len() - 1])
    } else {
        Ok(name)
    }
}

fn is_ip_literal_shape(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes[0].is_ascii_digit()
        && bytes.iter().all(|b| *b == b'.' || b.is_ascii_digit())
}

/// Fixed-capacity validated hostname (lowercase ASCII FQDN without a trailing
/// dot), used on serving paths and protocol gates to avoid per-request or
/// per-connection allocation. The label rules mirror the config `Fqdn` type;
/// the numeric-shorthand (IP-literal-looking) form is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedHostname {
    bytes: [u8; FQDN_MAX_LEN],
    len: usize,
}

impl FixedHostname {
    /// The normalized lowercase bytes, without a trailing dot.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// The normalized name as a `&str`; always ASCII by construction.
    ///
    /// # Panics
    ///
    /// Panics only if the normalized bytes are not valid UTF-8, impossible by
    /// construction because normalization accepts ASCII input only.
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).expect("FixedHostname is ASCII")
    }

    /// Normalizes `input` into a legal lowercase FQDN without a trailing dot,
    /// returning `None` for empty, over-length, non-ASCII, IP-literal-shaped,
    /// or malformed names. A single trailing dot is stripped before the
    /// `FQDN_MAX_LEN` bound is applied, so a 254-byte input consisting of a
    /// valid 253-byte name plus a trailing dot is accepted; any other 254-byte
    /// input is rejected without copying outside the fixed buffer.
    #[must_use]
    pub fn normalize(input: &[u8]) -> Option<FixedHostname> {
        if input.is_empty() || input.len() > FQDN_MAX_LEN + 1 {
            return None;
        }
        if !input.is_ascii() {
            return None;
        }
        let len = if input[input.len() - 1] == b'.' {
            input.len() - 1
        } else {
            input.len()
        };
        if len == 0 || len > FQDN_MAX_LEN {
            return None;
        }
        let mut out = FixedHostname {
            bytes: [0u8; FQDN_MAX_LEN],
            len,
        };
        for (i, &b) in input[..len].iter().enumerate() {
            out.bytes[i] = b.to_ascii_lowercase();
        }
        let mut label_len = 0usize;
        for i in 0..=out.len {
            let b = if i == out.len { b'.' } else { out.bytes[i] };
            match b {
                b'.' => {
                    if label_len == 0 || label_len > 63 {
                        return None;
                    }
                    let start = i - label_len;
                    if out.bytes[start] == b'-' || out.bytes[i - 1] == b'-' {
                        return None;
                    }
                    for &c in &out.bytes[start..i] {
                        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
                            return None;
                        }
                    }
                    label_len = 0;
                }
                _ => {
                    label_len += 1;
                }
            }
        }
        if is_ip_literal_shape(&out.bytes[..out.len]) {
            return None;
        }
        Some(out)
    }
}

#[cfg(test)]
mod fixed_hostname_tests {
    use super::FixedHostname;

    #[test]
    fn normalizes_uppercase_and_trailing_dot() {
        let h = FixedHostname::normalize(b"SUB.Example.ORG.").expect("normalize");
        assert_eq!(h.as_bytes(), b"sub.example.org");
    }

    #[test]
    fn rejects_ip_literal_shape() {
        assert!(FixedHostname::normalize(b"1.2.3.4").is_none());
        assert!(FixedHostname::normalize(b"93.184.216.34").is_none());
    }

    #[test]
    fn rejects_all_numeric_label_shapes() {
        for input in [
            &b"1.2.3.4"[..],
            &b"93.184.216.34"[..],
            &b"123"[..],
            &b"999.999.999.999"[..],
            &b"1.2.3.4."[..],
        ] {
            assert!(
                FixedHostname::normalize(input).is_none(),
                "expected {input:?} rejected"
            );
        }
    }

    #[test]
    fn accepts_numeric_prefixed_hostnames() {
        for input in [
            &b"4example.com"[..],
            &b"123.example.com"[..],
            &b"1-2.3.4"[..],
            &b"0x123.example.org"[..],
        ] {
            assert!(
                FixedHostname::normalize(input).is_some(),
                "expected {input:?} accepted"
            );
        }
    }

    #[test]
    fn rejects_malformed_labels() {
        assert!(FixedHostname::normalize(b"").is_none());
        assert!(FixedHostname::normalize(b"-bad.example.org").is_none());
        assert!(FixedHostname::normalize(b"bad-.example.org").is_none());
        assert!(FixedHostname::normalize(b"double..dot.example.org").is_none());
        assert!(FixedHostname::normalize(b"under_score.example.org").is_none());
    }

    #[test]
    fn accepts_253_byte_name_with_trailing_dot() {
        let mut name = Vec::with_capacity(254);
        for _ in 0..125 {
            name.extend_from_slice(b"a.");
        }
        name.extend_from_slice(b"abc.");
        assert_eq!(name.len(), 254, "valid 253-byte name plus trailing dot");
        let h = FixedHostname::normalize(&name).expect("253 canonical + dot must normalize");
        assert_eq!(h.as_bytes().len(), 253);
        assert!(FixedHostname::normalize(&name[..253]).is_some());
    }

    #[test]
    fn rejects_254_byte_name_without_dot_without_panic() {
        let name = [b'a'; 254];
        assert!(FixedHostname::normalize(&name).is_none());
    }

    #[test]
    fn rejects_255_byte_name_with_trailing_dot_without_panic() {
        let mut name = vec![b'a'; 254];
        name.push(b'.');
        assert!(FixedHostname::normalize(&name).is_none());
    }
}

#[cfg(test)]
mod fqdn_tests {
    use super::Fqdn;

    #[test]
    fn rejects_ip_literal_allowlist_entry() {
        assert!(Fqdn::parse("1.2.3.4:443").is_err());
        assert!(Fqdn::parse("93.184.216.34:443").is_err());
        assert!(Fqdn::parse("4example.com:443").is_ok());
    }

    #[test]
    fn rejects_all_numeric_label_entries_per_spec() {
        for entry in [
            "1.2.3.4:443",
            "93.184.216.34:443",
            "255.255.255.255:443",
            "123:443",
            "999.999.999.999:443",
        ] {
            assert!(Fqdn::parse(entry).is_err(), "expected {entry} rejected");
        }
    }

    #[test]
    fn rejects_trailing_dot_ip_literal_after_normalization() {
        assert!(Fqdn::parse("1.2.3.4.:443").is_err());
    }

    #[test]
    fn accepts_numeric_prefixed_hostnames() {
        for entry in [
            "4example.com:443",
            "123.example.com:443",
            "1-2.3.4:443",
            "0x123.example.org:443",
        ] {
            assert!(Fqdn::parse(entry).is_ok(), "expected {entry} accepted");
        }
    }

    #[test]
    fn rejects_empty_host_allowlist_entry_without_panic() {
        assert!(Fqdn::parse(":443").is_err());
        assert!(Fqdn::parse(":443.").is_err());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allowlist(Vec<Fqdn>);

impl Allowlist {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<&Fqdn> {
        self.0.get(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Fqdn> {
        self.0.iter()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenAddr {
    ip: IpAddr,
    port: u16,
}

impl ListenAddr {
    #[must_use]
    pub const fn ip(&self) -> IpAddr {
        self.ip
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    allowlist: Allowlist,
    listen: ListenAddr,
    startup_unresolved_allowance: u8,
    control: ControlTable,
    resolver: ResolverSet,
}

impl Config {
    #[must_use]
    pub const fn allowlist(&self) -> &Allowlist {
        &self.allowlist
    }

    /// The allowlist position of an exact `<fqdn>:<port>` pair, or `None` when
    /// no entry matches both hostname and port. The single source of allowlist
    /// authorization shared by the serving domain-block/attribution ordinals
    /// and the worker CONNECT decision (alumina-9t6w B1), so the pair predicate
    /// cannot drift between sites (alumina-sechd L14).
    pub(crate) fn allowlist_position(&self, hostname: &str, port: u16) -> Option<usize> {
        self.allowlist().iter().position(|entry| {
            entry.as_str().as_bytes() == hostname.as_bytes() && entry.port() == port
        })
    }

    #[must_use]
    pub const fn listen(&self) -> &ListenAddr {
        &self.listen
    }

    #[must_use]
    pub const fn startup_unresolved_allowance(&self) -> u8 {
        self.startup_unresolved_allowance
    }

    #[must_use]
    pub const fn control(&self) -> &ControlTable {
        &self.control
    }

    /// The validated repository resolver set (1..=`MAX_RESOLVERS` entries; index
    /// 0 is the primary). Sourced from the config document, never from a
    /// platform resolver file.
    #[must_use]
    pub const fn resolver_set(&self) -> &ResolverSet {
        &self.resolver
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Unreadable {
        path: String,
        source: String,
    },
    OversizedDocument {
        got: usize,
        limit: usize,
    },
    NotUtf8 {
        message: String,
    },
    ParseToml {
        message: String,
        span: Option<Range<usize>>,
    },
    MissingField(String),
    UnknownKey(String),
    UnknownTable(String),
    WrongType(String),
    AllowlistEmpty,
    AllowlistTooMany {
        got: usize,
    },
    DuplicateAllowlistName(String),
    InvalidFqdn {
        name: String,
        reason: String,
    },
    InvalidListen {
        value: String,
    },
    AllowanceOutOfRange {
        value: i64,
    },
    AnyIllegalScopeDomain,
    InvalidScope {
        key: String,
        value: String,
    },
    UnknownAction {
        name: String,
        value: String,
    },
    ActionTarpitDeferred {
        name: String,
    },
    ResolverCountOutOfRange {
        got: usize,
    },
    InvalidResolver {
        index: usize,
        value: String,
    },
    DuplicateResolver {
        index: usize,
        value: String,
    },
}

impl ConfigError {
    #[must_use]
    pub const fn exit_status(&self) -> i32 {
        78
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Unreadable { path, source } => {
                write!(f, "config unreadable: {path}: {source}")
            }
            ConfigError::OversizedDocument { got, limit } => {
                write!(
                    f,
                    "config exceeds {limit} bytes ({got} bytes read); rejected without truncation"
                )
            }
            ConfigError::NotUtf8 { message } => {
                write!(f, "config is not valid UTF-8: {message}")
            }
            ConfigError::ParseToml { message, span } => match span {
                Some(span) => write!(
                    f,
                    "config parse error at bytes {}..{}: {}",
                    span.start, span.end, message
                ),
                None => write!(f, "config parse error: {message}"),
            },
            ConfigError::MissingField(field) => {
                write!(f, "config missing required field: {field}")
            }
            ConfigError::UnknownKey(field) => write!(f, "config unknown key: {field}"),
            ConfigError::UnknownTable(table) => write!(f, "config unknown table: {table}"),
            ConfigError::WrongType(field) => write!(f, "config incorrect type: {field}"),
            ConfigError::AllowlistEmpty => write!(f, "config allowlist is empty (1..=32 required)"),
            ConfigError::AllowlistTooMany { got } => {
                write!(
                    f,
                    "config allowlist has {got} entries (max {ALLOWLIST_MAX})"
                )
            }
            ConfigError::DuplicateAllowlistName(name) => {
                write!(
                    f,
                    "config duplicate allowlist name after normalization: {name}"
                )
            }
            ConfigError::InvalidFqdn { name, reason } => {
                write!(f, "config invalid FQDN {name:?}: {reason}")
            }
            ConfigError::InvalidListen { value } => {
                write!(
                    f,
                    "config listener {value:?} invalid: expected numeric IPv4 or [bracketed IPv6] and port 1..=65535"
                )
            }
            ConfigError::AllowanceOutOfRange { value } => {
                write!(
                    f,
                    "config startup_unresolved_allowance {value} out of range 0..=allowlist_len-1"
                )
            }
            ConfigError::AnyIllegalScopeDomain => write!(
                f,
                "config any_illegal.scope \"domain\" invalid: AnyIllegal Block scope is connection or all only"
            ),
            ConfigError::InvalidScope { key, value } => write!(
                f,
                "config {key} value {value:?} invalid: expected connection, domain, or all"
            ),
            ConfigError::UnknownAction { name, value } => write!(
                f,
                "config allowed_fqdn.{name} early_data action value {value:?}: unknown action (expected flare_only or block)"
            ),
            ConfigError::ActionTarpitDeferred { name } => write!(
                f,
                "config allowed_fqdn.{name} early_data action is \"tarpit\": Tarpit pacing is deferred and is not accepted as an operational setting (docs/alumina-proxy.md tripwire amendment)"
            ),
            ConfigError::ResolverCountOutOfRange { got } => write!(
                f,
                "config resolver array has {got} entries (1..={MAX_RESOLVERS} required)"
            ),
            ConfigError::InvalidResolver { index, value } => write!(
                f,
                "config resolver[{0}] value {value:?} invalid: expected a numeric unicast IPv4/IPv6 address (optionally `#fqdn`, optionally `#fqdn#pin-sha256=<base64>`), port 53 (bare IP) or 853 (fqdn), no zone identifier, validated lowercase ASCII FQDN",
                index + 1
            ),
            ConfigError::DuplicateResolver { index, value } => write!(
                f,
                "config resolver[{0}] value {value:?} duplicates an earlier resolver entry",
                index + 1
            ),
        }
    }
}

/// Loads and parses the configuration document at `path`, enforcing the
/// on-disk size limit.
///
/// # Errors
///
/// Returns `Unreadable` when the file cannot be opened or read,
/// `OversizedDocument` when it exceeds `CONFIG_DOC_LIMIT`, `NotUtf8` when the
/// bytes are not UTF-8, and the same errors as [`parse_config_document`] from
/// the parse step.
pub fn load_config_document(path: &str) -> Result<Config, ConfigError> {
    let file = File::open(path).map_err(|source| ConfigError::Unreadable {
        path: path.to_owned(),
        source: source.to_string(),
    })?;
    let mut buf = Vec::with_capacity(CONFIG_DOC_LIMIT + 1);
    file.take((CONFIG_DOC_LIMIT + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|source| ConfigError::Unreadable {
            path: path.to_owned(),
            source: source.to_string(),
        })?;
    if buf.len() > CONFIG_DOC_LIMIT {
        return Err(ConfigError::OversizedDocument {
            got: buf.len(),
            limit: CONFIG_DOC_LIMIT,
        });
    }
    let doc = std::str::from_utf8(&buf).map_err(|source| ConfigError::NotUtf8 {
        message: source.to_string(),
    })?;
    parse_config_document(doc)
}

/// Parses a configuration document from `doc`, enforcing the size limit
/// before TOML parsing and table conversion.
///
/// # Errors
///
/// Returns `OversizedDocument` when `doc` exceeds `CONFIG_DOC_LIMIT`,
/// `ParseToml` when the document is not a TOML table, and the configuration
/// validation errors emitted while converting the table.
pub fn parse_config_document(doc: &str) -> Result<Config, ConfigError> {
    if doc.len() > CONFIG_DOC_LIMIT {
        return Err(ConfigError::OversizedDocument {
            got: doc.len(),
            limit: CONFIG_DOC_LIMIT,
        });
    }
    let value: toml::Value = toml::from_str(doc).map_err(|err| ConfigError::ParseToml {
        message: err.message().to_owned(),
        span: err.span(),
    })?;
    let toml::Value::Table(table) = value else {
        return Err(ConfigError::ParseToml {
            message: "document root is not a table".to_owned(),
            span: None,
        });
    };
    from_table(&table)
}

fn from_table(table: &toml::Table) -> Result<Config, ConfigError> {
    let listen = require_string(table, "listen")?;
    let allowance = require_integer(table, "startup_unresolved_allowance")?;
    for (key, value) in table {
        if !matches!(
            key.as_str(),
            "listen" | "startup_unresolved_allowance" | "resolver" | "any_illegal" | "allowed_fqdn"
        ) {
            return Err(match value {
                toml::Value::Table(_) => ConfigError::UnknownTable(key.clone()),
                _ => ConfigError::UnknownKey(key.clone()),
            });
        }
    }
    let any_illegal = table
        .get("any_illegal")
        .ok_or_else(|| ConfigError::MissingField("any_illegal".to_owned()))?;
    let (allowlist, domain_actions) = build_allowlist(table)?;
    let listen = parse_listen(&listen)?;
    let allowance = u8::try_from(allowance)
        .map_err(|_| ConfigError::AllowanceOutOfRange { value: allowance })?;
    if allowance as usize >= allowlist.len() {
        return Err(ConfigError::AllowanceOutOfRange {
            value: allowance.into(),
        });
    }
    let any_scope = parse_any_illegal(any_illegal)?;
    let control = ControlTable::new(any_scope, &domain_actions)
        .expect("build_allowlist validated 1..=32 entries, so ControlTable::new cannot fail");
    let resolver = build_resolver_set(table)?;
    Ok(Config {
        allowlist,
        listen,
        startup_unresolved_allowance: allowance,
        control,
        resolver,
    })
}

fn build_resolver_set(table: &toml::Table) -> Result<ResolverSet, ConfigError> {
    let values = require_string_list(table, "resolver")?;
    if values.is_empty() || values.len() > MAX_RESOLVERS {
        return Err(ConfigError::ResolverCountOutOfRange { got: values.len() });
    }
    let mut nameservers = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let ns = resolver::select(value).map_err(|_| ConfigError::InvalidResolver {
            index,
            value: value.clone(),
        })?;
        if nameservers.contains(&ns) {
            return Err(ConfigError::DuplicateResolver {
                index,
                value: value.clone(),
            });
        }
        nameservers.push(ns);
    }
    resolver::ResolverSet::from_slice(&nameservers).ok_or(ConfigError::ResolverCountOutOfRange {
        got: nameservers.len(),
    })
}

fn parse_any_illegal(value: &toml::Value) -> Result<AnyIllegalScope, ConfigError> {
    let toml::Value::Table(table) = value else {
        return Err(ConfigError::WrongType(
            "any_illegal: expected table".to_owned(),
        ));
    };
    for key in table.keys() {
        if key != "scope" {
            return Err(ConfigError::UnknownKey(format!("any_illegal.{key}")));
        }
    }
    let scope = require_string(table, "scope")
        .map_err(|err| prefix_group_error("any_illegal", "scope", err))?;
    match scope.as_str() {
        "connection" => Ok(AnyIllegalScope::Connection),
        "all" => Ok(AnyIllegalScope::All),
        "domain" => Err(ConfigError::AnyIllegalScopeDomain),
        other => Err(ConfigError::InvalidScope {
            key: "any_illegal.scope".to_owned(),
            value: other.to_owned(),
        }),
    }
}

fn parse_allowed_fqdn_table(
    value: &toml::Value,
    fqdn_key: &str,
) -> Result<DomainAction, ConfigError> {
    let toml::Value::Table(table) = value else {
        return Err(ConfigError::WrongType(format!(
            "allowed_fqdn.{fqdn_key}: expected table"
        )));
    };
    let mut early_data = None;
    for key in table.keys() {
        if key == "early_data" {
            early_data = Some(table.get(key).expect("key present in iteration"));
        } else {
            return Err(ConfigError::UnknownKey(format!(
                "allowed_fqdn.{fqdn_key}.{key}"
            )));
        }
    }
    let early_data = early_data
        .ok_or_else(|| ConfigError::MissingField(format!("allowed_fqdn.{fqdn_key}.early_data")))?;
    parse_early_data(early_data, fqdn_key)
}

fn parse_early_data(value: &toml::Value, fqdn_key: &str) -> Result<DomainAction, ConfigError> {
    let toml::Value::Table(table) = value else {
        return Err(ConfigError::WrongType(format!(
            "allowed_fqdn.{fqdn_key}.early_data: expected table"
        )));
    };
    for key in table.keys() {
        if !matches!(key.as_str(), "action" | "scope") {
            return Err(ConfigError::UnknownKey(format!(
                "allowed_fqdn.{fqdn_key}.early_data.{key}"
            )));
        }
    }
    let prefix = format!("allowed_fqdn.{fqdn_key}.early_data");
    let action = require_string(table, "action")
        .map_err(|err| prefix_group_error(&prefix, "action", err))?;
    let scope =
        require_string(table, "scope").map_err(|err| prefix_group_error(&prefix, "scope", err))?;
    let kind = match action.as_str() {
        "flare_only" => ActionKind::FlareOnly,
        "block" => ActionKind::Block,
        "tarpit" => {
            return Err(ConfigError::ActionTarpitDeferred {
                name: fqdn_key.to_owned(),
            });
        }
        other => {
            return Err(ConfigError::UnknownAction {
                name: fqdn_key.to_owned(),
                value: other.to_owned(),
            });
        }
    };
    let scope = match scope.as_str() {
        "connection" => Scope::Connection,
        "domain" => Scope::Domain,
        "all" => Scope::All,
        other => {
            return Err(ConfigError::InvalidScope {
                key: format!("allowed_fqdn.{fqdn_key}.early_data.scope"),
                value: other.to_owned(),
            });
        }
    };
    Ok(DomainAction::new(kind, scope))
}

fn prefix_group_error(table: &str, key: &str, err: ConfigError) -> ConfigError {
    match err {
        ConfigError::MissingField(field) => ConfigError::MissingField(format!("{table}.{field}")),
        ConfigError::WrongType(message) => {
            ConfigError::WrongType(format!("{table}.{key}: {message}"))
        }
        other => other,
    }
}

fn require_string(table: &toml::Table, key: &str) -> Result<String, ConfigError> {
    match table.get(key) {
        None => Err(ConfigError::MissingField(key.into())),
        Some(toml::Value::String(value)) => Ok(value.clone()),
        Some(value) => Err(ConfigError::WrongType(format!(
            "{}: expected string, got {}",
            key,
            value_kind(value)
        ))),
    }
}

fn require_integer(table: &toml::Table, key: &str) -> Result<i64, ConfigError> {
    match table.get(key) {
        None => Err(ConfigError::MissingField(key.into())),
        Some(toml::Value::Integer(value)) => Ok(*value),
        Some(value) => Err(ConfigError::WrongType(format!(
            "{}: expected integer, got {}",
            key,
            value_kind(value)
        ))),
    }
}

fn require_string_list(table: &toml::Table, key: &str) -> Result<Vec<String>, ConfigError> {
    match table.get(key) {
        None => Err(ConfigError::MissingField(key.into())),
        Some(toml::Value::Array(items)) => {
            let mut values = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                match item {
                    toml::Value::String(value) => values.push(value.clone()),
                    _ => {
                        return Err(ConfigError::WrongType(format!(
                            "{}[{}]: expected string, got {}",
                            key,
                            index,
                            value_kind(item)
                        )));
                    }
                }
            }
            Ok(values)
        }
        Some(value) => Err(ConfigError::WrongType(format!(
            "{}: expected array of strings, got {}",
            key,
            value_kind(value)
        ))),
    }
}

const fn value_kind(value: &toml::Value) -> &'static str {
    match value {
        toml::Value::String(_) => "string",
        toml::Value::Integer(_) => "integer",
        toml::Value::Float(_) => "float",
        toml::Value::Boolean(_) => "boolean",
        toml::Value::Datetime(_) => "datetime",
        toml::Value::Array(_) => "array",
        toml::Value::Table(_) => "table",
    }
}

fn build_allowlist(table: &toml::Table) -> Result<(Allowlist, Vec<DomainAction>), ConfigError> {
    let Some(allowed) = table.get("allowed_fqdn") else {
        return Err(ConfigError::AllowlistEmpty);
    };
    let toml::Value::Table(entries) = allowed else {
        return Err(ConfigError::WrongType(
            "allowed_fqdn: expected table".to_owned(),
        ));
    };
    if entries.is_empty() {
        return Err(ConfigError::AllowlistEmpty);
    }
    if entries.len() > ALLOWLIST_MAX {
        return Err(ConfigError::AllowlistTooMany { got: entries.len() });
    }
    let mut seen = std::collections::HashSet::new();
    let mut allowlist = Vec::with_capacity(entries.len());
    let mut actions = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let fqdn = Fqdn::parse(key).map_err(|reason| ConfigError::InvalidFqdn {
            name: key.clone(),
            reason,
        })?;
        let dedup = (fqdn.as_str().to_owned(), fqdn.port());
        if !seen.insert(dedup) {
            return Err(ConfigError::DuplicateAllowlistName(format!(
                "{}:{}",
                fqdn.as_str(),
                fqdn.port()
            )));
        }
        let action = parse_allowed_fqdn_table(value, key)?;
        allowlist.push(fqdn);
        actions.push(action);
    }
    Ok((Allowlist(allowlist), actions))
}

fn parse_listen(listen: &str) -> Result<ListenAddr, ConfigError> {
    let invalid = || ConfigError::InvalidListen {
        value: listen.to_owned(),
    };
    let Some((addr_part, port_part)) = listen.rsplit_once(':') else {
        return Err(invalid());
    };
    let port = parse_config_port(port_part).map_err(|_| invalid())?;
    let ip = if let Some(rest) = addr_part.strip_prefix('[') {
        let Some(inner) = rest.strip_suffix(']') else {
            return Err(invalid());
        };
        let addr: Ipv6Addr = inner.parse().map_err(|_| invalid())?;
        IpAddr::V6(addr)
    } else {
        let addr: Ipv4Addr = addr_part.parse().map_err(|_| invalid())?;
        IpAddr::V4(addr)
    };
    Ok(ListenAddr { ip, port })
}

#[cfg(test)]
mod listen_tests {
    use super::*;

    #[test]
    fn rejects_leading_zero_listen_port() {
        for listen in ["0.0.0.0:08080", "0.0.0.0:00443", "[::1]:0443"] {
            assert!(
                matches!(parse_listen(listen), Err(ConfigError::InvalidListen { .. })),
                "expected {listen} rejected"
            );
        }
    }

    #[test]
    fn accepts_canonical_listen_port() {
        let v4 = parse_listen("0.0.0.0:8080").expect("canonical v4");
        assert_eq!(v4.port(), 8080);
        let v6 = parse_listen("[::1]:8443").expect("canonical v6");
        assert_eq!(v6.port(), 8443);
    }

    #[test]
    fn rejects_invalid_listen_port_forms() {
        for listen in ["0.0.0.0:0", "0.0.0.0:65536", "0.0.0.0:", "0.0.0.0:port"] {
            assert!(
                matches!(parse_listen(listen), Err(ConfigError::InvalidListen { .. })),
                "expected {listen} rejected"
            );
        }
    }
}

#[cfg(test)]
mod enforcement_config_tests {
    use super::*;
    use crate::enforcement::action::{ActionKind, AnyIllegalScope, Scope};
    use std::fmt::Write as _;

    fn base() -> String {
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n"
            .to_owned()
    }

    fn entry(key: &str, action: &str, scope: &str) -> String {
        format!(
            "[allowed_fqdn.\"{key}\"]\nearly_data = {{ action = \"{action}\", scope = \"{scope}\" }}\n"
        )
    }

    fn group(entries: &str, any_scope: &str) -> String {
        format!(
            "{base}[any_illegal]\nscope = \"{any_scope}\"\n{entries}",
            base = base()
        )
    }

    #[test]
    fn missing_enforcement_group_fails() {
        let err = parse_config_document(&base()).expect_err("group is mandatory");
        assert!(
            matches!(&err, ConfigError::MissingField(f) if f == "any_illegal"),
            "expected MissingField(any_illegal), got {err:?}"
        );
    }

    #[test]
    fn parses_full_enforcement_group() {
        let doc = group(
            &format!(
                "{}{}",
                entry("sub.example.org:443", "block", "domain"),
                entry("other.example.org:443", "flare_only", "connection"),
            ),
            "all",
        );
        let cfg = parse_config_document(&doc).expect("valid enforcement config");
        let control = cfg.control();
        assert_eq!(control.any_illegal(), AnyIllegalScope::All);
        assert_eq!(control.len(), 2);
        let first = control
            .at(control.ordinal(0).expect("ordinal"))
            .expect("configured");
        assert_eq!(first.kind(), ActionKind::FlareOnly);
        assert_eq!(first.scope(), Scope::Connection);
        let second = control
            .at(control.ordinal(1).expect("ordinal"))
            .expect("configured");
        assert_eq!(second.kind(), ActionKind::Block);
        assert_eq!(second.scope(), Scope::Domain);
    }

    #[test]
    fn accepts_any_illegal_connection_scope() {
        let doc = group(&entry("a.example:443", "block", "domain"), "connection");
        let cfg = parse_config_document(&doc).expect("connection scope valid");
        assert_eq!(cfg.control().any_illegal(), AnyIllegalScope::Connection);
    }

    #[test]
    fn rejects_any_illegal_domain_scope() {
        let doc = group(&entry("a.example:443", "block", "domain"), "domain");
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::AnyIllegalScopeDomain),
            "expected AnyIllegalScopeDomain, got {err:?}"
        );
    }

    #[test]
    fn rejects_any_illegal_unknown_scope() {
        let doc = group(&entry("a.example:443", "block", "connection"), "wired");
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidScope { .. }),
            "expected InvalidScope, got {err:?}"
        );
    }

    #[test]
    fn rejects_missing_early_data() {
        let doc = format!(
            "{base}[any_illegal]\nscope = \"all\"\n[allowed_fqdn.\"a.example:443\"]\n",
            base = base()
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::MissingField(f) if f == "allowed_fqdn.a.example:443.early_data"),
            "expected MissingField(early_data), got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_key_in_allowed_fqdn_table() {
        let doc = format!(
            "{base}[any_illegal]\nscope = \"all\"\n[allowed_fqdn.\"a.example:443\"]\nearly_data = {{ action = \"block\", scope = \"domain\" }}\nja4 = \"x\"\n",
            base = base()
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::UnknownKey(k) if k == "allowed_fqdn.a.example:443.ja4"),
            "expected UnknownKey, got {err:?}"
        );
    }

    #[test]
    fn rejects_tarpit_kind_with_deferred_diagnostic() {
        let doc = group(&entry("a.example:443", "tarpit", "connection"), "all");
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::ActionTarpitDeferred { ref name } if name == "a.example:443"),
            "expected ActionTarpitDeferred, got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_action_kind() {
        let doc = group(&entry("a.example:443", "peek", "connection"), "all");
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::UnknownAction { ref name, .. } if name == "a.example:443"),
            "expected UnknownAction, got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_per_domain_scope() {
        let doc = group(&entry("a.example:443", "block", "wire"), "all");
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidScope { .. }),
            "expected InvalidScope, got {err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_after_normalization() {
        let doc = group(
            &format!(
                "{}{}",
                entry("a.example:443", "block", "domain"),
                entry("a.example.:443", "block", "domain"),
            ),
            "all",
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::DuplicateAllowlistName(n) if n == "a.example:443"),
            "expected DuplicateAllowlistName, got {err:?}"
        );
    }

    #[test]
    fn rejects_more_than_32_tables() {
        let mut doc = base();
        doc.push_str("[any_illegal]\nscope = \"all\"\n");
        for i in 0..33 {
            let _ = write!(
                doc,
                "[allowed_fqdn.\"n{i:02}.example:443\"]\nearly_data = {{ action = \"block\", scope = \"domain\" }}\n"
            );
        }
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::AllowlistTooMany { got: 33 }),
            "expected AllowlistTooMany, got {err:?}"
        );
    }

    #[test]
    fn rejects_empty_allowlist() {
        let doc = format!(
            "{base}[any_illegal]\nscope = \"all\"\n[allowed_fqdn]\n",
            base = base()
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::AllowlistEmpty),
            "expected AllowlistEmpty, got {err:?}"
        );
    }

    #[test]
    fn rejects_absent_allowlist() {
        let doc = format!("{base}[any_illegal]\nscope = \"all\"\n", base = base());
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::AllowlistEmpty),
            "expected AllowlistEmpty, got {err:?}"
        );
    }

    #[test]
    fn rejects_bare_fqdn_key() {
        let doc = group(&entry("a.example", "block", "domain"), "all");
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidFqdn { name, .. } if name == "a.example"),
            "expected InvalidFqdn, got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_top_level_key_unchanged() {
        let doc = format!("{}bogus = 1\n", base());
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::UnknownKey(_)),
            "expected UnknownKey, got {err:?}"
        );
    }

    fn hundred_byte_name(i: usize) -> String {
        format!("n{i:02}.{}.{}:443", "a".repeat(48), "b".repeat(43))
    }

    fn keyed_document(count: usize, any_scope: &str, action: &str, scope: &str) -> String {
        let mut doc = base();
        let _ = write!(doc, "[any_illegal]\nscope = \"{any_scope}\"\n");
        for i in 0..count {
            let _ = write!(
                doc,
                "[allowed_fqdn.\"{}\"]\nearly_data = {{ action = \"{action}\", scope = \"{scope}\" }}\n",
                hundred_byte_name(i)
            );
        }
        doc
    }

    #[test]
    fn compact_32_names_with_group_fit_16kib() {
        let doc = keyed_document(32, "all", "block", "domain");
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "compact config with full enforcement group fits 16384 bytes (len {})",
            doc.len()
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 32);
        assert_eq!(cfg.control().len(), 32);
    }

    #[test]
    fn flare_connection_32_hundred_byte_names_fit_and_parse() {
        let doc = keyed_document(32, "connection", "flare_only", "connection");
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "the longer spelling's measured total is {}",
            doc.len()
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 32);
        assert_eq!(cfg.control().len(), 32);
    }

    #[test]
    fn flare_connection_29_hundred_byte_names_fit_and_parse() {
        let doc = keyed_document(29, "connection", "flare_only", "connection");
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "29-name longer spelling fits 16384 bytes (len {})",
            doc.len()
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 29);
        assert_eq!(cfg.control().len(), 29);
    }

    #[test]
    fn compact_32_hundred_byte_names_measured_total_is_5548() {
        let doc = keyed_document(32, "all", "block", "domain");
        assert_eq!(
            doc.len(),
            5548,
            "compact 32-name measured total with resolver key"
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 32);
        assert_eq!(cfg.control().len(), 32);
    }

    #[test]
    fn compact_32_hundred_byte_names_with_ip_fqdn_resolver_measured_total_is_5567() {
        let doc = keyed_document(32, "all", "block", "domain").replacen(
            "resolver = [\"1.1.1.1\"]",
            "resolver = [\"1.1.1.1#cloudflare-dns.com\"]",
            1,
        );
        assert_eq!(
            doc.len(),
            5567,
            "tight 32×100-byte compact form with a single realistic IP#fqdn entry"
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 32);
        assert_eq!(cfg.control().len(), 32);
    }

    #[test]
    fn compact_32_hundred_byte_names_with_pinned_resolver_measured_total_is_5615() {
        let b64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let doc = keyed_document(32, "all", "block", "domain").replacen(
            "resolver = [\"1.1.1.1\"]",
            &format!("resolver = [\"1.1.1.1#dns.google#pin-sha256={b64}\"]"),
            1,
        );
        assert_eq!(
            doc.len(),
            5615,
            "tight 32×100-byte compact form with a pinned DoT entry"
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 32);
        assert_eq!(cfg.control().len(), 32);
    }

    #[test]
    fn flare_connection_32_hundred_byte_names_measured_total_is_5843() {
        let doc = keyed_document(32, "connection", "flare_only", "connection");
        assert_eq!(
            doc.len(),
            5843,
            "longer 32-name measured total with resolver key"
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 32);
        assert_eq!(cfg.control().len(), 32);
    }

    #[test]
    fn flare_connection_29_hundred_byte_names_measured_total_is_5306() {
        let doc = keyed_document(29, "connection", "flare_only", "connection");
        assert_eq!(
            doc.len(),
            5306,
            "29-name longer spelling measured total with resolver key"
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 29);
        assert_eq!(cfg.control().len(), 29);
    }
}

#[cfg(test)]
mod resolver_config_tests {
    use super::*;
    use std::fmt::Write as _;

    fn valid_doc(resolver: &str) -> String {
        format!(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = {resolver}\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"a.example:443\"]\nearly_data = {{ action = \"flare_only\", scope = \"connection\" }}\n"
        )
    }

    #[test]
    fn resolver_key_is_mandatory() {
        let d = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n";
        let err = parse_config_document(d).unwrap_err();
        assert!(
            matches!(&err, ConfigError::MissingField(f) if f == "resolver"),
            "expected MissingField(resolver), got {err:?}"
        );
    }

    #[test]
    fn resolver_primary_and_count_from_config() {
        let cfg = parse_config_document(&valid_doc(
            "[\"1.1.1.1\", \"8.8.8.8\", \"1.0.0.1\", \"8.8.4.4\"]",
        ))
        .expect("four resolvers valid");
        assert_eq!(cfg.resolver_set().len(), 4);
        assert_eq!(cfg.resolver_set().primary().addr().to_string(), "1.1.1.1");
        assert_eq!(
            cfg.resolver_set()
                .get(3)
                .expect("index 3")
                .addr()
                .to_string(),
            "8.8.4.4"
        );
        assert_eq!(cfg.resolver_set().primary().port(), 53);
        let single =
            parse_config_document(&valid_doc("[\"1.1.1.1\"]")).expect("one resolver valid");
        assert_eq!(single.resolver_set().len(), 1);
        assert_eq!(
            single.resolver_set().primary().addr().to_string(),
            "1.1.1.1"
        );
    }

    #[test]
    fn resolver_five_accepted() {
        let cfg = parse_config_document(&valid_doc(
            "[\"1.1.1.1\", \"8.8.8.8\", \"9.9.9.9\", \"208.67.222.222\", \"94.140.14.14\"]",
        ))
        .expect("five resolvers valid");
        assert_eq!(cfg.resolver_set().len(), 5);
        assert_eq!(cfg.resolver_set().primary().addr().to_string(), "1.1.1.1");
        assert_eq!(
            cfg.resolver_set()
                .get(4)
                .expect("index 4")
                .addr()
                .to_string(),
            "94.140.14.14"
        );
    }

    #[test]
    fn resolver_duplicates_rejected() {
        let err = parse_config_document(&valid_doc("[\"1.1.1.1\", \"1.1.1.1\"]"))
            .expect_err("exact duplicate resolver must be rejected");
        assert!(
            matches!(&err, ConfigError::DuplicateResolver { index: 1, value: v } if v == "1.1.1.1"),
            "exact duplicate must be DuplicateResolver{{index:1}}, got {err:?}"
        );
        assert_eq!(err.exit_status(), 78, "DuplicateResolver must exit 78");
    }

    #[test]
    fn resolver_duplicate_fqdn_and_pin_forms_rejected() {
        let b64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        for value in [
            "1.1.1.1#dns.google",
            &format!("9.9.9.9#dns.quad9.net#pin-sha256={b64}"),
        ] {
            let err = parse_config_document(&valid_doc(&format!("[\"{value}\", \"{value}\"]")))
                .expect_err("duplicate resolver must be rejected");
            assert!(
                matches!(&err, ConfigError::DuplicateResolver { index: 1, value: v } if v == value),
                "duplicate {value} must be DuplicateResolver{{index:1}}, got {err:?}"
            );
        }
    }

    #[test]
    fn resolver_ipv6_unicast_accepted() {
        let cfg = parse_config_document(&valid_doc("[\"2606:4700:4700::1111\"]"))
            .expect("ipv6 unicast resolver valid");
        assert_eq!(
            cfg.resolver_set().primary().addr().to_string(),
            "2606:4700:4700::1111"
        );
        assert_eq!(cfg.resolver_set().primary().port(), 53);
    }

    #[test]
    fn resolver_count_out_of_range_rejected() {
        let empty = parse_config_document(&valid_doc("[]")).unwrap_err();
        assert!(
            matches!(empty, ConfigError::ResolverCountOutOfRange { got: 0 }),
            "empty resolver must be ResolverCountOutOfRange, got {empty:?}"
        );
        let six = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\", \"8.8.8.8\", \"9.9.9.9\", \"208.67.222.222\", \"94.140.14.14\", \"1.0.0.1\"]\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n";
        let too_many = parse_config_document(six).unwrap_err();
        assert!(
            matches!(too_many, ConfigError::ResolverCountOutOfRange { got: 6 }),
            "six resolvers must be ResolverCountOutOfRange, got {too_many:?}"
        );
    }

    #[test]
    fn resolver_address_validation_from_config() {
        for (wrong, value) in [
            ("non-numeric", "not-an-address"),
            ("broadcast", "255.255.255.255"),
            ("multicast", "224.0.0.1"),
            ("unspecified", "0.0.0.0"),
            ("ipv6-multicast", "ff02::1"),
            ("zoned", "fe80::1%eth0"),
        ] {
            let cfg_doc = valid_doc(&format!("[\"{value}\"]"));
            let err = parse_config_document(&cfg_doc)
                .expect_err(&format!("resolver {wrong} must be rejected"));
            assert!(
                matches!(&err, ConfigError::InvalidResolver { index, value: v } if *index == 0 && v == value),
                "resolver {wrong} must be InvalidResolver{{index:0}}, got {err:?}"
            );
            assert_eq!(err.exit_status(), 78, "InvalidResolver must exit 78");
        }
    }

    #[test]
    fn resolver_wrong_type_rejected() {
        let d = valid_doc("42");
        let err = parse_config_document(&d).unwrap_err();
        assert!(
            matches!(&err, ConfigError::WrongType(_)),
            "integer resolver must be WrongType, got {err:?}"
        );
    }

    #[test]
    fn resolver_ip_fqdn_from_config() {
        let cfg = parse_config_document(&valid_doc("[\"1.1.1.1#dns.google\"]"))
            .expect("IP#fqdn resolver valid");
        assert_eq!(cfg.resolver_set().len(), 1);
        let primary = cfg.resolver_set().primary();
        assert_eq!(primary.addr().to_string(), "1.1.1.1");
        assert_eq!(
            primary.port(),
            853,
            "an fqdn resolver is a DoT entry on port 853"
        );
        assert_eq!(primary.fqdn().expect("fqdn carried").as_str(), "dns.google");
        assert!(primary.pin().is_none(), "no pin without the pin suffix");
    }

    #[test]
    fn resolver_pin_from_config() {
        // base64("A".repeat(32)) = 43 unpadded chars (AQ...), the resolver
        // grammar's canonical strict SPKI pin for a DoT entry.
        let b64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let cfg = parse_config_document(&valid_doc(&format!(
            "[\"9.9.9.9#dns.quad9.net#pin-sha256={b64}\"]"
        )))
        .expect("pinned resolver valid");
        assert_eq!(cfg.resolver_set().len(), 1);
        let primary = cfg.resolver_set().primary();
        assert_eq!(primary.addr().to_string(), "9.9.9.9");
        assert_eq!(primary.port(), 853, "a pinned entry is a DoT entry");
        assert_eq!(
            primary.fqdn().expect("fqdn carried").as_str(),
            "dns.quad9.net"
        );
        assert_eq!(
            primary.pin().expect("pin carried").as_bytes(),
            [0x01u8; 32],
            "the strict SPKI pin decodes to the raw digest"
        );
    }

    #[test]
    fn resolver_ip_only_from_config_has_no_fqdn() {
        let cfg =
            parse_config_document(&valid_doc("[\"1.1.1.1\"]")).expect("bare IP resolver valid");
        assert!(cfg.resolver_set().primary().fqdn().is_none());
        assert!(cfg.resolver_set().primary().is_ip_only());
    }

    #[test]
    fn config_document_with_utf8_bom_parses() {
        let doc = format!("\u{feff}{}", valid_doc("[\"1.1.1.1\"]"));
        let cfg = parse_config_document(&doc).expect("BOM-prefixed doc parses");
        assert_eq!(cfg.resolver_set().len(), 1);
        assert_eq!(cfg.resolver_set().primary().addr().to_string(), "1.1.1.1");
    }

    #[test]
    fn config_document_bom_counts_toward_size_limit() {
        let base = valid_doc("[\"1.1.1.1\"]");
        let pad = CONFIG_DOC_LIMIT.saturating_sub(base.len() + 2);
        let exact = format!("{base}\n#{}", "a".repeat(pad));
        assert_eq!(
            exact.len(),
            CONFIG_DOC_LIMIT,
            "padded doc is exactly the 16384-byte limit"
        );
        parse_config_document(&exact).expect("doc at exactly the limit parses");
        let with_bom = format!("\u{feff}{exact}");
        assert_eq!(with_bom.len(), CONFIG_DOC_LIMIT + 3, "BOM adds 3 bytes");
        let err = parse_config_document(&with_bom).expect_err("BOM-prefixed doc exceeds the limit");
        assert!(
            matches!(&err, ConfigError::OversizedDocument { got, limit } if *limit == CONFIG_DOC_LIMIT && *got == with_bom.len()),
            "expected OversizedDocument for {} bytes, got {err:?}",
            with_bom.len()
        );
    }

    #[test]
    fn resolver_bad_fqdn_from_config_is_invalid_resolver() {
        for value in [
            "1.1.1.1#*.example.com",
            "1.1.1.1#",
            "1.1.1.1#bücher.de",
            "1.1.1.1#ExAmPLe.com",
            "1.1.1.1#.example.com",
            "1.1.1.1#example.com.",
        ] {
            let err = parse_config_document(&valid_doc(&format!("[\"{value}\"]")))
                .expect_err("bad FQDN must be rejected");
            assert!(
                matches!(&err, ConfigError::InvalidResolver { index: 0, value: v } if v == value),
                "{value} must be InvalidResolver{{index:0}}, got {err:?}"
            );
            assert_eq!(err.exit_status(), 78, "must exit 78");
        }
    }

    #[test]
    fn resolver_ip_fqdn_example_fits_16kib() {
        let resolver = "[\"1.1.1.1#cloudflare-dns.com\", \"8.8.8.8#dns.google\", \"9.9.9.9#dns.quad9.net\", \"208.67.222.222#dns.opendns.com\", \"94.140.14.14#dns.adguard.com\"]";
        let example = format!(
            "listen = \"127.0.0.1:8080\"\nstartup_unresolved_allowance = 0\nresolver = {resolver}\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"api.github.com:443\"]\nearly_data = {{ action = \"flare_only\", scope = \"connection\" }}\n[allowed_fqdn.\"example.com:443\"]\nearly_data = {{ action = \"flare_only\", scope = \"connection\" }}\n[allowed_fqdn.\"www.example.net:443\"]\nearly_data = {{ action = \"flare_only\", scope = \"connection\" }}\n"
        );
        assert_eq!(
            example.len(),
            538,
            "16 KiB re-measure: the V37 golden-path IP#fqdn example config is serializer-pinned at 538 B"
        );
        assert!(
            example.len() <= CONFIG_DOC_LIMIT,
            "IP#fqdn example fits 16384 B (len {})",
            example.len()
        );
        let cfg = parse_config_document(&example).expect("example parses within the 16 KiB bound");
        assert_eq!(cfg.resolver_set().len(), 5);
        assert_eq!(
            cfg.resolver_set()
                .primary()
                .fqdn()
                .expect("fqdn carried")
                .as_str(),
            "cloudflare-dns.com"
        );
    }

    #[test]
    fn resolver_key_respected_in_compact_fit_form() {
        let mut compact = String::from(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\", \"8.8.8.8\", \"1.0.0.1\", \"8.8.4.4\"]\n[any_illegal]\nscope = \"all\"\n",
        );
        for i in 0..32usize {
            let _ = write!(
                compact,
                "[allowed_fqdn.\"{i}.{}.{}:443\"]\nearly_data = {{ action = \"block\", scope = \"domain\" }}\n",
                "a".repeat(48),
                "b".repeat(43)
            );
        }
        assert!(
            compact.len() <= CONFIG_DOC_LIMIT,
            "compact 32-name fit form with resolver must still be documented; measured {}",
            compact.len()
        );
    }
}

#[cfg(test)]
mod authorization_boundary_tests {
    use super::*;

    fn config() -> Config {
        parse_config_document(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"sub.example.org:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n[allowed_fqdn.\"other.test:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n",
        )
        .expect("valid config")
    }

    #[test]
    fn allowlist_position_matches_exact_pair_only() {
        let cfg = config();
        // Keyed tables sort by key (BTreeMap), so `other.test:443` precedes
        // `sub.example.org:443` and owns ordinal 0.
        assert_eq!(cfg.allowlist_position("other.test", 443), Some(0));
        assert_eq!(cfg.allowlist_position("sub.example.org", 443), Some(1));
    }

    #[test]
    fn allowlist_position_rejects_trailing_dot_and_case_variants() {
        let cfg = config();
        // The predicate is exact-bytes on the normalized stored name; a
        // trailing dot or case variant must not authorize (a trailing-dot
        // CONNECT that survived normalize would otherwise be a bypass).
        assert_eq!(cfg.allowlist_position("sub.example.org.", 443), None);
        assert_eq!(cfg.allowlist_position("SUB.EXAMPLE.ORG", 443), None);
        assert_eq!(cfg.allowlist_position("Sub.Example.Org", 443), None);
    }

    #[test]
    fn allowlist_position_rejects_superstring_and_substring() {
        let cfg = config();
        assert_eq!(cfg.allowlist_position("xsub.example.org", 443), None);
        assert_eq!(cfg.allowlist_position("example.org", 443), None);
        assert_eq!(
            cfg.allowlist_position("sub.example.org.evil.test", 443),
            None
        );
    }

    #[test]
    fn allowlist_position_rejects_empty_hostname_and_wrong_port() {
        let cfg = config();
        assert_eq!(cfg.allowlist_position("", 443), None);
        assert_eq!(cfg.allowlist_position("sub.example.org", 8443), None);
        assert_eq!(cfg.allowlist_position("sub.example.org", 0), None);
    }

    #[test]
    fn build_allowlist_same_host_different_ports_both_survive() {
        let cfg = parse_config_document(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:8443\"]\nearly_data = { action = \"flare_only\", scope = \"connection\" }\n",
        )
        .expect("dedup is by the full <fqdn>:<port> pair, so the same host at a second port is a distinct entry");
        assert_eq!(cfg.allowlist().len(), 2);
    }

    #[test]
    fn fqdn_parse_accepts_ascii_alabel_and_rejects_raw_utf8() {
        // Spec :61 permits IDNs only in A-label (xn--…) form; the A-label is
        // lowercase ASCII and must parse, while raw UTF-8 must be rejected.
        let alabel = Fqdn::parse("xn--bcher-kva.example:443").expect("A-label parses");
        assert_eq!(alabel.as_str(), "xn--bcher-kva.example");
        assert_eq!(alabel.port(), 443);
        let err = Fqdn::parse("bücher.example:443").expect_err("raw UTF-8 rejected");
        assert!(
            err.contains("not lowercase ASCII"),
            "expected label-charset rejection, got {err:?}"
        );
    }

    #[test]
    fn normalize_accepts_alabel_and_rejects_real_non_ascii_bytes() {
        let alabel =
            FixedHostname::normalize(b"xn--bcher-kva.example").expect("A-label normalizes");
        assert_eq!(alabel.as_bytes(), b"xn--bcher-kva.example");
        // Real UTF-8 (>0x7F) must hit the `!input.is_ascii()` reject branch,
        // unlike the pure-ASCII underscore label exercised by
        // `rejects_malformed_labels`.
        assert!(FixedHostname::normalize("bücher.example".as_bytes()).is_none());
        assert!(FixedHostname::normalize("b\u{e9}cher.example".as_bytes()).is_none());
    }
}

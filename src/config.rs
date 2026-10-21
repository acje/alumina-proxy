use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use crate::enforcement::action::{ActionKind, AnyIllegalScope, ControlTable, DomainAction, Scope};
use crate::resolver::{self, ResolverSet};

pub const CONFIG_DOC_LIMIT: usize = 4096;
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
        assert!(FixedHostname::normalize(b"non_ascii_example.org").is_none());
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
        index: usize,
        value: String,
    },
    ActionTarpitDeferred {
        index: usize,
    },
    ActionsLengthMismatch {
        got_kind: usize,
        got_scope: usize,
        expected: usize,
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
            ConfigError::UnknownAction { index, value } => write!(
                f,
                "config actions.kind[{}] value {value:?}: unknown action (expected flare_only or block)",
                index + 1
            ),
            ConfigError::ActionTarpitDeferred { index } => write!(
                f,
                "config actions.kind[{}] is \"tarpit\": Tarpit pacing is deferred and is not accepted as an operational setting (docs/alumina-proxy.md tripwire amendment)",
                index + 1
            ),
            ConfigError::ActionsLengthMismatch {
                got_kind,
                got_scope,
                expected,
            } => write!(
                f,
                "config [actions] kind/scope lengths {got_kind}/{got_scope} must equal allowlist length {expected}"
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
    let allowlist_names = require_string_list(table, "allowlist")?;
    let listen = require_string(table, "listen")?;
    let allowance = require_integer(table, "startup_unresolved_allowance")?;
    for (key, value) in table {
        if !matches!(
            key.as_str(),
            "allowlist"
                | "listen"
                | "startup_unresolved_allowance"
                | "resolver"
                | "any_illegal"
                | "actions"
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
    let actions = table
        .get("actions")
        .ok_or_else(|| ConfigError::MissingField("actions".to_owned()))?;
    let allowlist = build_allowlist(allowlist_names)?;
    let listen = parse_listen(&listen)?;
    let allowance = u8::try_from(allowance)
        .map_err(|_| ConfigError::AllowanceOutOfRange { value: allowance })?;
    if allowance as usize >= allowlist.len() {
        return Err(ConfigError::AllowanceOutOfRange {
            value: allowance.into(),
        });
    }
    let any_scope = parse_any_illegal(any_illegal)?;
    let domain_actions = parse_actions(actions, allowlist.len())?;
    let Some(control) = ControlTable::new(any_scope, &domain_actions) else {
        return Err(ConfigError::ActionsLengthMismatch {
            got_kind: domain_actions.len(),
            got_scope: domain_actions.len(),
            expected: ALLOWLIST_MAX,
        });
    };
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

fn parse_actions(
    value: &toml::Value,
    allowlist_len: usize,
) -> Result<Vec<DomainAction>, ConfigError> {
    let toml::Value::Table(table) = value else {
        return Err(ConfigError::WrongType("actions: expected table".to_owned()));
    };
    for key in table.keys() {
        if !matches!(key.as_str(), "kind" | "scope") {
            return Err(ConfigError::UnknownKey(format!("actions.{key}")));
        }
    }
    let kinds = require_string_list(table, "kind")
        .map_err(|err| prefix_group_error("actions", "kind", err))?;
    let scopes = require_string_list(table, "scope")
        .map_err(|err| prefix_group_error("actions", "scope", err))?;
    if kinds.len() != allowlist_len || scopes.len() != allowlist_len {
        return Err(ConfigError::ActionsLengthMismatch {
            got_kind: kinds.len(),
            got_scope: scopes.len(),
            expected: allowlist_len,
        });
    }
    let mut actions = Vec::with_capacity(kinds.len());
    for (index, (kind, scope)) in kinds.iter().zip(scopes.iter()).enumerate() {
        let kind = match kind.as_str() {
            "flare_only" => ActionKind::FlareOnly,
            "block" => ActionKind::Block,
            "tarpit" => return Err(ConfigError::ActionTarpitDeferred { index }),
            other => {
                return Err(ConfigError::UnknownAction {
                    index,
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
                    key: format!("actions.scope[{}]", index + 1),
                    value: other.to_owned(),
                });
            }
        };
        actions.push(DomainAction::new(kind, scope));
    }
    Ok(actions)
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

fn build_allowlist(names: Vec<String>) -> Result<Allowlist, ConfigError> {
    if names.is_empty() {
        return Err(ConfigError::AllowlistEmpty);
    }
    if names.len() > ALLOWLIST_MAX {
        return Err(ConfigError::AllowlistTooMany { got: names.len() });
    }
    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let fqdn =
            Fqdn::parse(&name).map_err(|reason| ConfigError::InvalidFqdn { name, reason })?;
        if !seen.insert(fqdn.as_str().to_owned()) {
            return Err(ConfigError::DuplicateAllowlistName(
                fqdn.as_str().to_owned(),
            ));
        }
        entries.push(fqdn);
    }
    Ok(Allowlist(entries))
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

    fn base(names: &str) -> String {
        format!(
            "allowlist = [{names}]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n"
        )
    }

    fn group(names: &str, any_scope: &str, kinds: &str, scopes: &str) -> String {
        format!(
            "{base}\n[any_illegal]\nscope = \"{any_scope}\"\n[actions]\nkind = {kinds}\nscope = {scopes}\n",
            base = base(names)
        )
    }

    #[test]
    fn missing_enforcement_group_fails() {
        let err = parse_config_document(&base("\"sub.example.org:443\""))
            .expect_err("group is mandatory");
        assert!(
            matches!(&err, ConfigError::MissingField(f) if f == "any_illegal"),
            "expected MissingField(any_illegal), got {err:?}"
        );
    }

    #[test]
    fn parses_full_enforcement_group() {
        let doc = group(
            "\"sub.example.org:443\", \"other.example.org:443\"",
            "all",
            "[\"block\", \"flare_only\"]",
            "[\"domain\", \"connection\"]",
        );
        let cfg = parse_config_document(&doc).expect("valid enforcement config");
        let control = cfg.control();
        assert_eq!(control.any_illegal(), AnyIllegalScope::All);
        assert_eq!(control.len(), 2);
        let first = control
            .at(control.ordinal(0).expect("ordinal"))
            .expect("configured");
        assert_eq!(first.kind(), ActionKind::Block);
        assert_eq!(first.scope(), Scope::Domain);
        let second = control
            .at(control.ordinal(1).expect("ordinal"))
            .expect("configured");
        assert_eq!(second.kind(), ActionKind::FlareOnly);
        assert_eq!(second.scope(), Scope::Connection);
    }

    #[test]
    fn accepts_any_illegal_connection_scope() {
        let doc = group(
            "\"a.example:443\"",
            "connection",
            "[\"block\"]",
            "[\"domain\"]",
        );
        let cfg = parse_config_document(&doc).expect("connection scope valid");
        assert_eq!(cfg.control().any_illegal(), AnyIllegalScope::Connection);
    }

    #[test]
    fn rejects_any_illegal_domain_scope() {
        let doc = group("\"a.example:443\"", "domain", "[\"block\"]", "[\"domain\"]");
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::AnyIllegalScopeDomain),
            "expected AnyIllegalScopeDomain, got {err:?}"
        );
    }

    #[test]
    fn rejects_any_illegal_unknown_scope() {
        let doc = group(
            "\"a.example:443\"",
            "wired",
            "[\"block\"]",
            "[\"connection\"]",
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidScope { .. }),
            "expected InvalidScope, got {err:?}"
        );
    }

    #[test]
    fn rejects_missing_actions_when_any_illegal_present() {
        let doc = format!(
            "{}\n[any_illegal]\nscope = \"all\"\n",
            base("\"a.example:443\"")
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::MissingField(f) if f == "actions"),
            "expected MissingField(actions), got {err:?}"
        );
    }

    #[test]
    fn rejects_missing_any_illegal_when_actions_present() {
        let doc = format!(
            "{}\n[actions]\nkind = [\"block\"]\nscope = [\"domain\"]\n",
            base("\"a.example:443\"")
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::MissingField(f) if f == "any_illegal"),
            "expected MissingField(any_illegal), got {err:?}"
        );
    }

    #[test]
    fn rejects_tarpit_kind_with_deferred_diagnostic() {
        let doc = group(
            "\"a.example:443\"",
            "all",
            "[\"tarpit\"]",
            "[\"connection\"]",
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::ActionTarpitDeferred { index: 0 }),
            "expected ActionTarpitDeferred, got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_action_kind() {
        let doc = group("\"a.example:443\"", "all", "[\"peek\"]", "[\"connection\"]");
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::UnknownAction { index: 0, .. }),
            "expected UnknownAction, got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_per_domain_scope() {
        let doc = group("\"a.example:443\"", "all", "[\"block\"]", "[\"wire\"]");
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidScope { .. }),
            "expected InvalidScope, got {err:?}"
        );
    }

    #[test]
    fn rejects_actions_length_mismatch() {
        let doc = group(
            "\"a.example:443\"",
            "all",
            "[\"block\", \"block\"]",
            "[\"domain\", \"domain\"]",
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::ActionsLengthMismatch { .. }),
            "expected ActionsLengthMismatch, got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_top_level_key_unchanged() {
        let doc = format!("{}bogus = 1\n", base("\"a.example:443\""));
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::UnknownKey(_)),
            "expected UnknownKey, got {err:?}"
        );
    }

    #[test]
    fn compact_32_names_with_group_fit_4kib() {
        let names: Vec<String> = (0..32)
            .map(|i| format!("n{i:02}.{}.{}:443", "a".repeat(48), "b".repeat(43)))
            .collect();
        let list = names
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let kinds = vec!["\"block\""; 32].join(", ");
        let scopes = vec!["\"domain\""; 32].join(", ");
        let doc = format!(
            "allowlist = [{list}]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"all\"\n[actions]\nkind = [{kinds}]\nscope = [{scopes}]\n"
        );
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "compact config with full enforcement group fits 4096 bytes (len {})",
            doc.len()
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 32);
        assert_eq!(cfg.control().len(), 32);
    }

    fn hundred_byte_names(count: usize) -> String {
        (0..count)
            .map(|i| format!("\"n{i:02}.{}.{}:443\"", "a".repeat(48), "b".repeat(43)))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn full_group_document(count: usize, any_scope: &str, kind: &str, scope: &str) -> String {
        let names = hundred_byte_names(count);
        let kinds = std::iter::repeat_n(format!("\"{kind}\""), count)
            .collect::<Vec<_>>()
            .join(", ");
        let scopes = std::iter::repeat_n(format!("\"{scope}\""), count)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "allowlist = [{names}]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"{any_scope}\"\n[actions]\nkind = [{kinds}]\nscope = [{scopes}]\n"
        )
    }

    #[test]
    fn flare_connection_32_hundred_byte_names_are_rejected_oversized() {
        let doc = full_group_document(32, "connection", "flare_only", "connection");
        assert!(
            doc.len() > CONFIG_DOC_LIMIT,
            "the longer spelling's measured total is {}",
            doc.len()
        );
        let err = parse_config_document(&doc).expect_err("oversized doc must be rejected");
        assert!(
            matches!(&err, ConfigError::OversizedDocument { got, limit } if *limit == CONFIG_DOC_LIMIT && *got == doc.len()),
            "expected OversizedDocument for {} bytes, got {err:?}",
            doc.len()
        );
    }

    #[test]
    fn flare_connection_29_hundred_byte_names_fit_and_parse() {
        let doc = full_group_document(29, "connection", "flare_only", "connection");
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "29-name longer spelling fits 4096 bytes (len {})",
            doc.len()
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 29);
        assert_eq!(cfg.control().len(), 29);
    }

    #[test]
    fn compact_32_hundred_byte_names_measured_total_is_4084() {
        let doc = full_group_document(32, "all", "block", "domain");
        assert_eq!(
            doc.len(),
            4084,
            "compact 32-name measured total with resolver key"
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 32);
        assert_eq!(cfg.control().len(), 32);
    }

    #[test]
    fn compact_32_hundred_byte_names_with_ip_fqdn_resolver_measured_total_is_4103() {
        let doc = full_group_document(32, "all", "block", "domain").replacen(
            "resolver = [\"1.1.1.1\"]",
            "resolver = [\"1.1.1.1#cloudflare-dns.com\"]",
            1,
        );
        assert_eq!(
            doc.len(),
            4103,
            "tight 32×100-byte compact form with a single realistic IP#fqdn entry exceeds 4096 B"
        );
        assert!(
            doc.len() > CONFIG_DOC_LIMIT,
            "a realistic IP#fqdn entry cannot fit the max-count/max-name compact form"
        );
        let err = parse_config_document(&doc).expect_err("oversized doc must be rejected");
        assert!(
            matches!(&err, ConfigError::OversizedDocument { got, limit } if *limit == CONFIG_DOC_LIMIT && *got == doc.len()),
            "expected OversizedDocument for {} bytes, got {err:?}",
            doc.len()
        );
    }

    #[test]
    fn compact_32_hundred_byte_names_with_pinned_resolver_measured_total_is_4151() {
        // base64("A".repeat(32)) = 43 unpadded chars (AQ...), the strict SPKI
        // pin grammar's canonical value; `#dns.google#pin-sha256=` plus the
        // 44-char padded digest costs 67 bytes over a bare-IP entry and cannot
        // fit the max-count/max-name compact form.
        let b64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let doc = full_group_document(32, "all", "block", "domain").replacen(
            "resolver = [\"1.1.1.1\"]",
            &format!("resolver = [\"1.1.1.1#dns.google#pin-sha256={b64}\"]"),
            1,
        );
        assert_eq!(
            doc.len(),
            4151,
            "tight 32×100-byte compact form with a pinned DoT entry exceeds 4096 B"
        );
        assert!(
            doc.len() > CONFIG_DOC_LIMIT,
            "a pinned DoT entry cannot fit the max-count/max-name compact form"
        );
        let err = parse_config_document(&doc).expect_err("oversized doc must be rejected");
        assert!(
            matches!(&err, ConfigError::OversizedDocument { got, limit } if *limit == CONFIG_DOC_LIMIT && *got == doc.len()),
            "expected OversizedDocument for {} bytes, got {err:?}",
            doc.len()
        );
    }

    #[test]
    fn flare_connection_32_hundred_byte_names_measured_total_is_4379() {
        let doc = full_group_document(32, "connection", "flare_only", "connection");
        assert_eq!(
            doc.len(),
            4379,
            "longer 32-name measured total with resolver key"
        );
        let err = parse_config_document(&doc).expect_err("oversized doc must be rejected");
        assert!(
            matches!(&err, ConfigError::OversizedDocument { got, limit } if *limit == CONFIG_DOC_LIMIT && *got == 4379),
            "expected OversizedDocument for 4379 bytes, got {err:?}"
        );
    }

    #[test]
    fn flare_connection_29_hundred_byte_names_measured_total_is_3983() {
        let doc = full_group_document(29, "connection", "flare_only", "connection");
        assert_eq!(
            doc.len(),
            3983,
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

    fn doc(resolver: &str, names: &str) -> String {
        format!(
            "allowlist = [{names}]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = {resolver}\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\"]\nscope = [\"connection\"]\n",
            names = if names.is_empty() {
                "\"a.example:443\""
            } else {
                names
            }
        )
    }

    fn valid_doc(resolver: &str) -> String {
        doc(resolver, "")
    }

    #[test]
    fn resolver_key_is_mandatory() {
        let d = "allowlist = [\"a.example:443\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\"]\nscope = [\"connection\"]\n";
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
        let six = "allowlist = [\"a.example:443\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\", \"8.8.8.8\", \"9.9.9.9\", \"208.67.222.222\", \"94.140.14.14\", \"1.0.0.1\"]\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\"]\nscope = [\"connection\"]\n";
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
            "padded doc is exactly the 4 KiB limit"
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
    fn resolver_ip_fqdn_example_fits_4kib() {
        let resolver = "[\"1.1.1.1#cloudflare-dns.com\", \"8.8.8.8#dns.google\", \"9.9.9.9#dns.quad9.net\", \"208.67.222.222#dns.opendns.com\", \"94.140.14.14#dns.adguard.com\"]";
        let example = format!(
            "allowlist = [\"api.github.com:443\", \"example.com:443\", \"www.example.net:443\"]\nlisten = \"127.0.0.1:8080\"\nstartup_unresolved_allowance = 0\nresolver = {resolver}\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\", \"flare_only\", \"flare_only\"]\nscope = [\"connection\", \"connection\", \"connection\"]\n"
        );
        assert_eq!(
            example.len(),
            437,
            "4 KiB re-measure: the V37 golden-path IP#fqdn example config is serializer-pinned at 437 B"
        );
        assert!(
            example.len() <= CONFIG_DOC_LIMIT,
            "IP#fqdn example fits 4096 B (len {})",
            example.len()
        );
        let cfg = parse_config_document(&example).expect("example parses within the 4 KiB bound");
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
        let mut names = Vec::with_capacity(32);
        for i in 0..32usize {
            names.push(format!("\"{i}.{}.{}:443\"", "a".repeat(48), "b".repeat(43)));
        }
        let kinds = std::iter::repeat_n("\"block\"", 32)
            .collect::<Vec<_>>()
            .join(", ");
        let scopes = std::iter::repeat_n("\"domain\"", 32)
            .collect::<Vec<_>>()
            .join(", ");
        let compact = format!(
            "allowlist = [{}]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\", \"8.8.8.8\", \"1.0.0.1\", \"8.8.4.4\"]\n[any_illegal]\nscope = \"all\"\n[actions]\nkind = [{kinds}]\nscope = [{scopes}]\n",
            names.join(", ")
        );
        assert!(
            compact.len() <= CONFIG_DOC_LIMIT,
            "compact 32-name fit form with resolver must still be documented; measured {}",
            compact.len()
        );
    }
}

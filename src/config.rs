use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::num::NonZeroU64;
use std::ops::Range;

use crate::enforcement::action::{
    ActionKind, AnyIllegalControl, Control, ControlTable, PerFqdnControl, Scope,
};
use crate::enforcement::state::AllScopeGate;
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
        let name = validate_bare_name(host)?;
        if is_ip_literal_shape(name.as_bytes()) {
            return Err("allowlist entry is an IP literal; use a DNS hostname".into());
        }
        let port = parse_config_port(port)?;
        Ok(Fqdn { name, port })
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

/// Validates one DNS label against the shared lowercase-ASCII rules: non-empty,
/// ≤63 bytes, no leading/trailing hyphen, only `[a-z0-9-]`.
fn validate_label(label: &str) -> Result<(), String> {
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
    Ok(())
}

/// Validates a bare DNS name (no port): normalizes a single trailing dot,
/// enforces the shared label rules and the `FQDN_MAX_LEN` byte bound, and
/// returns the normalized name. Shape-specific checks (IP-literal rejection,
/// minimum label count) are the caller's responsibility.
fn validate_bare_name(name: &str) -> Result<String, String> {
    let name = normalize_trailing_dot(name)?;
    if name.is_empty() {
        return Err("empty hostname".into());
    }
    if name.len() > FQDN_MAX_LEN {
        return Err("hostname exceeds 253 bytes".into());
    }
    for label in name.split('.') {
        validate_label(label)?;
    }
    Ok(name.to_owned())
}

/// Parses one declared `cname_bailiwick` suffix: a bare DNS zone name (no
/// port) validated by the shared bare-name rules plus the F-07 requirement of
/// at least two labels (a one-label suffix like `com` cannot be a safe zone).
fn parse_cname_bailiwick_suffix(input: &str) -> Result<String, String> {
    let name = validate_bare_name(input)?;
    if is_ip_literal_shape(name.as_bytes()) {
        return Err("declared suffix is an IP literal; use a DNS zone name".into());
    }
    if name.split('.').count() < 2 {
        return Err("declared suffix must have at least 2 labels".into());
    }
    Ok(name)
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
    cname_bailiwick: Vec<Vec<String>>,
    all_scope_gate: AllScopeGate,
}

impl Config {
    #[must_use]
    pub const fn allowlist(&self) -> &Allowlist {
        &self.allowlist
    }

    /// Per-allowlist declared `cname_bailiwick` suffixes, parallel to
    /// `allowlist()` order. An entry's list is empty when the key is absent or
    /// `[]` (the self-only default). The flat union across entries is derived
    /// in the DNS layer, not here.
    #[must_use]
    pub fn cname_bailiwick(&self) -> &[Vec<String>] {
        &self.cname_bailiwick
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

    /// The operator-configurable SP-001 All-scope gate (threshold/window);
    /// defaults to the trigger-happy (1, 900) bar when `[all_scope_gate]` is
    /// absent.
    #[must_use]
    pub const fn all_scope_gate(&self) -> AllScopeGate {
        self.all_scope_gate
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
    InvalidCnameBailiwick {
        name: String,
        reason: String,
    },
    CnameBailiwickTooMany {
        got: usize,
    },
    DivergentCnameBailiwick {
        name: String,
        reason: String,
    },
    InvalidListen {
        value: String,
    },
    AllowanceOutOfRange {
        value: i64,
    },
    AnyIllegalScopeInvalid {
        key: String,
        value: String,
    },
    AllScopeGateOutOfRange {
        key: String,
        value: i64,
    },
    InvalidScope {
        key: String,
        value: String,
    },
    UnknownAction {
        key: String,
        value: String,
    },
    ActionTarpitDeferred {
        key: String,
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
    MixedResolverTrust,
}

impl ConfigError {
    #[must_use]
    pub const fn exit_status(&self) -> i32 {
        78
    }
}

impl fmt::Display for ConfigError {
    #[expect(
        clippy::too_many_lines,
        reason = "exhaustive one-line Display arm per ConfigError variant kept inline"
    )]
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
            ConfigError::InvalidCnameBailiwick { name, reason } => {
                write!(f, "config invalid cname_bailiwick {name:?}: {reason}")
            }
            ConfigError::CnameBailiwickTooMany { got } => {
                write!(
                    f,
                    "config cname_bailiwick suffix total {got} exceeds the {ALLOWLIST_MAX} ceiling"
                )
            }
            ConfigError::DivergentCnameBailiwick { name, reason } => {
                write!(
                    f,
                    "config divergent cname_bailiwick on same bare name {name:?} across ports: {reason}"
                )
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
            ConfigError::AnyIllegalScopeInvalid { key, value } => write!(
                f,
                "config {key} value {value:?} invalid: any_illegal scope is connection or all only"
            ),
            ConfigError::AllScopeGateOutOfRange { key, value } => {
                write!(
                    f,
                    "config {key} {value} out of range: must be an integer >= 1"
                )
            }
            ConfigError::InvalidScope { key, value } => write!(
                f,
                "config {key} value {value:?} invalid: expected connection, fqdn, or all"
            ),
            ConfigError::UnknownAction { key, value } => write!(
                f,
                "config {key} value {value:?}: unknown action (expected ignore, notify, or block)"
            ),
            ConfigError::ActionTarpitDeferred { key } => write!(
                f,
                "config {key} is \"tarpit\": Tarpit pacing is deferred and is not accepted as an operational setting (docs/alumina-proxy.md tripwire amendment)"
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
            ConfigError::MixedResolverTrust => write!(
                f,
                "config resolver array mixes plain (bare-IP) and DoT (IP#fqdn) entries; a resolver set must be trust-homogeneous"
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
            "listen"
                | "startup_unresolved_allowance"
                | "resolver"
                | "any_illegal"
                | "allowed_fqdn"
                | "all_scope_gate"
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
    let parsed = build_allowlist(table)?;
    let listen = parse_listen(&listen)?;
    let allowance = u8::try_from(allowance)
        .map_err(|_| ConfigError::AllowanceOutOfRange { value: allowance })?;
    if allowance as usize >= parsed.allowlist.len() {
        return Err(ConfigError::AllowanceOutOfRange {
            value: allowance.into(),
        });
    }
    let any_controls = parse_any_illegal(any_illegal)?;
    let control = ControlTable::new(any_controls, &parsed.early_data, &parsed.ja4)
        .expect("build_allowlist validated 1..=32 entries, so ControlTable::new cannot fail");
    let resolver = build_resolver_set(table)?;
    let all_scope_gate = parse_all_scope_gate(table)?;
    Ok(Config {
        allowlist: parsed.allowlist,
        listen,
        startup_unresolved_allowance: allowance,
        control,
        resolver,
        cname_bailiwick: parsed.bailiwicks,
        all_scope_gate,
    })
}

fn build_resolver_set(table: &toml::Table) -> Result<ResolverSet, ConfigError> {
    let values = require_string_list(table, "resolver")?;
    if values.is_empty() || values.len() > MAX_RESOLVERS {
        return Err(ConfigError::ResolverCountOutOfRange { got: values.len() });
    }
    let mut nameservers = Vec::with_capacity(values.len());
    let mut plain_trust: Option<bool> = None;
    for (index, value) in values.iter().enumerate() {
        let ns = resolver::select(value).map_err(|_| ConfigError::InvalidResolver {
            index,
            value: value.clone(),
        })?;
        let is_plain = ns.is_ip_only();
        if let Some(existing) = plain_trust {
            if existing != is_plain {
                return Err(ConfigError::MixedResolverTrust);
            }
        } else {
            plain_trust = Some(is_plain);
        }
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

/// Parses the mandatory `[any_illegal]` per-control table: exactly the four
/// `connect_parse`/`host_not_allowlisted`/`tls_profile`/`ech` controls, each a
/// `{ action, scope }` table with `action` in `notify|block` (tarpit reserved)
/// and `scope` in `connection|all`. Every control key is mandatory; a missing
/// key is a startup failure, never a silent default.
fn parse_any_illegal(
    value: &toml::Value,
) -> Result<[Control; AnyIllegalControl::COUNT], ConfigError> {
    let toml::Value::Table(table) = value else {
        return Err(ConfigError::WrongType(
            "any_illegal: expected table".to_owned(),
        ));
    };
    let mut controls = [Control::new(ActionKind::Block, Scope::All); AnyIllegalControl::COUNT];
    let mut seen = [false; AnyIllegalControl::COUNT];
    for (key, value) in table {
        let control = match key.as_str() {
            "connect_parse" => AnyIllegalControl::ConnectParse,
            "host_not_allowlisted" => AnyIllegalControl::HostNotAllowlisted,
            "tls_profile" => AnyIllegalControl::TlsProfile,
            "ech" => AnyIllegalControl::Ech,
            other => return Err(ConfigError::UnknownKey(format!("any_illegal.{other}"))),
        };
        controls[control as usize] = parse_any_illegal_control(value, key)?;
        seen[control as usize] = true;
    }
    for (control, name) in [
        (AnyIllegalControl::ConnectParse, "connect_parse"),
        (
            AnyIllegalControl::HostNotAllowlisted,
            "host_not_allowlisted",
        ),
        (AnyIllegalControl::TlsProfile, "tls_profile"),
        (AnyIllegalControl::Ech, "ech"),
    ] {
        if !seen[control as usize] {
            return Err(ConfigError::MissingField(format!("any_illegal.{name}")));
        }
    }
    Ok(controls)
}

/// Parses one `[any_illegal]` control value: a `{ action, scope }` table whose
/// action is `notify|block` (tarpit reserved) and whose scope is
/// `connection|all`.
fn parse_any_illegal_control(value: &toml::Value, key: &str) -> Result<Control, ConfigError> {
    let toml::Value::Table(table) = value else {
        return Err(ConfigError::WrongType(format!(
            "any_illegal.{key}: expected table"
        )));
    };
    for k in table.keys() {
        if !matches!(k.as_str(), "action" | "scope") {
            return Err(ConfigError::UnknownKey(format!("any_illegal.{key}.{k}")));
        }
    }
    let prefix = format!("any_illegal.{key}");
    let action = require_string(table, "action")
        .map_err(|err| prefix_group_error(&prefix, "action", err))?;
    let scope =
        require_string(table, "scope").map_err(|err| prefix_group_error(&prefix, "scope", err))?;
    let kind = parse_action_kind(&action, &format!("{prefix}.action"))?;
    let scope = parse_any_illegal_scope(&scope, &format!("{prefix}.scope"))?;
    Ok(Control::new(kind, scope))
}

/// The shared action-keyword parser: `notify|block` are legal, `tarpit` is the
/// reserved deferred keyword rejected with its explicit diagnostic, and any
/// other token is an unknown action.
fn parse_action_kind(action: &str, key: &str) -> Result<ActionKind, ConfigError> {
    match action {
        "notify" => Ok(ActionKind::Notify),
        "block" => Ok(ActionKind::Block),
        "tarpit" => Err(ConfigError::ActionTarpitDeferred {
            key: key.to_owned(),
        }),
        other => Err(ConfigError::UnknownAction {
            key: key.to_owned(),
            value: other.to_owned(),
        }),
    }
}

/// The `any_illegal` scope grammar: `connection|all` only. A per-FQDN scope
/// literal (`fqdn`) is invalid here because an unattributable violation cannot
/// mark a configured domain.
fn parse_any_illegal_scope(scope: &str, key: &str) -> Result<Scope, ConfigError> {
    match scope {
        "connection" => Ok(Scope::Connection),
        "all" => Ok(Scope::All),
        other => Err(ConfigError::AnyIllegalScopeInvalid {
            key: key.to_owned(),
            value: other.to_owned(),
        }),
    }
}

/// The per-FQDN scope grammar: `connection|fqdn|all` (the `fqdn` literal is
/// the user spelling of the spec's `domain` scope).
fn parse_per_fqdn_scope(scope: &str, key: &str) -> Result<Scope, ConfigError> {
    match scope {
        "connection" => Ok(Scope::Connection),
        "fqdn" => Ok(Scope::Domain),
        "all" => Ok(Scope::All),
        other => Err(ConfigError::InvalidScope {
            key: key.to_owned(),
            value: other.to_owned(),
        }),
    }
}

/// Parses the optional `[all_scope_gate]` table: `threshold` (1..=`u32::MAX`)
/// and `window_secs` (1..=`u64::MAX`), both mandatory when the section is
/// present (all-or-nothing). An absent section yields the trigger-happy
/// default (threshold 1, window 900s).
fn parse_all_scope_gate(table: &toml::Table) -> Result<AllScopeGate, ConfigError> {
    let Some(value) = table.get("all_scope_gate") else {
        return Ok(AllScopeGate::default());
    };
    let toml::Value::Table(section) = value else {
        return Err(ConfigError::WrongType(
            "all_scope_gate: expected table".to_owned(),
        ));
    };
    for key in section.keys() {
        if !matches!(key.as_str(), "threshold" | "window_secs") {
            return Err(ConfigError::UnknownKey(format!("all_scope_gate.{key}")));
        }
    }
    let prefix = "all_scope_gate";
    let threshold = require_integer(section, "threshold")
        .map_err(|err| prefix_group_error(prefix, "threshold", err))?;
    let threshold = u32::try_from(threshold).map_err(|_| ConfigError::AllScopeGateOutOfRange {
        key: "all_scope_gate.threshold".to_owned(),
        value: threshold,
    })?;
    let threshold = NonZeroU32::new(threshold).ok_or(ConfigError::AllScopeGateOutOfRange {
        key: "all_scope_gate.threshold".to_owned(),
        value: 0,
    })?;
    let window_secs = require_integer(section, "window_secs")
        .map_err(|err| prefix_group_error(prefix, "window_secs", err))?;
    let window_secs =
        u64::try_from(window_secs).map_err(|_| ConfigError::AllScopeGateOutOfRange {
            key: "all_scope_gate.window_secs".to_owned(),
            value: window_secs,
        })?;
    let window_secs = NonZeroU64::new(window_secs).ok_or(ConfigError::AllScopeGateOutOfRange {
        key: "all_scope_gate.window_secs".to_owned(),
        value: 0,
    })?;
    Ok(AllScopeGate::new(threshold, window_secs))
}

fn parse_allowed_fqdn_table(
    value: &toml::Value,
    fqdn_key: &str,
) -> Result<(PerFqdnControl, PerFqdnControl, Vec<String>), ConfigError> {
    let toml::Value::Table(table) = value else {
        return Err(ConfigError::WrongType(format!(
            "allowed_fqdn.{fqdn_key}: expected table"
        )));
    };
    let mut early_data = None;
    let mut ja4 = None;
    let mut bailiwick = Vec::new();
    for key in table.keys() {
        match key.as_str() {
            "early_data" => {
                early_data = Some(table.get(key).expect("key present in iteration"));
            }
            "ja4" => {
                ja4 = Some(table.get(key).expect("key present in iteration"));
            }
            "cname_bailiwick" => {
                bailiwick = parse_cname_bailiwick(table, fqdn_key)?;
            }
            _ => {
                return Err(ConfigError::UnknownKey(format!(
                    "allowed_fqdn.{fqdn_key}.{key}"
                )));
            }
        }
    }
    let early_data = early_data
        .ok_or_else(|| ConfigError::MissingField(format!("allowed_fqdn.{fqdn_key}.early_data")))?;
    let ja4 =
        ja4.ok_or_else(|| ConfigError::MissingField(format!("allowed_fqdn.{fqdn_key}.ja4")))?;
    let early = parse_per_fqdn_control(early_data, fqdn_key, "early_data")?;
    let j4 = parse_per_fqdn_control(ja4, fqdn_key, "ja4")?;
    Ok((early, j4, bailiwick))
}

fn parse_cname_bailiwick(table: &toml::Table, fqdn_key: &str) -> Result<Vec<String>, ConfigError> {
    let value = table
        .get("cname_bailiwick")
        .expect("key present in iteration");
    let toml::Value::Array(items) = value else {
        return Err(ConfigError::WrongType(format!(
            "allowed_fqdn.{fqdn_key}.cname_bailiwick: expected array of strings"
        )));
    };
    let mut suffixes = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let toml::Value::String(name) = item else {
            return Err(ConfigError::WrongType(format!(
                "allowed_fqdn.{fqdn_key}.cname_bailiwick[{index}]: expected string, got {}",
                value_kind(item)
            )));
        };
        let normalized = parse_cname_bailiwick_suffix(name).map_err(|reason| {
            ConfigError::InvalidCnameBailiwick {
                name: name.clone(),
                reason,
            }
        })?;
        suffixes.push(normalized);
    }
    Ok(suffixes)
}

/// Parses one per-FQDN control value (`early_data` or `ja4`): either the bare
/// `"ignore"` opt-out shorthand or a `{ action, scope }` table with `action`
/// in `notify|block` (tarpit reserved) and `scope` in `connection|fqdn|all`.
fn parse_per_fqdn_control(
    value: &toml::Value,
    fqdn_key: &str,
    control_key: &str,
) -> Result<PerFqdnControl, ConfigError> {
    let prefix = format!("allowed_fqdn.{fqdn_key}.{control_key}");
    match value {
        toml::Value::String(action) => match action.as_str() {
            "ignore" => Ok(PerFqdnControl::ignore()),
            "tarpit" => Err(ConfigError::ActionTarpitDeferred { key: prefix }),
            other => Err(ConfigError::UnknownAction {
                key: prefix,
                value: other.to_owned(),
            }),
        },
        toml::Value::Table(table) => {
            for key in table.keys() {
                if !matches!(key.as_str(), "action" | "scope") {
                    return Err(ConfigError::UnknownKey(format!("{prefix}.{key}")));
                }
            }
            let action = require_string(table, "action")
                .map_err(|err| prefix_group_error(&prefix, "action", err))?;
            let scope = require_string(table, "scope")
                .map_err(|err| prefix_group_error(&prefix, "scope", err))?;
            let kind = parse_action_kind(&action, &format!("{prefix}.action"))?;
            let scope = parse_per_fqdn_scope(&scope, &format!("{prefix}.scope"))?;
            Ok(PerFqdnControl::control(kind, scope))
        }
        _ => Err(ConfigError::WrongType(format!(
            "{prefix}: expected \"ignore\" or an action table"
        ))),
    }
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

/// Parsed `[allowed_fqdn]` table: ordered entries plus their per-entry
/// `early_data`/`ja4` controls and `cname_bailiwick` suffix lists, kept
/// parallel to allowlist order.
struct ParsedAllowlist {
    allowlist: Allowlist,
    early_data: Vec<PerFqdnControl>,
    ja4: Vec<PerFqdnControl>,
    bailiwicks: Vec<Vec<String>>,
}

fn build_allowlist(table: &toml::Table) -> Result<ParsedAllowlist, ConfigError> {
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
    let mut bailiwick_by_name: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut allowlist = Vec::with_capacity(entries.len());
    let mut early_data = Vec::with_capacity(entries.len());
    let mut ja4 = Vec::with_capacity(entries.len());
    let mut bailiwicks = Vec::with_capacity(entries.len());
    let mut total_suffixes = 0usize;
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
        let (early, j4, suffixes) = parse_allowed_fqdn_table(value, key)?;
        // Same bare name on different ports collapses to the first entry's
        // suffix list at runtime (covers_for first-match position), so every
        // same-bare-name entry must declare byte-identical lists — any
        // divergence would silently narrow or widen the effective bailiwick.
        if let Some(prior) = bailiwick_by_name.get(fqdn.as_str()) {
            if prior != &suffixes {
                return Err(ConfigError::DivergentCnameBailiwick {
                    name: fqdn.as_str().to_owned(),
                    reason: format!(
                        "{}:{} declares cname_bailiwick {suffixes:?} but the first same-bare-name entry declares {prior:?}",
                        fqdn.as_str(),
                        fqdn.port()
                    ),
                });
            }
        } else {
            bailiwick_by_name.insert(fqdn.as_str().to_owned(), suffixes.clone());
        }
        total_suffixes += suffixes.len();
        if total_suffixes > ALLOWLIST_MAX {
            return Err(ConfigError::CnameBailiwickTooMany {
                got: total_suffixes,
            });
        }
        allowlist.push(fqdn);
        early_data.push(early);
        ja4.push(j4);
        bailiwicks.push(suffixes);
    }
    Ok(ParsedAllowlist {
        allowlist: Allowlist(allowlist),
        early_data,
        ja4,
        bailiwicks,
    })
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
    use crate::enforcement::action::{ActionKind, AnyIllegalControl, PerFqdnControl, Scope};
    use std::fmt::Write as _;
    use std::num::{NonZeroU32, NonZeroU64};

    fn base() -> String {
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n"
            .to_owned()
    }

    /// Builds the `[any_illegal]` block from `(control, action, scope)` triples.
    fn any_illegal(controls: &[(&str, &str, &str)]) -> String {
        let mut s = String::from("[any_illegal]\n");
        for (key, action, scope) in controls {
            let _ = writeln!(
                s,
                "{key} = {{ action = \"{action}\", scope = \"{scope}\" }}"
            );
        }
        s
    }

    /// The canonical four-control `[any_illegal]` block used by most tests.
    fn any_illegal_default() -> String {
        any_illegal(&[
            ("connect_parse", "notify", "connection"),
            ("host_not_allowlisted", "block", "all"),
            ("tls_profile", "block", "all"),
            ("ech", "block", "connection"),
        ])
    }

    /// A per-FQDN entry with raw `early_data`/`ja4` value spellings.
    fn entry(key: &str, early: &str, ja4: &str) -> String {
        format!("[allowed_fqdn.\"{key}\"]\nearly_data = {early}\nja4 = {ja4}\n")
    }

    /// A per-FQDN entry with table-form controls.
    fn entry_table(
        key: &str,
        early_action: &str,
        early_scope: &str,
        ja4_action: &str,
        ja4_scope: &str,
    ) -> String {
        entry(
            key,
            &format!("{{ action = \"{early_action}\", scope = \"{early_scope}\" }}"),
            &format!("{{ action = \"{ja4_action}\", scope = \"{ja4_scope}\" }}"),
        )
    }

    fn group(entries: &str) -> String {
        format!("{}{}{}", base(), any_illegal_default(), entries)
    }

    /// A valid full document (base + default enforcement + one allowlist entry)
    /// with an optional `[all_scope_gate]` section appended.
    fn gate_doc(gate_section: &str) -> String {
        format!(
            "{}{}",
            group(&entry_table(
                "a.example.org:443",
                "notify",
                "connection",
                "notify",
                "connection",
            )),
            gate_section
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
        let doc = group(&format!(
            "{}{}",
            entry_table(
                "sub.example.org:443",
                "notify",
                "connection",
                "block",
                "fqdn"
            ),
            entry(
                "other.example.org:443",
                "{ action = \"block\", scope = \"all\" }",
                "\"ignore\""
            ),
        ));
        let cfg = parse_config_document(&doc).expect("valid enforcement config");
        let control = cfg.control();
        assert_eq!(control.len(), 2);
        assert_eq!(
            control.any_illegal(AnyIllegalControl::ConnectParse),
            Control::new(ActionKind::Notify, Scope::Connection)
        );
        assert_eq!(
            control.any_illegal(AnyIllegalControl::HostNotAllowlisted),
            Control::new(ActionKind::Block, Scope::All)
        );
        assert_eq!(
            control.any_illegal(AnyIllegalControl::TlsProfile),
            Control::new(ActionKind::Block, Scope::All)
        );
        assert_eq!(
            control.any_illegal(AnyIllegalControl::Ech),
            Control::new(ActionKind::Block, Scope::Connection)
        );
        let first = control.ordinal(0).expect("ordinal");
        assert_eq!(
            control.early_data(first),
            Some(PerFqdnControl::control(ActionKind::Block, Scope::All))
        );
        assert_eq!(control.ja4(first), Some(PerFqdnControl::Ignore));
        let second = control.ordinal(1).expect("ordinal");
        assert_eq!(
            control.early_data(second),
            Some(PerFqdnControl::control(
                ActionKind::Notify,
                Scope::Connection
            ))
        );
        assert_eq!(
            control.ja4(second),
            Some(PerFqdnControl::control(ActionKind::Block, Scope::Domain))
        );
    }

    #[test]
    fn any_illegal_control_selects_its_own_action() {
        let doc = format!(
            "{}{}{}",
            base(),
            any_illegal(&[
                ("connect_parse", "notify", "connection"),
                ("host_not_allowlisted", "block", "all"),
                ("tls_profile", "notify", "all"),
                ("ech", "block", "connection"),
            ]),
            entry_table(
                "a.example:443",
                "notify",
                "connection",
                "notify",
                "connection"
            ),
        );
        let cfg = parse_config_document(&doc).expect("per-control any_illegal valid");
        let control = cfg.control();
        assert_eq!(
            control.any_illegal(AnyIllegalControl::ConnectParse),
            Control::new(ActionKind::Notify, Scope::Connection)
        );
        assert_eq!(
            control.any_illegal(AnyIllegalControl::HostNotAllowlisted),
            Control::new(ActionKind::Block, Scope::All)
        );
        assert_eq!(
            control.any_illegal(AnyIllegalControl::TlsProfile),
            Control::new(ActionKind::Notify, Scope::All)
        );
        assert_eq!(
            control.any_illegal(AnyIllegalControl::Ech),
            Control::new(ActionKind::Block, Scope::Connection)
        );
    }

    #[test]
    fn rejects_missing_any_illegal_control_key() {
        for missing in [
            "connect_parse",
            "host_not_allowlisted",
            "tls_profile",
            "ech",
        ] {
            let controls: Vec<(&str, &str, &str)> = [
                ("connect_parse", "notify", "connection"),
                ("host_not_allowlisted", "block", "all"),
                ("tls_profile", "block", "all"),
                ("ech", "block", "connection"),
            ]
            .into_iter()
            .filter(|(key, _, _)| *key != missing)
            .collect();
            let doc = format!(
                "{}{}{}",
                base(),
                any_illegal(&controls),
                entry_table(
                    "a.example:443",
                    "notify",
                    "connection",
                    "notify",
                    "connection"
                ),
            );
            let err = parse_config_document(&doc).unwrap_err();
            assert!(
                matches!(&err, ConfigError::MissingField(f) if f == &format!("any_illegal.{missing}")),
                "expected MissingField(any_illegal.{missing}), got {err:?}"
            );
            assert_eq!(err.exit_status(), 78, "missing control key must exit 78");
        }
    }

    #[test]
    fn rejects_unknown_any_illegal_control_key() {
        let doc = format!(
            "{}{}{}",
            base(),
            any_illegal(&[
                ("connect_parse", "notify", "connection"),
                ("host_not_allowlisted", "block", "all"),
                ("tls_profile", "block", "all"),
                ("ech", "block", "connection"),
                ("early_data", "notify", "connection"),
            ]),
            entry_table(
                "a.example:443",
                "notify",
                "connection",
                "notify",
                "connection"
            ),
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::UnknownKey(k) if k == "any_illegal.early_data"),
            "expected UnknownKey(any_illegal.early_data), got {err:?}"
        );
    }

    #[test]
    fn accepts_any_illegal_connection_scope() {
        let doc = format!(
            "{}{}{}",
            base(),
            any_illegal(&[
                ("connect_parse", "block", "connection"),
                ("host_not_allowlisted", "block", "connection"),
                ("tls_profile", "block", "connection"),
                ("ech", "block", "connection"),
            ]),
            entry_table(
                "a.example:443",
                "notify",
                "connection",
                "notify",
                "connection"
            ),
        );
        let cfg = parse_config_document(&doc).expect("connection scope valid");
        assert_eq!(
            cfg.control().any_illegal(AnyIllegalControl::Ech),
            Control::new(ActionKind::Block, Scope::Connection)
        );
    }

    #[test]
    fn rejects_any_illegal_domain_scope() {
        let doc = format!(
            "{}{}{}",
            base(),
            any_illegal(&[
                ("connect_parse", "notify", "connection"),
                ("host_not_allowlisted", "block", "domain"),
                ("tls_profile", "block", "all"),
                ("ech", "block", "connection"),
            ]),
            entry_table(
                "a.example:443",
                "notify",
                "connection",
                "notify",
                "connection"
            ),
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::AnyIllegalScopeInvalid { key, value }
                if key == "any_illegal.host_not_allowlisted.scope" && value == "domain"),
            "expected AnyIllegalScopeInvalid for the domain literal, got {err:?}"
        );
        assert_eq!(
            err.exit_status(),
            78,
            "invalid any_illegal scope must exit 78"
        );
    }

    #[test]
    fn rejects_any_illegal_fqdn_scope() {
        let doc = format!(
            "{}{}{}",
            base(),
            any_illegal(&[
                ("connect_parse", "notify", "connection"),
                ("host_not_allowlisted", "block", "fqdn"),
                ("tls_profile", "block", "all"),
                ("ech", "block", "connection"),
            ]),
            entry_table(
                "a.example:443",
                "notify",
                "connection",
                "notify",
                "connection"
            ),
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::AnyIllegalScopeInvalid { key, value }
                if key == "any_illegal.host_not_allowlisted.scope" && value == "fqdn"),
            "the fqdn literal is per-FQDN only, got {err:?}"
        );
    }

    #[test]
    fn rejects_any_illegal_unknown_scope() {
        let doc = format!(
            "{}{}{}",
            base(),
            any_illegal(&[
                ("connect_parse", "notify", "connection"),
                ("host_not_allowlisted", "block", "wired"),
                ("tls_profile", "block", "all"),
                ("ech", "block", "connection"),
            ]),
            entry_table(
                "a.example:443",
                "notify",
                "connection",
                "notify",
                "connection"
            ),
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::AnyIllegalScopeInvalid { .. }),
            "expected AnyIllegalScopeInvalid, got {err:?}"
        );
    }

    #[test]
    fn rejects_any_illegal_tarpit_with_deferred_diagnostic() {
        let doc = format!(
            "{}{}{}",
            base(),
            any_illegal(&[
                ("connect_parse", "tarpit", "connection"),
                ("host_not_allowlisted", "block", "all"),
                ("tls_profile", "block", "all"),
                ("ech", "block", "connection"),
            ]),
            entry_table(
                "a.example:443",
                "notify",
                "connection",
                "notify",
                "connection"
            ),
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::ActionTarpitDeferred { key } if key == "any_illegal.connect_parse.action"),
            "expected ActionTarpitDeferred on the any_illegal surface, got {err:?}"
        );
        assert_eq!(err.exit_status(), 78, "reserved tarpit must exit 78");
    }

    #[test]
    fn rejects_any_illegal_unknown_action() {
        let doc = format!(
            "{}{}{}",
            base(),
            any_illegal(&[
                ("connect_parse", "peek", "connection"),
                ("host_not_allowlisted", "block", "all"),
                ("tls_profile", "block", "all"),
                ("ech", "block", "connection"),
            ]),
            entry_table(
                "a.example:443",
                "notify",
                "connection",
                "notify",
                "connection"
            ),
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::UnknownAction { key, .. } if key == "any_illegal.connect_parse.action"),
            "expected UnknownAction on the any_illegal surface, got {err:?}"
        );
    }

    #[test]
    fn rejects_missing_early_data() {
        let doc = format!(
            "{}{}[allowed_fqdn.\"a.example:443\"]\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n",
            base(),
            any_illegal_default()
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::MissingField(f) if f == "allowed_fqdn.a.example:443.early_data"),
            "expected MissingField(early_data), got {err:?}"
        );
    }

    #[test]
    fn rejects_missing_ja4() {
        let doc = format!(
            "{}{}[allowed_fqdn.\"a.example:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\n",
            base(),
            any_illegal_default()
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::MissingField(f) if f == "allowed_fqdn.a.example:443.ja4"),
            "expected MissingField(ja4), got {err:?}"
        );
        assert_eq!(err.exit_status(), 78, "missing mandatory ja4 must exit 78");
    }

    #[test]
    fn accepts_ignore_shorthand_on_both_per_fqdn_controls() {
        let doc = group(&entry("a.example:443", "\"ignore\"", "\"ignore\""));
        let cfg = parse_config_document(&doc).expect("ignore shorthand valid");
        let control = cfg.control();
        let ordinal = control.ordinal(0).expect("ordinal");
        assert_eq!(control.early_data(ordinal), Some(PerFqdnControl::Ignore));
        assert_eq!(control.ja4(ordinal), Some(PerFqdnControl::Ignore));
    }

    #[test]
    fn rejects_per_fqdn_tarpit_with_deferred_diagnostic() {
        for (early, ja4) in [
            (
                "{ action = \"tarpit\", scope = \"connection\" }",
                "{ action = \"notify\", scope = \"connection\" }",
            ),
            (
                "{ action = \"notify\", scope = \"connection\" }",
                "{ action = \"tarpit\", scope = \"connection\" }",
            ),
        ] {
            let doc = group(&entry("a.example:443", early, ja4));
            let err = parse_config_document(&doc).unwrap_err();
            assert!(
                matches!(&err, ConfigError::ActionTarpitDeferred { .. }),
                "expected ActionTarpitDeferred, got {err:?}"
            );
            assert_eq!(err.exit_status(), 78, "reserved tarpit must exit 78");
        }
    }

    #[test]
    fn rejects_unknown_action_kind() {
        let doc = group(&entry(
            "a.example:443",
            "{ action = \"peek\", scope = \"connection\" }",
            "{ action = \"notify\", scope = \"connection\" }",
        ));
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::UnknownAction { key, .. } if key == "allowed_fqdn.a.example:443.early_data.action"),
            "expected UnknownAction, got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_per_fqdn_scope() {
        let doc = group(&entry(
            "a.example:443",
            "{ action = \"block\", scope = \"wire\" }",
            "{ action = \"notify\", scope = \"connection\" }",
        ));
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidScope { .. }),
            "expected InvalidScope, got {err:?}"
        );
    }

    #[test]
    fn accepts_per_fqdn_fqdn_scope_for_block() {
        let doc = group(&entry_table(
            "a.example:443",
            "block",
            "fqdn",
            "block",
            "fqdn",
        ));
        let cfg = parse_config_document(&doc).expect("fqdn scope valid per-FQDN");
        let control = cfg.control();
        let ordinal = control.ordinal(0).expect("ordinal");
        assert_eq!(
            control.early_data(ordinal),
            Some(PerFqdnControl::control(ActionKind::Block, Scope::Domain))
        );
        assert_eq!(
            control.ja4(ordinal),
            Some(PerFqdnControl::control(ActionKind::Block, Scope::Domain))
        );
    }

    #[test]
    fn accepts_per_fqdn_all_scope_for_block() {
        let doc = group(&entry_table(
            "a.example:443",
            "block",
            "all",
            "block",
            "all",
        ));
        let cfg = parse_config_document(&doc).expect("all scope valid per-FQDN");
        let control = cfg.control();
        let ordinal = control.ordinal(0).expect("ordinal");
        assert_eq!(
            control.early_data(ordinal),
            Some(PerFqdnControl::control(ActionKind::Block, Scope::All))
        );
    }

    #[test]
    fn rejects_unknown_key_in_allowed_fqdn_table() {
        let doc = group(&format!(
            "{}{}bogus = \"x\"\n",
            entry_table(
                "a.example:443",
                "notify",
                "connection",
                "notify",
                "connection"
            ),
            ""
        ));
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::UnknownKey(k) if k == "allowed_fqdn.a.example:443.bogus"),
            "expected UnknownKey, got {err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_after_normalization() {
        let doc = group(&format!(
            "{}{}",
            entry_table(
                "a.example:443",
                "notify",
                "connection",
                "notify",
                "connection"
            ),
            entry_table(
                "a.example.:443",
                "notify",
                "connection",
                "notify",
                "connection"
            ),
        ));
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::DuplicateAllowlistName(n) if n == "a.example:443"),
            "expected DuplicateAllowlistName, got {err:?}"
        );
    }

    #[test]
    fn rejects_more_than_32_tables() {
        let mut doc = format!("{}{}", base(), any_illegal_default());
        for i in 0..33 {
            let _ = write!(
                doc,
                "[allowed_fqdn.\"n{i:02}.example:443\"]\nearly_data = {{ action = \"block\", scope = \"fqdn\" }}\nja4 = {{ action = \"block\", scope = \"fqdn\" }}\n"
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
        let doc = format!("{}{}[allowed_fqdn]\n", base(), any_illegal_default());
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::AllowlistEmpty),
            "expected AllowlistEmpty, got {err:?}"
        );
    }

    #[test]
    fn rejects_absent_allowlist() {
        let doc = format!("{}{}", base(), any_illegal_default());
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::AllowlistEmpty),
            "expected AllowlistEmpty, got {err:?}"
        );
    }

    #[test]
    fn rejects_bare_fqdn_key() {
        let doc = group(&entry(
            "a.example",
            "{ action = \"notify\", scope = \"connection\" }",
            "{ action = \"notify\", scope = \"connection\" }",
        ));
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

    fn keyed_document(count: usize, action: &str, scope: &str) -> String {
        let mut doc = format!("{}{}", base(), any_illegal_default());
        for i in 0..count {
            let _ = write!(
                doc,
                "[allowed_fqdn.\"{}\"]\nearly_data = {{ action = \"{action}\", scope = \"{scope}\" }}\nja4 = {{ action = \"{action}\", scope = \"{scope}\" }}\n",
                hundred_byte_name(i)
            );
        }
        doc
    }

    #[test]
    fn compact_32_names_with_group_fit_16kib() {
        let doc = keyed_document(32, "block", "connection");
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
    fn notify_32_hundred_byte_names_fit_and_parse() {
        let doc = keyed_document(32, "notify", "connection");
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
    fn notify_29_hundred_byte_names_fit_and_parse() {
        let doc = keyed_document(29, "notify", "connection");
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
    fn compact_32_hundred_byte_names_with_ip_fqdn_resolver_fit_16kib() {
        let doc = keyed_document(32, "block", "connection").replacen(
            "resolver = [\"1.1.1.1\"]",
            "resolver = [\"1.1.1.1#cloudflare-dns.com\"]",
            1,
        );
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "32×100-byte compact form with a single realistic IP#fqdn entry fits (len {})",
            doc.len()
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 32);
        assert_eq!(cfg.control().len(), 32);
    }

    #[test]
    fn compact_32_hundred_byte_names_with_pinned_resolver_fit_16kib() {
        let b64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let doc = keyed_document(32, "block", "connection").replacen(
            "resolver = [\"1.1.1.1\"]",
            &format!("resolver = [\"1.1.1.1#dns.google#pin-sha256={b64}\"]"),
            1,
        );
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "32×100-byte compact form with a pinned DoT entry fits (len {})",
            doc.len()
        );
        let cfg = parse_config_document(&doc).expect("fits and parses");
        assert_eq!(cfg.allowlist().len(), 32);
        assert_eq!(cfg.control().len(), 32);
    }

    #[test]
    fn all_scope_gate_absent_defaults() {
        let cfg =
            parse_config_document(&gate_doc("")).expect("valid config without all_scope_gate");
        assert_eq!(cfg.all_scope_gate(), AllScopeGate::default());
        assert_eq!(cfg.all_scope_gate().threshold(), 1);
        assert_eq!(cfg.all_scope_gate().window_secs(), 900);
    }

    #[test]
    fn all_scope_gate_custom_values() {
        let doc = gate_doc("[all_scope_gate]\nthreshold = 5\nwindow_secs = 300\n");
        let cfg = parse_config_document(&doc).expect("valid all_scope_gate section");
        assert_eq!(
            cfg.all_scope_gate(),
            AllScopeGate::new(
                NonZeroU32::new(5).expect("5 is nonzero"),
                NonZeroU64::new(300).expect("300 is nonzero"),
            )
        );
        assert_eq!(cfg.all_scope_gate().threshold(), 5);
        assert_eq!(cfg.all_scope_gate().window_secs(), 300);
    }

    #[test]
    fn all_scope_gate_threshold_zero_rejected() {
        let doc = gate_doc("[all_scope_gate]\nthreshold = 0\nwindow_secs = 300\n");
        let err = parse_config_document(&doc).expect_err("threshold 0 must be rejected");
        assert!(
            matches!(&err, ConfigError::AllScopeGateOutOfRange { key, value } if key == "all_scope_gate.threshold" && *value == 0),
            "expected AllScopeGateOutOfRange(threshold=0), got {err:?}"
        );
        assert_eq!(err.exit_status(), 78, "AllScopeGateOutOfRange must exit 78");
    }

    #[test]
    fn all_scope_gate_threshold_negative_rejected() {
        let doc = gate_doc("[all_scope_gate]\nthreshold = -1\nwindow_secs = 300\n");
        let err = parse_config_document(&doc).expect_err("negative threshold must be rejected");
        assert!(
            matches!(&err, ConfigError::AllScopeGateOutOfRange { key, value } if key == "all_scope_gate.threshold" && *value == -1),
            "expected AllScopeGateOutOfRange(threshold=-1), got {err:?}"
        );
        assert_eq!(err.exit_status(), 78, "AllScopeGateOutOfRange must exit 78");
    }

    #[test]
    fn all_scope_gate_window_zero_rejected() {
        let doc = gate_doc("[all_scope_gate]\nthreshold = 5\nwindow_secs = 0\n");
        let err = parse_config_document(&doc).expect_err("window_secs 0 must be rejected");
        assert!(
            matches!(&err, ConfigError::AllScopeGateOutOfRange { key, value } if key == "all_scope_gate.window_secs" && *value == 0),
            "expected AllScopeGateOutOfRange(window_secs=0), got {err:?}"
        );
        assert_eq!(err.exit_status(), 78, "AllScopeGateOutOfRange must exit 78");
    }

    #[test]
    fn all_scope_gate_unknown_key_rejected() {
        let doc = gate_doc("[all_scope_gate]\nthreshold = 5\nwindow_secs = 300\nbogus = 1\n");
        let err =
            parse_config_document(&doc).expect_err("unknown all_scope_gate key must be rejected");
        assert!(
            matches!(&err, ConfigError::UnknownKey(k) if k == "all_scope_gate.bogus"),
            "expected UnknownKey(all_scope_gate.bogus), got {err:?}"
        );
    }

    #[test]
    fn all_scope_gate_wrong_type_rejected() {
        let doc = gate_doc("[all_scope_gate]\nthreshold = \"five\"\nwindow_secs = 300\n");
        let err = parse_config_document(&doc).expect_err("string threshold must be rejected");
        assert!(
            matches!(&err, ConfigError::WrongType(_)),
            "expected WrongType, got {err:?}"
        );
    }

    #[test]
    fn all_scope_gate_missing_key_rejected() {
        let doc = gate_doc("[all_scope_gate]\nwindow_secs = 300\n");
        let err = parse_config_document(&doc).expect_err("missing threshold must be rejected");
        assert!(
            matches!(&err, ConfigError::MissingField(f) if f == "all_scope_gate.threshold"),
            "expected MissingField(all_scope_gate.threshold), got {err:?}"
        );
    }

    #[test]
    fn all_scope_gate_not_a_table_rejected() {
        let doc = format!(
            "{}all_scope_gate = 5\n{}{}",
            base(),
            any_illegal_default(),
            entry_table(
                "a.example.org:443",
                "notify",
                "connection",
                "notify",
                "connection",
            ),
        );
        let err =
            parse_config_document(&doc).expect_err("non-table all_scope_gate must be rejected");
        assert!(
            matches!(&err, ConfigError::WrongType(_)),
            "expected WrongType, got {err:?}"
        );
    }
}
#[cfg(test)]
mod cname_bailiwick_config_tests {
    use super::*;

    fn base() -> String {
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n"
            .to_owned()
    }

    fn any_illegal() -> String {
        "[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n"
            .to_owned()
    }

    fn group(entries: &str) -> String {
        format!("{}{}{}", base(), any_illegal(), entries)
    }

    fn entry(key: &str) -> String {
        format!(
            "[allowed_fqdn.\"{key}\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
        )
    }

    fn entry_with_bailiwick(key: &str, suffixes: &str) -> String {
        format!(
            "[allowed_fqdn.\"{key}\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ncname_bailiwick = {suffixes}\n"
        )
    }

    #[test]
    fn accepts_optional_cname_bailiwick_and_exposes_per_entry_lists() {
        let doc = group(&format!(
            "{}{}",
            entry_with_bailiwick(
                "www.example.com:443",
                "[\"example.com\", \"cdn.example.com\"]"
            ),
            entry("other.test:443"),
        ));
        let cfg = parse_config_document(&doc).expect("valid config with cname_bailiwick");
        assert_eq!(
            cfg.allowlist().get(0).expect("entry").as_str(),
            "other.test"
        );
        assert_eq!(
            cfg.allowlist().get(1).expect("entry").as_str(),
            "www.example.com"
        );
        assert_eq!(
            cfg.cname_bailiwick(),
            &[
                Vec::<String>::new(),
                vec!["example.com".to_owned(), "cdn.example.com".to_owned()]
            ]
        );
    }

    #[test]
    fn absent_cname_bailiwick_defaults_to_self_only() {
        let doc = group(&entry("a.example:443"));
        let cfg = parse_config_document(&doc).expect("valid config");
        assert_eq!(cfg.cname_bailiwick(), &[Vec::<String>::new()]);
    }

    #[test]
    fn empty_cname_bailiwick_array_defaults_to_self_only() {
        let doc = group(&entry_with_bailiwick("a.example:443", "[]"));
        let cfg = parse_config_document(&doc).expect("valid config");
        assert_eq!(cfg.cname_bailiwick(), &[Vec::<String>::new()]);
    }

    #[test]
    fn normalizes_single_trailing_dot_in_declared_suffix() {
        let doc = group(&entry_with_bailiwick(
            "www.example.com:443",
            "[\"example.com.\"]",
        ));
        let cfg = parse_config_document(&doc).expect("single trailing dot normalized");
        assert_eq!(cfg.cname_bailiwick(), &[vec!["example.com".to_owned()]]);
    }

    #[test]
    fn early_data_only_configs_parse_identically() {
        let doc = group(&format!(
            "{}{}",
            entry("a.example:443"),
            entry("b.example:443")
        ));
        let cfg = parse_config_document(&doc).expect("backward-compatible");
        assert_eq!(cfg.allowlist().len(), 2);
        assert_eq!(cfg.control().len(), 2);
        assert_eq!(
            cfg.cname_bailiwick(),
            &[Vec::<String>::new(), Vec::<String>::new()]
        );
    }

    #[test]
    fn rejects_unknown_key_besides_early_data_ja4_and_cname_bailiwick() {
        let doc = group(
            "[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ncname_bailiwick = [\"example.com\"]\nbogus = \"x\"\n",
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::UnknownKey(k) if k == "allowed_fqdn.a.example:443.bogus"),
            "expected UnknownKey, got {err:?}"
        );
    }

    #[test]
    fn rejects_more_than_32_total_declared_suffixes() {
        let suffixes: Vec<String> = (0..33).map(|i| format!("cdn{i}.example.com")).collect();
        let list = format!("[\"{}\"]", suffixes.join("\", \""));
        let doc = group(&entry_with_bailiwick("www.example.com:443", &list));
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(err, ConfigError::CnameBailiwickTooMany { got: 33 }),
            "expected CnameBailiwickTooMany, got {err:?}"
        );
    }

    #[test]
    fn accepts_exactly_32_total_declared_suffixes() {
        let suffixes: Vec<String> = (0..32).map(|i| format!("cdn{i}.example.com")).collect();
        let list = format!("[\"{}\"]", suffixes.join("\", \""));
        let doc = group(&entry_with_bailiwick("www.example.com:443", &list));
        let cfg = parse_config_document(&doc).expect("32 total suffixes is the budget ceiling");
        assert_eq!(cfg.cname_bailiwick()[0].len(), 32);
    }

    #[test]
    fn accepts_same_bare_name_different_ports_with_identical_bailiwick() {
        let doc = group(&format!(
            "{}{}",
            entry_with_bailiwick("www.example.com:443", "[\"example.com\"]"),
            entry_with_bailiwick("www.example.com:8443", "[\"example.com\"]"),
        ));
        let cfg = parse_config_document(&doc).expect("identical bailiwick lists accepted");
        assert_eq!(cfg.allowlist().len(), 2);
        assert_eq!(
            cfg.cname_bailiwick(),
            &[
                vec!["example.com".to_owned()],
                vec!["example.com".to_owned()]
            ]
        );
    }

    #[test]
    fn rejects_same_bare_name_different_ports_with_divergent_bailiwick() {
        let doc = group(&format!(
            "{}{}",
            entry_with_bailiwick("www.example.com:443", "[\"example.com\"]"),
            entry("www.example.com:8443"),
        ));
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::DivergentCnameBailiwick { name, .. } if name == "www.example.com"),
            "expected DivergentCnameBailiwick, got {err:?}"
        );
    }

    #[test]
    fn rejects_same_bare_name_different_ports_with_divergent_bailiwick_reverse() {
        let doc = group(&format!(
            "{}{}",
            entry("www.example.com:443"),
            entry_with_bailiwick("www.example.com:8443", "[\"example.com\"]"),
        ));
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::DivergentCnameBailiwick { name, .. } if name == "www.example.com"),
            "expected DivergentCnameBailiwick, got {err:?}"
        );
    }

    #[test]
    fn rejects_invalid_declared_suffixes() {
        for (suffix, reason_fragment) in [
            ("", "empty"),
            ("com", "at least 2 labels"),
            ("-bad.example.com", "hyphen"),
            ("bad-.example.com", "hyphen"),
            ("double..dot.example.com", "empty label"),
            ("under_score.example.com", "not lowercase ASCII"),
            ("Bücher.example.com", "not lowercase ASCII"),
            ("1.2.3.4", "IP literal"),
            ("example.com..", "trailing dots"),
        ] {
            let doc = group(&entry_with_bailiwick(
                "www.example.com:443",
                &format!("[\"{suffix}\"]"),
            ));
            let err = parse_config_document(&doc).unwrap_err();
            assert!(
                matches!(&err, ConfigError::InvalidCnameBailiwick { name, reason }
                    if name == suffix && reason.contains(reason_fragment)),
                "expected InvalidCnameBailiwick for {suffix:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_overlong_labels_and_names() {
        let long_label = format!("{}.example.com", "a".repeat(64));
        let doc = group(&entry_with_bailiwick(
            "www.example.com:443",
            &format!("[\"{long_label}\"]"),
        ));
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidCnameBailiwick { reason, .. }
                if reason.contains("63")),
            "expected label-over-63 rejection, got {err:?}"
        );

        let long_name = format!(
            "{}.{}.{}.{}.{}",
            "a".repeat(60),
            "b".repeat(60),
            "c".repeat(60),
            "d".repeat(60),
            "e".repeat(60),
        );
        let doc = group(&entry_with_bailiwick(
            "www.example.com:443",
            &format!("[\"{long_name}\"]"),
        ));
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidCnameBailiwick { reason, .. }
                if reason.contains("253")),
            "expected over-253-byte rejection, got {err:?}"
        );
    }

    #[test]
    fn rejects_wrong_type_for_cname_bailiwick() {
        let doc = group(
            "[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ncname_bailiwick = \"example.com\"\n",
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::WrongType(m) if m.contains("cname_bailiwick")),
            "expected WrongType, got {err:?}"
        );
    }

    #[test]
    fn rejects_non_string_suffix_element() {
        let doc = group(
            "[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ncname_bailiwick = [\"example.com\", 42]\n",
        );
        let err = parse_config_document(&doc).unwrap_err();
        assert!(
            matches!(&err, ConfigError::WrongType(m) if m.contains("cname_bailiwick[1]")),
            "expected WrongType for element 1, got {err:?}"
        );
    }
}

#[cfg(test)]
mod resolver_config_tests {
    use super::*;
    use std::fmt::Write as _;

    fn valid_doc(resolver: &str) -> String {
        format!(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = {resolver}\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"a.example:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
        )
    }

    #[test]
    fn resolver_key_is_mandatory() {
        let d = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n";
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
        let six = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\", \"8.8.8.8\", \"9.9.9.9\", \"208.67.222.222\", \"94.140.14.14\", \"1.0.0.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n";
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
    fn resolver_mixed_plain_and_dot_trust_rejected() {
        for value in [
            "[\"1.1.1.1\", \"9.9.9.9#dns.quad9.net\"]",
            "[\"9.9.9.9#dns.quad9.net\", \"1.1.1.1\"]",
        ] {
            let err = parse_config_document(&valid_doc(value))
                .expect_err("mixed plain/DoT resolver array must be rejected");
            assert!(
                matches!(&err, ConfigError::MixedResolverTrust),
                "mixed resolver array must be MixedResolverTrust, got {err:?}"
            );
            assert_eq!(err.exit_status(), 78, "MixedResolverTrust must exit 78");
        }
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
            "listen = \"127.0.0.1:8080\"\nstartup_unresolved_allowance = 0\nresolver = {resolver}\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"api.github.com:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n[allowed_fqdn.\"example.com:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n[allowed_fqdn.\"www.example.net:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
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
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\", \"8.8.8.8\", \"1.0.0.1\", \"8.8.4.4\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n",
        );
        for i in 0..32usize {
            let _ = write!(
                compact,
                "[allowed_fqdn.\"{i}.{}.{}:443\"]\nearly_data = {{ action = \"block\", scope = \"fqdn\" }}\nja4 = {{ action = \"block\", scope = \"fqdn\" }}\n",
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
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"sub.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n[allowed_fqdn.\"other.test:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n",
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
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:8443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n",
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

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::num::NonZeroU64;
use std::ops::Range;

use crate::dns::cache::evidence::AssuranceRequirement;
use crate::dns::resolver::MAX_RESOLVERS;
use crate::dns::resolver::{self, ResolverSet};
use crate::enforcement::action::{
    ActionKind, AnyIllegalControl, Control, ControlTable, PerFqdnControl, Scope,
};
use crate::enforcement::state::{AllScopeGate, GateSet};
use crate::names::hostname::{FQDN_MAX_LEN, FixedHostname};

pub const CONFIG_DOC_LIMIT: usize = 16384;
pub const ALLOWLIST_MIN: usize = 1;
pub const ALLOWLIST_MAX: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct Fqdn {
    name: FixedHostname,
    port: u16,
}

/// Preserves the historical `Fqdn { name: "...", port: 443 }` debug shape.
impl std::fmt::Debug for Fqdn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fqdn")
            .field("name", &self.as_str())
            .field("port", &self.port)
            .finish()
    }
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
        if crate::names::rules::is_ip_literal_shape(name.as_bytes()) {
            return Err("allowlist entry is an IP literal; use a DNS hostname".into());
        }
        let port = parse_config_port(port)?;
        let payload = FixedHostname::normalize(name.as_bytes()).ok_or_else(|| {
            "internal: validated allowlist hostname rejected by FixedHostname::normalize"
                .to_string()
        })?;
        Ok(Fqdn {
            name: payload,
            port,
        })
    }

    /// The normalized bare `<fqdn>` (no port, no trailing dot): the key used
    /// for DNS cache entries, queries, and logs, so `NameIndex(u8)` stays
    /// keyed by the bare name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.name.as_str()
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
    use crate::names::rules::LabelFault::{BadHyphen, DisallowedByte, Empty, TooLong};
    crate::names::rules::classify_label(label.as_bytes()).map_err(|fault| match fault {
        Empty => "empty label".into(),
        TooLong => "label exceeds 63 bytes".into(),
        BadHyphen => "label starts or ends with hyphen".into(),
        DisallowedByte => format!("label {label:?} not lowercase ASCII [a-z0-9-]"),
    })
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
    if crate::names::rules::is_ip_literal_shape(name.as_bytes()) {
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

#[cfg(test)]
mod fqdn_tests;

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
    entry_requirements: [AssuranceRequirement; ALLOWLIST_MAX],
    listen: ListenAddr,
    startup_unresolved_allowance: u8,
    control: ControlTable,
    resolver: ResolverSet,
    cname_bailiwick: Vec<Vec<String>>,
    gates: GateSet,
}

#[cfg(test)]
impl Config {
    /// Tests only: a copy with the per-entry requirement at `index`
    /// replaced, inhabiting the valid invariant. Does not construct the
    /// selector variants on the production parse path.
    pub(crate) fn with_entry_requirement(
        mut self,
        index: usize,
        requirement: AssuranceRequirement,
    ) -> Self {
        self.entry_requirements[index] = requirement;
        self
    }
}

impl Config {
    #[must_use]
    pub const fn allowlist(&self) -> &Allowlist {
        &self.allowlist
    }

    /// Per-allowlist assurance requirement at `index`, parallel to
    /// `allowlist()` order; only `0..allowlist().len()` is ever read.
    pub(crate) const fn entry_requirement(&self, index: usize) -> AssuranceRequirement {
        self.entry_requirements[index]
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

    /// The per-class SP-001 All-scope gates (threshold/window per class);
    /// each defaults to threshold 1 / window 900s when its section is absent.
    #[must_use]
    pub const fn gates(&self) -> GateSet {
        self.gates
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
    EarlyDataBlockScopeInvalid {
        scope: String,
    },
    EarlyDataGateRejected,
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
    InvalidRecursivePolicy {
        value: String,
    },
    RecursiveDeclaresWeakResolver {
        index: usize,
        value: String,
    },
    InvalidDnsAssurance {
        key: String,
        reason: String,
    },
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
            ConfigError::EarlyDataBlockScopeInvalid { scope } => write!(
                f,
                "config early_data action \"block\" scope {scope:?} invalid: Block scope is connection only"
            ),
            ConfigError::EarlyDataGateRejected => write!(
                f,
                "config [early_data] gate section cannot arm: its all-scope block action is unreachable by construction (the only legal early_data block scope is connection; see docs/alumina-proxy.md F-02 close)"
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
            ConfigError::InvalidRecursivePolicy { value } => write!(
                f,
                "config recursive_dnssec_policy {value:?} invalid: only \"root_validating_no_stale\" is supported"
            ),
            ConfigError::RecursiveDeclaresWeakResolver { index, value } => write!(
                f,
                "config recursive_dnssec_policy requires a strict IP#fqdn#pin-sha256= entry for every resolver; resolver[{0}] {value:?} is weak",
                index + 1
            ),
            ConfigError::InvalidDnsAssurance { key, reason } => write!(f, "config {key}: {reason}"),
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

#[expect(
    clippy::expect_used,
    reason = "build_allowlist already validated 1..=32 entries, so ControlTable::new cannot fail"
)]
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
                | "bad_handshake"
                | "illegal_fqdn"
                | "early_data"
                | "ja4"
                | "recursive_dnssec_policy"
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
    let declared_root_validating =
        resolver.recursion_policy() == resolver::RecursionPolicy::RootValidatingNoStale;
    for (index, fqdn) in parsed.allowlist.iter().enumerate() {
        if parsed.requirements[index] != AssuranceRequirement::ResolverTrusted
            && !declared_root_validating
        {
            return Err(ConfigError::InvalidDnsAssurance {
                key: format!("{}:{}", fqdn.as_str(), fqdn.port()),
                reason: "requires recursive_dnssec_policy = \"root_validating_no_stale\" and every resolver strict".to_owned(),
            });
        }
    }
    let gates = {
        if table.get("early_data").is_some() {
            return Err(ConfigError::EarlyDataGateRejected);
        }
        GateSet::new(
            parse_gate_section(table, "bad_handshake")?,
            parse_gate_section(table, "illegal_fqdn")?,
            AllScopeGate::default(),
            parse_gate_section(table, "ja4")?,
        )
    };
    Ok(Config {
        allowlist: parsed.allowlist,
        entry_requirements: parsed.requirements,
        listen,
        startup_unresolved_allowance: allowance,
        control,
        resolver,
        cname_bailiwick: parsed.bailiwicks,
        gates,
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
    let set = resolver::ResolverSet::from_slice(&nameservers).ok_or(
        ConfigError::ResolverCountOutOfRange {
            got: nameservers.len(),
        },
    )?;
    if table.get("recursive_dnssec_policy").is_none() {
        return Ok(set);
    }
    let policy = require_string(table, "recursive_dnssec_policy")?;
    if policy != resolver::RECURSIVE_DNSSEC_POLICY_ROOT_VALIDATING_NO_STALE {
        return Err(ConfigError::InvalidRecursivePolicy { value: policy });
    }
    set.declared_root_validating_no_stale().map_err(|index| {
        ConfigError::RecursiveDeclaresWeakResolver {
            index,
            value: values[index].clone(),
        }
    })
}

/// Parses the mandatory `[any_illegal]` per-control table: exactly the four
/// `connect_parse`/`host_not_allowlisted`/`tls_profile`/`ech` controls, each a
/// `{ action, scope }` table with `action` in `notify|block` (tarpit reserved)
/// and `scope` in `connection|all`. Every control key is mandatory; a missing
/// key is a startup failure, never a silent default.
const ANY_ILLEGAL_CONTROL_KEYS: [(AnyIllegalControl, &str); AnyIllegalControl::COUNT] = [
    (AnyIllegalControl::ConnectParse, "connect_parse"),
    (
        AnyIllegalControl::HostNotAllowlisted,
        "host_not_allowlisted",
    ),
    (AnyIllegalControl::TlsProfile, "tls_profile"),
    (AnyIllegalControl::Ech, "ech"),
];

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
        let control = match ANY_ILLEGAL_CONTROL_KEYS
            .iter()
            .find(|(_, name)| *name == key.as_str())
        {
            Some((control, _)) => *control,
            None => return Err(ConfigError::UnknownKey(format!("any_illegal.{key}"))),
        };
        controls[control as usize] = parse_any_illegal_control(value, key)?;
        seen[control as usize] = true;
    }
    for (control, name) in ANY_ILLEGAL_CONTROL_KEYS {
        if !seen[control as usize] {
            return Err(ConfigError::MissingField(format!("any_illegal.{name}")));
        }
    }
    Ok(controls)
}

/// Reads the shared `{ action, scope }` control-table syntax used by the
/// `any_illegal` controls and the per-FQDN `early_data`/`ja4` table form:
/// rejects unrecognized keys, then requires the `action` string and the
/// `scope` string, then parses the action keyword. Scope grammar and each
/// consumer's policy are applied after this returns.
fn read_action_scope_table(
    table: &toml::Table,
    prefix: &str,
) -> Result<(ActionKind, String), ConfigError> {
    for key in table.keys() {
        if !matches!(key.as_str(), "action" | "scope") {
            return Err(ConfigError::UnknownKey(format!("{prefix}.{key}")));
        }
    }
    let action =
        require_string(table, "action").map_err(|err| prefix_group_error(prefix, "action", err))?;
    let scope =
        require_string(table, "scope").map_err(|err| prefix_group_error(prefix, "scope", err))?;
    let kind = parse_action_kind(&action, &format!("{prefix}.action"))?;
    Ok((kind, scope))
}

/// Parses one `[any_illegal]` control value: a `{ action, scope }` table whose
/// action is `notify|block` (tarpit reserved) and whose scope is
/// `connection|all`.
fn parse_any_illegal_control(value: &toml::Value, key: &str) -> Result<Control, ConfigError> {
    let prefix = format!("any_illegal.{key}");
    let toml::Value::Table(table) = value else {
        return Err(ConfigError::WrongType(format!("{prefix}: expected table")));
    };
    let (kind, scope_text) = read_action_scope_table(table, &prefix)?;
    let scope = parse_any_illegal_scope(&scope_text, &format!("{prefix}.scope"))?;
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

/// Parses one optional per-class gate table (e.g. `[bad_handshake]`):
/// `threshold` (1..=`u32::MAX`) and `window_secs` (1..=`u64::MAX`), both
/// mandatory when the section is present (all-or-nothing). An absent section
/// yields the default (threshold 1, window 900s).
fn parse_gate_section(table: &toml::Table, name: &str) -> Result<AllScopeGate, ConfigError> {
    let Some(value) = table.get(name) else {
        return Ok(AllScopeGate::default());
    };
    let toml::Value::Table(section) = value else {
        return Err(ConfigError::WrongType(format!("{name}: expected table")));
    };
    for key in section.keys() {
        if !matches!(key.as_str(), "threshold" | "window_secs") {
            return Err(ConfigError::UnknownKey(format!("{name}.{key}")));
        }
    }
    let threshold = require_integer(section, "threshold")
        .map_err(|err| prefix_group_error(name, "threshold", err))?;
    let threshold = u32::try_from(threshold).map_err(|_| ConfigError::AllScopeGateOutOfRange {
        key: format!("{name}.threshold"),
        value: threshold,
    })?;
    let threshold = NonZeroU32::new(threshold).ok_or(ConfigError::AllScopeGateOutOfRange {
        key: format!("{name}.threshold"),
        value: 0,
    })?;
    let window_secs = require_integer(section, "window_secs")
        .map_err(|err| prefix_group_error(name, "window_secs", err))?;
    let window_secs =
        u64::try_from(window_secs).map_err(|_| ConfigError::AllScopeGateOutOfRange {
            key: format!("{name}.window_secs"),
            value: window_secs,
        })?;
    let window_secs = NonZeroU64::new(window_secs).ok_or(ConfigError::AllScopeGateOutOfRange {
        key: format!("{name}.window_secs"),
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
    for (key, value) in table.iter() {
        match key.as_str() {
            "early_data" => {
                early_data = Some(value);
            }
            "ja4" => {
                ja4 = Some(value);
            }
            "cname_bailiwick" => {
                bailiwick = parse_cname_bailiwick(value, fqdn_key)?;
            }
            "dns_assurance" => {}
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

fn parse_dns_assurance(
    value: &toml::Value,
    fqdn_key: &str,
) -> Result<AssuranceRequirement, ConfigError> {
    let toml::Value::String(selector) = value else {
        return Err(ConfigError::WrongType(format!(
            "allowed_fqdn.{fqdn_key}.dns_assurance: expected string"
        )));
    };
    match selector.as_str() {
        "resolver_trusted" => Ok(AssuranceRequirement::ResolverTrusted),
        "resolver_authenticated" => Ok(AssuranceRequirement::ResolverAuthenticated),
        "delegated_dnssec" => Ok(AssuranceRequirement::DelegatedDnssec),
        _ => Err(ConfigError::InvalidDnsAssurance {
            key: format!("allowed_fqdn.{fqdn_key}.dns_assurance"),
            reason: format!("unknown dns_assurance selector {selector:?}"),
        }),
    }
}

fn parse_entry_requirement(
    value: &toml::Value,
    fqdn_key: &str,
) -> Result<AssuranceRequirement, ConfigError> {
    let toml::Value::Table(table) = value else {
        return Ok(AssuranceRequirement::ResolverTrusted);
    };
    table
        .get("dns_assurance")
        .map_or(Ok(AssuranceRequirement::ResolverTrusted), |selector| {
            parse_dns_assurance(selector, fqdn_key)
        })
}

fn parse_cname_bailiwick(value: &toml::Value, fqdn_key: &str) -> Result<Vec<String>, ConfigError> {
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
/// For `early_data` the only legal `block` scope is `connection`; `fqdn` and
/// `all` block scopes are invalid configuration (docs F-02 close), so an
/// upstream-sourced early-data signal cannot select a per-domain or
/// process-wide latch. `ja4` keeps the full scope grammar unchanged.
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
            let (kind, scope_text) = read_action_scope_table(table, &prefix)?;
            let scope = parse_per_fqdn_scope(&scope_text, &format!("{prefix}.scope"))?;
            if control_key == "early_data"
                && kind == ActionKind::Block
                && scope != Scope::Connection
            {
                return Err(ConfigError::EarlyDataBlockScopeInvalid { scope: scope_text });
            }
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
    requirements: [AssuranceRequirement; ALLOWLIST_MAX],
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
    let mut requirements = [AssuranceRequirement::ResolverTrusted; ALLOWLIST_MAX];
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
        requirements[allowlist.len()] = parse_entry_requirement(value, key)?;
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
        requirements,
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
mod cname_bailiwick_config_tests;
#[cfg(test)]
mod enforcement_config_tests;

#[cfg(test)]
mod resolver_config_tests;

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

#[cfg(test)]
mod hostname_rules {
    use super::*;

    fn reason(input: &str) -> String {
        Fqdn::parse(input).expect_err(input)
    }

    #[test]
    fn hostname_rules_config_exact_reasons_and_original_spelling() {
        for (input, expected) in [
            (".:443", "empty hostname"),
            ("a..b:443", "empty label"),
            ("-bad.example:443", "label starts or ends with hyphen"),
            (
                "bad_host.example:443",
                "label \"bad_host\" not lowercase ASCII [a-z0-9-]",
            ),
            (
                "1.2.3.4:443",
                "allowlist entry is an IP literal; use a DNS hostname",
            ),
            ("example.org..:443", "multiple trailing dots"),
        ] {
            assert_eq!(reason(input), expected, "FQDN reason for {input:?}");
        }
        assert_eq!(
            reason(&format!("{}.example:443", "a".repeat(64))),
            "label exceeds 63 bytes"
        );
        let displayed = ConfigError::InvalidFqdn {
            name: "A.BAD.:443".to_owned(),
            reason: reason("A.BAD.:443"),
        }
        .to_string();
        assert_eq!(
            displayed,
            "config invalid FQDN \"A.BAD.:443\": label \"A\" not lowercase ASCII [a-z0-9-]"
        );
    }

    #[test]
    fn hostname_rules_config_first_error_precedence() {
        let hyphen_long = format!("-{}.example:443", "a".repeat(63));
        let over = format!("{0}.{0}.{0}.{1}:443", "a".repeat(63), "Z".repeat(62));
        for (input, expected) in [
            (hyphen_long.as_str(), "label exceeds 63 bytes"),
            ("-_b.example:443", "label starts or ends with hyphen"),
            ("good.-_b.example:443", "label starts or ends with hyphen"),
            (
                "bad_.-x.example:443",
                "label \"bad_\" not lowercase ASCII [a-z0-9-]",
            ),
            (over.as_str(), "hostname exceeds 253 bytes"),
        ] {
            assert_eq!(reason(input), expected, "precedence for {input:?}");
        }
        let ok = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "c".repeat(61));
        assert_eq!(ok.len(), 253);
        assert!(
            Fqdn::parse(&format!("{ok}.:443")).is_ok(),
            "253 name plus trailing dot accepted"
        );
    }

    #[test]
    fn hostname_rules_cname_exact_reasons_and_precedence() {
        for (input, expected) in [
            (
                "1.2.3.4",
                "declared suffix is an IP literal; use a DNS zone name",
            ),
            (
                "123",
                "declared suffix is an IP literal; use a DNS zone name",
            ),
            ("com", "declared suffix must have at least 2 labels"),
        ] {
            assert_eq!(
                parse_cname_bailiwick_suffix(input).expect_err(input),
                expected
            );
        }
    }
}

#[cfg(test)]
impl Config {
    pub(crate) fn with_kernel_assigned_test_listener(mut self) -> Self {
        self.listen = ListenAddr {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
        };
        self
    }
}

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
    format!(
        "[allowed_fqdn.\"{key}\"]\nearly_data = {early}\nja4 = {ja4}\ndns_assurance = \"resolver_trusted\"\n"
    )
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
/// with optional per-class gate sections appended.
fn gate_doc(gate_sections: &str) -> String {
    format!(
        "{}{}",
        group(&entry_table(
            "a.example.org:443",
            "notify",
            "connection",
            "notify",
            "connection",
        )),
        gate_sections
    )
}

/// The three per-class gate section names in the fixed schema order.
const GATE_SECTIONS: [&str; 3] = ["bad_handshake", "illegal_fqdn", "ja4"];

/// A `[<name>]` gate section with the given `threshold`/`window_secs`.
fn gate_section(name: &str, threshold: u32, window: u64) -> String {
    format!("[{name}]\nthreshold = {threshold}\nwindow_secs = {window}\n")
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
            "{ action = \"block\", scope = \"connection\" }",
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
        Some(PerFqdnControl::control(
            ActionKind::Block,
            Scope::Connection
        ))
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
fn shared_action_scope_table_reports_combined_faults_in_order() {
    let allow = entry_table(
        "a.example:443",
        "notify",
        "connection",
        "notify",
        "connection",
    );
    let rest = "\
host_not_allowlisted = { action = \"block\", scope = \"all\" }
tls_profile = { action = \"block\", scope = \"all\" }
ech = { action = \"block\", scope = \"connection\" }";
    let connect_only = |control: &str| {
        format!(
            "{}{}{}",
            base(),
            format_args!("[any_illegal]\nconnect_parse = {control}\n{rest}\n"),
            allow,
        )
    };
    let with_early = |control: &str| {
        format!(
            "{}{}{}",
            base(),
            any_illegal_default(),
            entry(
                "a.example:443",
                control,
                "{ action = \"notify\", scope = \"connection\" }",
            ),
        )
    };

    let err = parse_config_document(&connect_only(
        "{ action = \"notify\", scope = \"connection\", bogus = 1 }",
    ))
    .unwrap_err();
    assert!(
        matches!(&err, ConfigError::UnknownKey(k) if k == "any_illegal.connect_parse.bogus"),
        "unknown key must precede any missing-field diagnostic: {err:?}"
    );

    let err = parse_config_document(&connect_only("{ scope = \"all\" }")).unwrap_err();
    assert!(
        matches!(&err, ConfigError::MissingField(f) if f == "any_illegal.connect_parse.action"),
        "missing action must precede missing scope: {err:?}"
    );

    let err = parse_config_document(&connect_only("{ action = \"notify\" }")).unwrap_err();
    assert!(
        matches!(&err, ConfigError::MissingField(f) if f == "any_illegal.connect_parse.scope"),
        "missing scope must be reported after a valid action string: {err:?}"
    );

    let err = parse_config_document(&connect_only("{ action = \"wire\", scope = \"fqdn\" }"))
        .unwrap_err();
    assert!(
        matches!(&err, ConfigError::UnknownAction { key, value } if key == "any_illegal.connect_parse.action" && value == "wire"),
        "action keyword must be parsed before the scope grammar: {err:?}"
    );

    for (build, prefix) in [
        (
            &connect_only as &dyn Fn(&str) -> String,
            "any_illegal.connect_parse",
        ),
        (
            &with_early as &dyn Fn(&str) -> String,
            "allowed_fqdn.a.example:443.early_data",
        ),
    ] {
        let err = parse_config_document(&build("{ bogus = 1 }")).unwrap_err();
        assert!(
            matches!(&err, ConfigError::UnknownKey(k) if k == &format!("{prefix}.bogus")),
            "unknown key must precede missing action on {prefix}: {err:?}"
        );
        let err = parse_config_document(&build("{}")).unwrap_err();
        assert!(
            matches!(&err, ConfigError::MissingField(f) if f == &format!("{prefix}.action")),
            "missing action must precede missing scope on {prefix}: {err:?}"
        );
        let err = parse_config_document(&build("{ action = \"wire\" }")).unwrap_err();
        assert!(
            matches!(&err, ConfigError::MissingField(f) if f == &format!("{prefix}.scope")),
            "missing scope must precede unknown action keyword on {prefix}: {err:?}"
        );
    }
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
        "{}{}[allowed_fqdn.\"a.example:443\"]\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n",
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
        "{}{}[allowed_fqdn.\"a.example:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n",
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
fn rejects_early_data_block_fqdn_scope() {
    let doc = group(&entry_table(
        "a.example:443",
        "block",
        "fqdn",
        "notify",
        "connection",
    ));
    let err = parse_config_document(&doc).unwrap_err();
    assert!(
        matches!(&err, ConfigError::EarlyDataBlockScopeInvalid { scope } if scope == "fqdn"),
        "expected EarlyDataBlockScopeInvalid(fqdn), got {err:?}"
    );
    assert_eq!(
        err.exit_status(),
        78,
        "invalid early_data block scope must exit 78"
    );
    assert!(
        err.to_string().contains("scope \"fqdn\""),
        "Display must surface the raw fqdn literal, not an internal scope spelling: {err}"
    );
}

#[test]
fn rejects_early_data_block_all_scope() {
    let doc = group(&entry_table(
        "a.example:443",
        "block",
        "all",
        "notify",
        "connection",
    ));
    let err = parse_config_document(&doc).unwrap_err();
    assert!(
        matches!(&err, ConfigError::EarlyDataBlockScopeInvalid { scope } if scope == "all"),
        "expected EarlyDataBlockScopeInvalid(all), got {err:?}"
    );
    assert_eq!(
        err.exit_status(),
        78,
        "invalid early_data block scope must exit 78"
    );
}

#[test]
fn accepts_notify_fqdn_and_all_early_data_scope() {
    for (scope, typed_scope) in [("fqdn", Scope::Domain), ("all", Scope::All)] {
        let doc = group(&entry_table(
            "a.example:443",
            "notify",
            scope,
            "notify",
            "connection",
        ));
        let cfg = parse_config_document(&doc)
            .expect("notify early_data keeps fqdn/all scopes legal (F-02 narrows block only)");
        let control = cfg.control();
        let ordinal = control.ordinal(0).expect("ordinal");
        assert_eq!(
            control.early_data(ordinal),
            Some(PerFqdnControl::control(ActionKind::Notify, typed_scope)),
            "notify scope {scope} must reach the early_data lane unchanged"
        );
    }
}

#[test]
fn ja4_keeps_fqdn_block_scope_for_block() {
    let doc = group(&entry_table(
        "a.example:443",
        "block",
        "connection",
        "block",
        "fqdn",
    ));
    let cfg = parse_config_document(&doc).expect("ja4 fqdn block scope valid per-FQDN");
    let control = cfg.control();
    let ordinal = control.ordinal(0).expect("ordinal");
    assert_eq!(
        control.early_data(ordinal),
        Some(PerFqdnControl::control(
            ActionKind::Block,
            Scope::Connection
        ))
    );
    assert_eq!(
        control.ja4(ordinal),
        Some(PerFqdnControl::control(ActionKind::Block, Scope::Domain))
    );
}

#[test]
fn ja4_keeps_all_block_scope_for_block() {
    let doc = group(&entry_table(
        "a.example:443",
        "block",
        "connection",
        "block",
        "all",
    ));
    let cfg = parse_config_document(&doc).expect("ja4 all block scope valid per-FQDN");
    let control = cfg.control();
    let ordinal = control.ordinal(0).expect("ordinal");
    assert_eq!(
        control.early_data(ordinal),
        Some(PerFqdnControl::control(
            ActionKind::Block,
            Scope::Connection
        ))
    );
    assert_eq!(
        control.ja4(ordinal),
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
            "[allowed_fqdn.\"n{i:02}.example:443\"]\nearly_data = {{ action = \"block\", scope = \"fqdn\" }}\nja4 = {{ action = \"block\", scope = \"fqdn\" }}\ndns_assurance = \"resolver_trusted\"\n"
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
            "[allowed_fqdn.\"{}\"]\nearly_data = {{ action = \"{action}\", scope = \"{scope}\" }}\nja4 = {{ action = \"{action}\", scope = \"{scope}\" }}\ndns_assurance = \"resolver_trusted\"\n",
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
fn gates_absent_default_all_slots() {
    let cfg = parse_config_document(&gate_doc("")).expect("valid config without gate sections");
    assert_eq!(cfg.gates(), GateSet::default());
    assert_eq!(cfg.gates().bad_handshake().threshold(), 1);
    assert_eq!(cfg.gates().bad_handshake().window_secs(), 900);
    assert_eq!(cfg.gates().illegal_fqdn().threshold(), 1);
    assert_eq!(cfg.gates().illegal_fqdn().window_secs(), 900);
    assert_eq!(cfg.gates().early_data().threshold(), 1);
    assert_eq!(cfg.gates().early_data().window_secs(), 900);
    assert_eq!(cfg.gates().ja4().threshold(), 1);
    assert_eq!(cfg.gates().ja4().window_secs(), 900);
}

#[test]
fn gates_custom_values_per_section() {
    let doc = gate_doc(&format!(
        "{}{}{}",
        gate_section("bad_handshake", 2, 120),
        gate_section("illegal_fqdn", 5, 300),
        gate_section("ja4", 11, 900),
    ));
    let cfg = parse_config_document(&doc).expect("valid three-section gate config");
    assert_eq!(
        cfg.gates().bad_handshake(),
        AllScopeGate::new(
            NonZeroU32::new(2).expect("2 is nonzero"),
            NonZeroU64::new(120).expect("120 is nonzero"),
        )
    );
    assert_eq!(
        cfg.gates().illegal_fqdn(),
        AllScopeGate::new(
            NonZeroU32::new(5).expect("5 is nonzero"),
            NonZeroU64::new(300).expect("300 is nonzero"),
        )
    );
    assert_eq!(
        cfg.gates().ja4(),
        AllScopeGate::new(
            NonZeroU32::new(11).expect("11 is nonzero"),
            NonZeroU64::new(900).expect("900 is nonzero"),
        )
    );
}

#[test]
fn early_data_gate_section_rejected_at_load() {
    let doc = gate_doc(&gate_section("early_data", 7, 600));
    let err = parse_config_document(&doc)
        .expect_err("[early_data] gate section must be rejected at load (exit 78)");
    assert!(
        matches!(err, ConfigError::EarlyDataGateRejected),
        "expected EarlyDataGateRejected, got {err:?}"
    );
    assert_eq!(
        err.exit_status(),
        78,
        "gate rejection must exit 78 (EX_CONFIG)"
    );
    let rendered = err.to_string();
    assert!(
        rendered.contains("[early_data]"),
        "diagnostic must name the section, got: {rendered}"
    );
    assert!(
        rendered.contains("unreachable by construction"),
        "diagnostic must state the unreachable-all-scope reason, got: {rendered}"
    );
}

#[test]
fn early_data_gate_section_rejected_regardless_of_value_shape_and_absent_loads() {
    let entry = entry_table(
        "a.example.org:443",
        "notify",
        "connection",
        "notify",
        "connection",
    );
    for top_level in [
        "[early_data]\nthreshold = 5\nwindow_secs = 300\n",
        "early_data = 5\n",
        "early_data = { threshold = 1, window_secs = 900 }\n",
    ] {
        let doc = format!("{}{}{}{}", base(), top_level, any_illegal_default(), entry,);
        let err = parse_config_document(&doc)
            .expect_err("[early_data] any value shape must be rejected at load");
        assert!(
            matches!(err, ConfigError::EarlyDataGateRejected),
            "expected EarlyDataGateRejected, got {err:?}"
        );
        assert_eq!(
            err.exit_status(),
            78,
            "gate rejection must exit 78 (EX_CONFIG)"
        );
    }
    let absent = gate_doc("");
    let cfg = parse_config_document(&absent).expect("config without [early_data] must load");
    assert_eq!(cfg.gates().early_data(), AllScopeGate::default());
    assert_eq!(cfg.gates().ja4(), AllScopeGate::default());
}

#[test]
fn early_data_gate_section_absent_while_per_fqdn_control_still_parses() {
    let doc = group(&entry_table(
        "a.example.org:443",
        "notify",
        "connection",
        "notify",
        "connection",
    ));
    let cfg = parse_config_document(&doc)
        .expect("per-FQDN early_data control without a gate section must load");
    let control = cfg.control();
    assert_eq!(control.len(), 1);
    let first = control.ordinal(0).expect("ordinal");
    assert_eq!(
        control.early_data(first),
        Some(PerFqdnControl::control(
            ActionKind::Notify,
            Scope::Connection
        ))
    );
    assert_eq!(
        control.ja4(first),
        Some(PerFqdnControl::control(
            ActionKind::Notify,
            Scope::Connection
        ))
    );
    assert_eq!(cfg.gates().early_data(), AllScopeGate::default());
    assert_eq!(cfg.gates().ja4(), AllScopeGate::default());
}

#[test]
fn gates_single_present_section_leaves_others_default() {
    let doc = gate_doc(&gate_section("illegal_fqdn", 5, 300));
    let cfg = parse_config_document(&doc).expect("valid single-section gate config");
    assert_eq!(
        cfg.gates().illegal_fqdn(),
        AllScopeGate::new(
            NonZeroU32::new(5).expect("5 is nonzero"),
            NonZeroU64::new(300).expect("300 is nonzero"),
        )
    );
    assert_eq!(cfg.gates().bad_handshake(), AllScopeGate::default());
    assert_eq!(cfg.gates().early_data(), AllScopeGate::default());
    assert_eq!(cfg.gates().ja4(), AllScopeGate::default());
}

#[test]
fn gate_section_threshold_zero_rejected_for_each_section() {
    for name in GATE_SECTIONS {
        let doc = gate_doc(&gate_section(name, 0, 300));
        let err =
            parse_config_document(&doc).expect_err(&format!("{name} threshold 0 must be rejected"));
        assert!(
            matches!(&err, ConfigError::AllScopeGateOutOfRange { key, value } if key == &format!("{name}.threshold") && *value == 0),
            "expected AllScopeGateOutOfRange({name}.threshold=0), got {err:?}"
        );
        assert_eq!(err.exit_status(), 78, "AllScopeGateOutOfRange must exit 78");
    }
}

#[test]
fn gate_section_threshold_negative_rejected_for_each_section() {
    for name in GATE_SECTIONS {
        let doc = gate_doc(&gate_section(name, 0, 300).replace("threshold = 0", "threshold = -1"));
        let err = parse_config_document(&doc)
            .expect_err(&format!("{name} negative threshold must be rejected"));
        assert!(
            matches!(&err, ConfigError::AllScopeGateOutOfRange { key, value } if key == &format!("{name}.threshold") && *value == -1),
            "expected AllScopeGateOutOfRange({name}.threshold=-1), got {err:?}"
        );
        assert_eq!(err.exit_status(), 78, "AllScopeGateOutOfRange must exit 78");
    }
}

#[test]
fn gate_section_window_zero_rejected_for_each_section() {
    for name in GATE_SECTIONS {
        let doc = gate_doc(&gate_section(name, 5, 0));
        let err = parse_config_document(&doc)
            .expect_err(&format!("{name} window_secs 0 must be rejected"));
        assert!(
            matches!(&err, ConfigError::AllScopeGateOutOfRange { key, value } if key == &format!("{name}.window_secs") && *value == 0),
            "expected AllScopeGateOutOfRange({name}.window_secs=0), got {err:?}"
        );
        assert_eq!(err.exit_status(), 78, "AllScopeGateOutOfRange must exit 78");
    }
}

#[test]
fn gate_section_unknown_key_rejected_for_each_section() {
    for name in GATE_SECTIONS {
        let doc = gate_doc(&format!(
            "[{name}]\nthreshold = 5\nwindow_secs = 300\nbogus = 1\n"
        ));
        let err =
            parse_config_document(&doc).expect_err(&format!("unknown {name} key must be rejected"));
        assert!(
            matches!(&err, ConfigError::UnknownKey(k) if k == &format!("{name}.bogus")),
            "expected UnknownKey({name}.bogus), got {err:?}"
        );
    }
}

#[test]
fn gate_section_wrong_type_rejected_for_each_section() {
    for name in GATE_SECTIONS {
        let doc = gate_doc(&format!(
            "[{name}]\nthreshold = \"five\"\nwindow_secs = 300\n"
        ));
        let err = parse_config_document(&doc)
            .expect_err(&format!("{name} string threshold must be rejected"));
        assert!(
            matches!(&err, ConfigError::WrongType(_)),
            "expected WrongType, got {err:?}"
        );
    }
}

#[test]
fn gate_section_missing_key_rejected_for_each_section() {
    for name in GATE_SECTIONS {
        let doc = gate_doc(&format!("[{name}]\nwindow_secs = 300\n"));
        let err = parse_config_document(&doc)
            .expect_err(&format!("{name} missing threshold must be rejected"));
        assert!(
            matches!(&err, ConfigError::MissingField(f) if f == &format!("{name}.threshold")),
            "expected MissingField({name}.threshold), got {err:?}"
        );
    }
}

#[test]
fn gate_section_not_a_table_rejected_for_each_section() {
    for name in GATE_SECTIONS {
        let doc = format!(
            "{}{name} = 5\n{}{}",
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
            parse_config_document(&doc).expect_err(&format!("non-table {name} must be rejected"));
        assert!(
            matches!(&err, ConfigError::WrongType(_)),
            "expected WrongType, got {err:?}"
        );
    }
}

#[test]
fn legacy_all_scope_gate_section_is_rejected_as_unknown_table() {
    let doc = gate_doc("[all_scope_gate]\nthreshold = 5\nwindow_secs = 300\n");
    let err = parse_config_document(&doc)
        .expect_err("the legacy [all_scope_gate] section must be rejected as an unknown table");
    assert!(
        matches!(&err, ConfigError::UnknownTable(t) if t == "all_scope_gate"),
        "expected UnknownTable(all_scope_gate), got {err:?}"
    );
    assert_eq!(err.exit_status(), 78, "the legacy section must exit 78");
}

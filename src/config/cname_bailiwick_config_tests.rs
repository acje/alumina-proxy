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
        "[allowed_fqdn.\"{key}\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n"
    )
}

fn entry_with_bailiwick(key: &str, suffixes: &str) -> String {
    format!(
        "[allowed_fqdn.\"{key}\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\ncname_bailiwick = {suffixes}\n"
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
        "[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\ncname_bailiwick = [\"example.com\"]\nbogus = \"x\"\n",
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
        "[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\ncname_bailiwick = \"example.com\"\n",
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
        "[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\ncname_bailiwick = [\"example.com\", 42]\n",
    );
    let err = parse_config_document(&doc).unwrap_err();
    assert!(
        matches!(&err, ConfigError::WrongType(m) if m.contains("cname_bailiwick[1]")),
        "expected WrongType for element 1, got {err:?}"
    );
}

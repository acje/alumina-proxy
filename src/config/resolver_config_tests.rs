use super::*;
use crate::dns::resolver::RecursionPolicy;
use std::fmt::Write as _;

fn valid_doc(resolver: &str) -> String {
    format!(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = {resolver}\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"a.example:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n"
    )
}

fn policy_doc(resolver: &str, policy: &str) -> String {
    valid_doc(resolver).replacen(
        "\nresolver",
        &format!("\nrecursive_dnssec_policy = \"{policy}\"\nresolver"),
        1,
    )
}

#[test]
fn resolver_key_is_mandatory() {
    let d = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n";
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
    let single = parse_config_document(&valid_doc("[\"1.1.1.1\"]")).expect("one resolver valid");
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
    let six = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\", \"8.8.8.8\", \"9.9.9.9\", \"208.67.222.222\", \"94.140.14.14\", \"1.0.0.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n";
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
    let cfg = parse_config_document(&valid_doc("[\"1.1.1.1\"]")).expect("bare IP resolver valid");
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
        "listen = \"127.0.0.1:8080\"\nstartup_unresolved_allowance = 0\nresolver = {resolver}\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"api.github.com:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n[allowed_fqdn.\"example.com:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n[allowed_fqdn.\"www.example.net:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n"
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
            "[allowed_fqdn.\"{i}.{}.{}:443\"]\nearly_data = {{ action = \"block\", scope = \"fqdn\" }}\nja4 = {{ action = \"block\", scope = \"fqdn\" }}\ndns_assurance = \"resolver_trusted\"\n",
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

#[test]
fn recursive_policy_absence_undeclared_and_declared_when_all_strict() {
    let cfg = parse_config_document(&valid_doc(
        "[\"9.9.9.9#dns.quad9.net#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"]",
    ))
    .expect("no declaration, strict pins: undeclared");
    assert_eq!(
        cfg.resolver_set().recursion_policy(),
        RecursionPolicy::Undeclared
    );
    let declared = parse_config_document(&policy_doc(
        "[\"9.9.9.9#dns.quad9.net#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\", \"1.1.1.1#cloudflare-dns.com#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"]",
        "root_validating_no_stale",
    ))
    .expect("explicit all-strict declaration valid");
    assert_eq!(
        declared.resolver_set().recursion_policy(),
        RecursionPolicy::RootValidatingNoStale
    );
}

#[test]
fn recursive_policy_weak_backup_rejected() {
    let err = parse_config_document(&policy_doc(
        "[\"9.9.9.9#dns.quad9.net#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\", \"1.1.1.1#cloudflare-dns.com\"]",
        "root_validating_no_stale",
    ))
    .expect_err("unpinned DoT backup is weak; declaration must fail closed");
    assert!(
        matches!(
            &err,
            ConfigError::RecursiveDeclaresWeakResolver { index: 1, .. }
        ),
        "weak backup must isolate index 1, got {err:?}"
    );
    assert_eq!(err.exit_status(), 78, "weak backup must exit 78");
}

#[test]
fn recursive_policy_plain_mix_precedes_weakness() {
    let err = parse_config_document(&policy_doc(
        "[\"9.9.9.9#dns.quad9.net#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\", \"1.1.1.1\"]",
        "root_validating_no_stale",
    ))
    .expect_err("bare-IP backup is a plain/DoT mix; MixedResolverTrust fires first");
    assert!(
        matches!(&err, ConfigError::MixedResolverTrust),
        "mixed trust must win over weakness, got {err:?}"
    );
    assert_eq!(err.exit_status(), 78, "MixedResolverTrust must exit 78");
}

#[test]
fn recursive_policy_unknown_value_rejected() {
    let err = parse_config_document(&policy_doc(
        "[\"9.9.9.9#dns.quad9.net#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"]",
        "permissive_no_stale",
    ))
    .expect_err("unrecognised policy value must be rejected");
    assert!(
        matches!(&err, ConfigError::InvalidRecursivePolicy { .. }),
        "unknown policy value must be InvalidRecursivePolicy, got {err:?}"
    );
    assert_eq!(err.exit_status(), 78, "InvalidRecursivePolicy must exit 78");
}

#[test]
fn recursive_policy_wrong_type_rejected() {
    let d = valid_doc(
        "[\"9.9.9.9#dns.quad9.net#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"]",
    )
    .replacen("\nresolver", "\nrecursive_dnssec_policy = 42\nresolver", 1);
    let err = parse_config_document(&d).expect_err("non-string policy must be rejected");
    assert!(
        matches!(
            &err,
            ConfigError::WrongType(f) if f.starts_with("recursive_dnssec_policy")
        ),
        "non-string policy must be WrongType, got {err:?}"
    );
    assert_eq!(err.exit_status(), 78, "WrongType must exit 78");
}

#[test]
fn dns_assurance_selectors_activate_with_declared_root_validating() {
    let inject = |doc: &str, selector: &str| {
        doc.replacen(
            "dns_assurance = \"resolver_trusted\"",
            &format!("dns_assurance = \"{selector}\""),
            1,
        )
    };
    for selector in ["resolver_authenticated", "delegated_dnssec"] {
        let err = parse_config_document(&inject(&valid_doc("[\"1.1.1.1\"]"), selector))
            .expect_err("strong selector without declared policy must be rejected");
        assert!(
            matches!(&err, ConfigError::InvalidDnsAssurance { .. }),
            "selector {selector} without declared policy got {err:?}"
        );
        assert_eq!(err.exit_status(), 78, "strong gate must exit 78");
    }
    let declared = policy_doc(
        "[\"1.1.1.1#cloudflare-dns.com#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"]",
        "root_validating_no_stale",
    );
    let cfg = parse_config_document(&inject(&declared, "resolver_authenticated"))
        .expect("authenticated selector accepts the declared policy");
    assert_eq!(
        cfg.entry_requirement(0),
        AssuranceRequirement::ResolverAuthenticated,
        "config-owned ordinal carries the activated requirement"
    );
}

fn dns_assurance_line(doc: &str, value: &str) -> String {
    doc.replacen(
        "dns_assurance = \"resolver_trusted\"",
        &format!("dns_assurance = {value}"),
        1,
    )
}

#[test]
fn dns_assurance_activate_ordinal_parity_matrix() {
    let strict =
        "[\"1.1.1.1#cloudflare-dns.com#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"]";
    let mut doc = policy_doc(strict, "root_validating_no_stale");
    doc.push_str(
        "[allowed_fqdn.\"a.example:8443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"delegated_dnssec\"\n[allowed_fqdn.\"b.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n",
    );
    let cfg = parse_config_document(&dns_assurance_line(&doc, "\"resolver_authenticated\""))
        .expect("three-entry strong allowlist");
    for (index, want) in [
        (0, AssuranceRequirement::ResolverAuthenticated),
        (1, AssuranceRequirement::DelegatedDnssec),
        (2, AssuranceRequirement::ResolverTrusted),
    ] {
        assert_eq!(cfg.entry_requirement(index), want);
    }
}

#[test]
fn dns_assurance_missing_key_rejects_78() {
    let d = valid_doc("[\"1.1.1.1\"]").replacen("\ndns_assurance = \"resolver_trusted\"", "", 1);
    let err = parse_config_document(&d).expect_err("omitted dns_assurance must be rejected");
    assert!(
        matches!(&err, ConfigError::InvalidDnsAssurance { key, .. } if key == "allowed_fqdn.a.example:443.dns_assurance"),
        "expected InvalidDnsAssurance for the entry key, got {err:?}"
    );
    assert_eq!(err.exit_status(), 78, "missing dns_assurance must exit 78");
}

#[test]
fn dns_assurance_unknown_token_and_wrong_type_reject_78() {
    let declared = policy_doc(
        "[\"1.1.1.1#cloudflare-dns.com#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"]",
        "root_validating_no_stale",
    );
    let unknown = parse_config_document(&dns_assurance_line(&declared, "\"bogus\"")).unwrap_err();
    assert!(matches!(&unknown, ConfigError::InvalidDnsAssurance { .. }));
    assert_eq!(unknown.exit_status(), 78);
    let wrong = parse_config_document(&dns_assurance_line(&declared, "42")).unwrap_err();
    assert!(matches!(&wrong, ConfigError::WrongType(_)));
    assert_eq!(wrong.exit_status(), 78);
}

#[test]
fn dns_assurance_strong_selector_cannot_weaken_resolver_set() {
    let strict = "9.9.9.9#dns.quad9.net#pin-sha256=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    for (selector, backup) in [
        ("resolver_authenticated", "1.1.1.1#cloudflare-dns.com"),
        ("delegated_dnssec", "1.1.1.1"),
    ] {
        let resolver = format!("[\"{strict}\", \"{backup}\"]");
        let value = format!("\"{selector}\"");
        let doc = policy_doc(&resolver, "root_validating_no_stale");
        let err = parse_config_document(&dns_assurance_line(&doc, &value)).unwrap_err();
        assert_eq!(
            err.exit_status(),
            78,
            "strong selector {selector} + {backup}"
        );
    }
}

use super::{ALLOWLIST_MAX, Fqdn};

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

#[test]
fn characterize_config_fqdn_parse_and_debug_baseline() {
    let l = |c: char| std::iter::repeat_n(c, 63).collect::<String>();
    for (input, name, port) in [
        ("example.com:443", "example.com", 443u16),
        ("example.com.:443", "example.com", 443),
        ("4example.com:443", "4example.com", 443),
        ("0x123.example.org:53", "0x123.example.org", 53),
        ("123.example.com:443", "123.example.com", 443),
    ] {
        let fqdn = Fqdn::parse(input).unwrap_or_else(|e| panic!("{input:?} should accept: {e}"));
        assert_eq!(fqdn.as_str(), name, "{input} normalized name");
        assert_eq!(fqdn.port(), port, "{input} port");
    }
    let max253 = format!("{}.{}.{}.{}", l('a'), l('b'), l('c'), "d".repeat(61));
    assert_eq!(max253.len(), 253);
    let fqdn = Fqdn::parse(&format!("{max253}:1"))
        .unwrap_or_else(|e| panic!("253-max should accept: {e}"));
    assert_eq!(fqdn.as_str(), max253);
    let fqdn = Fqdn::parse(&format!("{max253}.:1"))
        .unwrap_or_else(|e| panic!("253+dot should accept: {e}"));
    assert_eq!(fqdn.as_str(), max253);
    let over254 = format!("{}.{}.{}.{}", l('a'), l('b'), l('c'), "d".repeat(62));
    assert_eq!(over254.len(), 254);
    for (input, reason) in [
        ("example.com", "allowlist entry lacks a <fqdn>:<port> port"),
        (
            "1.2.3.4:443",
            "allowlist entry is an IP literal; use a DNS hostname",
        ),
        (
            "93.184.216.34:443",
            "allowlist entry is an IP literal; use a DNS hostname",
        ),
        (
            "123:443",
            "allowlist entry is an IP literal; use a DNS hostname",
        ),
        (
            "999.999.999.999:443",
            "allowlist entry is an IP literal; use a DNS hostname",
        ),
        (
            "Bad.example:443",
            "label \"Bad\" not lowercase ASCII [a-z0-9-]",
        ),
        (
            "bad_.example:443",
            "label \"bad_\" not lowercase ASCII [a-z0-9-]",
        ),
        (
            "bücher.example:443",
            "label \"bücher\" not lowercase ASCII [a-z0-9-]",
        ),
        (":443", "empty hostname"),
        (&format!("{over254}:1"), "hostname exceeds 253 bytes"),
        ("a..b:443", "empty label"),
        ("a.example..:443", "multiple trailing dots"),
        ("-a.example:443", "label starts or ends with hyphen"),
        ("a-.example:443", "label starts or ends with hyphen"),
        ("example.com:000", "port has a leading zero"),
        ("example.com:0", "port 0 is invalid"),
        ("example.com:65536", "port exceeds 65535"),
        ("example.com:abc", "port is not canonical decimal"),
        ("example.com:", "port is empty"),
    ] {
        let err = Fqdn::parse(input).expect_err("should reject");
        assert_eq!(err, reason, "{input:?} reason");
    }
    let err = Fqdn::parse("bad_.example:000").expect_err("host error must precede port error");
    assert_eq!(err, "label \"bad_\" not lowercase ASCII [a-z0-9-]");
    let err = Fqdn::parse("1.2.3.4:000").expect_err("IP-literal error must precede port error");
    assert_eq!(err, "allowlist entry is an IP literal; use a DNS hostname");
    let fqdn = Fqdn::parse("example.com:443").expect("fqdn");
    assert_eq!(
        format!("{fqdn:?}"),
        "Fqdn { name: \"example.com\", port: 443 }"
    );
}

#[test]
fn config_fqdn_fixed_stored_size_is_inline_and_bounded() {
    assert_eq!(std::mem::size_of::<Fqdn>(), 256);
    assert_eq!(std::mem::size_of::<Fqdn>() * ALLOWLIST_MAX, 8192);
}

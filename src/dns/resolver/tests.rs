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
    assert_eq!(v4.port(), DOT_PORT, "an FQDN entry dials DoT port 853");
    assert_eq!(v4.fqdn().expect("fqdn carried").as_str(), "dns.google");
    assert!(!v4.is_ip_only());
    let v6 = select("2606:4700:4700::1111#one.one.one.one").expect("v6 IP#fqdn");
    assert_eq!(
        v6.addr(),
        "2606:4700:4700::1111".parse::<IpAddr>().expect("parse")
    );
    assert_eq!(v6.fqdn().expect("fqdn carried").as_str(), "one.one.one.one");
    assert_eq!(v6.port(), DOT_PORT, "the v6 FQDN entry also dials DoT");
}

#[test]
fn select_bare_ip_has_no_fqdn_and_is_ip_only() {
    let ns = select("1.1.1.1").expect("bare IP accepted");
    assert!(ns.fqdn().is_none(), "bare IP carries no fqdn");
    assert!(ns.is_ip_only());
    assert_eq!(
        ns.port(),
        RESOLVER_PORT,
        "a bare-IP entry stays on plain DNS port 53"
    );
    assert!(ns.pin().is_none(), "a bare-IP entry carries no pin");
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
fn select_rejects_ip_literal_shape_fqdn() {
    for bad in ["1.1.1.1#1.2.3.4", "1.1.1.1#123"] {
        let err = select(bad)
            .err()
            .unwrap_or_else(|| panic!("{bad} must be rejected"));
        assert!(
            matches!(err, ResolverError::InvalidFqdn { .. }),
            "{bad} must be InvalidFqdn, got {err:?}"
        );
    }
}

#[test]
fn select_accepts_all_numeric_final_label() {
    for ok in ["1.1.1.1#example.123", "1.1.1.1#dns.123"] {
        let fqdn = select(ok)
            .expect("all-numeric final label is RFC 1123 DNS-name syntax")
            .fqdn()
            .expect("fqdn")
            .as_str()
            .to_owned();
        assert!(
            fqdn.ends_with(".123"),
            "{ok} must carry the all-numeric final label, got {fqdn:?}"
        );
    }
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
fn resolver_fqdn_stays_strict_where_hostname_normalize_is_lenient() {
    use crate::names::hostname::FixedHostname;

    let canon = "dns.quad9.net";
    assert_eq!(
        select(&format!("8.8.8.8#{canon}"))
            .expect("canonical fqdn accepted")
            .fqdn()
            .expect("fqdn carried")
            .as_str(),
        canon
    );
    assert_eq!(
        FixedHostname::normalize(canon.as_bytes())
            .expect("normalize accepts the canonical fqdn")
            .as_str(),
        canon
    );

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
        "both accept a 253-char canonical fqdn"
    );
    assert!(FixedHostname::normalize(max_total.as_bytes()).is_some());

    let strict_rows = ["ExAmPLe.Com", "dns.quad9.net.", "DNS.QUAD9.NET."];
    for token in strict_rows {
        assert!(
            matches!(
                select(&format!("8.8.8.8#{token}")),
                Err(ResolverError::InvalidFqdn { .. })
            ),
            "resolver must reject strict-violation {token:?}"
        );
    }
    let dot_254 = format!("{max_total}.");
    assert_eq!(dot_254.len(), 254);
    assert!(
        matches!(
            select(&format!("8.8.8.8#{dot_254}")),
            Err(ResolverError::InvalidFqdn { .. })
        ),
        "resolver rejects 253 bytes plus a trailing dot"
    );
    assert_eq!(
        FixedHostname::normalize("ExAmPLe.Com".as_bytes())
            .expect("normalize lowercases uppercase")
            .as_str(),
        "example.com"
    );
    assert_eq!(
        FixedHostname::normalize("dns.quad9.net.".as_bytes())
            .expect("normalize strips a single trailing dot")
            .as_str(),
        "dns.quad9.net"
    );
    assert_eq!(
        FixedHostname::normalize(dot_254.as_bytes())
            .expect("normalize accepts 253 bytes plus a trailing dot")
            .as_str(),
        max_total
    );

    for token in ["*.example.com", "bücher.example", "1.2.3.4"] {
        assert!(
            select(&format!("8.8.8.8#{token}")).is_err(),
            "resolver must reject {token:?}"
        );
        assert!(
            FixedHostname::normalize(token.as_bytes()).is_none(),
            "normalize must also reject {token:?}"
        );
    }
}

#[test]
fn resolved_and_serving_identity_sizes_stay_inline() {
    assert_eq!(
        core::mem::size_of::<Fqdn>(),
        254,
        "resolver FQDN payload stays 254 bytes (old layout)"
    );
    assert_eq!(
        core::mem::size_of::<crate::names::hostname::FixedHostname>(),
        254,
        "shared serving/resolver payload shrinks from 264 to 254 bytes"
    );
    assert_eq!(
        core::mem::size_of::<Nameserver>(),
        305,
        "Nameserver layout unaffected by the payload share"
    );
    assert_eq!(
        core::mem::size_of::<ResolverSet>(),
        1536,
        "ResolverSet layout unaffected by the payload share"
    );
}

#[test]
fn select_accepts_pin_sha256_and_carries_32_byte_pin() {
    // base64("A".repeat(32)) = 43 unpadded chars (AQ...
    let b64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    let ns =
        select(&format!("9.9.9.9#dns.quad9.net#pin-sha256={b64}")).expect("pinned entry accepted");
    assert_eq!(ns.addr(), "9.9.9.9".parse::<IpAddr>().expect("parse"));
    assert_eq!(ns.fqdn().expect("fqdn carried").as_str(), "dns.quad9.net");
    assert_eq!(ns.port(), DOT_PORT, "a pinned entry is a DoT entry");
    let pin = ns.pin().expect("pin carried");
    assert_eq!(pin.as_bytes(), [0x01u8; 32], "decoded to the raw digest");
    assert_eq!(
        ns.pin().expect("copy carries pin").as_bytes(),
        [0x01u8; 32],
        "Nanserver Copy preserves the pin"
    );
}

#[test]
fn select_accepts_unpadded_base64url_pin() {
    // Same 32 zero bytes, but unpadded URL-safe base64 (the '=' removed).
    let unpadded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_eq!(unpadded.len(), 43);
    let ns = select(&format!("1.1.1.1#dns.google#pin-sha256={unpadded}"))
        .expect("unpadded base64url pin accepted");
    assert_eq!(ns.pin().expect("pin").as_bytes(), [0u8; 32]);
}

#[test]
fn select_rejects_invalid_pin_shapes() {
    // 42 x 'A' + 'B': a well-formed 32-byte encoding never leaves non-zero
    // trailing bits, and 'B' puts the low two pad bits to 1.
    let nonzero_leftover = format!("{}B", "A".repeat(42));
    assert_eq!(nonzero_leftover.len(), 43);
    let bad_pins = [
        "abc",
        "not-valid-base64!!!!",
        &nonzero_leftover,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", // double padding ('=' inside data)
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",  // 44 data chars, no pad
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!x", // 45 chars
    ];
    for pin in bad_pins {
        let token = format!("9.9.9.9#dns.quad9.net#pin-sha256={pin}");
        let err = select(&token)
            .err()
            .unwrap_or_else(|| panic!("{token} must be rejected"));
        assert!(
            matches!(err, ResolverError::InvalidPin { .. }),
            "{token} must be InvalidPin, got {err:?}"
        );
    }
}

#[test]
fn select_rejects_pin_without_fqdn_or_bad_separator() {
    // A pin marker with no FQDN before it is an invalid FQDN, never a pin.
    assert!(matches!(
        select("9.9.9.9#pin-sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Err(ResolverError::InvalidFqdn { .. })
    ));
    // A double '#' before the marker leaves a '#' inside the FQDN part.
    assert!(matches!(
        select("9.9.9.9##pin-sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Err(ResolverError::InvalidFqdn { .. })
    ));
    // An empty pin value is invalid.
    assert!(matches!(
        select("9.9.9.9#dns.quad9.net#pin-sha256="),
        Err(ResolverError::InvalidPin { .. })
    ));
    // A pin is only accepted attached to a valid FQDN.
    assert!(matches!(
        select("9.9.9.9#*.quad9.net#pin-sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Err(ResolverError::WildcardFqdn { .. })
    ));
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

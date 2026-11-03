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
    assert!(FixedHostname::normalize(b"example.org..").is_none());
    assert!(FixedHostname::normalize(b".a").is_none());
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

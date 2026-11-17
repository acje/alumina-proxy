use super::ApprovedHostname;

#[test]
fn normalizes_uppercase_and_trailing_dot() {
    let h = ApprovedHostname::normalize(b"SUB.Example.ORG.").expect("normalize");
    assert_eq!(h.as_bytes(), b"sub.example.org");
}

#[test]
fn rejects_ip_literal_shape() {
    assert!(ApprovedHostname::normalize(b"1.2.3.4").is_none());
    assert!(ApprovedHostname::normalize(b"93.184.216.34").is_none());
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
            ApprovedHostname::normalize(input).is_none(),
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
            ApprovedHostname::normalize(input).is_some(),
            "expected {input:?} accepted"
        );
    }
}

#[test]
fn rejects_malformed_labels() {
    assert!(ApprovedHostname::normalize(b"").is_none());
    assert!(ApprovedHostname::normalize(b"-bad.example.org").is_none());
    assert!(ApprovedHostname::normalize(b"bad-.example.org").is_none());
    assert!(ApprovedHostname::normalize(b"double..dot.example.org").is_none());
    assert!(ApprovedHostname::normalize(b"under_score.example.org").is_none());
    assert!(ApprovedHostname::normalize(b"example.org..").is_none());
    assert!(ApprovedHostname::normalize(b".a").is_none());
}

#[test]
fn accepts_253_byte_name_with_trailing_dot() {
    let mut name = Vec::with_capacity(254);
    for _ in 0..125 {
        name.extend_from_slice(b"a.");
    }
    name.extend_from_slice(b"abc.");
    assert_eq!(name.len(), 254, "valid 253-byte name plus trailing dot");
    let h = ApprovedHostname::normalize(&name).expect("253 canonical + dot must normalize");
    assert_eq!(h.as_bytes().len(), 253);
    assert!(ApprovedHostname::normalize(&name[..253]).is_some());
}

#[test]
fn rejects_254_byte_name_without_dot_without_panic() {
    let name = [b'a'; 254];
    assert!(ApprovedHostname::normalize(&name).is_none());
}

#[test]
fn rejects_255_byte_name_with_trailing_dot_without_panic() {
    let mut name = vec![b'a'; 254];
    name.push(b'.');
    assert!(ApprovedHostname::normalize(&name).is_none());
}

/// Every accepted input must normalise to a name that normalises to itself.
fn assert_normalised_fixed_point(input: &[u8]) {
    if let Some(first) = ApprovedHostname::normalize(input) {
        assert_eq!(
            ApprovedHostname::normalize(first.as_bytes()),
            Some(first),
            "a normalised name must be a fixed point of normalisation"
        );
    }
}

/// Checked-in regression corpus for the property below. These are the
/// minimised inputs captured from a deliberately faulted twin of
/// `hostname_normalisation_is_total_and_idempotent` running under
/// `HEGEL_SEED=7`: the raw draw minimised to `[]` and the shaped draw to
/// `"a.AC"`. The replay is a plain `#[test]` rather than a
/// `#[hegel::reproduce_failure]` attribute: hegeltest 0.52.7 skips generation
/// whenever a blob is present and then panics once the fault is fixed, so the
/// attribute cannot hold a corpus in a green gate (bd alumina-dvgoj). This test
/// instead replays the same inputs through the same property body on every run,
/// while the property keeps generating its own cases at the `development`
/// profile's case count in `hegel.toml`.
#[test]
fn hostname_regression_replays_the_minimised_counterexample() {
    assert_normalised_fixed_point(&[]);
    assert_normalised_fixed_point(b"a.AC");
    let normalised =
        ApprovedHostname::normalize(b"a.AC").expect("minimised counterexample normalizes");
    assert_eq!(normalised.as_str(), "a.ac");
}

/// Totality and idempotence: arbitrary attacker bytes never panic the
/// normaliser, and every accepted name is a fixed point of normalisation. The
/// second, hostname-shaped draw keeps the accept branch mandatory rather than
/// merely reachable: arbitrary bytes essentially never form a legal FQDN, so a
/// raw-only property would never test idempotence at all (measured: zero
/// accepted inputs across the `development` profile's cases). `domains()`
/// draws RFC 1035 names — dot separated labels that each start and end
/// alphanumeric, with no leading or trailing dot, no port, and total length at
/// most `max_length` — so at 253 bytes, this crate's `FQDN_MAX_LEN`, every
/// draw is an accepted name and the assertion below fails the property if that
/// ever stops holding.
#[hegel::test(derandomize = true)]
fn hostname_normalisation_is_total_and_idempotent(tc: hegel::TestCase) {
    let raw = tc.draw(hegel::generators::binary().max_size(300));
    assert_normalised_fixed_point(&raw);
    let shaped = tc.draw(hegel::generators::domains().max_length(253));
    assert!(
        ApprovedHostname::normalize(shaped.as_bytes()).is_some(),
        "domains() with max_length 253 guarantees an RFC 1035 name of at most \
         FQDN_MAX_LEN bytes with letter-initial dot-separated labels and no \
         trailing dot, so {shaped:?} must normalise"
    );
    assert_normalised_fixed_point(shaped.as_bytes());
}

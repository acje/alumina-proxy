use super::*;

fn hello_msg(legacy: u16, versions: &[u16], snis: &[&str], ech: bool) -> Vec<u8> {
    hello_msg_comp(legacy, versions, snis, ech, 0)
}

fn hello_msg_comp(legacy: u16, versions: &[u16], snis: &[&str], ech: bool, comp: u8) -> Vec<u8> {
    let mut versions_data =
        vec![u8::try_from(versions.len() * 2).expect("versions data length fits u8")];
    for v in versions {
        versions_data.extend_from_slice(&v.to_be_bytes());
    }
    let mut snis_data = Vec::new();
    let mut names_data = Vec::new();
    for name in snis {
        names_data.push(0u8);
        names_data.extend_from_slice(
            &u16::try_from(name.len())
                .expect("sni name fits u16 wire length")
                .to_be_bytes(),
        );
        names_data.extend_from_slice(name.as_bytes());
    }
    snis_data.extend_from_slice(
        &u16::try_from(names_data.len())
            .expect("sni names block fits u16")
            .to_be_bytes(),
    );
    snis_data.extend_from_slice(&names_data);

    let mut exts = Vec::new();
    exts.extend_from_slice(&SUPPORTED_VERSIONS.to_be_bytes());
    exts.extend_from_slice(
        &u16::try_from(versions_data.len())
            .expect("versions data fits u16")
            .to_be_bytes(),
    );
    exts.extend_from_slice(&versions_data);
    exts.extend_from_slice(&SERVER_NAME.to_be_bytes());
    exts.extend_from_slice(
        &u16::try_from(snis_data.len())
            .expect("sni data fits u16")
            .to_be_bytes(),
    );
    exts.extend_from_slice(&snis_data);
    if ech {
        exts.extend_from_slice(&ENCRYPTED_CLIENT_HELLO.to_be_bytes());
        exts.extend_from_slice(&0u16.to_be_bytes());
    }

    let mut body = Vec::new();
    body.extend_from_slice(&legacy.to_be_bytes());
    body.extend_from_slice(&[0u8; RANDOM_LEN]);
    body.push(0);
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
    body.push(1);
    body.push(comp);
    body.extend_from_slice(
        &u16::try_from(exts.len())
            .expect("extensions data fits u16")
            .to_be_bytes(),
    );
    body.extend_from_slice(&exts);

    let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
    let hl = u32::try_from(body.len()).expect("client hello body fits u32");
    handshake.extend_from_slice(&hl.to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = vec![CONTENT_HANDSHAKE];
    record.extend_from_slice(&0x0301u16.to_be_bytes());
    record.extend_from_slice(
        &u16::try_from(handshake.len())
            .expect("handshake fits u16 wire length")
            .to_be_bytes(),
    );
    record.extend_from_slice(&handshake);
    record
}

fn record(payload: &[u8]) -> Vec<u8> {
    let mut record = vec![CONTENT_HANDSHAKE];
    record.extend_from_slice(&0x0301u16.to_be_bytes());
    record.extend_from_slice(
        &u16::try_from(payload.len())
            .expect("record payload fits u16 wire length")
            .to_be_bytes(),
    );
    record.extend_from_slice(payload);
    record
}

fn parse_one(bytes: &[u8]) -> Result<ClientHello, ChError> {
    let mut inspector = ChInspector::new();
    match inspector.feed(bytes)? {
        Inspect::Complete { .. } => Ok(inspector.hello().expect("complete has hello").clone()),
        Inspect::NeedMore => panic!("test message must complete within a single feed"),
    }
}

fn approved(name: &str) -> FixedHostname {
    FixedHostname::normalize(name.as_bytes()).expect("valid approved name")
}

fn server_name_ext(names: &[(u8, &[u8])]) -> Vec<u8> {
    let mut names_data = Vec::new();
    for (ty, name) in names {
        names_data.push(*ty);
        names_data.extend_from_slice(
            &u16::try_from(name.len())
                .expect("sni name fits u16 wire length")
                .to_be_bytes(),
        );
        names_data.extend_from_slice(name);
    }
    let mut ext = Vec::new();
    ext.extend_from_slice(
        &u16::try_from(names_data.len())
            .expect("sni names block fits u16")
            .to_be_bytes(),
    );
    ext.extend_from_slice(&names_data);
    ext
}

fn hello_with_extensions(exts: &[(u16, &[u8])]) -> Vec<u8> {
    hello_with_ciphers_and_extensions(&[0x002f], exts)
}

fn hello_with_ciphers_and_extensions(ciphers: &[u16], exts: &[(u16, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&TLS12.to_be_bytes());
    body.extend_from_slice(&[0u8; RANDOM_LEN]);
    body.push(0);
    body.extend_from_slice(
        &u16::try_from(ciphers.len() * 2)
            .expect("cipher list fits u16")
            .to_be_bytes(),
    );
    for cipher in ciphers {
        body.extend_from_slice(&cipher.to_be_bytes());
    }
    body.push(1);
    body.push(0);
    let mut blob = Vec::new();
    for (ty, data) in exts {
        blob.extend_from_slice(&ty.to_be_bytes());
        blob.extend_from_slice(
            &u16::try_from(data.len())
                .expect("extension data fits u16")
                .to_be_bytes(),
        );
        blob.extend_from_slice(data);
    }
    body.extend_from_slice(
        &u16::try_from(blob.len())
            .expect("extensions blob fits u16")
            .to_be_bytes(),
    );
    body.extend_from_slice(&blob);
    let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
    let hl = u32::try_from(body.len()).expect("client hello body fits u32");
    handshake.extend_from_slice(&hl.to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    record(&handshake)
}

fn alpn_ext(values: &[&[u8]]) -> Vec<u8> {
    let mut names = Vec::new();
    for value in values {
        names.push(u8::try_from(value.len()).expect("alpn value fits u8"));
        names.extend_from_slice(value);
    }
    let mut ext = Vec::new();
    ext.extend_from_slice(
        &u16::try_from(names.len())
            .expect("alpn names block fits u16")
            .to_be_bytes(),
    );
    ext.extend_from_slice(&names);
    ext
}

#[test]
fn accepts_tls13_with_single_sni() {
    let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
    let ch = parse_one(&msg).expect("parse");
    let v = validate(&ch, &approved("sub.example.org"));
    assert!(v.is_ok(), "valid TLS1.3 ClientHello: {v:?}");
    assert_eq!(ch.offered_versions(), &[TLS13]);
    assert_eq!(ch.server_name(), b"sub.example.org");
    assert_eq!(ch.sni_entries(), 1);
    assert!(!ch.has_ech());
}

#[test]
fn fragmented_records_are_boundary_independent() {
    let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
    let mut inspector = ChInspector::new();
    for chunk in msg.chunks(4) {
        match inspector.feed(chunk).expect("feed") {
            Inspect::NeedMore => {}
            Inspect::Complete { .. } => {
                let hello = inspector.hello().expect("complete has hello");
                validate(hello, &approved("sub.example.org")).expect("valid");
                return;
            }
        }
    }
    panic!("never completed");
}

#[test]
fn handshake_split_across_records_completes() {
    let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
    let mut split = record(&msg[5..5 + 12]);
    split.extend_from_slice(&record(&msg[5 + 12..]));
    let mut inspector = ChInspector::new();
    match inspector.feed(&split).expect("feed") {
        Inspect::Complete { consumed } => {
            let hello = inspector.hello().expect("complete has hello");
            validate(hello, &approved("sub.example.org")).expect("valid");
            assert_eq!(consumed, split.len(), "consumed ends at the hello");
        }
        Inspect::NeedMore => panic!("multi-record handshake must complete"),
    }
}

#[test]
fn rejects_tls12_only_offer() {
    let msg = hello_msg(TLS12, &[TLS12], &["sub.example.org"], false);
    assert_eq!(
        parse_one(&msg),
        Err(ChError::InvalidVersionOffer { version: TLS12 })
    );
}

#[test]
fn rejects_mixed_offer_with_extra_non_grease() {
    let msg = hello_msg(TLS12, &[TLS13, TLS12], &["sub.example.org"], false);
    assert_eq!(
        parse_one(&msg),
        Err(ChError::InvalidVersionOffer { version: TLS12 })
    );
}

#[test]
fn allows_grease_versions_alongside_tls13() {
    let msg = hello_msg(TLS12, &[0x0a0a, TLS13, 0x1a1a], &["sub.example.org"], false);
    parse_one(&msg).expect("grease allowed");
}

#[test]
fn rejects_grease_only_versions() {
    let msg = hello_msg(TLS12, &[0x0a0a], &["sub.example.org"], false);
    assert_eq!(
        parse_one(&msg),
        Err(ChError::InvalidVersionOffer { version: 0 })
    );
}

#[test]
fn rejects_missing_supported_versions() {
    let no_ext = [0u8, 0u8];
    let mut body = Vec::new();
    body.extend_from_slice(&TLS12.to_be_bytes());
    body.extend_from_slice(&[0u8; RANDOM_LEN]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&no_ext);
    let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
    let hl = u32::try_from(body.len()).expect("client hello body fits u32");
    handshake.extend_from_slice(&hl.to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let record = record(&handshake);
    assert_eq!(parse_one(&record), Err(ChError::MissingSupportedVersions));
}

#[test]
fn rejects_non_null_compression() {
    let msg = hello_msg_comp(TLS12, &[TLS13], &["sub.example.org"], false, 1);
    assert_eq!(parse_one(&msg), Err(ChError::NonNullCompression));
}

#[test]
fn rejects_multiple_compression_methods() {
    let msg = hello_msg_comp(TLS12, &[TLS13], &["sub.example.org"], false, 0);
    let mut multi = vec![HANDSHAKE_CLIENT_HELLO];
    let handshake = &msg[5..];
    let body = &handshake[4..];
    let hl = u32::try_from(body.len()).expect("client hello body fits u32");
    multi.extend_from_slice(&hl.to_be_bytes()[1..]);
    multi.extend_from_slice(&body[..41]);
    multi.push(2);
    multi.push(0);
    multi.push(1);
    multi.extend_from_slice(&body[44..]);
    let record = record(&multi);
    assert_eq!(parse_one(&record), Err(ChError::NonNullCompression));
}

#[test]
fn trailing_bytes_after_extensions_rejected() {
    let mut body = Vec::new();
    body.extend_from_slice(&TLS12.to_be_bytes());
    body.extend_from_slice(&[0u8; RANDOM_LEN]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(1);
    body.push(0);
    let sv = [0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
    body.extend_from_slice(
        &u16::try_from(sv.len())
            .expect("supported versions data fits u16")
            .to_be_bytes(),
    );
    body.extend_from_slice(&sv);
    body.extend_from_slice(&[0xab; 5]);
    let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
    let hl = u32::try_from(body.len()).expect("client hello body fits u32");
    handshake.extend_from_slice(&hl.to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let record = record(&handshake);
    assert!(matches!(
        parse_one(&record),
        Err(ChError::MalformedBody { .. })
    ));
}

#[test]
fn rejects_ech() {
    let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], true);
    let ch = parse_one(&msg).expect("parse");
    assert_eq!(
        validate(&ch, &approved("sub.example.org")),
        Err(ChError::EchPresent)
    );
}

#[test]
fn rejects_esni_codepoint() {
    let msg = hello_with_extensions(&[
        (SUPPORTED_VERSIONS, &[0x02, 0x03, 0x04]),
        (SERVER_NAME, &server_name_ext(&[(0, b"sub.example.org")])),
        (ENCRYPTED_SERVER_NAME, &[]),
    ]);
    let ch = parse_one(&msg).expect("parse");
    assert!(ch.has_ech());
    assert_eq!(
        validate(&ch, &approved("sub.example.org")),
        Err(ChError::EchPresent)
    );
}

#[test]
fn rejects_mismatched_sni() {
    let msg = hello_msg(TLS12, &[TLS13], &["other.example.net"], false);
    let ch = parse_one(&msg).expect("parse");
    assert_eq!(
        validate(&ch, &approved("sub.example.org")),
        Err(ChError::ServerNameMismatch)
    );
}

#[test]
fn trailing_dot_sni_matches_approved() {
    let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org."], false);
    let ch = parse_one(&msg).expect("parse");
    assert_eq!(ch.server_name(), b"sub.example.org");
    assert!(validate(&ch, &approved("sub.example.org")).is_ok());
}

#[test]
fn uppercase_sni_matches_approved() {
    let msg = hello_msg(TLS12, &[TLS13], &["SUB.Example.ORG"], false);
    let ch = parse_one(&msg).expect("parse");
    assert_eq!(ch.server_name(), b"sub.example.org");
    assert!(validate(&ch, &approved("sub.example.org")).is_ok());
}

#[test]
fn rejects_two_sni_entries() {
    let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org", "other.test"], false);
    let ch = parse_one(&msg).expect("parse");
    assert_eq!(
        validate(&ch, &approved("sub.example.org")),
        Err(ChError::InvalidServerName {
            detail: "requires exactly one host_name entry",
        })
    );
}

#[test]
fn rejects_duplicate_extension() {
    let mut body = Vec::new();
    body.extend_from_slice(&TLS12.to_be_bytes());
    body.extend_from_slice(&[0u8; RANDOM_LEN]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(1);
    body.push(0);
    let mut exts = Vec::new();
    for _ in 0..2 {
        exts.extend_from_slice(&0xfe00u16.to_be_bytes());
        exts.extend_from_slice(&0u16.to_be_bytes());
    }
    body.extend_from_slice(
        &u16::try_from(exts.len())
            .expect("extensions data fits u16")
            .to_be_bytes(),
    );
    body.extend_from_slice(&exts);

    let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
    let hl = u32::try_from(body.len()).expect("client hello body fits u32");
    handshake.extend_from_slice(&hl.to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let record = record(&handshake);
    assert_eq!(
        parse_one(&record),
        Err(ChError::DuplicateExtension { ext: 0xfe00 })
    );
}

#[test]
fn rejects_ssl_framing_first_byte() {
    let mut msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
    msg[0] = 0x80;
    assert_eq!(parse_one(&msg), Err(ChError::Sslv2Framing));
}

#[test]
fn rejects_ssl_framing_feed_time() {
    let mut inspector = ChInspector::new();
    assert_eq!(inspector.feed(&[0x80]), Err(ChError::Sslv2Framing));
}

#[test]
fn rejects_non_handshake_at_feed_time() {
    let mut inspector = ChInspector::new();
    let mut header = vec![23u8, 0x03, 0x01, 0x00, 0x00];
    header.extend_from_slice(&[0xab; 4]);
    assert_eq!(
        inspector.feed(&header),
        Err(ChError::NotHandshake { content_type: 23 })
    );
}

#[test]
fn short_record_does_not_panic() {
    let mut inspector = ChInspector::new();
    let result = inspector.feed(&[22, 3, 1, 0, 0]);
    assert_eq!(result, Err(ChError::ZeroLengthRecord));
}

#[test]
fn short_two_byte_payload_does_not_panic() {
    let mut inspector = ChInspector::new();
    let result = inspector.feed(&[22, 3, 1, 0, 2, 1, 0]);
    assert_eq!(result, Err(ChError::TruncatedHandshake));
}

#[test]
fn rejects_record_payload_over_limit() {
    let big = vec![0xabu8; RECORD_PAYLOAD_LIMIT + 1];
    let mut record = vec![CONTENT_HANDSHAKE, 0x03, 0x01];
    record.extend_from_slice(
        &u16::try_from(big.len())
            .expect("oversized payload fits u16")
            .to_be_bytes(),
    );
    record.extend_from_slice(&big);
    assert_eq!(
        parse_one(&record),
        Err(ChError::RecordTooLarge {
            got: RECORD_PAYLOAD_LIMIT + 1
        })
    );
}

#[test]
fn rejects_handshake_length_claim_over_bound() {
    let claimed = 0x0000_ffff_u32;
    let mut payload = vec![HANDSHAKE_CLIENT_HELLO];
    payload.extend_from_slice(&claimed.to_be_bytes()[1..]);
    payload.extend_from_slice(&[0xabu8; 28]);
    let wire = record(&payload);
    assert_eq!(
        parse_one(&wire),
        Err(ChError::HandshakeTooLarge {
            got: 4 + claimed as usize,
        }),
        "a ClientHello whose 3-byte handshake length claims more than 16 KiB must be rejected"
    );
}

#[test]
fn handshake_claim_exactly_at_bound_is_not_length_rejected() {
    let claimed = u32::try_from(MAX_HANDSHAKE_LEN - 4).expect("16 KiB handshake bound fits u32");
    let mut payload = vec![HANDSHAKE_CLIENT_HELLO];
    payload.extend_from_slice(&claimed.to_be_bytes()[1..]);
    payload.extend_from_slice(&[0xabu8; 28]);
    let mut inspector = ChInspector::new();
    assert_eq!(
        inspector.feed(&record(&payload)),
        Ok(Inspect::NeedMore),
        "a handshake claiming exactly the 16 KiB cap is incomplete, not length-rejected"
    );
}

#[test]
fn rejects_zero_length_handshake_record_between_fragments() {
    let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
    let mut split = record(&msg[5..5 + 12]);
    split.extend_from_slice(&record(&[]));
    split.extend_from_slice(&record(&msg[5 + 12..]));
    assert_eq!(parse_one(&split), Err(ChError::ZeroLengthRecord));
}

#[test]
fn exact_fill_64k_incomplete_stream_does_not_panic() {
    let mut wire = Vec::with_capacity(MAX_CLIENT_HELLO);
    let mut first = vec![HANDSHAKE_CLIENT_HELLO, 0x00, 0xff, 0xfc];
    first.extend_from_slice(&[0u8; 16380]);
    for payload in [first, vec![0u8; 16384], vec![0u8; 16384], vec![0u8; 16364]] {
        wire.push(CONTENT_HANDSHAKE);
        wire.extend_from_slice(&0x0301u16.to_be_bytes());
        wire.extend_from_slice(
            &u16::try_from(payload.len())
                .expect("record payload fits u16 wire length")
                .to_be_bytes(),
        );
        wire.extend_from_slice(&payload);
    }
    assert_eq!(
        wire.len(),
        MAX_CLIENT_HELLO,
        "exactly fills the inspection budget"
    );
    let mut inspector = ChInspector::new();
    let result = inspector.feed(&wire);
    assert_eq!(
        result,
        Err(ChError::HandshakeTooLarge { got: 65536 }),
        "full buffer without a complete hello must not panic"
    );
}

#[test]
fn non_handshake_pre_clienthello_rejected() {
    let mut msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
    msg[0] = 23;
    assert_eq!(
        parse_one(&msg),
        Err(ChError::NotHandshake { content_type: 23 })
    );
}

const SV: &[u8] = &[0x02, 0x03, 0x04];

#[test]
fn non_host_name_sni_rejected() {
    let wire = hello_with_extensions(&[
        (SUPPORTED_VERSIONS, SV),
        (SERVER_NAME, &server_name_ext(&[(1, b"unrecognized-type")])),
    ]);
    assert_eq!(
        parse_one(&wire),
        Err(ChError::InvalidServerName {
            detail: "non-host_name name type",
        }),
        "a server_name entry whose NameType is not host_name (0) must fail closed"
    );
}

#[test]
fn host_name_then_non_host_name_entry_rejected() {
    let wire = hello_with_extensions(&[
        (SUPPORTED_VERSIONS, SV),
        (
            SERVER_NAME,
            &server_name_ext(&[(0, b"sub.example.org"), (1, b"other")]),
        ),
    ]);
    assert_eq!(
        parse_one(&wire),
        Err(ChError::InvalidServerName {
            detail: "non-host_name name type",
        }),
        "a non-host_name entry must not be silently ignored, even alongside a valid host_name"
    );
}

#[test]
fn absent_sni_is_missing_identity() {
    let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV)]);
    let ch = parse_one(&wire).expect("an absent-SNI hello parses; validation denies it");
    assert_eq!(ch.sni_entries(), 0);
    assert_eq!(
        validate(&ch, &approved("sub.example.org")),
        Err(ChError::InvalidServerName {
            detail: "requires exactly one host_name entry",
        })
    );
}

#[test]
fn fragmented_short_first_record_is_rejected() {
    let mut inspector = ChInspector::new();
    assert_eq!(inspector.feed(&[22, 3, 1, 0, 2]), Ok(Inspect::NeedMore));
    assert_eq!(
        inspector.feed(&[1, 0]),
        Err(ChError::TruncatedHandshake),
        "a <4-byte first-record payload must fail closed regardless of fragmentation"
    );
}

#[test]
fn trailing_dot_other_domain_mismatch_still_rejected() {
    let msg = hello_msg(TLS12, &[TLS13], &["sub.example.com."], false);
    let ch = parse_one(&msg).expect("parse");
    assert_eq!(ch.server_name(), b"sub.example.com");
    assert_eq!(
        validate(&ch, &approved("sub.example.org")),
        Err(ChError::ServerNameMismatch),
        "normalizing a trailing dot must not mask a genuine two-domain mismatch"
    );
}

#[test]
fn accepts_exactly_32_offered_versions() {
    let versions = [TLS13; 32];
    let msg = hello_msg(TLS12, &versions, &["sub.example.org"], false);
    let ch = parse_one(&msg).expect("32 offered versions must parse");
    assert_eq!(ch.offered_versions().len(), 32);
}

#[test]
fn rejects_more_than_32_offered_versions() {
    let versions = [TLS13; 33];
    let msg = hello_msg(TLS12, &versions, &["sub.example.org"], false);
    assert_eq!(
        parse_one(&msg),
        Err(ChError::MalformedExtension {
            ext: SUPPORTED_VERSIONS,
        })
    );
}

#[test]
fn accepts_exactly_64_extensions() {
    let sni = server_name_ext(&[(0, b"sub.example.org")]);
    let mut exts = vec![(SUPPORTED_VERSIONS, SV), (SERVER_NAME, &sni)];
    for i in 0..62u16 {
        exts.push((0x100 + i, &b""[..]));
    }
    let ch = parse_one(&hello_with_extensions(&exts)).expect("64 distinct extensions must parse");
    assert_eq!(ch.sni_entries(), 1);
    assert_eq!(ch.server_name(), b"sub.example.org");
}

#[test]
fn rejects_more_than_64_extensions() {
    let sni = server_name_ext(&[(0, b"sub.example.org")]);
    let mut exts = vec![(SUPPORTED_VERSIONS, SV), (SERVER_NAME, &sni)];
    for i in 0..63u16 {
        exts.push((0x100 + i, &b""[..]));
    }
    assert_eq!(
        parse_one(&hello_with_extensions(&exts)),
        Err(ChError::TooManyExtensions)
    );
}

#[test]
fn retains_cipher_list_including_scsv() {
    let ciphers = [0x1301u16, 0x1302, 0x00ff, 0x002f];
    let wire = hello_with_ciphers_and_extensions(&ciphers, &[(SUPPORTED_VERSIONS, SV)]);
    let ch = parse_one(&wire).expect("parse");
    assert_eq!(ch.ciphers(), &ciphers);
}

#[test]
fn retains_extension_type_list_including_alpn_and_sigalgs() {
    let alpn = alpn_ext(&[b"h2"]);
    let sigalgs = [0x00u8, 0x04, 0x04, 0x01, 0x04, 0x03];
    let wire = hello_with_extensions(&[
        (SUPPORTED_VERSIONS, SV),
        (ALPN, &alpn),
        (SIGNATURE_ALGORITHMS, &sigalgs),
    ]);
    let ch = parse_one(&wire).expect("parse");
    assert_eq!(
        ch.extensions(),
        &[SUPPORTED_VERSIONS, ALPN, SIGNATURE_ALGORITHMS]
    );
}

#[test]
fn retains_alpn_first_value_bytes() {
    let alpn = alpn_ext(&[b"h2"]);
    let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (ALPN, &alpn)]);
    let ch = parse_one(&wire).expect("parse");
    assert_eq!(ch.alpn_first_value(), b"h2");
}

#[test]
fn retains_only_first_alpn_value() {
    let alpn = alpn_ext(&[b"h2", b"http/1.1"]);
    let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (ALPN, &alpn)]);
    let ch = parse_one(&wire).expect("parse");
    assert_eq!(ch.alpn_first_value(), b"h2");
}

#[test]
fn malformed_alpn_is_skipped_not_rejected() {
    let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (ALPN, &[0xff])]);
    let ch = parse_one(&wire).expect("a malformed ALPN extension must not reject the hello");
    assert_eq!(ch.alpn_first_value(), b"");
}

fn sigalgs_ext(values: &[u16]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(
        &u16::try_from(values.len() * 2)
            .expect("sigalgs list fits u16")
            .to_be_bytes(),
    );
    for value in values {
        data.extend_from_slice(&value.to_be_bytes());
    }
    data
}

#[test]
fn ja4_v1_published_vector_byte_for_byte() {
    let ciphers = [
        0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
        0xc02f, 0xc030, 0xcca8, 0xcca9,
    ];
    let ehash_exts = [
        0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d,
        0x0033, 0x4469, 0xff01,
    ];
    let sigalgs = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let alpn = alpn_ext(&[b"h2"]);
    let sni = server_name_ext(&[(0, b"sub.example.org")]);
    let sigalgs_data = sigalgs_ext(&sigalgs);
    let mut exts: Vec<(u16, &[u8])> = Vec::new();
    for ext in ehash_exts {
        let data: &[u8] = if ext == SUPPORTED_VERSIONS {
            SV
        } else if ext == SIGNATURE_ALGORITHMS {
            &sigalgs_data
        } else {
            &[]
        };
        exts.push((ext, data));
    }
    exts.push((SERVER_NAME, &sni));
    exts.push((ALPN, &alpn));
    let wire = hello_with_ciphers_and_extensions(&ciphers, &exts);
    let ch = parse_one(&wire).expect("parse");
    assert_eq!(ch.ja4(), *b"t13d1516h2_8daaf6152771_e5627efa2ab1");
}

#[test]
fn ja4_v4_spec_consistent_vector_byte_for_byte() {
    let ciphers = [
        0xaaaa, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ];
    let sigalgs = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let alpn = alpn_ext(&[&[0xba, 0xad]]);
    let sni = server_name_ext(&[(0, b"sub.example.org")]);
    let sigalgs_data = sigalgs_ext(&sigalgs);
    let exts: Vec<(u16, &[u8])> = vec![
        (0x9a9a, &[]),
        (0xff01, &[]),
        (0x0033, &[]),
        (0x002d, &[]),
        (0x0005, &[]),
        (0x4469, &[]),
        (SIGNATURE_ALGORITHMS, &sigalgs_data),
        (ALPN, &alpn),
        (0x0023, &[]),
        (0x001b, &[]),
        (SUPPORTED_VERSIONS, SV),
        (SERVER_NAME, &sni),
        (0x0012, &[]),
        (0x000a, &[]),
        (0x0017, &[]),
        (0x000b, &[]),
        (0x6a6a, &[]),
        (0x0015, &[]),
    ];
    let wire = hello_with_ciphers_and_extensions(&ciphers, &exts);
    let ch = parse_one(&wire).expect("parse");
    assert_eq!(ch.ja4(), *b"t13d1516bd_8daaf6152771_e5627efa2ab1");
}

#[test]
fn ja4_grease_filtered_from_counts_and_hashes() {
    let ciphers = [
        0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
        0xc02f, 0xc030, 0xcca8, 0xcca9, 0x1a1a,
    ];
    let ehash_exts = [
        0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d,
        0x0033, 0x4469, 0xff01, 0x2a2a,
    ];
    let sigalgs = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let alpn = alpn_ext(&[b"h2"]);
    let sni = server_name_ext(&[(0, b"sub.example.org")]);
    let sigalgs_data = sigalgs_ext(&sigalgs);
    let mut exts: Vec<(u16, &[u8])> = Vec::new();
    for ext in ehash_exts {
        let data: &[u8] = if ext == SUPPORTED_VERSIONS {
            SV
        } else if ext == SIGNATURE_ALGORITHMS {
            &sigalgs_data
        } else {
            &[]
        };
        exts.push((ext, data));
    }
    exts.push((SERVER_NAME, &sni));
    exts.push((ALPN, &alpn));
    let wire = hello_with_ciphers_and_extensions(&ciphers, &exts);
    let ch = parse_one(&wire).expect("parse");
    assert_eq!(
        ch.ja4(),
        *b"t13d1516h2_8daaf6152771_e5627efa2ab1",
        "GREASE ciphers and extensions must be filtered from counts and hashes"
    );
}

#[test]
fn ja4_version_tokens() {
    for (version, token) in [
        (0x0304u16, b"13"),
        (0x0303, b"12"),
        (0x0302, b"11"),
        (0x0301, b"10"),
        (0x0300, b"00"),
        (0x0400, b"00"),
    ] {
        let out = ja4_fingerprint(version, &[], &[], &[], &[])
            .expect("empty JA4 input fits fixed capacities");
        assert_eq!(&out[1..3], token, "version token for {version:#06x}");
    }
}

#[test]
fn ja4_ver_falls_back_to_record_layer_protocol_version() {
    let ch = ClientHello {
        versions: [0u16; MAX_VERSIONS],
        versions_len: 0,
        sni: [0u8; FQDN_MAX_LEN],
        sni_len: 0,
        sni_entries: 0,
        has_ech: false,
        ciphers: [0u16; MAX_CIPHERS],
        ciphers_len: 0,
        extensions: [0u16; MAX_EXTENSIONS],
        extensions_len: 0,
        alpn: [0u8; MAX_ALPN_VALUE],
        alpn_len: 0,
        sigalgs: [0u16; MAX_SIGALGS],
        sigalgs_len: 0,
        record_version: TLS12,
    };
    assert_eq!(
        &ch.ja4()[1..3],
        b"12",
        "an empty supported_versions must fall back to the record-layer protocol version, not 00"
    );
}

#[test]
fn ja4_v2_structural_intent_tls12_no_alpn() {
    let ciphers: Vec<u16> = (0..19u16).map(|i| 0x0100 + i).collect();
    let exts: Vec<u16> = std::iter::once(0x0000)
        .chain((0..7u16).map(|i| 0x1000 + i))
        .collect();
    let out = ja4_fingerprint(0x0303, &ciphers, &exts, &[], &[])
        .expect("test JA4 input fits fixed capacities");
    assert_eq!(
        out, *b"t12d190800_e5f6c4506bb0_04d33385c057",
        "empty sigalgs must omit the e-hash underscore (JA4.md: no sigalgs -> string ends without underscore)"
    );
}

#[test]
fn ja4_v3_structural_intent_46_ciphers_with_scsv() {
    let mut ciphers: Vec<u16> = (0..46u16).map(|i| 0x0100 + i).collect();
    ciphers[0] = 0x00ff;
    let alpn = alpn_ext(&[b"h2"]);
    let sni = server_name_ext(&[(0, b"sub.example.org")]);
    let exts = [
        (SUPPORTED_VERSIONS, SV),
        (SERVER_NAME, &sni),
        (ALPN, &alpn),
        (0x0005, &b""[..]),
        (0x000a, &b""[..]),
    ];
    let wire = hello_with_ciphers_and_extensions(&ciphers, &exts);
    let ch = parse_one(&wire).expect("parse");
    assert_eq!(&ch.ja4()[..10], b"t13d4605h2");
    assert_eq!(ch.ja4().len(), 36);
}

/// Byte-for-byte V2 gate: S4 (latest.pcapng stream 3, SNI
/// discovery.cem.cloud.us) wire lists from evidence bead alumina-2rkgn.
/// `legacy_version` 0303, no 0x002b, no ALPN, no GREASE.
#[test]
fn ja4_v2_published_vector_byte_for_byte() {
    let ciphers = [
        0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014,
        0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x000a,
    ];
    let exts = [
        0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0023, 0x0017, 0xff01,
    ];
    let sigalgs = [
        0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601,
        0x0603,
    ];
    let out = ja4_fingerprint(0x0303, &ciphers, &exts, &[], &sigalgs)
        .expect("test JA4 input fits fixed capacities");
    assert_eq!(out, *b"t12d190800_d83cc789557e_7af1ed941c26");
}

/// Byte-for-byte V3 gate: S5 (tls-alpn-h2.pcap stream 0, SNI
/// www.cloudflare.com) wire lists from evidence bead alumina-2rkgn.
/// `legacy_version` 0303, no 0x002b, ALPN first value "h2", no GREASE.
#[test]
fn ja4_v3_published_vector_byte_for_byte() {
    let ciphers = [
        0xc030, 0xc02c, 0xc028, 0xc024, 0xc014, 0xc00a, 0x009f, 0x006b, 0x0039, 0xcca9, 0xcca8,
        0xccaa, 0xff85, 0x00c4, 0x0088, 0x0081, 0x009d, 0x003d, 0x0035, 0x00c0, 0x0084, 0xc02f,
        0xc02b, 0xc027, 0xc023, 0xc013, 0xc009, 0x009e, 0x0067, 0x0033, 0x00be, 0x0045, 0x009c,
        0x003c, 0x002f, 0x00ba, 0x0041, 0xc011, 0xc007, 0x0005, 0x0004, 0xc012, 0xc008, 0x0016,
        0x000a, 0x00ff,
    ];
    let exts = [0x0000, 0x000b, 0x000a, 0x000d, 0x0010];
    let sigalgs = [
        0x0601, 0x0603, 0xefef, 0x0501, 0x0503, 0x0401, 0x0403, 0xeeee, 0xeded, 0x0301, 0x0303,
        0x0201, 0x0203,
    ];
    let out = ja4_fingerprint(0x0303, &ciphers, &exts, b"h2", &sigalgs)
        .expect("test JA4 input fits fixed capacities");
    assert_eq!(out, *b"t12d4605h2_85626a9a5f7f_aaf95bb78ec9");
}

#[test]
fn ja4_empty_lists_use_sentinel_hashes() {
    let out =
        ja4_fingerprint(0x0304, &[], &[], &[], &[]).expect("empty JA4 input fits fixed capacities");
    assert_eq!(out, *b"t13i000000_000000000000_000000000000");
}

#[test]
fn ja4_hashed_extensions_at_max_capacity_ok() {
    let extensions: Vec<u16> = (0..MAX_EXTENSIONS)
        .map(|i| 0x1000 + u16::try_from(i).expect("extension index fits u16"))
        .collect();
    let out = ja4_fingerprint(0x0304, &[], &extensions, &[], &[])
        .expect("64 hashed extensions fit the fixed capacity");
    assert_eq!(out.len(), 36);
}

#[test]
fn ja4_hashed_extensions_over_max_capacity_err() {
    let extensions: Vec<u16> = (0..=MAX_EXTENSIONS)
        .map(|i| 0x1000 + u16::try_from(i).expect("extension index fits u16"))
        .collect();
    assert_eq!(
        ja4_fingerprint(0x0304, &[], &extensions, &[], &[]),
        Err(Ja4Error::TooManyExtensions)
    );
}

#[test]
fn ja4_grease_sni_alpn_extensions_do_not_consume_capacity() {
    let mut extensions: Vec<u16> = (0..MAX_EXTENSIONS)
        .map(|i| 0x1000 + u16::try_from(i).expect("extension index fits u16"))
        .collect();
    extensions.push(SERVER_NAME);
    extensions.push(ALPN);
    extensions.extend([0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a]);
    let out = ja4_fingerprint(0x0304, &[], &extensions, &[], &[])
        .expect("GREASE/SNI/ALPN extensions are filtered before the capacity check");
    assert_eq!(out.len(), 36);
}

#[test]
fn ja4_hashed_ciphers_at_max_capacity_ok() {
    let ciphers: Vec<u16> = (0..MAX_CIPHERS + 2)
        .map(|i| 0x0100 + u16::try_from(i).expect("cipher index fits u16"))
        .filter(|&c| !is_grease(c))
        .take(MAX_CIPHERS)
        .collect();
    let out = ja4_fingerprint(0x0304, &ciphers, &[], &[], &[])
        .expect("8192 hashed ciphers fit the fixed capacity");
    assert_eq!(out.len(), 36);
}

#[test]
fn ja4_hashed_ciphers_over_max_capacity_err() {
    let ciphers: Vec<u16> = (0..MAX_CIPHERS + 3)
        .map(|i| 0x0100 + u16::try_from(i).expect("cipher index fits u16"))
        .filter(|&c| !is_grease(c))
        .take(MAX_CIPHERS + 1)
        .collect();
    assert_eq!(
        ja4_fingerprint(0x0304, &ciphers, &[], &[], &[]),
        Err(Ja4Error::TooManyCiphers)
    );
}

#[test]
fn ja4_grease_ciphers_do_not_consume_capacity() {
    let mut ciphers: Vec<u16> = (0..MAX_CIPHERS + 2)
        .map(|i| 0x0100 + u16::try_from(i).expect("cipher index fits u16"))
        .filter(|&c| !is_grease(c))
        .take(MAX_CIPHERS)
        .collect();
    ciphers.extend([0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a]);
    let out = ja4_fingerprint(0x0304, &ciphers, &[], &[], &[])
        .expect("GREASE ciphers are filtered before the capacity check");
    assert_eq!(out.len(), 36);
}

#[test]
fn retains_sigalgs_values_in_wire_order() {
    let sigalgs = [0x0403u16, 0x0804, 0x0401];
    let data = sigalgs_ext(&sigalgs);
    let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (SIGNATURE_ALGORITHMS, &data)]);
    let ch = parse_one(&wire).expect("parse");
    assert_eq!(ch.sigalgs(), &sigalgs);
}

#[test]
fn sigalgs_odd_length_retains_nothing() {
    let sigalgs = [0x00u8, 0x03, 0x04, 0x03, 0x04];
    let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (SIGNATURE_ALGORITHMS, &sigalgs)]);
    let ch = parse_one(&wire).expect("parse");
    assert!(ch.sigalgs().is_empty(), "sigalgs should be empty");
}

#[test]
fn sigalgs_declared_len_exceeding_data_retains_nothing() {
    let sigalgs = [0x00u8, 0x64, 0x04, 0x03];
    let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (SIGNATURE_ALGORITHMS, &sigalgs)]);
    let ch = parse_one(&wire).expect("parse");
    assert!(ch.sigalgs().is_empty(), "sigalgs should be empty");
}

#[test]
fn sigalgs_over_max_sigalgs_rejected() {
    let values: Vec<u16> = (0..70u16).map(|i| 0x0400 + i).collect();
    let data = sigalgs_ext(&values);
    let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (SIGNATURE_ALGORITHMS, &data)]);
    assert_eq!(parse_one(&wire), Err(ChError::TooManySigAlgs));
}

#[test]
fn sigalgs_at_max_sigalgs_accepted() {
    let values: Vec<u16> = (0..MAX_SIGALGS)
        .map(|i| 0x0400 + u16::try_from(i).expect("sigalg index fits u16"))
        .collect();
    let data = sigalgs_ext(&values);
    let wire = hello_with_extensions(&[(SUPPORTED_VERSIONS, SV), (SIGNATURE_ALGORITHMS, &data)]);
    let ch = parse_one(&wire).expect("parse");
    assert_eq!(ch.sigalgs(), &values[..]);
}

#[test]
fn sigalgs_over_max_rejects_as_profile() {
    assert_eq!(
        HelloRejectReason::from_ch_error(&ChError::TooManySigAlgs),
        HelloRejectReason::Profile
    );
}

#[cfg(feature = "alloc-witness")]
#[test]
fn ja4_path_is_allocation_free() {
    use crate::alloc::{self, Phase};
    let ciphers = [
        0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
        0xc02f, 0xc030, 0xcca8, 0xcca9,
    ];
    let ehash_exts = [
        0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d,
        0x0033, 0x4469, 0xff01,
    ];
    let sigalgs = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let alpn = alpn_ext(&[b"h2"]);
    let sni = server_name_ext(&[(0, b"sub.example.org")]);
    let sigalgs_data = sigalgs_ext(&sigalgs);
    let mut exts: Vec<(u16, &[u8])> = Vec::new();
    for ext in ehash_exts {
        let data: &[u8] = if ext == SUPPORTED_VERSIONS {
            SV
        } else if ext == SIGNATURE_ALGORITHMS {
            &sigalgs_data
        } else {
            &[]
        };
        exts.push((ext, data));
    }
    exts.push((SERVER_NAME, &sni));
    exts.push((ALPN, &alpn));
    let wire = hello_with_ciphers_and_extensions(&ciphers, &exts);
    let ch = parse_one(&wire).expect("parse");
    let full_exts = [
        0x0005,
        0x000a,
        0x000b,
        0x000d,
        0x0012,
        0x0015,
        0x0017,
        0x001b,
        0x0023,
        0x002b,
        0x002d,
        0x0033,
        0x4469,
        0xff01,
        SERVER_NAME,
        ALPN,
    ];

    let (out, counts) = alloc::run_phase(Phase::Serving, || {
        let pure = ja4_fingerprint(0x0304, &ciphers, &full_exts, b"h2", &sigalgs)
            .expect("test JA4 input fits fixed capacities");
        let method = ch.ja4();
        (pure, method)
    });
    assert_eq!(out.0, *b"t13d1516h2_8daaf6152771_e5627efa2ab1");
    assert_eq!(out.1, out.0);
    assert!(
        counts.all_zero(),
        "the JA4 computation path (pure fn + ClientHello::ja4) must be allocation-free: {counts:?}"
    );
}

#[test]
fn rejects_bad_record_version() {
    for bad in [0x0304u16, 0x0002, 0x0300] {
        let mut msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        msg[1] = (bad >> 8) as u8;
        msg[2] = (bad & 0xff) as u8;
        assert_eq!(parse_one(&msg), Err(ChError::BadRecordVersion { got: bad }));
    }
}

#[test]
fn rejects_unsupported_legacy_version() {
    for legacy in [0x0302u16, 0x0301] {
        let msg = hello_msg(legacy, &[TLS13], &["sub.example.org"], false);
        assert_eq!(
            parse_one(&msg),
            Err(ChError::UnsupportedLegacyVersion { got: legacy })
        );
    }
}

#[test]
fn rejects_missing_compression_methods() {
    let msg = hello_msg_comp(TLS12, &[TLS13], &["sub.example.org"], false, 0);
    let handshake = &msg[5..];
    let body = &handshake[4..];
    let mut new_body = Vec::new();
    new_body.extend_from_slice(&body[..41]);
    new_body.push(0);
    new_body.extend_from_slice(&body[43..]);
    let mut no_comp = vec![HANDSHAKE_CLIENT_HELLO];
    let hl = u32::try_from(new_body.len()).expect("client hello body fits u32");
    no_comp.extend_from_slice(&hl.to_be_bytes()[1..]);
    no_comp.extend_from_slice(&new_body);
    let record = record(&no_comp);
    assert_eq!(parse_one(&record), Err(ChError::MissingCompressionMethods));
}

#[test]
fn rejects_empty_sni_host_name() {
    let wire = hello_with_extensions(&[
        (SUPPORTED_VERSIONS, SV),
        (SERVER_NAME, &server_name_ext(&[(0, b"")])),
    ]);
    assert_eq!(
        parse_one(&wire),
        Err(ChError::InvalidServerName {
            detail: "host_name is not a legal FQDN",
        }),
        "a zero-length SNI host_name must fail closed at the wire/parser layer"
    );
}

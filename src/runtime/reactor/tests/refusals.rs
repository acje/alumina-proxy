use super::*;

#[test]
fn refused_wire_bodies_are_pinned_plain_text() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut expect = |name: &str, refusal: Refusal, want: &'static [u8]| {
            let mut client = connect(port);
            pump(serving, 20);
            assert_eq!(
                serving.storage().occupied(),
                1,
                "{name}: the refused client must be admitted first"
            );
            serving.refuse(0, refusal);
            let body = read_all(&mut client);
            assert_eq!(
                &body[..],
                want,
                "{name}: the exact wire body must be pinned plain text"
            );
        };
        expect(
            "no-resolved-addresses",
            Refusal::NoResolvedAddresses,
            b"HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 22\r\n\r\nno resolved addresses\n",
        );
        expect(
            "dial-failed",
            Refusal::DialFailed,
            b"HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 27\r\n\r\nupstream connection failed\n",
        );
        expect(
            "setup-timeout",
            Refusal::SetupTimeout,
            b"HTTP/1.1 504 Gateway Timeout\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 23\r\n\r\nsetup deadline expired\n",
        );
    });
}

#[test]
/// The five pre-Peer refusal sites carry the requested hostname into the
/// reject telemetry even though `slot.approved` is not yet set (G11-C01): a
/// `Forbidden` and a `NoResolvedAddresses` rejection must both emit
/// `hostname="<requested>"` on the warn-reject record — never a raw-SNI or a
/// missing hostname field.
fn pre_peer_refusals_carry_requested_hostname_in_reject_record() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "connection", "notify", "connection");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let mut forbidden = connect(port);
        forbidden
            .write_all(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
            .expect("forbidden head");
        pump(serving, 20);
        let fb = read_until(&mut forbidden, b"\r\n\r\n");
        assert!(
            fb.starts_with(b"HTTP/1.1 403"),
            "a non-allowlisted CONNECT must be 403, got {fb:?}"
        );
        let record = serving
            .storage()
            .logs()
            .last_record_bytes()
            .expect("Forbidden reject record");
        let text = String::from_utf8_lossy(record);
        assert!(
            text.contains("kind=reject") && text.contains("reason=\"forbidden\""),
            "the Forbidden refusal must emit a reject record: {text}"
        );
        assert!(
            text.contains("hostname=\"evil.example\""),
            "the Forbidden reject record must carry the requested hostname: {text}"
        );

        let mut unresolved = connect(port);
        unresolved
            .write_all(b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n")
            .expect("unresolved head");
        pump(serving, 20);
        let ub = read_until(&mut unresolved, b"\r\n\r\n");
        assert!(
            ub.starts_with(b"HTTP/1.1 502"),
            "an allowlisted CONNECT against an unpopulated cache must 502, got {ub:?}"
        );
        let record = serving
            .storage()
            .logs()
            .last_record_bytes()
            .expect("NoResolvedAddresses reject record");
        let text = String::from_utf8_lossy(record);
        assert!(
            text.contains("kind=reject") && text.contains("reason=\"dial_failed\""),
            "the NoResolvedAddresses refusal must emit a reject record: {text}"
        );
        assert!(
            text.contains("hostname=\"sub.example.org\""),
            "the NoResolvedAddresses reject record must carry the requested hostname: {text}"
        );
    });
}

#[test]
/// The pre-Peer `SetupTimeout` refusal must carry the requested hostname into
/// the reject telemetry once the CONNECT head has parsed (G11-C01): an
/// expired setup on a `ReadingConnect` slot whose parser holds a valid
/// request emits `hostname="<requested>"` on the warn-reject record, matching
/// the other pre-Peer refusal sites.
fn expire_setup_timeout_carries_requested_hostname_in_reject_record() {
    use crate::inspection::connect::Feed;
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut client = connect(port);
        pump(serving, 10);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );
        match serving.slots[0]
            .parser
            .feed(b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n")
            .expect("head feed")
        {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        assert!(
            matches!(serving.slots[0].stage, Stage::ReadingConnect),
            "a parser-fed head alone must leave the slot in ReadingConnect"
        );
        serving.expire_setup(0);
        let record = serving
            .storage()
            .logs()
            .last_record_bytes()
            .expect("SetupTimeout reject record");
        let text = String::from_utf8_lossy(record);
        assert!(
            text.contains("kind=reject") && text.contains("reason=\"setup_timeout\""),
            "the SetupTimeout refusal must emit a reject record: {text}"
        );
        assert!(
            text.contains("hostname=\"sub.example.org\""),
            "the pre-Peer SetupTimeout reject record must carry the requested hostname: {text}"
        );
        let body = read_until(&mut client, b"\r\n\r\n");
        assert!(
            body.starts_with(b"HTTP/1.1 504"),
            "an expired pre-Peer setup must receive 504, got {body:?}"
        );
    });
}

#[test]
/// The pre-Peer `SetupTimeout` refusal must NOT carry a hostname when the
/// CONNECT head has not parsed (G11-C01, docs/alumina-proxy.md:198): an
/// expired setup on a `ReadingConnect` slot whose parser holds no result
/// still emits the 504 reject record, but with the hostname field absent —
/// the hostname is carried only when the parsed request is valid.
fn expire_setup_timeout_without_parsed_head_omits_hostname() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut client = connect(port);
        pump(serving, 10);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );
        assert!(
            serving.slots[0].parser.result().is_none(),
            "precondition: no head has been fed, so the parser holds no result"
        );
        serving.expire_setup(0);
        let record = serving
            .storage()
            .logs()
            .last_record_bytes()
            .expect("SetupTimeout reject record");
        let text = String::from_utf8_lossy(record);
        assert!(
            text.contains("kind=reject") && text.contains("reason=\"setup_timeout\""),
            "the SetupTimeout refusal must emit a reject record: {text}"
        );
        assert!(
            !text.contains("hostname="),
            "an unparsed pre-Peer SetupTimeout reject record must omit the hostname: {text}"
        );
        let body = read_until(&mut client, b"\r\n\r\n");
        assert!(
            body.starts_with(b"HTTP/1.1 504"),
            "an expired pre-Peer setup must receive 504, got {body:?}"
        );
    });
}

#[test]
fn capacity_refusal_wire_body_is_pinned_plain_text() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut socks = Vec::new();
        for i in 0..=MAX_PENDING_SETUPS {
            socks.push(connect(port));
            if i % 16 == 15 {
                pump(serving, 4);
            }
        }
        pump(serving, 80);
        let mut last = socks[MAX_PENDING_SETUPS].try_clone().expect("clone");
        let body = read_all(&mut last);
        assert_eq!(
            &body[..],
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 12\r\n\r\nno capacity\n",
            "a capacity refusal must carry the pinned plain-text 503 body"
        );
    });
}

use super::*;
use std::net::{Ipv4Addr, TcpListener as StdListener, TcpStream};
use std::time::{Duration, Instant};

use crate::enforcement::policy::UnknownReason;
use crate::worker::{MAX_PENDING_SETUPS, SETUP_DEADLINE_SECS};

const RETAINED_OFFSET: usize = 137;

fn config(port: u16) -> crate::config::Config {
    let doc = format!(
        "allowlist = [\"sub.example.org:443\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\"]\nscope = [\"connection\"]\n"
    );
    crate::config::parse_config_document(&doc).expect("valid test config")
}

fn ephemeral_port() -> u16 {
    let probe = StdListener::bind("127.0.0.1:0").expect("bind probe");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

fn with_serving_stack(port: u16, body: impl FnOnce(&mut Serving) + Send + 'static) {
    let t = std::thread::Builder::new()
        .name("serving-test".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let mut serving = serve_on(port);
            body(&mut serving);
        })
        .expect("spawn serving thread");
    t.join().expect("serving thread");
}

fn serve_on(port: u16) -> Serving {
    let storage = ServeStorage::boot(&config(port)).expect("boot storage");
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), port))
        .expect("bind listener");
    let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
    Serving::new(storage, listener, traffic).expect("serving")
}

#[test]
fn serving_poll_timeout_folds_queued_log_drain_into_earliest_wait() {
    with_serving_stack(ephemeral_port(), |serving| {
        assert_eq!(
            serving.poll_timeout(),
            None,
            "no slots, no dns deadline, empty log queue: idle serving has no wait"
        );
        serving.storage_mut().logs_mut().startup_warning(
            1,
            "sub.example.org",
            crate::cache::Family::A,
        );
        assert_eq!(
            serving.poll_timeout(),
            Some(Duration::ZERO),
            "a queued runnable log folds to an immediate wake with no traffic (T3)"
        );
    });
}

#[test]
fn serving_poll_timeout_folds_bounded_floor_for_idle_selectable_now_due() {
    with_serving_stack(ephemeral_port(), |serving| {
        let secs = serving.storage().dns().now_u64();
        serving
            .storage_mut()
            .schedules_mut()
            .overwrite_due_at(0, crate::cache::Family::A, secs)
            .expect("due the A family now");
        let wait = serving.poll_timeout();
        assert!(
            matches!(wait, Some(d) if d >= Duration::from_millis(50) && d <= Duration::from_millis(200)),
            "an idle transport with a selectable-now due slot folds a bounded floor wake so \
             an indefinite production poll initiates the refresh without busy-spinning: \
             {wait:?}"
        );
    });
}

#[test]
fn serving_consumes_boot_traffic_buffers_by_value_not_reallocation() {
    std::thread::Builder::new()
        .name("serving-transfer-test".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(transfer_body)
        .expect("spawn transfer test")
        .join()
        .expect("transfer test thread");
}

fn transfer_body() {
    use crate::inventory::TrafficStorage;
    let port = ephemeral_port();
    let storage = ServeStorage::boot(&config(port)).expect("boot storage");
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), port))
        .expect("bind listener");
    let traffic = TrafficStorage::allocate().expect("boot traffic");
    let first_up = traffic.slots()[0].up.as_ptr();
    let last_down = traffic.slots()[MAX_TUNNELS - 1].down.as_ptr();
    let serving = Serving::new(storage, listener, traffic).expect("serving");
    assert_eq!(
        serving.slots[0].buf.as_ptr(),
        first_up,
        "slot 0 hold buffer must transfer by value without a second allocation"
    );
    assert_eq!(
        serving.slots[MAX_TUNNELS - 1].down.as_ptr(),
        last_down,
        "slot 511 down buffer must transfer by value without a second allocation"
    );
}

fn pump(serving: &mut Serving, times: usize) {
    for _ in 0..times {
        serving
            .run_once(Some(Duration::from_millis(2)))
            .expect("pump poll");
    }
}

#[cfg(all(test, feature = "alloc-witness"))]
fn turn_pump(runtime: &mut crate::runtime::Runtime, times: usize) {
    for _ in 0..times {
        runtime
            .turn(Some(Duration::from_millis(2)))
            .expect("an owner turn inside the witnessed shutdown may not error and stay silent");
    }
}

fn connect(port: u16) -> TcpStream {
    TcpStream::connect(SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), port))
        .expect("client connect")
}

fn wait_upstream_connected(up: &mio::net::TcpStream) {
    for _ in 0..10_000 {
        if up.peer_addr().is_ok() {
            return;
        }
        std::thread::yield_now();
    }
    panic!("the nonblocking upstream connect never resolved");
}

fn read_until(stream: &mut TcpStream, marker: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.windows(marker.len()).any(|w| w == marker) {
                    break;
                }
            }
        }
    }
    out
}

/// Puts the slot into an open-gate relay with a typed head/hello boundary,
/// so focused relay tests can drive real sockets through the actual owner.
fn open_relay(serving: &mut Serving, index: usize) {
    let ws = &mut serving.slots[index];
    ws.stage = Stage::Relay;
    ws.gate.on_connect_head(4);
    ws.gate.on_authorized();
    ws.gate.on_upstream_connected();
    ws.gate.on_response_ok();
    ws.gate.on_hello_validated(ValidatedHello::test_new(10));
    ws.gate.upstream_write(6);
}

#[test]
fn read_outcome_distinguishes_activity_from_retry_wait_and_failure() {
    use std::io::ErrorKind::{ConnectionReset, Interrupted, NotConnected, Unsupported, WouldBlock};
    assert_eq!(classify_read(&Ok(7)), ReadOutcome::Activity(Activity::Data));
    assert_eq!(classify_read(&Ok(0)), ReadOutcome::Activity(Activity::Eof));
    assert_eq!(
        classify_read(&Err(io::Error::from(ConnectionReset))),
        ReadOutcome::Activity(Activity::Reset),
        "an actual connection-reset read is the only error classified as early reset"
    );
    assert_eq!(
        classify_read(&Err(io::Error::from(WouldBlock))),
        ReadOutcome::Wait,
        "WouldBlock/readiness is not activity"
    );
    assert_eq!(
        classify_read(&Err(io::Error::from(Interrupted))),
        ReadOutcome::Retry,
        "an interrupted read is retried, never reported as a remote reset"
    );
    assert_eq!(
        classify_read(&Err(io::Error::from(NotConnected))),
        ReadOutcome::Failed,
        "a not-yet-connected read is a setup failure, never silent waiting"
    );
    assert_eq!(
        classify_read(&Err(io::Error::from(Unsupported))),
        ReadOutcome::Failed,
        "an unknown non-reset failure keeps its identity; it is never labelled early reset"
    );
}

fn hello_wire(sni: &[u8], ech_only: bool) -> Vec<u8> {
    hello_wire_ext(sni, ech_only, &[])
}

/// Builds a `ClientHello` wire frame with optional extra extensions appended
/// after the supported-versions/SNI pair, so fixtures can vary a fingerprint
/// input (e.g. an ALPN value) while keeping the rest of the hello identical.
fn hello_wire_ext(sni: &[u8], ech_only: bool, extra_ext: &[(u16, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x2a; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    if ech_only {
        ext.extend_from_slice(&[0xfe, 0x0d, 0x00, 0x00]);
    } else {
        let list_len = 3 + sni.len();
        ext.extend_from_slice(&[0x00, 0x00]);
        let len = 2 + list_len;
        ext.extend_from_slice(
            &u16::try_from(len)
                .expect("server name extension length fits u16")
                .to_be_bytes(),
        );
        ext.extend_from_slice(
            &u16::try_from(list_len)
                .expect("server name list length fits u16")
                .to_be_bytes(),
        );
        ext.push(0x00);
        ext.extend_from_slice(
            &u16::try_from(sni.len())
                .expect("sni name length fits u16")
                .to_be_bytes(),
        );
        ext.extend_from_slice(sni);
    }
    for &(ext_type, data) in extra_ext {
        ext.extend_from_slice(&ext_type.to_be_bytes());
        ext.extend_from_slice(
            &u16::try_from(data.len())
                .expect("extra extension length fits u16")
                .to_be_bytes(),
        );
        ext.extend_from_slice(data);
    }
    body.extend_from_slice(
        &u16::try_from(ext.len())
            .expect("extensions length fits u16")
            .to_be_bytes(),
    );
    body.extend_from_slice(&ext);

    let mut hs = vec![0x01];
    hs.extend_from_slice(
        &u32::try_from(body.len())
            .expect("client hello body fits u32")
            .to_be_bytes()[1..],
    );
    hs.extend_from_slice(&body);

    let mut record = Vec::new();
    record.extend_from_slice(&[0x16, 0x03, 0x03]);
    record.extend_from_slice(
        &u16::try_from(hs.len())
            .expect("handshake length fits u16")
            .to_be_bytes(),
    );
    record.extend_from_slice(&hs);
    record
}

fn hello_wire_no_sni() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x2a; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    let ext = [0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
    body.extend_from_slice(
        &u16::try_from(ext.len())
            .expect("extensions length fits u16")
            .to_be_bytes(),
    );
    body.extend_from_slice(&ext);

    let mut hs = vec![0x01];
    hs.extend_from_slice(
        &u32::try_from(body.len())
            .expect("client hello body fits u32")
            .to_be_bytes()[1..],
    );
    hs.extend_from_slice(&body);

    let mut record = Vec::new();
    record.extend_from_slice(&[0x16, 0x03, 0x03]);
    record.extend_from_slice(
        &u16::try_from(hs.len())
            .expect("handshake length fits u16")
            .to_be_bytes(),
    );
    record.extend_from_slice(&hs);
    record
}

fn drive_hello(serving: &mut Serving, wire: &[u8], approved: &str) {
    let index = 0;
    let ws = &mut serving.slots[index];
    ws.buf_base = 0;
    ws.buf_len = wire.len();
    ws.buf[..wire.len()].copy_from_slice(wire);
    ws.parse_rel = 0;
    ws.insp_rel = 0;
    ws.head_len = 0;
    ws.hello_end = None;
    ws.hello_consumed = 0;
    ws.fwd = 0;
    ws.approved = FixedHostname::normalize(approved.as_bytes());
    ws.stage = Stage::ValidatingHello;
    ws.gate.on_connect_head(0);
    ws.gate.on_authorized();
    ws.gate.on_upstream_connected();
    ws.gate.on_response_ok();
    serving.buffer_and_validate(index, &[]);
}

#[test]
fn forbidden_connect_gets_403_and_releases_the_slot() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut client = connect(port);
        client
            .write_all(b"CONNECT evil.example.net:443 HTTP/1.1\r\n\r\n")
            .expect("write head");
        pump(serving, 80);
        let body = read_until(&mut client, b"\r\n\r\n");
        assert!(
            body.starts_with(b"HTTP/1.1 403"),
            "forbidden CONNECT must receive 403, got {body:?}"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the refused slot must be released"
        );
    });
}

#[test]
fn refused_slot_is_reusable_after_release() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut c1 = connect(port);
        c1.write_all(b"CONNECT nope.example.net:443 HTTP/1.1\r\n\r\n")
            .expect("write head");
        pump(serving, 80);
        let b1 = read_until(&mut c1, b"\r\n\r\n");
        assert!(b1.starts_with(b"HTTP/1.1 403"));

        let mut c2 = connect(port);
        c2.write_all(b"CONNECT also-not.example.net:443 HTTP/1.1\r\n\r\n")
            .expect("write head");
        pump(serving, 80);
        let b2 = read_until(&mut c2, b"\r\n\r\n");
        assert!(b2.starts_with(b"HTTP/1.1 403"));
        assert_eq!(
            serving.storage().occupied(),
            0,
            "both refused slots must be released"
        );
    });
}

#[test]
fn client_fin_during_reading_connect_releases_the_setup_slot() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut client = connect(port);
        client
            .write_all(b"CONNECT sub.example.org:443 HTTP/1.1\r\n")
            .expect("write partial head");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("client fin during reading connect");
        pump(serving, 80);
        assert_eq!(
            serving.storage().occupied(),
            0,
            "a client FIN during ReadingConnect must release the setup seat immediately"
        );
    });
}

#[test]
fn hello_with_sni_mismatch_is_rejected_without_forwarding() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let wire = hello_wire(b"evil.example.net", false);
        let mut insp = ChInspector::new();
        assert!(matches!(insp.feed(&wire), Ok(Inspect::Complete { .. })));
        let approved = FixedHostname::normalize(b"sub.example.org");
        assert_eq!(
            client_hello::validate(insp.hello().expect("parsed hello"), &approved.unwrap()),
            Err(client_hello::ChError::ServerNameMismatch),
            "the fixture must fail validation only on the SNI, not on parsing"
        );
        drive_hello(serving, &wire, "sub.example.org");
        assert_eq!(
            serving.slots[0].fwd, 0,
            "no client byte may be forwarded upstream"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the rejected connection is closed and its seat released"
        );
    });
}

#[test]
fn hello_with_ech_is_rejected_without_forwarding() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let wire = hello_wire(b"sub.example.org", true);
        let mut insp = ChInspector::new();
        assert!(matches!(insp.feed(&wire), Ok(Inspect::Complete { .. })));
        let approved = FixedHostname::normalize(b"sub.example.org");
        assert_eq!(
            client_hello::validate(insp.hello().expect("parsed hello"), &approved.unwrap()),
            Err(client_hello::ChError::EchPresent),
            "the fixture must fail validation on ECH"
        );
        drive_hello(serving, &wire, "sub.example.org");
        assert_eq!(serving.slots[0].fwd, 0);
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the ECH connection is closed without forwarding"
        );
    });
}

#[test]
fn hello_without_sni_identity_is_rejected_without_forwarding() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let wire = hello_wire_no_sni();
        let mut insp = ChInspector::new();
        assert!(
            matches!(insp.feed(&wire), Ok(Inspect::Complete { .. })),
            "the absent-SNI fixture must parse so validation is what denies it"
        );
        let approved = FixedHostname::normalize(b"sub.example.org");
        assert_eq!(
            client_hello::validate(insp.hello().expect("parsed hello"), &approved.unwrap()),
            Err(client_hello::ChError::InvalidServerName {
                detail: "requires exactly one host_name entry",
            }),
            "an absent SNI is a missing-identity denial, not a mismatch"
        );
        drive_hello(serving, &wire, "sub.example.org");
        assert_eq!(
            serving.slots[0].fwd, 0,
            "no client byte may be forwarded upstream for a hello with no SNI identity"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the missing-identity connection is closed and its seat released"
        );
    });
}

#[test]
fn hello_with_illegal_sni_name_is_rejected_without_forwarding() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let wire = hello_wire(b"!bad", false);
        let mut insp = ChInspector::new();
        assert!(
            matches!(
                insp.feed(&wire),
                Err(client_hello::ChError::InvalidServerName { .. })
            ),
            "an illegal FQDN host_name must fail parsing as malformed identity"
        );
        drive_hello(serving, &wire, "sub.example.org");
        assert_eq!(
            serving.slots[0].fwd, 0,
            "no client byte may be forwarded upstream for a malformed SNI identity"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the malformed-identity connection is closed and its seat released"
        );
    });
}

#[test]
fn matching_hello_is_accepted_and_enters_the_hello_write() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let wire = hello_wire(b"sub.example.org", false);
        drive_hello(serving, &wire, "sub.example.org");
        let ws = &serving.slots[0];
        assert!(matches!(ws.stage, Stage::WritingHello));
        assert_eq!(ws.hello_end, Some(wire.len()));
        assert_eq!(ws.fwd, 0, "no upstream socket yet; nothing forwarded");
    });
}

#[test]
fn pipelined_clienthello_pre200_is_drained_on_validating_hello_entry() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;
        wait_upstream_connected(&client);
        let _ = peer_stream.set_nodelay(true);

        let wire = hello_wire(b"sub.example.org", false);
        peer_stream
            .write_all(&wire)
            .expect("clienthello pipelined before the CONNECT response completes");
        let mut delivered = [0u8; 128];
        let hello_delivered = loop {
            match client.peek(&mut delivered) {
                Ok(n) if n == wire.len() => break true,
                Ok(_) => break false,
                Err(_) => std::thread::yield_now(),
            }
        };
        assert!(
            hello_delivered,
            "the pipelined hello must be receivable (into the kernel buffer) before the phase entry"
        );

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.client = Some(client);
            ws.approved = FixedHostname::normalize(b"sub.example.org");
            ws.stage = Stage::SendingConnected;
            ws.head_len = 0;
            ws.buf_base = 0;
            ws.buf_len = 0;
            ws.fwd = 0;
            ws.insp_rel = 0;
            ws.hello_consumed = 0;
            ws.gate.on_connect_head(0);
            ws.gate.on_authorized();
            ws.gate.on_upstream_connected();
        }
        serving
            .client_writable(index)
            .expect("200 sent and the validating-hello entry runs");

        assert!(
            serving.slots[index].gate.hello_end().is_some(),
            "a ClientHello pipelined before the CONNECT response must be validated on the phase entry without a new readable edge"
        );
        assert!(
            matches!(serving.slots[index].stage, Stage::WritingHello),
            "the validated hello advances into the hello write"
        );
    });
}

#[test]
fn head_spanning_multiple_reads_reaches_403() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut client = connect(port);
        let mut head = Vec::new();
        head.extend_from_slice(b"CONNECT evil.example.net:443 HTTP/1.1\r\n");
        head.extend_from_slice(b"Padding: ");
        while head.len() < 6000 {
            head.push(b'x');
        }
        head.extend_from_slice(b"\r\n\r\n");
        client
            .write_all(&head)
            .expect("write 6 KiB head in one write");
        pump(serving, 120);
        let body = read_until(&mut client, b"\r\n\r\n");
        assert!(
            body.starts_with(b"HTTP/1.1 403"),
            "multi-read head must drain to the 403 decision, got {:?} (len {})",
            &body[..body.len().min(24)],
            body.len()
        );
    });
}

#[test]
fn malformed_head_gets_400() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut client = connect(port);
        client.write_all(b"\r\n\r\n").expect("write malformed head");
        pump(serving, 80);
        let body = read_until(&mut client, b"\r\n\r\n");
        assert!(
            body.starts_with(b"HTTP/1.1 400"),
            "malformed CONNECT must receive 400, got {body:?}"
        );
    });
}

#[test]
fn pending_capacity_refuses_with_503() {
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
        let body = read_until(&mut last, b"\r\n\r\n");
        assert!(
            body.starts_with(b"HTTP/1.1 503"),
            "129th silent connect must receive 503, got {body:?}"
        );
        assert_eq!(
            serving.storage().occupied(),
            MAX_PENDING_SETUPS,
            "the first 128 silent setups occupy their seats"
        );
    });
}

#[test]
fn setup_deadline_frees_silent_seats_with_504() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut socks = Vec::new();
        for i in 0..=MAX_PENDING_SETUPS {
            socks.push(connect(port));
            if i % 16 == 15 {
                pump(serving, 4);
            }
        }
        pump(serving, 40);
        let mut probe = socks[MAX_PENDING_SETUPS].try_clone().expect("clone");
        let body = read_until(&mut probe, b"\r\n\r\n");
        assert!(body.starts_with(b"HTTP/1.1 503"));
        let start = Instant::now();
        while serving.storage().occupied() > 0 {
            serving
                .run_once(None)
                .expect("block past the next setup deadline");
            assert!(
                start.elapsed() <= Duration::from_secs(SETUP_DEADLINE_SECS + 5),
                "setups were admitted with individually spread absolute deadlines; a single poll turn only ever reaches the earliest one (fdtt H2), and the sweep must keep blocking until every deadline has expired, not assert the spread covers all slots in one wake"
            );
        }
        for (i, sock) in socks[..MAX_PENDING_SETUPS].iter().enumerate() {
            let mut clone = sock.try_clone().expect("clone");
            let expired = read_until(&mut clone, b"\r\n\r\n");
            assert!(
                expired.starts_with(b"HTTP/1.1 504"),
                "a silent setup must receive 504 after its deadline, slot {i} got {expired:?}"
            );
        }
        assert_eq!(
            serving.storage().occupied(),
            0,
            "all silent setups must be released after the deadline"
        );
    });
}

#[test]
fn setup_deadline_frees_partial_hello_pseudo_handshake_seat() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let client = connect(port);
        pump(serving, 1);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "precondition: the connecting client is admitted into one setup seat"
        );

        // A slow-client pseudo-handshake: one validly-framed TLS record whose
        // claimed 5-byte payload is only partially delivered, so the inspector
        // retains the bytes and never completes a ClientHello (W7-L7a-F2).
        let partial: &[u8] = &[0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00];
        {
            let ws = &mut serving.slots[0];
            ws.buf_base = 0;
            ws.buf_len = partial.len();
            ws.buf[..partial.len()].copy_from_slice(partial);
            ws.parse_rel = 0;
            ws.insp_rel = 0;
            ws.head_len = 0;
            ws.hello_end = None;
            ws.hello_consumed = 0;
            ws.fwd = 0;
            ws.approved = FixedHostname::normalize(b"sub.example.org");
            ws.stage = Stage::ValidatingHello;
            ws.gate.on_connect_head(0);
            ws.gate.on_authorized();
            ws.gate.on_upstream_connected();
            ws.gate.on_response_ok();
        }
        serving.buffer_and_validate(0, &[]);
        assert!(
            matches!(serving.slots[0].stage, Stage::ValidatingHello),
            "a validly-framed but incomplete TLS record must keep the slot in ValidatingHello"
        );
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the partial-hello pseudo-handshake holds its setup seat"
        );

        let start = Instant::now();
        while serving.storage().occupied() > 0 {
            serving
                .run_once(None)
                .expect("block past the next setup deadline");
            assert!(
                start.elapsed() <= Duration::from_secs(SETUP_DEADLINE_SECS + 5),
                "the absolute setup deadline must free the partial-hello seat, not hold it past the bound"
            );
        }
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the setup deadline frees the partial-hello pseudo-handshake seat"
        );
        drop(client);
    });
}

#[test]
fn future_deadline_only_skips_expire_sweep() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let client = connect(port);
        pump(serving, 1);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted into one setup seat"
        );
        assert_eq!(
            serving.sweeps, 0,
            "C16: the O(512) expiry sweep must be skipped while the only live deadline (setup +10 s) is still in the future"
        );
        pump(serving, 1);
        assert_eq!(
            serving.sweeps, 0,
            "C16: the sweep must stay skipped with a live, unexpired deadline"
        );
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the future-dated setup must still hold its seat"
        );
        drop(client);
    });
}

#[test]
fn expired_idle_deadline_still_closes_slot_through_gate() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let client = connect(port);
        pump(serving, 1);
        assert_eq!(serving.storage().occupied(), 1, "one admitted setup");
        serving.slots[0].idle_deadline = Some(Instant::now() - Duration::from_millis(1));
        pump(serving, 1);
        assert_eq!(
            serving.storage().occupied(),
            0,
            "a deadline already elapsed must still be enforced by the C16-gated sweep"
        );
        assert!(
            serving.sweeps >= 1,
            "the C16 early-exit gate must still fire the sweep once the deadline has elapsed"
        );
        drop(client);
    });
}

#[test]
/// C50 lockstep: the per-slot deadline-presence bitmap and its O(1) emptiness
/// gate must track every armed deadline source (setup snapshot, connect, idle,
/// drain) through `sync_live_deadline`, so a fold-relevant deadline can never
/// be skipped on the C50 poll-timeout fold regardless of which source arms or
/// clears it. Also proves the highest-index slot reaches the final bitmap word.
fn c50_live_deadline_bitmap_tracks_slot_four_sources_in_lockstep() {
    use crate::worker::Deadline;
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        assert!(
            serving.live_deadline.is_empty(),
            "a fresh serving must carry no live deadline bits"
        );
        assert!(
            !serving.live_deadline.get(0),
            "a free slot must not be marked live"
        );
        let now = Instant::now();
        let setup = Deadline::setup(now);
        serving.slots[0].setup_deadline = Some(setup.limit());
        serving.sync_live_deadline(0);
        assert!(
            serving.live_deadline.get(0) && !serving.live_deadline.is_empty(),
            "the C15 setup snapshot must mark the slot live"
        );
        serving.slots[0].connect_deadline = Some(Deadline::connect_attempt(
            now + Duration::from_secs(5),
            setup,
        ));
        serving.sync_live_deadline(0);
        assert!(
            serving.live_deadline.get(0),
            "the connect deadline must keep the bit live"
        );
        serving.slots[0].idle_deadline = Some(now + Duration::from_secs(7));
        serving.slots[0].drain_deadline = Some(now + Duration::from_secs(3));
        serving.sync_live_deadline(0);
        assert!(
            serving.live_deadline.get(0),
            "idle/drain arms must keep the bit live"
        );
        // Each source can disappear one at a time: only clearing the last one
        // drops the bit. The connect deadline is the conservatively-sticky one
        // (cleared only on reset), mirroring its fold guard.
        serving.slots[0].setup_deadline = None;
        serving.slots[0].idle_deadline = None;
        serving.slots[0].drain_deadline = None;
        serving.sync_live_deadline(0);
        assert!(
            serving.live_deadline.get(0),
            "the remaining connect deadline must keep the slot live"
        );
        serving.slots[0].connect_deadline = None;
        serving.sync_live_deadline(0);
        assert!(
            !serving.live_deadline.get(0) && serving.live_deadline.is_empty(),
            "clearing the last source must clear the bit and restore emptiness"
        );
        // The final slot exercises the last bitmap word (511 in word 7).
        serving.slots[MAX_TUNNELS - 1].idle_deadline = Some(now + Duration::from_secs(9));
        serving.sync_live_deadline(MAX_TUNNELS - 1);
        assert!(
            serving.live_deadline.get(MAX_TUNNELS - 1)
                && serving.live_deadline.iter_live().eq([MAX_TUNNELS - 1]),
            "bit {} must be reachable through the final word",
            MAX_TUNNELS - 1
        );
        serving.slots[MAX_TUNNELS - 1].idle_deadline = None;
        serving.sync_live_deadline(MAX_TUNNELS - 1);
        assert!(
            serving.live_deadline.is_empty(),
            "cleanup must restore emptiness"
        );
    });
}

#[test]
/// S1: the poll-timeout fold over the C50-live slot must be the exact minimum
/// across every armed deadline source — the C15 setup snapshot, the
/// connect (Dialing-guarded), idle, and drain — mirroring the four
/// `expire_sweep` arms (docs/alumina-proxy.md:192). The slot stays live in the
/// bitmap while multi-armed, so no armed deadline can silently fall out of the
/// C16/C50 poll fold.
fn s1_fold_min_is_exact_min_over_all_four_arm_sources() {
    use crate::worker::Deadline;
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let _client = connect(port);
        pump(serving, 1);
        assert_eq!(serving.storage().occupied(), 1, "one admitted setup");
        let now = Instant::now();
        let handle = serving.slots[0].handle.as_ref().expect("admitted handle");
        let setup = serving
            .storage()
            .setup_deadline(handle)
            .expect("admitted setup deadline");
        let setup_limit = setup.limit();
        let connect_limit = now + Duration::from_secs(6);
        let idle_limit = now + Duration::from_secs(9);
        let drain_limit = now + Duration::from_secs(3);
        serving.slots[0].stage = Stage::Dialing;
        serving.slots[0].connect_deadline = Some(Deadline::connect_attempt(connect_limit, setup));
        serving.slots[0].idle_deadline = Some(idle_limit);
        serving.slots[0].drain_deadline = Some(drain_limit);
        serving.sync_live_deadline(0);
        serving.poll_timeout();
        let expected = [setup_limit, connect_limit, idle_limit, drain_limit]
            .into_iter()
            .min()
            .expect("min over four armed sources");
        assert_eq!(
            serving.next_expiry,
            Some(expected),
            "the fold must be the exact minimum over setup, connect, idle and drain"
        );
        assert!(
            serving.live_deadline.get(0),
            "a multi-armed slot must be marked live in the C50 bitmap"
        );
        // Shedding the connect source must not change the fold: setup+idle+drain
        // still produce the same minimum.
        serving.slots[0].connect_deadline = None;
        serving.slots[0].stage = Stage::ReadingConnect;
        serving.sync_live_deadline(0);
        serving.poll_timeout();
        assert_eq!(
            serving.next_expiry,
            Some(expected),
            "dropping the connect source (now the setup snapshot, idle and drain remain) \
             must not change the exact minimum fold"
        );
    });
}

#[test]
/// The C50 bit for an admitted setup must couple with the C16 gate so an
/// elapsed drain deadline still closes the slot through `run_once`, proving
/// the drain arm is folded (and enforced) off the lockstep bitmap, not lost.
fn drain_deadline_expired_still_closes_slot_through_gate() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let client = connect(port);
        pump(serving, 1);
        assert_eq!(serving.storage().occupied(), 1, "one admitted setup");
        serving.slots[0].drain_deadline = Some(Instant::now() - Duration::from_millis(1));
        serving.sync_live_deadline(0);
        pump(serving, 1);
        assert_eq!(
            serving.storage().occupied(),
            0,
            "an elapsed drain deadline must still be enforced by the C16-gated sweep"
        );
        assert!(
            serving.sweeps >= 1,
            "the C16 early-exit gate must still fire the sweep once the drain deadline has elapsed"
        );
        drop(client);
    });
}

#[test]
/// The connect deadline, folded only while the slot is Dialing, must also run
/// its retry enforcement through the real `run_once` gate (C16 + C50 coupling)
/// — not only via direct `expire_sweep` — so the connect arm is proven present
/// in the poll fold from an admitted, bitmap-live slot.
fn connect_deadline_expired_still_retries_through_gate() {
    use crate::cache::Family;
    use crate::connect::Feed;
    use crate::eligibility::NumericAddr;
    use std::net::Ipv4Addr;
    let port = ephemeral_port();
    let upstream_port = ephemeral_port();
    let cfg = config_pair(port, upstream_port);
    with_serving_stack_cfg(port, cfg, move |serving| {
        serving.storage_mut().publish_test_addr(
            0,
            NumericAddr::V4(Ipv4Addr::from([127, 0, 0, 1])),
            Family::A,
        );
        let mut client = connect(port);
        pump(serving, 10);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );
        let head = format!("CONNECT sub.example.org:{upstream_port} HTTP/1.1\r\n\r\n");
        match serving.slots[0]
            .parser
            .feed(head.as_bytes())
            .expect("head feed")
        {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        let handle = serving.slots[0].handle.as_ref().expect("admitted handle");
        let setup = serving
            .storage()
            .setup_deadline(handle)
            .expect("setup deadline");
        serving.slots[0].approved = FixedHostname::normalize(b"sub.example.org");
        serving.slots[0].approved_port = upstream_port;
        serving.slots[0].stage = Stage::Dialing;
        serving.slots[0].connect_family = Some(Family::A);
        serving.slots[0].connect_deadline = Some(crate::worker::Deadline::connect_attempt(
            Instant::now() - Duration::from_secs(3),
            setup,
        ));
        serving.sync_live_deadline(0);
        pump(serving, 10);
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the expired-dial retry must re-decide to NoBinding and release the seat"
        );
        let body = read_all(&mut client);
        assert!(
            body.starts_with(b"HTTP/1.1 502 Bad Gateway"),
            "the expired-dial retry must end in a pre-200 502, got {body:?}"
        );
    });
}

#[test]
fn stale_event_for_a_reused_slot_index_is_dropped() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let client =
            mio::net::TcpStream::connect(SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), port))
                .expect("client connect");
        serving.admit(client);
        assert_eq!(serving.storage().occupied(), 1);
        let current = serving.slots[0].slot_gen;
        let stale_gen = current.wrapping_sub(1);
        let stale = Token(
            (usize::try_from(stale_gen).expect("slot generation fits usize") << GEN_SHIFT) | 1,
        );
        serving
            .dispatch_readiness(
                stale,
                Readiness {
                    readable: true,
                    writable: true,
                    ..Readiness::none()
                },
            )
            .expect("dispatch stale event");
        assert_eq!(
            serving.storage().occupied(),
            1,
            "a stale event for the reused slot index must not close the new connection"
        );
    });
}

#[test]
fn dialing_combined_readable_writable_rejects_early_origin_data() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
        let origin_addr = origin.local_addr().expect("origin addr");
        let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
        let mut origin_stream = origin.accept().expect("accept origin side").0;

        let _client = connect(port);
        pump(serving, 40);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );

        let index = 0;
        let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
        {
            let ws = &mut serving.slots[index];
            ws.approved = FixedHostname::normalize(b"sub.example.org");
            ws.gate.on_connect_head(head_len);
            ws.gate.on_authorized();
            ws.stage = Stage::Dialing;
        }
        origin_stream
            .write_all(b"X")
            .expect("origin writes early data");
        let mut probe = [0u8; 1];
        let mut waits = 0;
        loop {
            match up.peek(&mut probe) {
                Ok(1) => break,
                Ok(_) => {}
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => panic!("peek origin early data: {err}"),
            }
            waits += 1;
            assert!(
                waits < 2000,
                "origin early data never became readable on the upstream socket"
            );
            std::thread::yield_now();
        }
        serving.slots[index].upstream = Some(up);

        let token = upstream_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: true,
                    ..Readiness::none()
                },
            )
            .expect("combined dialing event");

        assert_eq!(
            serving.storage().occupied(),
            0,
            "early origin data during Dialing must release the admitted seat before any 200/forward"
        );
        let ws = &serving.slots[0];
        assert!(
            ws.stage == Stage::Idle,
            "the terminated setup must leave the workspace idle, never advanced to a 200-sending stage"
        );
        assert!(
            ws.client.is_none(),
            "the client socket must be closed so no 200/forward can be delivered"
        );
        assert!(
            ws.upstream.is_none(),
            "the upstream socket must be closed once early activity is observed"
        );
    });
}

#[test]
fn dialing_readiness_without_origin_data_is_not_early_activity() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
        let origin_addr = origin.local_addr().expect("origin addr");
        let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
        let mut _origin_stream = origin.accept().expect("accept origin side").0;

        let _client = connect(port);
        pump(serving, 40);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );

        let index = 0;
        let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
        {
            let ws = &mut serving.slots[index];
            ws.approved = FixedHostname::normalize(b"sub.example.org");
            ws.gate.on_connect_head(head_len);
            ws.gate.on_authorized();
            ws.stage = Stage::Dialing;
            ws.upstream = Some(up);
        }

        let token = upstream_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: true,
                    ..Readiness::none()
                },
            )
            .expect("combined dialing event");

        assert_eq!(
            serving.storage().occupied(),
            1,
            "a WouldBlock readiness with no origin data must not terminate the setup"
        );
        assert!(
            serving.slots[0].stage == Stage::ValidatingHello,
            "with no origin data the combined event must only advance the connection (200 sent, hello pending)"
        );
    });
}

#[test]
fn upstream_read_interrupted_exhaustion_rewires_and_terminates_on_pending_data() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
        let origin_addr = origin.local_addr().expect("origin addr");
        let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
        let mut origin_stream = origin.accept().expect("accept origin side").0;
        wait_upstream_connected(&up);

        let mut client = connect(port);
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("client read timeout");
        pump(serving, 40);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );

        let index = 0;
        let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
        {
            let ws = &mut serving.slots[index];
            ws.approved = FixedHostname::normalize(b"sub.example.org");
            ws.gate.on_connect_head(head_len);
            ws.gate.on_authorized();
            ws.stage = Stage::Dialing;
            ws.upstream = Some(up);
        }
        serving.register_upstream(index).expect("register upstream");

        let mut reads = vec![Ok(1)];
        reads
            .extend((0..POLL_EVENTS_CAP).map(|_| Err(io::Error::from(io::ErrorKind::Interrupted))));
        serving.slots[index].test_reads = reads;

        let token = upstream_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("interrupted burst");

        assert_eq!(
            serving.storage().occupied(),
            1,
            "an interrupted read burst must neither release the seat nor wait silently"
        );
        assert!(
            serving.slots[index].stage == Stage::Dialing,
            "an interrupted burst must not advance or terminate the setup"
        );
        let early = read_until(&mut client, b"\r\n\r\n");
        assert!(
            early.is_empty(),
            "no 200/502/504 may be sent while the interrupted burst is still draining"
        );

        origin_stream.write_all(b"X").expect("origin writes data");
        let start = Instant::now();
        while serving.storage().occupied() > 0 {
            assert!(
                start.elapsed() <= Duration::from_millis(2000),
                "the rearmed upstream readable event was never delivered"
            );
            serving
                .run_once(Some(Duration::from_millis(10)))
                .expect("poll redelivers readiness");
        }

        assert_eq!(
            serving.storage().occupied(),
            0,
            "early data still pending after the interrupted burst must terminate on the rearmed event"
        );
    });
}

#[test]
fn not_connected_upstream_read_after_200_closes_without_injected_502() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
        let origin_addr = origin.local_addr().expect("origin addr");
        let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
        let _origin_stream = origin.accept().expect("accept origin side").0;
        wait_upstream_connected(&up);

        let mut client = connect(port);
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("client read timeout");
        pump(serving, 40);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );

        let index = 0;
        let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
        {
            let ws = &mut serving.slots[index];
            ws.approved = FixedHostname::normalize(b"sub.example.org");
            ws.gate.on_connect_head(head_len);
            ws.gate.on_authorized();
            ws.stage = Stage::Dialing;
            ws.upstream = Some(up);
        }
        serving.register_upstream(index).expect("register upstream");

        let token = upstream_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: true,
                    ..Readiness::none()
                },
            )
            .expect("connect the upstream and send 200");

        assert!(
            serving.slots[index].stage == Stage::ValidatingHello,
            "a connected, silent upstream advances past the 200 and waits for hello"
        );

        serving.slots[index].test_reads = vec![Err(io::Error::from(io::ErrorKind::NotConnected))];
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("not-connected read");

        assert_eq!(
            serving.storage().occupied(),
            0,
            "a not-yet-connected read is a confirmed setup failure once connectedness advanced"
        );
        let body = read_until(&mut client, b"\r\n\r\n");
        assert!(
            body.starts_with(b"HTTP/1.1 200"),
            "the completed connect already sent 200 and the failure must not inject a 502, got {body:?}"
        );
    });
}

#[test]
fn upstream_error_readiness_during_dialing_refuses_502_not_silent_close() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut client = connect(port);
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("client read timeout");
        pump(serving, 40);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );

        let index = 0;
        let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
        {
            let ws = &mut serving.slots[index];
            ws.approved = FixedHostname::normalize(b"sub.example.org");
            ws.gate.on_connect_head(head_len);
            ws.gate.on_authorized();
            ws.stage = Stage::Dialing;
        }
        serving.register_upstream(index).expect("register upstream");

        let token = upstream_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    error: true,
                    ..Readiness::none()
                },
            )
            .expect("upstream error readiness");

        assert_eq!(
            serving.storage().occupied(),
            0,
            "a refused dial must release the admitted seat with a 502, not a silent close"
        );
        let body = read_until(&mut client, b"\r\n\r\n");
        assert!(
            body.starts_with(b"HTTP/1.1 502"),
            "refused dialing upstream must refuse the pre-200 502, got {body:?}"
        );
    });
}

#[test]
fn dialing_upstream_read_failure_refuses_502_before_any_200() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
        let origin_addr = origin.local_addr().expect("origin addr");
        let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
        let _origin_stream = origin.accept().expect("accept origin side").0;
        wait_upstream_connected(&up);

        let mut client = connect(port);
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("client read timeout");
        pump(serving, 40);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );

        let index = 0;
        let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
        {
            let ws = &mut serving.slots[index];
            ws.approved = FixedHostname::normalize(b"sub.example.org");
            ws.gate.on_connect_head(head_len);
            ws.gate.on_authorized();
            ws.stage = Stage::Dialing;
            ws.upstream = Some(up);
        }
        serving.register_upstream(index).expect("register upstream");

        serving.slots[index].test_reads = vec![Err(io::Error::from(io::ErrorKind::Unsupported))];
        let token = upstream_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: true,
                    ..Readiness::none()
                },
            )
            .expect("dialing read failure");

        assert_eq!(
            serving.storage().occupied(),
            0,
            "a dialing read failure must release the admitted seat"
        );
        let body = read_until(&mut client, b"\r\n\r\n");
        assert!(
            body.starts_with(b"HTTP/1.1 502"),
            "a non-200-stage setup failure must produce a pre-200 502, got {body:?}"
        );
    });
}

#[test]
fn relay_pending_tail_then_fresh_bytes_preserve_order_and_count() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;
        let index = 0;
        let ws = &mut serving.slots[index];
        ws.upstream = Some(up);
        ws.head_len = 4;
        ws.hello_end = Some(10);
        ws.buf_base = 0;
        ws.buf_len = 20;
        ws.fwd = 4;
        ws.buf[..20].copy_from_slice(b"HEADHELLO!0123456789");
        ws.stage = Stage::Relay;
        ws.gate.on_connect_head(4);
        ws.gate.on_authorized();
        ws.gate.on_upstream_connected();
        ws.gate.on_response_ok();
        ws.gate.on_hello_validated(ValidatedHello::test_new(10));

        serving.flush_client_upstream(index);
        serving.append_client_bytes(index, b"FRESH");
        serving.flush_client_upstream(index);

        let mut got = Vec::new();
        let mut tmp = [0u8; 64];
        while got.len() < 21 {
            match sink_stream.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&tmp[..n]),
            }
        }
        assert_eq!(
            got,
            b"HELLO!0123456789FRESH".to_vec(),
            "pending tail then fresh bytes must reach the upstream in order, unduplicated"
        );
    });
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "long multi-phase compaction assertion"
)]
#[expect(
    clippy::large_stack_arrays,
    reason = "test staging buffer, not runtime path"
)]
fn forced_compaction_preserves_absolute_cursor_and_retained_suffix() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;
        sink_stream.set_nonblocking(true).expect("sink nonblocking");

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.head_len = 4;
            ws.hello_end = Some(10);
            ws.buf_base = 0;
            ws.fwd = 4;
            ws.stage = Stage::Relay;
            ws.gate.on_connect_head(4);
            ws.gate.on_authorized();
            ws.gate.on_upstream_connected();
            ws.gate.on_response_ok();
            ws.gate.on_hello_validated(ValidatedHello::test_new(10));
            ws.buf[..4].copy_from_slice(b"HEAD");
            ws.buf[4..10].copy_from_slice(b"HELLO!");
            let payload_start = 10usize;
            let payload = b"0123456789abcdef";
            let mut filled = payload_start;
            while filled + payload.len() <= HOLD_CAP - 3 {
                ws.buf[filled..filled + payload.len()].copy_from_slice(payload);
                filled += payload.len();
            }
            ws.buf_len = HOLD_CAP - 3;
            assert!(
                filled <= ws.buf_len,
                "padded payload must fit within the pre-fill workspace"
            );
            ws.buf[filled..ws.buf_len]
                .copy_from_slice(&test_offset_pattern(ws.buf_len - filled, 8));
        }
        serving.register_upstream(index).expect("register up");

        let committed_before = {
            let ws = &mut serving.slots[index];
            ws.buf_base + ws.fwd - ws.head_len
        };
        let hello_end_before = {
            let ws = &mut serving.slots[index];
            ws.hello_end
        };
        let suffix_before: Vec<u8> = {
            let ws = &mut serving.slots[index];
            ws.buf[ws.fwd..ws.buf_len].to_vec()
        };

        serving.append_client_bytes(index, b"FRESH");

        let ws = &mut serving.slots[index];
        assert_eq!(
            ws.buf_base + ws.fwd - ws.head_len,
            committed_before,
            "compaction must preserve the absolute committed cursor (base + fwd - head_len)"
        );
        assert_eq!(
            ws.hello_end, hello_end_before,
            "the absolute hello end must not shift when the base moves"
        );
        assert_eq!(
            &ws.buf[0..suffix_before.len()][..],
            &suffix_before[..],
            "the retained suffix must be preserved byte-for-byte across compaction"
        );

        serving.flush_client_upstream(index);
        let expected_len = suffix_before.len() + 5;
        let mut got = Vec::new();
        let mut tmp = [0u8; 65536];
        let deadline = Instant::now() + Duration::from_secs(3);
        while got.len() < expected_len {
            assert!(
                Instant::now() < deadline,
                "compacted stream never fully drained: got {} / {}",
                got.len(),
                expected_len
            );
            match sink_stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&tmp[..n]),
                Err(_) => {}
            }
            serving
                .run_once(Some(Duration::from_millis(1)))
                .expect("compaction-drain poll");
            match sink_stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&tmp[..n]),
                Err(_) => {}
            }
        }
        let mut expected = Vec::with_capacity(expected_len);
        expected.extend_from_slice(&suffix_before);
        expected.extend_from_slice(b"FRESH");
        assert_eq!(
            got, expected,
            "post-compaction delivery must match the pre-compaction suffix plus fresh bytes"
        );
    });
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "long staged relay-fin drain/half-close assertion"
)]
fn relay_client_fin_drains_pending_bytes_then_half_closes_and_releases() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
            ws.buf_len = 10;
            ws.fwd = 4;
            ws.buf[..10].copy_from_slice(b"HEAD!ABCDE");
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");
        let _ = peer_stream.set_read_timeout(Some(Duration::from_millis(50)));
        let _ = sink_stream.set_read_timeout(Some(Duration::from_millis(50)));

        peer_stream
            .write_all(b"Z")
            .expect("write final client byte");
        peer_stream
            .shutdown(std::net::Shutdown::Write)
            .expect("client fin");

        let mut pending = Vec::new();
        let mut tmp = [0u8; 64];
        let mut eof_seen = false;
        let fin_start = Instant::now();
        while !eof_seen {
            assert!(
                fin_start.elapsed() < Duration::from_secs(3),
                "pending drain/half-close never reached sink EOF"
            );
            match sink_stream.read(&mut tmp) {
                Ok(0) => eof_seen = true,
                Ok(n) => pending.extend_from_slice(&tmp[..n]),
                Err(_) => {
                    serving
                        .run_once(Some(Duration::from_millis(5)))
                        .expect("poll drain");
                    std::thread::yield_now();
                }
            }
        }
        assert_eq!(
            pending,
            b"!ABCDEZ".to_vec(),
            "a client FIN must conserve the accepted bytes through the half-close, not drop them"
        );
        assert!(
            matches!(serving.slots[index].stage, Stage::Relay),
            "the reverse direction stays open after the client EOF"
        );
        assert!(
            serving.slots[index].client.is_some(),
            "a half-close must not fully drop the client socket"
        );

        sink_stream.write_all(b"down!").expect("origin writes down");
        sink_stream
            .shutdown(std::net::Shutdown::Write)
            .expect("origin fin");
        let close_start = Instant::now();
        while serving.slots[index].stage != Stage::Idle {
            assert!(
                close_start.elapsed() < Duration::from_secs(3),
                "both-EOF drain never closed the slot"
            );
            serving
                .run_once(Some(Duration::from_millis(5)))
                .expect("poll drain2");
        }
        let mut down = Vec::new();
        let down_start = Instant::now();
        while !down.ends_with(b"down!") {
            assert!(
                down_start.elapsed() < Duration::from_secs(2),
                "peer never received the down bytes"
            );
            match peer_stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => down.extend_from_slice(&tmp[..n]),
                Err(_) => std::thread::yield_now(),
            }
        }
        assert_eq!(
            down,
            b"down!".to_vec(),
            "origin bytes must reach the client intact across the drain"
        );
        assert!(
            serving.slots[index].client.is_none(),
            "both directions drained must drop the client exactly once"
        );
        assert!(
            serving.slots[index].upstream.is_none(),
            "both directions drained must drop the upstream exactly once"
        );
    });
}

#[test]
fn sink_drain_of_client_upstream_resumes_paused_client_source() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
            ws.buf_len = 6;
            ws.fwd = 4;
            ws.buf[..6].copy_from_slice(b"HEAD!A");
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");

        peer_stream.write_all(b"Z").expect("client byte pending");

        let mut tmp = [0u8; 64];
        let mut got = Vec::new();
        let start = Instant::now();
        let _ = sink_stream.set_read_timeout(Some(Duration::from_millis(50)));
        while got.len() < 3 {
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "a paused client source was never resumed after the upstream sink drained"
            );
            serving
                .upstream_writable(index)
                .expect("drain + resume visit");
            if let Ok(n) = sink_stream.read(&mut tmp) {
                got.extend_from_slice(&tmp[..n]);
            }
            std::thread::yield_now();
        }
        assert_eq!(
            got,
            b"!AZ".to_vec(),
            "an upstream sink drain must resume the paused client read without a new edge"
        );
    });
}

#[test]
fn up_socket_receive_appends_once_at_nonzero_retained_tail() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;
        sink_stream.set_nonblocking(true).expect("sink nonblocking");

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;

        let index = 0;
        let prefix = test_offset_pattern(RETAINED_OFFSET, 11);
        let payload = test_offset_pattern(137, 17);
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
            ws.fwd = 0;
            ws.buf[..RETAINED_OFFSET].copy_from_slice(&prefix);
            ws.buf[RETAINED_OFFSET..CHUNK].fill(0xA5);
            ws.buf_len = RETAINED_OFFSET;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");

        peer_stream
            .write_all(&payload)
            .expect("write relay payload");
        let avail = Instant::now() + Duration::from_secs(2);
        while serving.slots[index]
            .client
            .as_ref()
            .expect("client present")
            .peek(&mut [0u8; 1])
            .is_err()
        {
            assert!(
                Instant::now() < avail,
                "the relay payload never became readable"
            );
            std::thread::yield_now();
        }

        serving.client_readable(index).expect("up read visit");

        let expected = RETAINED_OFFSET + payload.len();
        let mut got = Vec::new();
        let mut tmp = [0u8; 64];
        let deadline = Instant::now() + Duration::from_secs(2);
        while got.len() < expected && Instant::now() < deadline {
            match sink_stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(m) => got.extend_from_slice(&tmp[..m]),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::yield_now();
                }
                Err(_) => break,
            }
        }
        assert_eq!(
            got.len(),
            expected,
            "the upstream sink must receive the retained prefix plus relay bytes, got {}",
            got.len()
        );
        let n = got.len() - RETAINED_OFFSET;
        assert!(
            (1..=payload.len()).contains(&n),
            "the retained up tail must advance by exactly the returned read count, got {n}"
        );
        let mut forwarded = prefix;
        forwarded.extend_from_slice(&payload[..n]);
        assert_eq!(
            got, forwarded,
            "the retained prefix then the freshly appended tail bytes must reach the \
             upstream sink in order, byte-exact, once"
        );

        let ws = &serving.slots[index];
        assert_eq!(
            ws.buf_base,
            RETAINED_OFFSET + n,
            "the relay cursor reset must fold the forwarded prefix and tail into buf_base"
        );
        assert_eq!(ws.buf_len, 0, "a fully-drained relay slab must be empty");
        assert_eq!(ws.fwd, 0, "a fully-drained relay slab must reset fwd to 0");
        assert_eq!(
            &ws.buf[..n],
            &payload[..n],
            "the freshly appended relay bytes must be re-based at buf[..n]"
        );
        assert_eq!(
            ws.buf[n.max(RETAINED_OFFSET)],
            0xA5,
            "the byte beyond the re-based read region must stay untouched"
        );
    });
}

#[test]
fn down_socket_receive_appends_once_at_nonzero_retained_tail() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let origin_l = StdListener::bind("127.0.0.1:0").expect("origin bind");
        let origin_addr = origin_l.local_addr().expect("origin addr");
        let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
        let mut origin = origin_l.accept().expect("accept origin side").0;
        origin.set_nonblocking(true).expect("origin nonblocking");

        let index = 0;
        let prefix = test_offset_pattern(RETAINED_OFFSET, 23);
        let payload = test_offset_pattern(137, 29);
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
            ws.fwd = 0;
            ws.client = None;
            ws.down[..RETAINED_OFFSET].copy_from_slice(&prefix);
            ws.down[RETAINED_OFFSET..CHUNK].fill(0xA5);
            ws.down_len = RETAINED_OFFSET;
            ws.down_off = 0;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        origin.write_all(&payload).expect("write down payload");
        let avail = Instant::now() + Duration::from_secs(2);
        while serving.slots[index]
            .upstream
            .as_ref()
            .expect("upstream present")
            .peek(&mut [0u8; 1])
            .is_err()
        {
            assert!(
                Instant::now() < avail,
                "the down payload never became readable"
            );
            std::thread::yield_now();
        }

        serving
            .relay_upstream_to_client(index)
            .expect("down read visit");

        let ws = &serving.slots[index];
        let n = ws.down_len - RETAINED_OFFSET;
        assert!(
            (1..=payload.len()).contains(&n),
            "the retained down tail must advance by exactly the returned read count, got {n}"
        );
        assert_eq!(
            &ws.down[..RETAINED_OFFSET],
            prefix.as_slice(),
            "the retained down prefix must be untouched beneath the newly received bytes"
        );
        assert_eq!(
            &ws.down[RETAINED_OFFSET..RETAINED_OFFSET + n],
            &payload[..n],
            "received down bytes must be appended at the nonzero retained tail offset, once, \
             unduplicated"
        );
        assert_eq!(
            ws.down[RETAINED_OFFSET + n],
            0xA5,
            "the byte immediately after the committed down count must be untouched: a \
             second commit would overwrite it"
        );
        assert!(
            serving.slots[index].upstream.is_some(),
            "a stalled down flush must keep the upstream socket and the tunnel open"
        );
    });
}

#[test]
fn visit_budget_exhausts_on_ops_or_bytes_whichever_first() {
    let mut v = VisitState::live(0);
    assert!(!v.exhausted());
    for _ in 0..15 {
        v = v.note(1);
    }
    assert!(!v.exhausted(), "15 ops at 1 byte stay within the budget");
    v = v.note(1);
    assert!(
        v.exhausted(),
        "the 16th op exhausts the visit before the byte cap"
    );
    assert_eq!(
        v,
        VisitState::Live {
            slot: 0,
            ops: 16,
            bytes: 16,
        }
    );

    let mut v = VisitState::live(0);
    v = v.note(32 * 1024);
    assert!(!v.exhausted());
    v = v.note(32 * 1024);
    assert!(v.exhausted(), "64 KiB combined exhausts before 16 ops");
    assert_eq!(
        v,
        VisitState::Live {
            slot: 0,
            ops: 2,
            bytes: 64 * 1024,
        }
    );

    let mut v = VisitState::live(0);
    for _ in 0..15 {
        v = v.note(0);
    }
    assert!(!v.exhausted());
    v = v.note(0);
    assert!(
        v.exhausted(),
        "a WouldBlock/spurious attempt counts as an I/O operation (:146,:226)"
    );

    let idle = VisitState::idle();
    assert!(!idle.exhausted(), "an idle (non-visit) budget never trips");
    assert_eq!(idle.ops(), 0, "an idle visit owns no ops");
}

#[test]
fn batch_progress_rechecks_timers_before_the_visit_that_would_cross() {
    let mut p = BatchProgress::default();
    for _ in 0..15 {
        assert!(
            !p.due(),
            "the visit about to run stays inside 256, no recheck before dispatch"
        );
        p.accrue(16);
    }
    assert_eq!(p.work_since_recheck, 255);
    assert!(
        p.due(),
        "255 units + the next visit's 17 units = 272 > 256, the recheck must precede it"
    );
    p.work_since_recheck = 0;
    assert!(!p.due());
    p.accrue(16);
    assert_eq!(
        p.work_since_recheck, 17,
        "the boundary visit runs fully within the swept budget"
    );

    let p = BatchProgress {
        work_since_recheck: 239,
    };
    assert!(
        !p.due(),
        "239 + 17 = 256 lands exactly on the bound, so no early recheck"
    );
    let p = BatchProgress {
        work_since_recheck: 240,
    };
    assert!(
        p.due(),
        "240 + 17 crosses the bound, the recheck fires before the visit"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "long staged batch/coalescing assertion"
)]
#[expect(
    clippy::large_stack_arrays,
    reason = "test staging buffer, not runtime path"
)]
fn one_batch_two_tokens_one_slot_share_a_single_complete_visit() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");

        let got = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let got_reader = std::sync::Arc::clone(&got);
        let sink_reader = std::thread::spawn(move || {
            let mut tmp = [0u8; 65536];
            loop {
                match sink_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => *got_reader.lock().unwrap() += n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        let payload = test_offset_pattern(192 * 1024, 7);
        peer_stream.write_all(&payload).expect("write burst");
        let avail_start = Instant::now();
        while serving.slots[index]
            .client
            .as_ref()
            .expect("client present")
            .peek(&mut [0u8; 1])
            .is_err()
        {
            assert!(
                avail_start.elapsed() < Duration::from_secs(2),
                "the client burst never became readable"
            );
            std::thread::yield_now();
        }

        let client_token = client_token(serving.slots[index].slot_gen, index);
        let up_token = upstream_token(serving.slots[index].slot_gen, index);
        let before = serving.slots[index].buf_base + serving.slots[index].fwd;
        serving.in_batch = true;
        serving
            .dispatch_readiness(
                client_token,
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("batch client-readable token");
        serving
            .dispatch_readiness(
                up_token,
                Readiness {
                    writable: true,
                    ..Readiness::none()
                },
            )
            .expect("batch upstream-writable token");
        serving.in_batch = false;

        let after = serving.slots[index].buf_base + serving.slots[index].fwd;
        let sink_total = *got.lock().unwrap();
        assert!(
            after - before <= 64 * 1024,
            "one batch with both arms of one slot must stay inside one 64 KiB visit, moved {}",
            after - before
        );
        assert!(
            sink_total <= 64 * 1024,
            "sink bytes across the batch must stay inside one 64 KiB visit, got {sink_total}"
        );
        match serving.visit {
            VisitState::Live { ops, bytes, .. } => {
                assert!(
                    ops <= 16,
                    "the shared visit owns at most 16 ops, recorded {ops}"
                );
                assert!(
                    bytes <= 64 * 1024,
                    "the shared visit owns at most 64 KiB, recorded {bytes}"
                );
            }
            VisitState::Idle => {}
        }

        drop(peer_stream);
        serving.close_slot(index);
        sink_reader.join().expect("sink reader");
    });
}

#[test]
fn eof_read_attempts_count_toward_the_shared_visit_budget() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let sink_stream = sink.accept().expect("accept sink side").0;

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let peer_stream = peer_l.accept().expect("accept peer side").0;

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");

        peer_stream
            .shutdown(std::net::Shutdown::Write)
            .expect("client fin");
        let avail = Instant::now();
        while serving.slots[index]
            .client
            .as_ref()
            .expect("client present")
            .peek(&mut [0u8; 1])
            .is_err()
        {
            assert!(
                avail.elapsed() < Duration::from_secs(2),
                "client FIN never became readable"
            );
            std::thread::yield_now();
        }

        let client_token = client_token(serving.slots[index].slot_gen, index);

        serving.in_batch = true;
        serving.batch_gen = serving.batch_gen.wrapping_add(1);
        serving
            .dispatch_readiness(
                client_token,
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("client-readable dispatch");

        assert_eq!(
            serving.visit.ops(),
            1,
            "the up-flow EOF read must consume exactly one visit op, recorded {:?}",
            serving.visit
        );

        let _ = sink_stream.set_write_timeout(Some(Duration::from_millis(100)));
        sink_stream
            .shutdown(std::net::Shutdown::Write)
            .expect("upstream fin");
        let avail2 = Instant::now();
        while serving.slots[index]
            .upstream
            .as_ref()
            .expect("upstream present")
            .peek(&mut [0u8; 1])
            .is_err()
        {
            assert!(
                avail2.elapsed() < Duration::from_secs(2),
                "upstream FIN never became readable"
            );
            std::thread::yield_now();
        }

        let up_token = upstream_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                up_token,
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("upstream-readable dispatch");
        serving.in_batch = false;

        assert_eq!(
            serving.visit.ops(),
            2,
            "the down-flow EOF read must raise the total to exactly two visit ops \
             (one per EOF read), recorded {:?}",
            serving.visit
        );
        assert!(
            serving.slots[index].client.is_none() && serving.slots[index].upstream.is_none(),
            "both-EOF drained must close the slot exactly once"
        );
    });
}

#[test]
fn listener_yield_at_recheck_rearms_for_queued_clients_without_new_connects() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut clients = Vec::new();
        for _ in 0..6 {
            clients.push(connect(port));
        }
        serving.progress.work_since_recheck = 237;
        serving
            .run_once(Some(Duration::from_millis(2)))
            .expect("the first real poll consumes the listener edge");
        let first_wave = serving.storage().occupied();
        assert_eq!(
            first_wave, 2,
            "the preset ledger must make the accept turn yield mid-backlog after a bounded \
             admit (2), not drain the queue in one poll: admitted {first_wave}"
        );
        assert!(
            serving.progress.work_since_recheck <= 256,
            "the accept turn never pushes the ledger past the canonical 256-unit bound"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while serving.storage().occupied() < clients.len() {
            assert!(
                Instant::now() < deadline,
                "pre-queued clients must be admitted on later polls via the listener re-arm \
                 alone (no new connects ever arrive): occupied {} of {}",
                serving.storage().occupied(),
                clients.len()
            );
            serving
                .run_once(Some(Duration::from_millis(2)))
                .expect("resume poll");
        }
        assert_eq!(
            serving.storage().occupied(),
            clients.len(),
            "all six pre-queued clients are admitted across later polls with no new connects"
        );
        for c in clients {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
    });
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "long interleaved budget-split behaviour assertion"
)]
#[expect(
    clippy::large_stack_arrays,
    reason = "test staging buffer, not runtime path"
)]
fn interleaved_a_b_a_mixed_readwrite_timer_preserves_shared_budgets() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let expected_a = 96 * 1024;
        let expected_b = 96 * 1024;
        let pattern_a = test_offset_pattern(expected_a, 1);
        let pattern_b = test_offset_pattern(expected_b, 2);

        let got_a = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let got_b = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let mut readers = Vec::new();
        let mut peers = Vec::new();
        for (index, pattern) in [(0usize, &pattern_a), (1, &pattern_b)] {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;
            sink_stream.set_nonblocking(true).expect("sink nonblocking");

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;

            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");

            peer_stream
                .write_all(pattern)
                .expect("preload client pattern before poll");

            let lane_got = if index == 0 {
                std::sync::Arc::clone(&got_a)
            } else {
                std::sync::Arc::clone(&got_b)
            };
            let lane_stop = std::sync::Arc::clone(&stop);
            let reader = std::thread::spawn(move || {
                let mut tmp = [0u8; 65536];
                loop {
                    if lane_stop.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    match sink_stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => lane_got.lock().unwrap().extend_from_slice(&tmp[..n]),
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });
            readers.push(reader);
            peers.push(peer_stream);
        }

        serving.batch_gen = serving.batch_gen.wrapping_add(1);
        let gen_a = serving.slots[0].slot_gen;
        let gen_b = serving.slots[1].slot_gen;
        serving.in_batch = true;
        let a_token = client_token(gen_a, 0);
        let b_token = client_token(gen_b, 1);
        let a_up_token = upstream_token(gen_a, 0);
        let a0 = serving.slots[0].buf_base + serving.slots[0].fwd;
        serving
            .dispatch_readiness(
                a_token,
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("A client-readable batch token");
        let a1 = serving.slots[0].buf_base + serving.slots[0].fwd;
        serving
            .dispatch_readiness(
                b_token,
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("B client-readable batch token");
        let VisitState::Live {
            ops: b_ops_after_visit,
            ..
        } = serving.visit
        else {
            unreachable!("B's visit is live after its first token");
        };
        serving
            .dispatch_readiness(
                a_up_token,
                Readiness {
                    writable: true,
                    ..Readiness::none()
                },
            )
            .expect("A upstream-writable batch token");
        let a2 = serving.slots[0].buf_base + serving.slots[0].fwd;
        serving.in_batch = false;

        assert!(
            a1 - a0 <= 64 * 1024,
            "A's first batch token must stay inside one 64 KiB visit, moved {}",
            a1 - a0
        );
        assert!(
            a2 == a1,
            "A's upstream-writable token while B's visit is live must defer (reschedule), \
             not advance A: moved {a1} -> {a2}"
        );
        assert!(
            matches!(serving.visit, VisitState::Live { slot: 1, ops, .. } if ops == b_ops_after_visit),
            "A's deferred arm must not be charged to B's live visit; B's visit unchanged: {:?}",
            serving.visit
        );

        let mut pumps = 0;
        while pumps < 2000 {
            let done_a = got_a.lock().unwrap().len() >= expected_a;
            let done_b = got_b.lock().unwrap().len() >= expected_b;
            if done_a && done_b {
                break;
            }
            serving
                .run_once(Some(Duration::from_millis(2)))
                .expect("interleaved real-poll drain poll");
            pumps += 1;
        }
        serving.slots[0].idle_deadline = Some(Instant::now() - Duration::from_millis(1));
        serving.sync_live_deadline(0);
        serving
            .run_once(Some(Duration::from_millis(2)))
            .expect("sweep poll");
        assert!(
            matches!(serving.slots[0].stage, Stage::Idle),
            "one expired relay timer must be swept on the next owner turn (slot 0 was not idle)"
        );
        assert!(
            matches!(serving.slots[1].stage, Stage::Relay),
            "the timer sweep must not touch the other hot slot (slot 1 was not relay)"
        );

        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let tail_a = got_a.lock().unwrap().clone();
        let tail_b = got_b.lock().unwrap().clone();
        readers.remove(0).join().expect("sink reader A");
        readers.remove(0).join().expect("sink reader B");

        drop(peers);

        assert!(
            tail_a.len() >= expected_a && tail_b.len() >= expected_b,
            "both hot slots must be serviced repeatedly with no starvation: A {} / {} B {} / {}",
            tail_a.len(),
            expected_a,
            tail_b.len(),
            expected_b
        );
        assert_eq!(
            &tail_a[..expected_a],
            &pattern_a[..],
            "A's client bytes must arrive byte-exact at the upstream sink"
        );
        assert_eq!(
            &tail_b[..expected_b],
            &pattern_b[..],
            "B's client bytes must arrive byte-exact at the upstream sink"
        );
    });
}

#[test]
#[expect(
    clippy::large_stack_arrays,
    reason = "test staging buffer, not runtime path"
)]
fn retained_edge_reschedules_through_run_once_with_silent_peer() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");

        let got = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let got_reader = std::sync::Arc::clone(&got);
        let sink_reader = std::thread::spawn(move || {
            let mut tmp = [0u8; 65536];
            loop {
                match sink_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => *got_reader.lock().unwrap() += n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        let payload = test_offset_pattern(384 * 1024, 5);
        let payload_len = payload.len();
        let writer = std::thread::spawn(move || {
            peer_stream.write_all(&payload).expect("burst");
            peer_stream
                .shutdown(std::net::Shutdown::Write)
                .expect("peer half-close");
        });

        let start = Instant::now();
        while *got.lock().unwrap() < payload_len {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "the silent peer's relay tail stalled through real run_once: got {} of {}",
                *got.lock().unwrap(),
                payload_len
            );
            serving
                .run_once(Some(Duration::from_millis(10)))
                .expect("poll turns the relay forward");
        }
        writer.join().expect("peer writer");
        serving.close_slot(index);
        sink_reader.join().expect("sink reader");
        assert_eq!(
            *got.lock().unwrap(),
            payload_len,
            "bytes relayed via real run_once from a silent peer must be byte-exact"
        );
    });
}

#[test]
fn one_relay_visit_never_exceeds_the_combined_io_budget() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;
        let _ = sink_stream.set_read_timeout(Some(Duration::from_millis(50)));

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.stage = Stage::Relay;
            ws.head_len = 0;
            ws.buf_base = 0;
            ws.buf_len = 128 * 1024;
            ws.fwd = 0;
            ws.buf[..128 * 1024].copy_from_slice(&test_offset_pattern(128 * 1024, 9));
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");

        let token = upstream_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    writable: true,
                    ..Readiness::none()
                },
            )
            .expect("one writable relay visit");

        let moved = serving.slots[index].buf_base + serving.slots[index].fwd;
        assert!(
            moved <= 64 * 1024,
            "one connection visit must forward at most 64 KiB combined, forwarded {moved}"
        );
        assert!(
            moved > 0 && serving.slots[index].buf_base + serving.slots[index].fwd < 128 * 1024,
            "128 KiB pending must span more than one visit"
        );

        let mut total = moved;
        let drain_start = Instant::now();
        while serving.slots[index].buf_base + serving.slots[index].fwd < 128 * 1024 {
            assert!(
                drain_start.elapsed() < Duration::from_secs(3),
                "the rescheduled relay visit never resumed the pending upload"
            );
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        writable: true,
                        ..Readiness::none()
                    },
                )
                .expect("resumed writable visit");
            total = serving.slots[index].buf_base + serving.slots[index].fwd;
        }

        let mut got = 0usize;
        let mut tmp = [0u8; 4096];
        let recv_start = Instant::now();
        while got < total {
            assert!(
                recv_start.elapsed() < Duration::from_secs(3),
                "the sink never received all forwarded bytes"
            );
            match sink_stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => std::thread::yield_now(),
            }
        }
        assert_eq!(
            got, total,
            "bytes forwarded across budget-split visits must arrive once, unduplicated"
        );
        assert!(
            serving.slots[index].stage == Stage::Relay,
            "a budget-split relay visit must not advance or close the tunnel"
        );
    });
}

#[test]
fn reschedule_rearms_only_the_busy_upstream_after_a_writable_visit_exhausts() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let sink_stream = sink.accept().expect("accept sink side").0;
        let _ = sink_stream.set_read_timeout(Some(Duration::from_millis(50)));

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.stage = Stage::Relay;
            ws.head_len = 0;
            ws.buf_base = 0;
            ws.buf_len = 128 * 1024;
            ws.fwd = 0;
            ws.buf[..128 * 1024].copy_from_slice(&test_offset_pattern(128 * 1024, 12));
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");

        let client_arms_before = serving.reschedule_client_arms;
        let upstream_arms_before = serving.reschedule_upstream_arms;

        let token = upstream_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    writable: true,
                    ..Readiness::none()
                },
            )
            .expect("one writable relay visit");

        let moved = serving.slots[index].buf_base + serving.slots[index].fwd;
        assert!(
            moved > 0 && moved <= 64 * 1024,
            "one connection visit must forward a bounded non-zero slice, forwarded {moved}"
        );

        assert!(
            serving.reschedule_upstream_arms > upstream_arms_before,
            "the busy upstream interest must be re-armed when the visit exhausts mid-forward"
        );
        assert_eq!(
            serving.reschedule_client_arms, client_arms_before,
            "perf-mission C14: a writable-atom visit that never touches the client must not \
             re-register the client interest (docs/alumina-proxy.md:146)"
        );

        serving.close_slot(index);
    });
}

#[test]
fn client_visit_reschedule_arm_tracks_the_pending_flush_direction() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let index = 0;
        serving.slots[index].buf_len = 1024;
        serving.slots[index].fwd = 0;
        assert!(
            matches!(
                serving.client_visit_reschedule_arm(index),
                RescheduleArm::Both
            ),
            "unforwarded client bytes keep both the client and the upstream flush armed"
        );
        serving.slots[index].fwd = 1024;
        assert!(
            matches!(
                serving.client_visit_reschedule_arm(index),
                RescheduleArm::Client
            ),
            "a drained buffer leaves only the client interest armed for the relay read"
        );
    });
}

#[test]
fn preloaded_hold_drains_across_budget_splits_with_quiescent_sink_relying_on_rearm() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let sink_stream = sink.accept().expect("accept sink side").0;
        let _ = sink_stream.set_nonblocking(true);

        let index = 0;
        let hold = 96 * 1024;
        let pattern = test_offset_pattern(hold, 4);
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
            ws.fwd = 0;
            ws.buf[..hold].copy_from_slice(&pattern);
            ws.buf_len = hold;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");

        let mut progress_polls = 0usize;
        let mut last_fwd = 0usize;
        let deadline = Instant::now() + Duration::from_secs(5);
        while serving.slots[index].buf_base + serving.slots[index].fwd < hold {
            assert!(
                Instant::now() < deadline,
                "the quiescent-sink drain must cross the 64 KiB budget split across real \
                 polls with no peer consumption to re-trigger it: fwd {} of {}",
                serving.slots[index].buf_base + serving.slots[index].fwd,
                hold
            );
            serving
                .run_once(Some(Duration::from_millis(5)))
                .expect("real poll drives the re-armed drain");
            if serving.slots[index].buf_base + serving.slots[index].fwd > last_fwd {
                progress_polls += 1;
                last_fwd = serving.slots[index].buf_base + serving.slots[index].fwd;
            }
        }
        assert!(
            progress_polls >= 2,
            "the 96 KiB preload must cross at least one 64 KiB budget split through real \
             polls with the sink quiescent: saw {progress_polls} progress polls"
        );
        assert!(
            serving.slots[index].stage == Stage::Relay,
            "a budget-split drain must not advance or close the tunnel"
        );
        assert_eq!(
            serving.slots[index].buf_base + serving.slots[index].fwd,
            hold,
            "the quiescent sink must have absorbed the full preloaded hold"
        );
        let _ = sink_stream;
    });
}

#[test]
#[expect(
    clippy::large_stack_arrays,
    reason = "test staging buffer, not runtime path"
)]
fn preloaded_hold_drains_across_budget_splits_byte_exact_with_consuming_sink() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;
        let _ = sink_stream.set_nonblocking(true);

        let index = 0;
        let hold = 96 * 1024;
        let pattern = test_offset_pattern(hold, 4);
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
            ws.fwd = 0;
            ws.buf[..hold].copy_from_slice(&pattern);
            ws.buf_len = hold;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");

        let stop_reader = Arc::new(AtomicBool::new(false));
        let sink_got = Arc::new(Mutex::new(Vec::new()));
        let reader_stop = Arc::clone(&stop_reader);
        let reader_got = Arc::clone(&sink_got);
        let reader = std::thread::spawn(move || {
            let mut tmp = [0u8; 65536];
            loop {
                if reader_stop.load(Ordering::SeqCst) {
                    break;
                }
                match sink_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => reader_got.lock().unwrap().extend_from_slice(&tmp[..n]),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        let mut progress_polls = 0usize;
        let mut last_fwd = 0usize;
        let deadline = Instant::now() + Duration::from_secs(5);
        while serving.slots[index].buf_base + serving.slots[index].fwd < hold
            || sink_got.lock().unwrap().len() < hold
        {
            assert!(
                Instant::now() < deadline,
                "preloaded hold stalled mid-drain with the sink peer consuming: fwd {} / \
                 {}, sink got {} / {}",
                serving.slots[index].buf_base + serving.slots[index].fwd,
                hold,
                sink_got.lock().unwrap().len(),
                hold
            );
            serving
                .run_once(Some(Duration::from_millis(5)))
                .expect("real poll drives the drained hold");
            if serving.slots[index].buf_base + serving.slots[index].fwd > last_fwd {
                progress_polls += 1;
                last_fwd = serving.slots[index].buf_base + serving.slots[index].fwd;
            }
        }
        assert!(
            progress_polls >= 2,
            "the 96 KiB preload must span at least two 64 KiB budget-split polls, saw \
             {progress_polls}"
        );
        assert!(
            serving.slots[index].stage == Stage::Relay,
            "a budget-split drain must not advance or close the tunnel"
        );
        stop_reader.store(true, Ordering::SeqCst);
        reader.join().expect("sink reader");
        let got = sink_got.lock().unwrap().clone();
        assert_eq!(
            got,
            pattern,
            "the drained hold must reach the sink byte-exact (offset-distinguishing pattern): \
             got {}B",
            got.len()
        );
    });
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "long read-direction overflow-drain assertion"
)]
#[expect(
    clippy::large_stack_arrays,
    reason = "test staging buffer, not runtime path"
)]
fn read_direction_held_peer_drains_across_budget_splits_without_new_edges() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;
        let _ = sink_stream.set_nonblocking(true);

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;

        let index = 0;
        let hold = 96 * 1024;
        let pattern = test_offset_pattern(hold, 23);
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
            ws.fwd = 0;
            ws.buf_len = 0;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");

        peer_stream
            .write_all(&pattern)
            .expect("preload the full burst before the first real poll");

        let mut probe = vec![0u8; hold];
        let queue_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let queued = match serving.slots[index]
                .client
                .as_ref()
                .expect("client present")
                .peek(&mut probe)
            {
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => 0,
                Err(e) => panic!("peek exact queued length: {e}"),
            };
            if queued >= hold {
                break;
            }
            assert!(
                Instant::now() < queue_deadline,
                "the proxy-side client fd never queued the full {hold}-byte preload, peeked \
                 {queued}"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        let stop_reader = Arc::new(AtomicBool::new(false));
        let sink_got = Arc::new(Mutex::new(Vec::new()));
        let reader_stop = Arc::clone(&stop_reader);
        let reader_got = Arc::clone(&sink_got);
        let reader = std::thread::spawn(move || {
            let mut tmp = [0u8; 65536];
            loop {
                if reader_stop.load(Ordering::SeqCst) {
                    break;
                }
                match sink_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => reader_got.lock().unwrap().extend_from_slice(&tmp[..n]),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        let mut progress_polls = 0usize;
        let mut last_fwd = 0usize;
        let deadline = Instant::now() + Duration::from_secs(5);
        while serving.slots[index].buf_base + serving.slots[index].fwd < hold {
            assert!(
                Instant::now() < deadline,
                "the held-peer read-direction drain stalled without a re-armed client \
                 READABLE edge: fwd {} of {}",
                serving.slots[index].buf_base + serving.slots[index].fwd,
                hold
            );
            serving
                .run_once(Some(Duration::from_millis(5)))
                .expect("real poll drives the read-direction relay");
            if serving.slots[index].buf_base + serving.slots[index].fwd > last_fwd {
                progress_polls += 1;
                last_fwd = serving.slots[index].buf_base + serving.slots[index].fwd;
            }
        }
        let flush_deadline = Instant::now() + Duration::from_secs(5);
        while sink_got.lock().unwrap().len() < hold {
            assert!(
                Instant::now() < flush_deadline,
                "the sink reader never flushed all {hold} relayed bytes"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        stop_reader.store(true, Ordering::SeqCst);
        reader.join().expect("sink reader");
        drop(peer_stream);
        let got = sink_got.lock().unwrap().clone();
        assert_eq!(
            got,
            pattern,
            "the held-peer read-direction relay must reach the sink byte-exact: got {}B",
            got.len()
        );
        assert!(
            progress_polls >= 2,
            "the >64 KiB peer preload with a silent peer must cross at least one 64 KiB \
             budget split through a re-armed client READABLE edge, saw {progress_polls} \
             progress polls"
        );
        assert!(
            serving.slots[index].stage == Stage::Relay,
            "a budget-split read drain must not advance or close the tunnel"
        );
    });
}

#[test]
fn client_read_visit_shares_combined_read_write_budget() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;
        let _ = sink_stream.set_nonblocking(true);

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");

        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received_reader = std::sync::Arc::clone(&received);
        let sink_reader = std::thread::spawn(move || {
            let mut tmp = [0u8; 16384];
            loop {
                match sink_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => received_reader.lock().unwrap().extend_from_slice(&tmp[..n]),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        let payload = test_offset_pattern(96 * 1024, 10);
        peer_stream.write_all(&payload).expect("write burst");

        let token = client_token(serving.slots[index].slot_gen, index);
        let avail_start = Instant::now();
        while serving.slots[index]
            .client
            .as_ref()
            .expect("client present")
            .peek(&mut [0u8; 1])
            .is_err()
        {
            assert!(
                avail_start.elapsed() < Duration::from_secs(2),
                "the client burst never became readable"
            );
            std::thread::yield_now();
        }

        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("one client-readable visit");

        assert!(
            serving.visit.exhausted(),
            "a large read+write burst must exhaust the complete-visit budget in one visit"
        );

        let start = Instant::now();
        while received.lock().unwrap().len() < payload.len() {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "the rescheduled client burst never fully relayed"
            );
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("resume client visit");
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(peer_stream);
        serving.close_slot(index);
        sink_reader.join().expect("sink reader");
        let got = received.lock().unwrap().len();
        assert_eq!(
            got,
            payload.len(),
            "bytes relayed across budget-split visits must arrive intact and once"
        );
    });
}

#[test]
#[expect(
    clippy::large_stack_arrays,
    reason = "test staging buffer, not runtime path"
)]
fn four_mib_up_stream_survives_budget_split_visits_byte_conserved() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");

        let got = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let got_reader = std::sync::Arc::clone(&got);
        let sink_reader = std::thread::spawn(move || {
            let mut tmp = [0u8; 65536];
            loop {
                match sink_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => *got_reader.lock().unwrap() += n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        let payload = test_offset_pattern(4 * 1024 * 1024, 3);
        let payload_len = payload.len();
        let writer = std::thread::spawn(move || {
            let payload_clone = payload.clone();
            peer_stream.write_all(&payload_clone).expect("4 MiB burst");
            peer_stream
                .shutdown(std::net::Shutdown::Write)
                .expect("client half-close");
        });

        let client_token = client_token(serving.slots[index].slot_gen, index);
        let up_token = upstream_token(serving.slots[index].slot_gen, index);
        let start = Instant::now();
        while *got.lock().unwrap() < payload_len {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "4 MiB up relay never reached the sink: got {}",
                *got.lock().unwrap()
            );
            serving
                .dispatch_readiness(
                    client_token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("client-readable visit");
            serving
                .dispatch_readiness(
                    up_token,
                    Readiness {
                        writable: true,
                        ..Readiness::none()
                    },
                )
                .expect("upstream-writable visit");
            if serving.slots[index].upstream.is_none() {
                break;
            }
        }
        writer.join().expect("peer writer");
        serving.close_slot(index);
        sink_reader.join().expect("sink reader");
        let got_total = *got.lock().unwrap();
        assert_eq!(
            got_total, payload_len,
            "bytes relayed across budget-split visits must be conserved end to end"
        );
    });
}

#[test]
#[expect(
    clippy::large_stack_arrays,
    reason = "test staging buffer, not runtime path"
)]
fn four_mib_down_stream_survives_budget_split_visits_byte_conserved() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let origin_l = StdListener::bind("127.0.0.1:0").expect("origin bind");
        let origin_addr = origin_l.local_addr().expect("origin addr");
        let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
        let mut origin = origin_l.accept().expect("accept origin side").0;

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");

        let payload = test_offset_pattern(4 * 1024 * 1024, 6);
        let payload_len = payload.len();
        let writer_payload = payload.clone();
        let origin_writer = std::thread::spawn(move || {
            origin.write_all(&writer_payload).expect("4 MiB down burst");
            origin
                .shutdown(std::net::Shutdown::Write)
                .expect("origin FIN");
        });

        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let got_reader = std::sync::Arc::clone(&got);
        let client_reader = std::thread::spawn(move || {
            let mut tmp = [0u8; 65536];
            loop {
                match peer_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => got_reader.lock().unwrap().extend_from_slice(&tmp[..n]),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        let up_token = upstream_token(serving.slots[index].slot_gen, index);
        let client_token2 = client_token(serving.slots[index].slot_gen, index);
        let start = Instant::now();
        while got.lock().unwrap().len() < payload_len {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "4 MiB down relay never reached the client: got {}",
                got.lock().unwrap().len()
            );
            serving
                .dispatch_readiness(
                    up_token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("upstream-readable visit");
            serving
                .dispatch_readiness(
                    client_token2,
                    Readiness {
                        writable: true,
                        ..Readiness::none()
                    },
                )
                .expect("client-writable visit");
            if serving.slots[index].client.is_none() {
                break;
            }
        }
        origin_writer.join().expect("origin writer");
        serving.close_slot(index);
        client_reader.join().expect("client reader");
        let got_vec = got.lock().unwrap().clone();
        assert_eq!(
            got_vec, payload,
            "down bytes relayed across budget-split visits must arrive byte-exact"
        );
    });
}

#[test]
fn full_down_buffer_applies_backpressure_not_false_eof() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let upstream_peer_l = StdListener::bind("127.0.0.1:0").expect("upstream peer bind");
        let upstream_peer_addr = upstream_peer_l.local_addr().expect("upstream peer addr");
        let up = mio::net::TcpStream::connect(upstream_peer_addr).expect("upstream connect");
        let mut upstream_peer = upstream_peer_l
            .accept()
            .expect("accept upstream peer side")
            .0;

        let client_peer_l = StdListener::bind("127.0.0.1:0").expect("client peer bind");
        let client_peer_addr = client_peer_l.local_addr().expect("client peer addr");
        let client = mio::net::TcpStream::connect(client_peer_addr).expect("client connect");
        let client_peer = client_peer_l.accept().expect("accept client peer side").0;
        let _ = client_peer.set_read_timeout(Some(Duration::from_millis(100)));

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
            ws.fwd = 0;
            ws.down[..6].copy_from_slice(b"HELLOA");
            ws.down_len = DOWN_CAP - 1;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");
        upstream_peer
            .write_all(b"more")
            .expect("upstream data available with no room");

        let up_token = upstream_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                up_token,
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("no-room upstream-readable visit");

        assert!(
            matches!(serving.slots[index].stage, Stage::Relay),
            "a full down buffer must apply backpressure, not close the tunnel"
        );
        assert_eq!(
            serving.slots[index].down_len,
            DOWN_CAP - 1,
            "no bytes may be read into a zero-room down buffer"
        );
        assert!(
            serving.slots[index].upstream.is_some(),
            "a no-room upstream-readable visit must never false-EOF the upstream"
        );
        assert!(
            serving.slots[index].client.is_some(),
            "the downstream client socket must be retained under backpressure"
        );

        assert_eq!(
            serving.slots[index].down_len,
            DOWN_CAP - 1,
            "backpressure must not consume the pending downstream payload"
        );
    });
}

#[test]
fn stalled_reverse_fin_drains_exact_bytes_then_closes_once() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let client_peer_l = StdListener::bind("127.0.0.1:0").expect("client peer bind");
        let client_peer_addr = client_peer_l.local_addr().expect("client peer addr");
        let client = mio::net::TcpStream::connect(client_peer_addr).expect("client connect");
        let mut client_peer = client_peer_l.accept().expect("accept client peer side").0;
        let _ = client_peer.set_read_timeout(Some(Duration::from_millis(20)));

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
            ws.directional.down = SideEof::Open;
            let payload = b"STALLED-REVERSE-PAYLOAD-0123456789";
            ws.down[..payload.len()].copy_from_slice(payload);
            ws.down_len = payload.len();
            ws.down_off = 0;
        }
        open_relay(serving, index);
        serving.register_client(index).expect("register client");

        serving.observe_down_eof(index);
        assert!(
            matches!(
                serving.slots[index].directional.down,
                SideEof::Eof { half_closed: false }
            ),
            "the reverse EOF must be recorded as half-close pending while bytes remain buffered"
        );
        assert!(
            matches!(serving.slots[index].stage, Stage::Relay),
            "a stalled reverse buffer must keep the tunnel open (no premature half-close/close)"
        );

        let expected = b"STALLED-REVERSE-PAYLOAD-0123456789";
        let mut got = Vec::new();
        let mut tmp = [0u8; 64];
        let drain_start = Instant::now();
        while got.len() < expected.len() {
            assert!(
                drain_start.elapsed() < Duration::from_secs(5),
                "stalled reverse FIN never drained: got {} of {}",
                got.len(),
                expected.len()
            );
            serving
                .run_once(Some(Duration::from_millis(5)))
                .expect("gate-vicinity run poll");
            match client_peer.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&tmp[..n]),
                Err(_) => {}
            }
        }
        assert_eq!(
            got, expected,
            "the stalled reverse payload must arrive byte-exact after the buffer drains"
        );

        client_peer
            .shutdown(std::net::Shutdown::Write)
            .expect("client fin");
        let close_start = Instant::now();
        while !matches!(serving.slots[index].stage, Stage::Idle) {
            assert!(
                close_start.elapsed() < Duration::from_secs(5),
                "the slot never closed once both directions drained"
            );
            serving
                .run_once(Some(Duration::from_millis(5)))
                .expect("gate-vicinity run poll");
        }
    });
}

#[test]
fn second_gateopening_drain_shares_the_single_visit_budget() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let sink_stream = sink.accept().expect("accept sink side").0;
        let _ = sink_stream.set_read_timeout(Some(Duration::from_millis(50)));

        let client = mio::net::TcpStream::connect(
            StdListener::bind("127.0.0.1:0")
                .expect("peer bind")
                .local_addr()
                .expect("peer addr"),
        )
        .expect("client connect");

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::WritingHello;
            ws.head_len = 4;
            ws.buf_base = 0;
            ws.fwd = 0;
            ws.gate.on_connect_head(4);
            ws.gate.on_authorized();
            ws.gate.on_upstream_connected();
            ws.gate.on_response_ok();
            ws.gate.on_hello_validated(ValidatedHello::test_new(1024));

            ws.buf[..4].copy_from_slice(b"HEAD");
            let hello_region = test_offset_pattern(1020, 11);
            ws.buf[4..1024].copy_from_slice(&hello_region);
            let payload_region = test_offset_pattern(HOLD_CAP - 1024, 12);
            let mut filled = 1024;
            while filled < ws.buf.len() {
                let chunk = (ws.buf.len() - filled).min(1024);
                let window = filled - 1024;
                ws.buf[filled..filled + chunk]
                    .copy_from_slice(&payload_region[window..window + chunk]);
                filled += chunk;
            }
            ws.buf_len = ws.buf.len();
        }
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");
        assert!(
            !serving.slots[index].gate.is_open(),
            "the gate must still be closed before the crossing visit"
        );

        let _ = sink_stream.set_nonblocking(true);

        serving.in_batch = true;
        serving.batch_gen = serving.batch_gen.wrapping_add(1);
        let token = upstream_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    writable: true,
                    ..Readiness::none()
                },
            )
            .expect("one gate-crossing upstream-writable token");
        let consumed = match serving.visit {
            VisitState::Live { ops, bytes, .. } => (ops, bytes),
            VisitState::Idle => {
                unreachable!("the gate-crossing visit stays live until end of batch")
            }
        };
        let fwd_after = serving.slots[index].fwd;
        let gate_open = serving.slots[index].gate.is_open();
        let stage_after = serving.slots[index].stage;
        serving.in_batch = false;

        assert!(
            gate_open && matches!(stage_after, Stage::Relay),
            "the single visit must succeed in opening the gate prior to relay (gate={gate_open})"
        );
        assert!(
            consumed.0 <= 16 && consumed.1 <= 64 * 1024,
            "pre-open drain + post-open second drain must share ONE visit budget: {} ops / {} bytes",
            consumed.0,
            consumed.1
        );
        assert!(
            fwd_after > 1024,
            "the crossing visit must forward past the validated hello boundary (fwd {fwd_after})"
        );
        assert_eq!(
            serving.slots[index].down_len, 0,
            "the up-flow gate must open before any downstream read occurs in the visit"
        );
    });
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "long full-buffer/eof probe assertion"
)]
#[expect(
    clippy::large_stack_arrays,
    reason = "test staging buffer, not runtime path"
)]
fn full_up_buffer_never_reads_into_zero_room_or_false_eofs() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;
        sink_stream.set_nonblocking(true).expect("sink nonblocking");

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
            ws.fwd = 0;
            let pattern = test_offset_pattern(HOLD_CAP - 1, 13);
            ws.buf[..HOLD_CAP - 1].copy_from_slice(&pattern);
            ws.buf_len = HOLD_CAP - 1;
        }
        open_relay(serving, index);
        serving.register_client(index).expect("register client");
        serving.register_upstream(index).expect("register upstream");
        peer_stream
            .write_all(b"more")
            .expect("client data available with no room");

        let token = client_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("no-room readable visit");

        assert!(
            matches!(serving.slots[index].stage, Stage::Relay),
            "a full buffer must apply backpressure, not close the tunnel"
        );
        assert_eq!(
            serving.slots[index].buf_len,
            HOLD_CAP - 1,
            "no bytes may be read into a zero-room buffer"
        );
        assert!(
            serving.slots[index].client.is_some(),
            "a no-room readable visit must never false-EOF the client"
        );

        let expected = test_offset_pattern(HOLD_CAP - 1, 13);
        let stop_reader = Arc::new(AtomicBool::new(false));
        let sink_got = Arc::new(Mutex::new(Vec::new()));
        let reader_stop = Arc::clone(&stop_reader);
        let reader_got = Arc::clone(&sink_got);
        let reader = std::thread::spawn(move || {
            let mut tmp = [0u8; 65536];
            loop {
                if reader_stop.load(Ordering::SeqCst) {
                    break;
                }
                match sink_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => reader_got.lock().unwrap().extend_from_slice(&tmp[..n]),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        let drain_deadline = Instant::now();
        while sink_got.lock().unwrap().len() < expected.len() + 4 {
            assert!(
                drain_deadline.elapsed() < Duration::from_secs(3),
                "the full upstream buffer must drain to the origin once room appears: \
                 sink got {} of {}, fwd {} buf_len {} client {}",
                sink_got.lock().unwrap().len(),
                expected.len() + 4,
                serving.slots[index].fwd,
                serving.slots[index].buf_len,
                serving.slots[index].client.is_some()
            );
            serving
                .run_once(Some(Duration::from_millis(5)))
                .expect("real poll drives the drain and the follow-up head");
        }
        stop_reader.store(true, Ordering::SeqCst);
        reader.join().expect("sink reader");
        let got = sink_got.lock().unwrap().clone();
        let mut expected_tail = expected;
        expected_tail.extend_from_slice(b"more");
        assert_eq!(
            got, expected_tail,
            "the drained buffer plus the pending client bytes must reach the origin byte-exact"
        );
    });
}

#[test]
fn sink_drain_of_client_writes_resumes_paused_upstream_source() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;

        let index = 0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.down[..4].copy_from_slice(b"DOWN");
            ws.down_len = 4;
            ws.down_off = 0;
        }
        open_relay(serving, index);
        serving.register_upstream(index).expect("register up");
        serving.register_client(index).expect("register client");

        sink_stream.write_all(b"+").expect("origin byte pending");

        let mut tmp = [0u8; 64];
        let mut got = Vec::new();
        let start = Instant::now();
        let _ = peer_stream.set_read_timeout(Some(Duration::from_millis(50)));
        while got.len() < 5 {
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "a paused upstream source was never resumed after the client sink drained"
            );
            serving
                .client_writable(index)
                .expect("drain + resume visit");
            if let Ok(n) = peer_stream.read(&mut tmp) {
                got.extend_from_slice(&tmp[..n]);
            }
            std::thread::yield_now();
        }
        assert_eq!(
            got,
            b"DOWN+".to_vec(),
            "a client sink drain must resume the paused upstream read without a new edge"
        );
    });
}

#[test]
fn expiry_never_reinjects_after_a_begun_response() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut client = connect(port);
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("client read timeout");
        pump(serving, 20);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "silent client must be admitted"
        );

        {
            let ws = &mut serving.slots[0];
            ws.down[..BODY_200.len()].copy_from_slice(BODY_200);
            ws.down_len = BODY_200.len();
            ws.down_off = 0;
            ws.stage = Stage::SendingConnected;
        }
        let start = Instant::now();
        while serving.storage().occupied() > 0 {
            serving.run_once(None).expect("block to expiry");
            assert!(
                start.elapsed() <= Duration::from_secs(crate::worker::SETUP_DEADLINE_SECS + 5),
                "a begun-response slot must be released at its deadline"
            );
        }
        let mut tail = Vec::new();
        let tail_deadline = Instant::now();
        loop {
            if tail_deadline.elapsed() > Duration::from_secs(2) {
                break;
            }
            let mut tmp = [0u8; 256];
            match client.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => tail.extend_from_slice(&tmp[..n]),
            }
        }
        assert!(
            tail.starts_with(b"HTTP/1.1 200"),
            "the begun 200 must not be overwritten on expiry, got {:?}",
            &tail[..tail.len().min(24)]
        );
        assert!(
            !tail.windows(12).any(|w| w == b"HTTP/1.1 504"),
            "no 504 may be spliced after a begun response on expiry"
        );
    });
}

#[test]
fn sigterm_first_observation_enters_draining_and_stops_admission() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let client = connect(port);
        pump(serving, 40);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "a connecting client must be admitted before the signal"
        );
        assert!(
            serving.listener.is_some(),
            "admission is open before the first SIGTERM"
        );

        serving
            .signal_wake_mut()
            .expect("the serving owns the self-pipe write end")
            .write_all(&[1])
            .expect("write the signal byte into the self-pipe");
        pump(serving, 40);
        assert!(
            serving.is_shutdown(),
            "a self-pipe signal must reach draining through the shared poll"
        );
        assert!(
            matches!(serving.shutdown(), Shutdown::Draining { .. }),
            "the first SIGTERM must enter the draining phase"
        );
        assert_eq!(
            serving.signal_read_error(),
            None,
            "a healthy self-pipe drain must not name a real read error"
        );
        assert!(
            serving.listener.is_none(),
            "the listener must be dropped, so no later connection can be accepted"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "a pending setup is closed at the first signal; established tunnels drain"
        );
        assert!(
            !serving.storage().dns().has_active_exchange(),
            "the retained DNS transport is cancelled at the first signal"
        );
        drop(client);
    });
}

#[test]
fn sigterm_repeat_does_not_extend_the_deadline() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        serving.on_sigterm().expect("first SIGTERM observation");
        let Shutdown::Draining { deadline: first } = serving.shutdown() else {
            panic!("first SIGTERM must enter draining");
        };
        std::thread::sleep(Duration::from_millis(5));
        serving.on_sigterm().expect("second SIGTERM observation");
        let Shutdown::Draining { deadline: second } = serving.shutdown() else {
            panic!("state must stay draining after a second SIGTERM");
        };
        assert_eq!(
            first, second,
            "a later SIGTERM never extends the fixed shutdown deadline"
        );
    });
}

#[test]
fn sigterm_clean_drain_exits_zero_when_no_tunnels() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        serving.on_sigterm().expect("first SIGTERM observation");
        assert_eq!(serving.storage().occupied(), 0);
        assert_eq!(
            serving.shutdown_exit(),
            Some(ShutdownExit::Drained),
            "an empty drain after the first signal is a clean exit"
        );
        assert_eq!(ShutdownExit::Drained.code(), 0);
    });
}

#[test]
fn sigterm_deadline_force_closes_remaining_sockets_and_exits_seventy() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let client = connect(port);
        pump(serving, 40);
        assert_eq!(serving.storage().occupied(), 1);
        serving.slots[0].stage = Stage::Relay;

        serving.on_sigterm().expect("first SIGTERM observation");
        assert_eq!(
            serving.storage().occupied(),
            1,
            "an established relay keeps draining and is not closed by the signal itself"
        );
        assert_eq!(
            serving.shutdown_exit(),
            None,
            "while a tunnel occupies a slot before the deadline, the owner keeps draining"
        );

        serving.set_shutdown_deadline(Instant::now() - Duration::from_millis(1));
        assert_eq!(
            serving.shutdown_exit(),
            Some(ShutdownExit::Forced),
            "once the fixed deadline passes, remaining sockets are closed as a failure"
        );
        assert_eq!(ShutdownExit::Forced.code(), 70);
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the forced closure releases every remaining occupied socket"
        );
        drop(client);
    });
}

#[test]
fn sigterm_folds_shutdown_deadline_into_the_idle_poll_wait() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        assert_eq!(
            serving.poll_timeout(),
            None,
            "idle serving with no traffic/DNS/log has no wait"
        );
        serving.on_sigterm().expect("first SIGTERM observation");
        let wait = serving
            .poll_timeout()
            .expect("an idle drain must still wake at the shutdown deadline");
        assert!(
            wait <= Duration::from_secs(8),
            "the drain wait is bounded by the fixed 8s grace from the first observation, got {wait:?}"
        );
    });
}

#[test]
fn sigterm_dispatch_priority_no_accept_after_first_signal() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let client = connect(port);
        pump(serving, 40);
        assert_eq!(serving.storage().occupied(), 1);

        serving.on_sigterm().expect("first SIGTERM observation");
        let raw = 0;
        serving
            .dispatch_readiness(
                Token(raw),
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("stale listener readiness after the signal");
        assert_eq!(
            serving.storage().occupied(),
            0,
            "no admissions may occur after the first signal"
        );
        assert!(
            matches!(serving.shutdown(), Shutdown::Draining { .. }),
            "the owner stays in draining after a stale listener wake"
        );
        drop(client);
    });
}

#[cfg(feature = "alloc-witness")]
#[test]
fn sigterm_shutdown_path_spends_zero_allocations() {
    std::thread::Builder::new()
        .name("shutdown-alloc-witness".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(shutdown_alloc_witness_body)
        .expect("spawn shutdown alloc witness")
        .join()
        .expect("shutdown alloc witness thread");
}

#[cfg(feature = "alloc-witness")]
#[expect(
    clippy::too_many_lines,
    reason = "long alloc-witness shutdown composition body"
)]
fn shutdown_alloc_witness_body() {
    let port = ephemeral_port();
    let storage = ServeStorage::boot(&config(port)).expect("boot storage");
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), port))
        .expect("bind listener");
    let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
    let mut runtime = crate::runtime::Runtime::new(storage, listener, traffic)
        .expect("runtime owner (preallocate + attach)");

    let pending_client = connect(port);
    turn_pump(&mut runtime, 40);
    assert_eq!(
        runtime.serving().storage().occupied(),
        1,
        "the pending setup occupies the first storage slot before the signal"
    );

    let mut relay_client = connect(port);
    turn_pump(&mut runtime, 40);
    assert_eq!(
        runtime.serving().storage().occupied(),
        2,
        "two real admitted setups occupy storage before the signal: one pending, one promoted below"
    );

    let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
    let sink_addr = sink.local_addr().expect("sink addr");
    let upstream = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
    let _sink_stream = sink.accept().expect("accept sink side").0;
    wait_upstream_connected(&upstream);
    let index = 1;
    let wire = hello_wire(b"sub.example.org", false);
    relay_client
        .write_all(&wire)
        .expect("hello bytes available on the real admitted client socket");
    let drain_reader = {
        let mut drain = relay_client
            .try_clone()
            .expect("clone the relay client for the CONNECT-response drain reader");
        std::thread::Builder::new()
            .name("relay-client-drain".into())
            .spawn(move || {
                let mut buf = [0u8; 256];
                while matches!(drain.read(&mut buf), Ok(n) if n > 0) {}
            })
            .expect("spawn the CONNECT-response drain reader")
    };
    {
        let serving = runtime.serving_mut();
        let ws = &mut serving.slots[index];
        ws.approved = FixedHostname::normalize(b"sub.example.org");
        ws.gate.on_connect_head(0);
        ws.gate.on_authorized();
        ws.stage = Stage::Dialing;
        ws.upstream = Some(upstream);
        ws.head_len = 0;
        ws.buf_base = 0;
        ws.buf_len = 0;
        ws.fwd = 0;
        ws.insp_rel = 0;
        ws.hello_consumed = 0;
    }
    runtime
        .serving_mut()
        .register_upstream(index)
        .expect("register the real upstream socket");
    runtime
        .serving_mut()
        .upstream_writable(index)
        .expect("dial-connected promotion through the production owner path");
    turn_pump(&mut runtime, 40);
    assert!(
        runtime.serving().slots[index].tunnel.is_some(),
        "the promoted relay must graduate to a real storage tunnel handle"
    );
    assert!(
        matches!(runtime.serving().slots[index].stage, Stage::Relay),
        "an established relay holds the second slot before the signal"
    );
    assert!(
        runtime.serving().slots[index].client.is_some()
            && runtime.serving().slots[index].upstream.is_some(),
        "the relay owns live client and upstream sockets before the signal"
    );

    let ((), counts) = crate::alloc::run_phase(crate::alloc::Phase::Shutdown, || {
        runtime
            .serving_mut()
            .signal_wake_mut()
            .expect("the owner holds the self-pipe write end")
            .write_all(&[1])
            .expect("write the signal byte into the self-pipe");
        turn_pump(&mut runtime, 40);
        assert!(
            runtime.serving().is_shutdown(),
            "a real self-pipe signal must enter draining through Runtime::turn"
        );
        assert_eq!(
            runtime.serving().storage().occupied(),
            1,
            "the pending setup is closed at the first signal; the established relay keeps draining"
        );
        assert!(
            matches!(runtime.serving().slots[index].stage, Stage::Relay),
            "the established relay keeps draining past the first signal"
        );
        assert_eq!(
            runtime.serving_mut().shutdown_exit(),
            None,
            "while the relay still occupies a slot before the deadline, the drain does not settle"
        );
        runtime
            .serving_mut()
            .set_shutdown_deadline(Instant::now() - Duration::from_millis(1));
        turn_pump(&mut runtime, 40);
        let exit = runtime
            .serving_mut()
            .shutdown_exit()
            .expect("a drain past the fixed deadline must settle");
        assert_eq!(exit.code(), 70, "a forced closure exit is EX_SOFTWARE");
        assert!(
            runtime.serving().slots[index].client.is_none()
                && runtime.serving().slots[index].upstream.is_none(),
            "forced closure releases the relay sockets exactly once"
        );
        assert_eq!(
            runtime.serving().storage().occupied(),
            0,
            "forced closure releases the real storage tunnel through release_tunnel: occupied 2 -> 1 -> 0"
        );
        runtime.emit_shutdown_record_and_drain(exit);
        assert!(
            runtime.serving().is_shutdown(),
            "the typed shutdown record and final bounded drain keep the owner draining"
        );
    });
    assert!(
        counts.all_zero(),
        "the real-signal shutdown through Runtime::turn must allocate/deallocate nothing: {counts:?}"
    );
    drain_reader
        .join()
        .expect("the CONNECT-response drain reader exits after the forced close");
    drop(relay_client);
    drop(pending_client);
}

/// Compile-time pin of the fixed serving buffer profile (alumina-tm6m): each
/// tunnel carries two reused 128 KiB buffers across the 512-slot budget, and
/// pending setups stay within the 128-slot cap. These are true compile-time
/// guards, not runtime assertions over a constant.
const _: () = assert!(
    HOLD_CAP == 128 * 1024,
    "client->upstream buffer must be 128 KiB"
);
const _: () = assert!(
    DOWN_CAP == 128 * 1024,
    "upstream->client buffer must be 128 KiB"
);
const _: () = assert!(MAX_TUNNELS == 512, "the fixed tunnel budget is 512 slots");
const _: () = assert!(MAX_PENDING_SETUPS <= 128, "at most 128 pending setups");
const _: () = assert!(
    (HOLD_CAP + DOWN_CAP) * MAX_TUNNELS == 128 * 1024 * 1024,
    "two 128 KiB buffers per tunnel across 512 slots is the 128 MiB traffic profile"
);

fn serve_on_cfg(port: u16, cfg: &crate::config::Config) -> Serving {
    let storage = ServeStorage::boot(cfg).expect("boot storage");
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), port))
        .expect("bind listener");
    let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
    Serving::new(storage, listener, traffic).expect("serving")
}

fn cfg_doc1(port: u16, any_scope: &str, kind: &str, action_scope: &str) -> crate::config::Config {
    let doc = format!(
        "allowlist = [\"sub.example.org:443\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"{any_scope}\"\n[actions]\nkind = [\"{kind}\"]\nscope = [\"{action_scope}\"]\n"
    );
    crate::config::parse_config_document(&doc).expect("valid enforcement test config")
}

fn with_serving_stack_cfg(
    port: u16,
    cfg: crate::config::Config,
    body: impl FnOnce(&mut Serving) + Send + 'static,
) {
    let t = std::thread::Builder::new()
        .name("serving-test".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let mut serving = serve_on_cfg(port, &cfg);
            body(&mut serving);
        })
        .expect("spawn serving thread");
    t.join().expect("serving thread");
}

#[test]
fn any_illegal_all_latches_before_further_io_stops_admission_and_closes_pending() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "all", "flare_only", "connection");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let mut a = connect(port);
        a.write_all(b"CONNECT sub.example.org:44")
            .expect("partial head A");
        pump(serving, 20);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "a partial CONNECT head must hold an admitted pending seat"
        );
        assert!(!serving.storage().enforcement().block_all());

        let mut b = connect(port);
        b.write_all(b"CONNECT evil.example.net:443 HTTP/1.1\r\n\r\n")
            .expect("head B");
        pump(serving, 30);
        assert!(
            serving.storage().enforcement().block_all(),
            "the first AnyIllegal with scope all must latch before erasure"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the latch must close the pending A seat and the offender B before any further I/O"
        );

        let bb = read_until(&mut b, b"\r\n\r\n");
        assert!(
            bb.is_empty(),
            "after Block All the offender must receive no 403 and no bytes at all (EOF/RST), got {bb:?}"
        );

        a.set_nonblocking(true).expect("A nonblocking");
        let mut probe = [0u8; 8];
        match a.read(&mut probe) {
            Ok(0) => {}
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("pending A must be closed without a response, got {other:?}"),
        }

        serving
            .dispatch_readiness(
                Token(0),
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("stale listener readiness after the latch");
        assert_eq!(
            serving.storage().occupied(),
            0,
            "no admission happens after the catch-all latch"
        );
    });
}

fn fabric_validated_early_data(serving: &mut Serving, test_data: Option<usize>) {
    fabric_validated_early_data_at(serving, 0, test_data);
}

fn fabric_validated_early_data_at(serving: &mut Serving, index: usize, test_data: Option<usize>) {
    let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
    let origin_addr = origin.local_addr().expect("origin addr");
    let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
    let _origin_stream = origin.accept().expect("accept origin side").0;
    {
        let ws = &mut serving.slots[index];
        ws.approved = FixedHostname::normalize(b"sub.example.org");
        let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
        ws.head_len = head_len;
        ws.gate.on_connect_head(head_len);
        ws.gate.on_authorized();
        ws.gate.on_upstream_connected();
        ws.stage = Stage::Dialing;
        ws.upstream = Some(up);
    }
    serving.register_upstream(index).expect("register upstream");
    if let Some(n) = test_data {
        serving.slots[index].test_reads = Vec::new();
        serving.slots[index].test_reads = vec![Ok(n)];
    }
}

fn fabric_relay_slot(serving: &mut Serving, index: usize, approved: &[u8], pending_down: &[u8]) {
    let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
    let sink_addr = sink.local_addr().expect("sink addr");
    let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
    let _sink_stream = sink.accept().expect("accept sink side").0;
    {
        let ws = &mut serving.slots[index];
        ws.approved = FixedHostname::normalize(approved);
        ws.upstream = Some(up);
        ws.head_len = 4;
        ws.hello_end = Some(10);
        ws.buf_base = 0;
        ws.buf_len = 0;
        ws.down_off = 0;
        ws.down[..pending_down.len()].copy_from_slice(pending_down);
        ws.down_len = pending_down.len();
        ws.stage = Stage::Relay;
        ws.gate.on_connect_head(4);
        ws.gate.on_authorized();
        ws.gate.on_upstream_connected();
        ws.gate.on_response_ok();
    }
    serving.register_upstream(index).expect("register upstream");
}

#[test]
fn validated_early_data_applies_block_domain_and_terminates_setup() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "connection", "block", "domain");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let _client = connect(port);
        pump(serving, 20);
        assert_eq!(serving.storage().occupied(), 1, "boot traffic admitted");
        serving.slots[0].hello_end = Some(10);
        fabric_validated_early_data(serving, Some(5));
        let token = upstream_token(serving.slots[0].slot_gen, 0);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: false,
                    ..Readiness::none()
                },
            )
            .expect("early origin data");

        assert_eq!(
            serving.storage().occupied(),
            0,
            "early upstream data is a mandatory termination even under a Block action"
        );
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        assert!(
            serving.storage().enforcement().is_blocked(ordinal),
            "Block Domain must mark the validated configured-domain ordinal"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .actions_domain_block(ordinal),
            1
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .actions_flare(ordinal),
            0
        );
        assert!(
            !serving.storage().enforcement().block_all(),
            "Domain scope must never set the All latch"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_any_illegal_total(),
            0,
            "AnyIllegal counters stay untouched by a validated-domain fact"
        );
    });
}

#[test]
fn validated_early_data_flare_is_reporting_only_and_setup_still_terminates() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "connection", "flare_only", "connection");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let _client = connect(port);
        pump(serving, 20);
        assert_eq!(serving.storage().occupied(), 1, "boot traffic admitted");
        serving.slots[0].hello_end = Some(10);
        fabric_validated_early_data(serving, Some(5));
        let token = upstream_token(serving.slots[0].slot_gen, 0);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: false,
                    ..Readiness::none()
                },
            )
            .expect("early origin data");

        assert_eq!(
            serving.storage().occupied(),
            0,
            "FlareOnly never delays the mandatory denial"
        );
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .actions_flare(ordinal),
            1
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .actions_domain_block(ordinal),
            0
        );
        assert!(
            !serving.storage().enforcement().is_blocked(ordinal),
            "FlareOnly must not mark the domain blocked"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_unknown(UnknownReason::NotYetValidated),
            0
        );
    });
}

#[test]
fn prevalidated_early_data_folds_unknown_without_any_block() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "connection", "block", "domain");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let _client = connect(port);
        pump(serving, 20);
        assert_eq!(serving.storage().occupied(), 1, "boot traffic admitted");
        fabric_validated_early_data(serving, Some(5));
        serving.slots[0].hello_end = None;
        serving.slots[0].approved = None;
        let token = upstream_token(serving.slots[0].slot_gen, 0);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: false,
                    ..Readiness::none()
                },
            )
            .expect("pre-validated early data");

        assert_eq!(
            serving.storage().occupied(),
            0,
            "the anomaly still terminates setup as EvidenceInsufficient"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_unknown(UnknownReason::NotYetValidated),
            1,
            "missing validated identity folds Unknown(NotYetValidated), never a block verdict"
        );
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        assert!(
            !serving.storage().enforcement().is_blocked(ordinal),
            "EvidenceInsufficient must not mark any domain blocked"
        );
        assert!(
            !serving.storage().enforcement().block_all(),
            "EvidenceInsufficient must not set the All latch"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .actions_domain_block(ordinal),
            0
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_any_illegal_total(),
            0,
            "the anomaly is not AnyIllegal and carries no Block effect"
        );
    });
}

#[test]
fn domain_block_refuses_future_flow_of_the_ordinal_until_restart() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "connection", "block", "domain");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        assert!(!serving.storage().enforcement().is_blocked(ordinal));

        let mut evil = connect(port);
        evil.write_all(b"CONNECT attacker.example.net:443 HTTP/1.1\r\n\r\n")
            .expect("evil head");
        pump(serving, 20);
        let eb = read_until(&mut evil, b"\r\n\r\n");
        assert!(eb.starts_with(b"HTTP/1.1 403"), "untrusted CONNECT denied");
        assert!(
            !serving.storage().enforcement().is_blocked(ordinal),
            "an untrusted label must never mark a configured domain blocked"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_any_illegal(AnyIllegalCause::HostNotAllowlisted),
            1
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .actions_domain_block(ordinal),
            0
        );

        serving.storage_mut().publish_test_a(ordinal.get());
        let _trigger = connect(port);
        pump(serving, 20);
        assert_eq!(serving.storage().occupied(), 1, "pre-block peer admitted");
        serving.slots[0].hello_end = Some(10);
        fabric_validated_early_data(serving, Some(5));
        let token = upstream_token(serving.slots[0].slot_gen, 0);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: false,
                    ..Readiness::none()
                },
            )
            .expect("early data blocks the domain");
        assert!(serving.storage().enforcement().is_blocked(ordinal));

        let mut future = connect(port);
        future
            .write_all(b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n")
            .expect("future head");
        pump(serving, 20);
        let fb = read_until(&mut future, b"\r\n\r\n");
        assert!(
            fb.starts_with(b"HTTP/1.1 403"),
            "a future flow for the blocked ordinal must be refused before any dial, got {fb:?}"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .actions_domain_block(ordinal),
            1,
            "the early-data Block-Domain action is not re-applied by the refusal"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .refusals_blocked_domain(ordinal),
            1,
            "the future-flow refusal folds its own refusal channel, never the action"
        );
    });
}

#[test]
/// A same-hostname different-port CONNECT on an allowlisted-but-domain-blocked
/// ordinal must flow through `decide` to `HostNotAllowlisted`; it must never
/// take the bare-hostname early domain-block return (alumina-9t6w review B1).
fn port_mismatch_on_domain_blocked_ordinal_is_host_not_allowlisted() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "connection", "block", "domain");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        let mut latch = crate::enforcement::action::FirstSlot::new();
        serving.storage_mut().enforcement_mut().decide(
            &mut latch,
            crate::enforcement::policy::Violation::EarlyUpstreamData { ordinal },
        );
        assert!(
            serving.storage().enforcement().is_blocked(ordinal),
            "precondition: the configured-domain ordinal is domain-blocked"
        );

        let mut client = connect(port);
        client
            .write_all(b"CONNECT sub.example.org:8443 HTTP/1.1\r\n\r\n")
            .expect("different-port connect head");
        pump(serving, 40);
        let body = read_until(&mut client, b"\r\n\r\n");
        assert!(
            body.starts_with(b"HTTP/1.1 403"),
            "a port-mismatch CONNECT must be refused 403, got {body:?}"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_any_illegal(AnyIllegalCause::HostNotAllowlisted),
            1,
            "port mismatch must reach decide -> HostNotAllowlisted, not the early domain-block return"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .actions_domain_block(ordinal),
            1,
            "the port-mismatch refusal must not re-record the domain-block action"
        );
        assert!(
            serving.storage().enforcement().is_blocked(ordinal),
            "the pre-existing domain block itself is unchanged"
        );
    });
}

#[test]
/// A non-443 CONNECT on an allowlisted `<fqdn>:<port>` entry must be
/// authorized and dial the entry's own port — never the 443 default — and
/// Pair-authorization is exact `(hostname, port)`: against an unpopulated
/// cache a mismatched `:443` CONNECT is 403 (`HostNotAllowlisted`) while the
/// entry's own `{dial_port}` passes pair-authorization and reaches the
/// `NoBinding` 502. The pair-authorized slot then dials its entry port directly
/// into a deterministic in-process loopback listener, and `close_slot`
/// resets `approved_port` back to the 443 default (alumina-9t6w B2).
/// `Serving::dial` itself does not re-check `V4_EXCLUSIONS` (only the DNS
/// cache does), so the loopback dial is a legitimate seam; a hardcoded-443
/// bug would instead dial the loopback's 443 and trip the capture assertions.
fn non443_connect_dials_the_entry_port_then_resets_approved_port_on_close_slot() {
    let port = ephemeral_port();
    let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
    let dial_port = origin.local_addr().expect("origin addr").port();
    assert_ne!(
        dial_port, 443,
        "the loopback listener port must be non-443 for this regression"
    );
    let cfg_doc = format!(
        "allowlist = [\"sub.example.org:{dial_port}\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\"]\nscope = [\"connection\"]\n"
    );
    let cfg = crate::config::parse_config_document(&cfg_doc).expect("valid non-443 config");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let mut mismatch = connect(port);
        mismatch
            .write_all(b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n")
            .expect("443 head");
        pump(serving, 20);
        let mb = read_until(&mut mismatch, b"\r\n\r\n");
        assert!(
            mb.starts_with(b"HTTP/1.1 403"),
            "the :443 CONNECT must be rejected by pair-authorization, got {mb:?}"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_any_illegal(AnyIllegalCause::HostNotAllowlisted),
            1,
            "the port-mismatched CONNECT counts one HostNotAllowlisted fact"
        );

        let mut entry = connect(port);
        entry
            .write_all(format!("CONNECT sub.example.org:{dial_port} HTTP/1.1\r\n\r\n").as_bytes())
            .expect("entry head");
        pump(serving, 20);
        let eb = read_until(&mut entry, b"\r\n\r\n");
        assert!(
            eb.starts_with(b"HTTP/1.1 502 Bad Gateway"),
            "the pair-authorized CONNECT against an unpopulated cache must 502, got {eb:?}"
        );
        assert!(
            eb.windows(b"no resolved addresses".len())
                .any(|w| w == b"no resolved addresses"),
            "the 502 must be NoResolvedAddresses, not a refusal of the pair, got {eb:?}"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_any_illegal(AnyIllegalCause::HostNotAllowlisted),
            1,
            "the entry-port CONNECT passes pair-authorization and must not add a fact"
        );

        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ws = &mut serving.slots[0];
        ws.approved = Some(approved);
        ws.approved_port = dial_port;
        ws.stage = Stage::Dialing;
        serving
            .dial(
                0,
                crate::eligibility::NumericAddr::V4([127, 0, 0, 1].into()),
            )
            .expect("loopback dial");
        let _origin_stream = origin.accept().expect("accept origin side").0;
        let ws = &serving.slots[0];
        assert_eq!(
            ws.approved_port, dial_port,
            "the dial must target the entry port, not the 443 default"
        );
        assert!(
            ws.stage == Stage::Dialing,
            "the dialed slot must still hold Dialing"
        );
        serving.close_slot(0);
        let ws = &serving.slots[0];
        assert!(
            ws.stage == Stage::Idle,
            "close_slot must idle the workspace"
        );
        assert_eq!(
            ws.approved_port, 443,
            "close_slot must reset approved_port to the 443 default"
        );
        assert!(
            ws.approved.is_none(),
            "close_slot must clear the approved hostname"
        );
    });
}

#[test]
fn block_domain_closes_current_flow_with_matching_ordinal() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "connection", "block", "domain");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let _trigger_client = connect(port);
        pump(serving, 20);
        let mut relay_client = connect(port);
        pump(serving, 20);
        assert_eq!(
            serving.storage().occupied(),
            2,
            "two sub.example.org flows admitted before the block"
        );

        serving.slots[0].hello_end = Some(10);
        fabric_validated_early_data(serving, Some(5));
        fabric_relay_slot(serving, 1, b"sub.example.org", b"PENDING-DOWN-00");
        assert_eq!(serving.slots[1].down_len, 15, "relay has a pending payload");

        let token = upstream_token(serving.slots[0].slot_gen, 0);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: false,
                    ..Readiness::none()
                },
            )
            .expect("early data on the trigger blocks the domain");
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        assert!(serving.storage().enforcement().is_blocked(ordinal));
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the Block Domain sweep closes the current relay flow with the matching ordinal"
        );

        relay_client
            .set_nonblocking(true)
            .expect("client nonblocking");
        let mut probe = [0u8; 32];
        match relay_client.read(&mut probe) {
            Ok(0) => {}
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::ConnectionReset => {}
            Ok(n) => panic!(
                "the current-flow relay client must receive 0 of the pending payload, got {n} bytes {:?}",
                &probe[..n]
            ),
            Err(other) => panic!("relay client read failed: {other:?}"),
        }
    });
}

#[test]
fn block_domain_does_not_touch_unrelated_current_flow() {
    let port = ephemeral_port();
    let doc = format!(
        "allowlist = [\"sub.example.org:443\", \"trusted-other.example.net:443\"]\n\
         listen = \"127.0.0.1:{port}\"\n\
         startup_unresolved_allowance = 0\n\
         resolver = [\"1.1.1.1\"]\n\
         [any_illegal]\n\
         scope = \"connection\"\n\
         [actions]\n\
         kind = [\"block\", \"block\"]\n\
         scope = [\"domain\", \"domain\"]\n"
    );
    let cfg = crate::config::parse_config_document(&doc).expect("two-name config");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let _trigger_client = connect(port);
        pump(serving, 20);
        let keep_client = connect(port);
        pump(serving, 20);
        assert_eq!(serving.storage().occupied(), 2);

        serving.slots[0].hello_end = Some(10);
        fabric_validated_early_data(serving, Some(5));
        fabric_relay_slot(serving, 1, b"trusted-other.example.net", b"KEEP-00");
        let token = upstream_token(serving.slots[0].slot_gen, 0);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: false,
                    ..Readiness::none()
                },
            )
            .expect("early data on the trigger blocks the domain");
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        assert!(serving.storage().enforcement().is_blocked(ordinal));
        assert_eq!(
            serving.storage().occupied(),
            1,
            "an unrelated current flow for a different ordinal survives the domain sweep"
        );
        let other = FixedHostname::normalize(b"trusted-other.example.net").expect("normalize");
        let other_ordinal = serving
            .storage()
            .ordinal_for(&other)
            .expect("other ordinal");
        assert!(
            !serving.storage().enforcement().is_blocked(other_ordinal),
            "Block Domain must never mark an unrelated configured domain blocked"
        );
        drop(keep_client);
        pump(serving, 5);
    });
}

#[test]
fn block_all_guard_refuses_pending_relay_write_after_latch() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "all", "flare_only", "connection");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let mut relay_client = connect(port);
        pump(serving, 20);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "relay client admitted before the latch"
        );
        let index = 0;
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let _sink_stream = sink.accept().expect("accept sink side").0;
        {
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.head_len = 4;
            ws.hello_end = Some(10);
            ws.buf_base = 0;
            ws.buf_len = 8;
            ws.fwd = 4;
            ws.buf[..8].copy_from_slice(b"UPSTRM00");
            ws.down[..16].copy_from_slice(b"DOWNSTRM00XXXXXX");
            ws.down_len = 16;
            ws.down_off = 0;
            ws.stage = Stage::Relay;
            ws.gate.on_connect_head(4);
            ws.gate.on_authorized();
            ws.gate.on_upstream_connected();
            ws.gate.on_response_ok();
        }
        serving.register_upstream(index).expect("register upstream");
        assert_eq!(
            serving.slots[index].buf_len, 8,
            "a payload is pending client->upstream before the latch"
        );
        assert_eq!(
            serving.slots[index].down_len, 16,
            "a payload is pending upstream->client before the latch"
        );

        let mut evil = connect(port);
        evil.write_all(b"CONNECT evil.example.net:443 HTTP/1.1\r\n\r\n")
            .expect("evil head");
        pump(serving, 40);
        assert!(
            serving.storage().enforcement().block_all(),
            "the AnyIllegal All latch fires"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the latch closed the relay slot and its pending payload"
        );

        let ctoken = client_token(serving.slots[index].slot_gen, index);
        serving
            .dispatch_readiness(
                ctoken,
                Readiness {
                    writable: true,
                    ..Readiness::none()
                },
            )
            .expect("stale client writable handled");
        assert_eq!(
            serving.storage().occupied(),
            0,
            "post-latch client writable refuses instead of draining the pending payload"
        );
        assert!(serving.storage().enforcement().block_all());

        relay_client
            .set_nonblocking(true)
            .expect("client nonblocking");
        let mut probe = [0u8; 32];
        match relay_client.read(&mut probe) {
            Ok(0) => {}
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::ConnectionReset => {}
            Ok(n) => panic!(
                "the relay client must receive 0 of the pending payload after Block All, got {n} bytes {:?}",
                &probe[..n]
            ),
            Err(other) => panic!("relay client read failed: {other:?}"),
        }
    });
}

#[test]
fn client_writable_latch_guard_closes_live_relay_without_draining() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "all", "flare_only", "connection");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let mut evil = connect(port);
        evil.write_all(b"CONNECT evil.example.net:443 HTTP/1.1\r\n\r\n")
            .expect("evil head");
        pump(serving, 30);
        assert!(serving.storage().enforcement().block_all());
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the synchronous sweep closed every slot before the fault is injected"
        );

        let peer = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut reader = peer.accept().expect("accept client").0;
        {
            let ws = &mut serving.slots[0];
            ws.client = Some(client);
            ws.down_off = 0;
            ws.down[..16].copy_from_slice(b"DOWNSTRM00XXXXXX");
            ws.down_len = 16;
            ws.stage = Stage::Relay;
            ws.gate.on_connect_head(4);
            ws.gate.on_authorized();
            ws.gate.on_upstream_connected();
            ws.gate.on_response_ok();
            ws.hello_end = Some(10);
        }
        assert!(
            serving.slots[0].client.is_some() && matches!(serving.slots[0].stage, Stage::Relay),
            "the fault-injected relay slot is live after the sweep"
        );

        let ctoken = client_token(serving.slots[0].slot_gen, 0);
        serving
            .dispatch_readiness(
                ctoken,
                Readiness {
                    writable: true,
                    ..Readiness::none()
                },
            )
            .expect("post-latch client writable handled through the guard");
        assert!(
            matches!(serving.slots[0].stage, Stage::Idle | Stage::Closing),
            "the latch guard must close the live slot without any I/O"
        );
        assert!(
            serving.slots[0].client.is_none(),
            "the latch guard released the fault-injected slot"
        );

        reader.set_nonblocking(true).expect("reader nonblocking");
        let mut probe = [0u8; 32];
        match reader.read(&mut probe) {
            Ok(0) => {}
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::ConnectionReset => {}
            Ok(n) => panic!(
                "the post-latch client-writable guard must not drain the pending payload, got {n} bytes"
            ),
            Err(other) => panic!("reader read failed: {other:?}"),
        }
        drop(evil);
    });
}

#[test]
fn accept_all_latch_guard_holds_with_listener_re_attached() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "all", "flare_only", "connection");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let mut evil = connect(port);
        evil.write_all(b"CONNECT evil.example.net:443 HTTP/1.1\r\n\r\n")
            .expect("evil head");
        pump(serving, 30);
        assert!(serving.storage().enforcement().block_all());
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the latch closed every admitted flow before the fault is injected"
        );

        let back_port = ephemeral_port();
        let listener = TcpListener::bind(SocketAddr::new(
            IpAddr::V4([127, 0, 0, 1].into()),
            back_port,
        ))
        .expect("re-attach bind");
        serving
            .attach_listener(listener)
            .expect("attach listener after the latch");
        let pending = connect(back_port);
        std::thread::sleep(Duration::from_millis(20));
        serving.progress.work_since_recheck = 0;
        serving
            .dispatch_readiness(
                Token(0),
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )
            .expect("post-latch listener readiness handled through the guard");
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the accept_all latch guard must hold admission even with a live listener and a pending connection"
        );
        drop(pending);
        drop(evil);
    });
}

#[test]
fn internal_missing_approval_is_unknown_closes_locally_and_unrelated_flow_survives() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "all", "flare_only", "connection");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let wire = hello_wire(b"sub.example.org", false);
        {
            let ws = &mut serving.slots[0];
            ws.buf_base = 0;
            ws.buf_len = wire.len();
            ws.buf[..wire.len()].copy_from_slice(&wire);
            ws.parse_rel = 0;
            ws.insp_rel = 0;
            ws.head_len = 0;
            ws.hello_end = None;
            ws.hello_consumed = 0;
            ws.fwd = 0;
            ws.approved = None;
            ws.stage = Stage::ValidatingHello;
            ws.gate.on_connect_head(0);
            ws.gate.on_authorized();
            ws.gate.on_upstream_connected();
            ws.gate.on_response_ok();
        }
        fabric_relay_slot(serving, 1, b"sub.example.org", b"KEEP-00");
        serving.buffer_and_validate(0, &[]);
        assert!(
            matches!(serving.slots[0].stage, Stage::Idle),
            "the internal-fault slot closes locally"
        );
        assert!(
            matches!(serving.slots[1].stage, Stage::Relay),
            "an unrelated live flow survives the internal absence"
        );
        assert!(
            !serving.storage().enforcement().block_all(),
            "missing approved evidence must never latch Block All"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_any_illegal_total(),
            0,
            "no AnyIllegal folds for absent approved evidence"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_unknown(UnknownReason::MissingParseResult),
            1,
            "the absent approved evidence folds exactly one truthful Unknown"
        );
    });
}

#[test]
fn internal_missing_complete_hello_is_unknown_and_never_latches() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "all", "flare_only", "connection");
    with_serving_stack_cfg(port, cfg, move |serving| {
        {
            let ws = &mut serving.slots[0];
            ws.approved = FixedHostname::normalize(b"sub.example.org");
            ws.stage = Stage::ValidatingHello;
            ws.gate.on_connect_head(0);
            ws.gate.on_authorized();
            ws.gate.on_upstream_connected();
            ws.gate.on_response_ok();
        }
        serving.hello_complete(0);
        assert!(
            matches!(serving.slots[0].stage, Stage::Idle),
            "the internal-fault slot closes locally"
        );
        assert!(
            !serving.storage().enforcement().block_all(),
            "missing complete-hello evidence must never latch Block All"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_any_illegal_total(),
            0,
            "no AnyIllegal folds for absent hello-result evidence"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_unknown(UnknownReason::MissingParseResult),
            1,
            "the absent hello result folds exactly one truthful Unknown"
        );
    });
}

#[test]
fn genuine_malformed_hello_still_projects_any_illegal_and_latches_scope_all() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "all", "flare_only", "connection");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let wire = hello_wire(b"evil.example.net", false);
        let mut insp = ChInspector::new();
        assert!(matches!(insp.feed(&wire), Ok(Inspect::Complete { .. })));
        let approved = FixedHostname::normalize(b"sub.example.org");
        assert_eq!(
            client_hello::validate(
                insp.hello().expect("parsed hello"),
                &approved.expect("approx")
            ),
            Err(client_hello::ChError::ServerNameMismatch),
            "the fixture must fail validation only on the SNI, not on parsing"
        );
        drive_hello(serving, &wire, "sub.example.org");
        assert!(
            serving.storage().enforcement().block_all(),
            "a genuine malformed-hello denial must still latch Block All at scope all"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_any_illegal(AnyIllegalCause::TlsProfile(
                    HelloRejectReason::ServerNameMismatch
                )),
            1,
            "the genuine denial folds as AnyIllegal by its exact hello-reject discriminant"
        );
        assert_eq!(
            serving.storage().enforcement().counters().unknown_total(),
            0,
            "no Unknown folds for a genuine malformed-client denial"
        );
    });
}

#[cfg(feature = "alloc-witness")]
fn enforcement_witness_thread(body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name("enforcement-alloc-witness".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(body)
        .expect("spawn enforcement alloc witness")
        .join()
        .expect("enforcement alloc witness thread");
}

#[cfg(all(test, feature = "alloc-witness"))]
#[test]
fn block_all_latch_closure_spends_zero_allocations() {
    enforcement_witness_thread(|| {
        let port = ephemeral_port();
        let cfg = cfg_doc1(port, "all", "flare_only", "connection");
        let mut serving = serve_on_cfg(port, &cfg);
        let mut pending = connect(port);
        pending
            .write_all(b"CONNECT sub.example.org:44")
            .expect("partial head A");
        pump(&mut serving, 20);
        assert_eq!(serving.storage().occupied(), 1, "pending seat admitted");

        let mut relay_client = connect(port);
        pump(&mut serving, 20);
        assert_eq!(serving.storage().occupied(), 2, "relay client admitted");
        fabric_relay_slot(&mut serving, 1, b"sub.example.org", b"DOWNSTRM00XXXXXX");
        assert!(
            serving.slots[1].down_len > 0,
            "the relay slot holds a pending downstream payload"
        );
        assert!(
            serving.slots[1].upstream.is_some() && serving.slots[1].client.is_some(),
            "the relay slot owns live client and upstream sockets"
        );

        let mut evil = connect(port);
        evil.write_all(b"CONNECT evil.example.net:443 HTTP/1.1\r\n\r\n")
            .expect("head B");

        let ((), counts) = crate::alloc::run_phase(crate::alloc::Phase::Serving, || {
            pump(&mut serving, 30);
            assert!(
                serving.storage().enforcement().block_all(),
                "the AnyIllegal All latch fires"
            );
            assert_eq!(
                serving.storage().occupied(),
                0,
                "Block All closes the pending seat and the live relay slot"
            );
        });
        assert!(
            counts.all_zero(),
            "the Block-All latch closure over real occupied slots must allocate/deallocate nothing: {counts:?}"
        );

        relay_client
            .set_nonblocking(true)
            .expect("client nonblocking");
        let mut probe = [0u8; 32];
        match relay_client.read(&mut probe) {
            Ok(0) => {}
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::ConnectionReset => {}
            Ok(n) => panic!(
                "the live relay client must receive 0 of the pending payload after Block All, got {n} bytes"
            ),
            Err(other) => panic!("relay client read failed: {other:?}"),
        }
        drop(evil);
        drop(relay_client);
        drop(pending);
    });
}

#[cfg(all(test, feature = "alloc-witness"))]
#[test]
fn block_domain_current_flow_close_spends_zero_allocations() {
    enforcement_witness_thread(|| {
        let port = ephemeral_port();
        let cfg = cfg_doc1(port, "connection", "block", "domain");
        let mut serving = serve_on_cfg(port, &cfg);
        let _trigger_client = connect(port);
        pump(&mut serving, 20);
        let _relay_client = connect(port);
        pump(&mut serving, 20);
        assert_eq!(
            serving.storage().occupied(),
            2,
            "two sub.example.org flows admitted before the block"
        );

        serving.slots[0].hello_end = Some(10);
        fabric_validated_early_data(&mut serving, Some(5));
        fabric_relay_slot(&mut serving, 1, b"sub.example.org", b"PENDING-DOWN-00");

        let token = upstream_token(serving.slots[0].slot_gen, 0);
        let ((), counts) = crate::alloc::run_phase(crate::alloc::Phase::Serving, || {
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        readable: true,
                        writable: false,
                        ..Readiness::none()
                    },
                )
                .expect("early data blocks the domain");
            assert_eq!(
                serving.storage().occupied(),
                0,
                "the Block Domain sweep closes the matching current flow"
            );
        });
        assert!(
            counts.all_zero(),
            "the Block-Domain current-flow closure must allocate/deallocate nothing: {counts:?}"
        );
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        assert!(serving.storage().enforcement().is_blocked(ordinal));
    });
}

#[cfg(all(test, feature = "alloc-witness"))]
#[test]
fn early_data_projection_spends_zero_allocations() {
    enforcement_witness_thread(|| {
        let port = ephemeral_port();
        let cfg = cfg_doc1(port, "connection", "block", "domain");
        let mut serving = serve_on_cfg(port, &cfg);
        let _client = connect(port);
        pump(&mut serving, 20);
        assert_eq!(serving.storage().occupied(), 1, "boot traffic admitted");
        serving.slots[0].hello_end = Some(10);
        fabric_validated_early_data(&mut serving, Some(5));
        let token = upstream_token(serving.slots[0].slot_gen, 0);

        let ((), counts) = crate::alloc::run_phase(crate::alloc::Phase::Serving, || {
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        readable: true,
                        writable: false,
                        ..Readiness::none()
                    },
                )
                .expect("early origin data projects");
            assert_eq!(
                serving.storage().occupied(),
                0,
                "early upstream data terminates setup"
            );
            let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
            let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
            assert!(
                serving.storage().enforcement().is_blocked(ordinal),
                "validated early data marks the ordinal blocked"
            );
            assert_eq!(
                serving
                    .storage()
                    .enforcement()
                    .counters()
                    .actions_domain_block(ordinal),
                1
            );
        });
        assert!(
            counts.all_zero(),
            "the early-data projection and close must allocate/deallocate nothing: {counts:?}"
        );
    });
}

#[cfg(all(test, feature = "alloc-witness"))]
#[test]
fn block_all_storm_sweeps_128_slots_alloc_free() {
    enforcement_witness_thread(|| {
        let port = ephemeral_port();
        let cfg = cfg_doc1(port, "all", "flare_only", "connection");
        let mut serving = serve_on_cfg(port, &cfg);
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        for ws in serving.slots.iter_mut() {
            ws.approved = Some(approved);
            ws.stage = Stage::Dialing;
        }
        let ((), counts) = crate::alloc::run_phase(crate::alloc::Phase::Serving, || {
            let effect = serving.any_illegal(0, AnyIllegalCause::HostNotAllowlisted);
            assert!(
                matches!(effect, Effect::Block { scope: Scope::All }),
                "the storm trigger latches Block All"
            );
            assert!(
                serving
                    .slots
                    .iter()
                    .all(|s| s.stage == Stage::Idle || s.stage == Stage::Closing),
                "the Block-All sweep must recycle every one of the 128 occupied workspaces"
            );
        });
        assert!(
            counts.all_zero(),
            "the 128-slot Block-All storm sweep must allocate/deallocate nothing: {counts:?}"
        );
    });
}

#[test]
fn monitor_split_on_full_stack_distinguishes_block_action_from_later_refusal() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "connection", "block", "domain");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        serving.storage_mut().publish_test_a(ordinal.get());
        let _acceptor = connect(port);
        pump(serving, 20);
        assert_eq!(serving.storage().occupied(), 1, "pre-block peer admitted");
        serving.slots[0].hello_end = Some(10);
        fabric_validated_early_data(serving, Some(5));
        let token = upstream_token(serving.slots[0].slot_gen, 0);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: false,
                    ..Readiness::none()
                },
            )
            .expect("early data blocks the domain");
        assert!(serving.storage().enforcement().is_blocked(ordinal));
        {
            let m = serving.storage().enforcement().monitor();
            assert_eq!(m.facts_early_data(ordinal), 1, "one early-data fact");
            assert_eq!(
                m.actions_domain_block(ordinal),
                1,
                "the Block-Domain action is its own channel"
            );
            assert_eq!(
                m.refusals_blocked_domain(ordinal),
                0,
                "the action itself is never also a refusal"
            );
        }

        let mut future = connect(port);
        future
            .write_all(b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n")
            .expect("future head");
        pump(serving, 20);
        let fb = read_until(&mut future, b"\r\n\r\n");
        assert!(
            fb.starts_with(b"HTTP/1.1 403"),
            "a future flow for the blocked ordinal must be refused before any dial, got {fb:?}"
        );
        let m = serving.storage().enforcement().monitor();
        assert_eq!(m.actions_domain_block(ordinal), 1, "no re-applied action");
        assert_eq!(m.refusals_blocked_domain(ordinal), 1, "one later refusal");
        assert_eq!(
            m.refusals_total(),
            1,
            "the later refusal folds its own truthfully separated total"
        );
    });
}

#[test]
fn slot_capture_is_cleared_before_reuse_never_attributes_a_stale_generation() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "connection", "block", "domain");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        serving.storage_mut().publish_test_a(ordinal.get());

        let _first = connect(port);
        pump(serving, 20);
        assert_eq!(serving.storage().occupied(), 1, "pre-block peer admitted");
        assert!(
            serving.slots[0].capture.detail.is_none(),
            "a fresh slot carries no fact (generation {}), only the admit stamp",
            serving.slots[0].capture.generation
        );
        assert!(
            serving.slots[0].capture.generation != 0,
            "the admit stamps the slot's own new generation"
        );
        serving.slots[0].hello_end = Some(10);
        fabric_validated_early_data(serving, Some(5));
        let token = upstream_token(serving.slots[0].slot_gen, 0);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: false,
                    ..Readiness::none()
                },
            )
            .expect("early data blocks the domain");
        assert!(
            serving.storage().enforcement().is_blocked(ordinal),
            "cleared capture from reset must not prevent the block"
        );

        serving.close_slot(0);
        let _second = connect(port);
        pump(serving, 20);
        assert!(
            serving.slots[0].capture.detail.is_none(),
            "a reused slot starts with no stale generation's fact"
        );
        assert_eq!(
            serving.slots[0].capture.generation, serving.slots[0].slot_gen,
            "the reused slot's capture is correlated to its own new generation"
        );
    });
}

#[test]
fn production_detection_close_transfers_typed_capture_with_slot_identity_into_monitor() {
    let port = ephemeral_port();
    let cfg = cfg_doc1(port, "connection", "block", "domain");
    with_serving_stack_cfg(port, cfg, move |serving| {
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        serving.storage_mut().publish_test_a(ordinal.get());

        let _first = connect(port);
        pump(serving, 20);
        assert_eq!(serving.storage().occupied(), 1, "first peer admitted");
        let _second = connect(port);
        pump(serving, 20);
        assert_eq!(
            serving.storage().occupied(),
            2,
            "a second peer occupies a non-zero slot so the identity pin discriminates"
        );
        assert!(
            serving.slots[1].handle.is_some(),
            "slots assign lowest-free first, so the second peer holds slot 1"
        );

        serving.slots[1].hello_end = Some(10);
        fabric_validated_early_data_at(serving, 1, Some(5));
        let token = upstream_token(serving.slots[1].slot_gen, 1);
        serving
            .dispatch_readiness(
                token,
                Readiness {
                    readable: true,
                    writable: false,
                    ..Readiness::none()
                },
            )
            .expect("early data blocks the domain");
        assert!(
            serving.storage().enforcement().is_blocked(ordinal),
            "the production detection latched the ordinal"
        );
        let m = serving.storage().enforcement().monitor();
        assert_eq!(
            m.capture_detail_len(),
            1,
            "M3': close_slot consumed the non-zero stamped capture into the monitor (removal-sensitive)"
        );
        let cap = m.capture_detail(0).expect("correlated capture");
        assert_eq!(
            cap.slot, 1,
            "H1' pin: the capture carries the actual detection slot index 1, never ring position 0 or a hardcoded slot 0"
        );
        assert_eq!(
            cap.generation, serving.slots[1].slot_gen,
            "H1': the capture carries the per-slot generation at detection"
        );
        let detail = cap.detail;
        assert_eq!(
            detail.fact,
            CapturedFact::EarlyData(ordinal),
            "H1': the typed detection fact travels through detection -> close -> monitor"
        );
        assert_eq!(
            detail.effect,
            Effect::Block {
                scope: Scope::Domain
            },
            "H1': the applied effect travels through detection -> close -> monitor"
        );
    });
}

fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("read timeout");
    let mut out = Vec::new();
    let mut buf = [0u8; 128];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    out
}

fn drain_prefix(stream: &mut TcpStream, want: usize) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("read timeout");
    let mut got = Vec::new();
    let mut buf = [0u8; 512];
    while got.len() < want {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    got
}

/// Blocks until `stream` (a proxy-side socket) has at least one byte buffered,
/// so a synthetic readiness dispatch never races loopback delivery.
fn wait_readable(stream: &mio::net::TcpStream, label: &str) {
    let mut probe = [0u8; 1];
    for _ in 0..10_000 {
        if matches!(stream.peek(&mut probe), Ok(n) if n > 0) {
            return;
        }
        std::thread::yield_now();
    }
    panic!("{label} never became readable on the proxy side");
}

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

#[test]
/// A per-token dispatch would split slot 0's client and upstream arms across
/// two visits and false-`!live_here` reschedule the upstream arm until a
/// re-poll re-delivers it; the coalescer must keep both arms in one visit.
#[expect(clippy::too_many_lines, reason = "long two-pass coalescing assertion")]
fn two_pass_coalescing_dispatches_interleaved_pair_arms_contiguously() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink0 = StdListener::bind("127.0.0.1:0").expect("sink0 bind");
        let up0 = mio::net::TcpStream::connect(sink0.local_addr().expect("sink0 addr"))
            .expect("up0 connect");
        let mut sink0_stream = sink0.accept().expect("accept sink0").0;
        let sink1 = StdListener::bind("127.0.0.1:0").expect("sink1 bind");
        let up1 = mio::net::TcpStream::connect(sink1.local_addr().expect("sink1 addr"))
            .expect("up1 connect");
        let mut sink1_stream = sink1.accept().expect("accept sink1").0;

        let mut client0 = connect(port);
        let mut client1 = connect(port);
        pump(serving, 30);
        assert_eq!(
            serving.storage().occupied(),
            2,
            "both relay clients must be admitted"
        );

        serving.slots[0].upstream = Some(up0);
        open_relay(serving, 0);
        serving.slots[1].upstream = Some(up1);
        open_relay(serving, 1);

        client0.write_all(b"AB").expect("client0 queue");
        client1.write_all(b"CD").expect("client1 queue");
        sink0_stream.write_all(b"XY").expect("sink0 queue");
        sink1_stream.write_all(b"UV").expect("sink1 queue");
        wait_readable(
            serving.slots[0].client.as_ref().expect("client0 socket"),
            "proxy client0",
        );
        wait_readable(
            serving.slots[1].client.as_ref().expect("client1 socket"),
            "proxy client1",
        );
        wait_readable(
            serving.slots[0].upstream.as_ref().expect("up0 socket"),
            "proxy up0",
        );
        wait_readable(
            serving.slots[1].upstream.as_ref().expect("up1 socket"),
            "proxy up1",
        );

        let visits_before_0 = serving.slots[0].visits;
        let visits_before_1 = serving.slots[1].visits;
        serving.batch_gen = serving.batch_gen.wrapping_add(1);
        serving.in_batch = true;
        let g0 = serving.slots[0].slot_gen;
        let g1 = serving.slots[1].slot_gen;
        let tokens = [
            (
                client_token(g0, 0),
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            ),
            (
                client_token(g1, 1),
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            ),
            (
                upstream_token(g0, 0),
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            ),
            (
                upstream_token(g1, 1),
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            ),
        ];
        serving
            .dispatch_coalesced_batch(&tokens)
            .expect("coalesced batch");

        assert_eq!(
            drain_prefix(&mut sink0_stream, 2),
            b"AB".to_vec(),
            "slot 0 client->upstream made it in the single coalesced batch"
        );
        assert_eq!(
            drain_prefix(&mut sink1_stream, 2),
            b"CD".to_vec(),
            "slot 1 client->upstream made it in the single coalesced batch"
        );
        assert_eq!(
            drain_prefix(&mut client0, 2),
            b"XY".to_vec(),
            "slot 0 upstream->client arm was not false-rescheduled by the interleave"
        );
        assert_eq!(
            drain_prefix(&mut client1, 2),
            b"UV".to_vec(),
            "slot 1 upstream->client arm was not false-rescheduled by the interleave"
        );
        assert_eq!(
            serving.slots[0].visits - visits_before_0,
            1,
            "each slot's client+upstream arms folded into one contiguous visit"
        );
        assert_eq!(
            serving.slots[1].visits - visits_before_1,
            1,
            "each slot's client+upstream arms folded into one contiguous visit"
        );
        assert!(
            !serving.in_batch,
            "the coalesced batch must close its batch state"
        );
    });
}

#[test]
/// A payload far larger than the legacy 4 KiB chunk must land from one coarse
/// read into the slab and pair-flush in the same visit, never stalling on a
/// leftover that needs a re-poll.
fn coarse_relay_read_moves_large_payload_in_one_visit_keeping_flush_balance() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let up = mio::net::TcpStream::connect(sink.local_addr().expect("sink addr"))
            .expect("up connect");
        let mut sink_stream = sink.accept().expect("accept sink").0;

        let mut client = connect(port);
        pump(serving, 30);
        assert_eq!(serving.storage().occupied(), 1, "relay client admitted");
        serving.slots[0].upstream = Some(up);
        open_relay(serving, 0);

        let payload = vec![0x5a_u8; 20 * 1024];
        client.write_all(&payload).expect("client payload");
        wait_readable(
            serving.slots[0].client.as_ref().expect("proxy client"),
            "coarse proxy client",
        );

        serving.batch_gen = serving.batch_gen.wrapping_add(1);
        serving.in_batch = true;
        let token = client_token(serving.slots[0].slot_gen, 0);
        serving
            .dispatch_coalesced_batch(&[(
                token,
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            )])
            .expect("coarse client read");

        let mut got = drain_prefix(&mut sink_stream, payload.len());
        while got.len() < payload.len() {
            let more = drain_prefix(&mut sink_stream, payload.len() - got.len());
            if more.is_empty() {
                break;
            }
            got.extend_from_slice(&more);
        }
        assert_eq!(
            got.len(),
            payload.len(),
            "a coarse relay read must relay the whole oversized payload without a re-poll"
        );
        assert_eq!(
            got, payload,
            "the coarse-relayed payload must be byte exact"
        );
        assert!(
            matches!(serving.slots[0].stage, Stage::Relay),
            "the relay must stay open after the coarse read"
        );
        let ws = &serving.slots[0];
        assert_eq!(
            ws.fwd, ws.buf_len,
            "no accepted bytes may be left pending after the pair-flush"
        );
    });
}

#[test]
/// A single-slot `[client, upstream]` batch must dispatch the client arm
/// first (`client_first`), never the upstream arm: both directions shared one
/// `coalesced.seen` order value in the old code, so the upstream of a
/// client-first pair was wrongly ordered ahead and consumed the visit before
/// the client arm could refuse its head.
fn single_slot_client_first_batch_dispatches_client_arm_before_upstream() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut client = connect(port);
        pump(serving, 30);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the client must be admitted before the synthetic batch"
        );
        client
            .write_all(b"CONNECT nope.example.net:443 HTTP/1.1\r\n\r\n")
            .expect("forbidden head queued");
        wait_readable(
            serving.slots[0].client.as_ref().expect("proxy client"),
            "h1 proxy client",
        );

        let visits_before = serving.slots[0].visits;
        serving.batch_gen = serving.batch_gen.wrapping_add(1);
        serving.in_batch = true;
        let g0 = serving.slots[0].slot_gen;
        let tokens = [
            (
                client_token(g0, 0),
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            ),
            (
                upstream_token(g0, 0),
                Readiness {
                    error: true,
                    ..Readiness::none()
                },
            ),
        ];
        serving
            .dispatch_coalesced_batch(&tokens)
            .expect("single-slot client-first batch");

        assert_eq!(
            read_all(&mut client),
            b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n".to_vec(),
            "the client arm must dispatch first and refuse the head; if the \
             upstream error arm closed the slot first, the 403 never arrives"
        );
        assert!(
            matches!(serving.slots[0].stage, Stage::Idle),
            "the first arm's refusal close must leave the slot idle"
        );
        assert_eq!(
            serving.slots[0].visits - visits_before,
            1,
            "only the client arm may open a visit; the suppressed upstream arm adds none"
        );
        assert!(
            !serving.in_batch,
            "the coalesced batch must close its batch state"
        );
    });
}

#[test]
/// When a single-slot `[upstream, client]` batch's first (upstream) arm closes
/// the slot, the coalescer must suppress the remaining client arm instead of
/// dispatching it onto the closed slot: no visit may open and no 403 may be
/// emitted for a head that died with the closed connection.
fn coalesced_batch_suppresses_second_arm_after_first_arm_closes_slot() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let _client = connect(port);
        pump(serving, 30);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the client must be admitted before the synthetic batch"
        );

        let visits_before = serving.slots[0].visits;
        let gen_before = serving.slots[0].slot_gen;
        serving.batch_gen = serving.batch_gen.wrapping_add(1);
        serving.in_batch = true;
        let g0 = serving.slots[0].slot_gen;
        let tokens = [
            (
                upstream_token(g0, 0),
                Readiness {
                    error: true,
                    ..Readiness::none()
                },
            ),
            (
                client_token(g0, 0),
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            ),
        ];
        serving
            .dispatch_coalesced_batch(&tokens)
            .expect("single-slot upstream-first batch");

        assert!(
            serving.slots[0].client.is_none(),
            "the first arm's error close must drop the client handle"
        );
        assert!(
            matches!(serving.slots[0].stage, Stage::Idle),
            "the first arm's error close must leave the slot idle"
        );
        assert_eq!(
            serving.slots[0].slot_gen, gen_before,
            "the suppressed client arm must not touch the slot generation"
        );
        assert_eq!(
            serving.slots[0].visits - visits_before,
            0,
            "the error first arm closes before opening a visit and the second \
             arm must not open one either"
        );
        assert!(
            !serving.in_batch,
            "the coalesced batch must close its batch state"
        );
        assert_eq!(serving.storage().occupied(), 0, "the slot stays released");
    });
}

#[test]
/// Tokens folded for a slot carry the slot's generation at fold time, and the
/// Pass 2 guard also refuses to dispatch onto `Stage::Idle` state; a stale
/// token for an already-closed slot (the review's LISTENER-reuse generation
/// case, reachable here as a closed slot at its old generation) must be dropped
/// without folding, dispatching, or opening a visit.
fn coalesced_batch_ignores_stale_tokens_for_closed_slot() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let _client = connect(port);
        pump(serving, 30);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the client must be admitted before the batch"
        );
        let gen_before = serving.slots[0].slot_gen;

        let visits_before = serving.slots[0].visits;
        serving.batch_gen = serving.batch_gen.wrapping_add(1);
        serving.in_batch = true;
        let g0 = serving.slots[0].slot_gen;
        let tokens = [(
            upstream_token(g0, 0),
            Readiness {
                error: true,
                ..Readiness::none()
            },
        )];
        serving
            .dispatch_coalesced_batch(&tokens)
            .expect("error close batch");
        assert!(
            matches!(serving.slots[0].stage, Stage::Idle),
            "the error token must close the admitted slot"
        );
        assert_eq!(
            serving.slots[0].visits - visits_before,
            0,
            "an error close opens no visit"
        );

        let visits_before = serving.slots[0].visits;
        serving.batch_gen = serving.batch_gen.wrapping_add(1);
        serving.in_batch = true;
        let stale = [
            (
                client_token(gen_before, 0),
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            ),
            (
                upstream_token(gen_before, 0),
                Readiness {
                    readable: true,
                    ..Readiness::none()
                },
            ),
        ];
        serving
            .dispatch_coalesced_batch(&stale)
            .expect("stale token batch");
        assert!(
            matches!(serving.slots[0].stage, Stage::Idle),
            "a stale token for a closed slot must never re-arm it"
        );
        assert_eq!(
            serving.slots[0].visits - visits_before,
            0,
            "stale tokens for a closed slot must fold to nothing and open no visit"
        );
        assert!(
            !serving.in_batch,
            "the coalesced batch must close its batch state"
        );
        assert_eq!(serving.storage().occupied(), 0, "the slot stays released");
    });
}

#[test]
/// The arrival-order chain folded by Pass 1 (`fold`) and popped by Pass 2
/// (`next`) must dispatch slots in exact first-arrival order regardless of
/// slot index, each seen slot exactly once, then stay exhausted: the chain
/// walk replaces the former per-dispatch O(`MAX_TUNNELS`) min-scan with
/// identical selection semantics (C1 arrival-order index).
fn coalesced_batch_chain_dispatches_in_first_arrival_order_ignoring_slot_index() {
    let mut batch = CoalescedBatch::new();
    let ready = Readiness {
        readable: true,
        ..Readiness::none()
    };
    assert_eq!(batch.next(), None, "a fresh batch has nobody to dispatch");
    for index in [71usize, 3, 58, 71, 200, 3] {
        batch.fold(index, 7, true, ready);
    }
    for (i, expected) in [71usize, 3, 58, 200].into_iter().enumerate() {
        assert_eq!(
            batch.next(),
            Some(expected),
            "dispatch order {i} must be first-arrival, not slot-index"
        );
    }
    assert_eq!(
        batch.next(),
        None,
        "every seen slot dispatches exactly once, then the chain is exhausted"
    );
    assert_eq!(batch.next(), None, "the chain stays exhausted");
}

#[test]
/// A freshly folded slot is unseen, a folded slot is seen, and the pop that
/// dispatches it returns it to the unseen state; a fresh batch carries no
/// chain links or folded readiness across batches (UNSEEN/seen invariant).
fn coalesced_batch_pop_marks_slot_unseen_and_fresh_batch_is_clean() {
    let mut batch = CoalescedBatch::new();
    let ready = Readiness {
        readable: true,
        ..Readiness::none()
    };
    assert!(
        batch.slots.iter().all(|slot| !slot.seen()),
        "a fresh batch must fold no slot"
    );
    batch.fold(0, 1, false, ready);
    batch.fold(1, 1, false, ready);
    assert!(
        batch.slots[0].seen() && batch.slots[1].seen(),
        "a folded slot must be seen for the rest of its batch"
    );
    batch.next().expect("slot 0 pops first");
    assert!(
        !batch.slots[0].seen(),
        "a dispatched slot returns to the unseen state"
    );
    batch.next().expect("slot 1 pops second");
    assert!(
        !batch.slots[1].seen(),
        "the second dispatched slot is unseen again"
    );
    assert_eq!(batch.next(), None, "the batch is fully consumed");

    let mut fresh = CoalescedBatch::new();
    assert_eq!(
        fresh.next(),
        None,
        "a fresh batch starts with an empty, clean chain"
    );
    assert!(
        fresh.slots.iter().all(|slot| !slot.seen()),
        "no folded readiness leaks into a fresh batch"
    );
}

#[test]
/// An allowlisted CONNECT against an unpopulated DNS cache must flow through
/// the real `run_once`/`run_decision` path to a 502 refusal pinned to the
/// exact no-resolved-addresses wire body, and release the admitted slot.
fn allowlisted_unresolved_connect_refusal_is_wire_pinned_through_run_once() {
    let port = ephemeral_port();
    with_serving_stack(port, move |serving| {
        let mut client = connect(port);
        client
            .write_all(b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n")
            .expect("allowlisted connect head queued");
        pump(serving, 60);
        let body = read_all(&mut client);
        assert_eq!(
            &body[..],
            b"HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 22\r\n\r\nno resolved addresses\n",
            "allowlisted-but-unresolved CONNECT must refuse with the pinned 502 body"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the refused slot must be released back to the pool"
        );
    });
}

/// A test config allowlisting `sub.example.org:<upstream_port>` behind a
/// 127.0.0.1 entry listener, for retry/deadline tests that must target a
/// controllable (possibly closed) upstream port.
fn config_pair(port: u16, upstream_port: u16) -> crate::config::Config {
    let doc = format!(
        "allowlist = [\"sub.example.org:{upstream_port}\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\"]\nscope = [\"connection\"]\n"
    );
    crate::config::parse_config_document(&doc).expect("valid retry test config")
}

#[test]
/// The FIRST failed dial must be recorded back into the slot ledger and the
/// decision re-run against the advanced cursor, exactly once per failed
/// establishment: with a single A binding the re-decision resolves 502
/// "no resolved addresses", the body that proves a retry occurred rather than
/// the single-attempt "upstream connection failed".
fn first_dial_failure_records_and_re_decides_to_no_binding_502() {
    use crate::cache::Family;
    use crate::connect::Feed;
    use crate::eligibility::NumericAddr;
    use std::net::Ipv4Addr;
    let port = ephemeral_port();
    let upstream_port = ephemeral_port();
    let cfg = config_pair(port, upstream_port);
    with_serving_stack_cfg(port, cfg, move |serving| {
        let mut client = connect(port);
        pump(serving, 10);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );
        let head = format!("CONNECT sub.example.org:{upstream_port} HTTP/1.1\r\n\r\n");
        match serving.slots[0]
            .parser
            .feed(head.as_bytes())
            .expect("head feed")
        {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        serving.slots[0].approved = FixedHostname::normalize(b"sub.example.org");
        serving.slots[0].approved_port = upstream_port;
        serving.slots[0].gate.on_authorized();
        serving.slots[0].stage = Stage::Dialing;
        serving.slots[0].connect_family = Some(Family::A);
        serving
            .dial(0, NumericAddr::V4(Ipv4Addr::from([127, 0, 0, 1])))
            .expect("dial");
        pump(serving, 10);
        let body = read_all(&mut client);
        assert!(
            body.starts_with(b"HTTP/1.1 502 Bad Gateway"),
            "the consumed single attempt must refuse a pre-200 502, got {body:?}"
        );
        assert!(
            body.windows(b"no resolved addresses".len())
                .any(|w| w == b"no resolved addresses"),
            "the retry must re-decide to NoBinding, not repeat the single-attempt DialFailed, got {body:?}"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the refused slot must be released back to the pool"
        );
    });
}

#[test]
/// The complete retry loop over four real dials, end to end, against live
/// loopback listeners on `upstream_port` (the upstream-facing machine). Each
/// round real-dials the listener for the round's family, and the test accepts
/// that origin side immediately — bounded and nonblocking — to prove the dial
/// genuinely reached the network; a failed establishment is then recorded into
/// the slot ledger exactly where the retry seam would do so. Families alternate
/// A, Aaaa, A, Aaaa across the budget as the worker's selection flips; the
/// budget-exhausted seam then resolves to the fixed "upstream connection
/// failed" 502 refusal and releases the seat. The family per round is chosen by
/// the harness because destination eligibility (alumina-skhc) excludes loopback
/// from cache selection, so a hermetic served seam cannot select these
/// addresses itself.
#[expect(
    clippy::too_many_lines,
    reason = "long retry-loop exhaustion assertion over four dials"
)]
fn full_family_alternation_retry_loop_exhausts_at_four_real_dials() {
    use crate::cache::Family;
    use crate::connect::Feed;
    use crate::eligibility::NumericAddr;
    use std::net::{Ipv4Addr, Ipv6Addr};
    let port = ephemeral_port();
    let upstream_port = ephemeral_port();
    let v4 = StdListener::bind(SocketAddr::new(
        IpAddr::V4([127, 0, 0, 1].into()),
        upstream_port,
    ))
    .expect("live v4 listener");
    v4.set_nonblocking(true).expect("v4 nonblocking");
    let v6 = StdListener::bind(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        upstream_port,
    ))
    .expect("live v6 listener");
    v6.set_nonblocking(true).expect("v6 nonblocking");
    let cfg = config_pair(port, upstream_port);
    with_serving_stack_cfg(port, cfg, move |serving| {
        let mut client = connect(port);
        pump(serving, 10);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );
        let head = format!("CONNECT sub.example.org:{upstream_port} HTTP/1.1\r\n\r\n");
        match serving.slots[0]
            .parser
            .feed(head.as_bytes())
            .expect("head feed")
        {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        serving.slots[0].approved = FixedHostname::normalize(b"sub.example.org");
        serving.slots[0].approved_port = upstream_port;
        serving.slots[0].gate.on_authorized();
        serving.slots[0].stage = Stage::Dialing;
        let handle = serving.slots[0]
            .handle
            .take()
            .expect("admitted slot handle");
        let plan = [
            (
                Family::A,
                NumericAddr::V4(Ipv4Addr::from([127, 0, 0, 1])),
                &v4,
            ),
            (Family::Aaaa, NumericAddr::V6(Ipv6Addr::LOCALHOST), &v6),
            (
                Family::A,
                NumericAddr::V4(Ipv4Addr::from([127, 0, 0, 1])),
                &v4,
            ),
            (Family::Aaaa, NumericAddr::V6(Ipv6Addr::LOCALHOST), &v6),
        ];
        let mut seen = Vec::new();
        for (family, addr, listener) in plan {
            serving
                .dial(0, addr)
                .expect("the dial must initiate toward the live listener");
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match listener.accept() {
                    Ok((origin, _)) => {
                        drop(origin);
                        break;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "the real dial must reach this origin within the window"
                        );
                        std::thread::yield_now();
                    }
                    Err(e) => panic!("accepting the real dial: {e:?}"),
                }
            }
            seen.push(
                serving.slots[0]
                    .connect_family
                    .expect("a live dial must carry its family"),
            );
            serving
                .storage_mut()
                .record_attempt(&handle, family)
                .expect("record the failed establishment into the slot ledger");
        }
        serving.slots[0].handle = Some(handle);
        serving
            .fail_current_attempt(0)
            .expect("the exhausted budget resolves to the refusal");
        pump(serving, 10);
        let body = read_all(&mut client);
        assert!(
            body.starts_with(b"HTTP/1.1 502 Bad Gateway"),
            "the exhausted budget must refuse a pre-200 502, got {body:?}"
        );
        assert!(
            body.windows(b"upstream connection failed".len())
                .any(|w| w == b"upstream connection failed"),
            "the budget-exhausted refusal must pin the DialFailed body, got {body:?}"
        );
        assert_eq!(
            seen,
            vec![Family::A, Family::Aaaa, Family::A, Family::Aaaa],
            "the four real dials must alternate A then the other family across the budget"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the exhausted slot must be released back to the pool"
        );
    });
}

#[cfg(all(test, feature = "alloc-witness"))]
#[test]
/// The complete retry seam — real dial → record of the failed establishment →
/// re-attempt across the four real dials of the family-alternation budget,
/// ending in the `CandidatesExhausted` refusal and the seat release — must
/// complete inside the `Phase::Serving` witness with zero post-boot heap
/// allocation. Families are chosen per round by the harness because
/// destination eligibility (alumina-skhc) excludes loopback from cache
/// selection, so a hermetic served seam cannot select these addresses itself.
#[expect(
    clippy::too_many_lines,
    reason = "long alloc-witness retry seam assertion"
)]
fn full_retry_seam_records_redecides_and_redials_with_zero_allocations() {
    enforcement_witness_thread(|| {
        use crate::cache::Family;
        use crate::connect::Feed;
        use crate::eligibility::NumericAddr;
        use std::net::{Ipv4Addr, Ipv6Addr};
        let port = ephemeral_port();
        let upstream_port = ephemeral_port();
        let v4 = StdListener::bind(SocketAddr::new(
            IpAddr::V4([127, 0, 0, 1].into()),
            upstream_port,
        ))
        .expect("live v4 listener");
        v4.set_nonblocking(true).expect("v4 nonblocking");
        let v6 = StdListener::bind(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            upstream_port,
        ))
        .expect("live v6 listener");
        v6.set_nonblocking(true).expect("v6 nonblocking");
        let cfg = config_pair(port, upstream_port);
        let mut serving = serve_on_cfg(port, &cfg);
        let mut client = connect(port);
        pump(&mut serving, 10);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );
        let head = format!("CONNECT sub.example.org:{upstream_port} HTTP/1.1\r\n\r\n");
        match serving.slots[0]
            .parser
            .feed(head.as_bytes())
            .expect("head feed")
        {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        serving.slots[0].approved = FixedHostname::normalize(b"sub.example.org");
        serving.slots[0].approved_port = upstream_port;
        serving.slots[0].gate.on_authorized();
        serving.slots[0].stage = Stage::Dialing;
        let handle = serving.slots[0]
            .handle
            .take()
            .expect("admitted slot handle");
        let plan = [
            (
                Family::A,
                NumericAddr::V4(Ipv4Addr::from([127, 0, 0, 1])),
                &v4,
            ),
            (Family::Aaaa, NumericAddr::V6(Ipv6Addr::LOCALHOST), &v6),
            (
                Family::A,
                NumericAddr::V4(Ipv4Addr::from([127, 0, 0, 1])),
                &v4,
            ),
            (Family::Aaaa, NumericAddr::V6(Ipv6Addr::LOCALHOST), &v6),
        ];
        let mut seen = [None; crate::worker::MAX_UPSTREAM_ATTEMPTS];
        let ((), counts) = crate::alloc::run_phase(crate::alloc::Phase::Serving, || {
            for (round, (family, addr, listener)) in plan.into_iter().enumerate() {
                serving
                    .dial(0, addr)
                    .expect("the dial must initiate toward the live listener");
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    match listener.accept() {
                        Ok((origin, _)) => {
                            drop(origin);
                            break;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "the real dial must reach this origin within the window"
                            );
                            std::thread::yield_now();
                        }
                        Err(e) => panic!("accepting the real dial: {e:?}"),
                    }
                }
                seen[round] = serving.slots[0].connect_family;
                serving
                    .storage_mut()
                    .record_attempt(&handle, family)
                    .expect("record the failed establishment into the slot ledger");
            }
            serving.slots[0].handle = Some(handle);
            serving
                .fail_current_attempt(0)
                .expect("the exhausted budget resolves to the refusal");
            pump(&mut serving, 10);
        });
        assert!(
            counts.all_zero(),
            "the full retry seam must allocate/deallocate nothing: {counts:?}"
        );
        assert_eq!(
            seen,
            [
                Some(Family::A),
                Some(Family::Aaaa),
                Some(Family::A),
                Some(Family::Aaaa),
            ],
            "the four real dials must alternate A then the other family across the budget"
        );
        let body = read_all(&mut client);
        assert!(
            body.starts_with(b"HTTP/1.1 502 Bad Gateway"),
            "the budget-exhausted seam must refuse a pre-200 502, got {body:?}"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the exhausted slot must be released back to the pool"
        );
    });
}

#[test]
/// A closed upstream port for all four A bindings consumes the full slot
/// attempt budget through the real run loop and pins the "upstream connection
/// failed" wire body once `CandidatesExhausted` resolves.
fn closed_dial_exhausts_the_full_attempt_budget_to_502_upstream_failed() {
    use crate::cache::Family;
    use crate::connect::Feed;
    use crate::eligibility::NumericAddr;
    use std::net::Ipv4Addr;
    let port = ephemeral_port();
    let upstream_port = ephemeral_port();
    let cfg = config_pair(port, upstream_port);
    with_serving_stack_cfg(port, cfg, move |serving| {
        let mut client = connect(port);
        pump(serving, 10);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );
        let head = format!("CONNECT sub.example.org:{upstream_port} HTTP/1.1\r\n\r\n");
        match serving.slots[0]
            .parser
            .feed(head.as_bytes())
            .expect("head feed")
        {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        serving.slots[0].approved = FixedHostname::normalize(b"sub.example.org");
        serving.slots[0].approved_port = upstream_port;
        serving.slots[0].gate.on_authorized();
        serving.slots[0].stage = Stage::Dialing;
        serving.slots[0].connect_family = Some(Family::A);
        let handle = serving.slots[0].handle.take().expect("admitted handle");
        for _ in 0..3 {
            serving
                .storage_mut()
                .record_attempt(&handle, Family::A)
                .expect("record earlier A attempt");
        }
        serving.slots[0].handle = Some(handle);
        serving
            .dial(0, NumericAddr::V4(Ipv4Addr::from([127, 0, 0, 1])))
            .expect("dial");
        pump(serving, 10);
        let body = read_all(&mut client);
        assert!(
            body.starts_with(b"HTTP/1.1 502 Bad Gateway"),
            "the exhausted budget must refuse a pre-200 502, got {body:?}"
        );
        assert!(
            body.windows(b"upstream connection failed".len())
                .any(|w| w == b"upstream connection failed"),
            "the budget-exhausted refusal must pin the DialFailed body, got {body:?}"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the refused slot must be released back to the pool"
        );
    });
}

#[test]
/// A successful dial re-anchors a fresh clipped per-attempt connect deadline
/// at initiation (I26): after `run_decision` dials a live origin the workspace
/// holds the dialing family and a deadline freshly clipped from the setup
/// deadline, never a carried-over expired one.
fn dial_re_anchors_a_fresh_connect_deadline_at_initiation() {
    use crate::cache::Family;
    use crate::eligibility::NumericAddr;
    use std::net::Ipv4Addr;
    let port = ephemeral_port();
    let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
    let origin_port = origin.local_addr().expect("origin addr").port();
    let cfg = config_pair(port, origin_port);
    with_serving_stack_cfg(port, cfg, move |serving| {
        let mut client = connect(port);
        pump(serving, 10);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted and dialing"
        );
        let handle = serving.slots[0].handle.as_ref().expect("admitted handle");
        let setup = serving
            .storage()
            .setup_deadline(handle)
            .expect("setup deadline");
        serving.slots[0].approved = FixedHostname::normalize(b"sub.example.org");
        serving.slots[0].approved_port = origin_port;
        serving.slots[0].gate.on_authorized();
        serving.slots[0].stage = Stage::Dialing;
        serving.slots[0].connect_family = Some(Family::A);
        serving.slots[0].connect_deadline = Some(crate::worker::Deadline::connect_attempt(
            Instant::now() - Duration::from_secs(3),
            setup,
        ));
        let dial_start = Instant::now();
        serving
            .dial(0, NumericAddr::V4(Ipv4Addr::from([127, 0, 0, 1])))
            .expect("dial the live origin");
        let ws = &serving.slots[0];
        assert_eq!(
            ws.connect_family,
            Some(Family::A),
            "the dialing slot must carry the decided family"
        );
        let deadline = ws.connect_deadline.expect("dial re-anchored deadline");
        assert!(
            deadline.limit()
                >= dial_start + Duration::from_secs(crate::worker::CONNECT_DEADLINE_SECS),
            "the re-anchored deadline must run the full {} s from dial initiation, got {:?}",
            crate::worker::CONNECT_DEADLINE_SECS,
            deadline.limit()
        );
        let _origin_stream = origin.accept().expect("accept origin side").0;
        pump(serving, 30);
        let body = read_until(&mut client, b"\r\n\r\n");
        assert!(
            body.starts_with(b"HTTP/1.1 200"),
            "a live origin must complete the successful CONNECT, got {body:?}"
        );
        serving.close_slot(0);
    });
}

#[test]
/// An expired per-attempt connect deadline while a slot is still Dialing must
/// record one retry and re-decide, via `expire_sweep`, rather than sit frozen
/// on the stalled attempt (M1/I26 enforcement).
fn expired_connect_deadline_while_dialing_records_a_retry_through_expire_sweep() {
    use crate::cache::Family;
    use crate::connect::Feed;
    use crate::eligibility::NumericAddr;
    use std::net::Ipv4Addr;
    let port = ephemeral_port();
    let upstream_port = ephemeral_port();
    let cfg = config_pair(port, upstream_port);
    with_serving_stack_cfg(port, cfg, move |serving| {
        serving.storage_mut().publish_test_addr(
            0,
            NumericAddr::V4(Ipv4Addr::from([127, 0, 0, 1])),
            Family::A,
        );
        let mut client = connect(port);
        pump(serving, 10);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );
        let head = format!("CONNECT sub.example.org:{upstream_port} HTTP/1.1\r\n\r\n");
        match serving.slots[0]
            .parser
            .feed(head.as_bytes())
            .expect("head feed")
        {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        let handle = serving.slots[0].handle.as_ref().expect("admitted handle");
        let setup = serving
            .storage()
            .setup_deadline(handle)
            .expect("setup deadline");
        serving.slots[0].approved = FixedHostname::normalize(b"sub.example.org");
        serving.slots[0].approved_port = upstream_port;
        serving.slots[0].stage = Stage::Dialing;
        serving.slots[0].connect_family = Some(Family::A);
        serving.slots[0].connect_deadline = Some(crate::worker::Deadline::connect_attempt(
            Instant::now() - Duration::from_secs(3),
            setup,
        ));
        serving.expire_sweep(Instant::now());
        pump(serving, 10);
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the expired-dial retry must re-decide to NoBinding and release the seat"
        );
        let body = read_all(&mut client);
        assert!(
            body.starts_with(b"HTTP/1.1 502 Bad Gateway"),
            "the expired-dial retry must end in a pre-200 502, got {body:?}"
        );
    });
}

#[cfg(all(test, feature = "alloc-witness"))]
#[test]
/// The expired per-attempt connect deadline on a Dialing slot, driven through
/// `expire_sweep` → `note_expired_dial` → `fail_current_attempt` → retry
/// re-decision into the `NoBinding` refusal and seat release, must complete
/// inside the `Phase::Serving` witness with zero post-boot heap allocation
/// (M1/I26 enforcement, ov2g closure): every branch of the retry/deadline seam
/// is now alloc-witness-covered.
fn expire_sweep_dialing_expired_seam_records_retry_with_zero_allocations() {
    enforcement_witness_thread(|| {
        use crate::cache::Family;
        use crate::connect::Feed;
        use crate::eligibility::NumericAddr;
        use std::net::Ipv4Addr;
        let port = ephemeral_port();
        let upstream_port = ephemeral_port();
        let cfg = config_pair(port, upstream_port);
        let mut serving = serve_on_cfg(port, &cfg);
        serving.storage_mut().publish_test_addr(
            0,
            NumericAddr::V4(Ipv4Addr::from([127, 0, 0, 1])),
            Family::A,
        );
        let mut client = connect(port);
        pump(&mut serving, 10);
        assert_eq!(
            serving.storage().occupied(),
            1,
            "the connecting client must be admitted"
        );
        let head = format!("CONNECT sub.example.org:{upstream_port} HTTP/1.1\r\n\r\n");
        match serving.slots[0]
            .parser
            .feed(head.as_bytes())
            .expect("head feed")
        {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        let handle = serving.slots[0].handle.as_ref().expect("admitted handle");
        let setup = serving
            .storage()
            .setup_deadline(handle)
            .expect("setup deadline");
        serving.slots[0].approved = FixedHostname::normalize(b"sub.example.org");
        serving.slots[0].approved_port = upstream_port;
        serving.slots[0].stage = Stage::Dialing;
        serving.slots[0].connect_family = Some(Family::A);
        serving.slots[0].connect_deadline = Some(crate::worker::Deadline::connect_attempt(
            Instant::now() - Duration::from_secs(3),
            setup,
        ));
        let ((), counts) = crate::alloc::run_phase(crate::alloc::Phase::Serving, || {
            serving.expire_sweep(Instant::now());
            pump(&mut serving, 10);
        });
        assert!(
            counts.all_zero(),
            "the expire_sweep dialing-expired retry seam must allocate/deallocate nothing: {counts:?}"
        );
        assert_eq!(
            serving.storage().occupied(),
            0,
            "the expired-dial retry must re-decide to NoBinding and release the seat"
        );
        let body = read_all(&mut client);
        assert!(
            body.starts_with(b"HTTP/1.1 502 Bad Gateway"),
            "the expired-dial retry must end in a pre-200 502, got {body:?}"
        );
    });
}

#[test]
/// Saturated generation shifts in the token builders must fail closed without
/// panic: the local id stays decodable and the generation stays non-matchable
/// by any live slot, so a degenerate generation can only produce stale-drop.
fn saturated_generation_tokens_fail_closed_without_panic() {
    let idx = 3usize;
    let ct = client_token(u64::MAX, idx);
    assert_eq!(
        ct.0 & LOCAL_MASK,
        idx + 1,
        "the saturated client token must keep its local id decodable"
    );
    assert_ne!(
        (ct.0 >> GEN_SHIFT) as u64,
        u64::MAX,
        "the saturated generation must not falsely match a live generation"
    );
    let ut = upstream_token(u64::MAX, idx);
    assert_eq!(
        ut.0 & LOCAL_MASK,
        UPSTREAM_BASE + idx,
        "the saturated upstream token must keep its local id decodable"
    );
    let generation = 5u64;
    assert_eq!(
        client_token(generation, idx).0,
        ((usize::try_from(generation).expect("test generation fits usize") << GEN_SHIFT)
            | (idx + 1)),
        "ordinary in-range generations must round-trip exactly unchanged"
    );
    assert_eq!(
        upstream_token(generation, idx).0,
        ((usize::try_from(generation).expect("test generation fits usize") << GEN_SHIFT)
            | (UPSTREAM_BASE + idx)),
        "ordinary in-range generations must round-trip exactly unchanged"
    );
}

#[test]
/// The Peer-branch freshness fold (W6-H6b-F5) latches the persistent
/// "serving from a stale cache entry" monitor level bit on a Stale admission
/// and clears it on a later Fresh admission. The helper is invoked directly
/// against the real storage/cache/clock because a real `Peer` admission
/// requires an actual eligible upstream dial, which is not hermetic; the
/// one-line Peer-branch wiring itself is covered by review.
fn peer_admission_freshness_folds_serving_stale_level_bit() {
    use crate::cache::Family;
    use crate::connect::Feed;
    use crate::eligibility::NumericAddr;
    use std::net::Ipv4Addr;
    let port = ephemeral_port();
    let upstream_port = ephemeral_port();
    let cfg = config_pair(port, upstream_port);
    with_serving_stack_cfg(port, cfg, move |serving| {
        let mut parser = crate::connect::ConnectParser::new();
        let head = format!("CONNECT sub.example.org:{upstream_port} HTTP/1.1\r\n\r\n");
        match parser.feed(head.as_bytes()).expect("head feed") {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        let request = parser
            .result()
            .copied()
            .expect("parsed request")
            .expect("valid request");
        assert!(
            !serving.storage().enforcement().monitor().serving_stale(),
            "a fresh monitor must not be serving stale"
        );

        // A fresh family-A binding, folded immediately: the level bit stays clear.
        serving.storage_mut().publish_test_addr(
            0,
            NumericAddr::V4(Ipv4Addr::from([1, 1, 1, 1])),
            Family::A,
        );
        let receipt = serving.storage().cache_secs(Instant::now());
        serving.note_peer_freshness(&request, Family::A, Instant::now());
        assert!(
            !serving.storage().enforcement().monitor().serving_stale(),
            "a fresh admission must not latch the stale-serving level bit"
        );

        // Advance the clock past the 600 s freshness deadline (still inside the
        // retirement grace): the same entry is now Stale and must latch.
        serving
            .storage_mut()
            .mount_clock(Instant::now(), receipt + 601);
        serving.note_peer_freshness(&request, Family::A, Instant::now());
        assert!(
            serving.storage().enforcement().monitor().serving_stale(),
            "a stale admission must latch the persistent stale-serving level bit"
        );

        // A later fresh admission clears the level bit again.
        serving.storage_mut().mount_clock(Instant::now(), receipt);
        serving.note_peer_freshness(&request, Family::A, Instant::now());
        assert!(
            !serving.storage().enforcement().monitor().serving_stale(),
            "a later fresh admission must clear the stale-serving level bit"
        );
    });
}

#[test]
fn ja4_first_seen_records_baseline_without_signal() {
    with_serving_stack(ephemeral_port(), |serving| {
        let wire = hello_wire(b"sub.example.org", false);
        serving.slots[0].dest_ip = Some(NumericAddr::V4(Ipv4Addr::from([203, 0, 113, 1])));
        drive_hello(serving, &wire, "sub.example.org");
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        let entry = serving.ja4_baseline.entries[ordinal.get()][0];
        assert_eq!(
            entry.addr,
            NumericAddr::V4(Ipv4Addr::from([203, 0, 113, 1])),
            "the first-seen destination is persisted as the baseline key"
        );
        let ja4 = serving.slots[0].inspector.hello().expect("hello").ja4();
        assert_eq!(
            entry.ja4, ja4,
            "the full 36-byte JA4 is stored at first-seen"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_ja4_change(ordinal),
            0,
            "first-seen records the baseline and never flares a change signal"
        );
    });
}

#[test]
fn ja4_deviation_flares_signal_once_per_connection() {
    with_serving_stack(ephemeral_port(), |serving| {
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        let wire_a = hello_wire(b"sub.example.org", false);
        let wire_b = hello_wire_ext(
            b"sub.example.org",
            false,
            &[(0x0010, &[0x00, 0x03, 0x02, 0x68, 0x32])],
        );

        // conn1: first-seen baseline for the (ordinal, addr) pair.
        serving.slots[0].dest_ip = Some(NumericAddr::V4(Ipv4Addr::from([203, 0, 113, 1])));
        drive_hello(serving, &wire_a, "sub.example.org");
        let baseline = serving.ja4_baseline.entries[ordinal.get()][0].ja4;
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_ja4_change(ordinal),
            0,
            "first-seen never flares"
        );

        // conn2: a different JA4 on the same (ordinal, addr) is a deviation.
        serving.slots[0].reset();
        serving.slots[0].dest_ip = Some(NumericAddr::V4(Ipv4Addr::from([203, 0, 113, 1])));
        drive_hello(serving, &wire_b, "sub.example.org");
        let deviated = serving.slots[0].inspector.hello().expect("hello").ja4();
        assert_ne!(
            deviated, baseline,
            "the ALPN variant must produce a distinct JA4"
        );
        assert_eq!(
            serving.ja4_baseline.entries[ordinal.get()][0].ja4,
            baseline,
            "the baseline is never updated after first-seen"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_ja4_change(ordinal),
            1,
            "a deviation flares exactly one change signal"
        );

        // At-most-once: a second record attempt on the same connection is inert.
        serving.maybe_record_ja4_baseline(0);
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_ja4_change(ordinal),
            1,
            "the change signal fires at most once per connection"
        );

        // conn3: a fresh connection with the deviated JA4 flares again.
        serving.slots[0].reset();
        serving.slots[0].dest_ip = Some(NumericAddr::V4(Ipv4Addr::from([203, 0, 113, 1])));
        drive_hello(serving, &wire_b, "sub.example.org");
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_ja4_change(ordinal),
            2,
            "a later connection with the deviated JA4 flares again"
        );
    });
}

#[test]
fn ja4_baseline_defers_until_dial_persists_dest_ip() {
    with_serving_stack(ephemeral_port(), |serving| {
        let wire = hello_wire(b"sub.example.org", false);
        drive_hello(serving, &wire, "sub.example.org");
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        assert!(
            serving.slots[0].ja4_pending,
            "a hello completed before the destination IP is known defers the baseline"
        );
        assert_eq!(
            serving.ja4_baseline.entries[ordinal.get()][0].addr,
            EMPTY_JA4_ADDR,
            "no baseline is recorded before the destination IP is known"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_ja4_change(ordinal),
            0,
            "a deferred baseline never flares before the IP is known"
        );
        serving.slots[0].dest_ip = Some(NumericAddr::V4(Ipv4Addr::from([203, 0, 113, 1])));
        serving.maybe_record_ja4_baseline(0);
        assert!(
            !serving.slots[0].ja4_pending,
            "the deferred baseline resolves once the destination IP is known"
        );
        let entry = serving.ja4_baseline.entries[ordinal.get()][0];
        assert_eq!(
            entry.addr,
            NumericAddr::V4(Ipv4Addr::from([203, 0, 113, 1])),
            "the dial-persisted destination IP keys the deferred baseline"
        );
        assert_eq!(
            serving
                .storage()
                .enforcement()
                .counters()
                .facts_ja4_change(ordinal),
            0,
            "a deferred first-seen still never flares a change signal"
        );
    });
}

#[test]
fn ja4_baseline_row_full_returns_neutral() {
    with_serving_stack(ephemeral_port(), |serving| {
        let approved = FixedHostname::normalize(b"sub.example.org").expect("normalize");
        let ordinal = serving.storage().ordinal_for(&approved).expect("ordinal");
        let ja4 = [b'j'; 36];
        for i in 0..MAX_ADDRESSES {
            let addr = NumericAddr::V4(Ipv4Addr::from([
                10,
                0,
                0,
                u8::try_from(i).expect("row index fits u8"),
            ]));
            assert_eq!(
                serving.ja4_baseline.record(ordinal, addr, ja4),
                BaselineOutcome::FirstSeen,
                "each fresh address in the row is a first-seen baseline"
            );
        }
        assert_eq!(
            serving.ja4_baseline.record(
                ordinal,
                NumericAddr::V4(Ipv4Addr::from([10, 0, 0, 16])),
                ja4
            ),
            BaselineOutcome::RowFull,
            "a 17th distinct address overflows the fixed 16-entry row neutrally"
        );
    });
}

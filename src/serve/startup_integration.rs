use super::{LogStore, ServeStorage, ServingMode, StartupDecision, StartupError, StartupReport};
use crate::cache::Family;
use crate::config::{Config, ConfigError, parse_config_document};
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

const NOW0: u64 = 1000;

fn config_with(names: &str, allowance: u8, listen_port: u16) -> Config {
    let mut doc = format!(
        "listen = \"127.0.0.1:{listen_port}\"\nstartup_unresolved_allowance = {allowance}\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n"
    );
    for name in names.split(", ") {
        let name = name.trim_matches('"');
        let _ = write!(
            doc,
            "[allowed_fqdn.\"{name}\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
        );
    }
    parse_config_document(&doc).expect("valid test config")
}

fn ephemeral_config(names: &str, allowance: u8) -> Config {
    config_with(names, allowance, 9).with_kernel_assigned_test_listener()
}

fn read_query(sock: &mut TcpStream) -> Option<Vec<u8>> {
    let mut lenb = [0u8; 2];
    if sock.read_exact(&mut lenb).is_err() {
        return None;
    }
    let qlen = usize::from(u16::from_be_bytes(lenb));
    if qlen == 0 || qlen > 2048 {
        return None;
    }
    let mut q = vec![0u8; qlen];
    if sock.read_exact(&mut q).is_err() {
        return None;
    }
    Some(q)
}

fn write_message(sock: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(msg.len() + 2);
    out.extend_from_slice(
        &u16::try_from(msg.len())
            .expect("dns message fits u16 length prefix")
            .to_be_bytes(),
    );
    out.extend_from_slice(msg);
    sock.write_all(&out)?;
    sock.flush()
}

struct DnsResponder {
    addr: SocketAddr,
}

impl DnsResponder {
    fn spawn<F>(mut on_query: F) -> DnsResponder
    where
        F: FnMut(Vec<u8>) -> Option<Vec<u8>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind responder");
        let addr = listener.local_addr().expect("responder address");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut sock) = stream else {
                    break;
                };
                while let Some(query) = read_query(&mut sock) {
                    let Some(reply) = on_query(query) else {
                        break;
                    };
                    if write_message(&mut sock, &reply).is_err() {
                        break;
                    }
                }
            }
        });
        DnsResponder { addr }
    }
}

fn build_positive(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 16 {
        return None;
    }
    let tid = u16::from_be_bytes([query[0], query[1]]);
    let qname = &query[12..query.len() - 4];
    let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
    let rdata: &[u8] = match qtype {
        1 => &[1, 1, 1, 1],
        28 => &[
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ],
        _ => return None,
    };
    let mut msg = Vec::with_capacity(query.len() + 22);
    msg.extend_from_slice(&tid.to_be_bytes());
    msg.extend_from_slice(&0x8000u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&query[12..]);
    msg.extend_from_slice(qname);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&300u32.to_be_bytes());
    msg.extend_from_slice(
        &u16::try_from(rdata.len())
            .expect("rdata fits u16 wire length")
            .to_be_bytes(),
    );
    msg.extend_from_slice(rdata);
    Some(msg)
}

fn qname_contains(query: &[u8], label: &[u8]) -> bool {
    query.windows(label.len()).any(|w| w == label)
}

#[test]
fn full_serve_opens_listener_early_before_the_window_elapses() {
    let window = Duration::from_secs(2);
    let config = ephemeral_config("\"alpha.example.org:443\", \"beta.example.org:443\"", 0);
    let responder = DnsResponder::spawn(|q| build_positive(&q));
    let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
    let start = Instant::now();
    let outcome = storage
        .run_startup_within(responder.addr, NOW0, window)
        .expect("startup");
    let elapsed = start.elapsed();
    assert_eq!(outcome.decision, StartupDecision::Serve(ServingMode::Full));
    assert_eq!(outcome.report.resolved_names, 2);
    let listener = outcome.listener.expect("listener bound for full serve");
    let addr = listener.local_addr().expect("listener address");
    assert_eq!(
        addr.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        "test listener must stay loopback"
    );
    assert_ne!(
        addr.port(),
        0,
        "kernel-assigned listener must have a real port"
    );
    assert!(
        elapsed < window,
        "all-usable startup must return early, not wait the window"
    );
    let conn = TcpStream::connect(addr);
    assert!(conn.is_ok(), "bound listener must accept connections");
}

#[test]
fn exit75_is_decided_only_at_the_actual_window_deadline() {
    let window = Duration::from_millis(300);
    let guard = TcpListener::bind("127.0.0.1:0").expect("reserved listen guard");
    let guard_port = guard.local_addr().expect("guard address").port();
    let config = config_with(
        "\"alpha.example.org:443\", \"beta.example.org:443\"",
        0,
        guard_port,
    );
    let responder = DnsResponder::spawn(|query| {
        if qname_contains(&query, b"\x04beta") {
            None
        } else {
            build_positive(&query)
        }
    });
    let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
    let start = Instant::now();
    let outcome = storage
        .run_startup_within(responder.addr, NOW0, window)
        .expect("startup");
    let elapsed = start.elapsed();
    assert_eq!(outcome.decision, StartupDecision::Exit75 { unresolved: 1 });
    assert!(
        outcome.listener.is_none(),
        "exit 75 must not bind a listener even with its configured address occupied"
    );
    assert!(
        elapsed >= window,
        "unresolved startup must not be decided before the deadline (early snapshot)"
    );
}

#[test]
fn degraded_is_decided_only_at_the_actual_window_deadline() {
    let window = Duration::from_millis(300);
    let config = ephemeral_config("\"alpha.example.org:443\", \"beta.example.org:443\"", 1);
    let responder = DnsResponder::spawn(|query| {
        if qname_contains(&query, b"\x04beta") {
            None
        } else {
            build_positive(&query)
        }
    });
    let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
    let start = Instant::now();
    let outcome = storage
        .run_startup_within(responder.addr, NOW0, window)
        .expect("startup");
    let elapsed = start.elapsed();
    assert_eq!(
        outcome.decision,
        StartupDecision::Serve(ServingMode::Degraded)
    );
    assert!(
        outcome.listener.is_some(),
        "degraded serve must bind a listener"
    );
    assert!(
        elapsed >= window,
        "degraded startup must not be decided before the deadline (early snapshot)"
    );
}

#[test]
fn failed_lookup_retries_within_the_window_and_recovers_to_full() {
    let window = Duration::from_secs(2);
    let config = ephemeral_config("\"alpha.example.org:443\"", 0);
    let mut queries = 0u32;
    let responder = DnsResponder::spawn(move |query| {
        queries += 1;
        if queries <= 2 {
            None
        } else {
            build_positive(&query)
        }
    });
    let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
    let start = Instant::now();
    let outcome = storage
        .run_startup_within(responder.addr, NOW0, window)
        .expect("startup");
    let elapsed = start.elapsed();
    assert_eq!(
        outcome.decision,
        StartupDecision::Serve(ServingMode::Full),
        "the windowed retry must recover the failed lookup"
    );
    assert_eq!(outcome.report.resolved_names, 1);
    assert_eq!(outcome.report.failed, 2);
    assert!(outcome.listener.is_some());
    assert!(
        elapsed < window,
        "recovered startup must return early, not wait for the deadline"
    );
}

#[test]
fn retried_failures_and_never_attempted_sibling_report_truthful_not_attempted() {
    let window = Duration::from_millis(1600);
    let config = ephemeral_config("\"alpha.example.org:443\", \"beta.example.org:443\"", 1);
    let responder = DnsResponder::spawn(|query| {
        if qname_contains(&query, b"\x04beta") {
            None
        } else {
            build_positive(&query)
        }
    });
    let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
    let outcome = storage
        .run_startup_within(responder.addr, NOW0, window)
        .expect("startup");
    assert_eq!(outcome.report.resolved_names, 1, "alpha usable");
    assert!(
        outcome.report.failed >= 4,
        "beta retried at least once after its first failed exchange: {}",
        outcome.report.failed
    );
    assert_eq!(
        outcome.report.not_attempted, 1,
        "only alpha's sibling family went un-attempted; retried failures must \
             not erase the never-attempted slots (exchanges {}, failed {}, resolved {}):",
        outcome.report.exchanges, outcome.report.failed, outcome.report.resolved_names,
    );
}

#[test]
fn resolved_names_family_schedule_survives_for_serving_refresh() {
    let window = Duration::from_millis(1600);
    let config = ephemeral_config("\"alpha.example.org:443\", \"beta.example.org:443\"", 1);
    let responder = DnsResponder::spawn(|query| {
        if qname_contains(&query, b"\x04beta") {
            None
        } else {
            build_positive(&query)
        }
    });
    let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
    let outcome = storage
        .run_startup_within(responder.addr, NOW0, window)
        .expect("startup");
    assert_eq!(outcome.report.resolved_names, 1, "alpha usable");
    assert_eq!(
        storage.schedules().due_time(0, Family::Aaaa).unwrap(),
        Some(NOW0),
        "a resolved name's sibling family must keep its seeded due for the \
             serving refresh, never be re-clobbered to a later now"
    );
}

#[test]
fn resolved_name_sibling_stays_selectable_after_startup_for_serving() {
    let window = Duration::from_millis(1600);
    let config = ephemeral_config("\"alpha.example.org:443\", \"beta.example.org:443\"", 1);
    let responder = DnsResponder::spawn(|query| {
        if qname_contains(&query, b"\x04beta") {
            None
        } else {
            build_positive(&query)
        }
    });
    let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
    let outcome = storage
        .run_startup_within(responder.addr, NOW0, window)
        .expect("startup");
    assert_eq!(outcome.report.resolved_names, 1, "alpha usable");
    assert_eq!(
        storage.schedules.due_time(0, Family::Aaaa).unwrap(),
        Some(NOW0),
        "sibling due must be preserved for the serving refresh"
    );
    let selected = storage
        .schedules
        .select_due(NOW0 + 2)
        .expect("a future serving refresh must be selectable")
        .expect("alpha AAAA must not be stuck in-flight after the window");
    assert_eq!(selected.name(), 0);
    assert_eq!(selected.family(), Family::Aaaa);
}

#[test]
fn kernel_assigned_test_listener_avoids_the_released_port_rebind_race() {
    let window = Duration::from_millis(1600);
    let contender = TcpListener::bind("127.0.0.1:0").expect("held listener");
    let held_port = contender.local_addr().expect("held address").port();
    let config =
        config_with("\"alpha.example.org:443\"", 0, held_port).with_kernel_assigned_test_listener();
    let responder = DnsResponder::spawn(|query| build_positive(&query));
    let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
    let outcome = storage
        .run_startup_within(responder.addr, NOW0, window)
        .expect("startup");
    let listener = outcome.listener.expect("listener bound");
    let addr = listener.local_addr().expect("listener address");
    assert_eq!(
        addr.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        "test listener must stay loopback"
    );
    assert_ne!(
        addr.port(),
        0,
        "kernel-assigned listener must have a real port"
    );
    assert_ne!(
        addr.port(),
        held_port,
        "listener must not reuse the still-held contender port"
    );
    assert_eq!(outcome.decision, StartupDecision::Serve(ServingMode::Full));
    let conn = TcpStream::connect(addr);
    assert!(
        conn.is_ok(),
        "kernel-assigned listener must accept connections"
    );
    drop(contender);
}

#[test]
fn normally_configured_occupied_listen_addr_is_a_bind_error_after_ready() {
    let window = Duration::from_millis(1600);
    let guard = TcpListener::bind("127.0.0.1:0").expect("occupied-address guard");
    let guard_port = guard.local_addr().expect("guard address").port();
    let config = config_with("\"alpha.example.org:443\"", 0, guard_port);
    let responder = DnsResponder::spawn(|query| build_positive(&query));
    let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
    let Err(err) = storage.run_startup_within(responder.addr, NOW0, window) else {
        panic!("expected a bind error for an occupied configured listen address")
    };
    match err {
        StartupError::Listener { kind, detail } => {
            assert_eq!(kind, io::ErrorKind::AddrInUse);
            assert_eq!(detail, "connect listener bind");
        }
        other => panic!("unexpected startup error: {other:?}"),
    }
    let zero_parse = parse_config_document(
        "listen = \"127.0.0.1:0\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"alpha.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n",
    );
    parse_config_document(
        "listen = \"127.0.0.1:9\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"alpha.example.org:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\n",
    )
    .expect("the identical document at a legal port must stay valid");
    match zero_parse {
        Err(ConfigError::InvalidListen { value }) => assert_eq!(value, "127.0.0.1:0"),
        other => panic!("public parse of a zero listen port must yield InvalidListen: {other:?}"),
    }
}

/// The widest legal allowlist: `ALLOWLIST_MAX` keyed FQDNs, each exactly
/// `FQDN_MAX_LEN` bytes (four labels, the longest three at the 63-byte
/// bound), distinct per name, in one document under
/// [`crate::config::CONFIG_DOC_LIMIT`]. Every name stays unresolved in the
/// tests below, so the startup emission is the 32 + 1 record worst case.
fn widest_allowlist_config() -> Config {
    use crate::config::{ALLOWLIST_MAX, CONFIG_DOC_LIMIT, FQDN_MAX_LEN};
    let mut doc = String::from(
        "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n",
    );
    for ordinal in 0..ALLOWLIST_MAX {
        let mut first = format!("n{ordinal}");
        while first.len() < 63 {
            first.push('a');
        }
        let name = format!(
            "{first}.{}.{}.{}",
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(FQDN_MAX_LEN - 3 * 63 - 3)
        );
        assert_eq!(name.len(), FQDN_MAX_LEN, "the widest legal FQDN");
        let _ = write!(
            doc,
            "[allowed_fqdn.\"{name}:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
        );
    }
    assert!(
        doc.len() <= CONFIG_DOC_LIMIT,
        "the widest legal document ({} B) fits the {CONFIG_DOC_LIMIT} B bound",
        doc.len()
    );
    let config = crate::config::parse_config_document(&doc).expect("widest legal config");
    assert_eq!(config.allowlist().len(), ALLOWLIST_MAX);
    assert!(
        config
            .allowlist()
            .iter()
            .all(|name| name.as_str().len() == FQDN_MAX_LEN),
        "every allowlist entry sits at the 253-byte bound"
    );
    config
}

/// Every allowlisted name unresolved, with a full failed-exchange report.
fn all_unresolved_report() -> StartupReport {
    use crate::config::ALLOWLIST_MAX;
    use crate::startup_dns::NameOutcome;
    StartupReport {
        exchanges: 64,
        failed: 64,
        cancelled: 0,
        not_attempted: 0,
        resolved_names: 0,
        outcomes: [NameOutcome::Negative; ALLOWLIST_MAX],
        first_failure: None,
    }
}

/// A real file sink the store writes through its own unbuffered syscall
/// path, so the drain is observed as bytes on a descriptor rather than
/// through the test-only `flush_all` loop.
fn temp_sink_file() -> std::fs::File {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "alumina-serve-log-{}-{}.log",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("temp sink file")
}

/// A socketpair whose writer is already full, so every write is a real
/// `WouldBlock` on a live nonblocking descriptor.
fn stalled_sink() -> (
    LogStore,
    std::os::unix::net::UnixStream,
    std::os::unix::net::UnixStream,
) {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    let (reader, mut writer) = UnixStream::pair().expect("socketpair");
    writer.set_nonblocking(true).expect("writer nonblocking");
    let filler = [b'#'; 8 * 1024];
    let mut accepted = 0usize;
    while accepted < (1 << 20) {
        match writer.write(&filler) {
            Ok(0) => break,
            Ok(n) => accepted += n,
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => panic!("filling the stalled sink: {err}"),
        }
    }
    assert!(accepted > 0, "the socket buffer accepted the filler");
    let store = LogStore::with_fd(&writer).expect("stalled sink store");
    (store, reader, writer)
}

/// B-D1 regression: the readiness decision enqueues 33 records but one
/// `drain_sink` turn carries at most 16 fragments, so the bounded turn loop
/// must deliver every `startup_name` record and the summary to the real
/// sink — in ascending ordinal order, summary last — before the `Exit75`
/// decision that ends the process.
#[test]
fn startup_emission_over_widest_config_reaches_the_real_sink_before_exit75() {
    use crate::config::ALLOWLIST_MAX;
    use std::io::{Read, Seek};
    let config = widest_allowlist_config();
    let allowlist = config.allowlist();
    assert_eq!(allowlist.len(), ALLOWLIST_MAX);
    let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
    let mut file = temp_sink_file();
    storage.logs = LogStore::with_fd(&file).expect("file sink store");
    storage.emit_startup_records(
        9,
        &all_unresolved_report(),
        StartupDecision::Exit75 { unresolved: 32 },
    );
    assert_eq!(storage.logs.len(), 0, "the queue is empty after the drain");
    assert_eq!(
        storage.logs.dropped(),
        0,
        "all 33 records were enqueued and delivered, none dropped"
    );
    let mut out = Vec::new();
    file.rewind().expect("rewind the sink");
    file.read_to_end(&mut out).expect("read the sink");
    let text = String::from_utf8(out).expect("ascii records");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.len(),
        ALLOWLIST_MAX + 1,
        "32 startup_name records plus the summary reach the sink"
    );
    for (ordinal, line) in lines[..ALLOWLIST_MAX].iter().enumerate() {
        assert_eq!(
            *line,
            format!(
                "level=info kind=startup_name secs=9 ordinal={ordinal} name=\"{}\" outcome=negative",
                allowlist.get(ordinal).expect("allowlist ordinal").as_str()
            ),
            "record {ordinal}: ascending ordinal order and the full, untruncated FQDN"
        );
    }
    assert_eq!(
        lines[ALLOWLIST_MAX],
        "level=info kind=startup_final secs=9 status=\"failure\" allowance=0 usable=0 unresolved=32 exchanges=64 failed=64 not_attempted=0 dropped=0 names_dropped=0",
        "the aggregate readiness record is last and reports no loss"
    );
}

/// The stalled-sink half of the bounded loop: a sink that answers
/// `WouldBlock` stops the drain after the first refusing turn instead of
/// spending the cap or spinning, records survive for a later turn on a
/// serving decision, and a decision that exits counts each stranded record
/// exactly once.
#[test]
fn startup_drain_stops_on_a_stalled_sink_and_counts_each_stranded_record_once() {
    use crate::config::ALLOWLIST_MAX;

    let config = widest_allowlist_config();
    let report = all_unresolved_report();
    let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
    let (store, _reader, _writer) = stalled_sink();
    storage.logs = store;
    storage.emit_startup_records(9, &report, StartupDecision::Serve(ServingMode::Degraded));
    assert_eq!(
        storage.logs.len(),
        ALLOWLIST_MAX + 1,
        "a stalled sink ends the drain with every record still queued"
    );
    assert_eq!(
        storage.logs.sink_ops(),
        0,
        "the stalled sink accepted no fragment"
    );
    assert!(
        !storage.logs.sink_ready(),
        "the stop reason is the stalled sink, not the iteration cap"
    );
    assert_eq!(
        storage.logs.dropped(),
        0,
        "a serving decision counts nothing: the records are still deliverable"
    );
    let (store, _reader, _writer) = stalled_sink();
    storage.logs = store;
    storage.emit_startup_records(9, &report, StartupDecision::Exit75 { unresolved: 32 });
    assert_eq!(
        storage.logs.len(),
        0,
        "the queue an exiting owner cannot deliver is cleared"
    );
    assert_eq!(
        storage.logs.dropped(),
        (ALLOWLIST_MAX + 1) as u64,
        "each undeliverable record is counted exactly once, never twice"
    );
}

/// A DNS reply that points the queried allowlist name to an explicitly
/// configured `cname_bailiwick` suffix and terminates it there: CNAME RR
/// owner = the queried name, target = the declared suffix; the terminal
/// A/AAAA RR owner = the same declared suffix with valid TTL/RDATA. This is
/// the exact cross-suffix shape the bailiwick parser reaches (dns tests
/// `accepts_declared_suffix_cname_target`), at a real loopback responder.
fn build_cross_suffix_cname(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 16 {
        return None;
    }
    let tid = u16::from_be_bytes([query[0], query[1]]);
    let qname = &query[12..query.len() - 4];
    let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
    let rdata: &[u8] = match qtype {
        1 => &[1, 1, 1, 1],
        28 => &[
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ],
        _ => return None,
    };
    let target = b"\x03cdn\x07example\x03net\x00";
    let mut msg = Vec::with_capacity(query.len() + 40);
    msg.extend_from_slice(&tid.to_be_bytes());
    msg.extend_from_slice(&0x8000u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&2u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&query[12..]);
    msg.extend_from_slice(qname);
    msg.extend_from_slice(&5u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&200u32.to_be_bytes());
    msg.extend_from_slice(
        &u16::try_from(target.len())
            .expect("cname target wire length fits u16")
            .to_be_bytes(),
    );
    msg.extend_from_slice(target);
    msg.extend_from_slice(target);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&40u32.to_be_bytes());
    msg.extend_from_slice(
        &u16::try_from(rdata.len())
            .expect("terminal rdata wire length fits u16")
            .to_be_bytes(),
    );
    msg.extend_from_slice(rdata);
    Some(msg)
}

/// The same parsed Config and the same CNAME answers must drive the legacy
/// blocking storage window and the shared preallocated startup to one
/// identical result: with an explicit `cname_bailiwick` suffix the entry
/// resolves on both owners and decides `Serve(Full)`; without that suffix the
/// same cross-suffix CNAME is rejected on both owners, which decide `Exit75`
/// with zero resolved names and no cached CNAME broadening.
#[test]
fn configured_cross_suffix_cname_resolves_identically_on_shared_and_legacy_startup() {
    use crate::runtime::Preallocated;
    let window = Duration::from_millis(700);
    let cases = [
        (
            Some("cdn.example.net"),
            StartupDecision::Serve(ServingMode::Full),
            1,
            true,
        ),
        (None, StartupDecision::Exit75 { unresolved: 1 }, 0, false),
    ];
    for (suffix, expected_decision, expected_resolved, binds_listener) in cases {
        let config = parse_config_document(&cross_suffix_startup_doc(suffix))
            .expect("valid test config")
            .with_kernel_assigned_test_listener();
        let responder = DnsResponder::spawn(|q| build_cross_suffix_cname(&q));

        let legacy_outcome = ServeStorage::boot(&config)
            .expect("boot serving storage")
            .run_startup_within(responder.addr, NOW0, window)
            .expect("legacy startup window");

        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        let mut owner = Preallocated::preallocate(
            ServeStorage::boot(&config).expect("boot serving storage"),
            traffic,
        )
        .expect("preallocate serving workspaces");
        let shared_outcome = owner
            .run_startup_within(responder.addr, NOW0, window)
            .expect("shared startup window");

        assert_eq!(
            shared_outcome.decision, legacy_outcome.decision,
            "the shared MAIN path must take the identical readiness decision to the legacy storage window"
        );
        assert_eq!(
            shared_outcome.decision, expected_decision,
            "a configured-suffix admission must decide exactly this readiness result"
        );
        assert_eq!(
            shared_outcome.report.resolved_names, expected_resolved,
            "the shared MAIN owner must resolve exactly the names its configured suffix admits"
        );
        assert_eq!(
            shared_outcome.report.resolved_names, legacy_outcome.report.resolved_names,
            "legacy is the independent baseline: same config, same answers, same resolved count"
        );
        assert_eq!(
            shared_outcome.listener.is_some(),
            binds_listener,
            "a full-serving path binds the startup listener; an exit-75 path does not"
        );
    }
}

fn cross_suffix_startup_doc(bailiwick_target: Option<&str>) -> String {
    let bailiwick_clause = bailiwick_target
        .map(|host| format!("cname_bailiwick = [\"{host}\"]\n"))
        .unwrap_or_default();
    format!(
        "listen = \"127.0.0.1:9\"\n\
         startup_unresolved_allowance = 0\n\
         resolver = [\"1.1.1.1\"]\n\
         [any_illegal]\n\
         connect_parse = {{ action = \"notify\", scope = \"connection\" }}\n\
         host_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\n\
         tls_profile = {{ action = \"block\", scope = \"all\" }}\n\
         ech = {{ action = \"block\", scope = \"connection\" }}\n\
         [allowed_fqdn.\"alpha.example.org:443\"]\n\
         {bailiwick_clause}\
         early_data = {{ action = \"notify\", scope = \"connection\" }}\n\
         ja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
    )
}

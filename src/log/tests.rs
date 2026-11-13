use super::encoding::encode_entry_frame;
use super::*;

#[expect(
    clippy::duplicate_mod,
    reason = "one physical owner is included by several test modules in this crate"
)]
#[path = "../../tests/support/temp_dir.rs"]
mod temp_dir;

use crate::dns::cache::{Cache, Family};
use std::fmt::Write as _;

use crate::config::CONFIG_DOC_LIMIT;

use crate::names::hostname::FQDN_MAX_LEN;

use std::fs::File;

use std::io::{Read, Seek};

use std::os::unix::net::UnixStream;

use std::time::Instant;

fn temp_file() -> File {
    temp_dir::TempDir::private_sink_file("alumina-log")
}

fn file_logstore() -> (LogStore, File) {
    let file = temp_file();
    let store = LogStore::with_fd(&file).expect("file sink store");
    (store, file)
}

fn read_all(file: &mut File) -> Vec<u8> {
    let mut buf = Vec::new();
    file.rewind().expect("rewind");
    file.read_to_end(&mut buf).expect("read file");
    buf
}

fn flush_all(store: &mut LogStore) {
    for _ in 0..(QUEUE_SLOTS + 8) {
        store.drain_sink();
        if store.len() == 0 {
            break;
        }
    }
}

/// A distinct 253-byte FQDN (the `FQDN_MAX_LEN` bound) for index `i`:
/// 63 + 1 + 63 + 1 + 63 + 1 + 61 bytes of legal lowercase labels.
fn widest_name(index: usize) -> String {
    format!(
        "{index:02}{}.{}.{}.{}",
        "a".repeat(61),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    )
}

/// Validated owner identity for frame-caller tests: host and port parse
/// through the real Fqdn boundary, so no test fabricates unvalidated names.
fn typed_fqdn(host: &str, port: u16) -> crate::config::Fqdn {
    crate::config::Fqdn::parse(&format!("{host}:{port}")).expect("valid typed fqdn")
}

/// Builds and parses the widest legal configuration: `ALLOWLIST_MAX` keyed
/// allowlist tables each carrying a `FQDN_MAX_LEN`-byte name, plus
/// `MAX_RESOLVERS` resolvers carrying `FQDN_MAX_LEN`-byte FQDNs and pins,
/// all inside `CONFIG_DOC_LIMIT`. The name-bearing worst cases are measured
/// from this real document rather than a synthetic string.
fn widest_legal_config() -> (crate::config::Config, String) {
    use crate::config::ALLOWLIST_MAX;
    use crate::dns::resolver::MAX_RESOLVERS;
    let pin = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    let mut doc = String::new();
    doc.push_str("listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [");
    for i in 0..MAX_RESOLVERS {
        if i > 0 {
            doc.push_str(", ");
        }
        let _ = write!(
            doc,
            "\"2001:abcd:1234:5678:9abc:def0:1234:567{}#{pin_name}#pin-sha256={pin}\"",
            i + 1,
            pin_name = widest_name(i)
        );
    }
    doc.push_str(
            "]\n[any_illegal]\nconnect_parse = { action = \"block\", scope = \"all\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"all\" }\n",
        );
    for i in 0..ALLOWLIST_MAX {
        let _ = writeln!(
            doc,
            "[allowed_fqdn.\"{name}:443\"]\nearly_data = {{ action = \"block\", scope = \"connection\" }}\nja4 = {{ action = \"block\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n",
            name = widest_name(i)
        );
    }
    let config = crate::config::parse_config_document(&doc).expect("widest legal config");
    (config, doc)
}

fn scripted_out(store: &LogStore) -> &[u8] {
    let SinkIo::Scripted(sink) = &store.sink.io else {
        panic!("expected a scripted sink");
    };
    &sink.out
}

fn assert_scripted_stall_preserves_cursor_and_stream(first: ScriptedFirst, label: &str) {
    let mut subject = LogStore::with_scripted_sink(first).expect("scripted sink store");
    let (mut reference, mut reference_file) = file_logstore();
    for i in 0..40 {
        let name = format!("host-{i}.sub.example.org");
        subject.startup_warning_ctx(1, &name, Family::A, "timeout", None);
        reference.startup_warning_ctx(1, &name, Family::A, "timeout", None);
    }
    let enqueued = subject.len();
    subject.drain_sink();
    assert_eq!(
        subject.cursor.map(|cursor| cursor.off),
        Some(0),
        "{label}: the injected stall retains the cursor at the gather-start offset"
    );
    assert!(
        subject.sink.blocked,
        "{label}: the injected stall latches the sink blocked"
    );
    assert_eq!(
        subject.len(),
        enqueued,
        "{label}: the stalled write advances no queued record"
    );
    assert_eq!(
        subject.dropped(),
        0,
        "{label}: a live stalled sink never drops records"
    );
    flush_all(&mut reference);
    let expected = read_all(&mut reference_file);
    let mut turns = 0usize;
    while subject.len() > 0 && turns < 8 * QUEUE_SLOTS {
        subject.drain_sink();
        turns += 1;
    }
    assert_eq!(
        subject.len(),
        0,
        "{label}: the queue drains after the stall"
    );
    assert!(
        !subject.sink.blocked,
        "{label}: the successful resume clears the blocked latch"
    );
    assert_eq!(
        scripted_out(&subject),
        expected,
        "{label}: the drain resumes at the exact residue and emits a byte-identical stream"
    );
}

fn first_record_bytes(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .map_or(bytes.len(), |p| p + 1);
    &bytes[..end]
}

fn count_windows(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn assert_reserved_eviction_preserves_partial_record(n: usize, cursor_past_successor: bool) {
    let name = widest_name(0);
    assert_eq!(
        name.len(),
        253,
        "a legal max-length FQDN for the warning record"
    );
    let (mut a_store, mut a_file) = file_logstore();
    a_store.startup_warning_ctx(1, &name, Family::A, "timeout", None);
    flush_all(&mut a_store);
    let a_record = read_all(&mut a_file);
    let a_len = a_record.len();
    assert!(
        a_len > n,
        "the full warning record exceeds the partial cursor: {a_len} B > {n} B"
    );
    assert!(
        a_record.ends_with(b"\n"),
        "the reference first record is newline-terminated"
    );

    let (mut b_store, mut b_file) = file_logstore();
    b_store.monitor_summary(10_000, &mut Monitor::new());
    flush_all(&mut b_store);
    let successor_record = read_all(&mut b_file);
    let successor_len = successor_record.len();
    assert!(
        successor_len < a_len,
        "the surviving reserved successor is shorter than the full warning record: {successor_len} < {a_len}"
    );
    if cursor_past_successor {
        assert!(
            n > successor_len,
            "a cursor past the successor record end ({n} > {successor_len})"
        );
    } else {
        assert!(
            successor_len > n,
            "a cursor inside the successor record ({successor_len} > {n})"
        );
    }

    let mut subject = LogStore::with_scripted_sink(ScriptedFirst::Partial(
        std::num::NonZeroUsize::new(n).unwrap(),
    ))
    .expect("scripted sink store");
    subject.startup_warning_ctx(1, &name, Family::A, "timeout", None);
    let mut fill_monitor = Monitor::new();
    let mut secs = 10_000u64;
    while subject.len() < QUEUE_SLOTS {
        subject.monitor_summary(secs, &mut fill_monitor);
        secs += 1;
    }
    assert_eq!(
        subject.len(),
        QUEUE_SLOTS,
        "ring full before the partial drain"
    );
    assert_eq!(
        subject.dropped(),
        0,
        "no displacement before the partial drain"
    );

    subject.drain_sink();
    assert_eq!(
        subject.cursor.map(|cursor| cursor.off),
        Some(n),
        "the partial first write leaves the actual cursor at {n}"
    );

    subject.monitor_summary(secs, &mut fill_monitor);
    subject.monitor_summary(secs + 1, &mut fill_monitor);
    assert_eq!(
        subject.dropped(),
        2,
        "two whole-record displacements, front protected, newest eligible reserved fallback"
    );
    assert_eq!(subject.len(), QUEUE_SLOTS, "ring stays at capacity");

    let mut turns = 0usize;
    while subject.len() > 0 && turns < 8 * QUEUE_SLOTS {
        subject.drain_sink();
        turns += 1;
    }
    assert_eq!(subject.len(), 0, "the scripted sink drains the full ring");
    assert_eq!(
        subject.cursor.map(|cursor| cursor.off),
        None,
        "the fully drained ring leaves no residual sink cursor"
    );
    let got = scripted_out(&subject);
    assert_eq!(
        first_record_bytes(got),
        &a_record[..],
        "the emitted first record is the byte-exact full canonical warning record"
    );
    assert_eq!(
        count_windows(got, &successor_record[..]),
        1,
        "the surviving reserved successor is emitted exactly once after the protected front record"
    );
}

mod record_encoding {
    use super::*;

    #[test]
    fn logging_encoder_frames_and_escapes_deterministically() {
        let (mut store, mut file) = file_logstore();
        store.reject(
            7,
            RejectReason::Capacity,
            Some("127.0.0.1:40000".parse().unwrap()),
            Some("sub.example.org"),
        );
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("ascii record");
        let line = text.lines().next().expect("one record");
        assert!(
            line.starts_with(
                "level=warn kind=reject secs=7 reason=\"capacity\" client=\"127.0.0.1:40000\" hostname=\"sub.example.org\""
            ),
            "got: {line}"
        );
        assert!(text.ends_with('\n'), "newline framing ends the record");
    }

    #[test]
    fn logging_encoder_frames_exchange_failed_with_name_and_reason() {
        let (mut store, mut file) = file_logstore();
        store.exchange_failed(7, Some("sub.example.org"), "pin_mismatch", Some(2));
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("ascii record");
        let line = text.lines().next().expect("one record");
        assert!(
            line.starts_with(
                "level=warn kind=exchange_failed secs=7 name=\"sub.example.org\" reason=\"pin_mismatch\" resolver=2"
            ),
            "got: {line}"
        );
    }

    #[test]
    fn logging_encoder_frames_incident_open_with_family_and_reason() {
        let (mut store, mut file) = file_logstore();
        store.incident_open(7, "sub.example.org", Family::Aaaa, "pin_mismatch", Some(0));
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("ascii record");
        let line = text.lines().next().expect("one record");
        assert!(
            line.starts_with(
                "level=warn kind=incident_open secs=7 name=\"sub.example.org\" family=Aaaa reason=\"pin_mismatch\" resolver=0"
            ),
            "got: {line}"
        );
    }

    #[test]
    fn logging_encoder_frames_incident_recovered_with_family_and_duration() {
        let (mut store, mut file) = file_logstore();
        store.incident_recovered(9, "sub.example.org", Family::A, 42, Some(1));
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("ascii record");
        let line = text.lines().next().expect("one record");
        assert!(
            line.starts_with(
                "level=info kind=incident_recovered secs=9 name=\"sub.example.org\" family=A duration=42 resolver=1"
            ),
            "got: {line}"
        );
    }

    #[test]
    fn logging_encoder_exchange_failed_unknown_origin_is_explicit_quoted() {
        let (mut store, mut file) = file_logstore();
        store.exchange_failed(7, Some("sub.example.org"), "pin_mismatch", None);
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("ascii record");
        let line = text.lines().next().expect("one record");
        assert!(
            line.starts_with(
                "level=warn kind=exchange_failed secs=7 name=\"sub.example.org\" reason=\"pin_mismatch\" resolver=\"unknown\""
            ),
            "got: {line}"
        );
    }

    #[test]
    fn logging_encoder_escapes_quote_backslash_and_control_bytes() {
        let mut name = String::new();
        name.push_str("a\"b");
        name.push('\\');
        name.push('\n');
        name.push('\x01');
        name.push_str(".example.org");
        let (mut store, mut file) = file_logstore();
        store.startup_warning_ctx(1, &name, Family::A, "timeout", None);
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("escaped ascii");
        assert!(
            text.contains("name=\"a\\\"b\\\\\\x0a\\x01.example.org\""),
            "deterministic escape of quote/backslash/control: {text:?}"
        );
        assert_eq!(
            text.matches('\\').count(),
            5,
            "five escapes, no raw controls"
        );
        assert!(!text.as_bytes().contains(&b'\n') || text.ends_with('\n'));
    }
}

mod startup_records {
    use super::*;

    #[test]
    fn logging_startup_split_records_fit_widest_legal_config() {
        use crate::config::{ALLOWLIST_MAX, CONFIG_DOC_LIMIT};
        use crate::dns::outcome::{NameOutcome, NotAttemptedReason};
        let (config, doc) = widest_legal_config();
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "widest legal config fits the documented 16384-byte bound: {}",
            doc.len()
        );
        assert_eq!(config.allowlist().len(), ALLOWLIST_MAX);
        let (mut store, mut file) = file_logstore();
        for (ordinal, name) in config.allowlist().iter().enumerate() {
            assert!(
                store.startup_name(
                    u64::MAX,
                    StartupUnresolved {
                        ordinal: u32::try_from(ordinal).expect("allowlist ordinal fits u32"),
                        name: name.as_str(),
                        outcome: NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed),
                    },
                ),
                "per-name record {ordinal} is never dropped at the widest legal input"
            );
        }
        store.startup_final(
            u64::MAX,
            StartupStatus::Failed,
            FinalCounts {
                unresolved: ALLOWLIST_MAX as u64,
                exchanges: 64,
                failed: 64,
                ..FinalCounts::default()
            },
        );
        assert_eq!(
            store.dropped(),
            0,
            "no size-drop for the widest legal configuration"
        );
        flush_all(&mut store);
        let out = read_all(&mut file);
        let records: Vec<&[u8]> = out
            .split(|&b| b == b'\n')
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(
            records.len(),
            ALLOWLIST_MAX + 1,
            "one startup_name record per unresolved name, then the summary"
        );
        for (ordinal, record) in records.iter().enumerate().take(ALLOWLIST_MAX) {
            assert!(
                record.len() < SLOT_BYTES,
                "per-name record {ordinal} incl framing fits the 2 KiB entry: {}",
                record.len()
            );
            let text = std::str::from_utf8(record).expect("ASCII record");
            assert!(
                text.starts_with("level=info kind=startup_name "),
                "each unresolved name is its own startup_name record: {text}"
            );
            assert!(
                text.contains(config.allowlist().get(ordinal).expect("name").as_str()),
                "the full 253-byte FQDN is carried untruncated: {text}"
            );
        }
        let summary = records[ALLOWLIST_MAX];
        assert!(
            summary.starts_with(b"level=info kind=startup_final "),
            "the last record is the summary"
        );
        assert!(
            summary.windows(13).any(|w| w == b"names_dropped")
                && std::str::from_utf8(summary)
                    .expect("ASCII summary")
                    .contains(" names_dropped=0"),
            "the summary carries the per-name drop accounting"
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one measurement table building the worst-case input for every record kind"
    )]
    fn logging_worst_case_record_per_kind_fits_the_slot_with_margin() {
        use crate::dns::incident_report::TypeSummary;
        use crate::dns::outcome::{FailureReason, NotAttemptedReason, ProbeVerdict};
        use crate::enforcement::monitor::Monitor;
        let (config, doc) = widest_legal_config();
        let name = config.allowlist().get(0).expect("widest name").as_str();
        assert_eq!(name.len(), FQDN_MAX_LEN);
        let mut slot = [0u8; SLOT_BYTES];
        let mut worst: Vec<(&str, usize)> = Vec::new();

        let warn = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(Family::Aaaa)),
            Field::new("reason", Val::Str("window_closed")),
            Field::new("context", Val::OptStr(Some("both"))),
        ];
        let warn_bytes =
            encode_record(&mut slot, Level::Warn, Kind::StartupWarning, &warn).expect("fits");
        eprintln!(
            "measured startup_warning worst bytes={warn_bytes} headroom={}",
            SLOT_BYTES - warn_bytes
        );
        worst.push(("startup_warning", warn_bytes));

        worst.push((
            "startup_name",
            encode_record_name(
                &mut slot,
                u64::MAX,
                &StartupUnresolved {
                    ordinal: u32::MAX,
                    name,
                    outcome: NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed),
                },
            )
            .expect("fits"),
        ));

        let summary = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("status", Val::Str("terminated")),
            Field::new("allowance", Val::U64(u64::MAX)),
            Field::new("usable", Val::U64(u64::MAX)),
            Field::new("unresolved", Val::U64(u64::MAX)),
            Field::new("exchanges", Val::U64(u64::MAX)),
            Field::new("failed", Val::U64(u64::MAX)),
            Field::new("not_attempted", Val::U64(u64::MAX)),
            Field::new("dropped", Val::U64(u64::MAX)),
            Field::new("names_dropped", Val::U64(u64::MAX)),
        ];
        worst.push((
            "startup_final",
            encode_record_final(&mut slot, Level::Info, Kind::StartupFinal, &summary)
                .expect("fits"),
        ));

        let fatal_msg = "m".repeat(300);
        let fatal = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("message", Val::Str(&fatal_msg)),
        ];
        worst.push((
            "fatal",
            encode_record(&mut slot, Level::Error, Kind::Fatal, &fatal).expect("fits"),
        ));

        let shutdown = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("status", Val::Str("drained")),
            Field::new("dropped", Val::U64(u64::MAX)),
        ];
        worst.push((
            "shutdown_final",
            encode_record(&mut slot, Level::Info, Kind::ShutdownFinal, &shutdown).expect("fits"),
        ));

        let peer: SocketAddr = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535"
            .parse()
            .expect("widest peer");
        let reject = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("reason", Val::Str("tls_validation")),
            Field::new("client", Val::OptAddr(Some(peer))),
            Field::new("hostname", Val::OptStr(Some(name))),
        ];
        worst.push((
            "reject",
            encode_record(&mut slot, Level::Warn, Kind::Reject, &reject).expect("fits"),
        ));

        let activity = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("hostname", Val::OptStr(Some(name))),
            Field::new("peer", Val::OptAddr(Some(peer))),
            Field::new("activity", Val::Str("reset")),
        ];
        worst.push((
            "early_activity",
            encode_record(&mut slot, Level::Warn, Kind::EarlyActivity, &activity).expect("fits"),
        ));

        let threshold = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("dimension", Val::Str("setups")),
            Field::new("used", Val::U64(u64::MAX)),
            Field::new("cap", Val::U64(u64::MAX)),
        ];
        for (kind_name, kind, level) in [
            ("capacity_high", Kind::CapacityHigh, Level::Error),
            ("capacity_low", Kind::CapacityLow, Level::Info),
            ("queue_high", Kind::QueueHigh, Level::Error),
            ("queue_low", Kind::QueueLow, Level::Info),
        ] {
            worst.push((
                kind_name,
                encode_record(&mut slot, level, kind, &threshold).expect("fits"),
            ));
        }

        let exchange = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("name", Val::OptStr(Some(name))),
            Field::new("reason", Val::Str("pin_mismatch")),
            Field::new("resolver", resolver_val(true, None)),
        ];
        worst.push((
            "exchange_failed",
            encode_record(&mut slot, Level::Warn, Kind::ExchangeFailed, &exchange).expect("fits"),
        ));

        let incident_open = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(Family::Aaaa)),
            Field::new("reason", Val::Str("pin_mismatch")),
            Field::new("resolver", resolver_val(true, None)),
        ];
        worst.push((
            "incident_open",
            encode_record(&mut slot, Level::Warn, Kind::IncidentOpen, &incident_open)
                .expect("fits"),
        ));

        let incident_recovered = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(Family::Aaaa)),
            Field::new("duration", Val::U64(u64::MAX)),
            Field::new("resolver", resolver_val(true, None)),
        ];
        worst.push((
            "incident_recovered",
            encode_record(
                &mut slot,
                Level::Info,
                Kind::IncidentRecovered,
                &incident_recovered,
            )
            .expect("fits"),
        ));

        let incident_summary = IncidentSummary {
            window_start: u64::MAX - 1,
            window_end: u64::MAX,
            duration: 1,
            skipped: u32::MAX,
            overflow: true,
            types: [
                TypeSummary {
                    start: Some(u64::MAX - 1),
                    elapsed: u64::MAX,
                    reason: Some("pin_mismatch"),
                    resolver: None,
                    last_positive: Some(u64::MAX),
                    attempts: u64::MAX,
                    failures: u64::MAX,
                    addrs: u64::MAX,
                    state: "retired",
                    freshness: Some(u64::MAX),
                    retirement: Some(u64::MAX),
                },
                TypeSummary {
                    start: Some(u64::MAX - 1),
                    elapsed: u64::MAX,
                    reason: Some("pin_mismatch"),
                    resolver: None,
                    last_positive: Some(u64::MAX),
                    attempts: u64::MAX,
                    failures: u64::MAX,
                    addrs: u64::MAX,
                    state: "retired",
                    freshness: Some(u64::MAX),
                    retirement: Some(u64::MAX),
                },
            ],
            tunnels: u64::MAX,
            bytes: u64::MAX,
            stale: u64::MAX,
        };
        worst.push((
            "incident_summary",
            encode_record(
                &mut slot,
                Level::Error,
                Kind::IncidentSummary,
                &incident_summary_fields(u64::MAX, name, &incident_summary),
            )
            .expect("fits"),
        ));

        let incident_eligible = [
            Field::new("secs", Val::U64(u64::MAX)),
            Field::new("name", Val::Str(name)),
        ];
        worst.push((
            "incident_eligible_loss",
            encode_record(
                &mut slot,
                Level::Error,
                Kind::IncidentEligibleLoss,
                &incident_eligible,
            )
            .expect("fits"),
        ));
        worst.push((
            "incident_eligible_recovered",
            encode_record(
                &mut slot,
                Level::Info,
                Kind::IncidentEligibleRecovered,
                &incident_eligible,
            )
            .expect("fits"),
        ));

        let mut monitor = Monitor::new();
        monitor.saturate_all_for_test();
        monitor.set_peer_ip_v6_max_for_test();
        monitor.note_serving_stale();
        monitor.note_fact_downgrade_to_plain();
        worst.push((
            "monitor_summary",
            encode_monitor_summary(&mut slot, u64::MAX, &monitor).expect("fits"),
        ));
        let first_two_digit_index = 10usize;
        let mut domain_start = first_two_digit_index;
        worst.push((
            "monitor_domain",
            encode_monitor_domain_batch(&mut slot, u64::MAX, 1, 3, &monitor, &mut domain_start)
                .expect("fits"),
        ));
        let mut capture_start = 0usize;
        worst.push((
            "monitor_capture",
            encode_monitor_capture_batch(&mut slot, u64::MAX, 1, 3, &monitor, &mut capture_start)
                .expect("fits"),
        ));

        let set = config.resolver_set();
        let mut segments = [ResolverProbeSegment {
            index: 0,
            addr: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            fqdn: None,
            pin: false,
            verdict: ProbeVerdict::NotProbed,
        }; crate::dns::resolver::MAX_RESOLVERS];
        for (i, seg) in segments.iter_mut().enumerate() {
            let resolver = set.get(i).expect("widest resolver");
            *seg = ResolverProbeSegment {
                index: u32::try_from(i).expect("resolver index fits u32"),
                addr: resolver.addr(),
                fqdn: resolver.fqdn(),
                pin: resolver.pin().is_some(),
                verdict: ProbeVerdict::Failed(FailureReason::PinMismatch),
            };
        }
        worst.push((
            "resolver_probe",
            encode_record_probe(&mut slot, u64::MAX, &segments).expect("fits"),
        ));

        assert_eq!(worst.len(), 21, "every record kind is measured");
        for (kind_name, len) in &worst {
            eprintln!(
                "worst-case {kind_name:<16} {len:>5} B record, {:>5} B margin",
                SLOT_BYTES - len
            );
            assert!(
                *len < SLOT_BYTES,
                "{kind_name} worst case incl framing fits the 2 KiB entry: {len}"
            );
            if kind_name.starts_with("monitor") {
                assert!(
                    *len <= MONITOR_RECORD_MAX,
                    "{kind_name} worst case fits the 2048 B monitor record bound: {len}"
                );
            }
        }
        let name_len = worst
            .iter()
            .find(|(k, _)| *k == "startup_name")
            .expect("startup_name measured")
            .1;
        assert_eq!(
            name_len, STARTUP_NAME_MAX,
            "the measured startup_name worst case is exactly the const bound"
        );
        let domain_len = worst
            .iter()
            .find(|(k, _)| *k == "monitor_domain")
            .expect("monitor_domain measured")
            .1;
        assert_eq!(
            domain_len, 1870,
            "re-measured monitor_domain worst case: the maximal batch is DOMAIN_BATCH=11 \
             domains whose d<j>* keys all render two-digit indices (10..=20). Every key renders \
             its index in decimal, so a two-digit block costs 164 B against 157 B for a single \
             digit: five 16-byte u32::MAX counters, a 44-byte quoted 36-char d<j>v and a 40-byte \
             quoted 32-hex d<j>p. 66 B framing (30 header + 26 secs + 9 part + newline) plus \
             11 x 164 B = 1870 B is therefore the maximum"
        );
        assert_eq!(
            MONITOR_RECORD_MAX - domain_len,
            178,
            "the per-ordinal peer table leaves monitor_domain 178 B of the 2048 B bound"
        );
        let probe_len = worst
            .iter()
            .find(|(k, _)| *k == "resolver_probe")
            .expect("probe measured")
            .1;
        assert!(
            probe_len <= RESOLVER_PROBE_MAX,
            "measured resolver_probe worst case {probe_len} within the const bound {RESOLVER_PROBE_MAX}"
        );
        let summary_len = worst
            .iter()
            .find(|(k, _)| *k == "incident_summary")
            .expect("summary measured")
            .1;
        assert!(
            summary_len <= 2048,
            "worst unknown resolver-shape incident summary {summary_len} fits the 2048 B record bound"
        );
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "the widest legal document stays inside the config bound: {}",
            doc.len()
        );
    }

    #[test]
    fn logging_startup_name_drop_counts_exactly_once_per_attempt() {
        use crate::dns::outcome::NameOutcome;
        let un = StartupUnresolved {
            ordinal: 0,
            name: "a.example.org",
            outcome: NameOutcome::Negative,
        };
        let (mut full, _file) = file_logstore();
        let mut filled = 0usize;
        while !full.is_full() {
            assert!(full.startup_name(1, un), "filling the queue");
            filled += 1;
            assert!(filled <= QUEUE_SLOTS, "the queue fills within its capacity");
        }
        let before = full.dropped();
        assert!(
            !full.startup_name(1, un),
            "a full queue refuses the per-name record"
        );
        assert_eq!(
            full.dropped(),
            before + 1,
            "a queue-full per-name attempt increments the shared counter once"
        );

        let long = "z".repeat(SLOT_BYTES * 2);
        let (mut store, _file) = file_logstore();
        assert!(
            !store.startup_name(
                1,
                StartupUnresolved {
                    ordinal: 0,
                    name: &long,
                    outcome: NameOutcome::Negative,
                }
            ),
            "an oversize per-name record is dropped whole"
        );
        assert_eq!(
            store.dropped(),
            1,
            "an encode-overflow per-name attempt increments the shared counter once"
        );
        assert_eq!(
            store.len(),
            0,
            "nothing is committed for the dropped record"
        );
    }

    #[test]
    fn logging_startup_split_carries_each_name_outcome_and_reason() {
        use crate::dns::outcome::{FailureReason, NameOutcome, NotAttemptedReason};
        let (mut store, mut file) = file_logstore();
        for un in [
            StartupUnresolved {
                ordinal: 0,
                name: "neg.example.org",
                outcome: NameOutcome::Negative,
            },
            StartupUnresolved {
                ordinal: 1,
                name: "fail.example.org",
                outcome: NameOutcome::Failed(FailureReason::Timeout),
            },
            StartupUnresolved {
                ordinal: 2,
                name: "skip.example.org",
                outcome: NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed),
            },
            StartupUnresolved {
                ordinal: 3,
                name: "expire.example.org",
                outcome: NameOutcome::PositiveUnusable,
            },
            StartupUnresolved {
                ordinal: 4,
                name: "reject.example.org",
                outcome: NameOutcome::Failed(FailureReason::InsufficientAssurance),
            },
        ] {
            assert!(store.startup_name(9, un), "per-name record enqueued");
        }
        store.startup_final(9, StartupStatus::Failed, FinalCounts::default());
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text,
            "level=info kind=startup_name secs=9 ordinal=0 name=\"neg.example.org\" outcome=negative\n\
             level=info kind=startup_name secs=9 ordinal=1 name=\"fail.example.org\" outcome=failed reason=\"timeout\"\n\
             level=info kind=startup_name secs=9 ordinal=2 name=\"skip.example.org\" outcome=not_attempted reason=\"window_closed\"\n\
             level=info kind=startup_name secs=9 ordinal=3 name=\"expire.example.org\" outcome=positive_unusable\n\
             level=info kind=startup_name secs=9 ordinal=4 name=\"reject.example.org\" outcome=failed reason=\"insufficient_assurance\"\n\
             level=info kind=startup_final secs=9 status=\"failure\" allowance=0 usable=0 unresolved=0 exchanges=0 failed=0 not_attempted=0 dropped=0 names_dropped=0\n",
            "each name carries its outcome and reason in its own record, then the summary"
        );
    }
}

mod fatal_grammar {
    use super::*;

    #[test]
    fn logging_fatal_record_exact_grammar() {
        let (mut store, mut file) = file_logstore();
        store.fatal(7, format_args!("serving failed"));
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text, "level=error kind=fatal secs=7 message=\"serving failed\"\n",
            "the fatal record is one error record carrying the bounded message field"
        );
    }
}

mod oversize_drops {
    use super::*;

    #[test]
    fn logging_oversize_record_is_dropped_whole_and_counted() {
        let long = "z".repeat(SLOT_BYTES * 2);
        let (mut store, _file) = file_logstore();
        store.startup_warning_ctx(1, &long, Family::A, "timeout", None);
        assert_eq!(store.dropped(), 1, "oversize record dropped whole");
        assert_eq!(store.len(), 0, "nothing queued for the oversize record");
    }

    #[test]
    fn logging_resolver_probe_embeds_segments_inline_with_reasons() {
        use crate::dns::outcome::FailureReason;
        let b64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let doc = format!(
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1#one.one.one.one\", \"9.9.9.9#dns.quad9.net\", \"8.8.8.8#dns.google#pin-sha256={b64}\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"block\", scope = \"all\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"a.example:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n"
        );
        let config = crate::config::parse_config_document(&doc).expect("valid config");
        let resolvers = config.resolver_set();
        let bare = resolvers.get(0).expect("resolver 0");
        let quad9 = resolvers.get(1).expect("resolver 1");
        let google = resolvers.get(2).expect("resolver 2");
        let (mut store, mut file) = file_logstore();
        store.resolver_probe(
            11,
            &[
                ResolverProbeSegment {
                    index: 0,
                    addr: bare.addr(),
                    fqdn: bare.fqdn(),
                    pin: bare.pin().is_some(),
                    verdict: ProbeVerdict::Ok,
                },
                ResolverProbeSegment {
                    index: 1,
                    addr: quad9.addr(),
                    fqdn: quad9.fqdn(),
                    pin: quad9.pin().is_some(),
                    verdict: ProbeVerdict::Failed(FailureReason::Timeout),
                },
                ResolverProbeSegment {
                    index: 2,
                    addr: google.addr(),
                    fqdn: google.fqdn(),
                    pin: google.pin().is_some(),
                    verdict: ProbeVerdict::NotProbed,
                },
            ],
        );
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text,
            "level=info kind=resolver_probe secs=11 resolver0=\"1.1.1.1\" fqdn0=\"one.one.one.one\" verdict0=ok resolver1=\"9.9.9.9\" fqdn1=\"dns.quad9.net\" verdict1=failed reason1=\"timeout\" resolver2=\"8.8.8.8\" fqdn2=\"dns.google\" pin2=1 verdict2=not_probed\n",
            "single probe record embeds resolver/verdict/reason inline per resolver, no fan-out"
        );
    }

    #[test]
    fn logging_oversize_probe_record_is_dropped_whole_and_counted() {
        use crate::dns::outcome::FailureReason;
        let doc = "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1#dns.google\"]\n[any_illegal]\nconnect_parse = { action = \"notify\", scope = \"connection\" }\nhost_not_allowlisted = { action = \"block\", scope = \"all\" }\ntls_profile = { action = \"block\", scope = \"all\" }\nech = { action = \"block\", scope = \"connection\" }\n[allowed_fqdn.\"a.example:443\"]\nearly_data = { action = \"notify\", scope = \"connection\" }\nja4 = { action = \"notify\", scope = \"connection\" }\ndns_assurance = \"resolver_trusted\"\n";
        let config = crate::config::parse_config_document(doc).expect("valid config");
        let fqdn = config
            .resolver_set()
            .primary()
            .fqdn()
            .expect("fqdn carried");
        // The probe record is structurally bounded (MAX_RESOLVERS × FQDN_MAX_LEN
        // ≪ 2 KiB) for any real resolver set, so the only way to reach the
        // oversize path is a caller-supplied segment set far beyond the slot.
        let segments: Vec<ResolverProbeSegment<'_>> = (0..3000u32)
            .map(|i| ResolverProbeSegment {
                index: i,
                addr: "1.1.1.1".parse().expect("ip"),
                fqdn: Some(fqdn),
                pin: true,
                verdict: ProbeVerdict::Failed(FailureReason::Timeout),
            })
            .collect();
        let (mut store, _file) = file_logstore();
        store.resolver_probe(1, &segments);
        assert_eq!(store.dropped(), 1, "oversize probe record dropped whole");
        assert_eq!(
            store.len(),
            0,
            "nothing queued for the oversize probe record"
        );
    }
}

mod queue_overflow {
    use super::*;

    #[test]
    fn logging_queue_drops_when_full_and_counts() {
        let (mut store, _file) = file_logstore();
        for _ in 0..(QUEUE_SLOTS + 40) {
            store.startup_warning_ctx(1, "sub.example.org", Family::A, "timeout", None);
        }
        assert!(store.is_full(), "queue must be full after overfilling");
        assert_eq!(store.len(), QUEUE_SLOTS, "capacity never exceeds the bound");
        assert_eq!(
            store.dropped(),
            41,
            "296 warnings + 1 high edge on a 256-slot queue: whole-record drops are counted exactly (review M6)"
        );
        assert!(!store.dropped_overflow());
    }

    #[test]
    fn logging_drop_counter_saturation_sets_overflow_state() {
        let (mut store, _file) = file_logstore();
        store.saturate_dropped_for_test();
        store.startup_warning_ctx(1, "sub.example.org", Family::A, "timeout", None);
        assert_eq!(
            store.dropped(),
            u64::MAX,
            "drop count saturates, never wraps"
        );
        assert!(store.dropped_overflow(), "overflow flag latches");
    }

    #[test]
    fn logging_enqueue_fallible_err_commits_nothing_and_counts_nothing() {
        let (mut store, _file) = file_logstore();
        assert!(
            store.enqueue_normal(|slot| {
                let seed: &[u8] = b"level=info kind=fallible_seed ok\n";
                slot[..seed.len()].copy_from_slice(seed);
                Some(seed.len())
            }),
            "seed record queued"
        );
        let committed = store.len();
        let dropped = store.dropped();
        let r = store.enqueue_fallible(|slot| {
            slot[..5].copy_from_slice(b"dirty");
            Err("boom")
        });
        assert_eq!(
            r,
            Err("boom"),
            "encoder error is surfaced, not folded into a drop"
        );
        assert_eq!(store.len(), committed, "a failed encode commits no record");
        assert_eq!(store.dropped(), dropped, "a failed encode counts no drop");
        assert_eq!(
            store.last_record_bytes(),
            Some(b"level=info kind=fallible_seed ok\n".as_slice()),
            "the seed record stays the last committed record after the failed attempt"
        );
        assert!(!store.dropped_overflow());
    }

    #[test]
    fn logging_enqueue_fallible_success_commits_and_full_queue_drops_whole() {
        let (mut store, _file) = file_logstore();
        let record: &[u8] = b"level=info kind=fallible_record ok\n";
        assert!(record.len() < SLOT_BYTES, "payload fits the record slot");
        assert_eq!(
            store.enqueue_fallible(move |slot| {
                slot[..record.len()].copy_from_slice(record);
                Ok::<Option<usize>, &'static str>(Some(record.len()))
            }),
            Ok(true),
            "a successful typed enqueue commits"
        );
        assert_eq!(store.len(), 1, "one record committed");
        assert_eq!(store.dropped(), 0, "no drop on success");
        assert_eq!(
            store.last_record_bytes(),
            Some(record),
            "committed bytes are exact"
        );
        for _ in 1..QUEUE_SLOTS {
            assert!(
                store.enqueue_normal(|slot| {
                    let p: &[u8] = b"level=info kind=fallible_record ok\n";
                    slot[..p.len()].copy_from_slice(p);
                    Some(p.len())
                }),
                "ring fills to capacity"
            );
        }
        assert!(store.is_full(), "ring holds QUEUE_SLOTS records");
        let before = store.dropped();
        let r = store.enqueue_fallible(|_slot| Err("must not run on a full ring"));
        assert_eq!(
            r,
            Ok(false),
            "a full ring drops whole without running the encoder"
        );
        assert_eq!(
            store.dropped(),
            before + 1,
            "one attempt drop counted on the full ring"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "capacity never exceeds the bound");
        assert!(!store.dropped_overflow());
    }

    #[test]
    fn logging_enqueue_assurance_real_frame_metadata_and_typed_bound() {
        use crate::runtime::storage::ServeStorage;
        use std::time::Instant;
        const DNS_EPOCH: u64 = 1_700_000_000;
        let (config, _doc) = widest_legal_config();
        let mut owner = ServeStorage::boot(&config).expect("same-allowlist owner");
        let (mut store, _file) = file_logstore();
        let fqdn = config.allowlist().get(0).expect("widest owner");
        let epoch = Instant::now();
        owner.mount_clock(epoch, DNS_EPOCH);
        let snapshot = owner.capture_assurance(0, epoch).expect("owner snapshot");
        store.set_now(DNS_EPOCH + 100);
        let result = store.enqueue_assurance(
            &snapshot,
            u64::MAX,
            crate::log::encoding::AssurancePhase::Boot,
        );
        assert!(result, "real owner frame enqueued: {result:?}");
        let text = std::str::from_utf8(store.last_record_bytes().expect("committed frame"))
            .expect("ASCII frame");
        assert!(
            text.starts_with("level=info kind=dns_assurance name=\"") && text.ends_with('\n'),
            "canonical header via write_header and newline terminator: {text}"
        );
        assert!(
            text.contains(&format!(" secs={} seq={} phase=boot", DNS_EPOCH, u64::MAX)),
            "real secs from the bound view's mounted clock, sequence/phase in the one record: {text}"
        );
        assert!(
            text.contains(fqdn.as_str()) && text.contains("port=443"),
            "typed Fqdn name+port payload intact"
        );
        assert!(text.contains("a_retained=") && text.contains("aaaa_retained="));
        assert_eq!(
            store.secs,
            DNS_EPOCH + 100,
            "delayed event must not rewind the queue clock"
        );
        assert!(
            text.len() < SLOT_BYTES,
            "widest owner frame incl header/metadata fits the 2 KiB slot: {}",
            text.len()
        );
    }

    #[test]
    fn logging_enqueue_assurance_typed_lookup_error_and_full_drop_counted() {
        use crate::runtime::storage::ServeStorage;
        use std::time::Instant;
        const DNS_EPOCH: u64 = 1_700_000_000;
        let (config, _doc) = widest_legal_config();
        let mut owner = ServeStorage::boot(&config).expect("same-allowlist owner");
        let (mut store, _file) = file_logstore();
        let epoch = Instant::now();
        owner.mount_clock(epoch, DNS_EPOCH);
        let before_len = store.len();
        let before_dropped = store.dropped();
        let err = owner.capture_assurance(config.allowlist().len(), epoch);
        assert!(
            matches!(err, Err(crate::dns::cache::CacheError::NameOutOfRange)),
            "out-of-allowlist ordinal is a typed Err, never a counted drop"
        );
        assert_eq!(
            store.len(),
            before_len,
            "no record from the failed owner lookup"
        );
        assert_eq!(
            store.dropped(),
            before_dropped,
            "lookup error counts no drop"
        );
        for _ in 0..QUEUE_SLOTS {
            assert!(store.enqueue_normal(|slot| {
                let p: &[u8] = b"level=info kind=fill ok\n";
                slot[..p.len()].copy_from_slice(p);
                Some(p.len())
            }));
        }
        assert!(store.is_full(), "ring at capacity");
        let before = store.dropped();
        let snapshot = owner.capture_assurance(0, epoch).expect("owner snapshot");
        let full =
            store.enqueue_assurance(&snapshot, 2, crate::log::encoding::AssurancePhase::Change);
        assert!(!full, "a full ring drops whole");
        assert_eq!(store.dropped(), before + 1, "one attempt drop counted");
        assert_eq!(store.len(), QUEUE_SLOTS, "capacity bound holds");
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn widest_owner_snapshot_capture_and_enqueue_spends_zero_allocations() {
        use crate::alloc::{Phase, run_phase};
        use crate::dns::cache::CacheError;
        use crate::runtime::storage::ServeStorage;
        use std::time::Instant;
        let (config, _) = widest_legal_config();
        let mut owner = ServeStorage::boot(&config).expect("widest owner");
        let (mut store, _file) = file_logstore();
        let epoch = Instant::now();
        owner.mount_clock(epoch, 1_700_000_000);
        let (result, counts) = run_phase(Phase::Logging, || {
            let snapshot = owner.capture_assurance(0, epoch)?;
            Ok::<bool, CacheError>(store.enqueue_assurance(
                &snapshot,
                u64::MAX,
                crate::log::encoding::AssurancePhase::Boot,
            ))
        });
        assert_eq!(result, Ok(true));
        assert!(
            counts.all_zero(),
            "widest snapshot capture and enqueue: {counts:?}"
        );
    }

    #[test]
    fn logging_threshold_high_then_low_edges() {
        let (mut store, mut file) = file_logstore();
        for used in 0..=410usize {
            store.note_capacity(1, used, 0);
        }
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=capacity_high secs=1 dimension=\"slots\" used=410 cap=512"),
            "high edge at first exceed of 80%: {text}"
        );
        assert!(
            !text.contains("kind=capacity_low"),
            "no low edge before any high edge"
        );
        store.note_capacity(2, 358, 0);
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=capacity_low secs=2 dimension=\"slots\" used=358 cap=512"),
            "low edge after crossing below 70%: {text}"
        );
    }

    #[test]
    fn logging_early_activity_exact_record_unique_keys() {
        let (mut store, mut file) = file_logstore();
        store.early_activity(
            4,
            Some("sub.example.org"),
            Some("127.0.0.1:40000".parse().unwrap()),
            ActivityKind::Data,
        );
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text,
            "level=warn kind=early_activity secs=4 hostname=\"sub.example.org\" peer=\"127.0.0.1:40000\" activity=\"data\"\n",
            "exact early-activity record, no duplicate kind key (review R3/M1)"
        );
        assert_eq!(
            text.matches("kind=").count(),
            1,
            "the record key kind appears exactly once"
        );
    }

    #[test]
    fn logging_queue_threshold_edges_real_secs_on_enqueue_and_drain() {
        let (mut store, mut file) = file_logstore();
        for _ in 0..249 {
            store.startup_warning_ctx(100, "sub.example.org", Family::A, "timeout", None);
        }
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=queue_high secs=100 dimension=\"queue\" used=205 cap=256"),
            "high edge at first exceed of 80% with the enqueue secs: {text}"
        );
        assert_eq!(
            store.dropped(),
            0,
            "204.8 threshold crossing must not drop records"
        );
        assert!(
            text.contains("kind=queue_low"),
            "low edge present after drain: {text}"
        );
        let low_line = text.lines().find(|l| l.contains("kind=queue_low")).unwrap();
        let exp = "kind=queue_low secs=";
        let idx = low_line.find(exp).expect("low edge has real secs");
        assert!(
            low_line[idx..].starts_with(exp) && !low_line[idx + exp.len()..].starts_with('0'),
            "low edge carries the real monotonic sec (review M3), got: {low_line}"
        );
    }
}

mod sink_budget {
    use super::*;

    #[test]
    fn logging_sink_budget_binds_on_ops_then_bytes() {
        let (mut store, mut file) = file_logstore();
        let filler = "filler.example.org";
        for _ in 0..(SINK_MAX_BYTES / 512) {
            store.startup_warning_ctx(1, filler, Family::A, "timeout", None);
        }
        store.drain_sink();
        assert!(
            store.sink_ops() <= SINK_MAX_OPS,
            "op cap bounds one turn: {} ops",
            store.sink_ops()
        );
        let out = read_all(&mut file);
        assert!(
            out.len() <= SINK_MAX_BYTES,
            "byte cap bounds one turn: {}",
            out.len()
        );
        assert!(
            store.len() > 0,
            "unspent records stay queued for a later turn"
        );
        flush_all(&mut store);
        assert_eq!(store.len(), 0, "later turns flush the remainder");
    }
}

mod monitor_queue {
    use super::*;

    #[test]
    fn logging_monitor_full_queue_tallies_refused_detail_batches_per_class() {
        use crate::enforcement::monitor::{CapturedDetail, SlotCapture};
        let (mut store, _file) = file_logstore();
        for _ in 0..QUEUE_SLOTS {
            store.startup_warning_ctx(1, "sub.example.org", Family::A, "timeout", None);
        }
        assert!(store.is_full(), "ring is full before the monitor summary");
        let mut m = Monitor::new();
        for index in 0..(2 * DOMAIN_BATCH) {
            m.note_fact_early_data(DomainOrdinal::from_index(index).expect("ordinal in range"));
        }
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        for i in 0..(CAPTURE_BATCH + 1) {
            m.note_consumed_capture(SlotCapture {
                slot: i,
                generation: 1,
                detail: Some(CapturedDetail {
                    fact: CapturedFact::AnyIllegal(cause),
                    effect,
                }),
            });
        }
        let domain_batches = count_domain_batches(&m);
        let capture_batches = count_capture_batches(&m);
        assert_eq!(
            domain_batches, 2,
            "22 nonzero ordinals pack into 2 monitor_domain batches at 11 ordinals each"
        );
        assert_eq!(
            capture_batches, 2,
            "23 captures pack into 2 monitor_capture batches at 22 details each"
        );
        let dropped_before = store.dropped();
        assert!(
            store.monitor_summary(9, &mut m),
            "the reserved summary always commits (displaces a normal record on a full ring)"
        );
        assert_eq!(
            m.report_drops(),
            2,
            "RC2 F1: one report_drop per refused monitor_domain batch — exactly 2 batches on this full queue"
        );
        assert_eq!(
            m.capture_drops(),
            2,
            "RC3 F1: one capture_drop per refused monitor_capture batch — exactly 2 batches on this full queue"
        );
        assert_eq!(
            store.dropped(),
            dropped_before + 1 + u64::from(domain_batches + capture_batches),
            "whole-record accounting: the reserved displacement plus one generic drop per refused detail batch (no silent loss)"
        );
    }

    /// Every line of `text` that is a record of `kind`: the leading
    /// `level=info kind=` header excludes the longer detail-batch kinds.
    fn records_of_kind<'a>(text: &'a str, kind: &str) -> Vec<&'a str> {
        let header = format!("level=info kind={kind} ");
        text.lines()
            .filter(|line| line.starts_with(&header))
            .collect()
    }

    #[test]
    fn logging_monitor_summary_carries_the_domain_loss_it_causes() {
        let (mut store, mut file) = file_logstore();
        let mut guard = 0usize;
        while store.len() < QUEUE_SLOTS - 2 && guard < 8 * QUEUE_SLOTS {
            store.startup_warning_ctx(1, "sub.example.org", Family::A, "timeout", None);
            guard += 1;
        }
        assert_eq!(
            store.len(),
            QUEUE_SLOTS - 2,
            "two free slots: one for the reserved summary, one for a single detail batch"
        );
        let mut m = Monitor::new();
        for index in 0..=DOMAIN_BATCH {
            m.note_fact_early_data(DomainOrdinal::from_index(index).expect("ordinal in range"));
        }
        assert_eq!(
            count_domain_batches(&m),
            2,
            "DOMAIN_BATCH+1 nonzero ordinals need two monitor_domain batches"
        );
        let dropped_before = store.dropped();
        assert!(
            store.monitor_summary(9, &mut m),
            "the reserved summary commits into a free slot without displacing"
        );
        assert_eq!(
            store.len(),
            QUEUE_SLOTS,
            "the summary plus the one admitted detail batch fill the ring"
        );
        assert_eq!(
            m.report_drops(),
            1,
            "the second domain batch cannot be admitted: one report-time loss"
        );
        assert_eq!(
            store.dropped(),
            dropped_before + 1,
            "the refused batch is still a whole-record drop"
        );
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).expect("utf8 records");
        let summary = records_of_kind(&text, "monitor");
        assert_eq!(summary.len(), 1, "exactly one summary in this window");
        assert!(
            summary[0].contains(" report_drops=1 "),
            "the summary that reports the loss is the one that caused it: {}",
            summary[0]
        );
        let admitted = records_of_kind(&text, "monitor_domain");
        assert_eq!(
            admitted.len(),
            1,
            "only the admitted batch reaches the sink: {text}"
        );
        assert!(
            admitted[0].contains(" part=1/2 "),
            "the admitted batch keeps its position in the full batch set: {}",
            admitted[0]
        );

        let first_len = text.len();
        assert!(
            store.monitor_summary(10, &mut m),
            "the follow-up summary commits into the drained ring"
        );
        assert_eq!(
            store.dropped(),
            dropped_before + 1,
            "a summary that loses nothing drops nothing"
        );
        assert_eq!(
            m.report_drops(),
            1,
            "the same loss is never accounted twice"
        );
        flush_all(&mut store);
        let follow_up_text = String::from_utf8(read_all(&mut file)).expect("utf8 records");
        let follow_up_text = &follow_up_text[first_len..];
        let follow_up = records_of_kind(follow_up_text, "monitor");
        assert_eq!(follow_up.len(), 1, "exactly one follow-up summary");
        assert!(
            follow_up[0].contains(" report_drops=1 "),
            "the follow-up carries the already-delivered total, never a phantom loss: {}",
            follow_up[0]
        );
        let parts = records_of_kind(follow_up_text, "monitor_domain");
        assert_eq!(parts.len(), 2, "both batches fit the drained ring");
        assert!(
            parts[0].contains(" part=1/2 "),
            "first admitted batch stays 1/2: {}",
            parts[0]
        );
        assert!(
            parts[1].contains(" part=2/2 "),
            "the cursor resumes at the next batch and stays 2/2: {}",
            parts[1]
        );
    }

    #[test]
    fn logging_monitor_summary_carries_the_capture_loss_it_causes() {
        use crate::enforcement::monitor::{CapturedDetail, SlotCapture};
        let (mut store, mut file) = file_logstore();
        let mut guard = 0usize;
        while store.len() < QUEUE_SLOTS - 2 && guard < 8 * QUEUE_SLOTS {
            store.startup_warning_ctx(1, "sub.example.org", Family::A, "timeout", None);
            guard += 1;
        }
        assert_eq!(store.len(), QUEUE_SLOTS - 2, "one spare detail slot");
        let mut m = Monitor::new();
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        for i in 0..=CAPTURE_BATCH {
            m.note_consumed_capture(SlotCapture {
                slot: i,
                generation: 1,
                detail: Some(CapturedDetail {
                    fact: CapturedFact::AnyIllegal(cause),
                    effect,
                }),
            });
        }
        assert_eq!(
            count_capture_batches(&m),
            2,
            "CAPTURE_BATCH+1 captures need two monitor_capture batches"
        );
        assert_eq!(
            count_domain_batches(&m),
            0,
            "no domain detail in this window"
        );
        let dropped_before = store.dropped();
        assert!(store.monitor_summary(9, &mut m), "summary commits");
        assert_eq!(
            m.capture_drops(),
            1,
            "the refused capture batch keeps its own suppressed-detail channel"
        );
        assert_eq!(
            m.report_drops(),
            0,
            "a refused capture batch is never a domain report_drop"
        );
        assert_eq!(
            store.dropped(),
            dropped_before + 1,
            "the refused capture batch is one whole-record drop"
        );
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).expect("utf8 records");
        let summary = records_of_kind(&text, "monitor");
        assert_eq!(summary.len(), 1, "exactly one summary");
        assert!(
            summary[0].contains(" capture_drops=1 ") && summary[0].contains(" report_drops=0 "),
            "the summary carries the projected capture loss on its own counter: {}",
            summary[0]
        );
        let admitted = records_of_kind(&text, "monitor_capture");
        assert_eq!(
            admitted.len(),
            1,
            "only the admitted batch reaches the sink"
        );
        assert!(
            admitted[0].contains(" part=1/2 "),
            "the admitted batch keeps its position in the full batch set: {}",
            admitted[0]
        );
    }

    #[test]
    fn logging_monitor_queued_capture_batch_stranded_on_sink_failure_is_generic_drop() {
        use crate::enforcement::monitor::{CapturedDetail, SlotCapture};
        let (reader, writer) = UnixStream::pair().expect("socketpair");
        drop(reader);
        let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
        let mut m = Monitor::new();
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        for i in 0..CAPTURE_BATCH {
            m.note_consumed_capture(SlotCapture {
                slot: i,
                generation: 1,
                detail: Some(CapturedDetail {
                    fact: CapturedFact::AnyIllegal(cause),
                    effect,
                }),
            });
        }
        assert_eq!(
            count_capture_batches(&m),
            1,
            "22 captures pack into a single monitor_capture batch"
        );
        assert!(
            store.monitor_summary(9, &mut m),
            "the detail batch enqueues while the sink is still healthy"
        );
        assert_eq!(
            m.capture_drops(),
            0,
            "a successfully queued detail batch is never a capture_drop"
        );
        assert_eq!(m.report_drops(), 0, "and never a report_drop either");
        assert_eq!(
            store.len(),
            2,
            "reserved summary plus one capture detail batch are queued"
        );
        let dropped_before = store.dropped();
        store.drain_sink();
        assert!(store.sink_has_failed(), "EPIPE latches the sink failed");
        assert_eq!(
            store.len(),
            0,
            "stranded records are cleared, never retained"
        );
        assert_eq!(
            store.dropped(),
            dropped_before + 2,
            "RC4 F4-F7: an already-queued detail batch stranded at drain is counted as a whole-record drop"
        );
        assert_eq!(
            m.capture_drops(),
            0,
            "capture_drops untouched: drain_sink's whole-record drop path is type-separated from the monitor counters (unit-split pin, not a runtime call)"
        );
        let _ = writer;
    }

    #[test]
    fn logging_strand_queued_counts_forced_summary_residue_never_monitor_drops() {
        use crate::enforcement::monitor::{CapturedDetail, SlotCapture};
        let (mut store, _file) = file_logstore();
        let mut m = Monitor::new();
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        for i in 0..CAPTURE_BATCH {
            m.note_consumed_capture(SlotCapture {
                slot: i,
                generation: 1,
                detail: Some(CapturedDetail {
                    fact: CapturedFact::AnyIllegal(cause),
                    effect,
                }),
            });
        }
        assert!(
            store.monitor_summary(9, &mut m),
            "the forced monitor summary commits like the shutdown forced-report path"
        );
        assert_eq!(
            store.len(),
            2,
            "reserved summary plus one capture detail batch are queued"
        );
        let dropped_before = store.dropped();
        let stranded = store.strand_queued();
        assert_eq!(stranded, 2, "the exit path strands every queued record");
        assert_eq!(
            store.dropped(),
            dropped_before + 2,
            "stranded residue (incl. a forced shutdown summary) is counted once as whole-record drops, never silently lost (L18)"
        );
        assert_eq!(
            m.capture_drops(),
            0,
            "capture_drops untouched: strand_queued takes only &mut LogStore, so the monitor counters are type-separated here (mechanism-level pin, not call-site)"
        );
        assert_eq!(
            m.report_drops(),
            0,
            "report_drops untouched: type-separated from LogStore::strand_queued by its signature"
        );
        assert_eq!(store.len(), 0, "queue is empty after stranding");
    }
}

mod monitor_records {
    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn logging_monitor_summary_exact_grammar_and_zero_suppression() {
        use crate::eligibility::NumericAddr;
        use crate::enforcement::action::{DomainOrdinal, Scope};
        use crate::enforcement::monitor::{DnsAnomalyKind, Monitor};
        use crate::enforcement::policy::UnknownReason;
        use std::net::Ipv4Addr;
        let mut m = Monitor::new();
        m.note_fact_any_illegal(crate::enforcement::policy::AnyIllegalCause::HostNotAllowlisted);
        m.note_fact_any_illegal(crate::enforcement::policy::AnyIllegalCause::HostNotAllowlisted);
        m.note_fact_unknown(UnknownReason::Unattributed);
        m.note_fact_resolver_degraded();
        m.note_fact_dns_anomaly(DnsAnomalyKind::BailiwickViolation);
        let ordinal = DomainOrdinal::from_index(0).expect("bound-level ordinal");
        m.note_fact_early_data(ordinal);
        m.note_fact_expired_pin_cert();
        m.note_fact_ja4_seed();
        m.note_fact_ja4_change(
            ordinal,
            *b"t13d1516h2_8daaf6152771_02713d6af862",
            NumericAddr::V4(Ipv4Addr::from([203, 0, 113, 1])),
        );
        m.note_fact_ja4_change_loss(ordinal);
        m.note_action_first_slot_block(Scope::Connection);
        m.note_action_domain_block(ordinal);
        m.note_action_notify(ordinal);
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text,
            "level=info kind=monitor secs=7 facts_total=9 actions_total=3 refusals_total=0 \
             ofacts=0 oactions=0 orefusals=0 report_drops=0 oreport_drops=0 capture_drops=0 \
             ocapture_drops=0 s0=1 s1=0 ba=0 rd=1 ep=1 js=1 bv=1 \
             c15=2 unk3=1 dx=1\n\
             level=info kind=monitor_domain secs=7 part=1/1 d0f=1 d0b=1 d0n=1 d0j=1 \
             d0v=\"t13d1516h2_8daaf6152771_02713d6af862\" d0p=\"cb007101\"\n",
            "exact monitor grammar: the summary carries the fixed core and dx bitset, the single nonzero domain block rides its monitor_domain batch"
        );
        assert!(
            text.contains(" rd=1"),
            "the resolver-degraded fact key carries its fold: {text}"
        );
        assert!(
            !text.contains("rd=0"),
            "a zero resolver-degraded fold stays suppressed: {text}"
        );
        assert!(
            text.contains(" ep=1"),
            "the expired-pin-cert fact key carries its fold: {text}"
        );
        assert!(
            !text.contains("ep=0"),
            "a zero expired-pin-cert fold stays suppressed: {text}"
        );
        assert!(
            text.contains(" rd=1 ep=1 js=1 bv=1"),
            "the expired-pin fold and ja4-seed fold follow the resolver-degraded fold, then the dns-anomaly `bv` key: {text}"
        );
        assert!(
            text.contains(" js=1"),
            "the ja4-seed fact key carries its fold: {text}"
        );
        assert!(
            text.contains(" bv=1"),
            "the bailiwick-violation anomaly key carries its fold: {text}"
        );
        assert!(
            !text.contains("rpm="),
            "a zero ResolverPeerMismatch fold stays suppressed: {text}"
        );
        assert!(
            !text.contains("xttl="),
            "a zero ExtremeTtl fold stays suppressed: {text}"
        );
        assert!(
            text.contains(" c15=2"),
            "the AnyIllegal cause index 15 (HostNotAllowlisted) carries its fold: {text}"
        );
        assert!(
            text.contains("unk3=1"),
            "the Unattributed unknown reason index 3 carries its fold: {text}"
        );
        assert!(
            !text.contains("c0="),
            "zero causes stay suppressed (no c0 key)"
        );
        assert!(!text.contains(" d0="), "M4: no empty-valued d0 marker key");
        assert!(
            !text.contains(" r=1"),
            "M4: per-field zero-suppression drops the zero refusal field"
        );
        assert!(
            text.contains(" d0j=1"),
            "the per-ordinal ja4-change fold carries its key: {text}"
        );
        assert!(
            text.contains(" d0v=\"t13d1516h2_8daaf6152771_02713d6af862\""),
            "the per-ordinal ja4-change value carries the 36-char JA4: {text}"
        );
        assert!(
            text.contains(" d0p=\"cb007101\""),
            "the latest-overflow ordinal's peer IP rides beside the ja4-change value: {text}"
        );
        assert!(
            !text.contains("d1j="),
            "a zero ja4-change fold on another ordinal stays suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_domain_ja4_changes_carry_each_ordinals_own_peer() {
        use crate::eligibility::NumericAddr;
        use crate::enforcement::action::DomainOrdinal;
        use crate::enforcement::monitor::Monitor;
        use std::net::{Ipv4Addr, Ipv6Addr};
        let mut m = Monitor::new();
        let first = DomainOrdinal::from_index(0).expect("bound-level ordinal");
        let second = DomainOrdinal::from_index(1).expect("bound-level ordinal");
        m.note_fact_ja4_change(
            first,
            *b"t13d1516h2_8daaf6152771_02713d6af862",
            NumericAddr::V4(Ipv4Addr::from([203, 0, 113, 5])),
        );
        m.note_fact_ja4_change(
            second,
            *b"t13d1516h2_8daaf6152771_02713d6af863",
            NumericAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
        );
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains(" d0p=\"cb007105\""),
            "the first ordinal's change carries its own triggering peer: {text}"
        );
        assert!(
            text.contains(" d1p=\"20010db8000000000000000000000001\""),
            "the second ordinal's change carries its own triggering peer: {text}"
        );
    }

    #[test]
    fn logging_monitor_summary_emits_positive_rpm_and_xttl() {
        use crate::enforcement::monitor::{DnsAnomalyKind, Monitor};
        let mut m = Monitor::new();
        m.note_fact_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch);
        m.note_fact_dns_anomaly(DnsAnomalyKind::ResolverPeerMismatch);
        m.note_fact_dns_anomaly(DnsAnomalyKind::ExtremeTtl);
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains(" rpm=2"),
            "the resolver-peer-mismatch anomaly key carries its fold: {text}"
        );
        assert!(
            text.contains(" xttl=1"),
            "the extreme-ttl anomaly key carries its fold: {text}"
        );
    }

    #[cfg(test)]
    #[test]
    fn logging_monitor_all_saturated_record_fits_the_2k_slot() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.saturate_all_for_test();
        assert!(
            m.capture_detail_len() == crate::enforcement::monitor::CAPTURE_DETAIL_LEN,
            "the worst-case fixture fills the whole correlated-detail ring"
        );
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        for line in text.lines() {
            assert!(
                line.len() + 1 < SLOT_BYTES,
                "every emitted record stays inside the 2 KiB slot: {} bytes in {line}",
                line.len() + 1
            );
        }
        assert!(
            text.contains("ofacts=1"),
            "saturation latches the aggregate overflow flags: {text}"
        );
        assert!(
            text.contains("ocapture_drops=1"),
            "correlated-detail loss latches its own overflow: {text}"
        );
        assert!(
            text.contains("x0g="),
            "the correlated-detail section is emitted once captures exist: {text}"
        );
        assert!(
            text.contains("x0s=511"),
            "the all-saturated capture ring carries its worst legal slot identity: {text}"
        );
        assert!(
            text.contains(" sn=32"),
            "the saturated sustained-negatives level is emitted: {text}"
        );
        assert!(
            text.contains(" js=4294967295"),
            "the saturated ja4-seed fold is emitted: {text}"
        );
        assert!(
            text.contains(" d31p=\"cb007101\""),
            "saturation keys the latest-overflow peer IP to the last ordinal: {text}"
        );
    }

    #[test]
    fn logging_monitor_all_saturated_with_serving_stale_fits_the_2k_slot() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.saturate_all_for_test();
        m.note_serving_stale();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        for line in text.lines() {
            assert!(
                line.len() + 1 < SLOT_BYTES,
                "every emitted record stays inside the 2 KiB slot: {} bytes in {line}",
                line.len() + 1
            );
        }
        assert!(
            text.contains(" ss=1"),
            "the latched stale-serving bit survives the saturated record: {text}"
        );
        assert!(
            text.contains(" sn=32"),
            "the saturated sustained-negatives level survives the saturated record: {text}"
        );
        assert!(
            text.contains(" js=4294967295"),
            "the saturated ja4-seed fold survives the saturated record: {text}"
        );
        assert!(
            text.contains(" d31p=\"cb007101\""),
            "the latest-overflow peer IP survives the saturated record: {text}"
        );
    }

    #[test]
    fn logging_monitor_family_each_record_fits_monitor_record_max() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.saturate_all_for_test();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            7,
            "the saturated family is one summary plus 3 domain and 3 capture batches: {text}"
        );
        let mut summaries = 0;
        let mut domains = 0;
        let mut captures = 0;
        for line in &lines {
            assert!(
                line.len() + 1 < MONITOR_RECORD_MAX,
                "every family record stays under the 2048 B cap: {} bytes in {line}",
                line.len() + 1
            );
            if line.starts_with("level=info kind=monitor ") {
                summaries += 1;
            } else if line.starts_with("level=info kind=monitor_domain ") {
                domains += 1;
            } else if line.starts_with("level=info kind=monitor_capture ") {
                captures += 1;
            }
        }
        assert_eq!(summaries, 1, "exactly one summary record");
        assert_eq!(
            domains, 3,
            "32 saturated ordinals pack into 3 domain batches"
        );
        assert_eq!(
            captures, 3,
            "64 saturated details pack into 3 capture batches"
        );
        let mut parts: Vec<&str> = lines
            .iter()
            .filter(|l| l.starts_with("level=info kind=monitor_domain "))
            .map(|l| {
                l.split(" part=")
                    .nth(1)
                    .expect("part field")
                    .split(' ')
                    .next()
                    .expect("part token")
            })
            .collect();
        parts.sort_unstable();
        assert_eq!(
            parts,
            vec!["1/3", "2/3", "3/3"],
            "domain batches carry sequential part=n/total markers"
        );
        let mut capture_parts: Vec<&str> = lines
            .iter()
            .filter(|l| l.starts_with("level=info kind=monitor_capture "))
            .map(|l| {
                l.split(" part=")
                    .nth(1)
                    .expect("part field")
                    .split(' ')
                    .next()
                    .expect("part token")
            })
            .collect();
        capture_parts.sort_unstable();
        assert_eq!(
            capture_parts,
            vec!["1/3", "2/3", "3/3"],
            "capture batches carry sequential part=n/total markers"
        );
    }

    #[cfg(test)]
    #[test]
    fn logging_monitor_emits_distinct_slot_identity_for_equal_generation_slots() {
        use crate::enforcement::monitor::{CapturedDetail, SlotCapture};
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        let cap = |slot, generation| SlotCapture {
            slot,
            generation,
            detail: Some(CapturedDetail {
                fact: CapturedFact::AnyIllegal(cause),
                effect,
            }),
        };
        let mut m = Monitor::new();
        m.note_consumed_capture(cap(0, 1));
        m.note_consumed_capture(cap(1, 1));
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("x0s=0") && text.contains("x1s=1"),
            "H1': the encoded identity carries each capture's actual slot: {text}"
        );
        assert!(
            text.contains("x0g=1") && text.contains("x1g=1"),
            "H1': both slots share the equal per-slot generation: {text}"
        );
        assert!(
            text.contains("x0t=a15") && text.contains("x1t=a15"),
            "H1': both captures emit their typed fact: {text}"
        );
        assert!(
            text.contains("x0a=blk:c") && text.contains("x1a=blk:c"),
            "H1': both captures emit their applied effect: {text}"
        );
    }

    #[test]
    fn logging_monitor_summary_on_full_ring_preserves_the_shutdown_verdict() {
        use crate::enforcement::monitor::Monitor;
        use crate::enforcement::policy::UnknownReason;
        let (mut store, mut file) = file_logstore();
        let mut warnings = 0usize;
        while store.len() < QUEUE_SLOTS - 1 && warnings < 8 * QUEUE_SLOTS {
            store.startup_warning_ctx(100, "sub.example.org", Family::A, "timeout", None);
            warnings += 1;
        }
        assert_eq!(store.len(), QUEUE_SLOTS - 1, "fill leaves one free slot");
        store.shutdown_final(101, ShutdownStatus::Drained, store.dropped());
        assert_eq!(
            store.len(),
            QUEUE_SLOTS,
            "the shutdown verdict holds the last free ring slot"
        );
        let dropped_before = store.dropped();
        let mut m = Monitor::new();
        m.note_fact_unknown(UnknownReason::Unattributed);
        assert!(
            store.monitor_summary(101, &mut m),
            "a reserved monitor summary is admitted even on a full ring"
        );
        assert_eq!(
            store.dropped(),
            dropped_before + 1,
            "the displacement still counts its one whole-record victim (no silent loss)"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "the ring stays at capacity");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        let summary_count = text.matches("kind=monitor ").count();
        let verdict_count = text.matches("kind=shutdown_final ").count();
        assert_eq!(
            summary_count, 1,
            "the reserved monitor summary is emitted (verdict records: {verdict_count})"
        );
        assert_eq!(
            verdict_count, 1,
            "the forced reserved summary must not evict the terminal shutdown verdict \
             (monitor summaries: {summary_count})"
        );
        assert_eq!(
            text.matches("kind=startup_warning ").count(),
            warnings - 1,
            "the one displaced victim is a newest normal warning, not the verdict"
        );
        let verdict_ix = text
            .find("kind=shutdown_final ")
            .expect("a surviving shutdown verdict record");
        let summary_ix = text
            .find("kind=monitor ")
            .expect("a monitor summary record");
        assert!(
            verdict_ix < summary_ix,
            "the verdict is emitted before the summary that could have evicted it"
        );
    }
}

mod monitor_edges {
    use super::*;

    #[test]
    fn logging_monitor_emits_serving_stale_level_bit_when_latched() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.note_serving_stale();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains(" ss=1"),
            "the latched stale-serving level bit must be emitted: {text}"
        );
        assert!(
            !text.contains("ss=0"),
            "the bit is emitted only when latched, never as a zero: {text}"
        );
    }

    #[test]
    fn logging_monitor_suppresses_serving_stale_when_clear() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            !text.contains("ss="),
            "a clear stale-serving bit stays zero-suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_emits_sustained_negatives_when_nonzero() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.note_incident_open();
        m.note_incident_open();
        m.note_incident_open();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains(" sn=3"),
            "the sustained-negatives level carries its count: {text}"
        );
        assert!(
            !text.contains("sn=0"),
            "a zero sustained-negatives level stays suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_suppresses_sustained_negatives_when_zero() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            !text.contains("sn="),
            "a zero sustained-negatives level stays zero-suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_emits_downgrade_to_plain_when_nonzero() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.note_fact_downgrade_to_plain();
        m.note_fact_downgrade_to_plain();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains(" dp=2"),
            "the downgrade-to-plain fact key carries its fold: {text}"
        );
        assert!(
            !text.contains("dp=0"),
            "a zero downgrade fold stays suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_suppresses_downgrade_to_plain_when_zero() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            !text.contains("dp="),
            "a zero downgrade-to-plain fold stays zero-suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_emits_probe_relocations_when_nonzero() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.note_fact_probe_relocation();
        m.note_fact_probe_relocation();
        m.note_fact_probe_relocation();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains(" pr=3"),
            "the probe-relocation fact key carries its fold: {text}"
        );
        assert!(
            !text.contains("pr=0"),
            "a zero probe-relocation fold stays suppressed: {text}"
        );
    }

    #[test]
    fn logging_monitor_suppresses_probe_relocations_when_zero() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &mut m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            !text.contains("pr="),
            "a zero probe-relocation fold stays zero-suppressed: {text}"
        );
    }
}

mod reserved_records {
    use super::*;

    #[test]
    fn logging_reserved_startup_final_displaces_newest_normal_when_full() {
        let (mut store, mut file) = file_logstore();
        for i in 0..(QUEUE_SLOTS - 1) {
            store.startup_warning_ctx(
                100,
                &format!("n{i}.example.org"),
                Family::A,
                "timeout",
                None,
            );
        }
        assert_eq!(
            store.len(),
            QUEUE_SLOTS,
            "the high-edge record fills the last ring slot"
        );
        assert_eq!(store.dropped(), 0, "no warning is dropped during the fill");
        store.startup_final(
            101,
            StartupStatus::Full,
            FinalCounts {
                unresolved: 1,
                ..FinalCounts::default()
            },
        );
        assert_eq!(
            store.dropped(),
            1,
            "the reserved summary displaces and counts the newest normal record"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "the ring stays at capacity");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=startup_final"),
            "the reserved record is emitted: {text}"
        );
        assert!(
            !text.contains("n254.example.org"),
            "the newest normal warning is the displaced victim: {text}"
        );
        assert!(
            text.contains("n0.example.org") && text.contains("n253.example.org"),
            "the older normal warnings survive: {text}"
        );
    }

    #[test]
    fn logging_reserved_records_survive_normal_overflow() {
        let (mut store, mut file) = file_logstore();
        for i in 0..QUEUE_SLOTS {
            store.startup_final(
                100 + i as u64,
                StartupStatus::Full,
                FinalCounts {
                    unresolved: 1,
                    ..FinalCounts::default()
                },
            );
        }
        assert_eq!(store.len(), QUEUE_SLOTS, "reserved records fill the ring");
        let dropped_before = store.dropped();
        for _ in 0..16 {
            store.startup_warning_ctx(200, "sub.example.org", Family::A, "timeout", None);
        }
        assert_eq!(
            store.dropped(),
            dropped_before + 16,
            "normal overflow records are dropped whole, never displacing reserved ones"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "the ring stays at capacity");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text.matches("kind=startup_final").count(),
            QUEUE_SLOTS,
            "every reserved record survives the normal overflow: {text}"
        );
        assert!(
            !text.contains("kind=startup_warning"),
            "no normal overflow record is admitted: {text}"
        );
    }

    #[test]
    fn logging_all_reserved_full_drops_newest_reserved() {
        use crate::enforcement::monitor::Monitor;
        use crate::enforcement::policy::UnknownReason;
        let (mut store, mut file) = file_logstore();
        for i in 0..QUEUE_SLOTS {
            store.startup_final(
                100 + i as u64,
                StartupStatus::Full,
                FinalCounts {
                    unresolved: 1,
                    ..FinalCounts::default()
                },
            );
        }
        assert_eq!(store.len(), QUEUE_SLOTS, "reserved records fill the ring");
        let dropped_before = store.dropped();
        let mut m = Monitor::new();
        m.note_fact_unknown(UnknownReason::Unattributed);
        assert!(
            store.monitor_summary(101, &mut m),
            "a reserved monitor summary is admitted on an all-reserved full ring"
        );
        assert_eq!(
            store.dropped(),
            dropped_before + 1,
            "the newest reserved record is the bounded-not-lossless victim"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "the ring stays at capacity");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=monitor"),
            "the monitor summary is emitted: {text}"
        );
        assert!(
            !text.contains("secs=355"),
            "the newest reserved record is the displaced victim: {text}"
        );
        assert!(
            text.contains("secs=100"),
            "the oldest reserved records survive: {text}"
        );
    }

    #[test]
    fn logging_reserved_eviction_preserves_partial_record_long_successor() {
        assert_reserved_eviction_preserves_partial_record(7, false);
    }

    #[test]
    fn logging_reserved_eviction_preserves_partial_record_short_successor() {
        let (mut b_store, mut b_file) = file_logstore();
        b_store.monitor_summary(10_000, &mut Monitor::new());
        flush_all(&mut b_store);
        let successor_record = read_all(&mut b_file);
        assert_reserved_eviction_preserves_partial_record(successor_record.len() + 1, true);
    }
}

mod shutdown {
    use super::*;

    #[test]
    fn shutdown_final_record_carries_the_dropped_count() {
        let (mut store, mut file) = file_logstore();
        store.shutdown_final(101, ShutdownStatus::Drained, store.dropped());
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("dropped=0"),
            "the shutdown verdict names the dropped-record count: {text}"
        );
    }
}

mod writev_progress {
    use super::*;

    #[test]
    fn logging_stalled_pipe_yields_retains_cursor_and_counts_drops() {
        let (reader, writer) = UnixStream::pair().expect("socketpair");
        writer.set_nonblocking(true).expect("writer nonblocking");
        let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
        let big = "p".repeat(1000);
        let mut turns = 0;
        while turns < 8 * QUEUE_SLOTS && store.len() < QUEUE_SLOTS {
            store.startup_warning_ctx(1, &big, Family::A, "timeout", None);
            store.drain_sink();
            turns += 1;
        }
        assert_eq!(
            store.len(),
            QUEUE_SLOTS,
            "stalled sink retains the full queue"
        );
        assert!(
            !store.sink_has_failed(),
            "a full pipe is WouldBlock, not a sink failure"
        );
        let dropped_before = store.dropped();
        for _ in 0..16 {
            store.startup_warning_ctx(1, &big, Family::A, "timeout", None);
        }
        assert_eq!(
            store.dropped(),
            dropped_before + 16,
            "enqueue keeps dropping whole records while the sink is stalled"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "queued records stay put");
        let _ = reader;
        let _ = writer;
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn logging_enqueue_drop_drain_paths_spend_zero_allocations() {
        use crate::alloc::{Phase, run_phase};
        use crate::dns::outcome::{FailureReason, NameOutcome};
        let v4: SocketAddr = "192.0.2.10:40000".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
        let long = "z".repeat(SLOT_BYTES * 2);
        let unresolved = [
            StartupUnresolved {
                ordinal: 0,
                name: "sub.example.org",
                outcome: NameOutcome::Failed(FailureReason::Receive),
            },
            StartupUnresolved {
                ordinal: 1,
                name: "sub.example.org",
                outcome: NameOutcome::Negative,
            },
        ];
        let (_, control) = run_phase(Phase::Logging, || 0usize);
        assert!(control.all_zero(), "baseline should be quiet: {control:?}");
        let (mut store, _file) = file_logstore();
        let mut stdout_store = LogStore::new().expect("stdout sink store");
        let ((), counts) = run_phase(Phase::Logging, || {
            store.startup_warning_ctx(1, "sub.example.org", Family::A, "timeout", None);
            for un in unresolved {
                store.startup_name(2, un);
            }
            store.startup_final(2, StartupStatus::Failed, FinalCounts::default());
            store.early_activity(3, Some("sub.example.org"), Some(v4), ActivityKind::Data);
            store.reject(4, RejectReason::Capacity, Some(v4), Some("sub.example.org"));
            store.reject(
                5,
                RejectReason::DialFailed,
                Some(v6),
                Some("sub.example.org"),
            );
            store.reject(6, RejectReason::TlsValidation, None, None);
            store.note_capacity(7, 410, 0);
            store.note_capacity(8, 410, 103);
            for _ in 0..20 {
                store.startup_warning_ctx(9, &long, Family::A, "timeout", None);
            }
            for _ in 0..(QUEUE_SLOTS + 4) {
                store.startup_warning_ctx(10, "sub.example.org", Family::A, "timeout", None);
            }
            for _ in 0..(SINK_MAX_OPS + 4) {
                store.drain_sink();
            }
            for _ in 0..(QUEUE_SLOTS + 4) {
                stdout_store.startup_warning_ctx(11, "sub.example.org", Family::A, "timeout", None);
            }
            for _ in 0..(SINK_MAX_OPS + 4) {
                stdout_store.drain_sink();
            }
        });
        assert!(
            counts.all_zero(),
            "enqueue/drop/drain paths (file and stdout sink variants) must not allocate or deallocate after boot: {counts:?}"
        );
    }

    /// A resolver-proven negative (delegated class, resolver 0) recorded at
    /// receipt 1000 with a 600s TTL; read at 1700 so it is past its current
    /// expiry window while the retained proof is still the stored artifact.
    fn negative_evidence() -> crate::dns::cache::evidence::Evidence {
        crate::dns::cache::evidence::Evidence::new(
            true,
            true,
            true,
            crate::dns::cache::evidence::ResolverSource::index(0).unwrap(),
            Some(600),
            1000,
        )
        .unwrap()
    }

    /// Real-cache retained pin: a proven negative for both families survives
    /// current expiry with the exact family-prefixed kind/class/source and the
    /// time-valid/applicable flags read 0 while the proof is retained.
    #[test]
    fn entry_frame_retained_evidence_survives_current_expiry_with_family_prefix() {
        let mut cache = crate::dns::cache::Cache::new(1).unwrap();
        let name = cache.name_index(0).unwrap();
        for fam in [
            crate::dns::cache::Family::A,
            crate::dns::cache::Family::Aaaa,
        ] {
            cache
                .evict_nodata_evidenced(name, fam, negative_evidence())
                .unwrap();
        }
        let mut slot = [0u8; SLOT_BYTES];
        let n = crate::log::encoding::encode_entry_frame(
            &mut slot,
            &cache,
            name,
            &typed_fqdn("example.org", 443),
            1700,
        )
        .unwrap()
        .unwrap();
        let frame = std::str::from_utf8(&slot[..n]).unwrap();
        assert!(frame.starts_with("level=info kind=entry_frame name=\"example.org\" port=443"));
        assert!(frame.ends_with('\n'));
        for fam in ["a", "aaaa"] {
            let prefix = format!(
                "{fam}_retained=\"yes\" {fam}_retained_kind=\"nodata\" \
                 {fam}_retained_class=\"delegated\" {fam}_retained_source="
            );
            assert!(frame.contains(&prefix), "missing {prefix:?} in {frame:?}");
            assert!(
                frame.contains(&format!("{fam}_retained_time_valid=0")),
                "retained time-valid must read 0 after current expiry: {frame:?}"
            );
            assert!(
                frame.contains(&format!("{fam}_retained_applicable=0")),
                "retained applicable must read 0 after current expiry: {frame:?}"
            );
        }
    }

    /// Full-frame bound: a `FQDN_MAX_LEN` name plus max port plus both families
    /// with every retained-detail field present fits the fixed record slot; the
    /// measured byte count (newline included) is a current-frame fact, not a
    /// new resource ceiling.
    #[test]
    fn entry_frame_widest_name_max_port_and_both_families_fit_the_bounded_slot() {
        let mut cache = crate::dns::cache::Cache::new(1).unwrap();
        let name = cache.name_index(0).unwrap();
        for fam in [
            crate::dns::cache::Family::A,
            crate::dns::cache::Family::Aaaa,
        ] {
            cache
                .evict_nodata_evidenced(name, fam, negative_evidence())
                .unwrap();
        }
        let widest = widest_name(0);
        let mut slot = [0u8; SLOT_BYTES];
        let n = crate::log::encoding::encode_entry_frame(
            &mut slot,
            &cache,
            name,
            &typed_fqdn(&widest, 65_535),
            1700,
        )
        .unwrap()
        .unwrap();
        let frame = std::str::from_utf8(&slot[..n]).unwrap();
        assert!(
            frame.contains(&widest),
            "253-byte validated FQDN is embedded verbatim"
        );
        assert!(frame.contains("port=65535"));
        assert!(frame.contains("a_retained=") && frame.contains("aaaa_retained="));
        assert!(frame.ends_with('\n'), "frame ends with a newline");
        assert!(
            n <= 900,
            "full typed frame measured at {n} bytes (> conservative 900 bound)"
        );
    }

    /// Untrusted input boundary: an over-`FQDN_MAX_LEN` hostname is rejected
    /// by the validated `Fqdn` constructor, so no frame record can ever carry
    /// it — the same "no record emitted" guarantee the old overflow test made
    /// before identity became typed. (The generic `Entry` overflow fallback is
    /// exercised by the existing oversize-drop record tests.)
    #[test]
    fn entry_frame_rejects_oversized_hostname_at_input_boundary() {
        let absurd = format!("{}.example.org", "p".repeat(SLOT_BYTES));
        let rejected = crate::config::Fqdn::parse(&format!("{absurd}:443"));
        assert!(
            rejected.is_err(),
            "an over-253-byte hostname is rejected at the Fqdn boundary and no frame is emitted: {rejected:?}"
        );
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn entry_frame_format_spends_zero_allocations_in_phase() {
        use crate::alloc::{Phase, run_phase};
        let mut cache = crate::dns::cache::Cache::new(1).unwrap();
        let name = cache.name_index(0).unwrap();
        cache
            .evict_nodata_evidenced(name, crate::dns::cache::Family::A, negative_evidence())
            .unwrap();
        let typed = typed_fqdn("example.org", 443);
        let mut slot = [0u8; SLOT_BYTES];
        let (_, control) = run_phase(Phase::Logging, || 0usize);
        assert!(control.all_zero(), "baseline should be quiet: {control:?}");
        let ((), counts) = run_phase(Phase::Logging, || {
            let r = crate::log::encoding::encode_entry_frame(&mut slot, &cache, name, &typed, 1700);
            assert!(
                r.is_ok(),
                "frame must format inside the guarded phase: {r:?}"
            );
        });
        assert!(
            counts.all_zero(),
            "entry-frame formatting must not allocate post-boot: {counts:?}"
        );
    }

    #[test]
    fn logging_next_drain_contract_runnable_blocked_and_quiescent() {
        let now = Instant::now();
        let (empty, _empty_file) = file_logstore();
        assert_eq!(
            empty.next_drain(now),
            None,
            "an empty queue is quiescent and never wakes a poll"
        );

        {
            let (reader, writer) = UnixStream::pair().expect("socketpair");
            drop(reader);
            let mut epipe = LogStore::with_fd(&writer).expect("pipe sink store");
            epipe.startup_warning_ctx(1, "sub.example.org", Family::A, "timeout", None);
            epipe.drain_sink();
            assert!(epipe.sink_has_failed());
            assert_eq!(
                epipe.next_drain(now),
                None,
                "a failed sink is quiescent and never wakes a poll"
            );
            let _ = writer;
        }

        let (reader, writer) = UnixStream::pair().expect("socketpair");
        writer.set_nonblocking(true).expect("writer nonblocking");
        let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
        let big = "p".repeat(1000);
        for _ in 0..QUEUE_SLOTS {
            store.startup_warning_ctx(1, &big, Family::A, "timeout", None);
        }
        let mut turns = 0;
        while store.len() > 0 && turns < 8 * QUEUE_SLOTS {
            store.drain_sink();
            turns += 1;
        }
        assert!(store.len() > 0, "the pipe fills and records stay queued");
        assert_eq!(
            store.next_drain(now),
            Some(now + LOG_RETRY),
            "a WouldBlock-stalled sink retries on the bounded monotonic LOG_RETRY deadline, never busy-spinning"
        );

        let (mut runnable, _file) = file_logstore();
        runnable.startup_warning_ctx(1, "sub.example.org", Family::A, "timeout", None);
        assert_eq!(
            runnable.next_drain(now),
            Some(now),
            "queued non-blocked records are immediately runnable"
        );
        let _ = reader;
    }

    #[test]
    fn logging_sink_gathers_multiple_fragments_in_one_writev() {
        let (mut subject, mut subject_file) = file_logstore();
        let (mut reference, mut reference_file) = file_logstore();
        for i in 0..SINK_MAX_OPS {
            let name = format!("host-{i}.example.org");
            subject.startup_warning_ctx(1, &name, Family::A, "timeout", None);
            reference.startup_warning_ctx(1, &name, Family::A, "timeout", None);
        }
        subject.drain_sink();
        assert_eq!(
            subject.sink_syscalls(),
            1,
            "one writev gathers the whole per-turn fragment budget"
        );
        assert_eq!(
            subject.sink_ops(),
            SINK_MAX_OPS,
            "the per-turn op budget is spent in gathered fragments"
        );
        assert_eq!(subject.len(), 0, "the gathered turn drains the queue");
        flush_all(&mut reference);
        let expected = read_all(&mut reference_file);
        let got = read_all(&mut subject_file);
        assert_eq!(
            got, expected,
            "writev gather emits the byte-identical stream"
        );
    }

    #[test]
    fn logging_writev_partial_write_keeps_cursor_and_stream_identical() {
        use std::io::Read as _;
        let (mut reader, writer) = UnixStream::pair().expect("socketpair");
        writer.set_nonblocking(true).expect("writer nonblocking");
        reader.set_nonblocking(true).expect("reader nonblocking");
        let mut subject = LogStore::with_fd(&writer).expect("pipe sink store");
        let big = "p".repeat(1000);
        for _ in 0..40 {
            subject.startup_warning_ctx(1, &big, Family::A, "timeout", None);
        }
        let expected = {
            let (mut reference, mut file) = file_logstore();
            for _ in 0..40 {
                reference.startup_warning_ctx(1, &big, Family::A, "timeout", None);
            }
            flush_all(&mut reference);
            read_all(&mut file)
        };
        let mut got: Vec<u8> = Vec::new();
        let mut first_turn_bytes = 0usize;
        let mut turns = 0usize;
        while subject.len() > 0 && turns < 8 * QUEUE_SLOTS {
            subject.drain_sink();
            turns += 1;
            let mut chunk = [0u8; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&chunk[..n]),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("read: {e}"),
                }
            }
            if turns == 1 {
                first_turn_bytes = got.len();
            }
        }
        assert!(
            turns > 1,
            "the socket buffer must split the gather across turns"
        );
        assert!(
            first_turn_bytes < expected.len(),
            "the first writev is a partial write ({first_turn_bytes} < {})",
            expected.len()
        );
        assert_eq!(
            subject.dropped(),
            0,
            "a live stalled sink never drops records"
        );
        assert_eq!(
            got, expected,
            "partial writev turns never re-emit or skip bytes (byte-identical stream)"
        );
        let _ = reader;
        let _ = writer;
    }

    #[test]
    fn logging_writev_interrupted_keeps_cursor_and_stream_identical() {
        assert_scripted_stall_preserves_cursor_and_stream(
            ScriptedFirst::Interrupted,
            "Interrupted",
        );
    }

    #[test]
    fn logging_writev_zero_progress_keeps_cursor_and_stream_identical() {
        assert_scripted_stall_preserves_cursor_and_stream(ScriptedFirst::Zero, "zero progress");
    }
}

mod sink_failure {
    use super::*;

    #[test]
    fn logging_sink_failure_latches_and_never_blocks() {
        let (reader, writer) = UnixStream::pair().expect("socketpair");
        drop(reader);
        let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
        store.startup_warning_ctx(1, "sub.example.org", Family::A, "timeout", None);
        store.drain_sink();
        assert!(
            store.sink_has_failed(),
            "EPIPE latches the sink failed (SIGPIPE ignored by std per oracle B17)"
        );
        assert_eq!(
            store.dropped(),
            1,
            "the stranded record is counted as dropped, never silently lost (L18)"
        );
        assert_eq!(
            store.len(),
            0,
            "the stranded record is cleared, not retained (L18)"
        );
        store.drain_sink();
        assert!(
            store.sink_has_failed(),
            "a later turn keeps the failure latched"
        );
        assert_eq!(store.dropped(), 1, "no double-counting on a later turn");
        let _ = writer;
    }

    #[test]
    fn logging_sink_failure_latch_is_observed_by_owner_and_wouldblock_never_fails() {
        {
            let (reader, writer) = UnixStream::pair().expect("socketpair");
            drop(reader);
            let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
            store.startup_warning_ctx(1, "sub.example.org", Family::A, "timeout", None);
            store.drain_sink();
            assert!(
                store.sink_has_failed(),
                "the non-WouldBlock write error latches the sink (F-09)"
            );
            store.drain_sink();
            assert!(
                store.sink_has_failed(),
                "a later drain on the already-failed sink never consumes or clears the latch, so the owner observes it at the turn"
            );
            let _ = writer;
        }
        {
            let (reader, writer) = UnixStream::pair().expect("socketpair");
            writer.set_nonblocking(true).expect("writer nonblocking");
            let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
            let big = "p".repeat(1000);
            for _ in 0..QUEUE_SLOTS {
                store.startup_warning_ctx(1, &big, Family::A, "timeout", None);
            }
            let mut turns = 0;
            while store.len() > 0 && turns < 8 * QUEUE_SLOTS {
                store.drain_sink();
                assert!(
                    !store.sink_has_failed(),
                    "a WouldBlock-stalled sink never latches fatal (F-09)"
                );
                turns += 1;
            }
            assert!(store.len() > 0, "the pipe fills and records stay queued");
            assert!(
                !store.sink_has_failed(),
                "backpressure stalls the sink, it never fails it (F-09)"
            );
            let _ = reader;
        }
    }

    #[test]
    fn logging_sink_failure_counts_stranded_records_as_dropped() {
        let (reader, writer) = UnixStream::pair().expect("socketpair");
        drop(reader);
        let mut store = LogStore::with_fd(&writer).expect("pipe sink store");
        let big = "p".repeat(1000);
        let mut guard = 0;
        while guard < 8 * QUEUE_SLOTS && store.len() < QUEUE_SLOTS {
            store.startup_warning_ctx(1, &big, Family::A, "timeout", None);
            guard += 1;
        }
        assert_eq!(
            store.len(),
            QUEUE_SLOTS,
            "queue holds records before the failure"
        );
        let dropped_before = store.dropped();
        store.drain_sink();
        assert!(store.sink_has_failed(), "EPIPE latches the sink failed");
        assert_eq!(
            store.dropped(),
            dropped_before + QUEUE_SLOTS as u64,
            "every record stranded at the failure is counted under whole-record drop accounting (L18)"
        );
        assert_eq!(
            store.len(),
            0,
            "stranded records are cleared, not retained (L18)"
        );
        store.drain_sink();
        assert_eq!(
            store.dropped(),
            dropped_before + QUEUE_SLOTS as u64,
            "a later turn never double-counts the stranded records"
        );
        assert!(store.sink_has_failed(), "the failed latch persists");
        let _ = writer;
    }
}

mod typed_incidents {
    use super::*;

    #[test]
    fn startup_warning_carries_typed_first_failure_reason() {
        let (mut store, _file) = file_logstore();
        store.startup_warning_ctx(1, "sub.example.org", Family::A, "pin_mismatch", None);
        let text = String::from_utf8_lossy(store.last_record_bytes().expect("one warning queued"));
        assert!(
            text.contains("reason=\"pin_mismatch\""),
            "the first-failure startup warning must expose the typed reason token: {text}"
        );
    }

    #[test]
    fn startup_warning_ctx_renders_per_family_negative_lease_set() {
        let cases = [
            ([true, true], "both"),
            ([true, false], "a"),
            ([false, true], "aaaa"),
            ([false, false], "none"),
        ];
        for (flags, expect) in cases {
            let (mut store, _file) = file_logstore();
            store.startup_warning_ctx(1, "sub.example.org", Family::A, "pin_mismatch", Some(flags));
            let text = String::from_utf8_lossy(store.last_record_bytes().expect("warning queued"));
            assert!(
                text.contains(&format!("context=\"{expect}\"")),
                "current lease set {flags:?} renders {expect}: {text}"
            );
        }
    }

    #[test]
    fn startup_warning_ctx_omits_context_when_lease_set_unknown() {
        let (mut store, _file) = file_logstore();
        store.startup_warning_ctx(1, "sub.example.org", Family::A, "pin_mismatch", None);
        let text = String::from_utf8_lossy(store.last_record_bytes().expect("warning queued"));
        assert!(
            !text.contains("context="),
            "UNKNOWN lookup must omit the context token: {text}"
        );
    }

    #[test]
    fn incident_eligible_pair_carries_secs_name_level_and_kind() {
        let (mut store, _file) = file_logstore();
        store.incident_eligible(7, "sub.example.org", EligibleTransition::Lost);
        let loss = String::from_utf8_lossy(store.last_record_bytes().expect("loss queued"));
        assert_eq!(
            loss, "level=error kind=incident_eligible_loss secs=7 name=\"sub.example.org\"\n",
            "loss record pin"
        );
        store.incident_eligible(8, "sub.example.org", EligibleTransition::Recovered);
        let recovery = String::from_utf8_lossy(store.last_record_bytes().expect("recovery queued"));
        assert_eq!(
            recovery,
            "level=info kind=incident_eligible_recovered secs=8 name=\"sub.example.org\"\n",
            "recovery record pin"
        );
    }
}

#[test]
fn family_grade_empty_snapshot_is_explicit_none_within_a_slot() {
    let cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    let mut slot = [0u8; SLOT_BYTES];
    let len = encode_entry_frame(
        &mut slot,
        &cache,
        name,
        &typed_fqdn("example.org", 443),
        1000,
    )
    .unwrap()
    .expect("minimal empty-owner frame fits the 2 KiB slot");
    let frame = std::str::from_utf8(&slot[..len]).unwrap();
    assert!(frame.starts_with("level=info kind=entry_frame name=\"example.org\" port=443"));
    assert!(
        frame.contains(
            "a_current=\"none\" a_required=\"resolver_trusted\" a_outcome=\"unknown\" a_usable=0 a_retained=\"none\""
        ),
        "empty A block explicit and contiguous on the canonical frame: {frame}"
    );
    assert!(frame.ends_with('\n'), "canonical frame ends with a newline");
    assert!(len < SLOT_BYTES, "empty owner frame stays within its slot");
}

#[test]
fn entry_frame_minimal_empty_owner_is_explicit_none_for_both_families() {
    let cache = Cache::new(1).unwrap();
    let name = cache.name_index(0).unwrap();
    let mut slot = [0u8; SLOT_BYTES];
    let len = encode_entry_frame(
        &mut slot,
        &cache,
        name,
        &typed_fqdn("example.org", 443),
        1000,
    )
    .unwrap()
    .expect("minimal empty-owner frame fits the 2 KiB slot");
    assert_eq!(
        &slot[..len],
        b"level=info kind=entry_frame name=\"example.org\" port=443 a_current=\"none\" a_required=\"resolver_trusted\" a_outcome=\"unknown\" a_usable=0 a_retained=\"none\" aaaa_current=\"none\" aaaa_required=\"resolver_trusted\" aaaa_outcome=\"unknown\" aaaa_usable=0 aaaa_retained=\"none\"\n"
            .as_slice(),
        "minimal empty owner: both families explicit none, never invented"
    );
}

#[path = "support/process_harness.rs"]
mod process_harness;
use process_harness::{
    Refusal, capture_stdout, current_exe, serving_config_document, wait_for_success,
};

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mio::net::TcpListener as MioListener;

use alumina::config::parse_config_document;
use alumina::inventory::TrafficStorage;
use alumina::runtime::Runtime;
use alumina::runtime::ServeStorage;

const BODY_403: &str = "403 Forbidden";
const LOOPS: usize = 400;
const MAX_MONITOR_RECORDS: usize = 32;
const MONITOR_TIMEOUT: Duration = Duration::from_secs(120);
const NON_ALLOWLISTED_CONNECT: &[u8] = b"CONNECT nope.example.net:443 HTTP/1.1\r\n\r\n";
const SETTLE_TURNS: usize = 4;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--child") {
        child_main();
    } else {
        parent_main();
    }
}

fn spawn_piped_child() -> Child {
    Command::new(current_exe())
        .arg("--child")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child with a piped stdout")
}

struct MonitorRecords<'a> {
    lines: Vec<&'a str>,
    summaries: Vec<&'a str>,
    detail_batches: Vec<&'a str>,
}

impl<'a> MonitorRecords<'a> {
    fn classify(text: &'a str) -> Self {
        let lines: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("level=info kind=monitor"))
            .collect();
        let summaries = lines
            .iter()
            .copied()
            .filter(|l| l.starts_with("level=info kind=monitor "))
            .collect();
        let detail_batches = lines
            .iter()
            .copied()
            .filter(|l| {
                l.starts_with("level=info kind=monitor_domain ")
                    || l.starts_with("level=info kind=monitor_capture ")
            })
            .collect();
        Self {
            lines,
            summaries,
            detail_batches,
        }
    }

    fn assert_family(&self) {
        assert!(
            !self.lines.is_empty(),
            "the runtime must emit a coalesced monitor family on real stdout"
        );
        assert!(
            !self.summaries.is_empty(),
            "the runtime must emit at least one monitor summary on real stdout"
        );
        assert!(
            self.summaries.len() <= MAX_MONITOR_RECORDS,
            "summaries are coalesced to whole seconds, not per detection: {} lines",
            self.summaries.len()
        );
    }
}

fn assert_summary_fields(summaries: &[&str]) {
    for line in summaries {
        let facts = field_u64(line, "facts_total");
        let actions = field_u64(line, "actions_total");
        let refusals = field_u64(line, "refusals_total");
        assert!(
            facts >= 1 && actions >= 1 && facts == actions,
            "a refuse storm folds one fact per applied first-slot action: {line} (facts={facts} actions={actions})"
        );
        assert_eq!(
            refusals, 0,
            "Host-Not-Allowlisted refuses are detections+actions, never blocked-domain refusals: {line}"
        );
        assert!(line.contains(" ofacts=0"), "no counter saturated: {line}");
    }
}

fn assert_detail_records(records: &MonitorRecords<'_>) {
    for line in &records.detail_batches {
        assert!(
            line.contains(" part="),
            "every detail batch carries a part=<n>/<total> marker: {line}"
        );
        assert!(
            !line.contains("facts_total="),
            "detail batches carry no summary globals: {line}"
        );
    }
    for line in &records.lines {
        assert!(
            !line.contains("d0j="),
            "per-ordinal ja4-change is zero-suppressed on real stdout when no JA4 \
             deviation occurred: {line}"
        );
    }
}

fn assert_one_summary_per_second(summaries: &[&str], elapsed: u64, text: &str) {
    assert!(
        summaries.len() as u64 <= (elapsed + 2),
        "at most one summary per whole serving second (elapsed {elapsed}s got {}): {text}",
        summaries.len()
    );
}

fn parent_main() {
    let mut child = spawn_piped_child();
    let stdout = child.stdout.take().expect("piped child stdout");
    let started = Instant::now();
    let reader = std::thread::spawn(move || capture_stdout(stdout));
    wait_for_success(&mut child, MONITOR_TIMEOUT, "monitor stdout");
    let captured = reader.join().expect("stdout reader thread");
    let elapsed = started.elapsed().as_secs().max(1);

    let text = String::from_utf8_lossy(&captured);
    let records = MonitorRecords::classify(&text);
    records.assert_family();
    assert_summary_fields(&records.summaries);
    assert_detail_records(&records);
    assert_one_summary_per_second(&records.summaries, elapsed, &text);
    eprintln!(
        "MONITOR-STDOUT-OK loops={LOOPS} summaries={} detail_batches={} refusals=0 facts==actions elapsed={elapsed}s",
        records.summaries.len(),
        records.detail_batches.len()
    );
}

fn boot_serving_runtime() -> (u16, Runtime) {
    let bind = "127.0.0.1:0".parse().expect("valid bind address");
    let listener = MioListener::bind(bind).expect("bind serving listener");
    let port = listener.local_addr().expect("listener local addr").port();
    let config = parse_config_document(&serving_config_document(port)).expect("valid config");
    let mut storage = ServeStorage::boot(&config).expect("boot storage");
    storage
        .prepare_stdout_log_sink()
        .expect("prepare nonblocking stdout sink");
    let traffic = TrafficStorage::allocate().expect("allocate traffic storage");
    let runtime = Runtime::new(storage, listener, traffic).expect("preallocate + attach runtime");
    (port, runtime)
}

fn child_main() {
    let (port, mut runtime) = boot_serving_runtime();
    for i in 0..LOOPS {
        Refusal {
            head: NON_ALLOWLISTED_CONNECT,
            expected_body: BODY_403,
            settle_turns: SETTLE_TURNS,
            failure: &format!(
                "iteration {i}: the mandatory 403 stop must be served while stdout is drained"
            ),
        }
        .drive(&mut runtime, port);
        // A short pause every 50 exchanges lets the nonblocking stdout drain
        // catch up, so the storm exercises the sink rather than a backlog that
        // never reaches it.
        if i % 50 == 49 {
            std::thread::sleep(Duration::from_millis(30));
        }
    }
    runtime
        .turn(Some(Duration::from_millis(2)))
        .expect("final turn");
    eprintln!("MONITOR-STDOUT-CHILD-OK loops={LOOPS}");
}

fn field_u64(line: &str, key: &str) -> u64 {
    let needle = format!(" {key}=");
    let idx = line
        .find(&needle)
        .unwrap_or_else(|| panic!("missing {key}: {line}"));
    let rest = &line[idx + needle.len()..];
    let end = rest.find(' ').unwrap_or(rest.len());
    rest[..end].parse().expect("numeric field")
}

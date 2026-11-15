#[path = "support/process_harness.rs"]
mod process_harness;
use process_harness::{
    Refusal, boot_serving_runtime, capture_stdout, run_child_or_parent, spawn_piped_child,
    wait_for_success,
};

use std::time::{Duration, Instant};

const LOOPS: usize = 400;
const MAX_MONITOR_RECORDS: usize = 32;
const MONITOR_TIMEOUT: Duration = Duration::from_secs(120);
const SETTLE_TURNS: usize = 4;
const DRAIN_EVERY: usize = 50;
const DRAIN_PAUSE: Duration = Duration::from_millis(30);

fn main() {
    run_child_or_parent(parent_main, child_main);
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

fn child_main() {
    let (port, mut runtime) = boot_serving_runtime();
    for i in 0..LOOPS {
        Refusal::non_allowlisted_connect(
            SETTLE_TURNS,
            &format!(
                "iteration {i}: the mandatory 403 stop must be served while stdout is drained"
            ),
        )
        .drive(&mut runtime, port);
        if (i + 1) % DRAIN_EVERY == 0 {
            std::thread::sleep(DRAIN_PAUSE);
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

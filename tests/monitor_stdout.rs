use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mio::net::TcpListener as MioListener;

use alumina::config::parse_config_document;
use alumina::inventory::TrafficStorage;
use alumina::runtime::Runtime;
use alumina::serve::ServeStorage;

const BODY_403: &str = "403 Forbidden";
const LOOPS: usize = 400;
const MAX_MONITOR_RECORDS: usize = 32;
const MONITOR_TIMEOUT: Duration = Duration::from_secs(120);

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--child") {
        child_main();
    } else {
        parent_main();
    }
}

fn current_exe() -> std::path::PathBuf {
    std::env::current_exe().expect("current executable path")
}

fn wait_for_success(child: &mut Child, timeout: Duration, what: &str) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait child") {
            assert!(status.success(), "child ({what}) must exit 0, got {status}");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child ({what}) did not exit within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn parent_main() {
    let mut child = Command::new(current_exe())
        .arg("--child")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child with a piped stdout");
    let mut stdout = child.stdout.take().expect("piped child stdout");
    let started = Instant::now();
    let reader = std::thread::spawn(move || {
        let mut captured = Vec::new();
        let mut scratch = [0u8; 4096];
        loop {
            match stdout.read(&mut scratch) {
                Ok(0) => break,
                Ok(n) => captured.extend_from_slice(&scratch[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => panic!("read child stdout: {e}"),
            }
        }
        captured
    });
    wait_for_success(&mut child, MONITOR_TIMEOUT, "monitor stdout");
    let captured = reader.join().expect("stdout reader thread");
    let elapsed = started.elapsed().as_secs().max(1);

    let text = String::from_utf8_lossy(&captured);
    let monitor_lines: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("level=info kind=monitor"))
        .collect();
    assert!(
        !monitor_lines.is_empty(),
        "the runtime must emit a coalesced monitor family on real stdout"
    );
    let summaries: Vec<&str> = monitor_lines
        .iter()
        .copied()
        .filter(|l| l.starts_with("level=info kind=monitor "))
        .collect();
    let detail_batches: Vec<&str> = monitor_lines
        .iter()
        .copied()
        .filter(|l| {
            l.starts_with("level=info kind=monitor_domain ")
                || l.starts_with("level=info kind=monitor_capture ")
        })
        .collect();
    assert!(
        !summaries.is_empty(),
        "the runtime must emit at least one monitor summary on real stdout"
    );
    assert!(
        summaries.len() <= MAX_MONITOR_RECORDS,
        "summaries are coalesced to whole seconds, not per detection: {} lines",
        summaries.len()
    );
    for line in &summaries {
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
    for line in &detail_batches {
        assert!(
            line.contains(" part="),
            "every detail batch carries a part=<n>/<total> marker: {line}"
        );
        assert!(
            !line.contains("facts_total="),
            "detail batches carry no summary globals: {line}"
        );
    }
    for line in &monitor_lines {
        assert!(
            !line.contains("d0j="),
            "per-ordinal ja4-change is zero-suppressed on real stdout when no JA4 \
             deviation occurred: {line}"
        );
    }
    assert!(
        summaries.len() as u64 <= (elapsed + 2),
        "at most one summary per whole serving second (elapsed {elapsed}s got {}): {text}",
        summaries.len()
    );
    eprintln!(
        "MONITOR-STDOUT-OK loops={LOOPS} summaries={} detail_batches={} refusals=0 facts==actions elapsed={elapsed}s",
        summaries.len(),
        detail_batches.len()
    );
}

fn child_main() {
    let bind = "127.0.0.1:0".parse().expect("valid bind address");
    let listener = MioListener::bind(bind).expect("bind serving listener");
    let port = listener.local_addr().expect("listener local addr").port();
    let doc = format!(
        "listen = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"notify\", scope = \"connection\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"sub.example.org:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
    );
    let config = parse_config_document(&doc).expect("valid config");
    let mut storage = ServeStorage::boot(&config).expect("boot storage");
    storage
        .prepare_stdout_log_sink()
        .expect("prepare nonblocking stdout sink");
    let traffic = TrafficStorage::allocate().expect("allocate traffic storage");
    let mut runtime =
        Runtime::new(storage, listener, traffic).expect("preallocate + attach runtime");

    for i in 0..LOOPS {
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connect client");
        client
            .write_all(b"CONNECT nope.example.net:443 HTTP/1.1\r\n\r\n")
            .expect("write connect head");
        let mut seen = false;
        let mut buf = [0u8; 128];
        for _ in 0..100 {
            runtime
                .turn(Some(Duration::from_millis(2)))
                .expect("owner turn drives accept+decision+refuse+close");
            client.set_nonblocking(true).expect("nonblocking client");
            match client.read(&mut buf) {
                Ok(n) if n > 0 => {
                    if String::from_utf8_lossy(&buf[..n]).contains(BODY_403) {
                        seen = true;
                    }
                    break;
                }
                _ => {}
            }
        }
        assert!(
            seen,
            "iteration {i}: the mandatory 403 stop must be served while stdout is drained"
        );
        client.set_nonblocking(false).expect("blocking client");
        drop(client);
        for _ in 0..4 {
            runtime
                .turn(Some(Duration::from_millis(2)))
                .expect("owner turn settles close_slot reset");
        }
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

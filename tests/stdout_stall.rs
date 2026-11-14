#[path = "support/process_harness.rs"]
mod process_harness;
use process_harness::{current_exe, serving_config_document, wait_for_success};

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use mio::net::TcpListener as MioListener;

use alumina::config::parse_config_document;
use alumina::inventory::TrafficStorage;
use alumina::runtime::Runtime;
use alumina::runtime::ServeStorage;

const BODY_403: &str = "403 Forbidden";
const STALL_TIMEOUT: Duration = Duration::from_secs(120);

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--child") {
        child_main();
    } else {
        parent_main();
    }
}

/// Spawns the child with a piped stdout that is never read, so the pipe fills,
/// the child's nonblocking sink drops whole records, and the child must still
/// keep refusing connections. The parent waits for a clean exit within a
/// bounded timeout, killing and reaping the child on timeout.
fn parent_main() {
    let mut child = Command::new(current_exe())
        .arg("--child")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child with a piped, never-drained stdout");
    wait_for_success(&mut child, STALL_TIMEOUT, "stdout stall");
}

fn child_main() {
    let bind = "127.0.0.1:0".parse().expect("valid bind address");
    let listener = MioListener::bind(bind).expect("bind serving listener");
    let port = listener.local_addr().expect("listener local addr").port();
    let doc = serving_config_document(port);
    let config = parse_config_document(&doc).expect("valid config");
    let mut storage = ServeStorage::boot(&config).expect("boot storage");
    storage
        .prepare_stdout_log_sink()
        .expect("prepare nonblocking stdout sink");
    let traffic = TrafficStorage::allocate().expect("allocate traffic storage");
    let mut runtime =
        Runtime::new(storage, listener, traffic).expect("preallocate + attach runtime");

    let loops = 2000usize;
    for i in 0..loops {
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
                    let text = String::from_utf8_lossy(&buf[..n]);
                    if text.contains(BODY_403) {
                        seen = true;
                    }
                    break;
                }
                _ => {}
            }
        }
        assert!(
            seen,
            "iteration {i}: the server must still refuse with 403 while stdout is unconsumed"
        );
        client.set_nonblocking(false).expect("blocking client");
        drop(client);
        for _ in 0..4 {
            runtime
                .turn(Some(Duration::from_millis(2)))
                .expect("owner turn settles close_slot reset");
        }
    }

    let total_emitted = loops as u64;
    let dropped = runtime.serving().storage().log_dropped();
    assert!(
        dropped > 0,
        "the stall must actually fill the pipe and drop whole records: {dropped}"
    );
    assert!(
        dropped <= total_emitted,
        "drops are whole-record and never exceed the records emitted this run: {dropped}"
    );
    eprintln!(
        "STDOUT-STALL-OK loops={loops} refused-served-while-stalled=yes drops={dropped} (<= {total_emitted})"
    );
}

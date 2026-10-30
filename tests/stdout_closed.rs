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
const CLOSED_TIMEOUT: Duration = Duration::from_secs(120);
const EX_IOERR: i32 = 74;

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

/// Spawns the child with a piped stdout whose read end is closed in this
/// parent, so the child's first nonblocking sink write must fail with EPIPE
/// and latch the sink failed. The parent waits for the child to exit `74`
/// (`EX_IOERR`) within a bounded timeout, killing and reaping the child on
/// timeout. A leaked child that keeps running past the latch (the pre-F-09
/// behaviour) exits 0 and fails the assertion.
fn parent_main() {
    let mut child = Command::new(current_exe())
        .arg("--child")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child with a piped, then-closed stdout");
    drop(child.stdout.take());
    wait_for_ioerr(&mut child, CLOSED_TIMEOUT, "stdout closed");
}

fn wait_for_ioerr(child: &mut Child, timeout: Duration, what: &str) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait child") {
            let code = status.code();
            assert_eq!(
                code,
                Some(EX_IOERR),
                "child ({what}) must exit 74 (EX_IOERR) on a closed stdout read end, got {status}"
            );
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child ({what}) did not exit 74 within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
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

    let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connect client");
    client
        .write_all(b"CONNECT nope.example.net:443 HTTP/1.1\r\n\r\n")
        .expect("write connect head");
    let mut seen = false;
    let mut buf = [0u8; 128];
    for _ in 0..200 {
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
        "the server must still run decisions while stdout is write-failed"
    );
    eprintln!("STDOUT-CLOSED-LEAKED: the child kept running after the failed sink (pre-F-09)");
    drop(client);
}

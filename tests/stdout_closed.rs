use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use mio::net::TcpListener as MioListener;

use alumina::config::parse_config_document;
use alumina::inventory::TrafficStorage;
use alumina::runtime::{Preallocated, Runtime};
use alumina::serve::{ServeStorage, StartupDecision};
use alumina::serving::ServeError;

const BODY_403: &str = "403 Forbidden";
const CLOSED_TIMEOUT: Duration = Duration::from_secs(120);
const EX_IOERR: i32 = 74;
const NOW0: u64 = 1000;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--child-owner") => child_owner_main(),
        Some("--child-startup") => child_startup_main(),
        Some("--child-shutdown") => child_shutdown_main(),
        _ => parent_main(),
    }
}

/// The path to this test binary: the parent spawns the same executable in one
/// of the `--child-*` modes with a piped stdout whose read end it then closes,
/// so the child's first nonblocking sink write must fail with EPIPE and latch
/// the sink failed.
fn current_exe() -> std::path::PathBuf {
    std::env::current_exe().expect("current executable path")
}

/// Spawns the child with a piped stdout whose read end is closed in this
/// parent, so the child's sink permanently fails. Returns the child plus its
/// stderr pipe when requested (used to read the serving port).
fn spawn_closed(child_args: &[&str], capture_stderr: bool) -> Child {
    let mut child = Command::new(current_exe())
        .args(child_args)
        .stdout(Stdio::piped())
        .stderr(if capture_stderr {
            Stdio::piped()
        } else {
            Stdio::inherit()
        })
        .spawn()
        .expect("spawn child with a piped, then-closed stdout");
    drop(child.stdout.take());
    child
}

/// Waits for the child to exit with exactly `expected` within a bounded
/// timeout, killing and reaping the child on timeout. A leaked child that
/// keeps running past the latch (a regression) fails the assertion.
fn wait_for_exit(child: &mut Child, expected: i32, timeout: Duration, what: &str) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait child") {
            assert_eq!(
                status.code(),
                Some(expected),
                "child ({what}) must exit {expected}, got {status}"
            );
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child ({what}) did not exit {expected} within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Parses the first `PORT <n>` line the child prints on stderr.
fn read_port(mut stderr: impl Read) -> u16 {
    let mut buf = String::new();
    loop {
        let mut byte = [0u8; 1];
        match stderr.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => buf.push(byte[0] as char),
        }
        if buf.ends_with('\n') {
            if let Some(line) = buf.lines().find(|l| l.starts_with("PORT ")) {
                return u16::from_str(line.trim_start_matches("PORT ")).expect("port number");
            }
            buf.clear();
        }
    }
    panic!("child never reported its serving port; stderr so far: {buf:?}");
}

/// TCP-framed DNS over TCP: reads one 2-byte length-prefixed query.
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

/// Writes one 2-byte length-prefixed DNS over TCP message.
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

/// A local loopback plain-DNS responder that answers every query positively on
/// the loopback address, so the child's startup window resolves the allowlist
/// name early and reaches a `Serve` decision without external network. The
/// child's configured resolver is a bare-IP literal, which dials plain TCP DNS
/// (`startup_dns`), so a TCP DNS responder is sufficient.
struct DnsResponder {
    addr: SocketAddr,
}

impl DnsResponder {
    fn spawn() -> DnsResponder {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind responder");
        let addr = listener.local_addr().expect("responder address");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut sock) = stream else {
                    break;
                };
                while let Some(query) = read_query(&mut sock) {
                    let Some(reply) = build_positive(&query) else {
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

/// Builds a positive DNS reply (A or AAAA) echoing the question.
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

/// Returns a child with a single allowlist entry and the config used by all
/// closed-read-end scenarios: the refused CONNECT decision must carry the log
/// record whose drain fails, and a bare-IP resolver which dials plain DNS so a
/// loopback responder can resolve it.
fn config_doc(listen_port: u16) -> String {
    format!(
        "listen = \"127.0.0.1:{listen_port}\"\nstartup_unresolved_allowance = 0\nresolver = [\"127.0.0.1\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"notify\", scope = \"connection\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"sub.example.org:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\n"
    )
}

/// The parent drives three scenarios against one process each:
///
/// 1. Owner-latch: the owning turn's own drain latches after a refused
///    CONNECT is decided; the parent reads the 403 (the decision ran) and
///    asserts the child exits `74`.
/// 2. Startup-latch: the startup-window drain latches a sink failed before any
///    serving owner turn; the first `serve()` turn then must exit `74`, so a
///    latch by a non-owner drain is still observed by the owner.
/// 3. Shutdown precedence: the same startup-latch precedes a SIGTERM; the
///    owner observes the latch only after shutdown began, and must exit
///    `0` (the shutdown verdict wins) — never `74`.
fn parent_main() {
    scenario_owner_latch();
    scenario_startup_latch(false);
    scenario_startup_latch(true);
}

/// Scenario 1: a decided refusal is served and the owner-turn drain exits 74.
/// The 403 probe uses a bounded per-read timeout so a child that never serves
/// on the dead stdout cannot hold this parent in a blocking read past the
/// file-wide watchdog; a timed-out read is a probe, only EOF or a real I/O
/// error ends the read loop.
fn scenario_owner_latch() {
    let mut child = spawn_closed(&["--child-owner"], true);
    let mut stderr = child.stderr.take().expect("child stderr");
    let port = read_port(&mut stderr);
    let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connect client");
    client
        .write_all(b"CONNECT nope.example.net:443 HTTP/1.1\r\n\r\n")
        .expect("write connect head");
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");
    let mut seen = false;
    let mut buf = [0u8; 256];
    let deadline = Instant::now() + CLOSED_TIMEOUT;
    while Instant::now() < deadline && !seen {
        match client.read(&mut buf) {
            Ok(n) if n > 0 => {
                let text = String::from_utf8_lossy(&buf[..n]);
                if text.contains(BODY_403) {
                    seen = true;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Ok(_) | Err(_) => break,
        }
    }
    assert!(
        seen,
        "the server must decide (403) while stdout is write-failed, before it exits"
    );
    wait_for_exit(
        &mut child,
        EX_IOERR,
        CLOSED_TIMEOUT,
        "stdout closed (owner latch)",
    );
}

/// Scenario 2/3: run a startup window against a loopback DNS responder on a
/// dead stdout. The startup-window drain latches the sink; whether the first
/// serving owner turn exits `74` (no shutdown) or `0` (SIGTERM first) pins the
/// latch-observability and shutdown-precedence contracts.
fn scenario_startup_latch(shutdown_first: bool) {
    let responder = DnsResponder::spawn();
    let port = responder.addr.port().to_string();
    let args = if shutdown_first {
        ["--child-shutdown", &port]
    } else {
        ["--child-startup", &port]
    };
    let mut child = spawn_closed(&args, false);
    let expected = if shutdown_first { 0 } else { EX_IOERR };
    wait_for_exit(
        &mut child,
        expected,
        CLOSED_TIMEOUT,
        "startup-latched stdout",
    );
}

/// Reports an unexpected `serve()` return across the child modes. Every
/// expected outcome terminates inside `serve()` (exit `74` on a latched sink,
/// or the shutdown verdict), so any return here is a test failure whose actual
/// cause must be named and must not masquerade as a clean exit. The parent's
/// exit-code assertion is the authority: after printing, this terminates with
/// the distinct fail code `125`, which matches neither the expected `74` nor
/// the shutdown `0`, so a leaked child always fails its scenario.
fn report_unexpected_serve(what: &str, outcome: Result<std::convert::Infallible, ServeError>) {
    match outcome {
        Ok(never) => match never {},
        Err(e) => eprintln!("STDOUT-CLOSED-SERVE-ERROR ({what}): {e}"),
    }
    std::process::exit(125);
}

/// The owner-turn-latch mode: a refused CONNECT is decided and the first
/// serving owner turn whose drain latches exits 74.
fn child_owner_main() {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind address");
    let listener = MioListener::bind(bind).expect("bind serving listener");
    let port = listener.local_addr().expect("listener local addr").port();
    eprintln!("PORT {port}");
    let doc = config_doc(port);
    let config = parse_config_document(&doc).expect("valid config");
    let mut storage = ServeStorage::boot(&config).expect("boot storage");
    storage
        .prepare_stdout_log_sink()
        .expect("prepare nonblocking stdout sink");
    let traffic = TrafficStorage::allocate().expect("allocate traffic storage");
    let runtime = Runtime::new(storage, listener, traffic).expect("attach runtime");
    report_unexpected_serve("owner", runtime.serve());
}

/// Runs the production startup window with a dead stdout: the startup-window
/// drain latches the sink, and the first serving owner turn must exit 74.
fn child_startup_main() {
    match run_start_up() {
        Ok(runtime) => report_unexpected_serve("startup", runtime.serve()),
        Err(what) => {
            eprintln!("STDOUT-CLOSED-STARTUP-FAILED: {what}");
        }
    }
}

/// Runs the same startup-window latch, then begins shutdown before any serving
/// owner turn: the shutdown verdict must win and the child exits 0.
fn child_shutdown_main() {
    let runtime = match run_start_up() {
        Ok(runtime) => runtime,
        Err(what) => {
            eprintln!("STDOUT-CLOSED-STARTUP-FAILED: {what}");
            return;
        }
    };
    let killed = Command::new("kill")
        .args(["-TERM", &std::process::id().to_string()])
        .status()
        .expect("self-SIGTERM");
    assert!(killed.success(), "kill -TERM self must succeed");
    std::thread::sleep(Duration::from_millis(100));
    report_unexpected_serve("shutdown", runtime.serve());
}

/// Boots the storage, prepares the dead stdout sink, allocates the traffic
/// workspace, runs the startup window against the loopback responder, attaches
/// the bound listener, and returns the serving runtime. The startup-window
/// drain latches the sink failed (the dead stdout) with no exit behaviour and
/// leaves the latch for the serving owner to observe.
fn run_start_up() -> Result<Runtime, String> {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind address");
    let probe = TcpListener::bind(bind).expect("bind port probe");
    let listen_port = probe.local_addr().expect("probe address").port();
    drop(probe);
    let doc = config_doc(listen_port);
    let config = parse_config_document(&doc).map_err(|e| e.to_string())?;
    let mut storage = ServeStorage::boot(&config).map_err(|e| e.to_string())?;
    storage
        .prepare_stdout_log_sink()
        .map_err(|e| e.to_string())?;
    let Some(port) = std::env::args().nth(2) else {
        eprintln!("STDOUT-CLOSED-NO-RESPONDER");
        return Err("no responder port supplied".into());
    };
    let responder_port = u16::from_str(&port).expect("responder port");
    let nameserver = SocketAddr::from_str(&format!("127.0.0.1:{responder_port}"))
        .expect("loopback responder address");
    let traffic = TrafficStorage::allocate().expect("allocate traffic storage");
    let mut owner = Preallocated::preallocate(storage, traffic).expect("preallocate owner");
    let outcome = owner
        .run_startup(nameserver, NOW0)
        .map_err(|e| e.to_string())?;
    let StartupDecision::Serve(_) = outcome.decision else {
        return Err(format!(
            "startup did not decide to serve: {:?}",
            outcome.decision
        ));
    };
    let listener = outcome.listener.expect("serving decision binds a listener");
    owner.attach(listener).map_err(|e| e.to_string())
}

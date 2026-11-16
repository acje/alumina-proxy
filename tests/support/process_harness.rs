//! Test-only owner of the harness shared by every gate binary: a child copy's
//! executable path, the `--child` dispatch that selects a child body from the
//! parent's own entry point, a piped child spawn, the two bounded exit waits,
//! the stdout capture, the serving config document and boot the child starts
//! from, and the one-exchange refusal driver the parent-side gates replay. Both
//! waits kill and reap a child that outlives its deadline, so a hung or leaked
//! child fails its own test rather than the runner.
#![allow(
    dead_code,
    reason = "shared `#[path]` owner; each inclusion site uses only its subset"
)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use mio::net::TcpListener as MioListener;

use alumina::config::{Config, parse_config_document};
use alumina::inventory::TrafficStorage;
use alumina::runtime::{Runtime, ServeStorage};

/// The first process argument that selects a gate binary's child body over its
/// parent body.
pub(super) const CHILD_FLAG: &str = "--child";

/// This test binary's own path: the parent spawns the same executable in a
/// child mode.
pub(super) fn current_exe() -> PathBuf {
    std::env::current_exe().expect("current executable path")
}

/// Runs `child` when this process was spawned in `--child` mode, `parent`
/// otherwise.
pub(super) fn run_child_or_parent(parent: fn(), child: fn()) {
    if std::env::args().nth(1).as_deref() == Some(CHILD_FLAG) {
        child();
    } else {
        parent();
    }
}

/// Spawns this binary in `--child` mode with a piped stdout the parent owns and
/// inherited stderr.
pub(super) fn spawn_piped_child() -> Child {
    Command::new(current_exe())
        .arg(CHILD_FLAG)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child with a piped stdout")
}

/// Waits for the child to exit 0 within `timeout`, killing and reaping it on
/// timeout.
pub(super) fn wait_for_success(child: &mut Child, timeout: Duration, what: &str) {
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

/// Waits for the child to exit with exactly `expected` within `timeout`,
/// killing and reaping it on timeout. A leaked child that keeps running past
/// the latch (a regression) fails the assertion.
pub(super) fn wait_for_exit(child: &mut Child, expected: i32, timeout: Duration, what: &str) {
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

/// Reads the child's piped stdout to EOF, retrying only on `Interrupted`.
pub(super) fn capture_stdout(mut stdout: ChildStdout) -> Vec<u8> {
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
}

/// The serving config document the gate children boot from: one admitted FQDN,
/// a bare-IP resolver, and a notify-or-block action on every surface the gates
/// exercise. Binaries whose scenario needs a different resolver own their own
/// document.
pub(super) fn serving_config_document(port: u16) -> String {
    format!(
        "listen = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\nresolver = [\"1.1.1.1\"]\n[any_illegal]\nconnect_parse = {{ action = \"notify\", scope = \"connection\" }}\nhost_not_allowlisted = {{ action = \"notify\", scope = \"connection\" }}\ntls_profile = {{ action = \"block\", scope = \"all\" }}\nech = {{ action = \"block\", scope = \"connection\" }}\n[allowed_fqdn.\"sub.example.org:443\"]\nearly_data = {{ action = \"notify\", scope = \"connection\" }}\nja4 = {{ action = \"notify\", scope = \"connection\" }}\ndns_assurance = \"resolver_trusted\"\n"
    )
}

/// Boots the serving runtime the gate children drive from the shared serving
/// config document, with the nonblocking stdout sink prepared, and returns its
/// bound port and the attached runtime.
pub(super) fn boot_serving_runtime() -> (u16, Runtime) {
    let bind = "127.0.0.1:0".parse().expect("valid bind address");
    let listener = MioListener::bind(bind).expect("bind serving listener");
    let port = listener.local_addr().expect("listener local addr").port();
    let config = parse_config_document(&serving_config_document(port)).expect("valid config");
    (port, attach_serving_runtime(listener, &config))
}

/// Boots serving storage for `config`, prepares the nonblocking stdout sink,
/// allocates the traffic workspace, and attaches `listener`.
pub(super) fn attach_serving_runtime(listener: MioListener, config: &Config) -> Runtime {
    let mut storage = ServeStorage::boot(config).expect("boot storage");
    storage
        .prepare_stdout_log_sink()
        .expect("prepare nonblocking stdout sink");
    let traffic = TrafficStorage::allocate().expect("allocate traffic storage");
    Runtime::new(storage, listener, traffic).expect("preallocate + attach runtime")
}

/// The status line suffix of the non-allowlisted CONNECT refusal every 403 gate
/// replays.
pub(super) const STATUS_403: &str = "403 Forbidden";

/// The non-allowlisted CONNECT head every 403 gate replays.
pub(super) const NON_ALLOWLISTED_CONNECT: &[u8] = b"CONNECT nope.example.net:443 HTTP/1.1\r\n\r\n";

/// One client exchange the gate replays against its own runtime: the head
/// bytes written, the exact status line suffix the refusal reply must carry,
/// the settle turns that follow the close, and the failure text naming the
/// case. The reply is read to close, and the body after the head terminator
/// must be empty: `400`/`403` are the empty-body refusal classes.
pub(super) struct Refusal<'a> {
    pub(super) head: &'a [u8],
    pub(super) expected_status: &'a str,
    pub(super) settle_turns: usize,
    pub(super) failure: &'a str,
}

impl<'a> Refusal<'a> {
    /// The standard non-allowlisted CONNECT exchange: the shared head and 403
    /// stop status, with the caller's settle count and failure text.
    pub(super) fn non_allowlisted_connect(settle_turns: usize, failure: &'a str) -> Refusal<'a> {
        Refusal {
            head: NON_ALLOWLISTED_CONNECT,
            expected_status: STATUS_403,
            settle_turns,
            failure,
        }
    }

    /// Drives `runtime` for at most 100 two-millisecond turns, accumulating the
    /// reply until the peer closes and asserting it carried the exact expected
    /// status line over an empty body, then restores blocking mode, closes the
    /// client, and settles `settle_turns` further turns.
    pub(super) fn drive(&self, runtime: &mut Runtime, port: u16) {
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connect client");
        client.write_all(self.head).expect("write connect head");
        let mut reply = Vec::new();
        let mut closed = false;
        let mut scratch = [0u8; 128];
        for _ in 0..100 {
            runtime
                .turn(Some(Duration::from_millis(2)))
                .expect("owner turn drives accept+refuse+close");
            client.set_nonblocking(true).expect("nonblocking client");
            loop {
                match client.read(&mut scratch) {
                    Ok(0) => {
                        closed = true;
                        break;
                    }
                    Ok(n) => reply.extend_from_slice(&scratch[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("read the refusal reply: {e}"),
                }
            }
            if closed {
                break;
            }
        }
        assert!(
            closed,
            "the refusal must close the connection: {}",
            self.failure
        );
        let Some(head_end) = reply.windows(4).position(|w| w == b"\r\n\r\n") else {
            panic!(
                "{}: the refusal carried no head terminator; reply was {:?}",
                self.failure,
                String::from_utf8_lossy(&reply)
            );
        };
        let (head, body) = reply.split_at(head_end + 4);
        let status_end = head
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("the refusal head carries a status-line terminator");
        let status_line = String::from_utf8_lossy(&head[..status_end]);
        let expected = format!("HTTP/1.1 {}", self.expected_status);
        assert_eq!(
            status_line.as_ref(),
            expected.as_str(),
            "{}: the reply must open with the exact status line `{expected}`",
            self.failure
        );
        assert!(
            body.is_empty(),
            "{}: the refusal body must be empty after the head terminator, got {} byte(s) {:?} \
             (spec: policy violations receive an empty body)",
            self.failure,
            body.len(),
            String::from_utf8_lossy(body)
        );
        client.set_nonblocking(false).expect("blocking client");
        drop(client);
        for _ in 0..self.settle_turns {
            runtime
                .turn(Some(Duration::from_millis(2)))
                .expect("owner turn settles close_slot reset");
        }
    }
}

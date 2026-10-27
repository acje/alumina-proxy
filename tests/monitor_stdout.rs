use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use mio::net::TcpListener as MioListener;

use alumina::config::parse_config_document;
use alumina::inventory::TrafficStorage;
use alumina::runtime::Runtime;
use alumina::serve::ServeStorage;

const BODY_403: &str = "403 Forbidden";
const LOOPS: usize = 400;
const MAX_MONITOR_RECORDS: usize = 32;

#[expect(
    clippy::too_many_lines,
    reason = "long stdout-stall monitor test driver"
)]
fn main() {
    // SAFETY: `nix_pipe` (below) returns a freshly created pipe's read/write
    // ends written through a stack `[i32; 2]` after a successful `pipe(2)`, or
    // `None`; the `expect` asserts success, so `rd`/`wr` are valid, open pipe
    // fds owned by this single-threaded test until the process exits.
    let (rd, wr) = unsafe { nix_pipe().expect("pipe") };
    // SAFETY: `rd` is the valid, open pipe read end from `nix_pipe`.
    // `fcntl(F_GETFL)` dereferences no pointers and returns the descriptor
    // flags (asserted `>= 0`); `fcntl(F_SETFL, flags | O_NONBLOCK)` then sets
    // a single bit on that same verified-open fd using scalar arguments only.
    unsafe {
        let flags = libc::fcntl(rd, libc::F_GETFL);
        assert!(flags >= 0, "read end flags");
        assert_eq!(
            libc::fcntl(rd, libc::F_SETFL, flags | libc::O_NONBLOCK),
            0,
            "read end set non-blocking"
        );
    }
    // SAFETY: `wr` is a valid, open pipe fd created just above, and `dup2`
    // atomically redirects this process's stdout (fd 1) onto it. This
    // single-threaded harness does not use fd 1 between this call and the
    // service loop, and the result is asserted to be `1`.
    let dup = unsafe { libc::dup2(wr, 1) };
    assert_eq!(dup, 1, "stdout redirected onto the witness pipe");
    let _ = wr;
    let mut rd = rd;

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

    let mut captured: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 4096];
    let started = Instant::now();
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
        drain_stdout(&mut rd, &mut scratch, &mut captured);
        if i % 50 == 49 {
            std::thread::sleep(Duration::from_millis(30));
        }
    }
    runtime
        .turn(Some(Duration::from_millis(2)))
        .expect("final turn");
    drain_stdout(&mut rd, &mut scratch, &mut captured);

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
    let elapsed = started.elapsed().as_secs().max(1);
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

fn drain_stdout(rd: &mut libc::c_int, scratch: &mut [u8], captured: &mut Vec<u8>) {
    loop {
        // SAFETY: `*rd` is the valid, open pipe read end redirected to stdout
        // and never closed by another thread; `scratch.as_mut_ptr().cast()` is
        // a writable region of exactly `scratch.len()` bytes for the duration
        // of the call; `libc::read` writes at most `len` bytes, and a `-1`
        // return ends the drain loop before the buffer contents are read.
        let n = unsafe { libc::read(*rd, scratch.as_mut_ptr().cast(), scratch.len()) };
        if n > 0 {
            captured.extend_from_slice(
                &scratch[..usize::try_from(n).expect("read returned a positive byte count")],
            );
        } else {
            break;
        }
    }
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

// SAFETY: wraps `pipe(2)` for this test harness: on success both returned fds
// are valid, open pipe ends owned exclusively by the caller (no aliasing and
// no concurrent close before the harness exits them); on failure `None` is
// returned and no fds are consumed. The helper dereferences no memory other
// than the caller's stack `fds` array, written by `pipe(2)` only on success.
unsafe fn nix_pipe() -> Option<(libc::c_int, libc::c_int)> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds.as_mut_ptr()` points to a writable `[i32; 2]` that lives
    // for the whole call; `pipe(2)` writes exactly two ints on success and
    // touches nothing else, and failure (`-1`, `errno`) is handled by
    // returning `None` rather than reading `fds`.
    (unsafe { libc::pipe(fds.as_mut_ptr()) } == 0).then(|| (fds[0], fds[1]))
}

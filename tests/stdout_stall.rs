use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use mio::net::TcpListener as MioListener;

use alumina::config::parse_config_document;
use alumina::inventory::TrafficStorage;
use alumina::runtime::Runtime;
use alumina::serve::ServeStorage;

const BODY_403: &str = "403 Forbidden";

fn main() {
    // SAFETY: `nix_pipe` (below) returns a freshly created pipe's read/write
    // ends written through a stack `[i32; 2]` after a successful `pipe(2)`, or
    // `None`; the `expect` asserts success, so `rd`/`wr` are valid, open pipe
    // fds owned by this single-threaded test until the process exits.
    let (rd, wr) = unsafe { nix_pipe().expect("pipe") };
    // SAFETY: `wr` is a valid, open pipe fd created just above, and `dup2`
    // atomically redirects this process's stdout (fd 1) onto it. This
    // single-threaded harness does not use fd 1 between this call and the
    // service loop, and the result is asserted to be `1`.
    let dup = unsafe { libc::dup2(wr, 1) };
    assert_eq!(
        dup, 1,
        "stdout redirected onto the never-drained stall pipe"
    );
    #[cfg(target_os = "linux")]
    // SAFETY: `wr` is still the valid, open pipe write end created by
    // `nix_pipe`; `fcntl(F_SETPIPE_SZ, 4096)` takes only an integer size
    // argument on Linux (dereferences no pointers), and its `-1` failure
    // return is intentionally unchecked — pipe-size shrink is best-effort and
    // the stall assertion below does not depend on it.
    unsafe {
        libc::fcntl(wr, libc::F_SETPIPE_SZ, 4096);
    }
    let _ = rd;
    let _ = wr;

    let bind = "127.0.0.1:0".parse().expect("valid bind address");
    let listener = MioListener::bind(bind).expect("bind serving listener");
    let port = listener.local_addr().expect("listener local addr").port();
    let doc = format!(
        "allowlist = [\"sub.example.org:443\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\"]\nscope = [\"connection\"]\n"
    );
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

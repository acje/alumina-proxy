//! Test-only owner of the process harness shared by every gate binary that
//! drives a child copy of itself: its own executable path, the two bounded
//! exit waits, the stdout capture, and the serving config document the child
//! boots from. Both waits kill and reap a child that outlives its deadline, so
//! a hung or leaked child fails its own test rather than the runner.
#![allow(
    dead_code,
    reason = "shared `#[path]` owner; each inclusion site uses only its subset"
)]

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, ChildStdout};
use std::time::{Duration, Instant};

/// This test binary's own path: the parent spawns the same executable in a
/// child mode.
pub(super) fn current_exe() -> PathBuf {
    std::env::current_exe().expect("current executable path")
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

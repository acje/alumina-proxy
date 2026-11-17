//! Entry gate for the shipped executable: the boot-failure arm of `main()`.
//!
//! Every other gate child links the crate and re-implements the runtime
//! in-process, so nothing exercised the actual binary — its `main()`, its exit
//! code, or its diagnostic channel. This target spawns
//! `CARGO_BIN_EXE_alumina` as a child in a scratch working directory and holds
//! the documented boot-failure contract:
//!
//! - the binary reads `config.toml` from its working directory (no CLI or
//!   environment policy), so an empty or malformed directory is a boot failure;
//! - a boot failure exits `EX_CONFIG` (78), the code `main()` uses for every
//!   `run_boot` error;
//! - the failure is diagnosed on stderr as `alumina: <err>` and never on
//!   stdout: an empty stdout is the proof that no serving banner is printed
//!   before the boot decision;
//! - on Linux, `run_boot` reads `/proc/self/status` and refuses an unmet
//!   privilege prerequisite before it opens the config document
//!   (`src/boot/preflight.rs`). The child is spawned with the tested
//!   prerequisites — unprivileged UID, empty capability sets, `no_new_privs` —
//!   because a container-root child would legitimately be refused for its own
//!   root UID instead of reaching the config stage. That ordering is not
//!   observable from outside: with every prerequisite satisfied, swapping the
//!   two `run_boot` steps yields the same exit code and stderr.
//!
//! Off Linux the same spawn pins the other documented arm: the preflight has no
//! kernel probe to read, so it refuses with `PreflightError::NotLinux`
//! ("requires a Linux kernel") as `EX_CONFIG`, again with empty stdout. That
//! keeps this target a real assertion on a Darwin host rather than an empty
//! binary that silently passes.
//!
//! Prove / not prove. Proven: the real binary's boot-failure exit code, the
//! stderr diagnostic channel, and that a failed boot writes no serving banner
//! to stdout. NOT proven: the preflight-before-config ordering, which no
//! outside observation can separate while the prerequisites hold, and the
//! serving path — no listener is bound, no CONNECT is attempted, and the
//! 403/no-serving exchange against the real binary is not exercised here; the
//! serving half is deferred.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;

/// The unprivileged uid the boot prerequisites demand — the same uid the boot
/// fixtures drop to. Linux-only: the non-Linux arm never reaches a UID check.
#[cfg(target_os = "linux")]
const UNPRIVILEGED_UID: u32 = 65534;

/// Scratch working directory for one child: process-unique, world-traversable
/// (0755) so a dropped-privilege child can reach the config document inside it,
/// and removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(tag: &str) -> Self {
        Self(unique_dir(tag))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn unique_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "alumina-binary-entry-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create the binary-entry scratch directory");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))
        .expect("make the scratch directory traversable by the child");
    dir
}

/// Writes the fixed documented input name, readable by a dropped-privilege
/// child: a restrictive umask would otherwise leave the document unreadable and
/// the child would fail at the same "config" diagnostic for the wrong reason.
#[cfg(target_os = "linux")]
fn write_config(dir: &Path, body: &str) {
    let path = dir.join("config.toml");
    fs::write(&path, body).expect("write the scratch config document");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .expect("make the scratch config document readable by the child");
}

/// Spawns the shipped binary with `dir` as its working directory, capturing
/// both streams.
fn run_in(dir: &Path) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_alumina"));
    command
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(target_os = "linux")]
    require_boot_prerequisites(&mut command);
    command.output().expect("spawn the real alumina binary")
}

/// Gives the child the boot prerequisites `run_boot` checks, then executes it.
///
/// In a root container the child would otherwise be refused for its root UID
/// and non-empty capability sets, so privileges are dropped to an unprivileged
/// uid — groups before gid before uid, because once the uid is gone the process
/// can no longer change its supplementary groups. `no_new_privs` is then set
/// for every child, root or not: it is a prerequisite the child cannot inherit
/// from the test process.
#[cfg(target_os = "linux")]
fn require_boot_prerequisites(command: &mut Command) {
    // SAFETY: `pre_exec` runs in the forked child between fork and exec, where
    // only async-signal-safe work is sound. This closure allocates nothing,
    // takes no locks and calls only direct libc setters (setgroups, setgid,
    // setuid, prctl), each checked. Privilege drop plus no_new_privs are
    // exactly the prerequisites the real binary's boot preflight reads back
    // from /proc/self/status; a failure here is returned as the spawn error so
    // the test can never silently run the binary under a wrong privilege
    // profile.
    unsafe {
        command.pre_exec(|| {
            if libc::geteuid() == 0 {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgid(UNPRIVILEGED_UID) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(UNPRIVILEGED_UID) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Asserts the documented boot-failure envelope (exit `EX_CONFIG` 78, a
/// non-empty stderr diagnostic, empty stdout) and returns the observed stderr
/// so a caller can assert on stable substrings only.
fn ex_config_failure(output: &Output, scenario: &str) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(78),
        "{scenario}: a boot failure exits EX_CONFIG 78; observed {:?}, stdout {stdout:?}, stderr {stderr:?}",
        output.status
    );
    assert!(
        !stderr.trim().is_empty(),
        "{scenario}: a boot failure must diagnose itself on stderr; stdout was {stdout:?}"
    );
    assert!(
        stdout.is_empty(),
        "{scenario}: stdout must carry no serving banner before the boot decision; got {stdout:?}"
    );
    stderr.into_owned()
}

/// A missing config document: the config stage refuses, stdout stays clean.
///
/// The diagnostic is checked only for a stable substring (it names the config
/// input) and for the absence of the preflight diagnostic. Which of the two
/// boot steps ran first is not observable from outside once the prerequisites
/// are satisfied, so this test claims no ordering.
#[cfg(target_os = "linux")]
#[test]
fn missing_config_exits_ex_config_without_serving() {
    let dir = ScratchDir::new("missing");
    let output = run_in(dir.path());
    let stderr = ex_config_failure(&output, "missing config.toml");
    let lowered = stderr.to_lowercase();
    assert!(
        lowered.contains("config"),
        "the diagnostic must name the config input; stderr was: {stderr:?}"
    );
    assert!(
        !lowered.contains("prerequisite failure"),
        "the preflight must pass before the config is opened, so this must be the config stage; stderr was: {stderr:?}"
    );
}

/// A malformed config document the child can read: the same exit code and
/// channel, refused by parse/validation instead of by an unreadable document
/// or a hosting prerequisite — the wrong-reason trap `write_config` names.
#[cfg(target_os = "linux")]
#[test]
fn malformed_config_exits_ex_config_with_a_parse_diagnostic() {
    let dir = ScratchDir::new("malformed");
    write_config(dir.path(), "bogus = [");
    let output = run_in(dir.path());
    let stderr = ex_config_failure(&output, "malformed config.toml");
    let lowered = stderr.to_lowercase();
    assert!(
        lowered.contains("config"),
        "the diagnostic must name the config input; stderr was: {stderr:?}"
    );
    assert!(
        !lowered.contains("unreadable"),
        "the child must have READ the document, so the refusal is parse/validation, \
         not a read failure (`ConfigError::Unreadable` in src/config/mod.rs); \
         stderr was: {stderr:?}"
    );
    assert!(
        !lowered.contains("permission denied"),
        "an unreadable document also reports a 'config' substring, so a permission \
         refusal must fail here; stderr was: {stderr:?}"
    );
    assert!(
        !lowered.contains("prerequisite failure"),
        "a malformed document must be refused by the config stage, not by the preflight; stderr was: {stderr:?}"
    );
}

/// Off Linux the preflight itself is the boot failure: the kernel facts are
/// unreadable, the documented diagnostic names the Linux-kernel requirement,
/// and the exit code and clean stdout hold on this platform too.
#[cfg(not(target_os = "linux"))]
#[test]
fn preflight_refuses_a_non_linux_kernel_with_ex_config() {
    let dir = ScratchDir::new("non-linux");
    let output = run_in(dir.path());
    let stderr = ex_config_failure(&output, "non-Linux kernel");
    assert!(
        stderr.contains("Linux kernel"),
        "the preflight refusal must name the Linux-kernel requirement (src/boot/preflight.rs Display); stderr was: {stderr:?}"
    );
}

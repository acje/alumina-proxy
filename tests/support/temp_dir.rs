//! Test-only owner of temporary paths: every directory is a private (0700)
//! unpredictable name created exclusively, and every file is created with
//! `O_EXCL` inside it, so a co-tenant of a shared temp directory cannot
//! preplant a path or symlink and redirect a write.
#![allow(
    dead_code,
    reason = "shared `#[path]` owner; each inclusion site uses only its subset"
)]

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process;

/// Fresh-name attempts before a collision is a hard failure rather than a
/// silent retry loop.
const CREATE_ATTEMPTS: u32 = 8;

pub(super) struct TempDir(PathBuf);

impl TempDir {
    pub(super) fn new(tag: &str) -> Self {
        for _ in 0..CREATE_ATTEMPTS {
            let dir = std::env::temp_dir().join(format!(
                "alumina-{tag}-{}-{}",
                process::id(),
                random_hex()
            ));
            match Self::create_at(dir) {
                Ok(dir) => return dir,
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => panic!("create private temp dir: {err}"),
            }
        }
        panic!("create private temp dir: no unused name after {CREATE_ATTEMPTS} attempts");
    }

    /// `create_dir` is the symlink rejection: it fails `EEXIST` for any
    /// pre-existing path, file or symlink whatever it points at, so exclusive
    /// creation replaces a separate `lstat` probe and leaves no TOCTOU gap.
    pub(super) fn create_at(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir(&dir)?;
        if let Err(err) = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)) {
            let _ = fs::remove_dir(&dir);
            return Err(err);
        }
        Ok(TempDir(dir))
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }

    pub(super) fn write(&self, name: &str, body: &str) -> PathBuf {
        self.write_bytes(name, body.as_bytes())
    }

    pub(super) fn write_bytes(&self, name: &str, body: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create temp fixture exclusively (pre-existing path refused)");
        file.write_all(body).expect("write temp fixture");
        path
    }

    /// A read+write seekable `File` on an unlinked inode: created `O_EXCL`
    /// inside a fresh private directory that is removed immediately, so the
    /// descriptor stays valid while no path remains to be preplanted.
    pub(super) fn private_sink_file(prefix: &str) -> File {
        let dir = std::mem::ManuallyDrop::new(TempDir::new(prefix));
        let path = dir.path().join("sink");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create private sink file");
        fs::remove_dir_all(dir.path()).expect("unlink private sink directory");
        file
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn random_hex() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .expect("open /dev/urandom for a temp path name")
        .read_exact(&mut bytes)
        .expect("read 16 bytes of /dev/urandom entropy");
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

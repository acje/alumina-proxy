#!/usr/bin/env python3
"""Validator contract tests in an isolated repo with a stub fixture runner."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

VALIDATOR = Path(__file__).with_name("validate.sh")


class Validator(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo, self.tools = self.base / "repo", self.base / "tools"
        (self.repo / "docs/qa-package").mkdir(parents=True)
        (self.repo / "scripts").mkdir()
        self.variant = self.repo / "target/fixture-facts/release"
        self.variant.mkdir(parents=True)
        self.tools.mkdir()
        shutil.copyfile(VALIDATOR, self.repo / "docs/qa-package/validate.sh")
        for name in ("sh", "dirname", "date", "uname", "rm", "cat", "sha256sum"):
            if path := shutil.which(name):
                (self.tools / name).symlink_to(path)
        if not (self.tools / "sha256sum").exists():
            (self.tools / "shasum").symlink_to(shutil.which("shasum"))
            self.stub("sha256sum", 'exec shasum -a 256 "$@"')
        self.stub("git", 'case "$1" in rev-parse) printf "test-head\\n";; status) :;; *) exit 1;; esac')
        self.stub("file", 'case "${FILE_MODE:-ok}" in fail) exit 42;; dynamic) printf "ELF dynamically linked\\n";; nonelf) printf "text statically linked\\n";; *) printf "ELF statically linked\\n";; esac')
        (self.repo / "scripts/verify.sh").write_text('''#!/bin/sh
printf '%s\n' "$*" > "$RUN_LOG"
[ "$*" = 'fixtures boot' ] || exit 99
case "$FIXTURE_MODE" in fail) exit 42;; stale) exit 0;; esac
printf 'fresh binary\n' > target/fixture-facts/release/alumina
case "$FIXTURE_MODE" in
  missingbin) rm -f target/fixture-facts/release/alumina; exit 0;;
  missing) exit 0;;
  empty) : > target/fixture-facts/release/variant.sha256;;
  mismatch) printf 'wrong\n' > target/fixture-facts/release/variant.sha256;;
  *) sha256sum target/fixture-facts/release/alumina | { read -r hash rest; printf '%s\n' "$hash"; } > target/fixture-facts/release/variant.sha256;;
esac
[ "$FIXTURE_MODE" != fail_after_marker ] || exit 42
''')
        self.env = {**os.environ, "PATH": str(self.tools), "RUN_LOG": str(self.base / "run"), "FIXTURE_MODE": "fresh"}
        self.stale_marker()

    def stub(self, name, body):
        path = self.tools / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)

    def run_validator(self, **env):
        shell = os.environ.get("VALIDATOR_TEST_SHELL", "/bin/sh")
        return subprocess.run([shell, "docs/qa-package/validate.sh"], cwd=self.repo,
                              env={**self.env, **env}, text=True, capture_output=True)

    def stale_marker(self):
        binary = self.variant / "alumina"
        binary.write_bytes(b"old binary\n")
        binary.chmod(0o755)
        digest = subprocess.check_output([str(self.tools / "sha256sum"), str(binary)], env={**os.environ, "PATH": str(self.tools)}, text=True).split()[0]
        (self.variant / "variant.sha256").write_text(digest + "\n")

    def test_fresh_fixture_success_and_smoke_scope(self):
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.base / "run").read_text().strip(), "fixtures boot")
        self.assertIn("built in this run", result.stdout)
        self.assertIn("QA-PACKAGE-VALIDATE-OK", result.stdout)
        self.assertIn("not release qualification", result.stdout)

    def test_stale_missing_mismatch_and_fixture_failure_fail_closed(self):
        for mode in ("stale", "missing", "missingbin", "empty", "mismatch", "fail", "fail_after_marker"):
            with self.subTest(mode=mode):
                self.stale_marker()
                result = self.run_validator(FIXTURE_MODE=mode)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("QA-PACKAGE-VALIDATE-OK", result.stdout)
                self.assertNotIn("built in this run", result.stdout)

    def test_probe_failures_do_not_pass(self):
        for mode in ("fail", "dynamic", "nonelf"):
            with self.subTest(mode=mode):
                result = self.run_validator(FILE_MODE=mode)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("QA-PACKAGE-VALIDATE-OK", result.stdout)

    def test_missing_prerequisites_abort_before_fixture_and_marker_removal(self):
        for names in (("git",), ("file",), ("sha256sum", "shasum")):
            with self.subTest(names=names):
                original = (self.variant / "variant.sha256").read_bytes()
                moved = [(self.tools / n, self.base / n) for n in names if (self.tools / n).exists()]
                for tool, backup in moved:
                    tool.rename(backup)
                try:
                    result = self.run_validator()
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("QA-PACKAGE-PREREQ-FAIL", result.stderr)
                    self.assertFalse((self.base / "run").exists())
                    self.assertEqual((self.variant / "variant.sha256").read_bytes(), original)
                finally:
                    for tool, backup in moved:
                        backup.rename(tool)

    def test_marker_removal_and_hash_failures_are_fatal(self):
        (self.tools / "rm").unlink()
        self.stub("rm", "exit 42")
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "run").exists())
        self.assertIn("cannot clear prior", result.stderr)
        (self.tools / "rm").unlink()
        (self.tools / "rm").symlink_to(shutil.which("rm"))
        (self.tools / "sha256sum").unlink()
        self.stub("sha256sum", "exit 42")
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("QA-PACKAGE-PREREQ-FAIL", result.stderr)
        self.assertFalse((self.base / "run").exists())

    def test_artifact_hasher_error_is_not_masked(self):
        hasher, backup = self.tools / "sha256sum", self.base / "real-hasher"
        hasher.rename(backup)
        self.stub("sha256sum", 'case "$1" in /*) exit 42;; *) exec "$HASH_BACKUP" "$@";; esac')
        result = self.run_validator(HASH_BACKUP=str(backup))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("artifact hasher failed", result.stderr)
        self.assertNotIn("built in this run", result.stdout)


if __name__ == "__main__":
    unittest.main()
